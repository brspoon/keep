"""Install the exact reviewed vendor cohort offline, without a runtime shell.

Only preparation downloads packages. The installer checks the pinned inputs
again and lets apk verify signatures against the mounted public keys. The
final install, patches and removal of bundled tools share one image layer.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sysconfig
import tempfile

if __package__:
    from . import alpine_expat_sources as expat
    from . import alpine_zlib_sources as zlib
    from . import alpine_sqlite_sources as sqlite
    from . import alpine_musl_sources as musl
    from . import dhi_python_packages as python
    from . import dhi_certificate_packages as certificates
    from . import build_patched_expat as patched_expat
else:
    import alpine_expat_sources as expat
    import alpine_zlib_sources as zlib
    import alpine_sqlite_sources as sqlite
    import alpine_musl_sources as musl
    import dhi_python_packages as python
    import dhi_certificate_packages as certificates
    import build_patched_expat as patched_expat

ROOT = Path('/opt/runtime-packages')
COHORT = (('musl', musl, 'MUSL_SECURITY.json'),
          ('certificates', certificates, 'CA_CERTIFICATES_SECURITY.json'),
          ('expat', expat, 'EXPAT_SECURITY.json'),
          ('zlib', zlib, 'ZLIB_SECURITY.json'),
          ('sqlite', sqlite, 'SQLITE_SECURITY.json'),
          ('python', python, 'PYTHON_SECURITY.json'))


def arch():
    machine = platform.machine()
    if machine not in {'x86_64', 'aarch64'}:
        raise ValueError('Unreviewed package installation architecture')
    return {'x86_64': 'amd64', 'aarch64': 'arm64'}[machine]


def checked_file(path, digest):
    if path.is_symlink() or not path.is_file():
        raise ValueError('Package install input must be a regular file: ' + str(path))
    if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
        raise ValueError('Package install input checksum mismatch: ' + str(path))
    return path


def prepare(root=ROOT, architecture=None):
    architecture = architecture or arch()
    if root.is_symlink() or root.exists() and any(root.iterdir()):
        raise ValueError('Package preparation requires an empty safe directory')
    root.mkdir(parents=True, exist_ok=True)
    keys = root / 'keys'
    keys.mkdir()
    for name, helper, _ in COHORT:
        spec = helper.reviewed_spec()
        helper.prepare_packages(spec, architecture, root / name)
        signing = spec['signing_keys'][architecture]
        source = checked_file(root / name / 'keys' / signing['name'], signing['sha256'])
        target = keys / signing['name']
        if target.exists() and target.read_bytes() != source.read_bytes():
            raise ValueError('Conflicting reviewed package signing keys')
        target.write_bytes(source.read_bytes())


def installation_inputs(root, architecture):
    packages, keys = [], set()
    for name, helper, manifest_name in COHORT:
        spec = helper.reviewed_spec()
        manifest_path = root / name / manifest_name
        if manifest_path.is_symlink() or not manifest_path.is_file():
            raise ValueError('Missing regular package installation manifest')
        if json.loads(manifest_path.read_bytes()) != helper.build_security_manifest(architecture, root=None):
            raise ValueError('Package installation manifest differs from reviewed inputs')
        signing = spec['signing_keys'][architecture]
        checked_file(root / 'keys' / signing['name'], signing['sha256'])
        keys.add(signing['name'])
        for package in spec['packages']:
            path = root / name / (package['name'] + '-' + package['version'] + '.apk')
            packages.append(checked_file(path, package['binaries'][architecture]['sha256']))
    if {path.name for path in (root / 'keys').iterdir()} != keys:
        raise ValueError('Unreviewed package installation key')
    return packages


def clean_stdlib():
    stdlib = Path(sysconfig.get_path('stdlib'))
    ensurepip = stdlib / 'ensurepip'
    if ensurepip.exists():
        shutil.rmtree(ensurepip)
    for cache in stdlib.rglob('*.pyc'):
        cache.unlink()


def install(root=ROOT):
    architecture = arch()
    packages = installation_inputs(root, architecture)
    subprocess.run(['/sbin/apk', 'add', '--no-network', '--repositories-file', '/dev/null',
                    '--keys-dir', str(root / 'keys'), '--no-cache', '--upgrade',
                    *(str(path) for path in packages)], check=True)
    helper = Path(__file__).with_name('dhi_python_packages.py')
    # Start the new interpreter; this installer may still map the original
    # interpreter/library while apk replaces their filenames.
    subprocess.run(['/usr/bin/python3.14', '-B', str(helper), '--verify-installed',
                    '--architecture', architecture, '--manifest',
                    str(root / 'python/PYTHON_SECURITY.json')], check=True)
    verify_musl(root, architecture)
    verify_certificates(root, architecture)
    subprocess.run(['/usr/bin/python3.14', '-B', str(Path(__file__)),
                    '--install-expat'], check=True)
    subprocess.run(['/usr/bin/python3.14', '-B', str(Path(__file__)),
                    '--install-sqlite'], check=True)
    subprocess.run(['/usr/bin/python3.14', '-B',
                    str(Path(__file__).with_name('patch_python_runtime.py'))], check=True)
    subprocess.run(['/usr/bin/python3.14', '-B', str(Path(__file__)),
                    '--install-socket'], check=True)
    subprocess.run(['/usr/bin/python3.14', '-B', str(Path(__file__)), '--clean-stdlib'], check=True)


def install_socket(root=ROOT, architecture=None):
    """Apply the separately authenticated overlay after original vendor checks."""
    if __package__:
        from . import build_patched_socket as socket_build
    else:
        import build_patched_socket as socket_build
    architecture = architecture or arch()
    output = root / 'socket-patched'
    manifest = json.loads((output / 'SOCKET_SECURITY.json').read_bytes())
    socket_build.verify_manifest(manifest, architecture)
    spec = socket_build.reviewed_spec()
    library = Path(socket_build.extension_path(architecture))
    if library.is_symlink() or library.resolve(strict=True) != library:
        raise ValueError('Original socket extension must be canonical')
    checked_file(library, spec['native'][architecture]['original_extension_sha256'])
    replacement = checked_file(output / library.name, manifest['library']['sha256']).read_bytes()
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=library.parent, prefix='.keep-socket-', delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(replacement)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.chmod(0o755)
        os.replace(temporary, library)
        checked_file(library, manifest['library']['sha256'])
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def install_expat(root=ROOT, architecture=None, library=None, alias=None, vendor_library=None):
    """Replace the canonical vendor library with the separately reviewed build.

    The signed APK manifest still describes the original installed input. It
    never authenticates the replacement; that uses the independent build lock.
    """
    architecture = architecture or arch()
    output = root / 'expat-patched'
    body = patched_expat.regular_bytes(output / 'EXPAT_PATCHED_SECURITY.json',
                                       'Expat replacement manifest')
    manifest = json.loads(body)
    if body != patched_expat.json_bytes(manifest):
        raise ValueError('Expat replacement manifest must use canonical JSON bytes')
    patched_expat.verify_build_manifest(manifest, architecture)
    library = Path(library or manifest['library']['path'])
    alias = Path(alias or library.with_name(manifest['library']['soname']))
    vendor = expat.build_security_manifest(architecture, root=None)
    vendor_library = Path(vendor_library or vendor['library']['path'])
    if (vendor_library.is_symlink() or not vendor_library.is_file()
            or not alias.is_symlink() or alias.resolve(strict=True) != vendor_library
            or library.parent != vendor_library.parent
            or library != vendor_library and (library.exists() or library.is_symlink())):
        raise ValueError('Expat canonical vendor library, replacement path or SONAME alias differs')
    checked_file(vendor_library, vendor['library']['sha256'])
    replacement = patched_expat.regular_bytes(output / patched_expat.LIBRARY,
                                               'Expat replacement library')
    patched_expat.checked(replacement, manifest['library']['sha256'],
                          'Expat replacement library')
    # Never truncate a library an existing interpreter may still map. A fresh
    # interpreter in native qualification verifies the canonical new inode.
    temporary = None
    temporary_alias = None
    try:
        with tempfile.NamedTemporaryFile(dir=library.parent, prefix='.keep-expat-',
                                         delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(replacement)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.chmod(0o755)
        os.replace(temporary, library)
        checked_file(library, manifest['library']['sha256'])
        # Publish the new upstream library name only after verifying its bytes.
        # The old vendor input remains represented by its signed source record.
        with tempfile.NamedTemporaryFile(dir=alias.parent, prefix='.keep-expat-link-',
                                         delete=False) as stream:
            temporary_alias = Path(stream.name)
        temporary_alias.unlink()
        temporary_alias.symlink_to(library.name)
        os.replace(temporary_alias, alias)
        if alias.resolve(strict=True) != library:
            raise ValueError('Expat replacement SONAME alias differs')
        if vendor_library != library:
            checked_file(vendor_library, vendor['library']['sha256'])
            vendor_library.unlink()
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()
        if temporary_alias is not None and (temporary_alias.exists() or temporary_alias.is_symlink()):
            temporary_alias.unlink()


def install_sqlite(root=ROOT, architecture=None, *, directory=Path('/usr/lib')):
    """Install the independently authenticated library without relabeling its APK."""
    if __package__:
        from . import build_patched_sqlite as build
    else:
        import build_patched_sqlite as build
    architecture = architecture or arch()
    output = root / 'sqlite-patched'
    manifest_path = output / 'SQLITE_PATCHED_SECURITY.json'
    manifest = build.read_build_manifest(manifest_path, architecture)
    spec = build.reviewed_spec()
    vendor = directory / Path(build.VENDOR_LIBRARY).name
    library = directory / build.LIBRARY
    alias = directory / build.ALIAS
    vendor_hash = spec['expected_vendor_library_sha256'][architecture]
    if (directory.is_symlink() or not directory.is_dir()
            or vendor.is_symlink() or not vendor.is_file()
            or not alias.is_symlink() or alias.readlink().as_posix() != vendor.name
            or alias.resolve(strict=True) != vendor
            or library.is_symlink() or (vendor != library and library.exists())
            or {path.name for path in directory.glob('libsqlite3.so*')}
               != {vendor.name, alias.name}):
        raise ValueError('SQLite vendor library family or canonical SONAME differs')
    checked_file(vendor, vendor_hash)
    replacement = checked_file(output / build.LIBRARY,
                               manifest['library']['sha256']).read_bytes()
    temporary = temporary_alias = None
    try:
        with tempfile.NamedTemporaryFile(dir=directory, prefix='.keep-sqlite-',
                                         delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(replacement)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.chmod(0o755)
        os.replace(temporary, library)
        checked_file(library, manifest['library']['sha256'])
        with tempfile.NamedTemporaryFile(dir=directory, prefix='.keep-sqlite-link-',
                                         delete=False) as stream:
            temporary_alias = Path(stream.name)
        temporary_alias.unlink()
        temporary_alias.symlink_to(library.name)
        os.replace(temporary_alias, alias)
        if alias.resolve(strict=True) != library:
            raise ValueError('SQLite replacement SONAME alias differs')
        if vendor != library:
            checked_file(vendor, vendor_hash)
            vendor.unlink()
        checked_file(library, manifest['library']['sha256'])
        if set(directory.glob('libsqlite3.so*')) != {library, alias}:
            raise ValueError('SQLite replacement library family differs')
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()
        if temporary_alias is not None and (temporary_alias.exists() or temporary_alias.is_symlink()):
            temporary_alias.unlink()


def verify_certificates(root, architecture, *, build=False):
    command = ['/usr/bin/python3.14', '-B',
                    str(Path(__file__).with_name('dhi_certificate_packages.py')),
                    '--architecture', architecture, '--manifest',
                    str(root / 'certificates/CA_CERTIFICATES_SECURITY.json')]
    if build:
        command.extend(['--verify-build', '--prepared-root', str(root / 'certificates')])
    subprocess.run(command, check=True)


def verify_musl(root, architecture, *, build=False):
    # apk may replace the loader while this installer still maps its old inode.
    # Always execute a new interpreter to check the installed package.
    command = ['/usr/bin/python3.14', '-B',
               str(Path(__file__).with_name('alpine_musl_sources.py')),
               '--architecture', architecture, '--manifest',
               str(root / 'musl/MUSL_SECURITY.json')]
    if build:
        command.extend(['--verify-build', '--prepared-root', str(root / 'musl')])
    else:
        command.append('--verify-installed')
    subprocess.run(command, check=True)


def install_build_sqlite(root=ROOT):
    """Install the exact signed library input before measuring the build ABI."""
    architecture = arch()
    packages = installation_inputs(root, architecture)
    name = 'sqlite-libs-' + sqlite.VERSION + '.apk'
    selected = [path for path in packages if path.name == name]
    if len(selected) != 1:
        raise ValueError('Require the exact signed SQLite build package')
    subprocess.run(['/sbin/apk', 'add', '--no-network', '--repositories-file', '/dev/null',
                    '--keys-dir', str(root / 'keys'), '--no-cache', '--upgrade',
                    str(selected[0])], check=True)
    checked_file(Path('/' + sqlite.LIBRARY_PATH), sqlite.LIBRARY_SHA256[architecture])
    alias = Path('/' + sqlite.ALIAS_PATH)
    if not alias.is_symlink() or alias.readlink().as_posix() != Path(sqlite.LIBRARY_PATH).name:
        raise ValueError('SQLite build SONAME alias differs')


def install_build_python(root=ROOT):
    """Install only the signed Python cohort in a compiler image, not a runtime."""
    architecture = arch()
    packages = installation_inputs(root, architecture)
    names = {name + '-' + python.VERSION + '.apk' for name in python.PACKAGES}
    selected = [path for path in packages if path.name in names]
    if {path.name for path in selected} != names or len(selected) != len(names):
        raise ValueError('Require the exact reviewed build Python cohort')
    subprocess.run(['/sbin/apk', 'add', '--no-network', '--repositories-file', '/dev/null',
                    '--keys-dir', str(root / 'keys'), '--no-cache', '--upgrade',
                    *(str(path) for path in selected)], check=True)
    subprocess.run(['/usr/bin/python3.14', '-B',
                    str(Path(__file__).with_name('dhi_python_packages.py')),
                    '--verify-installed', '--architecture', architecture, '--manifest',
                    str(root / 'python/PYTHON_SECURITY.json')], check=True)
    verify_musl(root, architecture, build=True)
    verify_certificates(root, architecture, build=True)


def install_build_musl(root=ROOT):
    """Upgrade build libc and its exactly coupled development package offline."""
    architecture = arch()
    packages = installation_inputs(root, architecture)
    spec = musl.reviewed_spec()
    filename = 'musl-' + spec['version'] + '.apk'
    selected = [path for path in packages if path.name == filename]
    if len(selected) != 1:
        raise ValueError('Require the exact reviewed build musl package')
    development = musl.build_installation_inputs(root / 'musl', architecture)
    subprocess.run(['/sbin/apk', 'add', '--no-network', '--repositories-file', '/dev/null',
                    '--keys-dir', str(root / 'keys'), '--no-cache', '--upgrade',
                    str(selected[0]), *(str(path) for path in development)], check=True)
    verify_musl(root, architecture, build=True)


def install_certificates(root=ROOT):
    """Upgrade build CA files and their generator in one offline transaction."""
    architecture = arch()
    packages = installation_inputs(root, architecture)
    filename = certificates.PACKAGE + '-' + certificates.VERSION + '.apk'
    selected = [path for path in packages if path.name == filename]
    if len(selected) != 1:
        raise ValueError('Require the exact reviewed build certificate bundle')
    management = certificates.build_installation_inputs(root / 'certificates', architecture)
    subprocess.run(['/sbin/apk', 'add', '--no-network', '--repositories-file', '/dev/null',
                    '--keys-dir', str(root / 'keys'), '--no-cache', '--upgrade',
                    str(selected[0]), *(str(path) for path in management)], check=True)
    verify_certificates(root, architecture, build=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--prepare', action='store_true')
    mode.add_argument('--install', action='store_true')
    mode.add_argument('--install-certificates', action='store_true')
    mode.add_argument('--install-build-musl', action='store_true')
    mode.add_argument('--install-build-sqlite', action='store_true')
    mode.add_argument('--install-build-python', action='store_true')
    mode.add_argument('--install-expat', action='store_true')
    mode.add_argument('--install-socket', action='store_true')
    mode.add_argument('--install-sqlite', action='store_true')
    mode.add_argument('--clean-stdlib', action='store_true')
    args = parser.parse_args()
    if args.prepare:
        prepare()
    elif args.install:
        install()
    elif args.install_certificates:
        install_certificates()
    elif args.install_build_musl:
        install_build_musl()
    elif args.install_build_sqlite:
        install_build_sqlite()
    elif args.install_build_python:
        install_build_python()
    elif args.install_expat:
        install_expat()
    elif args.install_socket:
        install_socket()
    elif args.install_sqlite:
        install_sqlite()
    else:
        clean_stdlib()


if __name__ == '__main__':
    main()
