"""Install the exact reviewed vendor cohort offline, without a runtime shell.

Only preparation downloads packages. The installer checks the pinned inputs
again and lets apk verify signatures against the mounted public keys. The
final install, patches and removal of bundled tools share one image layer.
"""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import shutil
import subprocess
import sysconfig

if __package__:
    from . import alpine_expat_sources as expat
    from . import alpine_zlib_sources as zlib
    from . import dhi_python_packages as python
else:
    import alpine_expat_sources as expat
    import alpine_zlib_sources as zlib
    import dhi_python_packages as python

ROOT = Path('/opt/runtime-packages')
COHORT = (('expat', expat, 'EXPAT_SECURITY.json'),
          ('zlib', zlib, 'ZLIB_SECURITY.json'),
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
    subprocess.run(['/usr/bin/python3.14', '-B',
                    str(Path(__file__).with_name('patch_python_runtime.py'))], check=True)
    subprocess.run(['/usr/bin/python3.14', '-B', str(Path(__file__)), '--clean-stdlib'], check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--prepare', action='store_true')
    mode.add_argument('--install', action='store_true')
    mode.add_argument('--clean-stdlib', action='store_true')
    args = parser.parse_args()
    if args.prepare:
        prepare()
    elif args.install:
        install()
    else:
        clean_stdlib()


if __name__ == '__main__':
    main()
