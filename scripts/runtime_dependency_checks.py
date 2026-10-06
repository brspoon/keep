"""Qualify ordinary Expat and OpenSSL loading in the final native image.

Run without network or loader overrides. These checks are separate from the
nine security-patch probes and use only normal XML parsing and TLS setup.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat


EXPAT_VERSION = '2.9.0'
EXPAT_PACKAGE_VERSION = '2.9.0-r0'
EXPAT_BUILD_COMMIT = '46440e4654dc1e4e7d3a69b8a0a9e22fdeda4a88'
EXPAT_LIBRARY = Path('/usr/lib/libexpat.so.1.13.0')
EXPAT_ALIAS = Path('/usr/lib/libexpat.so.1')
EXPAT_LIBRARY_SHA256 = {
    'amd64': '0aa9093ce225c2f5d38a9083a4c203a6133ed9c592366f58e51a6a987f461f44',
    'arm64': '33828821b1a9f49dd434c7b7342a730b1f8b85b6d0b3f0a0558710faeb19988e',
}
OPENSSL_VERSION = '3.5.9'
SSL_LIBRARY = Path('/usr/lib/libssl.so.3')
CRYPTO_LIBRARY = Path('/usr/lib/libcrypto.so.3')
MANIFEST_PATH = Path('/app/EXPAT_SECURITY.json')
MAPS_PATH = Path('/proc/self/maps')
SHA256 = re.compile(r'[0-9a-f]{64}')
ROOT = Path(__file__).resolve().parents[1]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def architecture():
    require(platform.system() == 'Linux', 'Native Linux qualification is required')
    machine = platform.machine()
    require(machine in ('x86_64', 'aarch64'), 'Unreviewed native architecture')
    return {'x86_64': 'amd64', 'aarch64': 'arm64'}[machine]


def validate_expat_manifest(manifest, arch):
    """Bind the install record to the exact reviewed signed package payload."""
    require(arch in EXPAT_LIBRARY_SHA256, 'Unreviewed Expat architecture')
    require(isinstance(manifest, dict), 'Invalid Expat install manifest')
    expected = {
        'schema': 'keep-expat-security-v1', 'architecture': arch,
        'version': EXPAT_VERSION, 'package_version': EXPAT_PACKAGE_VERSION,
        'build_commit': EXPAT_BUILD_COMMIT,
    }
    require(all(manifest.get(key) == value for key, value in expected.items()),
            'Expat install identity differs from the reviewed packages')
    require(manifest.get('library') == {
        'path': str(EXPAT_LIBRARY), 'soname': 'libexpat.so.1',
        'sha256': EXPAT_LIBRARY_SHA256[arch],
    }, 'Expat installed library differs from the reviewed signed package')
    source_hash = manifest.get('source_manifest_sha256')
    require(isinstance(source_hash, str) and SHA256.fullmatch(source_hash),
            'Missing or invalid Expat source manifest hash')
    packages = manifest.get('packages')
    require(isinstance(packages, list) and len(packages) == 2
            and all(isinstance(row, dict) for row in packages),
            'Require both signed Expat package records')
    require(all(isinstance(row.get('name'), str) for row in packages)
            and {row['name'] for row in packages} == {'expat', 'libexpat'},
            'Expat package names differ')
    for row in packages:
        require(row.get('version') == EXPAT_PACKAGE_VERSION
                and row.get('signature_verified') is True,
                'Expat package version or signature verification differs')
        for name in ('apk_sha256', 'pkginfo_sha256', 'signing_key_sha256'):
            value = row.get(name)
            require(isinstance(value, str) and SHA256.fullmatch(value),
                    'Missing or invalid Expat package ' + name)
    require(manifest == expected_expat_manifest(arch, None),
            'Expat install manifest differs from the exact signed package and source records')
    return manifest


def read_expat_manifest(path, arch):
    path = Path(path)
    require(not path.is_symlink() and path.is_file(),
            'Expat install manifest must be a regular file')
    require(path.stat().st_size <= 128 * 1024, 'Expat install manifest is too large')
    body = path.read_bytes()
    require(len(body) <= 128 * 1024, 'Expat install manifest is too large')
    return validate_expat_manifest(json.loads(body), arch), hashlib.sha256(body).hexdigest()


def library_mappings(maps_text, prefix):
    """Read kernel file identities for every mapping of a dependency family."""
    mappings = []
    for line in maps_text.splitlines():
        fields = line.split(None, 5)
        if len(fields) != 6:
            continue
        path = fields[5]
        name = Path(path.removesuffix(' (deleted)')).name
        if name != prefix and not name.startswith(prefix + '.'):
            continue
        require(not path.endswith(' (deleted)'), 'Loaded library was deleted: ' + path)
        require(path.startswith('/'), 'Loaded library path is not absolute')
        require(re.fullmatch(r'[0-9a-fA-F]+:[0-9a-fA-F]+', fields[3]) is not None
                and fields[4].isdigit(), 'Invalid loaded library file identity')
        major, minor = (int(part, 16) for part in fields[3].split(':'))
        inode = int(fields[4])
        require(inode > 0, 'Loaded library has no file inode')
        mappings.append({'path': path, 'device': (major, minor), 'inode': inode})
    require(mappings, 'Ordinary imports did not map ' + prefix)
    return mappings


def file_identity(path):
    path = Path(path)
    before = path.stat()
    require(stat.S_ISREG(before.st_mode), 'Runtime library is not a regular file')
    body = path.read_bytes()
    after = path.stat()
    attributes = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    require(all(getattr(before, name) == getattr(after, name) for name in attributes),
            'Runtime library changed while hashing')
    return {
        'path': str(path), 'sha256': hashlib.sha256(body).hexdigest(),
        'device': f'{os.major(after.st_dev):x}:{os.minor(after.st_dev):x}',
        'inode': after.st_ino,
    }, after


def verify_loaded_library(canonical, prefix, maps_text, expected_sha256=None):
    """Require the mapped inode, device and bytes to match the installed target."""
    canonical = Path(canonical)
    require(canonical.is_absolute() and canonical.resolve(strict=True) == canonical,
            'Installed library is not at its canonical path')
    identity, installed = file_identity(canonical)
    if expected_sha256 is not None:
        require(identity['sha256'] == expected_sha256,
                'Installed library does not match the reviewed package hash')
    device = (os.major(installed.st_dev), os.minor(installed.st_dev))
    for mapped in library_mappings(maps_text, prefix):
        mapped_path = Path(mapped['path'])
        require(mapped_path.resolve(strict=True) == canonical,
                'Ordinary import loaded an unexpected library: ' + mapped['path'])
        require(mapped['device'] == device and mapped['inode'] == installed.st_ino,
                'Mapped library device or inode differs from the installed file')
        mapped_identity, _ = file_identity(mapped_path)
        require(mapped_identity['sha256'] == identity['sha256']
                and mapped_identity['inode'] == installed.st_ino
                and mapped_identity['device'] == identity['device'],
                'Mapped library bytes or identity differ from the installed file')
    return identity


def exercise_expat():
    import pyexpat

    require(pyexpat.EXPAT_VERSION == 'expat_' + EXPAT_VERSION
            and pyexpat.version_info == (2, 9, 0), 'Unexpected ordinary pyexpat version')
    events = []
    parser = pyexpat.ParserCreate()
    parser.StartElementHandler = lambda name, attrs: events.append(('start', name, attrs))
    parser.CharacterDataHandler = lambda data: events.append(('text', data))
    parser.EndElementHandler = lambda name: events.append(('end', name))
    parser.Parse(b'<keep><entry id="1">ready</entry></keep>', True)
    require(events == [('start', 'keep', {}), ('start', 'entry', {'id': '1'}),
                       ('text', 'ready'), ('end', 'entry'), ('end', 'keep')],
            'Ordinary Expat parsing failed')
    try:
        pyexpat.ParserCreate().Parse(b'<keep><entry></keep>', True)
    except pyexpat.ExpatError:
        pass
    else:
        raise ValueError('Malformed XML was not rejected')
    return EXPAT_VERSION


def exercise_openssl():
    import ssl

    require(ssl.OPENSSL_VERSION.startswith('OpenSSL ' + OPENSSL_VERSION + ' ')
            and ssl.OPENSSL_VERSION_INFO[:3] == (3, 5, 9),
            'Unexpected ordinary ssl version')
    context = ssl.create_default_context()
    require(context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname
            and bool(context.get_ca_certs()), 'Default TLS trust context is incomplete')
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    connection = context.wrap_bio(incoming, outgoing, server_hostname='example.invalid')
    require(isinstance(connection, ssl.SSLObject) and connection.context is context
            and connection.server_hostname == 'example.invalid', 'TLS object setup failed')
    try:
        connection.do_handshake()
    except ssl.SSLWantReadError:
        require(outgoing.pending > 0, 'TLS object did not produce a normal ClientHello')
    else:
        raise ValueError('TLS object unexpectedly completed without a peer')
    return OPENSSL_VERSION


def check_expat(arch, manifest_path=MANIFEST_PATH, maps_path=MAPS_PATH):
    version = exercise_expat()
    manifest, install_hash = read_expat_manifest(manifest_path, arch)
    require(EXPAT_ALIAS.is_symlink() and EXPAT_ALIAS.resolve(strict=True) == EXPAT_LIBRARY,
            'Expat SONAME alias does not resolve to libexpat.so.1.13.0')
    library = verify_loaded_library(EXPAT_LIBRARY, 'libexpat.so', Path(maps_path).read_text(),
                                    manifest['library']['sha256'])
    return {'version': version, 'libraries': {'expat': library},
            'source_manifest_sha256': manifest['source_manifest_sha256'],
            'install_manifest_sha256': install_hash}


def check_openssl(arch, maps_path=MAPS_PATH):
    version = exercise_openssl()
    maps_text = Path(maps_path).read_text()
    return {'version': version, 'libraries': {
        'ssl': verify_loaded_library(SSL_LIBRARY, 'libssl.so', maps_text),
        'crypto': verify_loaded_library(CRYPTO_LIBRARY, 'libcrypto.so', maps_text),
    }}


def qualify_runtime(manifest_path=MANIFEST_PATH, maps_path=MAPS_PATH):
    report = {'schema': 1, 'arch': None, 'success': False, 'tests': 0, 'failures': 0,
              'errors': [], 'versions': {}, 'loaded_libraries': {},
              'expat_source_manifest_sha256': None, 'expat_install_manifest_sha256': None}
    try:
        report['arch'] = architecture()
        require(not any(name in os.environ for name in ('LD_LIBRARY_PATH', 'LD_PRELOAD')),
                'Qualification requires ordinary loading without LD_LIBRARY_PATH or LD_PRELOAD')
    except (ValueError, OSError) as error:
        report['errors'].append({'check': 'environment', 'message': str(error)})
    else:
        for name, check in (
            ('expat', lambda: check_expat(report['arch'], manifest_path, maps_path)),
            ('openssl', lambda: check_openssl(report['arch'], maps_path)),
        ):
            report['tests'] += 1
            try:
                result = check()
                report['versions'][name] = result['version']
                report['loaded_libraries'].update(result['libraries'])
                if name == 'expat':
                    report['expat_source_manifest_sha256'] = result['source_manifest_sha256']
                    report['expat_install_manifest_sha256'] = result['install_manifest_sha256']
            except Exception as error:
                report['errors'].append({'check': name, 'message': str(error)})
    report['failures'] = len(report['errors'])
    report['success'] = report['tests'] == 2 and report['failures'] == 0
    return report


def expected_expat_manifest(arch, root):
    if __package__:
        from . import alpine_expat_sources
    else:
        import alpine_expat_sources
    return alpine_expat_sources.build_security_manifest(
        arch, root=Path(root) if root is not None else None)


def validate_report(report, arch, root=ROOT):
    """Replay retained native evidence without accessing a runtime filesystem."""
    require(arch in EXPAT_LIBRARY_SHA256, 'Unreviewed dependency report architecture')
    keys = {'schema', 'arch', 'success', 'tests', 'failures', 'errors', 'versions',
            'loaded_libraries', 'expat_source_manifest_sha256', 'expat_install_manifest_sha256'}
    require(isinstance(report, dict) and set(report) == keys,
            'Invalid dependency qualification report schema')
    require(type(report['schema']) is int and report['schema'] == 1
            and report['arch'] == arch and report['success'] is True
            and type(report['tests']) is int and report['tests'] == 2
            and type(report['failures']) is int and report['failures'] == 0
            and report['errors'] == [], 'Missing or failed native dependency qualification')
    require(report['versions'] == {'expat': EXPAT_VERSION, 'openssl': OPENSSL_VERSION},
            'Dependency report versions differ from the reviewed runtime')
    expected = validate_expat_manifest(expected_expat_manifest(arch, root), arch)
    expected_install_hash = hashlib.sha256(
        (json.dumps(expected, sort_keys=True, indent=2) + '\n').encode()).hexdigest()
    require(report['expat_source_manifest_sha256'] == expected['source_manifest_sha256']
            and report['expat_install_manifest_sha256'] == expected_install_hash,
            'Dependency report source or install manifest differs from the reviewed packages')
    libraries = report['loaded_libraries']
    require(isinstance(libraries, dict) and set(libraries) == {'expat', 'ssl', 'crypto'},
            'Incomplete dependency loaded-library evidence')
    for name, canonical in (('expat', EXPAT_LIBRARY), ('ssl', SSL_LIBRARY),
                            ('crypto', CRYPTO_LIBRARY)):
        identity = libraries[name]
        require(isinstance(identity, dict)
                and set(identity) == {'path', 'sha256', 'device', 'inode'},
                'Invalid dependency loaded-library identity')
        require(identity['path'] == str(canonical),
                'Dependency report loaded a noncanonical library: ' + name)
        require(isinstance(identity['sha256'], str) and SHA256.fullmatch(identity['sha256'])
                and isinstance(identity['device'], str)
                and re.fullmatch(r'[0-9a-f]+:[0-9a-f]+', identity['device'])
                and type(identity['inode']) is int and identity['inode'] > 0,
                'Invalid dependency loaded-library hash, device or inode')
    require(libraries['expat']['sha256'] == EXPAT_LIBRARY_SHA256[arch],
            'Dependency report Expat hash differs from the signed package')
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', action='store_true', help='Print the JSON qualification report')
    args = parser.parse_args(argv)
    report = qualify_runtime()
    if args.report:
        print(json.dumps(report, sort_keys=True))
    else:
        for error in report['errors']:
            print(error['check'] + ': ' + error['message'])
        print(f"Dependency qualification: {report['tests']} checks, {report['failures']} failures")
    return int(not report['success'])


if __name__ == '__main__':
    raise SystemExit(main())
