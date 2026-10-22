"""Qualify the active HTTPS and SMTP trust stores without network access.

Keep this module importable using only the standard library: retained native
reports are also checked outside the application image.
"""
import base64
import binascii
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
from types import SimpleNamespace


CERTIFI_VERSION = '2026.10.19'
CERTIFI_PATH = Path('/venv/lib/python3.14/site-packages/certifi/cacert.pem')
CERTIFI_SHA256 = '50f79f98dac192b20dbf73f35c56f0b0c557ab267ff5199d1117cc1180b70785'
CERTIFI_CERTIFICATES = 120
CERTIFI_FINGERPRINTS_SHA256 = '4b23d6276df62146e4278710951c658a026c69dcb7048c8a2033d78a0f5debe6'
EXCLUDED_ROOT = '86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b'
G1_ROOT = '40f6af0346a99aa1cd1d555a4e9cce62c7f9634603ee406615833dc8c8d00367'
CERTIFI_RETAINED_ROOTS = frozenset((G1_ROOT,
    '125609aa301da0a249b97a8239cb6a34216f44dcac9f3954b14292f2e8c8608f',
    'bc4d809b15189d78db3e1d8cf4f9726a795da1643ca5f1358e1ddb0edc0d7eb3'))
MANIFEST_PATH = Path('/app/CA_CERTIFICATES_SECURITY.json')
OVERRIDE_VARIABLES = ('SSL_CERT_FILE', 'SSL_CERT_DIR', 'REQUESTS_CA_BUNDLE', 'CURL_CA_BUNDLE')
TLS_PROBES = {backend + '_' + probe: True for backend in ('requests', 'smtp')
              for probe in ('trusted_exchange', 'hostname_rejection', 'untrusted_rejection')}
SHA256 = re.compile(r'[0-9a-f]{64}')
HASHED_CERTIFICATE = re.compile(r'[0-9a-fA-F]{8}\.[0-9]+')
MAX_BUNDLE_BYTES = 2 * 1024 * 1024
MAX_CERTIFICATES = 512
MAX_CAPATH_ENTRIES = 4096


def require(condition, message):
    if not condition:
        raise ValueError(message)


def certificate_packages():
    if __package__:
        from . import dhi_certificate_packages
    else:
        import dhi_certificate_packages
    return dhi_certificate_packages


def fingerprint_digest(fingerprints):
    return hashlib.sha256(('\n'.join(sorted(fingerprints)) + '\n').encode()).hexdigest()


def regular_file_bytes(path, limit=MAX_BUNDLE_BYTES):
    """Read a bounded regular file without accepting a symlink or changing inode."""
    path = Path(path)
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode), 'Certificate input must be a regular file')
    require(0 < before.st_size <= limit, 'Certificate input has an invalid size')
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
    with os.fdopen(os.open(path, flags), 'rb') as stream:
        opened = os.fstat(stream.fileno())
        require(stat.S_ISREG(opened.st_mode), 'Certificate input must be a regular file')
        body = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    final = path.lstat()
    fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    require(all(getattr(before, name) == getattr(opened, name) == getattr(after, name)
                == getattr(final, name) for name in fields),
            'Certificate input changed while reading')
    require(0 < len(body) <= limit and len(body) == after.st_size,
            'Certificate input has an invalid size')
    return body


def pem_fingerprints(body):
    """Inventory complete, unambiguous PEM certificates using DER SHA-256."""
    import ssl

    require(isinstance(body, bytes) and 0 < len(body) <= MAX_BUNDLE_BYTES,
            'Certificate bundle has an invalid size')
    try:
        lines = body.decode('ascii').splitlines()
    except UnicodeDecodeError as error:
        raise ValueError('Certificate bundle is not ASCII PEM') from error
    fingerprints, encoded = [], None
    validator = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    for line in lines:
        if encoded is None:
            if line == '-----BEGIN CERTIFICATE-----':
                encoded = []
            else:
                require(not line.strip() or line.startswith('#'),
                        'Unexpected content outside a PEM certificate')
        elif line == '-----END CERTIFICATE-----':
            try:
                compact = ''.join(encoded)
                der = base64.b64decode(compact, validate=True)
            except (ValueError, binascii.Error) as error:
                raise ValueError('Invalid PEM certificate encoding') from error
            require(der and base64.b64encode(der).decode() == compact,
                    'Noncanonical PEM certificate encoding')
            # OpenSSL may accept trailing DER bytes; require the outer sequence
            # to consume the entire certificate before asking it to parse X.509.
            require(len(der) > 2 and der[0] == 0x30, 'Invalid DER certificate sequence')
            length, offset = der[1], 2
            if length & 0x80:
                count = length & 0x7f
                require(1 <= count <= 4 and len(der) >= 2 + count and der[2] != 0,
                        'Invalid DER certificate length')
                length, offset = int.from_bytes(der[2:2 + count], 'big'), 2 + count
                require(length >= 128 and length.bit_length() > (count - 1) * 8,
                        'Noncanonical DER certificate length')
            require(length + offset == len(der), 'Truncated or trailing DER certificate data')
            try:
                validator.load_verify_locations(cadata=der)
            except ssl.SSLError as error:
                raise ValueError('Invalid X.509 certificate') from error
            fingerprints.append(hashlib.sha256(der).hexdigest())
            require(len(fingerprints) <= MAX_CERTIFICATES,
                    'Too many certificates in the bundle')
            encoded = None
        else:
            require(re.fullmatch(r'[A-Za-z0-9+/=]{1,128}', line) is not None,
                    'Invalid or ambiguous PEM certificate content')
            encoded.append(line)
    require(encoded is None and fingerprints, 'Incomplete or empty PEM certificate bundle')
    require(len(fingerprints) == len(set(fingerprints)), 'Duplicate PEM certificates')
    return sorted(fingerprints)


def bundle_identity(path):
    body = regular_file_bytes(path)
    fingerprints = pem_fingerprints(body)
    return {'path': str(path), 'sha256': hashlib.sha256(body).hexdigest(),
            'certificates': len(fingerprints), 'fingerprints': fingerprints,
            'fingerprints_sha256': fingerprint_digest(fingerprints)}


def validate_bundle(identity, path, digest, certificates, inventory_digest, retained):
    require(isinstance(identity, dict) and set(identity) == {
        'path', 'sha256', 'certificates', 'fingerprints', 'fingerprints_sha256'},
        'Invalid certificate bundle identity')
    fingerprints = identity['fingerprints']
    require(isinstance(fingerprints, list) and len(fingerprints) == certificates <= MAX_CERTIFICATES
            and all(isinstance(value, str)
            and SHA256.fullmatch(value) for value in fingerprints)
            and fingerprints == sorted(set(fingerprints)), 'Invalid certificate root inventory')
    require(identity['path'] == str(path) and identity['sha256'] == digest
            and type(identity['certificates']) is int
            and identity['certificates'] == certificates == len(fingerprints)
            and identity['fingerprints_sha256'] == inventory_digest == fingerprint_digest(fingerprints),
            'Certificate bundle differs from the reviewed bytes or root inventory')
    require(EXCLUDED_ROOT not in fingerprints and set(retained) <= set(fingerprints),
            'Excluded root present or unaffected certificate roots missing')


def capath_inventory(path, system_bundle):
    """Inspect every OpenSSL hashed entry, including roots loaded only on demand."""
    path = Path(path)
    try:
        path.lstat()
    except FileNotFoundError:
        return {'path': None, 'entries': 0, 'certificates': 0,
                'fingerprints': [], 'fingerprints_sha256': fingerprint_digest([])}
    path = path.resolve(strict=True)
    require(path.is_dir() and path == Path(system_bundle['path']).parent.resolve(strict=True),
            'OpenSSL certificate directory differs from the system bundle directory')
    before = path.stat()
    fingerprints, entries, inspected, total_bytes = set(), 0, 0, 0
    with os.scandir(path) as children:
        for entry in children:
            inspected += 1
            require(inspected <= MAX_CAPATH_ENTRIES, 'Too many OpenSSL certificate directory entries')
            if not HASHED_CERTIFICATE.fullmatch(entry.name):
                continue
            entries += 1
            body = regular_file_bytes(Path(entry.path).resolve(strict=True))
            total_bytes += len(body)
            require(total_bytes <= 16 * MAX_BUNDLE_BYTES, 'OpenSSL hashed certificate directory is too large')
            fingerprints.update(pem_fingerprints(body))
    after = path.stat()
    require(all(getattr(before, name) == getattr(after, name) for name in
                ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')),
            'OpenSSL certificate directory changed during inspection')
    require(EXCLUDED_ROOT not in fingerprints
            and fingerprints <= set(system_bundle['fingerprints']),
            'OpenSSL hashed certificate directory contains an unreviewed root')
    return {'path': str(path), 'entries': entries, 'certificates': len(fingerprints),
            'fingerprints': sorted(fingerprints), 'fingerprints_sha256': fingerprint_digest(fingerprints)}


def context_fingerprints(context):
    import ssl

    require(context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED,
            'Default TLS certificate and hostname verification are required')
    fingerprints = sorted(hashlib.sha256(cert).hexdigest()
                          for cert in context.get_ca_certs(binary_form=True))
    require(fingerprints and len(set(fingerprints)) == len(fingerprints),
            'Default TLS context has no roots or duplicate roots')
    return fingerprints


def exercise_tls(factory, certificate_pem, private_key_pem, handshake, expected_fingerprints):
    """Exercise normal exchange and distinguish hostname and chain rejection."""
    import ssl

    with tempfile.TemporaryDirectory(prefix='keep-ca-tls-') as directory:
        certificate, private_key = Path(directory) / 'certificate.pem', Path(directory) / 'key.pem'
        certificate.write_text(certificate_pem)
        private_key.write_text(private_key_pem)
        private_key.chmod(0o600)
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(certificate, private_key)
        probes = {}
        for probe, hostname, trusted in (
            ('trusted_exchange', 'keep-runtime.invalid', True),
            ('hostname_rejection', 'wrong-host.invalid', True),
            ('untrusted_rejection', 'keep-runtime.invalid', False),
        ):
            context = factory()
            require(context_fingerprints(context) == expected_fingerprints,
                    'TLS probe context differs from the reviewed root inventory')
            if trusted:
                context.load_verify_locations(cadata=certificate_pem)
            client_in, client_out, server_in, server_out = (ssl.MemoryBIO() for _ in range(4))
            client = context.wrap_bio(client_in, client_out, server_hostname=hostname)
            server = server_context.wrap_bio(server_in, server_out, server_side=True)
            try:
                handshake(client, server, client_in, client_out, server_in, server_out)
            except ssl.SSLCertVerificationError as error:
                expected = (62,) if probe == 'hostname_rejection' else (18, 19, 20, 21)
                require(probe != 'trusted_exchange' and error.verify_code in expected,
                        'TLS failed for a reason other than the expected certificate rejection')
            else:
                require(probe == 'trusted_exchange' and bool(client.getpeercert()),
                        'TLS did not reject an untrusted chain or mismatched hostname')
            probes[probe] = True
    return probes


def manifest_bytes(manifest):
    return (json.dumps(manifest, sort_keys=True, indent=2) + '\n').encode()


def qualify_trust(arch, certificate_pem, private_key_pem, handshake):
    import certifi
    import requests.adapters
    import ssl

    packages = certificate_packages()
    expected_manifest = packages.build_security_manifest(arch, root=None)
    require(not any(name in os.environ for name in OVERRIDE_VARIABLES),
            'Certificate qualification requires default trust without CA environment overrides')
    require(certifi.__version__ == CERTIFI_VERSION, 'Unexpected certifi version')
    actual_certifi = Path(certifi.where()).resolve(strict=True)
    require(actual_certifi == CERTIFI_PATH
            and Path(requests.adapters.DEFAULT_CA_BUNDLE_PATH).resolve(strict=True) == actual_certifi,
            'Requests default CA bundle does not resolve to the reviewed certifi path')
    connection = SimpleNamespace()
    requests.adapters.HTTPAdapter().cert_verify(connection, 'https://keep-runtime.invalid', True, None)
    require(connection.cert_reqs == 'CERT_REQUIRED'
            and Path(connection.ca_certs).resolve(strict=True) == actual_certifi,
            'Requests default adapter does not verify using the certifi bundle')
    certifi_bundle, system_bundle = bundle_identity(actual_certifi), bundle_identity(packages.SYSTEM_BUNDLE_PATH)
    validate_bundle(certifi_bundle, CERTIFI_PATH, CERTIFI_SHA256, CERTIFI_CERTIFICATES,
                    CERTIFI_FINGERPRINTS_SHA256, CERTIFI_RETAINED_ROOTS)
    validate_bundle(system_bundle, packages.SYSTEM_BUNDLE_PATH, packages.BUNDLE_SHA256,
                    packages.BUNDLE_CERTIFICATES, packages.BUNDLE_FINGERPRINTS_SHA256, (G1_ROOT,))
    install_bytes = regular_file_bytes(MANIFEST_PATH, 128 * 1024)
    require(install_bytes == manifest_bytes(expected_manifest),
            'Certificate install manifest differs from the exact signed package records')
    defaults = ssl.get_default_verify_paths()
    require(defaults.cafile is not None
            and Path(defaults.cafile).resolve(strict=True) == Path(packages.SYSTEM_BUNDLE_PATH),
            'Default SMTP CA file does not resolve to the reviewed system bundle')
    capath = capath_inventory(defaults.openssl_capath, system_bundle)
    factories = {'requests': lambda: ssl.create_default_context(cafile=str(actual_certifi)),
                 'smtp': ssl.create_default_context}
    default_inventory = {}
    probes = {}
    for backend, factory in factories.items():
        expected = certifi_bundle if backend == 'requests' else system_bundle
        fingerprints = context_fingerprints(factory())
        require(fingerprints == expected['fingerprints'],
                'Active ' + backend + ' TLS root inventory differs from the reviewed bundle')
        default_inventory[backend] = fingerprint_digest(fingerprints)
        probes.update({backend + '_' + key: value for key, value in exercise_tls(
            factory, certificate_pem, private_key_pem, handshake, expected['fingerprints']).items()})
    report = {'schema': 1, 'arch': arch, 'success': True, 'tests': 8, 'failures': 0,
              'errors': [], 'certifi_version': CERTIFI_VERSION, 'certifi': certifi_bundle,
              'system': system_bundle, 'capath': capath, 'default_root_inventories': default_inventory,
              'tls_probes': probes, 'install_manifest_sha256': hashlib.sha256(install_bytes).hexdigest(),
              'source_manifest_sha256': expected_manifest['source_manifest_sha256']}
    return validate_trust_report(report, arch)


def validate_trust_report(report, arch, root=None):
    """Check retained native trust evidence without importing requests or ssl."""
    packages = certificate_packages()
    manifest = packages.build_security_manifest(arch, root=root)
    require(isinstance(report, dict) and set(report) == {
        'schema', 'arch', 'success', 'tests', 'failures', 'errors', 'certifi_version',
        'certifi', 'system', 'capath', 'default_root_inventories', 'tls_probes',
        'install_manifest_sha256', 'source_manifest_sha256'}, 'Invalid certificate trust report schema')
    require(type(report['schema']) is int and report['schema'] == 1
            and report['arch'] == arch and report['success'] is True
            and type(report['tests']) is int and report['tests'] == 8
            and type(report['failures']) is int and report['failures'] == 0
            and report['errors'] == [] and report['certifi_version'] == CERTIFI_VERSION,
            'Missing or failed certificate trust qualification')
    validate_bundle(report['certifi'], CERTIFI_PATH, CERTIFI_SHA256, CERTIFI_CERTIFICATES,
                    CERTIFI_FINGERPRINTS_SHA256, CERTIFI_RETAINED_ROOTS)
    validate_bundle(report['system'], packages.SYSTEM_BUNDLE_PATH, packages.BUNDLE_SHA256,
                    packages.BUNDLE_CERTIFICATES, packages.BUNDLE_FINGERPRINTS_SHA256, (G1_ROOT,))
    require(report['install_manifest_sha256'] == hashlib.sha256(manifest_bytes(manifest)).hexdigest()
            and report['source_manifest_sha256'] == manifest['source_manifest_sha256'],
            'Certificate trust source or install manifest differs from the reviewed package')
    require(report['default_root_inventories'] == {
        'requests': CERTIFI_FINGERPRINTS_SHA256, 'smtp': packages.BUNDLE_FINGERPRINTS_SHA256},
        'Missing or modified active TLS root inventory')
    probes = report['tls_probes']
    require(isinstance(probes, dict) and set(probes) == set(TLS_PROBES)
            and all(value is True for value in probes.values()), 'Missing or failed certificate TLS probes')
    capath = report['capath']
    require(isinstance(capath, dict) and set(capath) == {
        'path', 'entries', 'certificates', 'fingerprints', 'fingerprints_sha256'},
        'Invalid OpenSSL hashed certificate inventory')
    fingerprints = capath['fingerprints']
    require(isinstance(fingerprints, list) and all(isinstance(value, str)
            and SHA256.fullmatch(value) for value in fingerprints)
            and fingerprints == sorted(set(fingerprints))
            and set(fingerprints) <= set(report['system']['fingerprints'])
            and EXCLUDED_ROOT not in fingerprints
            and capath['fingerprints_sha256'] == fingerprint_digest(fingerprints)
            and type(capath['certificates']) is int and capath['certificates'] == len(fingerprints)
            and type(capath['entries']) is int and 0 <= capath['entries'] <= MAX_CAPATH_ENTRIES
            and (capath['entries'] > 0) == bool(fingerprints)
            and capath['certificates'] <= capath['entries'] * MAX_CERTIFICATES
            and capath['path'] in (None, str(Path(packages.SYSTEM_BUNDLE_PATH).parent))
            and (capath['path'] is not None or capath['entries'] == 0),
            'Unreviewed or invalid OpenSSL hashed certificate inventory')
    return report
