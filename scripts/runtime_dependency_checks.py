"""Qualify ordinary Expat, OpenSSL and Python loading in the final native image.

Run without network or loader overrides. These checks are separate from the
nine security-patch probes and use only normal XML parsing and TLS setup.
"""
import argparse
import gc
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import sys
import tempfile
import weakref


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
PYTHON_MANIFEST_PATH = Path('/app/PYTHON_SECURITY.json')
PROC_EXECUTABLE_PATH = Path('/proc/self/exe')
PYTHON_VERSION = '3.14.8'
PYTHON_TLS_PROBES = {'wrap_bio_requires_hostname': True,
                     'sni_context_switch_handshake': True,
                     'tls_memory_bio_handshake': True}
MAPS_PATH = Path('/proc/self/maps')
SHA256 = re.compile(r'[0-9a-f]{64}')
ROOT = Path(__file__).resolve().parents[1]

# Public, synthetic test credentials used only for this isolated in-memory exchange.
TLS_CERTIFICATE = """-----BEGIN CERTIFICATE-----
MIIC5jCCAc6gAwIBAgIJAIgoF6HuoP8/MA0GCSqGSIb3DQEBCwUAMB8xHTAbBgNV
BAMMFGtlZXAtcnVudGltZS5pbnZhbGlkMCAXDTI2MTAwNzE1MzEwNFoYDzIxMjYw
OTEzMTUzMTA0WjAfMR0wGwYDVQQDDBRrZWVwLXJ1bnRpbWUuaW52YWxpZDCCASIw
DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKeH8opUPIPTPEYQxfio5Rf/dKSV
SVsVqTG26DLtI2at5yMZnqjJ2dYHETNcb03/B9pbkO+To1nkrP/lUNe+w7mtYtdw
eEqz/Vr0Jv1JQ3hiPDAD5SIO8KeDIxOS8Rwn3YCxPXqKVX4f0FIsr1rSnESV0aCA
dGzoIKgBvbHtRzLILhALldPy14r+egPUqdQvAEKt1dGBTlHa2cBUnaMLQosGOsr/
+DEy2BqpK7eJKEaLTf/6vaE1WgwarNHv0P2yy2Y+nem1+p3wYvckuhhSc0pYzokM
T4xCs3DME3zskNoDtzWukuuCWcRZ7jNezy2lIqwukF6Kt97BB0IBdK33IG8CAwEA
AaMjMCEwHwYDVR0RBBgwFoIUa2VlcC1ydW50aW1lLmludmFsaWQwDQYJKoZIhvcN
AQELBQADggEBAGE26u57z6JhYh2k/pzFoY53S/Aa78/wPsIQ0gO0hlC4scc+eUTQ
ACVdgDniIijM9bHKS6oskDjUTKnDgCofGC8XobHWM8ZzAsgYMmlIFRf/r2Zv/Vw6
ySSb/71YIBo2bpxFFCCNAMnNqexqSI+nECaAcsm9XWGDfAobzT4CXQTtZ343Jmkd
VMDI7n0p5oy3zil+tk1wBsIHjnR8y7BvXS8+XYcuk2T/WFcBGFfyYe5yYGF7QdIy
G7EkXN5Hi8LCTpS3/AzsJDZQWtgcARyt8hH5ScHeOXAMTp2wOJ3MrzDsMPSgBoiL
kaMYLFtCbCkknrzp1TAc1NdlKtZv1VBryTo=
-----END CERTIFICATE-----
"""
TLS_PRIVATE_KEY = """-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCnh/KKVDyD0zxG
EMX4qOUX/3SklUlbFakxtugy7SNmrecjGZ6oydnWBxEzXG9N/wfaW5Dvk6NZ5Kz/
5VDXvsO5rWLXcHhKs/1a9Cb9SUN4YjwwA+UiDvCngyMTkvEcJ92AsT16ilV+H9BS
LK9a0pxEldGggHRs6CCoAb2x7UcyyC4QC5XT8teK/noD1KnULwBCrdXRgU5R2tnA
VJ2jC0KLBjrK//gxMtgaqSu3iShGi03/+r2hNVoMGqzR79D9sstmPp3ptfqd8GL3
JLoYUnNKWM6JDE+MQrNwzBN87JDaA7c1rpLrglnEWe4zXs8tpSKsLpBeirfewQdC
AXSt9yBvAgMBAAECggEAWtr5iFeCsiNe7sit9Nrz033w7kkgDUvEBHgjmWrN5iOt
1HVSfEtr3gzbITWiD3Sd96ftBGDXGCtSPz1ICJkmYI5NqnUOZ8URQ8BhXL/c3W65
IXkbTMs5bD9MSJNKO3DLSb3Vj51yHAJ44ffl6aWKpg9yLk871MxW2YaIL/R0xm61
HEAEhvWkXbbhj4H1/nITne70JkIaRMDuf2XMmQ70NmK0xlQ5rAR2R4LJLU0CRzQe
JEEbQL+2AQKgk0SXTef62tgPuI/HxkQ6RBL257Z+dFVz/LKqKQ3+EYbqeUzuzII+
hNOMEd4KaWCE3Vc7Irt3vjgODhOkfc5frxaFLKaRwQKBgQDPKRabpK5jRWlFobGv
Ap9+A9pn1UWi8eMiqQR0Y7RsSGnGeGLhjpz8lGGWKA1QLZSfVwCLxSUbhj79nISI
c6I+FSGNvhUpklIUUiR7uoh4BwVbYNlKuaSCqJ/mpYM5l85hh05s6DVs67SDwOp4
2t2mMoMa3M0nWA+QEwail43hsQKBgQDPBxK0YguofxDwSSk03qtIOFMtS7/kxkut
AT3lHh+VLlJUa+cIJDR9GMLrSXUTmuX2UyBB85wHmpymIktqDqwgN9b2Q83f4fjb
Ng4uW2M51aD6VkrLzsyj4qDcEXv7GKfHZ6E2Lhkxa60iqmA5RIrSP3G4Rnp9DcvN
bt3dHRyMHwKBgFY7ND31fuGzsu5ZMC05WkqKMA+opyP8rB9xW3lXR3MLcXw8AG0D
gDVjTnvCkEgfsQ3imUeU+K1MZEwNKt3hxFczVJQ723NChQgQaT9XlhbgVUqENe70
95Wru2O24bjHiBDw0aRjxFlig/GUDAXilQDpZcl4v6zw6wl94fUsQNMBAoGBAIik
qnvUms1D0PJH16LFtVedlYi4Dpf5KcmuoCOxljbos/50mbCN9Pb8eOrDOTsPaekD
RK9DEyERs4MT76K4vHMnaAJzDldO1uoY65M9TmjFz9JrUkLi477nvjSCdcpto4/B
nm4cTxSHdWcD/S7PRrEunuh53C7eBD47hsSCim0RAoGBAI6vaNbQwMV2um+8euYy
dpzYl5KnRdEKCyhNwZzo376YQZoUbmDtBAtWodkYcbnrIT/4h4Wut4HqS8NoZh6Y
YLQeoTVw9u/Utd061CsjmwVWipiKSo+qjow0Mr0xTl9FOkSdRMAiSln3aof31vZB
OlpnQIaYvKn08om0LYJGfV/c
-----END PRIVATE KEY-----
"""


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


def python_packages():
    if __package__:
        from . import dhi_python_packages
    else:
        import dhi_python_packages
    return dhi_python_packages


def expected_python_manifest(arch, root):
    return python_packages().build_security_manifest(
        arch, root=Path(root) if root is not None else None)


def validate_python_manifest(manifest, arch):
    require(isinstance(manifest, dict) and manifest == expected_python_manifest(arch, None)
            and all(row.get('signature_verified') is True for row in manifest['packages']),
            'Python install manifest differs from the exact signed packages and source records')
    return manifest


def read_python_manifest(path, arch):
    path = Path(path)
    require(not path.is_symlink() and path.is_file(),
            'Python install manifest must be a regular file')
    require(path.stat().st_size <= 128 * 1024, 'Python install manifest is too large')
    body = path.read_bytes()
    require(len(body) <= 128 * 1024, 'Python install manifest is too large')
    return validate_python_manifest(json.loads(body), arch), hashlib.sha256(body).hexdigest()


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

    # CPython decodes OpenSSL 3's 0xMNN00PP0 number using the legacy five
    # fields, so the patch release is the fourth field, not the third.
    require(ssl.OPENSSL_VERSION.startswith('OpenSSL ' + OPENSSL_VERSION + ' ')
            and ssl.OPENSSL_VERSION_INFO == (3, 5, 0, 9, 0),
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


def memory_tls_handshake(client, server, client_in, client_out, server_in, server_out):
    """Complete a normal client/server exchange using only in-memory BIOs."""
    import ssl

    finished = set()
    for _ in range(128):
        for name, connection in (('client', client), ('server', server)):
            if name not in finished:
                try:
                    connection.do_handshake()
                    finished.add(name)
                except ssl.SSLWantReadError:
                    pass
        for outgoing, incoming in ((client_out, server_in), (server_out, client_in)):
            if outgoing.pending:
                incoming.write(outgoing.read())
        if len(finished) == 2:
            break
    require(len(finished) == 2, 'In-memory TLS handshake did not complete')
    client.write(b'keep runtime check')
    server_in.write(client_out.read())
    require(server.read(64) == b'keep runtime check', 'In-memory TLS request failed')
    server.write(b'ready')
    client_in.write(server_out.read())
    require(client.read(64) == b'ready', 'In-memory TLS response failed')


def exercise_python_tls():
    """Check hostname enforcement and a legitimate SNI context switch offline."""
    import ssl

    client_context = ssl.create_default_context(cadata=TLS_CERTIFICATE)
    require(client_context.check_hostname and client_context.verify_mode == ssl.CERT_REQUIRED,
            'Python TLS hostname verification is not enabled')
    for hostname in (None, ''):
        try:
            client_context.wrap_bio(ssl.MemoryBIO(), ssl.MemoryBIO(), server_hostname=hostname)
        except ValueError:
            pass
        else:
            raise ValueError('Hostname-checking wrap_bio accepted an absent server_hostname')

    with tempfile.TemporaryDirectory(prefix='keep-python-tls-') as directory:
        certificate = Path(directory) / 'certificate.pem'
        private_key = Path(directory) / 'key.pem'
        certificate.write_text(TLS_CERTIFICATE)
        private_key.write_text(TLS_PRIVATE_KEY)
        selected_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        selected_context.load_cert_chain(certificate, private_key)
        selected_reference = weakref.ref(selected_context)
        pending_contexts = [selected_context]
        del selected_context
        initial_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        callbacks = []

        def select_context(connection, server_name, original_context):
            require(server_name == 'keep-runtime.invalid' and original_context is initial_context,
                    'Unexpected SNI callback identity')
            callbacks.append(server_name)
            connection.context = pending_contexts.pop()
            gc.collect()
            require(selected_reference() is not None
                    and connection.context is selected_reference(),
                    'SNI-selected context was not retained by the TLS connection')

        initial_context.sni_callback = select_context
        client_in, client_out, server_in, server_out = (ssl.MemoryBIO() for _ in range(4))
        client = client_context.wrap_bio(client_in, client_out,
                                         server_hostname='keep-runtime.invalid')
        server = initial_context.wrap_bio(server_in, server_out, server_side=True)
        memory_tls_handshake(client, server, client_in, client_out, server_in, server_out)
        require(callbacks == ['keep-runtime.invalid'] and not pending_contexts
                and selected_reference() is not None
                and server.context is selected_reference() and bool(client.getpeercert()),
                'SNI context switch or verified peer handshake failed')
    return dict(PYTHON_TLS_PROBES)


def exercise_python():
    require(platform.python_implementation() == 'CPython'
            and sys.version_info[:3] == (3, 14, 8)
            and sys.version_info.releaselevel == 'final' and not sys.abiflags,
            'Unexpected ordinary Python version or ABI')
    return {'version': PYTHON_VERSION, 'tls_probes': exercise_python_tls()}


def verify_python_files(manifest, maps_text, executable=None, process_executable=None):
    """Bind the active interpreter, aliases and imported TLS files to signed bytes."""
    import _ssl

    executable = sys.executable if executable is None else executable
    process_executable = PROC_EXECUTABLE_PATH if process_executable is None else process_executable
    canonical = Path(manifest['executable']['path'])
    require(canonical.resolve(strict=True) == canonical,
            'Python executable is not at its canonical path')
    binary, _ = file_identity(canonical)
    require(binary['sha256'] == manifest['executable']['sha256'],
            'Python executable does not match the signed package')
    for active in (Path(executable), Path(process_executable)):
        require(active.resolve(strict=True) == canonical,
                'Active Python interpreter does not resolve to the signed executable')
        identity, _ = file_identity(active)
        require(all(identity[key] == binary[key] for key in ('sha256', 'device', 'inode')),
                'Active Python executable bytes or inode differ from the signed package')
    for name, target in manifest['aliases'].items():
        alias = Path(name)
        require(alias.is_symlink() and str(alias.readlink()) == target
                and alias.resolve(strict=True) == canonical,
                'Python executable alias differs from the signed package')
    abi_path = Path(manifest['abi_library']['path'])
    require(abi_path.resolve(strict=True) == abi_path, 'Python ABI library is not canonical')
    abi, _ = file_identity(abi_path)
    require(abi['sha256'] == manifest['abi_library']['sha256'],
            'Python ABI library does not match the signed package')
    library = Path(manifest['library']['path'])
    allowed = {library, abi_path}
    for mapped in library_mappings(maps_text, 'libpython3'):
        require(Path(mapped['path']).resolve(strict=True) in allowed,
                'Ordinary import mapped an unreviewed Python library')
        if Path(mapped['path']).resolve(strict=True) == abi_path:
            verify_loaded_library(abi_path, 'libpython3.so', maps_text, abi['sha256'])
    python = verify_loaded_library(library, 'libpython3.14.so', maps_text,
                                   manifest['library']['sha256'])
    extension = Path(manifest['ssl_extension']['path'])
    require(isinstance(getattr(_ssl, '__file__', None), str)
            and Path(_ssl.__file__).resolve(strict=True) == extension,
            'Ordinary ssl import selected an unreviewed Python extension')
    python_ssl = verify_loaded_library(extension, '_ssl', maps_text,
                                       manifest['ssl_extension']['sha256'])
    return {'files': {'executable': binary, 'abi_library': abi},
            'libraries': {'python': python, 'python_ssl': python_ssl},
            'aliases': dict(manifest['aliases'])}


def check_python(arch, manifest_path=PYTHON_MANIFEST_PATH, maps_path=MAPS_PATH):
    import ssl  # Normal imports must load the reviewed extension before reading maps.

    manifest, install_hash = read_python_manifest(manifest_path, arch)
    python_packages().verify_installed(python_packages().reviewed_spec(), arch, manifest)
    binding = verify_python_files(manifest, Path(maps_path).read_text())
    result = exercise_python()
    return {**binding, **result, 'source_manifest_sha256': manifest['source_manifest_sha256'],
            'install_manifest_sha256': install_hash}


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


def qualify_runtime(manifest_path=MANIFEST_PATH, maps_path=MAPS_PATH,
                    python_manifest_path=PYTHON_MANIFEST_PATH):
    report = {'schema': 2, 'arch': None, 'success': False, 'tests': 0, 'failures': 0,
              'errors': [], 'versions': {}, 'loaded_libraries': {},
              'expat_source_manifest_sha256': None, 'expat_install_manifest_sha256': None,
              'python_source_manifest_sha256': None, 'python_install_manifest_sha256': None,
              'python_files': {}, 'python_aliases': {}, 'python_tls_probes': {}}
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
            ('python', lambda: check_python(report['arch'], python_manifest_path, maps_path)),
        ):
            report['tests'] += 1
            try:
                result = check()
                report['versions'][name] = result['version']
                report['loaded_libraries'].update(result['libraries'])
                if name == 'expat':
                    report['expat_source_manifest_sha256'] = result['source_manifest_sha256']
                    report['expat_install_manifest_sha256'] = result['install_manifest_sha256']
                elif name == 'python':
                    report['python_source_manifest_sha256'] = result['source_manifest_sha256']
                    report['python_install_manifest_sha256'] = result['install_manifest_sha256']
                    report['python_files'] = result['files']
                    report['python_aliases'] = result['aliases']
                    report['python_tls_probes'] = result['tls_probes']
            except Exception as error:
                report['errors'].append({'check': name, 'message': str(error)})
    report['failures'] = len(report['errors'])
    report['success'] = report['tests'] == 3 and report['failures'] == 0
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
            'loaded_libraries', 'expat_source_manifest_sha256', 'expat_install_manifest_sha256',
            'python_source_manifest_sha256', 'python_install_manifest_sha256',
            'python_files', 'python_aliases', 'python_tls_probes'}
    require(isinstance(report, dict) and set(report) == keys,
            'Invalid dependency qualification report schema')
    require(type(report['schema']) is int and report['schema'] == 2
            and report['arch'] == arch and report['success'] is True
            and type(report['tests']) is int and report['tests'] == 3
            and type(report['failures']) is int and report['failures'] == 0
            and report['errors'] == [], 'Missing or failed native dependency qualification')
    require(report['versions'] == {'expat': EXPAT_VERSION, 'openssl': OPENSSL_VERSION,
                                   'python': PYTHON_VERSION},
            'Dependency report versions differ from the reviewed runtime')
    expected = validate_expat_manifest(expected_expat_manifest(arch, root), arch)
    expected_install_hash = hashlib.sha256(
        (json.dumps(expected, sort_keys=True, indent=2) + '\n').encode()).hexdigest()
    require(report['expat_source_manifest_sha256'] == expected['source_manifest_sha256']
            and report['expat_install_manifest_sha256'] == expected_install_hash,
            'Dependency report source or install manifest differs from the reviewed packages')
    python = validate_python_manifest(expected_python_manifest(arch, root), arch)
    python_install_hash = hashlib.sha256(
        (json.dumps(python, sort_keys=True, indent=2) + '\n').encode()).hexdigest()
    require(report['python_source_manifest_sha256'] == python['source_manifest_sha256']
            and report['python_install_manifest_sha256'] == python_install_hash,
            'Dependency report Python source or install manifest differs from the reviewed packages')
    probes = report['python_tls_probes']
    require(isinstance(probes, dict) and set(probes) == set(PYTHON_TLS_PROBES)
            and all(value is True for value in probes.values()),
            'Missing or failed Python TLS qualification probes')
    require(report['python_aliases'] == python['aliases'],
            'Dependency report Python aliases differ from the signed package')
    libraries = report['loaded_libraries']
    require(isinstance(libraries, dict)
            and set(libraries) == {'expat', 'ssl', 'crypto', 'python', 'python_ssl'},
            'Incomplete dependency loaded-library evidence')
    for name, canonical in (('expat', EXPAT_LIBRARY), ('ssl', SSL_LIBRARY),
                            ('crypto', CRYPTO_LIBRARY),
                            ('python', Path(python['library']['path'])),
                            ('python_ssl', Path(python['ssl_extension']['path']))):
        validate_file_identity(libraries[name], canonical)
    require(libraries['expat']['sha256'] == EXPAT_LIBRARY_SHA256[arch],
            'Dependency report Expat hash differs from the signed package')
    for name, record in (('python', python['library']), ('python_ssl', python['ssl_extension'])):
        require(libraries[name]['sha256'] == record['sha256'],
                'Dependency report Python loaded-library hash differs from the signed package')
    files = report['python_files']
    require(isinstance(files, dict) and set(files) == {'executable', 'abi_library'},
            'Incomplete dependency Python file evidence')
    for name in ('executable', 'abi_library'):
        validate_file_identity(files[name], Path(python[name]['path']))
        require(files[name]['sha256'] == python[name]['sha256'],
                'Dependency report Python file hash differs from the signed package')
    return report


def validate_file_identity(identity, canonical):
    require(isinstance(identity, dict)
            and set(identity) == {'path', 'sha256', 'device', 'inode'},
            'Invalid dependency loaded-library identity')
    require(identity['path'] == str(canonical),
            'Dependency report used a noncanonical file: ' + str(canonical))
    require(isinstance(identity['sha256'], str) and SHA256.fullmatch(identity['sha256'])
            and isinstance(identity['device'], str)
            and re.fullmatch(r'[0-9a-f]+:[0-9a-f]+', identity['device'])
            and type(identity['inode']) is int and identity['inode'] > 0,
            'Invalid dependency loaded-library hash, device or inode')


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
