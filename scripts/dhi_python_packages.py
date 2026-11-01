#!/usr/bin/env python3
"""Prepare exact DHI-signed Python APKs; native source provenance remains mandatory.

No package manager, downloaded recipe or source archive is executed here.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import platform
import subprocess
import tarfile
import tempfile
import urllib.request
import zlib

VERSION = '3.14.10-r1'
BUILD_COMMIT = '2057d765a36e9e029e58a57fe2e2ad70c69994e7'
RECIPE_REVISION = 'e74ceb30fa1b1f5ae262f97fbc9b7154b9b68305'
RECIPE_SHA256 = '6c2e5f57588f6f73ba7b1224582682c6d6d76647d3f29a12ef535a35b0ac517d'
ARCHES = {'amd64': 'x86_64', 'arm64': 'aarch64'}
PACKAGES = ('pyc-3.14', 'python-3.14', 'python-3.14-pyc', 'python-3.14-pycache-pyc0')
KEY_NAME = 'dhi-apk@docker-0F81AD7700D99184.rsa.pub'
KEY_SHA256 = '0003d0ae2bf20db9669f784d6ccd5d52265cb1b73fdb14f5186b348b3308f0cd'
ROOT = Path(__file__).resolve().parents[1]
LIMIT = 64 * 1024 * 1024
BINARY_SHA256 = {'amd64': {'pyc-3.14': '32af44001d15520d2af972ea7649648e3331d0d8944b1741028c45722c1a523e',
           'python-3.14': 'b6cafd2183d664a9789cd98624d67642599756c296997718556baa3c083de086',
           'python-3.14-pyc': '4517f5d126e44adc55ac3a837d9d8c0139d7a35ac0af68718673b0a24c3f3817',
           'python-3.14-pycache-pyc0': '54d713e15e1fa923804393dbb21458eadfd94d1e918d97342e67dbef085faa2f'},
 'arm64': {'pyc-3.14': '32af44001d15520d2af972ea7649648e3331d0d8944b1741028c45722c1a523e',
           'python-3.14': 'f9fc352af6ee077f52bedd53f18585f0f3a72dcd28ef406f8626251923a1d8ad',
           'python-3.14-pyc': '4517f5d126e44adc55ac3a837d9d8c0139d7a35ac0af68718673b0a24c3f3817',
           'python-3.14-pycache-pyc0': '4a437079fbbfe51b905be567a5a86ab2f9d66416594a229a2f88ddad8d61341b'}}
PKGINFO_SHA256 = {'amd64': {'pyc-3.14': 'e508bd0ed055755fe7321da156d885a1f88bd3fdf174c96e23dfdf46b3de9c13',
           'python-3.14': '36cbd935b41f3a9eeaa800805cdf6d18d9f730f1f7574c75e521887915d17eb3',
           'python-3.14-pyc': 'dd091d0638620b1b7e01d973bafb81cfa7a0dbadf30d118312e09423271e6903',
           'python-3.14-pycache-pyc0': '4fc29dfc0a0e314399c87b20b6a570b24506539f549b690a3bec9683454fa6e8'},
 'arm64': {'pyc-3.14': 'e508bd0ed055755fe7321da156d885a1f88bd3fdf174c96e23dfdf46b3de9c13',
           'python-3.14': '834cfcc0d24c01a9adf331674ee4ad78e61de2d696db0a620af8c37b8e08801c',
           'python-3.14-pyc': 'dd091d0638620b1b7e01d973bafb81cfa7a0dbadf30d118312e09423271e6903',
           'python-3.14-pycache-pyc0': '97cc9ca76ee5dd567b9e8a35d7beb6302afd1e1298ba9755c833498690737dcb'}}
PKGINFO_FIELDS = {'pyc-3.14': {'provides': ['pyc=3.14.10-r1']},
 'python-3.14': {'depend': ['python3~3.14',
                            'so:libbz2.so.1',
                            'so:libc.musl-x86_64.so.1',
                            'so:libcrypto.so.3',
                            'so:libexpat.so.1',
                            'so:libffi.so.8',
                            'so:libgdbm_compat.so.4',
                            'so:liblzma.so.5',
                            'so:libmpdec.so.4',
                            'so:libncursesw.so.6',
                            'so:libpanelw.so.6',
                            'so:libreadline.so.8',
                            'so:libsqlite3.so.0',
                            'so:libssl.so.3',
                            'so:libuuid.so.1',
                            'so:libz.so.1'],
                 'provides': ['python3=3.14.10-r1',
                              'cmd:idle3.14=3.14.10-r1',
                              'cmd:idle3=3.14.10-r1',
                              'cmd:idle=3.14.10-r1',
                              'cmd:pydoc3.14=3.14.10-r1',
                              'cmd:pydoc3=3.14.10-r1',
                              'cmd:pydoc=3.14.10-r1',
                              'cmd:python3.14=3.14.10-r1',
                              'cmd:python3=3.14.10-r1',
                              'cmd:python=3.14.10-r1',
                              'so:libpython3.14.so.1.0=1.0',
                              'so:libpython3.so=0']},
 'python-3.14-pyc': {'depend': ['python-3.14-pycache-pyc0=3.14.10-r1', 'pyc-3.14'],
                     'provides': ['python3-pyc=3.14.10-r1'],
                     'install_if': ['python-3.14=3.14.10-r1']},
 'python-3.14-pycache-pyc0': {'provides': ['python3-pycache-pyc0=3.14.10-r1']}}
RUNTIME_FILES = {'amd64': {'executable': {'path': '/usr/bin/python3.14',
                          'sha256': '40a479011281ea749aff463b96105c1e55b8e91eb94652a097fb64ea3e7c5c10'},
           'library': {'path': '/usr/lib/libpython3.14.so.1.0',
                       'soname': 'libpython3.14.so.1.0',
                       'sha256': 'da668f94c32f5f8f085cb0cf86a705c7e214b8ad398340cfc97ee6289aa9e44a'},
           'abi_library': {'path': '/usr/lib/libpython3.so',
                           'sha256': 'b176cf514525d9406fd90259b3c10a1fed308c668df7a11fda8bca2b143a1e0d'},
           'ssl_extension': {'path': '/usr/lib/python3.14/lib-dynload/_ssl.cpython-314-x86_64-linux-musl.so',
                             'sha256': 'fb3c55514bb59ad8c8ed0499f66c3e7eef81b8a0d21dbf3f8c12ce84f0d00bab'}},
 'arm64': {'executable': {'path': '/usr/bin/python3.14',
                          'sha256': 'a6779dd68626ee4d1741609b59b45c40433fd9afd0f8a4183a544359ad47e629'},
           'library': {'path': '/usr/lib/libpython3.14.so.1.0',
                       'soname': 'libpython3.14.so.1.0',
                       'sha256': 'ead775886e9b8497ab9a09257475e123df1386fd52c1d00db44adf471a593866'},
           'abi_library': {'path': '/usr/lib/libpython3.so',
                           'sha256': '2f3ffcd3570a1e39b52c0fee4b6083143a5acd0b262de1147078b0bbde8d9d7f'},
           'ssl_extension': {'path': '/usr/lib/python3.14/lib-dynload/_ssl.cpython-314-aarch64-linux-musl.so',
                             'sha256': '38603ae8d849c474935e0fe12e74f2463c12a954c84ecd7adde6f150439a0cfd'}}}
ALIASES = {'/usr/bin/python': 'python3', '/usr/bin/python3': 'python3.14'}


def checked(body, expected, label):
    if hashlib.sha256(body).hexdigest() != expected:
        raise ValueError(label + ' checksum mismatch')
    return body


def download(url):
    with urllib.request.urlopen(url, timeout=60) as response:
        body = response.read(LIMIT + 1)
    if len(body) > LIMIT:
        raise ValueError('Python APK download exceeds size limit')
    return body


def reviewed_spec(root=None):
    recipe_path = 'package/apk/main/python/alpine-3.24/3.14.yaml'
    spec = {
        'origin': 'python-3.14', 'version': VERSION, 'image': 'dhi.io/pkg-python',
        'tag': VERSION + '-apk-alpine3.24',
        'reference': 'dhi.io/pkg-python:' + VERSION + '-apk-alpine3.24',
        'predicate_image_name': 'dhi/pkg-python',
        'recipe': {'path': recipe_path, 'revision': RECIPE_REVISION,
                   'sha256': RECIPE_SHA256,
                   'url': 'https://raw.githubusercontent.com/docker-hardened-images/catalog/'
                          + RECIPE_REVISION + '/' + recipe_path,
                   'upstream_commit': None},
        'declared_tags': ['3.14.10-apk-alpine3.24', VERSION + '-apk-alpine3.24'],
        'mutable_tag_reused_across_upstream_versions': False,
        'signing_keys': {arch: {'name': KEY_NAME,
                               'url': 'https://dhi.io/keyring/' + KEY_NAME,
                               'sha256': KEY_SHA256} for arch in ARCHES},
        'packages': [
            {'name': name, 'version': VERSION, 'license': 'PSF-2.0',
             'build_commit': BUILD_COMMIT,
             'binaries': {arch: {
                 'url': f'https://dhi.io/apk/alpine/v3.24/main/{native}/{name}-{VERSION}.apk',
                 'sha256': BINARY_SHA256[arch][name]} for arch, native in ARCHES.items()}}
            for name in PACKAGES],
    }
    if root is not None:
        lock = json.loads((Path(root) / 'docs/os-package-sources.json').read_text())
        rows = [row for row in lock['origins'] if row.get('origin') == 'python-3.14']
        if (rows != [spec] or json.dumps(rows, sort_keys=True)
                != json.dumps([spec], sort_keys=True)):
            raise ValueError('Python source map differs from the exact reviewed DHI origin')
        return rows[0]
    return spec


def source_lock_bytes(spec):
    lock = (json.dumps(spec, sort_keys=True, indent=2) + '\n').encode()
    expected = (json.dumps(reviewed_spec(), sort_keys=True, indent=2) + '\n').encode()
    if lock != expected:
        raise ValueError('Python source map differs from the exact reviewed DHI origin')
    return lock


def gzip_parts(body):
    parts = []
    while body:
        decoder = zlib.decompressobj(31)
        decoded = decoder.decompress(body, LIMIT + 1)
        if len(decoded) > LIMIT or not decoder.eof:
            raise ValueError('Invalid or oversized Python APK gzip member')
        used = len(body) - len(decoder.unused_data)
        parts.append((body[:used], decoded))
        if len(parts) > 3:
            raise ValueError('Unexpected Python APK gzip members')
        body = decoder.unused_data
    if len(parts) != 3:
        raise ValueError('Require signature, control and data Python APK gzip members')
    return parts


def tar_entries(body):
    entries, total = {}, 0
    with tarfile.open(fileobj=io.BytesIO(body), mode='r:', ignore_zeros=True) as archive:
        for count, member in enumerate(archive, 1):
            name = member.name
            path = PurePosixPath(name)
            if (not name or path.is_absolute() or '..' in path.parts or '\\' in name
                    or '\x00' in name or path.as_posix() != name):
                raise ValueError('Unsafe Python APK archive path')
            total += member.size
            if count > 10000 or total > LIMIT or name in entries:
                raise ValueError('Ambiguous or oversized Python APK archive')
            if not (member.isfile() or member.isdir() or member.issym()):
                raise ValueError('Unsupported Python APK member type')
            entry = archive.extractfile(member).read() if member.isfile() else None
            if entry is not None and len(entry) != member.size:
                raise ValueError('Truncated Python APK entry')
            entries[name] = {'member': member, 'body': entry}
    return entries


def verify_rsa(signature, control, key):
    # APK v2 signs the original compressed control member using RSA/SHA-1.
    # Its datahash binds the compressed payload; reviewed SHA256 pins apply too.
    with tempfile.TemporaryDirectory(prefix='keep-python-signature-') as directory:
        root = Path(directory)
        for name, body in (('signature', signature), ('control', control), ('key.pem', key)):
            (root / name).write_bytes(body)
        try:
            subprocess.run(['openssl', 'dgst', '-sha1', '-verify', str(root / 'key.pem'),
                            '-signature', str(root / 'signature'), str(root / 'control')],
                           check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
        except (OSError, subprocess.SubprocessError) as error:
            raise ValueError('Python APK RSA signature verification failed') from error


def metadata_fields(metadata):
    if len(metadata) > 65536:
        raise ValueError('Python APK metadata exceeds size limit')
    fields = {}
    for line in metadata.decode('utf-8').splitlines():
        if ' = ' in line:
            key, value = line.split(' = ', 1)
            fields.setdefault(key, []).append(value)
    return fields


def expected_fields(name, architecture):
    fields = {key: list(values) for key, values in PKGINFO_FIELDS[name].items()}
    for key, values in fields.items():
        fields[key] = [value.replace('musl-x86_64', 'musl-' + ARCHES[architecture])
                       for value in values]
    return fields


def package_identity(metadata, name, architecture, payload_hash):
    fields = metadata_fields(metadata)
    native = 'noarch' if name in ('pyc-3.14', 'python-3.14-pyc') else ARCHES[architecture]
    expected = {'pkgname': name, 'pkgver': VERSION, 'origin': 'python-3.14',
                'arch': native, 'commit': BUILD_COMMIT, 'license': 'PSF-2.0',
                'url': 'https://www.python.org/', 'datahash': payload_hash}
    if any(fields.get(key) != [value] for key, value in expected.items()):
        raise ValueError('Python APK package identity, license or payload hash mismatch')
    exact = expected_fields(name, architecture)
    for field in ('depend', 'provides', 'install_if'):
        actual, values = fields.get(field, []), exact.get(field, [])
        if len(actual) != len(values) or set(actual) != set(values):
            raise ValueError('Python APK dependency or provision mismatch')
    return expected


def verify_apk(body, name, architecture, key):
    if architecture not in ARCHES or name not in PACKAGES:
        raise ValueError('Unsupported Python package or architecture')
    checked(body, BINARY_SHA256[architecture][name], name + ' APK')
    checked(key, KEY_SHA256, 'DHI signing key')
    parts = gzip_parts(body)
    signs = tar_entries(parts[0][1])
    signature_name = '.SIGN.RSA.' + KEY_NAME
    if set(signs) != {signature_name} or signs[signature_name]['body'] is None:
        raise ValueError('Python APK signing key name mismatch')
    verify_rsa(signs[signature_name]['body'], parts[1][0], key)
    controls = tar_entries(parts[1][1])
    if '.PKGINFO' not in controls or controls['.PKGINFO']['body'] is None:
        raise ValueError('Python APK lacks regular package metadata')
    metadata = controls['.PKGINFO']['body']
    checked(metadata, PKGINFO_SHA256[architecture][name], 'Python APK metadata')
    identity = package_identity(metadata, name, architecture, hashlib.sha256(parts[2][0]).hexdigest())
    payload = tar_entries(parts[2][1])
    if name == 'python-3.14':
        for record in RUNTIME_FILES[architecture].values():
            entry = payload.get(record['path'].lstrip('/'), {})
            if entry.get('body') is None:
                raise ValueError('Python APK canonical runtime file is not regular')
            checked(entry['body'], record['sha256'], 'Python canonical runtime file')
        for path, target in ALIASES.items():
            member = payload.get(path.lstrip('/'), {}).get('member')
            if member is None or not member.issym() or member.linkname != target:
                raise ValueError('Python APK executable alias mismatch')
    return metadata, {**identity, 'apk_sha256': hashlib.sha256(body).hexdigest(),
                      'pkginfo_sha256': hashlib.sha256(metadata).hexdigest(),
                      'signature_verified': True, 'signing_key_sha256': KEY_SHA256}


def security_manifest(spec, architecture):
    lock = source_lock_bytes(spec)
    if architecture not in ARCHES:
        raise ValueError('Unsupported Python architecture')
    return {'schema': 'keep-python-security-v1', 'architecture': architecture,
            'version': '3.14.10', 'package_version': VERSION, 'build_commit': BUILD_COMMIT,
            'source_manifest_sha256': hashlib.sha256(lock).hexdigest(),
            **{key: dict(value) for key, value in RUNTIME_FILES[architecture].items()},
            'aliases': dict(ALIASES),
            'packages': [{'name': name, 'version': VERSION,
                          'apk_sha256': BINARY_SHA256[architecture][name],
                          'pkginfo_sha256': PKGINFO_SHA256[architecture][name],
                          'signature_verified': True, 'signing_key_sha256': KEY_SHA256}
                         for name in PACKAGES]}


def build_security_manifest(architecture, root=ROOT):
    return security_manifest(reviewed_spec(root), architecture)


def prepare_packages(spec, architecture, output_root, fetch=download):
    manifest = security_manifest(spec, architecture)
    root = Path(output_root)
    if root.is_symlink() or root.exists() and any(root.iterdir()):
        raise ValueError('Python package output must be empty without symlinks')
    root.mkdir(parents=True, exist_ok=True)
    key = checked(fetch('https://dhi.io/keyring/' + KEY_NAME), KEY_SHA256, 'DHI signing key')
    (root / 'keys').mkdir()
    (root / 'keys' / KEY_NAME).write_bytes(key)
    for package in spec['packages']:
        name = package['name']
        body = fetch(package['binaries'][architecture]['url'])
        metadata, _ = verify_apk(body, name, architecture, key)
        filename = name + '-' + VERSION + '.apk'
        (root / filename).write_bytes(body)
        (root / (filename + '.PKGINFO')).write_bytes(metadata)
    (root / 'PYTHON_SECURITY.json').write_text(json.dumps(manifest, sort_keys=True, indent=2) + '\n')
    return manifest


def installed_records(body):
    if len(body) > 8 * 1024 * 1024:
        raise ValueError('Python installed package database exceeds size limit')
    records = []
    for block in body.decode('utf-8').split('\n\n'):
        fields = {}
        for line in block.splitlines():
            if len(line) >= 2 and line[1] == ':' and line[0] in 'PVAcLoUDpi':
                key, value = line[0], line[2:]
                if key in fields:
                    raise ValueError('Duplicate installed Python package field')
                fields[key] = value
        if fields.get('P') in PACKAGES:
            records.append(fields)
    if len(records) != len(PACKAGES) or {row.get('P') for row in records} != set(PACKAGES):
        raise ValueError('Require the complete installed Python package cohort')
    return records


def verify_installed(spec, architecture, manifest, runtime_root='/'):
    expected = security_manifest(spec, architecture)
    if manifest != expected or any(row['signature_verified'] is not True
                                   for row in manifest['packages']):
        raise ValueError('Python installation manifest differs from reviewed packages')
    root = Path(runtime_root).resolve()
    records = installed_records((root / 'lib/apk/db/installed').read_bytes())
    for row in records:
        name = row['P']
        native = 'noarch' if name in ('pyc-3.14', 'python-3.14-pyc') else ARCHES[architecture]
        exact = {'V': VERSION, 'A': native, 'o': 'python-3.14', 'c': BUILD_COMMIT,
                 'L': 'PSF-2.0', 'U': 'https://www.python.org/'}
        if any(row.get(key) != value for key, value in exact.items()):
            raise ValueError('Installed Python package identity mismatch')
        fields = expected_fields(name, architecture)
        for key, field in (('D', 'depend'), ('p', 'provides'), ('i', 'install_if')):
            values = fields.get(field, [])
            actual = row.get(key, '').split()
            if len(actual) != len(values) or set(actual) != set(values):
                raise ValueError('Installed Python dependency or provision mismatch')
    for record in RUNTIME_FILES[architecture].values():
        target = root / record['path'].lstrip('/')
        if target.is_symlink() or not target.is_file() or target.resolve() != target.absolute():
            raise ValueError('Installed Python canonical file path mismatch')
        checked(target.read_bytes(), record['sha256'], 'Installed Python canonical file')
    for path, target in ALIASES.items():
        alias = root / path.lstrip('/')
        if not alias.is_symlink() or alias.readlink().as_posix() != target:
            raise ValueError('Installed Python executable alias mismatch')
        if alias.resolve() != (root / 'usr/bin/python3.14').resolve():
            raise ValueError('Installed Python executable alias resolves elsewhere')
    return expected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--architecture', choices=ARCHES,
                        default={'x86_64': 'amd64', 'aarch64': 'arm64'}.get(platform.machine()))
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--prepare-packages', action='store_true')
    mode.add_argument('--verify-installed', action='store_true')
    parser.add_argument('--output')
    parser.add_argument('--manifest')
    parser.add_argument('--runtime-root', default='/')
    args = parser.parse_args()
    if args.prepare_packages:
        if not args.output:
            parser.error('Package preparation requires --output')
        result = prepare_packages(reviewed_spec(), args.architecture, args.output)
    else:
        if not args.manifest:
            parser.error('Installation verification requires --manifest')
        result = verify_installed(reviewed_spec(), args.architecture,
                                  json.loads(Path(args.manifest).read_text()), args.runtime_root)
    print(json.dumps({'architecture': args.architecture, 'version': VERSION,
                      'source_manifest_sha256': result['source_manifest_sha256']}))


if __name__ == '__main__':
    main()
