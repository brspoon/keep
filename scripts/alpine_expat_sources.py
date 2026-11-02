#!/usr/bin/env python3
"""Verify signed Alpine Expat APKs and retain their exact matching sources.

The reviewed packages come from Alpine, not Docker package attestations.
Downloaded recipes and source archives are inspected as data, never executed.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import platform
import re
import subprocess
import tarfile
import tempfile
import urllib.request
import zlib


VERSION = '2.10.0-r0'
BUILD_COMMIT = 'e18a81f6461517119d85f2650a4f3e5e01861d28'
APORTS_URL = f'https://gitlab.alpinelinux.org/api/v4/projects/alpine%2Faports/repository/archive.tar.gz?sha={BUILD_COMMIT}'
APORTS_PREFIX = f'aports-{BUILD_COMMIT}-{BUILD_COMMIT}'
APORTS_SHA256 = 'bad26ef1fe33691152dbb1c7e1bfbf7155083fc51fcc50faa2f32f5d416636d4'
APKBUILD_URL = f'https://gitlab.alpinelinux.org/api/v4/projects/alpine%2Faports/repository/files/main%2Fexpat%2FAPKBUILD/raw?ref={BUILD_COMMIT}'
APKBUILD_SHA256 = '8f6b72616d400bf56d24b6577a7843901e2a4d4da29339693e19f76e928646ed'
SOURCE_URL = 'https://github.com/libexpat/libexpat/releases/download/R_2_10_0/expat-2.10.0.tar.xz'
SOURCE_SHA256 = 'c624ba2998fc65df1163a49641ff3f9ab73138b11641d92c86bee0fb01b1bc7f'
SOURCE_SHA512 = 'bd61f361d823f67586dad246fa4d4abbe3d22f5a0f9a28401e7a2fc96753d5bae33fbe4068fae72f016998d0da9d8c92edc4abd2fe8a8e4aafc775a8ab547c44'
SIGNATURE_SHA256 = '1944af90d9e7abe645ec7b27847038ca7ddb6b1d2a25ac82c1565d50c2ee08af'
COPYING_SHA256 = '31b15de82aa19a845156169a17a5488bf597e561b2c318d159ed583139b25e87'
ARCHES = {'amd64': 'x86_64', 'arm64': 'aarch64'}
KEYS = {
    'amd64': {'name': 'alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub',
              'sha256': '207e4696d3c05f7cb05966aee557307151f1f00217af4143c1bcaf33b8df733f'},
    'arm64': {'name': 'alpine-devel@lists.alpinelinux.org-616ae350.rsa.pub',
              'sha256': 'd11f6b21c61b4274e182eb888883a8ba8acdbf820dcc7a6d82a7d9fc2fd2836d'},
}
BINARY_SHA256 = {
    'amd64': {'expat': '7a42363e4618ed9440de78df652aca22e9788cbed2e87e1233bb2433f4ad675f',
              'libexpat': 'ad565cb50371c22a746fa6cf9435d814fd6d1439220dc4dc80318088d9ea03db'},
    'arm64': {'expat': '7cdb36ea041ab1a7b218d3ce23b82fb7759cded6a1e0f845a216dfe827fe45f8',
              'libexpat': '2c493582b0a3464f65a47647b5c24c89416d26be8bd82336cb588b88edfb95ce'},
}
LIBRARY_SHA256 = {
    'amd64': '81b28279f2bb5cd61af664e75a18cbf3c016c2643c71691c1485d244bf272222',
    'arm64': 'a001712eb4601c5b40608d84b33ced8cb8cf67da5dc7fd814742b2ba84709add',
}
PKGINFO_SHA256 = {
    'amd64': {'expat': '00af1f0059af004182ead170cd7270d50b496a39faced3597a983de54bdf9ee6',
              'libexpat': '5cc2bc344c47ed99458ca2015ba4b206fce51692670bde9222ae221acac48e49'},
    'arm64': {'expat': 'eb3114810b21edda76d4a2b2b90f32ae3c2e1ee91755d87d4d56d54309fa8cc1',
              'libexpat': '050d06aac05d15a957351aba639b2b10b8a4d6b729a0c21a8a4e2911327cf1a2'},
}
ROOT = Path(__file__).resolve().parents[1]
LIBRARY_PATH = 'usr/lib/libexpat.so.1.13.1'
DOWNLOAD_LIMIT = 128 * 1024 * 1024
APK_DECODE_LIMIT = 16 * 1024 * 1024


def download(url):
    with urllib.request.urlopen(url, timeout=60) as response:
        body = response.read(DOWNLOAD_LIMIT + 1)
    if len(body) > DOWNLOAD_LIMIT:
        raise ValueError('Expat download exceeds size limit')
    return body


def checked(body, algorithm, expected, label):
    if hashlib.new(algorithm, body).hexdigest() != expected:
        raise ValueError(label + ' checksum mismatch')
    return body


def reviewed_spec(root=None):
    """The exact reviewed origin record also binds installation to source delivery."""
    spec = {
        'origin': 'expat', 'version': VERSION, 'source_method': 'alpine-signed-expat-v1',
        'recipe': {'path': 'main/expat/APKBUILD', 'revision': BUILD_COMMIT,
                   'url': APKBUILD_URL, 'sha256': APKBUILD_SHA256,
                   'archive_url': APORTS_URL, 'archive_sha256': APORTS_SHA256,
                   'archive_prefix': APORTS_PREFIX},
        'source': {'url': SOURCE_URL, 'sha256': SOURCE_SHA256, 'sha512': SOURCE_SHA512,
                   'signature_url': SOURCE_URL + '.asc', 'signature_sha256': SIGNATURE_SHA256,
                   'license_path': 'expat-2.10.0/COPYING', 'license_sha256': COPYING_SHA256},
        'signing_keys': {arch: {**key, 'url': 'https://alpinelinux.org/keys/' + key['name']}
                         for arch, key in KEYS.items()},
        'packages': [
            {'name': name, 'version': VERSION, 'license': 'MIT', 'build_commit': BUILD_COMMIT,
             'binaries': {arch: {
                 'url': f'https://dl-cdn.alpinelinux.org/alpine/edge/main/{native}/{name}-{VERSION}.apk',
                 'sha256': BINARY_SHA256[arch][name]}
                 for arch, native in ARCHES.items()}}
            for name in ('expat', 'libexpat')],
    }
    if root is not None:
        lock = json.loads((Path(root) / 'docs/os-package-sources.json').read_text())
        rows = [row for row in lock['origins'] if row.get('origin') == 'expat']
        if rows != [spec]:
            raise ValueError('Expat source map differs from the exact reviewed Alpine origin')
        return rows[0]
    return spec


def source_lock_bytes(package_spec):
    if package_spec != reviewed_spec():
        raise ValueError('Expat source map differs from the exact reviewed Alpine origin')
    return (json.dumps(package_spec, sort_keys=True, indent=2) + '\n').encode()


def safe_name(name):
    path = PurePosixPath(name)
    if not name or path.is_absolute() or '..' in path.parts or '\\' in name or '\x00' in name:
        raise ValueError('Unsafe Expat archive path')
    return path.as_posix()


def read_member(body, name):
    with tarfile.open(fileobj=io.BytesIO(body), mode='r:*') as archive:
        matches, total = [], 0
        for count, member in enumerate(archive, 1):
            safe_name(member.name)
            total += member.size
            if count > 250000 or total > 512 * 1024 * 1024:
                raise ValueError('Expat source archive exceeds inventory limit')
            if member.name == name:
                if not member.isfile() or member.size > 4 * 1024 * 1024:
                    raise ValueError('Expat source entry must be a bounded regular file')
                matches.append(member)
        if len(matches) != 1:
            raise ValueError('Require one exact Expat source entry: ' + name)
        return archive.extractfile(matches[0]).read()


def gzip_parts(body):
    parts = []
    while body:
        decoder = zlib.decompressobj(31)
        decoded = decoder.decompress(body, APK_DECODE_LIMIT + 1)
        if len(decoded) > APK_DECODE_LIMIT or not decoder.eof:
            raise ValueError('Invalid or oversized Expat APK gzip member')
        used = len(body) - len(decoder.unused_data)
        parts.append((body[:used], decoded))
        if len(parts) > 3:
            raise ValueError('Unexpected Expat APK gzip members')
        body = decoder.unused_data
    if len(parts) != 3:
        raise ValueError('Require signature, control and data APK gzip members')
    return parts


def tar_entries(body):
    entries, total = {}, 0
    with tarfile.open(fileobj=io.BytesIO(body), mode='r:', ignore_zeros=True) as archive:
        for count, member in enumerate(archive, 1):
            name = safe_name(member.name)
            total += member.size
            if count > 10000 or total > APK_DECODE_LIMIT or name in entries:
                raise ValueError('Ambiguous or oversized Expat APK archive')
            if not (member.isfile() or member.isdir() or member.issym()):
                raise ValueError('Unsupported Expat APK member type')
            entries[name] = {'member': member,
                             'body': archive.extractfile(member).read() if member.isfile() else None}
    return entries


def verify_rsa(signature, control, key):
    """APK v2 .SIGN.RSA covers the original compressed control member with SHA-1.

    The control's SHA-256 datahash binds the original compressed payload, and the
    reviewed outer APK SHA-256 and key SHA-256 remain mandatory independently.
    """
    with tempfile.TemporaryDirectory(prefix='keep-expat-signature-') as directory:
        root = Path(directory)
        for name, body in (('signature', signature), ('control', control), ('key.pem', key)):
            (root / name).write_bytes(body)
        try:
            subprocess.run(['openssl', 'dgst', '-sha1', '-verify', str(root / 'key.pem'),
                            '-signature', str(root / 'signature'), str(root / 'control')],
                           check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
        except (OSError, subprocess.SubprocessError) as error:
            raise ValueError('Expat APK RSA signature verification failed') from error


def package_identity(metadata, name, architecture, payload_hash):
    if len(metadata) > 65536:
        raise ValueError('Expat APK metadata exceeds size limit')
    fields = {}
    for line in metadata.decode('utf-8').splitlines():
        if ' = ' not in line:
            continue
        key, value = line.split(' = ', 1)
        fields.setdefault(key, []).append(value)
    expected = {'pkgname': name, 'pkgver': VERSION, 'origin': 'expat',
                'arch': ARCHES[architecture], 'commit': BUILD_COMMIT,
                'license': 'MIT', 'url': 'https://libexpat.github.io/', 'datahash': payload_hash}
    if any(fields.get(key) != [value] for key, value in expected.items()):
        raise ValueError('Expat APK package identity, license or payload hash mismatch')
    dependencies = {'so:libc.musl-' + ARCHES[architecture] + '.so.1'}
    provides = {'so:libexpat.so.1=1.13.1'}
    if name == 'expat':
        dependencies.add('so:libexpat.so.1')
        provides = {'cmd:xmlwf=' + VERSION}
    for field, values in (('depend', dependencies), ('provides', provides)):
        actual = fields.get(field, [])
        if len(actual) != len(values) or set(actual) != values:
            raise ValueError('Expat APK dependency or SONAME provision mismatch')
    return expected


def verify_apk(body, name, architecture, key):
    if architecture not in ARCHES or name not in ('expat', 'libexpat'):
        raise ValueError('Unsupported Expat package or architecture')
    checked(body, 'sha256', BINARY_SHA256[architecture][name], name + ' APK')
    checked(key, 'sha256', KEYS[architecture]['sha256'], 'Alpine signing key')
    parts = gzip_parts(body)
    signs = tar_entries(parts[0][1])
    signature_name = '.SIGN.RSA.' + KEYS[architecture]['name']
    if set(signs) != {signature_name} or signs[signature_name]['body'] is None:
        raise ValueError('Expat APK signing key name mismatch')
    verify_rsa(signs[signature_name]['body'], parts[1][0], key)
    controls = tar_entries(parts[1][1])
    if '.PKGINFO' not in controls or controls['.PKGINFO']['body'] is None:
        raise ValueError('Expat APK lacks regular package metadata')
    metadata = controls['.PKGINFO']['body']
    checked(metadata, 'sha256', PKGINFO_SHA256[architecture][name], 'Expat APK metadata')
    identity = package_identity(metadata, name, architecture, hashlib.sha256(parts[2][0]).hexdigest())
    payload = tar_entries(parts[2][1])
    if name == 'libexpat':
        library = payload.get(LIBRARY_PATH, {})
        alias = payload.get('usr/lib/libexpat.so.1', {}).get('member')
        if library.get('body') is None or alias is None or not alias.issym() or alias.linkname != 'libexpat.so.1.13.1':
            raise ValueError('Expat APK canonical library or SONAME alias mismatch')
        checked(library['body'], 'sha256', LIBRARY_SHA256[architecture], 'Expat runtime library')
    return metadata, {**identity, 'apk_sha256': hashlib.sha256(body).hexdigest(),
                      'pkginfo_sha256': hashlib.sha256(metadata).hexdigest(),
                      'signature_verified': True, 'signing_key_sha256': KEYS[architecture]['sha256']}


def recipe_identity(body):
    text = body.decode('utf-8')
    for key, value in {'pkgname': 'expat', 'pkgver': '2.10.0', 'pkgrel': '0', 'license': '"MIT"'}.items():
        if re.findall(r'^' + key + r'=([^\n]+)$', text, re.M) != [value]:
            raise ValueError('Expat APKBUILD identity mismatch')
    declaration = 'source="https://github.com/libexpat/libexpat/releases/download/$_tagver/expat-$pkgver.tar.xz"'
    if text.splitlines().count(declaration) != 1:
        raise ValueError('Expat APKBUILD source declaration mismatch')
    blocks = re.findall(r'^sha512sums="\n([^"\n]+)\n"$', text, re.M)
    if blocks != [SOURCE_SHA512 + '  expat-2.10.0.tar.xz']:
        raise ValueError('Expat APKBUILD source checksum mismatch')


def empty_output(output_root):
    root = Path(output_root)
    if root.is_symlink() or root.exists() and any(root.iterdir()):
        raise ValueError('Expat output must be empty without symlinks')
    root.mkdir(parents=True, exist_ok=True)
    return root


def retain(root, records, name, body, url, role, source_path=None):
    target = root / safe_name(name)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(body)
    records.append({'path': name, 'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest(),
                    'url': url, 'role': role, 'source_path': source_path or name})


def security_manifest(package_spec, architecture):
    lock = source_lock_bytes(package_spec)
    if architecture not in ARCHES:
        raise ValueError('Unsupported Expat architecture')
    return {
        'schema': 'keep-expat-security-v1', 'architecture': architecture,
        'version': '2.10.0', 'package_version': VERSION, 'build_commit': BUILD_COMMIT,
        'source_manifest_sha256': hashlib.sha256(lock).hexdigest(),
        'library': {'path': '/' + LIBRARY_PATH, 'soname': 'libexpat.so.1',
                    'sha256': LIBRARY_SHA256[architecture]},
        'packages': [{'name': name, 'version': VERSION,
                      'apk_sha256': BINARY_SHA256[architecture][name],
                      'pkginfo_sha256': PKGINFO_SHA256[architecture][name],
                      'signature_verified': True,
                      'signing_key_sha256': KEYS[architecture]['sha256']}
                     for name in ('expat', 'libexpat')],
    }


def build_security_manifest(architecture, root=ROOT):
    """Derive expected installation proof without downloads or runtime access."""
    return security_manifest(reviewed_spec(root), architecture)


def prepare(root, package_spec, architecture, fetch, records):
    lock = source_lock_bytes(package_spec)
    if architecture not in ARCHES:
        raise ValueError('Unsupported Expat architecture')
    retain(root, records, 'source-lock.json', lock, 'reviewed-source-lock:expat', 'reviewed-source-lock')
    signing = package_spec['signing_keys'][architecture]
    key = checked(fetch(signing['url']), 'sha256', signing['sha256'], 'Alpine signing key')
    retain(root, records, 'keys/' + signing['name'], key, signing['url'], 'alpine-signing-key')
    packages = []
    for package in package_spec['packages']:
        name = package['name']
        binary = package['binaries'][architecture]
        body = checked(fetch(binary['url']), 'sha256', binary['sha256'], name + ' APK')
        metadata, identity = verify_apk(body, name, architecture, key)
        filename = name + '-' + VERSION + '.apk'
        retain(root, records, filename, body, binary['url'], 'signed-alpine-binary-evidence')
        retain(root, records, filename + '.PKGINFO', metadata, binary['url'], 'package-build-identity')
        packages.append(identity)
    installation = security_manifest(package_spec, architecture)
    retain(root, records, 'EXPAT_SECURITY.json',
           (json.dumps(installation, sort_keys=True, indent=2) + '\n').encode(),
           'verified-alpine-packages:expat', 'runtime-installation-manifest')
    return installation, packages


def prepare_packages(package_spec, architecture, output_root, fetch=download):
    """Prepare only the exact signed APKs/key and manifest for a mounted install."""
    return prepare(empty_output(output_root), package_spec, architecture, fetch, [])[0]


def collect_sources(package_spec, architecture, runtime_inventory, output_root, fetch=download):
    source_lock_bytes(package_spec)
    if architecture not in ARCHES:
        raise ValueError('Unsupported Expat architecture')
    rows = [row for row in runtime_inventory.get('os_packages', []) if row.get('name') in {'expat', 'libexpat'}]
    if len(rows) != 2 or {row['name'] for row in rows} != {'expat', 'libexpat'}:
        raise ValueError('Require both actual runtime Expat packages')
    expected = {'version': VERSION, 'origin': 'expat', 'license': 'MIT',
                'build_commit': BUILD_COMMIT, 'url': 'https://libexpat.github.io/'}
    if any(any(row.get(key) != value for key, value in expected.items()) for row in rows):
        raise ValueError('Actual runtime Expat package identity mismatch')
    root, records = empty_output(output_root), []
    installation, packages = prepare(root, package_spec, architecture, fetch, records)
    recipes = checked(fetch(APORTS_URL), 'sha256', APORTS_SHA256, 'Complete Expat aports context')
    recipe_path = f'{APORTS_PREFIX}/main/expat/APKBUILD'
    recipe = checked(read_member(recipes, recipe_path), 'sha256', APKBUILD_SHA256, 'Expat APKBUILD')
    recipe_identity(recipe)
    retain(root, records, f'aports-{BUILD_COMMIT}.tar.gz', recipes, APORTS_URL, 'complete-alpine-build-recipes')
    retain(root, records, 'context/main/expat/APKBUILD', recipe, APKBUILD_URL, 'matching-apk-build-script', recipe_path)
    source = checked(fetch(SOURCE_URL), 'sha256', SOURCE_SHA256, 'Expat source')
    checked(source, 'sha512', SOURCE_SHA512, 'Expat recipe source')
    retain(root, records, 'expat-2.10.0.tar.xz', source, SOURCE_URL, 'upstream-source')
    signature = checked(fetch(SOURCE_URL + '.asc'), 'sha256', SIGNATURE_SHA256, 'Expat upstream signature')
    retain(root, records, 'expat-2.10.0.tar.xz.asc', signature, SOURCE_URL + '.asc', 'upstream-detached-signature')
    copying = checked(read_member(source, 'expat-2.10.0/COPYING'), 'sha256', COPYING_SHA256, 'Expat full notice')
    retain(root, records, 'expat-2.10.0-COPYING', copying, SOURCE_URL, 'upstream-notice', 'expat-2.10.0/COPYING')
    runtime = {'os_packages': sorted(rows, key=lambda row: row['name'])}
    retain(root, records, 'runtime-expat-identity.json', (json.dumps(runtime, indent=2) + '\n').encode(),
           'verified-candidate-runtime:/lib/apk/db/installed', 'runtime-package-build-identity')
    manifest = {
        'schema': 1, 'origin': 'expat', 'version': VERSION, 'architecture': architecture,
        'build_commit': BUILD_COMMIT, 'provider_oci_binding': False, 'source_image_digest': None,
        'binding_method': 'signed-alpine-packages', 'package_inputs': packages,
        'source_manifest_sha256': installation['source_manifest_sha256'],
        'installation_manifest_sha256': hashlib.sha256((root / 'EXPAT_SECURITY.json').read_bytes()).hexdigest(),
        'files': records, 'upstream_signature_verified': False,
        'coverage': 'Exact Alpine-signed APKs, RSA verification keys, native installed package identities, '
                    'complete pinned aports context and checksum-matching Expat source and MIT notice. '
                    'The upstream detached signature is retained without a separate OpenPGP verification claim; '
                    'no Docker package-build or source-image attestation is claimed.',
    }
    (root / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--map', help='Reviewed OS source map; omitted only for exact package preparation')
    parser.add_argument('--architecture', choices=ARCHES,
                        default={'x86_64': 'amd64', 'aarch64': 'arm64'}.get(platform.machine()))
    parser.add_argument('--prepare-packages', action='store_true')
    parser.add_argument('--runtime-inventory')
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    spec = reviewed_spec()
    if args.map:
        rows = [row for row in json.loads(Path(args.map).read_text())['origins'] if row['origin'] == 'expat']
        if len(rows) != 1:
            parser.error('Require one exact Expat origin in the reviewed source map')
        spec = rows[0]
    if args.prepare_packages:
        result = prepare_packages(spec, args.architecture, args.output)
    else:
        if not args.map or not args.runtime_inventory:
            parser.error('Source collection requires --map and --runtime-inventory')
        result = collect_sources(spec, args.architecture,
                                 json.loads(Path(args.runtime_inventory).read_text()), args.output)
    print(json.dumps({'architecture': args.architecture, 'version': VERSION,
                      'source_manifest_sha256': result['source_manifest_sha256']}))


if __name__ == '__main__':
    main()
