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


VERSION = '2.9.0-r0'
BUILD_COMMIT = '46440e4654dc1e4e7d3a69b8a0a9e22fdeda4a88'
APORTS_URL = f'https://github.com/alpinelinux/aports/archive/{BUILD_COMMIT}.tar.gz'
APORTS_SHA256 = '0b1b0728f3251b9e06f96d31117b36f38f9a1da4b62b21cc8df11bba1e90f3bc'
APKBUILD_URL = f'https://raw.githubusercontent.com/alpinelinux/aports/{BUILD_COMMIT}/main/expat/APKBUILD'
APKBUILD_SHA256 = '40c194d5e234244805b965384fa6d47557aceb344e1cd92095695b17acc326f5'
SOURCE_URL = 'https://github.com/libexpat/libexpat/releases/download/R_2_9_0/expat-2.9.0.tar.xz'
SOURCE_SHA256 = '1e6371862cc31999b368c3b89b49994f0677e1bab5f1b2b85ae3741f5d803051'
SOURCE_SHA512 = ('677b5a39ea47aa238813412061eefba0ff2e819597efee69452eab7fd63b138753'
                 '7eda0dfd4e5891b938be202dc87df4b5115bdae75c6b81643ac2363bb99b34')
SIGNATURE_SHA256 = 'd1f5832ac46a9f92492ee15ceb50bc1bb2c8d590e5932ccf931cf7e8de1adf4a'
COPYING_SHA256 = '31b15de82aa19a845156169a17a5488bf597e561b2c318d159ed583139b25e87'
ARCHES = {'amd64': 'x86_64', 'arm64': 'aarch64'}
KEYS = {
    'amd64': {'name': 'alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub',
              'sha256': '207e4696d3c05f7cb05966aee557307151f1f00217af4143c1bcaf33b8df733f'},
    'arm64': {'name': 'alpine-devel@lists.alpinelinux.org-616ae350.rsa.pub',
              'sha256': 'd11f6b21c61b4274e182eb888883a8ba8acdbf820dcc7a6d82a7d9fc2fd2836d'},
}
BINARY_SHA256 = {
    'amd64': {'expat': 'bc0f3cd4b150b40fdd6556204a310b22b81a73d0e75f90009256cde14b43de94',
              'libexpat': 'fd4bd715c769df8ffaa55819f765adec28bd9aa35638876285d6c3d0ff7adea3'},
    'arm64': {'expat': '814367b2eb920b9ad1ac32a74cec81bcb0a25aa320c112d09098f5a3ef38a5b0',
              'libexpat': 'bab7910aaf12e590bea815290e6c33f2e4fd40f7450285b21a1e8ee06333d6cc'},
}
LIBRARY_SHA256 = {
    'amd64': '0aa9093ce225c2f5d38a9083a4c203a6133ed9c592366f58e51a6a987f461f44',
    'arm64': '33828821b1a9f49dd434c7b7342a730b1f8b85b6d0b3f0a0558710faeb19988e',
}
PKGINFO_SHA256 = {
    'amd64': {'expat': 'c19334fd2ac53edd1160b4b6cdff019d7d850b01d486ad4f4abbcb419ba725e5',
              'libexpat': '87ca0b34e8442340c765e90d9295728debc48b4ef44c4ae97bdceab5380945fa'},
    'arm64': {'expat': '4644f1f730eb9a9593f1f1896cbdd73eaa69f714e6eabae268e333795a0a6def',
              'libexpat': '7f784564d63fcb8464006ff3af34ca714252faf4af404a0682fafa19272944ab'},
}
ROOT = Path(__file__).resolve().parents[1]
LIBRARY_PATH = 'usr/lib/libexpat.so.1.13.0'
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
                   'archive_url': APORTS_URL, 'archive_sha256': APORTS_SHA256},
        'source': {'url': SOURCE_URL, 'sha256': SOURCE_SHA256, 'sha512': SOURCE_SHA512,
                   'signature_url': SOURCE_URL + '.asc', 'signature_sha256': SIGNATURE_SHA256,
                   'license_path': 'expat-2.9.0/COPYING', 'license_sha256': COPYING_SHA256},
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
    provides = {'so:libexpat.so.1=1.13.0'}
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
        if library.get('body') is None or alias is None or not alias.issym() or alias.linkname != 'libexpat.so.1.13.0':
            raise ValueError('Expat APK canonical library or SONAME alias mismatch')
        checked(library['body'], 'sha256', LIBRARY_SHA256[architecture], 'Expat runtime library')
    return metadata, {**identity, 'apk_sha256': hashlib.sha256(body).hexdigest(),
                      'pkginfo_sha256': hashlib.sha256(metadata).hexdigest(),
                      'signature_verified': True, 'signing_key_sha256': KEYS[architecture]['sha256']}


def recipe_identity(body):
    text = body.decode('utf-8')
    for key, value in {'pkgname': 'expat', 'pkgver': '2.9.0', 'pkgrel': '0', 'license': '"MIT"'}.items():
        if re.findall(r'^' + key + r'=([^\n]+)$', text, re.M) != [value]:
            raise ValueError('Expat APKBUILD identity mismatch')
    declaration = 'source="https://github.com/libexpat/libexpat/releases/download/$_tagver/expat-$pkgver.tar.xz"'
    if text.splitlines().count(declaration) != 1:
        raise ValueError('Expat APKBUILD source declaration mismatch')
    blocks = re.findall(r'^sha512sums="\n([^"\n]+)\n"$', text, re.M)
    if blocks != [SOURCE_SHA512 + '  expat-2.9.0.tar.xz']:
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
        'version': '2.9.0', 'package_version': VERSION, 'build_commit': BUILD_COMMIT,
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
    recipe_path = f'aports-{BUILD_COMMIT}/main/expat/APKBUILD'
    recipe = checked(read_member(recipes, recipe_path), 'sha256', APKBUILD_SHA256, 'Expat APKBUILD')
    recipe_identity(recipe)
    retain(root, records, f'aports-{BUILD_COMMIT}.tar.gz', recipes, APORTS_URL, 'complete-alpine-build-recipes')
    retain(root, records, 'context/main/expat/APKBUILD', recipe, APKBUILD_URL, 'matching-apk-build-script', recipe_path)
    source = checked(fetch(SOURCE_URL), 'sha256', SOURCE_SHA256, 'Expat source')
    checked(source, 'sha512', SOURCE_SHA512, 'Expat recipe source')
    retain(root, records, 'expat-2.9.0.tar.xz', source, SOURCE_URL, 'upstream-source')
    signature = checked(fetch(SOURCE_URL + '.asc'), 'sha256', SIGNATURE_SHA256, 'Expat upstream signature')
    retain(root, records, 'expat-2.9.0.tar.xz.asc', signature, SOURCE_URL + '.asc', 'upstream-detached-signature')
    copying = checked(read_member(source, 'expat-2.9.0/COPYING'), 'sha256', COPYING_SHA256, 'Expat full notice')
    retain(root, records, 'expat-2.9.0-COPYING', copying, SOURCE_URL, 'upstream-notice', 'expat-2.9.0/COPYING')
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
