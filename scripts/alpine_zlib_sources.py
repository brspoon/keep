#!/usr/bin/env python3
"""Verify signed Alpine zlib APKs and retain their exact matching sources.

The packages are bound to Alpine signatures and reviewed bytes, without claiming
a Docker package-build or source-image attestation. Sources are never executed.
"""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import re

if __package__:
    from .alpine_expat_sources import (
        checked, download, empty_output, gzip_parts, read_member, retain, tar_entries,
        verify_rsa,
    )
else:
    from alpine_expat_sources import (
        checked, download, empty_output, gzip_parts, read_member, retain, tar_entries,
        verify_rsa,
    )


VERSION = '1.3.2-r1'
UPSTREAM_VERSION = '1.3.2'
UPSTREAM_COMMIT = 'df84af25dc1942490e1d1c899a07619152a46148'
BUILD_COMMIT = '0afa2da0e8c8051c6f8f64a7a388e5a259904245'
APORTS_URL = f'https://github.com/alpinelinux/aports/archive/{BUILD_COMMIT}.tar.gz'
APORTS_SHA256 = 'd64797bed37c573333fdda5061a4636c2c8106a2d01dd0cfb327a6a135cf46d3'
APKBUILD_URL = f'https://raw.githubusercontent.com/alpinelinux/aports/{BUILD_COMMIT}/main/zlib/APKBUILD'
APKBUILD_SHA256 = 'c9348892bf3857602fe74fcc1d411e263b408b7d70344170396f5993a62bbe26'
PATCH_URL = f'https://raw.githubusercontent.com/alpinelinux/aports/{BUILD_COMMIT}/main/zlib/CVE-2026-85091.patch'
PATCH_SHA256 = '110ff14375733173d8aa54574473424fbd7dfe4b81f1ca34a759c6fe14b15b14'
PATCH_SHA512 = ('878888308a51296470f05eca59a79212314d4c9a26c19bbf70c1cb1b8d25eb42e'
                '0cce5a001acbe287268aa215c854cb5a9990ff62b7aefa9de221803d172957e')
SOURCE_URL = 'https://zlib.net/fossils/zlib-1.3.2.tar.gz'
SOURCE_SHA256 = 'bb329a0a2cd0274d05519d61c667c062e06990d72e125ee2dfa8de64f0119d16'
SOURCE_SHA512 = ('70963771ea5d763614278a69b474f09b7d237ef8f53b675a10fe31d9923aeef601'
                 '504b35d7ebd1b1e7f347e9ebb048e6b3b47fffdf137e7bdc7e8d5eb4ec4692')
LICENSE_SHA256 = 'e32ff4e00d9d94930537635291da39e7e612703334bf6fde8c7f1686fe8a45a2'
ARCHES = {'amd64': 'x86_64', 'arm64': 'aarch64'}
KEYS = {
    'amd64': {'name': 'alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub',
              'sha256': '207e4696d3c05f7cb05966aee557307151f1f00217af4143c1bcaf33b8df733f'},
    'arm64': {'name': 'alpine-devel@lists.alpinelinux.org-616ae350.rsa.pub',
              'sha256': 'd11f6b21c61b4274e182eb888883a8ba8acdbf820dcc7a6d82a7d9fc2fd2836d'},
}
BINARY_SHA256 = {
    'amd64': '63aeea03c15a2f9018f81805cfc8aa926bdf5cd68921f22149c2fbb5d0ee9f47',
    'arm64': '1f77a542ac6634761b9fe38d8bdca19b154071dcfa25432e73f2bc8a0740a33f',
}
LIBRARY_SHA256 = {
    'amd64': 'ecc8b9dfc45eb7fa29b410ffaca6257873890de53b80fe91735737b49067c5f2',
    'arm64': 'afe41fdd58868461eae3b04068f334bfad2d4ecd0e11c7e30f9afafe06f28528',
}
PKGINFO_SHA256 = {
    'amd64': '395e0ee97996853c6cf03f17dfe25b57d109b0432c6faabb585d78e6ac6f534a',
    'arm64': 'a05759ee7a44bc55b4e9455d12f5220293724e7f743fdae265863c00e02c521b',
}
ROOT = Path(__file__).resolve().parents[1]
LIBRARY_PATH = 'usr/lib/libz.so.1.3.2'
ALIAS_PATH = 'usr/lib/libz.so.1'


def reviewed_spec(root=None):
    """Return only the exact source/package identity reviewed for both arches."""
    spec = {
        'origin': 'zlib', 'version': VERSION, 'source_method': 'alpine-signed-zlib-v1',
        'recipe': {'path': 'main/zlib/APKBUILD', 'revision': BUILD_COMMIT,
                   'url': APKBUILD_URL, 'sha256': APKBUILD_SHA256,
                   'archive_url': APORTS_URL, 'archive_sha256': APORTS_SHA256},
        'source': {'url': SOURCE_URL, 'sha256': SOURCE_SHA256, 'sha512': SOURCE_SHA512,
                   'license_path': 'zlib-1.3.2/LICENSE', 'license_sha256': LICENSE_SHA256},
        'patch': {'path': 'main/zlib/CVE-2026-85091.patch', 'url': PATCH_URL,
                  'sha256': PATCH_SHA256, 'sha512': PATCH_SHA512,
                  'upstream_commit': UPSTREAM_COMMIT},
        'signing_keys': {arch: {**key, 'url': 'https://alpinelinux.org/keys/' + key['name']}
                         for arch, key in KEYS.items()},
        'packages': [{'name': 'zlib', 'version': VERSION, 'license': 'Zlib',
                      'build_commit': BUILD_COMMIT,
                      'binaries': {arch: {
                          'url': f'https://dl-cdn.alpinelinux.org/alpine/v3.24/main/{native}/zlib-{VERSION}.apk',
                          'sha256': BINARY_SHA256[arch],
                          'pkginfo_sha256': PKGINFO_SHA256[arch],
                          'library_sha256': LIBRARY_SHA256[arch]}
                          for arch, native in ARCHES.items()}}],
    }
    if root is not None:
        lock = json.loads((Path(root) / 'docs/os-package-sources.json').read_text())
        rows = [row for row in lock['origins'] if row.get('origin') == 'zlib']
        if rows != [spec]:
            raise ValueError('zlib source map differs from the exact reviewed Alpine origin')
        return rows[0]
    return spec


def source_lock_bytes(package_spec):
    if package_spec != reviewed_spec():
        raise ValueError('zlib source map differs from the exact reviewed Alpine origin')
    return (json.dumps(package_spec, sort_keys=True, indent=2) + '\n').encode()


def package_identity(metadata, architecture, payload_hash):
    if len(metadata) > 65536:
        raise ValueError('zlib APK metadata exceeds size limit')
    fields = {}
    for line in metadata.decode('utf-8').splitlines():
        if ' = ' in line:
            key, value = line.split(' = ', 1)
            fields.setdefault(key, []).append(value)
    expected = {'pkgname': 'zlib', 'pkgver': VERSION, 'origin': 'zlib',
                'arch': ARCHES[architecture], 'commit': BUILD_COMMIT,
                'license': 'Zlib', 'url': 'https://zlib.net/', 'datahash': payload_hash}
    if any(fields.get(key) != [value] for key, value in expected.items()):
        raise ValueError('zlib APK package identity, license or payload hash mismatch')
    for field, values in (
            ('depend', {'so:libc.musl-' + ARCHES[architecture] + '.so.1'}),
            ('provides', {'so:libz.so.1=1.3.2'})):
        actual = fields.get(field, [])
        if len(actual) != len(values) or set(actual) != values:
            raise ValueError('zlib APK dependency or SONAME provision mismatch')
    return expected


def verify_apk(body, architecture, key):
    if architecture not in ARCHES:
        raise ValueError('Unsupported zlib architecture')
    checked(body, 'sha256', BINARY_SHA256[architecture], 'zlib APK')
    checked(key, 'sha256', KEYS[architecture]['sha256'], 'Alpine signing key')
    parts = gzip_parts(body)
    signs = tar_entries(parts[0][1])
    signature_name = '.SIGN.RSA.' + KEYS[architecture]['name']
    if set(signs) != {signature_name} or signs[signature_name]['body'] is None:
        raise ValueError('zlib APK signing key name mismatch')
    verify_rsa(signs[signature_name]['body'], parts[1][0], key)
    controls = tar_entries(parts[1][1])
    if set(controls) != {'.PKGINFO'} or controls['.PKGINFO']['body'] is None:
        raise ValueError('zlib APK requires only regular package metadata')
    metadata = controls['.PKGINFO']['body']
    checked(metadata, 'sha256', PKGINFO_SHA256[architecture], 'zlib APK metadata')
    identity = package_identity(metadata, architecture, hashlib.sha256(parts[2][0]).hexdigest())
    payload = tar_entries(parts[2][1])
    if set(payload) != {'usr', 'usr/lib', LIBRARY_PATH, ALIAS_PATH}:
        raise ValueError('zlib APK contains unexpected payload entries')
    if not all(payload[path]['member'].isdir() for path in ('usr', 'usr/lib')):
        raise ValueError('zlib APK library parents must be directories')
    library, alias = payload[LIBRARY_PATH], payload[ALIAS_PATH]['member']
    if (library['body'] is None or not alias.issym()
            or alias.linkname != 'libz.so.1.3.2'):
        raise ValueError('zlib APK canonical library or SONAME alias mismatch')
    checked(library['body'], 'sha256', LIBRARY_SHA256[architecture], 'zlib runtime library')
    return metadata, {**identity, 'apk_sha256': hashlib.sha256(body).hexdigest(),
                      'pkginfo_sha256': hashlib.sha256(metadata).hexdigest(),
                      'signature_verified': True, 'signing_key_sha256': KEYS[architecture]['sha256'],
                      'library_sha256': LIBRARY_SHA256[architecture]}


def recipe_identity(body):
    text = body.decode('utf-8')
    for key, value in {'pkgname': 'zlib', 'pkgver': UPSTREAM_VERSION,
                       'pkgrel': '1', 'license': '"Zlib"'}.items():
        if re.findall(r'^' + key + r'=([^\n]+)$', text, re.M) != [value]:
            raise ValueError('zlib APKBUILD identity mismatch')
    declaration = 'source="https://zlib.net/fossils/zlib-$pkgver.tar.gz\n\tCVE-2026-85091.patch\n\t"'
    if text.count(declaration) != 1:
        raise ValueError('zlib APKBUILD source declaration mismatch')
    sums = SOURCE_SHA512 + '  zlib-1.3.2.tar.gz\n' + PATCH_SHA512 + '  CVE-2026-85091.patch'
    if re.findall(r'^sha512sums="\n([^"\n]+\n[^"\n]+)\n"$', text, re.M) != [sums]:
        raise ValueError('zlib APKBUILD source or patch checksum mismatch')
    if '#   1.3.2-r1:\n#     - CVE-2026-85091\n' not in text:
        raise ValueError('zlib APKBUILD lacks the reviewed security-fix declaration')


def security_manifest(package_spec, architecture):
    lock = source_lock_bytes(package_spec)
    if architecture not in ARCHES:
        raise ValueError('Unsupported zlib architecture')
    return {
        'schema': 'keep-zlib-security-v1', 'architecture': architecture,
        'version': UPSTREAM_VERSION, 'package_version': VERSION,
        'build_commit': BUILD_COMMIT, 'upstream_commit': UPSTREAM_COMMIT,
        'archive_sha256': SOURCE_SHA256,
        'source_manifest_sha256': hashlib.sha256(lock).hexdigest(),
        'library': {'path': '/' + LIBRARY_PATH, 'soname': 'libz.so.1',
                    'sha256': LIBRARY_SHA256[architecture]},
        'packages': [{'name': 'zlib', 'version': VERSION,
                      'apk_sha256': BINARY_SHA256[architecture],
                      'pkginfo_sha256': PKGINFO_SHA256[architecture],
                      'signature_verified': True,
                      'signing_key_sha256': KEYS[architecture]['sha256']}],
    }


def build_security_manifest(architecture, root=ROOT):
    """Derive expected installation proof without downloads or runtime access."""
    return security_manifest(reviewed_spec(root), architecture)


def prepare(root, package_spec, architecture, fetch, records):
    lock = source_lock_bytes(package_spec)
    if architecture not in ARCHES:
        raise ValueError('Unsupported zlib architecture')
    retain(root, records, 'source-lock.json', lock, 'reviewed-source-lock:zlib', 'reviewed-source-lock')
    signing = package_spec['signing_keys'][architecture]
    key = checked(fetch(signing['url']), 'sha256', signing['sha256'], 'Alpine signing key')
    retain(root, records, 'keys/' + signing['name'], key, signing['url'], 'alpine-signing-key')
    binary = package_spec['packages'][0]['binaries'][architecture]
    body = checked(fetch(binary['url']), 'sha256', binary['sha256'], 'zlib APK')
    metadata, identity = verify_apk(body, architecture, key)
    filename = 'zlib-' + VERSION + '.apk'
    retain(root, records, filename, body, binary['url'], 'signed-alpine-binary-evidence')
    retain(root, records, filename + '.PKGINFO', metadata, binary['url'], 'package-build-identity')
    installation = security_manifest(package_spec, architecture)
    retain(root, records, 'ZLIB_SECURITY.json',
           (json.dumps(installation, sort_keys=True, indent=2) + '\n').encode(),
           'verified-alpine-packages:zlib', 'runtime-installation-manifest')
    return installation, [identity]


def prepare_packages(package_spec, architecture, output_root, fetch=download):
    """Prepare exact signed APK/key and manifest for an offline mounted install."""
    return prepare(empty_output(output_root), package_spec, architecture, fetch, [])[0]


def collect_sources(package_spec, architecture, runtime_inventory, output_root, fetch=download):
    source_lock_bytes(package_spec)
    if architecture not in ARCHES:
        raise ValueError('Unsupported zlib architecture')
    rows = [row for row in runtime_inventory.get('os_packages', []) if row.get('name') == 'zlib']
    expected = {'version': VERSION, 'origin': 'zlib', 'license': 'Zlib',
                'build_commit': BUILD_COMMIT, 'url': 'https://zlib.net/'}
    if len(rows) != 1 or any(rows[0].get(key) != value for key, value in expected.items()):
        raise ValueError('Actual runtime zlib package identity mismatch')
    root, records = empty_output(output_root), []
    installation, packages = prepare(root, package_spec, architecture, fetch, records)
    recipes = checked(fetch(APORTS_URL), 'sha256', APORTS_SHA256, 'Complete zlib aports context')
    prefix = f'aports-{BUILD_COMMIT}/main/zlib/'
    recipe = checked(read_member(recipes, prefix + 'APKBUILD'), 'sha256', APKBUILD_SHA256, 'zlib APKBUILD')
    recipe_identity(recipe)
    patch = checked(read_member(recipes, prefix + 'CVE-2026-85091.patch'), 'sha256', PATCH_SHA256, 'zlib security patch')
    checked(patch, 'sha512', PATCH_SHA512, 'zlib recipe patch')
    if not patch.startswith(('From ' + UPSTREAM_COMMIT + ' ').encode()):
        raise ValueError('zlib patch has the wrong upstream fix identity')
    retain(root, records, f'aports-{BUILD_COMMIT}.tar.gz', recipes, APORTS_URL, 'complete-alpine-build-recipes')
    retain(root, records, 'context/main/zlib/APKBUILD', recipe, APKBUILD_URL, 'matching-apk-build-script', prefix + 'APKBUILD')
    retain(root, records, 'context/main/zlib/CVE-2026-85091.patch', patch, PATCH_URL, 'matching-apk-build-patch', prefix + 'CVE-2026-85091.patch')
    source = checked(fetch(SOURCE_URL), 'sha256', SOURCE_SHA256, 'zlib source')
    checked(source, 'sha512', SOURCE_SHA512, 'zlib recipe source')
    retain(root, records, 'zlib-1.3.2.tar.gz', source, SOURCE_URL, 'upstream-source')
    license_body = checked(read_member(source, 'zlib-1.3.2/LICENSE'), 'sha256', LICENSE_SHA256, 'zlib full notice')
    retain(root, records, 'zlib-1.3.2-LICENSE', license_body, SOURCE_URL, 'upstream-notice', 'zlib-1.3.2/LICENSE')
    retain(root, records, 'runtime-zlib-identity.json',
           (json.dumps({'os_packages': rows}, indent=2) + '\n').encode(),
           'verified-candidate-runtime:/lib/apk/db/installed', 'runtime-package-build-identity')
    manifest = {
        'schema': 1, 'origin': 'zlib', 'version': VERSION, 'architecture': architecture,
        'build_commit': BUILD_COMMIT, 'provider_oci_binding': False, 'source_image_digest': None,
        'binding_method': 'signed-alpine-packages', 'package_inputs': packages,
        'source_manifest_sha256': installation['source_manifest_sha256'],
        'installation_manifest_sha256': hashlib.sha256((root / 'ZLIB_SECURITY.json').read_bytes()).hexdigest(),
        'files': records, 'upstream_signature_verified': False,
        'coverage': 'Exact Alpine-signed zlib APK, RSA verification key, native installed package identity, '
                    'complete pinned aports context, exact upstream security patch and checksum-matching '
                    'zlib source and full license. No separate upstream OpenPGP verification or Docker '
                    'package-build or source-image attestation is claimed.',
    }
    (root / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--map', help='Reviewed OS source map; optional only for exact package preparation')
    parser.add_argument('--architecture', choices=ARCHES,
                        default={'x86_64': 'amd64', 'aarch64': 'arm64'}.get(platform.machine()))
    parser.add_argument('--prepare-packages', action='store_true')
    parser.add_argument('--runtime-inventory')
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    spec = reviewed_spec()
    if args.map:
        rows = [row for row in json.loads(Path(args.map).read_text())['origins'] if row.get('origin') == 'zlib']
        if len(rows) != 1:
            parser.error('Require one exact zlib origin in the reviewed source map')
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
