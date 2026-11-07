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


VERSION = '1.4-r0'
UPSTREAM_VERSION = '1.4'
UPSTREAM_COMMIT = 'df84af25dc1942490e1d1c899a07619152a46148'
GZWRITE_SHA256 = 'e57621b7fffbc1909401acad13bef42adb5debee24a4c356a246f6b480e2db02'
BUILD_COMMIT = 'bdf501c870a92a05c097857401f69c48c4810384'
APORTS_URL = ('https://gitlab.alpinelinux.org/api/v4/projects/alpine%2Faports/'
              f'repository/archive.tar.gz?sha={BUILD_COMMIT}')
APORTS_PREFIX = f'aports-{BUILD_COMMIT}-{BUILD_COMMIT}'
APORTS_SHA256 = '3a94eb2eb15859d68261e285e35abd99f481439fe23e6ea9fae25fb1a1871631'
APKBUILD_URL = (f'https://gitlab.alpinelinux.org/alpine/aports/-/raw/{BUILD_COMMIT}'
                '/main/zlib/APKBUILD')
APKBUILD_SHA256 = 'f03e134596ecd53717a25715fd7b7616a0ad42a151246ee9c2a06242370ec51b'
SOURCE_URL = 'https://zlib.net/fossils/zlib-1.4.tar.gz'
SOURCE_SHA256 = '02dd159783677a749c04adbdd02b55b8a2bcc7e054f51b76b549199a916ad584'
SOURCE_SHA512 = ('13f02285da85956ff722d814695b96807aff7a511ebf4b6d98cf708c35392066609'
                 '3cc18b6653cd7992c8e75c103f7b4baf2de3a105c2db9dcd62bab2c940859')
LICENSE_SHA256 = 'e32ff4e00d9d94930537635291da39e7e612703334bf6fde8c7f1686fe8a45a2'
ARCHES = {'amd64': 'x86_64', 'arm64': 'aarch64'}
KEYS = {
    'amd64': {'name': 'alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub',
              'sha256': '207e4696d3c05f7cb05966aee557307151f1f00217af4143c1bcaf33b8df733f'},
    'arm64': {'name': 'alpine-devel@lists.alpinelinux.org-616ae350.rsa.pub',
              'sha256': 'd11f6b21c61b4274e182eb888883a8ba8acdbf820dcc7a6d82a7d9fc2fd2836d'},
}
BINARY_SHA256 = {
    'amd64': '7b05bc778b8b25cd880835b40114182bd4d1581717504d0129c810c0a14291cb',
    'arm64': 'd3e30d012a3445222b0b4a28f1d4d97ce67387f8b48561921111696da174f0de',
}
LIBRARY_SHA256 = {
    'amd64': '9995c2fe07ba436423709dd8ce6a186c2c6b3db7ac7719496a55554c4a95274e',
    'arm64': '0ad1835b2abd14d0297d4ef0694460bc06ed964478a166a698c10608b2b2abbb',
}
PKGINFO_SHA256 = {
    'amd64': '2eb5885520ad91e7ad574c6a77472ba3cd33a145235c2bc17156d8d7c19ba1da',
    'arm64': '2840c2a64f0600e01fd18abdd04f6392bb61ce917f0703e18bc6896ab99692c1',
}
ROOT = Path(__file__).resolve().parents[1]
LIBRARY_PATH = 'usr/lib/libz.so.1.4'
ALIAS_PATH = 'usr/lib/libz.so.1'


def reviewed_spec(root=None):
    """Return only the exact source/package identity reviewed for both arches."""
    spec = {
        'origin': 'zlib', 'version': VERSION, 'source_method': 'alpine-signed-zlib-v1',
        'recipe': {'path': 'main/zlib/APKBUILD', 'revision': BUILD_COMMIT,
                   'url': APKBUILD_URL, 'sha256': APKBUILD_SHA256,
                   'archive_url': APORTS_URL, 'archive_sha256': APORTS_SHA256},
        'source': {'url': SOURCE_URL, 'sha256': SOURCE_SHA256, 'sha512': SOURCE_SHA512,
                   'license_path': 'zlib-1.4/LICENSE', 'license_sha256': LICENSE_SHA256},
        'upstream_fix': {'commit': UPSTREAM_COMMIT, 'path': 'zlib-1.4/gzwrite.c',
                         'sha256': GZWRITE_SHA256},
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
            ('provides', {'so:libz.so.1=1.4'})):
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
            or alias.linkname != 'libz.so.1.4'):
        raise ValueError('zlib APK canonical library or SONAME alias mismatch')
    checked(library['body'], 'sha256', LIBRARY_SHA256[architecture], 'zlib runtime library')
    return metadata, {**identity, 'apk_sha256': hashlib.sha256(body).hexdigest(),
                      'pkginfo_sha256': hashlib.sha256(metadata).hexdigest(),
                      'signature_verified': True, 'signing_key_sha256': KEYS[architecture]['sha256'],
                      'library_sha256': LIBRARY_SHA256[architecture]}


def recipe_identity(body):
    text = body.decode('utf-8')
    for key, value in {'pkgname': 'zlib', 'pkgver': UPSTREAM_VERSION,
                       'pkgrel': '0', 'license': '"Zlib"'}.items():
        if re.findall(r'^' + key + r'=([^\n]+)$', text, re.M) != [value]:
            raise ValueError('zlib APKBUILD identity mismatch')
    if re.findall(r'^source=(.*)$', text, re.M) != ['"https://zlib.net/fossils/zlib-$pkgver.tar.gz"']:
        raise ValueError('zlib APKBUILD source declaration mismatch')
    if re.findall(r'^sha512sums="\n([^"\n]+)\n"$', text, re.M) != [SOURCE_SHA512 + '  zlib-1.4.tar.gz']:
        raise ValueError('zlib APKBUILD source checksum mismatch')
    if '#   1.4-r0:\n#     - CVE-2026-4738\n' not in text:
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
    prefix = APORTS_PREFIX + '/main/zlib/'
    recipe = checked(read_member(recipes, prefix + 'APKBUILD'), 'sha256', APKBUILD_SHA256, 'zlib APKBUILD')
    recipe_identity(recipe)
    retain(root, records, f'aports-{BUILD_COMMIT}.tar.gz', recipes, APORTS_URL, 'complete-alpine-build-recipes')
    retain(root, records, 'context/main/zlib/APKBUILD', recipe, APKBUILD_URL, 'matching-apk-build-script', prefix + 'APKBUILD')
    source = checked(fetch(SOURCE_URL), 'sha256', SOURCE_SHA256, 'zlib source')
    checked(source, 'sha512', SOURCE_SHA512, 'zlib recipe source')
    checked(read_member(source, 'zlib-1.4/gzwrite.c'), 'sha256', GZWRITE_SHA256,
            'zlib integrated gzwrite correction')
    retain(root, records, 'zlib-1.4.tar.gz', source, SOURCE_URL, 'upstream-source')
    license_body = checked(read_member(source, 'zlib-1.4/LICENSE'), 'sha256', LICENSE_SHA256, 'zlib full notice')
    retain(root, records, 'zlib-1.4-LICENSE', license_body, SOURCE_URL, 'upstream-notice', 'zlib-1.4/LICENSE')
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
                    'complete pinned aports context, integrated upstream correction and checksum-matching '
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
