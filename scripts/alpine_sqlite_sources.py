#!/usr/bin/env python3
"""Verify signed Alpine sqlite APKs and retain their exact matching sources.

The packages are bound to Alpine signatures and reviewed bytes, without claiming
a Docker package-build or source-image attestation. Sources are never executed.
"""
import argparse
import hashlib
import io
import zipfile
import tarfile
import stat
import json
from pathlib import Path
import platform
import re

if __package__:
    from .alpine_expat_sources import (
        checked, download, empty_output, gzip_parts, read_member, retain, tar_entries,
        verify_rsa, safe_name,
    )
else:
    from alpine_expat_sources import (
        checked, download, empty_output, gzip_parts, read_member, retain, tar_entries,
        verify_rsa, safe_name,
    )


VERSION = '3.54.1-r0'
UPSTREAM_VERSION = '3.54.1'
UPSTREAM_COMMIT = '57520227c95396ce39ba6ecaac8d475b78dd3964'
AMALGAMATION_SHA256 = '0c657666d819f261cc4007526ad57e1669de9949df7a8ea847aa284a2bf0ee52'
BUILD_COMMIT = 'f8081b25590214e2695a4faa77c7892bd902a4e8'
APORTS_URL = ('https://gitlab.alpinelinux.org/api/v4/projects/alpine%2Faports/'
              f'repository/archive.tar.gz?sha={BUILD_COMMIT}')
APORTS_PREFIX = f'aports-{BUILD_COMMIT}-{BUILD_COMMIT}'
APORTS_SHA256 = '63d1d80979d1f5d427ce463a77c922417fb28c49c4e9cbdd2b8e921e4a9dbc2d'
APKBUILD_URL = ('https://gitlab.alpinelinux.org/api/v4/projects/alpine%2Faports/'
                f'repository/files/main%2Fsqlite%2FAPKBUILD/raw?ref={BUILD_COMMIT}')
APKBUILD_SHA256 = 'de648fc75c4ec249f958c9cf557793ab35a5a9e90b7d8758a3ec654f483117bd'
SOURCE_URL = 'https://www.sqlite.org/2026/sqlite-autoconf-3540100.tar.gz'
SOURCE_SHA256 = '926ef8d3eab93fbf6e06011901273eec076b25594a4e1cdadd50c987f4f6d64e'
SOURCE_SHA512 = '3df4348f54f5cd0554eec6d91e1d08a70535b7b78f497b2c6f24910b5087f6ef70483c9e35fa388bd8f38483cb8d1cb84e98ccdd58b9f525a10e0cf48c8c6742'
PREFERRED_SOURCE_URL = 'https://www.sqlite.org/2026/sqlite-src-3540100.zip'
PREFERRED_SOURCE_SHA256 = '387e7f6cad4797b17848c07d453dc6606917bb356a6cfe5a3abafd38c240c71b'
PREFERRED_SOURCE_SHA512 = '1c728b93da228d2c135096a5896728934d7d3eda4bdaa2dd05bb02812691ed56c8a4a9181b3b00215f5849d5cd8a191a7cbbc132f11b1fa2ebb6f8abaa92c677'
LICENSE_SHA256 = 'ee6af51062b30d532991face5164136ae6f84e265ecf8abe89dc69dac45ca1e7'
ARCHES = {'amd64': 'x86_64', 'arm64': 'aarch64'}
KEYS = {
    'amd64': {'name': 'alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub',
              'sha256': '207e4696d3c05f7cb05966aee557307151f1f00217af4143c1bcaf33b8df733f'},
    'arm64': {'name': 'alpine-devel@lists.alpinelinux.org-616ae350.rsa.pub',
              'sha256': 'd11f6b21c61b4274e182eb888883a8ba8acdbf820dcc7a6d82a7d9fc2fd2836d'},
}
BINARY_SHA256 = {
    'amd64': '5dfd76936e795efd988d6bad4949b8d20c410d6dc9dd256da884111f668f3915',
    'arm64': 'e92861972b07c848fbf7e2e5ed20ca872c00f3a87550d01a5f7820d4d02df526',
}
LIBRARY_SHA256 = {
    'amd64': '2a0a9f55c43f4f1d1f6021a951ca02653690264352e7a0ff4d80fbe85da3ecca',
    'arm64': 'a7229e8dffcdc7a1c3768dec0eb3452376e056dc0ffe6c3cc2d7c491a54ae9cf',
}
PKGINFO_SHA256 = {
    'amd64': 'c1f41c33d7d1e2c1a38da92dc56ac64bbdd3c23cb1e247943a6562fd1ae24c73',
    'arm64': '0786980e2fb06011bf8b8cdcc5e7af46a8c48a5b5a3c2a7ce2fbe4a8c14e9f4a',
}
ROOT = Path(__file__).resolve().parents[1]
LIBRARY_PATH = 'usr/lib/libsqlite3.so.3.54.1'
ALIAS_PATH = 'usr/lib/libsqlite3.so.0'


def reviewed_spec(root=None):
    """Return only the exact source/package identity reviewed for both arches."""
    spec = {
        'origin': 'sqlite', 'version': VERSION, 'source_method': 'alpine-signed-sqlite-v1',
        'recipe': {'path': 'main/sqlite/APKBUILD', 'revision': BUILD_COMMIT,
                   'url': APKBUILD_URL, 'sha256': APKBUILD_SHA256,
                   'archive_url': APORTS_URL, 'archive_sha256': APORTS_SHA256},
        'source': {'url': SOURCE_URL, 'sha256': SOURCE_SHA256, 'sha512': SOURCE_SHA512,
                   'amalgamation_sha256': AMALGAMATION_SHA256},
        'preferred_source': {'url': PREFERRED_SOURCE_URL, 'sha256': PREFERRED_SOURCE_SHA256,
                             'sha512': PREFERRED_SOURCE_SHA512,
                             'license_path': 'sqlite-src-3540100/LICENSE.md',
                             'license_sha256': LICENSE_SHA256},
        'upstream_release': {'commit': UPSTREAM_COMMIT, 'version': UPSTREAM_VERSION},
        'signing_keys': {arch: {**key, 'url': 'https://alpinelinux.org/keys/' + key['name']}
                         for arch, key in KEYS.items()},
        'packages': [{'name': 'sqlite-libs', 'version': VERSION, 'license': 'blessing',
                      'build_commit': BUILD_COMMIT,
                      'binaries': {arch: {
                          'url': f'https://dl-cdn.alpinelinux.org/alpine/edge/main/{native}/sqlite-libs-{VERSION}.apk',
                          'sha256': BINARY_SHA256[arch],
                          'pkginfo_sha256': PKGINFO_SHA256[arch],
                          'library_sha256': LIBRARY_SHA256[arch]}
                          for arch, native in ARCHES.items()}}],
    }
    if root is not None:
        lock = json.loads((Path(root) / 'docs/os-package-sources.json').read_text())
        rows = [row for row in lock['origins'] if row.get('origin') == 'sqlite']
        if rows != [spec]:
            raise ValueError('sqlite source map differs from the exact reviewed Alpine origin')
        return rows[0]
    return spec


def source_lock_bytes(package_spec):
    if package_spec != reviewed_spec():
        raise ValueError('sqlite source map differs from the exact reviewed Alpine origin')
    return (json.dumps(package_spec, sort_keys=True, indent=2) + '\n').encode()


def package_identity(metadata, architecture, payload_hash):
    if len(metadata) > 65536:
        raise ValueError('sqlite APK metadata exceeds size limit')
    fields = {}
    for line in metadata.decode('utf-8').splitlines():
        if ' = ' in line:
            key, value = line.split(' = ', 1)
            fields.setdefault(key, []).append(value)
    expected = {'pkgname': 'sqlite-libs', 'pkgver': VERSION, 'origin': 'sqlite',
                'arch': ARCHES[architecture], 'commit': BUILD_COMMIT,
                'license': 'blessing', 'url': 'https://www.sqlite.org/', 'datahash': payload_hash}
    if any(fields.get(key) != [value] for key, value in expected.items()):
        raise ValueError('sqlite APK package identity, license or payload hash mismatch')
    for field, values in (
            ('depend', {'so:libc.musl-' + ARCHES[architecture] + '.so.1'}),
            ('provides', {'so:libsqlite3.so.0=3.54.1'})):
        actual = fields.get(field, [])
        if len(actual) != len(values) or set(actual) != values:
            raise ValueError('sqlite APK dependency or SONAME provision mismatch')
    return expected


def verify_apk(body, architecture, key):
    if architecture not in ARCHES:
        raise ValueError('Unsupported sqlite architecture')
    checked(body, 'sha256', BINARY_SHA256[architecture], 'sqlite APK')
    checked(key, 'sha256', KEYS[architecture]['sha256'], 'Alpine signing key')
    parts = gzip_parts(body)
    signs = tar_entries(parts[0][1])
    signature_name = '.SIGN.RSA.' + KEYS[architecture]['name']
    if set(signs) != {signature_name} or signs[signature_name]['body'] is None:
        raise ValueError('sqlite APK signing key name mismatch')
    verify_rsa(signs[signature_name]['body'], parts[1][0], key)
    controls = tar_entries(parts[1][1])
    if set(controls) != {'.PKGINFO'} or controls['.PKGINFO']['body'] is None:
        raise ValueError('sqlite APK requires only regular package metadata')
    metadata = controls['.PKGINFO']['body']
    checked(metadata, 'sha256', PKGINFO_SHA256[architecture], 'sqlite APK metadata')
    identity = package_identity(metadata, architecture, hashlib.sha256(parts[2][0]).hexdigest())
    payload = tar_entries(parts[2][1])
    if set(payload) != {'usr', 'usr/lib', LIBRARY_PATH, ALIAS_PATH}:
        raise ValueError('sqlite APK contains unexpected payload entries')
    if not all(payload[path]['member'].isdir() for path in ('usr', 'usr/lib')):
        raise ValueError('sqlite APK library parents must be directories')
    library, alias = payload[LIBRARY_PATH], payload[ALIAS_PATH]['member']
    if (library['body'] is None or not alias.issym()
            or alias.linkname != 'libsqlite3.so.3.54.1'):
        raise ValueError('sqlite APK canonical library or SONAME alias mismatch')
    checked(library['body'], 'sha256', LIBRARY_SHA256[architecture], 'sqlite runtime library')
    return metadata, {**identity, 'apk_sha256': hashlib.sha256(body).hexdigest(),
                      'pkginfo_sha256': hashlib.sha256(metadata).hexdigest(),
                      'signature_verified': True, 'signing_key_sha256': KEYS[architecture]['sha256'],
                      'library_sha256': LIBRARY_SHA256[architecture]}


def recipe_identity(body):
    text = body.decode('utf-8')
    for key, value in {'pkgname': 'sqlite', 'pkgver': UPSTREAM_VERSION,
                       'pkgrel': '0', 'license': '"blessing"'}.items():
        if re.findall(r'^' + key + r'=([^\n]+)$', text, re.M) != [value]:
            raise ValueError('SQLite APKBUILD identity mismatch')
    declaration = ('source="https://www.sqlite.org/2026/sqlite-autoconf-$_ver.tar.gz\n'
                   '\thttps://www.sqlite.org/2026/sqlite-src-$_ver.zip\n\t"')
    if text.count(declaration) != 1 or len(re.findall(r'^source=', text, re.M)) != 1:
        raise ValueError('SQLite APKBUILD source declaration mismatch')
    sums = SOURCE_SHA512 + '  sqlite-autoconf-3540100.tar.gz\n' + PREFERRED_SOURCE_SHA512 + '  sqlite-src-3540100.zip'
    if re.findall(r'^sha512sums="\n([^"\n]+\n[^"\n]+)\n"$', text, re.M) != [sums]:
        raise ValueError('SQLite APKBUILD source checksum mismatch')


def amalgamation(body):
    with tarfile.open(fileobj=io.BytesIO(body), mode='r:*') as archive:
        matches, total = [], 0
        for count, member in enumerate(archive, 1):
            safe_name(member.name)
            total += member.size
            if count > 250000 or total > 512 * 1024 * 1024:
                raise ValueError('SQLite source archive exceeds inventory limit')
            if member.name == 'sqlite-autoconf-3540100/sqlite3.c':
                if not member.isfile() or not 0 < member.size <= 16 * 1024 * 1024:
                    raise ValueError('SQLite amalgamation must be a bounded regular file')
                matches.append(member)
        if len(matches) != 1:
            raise ValueError('Require one exact SQLite amalgamation')
        return checked(archive.extractfile(matches[0]).read(), 'sha256',
                       AMALGAMATION_SHA256, 'SQLite official amalgamation')


def preferred_license(body):
    with zipfile.ZipFile(io.BytesIO(body)) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)) or len(names) > 20000:
            raise ValueError('Ambiguous SQLite preferred source archive')
        row = archive.getinfo('sqlite-src-3540100/LICENSE.md')
        if (row.is_dir() or stat.S_ISLNK(row.external_attr >> 16)
                or row.flag_bits & 1 or not 0 < row.file_size <= 128 * 1024):
            raise ValueError('Invalid SQLite full notice')
        return checked(archive.read(row), 'sha256', LICENSE_SHA256, 'SQLite full notice')


def security_manifest(package_spec, architecture):
    lock = source_lock_bytes(package_spec)
    if architecture not in ARCHES:
        raise ValueError('Unsupported sqlite architecture')
    return {
        'schema': 'keep-sqlite-package-security-v1', 'architecture': architecture,
        'version': UPSTREAM_VERSION, 'package_version': VERSION,
        'build_commit': BUILD_COMMIT, 'upstream_commit': UPSTREAM_COMMIT,
        'archive_sha256': SOURCE_SHA256,
        'source_manifest_sha256': hashlib.sha256(lock).hexdigest(),
        'library': {'path': '/' + LIBRARY_PATH, 'soname': 'libsqlite3.so.0',
                    'sha256': LIBRARY_SHA256[architecture]},
        'packages': [{'name': 'sqlite-libs', 'version': VERSION,
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
        raise ValueError('Unsupported sqlite architecture')
    retain(root, records, 'source-lock.json', lock, 'reviewed-source-lock:sqlite', 'reviewed-source-lock')
    signing = package_spec['signing_keys'][architecture]
    key = checked(fetch(signing['url']), 'sha256', signing['sha256'], 'Alpine signing key')
    retain(root, records, 'keys/' + signing['name'], key, signing['url'], 'alpine-signing-key')
    binary = package_spec['packages'][0]['binaries'][architecture]
    body = checked(fetch(binary['url']), 'sha256', binary['sha256'], 'sqlite APK')
    metadata, identity = verify_apk(body, architecture, key)
    filename = 'sqlite-libs-' + VERSION + '.apk'
    retain(root, records, filename, body, binary['url'], 'signed-alpine-binary-evidence')
    retain(root, records, filename + '.PKGINFO', metadata, binary['url'], 'package-build-identity')
    installation = security_manifest(package_spec, architecture)
    retain(root, records, 'SQLITE_SECURITY.json',
           (json.dumps(installation, sort_keys=True, indent=2) + '\n').encode(),
           'verified-alpine-packages:sqlite', 'runtime-installation-manifest')
    return installation, [identity]


def prepare_packages(package_spec, architecture, output_root, fetch=download):
    """Prepare exact signed APK/key and manifest for an offline mounted install."""
    return prepare(empty_output(output_root), package_spec, architecture, fetch, [])[0]


def collect_sources(package_spec, architecture, runtime_inventory, output_root, fetch=download):
    source_lock_bytes(package_spec)
    if architecture not in ARCHES:
        raise ValueError('Unsupported sqlite architecture')
    rows = [row for row in runtime_inventory.get('os_packages', []) if row.get('name') == 'sqlite-libs']
    expected = {'version': VERSION, 'origin': 'sqlite', 'license': 'blessing',
                'build_commit': BUILD_COMMIT, 'url': 'https://www.sqlite.org/'}
    if len(rows) != 1 or any(rows[0].get(key) != value for key, value in expected.items()):
        raise ValueError('Actual runtime sqlite package identity mismatch')
    root, records = empty_output(output_root), []
    installation, packages = prepare(root, package_spec, architecture, fetch, records)
    recipes = checked(fetch(APORTS_URL), 'sha256', APORTS_SHA256, 'Complete sqlite aports context')
    prefix = APORTS_PREFIX + '/main/sqlite/'
    recipe = checked(read_member(recipes, prefix + 'APKBUILD'), 'sha256', APKBUILD_SHA256, 'sqlite APKBUILD')
    recipe_identity(recipe)
    retain(root, records, f'aports-{BUILD_COMMIT}.tar.gz', recipes, APORTS_URL, 'complete-alpine-build-recipes')
    retain(root, records, 'context/main/sqlite/APKBUILD', recipe, APKBUILD_URL, 'matching-apk-build-script', prefix + 'APKBUILD')
    source = checked(fetch(SOURCE_URL), 'sha256', SOURCE_SHA256, 'sqlite source')
    checked(source, 'sha512', SOURCE_SHA512, 'sqlite recipe source')
    amalgamation(source)
    retain(root, records, 'sqlite-autoconf-3540100.tar.gz', source, SOURCE_URL, 'upstream-source')
    preferred = checked(fetch(PREFERRED_SOURCE_URL), 'sha256', PREFERRED_SOURCE_SHA256,
                        'SQLite preferred source')
    checked(preferred, 'sha512', PREFERRED_SOURCE_SHA512, 'SQLite recipe preferred source')
    retain(root, records, 'sqlite-src-3540100.zip', preferred, PREFERRED_SOURCE_URL, 'upstream-source')
    retain(root, records, 'SQLite-LICENSE.md', preferred_license(preferred), PREFERRED_SOURCE_URL,
           'upstream-notice', 'sqlite-src-3540100/LICENSE.md')
    retain(root, records, 'runtime-sqlite-identity.json',
           (json.dumps({'os_packages': rows}, indent=2) + '\n').encode(),
           'verified-candidate-runtime:/lib/apk/db/installed', 'runtime-package-build-identity')
    manifest = {
        'schema': 1, 'origin': 'sqlite', 'version': VERSION, 'architecture': architecture,
        'build_commit': BUILD_COMMIT, 'provider_oci_binding': False, 'source_image_digest': None,
        'binding_method': 'signed-alpine-packages', 'package_inputs': packages,
        'source_manifest_sha256': installation['source_manifest_sha256'],
        'installation_manifest_sha256': hashlib.sha256((root / 'SQLITE_SECURITY.json').read_bytes()).hexdigest(),
        'files': records, 'upstream_signature_verified': False,
        'coverage': 'Exact Alpine-signed sqlite APK, RSA verification key, native installed package identity, '
                    'complete pinned aports context, checksum-matching amalgamation and preferred '
                    'sqlite source and full license. The vendor signature does not cover the custom runtime rebuild. No separate upstream OpenPGP verification or Docker '
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
        rows = [row for row in json.loads(Path(args.map).read_text())['origins'] if row.get('origin') == 'sqlite']
        if len(rows) != 1:
            parser.error('Require one exact sqlite origin in the reviewed source map')
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
