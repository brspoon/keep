#!/usr/bin/env python3
"""Retain checked IANA 2026c data and its complete public build inputs.

Docker's published timezone package-image tag is reused across IANA releases.
This source-only fallback retains the exact 2026c release and pinned recipe
inputs without inventing an unavailable historical provider OCI digest. No
downloaded recipe is executed and no package binary is redistributed here.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import tarfile


RECIPE_REVISION = 'a399ba8b3297ee5f29c05f9a1d2068743eaae797'
RECIPE_PATH = 'package/apk/main/tzdata/alpine-3.24/2025.yaml'
RECIPE_URL = f'https://raw.githubusercontent.com/docker-hardened-images/catalog/{RECIPE_REVISION}/{RECIPE_PATH}'
RECIPE_SHA256 = '89b635b656749b62f535c5e8ce887eec1e31e5558700ad7b3eda72e8fadb42a5'
APORTS_COMMIT = 'abde3c23ae79b9d3b7bf1a089076703ccda73875'
APORTS_URL = f'https://github.com/alpinelinux/aports/archive/{APORTS_COMMIT}.tar.gz'
APORTS_SHA256 = '2608485df3d15023b18c97022f5d3d1a9b8189120e0b8d5567fe8cee1d999b8f'
APKBUILD_SHA256 = 'f5b07ef538adab90964624e7a3df7d0b144ce31b0387f360bb3e6c9b480b33d1'
LGPL_URL = 'https://www.gnu.org/licenses/old-licenses/lgpl-2.0.txt'
LGPL_SHA256 = 'cc535c21133c895b56b374c8a1dc1eb948d99003ed2b47372069456b62f42b24'
LGPL_PATH = Path(__file__).resolve().parents[1] / 'docs/licenses/os' / (LGPL_SHA256 + '.txt')
SOURCE_INPUTS = {
    'tzcode2026c.tar.gz': {
        'url': 'https://www.iana.org/time-zones/repository/releases/tzcode2026c.tar.gz',
        'sha512': 'ad1aadf26b9aaca487a4f780d7a8ebf1d7383472ce587b06cb63852d4eb030dbd190b537e393e75d59530318581e9d3f492ff5f97bbac78f548d0755c4f7257f',
    },
    'tzdata2026c.tar.gz': {
        'url': 'https://www.iana.org/time-zones/repository/releases/tzdata2026c.tar.gz',
        'sha512': 'e0b4b7044b66fbc27bc21d13d18063abcdf78ab58d5ba5fd64bd1a88d86e9d495f45add4d8e65bb6c40249f9c94ca29b72c8ebba8d0e4c468f2965ac77932ef0',
    },
    'posixtz-0.5.tar.xz': {
        'url': 'https://dev.alpinelinux.org/archive/posixtz/posixtz-0.5.tar.xz',
        'sha512': '68dbaab9f4aef166ac2f2d40b49366527b840bebe17a47599fe38345835e4adb8a767910745ece9c384b57af815a871243c3e261a29f41d71f8054df3061b3fd',
    },
}
PATCH_INPUTS = {
    '0001-posixtz-ensure-the-file-offset-we-pass-to-lseek-is-o.patch':
        '0f2a10ee2bb4007f57b59123d1a0b8ef6accf99e568f21537f0bb19f290fff46e24050f55f12569d7787be600e1b62aa790ea85a333153f3ea081a812c81b1b5',
    '0002-fix-implicit-declaration-warnings-by-including-strin.patch':
        'fb322ab7867517ba39265d56d3576cbcea107c205d524e87015c1819bbb7361f7322232ee3b86ea9b8df2886e7e06a6424e3ac83b2006be290a33856c7d40ac4',
}


def download(url):
    from source_download import download as fetch_bytes
    return fetch_bytes(url, maximum=128 * 1024 * 1024, timeout=60)


def checked(body, algorithm, expected, label):
    if hashlib.new(algorithm, body).hexdigest() != expected:
        raise ValueError(label + ' ' + algorithm + ' checksum mismatch')
    return body


def retained_lgpl_notice():
    """Reuse the complete reviewed notice, with its original digest enforced."""
    if LGPL_PATH.is_symlink() or not LGPL_PATH.is_file():
        raise ValueError('Retained GNU LGPL notice must be a regular file')
    with LGPL_PATH.open('rb') as notice:
        body = notice.read(128 * 1024 + 1)
    if len(body) > 128 * 1024:
        raise ValueError('Retained GNU LGPL notice exceeds the size limit')
    return checked(body, 'sha256', LGPL_SHA256, 'GNU LGPL notice')


def read_member(body, name):
    """Read a unique regular member, with no archive filesystem extraction."""
    with tarfile.open(fileobj=io.BytesIO(body), mode='r:*') as archive:
        matches = []
        for count, member in enumerate(archive, 1):
            path = PurePosixPath(member.name)
            if (path.is_absolute() or '..' in path.parts or '\\' in member.name
                    or '\x00' in member.name or re.match(r'^[A-Za-z]:', member.name)):
                raise ValueError('Unsafe timezone source archive path')
            if count > 250000:
                raise ValueError('Timezone source archive member limit exceeded')
            if member.name == name:
                if not member.isfile() or member.size > 4 * 1024 * 1024:
                    raise ValueError('Timezone source entry must be a bounded regular file')
                matches.append(member)
        if len(matches) != 1:
            raise ValueError('Require exactly one timezone archive entry: ' + name)
        return archive.extractfile(matches[0]).read()


def recipe_identity(recipe):
    for key, value in {'pkgname': 'tzdata', 'pkgver': '2026c', '_ptzver': '0.5', 'pkgrel': '0'}.items():
        if re.findall(r'^' + re.escape(key) + r'=([^\n]+)$', recipe, re.M) != [value]:
            raise ValueError('Timezone APKBUILD version identity mismatch')
    blocks = re.findall(r'^sha512sums="\n([^\"]+)"$', recipe, re.M)
    if len(blocks) != 1:
        raise ValueError('Timezone APKBUILD requires one complete source checksum list')
    checksums = {}
    for line in blocks[0].strip().splitlines():
        match = re.fullmatch(r'([a-f0-9]{128})  ([^\s]+)', line)
        if not match or match[2] in checksums:
            raise ValueError('Malformed or duplicate timezone source checksum')
        checksums[match[2]] = match[1]
    expected = {name: row['sha512'] for name, row in SOURCE_INPUTS.items()} | PATCH_INPUTS
    if checksums != expected:
        raise ValueError('Timezone APKBUILD source checksum mismatch')


def collect_sources(package_spec, architecture, output_root, fetch=download):
    """Retain checked public source inputs; make the missing OCI binding explicit."""
    packages = package_spec.get('packages', [])
    if (package_spec.get('origin') != 'tzdata' or package_spec.get('version') != '2026c-r0'
            or architecture not in {'amd64', 'arm64'} or len(packages) != 1):
        raise ValueError('Fallback only covers the installed 2026c timezone data package')
    package = packages[0]
    binary = package.get('binaries', {}).get(architecture, {})
    if (package.get('name') != 'tzdata' or package.get('version') != '2026c-r0'
            or package.get('license') != 'Public-Domain'
            or not re.fullmatch(r'[a-f0-9]{64}', binary.get('sha256', ''))):
        raise ValueError('Timezone package identity or recorded binary digest mismatch')
    recipe_metadata = package_spec.get('recipe', {})
    if any(recipe_metadata.get(key) != value for key, value in {
            'path': RECIPE_PATH, 'revision': RECIPE_REVISION, 'sha256': RECIPE_SHA256,
            'upstream_commit': APORTS_COMMIT}.items()):
        raise ValueError('Reviewed timezone recipe metadata mismatch')
    lgpl_notice = retained_lgpl_notice()
    root = Path(output_root)
    if root.is_symlink() or (root.exists() and any(root.iterdir())):
        raise ValueError('Timezone source output must be an empty directory')
    root.mkdir(parents=True, exist_ok=True)
    records = []

    def retain(name, body, url, role):
        if Path(name).name != name:
            raise ValueError('Unsafe timezone output filename')
        (root / name).write_bytes(body)
        record = {'path': name, 'url': url, 'role': role,
                  'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest()}
        records.append(record)
        return record

    provider_recipe = checked(fetch(RECIPE_URL), 'sha256', RECIPE_SHA256, 'DHI timezone recipe')
    for literal in ('image: dhi.io/pkg-tzdata', '  VERSION: 2026c', '  COMMIT_SHA: ' + APORTS_COMMIT):
        if literal not in provider_recipe.decode('utf-8').splitlines():
            raise ValueError('Pinned DHI timezone recipe identity mismatch')
    retain('dhi-tzdata-2026c.yaml', provider_recipe, RECIPE_URL, 'pinned-provider-build-recipe')
    recipes = checked(fetch(APORTS_URL), 'sha256', APORTS_SHA256, 'Complete Alpine recipe archive')
    apkbuild = checked(read_member(recipes, f'aports-{APORTS_COMMIT}/main/tzdata/APKBUILD'),
                       'sha256', APKBUILD_SHA256, 'Timezone APKBUILD')
    recipe_identity(apkbuild.decode('utf-8'))
    retain(f'aports-{APORTS_COMMIT}.tar.gz', recipes, APORTS_URL, 'complete-alpine-build-recipes')
    retain('tzdata-2026c-APKBUILD', apkbuild, APORTS_URL, 'matching-apk-build-script')
    for name, checksum in PATCH_INPUTS.items():
        patch = checked(read_member(recipes, f'aports-{APORTS_COMMIT}/main/tzdata/{name}'),
                        'sha512', checksum, 'Timezone build patch')
        retain(name, patch, APORTS_URL, 'matching-build-patch')
    for name, source in SOURCE_INPUTS.items():
        body = checked(fetch(source['url']), 'sha512', source['sha512'], 'Timezone source')
        retain(name, body, source['url'], 'upstream-source')
        if name.startswith(('tzdata', 'tzcode')):
            if read_member(body, 'version').strip() != b'2026c':
                raise ValueError('IANA archive version does not match installed timezone data')
            retain(name.split('.')[0] + '-LICENSE', read_member(body, 'LICENSE'),
                   source['url'], 'upstream-notice')
            if name.startswith('tzcode'):
                for member in ('date.c', 'newstrftime.3', 'strftime.c'):
                    retain('tzcode2026c-BSD-' + member, read_member(body, member),
                           source['url'], 'upstream-bsd-attribution-source')
        else:
            retain('posixtz-0.5-COPYRIGHT.c', read_member(body, 'posixtz-0.5/posixtz.c'),
                   source['url'], 'upstream-lgpl-attribution-source')
    lgpl_record = retain('posixtz-LGPL-2.0.txt', lgpl_notice, LGPL_URL, 'upstream-lgpl-license')
    lgpl_record.update({'acquisition': 'verified-repository-notice',
                        'repository_path': f'docs/licenses/os/{LGPL_SHA256}.txt'})
    manifest = {
        'schema': 1, 'origin': 'tzdata', 'version': '2026c-r0', 'architecture': architecture,
        'provider_oci_binding': False,
        'binding_method': 'IANA release version and source checksums in the pinned public provider/Alpine recipes; no historical provider OCI digest inferred.',
        'package_input': {'name': 'tzdata', 'version': '2026c-r0', 'license': 'Public-Domain',
                          'binary_sha256': binary['sha256'], 'binary_url': binary.get('url'),
                          'installed_build_commit': package.get('build_commit')},
        'recipe_revision': RECIPE_REVISION, 'aports_commit': APORTS_COMMIT,
        'files': records,
        'coverage': 'Matching IANA 2026c timezone source data and complete public build recipe/patch inputs. BSD exceptions and LGPL POSIXtz build-source notices are retained; POSIXtz utilities are not claimed to be installed in the runtime image.',
    }
    (root / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--map', type=Path, default=Path('docs/os-package-sources.json'))
    parser.add_argument('--arch', choices=('amd64', 'arm64'), required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    rows = [row for row in json.loads(args.map.read_text())['origins'] if row['origin'] == 'tzdata']
    if len(rows) != 1:
        raise ValueError('Source map must identify exactly one timezone package origin')
    manifest = collect_sources(rows[0], args.arch, args.output)
    print(json.dumps({'origin': manifest['origin'], 'version': manifest['version'],
                      'files': len(manifest['files']), 'provider_oci_binding': False}))


if __name__ == '__main__':
    main()
