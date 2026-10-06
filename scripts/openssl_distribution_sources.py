#!/usr/bin/env python3
"""Retain OpenSSL's checked public sources when provider source metadata is absent.

The exact installed APK identities are bound to the pinned native base's
materials and runtime inventory. Public Docker/Alpine recipes, every patch and
the upstream release are retained. This reconstruction has no package source
image or signed package-build provenance claim.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import tarfile
import io
import urllib.request

from oci_source_materials import safe_name


RECIPE_REVISION = 'a4d552587e85e8c20a2b28523adab64c804893ee'
RECIPE_PATH = 'package/apk/main/openssl/alpine-3.24/3.yaml'
RECIPE_URL = f'https://raw.githubusercontent.com/docker-hardened-images/catalog/{RECIPE_REVISION}/{RECIPE_PATH}'
RECIPE_SHA256 = '9636e0fa53edd2d8a992ce8ce22cd5e60c67a292e265a5360ffdb382f5ec7cd1'
APORTS_COMMIT = '013edf8b29199933e8ea34dde460b5584b979042'
APORTS_URL = f'https://github.com/alpinelinux/aports/archive/{APORTS_COMMIT}.tar.gz'
APORTS_SHA256 = '38efb39aec042bda9d117ef4b27602a76a14472a30ff7732f6304715d4e2647e'
APKBUILD_SHA256 = '612ccf2841efe957089e825b50292a20efb0d9ba8ca3f2a292cefa2515963d21'
SOURCE_URL = 'https://github.com/openssl/openssl/releases/download/openssl-3.5.9/openssl-3.5.9.tar.gz'
SOURCE_SHA256 = '603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a'
SOURCE_SHA512 = ('c4c8136fd2c98d13bb85a57bfb0def25c906f47f1fe97675cd114594944eab957'
                 'b5b81a3e0f48826e1a0f093afff5e83766b539d49768f6db68310fd678d7de6')
# DHI's checked recipe bumps this original APKBUILD to 3.5.9-r0 and
# recalculates checksums. Retain and validate both identities explicitly.
ORIGINAL_SOURCE_SHA512 = ('62a1dbed0fad75245b332e41b85a1f7c2379189525e7628a7cf68947d115e90a'
                 '47f179e3f87d27641e5b2d357c357292179fc0e64eccecdebc81c083f7a8ebe4')
PATCH_SHA512 = ('b2541075148fd5af4552d34158deb1a325f5adced90626dc03fd126f47323cde949'
                'b15b2657523c34b26530b322312a43bd42ada7295b4f2dd1d3b5d11892c62')
LICENSE_SHA256 = '7d5450cb2d142651b8afa315b5f238efc805dad827d91ba367d8516bc9d49e7a'
BUILD_COMMIT = 'a5ef7ba4aeb961c591312c4301e602c12415c359'
NATIVE_DIGESTS = {
    'amd64': 'sha256:fa220ee7ebeadd3e4d68f5fecb73dd29b69622684ce130157e59fd9811cbeb80',
    'arm64': 'sha256:233127fc1adc0748f183e2341864e6c3caa2c9855819657c26b4a49c50fd7f06',
}


def download(url):
    with urllib.request.urlopen(url, timeout=60) as response:
        body = response.read(128 * 1024 * 1024 + 1)
    if len(body) > 128 * 1024 * 1024:
        raise ValueError('OpenSSL source exceeds download limit')
    return body


def checked(body, algorithm, expected, label):
    if hashlib.new(algorithm, body).hexdigest() != expected:
        raise ValueError(label + ' checksum mismatch')
    return body


def read_member(body, name):
    with tarfile.open(fileobj=io.BytesIO(body), mode='r:*') as archive:
        matches = []
        for count, member in enumerate(archive, 1):
            safe_name(member.name)
            if count > 250000:
                raise ValueError('OpenSSL source member limit exceeded')
            if member.name == name:
                if not member.isfile() or member.size > 4 * 1024 * 1024:
                    raise ValueError('OpenSSL source entry must be a bounded regular file')
                matches.append(member)
        if len(matches) != 1:
            raise ValueError('Require one exact OpenSSL source archive entry: ' + name)
        return archive.extractfile(matches[0]).read()


def recipe_identity(body):
    text = body.decode('utf-8')
    for key, value in {'pkgname': 'openssl', 'pkgver': '3.5.8', 'pkgrel': '0',
                       'license': '"Apache-2.0"'}.items():
        if re.findall(r'^' + key + r'=([^\n]+)$', text, re.M) != [value]:
            raise ValueError('OpenSSL APKBUILD identity mismatch')
    blocks = re.findall(r'^sha512sums="\n([^\"]+)"$', text, re.M)
    expected = {'openssl-3.5.8.tar.gz': ORIGINAL_SOURCE_SHA512, 'auxv.patch': PATCH_SHA512}
    if len(blocks) != 1:
        raise ValueError('Require complete OpenSSL source checksum list')
    checksums = {}
    for line in blocks[0].strip().splitlines():
        match = re.fullmatch(r'([a-f0-9]{128})  ([^\s]+)', line)
        if not match or match[2] in checksums:
            raise ValueError('Malformed OpenSSL source checksums')
        checksums[match[2]] = match[1]
    if checksums != expected:
        raise ValueError('OpenSSL APKBUILD source checksum mismatch')
    if ('source="https://github.com/openssl/openssl/releases/download/openssl-$pkgver/openssl-$pkgver.tar.gz\n'
            '\tauxv.patch\n\t"') not in text:
        raise ValueError('OpenSSL source declaration changed')


def bind_packages(package_spec, architecture, base_provenance, runtime_inventory):
    if architecture not in NATIVE_DIGESTS:
        raise ValueError('Unsupported OpenSSL source architecture')
    subjects = base_provenance.get('subject', [])
    native = NATIVE_DIGESTS[architecture]
    if (base_provenance.get('predicateType') != 'https://slsa.dev/provenance/v1'
            or not subjects or any(row.get('digest', {}).get('sha256') != native.split(':')[1]
                                   for row in subjects)):
        raise ValueError('OpenSSL base provenance has the wrong pinned native subject')
    materials = base_provenance.get('predicate', {}).get('buildDefinition', {}).get('resolvedDependencies', [])
    actual = {row['name']: row for row in runtime_inventory.get('os_packages', [])}
    expected_names = {'openssl', 'libcrypto3', 'libssl3'}
    packages = package_spec.get('packages', [])
    if ({row.get('name') for row in packages} != expected_names or len(packages) != 3
            or package_spec.get('origin') != 'openssl' or package_spec.get('version') != '3.5.9-r0'):
        raise ValueError('Public reconstruction only covers exact reviewed OpenSSL packages')
    results = []
    for package in packages:
        binary = package.get('binaries', {}).get(architecture, {})
        if (package.get('version') != '3.5.9-r0' or package.get('license') != 'Apache-2.0'
                or package.get('build_commit') != BUILD_COMMIT
                or not re.fullmatch(r'[a-f0-9]{64}', binary.get('sha256', ''))):
            raise ValueError('Reviewed OpenSSL package build identity mismatch')
        installed = actual.get(package['name'], {})
        if any(installed.get(key) != value for key, value in {
                'version': '3.5.9-r0', 'origin': 'openssl', 'license': 'Apache-2.0',
                'build_commit': BUILD_COMMIT}.items()):
            raise ValueError('Actual runtime OpenSSL package build identity mismatch')
        matches = [row for row in materials if row.get('uri') == binary.get('url')
                   and row.get('digest', {}).get('sha256') == binary['sha256']]
        if len(matches) != 1:
            raise ValueError('Actual pinned base materials do not contain exact reviewed OpenSSL APK')
        results.append({'name': package['name'], 'version': package['version'],
            'license': package['license'], 'installed_build_commit': BUILD_COMMIT,
            'binary_url': binary['url'], 'binary_sha256': binary['sha256']})
    return native, results


def collect_sources(package_spec, architecture, base_provenance, runtime_inventory,
                    output_root, fetch=download):
    native, packages = bind_packages(package_spec, architecture, base_provenance, runtime_inventory)
    metadata = package_spec.get('recipe', {})
    if any(metadata.get(key) != value for key, value in {
            'path': RECIPE_PATH, 'revision': RECIPE_REVISION, 'sha256': RECIPE_SHA256,
            'upstream_commit': APORTS_COMMIT}.items()):
        raise ValueError('Reviewed OpenSSL provider recipe identity mismatch')
    root = Path(output_root)
    if root.is_symlink() or root.exists() and any(root.iterdir()):
        raise ValueError('OpenSSL source output must be empty without symlinks')
    root.mkdir(parents=True, exist_ok=True)
    records = []
    def retain(name, body, url, role, source_path=None):
        name = safe_name(name)
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(body)
        records.append({'path': name, 'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest(),
                        'url': url, 'role': role, 'source_path': source_path or name})
    provider = checked(fetch(RECIPE_URL), 'sha256', RECIPE_SHA256, 'Public Docker OpenSSL recipe')
    for line in ('image: dhi.io/pkg-openssl', '  COMMIT_SHA: ' + APORTS_COMMIT,
                 '  VERSION: 3.5.9', '  _VERSION: 3.5.8', '  REL: "0"',
                 '  _REL: "0"', '  EXTRA_PATCHES: "false"',
                 '        - uses: abuild/bump@v1', '            rel: 0',
                 '            version: 3.5.9', '            command: checksum'):
        if line not in provider.decode('utf-8').splitlines():
            raise ValueError('Public Docker OpenSSL recipe declarations changed')
    retain('dhi-openssl-3.5.9-r0.yaml', provider, RECIPE_URL, 'pinned-provider-build-recipe')
    recipes = checked(fetch(APORTS_URL), 'sha256', APORTS_SHA256, 'Complete OpenSSL aports context')
    recipe_member = f'aports-{APORTS_COMMIT}/main/openssl/APKBUILD'
    apkbuild = checked(read_member(recipes, recipe_member), 'sha256', APKBUILD_SHA256, 'OpenSSL APKBUILD')
    recipe_identity(apkbuild)
    retain(f'aports-{APORTS_COMMIT}.tar.gz', recipes, APORTS_URL, 'complete-alpine-build-recipes')
    retain('context/main/openssl/APKBUILD', apkbuild, APORTS_URL, 'matching-apk-build-script', recipe_member)
    for name in ('auxv.patch', 'openssl-fips.post-install'):
        member = f'aports-{APORTS_COMMIT}/main/openssl/{name}'
        body = read_member(recipes, member)
        if name == 'auxv.patch':
            checked(body, 'sha512', PATCH_SHA512, 'OpenSSL build patch')
        retain('context/main/openssl/' + name, body, APORTS_URL, 'matching-build-context', member)
    upstream = checked(fetch(SOURCE_URL), 'sha256', SOURCE_SHA256, 'OpenSSL upstream source')
    checked(upstream, 'sha512', SOURCE_SHA512, 'OpenSSL APKBUILD upstream source')
    version = read_member(upstream, 'openssl-3.5.9/VERSION.dat').decode('utf-8')
    for line in ('MAJOR=3', 'MINOR=5', 'PATCH=9'):
        if line not in version.splitlines():
            raise ValueError('OpenSSL upstream source version mismatch')
    retain('openssl-3.5.9.tar.gz', upstream, SOURCE_URL, 'upstream-source')
    license_text = checked(read_member(upstream, 'openssl-3.5.9/LICENSE.txt'), 'sha256', LICENSE_SHA256, 'OpenSSL full license')
    retain('openssl-3.5.9-LICENSE.txt', license_text, SOURCE_URL, 'upstream-notice', 'openssl-3.5.9/LICENSE.txt')
    retain('openssl-3.5.9-AUTHORS.md', read_member(upstream, 'openssl-3.5.9/AUTHORS.md'), SOURCE_URL,
           'upstream-attribution', 'openssl-3.5.9/AUTHORS.md')
    retain('base-provenance.json', (json.dumps(base_provenance, indent=2) + '\n').encode(),
           'verified-native-base:' + native, 'native-base-material-binding')
    runtime = {'os_packages': [actual for actual in runtime_inventory['os_packages'] if actual['name'] in {'openssl', 'libcrypto3', 'libssl3'}]}
    retain('runtime-openssl-identity.json', (json.dumps(runtime, indent=2) + '\n').encode(),
           'verified-candidate-runtime:/lib/apk/db/installed', 'runtime-package-build-identity')
    manifest = {'schema': 1, 'origin': 'openssl', 'version': '3.5.9-r0', 'architecture': architecture,
        'provider_oci_binding': False, 'source_image_digest': None, 'native_image_digest': native,
        'binding_method': 'pinned-public-openssl-reconstruction', 'package_inputs': packages,
        'recipe_revision': RECIPE_REVISION, 'aports_commit': APORTS_COMMIT,
        'files': records,
        'coverage': 'Exact OpenSSL 3.5.9 sources, complete pinned public Docker/Alpine recipes, auxv patch and install context. The checked Docker recipe bumps the original 3.5.8 APKBUILD to 3.5.9-r0 and recalculates its checksums. Installed 3.5.9-r0 APK identities and hashes match pinned native-base materials. Caller verifies original base provenance; no package source-image or signed package-build provenance is claimed.'}
    (root / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--map', default=str(Path(__file__).resolve().parents[1] / 'docs/os-package-sources.json'))
    parser.add_argument('--architecture', choices=('amd64', 'arm64'), required=True)
    parser.add_argument('--base-provenance', required=True)
    parser.add_argument('--runtime-inventory', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    spec = next(row for row in json.loads(Path(args.map).read_text())['origins'] if row['origin'] == 'openssl')
    manifest = collect_sources(spec, args.architecture,
        json.loads(Path(args.base_provenance).read_text()), json.loads(Path(args.runtime_inventory).read_text()), args.output)
    print(json.dumps({'origin': 'openssl', 'architecture': args.architecture,
                      'provider_oci_binding': False, 'files': len(manifest['files'])}))


if __name__ == '__main__':
    main()
