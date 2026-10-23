"""Verify isolated build-only Fortify headers and retain their matching sources.

No APK is installed and no downloaded build script is executed. Both vendor
packages must contain exactly the same ten headers as the complete upstream
source plus Alpine's single reviewed patch.
"""
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import tarfile

if __package__:
    from . import alpine_expat_sources as alpine
else:
    import alpine_expat_sources as alpine

VERSION = '3.0.1-r2'
SOURCE_ROOT = 'fortify-headers-3.0.1'
BUILD_COMMIT = '363be18be4b1f33af5a058990ba9b297e8fb547b'
CONTEXT_URL = f'https://github.com/alpinelinux/aports/archive/{BUILD_COMMIT}.tar.gz'
CONTEXT_SHA256 = '8e2e9363eca846ea6dc9a8c0c741109e19677c26d94a823e1a7548bd325c19a2'
RECIPE_URL = f'https://raw.githubusercontent.com/alpinelinux/aports/{BUILD_COMMIT}/main/fortify-headers/APKBUILD'
RECIPE_SHA256 = '1723fbc05affc9376319d2ae18d036ee48ff1d1f9e259ca11ade11cc0ed515b0'
PATCH_URL = RECIPE_URL.rsplit('/', 1)[0] + '/clang.patch'
PATCH_SHA256 = 'd89c6260d79af6f7022ecf45e9825dbbda3c9fea3ad917a524cddc158cef56ef'
PATCH_SHA512 = ('96bce32ff14f0964ed304086ba124b0b3ed256228699ff7cd6b40c735995f3fc2c7'
                'de5a6518c40012dd81371c6a7fbbe2d9e6e6d4723aa43956028f5336dd0ad')
SOURCE_URL = 'https://github.com/jvoisin/fortify-headers/archive/refs/tags/3.0.1.tar.gz'
SOURCE_SHA256 = '576ac1dc2db9a503d8458c1e9f4a6ce8b0437cfc3c507859d7601a3b8d8ac0e6'
SOURCE_SHA512 = ('bb4e98ed5bcc5ba97f1a57935642b19b87b3c3b8c28c6421394d02ab4ef8d6548'
                 '19397910914cbfc2bc9c938a6b18b7efafd8a73d681a20c32b73dd22f5041bf')
LICENSE_SHA256 = 'f9c890cf570f24fefbe1605a073b430630b0ff63e8d9fc53591bb5528120d424'
ORIGINAL_PATCHED_HEADER_SHA256 = '1dbb77a0f1ecc319d682f429d29c3634c0046f6af7e16dd245410209a09e3bd3'
PATCH_BEFORE = b'#define _FORTIFY_POSN(n) const __attribute__((pass_object_size__(n)))'
PATCH_AFTER = b'#define _FORTIFY_POSN(n) const __attribute__((pass_object_size(n)))'
DATA_SHA256 = '501448d04f6604ae5e50277a02b79abbe7c9546b2ef86a04be53c253a6927801'
APK_SHA256 = {'amd64': '5ffaebd9f141ac3e3fa0cc99f798f64b4c0aa16fb06a7a77e68f63f350fe23aa',
              'arm64': '72bf2a77475f2550a7345683c77b39487ee94ecbc2ca11ed5314161f3b927d76'}
PKGINFO_SHA256 = {'amd64': '17d62c70bbae7c291d4272c3ea0c38d2425ba7f41821ba11478737aef7086222',
                  'arm64': 'df1fdf8be8b1deeb4e54efa6315d662a4236edbd4b1026a3b4fd47a5599bfa53'}
HEADERS = {
    'fortify-headers.h': '48e4cd8fedb6928c841d36ddb3affc6211013cce5e00691e422544d11dece694',
    'poll.h': '7419da106bcd51e8665828cf87cae9565c550b01765e617156771e6417c926ae',
    'stdio.h': '676bdbc3abfecc23d0147590f8aaeaf21c4791daa20f84bf6198054b2d2527af',
    'stdlib.h': '8916d455b280f12f737b4b70d5c4489b9d2b078e3dc9a69a62a3e2c8b38d0b9d',
    'string.h': 'a4799fa3eab2f969f38ea4962cf2bd3e2ec8b49f376e9a459b024c0abc88926f',
    'strings.h': '6c156a2e571e490c85c5ba0abc5e36ba90f56e3963049462043dd6a95fa9b1f4',
    'sys/select.h': 'cd8d09e913cf2eb3c78a77c59b47f957980b29ce9760647f6dda1d3f0ed579cb',
    'sys/socket.h': '21329dcc81a50a04990a1cfe9cea3efb8cb11850ccf7541436a21bce41f6f926',
    'unistd.h': 'd53dade38894de3f7925898f605be52ab8dfed75f8224977bd603bb22dd566cc',
    'wchar.h': 'c2ba1bc129c88d466de0fab78867e01e691055358ca6f0feaa2ce9a55700a0d3',
}
download = alpine.download


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def checked(body, expected, label):
    return alpine.checked(body, 'sha256', expected, label)


def reviewed_spec():
    return {
        'schema': 'keep-fortify-header-inputs-v1', 'package': 'fortify-headers',
        'version': VERSION, 'package_architecture': 'noarch', 'license': '0BSD',
        'build_commit': BUILD_COMMIT, 'installation': 'isolated-compiler-include-only',
        'context': {'url': CONTEXT_URL, 'sha256': CONTEXT_SHA256},
        'recipe': {'url': RECIPE_URL, 'sha256': RECIPE_SHA256},
        'source': {'url': SOURCE_URL, 'sha256': SOURCE_SHA256, 'sha512': SOURCE_SHA512,
                   'root': SOURCE_ROOT, 'license_sha256': LICENSE_SHA256},
        'patch': {'url': PATCH_URL, 'sha256': PATCH_SHA256, 'sha512': PATCH_SHA512,
                  'original_header_sha256': ORIGINAL_PATCHED_HEADER_SHA256,
                  'upstream_commit': 'c1642e5a43de3affa75d52c3577ee1be4c874a5d'},
        'headers': dict(HEADERS), 'data_sha256': DATA_SHA256,
        'packages': {arch: {
            'url': f'https://dl-cdn.alpinelinux.org/alpine/v3.24/main/{native}/fortify-headers-{VERSION}.apk',
            'sha256': APK_SHA256[arch], 'pkginfo_sha256': PKGINFO_SHA256[arch],
            'signing_key': {**alpine.KEYS[arch],
                            'url': 'https://alpinelinux.org/keys/' + alpine.KEYS[arch]['name']}}
            for arch, native in alpine.ARCHES.items()},
    }


def source_lock_bytes():
    return json_bytes(reviewed_spec())


def source_download_records():
    spec = reviewed_spec()
    records = [
        {'path': f'aports-{BUILD_COMMIT}.tar.gz', **spec['context'], 'role': 'complete-alpine-build-recipes'},
        {'path': 'APKBUILD', **spec['recipe'], 'role': 'matching-apk-build-script'},
        {'path': 'clang.patch', 'url': PATCH_URL, 'sha256': PATCH_SHA256, 'role': 'matching-source-patch'},
        {'path': SOURCE_ROOT + '.tar.gz', 'url': SOURCE_URL, 'sha256': SOURCE_SHA256, 'role': 'upstream-source'},
    ]
    for arch, package in spec['packages'].items():
        records.extend([
            {'path': f'packages/{arch}/fortify-headers-{VERSION}.apk', 'url': package['url'],
             'sha256': package['sha256'], 'role': 'signed-alpine-binary-evidence'},
            {'path': 'keys/' + package['signing_key']['name'],
             'url': package['signing_key']['url'], 'sha256': package['signing_key']['sha256'],
             'role': 'alpine-signing-key'},
        ])
    return records


def verify_apk(body, architecture, key):
    if architecture not in APK_SHA256:
        raise ValueError('Unsupported Fortify input architecture')
    checked(body, APK_SHA256[architecture], 'Fortify APK')
    signing = alpine.KEYS[architecture]
    checked(key, signing['sha256'], 'Fortify Alpine signing key')
    parts = alpine.gzip_parts(body)
    signatures = alpine.tar_entries(parts[0][1])
    signature_name = '.SIGN.RSA.' + signing['name']
    if set(signatures) != {signature_name} or signatures[signature_name]['body'] is None:
        raise ValueError('Fortify APK signing key name differs')
    alpine.verify_rsa(signatures[signature_name]['body'], parts[1][0], key)
    controls = alpine.tar_entries(parts[1][1])
    if set(controls) != {'.PKGINFO'} or controls['.PKGINFO']['body'] is None:
        raise ValueError('Fortify APK must contain only package metadata and no scripts')
    metadata = checked(controls['.PKGINFO']['body'], PKGINFO_SHA256[architecture], 'Fortify APK metadata')
    fields = {}
    for line in metadata.decode().splitlines():
        if ' = ' in line:
            name, value = line.split(' = ', 1)
            fields.setdefault(name, []).append(value)
    expected = {'pkgname': 'fortify-headers', 'pkgver': VERSION, 'origin': 'fortify-headers',
                'arch': 'noarch', 'commit': BUILD_COMMIT, 'license': '0BSD',
                'url': 'https://github.com/jvoisin/fortify-headers', 'datahash': DATA_SHA256}
    if any(fields.get(name) != [value] for name, value in expected.items()):
        raise ValueError('Fortify signed package identity differs')
    if any(fields.get(name) for name in ('depend', 'provides', 'install_if', 'triggers')):
        raise ValueError('Fortify input must have no dependencies, providers or scripts')
    checked(parts[2][0], DATA_SHA256, 'Fortify signed compressed payload')
    payload = alpine.tar_entries(parts[2][1])
    headers = {name.removeprefix('usr/include/fortify/'): value['body']
               for name, value in payload.items() if value['member'].isfile()}
    if set(headers) != set(HEADERS) or any(
            not name.startswith('usr/include/fortify/') for name, value in payload.items()
            if value['member'].isfile()) or any(
                not (value['member'].isfile() or value['member'].isdir()) for value in payload.values()):
        raise ValueError('Fortify APK must contain exactly the ten reviewed regular headers')
    for name, checksum in HEADERS.items():
        checked(headers[name], checksum, 'Fortify APK header ' + name)
    return metadata, headers, {'architecture': architecture, **expected,
                               'apk_sha256': APK_SHA256[architecture],
                               'pkginfo_sha256': PKGINFO_SHA256[architecture],
                               'signing_key_sha256': signing['sha256'], 'signature_verified': True}


def source_files(body):
    files, seen, total = {}, set(), 0
    with tarfile.open(fileobj=io.BytesIO(body), mode='r:gz') as archive:
        for number, member in enumerate(archive, 1):
            name = alpine.safe_name(member.name)
            path = PurePosixPath(name)
            if (not path.parts or path.parts[0] != SOURCE_ROOT or name in seen or number > 10000
                    or not (member.isdir() or member.isfile())):
                raise ValueError('Unsafe or ambiguous Fortify source archive')
            seen.add(name)
            total += member.size
            if member.size < 0 or member.size > 1024 * 1024 or total > 16 * 1024 * 1024:
                raise ValueError('Fortify source archive exceeds inventory limit')
            if member.isfile():
                files['/'.join(path.parts[1:])] = archive.extractfile(member).read()
    return files


def replay_source(body, patch):
    checked(body, SOURCE_SHA256, 'Complete Fortify upstream source')
    if hashlib.sha512(body).hexdigest() != SOURCE_SHA512:
        raise ValueError('Fortify source SHA-512 mismatch')
    checked(patch, PATCH_SHA256, 'Fortify Alpine patch')
    if hashlib.sha512(patch).hexdigest() != PATCH_SHA512:
        raise ValueError('Fortify patch SHA-512 mismatch')
    files = source_files(body)
    checked(files['LICENSE'], LICENSE_SHA256, 'Fortify full license')
    original = checked(files['include/fortify-headers.h'], ORIGINAL_PATCHED_HEADER_SHA256,
                       'Original Fortify patched header')
    if original.count(PATCH_BEFORE) != 1 or PATCH_AFTER in original:
        raise ValueError('Fortify patch context differs')
    files['include/fortify-headers.h'] = original.replace(PATCH_BEFORE, PATCH_AFTER, 1)
    headers = {name.removeprefix('include/'): content for name, content in files.items()
               if name.startswith('include/')}
    if set(headers) != set(HEADERS):
        raise ValueError('Complete Fortify source header set differs')
    for name, checksum in HEADERS.items():
        checked(headers[name], checksum, 'Replayed Fortify source header ' + name)
    return files, headers


def verify_prepared_headers(include):
    include = Path(include)
    if include.is_symlink() or not include.is_dir():
        raise ValueError('Prepared Fortify include path must be a regular directory')
    paths = list(include.rglob('*'))
    if any(path.is_symlink() or not (path.is_dir() or path.is_file()) for path in paths):
        raise ValueError('Unsafe prepared Fortify include entry')
    files = {path.relative_to(include).as_posix(): path for path in paths if path.is_file()}
    if set(files) != set(HEADERS):
        raise ValueError('Prepared Fortify header set differs')
    for name, checksum in HEADERS.items():
        if files[name].stat().st_size > 1024 * 1024:
            raise ValueError('Prepared Fortify header exceeds size limit')
        checked(files[name].read_bytes(), checksum, 'Prepared Fortify header ' + name)
    return dict(HEADERS)


def prepare(output, fetch=download):
    root, records = alpine.empty_output(output), []
    inputs = {}
    for record in source_download_records():
        body = checked(fetch(record['url']), record['sha256'], 'Fortify retained input')
        inputs[record['path']] = body
        alpine.retain(root, records, record['path'], body, record['url'], record['role'])
    context = inputs[f'aports-{BUILD_COMMIT}.tar.gz']
    prefix = f'aports-{BUILD_COMMIT}/main/fortify-headers/'
    for name, checksum in (('APKBUILD', RECIPE_SHA256), ('clang.patch', PATCH_SHA256)):
        body = alpine.read_member(context, prefix + name)
        checked(body, checksum, 'Complete Fortify recipe context ' + name)
        if body != inputs[name]:
            raise ValueError('Fortify raw recipe differs from complete context')
    files, headers = replay_source(inputs[SOURCE_ROOT + '.tar.gz'], inputs['clang.patch'])
    packages = []
    for arch in alpine.ARCHES:
        metadata, payload, identity = verify_apk(inputs[f'packages/{arch}/fortify-headers-{VERSION}.apk'],
                                                arch, inputs['keys/' + alpine.KEYS[arch]['name']])
        if payload != headers:
            raise ValueError('Signed Fortify headers differ from complete replayed source')
        alpine.retain(root, records, f'packages/{arch}/fortify-headers-{VERSION}.apk.PKGINFO', metadata,
                      reviewed_spec()['packages'][arch]['url'], 'package-build-identity')
        packages.append(identity)
    alpine.retain(root, records, 'LICENSE', files['LICENSE'], SOURCE_URL, 'upstream-notice',
                  SOURCE_ROOT + '/LICENSE')
    for name, body in sorted(headers.items()):
        alpine.retain(root, records, 'include/' + name, body, SOURCE_URL,
                      'upstream-permissive-attribution-source', SOURCE_ROOT + '/include/' + name)
    verify_prepared_headers(root / 'include')
    manifest = {'schema': 'keep-fortify-header-inputs-v1', 'version': VERSION,
                'source_manifest_sha256': hashlib.sha256(source_lock_bytes()).hexdigest(),
                'binding_method': 'verified-alpine-header-inputs', 'provider_oci_binding': False,
                'installation': 'isolated-compiler-include-only', 'packages': packages,
                'headers': dict(HEADERS), 'files': records,
                'coverage': 'Both Alpine-signed noarch APK inputs, verified RSA signatures and payloads, '
                            'complete pinned aports context, matching upstream source and clang.patch, '
                            'the complete license and all ten attributed matching headers. '
                            'No APK installation or independent upstream GPG verification is claimed.'}
    (root / 'manifest.json').write_bytes(json_bytes(manifest))
    return manifest
