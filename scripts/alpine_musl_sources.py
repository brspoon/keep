#!/usr/bin/env python3
"""Verify exact Alpine musl packages and retain their complete matching sources.

The runtime uses only musl; the build stage additionally needs matching musl-dev.
Downloaded recipes, archives and package payloads are inspected, never executed.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile

if __package__:
    from .alpine_expat_sources import checked, download, empty_output, read_member, retain
    from .dhi_python_packages import gzip_parts, tar_entries, verify_rsa, metadata_fields
else:
    from alpine_expat_sources import checked, download, empty_output, read_member, retain
    from dhi_python_packages import gzip_parts, tar_entries, verify_rsa, metadata_fields


VERSION = '1.2.6-r3'
UPSTREAM_VERSION = '1.2.6'
BUILD_COMMIT = '8f79d39391b46d6dbf1800fb68b8212a21d5ee2e'
UPSTREAM_COMMIT = '7813e9119eb5fe681b6750b8a033a0490bca0941'
APORTS_URL = 'https://github.com/alpinelinux/aports/archive/' + BUILD_COMMIT + '.tar.gz'
APORTS_SHA256 = 'ea30c7a4e842d60d44f71796bbd5ab84a2f9cc5c47f4da1558043fca9a9b79d4'
APKBUILD_URL = 'https://raw.githubusercontent.com/alpinelinux/aports/' + BUILD_COMMIT + '/main/musl/APKBUILD'
APKBUILD_SHA256 = '22c5adb3f3b68ab84e5ff7d20df68447063d1ecb5c7b39afd5a04a1dfd444a35'
PATCH_URL = 'https://raw.githubusercontent.com/alpinelinux/aports/' + BUILD_COMMIT + '/main/musl/CVE-2026-107891.patch'
PATCH_SHA256 = '0cf0090ab433e8f9ed08ae03a0c93aff557c1d3e347260f62a61a10281f5333b'
PATCH_SHA512 = 'df73a35b9da531021ad5b1a6aad12b9d8d69de2bed7fc91b1156d9727476ab25c0d3c2341d60488152ee8ccbddb83786e91fff950cdb177b9b04673da98fdc4e'
SOURCE_URL = 'https://musl.libc.org/releases/musl-1.2.6.tar.gz'
SOURCE_SHA256 = 'd585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a'
SOURCE_SHA512 = '1adad96eddb3a2eb0cacb3e363b0046568925fcdd75cf8b0503f2139df1f693d64730779ca0ce8131b7624ab2d37f4247bb1d3393c523de6e30d2b1d7732555c'
SIGNATURE_SHA256 = '8a696228404cd4bae6379cf7538fc5d18c133b0ada54a41c1c6cef31d3c22ab6'
COPYRIGHT_SHA256 = 'b870108ec5e7790e9f9919064f1b9421d62d5f9b0e6c230c6adf7ea2da62e97b'
ARCHES = {'amd64': 'x86_64', 'arm64': 'aarch64'}
KEYS = {
    "amd64": {
        "name": "alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub",
        "sha256": "207e4696d3c05f7cb05966aee557307151f1f00217af4143c1bcaf33b8df733f"
    },
    "arm64": {
        "name": "alpine-devel@lists.alpinelinux.org-616ae350.rsa.pub",
        "sha256": "d11f6b21c61b4274e182eb888883a8ba8acdbf820dcc7a6d82a7d9fc2fd2836d"
    }
}
BINARY_SHA256 = {
    "amd64": {
        "musl": "e142255d0fa397f14318996bc10378093dcc069dc3dd1b6818c8f28a789c21da",
        "musl-dev": "310b51cff12e1d5ce5f135c558a82e2550427da5465bbd16c9ff9b05e63ee3d9"
    },
    "arm64": {
        "musl": "2e17864102278d9049c3a56f1bceed9e8cf287065617e579325123443daed8a5",
        "musl-dev": "45afe0a9f78de3402b6b5d11f5153ed955bf59d59b45344d9c3fed9f4bbf2f66"
    }
}
PKGINFO_SHA256 = {
    "amd64": {
        "musl": "9ce97a54370f1059cbdd6b940a2b0fac4d5e2b370103b0329895310af948d8e0",
        "musl-dev": "fcee1d1112be6ad0b3b23243e111dbc98cc11c508592361e5113d2774df490df"
    },
    "arm64": {
        "musl": "f9cdee26ee21a62f00b1cd6bf92a01af98b7e72aac4e851a5708d9669acfc178",
        "musl-dev": "7314b4c227776e953da2de01a66889836d088213e075de55938a8b2f8ada0087"
    }
}
LOADER_SHA256 = {
    "amd64": "095b047c631447e4fa50401fa7ffce01f678587040d65ba18c574981dc630de5",
    "arm64": "53282acc2be8a08a9fdcf880334bf35bbfd0a13862b7f3616be3919fcda11793"
}
LIBRARY_SHA256 = LOADER_SHA256
DEV_INVENTORY_SHA256 = {
    "amd64": "c7df0bc3f11bcc74540cf830af54e39e437133eb3a945529cbc9550100b87bd8",
    "arm64": "b943e9901a06ee38128d0064ab20cbdf12d99979bc59b668ebd106c31f8d2313"
}
CONTEXT_FILES = {
    "0001-add-stub-for-pthread_mutexattr_setprioceiling.patch": {
        "sha256": "b2067680c66af9eb9f4fdc1fa5d9337a9fd62bdab2c437b416aa97d79eb884ee",
        "sha512": "83ec0f774dbb5d4f4d4b917d149ea0ef609d028d18ae7624e90fedda6e3174c91ade93751bfd376adfa2848155110fc4dd02b6790363b98e5395c4787e8731e8"
    },
    "CVE-2026-107891.patch": {
        "sha256": "0cf0090ab433e8f9ed08ae03a0c93aff557c1d3e347260f62a61a10281f5333b",
        "sha512": "df73a35b9da531021ad5b1a6aad12b9d8d69de2bed7fc91b1156d9727476ab25c0d3c2341d60488152ee8ccbddb83786e91fff950cdb177b9b04673da98fdc4e"
    },
    "CVE-2026-40200.patch": {
        "sha256": "1ee29f64f9ca8e8ad7c349779d661ff6b52126a27575d3586981357a52c406fb",
        "sha512": "a64ab7688d1a85e560b5687783df482d2467a79a74400da5a1601382847d6b4e6a79b7529a8dc80c46ddda8dc2a812f2261557fc8ee98dc3bdf7322761bd6d9c"
    },
    "CVE-2026-6042.patch": {
        "sha256": "1d0be2e72b9d5bd16546b923aa8af861d271322f01644716a81823bec4065c99",
        "sha512": "f7849abeab0e4eab992a80464afa07b9c8aae5cee76040523b9dbc0931435f28ea8f5792b8a4a0cd6d608ac2f37e3225e89afcb3171a0a6df44450ed57cee83b"
    },
    "__stack_chk_fail_local.c": {
        "sha256": "299a7d75a09de3e2e11e7fb4acc3182e4a14e868093d2f30938fce9bfcff13da",
        "sha512": "062bb49fa54839010acd4af113e20f7263dde1c8a2ca359b5fb2661ef9ed9d84a0f7c3bc10c25dcfa10bb3c5a4874588dff636ac43d5dbb3d748d75400756d0b"
    },
    "fix-loongarch64-zero-len-extcontext.patch": {
        "sha256": "92c8e965798ed516c15cb2a4e7c4ac45ec1eb68b6abff16c73adff2a3bae1b14",
        "sha512": "6eae45aa82db69bc96386aedf3d1bfe83dfa0a7b4b824326c1c7e1bab31100d635ed0e8930c26a1694697fad59167a42e2b5f3a2ac51b07e36d85f047e268cff"
    },
    "getconf.c": {
        "sha256": "d87d0cbb3690ae2c5d8cc218349fd8278b93855dd625deaf7ae50e320aad247c",
        "sha512": "0d80f37b34a35e3d14b012257c50862dfeb9d2c81139ea2dfa101d981d093b009b9fa450ba27a708ac59377a48626971dfc58e20a3799084a65777a0c32cbc7d"
    },
    "getent.c": {
        "sha256": "a6171c2db641cdd99c164169d3c5c6ca323617483cedec4cbbe3eb39c5834df0",
        "sha512": "246e029350d4295147fe311108dcfb991ef130271b856040c1fb6a9955414f263d2a51f978b8ae91f52ff49705e8e4572b8f0e6939801fa854e3f095a67d3d64"
    },
    "handle-aux-at_base.patch": {
        "sha256": "2a65e03b94217063d72fe998e5fb2e25cd01716078a3ba1b0ab574ab205111e6",
        "sha512": "a76f79b801497ad994746cf82bb6eaf86f9e1ae646e6819fbae8532a7f4eee53a96ac1d4e789ec8f66aea2a68027b0597f7a579b3369e01258da8accfce41370"
    },
    "iconv.c": {
        "sha256": "f79a2930a2e5bb0624321589edf8b889d1e9b603e01e6b7ae214616605b3fdd7",
        "sha512": "9d42d66fb1facce2b85dad919be5be819ee290bd26ca2db00982b2f8e055a0196290a008711cbe2b18ec9eee8d2270e3b3a4692c5a1b807013baa5c2b70a2bbf"
    },
    "ldconfig": {
        "sha256": "7065021e04a5060957b5c6907af671a7028230d91927fb0c25892cadd9312b7c",
        "sha512": "29da5e89358103846a42987c2a5ff26ec131e29a6a7a714cd0e2941baf1f1e5cd9b1ee66f488c8e222135031bf2de507d7d05b037ab65c30482147dba63d2e52"
    }
}
ATTRIBUTION_SOURCES = {
    "musl-1.2.6/src/complex/ccoshf.c": "6ebf4355682268356685ba79621a47f2f955ca910bf13ca6ed32bb52e893574f",
    "musl-1.2.6/src/crypt/crypt_blowfish.c": "0f9054739e295e3e981e7aa29c8f287a190aef065b84a82a4c6817120d5da05d",
    "musl-1.2.6/src/crypt/crypt_des.c": "546b4ee35446fb2a551d7414779395789f81d53aefbabd8914375686af5d228e",
    "musl-1.2.6/src/math/__tanl.c": "3788db7251d2e14b17e761bc2eccd0d8faa3c72c16eef7a56ca2ca75eca177df",
    "musl-1.2.6/src/math/exp.c": "7db56f21ca9b8915d36dd5099b707aafeb6a736eae798e19b76b074764e75f34",
    "musl-1.2.6/src/math/expm1l.c": "a8362abd18ef31f00a7dd74c8b618ef658a4e9c3919c456d03d65a12fe445c2f",
    "musl-1.2.6/src/math/fmaf.c": "e5baf54228b74b036da629902d811f9f57de26133a03ce290879b5ec6de04433",
    "musl-1.2.6/src/math/sincos.c": "2b88cfba380b8d5aa8f8f6b9f055aee91fe112de9f967a4484807afcb5405d9d",
    "musl-1.2.6/src/regex/regcomp.c": "56b0a765e084a5cd3ed7113a893b50d259265ba76b6bea98889c45d7aec302a0",
    "musl-1.2.6/src/stdlib/qsort.c": "dc9a8fd43bd2c98c437c05c214a8715df22ed746a2912969eb154fa9090213f4",
    "musl-1.2.6/src/string/aarch64/memcpy.S": "1ead3716276e8a58e2e015e89fd565d9f33c10b2bc482c303b68b90c9d0f7cef"
}
ROOT = Path(__file__).resolve().parents[1]


def serialized(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def loader_path(architecture):
    if architecture not in ARCHES:
        raise ValueError('Unsupported musl architecture')
    return 'lib/ld-musl-' + ARCHES[architecture] + '.so.1'


def aliases(architecture):
    return {'/lib/libc.musl-' + ARCHES[architecture] + '.so.1':
            Path(loader_path(architecture)).name}


def expected_fields(name, architecture):
    loader_path(architecture)
    if name == 'musl':
        return {'depend': [], 'provides': ['so:libc.musl-' + ARCHES[architecture] + '.so.1=1']}
    if name == 'musl-dev':
        return {'depend': ['musl=' + VERSION], 'provides': ['libc-dev=' + VERSION]}
    raise ValueError('Unsupported musl package')


def reviewed_spec(root=None):
    spec = {
        'origin': 'musl', 'version': VERSION, 'source_method': 'alpine-signed-musl-v1',
        'recipe': {'path': 'main/musl/APKBUILD', 'revision': BUILD_COMMIT,
                   'url': APKBUILD_URL, 'sha256': APKBUILD_SHA256,
                   'archive_url': APORTS_URL, 'archive_sha256': APORTS_SHA256,
                   'context_files': {name: dict(row) for name, row in CONTEXT_FILES.items()}},
        'source': {'url': SOURCE_URL, 'sha256': SOURCE_SHA256, 'sha512': SOURCE_SHA512,
                   'signature_url': SOURCE_URL + '.asc', 'signature_sha256': SIGNATURE_SHA256,
                   'license_path': 'musl-1.2.6/COPYRIGHT', 'license_sha256': COPYRIGHT_SHA256,
                   'attribution_sources': dict(ATTRIBUTION_SOURCES)},
        'patch': {'path': 'main/musl/CVE-2026-107891.patch', 'url': PATCH_URL,
                  'sha256': PATCH_SHA256, 'sha512': PATCH_SHA512,
                  'upstream_commit': UPSTREAM_COMMIT},
        'signing_keys': {arch: {**key, 'url': 'https://alpinelinux.org/keys/' + key['name']}
                         for arch, key in KEYS.items()},
    }
    for field, name in [('packages', 'musl'), ('build_only_packages', 'musl-dev')]:
        spec[field] = [{'name': name, 'version': VERSION, 'license': 'MIT',
                        'build_commit': BUILD_COMMIT, 'binaries': {arch: {
                            'url': 'https://dl-cdn.alpinelinux.org/alpine/v3.24/main/'
                                   + native + '/' + name + '-' + VERSION + '.apk',
                            'sha256': BINARY_SHA256[arch][name],
                            'pkginfo_sha256': PKGINFO_SHA256[arch][name],
                            **({'library_sha256': LOADER_SHA256[arch]} if name == 'musl'
                               else {'payload_inventory_sha256': DEV_INVENTORY_SHA256[arch]}),
                        } for arch, native in ARCHES.items()}}]
    if root is not None:
        rows = [row for row in json.loads((Path(root) / 'docs/os-package-sources.json').read_bytes())['origins']
                if row.get('origin') == 'musl']
        if serialized(rows) != serialized([spec]):
            raise ValueError('musl source map differs from the exact reviewed Alpine origin')
    return spec


def source_lock_bytes(package_spec):
    if serialized(package_spec) != serialized(reviewed_spec()):
        raise ValueError('musl source map differs from the exact reviewed Alpine origin')
    return (json.dumps(package_spec, sort_keys=True, indent=2) + '\n').encode()


def payload_inventory(payload):
    rows = []
    for name, entry in sorted(payload.items()):
        member, body = entry['member'], entry['body']
        if (PurePosixPath(name).as_posix() != name or member.name != name
                or PurePosixPath(name).is_absolute() or '..' in PurePosixPath(name).parts
                or '\\' in name or member.uid != 0 or member.gid != 0):
            raise ValueError('Unsafe musl payload path or ownership')
        if member.isdir():
            kind = 'directory'
        elif member.issym():
            kind = 'symlink'
        elif member.isfile() and body is not None:
            kind = 'file'
        else:
            raise ValueError('Unsupported musl payload type')
        row = {'path': name, 'type': kind, 'mode': member.mode,
               'uid': member.uid, 'gid': member.gid}
        if kind == 'file':
            row.update(bytes=len(body), sha256=hashlib.sha256(body).hexdigest())
        elif kind == 'symlink':
            row['target'] = member.linkname
        rows.append(row)
    return rows


def core_inventory(architecture):
    loader = loader_path(architecture)
    alias, target = next(iter(aliases(architecture).items()))
    return [
        {'path': 'lib', 'type': 'directory', 'mode': 0o755, 'uid': 0, 'gid': 0},
        {'path': loader, 'type': 'file', 'mode': 0o755, 'uid': 0, 'gid': 0,
         'sha256': LOADER_SHA256[architecture]},
        {'path': alias.lstrip('/'), 'type': 'symlink', 'mode': 0o777, 'uid': 0, 'gid': 0,
         'target': target},
    ]


def verify_apk(body, name, architecture, key):
    expected = expected_fields(name, architecture)
    checked(body, 'sha256', BINARY_SHA256[architecture][name], name + ' APK')
    checked(key, 'sha256', KEYS[architecture]['sha256'], 'Alpine signing key')
    parts = gzip_parts(body)
    signs = tar_entries(parts[0][1])
    signature = '.SIGN.RSA.' + KEYS[architecture]['name']
    if set(signs) != {signature} or signs[signature]['body'] is None:
        raise ValueError('musl APK signing key name mismatch')
    verify_rsa(signs[signature]['body'], parts[1][0], key)
    control = tar_entries(parts[1][1])
    if set(control) != {'.PKGINFO'} or control['.PKGINFO']['body'] is None:
        raise ValueError('musl APK must contain only regular metadata without install scripts')
    metadata = control['.PKGINFO']['body']
    checked(metadata, 'sha256', PKGINFO_SHA256[architecture][name], 'musl APK metadata')
    fields = metadata_fields(metadata)
    identity = {'pkgname': name, 'pkgver': VERSION, 'origin': 'musl',
                'arch': ARCHES[architecture], 'commit': BUILD_COMMIT, 'license': 'MIT',
                'url': 'https://musl.libc.org/', 'datahash': hashlib.sha256(parts[2][0]).hexdigest()}
    if any(fields.get(field) != [value] for field, value in identity.items()):
        raise ValueError('musl APK identity, license or payload hash mismatch')
    for field in ('depend', 'provides', 'replaces', 'install_if', 'triggers'):
        if sorted(fields.get(field, [])) != sorted(expected.get(field, [])):
            raise ValueError('musl APK dependency or SONAME provision mismatch')
    payload = tar_entries(parts[2][1])
    inventory = payload_inventory(payload)
    if name == 'musl':
        expected_inventory = core_inventory(architecture)
        if len(inventory) != len(expected_inventory):
            raise ValueError('musl APK has unexpected payload members')
        for actual, reviewed in zip(inventory, expected_inventory):
            if any(actual.get(field) != value for field, value in reviewed.items()):
                raise ValueError('musl APK canonical loader or libc alias differs')
    else:
        alias = 'usr/lib/libc.so'
        for row in inventory:
            if row['path'] not in {'usr', 'usr/include', 'usr/lib'} and not row['path'].startswith(('usr/include/', 'usr/lib/')):
                raise ValueError('musl-dev APK has unexpected payload members')
            if row['type'] == 'symlink' and (row['path'] != alias
                    or row['target'] != '../../' + loader_path(architecture)):
                raise ValueError('musl-dev APK libc alias differs')
        entry = payload.get(alias, {}).get('member')
        if entry is None or not entry.issym() or entry.linkname != '../../' + loader_path(architecture):
            raise ValueError('musl-dev APK libc alias differs')
        if hashlib.sha256(serialized(inventory)).hexdigest() != DEV_INVENTORY_SHA256[architecture]:
            raise ValueError('musl-dev APK payload inventory differs')
    return metadata, {**identity, 'apk_sha256': BINARY_SHA256[architecture][name],
                      'pkginfo_sha256': PKGINFO_SHA256[architecture][name],
                      'signature_verified': True, 'signing_key_sha256': KEYS[architecture]['sha256']}


def security_manifest(package_spec, architecture):
    lock = source_lock_bytes(package_spec)
    loader = loader_path(architecture)
    def package(name):
        return {'name': name, 'version': VERSION, 'apk_sha256': BINARY_SHA256[architecture][name],
                'pkginfo_sha256': PKGINFO_SHA256[architecture][name], 'signature_verified': True,
                'signing_key_sha256': KEYS[architecture]['sha256']}
    return {'schema': 'keep-musl-security-v1', 'architecture': architecture,
            'version': UPSTREAM_VERSION, 'package_version': VERSION, 'build_commit': BUILD_COMMIT,
            'upstream_commit': UPSTREAM_COMMIT, 'archive_sha256': SOURCE_SHA256,
            'source_manifest_sha256': hashlib.sha256(lock).hexdigest(),
            'library': {'path': '/' + loader, 'soname': 'libc.musl-' + ARCHES[architecture] + '.so.1',
                        'sha256': LOADER_SHA256[architecture]},
            'aliases': aliases(architecture), 'packages': [package('musl')],
            'build_only_packages': [package('musl-dev')],
            'dev_payload_inventory_sha256': DEV_INVENTORY_SHA256[architecture]}


def build_security_manifest(architecture, root=ROOT):
    return security_manifest(reviewed_spec(root), architecture)


def prepare(root, package_spec, architecture, fetch, records):
    lock = source_lock_bytes(package_spec)
    loader_path(architecture)
    retain(root, records, 'source-lock.json', lock, 'reviewed-source-lock:musl', 'reviewed-source-lock')
    signing = package_spec['signing_keys'][architecture]
    key = checked(fetch(signing['url']), 'sha256', signing['sha256'], 'Alpine signing key')
    retain(root, records, 'keys/' + signing['name'], key, signing['url'], 'alpine-signing-key')
    identities = []
    for row in package_spec['packages'] + package_spec['build_only_packages']:
        name, binary = row['name'], row['binaries'][architecture]
        body = checked(fetch(binary['url']), 'sha256', binary['sha256'], name + ' APK')
        metadata, identity = verify_apk(body, name, architecture, key)
        filename = name + '-' + VERSION + '.apk'
        retain(root, records, filename, body, binary['url'], 'signed-alpine-binary-evidence')
        retain(root, records, filename + '.PKGINFO', metadata, binary['url'], 'package-build-identity')
        identities.append(identity)
    installation = security_manifest(package_spec, architecture)
    retain(root, records, 'MUSL_SECURITY.json',
           (json.dumps(installation, sort_keys=True, indent=2) + '\n').encode(),
           'verified-alpine-packages:musl', 'runtime-installation-manifest')
    return installation, identities


def prepare_packages(package_spec, architecture, output_root, fetch=download):
    source_lock_bytes(package_spec)
    loader_path(architecture)
    return prepare(empty_output(output_root), package_spec, architecture, fetch, [])[0]


def recipe_identity(body):
    text = body.decode('utf-8')
    for field, value in {'pkgname': 'musl', 'pkgver': UPSTREAM_VERSION,
                         'pkgrel': '3', 'license': '"MIT"'}.items():
        if re.findall(r'^' + field + r'=([^\n]+)$', text, re.M) != [value]:
            raise ValueError('musl APKBUILD identity mismatch')
    blocks = re.findall(r'^source="([^"]*)"', text, re.M)
    expected_sources = ['https://musl.libc.org/releases/musl-$pkgver.tar.gz', *CONTEXT_FILES]
    if len(blocks) != 1 or sorted(blocks[0].split()) != sorted(expected_sources):
        raise ValueError('musl APKBUILD source declaration mismatch')
    sums = re.findall(r'^sha512sums="\n([^"]*)"', text, re.M)
    rows = [] if len(sums) != 1 else [line.split('  ') for line in sums[0].splitlines()]
    expected_sums = {'musl-1.2.6.tar.gz': SOURCE_SHA512,
                     **{name: row['sha512'] for name, row in CONTEXT_FILES.items()}}
    if (len(rows) != len(expected_sums) or any(len(row) != 2 for row in rows)
            or {row[1]: row[0] for row in rows} != expected_sums):
        raise ValueError('musl APKBUILD source or patch checksum mismatch')
    if '#   ' + VERSION + ':\n#     - CVE-2026-107891\n' not in text:
        raise ValueError('musl APKBUILD lacks the reviewed security-fix declaration')


def context_files(body):
    prefix = 'aports-' + BUILD_COMMIT + '/main/musl/'
    files, total = {}, 0
    with tarfile.open(fileobj=io.BytesIO(body), mode='r:*') as archive:
        for count, member in enumerate(archive, 1):
            total += member.size
            if count > 250000 or total > 512 * 1024 * 1024:
                raise ValueError('musl aports context exceeds inventory limit')
            if not member.name.startswith(prefix) or member.isdir():
                continue
            name = member.name[len(prefix):]
            if name not in {'APKBUILD', *CONTEXT_FILES} or name in files or not member.isfile():
                raise ValueError('Unexpected or ambiguous musl aports context file')
            files[name] = archive.extractfile(member).read()
    if set(files) != {'APKBUILD', *CONTEXT_FILES}:
        raise ValueError('Incomplete musl aports context')
    checked(files['APKBUILD'], 'sha256', APKBUILD_SHA256, 'musl APKBUILD')
    recipe_identity(files['APKBUILD'])
    for name, expected in CONTEXT_FILES.items():
        checked(files[name], 'sha256', expected['sha256'], 'musl recipe input ' + name)
        checked(files[name], 'sha512', expected['sha512'], 'musl recipe input ' + name)
    patch = files['CVE-2026-107891.patch']
    checked(patch, 'sha256', PATCH_SHA256, 'musl security patch')
    checked(patch, 'sha512', PATCH_SHA512, 'musl security patch')
    if not patch.startswith(('>From ' + UPSTREAM_COMMIT + ' ').encode()):
        raise ValueError('musl patch has the wrong upstream fix identity')
    return files


def collect_sources(package_spec, architecture, runtime_inventory, output_root, fetch=download):
    source_lock_bytes(package_spec)
    loader_path(architecture)
    rows = [row for row in runtime_inventory.get('os_packages', [])
            if row.get('origin') == 'musl' or row.get('name') in {'musl', 'musl-dev', 'musl-utils'}]
    expected = {'name': 'musl', 'version': VERSION, 'origin': 'musl', 'license': 'MIT',
                'build_commit': BUILD_COMMIT, 'url': 'https://musl.libc.org/'}
    if len(rows) != 1 or any(rows[0].get(field) != value for field, value in expected.items()):
        raise ValueError('Actual runtime musl package identity mismatch')
    root, records = empty_output(output_root), []
    installation, identities = prepare(root, package_spec, architecture, fetch, records)
    recipes = checked(fetch(APORTS_URL), 'sha256', APORTS_SHA256, 'Complete musl aports context')
    files = context_files(recipes)
    retain(root, records, 'aports-' + BUILD_COMMIT + '.tar.gz', recipes,
           APORTS_URL, 'complete-alpine-build-recipes')
    for name, body in files.items():
        role = 'matching-apk-build-script' if name == 'APKBUILD' else (
            'matching-apk-build-patch' if name.endswith('.patch') else 'matching-apk-build-source')
        retain(root, records, 'context/main/musl/' + name, body,
               'https://raw.githubusercontent.com/alpinelinux/aports/' + BUILD_COMMIT + '/main/musl/' + name,
               role, 'aports-' + BUILD_COMMIT + '/main/musl/' + name)
    source = checked(fetch(SOURCE_URL), 'sha256', SOURCE_SHA256, 'musl upstream source')
    checked(source, 'sha512', SOURCE_SHA512, 'musl recipe source')
    retain(root, records, 'musl-1.2.6.tar.gz', source, SOURCE_URL, 'upstream-source')
    signature = checked(fetch(SOURCE_URL + '.asc'), 'sha256', SIGNATURE_SHA256, 'musl upstream signature')
    retain(root, records, 'musl-1.2.6.tar.gz.asc', signature, SOURCE_URL + '.asc', 'upstream-detached-signature')
    copying = checked(read_member(source, 'musl-1.2.6/COPYRIGHT'), 'sha256', COPYRIGHT_SHA256, 'musl full notice')
    retain(root, records, 'musl-1.2.6-COPYRIGHT', copying, SOURCE_URL, 'upstream-notice', 'musl-1.2.6/COPYRIGHT')
    for name, expected_hash in ATTRIBUTION_SOURCES.items():
        body = checked(read_member(source, name), 'sha256', expected_hash, 'musl attribution source')
        retain(root, records, 'attribution/' + name, body, SOURCE_URL,
               'upstream-permissive-attribution-source', name)
    retain(root, records, 'runtime-musl-identity.json',
           (json.dumps({'os_packages': rows}, sort_keys=True, indent=2) + '\n').encode(),
           'verified-candidate-runtime:/lib/apk/db/installed', 'runtime-package-build-identity')
    manifest = {'schema': 1, 'origin': 'musl', 'version': VERSION, 'architecture': architecture,
                'build_commit': BUILD_COMMIT, 'provider_oci_binding': False, 'source_image_digest': None,
                'binding_method': 'signed-alpine-packages', 'package_inputs': identities,
                'source_manifest_sha256': installation['source_manifest_sha256'],
                'installation_manifest_sha256': hashlib.sha256((root / 'MUSL_SECURITY.json').read_bytes()).hexdigest(),
                'files': records, 'upstream_signature_verified': False,
                'coverage': 'Exact Alpine-signed runtime musl and build-only musl-dev APKs, native runtime '
                            'identity, complete pinned aports context and all recipe inputs, checksum-matching '
                            'upstream source, full COPYRIGHT and selected permissive attribution sources. '
                            'The retained upstream signature has no separate OpenPGP verification claim; '
                            'no Docker package-build or source-image attestation is claimed.'}
    (root / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    return manifest


def installed_stat(path):
    return path.lstat()


def verify_entries(root, inventory):
    for row in inventory:
        path = root / row['path']
        if path.parent.resolve() != path.parent.absolute():
            raise ValueError('Installed musl path has a noncanonical parent')
        before = installed_stat(path)
        if (stat.S_IMODE(before.st_mode) != row['mode']
                or before.st_uid != row['uid'] or before.st_gid != row['gid']):
            raise ValueError('Installed musl ownership or mode differs')
        kind = row['type']
        if kind == 'directory':
            if not stat.S_ISDIR(before.st_mode):
                raise ValueError('Installed musl directory differs')
        elif kind == 'symlink':
            if not stat.S_ISLNK(before.st_mode) or os.readlink(path) != row['target']:
                raise ValueError('Installed musl alias differs')
        elif (not stat.S_ISREG(before.st_mode) or path.resolve() != path.absolute()
              or before.st_size > 64 * 1024 * 1024
              or 'bytes' in row and before.st_size != row['bytes']):
            raise ValueError('Installed musl file is not the canonical reviewed file')
        else:
            checked(path.read_bytes(), 'sha256', row['sha256'], 'Installed musl file')
        after = installed_stat(path)
        stable = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_size',
                  'st_mtime_ns', 'st_ctime_ns')
        if any(getattr(before, field) != getattr(after, field) for field in stable):
            raise ValueError('Installed musl file changed during verification')


def regular_file(path):
    if path.is_symlink() or not path.is_file() or path.resolve() != path.absolute():
        raise ValueError('musl preparation input must be a canonical regular file')
    return path


def verify_database(root, architecture, names):
    database = regular_file(root / 'lib/apk/db/installed').read_text()
    records = {}
    for block in database.split('\n\n'):
        fields = {}
        for line in block.splitlines():
            if len(line) > 1 and line[1] == ':' and line[0] in 'PVAcLoUDp':
                if line[0] in fields:
                    raise ValueError('Duplicate installed musl package field')
                fields[line[0]] = line[2:]
        name = fields.get('P')
        if name not in names:
            if names == ['musl'] and fields.get('o') == 'musl':
                raise ValueError('Unexpected musl subpackage in runtime')
            continue
        if name in records:
            raise ValueError('Duplicate installed musl package identity')
        expected = {'P': name, 'V': VERSION, 'A': ARCHES[architecture], 'o': 'musl',
                    'c': BUILD_COMMIT, 'L': 'MIT', 'U': 'https://musl.libc.org/'}
        if any(fields.get(field) != value for field, value in expected.items()):
            raise ValueError('Installed musl APK identity differs')
        for code, field in [('D', 'depend'), ('p', 'provides')]:
            if sorted(fields.get(code, '').split()) != sorted(expected_fields(name, architecture)[field]):
                raise ValueError('Installed musl APK dependencies or provisions differ')
        records[name] = fields
    if set(records) != set(names):
        raise ValueError('Missing installed musl package identity')


def checked_manifest(architecture, manifest):
    expected = build_security_manifest(architecture, root=None)
    if serialized(manifest) != serialized(expected):
        raise ValueError('musl installation manifest differs from reviewed packages')
    return expected


def verify_installed(architecture, manifest, runtime_root='/'):
    checked_manifest(architecture, manifest)
    root = Path(runtime_root).resolve()
    verify_entries(root, core_inventory(architecture))
    verify_database(root, architecture, ['musl'])
    return manifest


def prepared_payloads(prepared_root, architecture):
    loader_path(architecture)
    root = Path(prepared_root)
    if root.is_symlink() or root.resolve() != root.absolute():
        raise ValueError('musl prepared root must be canonical without symlinks')
    root = root.resolve()
    manifest = json.loads(regular_file(root / 'MUSL_SECURITY.json').read_bytes())
    checked_manifest(architecture, manifest)
    if regular_file(root / 'source-lock.json').read_bytes() != source_lock_bytes(reviewed_spec()):
        raise ValueError('musl preparation source lock differs')
    keys = root / 'keys'
    if keys.is_symlink() or {p.name for p in keys.iterdir()} != {KEYS[architecture]['name']}:
        raise ValueError('Unreviewed musl preparation signing key')
    key = regular_file(keys / KEYS[architecture]['name']).read_bytes()
    checked(key, 'sha256', KEYS[architecture]['sha256'], 'Alpine signing key')
    payloads = {}
    for name in ('musl', 'musl-dev'):
        path = regular_file(root / (name + '-' + VERSION + '.apk'))
        body = path.read_bytes()
        metadata, _ = verify_apk(body, name, architecture, key)
        if regular_file(path.with_name(path.name + '.PKGINFO')).read_bytes() != metadata:
            raise ValueError('musl prepared metadata differs from signed APK')
        payloads[name] = (path, payload_inventory(tar_entries(gzip_parts(body)[2][1])))
    return payloads


def build_installation_inputs(prepared_root, architecture):
    return [prepared_payloads(prepared_root, architecture)['musl-dev'][0]]


def verify_build_installed(architecture, manifest, prepared_root, runtime_root='/'):
    checked_manifest(architecture, manifest)
    payloads = prepared_payloads(prepared_root, architecture)
    root = Path(runtime_root).resolve()
    verify_entries(root, payloads['musl'][1])
    verify_entries(root, payloads['musl-dev'][1])
    verify_database(root, architecture, ['musl', 'musl-dev'])
    return manifest


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--verify-installed', action='store_true')
    mode.add_argument('--verify-build', action='store_true')
    parser.add_argument('--architecture', required=True, choices=ARCHES)
    parser.add_argument('--manifest', required=True, type=Path)
    parser.add_argument('--prepared-root', type=Path)
    args = parser.parse_args(argv)
    manifest = json.loads(args.manifest.read_bytes())
    if args.verify_build:
        if args.prepared_root is None:
            parser.error('--verify-build requires --prepared-root')
        verify_build_installed(args.architecture, manifest, args.prepared_root)
    else:
        verify_installed(args.architecture, manifest)


if __name__ == '__main__':
    main()
