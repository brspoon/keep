#!/usr/bin/env python3
"""Verify the exact signed build-only C++ inputs without changing the C compiler.

The package manager runs offline with scripts disabled. Its installed files and
hardlink aliases must match the complete signed payload before Expat configures.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import platform
import stat
import subprocess
import tarfile

if __package__:
    from .dhi_python_packages import checked, download, gzip_parts, metadata_fields, verify_rsa
else:
    from dhi_python_packages import checked, download, gzip_parts, metadata_fields, verify_rsa


VERSION = '15.2.0-r7'
BUILD_COMMIT = 'ddcf93c394b61ccf6be91b915a92a7454a14fcba'
LICENSE = 'GPL-2.0-or-later AND LGPL-2.1-or-later'
ARCHES = {'amd64': 'x86_64', 'arm64': 'aarch64'}
PACKAGES = ('g++', 'libstdc++-dev')
KEY_NAME = 'dhi-apk@docker-0F81AD7700D99184.rsa.pub'
KEY_SHA256 = '0003d0ae2bf20db9669f784d6ccd5d52265cb1b73fdb14f5186b348b3308f0cd'
KEY_URL = 'https://dhi.io/keyring/' + KEY_NAME
PREPARED_ROOT = Path('/opt/build-cpp')
LIMIT = 64 * 1024 * 1024
APK_SHA256 = {
    'amd64': {'g++': '355ab6821be1969fad319ce774f8b0e1a51158e9f27065f75478fda5aa1f6a7e',
              'libstdc++-dev': 'd98e3f81bf5995356525cc908b60e2252d59c86b38a417bcdb4d4008ce1e42b3'},
    'arm64': {'g++': 'ddeaf586e369190b045e0a47f27b607c367ee001a1c5f00b99450d0358d878f8',
              'libstdc++-dev': '35d53729002314bb547781917194fa756d65d083cc5691a4a52845dd7dff32e5'},
}
PKGINFO_SHA256 = {
    'amd64': {'g++': '7b0bb38d3683b0f01402cc916c3c746591be89ce994aa885b435f91c19c983f4',
              'libstdc++-dev': '10e9228c6f212f1c19125e6405222e6f99946e5ccc39b79e2d6f08d3f69eeb15'},
    'arm64': {'g++': '5525bdcbbe57bb58db231fa3afd60fa601e5f7d5b46cbbe6d41d15c9b30d0970',
              'libstdc++-dev': 'b8d9472c6fc7c27d7fbcaf67a3e9e2ef643d37b9d90a7d110b374f96083298c8'},
}
DATA_SHA256 = {
    'amd64': {'g++': '2b85abd29682fc5130ef8b378f9fee3f085180f29ce01aa9d5b90174ee0bf496',
              'libstdc++-dev': '56c2cabd61fb2112db708c0363482c81fe91365f8aaed2338ea3db7c504b0f29'},
    'arm64': {'g++': 'aef88ed1fc1d6c5933cb37bf50ddb0fcb97accd91d0f262e6f602af93f41840b',
              'libstdc++-dev': '4e6e96a8e72199f9a58c06f98849cde1d131de9f36707f70d0f29df847dacbaf'},
}
PAYLOAD_SHA256 = {
    'amd64': {'g++': '067f1ce44b9e0ce261083619fee865a3ce4f08da3b38af8a92ac22263da079a3',
              'libstdc++-dev': 'd076ddec58e4386826f30a7b8d8684f495c5632f53e8daa53620f9477f462380'},
    'arm64': {'g++': '5ff632839094f8fac17fd279590db2b32a24460182792d1f38b72fcd3540b51f',
              'libstdc++-dev': 'cfbd8990e9b2f7edcc8809d1e6fa166cc291541351c3a6c12e36beebcbd3fcc3'},
}
# These files belong to the unchanged, signed development-image package cohort.
COHORT_FILES = {
    'amd64': {'usr/bin/gcc': 'cd314c5e8159e9984b63685b98a04797b4f77af3c1f771c27f240d3491a4f89c',
              'usr/lib/libstdc++.so.6.0.34': 'cdcb4026e2372f703c5c9eb9b967a29ff9002b07d732d3060fb2102083fdf52e'},
    'arm64': {'usr/bin/gcc': 'b006211469e77f67bb5ba4c72f94242ae69f6d989d8e13e73113a6fdeca715db',
              'usr/lib/libstdc++.so.6.0.34': '3e1212917fc686611dd17dd1df8e06a61eef9c08309d3e34c8516975d5a6e8f2'},
}
COHORT_APK_SHA256 = {
    'amd64': {'gcc': '498f20fa6658279a911f0358df6d5726a51ccc40f57a00dfd9871445126026db',
              'libstdc++': '967d7c1f8c21daa1b1e3ae1feafcfacd0278e2cbf143693fae9c2f2690f67257'},
    'arm64': {'gcc': '1939c626eaa94bf14d9d4c80c7078d8c2ccd68c4caf5e644aa60b83c6966c5cb',
              'libstdc++': 'd62d3b0f270635020079ba131f3cadf1bf8a8dc66324d6d6696c5abf88522f48'},
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def digest(body):
    return hashlib.sha256(body).hexdigest()


def target(architecture):
    require(architecture in ARCHES, 'Unsupported C++ build architecture')
    return ARCHES[architecture] + '-alpine-linux-musl'


def package_url(name, architecture):
    require(name in PACKAGES, 'Unsupported C++ build package')
    return ('https://dhi.io/apk/alpine/v3.24/main/' + ARCHES[architecture]
            + '/' + name + '-' + VERSION + '.apk')


def expected_fields(name, architecture):
    if name == 'libstdc++-dev':
        return {'depend': ['libstdc++=' + VERSION], 'provides': ['++_dev_provides'],
                'replaces': ['g++']}
    return {'depend': ['libstdc++-dev=' + VERSION, 'gcc=' + VERSION, 'musl-dev',
                       'libstdc++=' + VERSION, 'so:libc.musl-' + ARCHES[architecture] + '.so.1',
                       'so:libgmp.so.10', 'so:libisl.so.23', 'so:libmpc.so.3',
                       'so:libmpfr.so.6', 'so:libz.so.1'],
            'provides': ['++_provides', *['cmd:' + command + '=' + VERSION for command in
                        ('c++', 'g++', target(architecture) + '-c++', target(architecture) + '-g++')]],
            'replaces': ['++_replaces']}


def reviewed_spec():
    return {'schema': 'keep-dhi-cpp-build-inputs-v1', 'origin': 'gcc', 'version': VERSION,
            'build_commit': BUILD_COMMIT, 'license': LICENSE, 'installation': 'build-only-offline-apk',
            'signing_key': {'name': KEY_NAME, 'sha256': KEY_SHA256, 'url': KEY_URL},
            'unchanged_cohort_files': COHORT_FILES,
            'unchanged_cohort_apk_sha256': COHORT_APK_SHA256,
            'packages': {arch: {name: {'url': package_url(name, arch),
                'sha256': APK_SHA256[arch][name], 'pkginfo_sha256': PKGINFO_SHA256[arch][name],
                'data_sha256': DATA_SHA256[arch][name], 'payload_sha256': PAYLOAD_SHA256[arch][name],
                **expected_fields(name, arch)} for name in PACKAGES} for arch in ARCHES}}


def source_lock_bytes():
    return json_bytes(reviewed_spec())


def source_download_records():
    return [{'path': arch + '/' + name + '-' + VERSION + '.apk',
             'url': package_url(name, arch), 'sha256': APK_SHA256[arch][name],
             'role': 'vendor-build-only-apk'} for arch in ARCHES for name in PACKAGES] + [
            {'path': 'keys/' + KEY_NAME, 'url': KEY_URL, 'sha256': KEY_SHA256,
             'role': 'vendor-apk-signing-key'}]


def safe_name(name):
    path = PurePosixPath(name)
    require(name and not path.is_absolute() and '..' not in path.parts and '\\' not in name
            and '\x00' not in name and path.as_posix() == name,
            'Unsafe C++ APK archive path')
    return name


def tar_entries(body):
    entries, total = {}, 0
    with tarfile.open(fileobj=io.BytesIO(body), mode='r:', ignore_zeros=True) as archive:
        for count, member in enumerate(archive, 1):
            name = safe_name(member.name)
            total += member.size
            require(count <= 4096 and 0 <= member.size <= LIMIT and total <= LIMIT
                    and name not in entries, 'Ambiguous or oversized C++ APK archive')
            require(member.isfile() or member.isdir() or member.issym() or member.islnk(),
                    'Unsupported C++ APK member type')
            require(member.uid == 0 and member.gid == 0 and not member.mode & 0o7000,
                    'Unsafe C++ APK ownership or mode')
            data = archive.extractfile(member).read() if member.isfile() else None
            require(data is None or len(data) == member.size, 'Truncated C++ APK entry')
            entries[name] = {'member': member, 'body': data}
    for name, entry in entries.items():
        member = entry['member']
        for parent in PurePosixPath(name).parents:
            if parent.as_posix() in entries:
                require(entries[parent.as_posix()]['member'].isdir(), 'C++ APK parent is not a directory')
        if member.islnk():
            link = safe_name(member.linkname)
            require(link in entries and entries[link]['member'].isfile()
                    and member.mode == entries[link]['member'].mode,
                    'C++ APK hardlink must target a regular member in the same payload')
        if member.issym():
            require(name == 'usr/lib/libstdc++.so' and member.linkname == 'libstdc++.so.6.0.34',
                    'Unreviewed C++ APK symbolic link')
    return entries


def payload_manifest(payload):
    rows = []
    for name, entry in sorted(payload.items()):
        member = entry['member']
        row = {'path': name, 'type': 'regular' if member.isfile() else 'directory' if member.isdir()
               else 'hardlink' if member.islnk() else 'symlink', 'linkname': member.linkname,
               'mode': member.mode, 'uid': member.uid, 'gid': member.gid, 'bytes': member.size}
        if entry['body'] is not None:
            row['sha256'] = digest(entry['body'])
        rows.append(row)
    return rows


def verify_apk(body, name, architecture, key):
    target(architecture)
    require(name in PACKAGES, 'Unsupported C++ build package')
    checked(body, APK_SHA256[architecture][name], 'C++ build APK')
    checked(key, KEY_SHA256, 'C++ build DHI signing key')
    parts = gzip_parts(body)
    signs = tar_entries(parts[0][1])
    signature = '.SIGN.RSA.' + KEY_NAME
    require(set(signs) == {signature} and signs[signature]['body'] is not None,
            'C++ build APK signing key name differs')
    verify_rsa(signs[signature]['body'], parts[1][0], key)
    control = tar_entries(parts[1][1])
    require(set(control) == {'.PKGINFO'} and control['.PKGINFO']['body'] is not None,
            'C++ build APK must contain metadata without install scripts')
    metadata = checked(control['.PKGINFO']['body'], PKGINFO_SHA256[architecture][name],
                       'C++ build APK metadata')
    datahash = digest(parts[2][0])
    require(datahash == DATA_SHA256[architecture][name], 'C++ build APK compressed payload differs')
    fields = metadata_fields(metadata)
    expected = {'pkgname': name, 'pkgver': VERSION, 'origin': 'gcc', 'arch': ARCHES[architecture],
                'commit': BUILD_COMMIT, 'license': LICENSE, 'url': 'https://gcc.gnu.org', 'datahash': datahash}
    require(all(fields.get(k) == [v] for k, v in expected.items()), 'C++ build APK identity differs')
    exact = expected_fields(name, architecture)
    for field in ('depend', 'provides', 'replaces', 'install_if', 'triggers'):
        require(sorted(fields.get(field, [])) == sorted(exact.get(field, [])),
                'C++ build APK dependencies or provisions differ')
    payload = tar_entries(parts[2][1])
    checked(json_bytes(payload_manifest(payload)), PAYLOAD_SHA256[architecture][name],
            'C++ build APK complete payload inventory')
    return metadata, payload


def regular_bytes(path, limit=LIMIT):
    path = Path(path)
    require(not path.is_symlink() and path.is_file() and path.resolve() == path.absolute()
            and path.stat().st_size <= limit, 'C++ input must be a bounded canonical regular file')
    body = path.read_bytes()
    require(len(body) <= limit, 'Oversized C++ input')
    return body


def empty_directory(path):
    path = Path(path).absolute()
    require(all(not parent.is_symlink() for parent in (path, *path.parents)),
            'C++ build output must not contain symlink ancestors')
    path.mkdir(parents=True, exist_ok=True)
    require(path.is_dir() and not any(path.iterdir()), 'C++ build output must be empty')
    return path


def prepare(output, *, architecture=None, fetch=download):
    architectures = list(ARCHES) if architecture is None else [architecture]
    require(all(arch in ARCHES for arch in architectures), 'Unsupported C++ build architecture')
    destination = empty_directory(output)
    key = checked(fetch(KEY_URL), KEY_SHA256, 'C++ build DHI signing key')
    (destination / 'keys').mkdir()
    (destination / 'keys' / KEY_NAME).write_bytes(key)
    files = [{'path': 'keys/' + KEY_NAME, 'url': KEY_URL, 'sha256': KEY_SHA256,
              'bytes': len(key), 'role': 'vendor-apk-signing-key'}]
    for arch in architectures:
        (destination / arch).mkdir()
        for name in PACKAGES:
            body = fetch(package_url(name, arch))
            metadata, _ = verify_apk(body, name, arch, key)
            relative = arch + '/' + name + '-' + VERSION + '.apk'
            for suffix, data, role in (('', body, 'vendor-build-only-apk'),
                                       ('.PKGINFO', metadata, 'vendor-build-only-apk-metadata')):
                (destination / (relative + suffix)).write_bytes(data)
                files.append({'path': relative + suffix, 'url': package_url(name, arch),
                              'bytes': len(data), 'sha256': digest(data), 'role': role})
    manifest = {'schema': 'keep-cpp-prepared-inputs-v1', 'architectures': architectures,
                'source_manifest_sha256': digest(source_lock_bytes()), 'files': files}
    (destination / 'CPP_BUILD_INPUTS.json').write_bytes(json_bytes(manifest))
    return manifest


def installation_inputs(output, architecture):
    target(architecture)
    root = Path(output).absolute()
    manifest = json.loads(regular_bytes(root / 'CPP_BUILD_INPUTS.json'))
    require(manifest.get('schema') == 'keep-cpp-prepared-inputs-v1'
            and architecture in manifest.get('architectures', [])
            and manifest.get('source_manifest_sha256') == digest(source_lock_bytes()),
            'C++ prepared input identity differs')
    require({path.name for path in (root / 'keys').iterdir()} == {KEY_NAME},
            'Unreviewed C++ build installation key')
    key = regular_bytes(root / 'keys' / KEY_NAME)
    paths, payloads = [], {}
    for name in PACKAGES:
        path = root / architecture / (name + '-' + VERSION + '.apk')
        metadata, payloads[name] = verify_apk(regular_bytes(path), name, architecture, key)
        require(regular_bytes(Path(str(path) + '.PKGINFO')) == metadata,
                'C++ retained metadata differs from signed APK')
        paths.append(path)
    return paths, payloads


def installed_records(runtime_root='/'):
    body = regular_bytes(Path(runtime_root) / 'lib/apk/db/installed', 16 * 1024 * 1024)
    records = {}
    for block in body.decode().split('\n\n'):
        fields = {}
        for line in block.splitlines():
            if len(line) > 1 and line[1] == ':' and line[0] in 'PVAcLoUDpr':
                require(line[0] not in fields, 'Duplicate C++ installed package field')
                fields[line[0]] = line[2:]
        if fields:
            require('P' in fields and fields['P'] not in records, 'Ambiguous installed C++ package database')
            records[fields['P']] = fields
    return records


def verify_cohort(architecture, runtime_root='/'):
    root = Path(runtime_root).absolute()
    require(set(COHORT_FILES) == set(ARCHES) and COHORT_FILES[architecture],
            'Missing reviewed C compiler and C++ runtime cohort')
    for name, expected in COHORT_FILES[architecture].items():
        checked(regular_bytes(root / name, LIMIT), expected, 'Unchanged C++ build dependency ' + name)
    alias = root / 'usr/lib/libstdc++.so.6'
    require(alias.is_symlink() and os.readlink(alias) == 'libstdc++.so.6.0.34',
            'Unchanged C++ runtime SONAME alias differs')
    records = installed_records(root)
    for name in ('gcc', 'libstdc++'):
        expected = {'P': name, 'V': VERSION, 'A': ARCHES[architecture], 'o': 'gcc',
                    'c': BUILD_COMMIT, 'L': LICENSE, 'U': 'https://gcc.gnu.org'}
        require(name in records and all(records[name].get(k) == v for k, v in expected.items()),
                'C++ build requires the unchanged reviewed native gcc and libstdc++ packages')
    return records


def verify_payload_installed(payload, runtime_root='/'):
    root = Path(runtime_root).absolute()
    for name, entry in payload.items():
        member, path = entry['member'], root / name
        require(all(not parent.is_symlink() for parent in path.parents),
                'Installed C++ payload has a symbolic-link ancestor')
        info = path.lstat()
        require(info.st_uid == member.uid and info.st_gid == member.gid
                and stat.S_IMODE(info.st_mode) == member.mode, 'Installed C++ payload ownership or mode differs')
        if member.isdir():
            require(stat.S_ISDIR(info.st_mode), 'Missing installed C++ payload directory')
        elif member.issym():
            require(path.is_symlink() and os.readlink(path) == member.linkname,
                    'Installed C++ symbolic link differs')
        elif member.islnk():
            original = root / member.linkname
            require(stat.S_ISREG(info.st_mode) and not original.is_symlink()
                    and (info.st_dev, info.st_ino) == (original.stat().st_dev, original.stat().st_ino),
                    'Installed C++ hardlink alias differs')
        else:
            require(stat.S_ISREG(info.st_mode) and regular_bytes(path) == entry['body'],
                    'Installed C++ regular payload differs: ' + name)


def installation_manifest(architecture):
    target(architecture)
    return {'schema': 'keep-cpp-build-security-v1', 'architecture': architecture,
            'source_manifest_sha256': digest(source_lock_bytes()), 'version': VERSION,
            'build_commit': BUILD_COMMIT, 'unchanged_cohort_files': COHORT_FILES[architecture],
            'packages': {name: {'apk_sha256': APK_SHA256[architecture][name],
                'pkginfo_sha256': PKGINFO_SHA256[architecture][name],
                'payload_sha256': PAYLOAD_SHA256[architecture][name],
                'signature_verified': True} for name in PACKAGES},
            'signing_key_sha256': KEY_SHA256, 'package_scripts_executed': False}


def verify_installed(architecture, *, prepared_root=PREPARED_ROOT, runtime_root='/'):
    _, payloads = installation_inputs(prepared_root, architecture)
    records = verify_cohort(architecture, runtime_root)
    for name, payload in payloads.items():
        expected = {'P': name, 'V': VERSION, 'A': ARCHES[architecture], 'o': 'gcc',
                    'c': BUILD_COMMIT, 'L': LICENSE, 'U': 'https://gcc.gnu.org'}
        require(name in records and all(records[name].get(k) == v for k, v in expected.items()),
                'Installed C++ package identity differs')
        for field, key in (('depend', 'D'), ('provides', 'p'), ('replaces', 'r')):
            require(sorted(records[name].get(key, '').split()) == sorted(expected_fields(name, architecture)[field]),
                    'Installed C++ package dependency or provision differs')
        verify_payload_installed(payload, runtime_root)
    return installation_manifest(architecture)


def native_architecture():
    require(platform.system() == 'Linux', 'C++ build package installation requires native Linux')
    arch = {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(platform.machine())
    require(arch in ARCHES, 'Unsupported native C++ architecture')
    return arch


def install(output, *, architecture=None):
    arch = native_architecture()
    require(architecture is None or architecture == arch, 'C++ build package cross-installation is forbidden')
    paths, _ = installation_inputs(output, arch)
    before = verify_cohort(arch)
    require(not any(name in before for name in PACKAGES), 'C++ build-only packages must be newly installed')
    subprocess.run(['/sbin/apk', 'add', '--no-network', '--repositories-file', '/dev/null',
                    '--keys-dir', str(Path(output).absolute() / 'keys'), '--no-cache', '--no-scripts',
                    *(str(path) for path in paths)], check=True, timeout=180)
    manifest = verify_installed(arch, prepared_root=output)
    after = installed_records()
    require({name: row for name, row in after.items() if name not in PACKAGES} == before,
            'C++ build installation changed an existing package')
    environment = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}
    actual_target = subprocess.check_output(['/usr/bin/g++', '-dumpmachine'], env=environment,
                                            text=True, timeout=20).strip()
    actual_version = subprocess.check_output(['/usr/bin/g++', '-dumpfullversion'], env=environment,
                                             text=True, timeout=20).strip()
    require(actual_target == target(arch) and actual_version == VERSION.split('-r')[0],
            'Installed native C++ compiler target or version differs')
    (Path(output) / 'CPP_BUILD_SECURITY.json').write_bytes(json_bytes(manifest))
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--prepare', action='store_true')
    mode.add_argument('--install', action='store_true')
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--architecture', choices=ARCHES)
    args = parser.parse_args()
    if args.prepare:
        architecture = native_architecture()
        require(args.architecture is None or args.architecture == architecture,
                'C++ build package cross-preparation is forbidden')
        result = prepare(args.output, architecture=architecture)
    else:
        result = install(args.output, architecture=args.architecture)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
