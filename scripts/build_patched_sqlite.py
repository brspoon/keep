#!/usr/bin/env python3
"""Build the official SQLite library without changing the vendor APK identity.

Preparation discovers native hashes only. Both architectures' reviewed compiler,
original library and output hashes are mandatory before any qualified receipt.
The command-line shell and recovery extension are never compiled or installed.
"""
import argparse
import ctypes
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shlex
import shutil
import struct
import subprocess
import tarfile
import urllib.request
from urllib.parse import urlsplit
import zipfile

if __package__:
    from . import fortify_header_sources as fortify
    from . import dhi_cpp_packages as cpp
    from . import expat_build_tools as build_tools
else:
    import fortify_header_sources as fortify
    import dhi_cpp_packages as cpp
    import expat_build_tools as build_tools

ROOT = Path(__file__).resolve().parents[1]
WORK = Path('/opt/keep-sqlite-build')
SOURCE_DIRECTORY = 'sqlite-autoconf-3540100'
LIBRARY = 'libsqlite3.so.3.54.1'
ALIAS = 'libsqlite3.so.0'
VENDOR_LIBRARY = '/usr/lib/libsqlite3.so.3.54.1'
BUILD_SCRIPT = 'scripts/build_patched_sqlite.py'
PATCH_PATH = 'scripts/sqlite_security_patches.json'
BUILD_IDENTITY = 'keep-sqlite-3.54.1-library-v1'
UPSTREAM_VERSION = '3.54.1'
SOURCE_ID = '2026-10-16 14:45:20 555e07ef33f69a0957d24d8e555b702464a131d6f1607f4c3c1e4551e8e6ca76'
UPSTREAM_RELEASE = {'tag': 'version-3.54.1', 'commit': '57520227c95396ce39ba6ecaac8d475b78dd3964',
                    'fossil_source_id': SOURCE_ID}
SOURCE_URL = 'https://www.sqlite.org/2026/sqlite-autoconf-3540100.tar.gz'
SOURCE_SHA256 = '926ef8d3eab93fbf6e06011901273eec076b25594a4e1cdadd50c987f4f6d64e'
SOURCE_SHA512 = '3df4348f54f5cd0554eec6d91e1d08a70535b7b78f497b2c6f24910b5087f6ef70483c9e35fa388bd8f38483cb8d1cb84e98ccdd58b9f525a10e0cf48c8c6742'
PREFERRED_SOURCE_URL = 'https://www.sqlite.org/2026/sqlite-src-3540100.zip'
PREFERRED_SOURCE_SHA256 = '387e7f6cad4797b17848c07d453dc6606917bb356a6cfe5a3abafd38c240c71b'
PREFERRED_SOURCE_SHA512 = '1c728b93da228d2c135096a5896728934d7d3eda4bdaa2dd05bb02812691ed56c8a4a9181b3b00215f5849d5cd8a191a7cbbc132f11b1fa2ebb6f8abaa92c677'
RECIPE_URL = 'https://raw.githubusercontent.com/alpinelinux/aports/f8081b25590214e2695a4faa77c7892bd902a4e8/main/sqlite/APKBUILD'
RECIPE_SHA256 = 'de648fc75c4ec249f958c9cf557793ab35a5a9e90b7d8758a3ec654f483117bd'
PATCH_SHA256 = '0309b5f618067978d0ef0c648d1e97ee83ea55ea4c543b42135927403cabd8a3'
AMALGAMATION_SHA256 = '0c657666d819f261cc4007526ad57e1669de9949df7a8ea847aa284a2bf0ee52'
AMALGAMATION_SHA3_256 = 'e2b869d3003b33c942b7dd7063604fbc53553e1b66609570df39b9b7b558ee81'
BUILD_IMAGE = 'dhi.io/python:3.14-alpine3.24-dev@sha256:b718c87cdd7bb7dc88d6bbe347f81123b9cf6f2dac6eec6d4828c2cd8262582d'
FORTIFY_HELPER_SHA256 = '931dee2acb84af6bb7f18f5eb0bd8e46c931c954d6e96e3e1a27ae8cb44b66e0'
CPP_HELPER_SHA256 = '3563bab213c2e8d24ccf362d51e58ff1275ec09cce383c10148185b9b87c7cfb'
BUILD_TOOLS_HELPER_SHA256 = '648f9c4be04ffa54e13d3dc0d382f8c6f019b76619ac14163486581b7370b9fa'
TARGETS = {'amd64': 'x86_64-alpine-linux-musl', 'arm64': 'aarch64-alpine-linux-musl'}
SOURCE_DATE_EPOCH = '1792161920'
DEFINITIONS = ('SQLITE_THREADSAFE=1', 'SQLITE_DEFAULT_AUTOVACUUM=0', 'SQLITE_DEFAULT_RECURSIVE_TRIGGERS=0',
    'SQLITE_ENABLE_COLUMN_METADATA', 'SQLITE_ENABLE_DBSTAT_VTAB', 'SQLITE_ENABLE_FTS3',
    'SQLITE_ENABLE_FTS3_PARENTHESIS', 'SQLITE_ENABLE_FTS4', 'SQLITE_ENABLE_FTS5',
    'SQLITE_ENABLE_GEOPOLY', 'SQLITE_ENABLE_MATH_FUNCTIONS', 'SQLITE_ENABLE_PERCENTILE',
    'SQLITE_ENABLE_PREUPDATE_HOOK', 'SQLITE_ENABLE_RTREE', 'SQLITE_ENABLE_SESSION',
    'SQLITE_ENABLE_UNLOCK_NOTIFY', 'SQLITE_SECURE_DELETE', 'SQLITE_SOUNDEX',
    'SQLITE_USE_URI', 'SQLITE_MAX_VARIABLE_NUMBER=250000')
REQUIRED_COMPILE_OPTIONS = (
    'ATOMIC_INTRINSICS=1', 'COMPILER=gcc-15.2.0', 'DEFAULT_AUTOVACUUM', 'DEFAULT_CACHE_SIZE=-2000',
    'DEFAULT_FILE_FORMAT=4', 'DEFAULT_JOURNAL_SIZE_LIMIT=-1', 'DEFAULT_MMAP_SIZE=0', 'DEFAULT_PAGE_SIZE=4096',
    'DEFAULT_PCACHE_INITSZ=20', 'DEFAULT_RECURSIVE_TRIGGERS', 'DEFAULT_SECTOR_SIZE=4096',
    'DEFAULT_SYNCHRONOUS=2', 'DEFAULT_WAL_AUTOCHECKPOINT=1000', 'DEFAULT_WAL_SYNCHRONOUS=2',
    'DEFAULT_WORKER_THREADS=0', 'DIRECT_OVERFLOW_READ', 'ENABLE_COLUMN_METADATA', 'ENABLE_DBSTAT_VTAB',
    'ENABLE_FTS3', 'ENABLE_FTS3_PARENTHESIS', 'ENABLE_FTS4', 'ENABLE_FTS5', 'ENABLE_GEOPOLY',
    'ENABLE_MATH_FUNCTIONS', 'ENABLE_PERCENTILE', 'ENABLE_PREUPDATE_HOOK', 'ENABLE_RTREE',
    'ENABLE_SESSION', 'ENABLE_UNLOCK_NOTIFY', 'MALLOC_SOFT_LIMIT=1024', 'MAX_ATTACHED=10',
    'MAX_COLUMN=2000', 'MAX_COMPOUND_SELECT=500', 'MAX_DEFAULT_PAGE_SIZE=8192', 'MAX_EXPR_DEPTH=1000',
    'MAX_FUNCTION_ARG=1000', 'MAX_LENGTH=1000000000', 'MAX_LIKE_PATTERN_LENGTH=50000',
    'MAX_MMAP_SIZE=0x7fff0000', 'MAX_PAGE_COUNT=0xfffffffe', 'MAX_PAGE_SIZE=65536',
    'MAX_SCHEMA=10000000', 'MAX_SQL_LENGTH=1000000000', 'MAX_TRIGGER_DEPTH=1000', 'MAX_VARIABLE_NUMBER=250000',
    'MAX_VDBE_OP=250000000', 'MAX_WORKER_THREADS=8', 'MUTEX_PTHREADS', 'SECURE_DELETE',
    'SOUNDEX', 'SYSTEM_MALLOC', 'TEMP_STORE=1', 'THREADSAFE=1', 'USE_URI')
ENVIRONMENT = {
    'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
    'CC': '/usr/bin/gcc', 'LC_ALL': 'C', 'TZ': 'UTC', 'SOURCE_DATE_EPOCH': SOURCE_DATE_EPOCH,
    'CFLAGS': '-O2 -fPIC -fstack-clash-protection -Wformat -Werror=format-security -fstack-protector-strong -ffile-prefix-map=/opt/keep-sqlite-build=.',
    'CPPFLAGS': '-D_FORTIFY_SOURCE=2 -I/opt/keep-sqlite-build/fortify/include',
    'LDFLAGS': '-Wl,--as-needed,-O1,--sort-common,--build-id=sha1 -Wl,-z,pack-relative-relocs,-z,relro,-z,now,-z,noexecstack',
}
ARCHITECTURE_CFLAGS = {'amd64': '-fno-plt', 'arm64': ''}
EXPECTED_HARDENING = {'gnu_stack_non_executable': True, 'relro': True, 'bind_now': True,
                      'stack_protector': True, 'fortify_source': 2}
VENDOR_ABI = {'export_count': 353, 'exports_sha256': '1823bb48786d4ad4fedfeafc82399cb3b1678ece66e633dd67c268da19507921'}
REQUIRED_LIMIT_DEFAULTS = {'schema': 10000000, 'trigger_steps': 65000}
LIMIT = 32 * 1024 * 1024
SHA256 = re.compile(r'[a-f0-9]{64}\Z')

def json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()

def digest(body):
    return hashlib.sha256(body).hexdigest()

def require(condition, message):
    if not condition:
        raise ValueError(message)

def checked(body, expected, label):
    require(digest(body) == expected, label + ' checksum mismatch')
    return body

def regular_bytes(path, label, limit=LIMIT):
    path = Path(path)
    require(not path.is_symlink() and path.is_file() and path.stat().st_size <= limit,
            label + ' must be a bounded regular file')
    body = path.read_bytes()
    require(len(body) <= limit, label + ' exceeds size limit')
    return body

def download(url):
    parsed = urlsplit(url)
    require(parsed.scheme == 'https' and parsed.hostname and not parsed.username and not parsed.password
            and parsed.port is None and not parsed.fragment, 'Invalid SQLite build input URL')
    with urllib.request.urlopen(url, timeout=60) as response:
        final = urlsplit(response.geturl())
        require(final.scheme == 'https' and final.hostname and not final.username and not final.password,
                'Unsafe SQLite build input redirect')
        body = response.read(LIMIT + 1)
    require(len(body) <= LIMIT, 'SQLite source exceeds size limit')
    return body

def immutable_spec():
    return {'schema': 'keep-sqlite-build-v1', 'identity': BUILD_IDENTITY,
        'upstream_version': UPSTREAM_VERSION, 'upstream_release': dict(UPSTREAM_RELEASE),
        'source_id': SOURCE_ID, 'source': {'url': SOURCE_URL, 'sha256': SOURCE_SHA256,
            'sha512': SOURCE_SHA512, 'directory': SOURCE_DIRECTORY},
        'preferred_source': {'url': PREFERRED_SOURCE_URL, 'sha256': PREFERRED_SOURCE_SHA256,
            'sha512': PREFERRED_SOURCE_SHA512},
        'vendor_recipe': {'url': RECIPE_URL, 'sha256': RECIPE_SHA256},
        'vendor_package': {'origin': 'sqlite', 'name': 'sqlite-libs', 'version': '3.54.1-r0',
            'build_commit': 'f8081b25590214e2695a4faa77c7892bd902a4e8',
            'library': VENDOR_LIBRARY, 'alias': '/usr/lib/' + ALIAS,
            'apk_sha256': {'amd64': '5dfd76936e795efd988d6bad4949b8d20c410d6dc9dd256da884111f668f3915',
                'arm64': 'e92861972b07c848fbf7e2e5ed20ca872c00f3a87550d01a5f7820d4d02df526'}},
        'patch_manifest': {'path': PATCH_PATH, 'sha256': PATCH_SHA256},
        'patched_files': {'sqlite3.c': AMALGAMATION_SHA256}, 'build_script': BUILD_SCRIPT,
        'fortify_headers': fortify.reviewed_spec(),
        'fortify_helper': {'path': 'scripts/fortify_header_sources.py', 'sha256': FORTIFY_HELPER_SHA256},
        'cpp_packages': cpp.reviewed_spec(),
        'cpp_helper': {'path': 'scripts/dhi_cpp_packages.py', 'sha256': CPP_HELPER_SHA256},
        'build_tools': build_tools.reviewed_spec(),
        'build_tools_helper': {'path': 'scripts/expat_build_tools.py', 'sha256': BUILD_TOOLS_HELPER_SHA256},
        'build': {'image': BUILD_IMAGE, 'directory': str(WORK), 'compiler': '/usr/bin/gcc',
            'compiler_targets': dict(TARGETS), 'environment': dict(ENVIRONMENT),
            'architecture_cflags': dict(ARCHITECTURE_CFLAGS), 'definitions': list(DEFINITIONS),
            'sources': ['sqlite3.c'], 'library_only': True},
        'library': {'path': '/usr/lib/' + LIBRARY, 'soname': ALIAS},
        'required_hardening': dict(EXPECTED_HARDENING), 'required_abi': dict(VENDOR_ABI),
        'required_compile_options': list(REQUIRED_COMPILE_OPTIONS),
        'required_limit_defaults': dict(REQUIRED_LIMIT_DEFAULTS)}

def reviewed_spec(root=None, *, lock_path=None):
    require(lock_path is None or root is None or Path(root) == ROOT, 'Specify a SQLite root or explicit lock path')
    path = Path(lock_path) if lock_path is not None else Path(root or ROOT) / 'docs/sqlite-build.json'
    body = regular_bytes(path, 'SQLite build lock')
    spec = json.loads(body)
    require(isinstance(spec, dict), 'Invalid SQLite build lock')
    remaining = dict(spec)
    for field in ('expected_library_sha256', 'compiler_sha256', 'expected_vendor_library_sha256'):
        values = remaining.pop(field, None)
        require(isinstance(values, dict) and set(values) == set(TARGETS)
                and all(value is None or isinstance(value, str) and SHA256.fullmatch(value) for value in values.values()),
                'SQLite build lock requires both native ' + field + ' records')
    script_hash = remaining.pop('build_script_sha256', None)
    require(isinstance(script_hash, str) and SHA256.fullmatch(script_hash), 'Missing SQLite build script hash')
    require(remaining == immutable_spec(), 'SQLite build lock differs from reviewed source or build facts')
    require(body == json_bytes(spec), 'SQLite build lock must use canonical JSON bytes')
    checked(regular_bytes(Path(__file__), 'SQLite build script'), script_hash, 'SQLite build script')
    for module, expected in ((fortify, FORTIFY_HELPER_SHA256), (cpp, CPP_HELPER_SHA256),
                             (build_tools, BUILD_TOOLS_HELPER_SHA256)):
        checked(regular_bytes(module.__file__, 'SQLite build input helper'), expected, 'SQLite build input helper')
    return spec

def require_output_pins(spec):
    for field in ('expected_library_sha256', 'compiler_sha256', 'expected_vendor_library_sha256'):
        require(all(isinstance(value, str) and SHA256.fullmatch(value) for value in spec[field].values()),
                'SQLite ' + field + ' must be reviewed for both architectures; preparation is not qualified')

def source_replay_record():
    return {'schema': 'keep-sqlite-source-replay-v1', 'identity': BUILD_IDENTITY,
        'upstream_release': dict(UPSTREAM_RELEASE), 'source_sha256': SOURCE_SHA256,
        'preferred_source_sha256': PREFERRED_SOURCE_SHA256, 'vendor_recipe_sha256': RECIPE_SHA256,
        'patch_manifest_sha256': PATCH_SHA256, 'patched_files': {'sqlite3.c': AMALGAMATION_SHA256},
        'fortify_headers': fortify.reviewed_spec(), 'cpp_packages': cpp.reviewed_spec(),
        'build_tools': build_tools.reviewed_spec()}

def source_download_records():
    return [{'path': SOURCE_DIRECTORY + '.tar.gz', 'url': SOURCE_URL, 'sha256': SOURCE_SHA256, 'role': 'upstream-source'},
        {'path': 'sqlite-src-3540100.zip', 'url': PREFERRED_SOURCE_URL, 'sha256': PREFERRED_SOURCE_SHA256, 'role': 'upstream-source'},
        {'path': 'APKBUILD', 'url': RECIPE_URL, 'sha256': RECIPE_SHA256, 'role': 'reference-vendor-build-script'},
        *[{**row, 'path': 'fortify/' + row['path']} for row in fortify.source_download_records()],
        *[{**row, 'path': 'cpp/' + row['path']} for row in cpp.source_download_records()],
        *[{**row, 'path': 'build-tools/' + row['path']} for row in build_tools.source_download_records()]]

def _manifest(spec, arch, library_hash, compiler_hash, vendor_hash, *, qualified):
    require(arch in TARGETS, 'Unsupported native SQLite architecture')
    return {'schema': 'keep-sqlite-patched-security-v1', 'architecture': arch,
        'qualified': qualified, 'purpose': 'reviewed-build' if qualified else 'preparation-only',
        'identity': BUILD_IDENTITY, 'upstream_version': UPSTREAM_VERSION, 'source_id': SOURCE_ID,
        'vendor_package_version': '3.54.1-r0', 'vendor_apk_signature_applies_to_replacement': False,
        'build_lock_sha256': digest(json_bytes(spec)), 'build_script_sha256': spec['build_script_sha256'],
        'build_image': BUILD_IMAGE, 'source_sha256': SOURCE_SHA256,
        'preferred_source_sha256': PREFERRED_SOURCE_SHA256, 'patch_manifest_sha256': PATCH_SHA256,
        'source_replay_sha256': digest(json_bytes(source_replay_record())),
        'fortify_source_manifest_sha256': digest(fortify.source_lock_bytes()),
        'cpp_source_manifest_sha256': digest(cpp.source_lock_bytes()),
        'cpp_installation_manifest_sha256': digest(cpp.json_bytes(cpp.installation_manifest(arch))),
        'build_tools_source_manifest_sha256': digest(build_tools.source_lock_bytes()),
        'build_tools_installation_manifest_sha256': digest(json_bytes(build_tools.installation_manifest(arch))),
        'compiler': {'path': '/usr/bin/gcc', 'target': TARGETS[arch], 'sha256': compiler_hash},
        'vendor_library': {'path': VENDOR_LIBRARY, 'soname': ALIAS, 'sha256': vendor_hash},
        'library': {**spec['library'], 'sha256': library_hash},
        'hardening': dict(EXPECTED_HARDENING), 'abi': dict(VENDOR_ABI),
        'required_compile_options': list(REQUIRED_COMPILE_OPTIONS),
        'required_limit_defaults': dict(REQUIRED_LIMIT_DEFAULTS), 'library_only': True}

def expected_manifest(arch, root=ROOT, *, lock_path=None):
    spec = reviewed_spec(root, lock_path=lock_path)
    require_output_pins(spec)
    require(arch in TARGETS, 'Unsupported native SQLite architecture')
    return _manifest(spec, arch, spec['expected_library_sha256'][arch], spec['compiler_sha256'][arch],
                     spec['expected_vendor_library_sha256'][arch], qualified=True)

def verify_build_manifest(manifest, arch, root=ROOT, *, lock_path=None):
    require(isinstance(manifest, dict) and manifest.get('qualified') is True
            and manifest.get('purpose') == 'reviewed-build', 'SQLite preparation or unqualified manifest cannot qualify a runtime')
    require(manifest == expected_manifest(arch, root, lock_path=lock_path), 'SQLite replacement manifest differs from reviewed identities')
    return manifest

def read_build_manifest(path, arch=None, *, manifest_path=None, lock_path=None):
    if arch is None:
        arch = path
        path = manifest_path or Path('/app/SQLITE_PATCHED_SECURITY.json')
        lock_path = lock_path or Path('/app/SQLITE_BUILD.json')
    else:
        require(manifest_path is None, 'SQLite manifest path specified twice')
    body = regular_bytes(path, 'SQLite build manifest')
    value = json.loads(body)
    require(body == json_bytes(value), 'SQLite build manifest must use canonical JSON bytes')
    return verify_build_manifest(value, arch, lock_path=lock_path)

def empty_directory(path):
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts and not any(p.is_symlink() for p in (path, *path.parents)), 'Unsafe SQLite output path')
    require(not path.exists() or path.is_dir() and not any(path.iterdir()), 'SQLite output directory must be empty')
    path.mkdir(parents=True, exist_ok=True)
    return path

def source_members(body):
    files, seen, total = {}, set(), 0
    with tarfile.open(fileobj=io.BytesIO(body), mode='r:gz') as package:
        for count, member in enumerate(package, 1):
            path = PurePosixPath(member.name)
            require(member.name and not path.is_absolute() and '..' not in path.parts and '\\' not in member.name
                    and '\x00' not in member.name and path.parts[0] == SOURCE_DIRECTORY
                    and path.as_posix() == member.name.rstrip('/'), 'Unsafe SQLite source archive path')
            require(path.as_posix() not in seen, 'Duplicate SQLite source archive member')
            seen.add(path.as_posix()); total += member.size
            require(count <= 10000 and 0 <= member.size <= LIMIT and total <= 64 * 1024 * 1024,
                    'SQLite source archive exceeds bounds')
            require((member.isfile() or member.isdir()) and not member.mode & 0o7000, 'Unsupported SQLite source member')
            if member.isfile():
                require(len(path.parts) >= 2, 'Invalid SQLite source file')
                data = package.extractfile(member).read()
                require(len(data) == member.size, 'Truncated SQLite source file')
                files['/'.join(path.parts[1:])] = (data, member.mode & 0o777)
    require(bool(files), 'Empty SQLite source archive')
    return files

def verify_sources(files, preferred, patch):
    require(patch == {'schema': 'keep-sqlite-patches-v1', 'upstream_version': UPSTREAM_VERSION,
        'upstream_release': UPSTREAM_RELEASE, 'fixes_in_upstream_release': [{'id': 'CVE-2026-119376',
            'commit': 'd54522a5b832422ab893a1e9fa7a99ab314ea4e2',
            'fossil_commit': '252c0b7bf5a727d29605672bb58e06c758173c276671df3e388a68294998b4d3'}],
        'patches': [], 'local_patches': [], 'patched_files': {'sqlite3.c': AMALGAMATION_SHA256}},
        'SQLite patch manifest differs from official unmodified release')
    require('sqlite3.c' in files and 'sqlite3.h' in files, 'Missing SQLite amalgamation')
    amalgamation = checked(files['sqlite3.c'][0], AMALGAMATION_SHA256, 'SQLite amalgamation')
    require(hashlib.sha3_256(amalgamation).hexdigest() == AMALGAMATION_SHA3_256
            and re.search(rb'^#define SQLITE_VERSION\s+"3\.54\.1"\s*$', amalgamation, re.M)
            and SOURCE_ID.encode() in amalgamation, 'SQLite official release identity differs')
    with zipfile.ZipFile(io.BytesIO(preferred)) as package:
        names = package.namelist()
        require(len(names) == len(set(names)) and len(names) <= 20000, 'Ambiguous SQLite preferred-source ZIP')
        def member(name, limit):
            row = package.getinfo('sqlite-src-3540100/' + name)
            require(not row.is_dir() and not row.flag_bits & 1 and 0 < row.file_size <= limit,
                    'Invalid bounded SQLite preferred-source member')
            with package.open(row) as stream:
                body = stream.read(limit + 1)
            require(len(body) == row.file_size, 'Truncated SQLite preferred-source member')
            return body
        require(member('manifest.uuid', 128).decode().strip() == SOURCE_ID.rsplit(' ', 1)[1],
                'SQLite preferred-source Fossil identity differs')
        license_body = member('LICENSE.md', 128 * 1024)
    return license_body

def replay_sources(output, *, root=ROOT, lock_path=None, fetch=download):
    spec = reviewed_spec(root, lock_path=lock_path)
    archive = checked(fetch(SOURCE_URL), SOURCE_SHA256, 'SQLite release source')
    preferred = checked(fetch(PREFERRED_SOURCE_URL), PREFERRED_SOURCE_SHA256, 'SQLite preferred source')
    require(hashlib.sha512(archive).hexdigest() == SOURCE_SHA512 and hashlib.sha512(preferred).hexdigest() == PREFERRED_SOURCE_SHA512,
            'SQLite source SHA-512 differs from independently reviewed recipe')
    recipe = checked(fetch(RECIPE_URL), RECIPE_SHA256, 'SQLite reference recipe')
    patch = checked(regular_bytes(Path(root) / PATCH_PATH, 'SQLite patch manifest'), PATCH_SHA256, 'SQLite patch manifest')
    files = source_members(archive)
    license_body = verify_sources(files, preferred, json.loads(patch))
    destination = empty_directory(output); source = destination / SOURCE_DIRECTORY; source.mkdir()
    for name, (body, mode) in sorted(files.items()):
        path = source / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(body); path.chmod(mode)
        os.utime(path, (int(SOURCE_DATE_EPOCH), int(SOURCE_DATE_EPOCH)))
    retained = {SOURCE_DIRECTORY + '.tar.gz': archive, 'sqlite-src-3540100.zip': preferred,
        'APKBUILD': recipe, 'sqlite_security_patches.json': patch,
        'build_patched_sqlite.py': regular_bytes(__file__, 'SQLite build script'),
        'fortify_header_sources.py': regular_bytes(fortify.__file__, 'Fortify helper'),
        'dhi_cpp_packages.py': regular_bytes(cpp.__file__, 'C++ helper'),
        'expat_build_tools.py': regular_bytes(build_tools.__file__, 'Build-tool helper'),
        'sqlite-build.json': json_bytes(spec), 'SOURCE_REPLAY.json': json_bytes(source_replay_record()), 'COPYING': license_body}
    for name, body in retained.items():
        (destination / name).write_bytes(body)
    fortify.prepare(destination / 'fortify', fetch=fetch)
    cpp.prepare(destination / 'cpp', fetch=fetch)
    build_tools.prepare(destination / 'build-tools', fetch=fetch)
    return source_replay_record()

def elf_information(body, arch, *, require_hardening=True):
    require(arch in TARGETS and len(body) >= 64 and body[:6] == b'\x7fELF\x02\x01'
            and int.from_bytes(body[16:18], 'little') == 3
            and int.from_bytes(body[18:20], 'little') == {'amd64': 62, 'arm64': 183}[arch], 'SQLite ELF architecture/type differs')
    def bounded(offset, size):
        require(0 <= offset <= len(body) and 0 <= size <= len(body) - offset, 'Invalid SQLite ELF bounds')
        return body[offset:offset + size]
    def string(table, offset):
        require(0 <= offset < len(table), 'Invalid SQLite ELF string offset')
        end = table.find(b'\0', offset); require(end >= offset, 'Unterminated SQLite ELF string')
        return table[offset:end].decode('ascii')
    header = struct.unpack('<16sHHIQQQIHHHHHH', bounded(0, 64))
    phoff, shoff, phsize, phcount, shsize, shcount = header[5], header[6], header[9], header[10], header[11], header[12]
    require(phsize == 56 and shsize == 64 and 0 < phcount <= 128 and 0 < shcount <= 1024, 'Invalid SQLite ELF tables')
    programs = [struct.unpack('<IIQQQQQQ', bounded(phoff + n * phsize, phsize)) for n in range(phcount)]
    dynamic = [p for p in programs if p[0] == 2]; require(len(dynamic) == 1 and dynamic[0][5] % 16 == 0, 'Invalid SQLite dynamic table')
    tags, ended = {}, False
    for tag, value in struct.iter_unpack('<qQ', bounded(dynamic[0][2], dynamic[0][5])):
        if tag == 0: ended = True; break
        tags.setdefault(tag, []).append(value)
    require(ended and len(tags.get(5, [])) == len(tags.get(10, [])) == len(tags.get(14, [])) == 1, 'Invalid SQLite string table/SONAME')
    address, size = tags[5][0], tags[10][0]
    loads = [p for p in programs if p[0] == 1 and p[3] <= address and address + size <= p[3] + p[5]]
    require(len(loads) == 1, 'SQLite string table outside file-backed segment')
    strings = bounded(loads[0][2] + address - loads[0][3], size)
    require(string(strings, tags[14][0]) == ALIAS, 'SQLite SONAME differs from vendor ABI')
    needed = [string(strings, v) for v in tags.get(1, [])]
    require(needed == ['libc.musl-' + {'amd64': 'x86_64', 'arm64': 'aarch64'}[arch] + '.so.1'], 'SQLite has unreviewed dynamic dependencies')
    sections = [struct.unpack('<IIQQQQIIQQ', bounded(shoff + n * shsize, shsize)) for n in range(shcount)]
    symbols = [s for s in sections if s[1] == 11]
    require(len(symbols) == 1 and symbols[0][9] == 24 and symbols[0][5] % 24 == 0
            and symbols[0][6] < len(sections), 'Invalid SQLite dynamic symbols')
    symbols = symbols[0]; names = sections[symbols[6]]; require(names[1] == 3, 'Invalid SQLite symbol names')
    names = bounded(names[4], names[5]); exports, protected = {}, False
    for name, info, other, index, _, _ in struct.iter_unpack('<IBBHQQ', bounded(symbols[4], symbols[5])):
        name = string(names, name)
        if index == 0 and name == '__stack_chk_fail': protected = True
        if index != 0 and info >> 4 in (1, 2) and other & 3 == 0 and name.startswith('sqlite3'):
            require(name not in exports, 'Duplicate SQLite exported symbol'); exports[name] = info & 15
    require(bool(exports), 'Missing SQLite exported API')
    if require_hardening:
        stacks = [p for p in programs if p[0] == 0x6474e551]
        require(len(stacks) == 1 and stacks[0][1] == 6, 'SQLite stack must be explicitly non-executable')
        require(len([p for p in programs if p[0] == 0x6474e552 and p[6] > 0]) == 1, 'SQLite RELRO missing')
        require(24 in tags or any(v & 8 for v in tags.get(30, [])) or any(v & 1 for v in tags.get(0x6ffffffb, [])), 'SQLite immediate binding missing')
        require(protected, 'SQLite stack-protector binding missing')
    return {'export_count': len(exports), 'exports_sha256': digest(json_bytes(exports)), 'exports': exports,
            'soname': ALIAS, 'needed': needed}

def build_environment(arch):
    require(arch in TARGETS, 'Unsupported native SQLite architecture')
    environment = dict(ENVIRONMENT)
    if ARCHITECTURE_CFLAGS[arch]: environment['CFLAGS'] += ' ' + ARCHITECTURE_CFLAGS[arch]
    return environment

def compile_command(arch):
    environment = build_environment(arch)
    return ['/usr/bin/gcc', *shlex.split(environment['CFLAGS']), *shlex.split(environment['CPPFLAGS']),
        *['-D' + name for name in DEFINITIONS], '-shared', '-Wl,-soname,' + ALIAS,
        '-o', LIBRARY, 'sqlite3.c', *shlex.split(environment['LDFLAGS']), '-pthread', '-ldl', '-lm']

def runtime_features(library):
    loaded = ctypes.CDLL(str(library))
    loaded.sqlite3_libversion.restype = loaded.sqlite3_sourceid.restype = ctypes.c_char_p
    loaded.sqlite3_compileoption_get.argtypes = [ctypes.c_int]; loaded.sqlite3_compileoption_get.restype = ctypes.c_char_p
    loaded.sqlite3_threadsafe.restype = ctypes.c_int
    require(loaded.sqlite3_libversion().decode() == UPSTREAM_VERSION and loaded.sqlite3_sourceid().decode() == SOURCE_ID,
            'Loaded SQLite replacement version/source identity differs')
    options = []
    for i in range(256):
        value = loaded.sqlite3_compileoption_get(i)
        if value is None: break
        options.append(value.decode('ascii'))
    else: raise ValueError('Unbounded SQLite compile options')
    require(sorted(options) == list(REQUIRED_COMPILE_OPTIONS) and len(options) == len(set(options))
            and loaded.sqlite3_threadsafe() == 1, 'SQLite compiled features, threading or limits differ from vendor baseline: ' + json.dumps(options))
    loaded.sqlite3_open.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_void_p)]
    loaded.sqlite3_open.restype = ctypes.c_int
    loaded.sqlite3_close.argtypes = [ctypes.c_void_p]; loaded.sqlite3_close.restype = ctypes.c_int
    loaded.sqlite3_limit.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int]
    loaded.sqlite3_limit.restype = ctypes.c_int
    connection = ctypes.c_void_p()
    require(loaded.sqlite3_open(b':memory:', ctypes.byref(connection)) == 0 and bool(connection), 'SQLite compatibility database could not open')
    try:
        limits = {name: loaded.sqlite3_limit(connection, number, -1)
                  for name, number in (('schema', 13), ('trigger_steps', 14))}
        require(limits == REQUIRED_LIMIT_DEFAULTS, 'SQLite upstream 3.54 limit defaults differ')
    finally:
        require(loaded.sqlite3_close(connection) == 0, 'SQLite compatibility database did not close')
    return {'version': UPSTREAM_VERSION, 'source_id': SOURCE_ID, 'compile_options': sorted(options),
            'threadsafe': 1, 'limit_defaults': limits}

def verify_vendor_source_map(root):
    mapping = json.loads(regular_bytes(Path(root) / 'docs/os-package-sources.json', 'SQLite original vendor source map'))
    rows = [row for row in mapping.get('origins', []) if row.get('origin') == 'sqlite']
    require(len(rows) == 1 and rows[0].get('version') == '3.54.1-r0', 'SQLite original vendor origin/version differs')
    packages = rows[0].get('packages', [])
    expected = immutable_spec()['vendor_package']
    require(len(packages) == 1 and packages[0].get('name') == expected['name']
            and packages[0].get('version') == expected['version']
            and packages[0].get('build_commit') == expected['build_commit'], 'SQLite original vendor package identity differs')
    binaries = packages[0].get('binaries', {})
    require(set(binaries) == set(TARGETS)
            and all(binaries[arch].get('sha256') == expected['apk_sha256'][arch] for arch in TARGETS),
            'SQLite original signed vendor payload pins differ')
    return expected

def build(output, preparation=False, *, architecture=None, root=ROOT, fetch=download):
    require(type(preparation) is bool, 'SQLite preparation must be explicit')
    spec = reviewed_spec(root)
    if not preparation: require_output_pins(spec)
    verify_vendor_source_map(root)
    require(platform.system() == 'Linux', 'SQLite requires a native Linux build')
    arch = {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(platform.machine())
    require(arch in TARGETS and (architecture is None or architecture == arch), 'SQLite cross-compilation is not qualified')
    require(os.environ.get('KEEP_SQLITE_BUILD_IMAGE') == BUILD_IMAGE, 'SQLite build image declaration differs')
    environment = build_environment(arch)
    compiler = Path('/usr/bin/gcc').resolve(strict=True)
    compiler_hash = digest(regular_bytes(compiler, 'SQLite compiler', 128 * 1024 * 1024))
    target = subprocess.check_output(['/usr/bin/gcc', '-dumpmachine'], env=environment, timeout=30).decode().strip()
    require(target == TARGETS[arch], 'SQLite compiler target differs')
    require(spec['compiler_sha256'][arch] is None or spec['compiler_sha256'][arch] == compiler_hash, 'SQLite compiler hash differs')
    vendor_body = regular_bytes(VENDOR_LIBRARY, 'Original SQLite vendor library'); vendor_hash = digest(vendor_body)
    require(Path('/usr/lib/' + ALIAS).is_symlink() and Path('/usr/lib/' + ALIAS).resolve(strict=True) == Path(VENDOR_LIBRARY), 'Original SQLite alias differs')
    require(spec['expected_vendor_library_sha256'][arch] is None or spec['expected_vendor_library_sha256'][arch] == vendor_hash, 'Original SQLite vendor library hash differs')
    vendor_abi = elf_information(vendor_body, arch)
    vendor_features = runtime_features(Path(VENDOR_LIBRARY))
    require({k: vendor_abi[k] for k in VENDOR_ABI} == VENDOR_ABI, 'Original SQLite exported ABI differs')
    cpp_proof, tools_proof = cpp.verify_installed(arch), build_tools.verify_installed(arch)
    require(regular_bytes(cpp.PREPARED_ROOT / 'CPP_BUILD_SECURITY.json', 'C++ build receipt') == cpp.json_bytes(cpp_proof)
            and regular_bytes(build_tools.PREPARED_ROOT / 'BUILD_TOOLS_SECURITY.json', 'Build-tool receipt') == json_bytes(tools_proof), 'SQLite build input receipts differ')
    destination = empty_directory(output)
    require(destination != WORK and not destination.is_relative_to(WORK) and not WORK.is_relative_to(destination), 'SQLite output overlaps fixed workspace')
    replay_sources(WORK, root=root, fetch=fetch); fortify.verify_prepared_headers(WORK / 'fortify/include')
    macros = subprocess.check_output(['/usr/bin/gcc', *shlex.split(environment['CFLAGS']),
        *shlex.split(environment['CPPFLAGS']), '-dM', '-E', '-x', 'c', '-'], input=b'#include <string.h>\n', env=environment, timeout=30).decode()
    require('#define _FORTIFY_SOURCE 2' in macros and '#define _FORTIFY_STRING_H' in macros
            and '#define __SSP_STRONG__' in macros, 'SQLite effective fortify/stack protection missing')
    command = compile_command(arch); source = WORK / SOURCE_DIRECTORY
    subprocess.run(command, cwd=source, env=environment, check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=900)
    built = source / LIBRARY; library = regular_bytes(built, 'Built SQLite library'); protections = elf_information(library, arch)
    require(all(protections['exports'].get(name) == kind for name, kind in vendor_abi['exports'].items()), 'SQLite replacement removed or changed vendor ABI exports')
    features = runtime_features(built); fortify.verify_prepared_headers(WORK / 'fortify/include')
    require(cpp.verify_installed(arch) == cpp_proof and build_tools.verify_installed(arch) == tools_proof, 'SQLite build input cohort changed')
    library_hash = digest(library)
    require(spec['expected_library_sha256'][arch] is None or spec['expected_library_sha256'][arch] == library_hash, 'SQLite output differs from reviewed native hash')
    manifest = _manifest(spec, arch, library_hash, compiler_hash, vendor_hash, qualified=not preparation)
    if not preparation: verify_build_manifest(manifest, arch, root)
    (destination / LIBRARY).write_bytes(library); (destination / LIBRARY).chmod(0o755)
    for name in (SOURCE_DIRECTORY + '.tar.gz', 'sqlite-src-3540100.zip', 'APKBUILD', 'sqlite_security_patches.json',
                 'build_patched_sqlite.py', 'fortify_header_sources.py', 'dhi_cpp_packages.py', 'expat_build_tools.py',
                 'sqlite-build.json', 'SOURCE_REPLAY.json', 'COPYING'):
        shutil.copyfile(WORK / name, destination / name)
    for name in ('fortify', 'cpp', 'build-tools'): shutil.copytree(WORK / name, destination / name)
    (destination / 'CPP_BUILD_SECURITY.json').write_bytes(cpp.json_bytes(cpp_proof))
    (destination / 'BUILD_TOOLS_SECURITY.json').write_bytes(json_bytes(tools_proof))
    (destination / 'BUILD_ENVIRONMENT.json').write_bytes(json_bytes({'compiler_sha256': compiler_hash,
        'vendor_library_sha256': vendor_hash, 'command': command, 'environment': environment,
        'effective_compiler_hardening': {'fortify_source': 2, 'fortify_headers_active': True, 'stack_protector_strong': True},
        'elf_verification': protections, 'vendor_abi': vendor_abi, 'vendor_runtime_features': vendor_features, 'runtime_features': features,
        'build_image_declaration': BUILD_IMAGE, 'image_identity_requires_external_provenance_verification': True,
        'library_only': True, 'cpp_build_inputs': cpp_proof, 'build_tool_inputs': tools_proof}))
    (destination / 'SQLITE_PATCHED_SECURITY.json').write_bytes(json_bytes(manifest))
    require(WORK == Path('/opt/keep-sqlite-build') and not WORK.is_symlink(), 'SQLite workspace cleanup identity differs')
    shutil.rmtree(WORK)
    return manifest

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True)
    parser.add_argument('--preparation', action='store_true')
    parser.add_argument('--architecture', choices=TARGETS)
    parser.add_argument('--root', type=Path, default=ROOT)
    args = parser.parse_args()
    print(json.dumps(build(args.output, args.preparation, architecture=args.architecture, root=args.root), sort_keys=True))

if __name__ == '__main__':
    main()
