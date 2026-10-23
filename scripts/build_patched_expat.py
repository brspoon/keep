#!/usr/bin/env python3
"""Build a source-identified Expat overlay without changing vendor APK claims.

Preparation only discovers native output identities. It never creates a manifest
accepted by verify_build_manifest; normal builds require reviewed hashes for both
architectures and reproduce them before an output manifest is written.
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
import shutil
import shlex
import struct
import subprocess
import tarfile
import urllib.request

if __package__:
    from . import fortify_header_sources as fortify
else:
    import fortify_header_sources as fortify


ROOT = Path(__file__).resolve().parents[1]
WORK = Path('/opt/keep-expat-build')
SOURCE_DIRECTORY = 'expat-2.9.0'
LIBRARY = 'libexpat.so.1.13.0'
PATCH_PATH = 'scripts/expat_security_patches.json'
BUILD_SCRIPT = 'scripts/build_patched_expat.py'
FORTIFY_HELPER = 'scripts/fortify_header_sources.py'
FORTIFY_HELPER_SHA256 = '931dee2acb84af6bb7f18f5eb0bd8e46c931c954d6e96e3e1a27ae8cb44b66e0'
BUILD_IDENTITY = 'keep-expat-2.9.0-c30145b-d8f31e6-v1'
BUILD_IMAGE = ('dhi.io/python:3.14-alpine3.24-dev@sha256:'
               'b718c87cdd7bb7dc88d6bbe347f81123b9cf6f2dac6eec6d4828c2cd8262582d')
SOURCE_URL = 'https://github.com/libexpat/libexpat/releases/download/R_2_9_0/expat-2.9.0.tar.xz'
SOURCE_SHA256 = '1e6371862cc31999b368c3b89b49994f0677e1bab5f1b2b85ae3741f5d803051'
SOURCE_SHA512 = ('677b5a39ea47aa238813412061eefba0ff2e819597efee69452eab7fd63b138753'
                 '7eda0dfd4e5891b938be202dc87df4b5115bdae75c6b81643ac2363bb99b34')
COPYING_SHA256 = '31b15de82aa19a845156169a17a5488bf597e561b2c318d159ed583139b25e87'
PATCH_SHA256 = '1ec958c7d2400522c7d8cdf51f242702531c3448f8d3639cf23f88260725e5d6'
RECIPE_URL = ('https://raw.githubusercontent.com/alpinelinux/aports/'
              '46440e4654dc1e4e7d3a69b8a0a9e22fdeda4a88/main/expat/APKBUILD')
RECIPE_SHA256 = '40c194d5e234244805b965384fa6d47557aceb344e1cd92095695b17acc326f5'
COMMITS = (
    'd545081f6a90792208e0d274888a352e2e5d894d',
    'da504c0c111086072172431c76867800673fbc34',
    'c30145b28632b31f805d57f9838ba36b8db99367',
    'd8f31e647a4d1eda088e89354f4769b0dad303d3',
)
ORIGINAL_FILES = {
    'lib/xmlparse.c': '899afeaddf424a6f4bf9a0a77159248b485bf5c072475d547ef16c2942a86dd5',
    'tests/acc_tests.c': 'd10a7cf72862400cd03e52686d037d2f07cd80a4a2153853ae2ccd09d7d7820d',
    'tests/alloc_tests.c': '1f8277ba331b043898f1048332ed4314d4b1ead4473171702dda3cf163fb574d',
}
PATCHED_FILES = {
    'lib/xmlparse.c': '743fe05595ffa5bd2724d49c00377caa21afb0a02a09e2d225533c94b68e830e',
    'tests/acc_tests.c': 'b14268ec3f20b830742b66ee0144dd9264f70de5371de651ab34346f24a80c1b',
    'tests/alloc_tests.c': '0ae93e47a57c670beec81b899108a2691f0a46af74a389762c41aff53ddfa8b9',
}
TARGETS = {'amd64': 'x86_64-alpine-linux-musl', 'arm64': 'aarch64-alpine-linux-musl'}
SOURCE_DATE_EPOCH = '1792762956'
CONFIGURE_OPTIONS = ('--prefix=/usr', '--mandir=/usr/share/man', '--enable-static')
ENVIRONMENT = {
    'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
    'CC': '/usr/bin/gcc',
    'CFLAGS': ('-Os -fstack-clash-protection -Wformat -Werror=format-security '
               '-fstack-protector-strong -ffile-prefix-map=/opt/keep-expat-build=.'),
    'CPPFLAGS': '-D_FORTIFY_SOURCE=2 -I/opt/keep-expat-build/fortify/include',
    'LDFLAGS': ('-Wl,--as-needed,-O1,--sort-common,--build-id=sha1 '
                '-Wl,-z,pack-relative-relocs,-z,relro,-z,now,-z,noexecstack'),
    'SOURCE_DATE_EPOCH': SOURCE_DATE_EPOCH, 'LC_ALL': 'C', 'TZ': 'UTC',
    'SHELL': '/bin/sh', 'CONFIG_SHELL': '/bin/sh',
}
ARCHITECTURE_CFLAGS = {'amd64': '-fno-plt', 'arm64': ''}
EXPECTED_HARDENING = {'gnu_stack_non_executable': True, 'relro': True,
                      'bind_now': True, 'stack_protector': True, 'fortify_source': 2}
EXPECTED_ABI = {
    'exports_sha256': '89ef922b0558f2ee73e46ace5331d4ec9da8718bccb483738983d5dc04d20465',
    'export_count': 83,
    'features': {'sizeof(XML_Char)': 1, 'sizeof(XML_LChar)': 1,
                 'XML_DTD': 0, 'XML_CONTEXT_BYTES': 1024, 'XML_NS': 0,
                 'XML_BLAP_MAX_AMP': 100, 'XML_BLAP_ACT_THRES': 8388608,
                 'XML_GE': 0, 'XML_AT_MAX_AMP': 100, 'XML_AT_ACT_THRES': 67108864},
}
LIMIT = 16 * 1024 * 1024
SHA256 = re.compile(r'[a-f0-9]{64}')


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
    with urllib.request.urlopen(url, timeout=60) as response:
        body = response.read(LIMIT + 1)
    require(len(body) <= LIMIT, 'Expat source input exceeds size limit')
    return body


def immutable_spec():
    """Source facts remain compiled into the checker, including runtime use."""
    return {
        'schema': 'keep-expat-build-v1', 'identity': BUILD_IDENTITY,
        'upstream_version': '2.9.0', 'vendor_package_version': '2.9.0-r0',
        'source': {'url': SOURCE_URL, 'sha256': SOURCE_SHA256, 'sha512': SOURCE_SHA512,
                   'directory': SOURCE_DIRECTORY, 'copying_sha256': COPYING_SHA256},
        'vendor_recipe': {'url': RECIPE_URL, 'sha256': RECIPE_SHA256},
        'patch_manifest': {'path': PATCH_PATH, 'sha256': PATCH_SHA256},
        'commits': list(COMMITS), 'original_files': dict(ORIGINAL_FILES),
        'patched_files': dict(PATCHED_FILES), 'build_script': BUILD_SCRIPT,
        'fortify_headers': fortify.reviewed_spec(),
        'fortify_helper': {'path': FORTIFY_HELPER, 'sha256': FORTIFY_HELPER_SHA256},
        'build': {'image': BUILD_IMAGE, 'directory': str(WORK),
                  'compiler': '/usr/bin/gcc', 'compiler_targets': dict(TARGETS),
                  'environment': dict(ENVIRONMENT), 'configure_options': list(CONFIGURE_OPTIONS),
                  'architecture_cflags': dict(ARCHITECTURE_CFLAGS),
                  'commands': [['make', '-j2'], ['make', 'check']]},
        'library': {'path': '/usr/lib/' + LIBRARY, 'soname': 'libexpat.so.1'},
        'required_hardening': dict(EXPECTED_HARDENING),
        'required_abi': {**EXPECTED_ABI, 'features': dict(EXPECTED_ABI['features'])},
    }


def reviewed_spec(root=None, *, lock_path=None):
    """Read the reviewed lock; nullable output pins never qualify a build."""
    require(lock_path is None or root is None or Path(root) == ROOT,
            'Specify either an Expat root or an explicit lock path')
    path = Path(lock_path) if lock_path is not None else Path(root or ROOT) / 'docs/expat-build.json'
    body = regular_bytes(path, 'Expat build lock')
    spec = json.loads(body)
    require(isinstance(spec, dict), 'Invalid Expat build lock')
    remaining = dict(spec)
    for name in ('expected_library_sha256', 'compiler_sha256'):
        values = remaining.pop(name, None)
        require(isinstance(values, dict) and set(values) == set(TARGETS),
                'Expat build lock requires both native ' + name + ' records')
        require(all(value is None or isinstance(value, str) and SHA256.fullmatch(value)
                    for value in values.values()), 'Invalid Expat ' + name)
    script_hash = remaining.pop('build_script_sha256', None)
    require(isinstance(script_hash, str) and SHA256.fullmatch(script_hash),
            'Missing reviewed Expat build script hash')
    require(remaining == immutable_spec(), 'Expat build lock differs from reviewed source or recipe facts')
    require(body == json_bytes(spec), 'Expat build lock must use canonical JSON bytes')
    checked(regular_bytes(Path(__file__), 'Expat build script'), script_hash, 'Expat build script')
    checked(regular_bytes(Path(fortify.__file__), 'Fortify source helper'),
            FORTIFY_HELPER_SHA256, 'Fortify source helper')
    return spec


def require_output_pins(spec):
    for field in ('expected_library_sha256', 'compiler_sha256'):
        require(all(isinstance(value, str) and SHA256.fullmatch(value)
                    for value in spec[field].values()),
                'Expat ' + field + ' must be reviewed for both architectures; preparation is not qualified')


def source_replay_record():
    return {'schema': 'keep-expat-source-replay-v2', 'identity': BUILD_IDENTITY,
            'source_sha256': SOURCE_SHA256, 'vendor_recipe_sha256': RECIPE_SHA256,
            'patch_manifest_sha256': PATCH_SHA256, 'commits': list(COMMITS),
            'original_files': dict(ORIGINAL_FILES), 'patched_files': dict(PATCHED_FILES),
            'fortify_headers': fortify.reviewed_spec()}


def source_download_records():
    """Actual original downloads retained below the common Expat replay root."""
    return [
        {'path': 'expat-2.9.0.tar.xz', 'url': SOURCE_URL, 'sha256': SOURCE_SHA256, 'role': 'upstream-source'},
        {'path': 'APKBUILD', 'url': RECIPE_URL, 'sha256': RECIPE_SHA256, 'role': 'matching-apk-build-script'},
        *[{**record, 'path': 'fortify/' + record['path']} for record in fortify.source_download_records()],
    ]


def _manifest(spec, arch, library_hash, compiler_hash, *, qualified):
    require(arch in TARGETS, 'Unsupported native Expat architecture')
    return {
        'schema': 'keep-expat-patched-security-v1', 'architecture': arch,
        'qualified': qualified, 'purpose': 'reviewed-build' if qualified else 'preparation-only',
        'identity': BUILD_IDENTITY, 'upstream_version': '2.9.0',
        'vendor_package_version': '2.9.0-r0',
        'vendor_apk_signature_applies_to_replacement': False,
        'build_lock_sha256': digest(json_bytes(spec)),
        'build_script_sha256': spec['build_script_sha256'],
        'build_image': BUILD_IMAGE, 'source_sha256': SOURCE_SHA256,
        'patch_manifest_sha256': PATCH_SHA256, 'patched_files': dict(PATCHED_FILES),
        'source_replay_sha256': digest(json_bytes(source_replay_record())),
        'fortify_source_manifest_sha256': digest(fortify.source_lock_bytes()),
        'compiler': {'path': '/usr/bin/gcc', 'target': TARGETS[arch], 'sha256': compiler_hash},
        'library': {**spec['library'], 'sha256': library_hash},
        'hardening': dict(EXPECTED_HARDENING),
        'abi': {**EXPECTED_ABI, 'features': dict(EXPECTED_ABI['features'])},
    }


def expected_manifest(arch, root=ROOT, *, lock_path=None):
    spec = reviewed_spec(root, lock_path=lock_path)
    require_output_pins(spec)
    require(arch in TARGETS, 'Unsupported native Expat architecture')
    return _manifest(spec, arch, spec['expected_library_sha256'][arch],
                     spec['compiler_sha256'][arch], qualified=True)


def verify_build_manifest(manifest, arch, root=ROOT, *, lock_path=None):
    require(isinstance(manifest, dict) and manifest.get('qualified') is True
            and manifest.get('purpose') == 'reviewed-build',
            'Expat preparation or unqualified manifest cannot qualify a runtime')
    require(manifest == expected_manifest(arch, root, lock_path=lock_path),
            'Expat replacement manifest differs from reviewed build/source/library identities')
    return manifest


def empty_directory(path):
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts, 'Expat output must be an absolute path')
    require(not any(part.is_symlink() for part in (path, *path.parents)),
            'Expat output path must not contain symlinks')
    require(not path.exists() or path.is_dir() and not any(path.iterdir()),
            'Expat output directory must be empty')
    path.mkdir(parents=True, exist_ok=True)
    return path


def source_members(body):
    """Return only regular bounded members below the exact release directory."""
    files, total, seen = {}, 0, set()
    with tarfile.open(fileobj=io.BytesIO(body), mode='r:xz') as archive:
        for number, member in enumerate(archive, 1):
            path = PurePosixPath(member.name)
            require(member.name and not path.is_absolute() and '..' not in path.parts
                    and '\\' not in member.name and '\x00' not in member.name
                    and path.parts[0] == SOURCE_DIRECTORY,
                    'Unsafe Expat source archive path')
            name = path.as_posix()
            require(name not in seen, 'Duplicate Expat source archive path')
            seen.add(name)
            total += member.size
            require(number <= 10000 and 0 <= member.size <= LIMIT and total <= 64 * 1024 * 1024,
                    'Expat source archive exceeds inventory limit')
            require(member.isfile() or member.isdir(), 'Unsupported Expat source archive member')
            require(not member.mode & 0o7000, 'Unsafe Expat source file mode')
            if member.isfile():
                require(len(path.parts) >= 2, 'Invalid Expat source file path')
                relative = '/'.join(path.parts[1:])
                files[relative] = (archive.extractfile(member).read(), member.mode & 0o777)
    require(files, 'Empty Expat source archive')
    return files


def apply_source_patches(files, manifest):
    require(isinstance(manifest, dict) and manifest.get('schema') == 'keep-expat-patches-v1'
            and manifest.get('upstream_version') == '2.9.0'
            and manifest.get('patched_files') == PATCHED_FILES,
            'Invalid Expat patch manifest')
    require([row['commit'] for row in manifest.get('patches', [])] == list(COMMITS),
            'Expat upstream patch sequence differs')
    result = dict(files)
    for path, expected in ORIGINAL_FILES.items():
        require(path in result, 'Missing original Expat source file')
        checked(result[path][0], expected, 'Original Expat source ' + path)
    for patch in manifest['patches']:
        for file in patch['files']:
            path = file['path']
            require(path in PATCHED_FILES, 'Unreviewed Expat patch target')
            body, mode = result[path]
            checked(body, file['before_sha256'], 'Expat patch input ' + path)
            for hunk in file['hunks']:
                before, after = hunk['before'].encode(), hunk['after'].encode()
                require(before and body.count(before) == 1,
                        'Expat security patch context mismatch: ' + path)
                body = body.replace(before, after, 1)
            checked(body, file['after_sha256'], 'Expat patch output ' + path)
            result[path] = (body, mode)
    for path, expected in PATCHED_FILES.items():
        checked(result[path][0], expected, 'Complete patched Expat source ' + path)
    return result


def replay_sources(output, *, root=ROOT, lock_path=None, fetch=download):
    """Recreate full matching sources offline when fetch supplies retained bytes.

    This step does not compile or qualify a runtime and accepts an unpinned lock
    solely to prepare the exact same source inputs for initial native builds.
    """
    spec = reviewed_spec(root, lock_path=lock_path)
    patch_body = checked(regular_bytes(Path(root) / PATCH_PATH, 'Expat patch manifest'),
                         PATCH_SHA256, 'Expat patch manifest')
    archive = checked(fetch(SOURCE_URL), SOURCE_SHA256, 'Expat release source')
    require(hashlib.sha512(archive).hexdigest() == SOURCE_SHA512,
            'Expat release source SHA-512 mismatch')
    recipe = checked(fetch(RECIPE_URL), RECIPE_SHA256, 'Original Expat APKBUILD')
    files = apply_source_patches(source_members(archive), json.loads(patch_body))
    checked(files['COPYING'][0], COPYING_SHA256, 'Expat full COPYING notice')
    destination = empty_directory(output)
    source = destination / SOURCE_DIRECTORY
    source.mkdir()
    for name, (body, mode) in sorted(files.items()):
        path = source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body)
        path.chmod(mode)
        os.utime(path, (int(SOURCE_DATE_EPOCH), int(SOURCE_DATE_EPOCH)))
    retained = {
        'expat-2.9.0.tar.xz': archive, 'expat_security_patches.json': patch_body,
        'APKBUILD': recipe, 'build_patched_expat.py': regular_bytes(Path(__file__), 'Expat build script'),
        'fortify_header_sources.py': regular_bytes(Path(fortify.__file__), 'Fortify source helper'),
        'expat-build.json': json_bytes(spec), 'SOURCE_REPLAY.json': json_bytes(source_replay_record()),
    }
    for name, body in retained.items():
        (destination / name).write_bytes(body)
    fortify.prepare(destination / 'fortify', fetch=fetch)
    return source_replay_record()


def native_architecture():
    require(platform.system() == 'Linux', 'Expat build requires native Linux')
    arch = {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(platform.machine())
    require(arch in TARGETS, 'Unsupported native Expat build architecture')
    return arch


def build_environment(arch):
    require(arch in TARGETS, 'Unsupported native Expat architecture')
    environment = dict(ENVIRONMENT)
    if ARCHITECTURE_CFLAGS[arch]:
        environment['CFLAGS'] += ' ' + ARCHITECTURE_CFLAGS[arch]
    return environment


def compiler_identity(arch):
    environment = build_environment(arch)
    compiler = Path('/usr/bin/gcc').resolve(strict=True)
    compiler_hash = digest(regular_bytes(compiler, 'Native Expat compiler', 128 * 1024 * 1024))
    target = subprocess.check_output(['/usr/bin/gcc', '-dumpmachine'], env=environment,
                                     timeout=30).decode().strip()
    require(target == TARGETS[arch], 'Expat compiler target differs from native reviewed target')
    version = subprocess.check_output(['/usr/bin/gcc', '--version'], env=environment,
                                      timeout=30).decode()
    return compiler_hash, version


def compiler_diagnostics(macros, arch):
    """Bounded non-secret evidence for a failed native compiler precondition."""
    names = ('_FORTIFY_SOURCE', '_FORTIFY_STRING_H', '_FORTIFY_HEADERS_H',
             '__SSP_STRONG__', '__SSP__', '__OPTIMIZE__', '__GNUC__', '__GNUC_MINOR__')
    headers = {}
    for name in ('/usr/include/string.h', '/usr/include/fortify/string.h',
                 '/usr/include/fortify/fortify-headers.h',
                 str(WORK / 'fortify/include/string.h'), str(WORK / 'fortify/include/fortify-headers.h')):
        path = Path(name)
        item = {'exists': path.exists(), 'is_symlink': path.is_symlink()}
        if path.is_file() and not path.is_symlink() and path.stat().st_size <= 512 * 1024:
            item['sha256'] = digest(regular_bytes(path, 'Compiler diagnostic header', 512 * 1024))
        headers[name] = item
    environment = build_environment(arch)
    return {'schema': 'keep-expat-compiler-diagnostics-v1', 'architecture': arch,
            'macros': {name: macros.get(name) for name in names}, 'headers': headers,
            'cflags': environment['CFLAGS'], 'cppflags': environment['CPPFLAGS']}


def compiler_hardening(arch):
    """Check effective SSP and fortify headers, rather than only spelling flags."""
    environment = build_environment(arch)
    command = ['/usr/bin/gcc', *shlex.split(environment['CFLAGS']),
               *shlex.split(environment['CPPFLAGS']), '-dM', '-E', '-x', 'c', '-']
    output = subprocess.check_output(command, input=b'#include <string.h>\n',
                                     env=environment, timeout=30).decode()
    macros = dict(re.findall(r'^#define (\w+)(?: ([^\n]*))?$', output, re.M))
    if not (macros.get('_FORTIFY_SOURCE') == '2' and '_FORTIFY_STRING_H' in macros
            and '__SSP_STRONG__' in macros):
        raise ValueError('Expat effective compiler stack protection or fortify headers are missing; '
                         + json.dumps(compiler_diagnostics(macros, arch), sort_keys=True))
    return {'fortify_source': 2, 'fortify_headers_active': True, 'stack_protector_strong': True}


def check_library(body, arch):
    require(len(body) >= 64 and body[:6] == b'\x7fELF\x02\x01',
            'Expat replacement must be a 64-bit little-endian ELF library')
    require(int.from_bytes(body[16:18], 'little') == 3
            and int.from_bytes(body[18:20], 'little') == {'amd64': 62, 'arm64': 183}[arch],
            'Expat replacement ELF architecture or type differs')


def elf_protections(body, arch):
    """Inspect final ELF bytes without relying on readelf in a shell-free image."""
    check_library(body, arch)

    def bounded(offset, size):
        require(0 <= offset <= len(body) and 0 <= size <= len(body) - offset,
                'Invalid Expat ELF table bounds')
        return body[offset:offset + size]

    def string(table, offset):
        require(0 <= offset < len(table), 'Invalid Expat ELF string offset')
        end = table.find(b'\0', offset)
        require(end >= offset, 'Unterminated Expat ELF string')
        return table[offset:end].decode('ascii')

    header = struct.unpack('<16sHHIQQQIHHHHHH', bounded(0, 64))
    phoff, shoff, phsize, phcount, shsize, shcount = (
        header[5], header[6], header[9], header[10], header[11], header[12])
    require(phsize == 56 and shsize == 64 and 0 < phcount <= 128 and 0 < shcount <= 1024,
            'Invalid Expat ELF header table dimensions')
    programs = [struct.unpack('<IIQQQQQQ', bounded(phoff + number * phsize, phsize))
                for number in range(phcount)]
    stacks = [row for row in programs if row[0] == 0x6474e551]
    require(len(stacks) == 1 and stacks[0][1] == 6,
            'Expat GNU_STACK must explicitly be readable/writable and non-executable')
    relro = [row for row in programs if row[0] == 0x6474e552]
    require(len(relro) == 1 and relro[0][6] > 0, 'Expat ELF requires GNU_RELRO protection')
    dynamic = [row for row in programs if row[0] == 2]
    require(len(dynamic) == 1 and dynamic[0][5] % 16 == 0,
            'Invalid Expat ELF dynamic table')
    entries = struct.iter_unpack('<qQ', bounded(dynamic[0][2], dynamic[0][5]))
    tags = {}
    ended = False
    for tag, value in entries:
        if tag == 0:
            ended = True
            break
        tags.setdefault(tag, []).append(value)
    require(ended, 'Unterminated Expat ELF dynamic table')
    require(24 in tags or any(value & 8 for value in tags.get(30, []))
            or any(value & 1 for value in tags.get(0x6ffffffb, [])),
            'Expat ELF requires immediate binding (NOW)')
    require(len(tags.get(5, [])) == len(tags.get(10, [])) == len(tags.get(14, [])) == 1,
            'Expat ELF requires one string table and SONAME')
    address, size = tags[5][0], tags[10][0]
    loads = [row for row in programs if row[0] == 1 and row[3] <= address
             and address + size <= row[3] + row[5]]
    require(len(loads) == 1, 'Expat ELF string table is outside its file-backed load segment')
    strings = bounded(loads[0][2] + address - loads[0][3], size)
    require(string(strings, tags[14][0]) == 'libexpat.so.1',
            'Built Expat SONAME differs from the vendor ABI')
    require([string(strings, value) for value in tags.get(1, [])]
            == ['libc.musl-' + {'amd64': 'x86_64', 'arm64': 'aarch64'}[arch] + '.so.1'],
            'Expat replacement has unreviewed dynamic dependencies')
    sections = [struct.unpack('<IIQQQQIIQQ', bounded(shoff + number * shsize, shsize))
                for number in range(shcount)]
    symbols = [row for row in sections if row[1] == 11]
    require(len(symbols) == 1 and symbols[0][9] == 24 and symbols[0][5] % 24 == 0,
            'Invalid Expat ELF dynamic symbol table')
    symbol_section = symbols[0]
    require(symbol_section[6] < len(sections), 'Invalid Expat ELF symbol string-table link')
    symbol_strings = sections[symbol_section[6]]
    require(symbol_strings[1] == 3, 'Expat ELF symbols require a string table')
    symbol_names = bounded(symbol_strings[4], symbol_strings[5])
    exports, stack_protected = [], False
    for name, info, other, index, _, _ in struct.iter_unpack(
            '<IBBHQQ', bounded(symbol_section[4], symbol_section[5])):
        symbol = string(symbol_names, name)
        if index == 0 and symbol == '__stack_chk_fail':
            stack_protected = True
        if index != 0 and info >> 4 in (1, 2) and info & 15 in (2, 10) and other & 3 == 0:
            if symbol.startswith('XML_'):
                exports.append(symbol)
    require(stack_protected, 'Expat ELF has no stack-protector failure binding')
    exports.sort()
    export_hash = digest(('\n'.join(exports) + '\n').encode())
    require(len(exports) == EXPECTED_ABI['export_count']
            and export_hash == EXPECTED_ABI['exports_sha256'],
            'Expat exported API differs from the complete 2.9.0 ABI')
    return {'hardening': {key: value for key, value in EXPECTED_HARDENING.items()
                          if key != 'fortify_source'},
            'exports_sha256': export_hash, 'export_count': len(exports)}


def runtime_features(library):
    """The build uses this exact file; final delivery checks normal loading."""
    class Feature(ctypes.Structure):
        _fields_ = [('feature', ctypes.c_int), ('name', ctypes.c_char_p), ('value', ctypes.c_long)]

    loaded = ctypes.CDLL(str(library))
    loaded.XML_GetFeatureList.argtypes = []
    loaded.XML_GetFeatureList.restype = ctypes.POINTER(Feature)
    table = loaded.XML_GetFeatureList()
    require(bool(table), 'Expat feature list is missing')
    features = {}
    for number in range(64):
        item = table[number]
        if item.feature == 0:
            break
        require(item.name is not None, 'Expat feature name is missing')
        name = item.name.decode('ascii')
        require(name not in features, 'Duplicate Expat feature')
        features[name] = item.value
    else:
        raise ValueError('Expat feature list is not bounded')
    require(features == EXPECTED_ABI['features'], 'Expat default build features differ from the vendor ABI')
    return features


def build(output, preparation=False, *, architecture=None, root=ROOT, fetch=download):
    require(type(preparation) is bool, 'Expat preparation must be explicit')
    spec = reviewed_spec(root)
    if not preparation:
        require_output_pins(spec)
    arch = native_architecture()
    require(architecture is None or architecture == arch, 'Expat cross-compilation is not qualified')
    require(os.environ.get('KEEP_EXPAT_BUILD_IMAGE') == BUILD_IMAGE,
            'Expat build image declaration differs from reviewed DHI development image')
    compiler_hash, compiler_version = compiler_identity(arch)
    expected_compiler = spec['compiler_sha256'][arch]
    require(expected_compiler is None or compiler_hash == expected_compiler,
            'Expat native compiler differs from reviewed compiler hash')
    destination = empty_directory(output)
    require(destination != WORK and not destination.is_relative_to(WORK)
            and not WORK.is_relative_to(destination), 'Expat output overlaps its fixed build workspace')
    replay_sources(WORK, root=root, fetch=fetch)
    fortify.verify_prepared_headers(WORK / 'fortify/include')
    effective_hardening = compiler_hardening(arch)
    source = WORK / SOURCE_DIRECTORY
    environment = build_environment(arch)
    configure = ['./configure', '--build=' + TARGETS[arch], '--host=' + TARGETS[arch],
                 *CONFIGURE_OPTIONS]
    for command in (configure, ['make', '-j2'], ['make', 'check']):
        subprocess.run(command, cwd=source, env=environment, check=True, timeout=1800)
    built = source / 'lib' / '.libs' / LIBRARY
    library = regular_bytes(built, 'Built Expat replacement')
    protections = elf_protections(library, arch)
    features = runtime_features(built)
    fortify.verify_prepared_headers(WORK / 'fortify/include')
    library_hash = digest(library)
    expected_library = spec['expected_library_sha256'][arch]
    require(expected_library is None or library_hash == expected_library,
            'Built Expat library differs from reviewed native output hash')
    manifest = _manifest(spec, arch, library_hash, compiler_hash, qualified=not preparation)
    if not preparation:
        verify_build_manifest(manifest, arch, root)
    (destination / LIBRARY).write_bytes(library)
    (destination / LIBRARY).chmod(0o755)
    (destination / 'COPYING').write_bytes(regular_bytes(source / 'COPYING', 'Expat COPYING'))
    for name in ('expat-2.9.0.tar.xz', 'expat_security_patches.json', 'APKBUILD',
                 'build_patched_expat.py', 'fortify_header_sources.py',
                 'expat-build.json', 'SOURCE_REPLAY.json'):
        shutil.copyfile(WORK / name, destination / name)
    shutil.copytree(WORK / 'fortify', destination / 'fortify')
    (destination / 'BUILD_ENVIRONMENT.json').write_bytes(json_bytes({
        'compiler_version': compiler_version, 'compiler_sha256': compiler_hash,
        'configure': configure, 'environment': environment,
        'effective_compiler_hardening': effective_hardening,
        'elf_verification': protections, 'runtime_features': features,
        'build_image_declaration': BUILD_IMAGE,
        'image_identity_requires_external_provenance_verification': True,
        'upstream_make_check_passed': True,
    }))
    # Write the accepted/unqualified record last; a partial build has no receipt.
    (destination / 'EXPAT_PATCHED_SECURITY.json').write_bytes(json_bytes(manifest))
    require(WORK == Path('/opt/keep-expat-build') and not WORK.is_symlink(),
            'Expat workspace cleanup identity differs')
    shutil.rmtree(WORK)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True)
    parser.add_argument('--preparation', action='store_true')
    parser.add_argument('--architecture', choices=TARGETS)
    parser.add_argument('--root', type=Path, default=ROOT)
    args = parser.parse_args()
    result = build(args.output, args.preparation, architecture=args.architecture, root=args.root)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
