#!/usr/bin/env python3
"""Build a source-bound native _socket overlay with separate preparatory evidence."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import subprocess
import sys
import sysconfig
import tarfile
import urllib.request

if __package__:
    from . import build_patched_expat as compiler_profile
else:
    import build_patched_expat as compiler_profile

SOURCE_URL = 'https://www.python.org/ftp/python/3.14.8/Python-3.14.8.tar.xz'
SOURCE_SHA256 = 'c2215904f02b175596dc49351585104f4bc20341e1c47378b26a2c274360ce73'
PATCH_PATH = Path(__file__).with_name('python_socket_patches.json')
WORK = Path('/opt/keep-socket-build')
SOURCE_DIRECTORY = 'Python-3.14.8'
ROOT = Path(__file__).resolve().parents[1]
IDENTITY = 'keep-python-3.14.8-socket-nul-v1'
ARCH_NAMES = {'amd64': 'x86_64', 'arm64': 'aarch64'}


def json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()


def reviewed_spec(root=ROOT, *, lock_path=None):
    path = Path(lock_path) if lock_path is not None else Path(root) / 'docs/python-socket-build.json'
    require(path.is_file() and not path.is_symlink(), 'Missing reviewed socket build lock')
    spec = json.loads(path.read_bytes())
    patch = json.loads(PATCH_PATH.read_bytes())
    require(set(spec) == {'schema', 'identity', 'source_url', 'source_sha256',
                         'patch_sha256', 'patched_source_sha256', 'native'},
            'Unexpected socket build lock fields')
    require(spec['schema'] == 'keep-socket-build-v1' and spec['identity'] == IDENTITY
            and spec['source_url'] == SOURCE_URL and spec['source_sha256'] == SOURCE_SHA256
            and spec['patch_sha256'] == digest(PATCH_PATH.read_bytes())
            and spec['patched_source_sha256'] == patch['after_sha256']
            and set(spec['native']) == set(ARCH_NAMES), 'Socket source/build identity differs')
    for arch, row in spec['native'].items():
        require(set(row) == {'extension_sha256', 'original_extension_sha256',
                             'compiler_sha256', 'pyconfig_sha256'}, 'Socket native lock fields differ')
        require(all(isinstance(v, str) and len(v) == 64
                    and all(c in '0123456789abcdef' for c in v) for v in row.values()),
                'Socket preparation pins cannot qualify a runtime')
    return spec


def extension_path(arch):
    require(arch in ARCH_NAMES, 'Unsupported socket architecture')
    return '/usr/lib/python3.14/lib-dynload/_socket.cpython-314-' + ARCH_NAMES[arch] + '-linux-musl.so'


def expected_manifest(arch, root=ROOT, *, lock_path=None):
    spec = reviewed_spec(root, lock_path=lock_path)
    require(arch in ARCH_NAMES, 'Unsupported socket architecture')
    return {'schema': 'keep-socket-security-v1', 'qualified': True, 'identity': IDENTITY,
            'architecture': arch, 'build_lock_sha256': digest(json_bytes(spec)),
            'source_sha256': SOURCE_SHA256, 'patch_sha256': spec['patch_sha256'],
            'source_file_sha256': spec['patched_source_sha256'],
            'compiler_sha256': spec['native'][arch]['compiler_sha256'],
            'pyconfig_sha256': spec['native'][arch]['pyconfig_sha256'],
            'library': {'path': extension_path(arch),
                        'sha256': spec['native'][arch]['extension_sha256']}}


def verify_manifest(manifest, arch, root=ROOT, *, lock_path=None):
    require(manifest == expected_manifest(arch, root, lock_path=lock_path),
            'Socket replacement manifest differs')
    return manifest


def verify_runtime(arch, root=ROOT, app=Path('/app')):
    import _socket
    manifest_path = Path(app) / 'SOCKET_SECURITY.json'
    require(manifest_path.is_file() and not manifest_path.is_symlink(), 'Missing socket manifest')
    body = manifest_path.read_bytes()
    require(len(body) <= 128 * 1024, 'Socket manifest exceeds bound')
    manifest = verify_manifest(json.loads(body), arch, root,
                               lock_path=Path(app) / 'PYTHON_SOCKET_BUILD.json')
    require(body == json_bytes(manifest), 'Noncanonical socket manifest')
    path = Path(manifest['library']['path'])
    require(not path.is_symlink() and path.is_file() and path.resolve(strict=True) == path
            and Path(_socket.__file__) == path and path.stat().st_size < 4 * 1024 * 1024
            and digest(path.read_bytes()) == manifest['library']['sha256'],
            'Ordinary socket import differs from reviewed canonical extension')
    return manifest


def digest(body):
    return hashlib.sha256(body).hexdigest()


def require(ok, message):
    if not ok:
        raise ValueError(message)


def patched_source(body, manifest):
    require(manifest.get('schema') == 'keep-python-socket-patches-v1'
            and manifest.get('path') == 'Modules/socketmodule.c'
            and manifest.get('upstream_version') == '3.14.8', 'Wrong socket patch scope')
    require(digest(body) == manifest['before_sha256'], 'Socket source input differs')
    for hunk in manifest['hunks']:
        before, after = hunk['before'].encode(), hunk['after'].encode()
        require(before and body.count(before) == 1, 'Socket patch context differs')
        body = body.replace(before, after, 1)
    require(digest(body) == manifest['after_sha256'], 'Socket patched source differs')
    return body


def extract_source(body, destination):
    require(digest(body) == SOURCE_SHA256, 'Python source archive differs')
    require(not destination.exists(), 'Socket source workspace already exists')
    destination.mkdir(parents=True)
    seen, total = set(), 0
    with tarfile.open(fileobj=io.BytesIO(body), mode='r:xz') as archive:
        for number, member in enumerate(archive, 1):
            path = PurePosixPath(member.name)
            require(not path.is_absolute() and '..' not in path.parts
                    and path.parts and path.parts[0] == SOURCE_DIRECTORY
                    and '\\' not in member.name and '\0' not in member.name,
                    'Unsafe Python source member')
            require(member.name not in seen and (member.isfile() or member.isdir()),
                    'Duplicate or special Python source member')
            seen.add(member.name)
            total += member.size
            require(number <= 40000 and 0 <= member.size <= 16 * 1024 * 1024
                    and total <= 200 * 1024 * 1024 and not member.mode & 0o7000,
                    'Python source exceeds bounds')
            target = destination.joinpath(*path.parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(archive.extractfile(member).read())
                target.chmod(member.mode & 0o777)
    return destination / SOURCE_DIRECTORY


def build(output, preparation=False):
    require(platform.system() == 'Linux' and sys.version_info[:3] == (3, 14, 8),
            'Socket preparation requires native Linux Python 3.14.8')
    arch = {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(platform.machine())
    require(arch is not None, 'Unsupported native socket architecture')
    require(output.is_absolute() and not output.exists() and not WORK.exists(),
            'Socket preparation requires new absolute workspaces')
    output.mkdir(parents=True)
    spec = None if preparation else reviewed_spec()
    import _socket
    original = Path(_socket.__file__)
    require(original.is_file() and not original.is_symlink(), 'Original socket is not regular')
    # Numeric-only flags prohibit DNS even in the deliberately vulnerable control.
    rows = _socket.getaddrinfo('127.0.0.1\0ignored', '8\0ignored', _socket.AF_INET,
        _socket.SOCK_STREAM, 0, _socket.AI_NUMERICHOST | _socket.AI_NUMERICSERV)
    require(rows and all(row[4] == ('127.0.0.1', 8) for row in rows),
            'Original socket no longer reproduces the reviewed numeric truncation')
    compiler_hash, _ = compiler_profile.compiler_identity(arch)
    require(compiler_hash == compiler_profile.reviewed_spec()['compiler_sha256'][arch],
            'Socket compiler differs from reviewed native toolchain')
    with urllib.request.urlopen(SOURCE_URL, timeout=90) as response:
        body = response.read(32 * 1024 * 1024 + 1)
    require(len(body) <= 32 * 1024 * 1024, 'Python source download exceeds bound')
    source = extract_source(body, WORK)
    compiler_profile.fortify.prepare(WORK / 'fortify')
    compiler_profile.fortify.verify_prepared_headers(WORK / 'fortify/include')
    patch_body = PATCH_PATH.read_bytes()
    manifest = json.loads(patch_body)
    target = source / 'Modules/socketmodule.c'
    target.write_bytes(patched_source(target.read_bytes(), manifest))
    env = {**os.environ, 'SOURCE_DATE_EPOCH': '1793550000', 'LC_ALL': 'C', 'TZ': 'UTC'}
    configure = ['./configure', '--prefix=/usr', '--without-ensurepip',
                 '--disable-test-modules', '--with-system-expat']
    subprocess.run(configure, cwd=source, env=env, check=True, timeout=900)
    suffix = sysconfig.get_config_var('EXT_SUFFIX')
    require(isinstance(suffix, str) and suffix.startswith('.cpython-314-')
            and suffix.endswith('.so'), 'Unexpected Python extension ABI')
    library = output / ('_socket' + suffix)
    cflags = ['-Os', '-fPIC', '-fstack-protector-strong', '-fstack-clash-protection',
              '-Wformat', '-Werror=format-security', '-D_FORTIFY_SOURCE=2',
              '-DPy_BUILD_CORE_MODULE', '-I.', '-IInclude', '-IInclude/internal',
              '-I' + str(WORK / 'fortify/include'),
              '-ffile-prefix-map=' + str(WORK) + '=.']
    command = ['/usr/bin/gcc', *cflags, '-shared', 'Modules/socketmodule.c',
               '-Wl,--as-needed,-O1,--build-id=sha1,-z,relro,-z,now,-z,noexecstack',
               '-o', str(library)]
    macros = subprocess.check_output(['/usr/bin/gcc', *cflags, '-dM', '-E', '-x', 'c', '-'],
                                     input=b'#include <string.h>\n', cwd=source, env=env)
    defines = dict(re.findall(r'^#define (\w+)(?: ([^\n]*))?$', macros.decode(), re.M))
    require(defines.get('_FORTIFY_SOURCE') == '2' and '_FORTIFY_STRING_H' in defines
            and '__SSP_STRONG__' in defines, 'Socket effective compiler hardening differs')
    hardening = {'fortify_source': 2, 'fortify_headers_active': True,
                 'stack_protector_strong': True}
    subprocess.run(command, cwd=source, env=env, check=True, timeout=180)
    subprocess.run(['/usr/bin/strip', '--strip-unneeded', str(library)], check=True)
    probes = subprocess.check_output([sys.executable, '-B',
        str(Path(__file__).with_name('socket_security_checks.py')),
        '--extension', str(library)], env=env, timeout=30)
    (output / 'SOCKET_PROBES.json').write_bytes(probes)
    (output / 'python_socket_patches.json').write_bytes(patch_body)
    (output / 'socketmodule.c').write_bytes(target.read_bytes())
    (output / 'pyconfig.h').write_bytes((source / 'pyconfig.h').read_bytes())
    (output / 'LICENSE').write_bytes((source / 'LICENSE').read_bytes())
    compiler = Path('/usr/bin/gcc').resolve(strict=True)
    record = {'schema': 'keep-socket-preparation-v1', 'qualified': False,
              'architecture': arch, 'source_url': SOURCE_URL,
              'source_sha256': SOURCE_SHA256, 'patch_sha256': digest(patch_body),
              'source_file_sha256': digest(target.read_bytes()),
              'pyconfig_sha256': digest((source / 'pyconfig.h').read_bytes()),
              'compiler_sha256': digest(compiler.read_bytes()),
              'effective_hardening': hardening,
              'original_extension_sha256': digest(original.read_bytes()),
              'original_numeric_truncation_reproduced': True,
              'compiler_version': subprocess.check_output([str(compiler), '--version']).decode(),
              'configure': configure, 'compile': command,
              'extension': library.name, 'extension_sha256': digest(library.read_bytes()),
              'probes': json.loads(probes)}
    (output / 'SOCKET_PREPARATION.json').write_text(json.dumps(record, indent=2) + '\n')
    if not preparation:
        for field in ('extension_sha256', 'original_extension_sha256',
                      'compiler_sha256', 'pyconfig_sha256'):
            require(record[field] == spec['native'][arch][field],
                    'Socket native build differs from reviewed ' + field)
        (output / 'SOCKET_SECURITY.json').write_bytes(json_bytes(expected_manifest(arch)))
        (output / 'PYTHON_SOCKET_BUILD.json').write_bytes(json_bytes(spec))
    print(json.dumps(record, sort_keys=True))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--preparation', action='store_true')
    mode.add_argument('--build', action='store_true')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    build(args.output, preparation=args.preparation)
