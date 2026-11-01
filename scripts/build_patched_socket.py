#!/usr/bin/env python3
"""Prepare a source-bound native _socket overlay; preparation cannot qualify images.

The final installer must require reviewed output hashes for both architectures.
This command currently produces preparatory evidence only, never installs files.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import platform
import subprocess
import sys
import sysconfig
import tarfile
import urllib.request

SOURCE_URL = 'https://www.python.org/ftp/python/3.14.8/Python-3.14.8.tar.xz'
SOURCE_SHA256 = 'c2215904f02b175596dc49351585104f4bc20341e1c47378b26a2c274360ce73'
PATCH_PATH = Path(__file__).with_name('python_socket_patches.json')
WORK = Path('/opt/keep-socket-build')
SOURCE_DIRECTORY = 'Python-3.14.8'


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


def preparation(output):
    require(platform.system() == 'Linux' and sys.version_info[:3] == (3, 14, 8),
            'Socket preparation requires native Linux Python 3.14.8')
    arch = {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(platform.machine())
    require(arch is not None, 'Unsupported native socket architecture')
    require(output.is_absolute() and not output.exists() and not WORK.exists(),
            'Socket preparation requires new absolute workspaces')
    output.mkdir(parents=True)
    with urllib.request.urlopen(SOURCE_URL, timeout=90) as response:
        body = response.read(32 * 1024 * 1024 + 1)
    require(len(body) <= 32 * 1024 * 1024, 'Python source download exceeds bound')
    source = extract_source(body, WORK)
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
              '-ffile-prefix-map=' + str(WORK) + '=.']
    command = ['/usr/bin/gcc', *cflags, '-shared', 'Modules/socketmodule.c',
               '-Wl,--as-needed,-O1,--build-id=sha1,-z,relro,-z,now,-z,noexecstack',
               '-o', str(library)]
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
              'compiler_version': subprocess.check_output([str(compiler), '--version']).decode(),
              'configure': configure, 'compile': command,
              'extension': library.name, 'extension_sha256': digest(library.read_bytes()),
              'probes': json.loads(probes)}
    (output / 'SOCKET_PREPARATION.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record, sort_keys=True))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--preparation', action='store_true', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    preparation(args.output)
