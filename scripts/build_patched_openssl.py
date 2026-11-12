"""Build source-bound OpenSSL backports without relabeling the vendor APKs.

Preparation discovers output hashes. Only a build reproducing reviewed native
pins can emit a runtime receipt. No FIPS module or certification is supplied.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import shutil
import struct
import subprocess
import tarfile
import tempfile
import urllib.request

if __package__:
    from . import build_patched_expat as profile
    from . import openssl_build_tools as perl
else:
    import build_patched_expat as profile
    import openssl_build_tools as perl

ROOT = Path(__file__).resolve().parents[1]
WORK = Path('/opt/keep-openssl-build')
SOURCE_DIRECTORY = 'openssl-3.5.9'
SOURCE_URL = 'https://github.com/openssl/openssl/releases/download/openssl-3.5.9/openssl-3.5.9.tar.gz'
SOURCE_SHA256 = '603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a'
BUILD_IMAGE = profile.BUILD_IMAGE
IDENTITY = 'keep-openssl-3.5.9-november-backports-v1'
COMMITS = ('159e1de0c448d7b9f09ad768c8e141def4aa1eb4',
           'a0051cfe699bf5a047bc1c4faef65f80f7987366',
           '1a73dc590cbad62d6f0329ea4779eadaa8d8fd75',
           'f6244675833e097c2429a40d1b206d95385bd42f',
           '257a3427aa0ef8d9dd2ef5b3e2d1c021a221b116')
FILES = ('usr/lib/libcrypto.so.3', 'usr/lib/libssl.so.3', 'usr/bin/openssl',
         'usr/lib/engines-3/afalg.so', 'usr/lib/engines-3/capi.so',
         'usr/lib/engines-3/loader_attic.so', 'usr/lib/engines-3/padlock.so',
         'usr/lib/ossl-modules/legacy.so')
OPTIONS = ('--prefix=/usr', '--libdir=lib', '--openssldir=/etc/ssl',
           'enable-fips', 'enable-ktls', 'shared', 'no-zlib', 'no-async', 'no-comp',
           'no-idea', 'no-mdc2', 'no-rc5', 'no-ec2m', 'no-ssl3', 'no-seed',
           'no-weak-ssl-ciphers')
AUXV_URL = ('https://raw.githubusercontent.com/alpinelinux/aports/'
            '013edf8b29199933e8ea34dde460b5584b979042/main/openssl/auxv.patch')
AUXV_SHA512 = ('b2541075148fd5af4552d34158deb1a325f5adced90626dc03fd126f47323cde949'
               'b15b2657523c34b26530b322312a43bd42ada7295b4f2dd1d3b5d11892c62')
require, checked, digest, json_bytes = profile.require, profile.checked, profile.digest, profile.json_bytes


def download(url):
    with urllib.request.urlopen(url, timeout=60) as response:
        body = response.read(128 * 1024 * 1024 + 1)
    require(len(body) <= 128 * 1024 * 1024, 'OpenSSL input exceeds bound')
    return body


def environment(arch):
    result = profile.build_environment(arch)
    result = {k: v.replace('/opt/keep-expat-build', str(WORK)) for k, v in result.items()}
    result['SOURCE_DATE_EPOCH'] = '1794268800'
    # OpenSSL records its flags in libcrypto; deterministic paths are required.
    return result


def facts(root=ROOT):
    def source(name):
        path = Path(root) / 'scripts' / name
        return path if path.is_file() else Path(__file__).with_name(name)
    return {'schema': 'keep-openssl-build-v1', 'identity': IDENTITY,
            'source_url': SOURCE_URL, 'source_sha256': SOURCE_SHA256,
            'patch_sha256': digest(source('openssl_security_patches.json').read_bytes()),
            'build_script_sha256': digest(Path(__file__).read_bytes()),
            'perl_lock_sha256': perl.LOCK_SHA256,
            'perl_helper_sha256': digest(Path(perl.__file__).read_bytes()),
            'compiler_profile_sha256': digest(Path(profile.__file__).read_bytes()),
            'toolchain': {name: {'helper_sha256': digest(Path(module.__file__).read_bytes()),
                                'source_lock_sha256': digest(json_bytes(module.reviewed_spec()))}
                          for name, module in (('fortify', profile.fortify), ('cpp', profile.cpp),
                                               ('build_tools', profile.build_tools))},
            'build_image': BUILD_IMAGE, 'configure_options': list(OPTIONS),
            'environment': {a: environment(a) for a in profile.TARGETS},
            'commits': list(COMMITS), 'files': list(FILES)}


def reviewed_spec(root=ROOT, *, lock_path=None, preparation=False):
    path = Path(lock_path) if lock_path is not None else Path(root) / 'docs/openssl-build.json'
    body = profile.regular_bytes(path, 'OpenSSL build lock')
    spec = json.loads(body)
    require(body == json_bytes(spec), 'OpenSSL build lock is not canonical')
    require({k: v for k, v in spec.items() if k != 'native'} == facts(root),
            'OpenSSL locked build facts differ')
    require(set(spec['native']) == set(profile.TARGETS), 'Both OpenSSL native records are required')
    for row in spec['native'].values():
        require(set(row) == {'compiler_sha256', 'vendor_files', 'files', 'abi'}, 'OpenSSL native fields differ')
        require(set(row['vendor_files']) == set(FILES) and set(row['files']) == set(FILES),
                'OpenSSL output family differs')
        values = [row['compiler_sha256'], *row['vendor_files'].values(), *row['files'].values()]
        require(all(preparation and v is None or isinstance(v, str) and re.fullmatch('[a-f0-9]{64}', v)
                    for v in values), 'Unreviewed OpenSSL native pins cannot qualify a runtime')
        require(preparation or set(row['abi']) == {'libcrypto.so.3', 'libssl.so.3'},
                'OpenSSL vendor ABI is missing')
        for abi in row['abi'].values():
            require(set(abi) == {'exports_sha256', 'export_count', 'version_definitions_sha256'}
                    and type(abi['export_count']) is int and 0 < abi['export_count'] < 100000
                    and all(isinstance(abi[k], str) and re.fullmatch('[a-f0-9]{64}', abi[k])
                            for k in ('exports_sha256', 'version_definitions_sha256')),
                    'OpenSSL ABI identity is incomplete')
    return spec


def expected_manifest(arch, root=ROOT, *, lock_path=None):
    spec = reviewed_spec(root, lock_path=lock_path)
    return {'schema': 'keep-openssl-security-v1', 'identity': IDENTITY, 'qualified': True,
            'architecture': arch, 'build_lock_sha256': digest(json_bytes(spec)),
            'source_sha256': SOURCE_SHA256, 'patch_sha256': spec['patch_sha256'],
            'native': spec['native'][arch], 'upstream_tests': True,
            'vendor_apk_signature_applies_to_replacement': False, 'fips_module_installed': False}


def verify_manifest(manifest, arch, root=ROOT, *, lock_path=None):
    require(manifest == expected_manifest(arch, root, lock_path=lock_path),
            'OpenSSL replacement receipt differs from reviewed source, native or test identities')
    return manifest


def extract_source(body, output):
    checked(body, SOURCE_SHA256, 'OpenSSL release source')
    output = profile.empty_directory(output)
    seen, total = set(), 0
    with tarfile.open(fileobj=io.BytesIO(body), mode='r:gz') as archive:
        for number, member in enumerate(archive, 1):
            path = PurePosixPath(member.name)
            require(path.parts and path.parts[0] == SOURCE_DIRECTORY and not path.is_absolute()
                    and '..' not in path.parts and '\\' not in member.name and '\x00' not in member.name
                    and member.name not in seen, 'Unsafe or repeated OpenSSL source member')
            seen.add(member.name); total += member.size
            require(number <= 30000 and 0 <= member.size <= 32 * 1024 * 1024
                    and total <= 256 * 1024 * 1024 and not member.mode & 0o7000
                    and (member.isfile() or member.isdir()), 'Unsupported OpenSSL source archive member')
            target = output.joinpath(*path.parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(archive.extractfile(member).read()); target.chmod(member.mode & 0o777)
                os.utime(target, (1794268800, 1794268800))
    return output / SOURCE_DIRECTORY


def apply_patches(source, manifest):
    require(manifest['schema'] == 'keep-openssl-patches-v1' and manifest['version'] == '3.5.9'
            and [p['commit'] for p in manifest['patches']] == list(COMMITS), 'OpenSSL patch scope differs')
    for path, checksum in manifest['original_files'].items():
        safe = PurePosixPath(path)
        require(not safe.is_absolute() and '..' not in safe.parts and '\\' not in path and '\x00' not in path,
                'Unsafe OpenSSL original source path')
        checked((source / path).read_bytes(), checksum, 'Original OpenSSL source ' + path)
    for patch in manifest['patches']:
        for row in patch['files']:
            path = PurePosixPath(row['path'])
            require(not path.is_absolute() and '..' not in path.parts and str(path) in manifest['original_files'],
                    'Unexpected OpenSSL patch target')
            target = source / path
            body = checked(target.read_bytes(), row['before_sha256'], 'OpenSSL patch input')
            for hunk in row['hunks']:
                before, after = hunk['before'].encode(), hunk['after'].encode()
                require(before and body.count(before) == 1, 'OpenSSL patch context differs')
                body = body.replace(before, after, 1)
            target.write_bytes(checked(body, row['after_sha256'], 'OpenSSL patch output'))
    for path, checksum in manifest['patched_files'].items():
        checked((source / path).read_bytes(), checksum, 'Complete patched OpenSSL source')


def apply_auxv(source, patch):
    """Replay the exact vendor patch without a fuzzy patch utility."""
    parts = re.split(r'(?m)^--- a/', patch)[1:]
    require(len(parts) == 3, 'Vendor auxv patch file set differs')
    for part in parts:
        name = part.splitlines()[0]
        require(name in {'crypto/armcap.c', 'crypto/ppccap.c', 'crypto/s390xcap.c'},
                'Vendor auxv patch target differs')
        target = source / name
        body = target.read_text()
        for hunk in re.split(r'(?m)^@@[^\n]*\n', part)[1:]:
            before, after = [], []
            for line in hunk.splitlines(keepends=True):
                if line.startswith(' '): before.append(line[1:]); after.append(line[1:])
                elif line.startswith('-'): before.append(line[1:])
                elif line.startswith('+'): after.append(line[1:])
                else: break
            before, after = ''.join(before), ''.join(after)
            require(before and body.count(before) == 1, 'Vendor auxv patch context differs')
            body = body.replace(before, after, 1)
        target.write_text(body)


def replay_sources(output, *, root=ROOT, fetch=download):
    spec = reviewed_spec(root, preparation=True)
    output = profile.empty_directory(output)
    archive = checked(fetch(SOURCE_URL), SOURCE_SHA256, 'OpenSSL source archive')
    (output / (SOURCE_DIRECTORY + '.tar.gz')).write_bytes(archive)
    source = extract_source(archive, output / 'source')
    auxv = fetch(AUXV_URL)
    require(hashlib.sha512(auxv).hexdigest() == AUXV_SHA512, 'Vendor auxv patch differs')
    apply_auxv(source, auxv.decode())
    (output / 'auxv.patch').write_bytes(auxv)
    patch = checked((Path(root) / 'scripts/openssl_security_patches.json').read_bytes(),
                    spec['patch_sha256'], 'OpenSSL patch manifest')
    manifest = json.loads(patch)
    # Retain original upstream patches as well as exact-context replay records.
    for row in manifest['patches']:
        (output / (row['commit'] + '.patch')).write_bytes(
            checked(fetch(row['url']), row['sha256'], 'Original upstream OpenSSL patch'))
    apply_patches(source, manifest)
    (output / 'openssl_security_patches.json').write_bytes(patch)
    return source


def elf_identity(path, arch):
    body = profile.regular_bytes(path, 'OpenSSL ELF', 32 * 1024 * 1024)
    profile.check_library(body, arch)
    header = struct.unpack('<16sHHIQQQIHHHHHH', body[:64])
    phoff, shoff, phsize, phcount, shsize, shcount = header[5], header[6], header[9], header[10], header[11], header[12]
    require(phsize == 56 and shsize == 64 and 0 < phcount < 128 and 0 < shcount < 1024, 'Invalid OpenSSL ELF tables')
    def bounded(offset, size):
        require(0 <= offset <= len(body) and 0 <= size <= len(body) - offset, 'Invalid OpenSSL ELF bounds')
        return body[offset:offset + size]
    def string(table, offset):
        require(0 <= offset < len(table), 'Invalid OpenSSL ELF string offset')
        end = table.find(b'\0', offset); require(end >= offset, 'Unterminated OpenSSL ELF string')
        return table[offset:end].decode('ascii')
    programs = [struct.unpack('<IIQQQQQQ', bounded(phoff + i * phsize, phsize)) for i in range(phcount)]
    require([p[1] for p in programs if p[0] == 0x6474e551] == [6]
            and len([p for p in programs if p[0] == 0x6474e552 and p[6]]) == 1,
            'OpenSSL stack or RELRO protection differs')
    dynamic = [p for p in programs if p[0] == 2]; require(len(dynamic) == 1, 'OpenSSL dynamic table differs')
    tags = {}
    for tag, value in struct.iter_unpack('<qQ', bounded(dynamic[0][2], dynamic[0][5])):
        if tag == 0: break
        tags.setdefault(tag, []).append(value)
    require(24 in tags or any(v & 8 for v in tags.get(30, [])) or any(v & 1 for v in tags.get(0x6ffffffb, [])),
            'OpenSSL immediate binding is absent')
    require(not tags.get(15) and not tags.get(29), 'OpenSSL contains a loader override')
    sections = [struct.unpack('<IIQQQQIIQQ', bounded(shoff + i * shsize, shsize)) for i in range(shcount)]
    symbols = [s for s in sections if s[1] == 11]; require(len(symbols) == 1 and symbols[0][9] == 24, 'Invalid OpenSSL symbols')
    names = sections[symbols[0][6]]; names = bounded(names[4], names[5])
    exports, ssp = [], False
    for name, info, other, index, _, _ in struct.iter_unpack('<IBBHQQ', bounded(symbols[0][4], symbols[0][5])):
        symbol = string(names, name)
        ssp |= index == 0 and symbol == '__stack_chk_fail'
        if index and info >> 4 in (1, 2) and other & 3 == 0 and symbol:
            exports.append(symbol)
    require(ssp, 'OpenSSL stack protection binding is absent')
    # Symbol names and version-definition bytes bind the full vendor ABI.
    versions = [s for s in sections if s[1] == 0x6ffffffd]
    require(len(versions) == 1, 'OpenSSL versioned ABI is missing')
    return {'exports_sha256': digest(('\n'.join(sorted(exports)) + '\n').encode()),
            'export_count': len(exports), 'version_definitions_sha256': digest(bounded(versions[0][4], versions[0][5]))}


def build(output, *, preparation=False, root=ROOT):
    spec = reviewed_spec(root, preparation=preparation)
    arch = profile.native_architecture()
    require(os.environ.get('KEEP_OPENSSL_BUILD_IMAGE') == BUILD_IMAGE, 'OpenSSL build image differs')
    compiler, _ = profile.compiler_identity(arch)
    inputs = {'cpp': profile.cpp.verify_installed(arch), 'tools': profile.build_tools.verify_installed(arch),
              'perl': perl.verify_installed(perl.PREPARED, arch)}
    output = profile.empty_directory(output)
    require(not WORK.exists(), 'OpenSSL build workspace is already present')
    archive = checked(download(SOURCE_URL), SOURCE_SHA256, 'OpenSSL release source')
    source = extract_source(archive, WORK)
    profile.fortify.prepare(WORK / 'fortify')
    auxv = download(AUXV_URL)
    require(hashlib.sha512(auxv).hexdigest() == AUXV_SHA512, 'Vendor auxv patch differs')
    # Apply only the checksum-locked vendor patch, with no fuzz or external input.
    apply_auxv(source, auxv.decode())
    env = environment(arch)
    macros = subprocess.check_output(['/usr/bin/gcc', *shlex.split(env['CFLAGS']), *shlex.split(env['CPPFLAGS']),
                                      '-dM', '-E', '-x', 'c', '-'], input=b'#include <string.h>\n', env=env).decode()
    require('#define _FORTIFY_SOURCE 2' in macros and '#define __SSP_STRONG__ 3' in macros
            and '_FORTIFY_STRING_H' in macros, 'OpenSSL effective compiler hardening differs')
    configure = ['/usr/bin/perl', './Configure', {'amd64': 'linux-x86_64', 'arm64': 'linux-aarch64'}[arch],
                 *OPTIONS, *(('enable-ec_nistp_64_gcc_128',) if arch == 'amd64' else ())]
    def run(command, timeout=1800):
        log = output / ('build-' + str(len(list(output.glob('build-*.log')))) + '.log')
        try:
            with log.open('wb') as stream:
                subprocess.run(command, cwd=source, env=env, stdout=stream, stderr=subprocess.STDOUT, check=True, timeout=timeout)
        except subprocess.SubprocessError:
            print(log.read_text(errors='replace')[-12000:], flush=True)
            raise
    run(configure)
    manifest = json.loads((Path(root) / 'scripts/openssl_security_patches.json').read_bytes())
    for patch in manifest['patches']:
        checked(download(patch['url']), patch['sha256'], 'Original upstream fix')
    apply_patches(source, manifest)
    run(['make', '-j2'])
    run(['make', 'test', 'HARNESS_JOBS=2'], timeout=2400)
    installed = WORK / 'install'
    run(['make', 'install_sw', 'DESTDIR=' + str(installed)])
    hashes = {name: digest(profile.regular_bytes(installed / name, 'OpenSSL installed output', 32 * 1024 * 1024)) for name in FILES}
    vendor_root = Path('/opt/openssl-vendor-usr')
    require(vendor_root.is_dir(), 'Read-only pinned runtime vendor inputs are missing')
    vendor = {name: digest(profile.regular_bytes(vendor_root / name.removeprefix('usr/'),
                       'OpenSSL vendor input', 32 * 1024 * 1024)) for name in FILES}
    abi = {name: elf_identity(installed / 'usr/lib' / name, arch) for name in ('libcrypto.so.3', 'libssl.so.3')}
    require(abi == {name: elf_identity(vendor_root / 'lib' / name, arch) for name in abi}, 'OpenSSL vendor ABI changed')
    native = {'compiler_sha256': compiler, 'vendor_files': vendor, 'files': hashes, 'abi': abi}
    if not preparation:
        require(native == spec['native'][arch], 'OpenSSL output or compiler differs from reviewed native hashes')
    require(profile.cpp.verify_installed(arch) == inputs['cpp'] and profile.build_tools.verify_installed(arch) == inputs['tools']
            and perl.verify_installed(perl.PREPARED, arch) == inputs['perl'], 'OpenSSL toolchain changed while building')
    for name in FILES:
        target = output / name; target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(installed / name, target); target.chmod(0o755)
    result = ({'schema': 'keep-openssl-preparation-v1', 'qualified': False, 'architecture': arch,
               'native': native,
               'upstream_tests': True, 'build_inputs': inputs} if preparation else expected_manifest(arch, root))
    (output / ('OPENSSL_PREPARATION.json' if preparation else 'OPENSSL_SECURITY.json')).write_bytes(json_bytes(result))
    shutil.rmtree(WORK)
    return result


def install(output, arch, *, runtime_root=Path('/'), root=ROOT):
    """Replace only reviewed regular payloads; preserve configuration and trust."""
    output = Path(output)
    manifest_path = output / 'OPENSSL_SECURITY.json'
    manifest = verify_manifest(json.loads(profile.regular_bytes(manifest_path, 'OpenSSL receipt')), arch, root)
    native = manifest['native']
    targets = {}
    for name in FILES:
        target = Path(runtime_root) / name
        require(not any(p.is_symlink() for p in (target, *target.parents)) and target.is_file(),
                'OpenSSL vendor payload is not canonical: ' + name)
        checked(target.read_bytes(), native['vendor_files'][name], 'Original OpenSSL payload')
        replacement = checked(profile.regular_bytes(output / name, 'OpenSSL replacement', 32 * 1024 * 1024),
                              native['files'][name], 'OpenSSL replacement')
        targets[target] = replacement
    for target, body in targets.items():
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(dir=target.parent, prefix='.keep-openssl-', delete=False) as stream:
                temporary = Path(stream.name); stream.write(body); stream.flush(); os.fsync(stream.fileno())
            temporary.chmod(0o755)
            os.replace(temporary, target)
            checked(target.read_bytes(), digest(body), 'Installed OpenSSL payload')
        finally:
            if temporary is not None and temporary.exists(): temporary.unlink()
    return manifest


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--preparation', action='store_true')
    parser.add_argument('--install', action='store_true')
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    require(not (args.install and args.preparation), 'OpenSSL preparation cannot install a runtime')
    result = (install(args.output, profile.native_architecture()) if args.install
              else build(args.output, preparation=args.preparation))
    print(json.dumps(result, sort_keys=True))
