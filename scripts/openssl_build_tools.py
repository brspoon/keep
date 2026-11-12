"""Verify the signed, build-only Perl interpreter and its matching sources."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import tarfile

if __package__:
    from . import expat_build_tools as tools
    from . import dhi_python_packages as python_packages
else:
    import expat_build_tools as tools
    import dhi_python_packages as python_packages

ROOT = Path(__file__).resolve().parents[1]
PREPARED = Path('/opt/openssl-build-tools')
LOCK_SHA256 = 'ab1c9835a194ff22f161d9498268fa34e1b12e731cad548cd12941cf74b32cc8'
require, checked, digest, json_bytes = tools.require, tools.checked, tools.digest, tools.json_bytes


def reviewed_spec(root=ROOT):
    body = (Path(root) / 'docs/openssl-build-tools.json').read_bytes()
    checked(body, LOCK_SHA256, 'OpenSSL build-only Perl lock')
    spec = json.loads(body)
    require(spec['version'] == '5.42.3-r0' and set(spec['binaries']) == {'amd64', 'arm64'},
            'Unexpected Perl build cohort')
    return spec


def verify_apk(body, architecture, key, spec):
    signing = tools.alpine.KEYS[architecture]
    expected = spec['binaries'][architecture]
    checked(body, expected['sha256'], 'Build-only Perl APK')
    checked(key, signing['sha256'], 'Build-only Perl signing key')
    parts = python_packages.gzip_parts(body)
    signatures = tools.archive_entries(parts[0][1])
    name = '.SIGN.RSA.' + signing['name']
    require(set(signatures) == {name} and signatures[name]['body'] is not None,
            'Unexpected Perl signature identity')
    tools.alpine.verify_rsa(signatures[name]['body'], parts[1][0], key)
    controls = tools.archive_entries(parts[1][1])
    require(set(controls) == set(expected['controls']), 'Unexpected Perl installation scripts')
    for name, checksum in expected['controls'].items():
        checked(controls[name]['body'], checksum, 'Perl control ' + name)
    fields = tools.cpp.metadata_fields(controls['.PKGINFO']['body'])
    require(fields == expected['fields'] and fields['pkgname'] == ['perl']
            and fields['pkgver'] == [spec['version']]
            and fields['commit'] == [spec['build_commit']]
            and fields['arch'] == [tools.alpine.ARCHES[architecture]],
            'Perl signed package identity differs')
    checked(parts[2][0], expected['data_sha256'], 'Perl compressed payload')
    payload = tools.archive_entries(parts[2][1])
    checked(json_bytes(tools.cpp.payload_manifest(payload)), expected['payload_sha256'],
            'Complete Perl payload')
    return payload


def prepare(output, architecture, *, root=ROOT, fetch=tools.download):
    spec = reviewed_spec(root)
    output = Path(output)
    require(not output.exists(), 'Perl preparation directory already exists')
    output.mkdir(parents=True)
    key = tools.alpine.KEYS[architecture]
    key_body = fetch('https://alpinelinux.org/keys/' + key['name'])
    apk = fetch(spec['binaries'][architecture]['url'])
    verify_apk(apk, architecture, key_body, spec)
    (output / key['name']).write_bytes(key_body)
    (output / 'perl.apk').write_bytes(apk)
    for item in spec['sources']:
        body = fetch(item['url'])
        algorithm = 'sha256' if 'sha256' in item else 'sha512'
        require(hashlib.new(algorithm, body).hexdigest() == item[algorithm], 'Perl matching source differs')
        (output / item['path']).write_bytes(body)
    verify_sources(output, spec)
    (output / 'openssl-build-tools.json').write_bytes(json_bytes(spec))
    return spec


def verify_sources(output, spec):
    output = Path(output)
    for row in spec['sources']:
        path = output / row['path']
        require(path.is_file() and not path.is_symlink(), 'Missing regular Perl source input')
        algorithm = 'sha256' if 'sha256' in row else 'sha512'
        require(hashlib.new(algorithm, path.read_bytes()).hexdigest() == row[algorithm],
                'Retained Perl source checksum differs')
    for name, checksum in spec['recipe_files'].items():
        checked((output / ('recipe-' + name)).read_bytes(), checksum, 'Complete Perl recipe input')
    recipe = (output / 'recipe-APKBUILD').read_text()
    require(re.findall(r'^pkgver=(.*)$', recipe, re.M) == ['5.42.3']
            and re.findall(r'^pkgrel=(.*)$', recipe, re.M) == ['0'], 'Perl recipe version differs')
    checksums = dict((name, checksum) for checksum, name in
                     re.findall(r'^([a-f0-9]{128})  (\S+)$', recipe, re.M))
    expected = {'perl-5.42.3.tar.xz': 'perl-5.42.3.tar.xz',
                'perl-cross-1.6.3.tar.gz.noauto': 'perl-cross-1.6.3.tar.gz'}
    expected.update({name: 'recipe-' + name for name in spec['recipe_files'] if name != 'APKBUILD'})
    require(set(checksums) == set(expected), 'Perl recipe source list is incomplete')
    for name, path in expected.items():
        require(hashlib.sha512((output / path).read_bytes()).hexdigest() == checksums[name],
                'Perl source does not match its exact signed-build recipe')
    return {'build_commit': spec['build_commit'], 'lock_sha256': LOCK_SHA256,
            'source_inputs': len(spec['sources'])}


def install(output, architecture):
    output = Path(output)
    spec = reviewed_spec()
    verify_sources(output, spec)
    key = tools.alpine.KEYS[architecture]
    payload = verify_apk((output / 'perl.apk').read_bytes(), architecture,
                         (output / key['name']).read_bytes(), spec)
    subprocess.run(['/sbin/apk', 'add', '--no-network', '--repositories-file', '/dev/null',
                    '--keys-dir', str(output), '--no-cache', str(output / 'perl.apk')], check=True)
    verify_installed(output, architecture, payload=payload)


def verify_installed(output, architecture, *, payload=None):
    spec = reviewed_spec()
    output = Path(output)
    key = tools.alpine.KEYS[architecture]
    if payload is None:
        payload = verify_apk((output / 'perl.apk').read_bytes(), architecture,
                             (output / key['name']).read_bytes(), spec)
    # Inspect the complete interpreter and module payload before executing Perl.
    for name, entry in payload.items():
        path, member = Path('/') / name, entry['member']
        if member.isfile():
            require(path.is_file() and not path.is_symlink(), 'Missing regular Perl input: ' + name)
            checked(path.read_bytes(), digest(entry['body']), 'Installed Perl input ' + name)
        elif member.issym():
            require(path.is_symlink() and path.readlink().as_posix() == member.linkname,
                    'Installed Perl link differs: ' + name)
        elif member.islnk():
            require(path.is_file() and path.samefile(Path('/') / member.linkname),
                    'Installed Perl hard link differs: ' + name)
    return {'lock_sha256': LOCK_SHA256, 'apk_sha256': spec['binaries'][architecture]['sha256'],
            'payload_sha256': spec['binaries'][architecture]['payload_sha256']}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prepare', action='store_true')
    parser.add_argument('--install', action='store_true')
    parser.add_argument('--architecture', choices=('amd64', 'arm64'))
    parser.add_argument('--output', type=Path, default=PREPARED)
    args = parser.parse_args()
    architecture = args.architecture or {'x86_64': 'amd64', 'aarch64': 'arm64'}[__import__('platform').machine()]
    require(args.prepare != args.install, 'Choose Perl preparation or installation')
    if args.prepare:
        prepare(args.output, architecture)
    else:
        install(args.output, architecture)
