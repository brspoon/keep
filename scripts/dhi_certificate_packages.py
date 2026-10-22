"""Verify and install the exact signed DHI certificate bundle offline."""
import argparse
import hashlib
import json
from pathlib import Path

if __package__:
    from .dhi_python_packages import checked, download, gzip_parts, tar_entries, verify_rsa, metadata_fields
else:
    from dhi_python_packages import checked, download, gzip_parts, tar_entries, verify_rsa, metadata_fields

ROOT = Path(__file__).resolve().parents[1]
VERSION = '20261020-r0'
PACKAGE = 'ca-certificates-bundle'
BUILD_COMMIT = '68cdc7eb180fe3a0843d7489185b3ca10ea806d1'
RECIPE_REVISION = '6428625d5032aaa4bc4c05dfde7f49c1268424ce'
RECIPE_SHA256 = 'ed3f1946ad81f4a1db00c4f43ec35ef946f404cc127ccc596c2dd2783c544ce3'
KEY_NAME = 'dhi-apk@docker-0F81AD7700D99184.rsa.pub'
KEY_SHA256 = '0003d0ae2bf20db9669f784d6ccd5d52265cb1b73fdb14f5186b348b3308f0cd'
APK_SHA256 = '49cc005952a3d525bdc5ef16aea944443d07676e5bc1ea0431c2364a37d6dc09'
PKGINFO_SHA256 = '7284504dd17c5f122f4083fcdcb2f5e3ee312f277cb1c043bfddc545ec3d7e4b'
SYSTEM_BUNDLE_PATH = '/etc/ssl/certs/ca-certificates.crt'
BUNDLE_SHA256 = '5961c0a3c65459931c023e0075c09733f09aea4ca439cb85bc4a08bb4f3f568b'
BUNDLE_CERTIFICATES = 118
BUNDLE_FINGERPRINTS_SHA256 = '077fe6a7639d6ef14a8fe2661e92b064f7701b8df283e1445f38a66a47b07acb'
ARCHES = {'amd64': 'x86_64', 'arm64': 'aarch64'}
ALIASES = {'/etc/ssl/cert.pem': 'certs/ca-certificates.crt',
           '/etc/ssl1.1/cert.pem': '/etc/ssl/cert.pem',
           '/etc/ssl1.1/certs': '/etc/ssl/certs'}


def reviewed_spec(root=None):
    recipe = 'package/apk/main/ca-certificates/alpine-3.24/20251003.yaml'
    spec = {
        'origin': 'ca-certificates', 'version': VERSION,
        'image': 'dhi.io/pkg-ca-certificates', 'tag': VERSION + '-alpine3.24',
        'reference': 'dhi.io/pkg-ca-certificates:' + VERSION + '-alpine3.24',
        'predicate_image_name': 'dhi/pkg-ca-certificates',
        'recipe': {'path': recipe, 'revision': RECIPE_REVISION, 'sha256': RECIPE_SHA256,
                   'url': 'https://raw.githubusercontent.com/docker-hardened-images/catalog/'
                          + RECIPE_REVISION + '/' + recipe,
                   'upstream_commit': 'e78f5987166c6ffbe23f6472e2e8f040298fe2da'},
        'declared_tags': ['20261020-alpine3.24', VERSION + '-alpine3.24'],
        'mutable_tag_reused_across_upstream_versions': False,
        'signing_keys': {arch: {'name': KEY_NAME, 'sha256': KEY_SHA256,
                               'url': 'https://dhi.io/keyring/' + KEY_NAME} for arch in ARCHES},
        'packages': [{'name': PACKAGE, 'version': VERSION, 'license': 'MPL-2.0 AND MIT',
                      'build_commit': BUILD_COMMIT, 'binaries': {arch: {
                          'url': 'https://dhi.io/apk/alpine/v3.24/main/' + native
                                 + '/' + PACKAGE + '-' + VERSION + '.apk',
                          'sha256': APK_SHA256} for arch, native in ARCHES.items()}}],
    }
    if root is not None:
        rows = [r for r in json.loads((Path(root) / 'docs/os-package-sources.json').read_bytes())['origins']
                if r.get('origin') == 'ca-certificates']
        if rows != [spec] or json.dumps(rows, sort_keys=True) != json.dumps([spec], sort_keys=True):
            raise ValueError('Certificate source map differs from reviewed DHI packages')
    return spec


def source_lock_bytes(spec):
    expected = reviewed_spec()
    if spec != expected or json.dumps(spec, sort_keys=True) != json.dumps(expected, sort_keys=True):
        raise ValueError('Certificate source map differs from reviewed DHI packages')
    return (json.dumps(spec, sort_keys=True, indent=2) + '\n').encode()


def verify_apk(body, architecture, key):
    if architecture not in ARCHES:
        raise ValueError('Unsupported certificate architecture')
    checked(body, APK_SHA256, 'Certificate APK')
    checked(key, KEY_SHA256, 'DHI certificate signing key')
    parts = gzip_parts(body)
    signs = tar_entries(parts[0][1])
    signature = '.SIGN.RSA.' + KEY_NAME
    if set(signs) != {signature} or signs[signature]['body'] is None:
        raise ValueError('Certificate APK signing key name mismatch')
    verify_rsa(signs[signature]['body'], parts[1][0], key)
    control = tar_entries(parts[1][1])
    if set(control) != {'.PKGINFO'} or control['.PKGINFO']['body'] is None:
        raise ValueError('Certificate bundle must have metadata without install scripts')
    metadata = control['.PKGINFO']['body']
    checked(metadata, PKGINFO_SHA256, 'Certificate APK metadata')
    fields = metadata_fields(metadata)
    expected = {'pkgname': PACKAGE, 'pkgver': VERSION, 'origin': 'ca-certificates',
                'arch': 'noarch', 'commit': BUILD_COMMIT, 'license': 'MPL-2.0 AND MIT',
                'url': 'https://www.mozilla.org/en-US/about/governance/policies/security-group/certs/',
                'datahash': hashlib.sha256(parts[2][0]).hexdigest()}
    if any(fields.get(k) != [v] for k, v in expected.items()):
        raise ValueError('Certificate APK identity, license or payload mismatch')
    for name, values in [('depend', []), ('provides', ['ca-certificates-cacert=' + VERSION]),
                         ('replaces', ['libressl2.7-libcrypto', 'libcrypto1.1'])]:
        if sorted(fields.get(name, [])) != sorted(values):
            raise ValueError('Certificate APK dependencies or provisions differ')
    payload = tar_entries(parts[2][1])
    directories = {'etc', 'etc/ssl', 'etc/ssl/certs', 'etc/ssl1.1'}
    allowed = directories | {SYSTEM_BUNDLE_PATH.lstrip('/')} | {p.lstrip('/') for p in ALIASES}
    if set(payload) != allowed:
        raise ValueError('Certificate APK has unexpected payload members')
    for name, entry in payload.items():
        member = entry['member']
        if member.uid != 0 or member.gid != 0:
            raise ValueError('Certificate APK ownership differs')
        if name in directories:
            if not member.isdir() or member.mode != 0o755:
                raise ValueError('Certificate APK directory differs')
        elif name == SYSTEM_BUNDLE_PATH.lstrip('/'):
            if entry['body'] is None or member.mode != 0o644:
                raise ValueError('Certificate APK bundle must be a regular public file')
            checked(entry['body'], BUNDLE_SHA256, 'Certificate bundle')
        elif not member.issym() or member.linkname != ALIASES['/' + name]:
            raise ValueError('Certificate APK alias differs')
    return metadata


def build_security_manifest(architecture, root=ROOT):
    if architecture not in ARCHES:
        raise ValueError('Unsupported certificate architecture')
    spec = reviewed_spec(root)
    return {'schema': 'keep-ca-security-v1', 'architecture': architecture,
            'package_version': VERSION, 'build_commit': BUILD_COMMIT,
            'source_manifest_sha256': hashlib.sha256(source_lock_bytes(spec)).hexdigest(),
            'bundle': {'path': SYSTEM_BUNDLE_PATH, 'sha256': BUNDLE_SHA256},
            'aliases': dict(ALIASES), 'packages': [{'name': PACKAGE, 'version': VERSION,
                'apk_sha256': APK_SHA256, 'pkginfo_sha256': PKGINFO_SHA256,
                'signature_verified': True, 'signing_key_sha256': KEY_SHA256}]}


def prepare_packages(spec, architecture, output_root, fetch=download):
    source_lock_bytes(spec)
    manifest = build_security_manifest(architecture, root=None)
    root = Path(output_root)
    if root.is_symlink() or root.exists() and any(root.iterdir()):
        raise ValueError('Certificate package output must be empty without symlinks')
    root.mkdir(parents=True, exist_ok=True)
    key = checked(fetch(spec['signing_keys'][architecture]['url']), KEY_SHA256, 'DHI signing key')
    (root / 'keys').mkdir()
    (root / 'keys' / KEY_NAME).write_bytes(key)
    body = fetch(spec['packages'][0]['binaries'][architecture]['url'])
    metadata = verify_apk(body, architecture, key)
    name = PACKAGE + '-' + VERSION + '.apk'
    (root / name).write_bytes(body)
    (root / (name + '.PKGINFO')).write_bytes(metadata)
    (root / 'CA_CERTIFICATES_SECURITY.json').write_text(json.dumps(manifest, sort_keys=True, indent=2) + '\n')
    return manifest


def verify_installed(architecture, manifest, runtime_root='/'):
    expected_manifest = build_security_manifest(architecture, root=None)
    if (manifest != expected_manifest or json.dumps(manifest, sort_keys=True)
            != json.dumps(expected_manifest, sort_keys=True)):
        raise ValueError('Certificate installation manifest differs from reviewed packages')
    root = Path(runtime_root).resolve()
    bundle = root / SYSTEM_BUNDLE_PATH.lstrip('/')
    if bundle.is_symlink() or not bundle.is_file() or bundle.resolve() != bundle.absolute():
        raise ValueError('Certificate bundle is not a canonical regular file')
    checked(bundle.read_bytes(), BUNDLE_SHA256, 'Installed certificate bundle')
    for path, target in ALIASES.items():
        link = root / path.lstrip('/')
        if not link.is_symlink() or link.readlink().as_posix() != target:
            raise ValueError('Installed certificate alias differs')
    database = (root / 'lib/apk/db/installed').read_text()
    records = []
    for block in database.split('\n\n'):
        fields = {}
        for line in block.splitlines():
            if len(line) > 1 and line[1] == ':' and line[0] in 'PVAcLoUDp':
                if line[0] in fields:
                    raise ValueError('Duplicate installed certificate package field')
                fields[line[0]] = line[2:]
        if fields.get('P') == PACKAGE:
            records.append(fields)
    expected = {'P': PACKAGE, 'V': VERSION, 'A': 'noarch', 'o': 'ca-certificates',
                'c': BUILD_COMMIT, 'L': 'MPL-2.0 AND MIT',
                'U': 'https://www.mozilla.org/en-US/about/governance/policies/security-group/certs/',
                'p': 'ca-certificates-cacert=' + VERSION}
    if len(records) != 1 or any(records[0].get(k) != v for k, v in expected.items()) or records[0].get('D'):
        raise ValueError('Installed certificate APK identity differs')
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--architecture', required=True, choices=ARCHES)
    parser.add_argument('--manifest', required=True, type=Path)
    args = parser.parse_args()
    verify_installed(args.architecture, json.loads(args.manifest.read_bytes()))


if __name__ == '__main__':
    main()
