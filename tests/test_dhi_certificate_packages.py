"""The signed noarch CA bundle and installed trust paths stay exactly bound."""
from contextlib import ExitStack
import copy
import gzip
import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import Mock, patch

from scripts import dhi_certificate_packages as packages


def digest(body):
    return hashlib.sha256(body).hexdigest()


def archive(entries=(), links=None, directories=(), attributes=None):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w') as bundle:
        for name, kind, body in (
                [(name, 'directory', None) for name in directories]
                + [(name, 'file', body) for name, body in entries]
                + [(name, 'link', target) for name, target in (links or {}).items()]):
            member = tarfile.TarInfo(name)
            if kind == 'directory':
                member.type, member.mode = tarfile.DIRTYPE, 0o755
            elif kind == 'link':
                member.type, member.linkname = tarfile.SYMTYPE, body
            else:
                member.size, member.mode = len(body), 0o644
            for key, value in (attributes or {}).get(name, {}).items():
                setattr(member, key, value)
            bundle.addfile(member, io.BytesIO(body) if kind == 'file' else None)
    return output.getvalue()


@unittest.skipUnless(shutil.which('openssl'), 'APK verification requires OpenSSL')
class DhiCertificatePackageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = tempfile.TemporaryDirectory(prefix='keep-ca-test-key-')
        cls.addClassCleanup(cls.keys.cleanup)
        cls.private = Path(cls.keys.name) / 'test-key.pem'
        subprocess.run(['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt',
                        'rsa_keygen_bits:2048', '-out', str(cls.private)], check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        cls.key = subprocess.check_output(['openssl', 'pkey', '-in', str(cls.private), '-pubout'])

    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.bundle = b'bounded synthetic public CA bundle fixture\n'
        self.stack.enter_context(patch.object(packages, 'KEY_SHA256', digest(self.key)))
        self.stack.enter_context(patch.object(packages, 'BUNDLE_SHA256', digest(self.bundle)))
        self.body, self.metadata = self.apk()
        self.stack.enter_context(patch.object(packages, 'APK_SHA256', digest(self.body)))
        self.stack.enter_context(patch.object(packages, 'PKGINFO_SHA256', digest(self.metadata)))
        self.spec = packages.reviewed_spec()
        self.bodies = {'https://dhi.io/keyring/' + packages.KEY_NAME: self.key}
        for arch in packages.ARCHES:
            self.bodies[self.url(arch)] = self.body

    @staticmethod
    def url(arch):
        return ('https://dhi.io/apk/alpine/v3.24/main/' + packages.ARCHES[arch]
                + '/' + packages.PACKAGE + '-' + packages.VERSION + '.apk')

    def apk(self, *, changes=None, extra_fields=(), entries=None, aliases=None,
            directories=None, attributes=None, control_extra=(), signer=None):
        data = gzip.compress(archive(
            [(packages.SYSTEM_BUNDLE_PATH.lstrip('/'), self.bundle)] if entries is None else entries,
            {path.lstrip('/'): target for path, target in
             (packages.ALIASES if aliases is None else aliases).items()},
            ('etc', 'etc/ssl', 'etc/ssl/certs', 'etc/ssl1.1')
            if directories is None else directories,
            attributes), mtime=0)
        fields = {'pkgname': packages.PACKAGE, 'pkgver': packages.VERSION,
                  'origin': 'ca-certificates', 'arch': 'noarch', 'commit': packages.BUILD_COMMIT,
                  'license': 'MPL-2.0 AND MIT',
                  'url': 'https://www.mozilla.org/en-US/about/governance/policies/security-group/certs/',
                  'datahash': digest(data)}
        fields.update(changes or {})
        metadata = ''.join(key + ' = ' + value + '\n' for key, value in fields.items())
        metadata += 'provides = ca-certificates-cacert=' + packages.VERSION + '\n'
        metadata += 'replaces = libressl2.7-libcrypto\nreplaces = libcrypto1.1\n'
        metadata += ''.join(key + ' = ' + value + '\n' for key, value in extra_fields)
        metadata = metadata.encode()
        control = gzip.compress(archive([('.PKGINFO', metadata), *control_extra]), mtime=0)
        signature = subprocess.run(['openssl', 'dgst', '-sha1', '-sign', str(self.private)],
                                   input=control, check=True, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE).stdout
        signed = gzip.compress(archive([
            ('.SIGN.RSA.' + (signer or packages.KEY_NAME), signature)]), mtime=0)
        return signed + control + data, metadata

    def rebind(self, **changes):
        body, metadata = self.apk(**changes)
        packages.APK_SHA256, packages.PKGINFO_SHA256 = digest(body), digest(metadata)
        return body

    def runtime(self, root):
        root = Path(root)
        bundle = root / packages.SYSTEM_BUNDLE_PATH.lstrip('/')
        bundle.parent.mkdir(parents=True)
        bundle.write_bytes(self.bundle)
        for path, target in packages.ALIASES.items():
            alias = root / path.lstrip('/')
            alias.parent.mkdir(parents=True, exist_ok=True)
            alias.symlink_to(target)
        fields = {'P': packages.PACKAGE, 'V': packages.VERSION, 'A': 'noarch',
                  'o': 'ca-certificates', 'c': packages.BUILD_COMMIT,
                  'L': 'MPL-2.0 AND MIT',
                  'U': 'https://www.mozilla.org/en-US/about/governance/policies/security-group/certs/',
                  'p': 'ca-certificates-cacert=' + packages.VERSION}
        database = root / 'lib/apk/db/installed'
        database.parent.mkdir(parents=True)
        database.write_text(''.join(key + ':' + value + '\n' for key, value in fields.items()) + '\n')
        return database

    def test_reviewed_source_map_binds_both_native_urls_to_same_noarch_apk(self):
        self.assertEqual(self.spec['origin'], 'ca-certificates')
        self.assertEqual(self.spec['version'], packages.VERSION)
        self.assertEqual(len(self.spec['packages']), 1)
        for arch in packages.ARCHES:
            row = self.spec['packages'][0]['binaries'][arch]
            self.assertEqual(row, {'url': self.url(arch), 'sha256': digest(self.body)})
            self.assertEqual(self.spec['signing_keys'][arch]['sha256'], digest(self.key))
        self.assertEqual(json.loads(packages.source_lock_bytes(self.spec)), self.spec)
        with tempfile.TemporaryDirectory() as temporary:
            docs = Path(temporary) / 'docs'
            docs.mkdir()
            path = docs / 'os-package-sources.json'
            path.write_text(json.dumps({'origins': [{'origin': 'other'}, self.spec]}))
            self.assertEqual(packages.reviewed_spec(temporary), self.spec)
            path.write_text(json.dumps({'origins': [self.spec, self.spec]}))
            with self.assertRaisesRegex(ValueError, 'source map'):
                packages.reviewed_spec(temporary)

    def test_source_map_edits_and_json_type_substitutions_are_rejected(self):
        for change in ('version', 'url', 'key', 'boolean'):
            with self.subTest(change=change):
                bad = copy.deepcopy(self.spec)
                if change == 'version':
                    bad['version'] = 'unreviewed'
                elif change == 'url':
                    bad['packages'][0]['binaries']['arm64']['url'] = 'https://example.test/other.apk'
                elif change == 'key':
                    bad['signing_keys']['amd64']['sha256'] = 'f' * 64
                else:
                    bad['mutable_tag_reused_across_upstream_versions'] = 0
                with self.assertRaisesRegex(ValueError, 'source map'):
                    packages.source_lock_bytes(bad)
                with tempfile.TemporaryDirectory() as temporary:
                    docs = Path(temporary) / 'docs'
                    docs.mkdir()
                    (docs / 'os-package-sources.json').write_text(json.dumps({'origins': [bad]}))
                    with self.assertRaisesRegex(ValueError, 'source map'):
                        packages.reviewed_spec(temporary)

    def test_prepare_verifies_signed_noarch_bundle_for_both_architectures(self):
        for arch in packages.ARCHES:
            with self.subTest(architecture=arch), tempfile.TemporaryDirectory() as temporary:
                fetch = Mock(side_effect=self.bodies.__getitem__)
                manifest = packages.prepare_packages(self.spec, arch, temporary, fetch)
                root = Path(temporary)
                name = packages.PACKAGE + '-' + packages.VERSION + '.apk'
                self.assertEqual((root / name).read_bytes(), self.body)
                self.assertEqual((root / (name + '.PKGINFO')).read_bytes(), self.metadata)
                self.assertEqual((root / 'keys' / packages.KEY_NAME).read_bytes(), self.key)
                self.assertEqual(json.loads((root / 'CA_CERTIFICATES_SECURITY.json').read_text()), manifest)
                self.assertEqual(manifest, packages.build_security_manifest(arch, root=None))
                self.assertEqual([call.args[0] for call in fetch.call_args_list],
                                 ['https://dhi.io/keyring/' + packages.KEY_NAME, self.url(arch)])

    def test_output_must_be_empty_without_symlinks(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            occupied = root / 'occupied'
            occupied.mkdir()
            (occupied / 'keep').write_bytes(b'keep')
            alias = root / 'alias'
            alias.symlink_to(occupied, target_is_directory=True)
            for output in (occupied, alias):
                with self.subTest(output=output), self.assertRaisesRegex(ValueError, 'output'):
                    packages.prepare_packages(self.spec, 'amd64', output, Mock())
            self.assertEqual((occupied / 'keep').read_bytes(), b'keep')

    def test_unknown_architecture_is_rejected_before_download(self):
        with tempfile.TemporaryDirectory() as temporary:
            fetch = Mock()
            with self.assertRaisesRegex(ValueError, 'architecture'):
                packages.prepare_packages(self.spec, 's390x', temporary, fetch)
            fetch.assert_not_called()
        with self.assertRaisesRegex(ValueError, 'architecture'):
            packages.verify_apk(self.body, 'noarch', self.key)

    def test_outer_apk_key_and_metadata_checksums_are_mandatory(self):
        for body, key, label in ((self.body + b'changed', self.key, 'APK'),
                                 (self.body, self.key + b'changed', 'key')):
            with self.subTest(label=label), self.assertRaisesRegex(ValueError, 'checksum mismatch'):
                packages.verify_apk(body, 'amd64', key)
        with patch.object(packages, 'PKGINFO_SHA256', 'f' * 64), \
                self.assertRaisesRegex(ValueError, 'metadata checksum mismatch'):
            packages.verify_apk(self.body, 'amd64', self.key)

    def test_invalid_signature_cannot_be_approved_by_outer_hash(self):
        parts = packages.gzip_parts(self.body)
        signed = gzip.compress(archive([
            ('.SIGN.RSA.' + packages.KEY_NAME, b'not a valid RSA signature')]), mtime=0)
        body = signed + parts[1][0] + parts[2][0]
        packages.APK_SHA256 = digest(body)
        with self.assertRaisesRegex(ValueError, 'RSA signature'):
            packages.verify_apk(body, 'amd64', self.key)

    def test_wrong_signer_datahash_and_noarch_identity_are_rejected(self):
        for change in ({'signer': 'unreviewed.rsa.pub'},
                       {'changes': {'datahash': 'f' * 64}},
                       {'changes': {'pkgver': '20251003-r0'}},
                       {'changes': {'arch': 'x86_64'}},
                       {'changes': {'arch': 'aarch64'}},
                       {'changes': {'origin': 'other'}},
                       {'changes': {'commit': 'f' * 40}},
                       {'changes': {'license': 'unknown'}},
                       {'changes': {'url': 'https://example.test/'}}):
            body = self.rebind(**change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                packages.verify_apk(body, 'amd64', self.key)

    def test_extra_dependencies_provisions_duplicate_fields_and_scripts_are_rejected(self):
        for change in ({'extra_fields': [('depend', 'unreviewed')]},
                       {'extra_fields': [('provides', 'unreviewed=1')]},
                       {'extra_fields': [('replaces', 'unreviewed')]},
                       {'extra_fields': [('license', 'MPL-2.0 AND MIT')]},
                       {'control_extra': [('.post-install', b'#!/bin/sh\nexit 0\n')]}):
            body = self.rebind(**change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                packages.verify_apk(body, 'amd64', self.key)

    def test_unknown_missing_unsafe_or_duplicate_payload_members_are_rejected(self):
        bundle = (packages.SYSTEM_BUNDLE_PATH.lstrip('/'), self.bundle)
        for entries in ([bundle, ('etc/unreviewed', b'new trust policy')], [],
                        [bundle, ('../escape', b'outside')],
                        [bundle, bundle]):
            body = self.rebind(entries=entries)
            with self.subTest(entries=entries), self.assertRaises(ValueError):
                packages.verify_apk(body, 'amd64', self.key)

    def test_payload_bytes_alias_targets_ownership_and_modes_are_exact(self):
        path = packages.SYSTEM_BUNDLE_PATH.lstrip('/')
        aliases = dict(packages.ALIASES)
        aliases['/etc/ssl/cert.pem'] = 'other.crt'
        for change in ({'entries': [(path, b'unreviewed certificate')]},
                       {'aliases': aliases}, {'aliases': {}},
                       {'attributes': {path: {'mode': 0o666}}},
                       {'attributes': {path: {'uid': 1000}}},
                       {'attributes': {'etc/ssl': {'gid': 1000}}},
                       {'attributes': {'etc/ssl': {'mode': 0o777}}}):
            body = self.rebind(**change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                packages.verify_apk(body, 'amd64', self.key)

    def test_incomplete_or_extra_gzip_members_are_rejected(self):
        for body in (self.body[:-20], self.body + gzip.compress(b'unreviewed', mtime=0),
                     packages.gzip_parts(self.body)[0][0]):
            packages.APK_SHA256 = digest(body)
            with self.subTest(length=len(body)), self.assertRaises(ValueError):
                packages.verify_apk(body, 'amd64', self.key)

    def test_installed_bundle_aliases_and_noarch_identity_pass_for_both_architectures(self):
        for arch in packages.ARCHES:
            with self.subTest(architecture=arch), tempfile.TemporaryDirectory() as temporary:
                self.runtime(temporary)
                manifest = packages.build_security_manifest(arch, root=None)
                self.assertEqual(packages.verify_installed(arch, manifest, temporary), manifest)

    def test_missing_wrong_or_duplicate_installed_identity_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            database = self.runtime(temporary)
            original = database.read_text()
            manifest = packages.build_security_manifest('amd64', root=None)
            for bad in (original.replace('P:' + packages.PACKAGE, 'P:other'),
                        original.replace('V:' + packages.VERSION, 'V:20251003-r0'),
                        original.replace('A:noarch', 'A:x86_64'),
                        original.replace('o:ca-certificates', 'o:other'),
                        original.replace('c:' + packages.BUILD_COMMIT, 'c:' + 'f' * 40),
                        original.replace('L:MPL-2.0 AND MIT', 'L:unknown'),
                        original.replace('U:https://www.mozilla.org/', 'U:https://example.test/'),
                        original.replace('p:ca-certificates-cacert=', 'p:other='),
                        original.replace('A:noarch', 'A:noarch\nD:unreviewed'),
                        original.replace('A:noarch', 'A:noarch\nA:noarch'),
                        original + original):
                database.write_text(bad)
                with self.subTest(database=bad), self.assertRaises(ValueError):
                    packages.verify_installed('amd64', manifest, temporary)

    def test_installed_bundle_hash_aliases_and_canonical_paths_are_required(self):
        for change in ('bytes', 'missing', 'bundle-symlink', 'parent-symlink',
                       'alias-target', 'alias-file', 'alias-missing'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temporary:
                self.runtime(temporary)
                root = Path(temporary)
                bundle = root / packages.SYSTEM_BUNDLE_PATH.lstrip('/')
                alias = root / 'etc/ssl/cert.pem'
                if change == 'bytes':
                    bundle.write_bytes(b'unreviewed trust bundle')
                elif change == 'missing':
                    bundle.unlink()
                elif change == 'bundle-symlink':
                    bundle.rename(bundle.with_name('other.crt'))
                    bundle.symlink_to('other.crt')
                elif change == 'parent-symlink':
                    bundle.parent.rename(bundle.parent.with_name('other-certs'))
                    bundle.parent.symlink_to('other-certs', target_is_directory=True)
                else:
                    alias.unlink()
                    if change == 'alias-target':
                        alias.symlink_to('other.crt')
                    elif change == 'alias-file':
                        alias.write_bytes(self.bundle)
                with self.assertRaises(ValueError):
                    packages.verify_installed('amd64',
                        packages.build_security_manifest('amd64', root=None), temporary)

    def test_changed_manifest_and_integer_signature_claim_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            self.runtime(temporary)
            for change in ('version', 'architecture', 'bundle', 'signature'):
                with self.subTest(change=change):
                    manifest = packages.build_security_manifest('amd64', root=None)
                    if change == 'version':
                        manifest['package_version'] = 'unreviewed'
                    elif change == 'architecture':
                        manifest['architecture'] = 'arm64'
                    elif change == 'bundle':
                        manifest['bundle']['sha256'] = 'f' * 64
                    else:
                        manifest['packages'][0]['signature_verified'] = 1
                    with self.assertRaisesRegex(ValueError, 'manifest'):
                        packages.verify_installed('amd64', manifest, temporary)


if __name__ == '__main__':
    unittest.main()
