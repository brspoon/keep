import copy
import hashlib
import io
import json
import os
from pathlib import Path
import pyexpat
import ssl
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from scripts import alpine_expat_sources
from scripts import runtime_dependency_checks as checks


class ExpatInstallManifestTests(unittest.TestCase):
    def manifest(self, arch='amd64'):
        return alpine_expat_sources.build_security_manifest(arch, root=None)

    def test_each_reviewed_native_package_identity_passes(self):
        for arch in ('amd64', 'arm64'):
            with self.subTest(arch=arch):
                manifest = self.manifest(arch)
                self.assertEqual(checks.validate_expat_manifest(manifest, arch), manifest)

    def test_wrong_version_architecture_build_and_library_are_rejected(self):
        for field in ('schema', 'architecture', 'version', 'package_version', 'build_commit'):
            with self.subTest(field=field):
                manifest = self.manifest()
                manifest[field] = 'unreviewed'
                with self.assertRaises(ValueError):
                    checks.validate_expat_manifest(manifest, 'amd64')
        for field in ('path', 'soname', 'sha256'):
            with self.subTest(library_field=field):
                manifest = self.manifest()
                manifest['library'][field] = 'unreviewed'
                with self.assertRaises(ValueError):
                    checks.validate_expat_manifest(manifest, 'amd64')
        with self.assertRaises(ValueError):
            checks.validate_expat_manifest(self.manifest(), 'arm64')

    def test_missing_package_bad_hash_and_unverified_signature_are_rejected(self):
        invalid = []
        for value in (None, [], self.manifest()['packages'][:1]):
            manifest = self.manifest()
            manifest['packages'] = value
            invalid.append(manifest)
        for field, value in (('name', 'unrelated'), ('version', '2.8.5-r0'),
                             ('signature_verified', False), ('signature_verified', 1),
                             ('apk_sha256', 'short'), ('pkginfo_sha256', None),
                             ('signing_key_sha256', 'A' * 64)):
            manifest = self.manifest()
            manifest['packages'][0][field] = value
            invalid.append(manifest)
        manifest = self.manifest()
        manifest['source_manifest_sha256'] = 'invalid'
        invalid.append(manifest)
        for manifest in invalid:
            with self.subTest(manifest=manifest), self.assertRaises(ValueError):
                checks.validate_expat_manifest(manifest, 'amd64')

    def test_install_manifest_hash_binds_exact_bytes_and_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'EXPAT_SECURITY.json'
            body = (json.dumps(self.manifest(), sort_keys=True, indent=2) + '\n').encode()
            path.write_bytes(body)
            manifest, digest = checks.read_expat_manifest(path, 'amd64')
            self.assertEqual(manifest, self.manifest())
            self.assertEqual(digest, hashlib.sha256(body).hexdigest())
            alias = path.with_name('alias.json')
            alias.symlink_to(path.name)
            with self.assertRaisesRegex(ValueError, 'regular file'):
                checks.read_expat_manifest(alias, 'amd64')

    def test_well_formed_but_unreviewed_package_and_source_hashes_are_rejected(self):
        for field in ('apk_sha256', 'pkginfo_sha256', 'signing_key_sha256'):
            with self.subTest(field=field):
                manifest = self.manifest()
                manifest['packages'][0][field] = 'a' * 64
                with self.assertRaisesRegex(ValueError, 'exact signed package'):
                    checks.validate_expat_manifest(manifest, 'amd64')
        manifest = self.manifest()
        manifest['source_manifest_sha256'] = 'a' * 64
        with self.assertRaisesRegex(ValueError, 'exact signed package'):
            checks.validate_expat_manifest(manifest, 'amd64')


class LoadedLibraryIdentityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.library = self.root / 'libexpat.so.1.13.0'
        self.library.write_bytes(b'reviewed signed package library fixture')
        self.digest = hashlib.sha256(self.library.read_bytes()).hexdigest()

    def mapping(self, path=None, *, inode=None, device=None):
        path = self.library if path is None else Path(path)
        entry = path.stat()
        device = (os.major(entry.st_dev), os.minor(entry.st_dev)) if device is None else device
        inode = entry.st_ino if inode is None else inode
        return f'7f100000-7f101000 r-xp 00000000 {device[0]:02x}:{device[1]:02x} {inode} {path}\n'

    def verify(self, text, digest=None):
        return checks.verify_loaded_library(self.library, 'libexpat.so', text,
                                            self.digest if digest is None else digest)

    def test_all_mapped_segments_and_valid_alias_match_the_canonical_file(self):
        alias = self.library.with_name('libexpat.so.1')
        alias.symlink_to(self.library.name)
        identity = self.verify(self.mapping() + self.mapping(alias))
        self.assertEqual(identity['path'], str(self.library))
        self.assertEqual(identity['sha256'], self.digest)
        self.assertEqual(identity['inode'], self.library.stat().st_ino)

    def test_matching_explicit_copy_does_not_accept_default_vendor_binding(self):
        vendor = self.root / 'vendor' / 'libexpat.so.1.13.0'
        vendor.parent.mkdir()
        vendor.write_bytes(b'unreviewed vendor library fixture')
        with self.assertRaisesRegex(ValueError, 'unexpected library'):
            self.verify(self.mapping(vendor))
        with self.assertRaisesRegex(ValueError, 'unexpected library'):
            self.verify(self.mapping() + self.mapping(vendor))

    def test_missing_mapping_wrong_inode_wrong_device_and_deleted_library_fail(self):
        cases = ('', self.mapping(inode=self.library.stat().st_ino + 1),
                 self.mapping(device=(255, 255)), self.mapping().rstrip() + ' (deleted)\n',
                 self.mapping(inode=0))
        for text in cases:
            with self.subTest(text=text), self.assertRaises(ValueError):
                self.verify(text)

    def test_wrong_file_hash_or_noncanonical_install_target_fails(self):
        with self.assertRaisesRegex(ValueError, 'package hash'):
            self.verify(self.mapping(), 'f' * 64)
        alias = self.library.with_name('libexpat.so.1')
        alias.symlink_to(self.library.name)
        with self.assertRaisesRegex(ValueError, 'canonical path'):
            checks.verify_loaded_library(alias, 'libexpat.so', self.mapping(), self.digest)

    def test_expat_check_requires_the_installed_soname_alias_and_mapped_package_bytes(self):
        alias = self.library.with_name('libexpat.so.1')
        alias.symlink_to(self.library.name)
        maps = self.root / 'maps'
        maps.write_text(self.mapping())
        manifest = {'library': {'sha256': self.digest}, 'source_manifest_sha256': 'a' * 64}
        with patch.object(checks, 'EXPAT_LIBRARY', self.library), \
             patch.object(checks, 'EXPAT_ALIAS', alias), \
             patch.object(checks, 'exercise_expat', return_value='2.9.0'), \
             patch.object(checks, 'read_expat_manifest', return_value=(manifest, 'b' * 64)):
            result = checks.check_expat('amd64', self.root / 'install.json', maps)
            self.assertEqual(result['libraries']['expat']['sha256'], self.digest)
            self.assertEqual(result['install_manifest_sha256'], 'b' * 64)
            alias.unlink()
            alias.write_bytes(self.library.read_bytes())
            with self.assertRaisesRegex(ValueError, 'SONAME alias'):
                checks.check_expat('amd64', self.root / 'install.json', maps)

    def test_openssl_check_requires_both_canonical_mapped_libraries(self):
        ssl_library = self.root / 'libssl.so.3'
        crypto_library = self.root / 'libcrypto.so.3'
        ssl_library.write_bytes(b'normal ssl library fixture')
        crypto_library.write_bytes(b'normal crypto library fixture')
        maps = self.root / 'maps'
        maps.write_text(self.mapping(ssl_library) + self.mapping(crypto_library))
        with patch.object(checks, 'SSL_LIBRARY', ssl_library), \
             patch.object(checks, 'CRYPTO_LIBRARY', crypto_library), \
             patch.object(checks, 'exercise_openssl', return_value='3.5.9'):
            result = checks.check_openssl('amd64', maps)
            self.assertEqual(set(result['libraries']), {'ssl', 'crypto'})
            self.assertEqual(result['libraries']['crypto']['sha256'],
                             hashlib.sha256(crypto_library.read_bytes()).hexdigest())
            maps.write_text(self.mapping(ssl_library))
            with self.assertRaisesRegex(ValueError, 'did not map libcrypto'):
                checks.check_openssl('amd64', maps)

    def test_hashing_rejects_a_changed_file_identity(self):
        before = self.library.stat()
        # Return another real inode for the second stat rather than mocking hashes.
        other = self.library.with_name('other')
        other.write_bytes(self.library.read_bytes())
        after = other.stat()
        with patch.object(Path, 'stat', side_effect=(before, after)):
            with self.assertRaisesRegex(ValueError, 'changed while hashing'):
                checks.file_identity(self.library)


class BenignFunctionalChecksTests(unittest.TestCase):
    def test_normal_and_malformed_xml_are_checked_with_the_real_parser(self):
        with patch.object(pyexpat, 'EXPAT_VERSION', 'expat_2.9.0'), \
             patch.object(pyexpat, 'version_info', (2, 9, 0)):
            self.assertEqual(checks.exercise_expat(), '2.9.0')
        with patch.object(pyexpat, 'EXPAT_VERSION', 'expat_2.8.5'):
            with self.assertRaisesRegex(ValueError, 'pyexpat version'):
                checks.exercise_expat()

    def test_default_ca_trust_and_in_memory_tls_object_work_without_network(self):
        with patch.object(ssl, 'OPENSSL_VERSION', 'OpenSSL 3.5.9 fixture'), \
             patch.object(ssl, 'OPENSSL_VERSION_INFO', (3, 5, 0, 9, 0)):
            self.assertEqual(checks.exercise_openssl(), '3.5.9')
        with patch.object(ssl, 'OPENSSL_VERSION', 'OpenSSL 3.5.8 fixture'):
            with self.assertRaisesRegex(ValueError, 'ssl version'):
                checks.exercise_openssl()

    def test_openssl_numeric_version_must_match_the_reviewed_release(self):
        with patch.object(ssl, 'OPENSSL_VERSION', 'OpenSSL 3.5.9 fixture'):
            for version in ((3, 5, 0, 8, 0), (3, 5, 9, 0, 0), (3, 5, 0, 9, 15)):
                with self.subTest(version=version), \
                     patch.object(ssl, 'OPENSSL_VERSION_INFO', version):
                    with self.assertRaisesRegex(ValueError, 'ssl version'):
                        checks.exercise_openssl()


class RuntimeReportTests(unittest.TestCase):
    def results(self):
        def library(name):
            return {'path': '/usr/lib/' + name, 'sha256': 'b' * 64,
                    'device': '0:1', 'inode': 123}
        return (
            {'version': '2.9.0', 'libraries': {'expat': library('libexpat.so.1.13.0')},
             'source_manifest_sha256': 'c' * 64, 'install_manifest_sha256': 'd' * 64},
            {'version': '3.5.9', 'libraries': {'ssl': library('libssl.so.3'),
                                            'crypto': library('libcrypto.so.3')}},
        )

    def test_report_binds_both_versions_loaded_hashes_and_source_install_manifests(self):
        expat, openssl = self.results()
        with patch.object(checks, 'architecture', return_value='arm64'), \
             patch.dict(os.environ, {}, clear=True), \
             patch.object(checks, 'check_expat', return_value=expat), \
             patch.object(checks, 'check_openssl', return_value=openssl):
            report = checks.qualify_runtime()
        self.assertEqual(report, {
            'schema': 1, 'arch': 'arm64', 'success': True, 'tests': 2, 'failures': 0,
            'errors': [], 'versions': {'expat': '2.9.0', 'openssl': '3.5.9'},
            'loaded_libraries': {**expat['libraries'], **openssl['libraries']},
            'expat_source_manifest_sha256': 'c' * 64,
            'expat_install_manifest_sha256': 'd' * 64,
        })

    def test_dependency_failure_is_reported_and_the_other_check_still_runs(self):
        _, openssl = self.results()
        with patch.object(checks, 'architecture', return_value='amd64'), \
             patch.dict(os.environ, {}, clear=True), \
             patch.object(checks, 'check_expat', side_effect=ValueError('wrong binding')), \
             patch.object(checks, 'check_openssl', return_value=openssl) as ssl_check:
            report = checks.qualify_runtime()
        self.assertFalse(report['success'])
        self.assertEqual(report['tests'], 2)
        self.assertEqual(report['failures'], 1)
        self.assertEqual(report['errors'], [{'check': 'expat', 'message': 'wrong binding'}])
        self.assertEqual(report['versions'], {'openssl': '3.5.9'})
        ssl_check.assert_called_once()

    def test_loader_overrides_block_qualification_before_importing_dependencies(self):
        for name in ('LD_LIBRARY_PATH', 'LD_PRELOAD'):
            with self.subTest(name=name), \
                 patch.object(checks, 'architecture', return_value='amd64'), \
                 patch.dict(os.environ, {name: '/unexpected'}, clear=True), \
                 patch.object(checks, 'check_expat') as expat, \
                 patch.object(checks, 'check_openssl') as openssl:
                report = checks.qualify_runtime()
                self.assertFalse(report['success'])
                self.assertEqual(report['tests'], 0)
                self.assertEqual(report['errors'][0]['check'], 'environment')
                expat.assert_not_called()
                openssl.assert_not_called()

    def test_report_cli_emits_failure_json_and_returns_nonzero(self):
        report = {'success': False, 'errors': [{'check': 'expat', 'message': 'wrong binding'}]}
        output = io.StringIO()
        with patch.object(checks, 'qualify_runtime', return_value=report), redirect_stdout(output):
            self.assertEqual(checks.main(['--report']), 1)
        self.assertEqual(json.loads(output.getvalue()), report)


class RetainedDependencyReportTests(unittest.TestCase):
    def setUp(self):
        self.manifest = ExpatInstallManifestTests().manifest()
        install_hash = hashlib.sha256(
            (json.dumps(self.manifest, sort_keys=True, indent=2) + '\n').encode()).hexdigest()
        self.report = {
            'schema': 1, 'arch': 'amd64', 'success': True, 'tests': 2, 'failures': 0,
            'errors': [], 'versions': {'expat': '2.9.0', 'openssl': '3.5.9'},
            'loaded_libraries': {
                name: {'path': str(path), 'sha256': digest, 'device': '0:1', 'inode': inode}
                for name, path, digest, inode in (
                    ('expat', checks.EXPAT_LIBRARY, checks.EXPAT_LIBRARY_SHA256['amd64'], 101),
                    ('ssl', checks.SSL_LIBRARY, 'e' * 64, 102),
                    ('crypto', checks.CRYPTO_LIBRARY, 'f' * 64, 103),
                )
            },
            'expat_source_manifest_sha256': self.manifest['source_manifest_sha256'],
            'expat_install_manifest_sha256': install_hash,
        }

    def validate(self, report):
        with patch.object(checks, 'expected_expat_manifest', return_value=self.manifest) as source:
            result = checks.validate_report(report, 'amd64', root=Path('/source-fixture'))
        source.assert_any_call('amd64', Path('/source-fixture'))
        source.assert_any_call('amd64', None)
        return result

    def test_original_native_report_replays_without_runtime_filesystem(self):
        with patch.object(checks, 'file_identity', side_effect=AssertionError('runtime access')), \
             patch.object(checks, 'check_expat', side_effect=AssertionError('runtime import')), \
             patch.object(checks, 'check_openssl', side_effect=AssertionError('runtime import')):
            self.assertEqual(self.validate(self.report), self.report)

    def test_replay_derives_both_manifest_hashes_from_the_real_reviewed_source_map(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lock = root / 'docs/os-package-sources.json'
            lock.parent.mkdir()
            spec = alpine_expat_sources.reviewed_spec()
            lock.write_text(json.dumps({'origins': [spec]}))
            self.assertEqual(checks.validate_report(self.report, 'amd64', root), self.report)
            spec['recipe']['sha256'] = 'a' * 64
            lock.write_text(json.dumps({'origins': [spec]}))
            with self.assertRaisesRegex(ValueError, 'exact reviewed Alpine origin'):
                checks.validate_report(self.report, 'amd64', root)

    def test_failed_wrong_arch_incomplete_and_invalid_report_fields_are_rejected(self):
        invalid = [None, {}, {**self.report, 'unexpected': True}]
        for key, value in (('schema', True), ('arch', 'arm64'), ('success', 1),
                           ('tests', True), ('tests', 1), ('failures', False), ('failures', 1),
                           ('errors', [{}]), ('versions', {'expat': '2.9.0', 'openssl': '3.5.8'}),
                           ('expat_source_manifest_sha256', 'b' * 64),
                           ('expat_install_manifest_sha256', 'b' * 64)):
            invalid.append({**self.report, key: value})
        for report in invalid:
            with self.subTest(report=report), self.assertRaises(ValueError):
                self.validate(report)

    def test_vendor_substitution_missing_libraries_and_invalid_identities_are_rejected(self):
        invalid = []
        for name in ('expat', 'ssl', 'crypto'):
            report = copy.deepcopy(self.report)
            del report['loaded_libraries'][name]
            invalid.append(report)
            for field, value in (('path', '/lib/vendor-' + name + '.so'), ('sha256', 'bad'),
                                 ('device', 'invalid'), ('inode', True), ('inode', 0)):
                report = copy.deepcopy(self.report)
                report['loaded_libraries'][name][field] = value
                invalid.append(report)
        report = copy.deepcopy(self.report)
        report['loaded_libraries']['expat']['sha256'] = 'b' * 64
        invalid.append(report)
        for report in invalid:
            with self.subTest(report=report), self.assertRaises(ValueError):
                self.validate(report)


if __name__ == '__main__':
    unittest.main()
