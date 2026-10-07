import copy
import hashlib
import io
import json
import os
from pathlib import Path
import pyexpat
import ssl
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from scripts import alpine_expat_sources
from scripts import dhi_python_packages
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


class PythonInstallManifestTests(unittest.TestCase):
    def manifest(self, arch='amd64'):
        return dhi_python_packages.build_security_manifest(arch, root=None)

    def test_both_exact_signed_package_cohorts_are_required(self):
        for arch in ('amd64', 'arm64'):
            with self.subTest(arch=arch):
                manifest = self.manifest(arch)
                self.assertEqual(checks.validate_python_manifest(manifest, arch), manifest)
        for field, value in (('schema', 'other'), ('architecture', 'arm64'),
                             ('version', '3.14.7'), ('package_version', '3.14.7-r2'),
                             ('build_commit', 'a' * 40), ('source_manifest_sha256', 'a' * 64)):
            manifest = self.manifest()
            manifest[field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'exact signed packages'):
                checks.validate_python_manifest(manifest, 'amd64')

    def test_package_signature_source_alias_and_each_runtime_hash_are_exact(self):
        invalid = [None, {}, {**self.manifest(), 'unexpected': True}]
        for name in ('executable', 'library', 'abi_library', 'ssl_extension'):
            for field, value in (('path', '/vendor/file'), ('sha256', 'a' * 64)):
                manifest = self.manifest()
                manifest[name][field] = value
                invalid.append(manifest)
        for field, value in (('name', 'other'), ('version', '3.14.7-r2'),
                             ('signature_verified', False), ('signature_verified', 1),
                             ('apk_sha256', 'a' * 64), ('pkginfo_sha256', 'a' * 64),
                             ('signing_key_sha256', 'a' * 64)):
            manifest = self.manifest()
            manifest['packages'][0][field] = value
            invalid.append(manifest)
        manifest = self.manifest()
        manifest['packages'].pop()
        invalid.append(manifest)
        manifest = self.manifest()
        manifest['aliases']['/usr/bin/python'] = 'vendor-python'
        invalid.append(manifest)
        for manifest in invalid:
            with self.subTest(manifest=manifest), self.assertRaises(ValueError):
                checks.validate_python_manifest(manifest, 'amd64')

    def test_original_install_bytes_and_regular_file_are_required(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'PYTHON_SECURITY.json'
            body = (json.dumps(self.manifest(), sort_keys=True, indent=2) + '\n').encode()
            path.write_bytes(body)
            manifest, digest = checks.read_python_manifest(path, 'amd64')
            self.assertEqual(manifest, self.manifest())
            self.assertEqual(digest, hashlib.sha256(body).hexdigest())
            alias = path.with_name('alias.json')
            alias.symlink_to(path.name)
            with self.assertRaisesRegex(ValueError, 'regular file'):
                checks.read_python_manifest(alias, 'amd64')
            path.write_bytes(b' ' * (128 * 1024 + 1))
            with self.assertRaisesRegex(ValueError, 'too large'):
                checks.read_python_manifest(path, 'amd64')


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


class LoadedPythonIdentityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.manifest = PythonInstallManifestTests().manifest()
        for name, filename in (('executable', 'python3.14'), ('library', 'libpython3.14.so.1.0'),
                               ('abi_library', 'libpython3.so'), ('ssl_extension', '_ssl.fixture.so')):
            path = self.root / filename
            path.write_bytes(('signed ' + name + ' fixture').encode())
            self.manifest[name]['path'] = str(path)
            self.manifest[name]['sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
        self.python3 = self.root / 'python3'
        self.python3.symlink_to('python3.14')
        self.python = self.root / 'python'
        self.python.symlink_to('python3')
        self.venv = self.root / 'venv-python'
        self.venv.symlink_to('python')
        self.process = self.root / 'proc-exe'
        self.process.symlink_to('python3.14')
        self.manifest['aliases'] = {str(self.python): 'python3', str(self.python3): 'python3.14'}

    def mapping(self, name, **changes):
        path = Path(self.manifest[name]['path'])
        metadata = path.stat()
        device = changes.get('device', (os.major(metadata.st_dev), os.minor(metadata.st_dev)))
        inode = changes.get('inode', metadata.st_ino)
        return f'7f100000-7f101000 r-xp 00000000 {device[0]:02x}:{device[1]:02x} {inode} {path}\n'

    def maps(self):
        return self.mapping('library') + self.mapping('ssl_extension')

    def verify(self, maps=None, executable=None):
        import _ssl
        with patch.object(_ssl, '__file__', self.manifest['ssl_extension']['path'], create=True):
            return checks.verify_python_files(self.manifest, self.maps() if maps is None else maps,
                                               self.venv if executable is None else executable, self.process)

    def test_venv_alias_process_binary_and_both_default_library_mappings_match(self):
        result = self.verify()
        self.assertEqual(set(result['libraries']), {'python', 'python_ssl'})
        for name in ('executable', 'abi_library'):
            self.assertEqual(result['files'][name]['sha256'], self.manifest[name]['sha256'])
        self.assertEqual(result['aliases'], self.manifest['aliases'])
        self.assertEqual(self.verify(self.maps() + self.mapping('abi_library')), result)

    def test_wrong_interpreter_alias_or_process_binary_is_rejected(self):
        other = self.root / 'vendor-python'
        other.write_bytes(b'vendor interpreter')
        for alias in (self.venv, self.process, self.python, self.python3):
            target = alias.readlink()
            alias.unlink()
            alias.symlink_to(other.name)
            with self.subTest(alias=alias), self.assertRaises(ValueError):
                self.verify()
            alias.unlink()
            alias.symlink_to(target)
        self.python.unlink()
        self.python.write_bytes(Path(self.manifest['executable']['path']).read_bytes())
        with self.assertRaisesRegex(ValueError, 'executable alias'):
            self.verify(executable=Path(self.manifest['executable']['path']))

    def test_every_python_runtime_hash_and_default_binding_is_required(self):
        for name in ('executable', 'library', 'abi_library', 'ssl_extension'):
            path = Path(self.manifest[name]['path'])
            original = path.read_bytes()
            path.write_bytes(original + b'changed')
            with self.subTest(file=name), self.assertRaises(ValueError):
                self.verify()
            path.write_bytes(original)
        for name in ('library', 'ssl_extension'):
            maps = self.maps().replace(self.mapping(name), '')
            with self.subTest(mapping=name), self.assertRaisesRegex(ValueError, 'did not map'):
                self.verify(maps)

    def test_old_python_library_or_extension_mapping_and_deleted_mapping_are_rejected(self):
        old = self.root / 'libpython3.13.so.1.0'
        old.write_bytes(b'old Python library')
        metadata = old.stat()
        line = (f'7f100000-7f101000 r-xp 00000000 {os.major(metadata.st_dev):02x}:'
                f'{os.minor(metadata.st_dev):02x} {metadata.st_ino} {old}\n')
        with self.assertRaisesRegex(ValueError, 'unreviewed Python library'):
            self.verify(self.maps() + line)
        for name in ('library', 'ssl_extension'):
            original = self.mapping(name)
            for changed in (self.mapping(name, inode=metadata.st_ino),
                            self.mapping(name, device=(255, 255)),
                            original.rstrip() + ' (deleted)\n'):
                with self.subTest(name=name, changed=changed), self.assertRaises(ValueError):
                    self.verify(self.maps().replace(original, changed))
        import _ssl
        with patch.object(_ssl, '__file__', str(old), create=True):
            with self.assertRaisesRegex(ValueError, 'unreviewed Python extension'):
                checks.verify_python_files(self.manifest, self.maps(), self.venv, self.process)

    def test_python_gate_requires_complete_installed_package_and_tls_qualification(self):
        import _ssl
        maps = self.root / 'maps'
        maps.write_text(self.maps())
        packages = checks.python_packages()
        with patch.object(checks, 'read_python_manifest', return_value=(self.manifest, 'c' * 64)), \
             patch.object(sys, 'executable', str(self.venv)), \
             patch.object(checks, 'PROC_EXECUTABLE_PATH', self.process), \
             patch.object(_ssl, '__file__', self.manifest['ssl_extension']['path'], create=True), \
             patch.object(packages, 'verify_installed', return_value=self.manifest) as installed, \
             patch.object(checks, 'exercise_python', return_value={
                 'version': '3.14.8', 'tls_probes': dict(checks.PYTHON_TLS_PROBES)}) as probes:
            result = checks.check_python('amd64', self.root / 'manifest.json', maps)
            self.assertEqual(result['tls_probes'], checks.PYTHON_TLS_PROBES)
            self.assertEqual(result['install_manifest_sha256'], 'c' * 64)
            installed.assert_called_once_with(packages.reviewed_spec(), 'amd64', self.manifest)
            probes.assert_called_once()
            installed.side_effect = ValueError('installed package mismatch')
            probes.reset_mock()
            with self.assertRaisesRegex(ValueError, 'installed package mismatch'):
                checks.check_python('amd64', self.root / 'manifest.json', maps)
            probes.assert_not_called()


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

    def fixed_wrap_bio(self, context, *args, **kwargs):
        if context.check_hostname and not kwargs.get('server_hostname'):
            raise ValueError('check_hostname requires server_hostname')
        return self.original_wrap_bio(context, *args, **kwargs)

    def test_hostname_rejection_and_real_sni_switch_handshake_without_network(self):
        # Local Python may predate the upstream guard; model only that entry
        # rejection while exercising the real certificate, callback and BIOs.
        self.original_wrap_bio = ssl.SSLContext.wrap_bio
        with patch.object(ssl.SSLContext, 'wrap_bio',
                          lambda context, *args, **kwargs: self.fixed_wrap_bio(context, *args, **kwargs)):
            self.assertEqual(checks.exercise_python_tls(), checks.PYTHON_TLS_PROBES)

    def test_a_missing_hostname_guard_blocks_before_sni_or_handshake(self):
        original = ssl.SSLContext.wrap_bio

        def unchecked(context, *args, **kwargs):
            previous = context.check_hostname
            context.check_hostname = False
            try:
                return original(context, *args, **kwargs)
            finally:
                context.check_hostname = previous

        with patch.object(ssl.SSLContext, 'wrap_bio', unchecked), \
             patch.object(checks, 'memory_tls_handshake') as handshake:
            with self.assertRaisesRegex(ValueError, 'absent server_hostname'):
                checks.exercise_python_tls()
        handshake.assert_not_called()

    def test_tls_control_rejects_a_wrong_peer_hostname_with_real_verification(self):
        with tempfile.TemporaryDirectory() as directory:
            certificate, key = Path(directory) / 'certificate.pem', Path(directory) / 'key.pem'
            certificate.write_text(checks.TLS_CERTIFICATE)
            key.write_text(checks.TLS_PRIVATE_KEY)
            server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_context.load_cert_chain(certificate, key)
            client_context = ssl.create_default_context(cadata=checks.TLS_CERTIFICATE)
            client_in, client_out, server_in, server_out = (ssl.MemoryBIO() for _ in range(4))
            client = client_context.wrap_bio(client_in, client_out, server_hostname='wrong.invalid')
            server = server_context.wrap_bio(server_in, server_out, server_side=True)
            with self.assertRaises(ssl.SSLCertVerificationError):
                checks.memory_tls_handshake(client, server, client_in, client_out, server_in, server_out)

    def test_python_version_gate_precedes_tls_checks(self):
        from collections import namedtuple
        version = namedtuple('Version', 'major minor micro releaselevel serial')
        with patch.object(sys, 'version_info', version(3, 14, 7, 'final', 0)), \
             patch.object(checks, 'exercise_python_tls') as tls:
            with self.assertRaisesRegex(ValueError, 'ordinary Python version'):
                checks.exercise_python()
            tls.assert_not_called()
        with patch.object(sys, 'version_info', version(3, 14, 8, 'final', 0)), \
             patch.object(checks.platform, 'python_implementation', return_value='CPython'), \
             patch.object(sys, 'abiflags', ''), \
             patch.object(checks, 'exercise_python_tls', return_value=dict(checks.PYTHON_TLS_PROBES)):
            self.assertEqual(checks.exercise_python(),
                             {'version': '3.14.8', 'tls_probes': checks.PYTHON_TLS_PROBES})

    @unittest.skipUnless(sys.version_info[:3] == (3, 14, 8), 'Requires the reviewed native Python')
    def test_reviewed_native_python_runs_the_unmodified_tls_probes(self):
        self.assertEqual(checks.exercise_python(),
                         {'version': '3.14.8', 'tls_probes': checks.PYTHON_TLS_PROBES})


class RuntimeReportTests(unittest.TestCase):
    def results(self):
        def library(name):
            return {'path': '/usr/lib/' + name, 'sha256': 'b' * 64,
                    'device': '0:1', 'inode': 123}
        python = dhi_python_packages.build_security_manifest('arm64', root=None)
        return (
            {'version': '2.9.0', 'libraries': {'expat': library('libexpat.so.1.13.0')},
             'source_manifest_sha256': 'c' * 64, 'install_manifest_sha256': 'd' * 64},
            {'version': '3.5.9', 'libraries': {'ssl': library('libssl.so.3'),
                                            'crypto': library('libcrypto.so.3')}},
            {'version': '3.14.8',
             'libraries': {'python': library('libpython3.14.so.1.0'),
                           'python_ssl': library('_ssl.fixture.so')},
             'files': {'executable': library('python3.14'), 'abi_library': library('libpython3.so')},
             'aliases': python['aliases'], 'tls_probes': dict(checks.PYTHON_TLS_PROBES),
             'source_manifest_sha256': 'e' * 64, 'install_manifest_sha256': 'f' * 64},
        )

    def test_report_binds_both_versions_loaded_hashes_and_source_install_manifests(self):
        expat, openssl, python = self.results()
        with patch.object(checks, 'architecture', return_value='arm64'), \
             patch.dict(os.environ, {}, clear=True), \
             patch.object(checks, 'check_expat', return_value=expat), \
             patch.object(checks, 'check_openssl', return_value=openssl), \
             patch.object(checks, 'check_python', return_value=python):
            report = checks.qualify_runtime()
        self.assertEqual(report, {
            'schema': 2, 'arch': 'arm64', 'success': True, 'tests': 3, 'failures': 0,
            'errors': [], 'versions': {'expat': '2.9.0', 'openssl': '3.5.9', 'python': '3.14.8'},
            'loaded_libraries': {**expat['libraries'], **openssl['libraries'], **python['libraries']},
            'expat_source_manifest_sha256': 'c' * 64,
            'expat_install_manifest_sha256': 'd' * 64,
            'python_source_manifest_sha256': 'e' * 64,
            'python_install_manifest_sha256': 'f' * 64,
            'python_files': python['files'], 'python_aliases': python['aliases'],
            'python_tls_probes': python['tls_probes'],
        })

    def test_dependency_failure_is_reported_and_the_other_check_still_runs(self):
        _, openssl, python = self.results()
        with patch.object(checks, 'architecture', return_value='amd64'), \
             patch.dict(os.environ, {}, clear=True), \
             patch.object(checks, 'check_expat', side_effect=ValueError('wrong binding')), \
             patch.object(checks, 'check_openssl', return_value=openssl) as ssl_check, \
             patch.object(checks, 'check_python', return_value=python) as python_check:
            report = checks.qualify_runtime()
        self.assertFalse(report['success'])
        self.assertEqual(report['tests'], 3)
        self.assertEqual(report['failures'], 1)
        self.assertEqual(report['errors'], [{'check': 'expat', 'message': 'wrong binding'}])
        self.assertEqual(report['versions'], {'openssl': '3.5.9', 'python': '3.14.8'})
        ssl_check.assert_called_once()
        python_check.assert_called_once()

    def test_loader_overrides_block_qualification_before_importing_dependencies(self):
        for name in ('LD_LIBRARY_PATH', 'LD_PRELOAD'):
            with self.subTest(name=name), \
                 patch.object(checks, 'architecture', return_value='amd64'), \
                 patch.dict(os.environ, {name: '/unexpected'}, clear=True), \
                 patch.object(checks, 'check_expat') as expat, \
                 patch.object(checks, 'check_openssl') as openssl, \
                 patch.object(checks, 'check_python') as python:
                report = checks.qualify_runtime()
                self.assertFalse(report['success'])
                self.assertEqual(report['tests'], 0)
                self.assertEqual(report['errors'][0]['check'], 'environment')
                expat.assert_not_called()
                openssl.assert_not_called()
                python.assert_not_called()

    def test_report_cli_emits_failure_json_and_returns_nonzero(self):
        report = {'success': False, 'errors': [{'check': 'expat', 'message': 'wrong binding'}]}
        output = io.StringIO()
        with patch.object(checks, 'qualify_runtime', return_value=report), redirect_stdout(output):
            self.assertEqual(checks.main(['--report']), 1)
        self.assertEqual(json.loads(output.getvalue()), report)


class RetainedDependencyReportTests(unittest.TestCase):
    def setUp(self):
        self.manifest = ExpatInstallManifestTests().manifest()
        self.python = PythonInstallManifestTests().manifest()
        install_hash = hashlib.sha256(
            (json.dumps(self.manifest, sort_keys=True, indent=2) + '\n').encode()).hexdigest()
        self.report = {
            'schema': 2, 'arch': 'amd64', 'success': True, 'tests': 3, 'failures': 0,
            'errors': [], 'versions': {'expat': '2.9.0', 'openssl': '3.5.9', 'python': '3.14.8'},
            'loaded_libraries': {
                name: {'path': str(path), 'sha256': digest, 'device': '0:1', 'inode': inode}
                for name, path, digest, inode in (
                    ('expat', checks.EXPAT_LIBRARY, checks.EXPAT_LIBRARY_SHA256['amd64'], 101),
                    ('ssl', checks.SSL_LIBRARY, 'e' * 64, 102),
                    ('crypto', checks.CRYPTO_LIBRARY, 'f' * 64, 103),
                    ('python', self.python['library']['path'], self.python['library']['sha256'], 104),
                    ('python_ssl', self.python['ssl_extension']['path'], self.python['ssl_extension']['sha256'], 105),
                )
            },
            'expat_source_manifest_sha256': self.manifest['source_manifest_sha256'],
            'expat_install_manifest_sha256': install_hash,
            'python_source_manifest_sha256': self.python['source_manifest_sha256'],
            'python_install_manifest_sha256': hashlib.sha256(
                (json.dumps(self.python, sort_keys=True, indent=2) + '\n').encode()).hexdigest(),
            'python_files': {
                name: {'path': self.python[name]['path'], 'sha256': self.python[name]['sha256'],
                       'device': '0:1', 'inode': inode}
                for name, inode in (('executable', 106), ('abi_library', 107))
            },
            'python_aliases': self.python['aliases'],
            'python_tls_probes': dict(checks.PYTHON_TLS_PROBES),
        }

    def validate(self, report):
        with patch.object(checks, 'expected_expat_manifest', return_value=self.manifest) as source, \
             patch.object(checks, 'expected_python_manifest', return_value=self.python) as python_source:
            result = checks.validate_report(report, 'amd64', root=Path('/source-fixture'))
        source.assert_any_call('amd64', Path('/source-fixture'))
        source.assert_any_call('amd64', None)
        python_source.assert_any_call('amd64', Path('/source-fixture'))
        python_source.assert_any_call('amd64', None)
        return result

    def test_original_native_report_replays_without_runtime_filesystem(self):
        with patch.object(checks, 'file_identity', side_effect=AssertionError('runtime access')), \
             patch.object(checks, 'check_expat', side_effect=AssertionError('runtime import')), \
             patch.object(checks, 'check_openssl', side_effect=AssertionError('runtime import')), \
             patch.object(checks, 'check_python', side_effect=AssertionError('runtime import')):
            self.assertEqual(self.validate(self.report), self.report)

    def test_replay_derives_both_manifest_hashes_from_the_real_reviewed_source_map(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lock = root / 'docs/os-package-sources.json'
            lock.parent.mkdir()
            spec = alpine_expat_sources.reviewed_spec()
            lock.write_text(json.dumps({'origins': [spec, dhi_python_packages.reviewed_spec()]}))
            self.assertEqual(checks.validate_report(self.report, 'amd64', root), self.report)
            spec['recipe']['sha256'] = 'a' * 64
            lock.write_text(json.dumps({'origins': [spec, dhi_python_packages.reviewed_spec()]}))
            with self.assertRaisesRegex(ValueError, 'exact reviewed Alpine origin'):
                checks.validate_report(self.report, 'amd64', root)

    def test_failed_wrong_arch_incomplete_and_invalid_report_fields_are_rejected(self):
        invalid = [None, {}, {**self.report, 'unexpected': True}]
        for key, value in (('schema', True), ('schema', 1), ('arch', 'arm64'), ('success', 1),
                           ('tests', True), ('tests', 2), ('failures', False), ('failures', 1),
                           ('errors', [{}]), ('versions', {'expat': '2.9.0', 'openssl': '3.5.8'}),
                           ('expat_source_manifest_sha256', 'b' * 64),
                           ('expat_install_manifest_sha256', 'b' * 64),
                           ('python_source_manifest_sha256', 'b' * 64),
                           ('python_install_manifest_sha256', 'b' * 64),
                           ('python_tls_probes', {}),
                           ('python_tls_probes', {**checks.PYTHON_TLS_PROBES,
                                                  'wrap_bio_requires_hostname': 1}),
                           ('python_aliases', {'/usr/bin/python': 'other'})):
            invalid.append({**self.report, key: value})
        for report in invalid:
            with self.subTest(report=report), self.assertRaises(ValueError):
                self.validate(report)

    def test_vendor_substitution_missing_libraries_and_invalid_identities_are_rejected(self):
        invalid = []
        for name in ('expat', 'ssl', 'crypto', 'python', 'python_ssl'):
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

    def test_python_file_hashes_and_original_package_source_lock_must_match(self):
        for name in ('executable', 'abi_library'):
            for field, value in (('path', '/vendor/python'), ('sha256', 'a' * 64),
                                 ('inode', True), ('device', 'invalid')):
                report = copy.deepcopy(self.report)
                report['python_files'][name][field] = value
                with self.subTest(name=name, field=field), self.assertRaises(ValueError):
                    self.validate(report)
        for name in ('python', 'python_ssl'):
            report = copy.deepcopy(self.report)
            report['loaded_libraries'][name]['sha256'] = 'a' * 64
            with self.subTest(library=name), self.assertRaisesRegex(ValueError, 'Python loaded-library hash'):
                self.validate(report)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lock = root / 'docs/os-package-sources.json'
            lock.parent.mkdir()
            spec = dhi_python_packages.reviewed_spec()
            spec['recipe']['sha256'] = 'a' * 64
            lock.write_text(json.dumps({'origins': [alpine_expat_sources.reviewed_spec(), spec]}))
            with self.assertRaisesRegex(ValueError, 'exact reviewed DHI origin'):
                checks.validate_report(self.report, 'amd64', root)


if __name__ == '__main__':
    unittest.main()
