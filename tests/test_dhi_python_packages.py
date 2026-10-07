"""Exact signed Python package cohort and default runtime bytes remain bound."""
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

from scripts import dhi_python_packages as packages


def archive(entries, links=None):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w') as output:
        for name, body in entries:
            member = tarfile.TarInfo(name)
            member.size = len(body)
            output.addfile(member, io.BytesIO(body))
        for name, target in (links or {}).items():
            member = tarfile.TarInfo(name)
            member.type, member.linkname = tarfile.SYMTYPE, target
            output.addfile(member)
    return stream.getvalue()


@unittest.skipUnless(shutil.which('openssl'), 'APK verification requires OpenSSL')
class DhiPythonPackageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key_directory = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.key_directory.cleanup)
        cls.private = Path(cls.key_directory.name) / 'test-key.pem'
        subprocess.run(['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt',
                        'rsa_keygen_bits:2048', '-out', str(cls.private)], check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        cls.key = subprocess.check_output(['openssl', 'pkey', '-in', str(cls.private), '-pubout'])

    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(packages, 'KEY_SHA256', hashlib.sha256(self.key).hexdigest()))
        self.files = copy.deepcopy(packages.RUNTIME_FILES)
        self.runtime_bytes = {}
        for arch, records in self.files.items():
            self.runtime_bytes[arch] = {}
            for key, record in records.items():
                body = ('ordinary test ' + arch + ' ' + key).encode()
                self.runtime_bytes[arch][record['path']] = body
                record['sha256'] = hashlib.sha256(body).hexdigest()
        self.stack.enter_context(patch.object(packages, 'RUNTIME_FILES', self.files))
        self.bodies = {'https://dhi.io/keyring/' + packages.KEY_NAME: self.key}
        binaries, metadata = {}, {}
        for arch in packages.ARCHES:
            binaries[arch], metadata[arch] = {}, {}
            for name in packages.PACKAGES:
                body, info = self.apk(name, arch)
                self.bodies[self.url(name, arch)] = body
                binaries[arch][name] = hashlib.sha256(body).hexdigest()
                metadata[arch][name] = hashlib.sha256(info).hexdigest()
        self.stack.enter_context(patch.object(packages, 'BINARY_SHA256', binaries))
        self.stack.enter_context(patch.object(packages, 'PKGINFO_SHA256', metadata))
        self.spec = packages.reviewed_spec()

    @staticmethod
    def url(name, arch):
        return f'https://dhi.io/apk/alpine/v3.24/main/{packages.ARCHES[arch]}/{name}-{packages.VERSION}.apk'

    def apk(self, name, arch, *, changes=None, signer=None, aliases=None, files=None):
        entries, links = [], {}
        if name == 'python-3.14':
            entries = [(path.lstrip('/'), body) for path, body in
                       (files or self.runtime_bytes[arch]).items()]
            links = {path.lstrip('/'): value for path, value in
                     (packages.ALIASES if aliases is None else aliases).items()}
        data = gzip.compress(archive(entries, links), mtime=0)
        native = 'noarch' if name in ('pyc-3.14', 'python-3.14-pyc') else packages.ARCHES[arch]
        identity = {'pkgname': name, 'pkgver': packages.VERSION, 'origin': 'python-3.14',
                    'arch': native, 'commit': packages.BUILD_COMMIT, 'license': 'PSF-2.0',
                    'url': 'https://www.python.org/', 'datahash': hashlib.sha256(data).hexdigest()}
        identity.update(changes or {})
        info = ''.join(key + ' = ' + value + '\n' for key, value in identity.items())
        for field, values in packages.expected_fields(name, arch).items():
            info += ''.join(field + ' = ' + value + '\n' for value in values)
        info = info.encode()
        control = gzip.compress(archive([('.PKGINFO', info)]), mtime=0)
        signature = subprocess.run(['openssl', 'dgst', '-sha1', '-sign', str(self.private)],
                                   input=control, check=True, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE).stdout
        signed = gzip.compress(archive([('.SIGN.RSA.' + (signer or packages.KEY_NAME), signature)]), mtime=0)
        return signed + control + data, info

    def rebind(self, name, arch='amd64', **changes):
        body, info = self.apk(name, arch, **changes)
        packages.BINARY_SHA256[arch][name] = hashlib.sha256(body).hexdigest()
        packages.PKGINFO_SHA256[arch][name] = hashlib.sha256(info).hexdigest()
        return body

    def runtime(self, root, arch='amd64'):
        root = Path(root)
        for path, body in self.runtime_bytes[arch].items():
            target = root / path.lstrip('/')
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(body)
        for path, target in packages.ALIASES.items():
            (root / path.lstrip('/')).symlink_to(target)
        records = []
        for name in packages.PACKAGES:
            native = 'noarch' if name in ('pyc-3.14', 'python-3.14-pyc') else packages.ARCHES[arch]
            row = {'P': name, 'V': packages.VERSION, 'A': native, 'o': 'python-3.14',
                   'c': packages.BUILD_COMMIT, 'L': 'PSF-2.0', 'U': 'https://www.python.org/'}
            for key, field in [('D', 'depend'), ('p', 'provides'), ('i', 'install_if')]:
                values = packages.expected_fields(name, arch).get(field, [])
                if values:
                    row[key] = ' '.join(values)
            records.append(''.join(key + ':' + value + '\n' for key, value in row.items()))
        database = root / 'lib/apk/db/installed'
        database.parent.mkdir(parents=True)
        database.write_text('\n'.join(records) + '\n')
        return database

    def test_complete_signed_cohort_passes_for_both_architectures(self):
        for arch in packages.ARCHES:
            with self.subTest(architecture=arch), tempfile.TemporaryDirectory() as root:
                fetch = Mock(side_effect=self.bodies.__getitem__)
                result = packages.prepare_packages(self.spec, arch, root, fetch)
                self.assertEqual(fetch.call_count, 5)
                self.assertEqual(result, packages.security_manifest(self.spec, arch))
                self.assertEqual(json.loads((Path(root) / 'PYTHON_SECURITY.json').read_text()), result)
                self.assertEqual({p.name for p in Path(root).glob('*.apk')},
                                 {name + '-' + packages.VERSION + '.apk' for name in packages.PACKAGES})
                self.assertFalse((Path(root) / 'manifest.json').exists())

    def test_outer_and_key_checksums_are_mandatory(self):
        body = self.bodies[self.url('python-3.14', 'amd64')]
        for candidate, key in [(body + b'changed', self.key), (body, self.key + b'changed')]:
            with self.assertRaisesRegex(ValueError, 'checksum mismatch'):
                packages.verify_apk(candidate, 'python-3.14', 'amd64', key)

    def test_invalid_signature_cannot_be_approved_by_outer_hash(self):
        original = self.bodies[self.url('pyc-3.14', 'amd64')]
        parts = packages.gzip_parts(original)
        signed = gzip.compress(archive([('.SIGN.RSA.' + packages.KEY_NAME, b'bad signature')]), mtime=0)
        body = signed + parts[1][0] + parts[2][0]
        packages.BINARY_SHA256['amd64']['pyc-3.14'] = hashlib.sha256(body).hexdigest()
        with self.assertRaisesRegex(ValueError, 'RSA signature'):
            packages.verify_apk(body, 'pyc-3.14', 'amd64', self.key)

    def test_wrong_signer_payload_hash_and_metadata_identity_are_rejected(self):
        for change in [{'signer': 'unreviewed.pem'}, {'changes': {'datahash': 'f' * 64}},
                       {'changes': {'pkgver': '3.14.7-r2'}}, {'changes': {'arch': 'aarch64'}},
                       {'changes': {'commit': 'f' * 40}}, {'changes': {'license': 'unknown'}}]:
            body = self.rebind('python-3.14', **change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                packages.verify_apk(body, 'python-3.14', 'amd64', self.key)

    def test_package_dependency_provision_and_install_if_are_exact(self):
        _, info = self.apk('python-3.14-pyc', 'amd64')
        payload_hash = packages.metadata_fields(info)['datahash'][0]
        for bad in [info + b'depend = additional-risk\n', info + b'provides = unexpected\n',
                    info.replace(b'install_if = python-3.14=3.14.8-r0',
                                 b'install_if = python-3.14=3.14.7-r2'),
                    info + b'license = PSF-2.0\n']:
            with self.assertRaises(ValueError):
                packages.package_identity(bad, 'python-3.14-pyc', 'amd64', payload_hash)

    def test_reviewed_runtime_hashes_and_executable_aliases_are_mandatory(self):
        files = dict(self.runtime_bytes['amd64'])
        files['/usr/bin/python3.14'] = b'other executable'
        for change in [{'files': files}, {'aliases': {'/usr/bin/python': 'other'}},
                       {'aliases': {'/usr/bin/python': 'python3', '/usr/bin/python3': '/outside'}}]:
            body = self.rebind('python-3.14', **change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                packages.verify_apk(body, 'python-3.14', 'amd64', self.key)

    def test_incomplete_oversized_and_unsafe_archive_forms_are_rejected(self):
        body = self.bodies[self.url('pyc-3.14', 'amd64')]
        with self.assertRaises(ValueError):
            packages.gzip_parts(body + gzip.compress(b'extra', mtime=0))
        with self.assertRaises(ValueError):
            packages.gzip_parts(packages.gzip_parts(body)[0][0])
        for entries in [[('../escape', b'data')], [('/absolute', b'data')],
                        [('duplicate', b'one'), ('duplicate', b'two')]]:
            with self.assertRaises(ValueError):
                packages.tar_entries(archive(entries))
        with patch.object(packages, 'LIMIT', 20), self.assertRaises(ValueError):
            packages.gzip_parts(body)

    def test_offline_manifest_and_changed_source_map_fail_closed(self):
        self.assertEqual(packages.build_security_manifest('amd64', root=None),
                         packages.security_manifest(self.spec, 'amd64'))
        bad = copy.deepcopy(self.spec)
        bad['packages'][0]['binaries']['amd64']['sha256'] = 'f' * 64
        with self.assertRaisesRegex(ValueError, 'source map'):
            packages.security_manifest(bad, 'amd64')
        bad = copy.deepcopy(self.spec)
        bad['mutable_tag_reused_across_upstream_versions'] = 0
        with self.assertRaisesRegex(ValueError, 'source map'):
            packages.security_manifest(bad, 'amd64')
        with tempfile.TemporaryDirectory() as root:
            docs = Path(root) / 'docs'
            docs.mkdir()
            (docs / 'os-package-sources.json').write_text(json.dumps({'origins': [self.spec]}))
            self.assertEqual(packages.build_security_manifest('amd64', root),
                             packages.security_manifest(self.spec, 'amd64'))

    def test_installed_native_cohort_and_bytes_pass_for_both_architectures(self):
        for arch in packages.ARCHES:
            with self.subTest(architecture=arch), tempfile.TemporaryDirectory() as root:
                self.runtime(root, arch)
                manifest = packages.security_manifest(self.spec, arch)
                self.assertEqual(packages.verify_installed(self.spec, arch, manifest, root), manifest)

    def test_missing_mismatched_or_duplicate_installed_cohort_is_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            database = self.runtime(root)
            original = database.read_text()
            manifest = packages.security_manifest(self.spec, 'amd64')
            for bad in [original.replace('V:3.14.8-r0', 'V:3.14.7-r2', 1),
                        original.replace('L:PSF-2.0', 'L:unknown', 1),
                        original.replace('c:' + packages.BUILD_COMMIT, 'c:' + 'f' * 40, 1),
                        original.replace('P:pyc-3.14', 'P:unknown', 1),
                        original + '\n' + original.split('\n\n')[0] + '\n',
                        original.replace('D:python3~3.14', 'D:unexpected python3~3.14', 1)]:
                database.write_text(bad)
                with self.assertRaises(ValueError):
                    packages.verify_installed(self.spec, 'amd64', manifest, root)

    def test_changed_installed_bytes_alias_or_manifest_is_rejected(self):
        for change in ['bytes', 'alias', 'manifest', 'canonical-symlink', 'integer-signature']:
            with self.subTest(change=change), tempfile.TemporaryDirectory() as root:
                self.runtime(root)
                manifest = packages.security_manifest(self.spec, 'amd64')
                exe = Path(root) / 'usr/bin/python3.14'
                if change == 'bytes':
                    exe.write_bytes(b'changed executable')
                elif change == 'alias':
                    alias = Path(root) / 'usr/bin/python'
                    alias.unlink()
                    alias.symlink_to('python3.14')
                elif change == 'canonical-symlink':
                    other = exe.with_name('other')
                    exe.rename(other)
                    exe.symlink_to('other')
                elif change == 'integer-signature':
                    manifest['packages'][0]['signature_verified'] = 1
                else:
                    manifest['package_version'] = '3.14.7-r2'
                with self.assertRaises(ValueError):
                    packages.verify_installed(self.spec, 'amd64', manifest, root)


if __name__ == '__main__':
    unittest.main()
