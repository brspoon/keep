"""Build-only header inputs retain signed package and complete source identity."""
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
from unittest.mock import patch

from scripts import fortify_header_sources as fortify


def archive(files, mode='w', extra=None):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode=mode) as output:
        for name, body in files.items():
            member = tarfile.TarInfo(name)
            member.size = len(body)
            output.addfile(member, io.BytesIO(body))
        if extra is not None:
            output.addfile(extra)
    return stream.getvalue()


@unittest.skipUnless(shutil.which('openssl'), 'APK RSA verification requires OpenSSL')
class FortifyHeaderSourceTests(unittest.TestCase):
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
        keys = copy.deepcopy(fortify.alpine.KEYS)
        for key in keys.values():
            key['sha256'] = hashlib.sha256(self.key).hexdigest()
        self.stack.enter_context(patch.object(fortify.alpine, 'KEYS', keys))
        self.license = b'Complete upstream license and copyright notice\n'
        headers = {name: ('Full attributed header ' + name + '\n').encode() for name in fortify.HEADERS}
        headers['fortify-headers.h'] += fortify.PATCH_BEFORE + b'\n'
        self.originals = {'LICENSE': self.license, 'README.md': b'Complete upstream context',
                          **{'include/' + name: body for name, body in headers.items()}}
        self.headers = {**headers, 'fortify-headers.h': headers['fortify-headers.h'].replace(
            fortify.PATCH_BEFORE, fortify.PATCH_AFTER)}
        self.stack.enter_context(patch.object(fortify, 'HEADERS',
            {name: hashlib.sha256(body).hexdigest() for name, body in self.headers.items()}))
        self.stack.enter_context(patch.object(fortify, 'ORIGINAL_PATCHED_HEADER_SHA256',
            hashlib.sha256(headers['fortify-headers.h']).hexdigest()))
        self.stack.enter_context(patch.object(fortify, 'LICENSE_SHA256', hashlib.sha256(self.license).hexdigest()))
        self.patch = b'Complete exact Alpine patch fixture\n'
        self.stack.enter_context(patch.object(fortify, 'PATCH_SHA256', hashlib.sha256(self.patch).hexdigest()))
        self.stack.enter_context(patch.object(fortify, 'PATCH_SHA512', hashlib.sha512(self.patch).hexdigest()))
        self.source = self.source_archive(self.originals)
        self.stack.enter_context(patch.object(fortify, 'SOURCE_SHA256', hashlib.sha256(self.source).hexdigest()))
        self.stack.enter_context(patch.object(fortify, 'SOURCE_SHA512', hashlib.sha512(self.source).hexdigest()))
        recipe = b'Exact package recipe fixture\n'
        self.stack.enter_context(patch.object(fortify, 'RECIPE_SHA256', hashlib.sha256(recipe).hexdigest()))
        prefix = 'aports-' + fortify.BUILD_COMMIT + '/main/fortify-headers/'
        context = archive({prefix + 'APKBUILD': recipe, prefix + 'clang.patch': self.patch}, 'w:gz')
        self.stack.enter_context(patch.object(fortify, 'CONTEXT_SHA256', hashlib.sha256(context).hexdigest()))
        self.apks, self.metadata_hashes = {}, {}
        for arch in fortify.alpine.ARCHES:
            body, metadata, data_hash = self.apk(arch)
            self.apks[arch] = body
            self.metadata_hashes[arch] = hashlib.sha256(metadata).hexdigest()
        self.stack.enter_context(patch.object(fortify, 'DATA_SHA256', data_hash))
        self.stack.enter_context(patch.object(fortify, 'APK_SHA256',
            {arch: hashlib.sha256(body).hexdigest() for arch, body in self.apks.items()}))
        self.stack.enter_context(patch.object(fortify, 'PKGINFO_SHA256', self.metadata_hashes))
        self.inputs = {fortify.SOURCE_URL: self.source, fortify.PATCH_URL: self.patch,
                       fortify.RECIPE_URL: recipe, fortify.CONTEXT_URL: context}
        for arch, package in fortify.reviewed_spec()['packages'].items():
            self.inputs[package['url']] = self.apks[arch]
            self.inputs[package['signing_key']['url']] = self.key

    @staticmethod
    def source_archive(files):
        return archive({fortify.SOURCE_ROOT + '/' + name: body for name, body in files.items()}, 'w:gz')

    def apk(self, arch, *, headers=None, changes=None, script=False, bad_signature=False):
        payload = archive({'usr/include/fortify/' + name: body
                           for name, body in (headers or self.headers).items()})
        data = gzip.compress(payload, mtime=0)
        data_hash = hashlib.sha256(data).hexdigest()
        fields = {'pkgname': 'fortify-headers', 'pkgver': fortify.VERSION,
                  'origin': 'fortify-headers', 'arch': 'noarch', 'commit': fortify.BUILD_COMMIT,
                  'license': '0BSD', 'url': 'https://github.com/jvoisin/fortify-headers',
                  'datahash': data_hash, 'packager': 'fixture ' + arch}
        fields.update(changes or {})
        metadata = ''.join(key + ' = ' + value + '\n' for key, value in fields.items()).encode()
        controls = {'.PKGINFO': metadata}
        if script:
            controls['.post-install'] = b'unreviewed package script'
        control = gzip.compress(archive(controls), mtime=0)
        signature = subprocess.run(['openssl', 'dgst', '-sha1', '-sign', str(self.private)],
                                   input=control, check=True, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE).stdout
        if bad_signature:
            signature = b'invalid RSA signature'
        signed = gzip.compress(archive({'.SIGN.RSA.' + fortify.alpine.KEYS[arch]['name']: signature}), mtime=0)
        return signed + control + data, metadata, data_hash

    def reviewed_altered_apk(self, arch='amd64', **kwargs):
        body, metadata, data_hash = self.apk(arch, **kwargs)
        fortify.APK_SHA256[arch] = hashlib.sha256(body).hexdigest()
        fortify.PKGINFO_SHA256[arch] = hashlib.sha256(metadata).hexdigest()
        return body, data_hash

    def test_both_signed_inputs_replay_exact_source_headers_and_preserve_complete_notices(self):
        with tempfile.TemporaryDirectory() as directory:
            result = fortify.prepare(directory, fetch=self.inputs.__getitem__)
            self.assertEqual(len(result['packages']), 2)
            self.assertTrue(all(row['signature_verified'] for row in result['packages']))
            self.assertEqual(result['installation'], 'isolated-compiler-include-only')
            self.assertEqual((Path(directory) / 'LICENSE').read_bytes(), self.license)
            self.assertEqual(fortify.verify_prepared_headers(Path(directory) / 'include'), fortify.HEADERS)
            notices = [row for row in result['files'] if row['role'] == 'upstream-permissive-attribution-source']
            self.assertEqual(len(notices), 10)
            for record in result['files']:
                body = (Path(directory) / record['path']).read_bytes()
                self.assertEqual(hashlib.sha256(body).hexdigest(), record['sha256'])
                self.assertEqual(len(body), record['bytes'])
            self.assertEqual((Path(directory) / (fortify.SOURCE_ROOT + '.tar.gz')).read_bytes(), self.source)

    def test_changed_download_key_archive_recipe_or_patch_cannot_complete(self):
        for record in fortify.source_download_records():
            inputs = dict(self.inputs)
            inputs[record['url']] += b'changed input'
            with self.subTest(path=record['path']), tempfile.TemporaryDirectory() as directory:
                with self.assertRaises(ValueError):
                    fortify.prepare(directory, fetch=inputs.__getitem__)
                self.assertFalse((Path(directory) / 'manifest.json').exists())

    def test_invalid_rsa_signature_is_rejected_even_when_outer_hash_is_reviewed(self):
        body, _ = self.reviewed_altered_apk(bad_signature=True)
        with self.assertRaisesRegex(ValueError, 'RSA signature'):
            fortify.verify_apk(body, 'amd64', self.key)

    def test_signed_identity_dependency_or_script_mismatch_is_rejected(self):
        for changes in ({'changes': {'license': 'other'}}, {'changes': {'arch': 'x86_64'}},
                        {'changes': {'depend': 'unreviewed'}}, {'script': True}):
            body, _ = self.reviewed_altered_apk(**changes)
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                fortify.verify_apk(body, 'amd64', self.key)

    def test_changed_signed_header_is_rejected_after_signature_and_payload_verification(self):
        headers = {**self.headers, 'string.h': b'different signed header'}
        body, data_hash = self.reviewed_altered_apk(headers=headers)
        with patch.object(fortify, 'DATA_SHA256', data_hash), self.assertRaisesRegex(ValueError, 'APK header'):
            fortify.verify_apk(body, 'amd64', self.key)

    def test_complete_source_license_and_each_replayed_header_remain_independently_bound(self):
        for target in ('LICENSE', 'include/string.h'):
            body = self.source_archive({**self.originals, target: b'changed preferred source'})
            with self.subTest(target=target), patch.object(fortify, 'SOURCE_SHA256', hashlib.sha256(body).hexdigest()), \
                    patch.object(fortify, 'SOURCE_SHA512', hashlib.sha512(body).hexdigest()), self.assertRaises(ValueError):
                fortify.replay_source(body, self.patch)

    def test_changed_prepared_header_or_extra_file_cannot_reach_compilation(self):
        with tempfile.TemporaryDirectory() as directory:
            fortify.prepare(directory, fetch=self.inputs.__getitem__)
            include = Path(directory) / 'include'
            (include / 'string.h').write_bytes(b'tampered after preparation')
            with self.assertRaisesRegex(ValueError, 'Prepared Fortify header'):
                fortify.verify_prepared_headers(include)
            (include / 'string.h').write_bytes(self.headers['string.h'])
            (include / 'unexpected.h').write_bytes(b'unreviewed include')
            with self.assertRaisesRegex(ValueError, 'header set'):
                fortify.verify_prepared_headers(include)


if __name__ == '__main__':
    unittest.main()
