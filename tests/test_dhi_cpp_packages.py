"""Build-only C++ packages retain signed identity and exact installed payloads."""
from contextlib import ExitStack
import copy
import gzip
import hashlib
import io
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from scripts import dhi_cpp_packages as cpp


def archive(files, links=None, *, script=False):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w') as result:
        for name, body in files.items():
            member = tarfile.TarInfo(name)
            member.mode = 0o755 if name.startswith('usr/bin/') else 0o644
            member.size = len(body)
            result.addfile(member, io.BytesIO(body))
        for name, (kind, target) in (links or {}).items():
            member = tarfile.TarInfo(name)
            member.type, member.linkname = kind, target
            member.mode = 0o755 if kind == tarfile.LNKTYPE else 0o777
            result.addfile(member)
        if script:
            member = tarfile.TarInfo('.post-install')
            result.addfile(member, io.BytesIO())
    return output.getvalue()


@unittest.skipUnless(shutil.which('openssl'), 'APK RSA verification requires OpenSSL')
class CppBuildPackageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.keys.cleanup)
        cls.private = Path(cls.keys.name) / 'private.pem'
        subprocess.run(['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt',
                        'rsa_keygen_bits:2048', '-out', str(cls.private)], check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        cls.key = subprocess.check_output(['openssl', 'pkey', '-in', str(cls.private), '-pubout'])

    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(cpp, 'KEY_SHA256', cpp.digest(self.key)))
        for field in ('APK_SHA256', 'PKGINFO_SHA256', 'DATA_SHA256', 'PAYLOAD_SHA256'):
            self.stack.enter_context(patch.object(cpp, field, {a: {} for a in cpp.ARCHES}))
        self.inputs = {cpp.KEY_URL: self.key}
        for arch in cpp.ARCHES:
            for name in cpp.PACKAGES:
                body, metadata, data, payload = self.apk(name, arch)
                self.approve(name, arch, body, metadata, data, payload)
                self.inputs[cpp.package_url(name, arch)] = body
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name).resolve()

    def apk(self, name='g++', arch='amd64', *, change=None, bad_signature=False, script=False,
            link_target='usr/bin/c++', content=b'checked compiler driver'):
        if name == 'g++':
            files = {'usr/bin/c++': content, 'usr/libexec/cc1plus': b'checked C++ compiler frontend'}
            links = {'usr/bin/g++': (tarfile.LNKTYPE, link_target)}
        else:
            files = {'usr/include/c++/15.2.0/string': b'checked standard library header'}
            links = {'usr/lib/libstdc++.so': (tarfile.SYMTYPE, 'libstdc++.so.6.0.34')}
        payload = archive(files, links)
        data = gzip.compress(payload, mtime=0)
        fields = {'pkgname': [name], 'pkgver': [cpp.VERSION], 'origin': ['gcc'],
                  'arch': [cpp.ARCHES[arch]], 'commit': [cpp.BUILD_COMMIT],
                  'license': [cpp.LICENSE], 'url': ['https://gcc.gnu.org'],
                  'datahash': [cpp.digest(data)], **copy.deepcopy(cpp.expected_fields(name, arch))}
        fields.update(change or {})
        metadata = ''.join(k + ' = ' + v + '\n' for k, values in fields.items() for v in values).encode()
        control = gzip.compress(archive({'.PKGINFO': metadata}, script=script), mtime=0)
        signature = subprocess.run(['openssl', 'dgst', '-sha1', '-sign', str(self.private)],
                                   input=control, check=True, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE).stdout
        if bad_signature:
            signature = b'invalid RSA signature'
        signed = gzip.compress(archive({'.SIGN.RSA.' + cpp.KEY_NAME: signature}), mtime=0)
        return signed + control + data, metadata, data, payload

    @staticmethod
    def approve(name, arch, body, metadata, data, payload):
        cpp.APK_SHA256[arch][name] = cpp.digest(body)
        cpp.PKGINFO_SHA256[arch][name] = cpp.digest(metadata)
        cpp.DATA_SHA256[arch][name] = cpp.digest(data)
        cpp.PAYLOAD_SHA256[arch][name] = cpp.digest(cpp.json_bytes(cpp.payload_manifest(cpp.tar_entries(payload))))

    def altered(self, **kwargs):
        parts = self.apk(**kwargs)
        self.approve(kwargs.get('name', 'g++'), kwargs.get('arch', 'amd64'), *parts)
        return parts[0]

    def test_both_architecture_preparation_retains_original_signed_bytes_and_metadata(self):
        prepared = self.root / 'prepared'
        manifest = cpp.prepare(prepared, fetch=self.inputs.__getitem__)
        self.assertEqual(manifest['architectures'], list(cpp.ARCHES))
        self.assertEqual(len(manifest['files']), 9)
        for record in cpp.source_download_records():
            self.assertEqual((prepared / record['path']).read_bytes(), self.inputs[record['url']])
        for arch in cpp.ARCHES:
            paths, payloads = cpp.installation_inputs(prepared, arch)
            self.assertEqual(len(paths), 2)
            self.assertEqual(set(payloads), set(cpp.PACKAGES))

    def test_invalid_signature_and_changed_key_or_download_are_rejected(self):
        body = self.altered(bad_signature=True)
        with self.assertRaisesRegex(ValueError, 'RSA signature'):
            cpp.verify_apk(body, 'g++', 'amd64', self.key)
        for record in cpp.source_download_records():
            inputs = {**self.inputs, record['url']: self.inputs[record['url']] + b'tampered'}
            with self.subTest(record=record['path']), tempfile.TemporaryDirectory() as directory:
                with self.assertRaises(ValueError):
                    cpp.prepare(directory, fetch=inputs.__getitem__)

    def test_signed_identity_dependencies_and_package_scripts_cannot_drift(self):
        for changes in ({'change': {'license': ['other']}}, {'change': {'arch': ['other']}},
                        {'change': {'depend': ['unreviewed']}}, {'change': {'provides': ['other']}},
                        {'change': {'triggers': ['/usr']}}, {'script': True}):
            body = self.altered(**changes)
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                cpp.verify_apk(body, 'g++', 'amd64', self.key)

    def test_complete_inventory_is_independent_of_outer_signature_and_metadata_pins(self):
        expected = cpp.PAYLOAD_SHA256['amd64']['g++']
        body = self.altered(content=b'changed signed compiler')
        cpp.PAYLOAD_SHA256['amd64']['g++'] = expected
        with self.assertRaisesRegex(ValueError, 'complete payload inventory'):
            cpp.verify_apk(body, 'g++', 'amd64', self.key)

    def test_archive_hardlinks_must_target_same_payload_regular_files(self):
        for target in ('../outside', '/absolute', 'usr/bin/missing', 'usr/bin/g++'):
            with self.subTest(target=target), self.assertRaisesRegex(ValueError, 'hardlink|Unsafe'):
                self.altered(link_target=target)
        with self.assertRaises(ValueError):
            cpp.tar_entries(archive({'../outside': b'x'}))
        with self.assertRaisesRegex(ValueError, 'symbolic link'):
            cpp.tar_entries(archive({}, {'usr/bin/g++': (tarfile.SYMTYPE, 'c++')}))

    def install_fixture(self, payload):
        for name, entry in payload.items():
            path, member = self.root / name, entry['member']
            path.parent.mkdir(parents=True, exist_ok=True)
            if member.isfile():
                path.write_bytes(entry['body'])
                path.chmod(member.mode)
            elif member.islnk():
                os.link(self.root / member.linkname, path)
            elif member.issym():
                path.symlink_to(member.linkname)
                if hasattr(os, 'lchmod'):
                    os.lchmod(path, member.mode)

    def root_ownership(self):
        original = Path.lstat
        def owned(path):
            values = list(original(path))
            values[4] = values[5] = 0
            return os.stat_result(values)
        return patch.object(Path, 'lstat', owned)

    def test_installed_payload_requires_all_regular_bytes_links_and_same_hardlink_inodes(self):
        _, payload = cpp.verify_apk(self.inputs[cpp.package_url('g++', 'amd64')], 'g++', 'amd64', self.key)
        self.install_fixture(payload)
        with self.root_ownership():
            cpp.verify_payload_installed(payload, self.root)
            (self.root / 'usr/libexec/cc1plus').write_bytes(b'tampered frontend')
            with self.assertRaisesRegex(ValueError, 'regular payload'):
                cpp.verify_payload_installed(payload, self.root)
            (self.root / 'usr/libexec/cc1plus').write_bytes(payload['usr/libexec/cc1plus']['body'])
            alias = self.root / 'usr/bin/g++'
            alias.unlink()
            shutil.copyfile(self.root / 'usr/bin/c++', alias)
            alias.chmod(0o755)
            with self.assertRaisesRegex(ValueError, 'hardlink alias'):
                cpp.verify_payload_installed(payload, self.root)

    def test_installed_standard_library_symlink_cannot_redirect(self):
        name = 'libstdc++-dev'
        _, payload = cpp.verify_apk(self.inputs[cpp.package_url(name, 'amd64')], name, 'amd64', self.key)
        self.install_fixture(payload)
        with self.root_ownership():
            cpp.verify_payload_installed(payload, self.root)
            alias = self.root / 'usr/lib/libstdc++.so'
            alias.unlink()
            alias.symlink_to('/unreviewed/library')
            if hasattr(os, 'lchmod'):
                os.lchmod(alias, 0o777)
            with self.assertRaisesRegex(ValueError, 'symbolic link'):
                cpp.verify_payload_installed(payload, self.root)

    def test_c_compiler_runtime_and_installed_package_identity_must_match_reviewed_cohort(self):
        files = {'usr/bin/gcc': b'original signed C compiler',
                 'usr/lib/libstdc++.so.6.0.34': b'original signed C++ runtime'}
        for name, body in files.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(body)
        (self.root / 'usr/lib/libstdc++.so.6').symlink_to('libstdc++.so.6.0.34')
        database = self.root / 'lib/apk/db/installed'
        database.parent.mkdir(parents=True)
        body = ''.join('P:' + name + '\nV:' + cpp.VERSION + '\nA:x86_64\no:gcc\nc:'
                       + cpp.BUILD_COMMIT + '\nL:' + cpp.LICENSE + '\nU:https://gcc.gnu.org\n\n'
                       for name in ('gcc', 'libstdc++'))
        database.write_text(body)
        pins = {arch: {name: cpp.digest(data) for name, data in files.items()} for arch in cpp.ARCHES}
        with patch.object(cpp, 'COHORT_FILES', pins):
            cpp.verify_cohort('amd64', self.root)
            for name, original in files.items():
                (self.root / name).write_bytes(b'changed dependency')
                with self.subTest(name=name), self.assertRaisesRegex(ValueError, r'Unchanged C\+\+ build dependency'):
                    cpp.verify_cohort('amd64', self.root)
                (self.root / name).write_bytes(original)
            database.write_text(body.replace('V:' + cpp.VERSION, 'V:other', 1))
            with self.assertRaisesRegex(ValueError, 'unchanged reviewed native'):
                cpp.verify_cohort('amd64', self.root)

    def test_offline_transaction_installs_only_two_verified_packages_without_scripts(self):
        prepared = self.root / 'prepared'
        cpp.prepare(prepared, architecture='amd64', fetch=self.inputs.__getitem__)
        existing = {'gcc': {'P': 'gcc'}, 'libstdc++': {'P': 'libstdc++'}}
        after = {**existing, 'g++': {'P': 'g++'}, 'libstdc++-dev': {'P': 'libstdc++-dev'}}
        with patch.object(cpp, 'native_architecture', return_value='amd64'), \
                patch.object(cpp, 'verify_cohort', return_value=existing), \
                patch.object(cpp, 'verify_installed', return_value=cpp.installation_manifest('amd64')), \
                patch.object(cpp, 'installed_records', return_value=after), \
                patch.object(cpp.subprocess, 'run') as command, \
                patch.object(cpp.subprocess, 'check_output', side_effect=[cpp.target('amd64'), '15.2.0']):
            cpp.install(prepared)
        arguments = command.call_args.args[0]
        self.assertTrue(all(option in arguments for option in ('--no-network', '--no-cache', '--no-scripts')))
        self.assertNotIn('--allow-untrusted', arguments)
        self.assertEqual([Path(value).name for value in arguments if value.endswith('.apk')],
                         [name + '-' + cpp.VERSION + '.apk' for name in cpp.PACKAGES])

    def test_existing_package_changes_or_wrong_native_compiler_cannot_get_receipt(self):
        for wrong in ('cohort', 'target'):
            prepared = self.root / wrong
            cpp.prepare(prepared, architecture='amd64', fetch=self.inputs.__getitem__)
            after = {'gcc': {'P': 'gcc', 'V': 'altered'}} if wrong == 'cohort' else {'gcc': {'P': 'gcc'}}
            with self.subTest(wrong=wrong), patch.object(cpp, 'native_architecture', return_value='amd64'), \
                    patch.object(cpp, 'verify_cohort', return_value={'gcc': {'P': 'gcc'}}), \
                    patch.object(cpp, 'verify_installed', return_value=cpp.installation_manifest('amd64')), \
                    patch.object(cpp, 'installed_records', return_value=after), \
                    patch.object(cpp.subprocess, 'run'), \
                    patch.object(cpp.subprocess, 'check_output', side_effect=['wrong-native', '15.2.0']), \
                    self.assertRaises(ValueError):
                cpp.install(prepared)
            self.assertFalse((prepared / 'CPP_BUILD_SECURITY.json').exists())


if __name__ == '__main__':
    unittest.main()
