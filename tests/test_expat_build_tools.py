"""Required build tools keep signed package, complete source and license identity."""
from contextlib import ExitStack
import copy
import gzip
import io
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from scripts import expat_build_tools as tools
from tests import test_dhi_cpp_packages as cpp_tests

archive = cpp_tests.archive


@unittest.skipUnless(shutil.which('openssl'), 'APK RSA verification requires OpenSSL')
class ExpatBuildToolTests(unittest.TestCase):
    setUpClass = cpp_tests.CppBuildPackageTests.__dict__['setUpClass']

    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(tools, 'PACKAGES', copy.deepcopy(tools.PACKAGES)))
        keys = copy.deepcopy(tools.alpine.KEYS)
        for key in keys.values():
            key['sha256'] = tools.digest(self.key)
        self.stack.enter_context(patch.object(tools.alpine, 'KEYS', keys))
        self.bodies = {}
        for arch in tools.alpine.ARCHES:
            for name in tools.PACKAGES:
                self.bodies[(name, arch)] = self.apk(name, arch)

    def apk(self, name='make', arch='amd64', *, changes=None, bad_signature=False,
            extra_script=False, payload_body=b'exact signed executable', approve=True):
        spec = tools.PACKAGES[name]
        binary = spec['binaries'][arch]
        files = {'usr/bin/make' if name == 'make' else 'bin/bash': payload_body}
        links = {'usr/bin/gmake': (tarfile.SYMTYPE, 'make')} if name == 'make' else {}
        payload = archive(files, links)
        data = gzip.compress(payload, mtime=0)
        fields = {'pkgname': [name], 'pkgver': [spec['version']], 'origin': [name],
                  'arch': [tools.alpine.ARCHES[arch]], 'commit': [spec['build_commit']],
                  'license': [spec['license']], 'url': [spec['url']], 'datahash': [tools.digest(data)],
                  **{key: binary.get(key, []) for key in ('depend', 'provides', 'replaces', 'install_if', 'triggers')}}
        fields.update(changes or {})
        metadata = ''.join(k + ' = ' + v + '\n' for k, values in fields.items() for v in values).encode()
        controls = {path: (metadata if path == '.PKGINFO' else b'reviewed control, never executed')
                    for path in binary['controls']}
        if extra_script:
            controls['.unreviewed-install'] = b'unreviewed script'
        control = gzip.compress(archive(controls), mtime=0)
        signature = subprocess.run(['openssl', 'dgst', '-sha1', '-sign', str(self.private)],
                                   input=control, check=True, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE).stdout
        if bad_signature:
            signature = b'invalid signature'
        sign = gzip.compress(archive({'.SIGN.RSA.' + tools.alpine.KEYS[arch]['name']: signature}), mtime=0)
        body = sign + control + data
        if approve:
            binary['sha256'] = tools.digest(body)
            binary['data_sha256'] = tools.digest(data)
            binary['controls'] = {path: tools.digest(value) for path, value in controls.items()
                                  if path != '.unreviewed-install'}
            binary['payload_sha256'] = tools.digest(tools.json_bytes(
                tools.cpp.payload_manifest(tools.archive_entries(payload))))
        return body

    def test_exact_signed_make_and_bash_inputs_verify_for_both_architectures(self):
        for (name, arch), body in self.bodies.items():
            controls, payload = tools.verify_apk(body, name, arch, self.key)
            self.assertIn('.PKGINFO', controls)
            self.assertTrue(payload)
        records = tools.source_download_records()
        self.assertEqual(sum(row['path'].endswith('.apk') for row in records), 4)

    def test_bad_rsa_signature_or_additional_control_script_is_rejected(self):
        for changes in ({'bad_signature': True}, {'extra_script': True}):
            body = self.apk(**changes)
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                tools.verify_apk(body, 'make', 'amd64', self.key)

    def test_signed_identity_and_dependency_changes_remain_rejected(self):
        for field in ('pkgver', 'license', 'arch', 'commit', 'depend', 'provides', 'triggers'):
            body = self.apk(changes={field: ['unreviewed']})
            with self.subTest(field=field), self.assertRaises(ValueError):
                tools.verify_apk(body, 'make', 'amd64', self.key)

    def test_complete_payload_inventory_cannot_be_replaced_by_a_new_outer_pin(self):
        old = tools.PACKAGES['make']['binaries']['amd64']['payload_sha256']
        body = self.apk(payload_body=b'changed signed program')
        tools.PACKAGES['make']['binaries']['amd64']['payload_sha256'] = old
        with self.assertRaisesRegex(ValueError, 'complete payload inventory'):
            tools.verify_apk(body, 'make', 'amd64', self.key)

    def test_source_license_and_complete_recipe_link_identity_are_independent(self):
        spec = tools.PACKAGES['make']
        prefix = 'aports-' + spec['build_commit'] + '/main/make/'
        recipe, notice = b'complete pinned build recipe', b'complete GPL license'
        spec['recipe_files'] = {
            'APKBUILD': {'bytes': len(recipe), 'sha256': tools.digest(recipe), 'type': 'file', 'target': None},
            'alias': {'bytes': None, 'sha256': None, 'type': 'symlink', 'target': 'APKBUILD'}}
        spec['notices'] = [{'archive': 'source.tar.gz', 'source_path': 'make-4.4.1/COPYING',
                            'sha256': tools.digest(notice), 'path': 'notices/COPYING', 'url': 'https://example.test/source'}]
        context = gzip.compress(archive({prefix + 'APKBUILD': recipe},
                                        {prefix + 'alias': (tarfile.SYMTYPE, 'APKBUILD')}), mtime=0)
        inputs = {'make/' + spec['context_path']: context, 'make/APKBUILD': recipe,
                  'make/source.tar.gz': b'archive read by bounded notice helper'}
        with tempfile.TemporaryDirectory() as directory, patch.object(tools.alpine, 'read_member', return_value=notice):
            records = []
            tools.verify_source_inputs('make', inputs, Path(directory), records)
            self.assertTrue(any(row['role'] == 'matching-build-recipe-link' for row in records))
            self.assertEqual((Path(directory) / 'make/notices/COPYING').read_bytes(), notice)
        with tempfile.TemporaryDirectory() as directory, patch.object(tools.alpine, 'read_member', return_value=b'altered GPL'), \
                self.assertRaisesRegex(ValueError, 'full license'):
            tools.verify_source_inputs('make', inputs, Path(directory), [])
        spec['recipe_files']['alias']['target'] = 'unreviewed'
        with tempfile.TemporaryDirectory() as directory, self.assertRaisesRegex(ValueError, 'link identity'):
            tools.verify_source_inputs('make', inputs, Path(directory), [])

    def test_installation_is_offline_disables_scripts_and_preserves_existing_packages(self):
        before = {'gcc': {'P': 'gcc'}}
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(tools.cpp, 'native_architecture', return_value='amd64'), \
                patch.object(tools, 'installation_inputs', return_value=([Path('/make.apk'), Path('/bash.apk')], {})), \
                patch.object(tools.cpp, 'verify_cohort', return_value=before), \
                patch.object(tools, 'verify_installed', return_value=tools.installation_manifest('amd64')), \
                patch.object(tools.cpp, 'installed_records', return_value={**before, 'make': {}, 'bash': {}}), \
                patch.object(tools.subprocess, 'check_output', side_effect=['GNU Make 4.4.1\n', 'GNU bash, version 5.3.9\n']), \
                patch.object(tools.subprocess, 'run') as run:
            result = tools.install(directory)
            self.assertFalse(result['package_scripts_executed'])
            command = run.call_args.args[0]
            self.assertTrue(all(flag in command for flag in ('--no-network', '--no-scripts', '--no-cache')))
            self.assertNotIn('--allow-untrusted', command)
            self.assertEqual(command[-2:], ['/make.apk', '/bash.apk'])


if __name__ == '__main__':
    unittest.main()
