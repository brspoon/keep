"""Only the exact mounted cohort reaches offline APK installation and cleanup."""
from contextlib import ExitStack
import copy
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, call, patch

from scripts import install_runtime_packages as installer


ROOT = Path(__file__).resolve().parents[1]


class InstallRuntimePackageTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        directory = self.stack.enter_context(tempfile.TemporaryDirectory())
        self.root = Path(directory) / 'packages'
        self.helpers, cohort = {}, []
        definitions = (
            ('musl', ('musl',), '1.2.6-r3', 'MUSL_SECURITY.json'),
            ('certificates', ('ca-certificates-bundle',), '20261020-r0', 'CA_CERTIFICATES_SECURITY.json'),
            ('expat', ('expat', 'libexpat'), '2.9.0-r0', 'EXPAT_SECURITY.json'),
            ('zlib', ('zlib',), '1.3.2-r1', 'ZLIB_SECURITY.json'),
            ('python', ('pyc-3.14', 'python-3.14', 'python-3.14-pyc',
                        'python-3.14-pycache-pyc0'), '3.14.8-r0', 'PYTHON_SECURITY.json'),
        )
        self.bodies, self.keys, self.specs, self.manifests = {}, {}, {}, {}
        for name, packages, version, manifest_name in definitions:
            key_name = 'dhi-test.rsa.pub' if name in ('python', 'certificates') else 'alpine-test.rsa.pub'
            key_body = b'fixture DHI public key' if name in ('python', 'certificates') else b'fixture Alpine public key'
            self.keys[name] = key_body
            signing = {'name': key_name, 'sha256': hashlib.sha256(key_body).hexdigest()}
            spec = {'signing_keys': {arch: dict(signing) for arch in ('amd64', 'arm64')},
                    'packages': []}
            for package in packages:
                binaries = {}
                for arch in ('amd64', 'arm64'):
                    body = ('signed fixture APK ' + package + ' ' + arch).encode()
                    self.bodies[(name, package, arch)] = body
                    binaries[arch] = {'sha256': hashlib.sha256(body).hexdigest()}
                spec['packages'].append({'name': package, 'version': version, 'binaries': binaries})
            self.specs[name] = spec
            self.manifests[name] = {arch: {'schema': 'fixture-security-v1', 'architecture': arch,
                                         'package_version': version, 'package_count': len(packages),
                                         'source_manifest_sha256': 'a' * 64,
                                         'library': {'sha256': 'b' * 64},
                                         'packages': [{'name': package['name'],
                                                       'apk_sha256': package['binaries'][arch]['sha256']}
                                                      for package in spec['packages']]}
                                    for arch in ('amd64', 'arm64')}
            helper = SimpleNamespace(
                KEY_NAME=key_name, KEY_SHA256=signing['sha256'],
                reviewed_spec=Mock(side_effect=lambda name=name: copy.deepcopy(self.specs[name])),
                build_security_manifest=Mock(side_effect=lambda architecture, root=None, name=name:
                                             copy.deepcopy(self.manifests[name][architecture])),
                prepare_packages=Mock(side_effect=lambda spec, architecture, output, name=name:
                                      self.write_helper(name, architecture, output)),
            )
            self.helpers[name] = helper
            cohort.append((name, helper, manifest_name))
        self.cohort = tuple(cohort)
        self.stack.enter_context(patch.object(installer, 'COHORT', self.cohort))

    def write_helper(self, name, architecture, output):
        output.mkdir(parents=True)
        (output / 'keys').mkdir()
        signing = self.specs[name]['signing_keys'][architecture]
        (output / 'keys' / signing['name']).write_bytes(self.keys[name])
        for package in self.specs[name]['packages']:
            (output / (package['name'] + '-' + package['version'] + '.apk')).write_bytes(
                self.bodies[(name, package['name'], architecture)])
        manifest_name = next(row[2] for row in self.cohort if row[0] == name)
        (output / manifest_name).write_text(json.dumps(self.manifests[name][architecture]))
        return self.manifests[name][architecture]

    def prepared(self, architecture='amd64'):
        installer.prepare(self.root, architecture)
        return self.root

    def expected_packages(self):
        return [self.root / name / (package['name'] + '-' + package['version'] + '.apk')
                for name, _, _ in self.cohort for package in self.specs[name]['packages']]

    def assert_install_held(self, error=ValueError):
        with patch.object(installer, 'arch', return_value='amd64'), \
                patch.object(installer.subprocess, 'run') as run, self.assertRaises(error):
            installer.install(self.root)
        run.assert_not_called()

    def test_preparation_merges_only_identical_reviewed_keys_and_exact_nine_packages(self):
        for architecture in ('amd64', 'arm64'):
            with self.subTest(architecture=architecture), tempfile.TemporaryDirectory() as directory:
                root = Path(directory) / 'prepared'
                installer.prepare(root, architecture)
                self.assertEqual({path.name for path in (root / 'keys').iterdir()},
                                 {'alpine-test.rsa.pub', 'dhi-test.rsa.pub'})
                packages = installer.installation_inputs(root, architecture)
                self.assertEqual(len(packages), 9)
                self.assertEqual({path.name for path in packages},
                                 {package['name'] + '-' + package['version'] + '.apk'
                                  for spec in self.specs.values() for package in spec['packages']})
                for helper in self.helpers.values():
                    helper.build_security_manifest.assert_called_with(architecture, root=None)

    def test_preparation_rejects_conflicting_validly_hashed_key_bytes(self):
        self.keys['zlib'] = b'different key under same reviewed filename'
        digest = hashlib.sha256(self.keys['zlib']).hexdigest()
        for signing in self.specs['zlib']['signing_keys'].values():
            signing['sha256'] = digest
        with self.assertRaisesRegex(ValueError, 'Conflicting'):
            installer.prepare(self.root, 'amd64')
        self.helpers['python'].prepare_packages.assert_not_called()

    def test_preparation_failure_stops_later_cohort_preparation(self):
        self.helpers['zlib'].prepare_packages.side_effect = ValueError('signature failure')
        with self.assertRaisesRegex(ValueError, 'signature failure'):
            installer.prepare(self.root, 'amd64')
        self.helpers['python'].prepare_packages.assert_not_called()

    def test_preparation_rejects_nonempty_and_symlink_roots(self):
        self.root.mkdir()
        (self.root / 'preserved').write_text('existing')
        with self.assertRaisesRegex(ValueError, 'empty safe'):
            installer.prepare(self.root, 'amd64')
        link = self.root.parent / 'link'
        link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'empty safe'):
            installer.prepare(link, 'amd64')
        for helper in self.helpers.values():
            helper.prepare_packages.assert_not_called()

    def test_architecture_is_native_and_unknown_machines_are_rejected(self):
        for machine, architecture in (('x86_64', 'amd64'), ('aarch64', 'arm64')):
            with patch.object(installer.platform, 'machine', return_value=machine):
                self.assertEqual(installer.arch(), architecture)
        with patch.object(installer.platform, 'machine', return_value='riscv64'), \
                patch.object(installer.subprocess, 'run') as run, self.assertRaisesRegex(ValueError, 'architecture'):
            installer.install(self.root)
        run.assert_not_called()

    def test_tampered_apk_is_blocked_before_native_command(self):
        self.prepared()
        path = self.expected_packages()[4]
        path.write_bytes(path.read_bytes() + b'tampered')
        self.assert_install_held()

    def test_wrong_architecture_apk_is_blocked_before_native_command(self):
        self.prepared()
        package = self.specs['python']['packages'][1]
        path = self.root / 'python' / (package['name'] + '-' + package['version'] + '.apk')
        path.write_bytes(self.bodies[('python', package['name'], 'arm64')])
        self.assert_install_held()

    def test_expected_apk_digest_is_enforced_independently(self):
        self.prepared()
        self.specs['python']['packages'][0]['binaries']['amd64']['sha256'] = '0' * 64
        self.assert_install_held()

    def test_tampered_key_and_unreviewed_key_are_blocked_before_native_command(self):
        self.prepared()
        path = self.root / 'keys/alpine-test.rsa.pub'
        original = path.read_bytes()
        path.write_bytes(original + b'tampered')
        self.assert_install_held()
        path.write_bytes(original)
        (self.root / 'keys/unreviewed.rsa.pub').write_bytes(b'unreviewed key')
        self.assert_install_held()

    def test_missing_apk_and_missing_key_are_blocked_before_native_command(self):
        self.prepared()
        apk = self.expected_packages()[0]
        body = apk.read_bytes()
        apk.unlink()
        self.assert_install_held()
        apk.write_bytes(body)
        (self.root / 'keys/dhi-test.rsa.pub').unlink()
        self.assert_install_held()

    def test_symlink_apk_key_and_manifest_are_blocked_even_with_expected_bytes(self):
        self.prepared()
        for path in (self.expected_packages()[0], self.root / 'keys/dhi-test.rsa.pub',
                     self.root / 'python/PYTHON_SECURITY.json'):
            body = path.read_bytes()
            saved = self.root.parent / ('saved-' + path.name)
            saved.write_bytes(body)
            path.unlink()
            path.symlink_to(saved)
            with self.subTest(path=path):
                self.assert_install_held()
            path.unlink()
            path.write_bytes(body)

    def test_manifest_architecture_version_and_added_fields_are_exact(self):
        self.prepared()
        path = self.root / 'python/PYTHON_SECURITY.json'
        expected = self.manifests['python']['amd64']
        for manifest in ({**expected, 'architecture': 'arm64'},
                         {**expected, 'package_version': '3.14.7-r2'},
                         {**expected, 'unreviewed': True}):
            path.write_text(json.dumps(manifest))
            with self.subTest(manifest=manifest):
                self.assert_install_held()

    def test_missing_or_malformed_manifest_is_blocked_before_native_command(self):
        self.prepared()
        path = self.root / 'zlib/ZLIB_SECURITY.json'
        path.unlink()
        self.assert_install_held()
        path.write_text('incomplete {')
        self.assert_install_held()

    def test_manifest_source_library_and_package_hashes_are_enforced(self):
        self.prepared()
        path = self.root / 'zlib/ZLIB_SECURITY.json'
        for field in ('source_manifest_sha256', 'library', 'packages'):
            manifest = copy.deepcopy(self.manifests['zlib']['amd64'])
            if field == 'library':
                manifest[field]['sha256'] = '0' * 64
            elif field == 'packages':
                manifest[field][0]['apk_sha256'] = '0' * 64
            else:
                manifest[field] = '0' * 64
            path.write_text(json.dumps(manifest))
            with self.subTest(field=field):
                self.assert_install_held()

    def test_successful_final_install_uses_exact_offline_command_then_fresh_interpreter(self):
        self.prepared()
        with patch.object(installer, 'arch', return_value='amd64'), \
                patch.object(installer.subprocess, 'run') as run:
            installer.install(self.root)
        tool = Path(installer.__file__).parent
        self.assertEqual(run.call_args_list, [
            call(['/sbin/apk', 'add', '--no-network', '--repositories-file', '/dev/null',
                  '--keys-dir', str(self.root / 'keys'), '--no-cache', '--upgrade',
                  *(str(path) for path in self.expected_packages())], check=True),
            call(['/usr/bin/python3.14', '-B', str(tool / 'dhi_python_packages.py'),
                  '--verify-installed', '--architecture', 'amd64', '--manifest',
                  str(self.root / 'python/PYTHON_SECURITY.json')], check=True),
            call(['/usr/bin/python3.14', '-B', str(tool / 'alpine_musl_sources.py'),
                  '--architecture', 'amd64', '--manifest',
                  str(self.root / 'musl/MUSL_SECURITY.json'), '--verify-installed'], check=True),
            call(['/usr/bin/python3.14', '-B', str(tool / 'dhi_certificate_packages.py'),
                  '--architecture', 'amd64', '--manifest',
                  str(self.root / 'certificates/CA_CERTIFICATES_SECURITY.json')], check=True),
            call(['/usr/bin/python3.14', '-B', str(tool / 'install_runtime_packages.py'),
                  '--install-expat'], check=True),
            call(['/usr/bin/python3.14', '-B', str(tool / 'patch_python_runtime.py')], check=True),
            call(['/usr/bin/python3.14', '-B', str(tool / 'install_runtime_packages.py'),
                  '--clean-stdlib'], check=True),
        ])
        self.assertNotIn('--allow-untrusted', run.call_args_list[0].args[0])

    def test_failure_at_each_native_step_prevents_all_later_steps(self):
        self.prepared()
        for failing_step in range(7):
            def fail(command, *, check):
                if run.call_count == failing_step + 1:
                    raise subprocess.CalledProcessError(1, command)
            with self.subTest(failing_step=failing_step), patch.object(installer, 'arch', return_value='amd64'), \
                    patch.object(installer.subprocess, 'run', side_effect=fail) as run, \
                    self.assertRaises(subprocess.CalledProcessError):
                installer.install(self.root)
            self.assertEqual(run.call_count, failing_step + 1)

    def test_cli_install_always_verifies_patches_and_cleans(self):
        packages = self.expected_packages()
        with patch.object(sys, 'argv', ['installer.py', '--install']), \
                patch.object(installer, 'arch', return_value='arm64'), \
                patch.object(installer, 'installation_inputs', return_value=packages), \
                patch.object(installer.subprocess, 'run') as run:
            installer.main()
        self.assertEqual(run.call_count, 7)
        verification = run.call_args_list[1].args[0]
        self.assertEqual(verification[0:2], ['/usr/bin/python3.14', '-B'])
        self.assertIn('--verify-installed', verification)
        self.assertIn('arm64', verification)
        self.assertEqual(Path(run.call_args_list[2].args[0][2]).name, 'alpine_musl_sources.py')
        self.assertIn('--verify-installed', run.call_args_list[2].args[0])
        self.assertEqual(Path(run.call_args_list[3].args[0][2]).name, 'dhi_certificate_packages.py')
        self.assertEqual(run.call_args_list[4].args[0][-1], '--install-expat')
        self.assertEqual(Path(run.call_args_list[5].args[0][2]).name, 'patch_python_runtime.py')
        self.assertEqual(run.call_args_list[6].args[0][-1], '--clean-stdlib')

    def test_build_musl_requires_matching_development_package_and_fresh_verification(self):
        self.prepared()
        development = self.root / 'musl/build/musl-dev-1.2.6-r3.apk'
        with patch.object(installer, 'arch', return_value='amd64'), \
                patch.object(installer.musl, 'build_installation_inputs', return_value=[development]) as inputs, \
                patch.object(installer.subprocess, 'run') as run:
            installer.install_build_musl(self.root)
        inputs.assert_called_once_with(self.root / 'musl', 'amd64')
        self.assertEqual(run.call_args_list, [
            call(['/sbin/apk', 'add', '--no-network', '--repositories-file', '/dev/null',
                  '--keys-dir', str(self.root / 'keys'), '--no-cache', '--upgrade',
                  str(self.root / 'musl/musl-1.2.6-r3.apk'), str(development)], check=True),
            call(['/usr/bin/python3.14', '-B', str(Path(installer.__file__).with_name('alpine_musl_sources.py')),
                  '--architecture', 'amd64', '--manifest', str(self.root / 'musl/MUSL_SECURITY.json'),
                  '--verify-build', '--prepared-root', str(self.root / 'musl')], check=True),
        ])

    def test_unverified_build_musl_or_headers_stop_before_package_installation(self):
        self.prepared()
        with patch.object(installer, 'arch', return_value='amd64'), \
                patch.object(installer.musl, 'build_installation_inputs', side_effect=ValueError('bad headers')), \
                patch.object(installer.subprocess, 'run') as run, self.assertRaisesRegex(ValueError, 'bad headers'):
            installer.install_build_musl(self.root)
        run.assert_not_called()
        (self.root / 'musl/musl-1.2.6-r3.apk').write_bytes(b'changed loader')
        with patch.object(installer, 'arch', return_value='amd64'), \
                patch.object(installer.musl, 'build_installation_inputs') as inputs, \
                patch.object(installer.subprocess, 'run') as run, self.assertRaises(ValueError):
            installer.install_build_musl(self.root)
        inputs.assert_not_called()
        run.assert_not_called()

    def test_build_refresh_installs_checked_generator_and_bundle_in_one_transaction(self):
        self.prepared()
        management = self.root / 'certificates/build/ca-certificates-20261020-r0.apk'
        with patch.object(installer, 'arch', return_value='amd64'), \
                patch.object(installer.certificates, 'build_installation_inputs', return_value=[management]) as inputs, \
                patch.object(installer.subprocess, 'run') as run:
            installer.install_certificates(self.root)
        inputs.assert_called_once_with(self.root / 'certificates', 'amd64')
        self.assertEqual(run.call_count, 2)
        command = run.call_args_list[0].args[0]
        self.assertIn('--no-network', command)
        self.assertEqual([p for p in command if p.endswith('.apk')],
                         [str(self.root / 'certificates/ca-certificates-bundle-20261020-r0.apk'),
                          str(management)])
        self.assertEqual(Path(run.call_args_list[1].args[0][2]).name, 'dhi_certificate_packages.py')
        self.assertEqual(run.call_args_list[1].args[0][-3:],
                         ['--verify-build', '--prepared-root', str(self.root / 'certificates')])
        self.assertNotIn('--no-scripts', run.call_args_list[0].args[0])

    def test_build_refresh_rejects_unverified_generator_before_apk(self):
        self.prepared()
        with patch.object(installer, 'arch', return_value='amd64'), \
                patch.object(installer.certificates, 'build_installation_inputs', side_effect=ValueError('bad generator')), \
                patch.object(installer.subprocess, 'run') as run, \
                self.assertRaisesRegex(ValueError, 'bad generator'):
            installer.install_certificates(self.root)
        run.assert_not_called()

    def test_build_refresh_rejects_missing_or_modified_certificate_inputs(self):
        self.prepared()
        path = self.root / 'certificates/ca-certificates-bundle-20261020-r0.apk'
        path.write_bytes(b'unreviewed replacement')
        with patch.object(installer, 'arch', return_value='amd64'), \
                patch.object(installer.subprocess, 'run') as run, self.assertRaises(ValueError):
            installer.install_certificates(self.root)
        run.assert_not_called()

    def test_removed_development_flag_cannot_skip_final_patch_or_cleanup(self):
        with patch.object(sys, 'argv', ['installer.py', '--install', '--development']), \
                patch.object(sys, 'stderr', io.StringIO()), \
                patch.object(installer, 'install') as install, self.assertRaises(SystemExit) as error:
            installer.main()
        self.assertEqual(error.exception.code, 2)
        install.assert_not_called()

    def test_cleanup_removes_new_stdlib_bootstrap_and_all_bytecode_only(self):
        stdlib = self.root.parent / 'stdlib'
        for relative in ('ensurepip/_bundled/pip.whl', 'module.py', '__pycache__/module.pyc',
                         'nested/old.pyc', 'nested/kept.py'):
            path = stdlib / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'fixture')
        unrelated = self.root.parent / 'unrelated.pyc'
        unrelated.write_bytes(b'preserved')
        with patch.object(installer.sysconfig, 'get_path', return_value=str(stdlib)) as stdlib_path:
            installer.clean_stdlib()
        stdlib_path.assert_called_once_with('stdlib')
        self.assertFalse((stdlib / 'ensurepip').exists())
        self.assertEqual(list(stdlib.rglob('*.pyc')), [])
        self.assertEqual((stdlib / 'module.py').read_bytes(), b'fixture')
        self.assertEqual((stdlib / 'nested/kept.py').read_bytes(), b'fixture')
        self.assertEqual(unrelated.read_bytes(), b'preserved')

    def test_cleanup_removes_bytecode_symlink_without_removing_external_target(self):
        stdlib = self.root.parent / 'stdlib'
        stdlib.mkdir()
        external = self.root.parent / 'external.pyc'
        external.write_bytes(b'protected external bytes')
        cache = stdlib / 'module.pyc'
        cache.symlink_to(external)
        with patch.object(installer.sysconfig, 'get_path', return_value=str(stdlib)):
            installer.clean_stdlib()
        self.assertFalse(cache.is_symlink())
        self.assertEqual(external.read_bytes(), b'protected external bytes')


class RealInstallerContractTests(unittest.TestCase):
    def test_actual_cohort_metadata_supports_all_nine_offline_inputs(self):
        # Keep genuine helper contracts here; substitute only file checks so this
        # test neither downloads vendor APKs nor invokes a native package manager.
        for architecture in ('amd64', 'arm64'):
            with self.subTest(architecture=architecture), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / 'keys').mkdir()
                expected = []
                for name, helper, manifest_name in installer.COHORT:
                    spec = helper.reviewed_spec()
                    (root / name).mkdir()
                    (root / name / manifest_name).write_text(
                        json.dumps(helper.build_security_manifest(architecture, root=None)))
                    key_name = (helper.KEY_NAME if name == 'python'
                                else spec['signing_keys'][architecture]['name'])
                    (root / 'keys' / key_name).write_bytes(b'fixture key checked separately')
                    expected.extend(root / name / (package['name'] + '-' + package['version'] + '.apk')
                                    for package in spec['packages'])
                with patch.object(installer, 'checked_file', side_effect=lambda path, digest: path) as checked:
                    actual = installer.installation_inputs(root, architecture)
                self.assertEqual(actual, expected)
                self.assertEqual(len(actual), 9)
                self.assertEqual(sum(path.suffix == '.apk' for path, _ in (item.args for item in checked.call_args_list)), 9)

    def test_final_docker_layer_installs_verifies_patches_and_cleans_without_tool_copies(self):
        text = (ROOT / 'Dockerfile').read_text()
        final = text.rsplit('\nFROM ', 1)[1]
        instructions = re.sub(r'\\\n\s*', ' ', final).splitlines()
        installs = [line for line in instructions if line.startswith('RUN ') and
                    'install_runtime_packages.py' in line]
        self.assertEqual(len(installs), 1)
        install = installs[0]
        for mount in ('source=/sbin/apk,target=/sbin/apk',
                      'source=/usr/lib/libapk.so.3.0.0,target=/usr/lib/libapk.so.3.0.0',
                      'source=/opt/runtime-packages,target=/opt/runtime-packages',
                      'source=/opt/runtime-build-tools,target=/opt/runtime-build-tools'):
            self.assertIn(mount, install)
        self.assertIn('"--install"', install)
        self.assertNotIn('--development', install)
        self.assertNotRegex(install, r'(?:^|,)rw(?:,|\s|$)|readonly=false')
        copied_tools = [line for line in instructions if line.startswith('COPY ') and
                        any(name in line for name in ('install_runtime_packages.py',
                                                     'patch_python_runtime.py', '/sbin/apk',
                                                     '/opt/runtime-build-tools', '.apk '))]
        self.assertEqual(copied_tools, [])
        dependency = next(stage for stage in re.split(r'(?m)^FROM ', text)[1:]
                          if re.search(r'\bAS dependencies\s*$', stage.splitlines()[0]))
        self.assertNotIn('"--install"', dependency)
        inputs = next(stage for stage in re.split(r'(?m)^FROM ', text)[1:]
                      if re.search(r'\bAS runtime-inputs\s*$', stage.splitlines()[0]))
        self.assertIn('"--install-build-musl"', inputs)
        self.assertIn('FROM runtime-inputs AS dependencies', text)
        self.assertLess(dependency.index('build_patched_expat.py'), dependency.index('COPY requirements.txt'))
        self.assertIn('/opt/runtime-packages/musl/MUSL_SECURITY.json /app/MUSL_SECURITY.json', final)
        self.assertIn('RUN python -m venv', dependency)
        all_instructions = re.sub(r'\\\n\s*', ' ', text).splitlines()
        all_installs = [line for line in all_instructions if line.startswith('RUN ') and
                        'install_runtime_packages.py' in line and '"--install"' in line]
        self.assertEqual(all_installs, installs)


class ExpatReplacementInstallationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.output = self.root / 'expat-patched'
        self.output.mkdir()
        self.library = self.root / 'libexpat.so.1.13.0'
        self.library.write_bytes(b'original signed library')
        self.alias = self.root / 'libexpat.so.1'
        self.alias.symlink_to(self.library.name)
        self.replacement = b'reviewed replacement library'
        self.manifest = {'qualified': True, 'purpose': 'reviewed-build',
                         'library': {'path': str(self.library), 'soname': self.alias.name,
                                     'sha256': hashlib.sha256(self.replacement).hexdigest()}}
        self.write_manifest()
        (self.output / installer.patched_expat.LIBRARY).write_bytes(self.replacement)
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.verify = self.stack.enter_context(patch.object(
            installer.patched_expat, 'verify_build_manifest', return_value=self.manifest))
        self.stack.enter_context(patch.object(installer.expat, 'build_security_manifest',
            return_value={'library': {'sha256': hashlib.sha256(self.library.read_bytes()).hexdigest()}}))

    def write_manifest(self):
        (self.output / 'EXPAT_PATCHED_SECURITY.json').write_bytes(
            installer.patched_expat.json_bytes(self.manifest))

    def install(self):
        installer.install_expat(self.root, 'amd64', self.library, self.alias)

    def test_replaces_canonical_inode_without_changing_the_soname_alias(self):
        inode = self.library.stat().st_ino
        self.install()
        self.assertEqual(self.library.read_bytes(), self.replacement)
        self.assertNotEqual(self.library.stat().st_ino, inode)
        self.assertEqual(self.alias.readlink(), Path(self.library.name))
        self.verify.assert_called_once_with(self.manifest, 'amd64')
        self.assertEqual(list(self.root.glob('.keep-expat-*')), [])

    def test_modified_input_output_manifest_or_alias_holds_replacement(self):
        for failure in ('vendor', 'replacement', 'alias', 'manifest'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as _:
                original = self.library.read_bytes()
                if failure == 'vendor':
                    self.library.write_bytes(b'changed original')
                elif failure == 'replacement':
                    (self.output / installer.patched_expat.LIBRARY).write_bytes(b'changed replacement')
                elif failure == 'alias':
                    self.alias.unlink()
                    self.alias.write_bytes(b'not a symlink')
                else:
                    (self.output / 'EXPAT_PATCHED_SECURITY.json').write_text(json.dumps(self.manifest))
                with self.assertRaises(ValueError):
                    self.install()
                self.assertNotEqual(self.library.read_bytes(), self.replacement)
                self.library.write_bytes(original)
                (self.output / installer.patched_expat.LIBRARY).write_bytes(self.replacement)
                self.alias.unlink()
                self.alias.symlink_to(self.library.name)
                self.write_manifest()

    def test_preparation_receipt_is_rejected_by_the_real_gate(self):
        # Stop mocking only this call; preparation must fail before output pins.
        self.stack.close()
        self.manifest.update(qualified=False, purpose='preparation-only')
        self.write_manifest()
        with self.assertRaisesRegex(ValueError, 'preparation or unqualified'):
            self.install()


if __name__ == '__main__':
    unittest.main()
