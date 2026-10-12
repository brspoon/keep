import ast
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

import test_helper_bundle as fixture

PORT = Path(__file__).parent / 'installer-port'
INSTALLER_SOURCE = PORT / 'scripts' / 'install_keep.py'
if not INSTALLER_SOURCE.is_file():
    INSTALLER_SOURCE = Path(fixture.bundle.__file__).resolve().parent / 'scripts' / 'install_keep.py'
spec = importlib.util.spec_from_file_location('draft_install_keep', INSTALLER_SOURCE)
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


class InstallerIntegrationTests(unittest.TestCase):
    setUp = fixture.BundleTests.setUp
    client = fixture.BundleTests.client
    def stage(self, **values):
        client = self.client(**values)
        return installer.stage_maintenance_helper(self.root, self.version,
            fetch=lambda url, limit: client.get(url, limit=limit))

    def test_helper_staging_preserves_owner_database_env_compose_and_existing_enrollment(self):
        protected = {'.env': b'FLASK_SECRET_KEY=synthetic-secret-only\n',
                     'compose.yml': b'name: keep\n', 'keep.sqlite3': b'synthetic-protected-owner-record'}
        for name, data in protected.items():
            self.paths.publish(self.root / name, data)
        state = self.paths.mkdir(self.root / '.maintenance-host')
        self.paths.publish(state / 'enrollment-active.json', b'synthetic-existing-enrollment')
        staged = self.stage()
        self.assertEqual(staged, self.stage())
        self.assertEqual({name: self.paths.read(self.root / name) for name in protected}, protected)
        self.assertEqual(self.paths.read(state / 'enrollment-active.json'), b'synthetic-existing-enrollment')
        proof = json.loads(self.paths.read(staged / 'bundle-proof.json'))
        self.assertEqual(proof['archive_sha256'], self.digest)
        self.assertEqual(proof['revision'], self.revision)

    def test_unverified_source_never_creates_helper_state(self):
        for values in ({'immutable': False}, {'wrong_digest': True}, {'no_helper': True}):
            with self.subTest(values=values), self.assertRaises(installer.InstallError):
                self.stage(**values)
            self.assertFalse((self.root / '.maintenance-host').exists())

    def test_source_collision_keeps_prior_helper_source_and_never_enrolls(self):
        staged = self.stage()
        self.paths.publish(staged / 'host_cli.py', b'changed', overwrite=True)
        with self.assertRaises(installer.InstallError):
            self.stage()
        self.assertFalse((self.root / '.maintenance-host' / 'enrollment-active.json').exists())
        self.assertEqual(self.paths.read(staged / 'host_cli.py'), b'changed')

    def test_default_installer_still_accepts_python39_syntax_and_never_stages_helper(self):
        source = INSTALLER_SOURCE.read_text()
        ast.parse(source, feature_version=(3, 9))
        with patch.object(installer, 'install') as install, patch.object(installer, 'stage_maintenance_helper') as stage, \
             patch.object(installer.sys, 'version_info', (3, 9)), patch('sys.stdout', new=io.StringIO()):
            installer.main(['--url', 'https://keep.example.test'])
        install.assert_called_once()
        stage.assert_not_called()

    def test_opt_in_python39_failure_happens_before_any_installation_mutation(self):
        with patch.object(installer, 'start_installation') as start, patch.object(installer, 'stage_maintenance_helper') as stage, \
             patch.object(installer.sys, 'version_info', (3, 9)), patch('sys.stderr', new=io.StringIO()), self.assertRaises(SystemExit):
            installer.main(['--start', '--maintenance-helper'])
        start.assert_not_called()
        stage.assert_not_called()


if __name__ == '__main__':
    unittest.main()
