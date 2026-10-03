"""Offline tests of disposable installer trial admission and exact cleanup."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path('scripts').resolve()))
import installer_container_trial as trial


class DockerFixture:
    def __init__(self):
        self.calls = []
        self.containers = []
        self.volumes = []
        self.networks = []
        self.directory = None
        self.foreign = False
        self.owner = False
        self.starts = 0
        self.keep_volume = False
        self.image = {'Id': 'sha256:' + 'd' * 64, 'Os': 'linux', 'Architecture': 'amd64', 'Config': {'Labels': {
            'org.opencontainers.image.version': (trial.ROOT / 'VERSION').read_text().strip(),
            'org.opencontainers.image.revision': 'a' * 40}}}

    def command(self, argv, *, cwd, timeout, input=None):
        self.calls.append((argv, input))
        if argv[1:3] == ['context', 'inspect']:
            output = json.dumps('unix:///var/run/docker.sock')
        elif argv[1:3] == ['image', 'inspect']:
            output = json.dumps([self.image])
        elif argv[1] == 'ps':
            output = '\n'.join(self.containers)
        elif argv[1:3] == ['volume', 'ls']:
            output = '\n'.join(self.volumes)
        elif argv[1:3] == ['network', 'ls']:
            output = '\n'.join(self.networks)
        elif argv[1] == 'inspect':
            records = []
            for container, service in zip(self.containers, ('keep-app', 'keep-digest')):
                records.append({'Id': container, 'Config': {'Labels': {
                    'com.docker.compose.project': 'keep', 'com.docker.compose.service': service,
                    'com.docker.compose.project.working_dir': '/another/install' if self.foreign else str(self.directory)}},
                    'State': {'Running': True, 'Health': {'Status': 'healthy'}}})
            output = json.dumps(records)
        elif argv[1:3] == ['volume', 'inspect']:
            output = json.dumps([{'Name': trial.VOLUME, 'CreatedAt': '2026-10-02T12:00:00Z', 'Labels': {
                'com.docker.compose.project': 'keep', 'com.docker.compose.volume': 'keep-data'}}])
        elif argv[1:3] == ['network', 'inspect']:
            output = json.dumps([{'Id': 'c' * 64, 'Name': trial.NETWORK, 'Labels': {'com.docker.compose.project': 'keep'}}])
        elif argv[1] == 'compose' and 'exec' in argv:
            if argv[-1] == trial.PROBE_CODES:
                self.code_inputs = json.loads(input)
                output = json.dumps({'old_valid': False, 'new_valid': True})
            else:
                if argv[-1] == trial.CLAIM_OWNER:
                    self.owner = True
                    self.claim_input = input
                output = json.dumps({'owner_matches': self.owner, 'integrity': 'ok', 'bootstrap_count': 0})
        elif argv[1] == 'compose' and 'down' in argv:
            self.containers = []
            self.networks = []
            output = ''
        elif argv[1:3] == ['volume', 'rm']:
            if not self.keep_volume:
                self.volumes = []
            output = ''
        else:
            raise AssertionError('Unexpected Docker command: ' + repr(argv))
        return subprocess.CompletedProcess(argv, 0, output, '')

    def start(self, directory, **options):
        self.starts += 1
        self.directory = directory
        self.containers = ['a' * 64, 'b' * 64]
        self.volumes = [trial.VOLUME]
        self.networks = [trial.NETWORK]
        (directory / '.env').write_bytes(b'FLASK_SECRET_KEY=synthetic-private-secret\n')
        (directory / '.env').chmod(0o600)
        (directory / 'compose.yml').write_text('name: keep\n')
        self.options = options
        result = {'directory': directory, 'url': 'http://127.0.0.1:' + str(options['port']), 'owner_exists': self.owner}
        if not self.owner:
            result['code'] = ('x' if self.starts == 1 else 'y') * 43
        return result


class InstallerContainerTrialTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.fixture = DockerFixture()

    def run_fixture(self):
        with patch.dict(os.environ, {'DOCKER_HOST': ''}), \
             patch.object(trial.install_keep, 'start_installation', side_effect=self.fixture.start), \
             patch.object(trial.InstallerTrial, 'setup_http'), \
             patch.object(trial.socket, 'socket') as listener:
            listener.return_value.__enter__.return_value.getsockname.return_value = ('127.0.0.1', 50001)
            return trial.run_trial('keep-ci:latest', self.root / 'evidence.json', runner=self.fixture.command)

    def test_fresh_rerun_claim_cleanup_report_is_bound_and_contains_no_credentials(self):
        report = self.run_fixture()
        self.assertEqual(report['outcome'], 'passed')
        self.assertEqual(report['candidate']['image_id'], 'sha256:' + 'd' * 64)
        self.assertEqual([phase['name'] for phase in report['phases']],
                         ['fresh-install', 'installer-rerun', 'owner-preservation'])
        self.assertTrue(report['cleanup']['resources_absent'])
        self.assertEqual(report['cleanup']['preexisting_resources'], {'containers': [], 'volumes': [], 'networks': []})
        self.assertEqual(self.fixture.starts, 3)
        self.assertTrue(self.fixture.options['skip_pull'])
        self.assertEqual(self.fixture.options['bind_address'], '127.0.0.1')
        self.assertEqual(self.fixture.options['source_directory'], trial.ROOT)
        self.assertEqual(self.fixture.code_inputs, ['x' * 43, 'y' * 43])
        self.assertEqual(self.fixture.claim_input, 'y' * 43)
        serialized = (self.root / 'evidence.json').read_text()
        for secret in ('x' * 43, 'y' * 43, 'synthetic-private-secret', 'FLASK_SECRET_KEY'):
            self.assertNotIn(secret, serialized)
        self.assertEqual((self.root / 'evidence.json').stat().st_mode & 0o777, 0o600)
        self.assertFalse(self.fixture.directory.exists())
        self.assertEqual(self.fixture.containers + self.fixture.volumes + self.fixture.networks, [])
        removals = [argv for argv, _ in self.fixture.calls if 'rm' in argv or 'down' in argv]
        self.assertEqual(removals[-1], ['docker', 'volume', 'rm', trial.VOLUME])
        self.assertFalse(any('-v' in argv or 'prune' in argv for argv, _ in self.fixture.calls))

    def test_any_existing_keep_resource_prevents_start_and_all_docker_mutations(self):
        for kind, value in (('containers', 'a' * 64), ('volumes', trial.VOLUME), ('networks', trial.NETWORK)):
            with self.subTest(kind=kind):
                self.fixture = DockerFixture()
                setattr(self.fixture, kind, [value])
                (self.root / 'evidence.json').unlink(missing_ok=True)
                with self.assertRaises(trial.TrialError):
                    self.run_fixture()
                self.assertEqual(self.fixture.starts, 0)
                self.assertFalse(any('rm' in argv or 'down' in argv for argv, _ in self.fixture.calls))
                self.assertEqual(getattr(self.fixture, kind), [value])

    def test_foreign_container_directory_holds_cleanup_and_preserves_files_and_volume(self):
        self.fixture.foreign = True
        with self.assertRaises(trial.TrialError):
            self.run_fixture()
        self.assertEqual(self.fixture.volumes, [trial.VOLUME])
        self.assertTrue(self.fixture.directory.exists())
        self.assertFalse(any('rm' in argv or 'down' in argv for argv, _ in self.fixture.calls))
        report = json.loads((self.root / 'evidence.json').read_text())
        self.assertEqual(report['outcome'], 'failed')
        self.assertFalse(report['cleanup']['resources_absent'])
        self.addCleanup(trial.shutil.rmtree, self.fixture.directory)

    def test_failed_cleanup_never_reports_success(self):
        self.fixture.keep_volume = True
        with self.assertRaises(trial.TrialError):
            self.run_fixture()
        report = json.loads((self.root / 'evidence.json').read_text())
        self.assertEqual(report['outcome'], 'failed')
        self.assertFalse(report['cleanup']['resources_absent'])
        self.assertTrue(self.fixture.directory.exists())
        self.addCleanup(trial.shutil.rmtree, self.fixture.directory)

    def test_remote_docker_daemon_refused_before_any_docker_request(self):
        with patch.dict(os.environ, {'DOCKER_HOST': 'tcp://production.example:2376'}):
            subject = trial.InstallerTrial('keep-ci:latest', runner=self.fixture.command)
            self.addCleanup(trial.shutil.rmtree, subject.directory)
            with self.assertRaisesRegex(trial.TrialError, 'local Unix Docker daemon'):
                subject.preflight()
        self.assertEqual(self.fixture.calls, [])

    def test_existing_evidence_is_not_replaced_and_trial_never_starts(self):
        (self.root / 'evidence.json').write_text('existing evidence')
        with self.assertRaisesRegex(trial.TrialError, 'already exists'):
            self.run_fixture()
        self.assertEqual(self.fixture.calls, [])
        self.assertEqual((self.root / 'evidence.json').read_text(), 'existing evidence')

    def test_http_setup_requires_form_and_http_only_lax_cookie_without_secure(self):
        subject = trial.InstallerTrial('keep-ci:latest', runner=self.fixture.command)
        self.addCleanup(trial.shutil.rmtree, subject.directory)
        valid = 'session=synthetic; HttpOnly; Path=/; SameSite=Lax'
        cases = ((valid, b'<input name="bootstrap_code">', True),
                 (valid + '; Secure', b'<input name="bootstrap_code">', False),
                 ('session=synthetic; SameSite=Lax', b'<input name="bootstrap_code">', False),
                 ('session=synthetic; HttpOnly; SameSite=Strict', b'<input name="bootstrap_code">', False),
                 (valid, b'<p>No setup form</p>', False))
        for cookie, body, allowed in cases:
            response = MagicMock()
            response.__enter__.return_value = response
            response.read.return_value = body
            response.status = 200
            response.headers.get_all.return_value = [cookie]
            opener = MagicMock()
            opener.open.return_value = response
            with self.subTest(cookie=cookie, body=body), \
                 patch.object(trial.urllib.request, 'build_opener', return_value=opener):
                if allowed:
                    subject.setup_http('http://127.0.0.1:50001')
                else:
                    with self.assertRaisesRegex(trial.TrialError, 'session cookie contract'):
                        subject.setup_http('http://127.0.0.1:50001')
            opener.open.assert_called_once_with('http://127.0.0.1:50001/setup', timeout=15)
