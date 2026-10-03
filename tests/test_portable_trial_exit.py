"""Offline CLI and cleanup failure behavior for portable recovery trials."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from contextlib import redirect_stdout, redirect_stderr
import io

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import portable_container_trial as trial_module


class PortableTrialExitTests(unittest.TestCase):
    def test_cli_returns_failure_when_report_outcome_is_failed(self):
        with patch.object(trial_module, 'run_trial', return_value={'outcome': 'failed'}), \
             redirect_stdout(io.StringIO()):
            self.assertEqual(trial_module.main(['--candidate-image', 'keep:test']), 1)
        with patch.object(trial_module, 'run_trial', return_value={'outcome': 'passed'}), \
             redirect_stdout(io.StringIO()):
            self.assertEqual(trial_module.main(['--candidate-image', 'keep:test']), 0)

    def test_cleanup_inventory_error_and_incomplete_volumes_are_recorded(self):
        for failed_inventory in (True, False):
            with self.subTest(failed_inventory=failed_inventory), tempfile.TemporaryDirectory() as tmp:
                instance = trial_module.Trial.__new__(trial_module.Trial)
                instance.project = 'keep-recovery-012345abcdef'
                instance.temp = Path(tmp)
                instance.volume_names = {name: instance.project + '-' + name for name in
                                         ('fresh-data', 'fixture-data', 'restore-data', 'rollback-data')}
                instance.report = {'cleanup': {'containers_removed': False, 'volumes_removed': []}}
                instance.remove_containers = MagicMock()
                network = SimpleNamespace(returncode=1 if failed_inventory else 0, stdout='', stderr='offline')
                missing = SimpleNamespace(returncode=1, stdout='', stderr='no such volume')
                with patch.object(trial_module.subprocess, 'run', side_effect=[network, *([missing] * 4)]):
                    instance.remove_and_cleanup('synthetic-overlay')
                cleanup = instance.report['cleanup']
                self.assertTrue(cleanup['containers_removed'])
                self.assertEqual(cleanup['volumes_removed'], [])
                if failed_inventory:
                    self.assertEqual(cleanup['network_inventory_error'],
                                     'Could not verify exact trial network inventory')
                else:
                    self.assertNotIn('network_inventory_error', cleanup)

    def test_run_trial_marks_incomplete_cleanup_as_failed_and_writes_evidence(self):
        volume_names = {name: 'keep-recovery-012345abcdef-' + name for name in
                        ('fresh-data', 'fixture-data', 'restore-data', 'rollback-data')}
        candidate = {'reference': 'keep:test', 'runtime_reference': 'sha256:' + 'a' * 64,
                     'image_id': 'sha256:' + 'a' * 64, 'version': '2.18.0',
                     'revision': 'b' * 40, 'architecture': 'amd64', 'os': 'linux'}

        class FakeTrial:
            def __init__(self, *_args):
                self.project = 'keep-recovery-012345abcdef'
                self.temp = Path('/synthetic')
                self.volume_names = volume_names
                self.report = {'cleanup': {'containers_removed': False, 'volumes_removed': []}}
                self.overlay_images = {}

            def assert_trial_names_unused(self): pass
            def phase(self, _name, _action): return 'ok'
            def write_overlay(self, *_args, **_kwargs): return 'synthetic-overlay'
            def remove_containers(self, *_args): pass
            def start(self, *_args, **_kwargs): pass
            def stop(self, *_args, **_kwargs): pass
            def fresh_install(self, *_args, **_kwargs): return {}
            def seed_fixture(self, *_args, **_kwargs): return {}
            def verify_fixture(self, *_args, **_kwargs): return {}
            def fingerprint(self, *_args, **_kwargs): return {}
            def compare_fingerprints(self, *_args, **_kwargs): return {}
            def backup(self, *_args, **_kwargs): return 'sha256:' + 'c' * 64
            def compose_run(self, *_args, **_kwargs): return SimpleNamespace(returncode=0)
            def fail_upgrade(self, *_args, **_kwargs): return {}
            def preserve_failed_database(self, *_args, **_kwargs): return []
            def remove_and_cleanup(self, _overlay):
                self.report['cleanup']['containers_removed'] = True
                self.report['cleanup']['network_inventory_error'] = 'inventory unavailable'
            def write_report(self, path):
                Path(path).write_text(json.dumps(self.report))

        with tempfile.TemporaryDirectory() as tmp:
            evidence = Path(tmp) / 'evidence.json'
            args = SimpleNamespace(candidate_image='keep:test', previous_image=None,
                                   evidence=evidence, health_timeout=30,
                                   url='https://keep-recovery.invalid')
            with patch.object(trial_module, '_run', return_value=SimpleNamespace(stdout='2.24.4')), \
                 patch.object(trial_module, '_image_metadata', return_value=candidate), \
                 patch.object(trial_module, 'Trial', FakeTrial):
                report = trial_module.run_trial(args)
            self.assertEqual(report['outcome'], 'failed')
            self.assertEqual(json.loads(evidence.read_text())['outcome'], 'failed')
            self.assertIn('network_inventory_error', report['cleanup'])


if __name__ == '__main__':
    unittest.main()
