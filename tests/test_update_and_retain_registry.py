"""Offline tests for the deployment-triggered registry retention wrapper."""
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import update_and_retain_registry as wrapper


class UpdateAndRetainRegistryTests(unittest.TestCase):
    NOW = datetime(2026, 10, 2, 12, 0, 0, tzinfo=timezone.utc)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        state = self.root / '.registry-state'
        state.mkdir(mode=0o700)
        backup = self.root / 'full-backups'
        backup.mkdir()
        configuration = {'backup_directory': str(backup), 'backup_pattern': 'keep-backup-*.tar.gz',
                         'containers': ['fixture-app', 'fixture-digest'], 'archive_prefix': 'keep'}
        path = state / 'retention-config.json'
        path.write_text(json.dumps(configuration)); path.chmod(0o600)
        (self.root / '.git').mkdir()
        (self.root / '.git/keep-deploy.lock').write_text('')
        self.receipts = {}

    def test_missing_operator_configuration_holds_cleanup_without_a_marker(self):
        self.write_receipt(self.receipt())
        (self.root / '.registry-state/retention-config.json').unlink()
        code, status, run = self.execute(lambda *_args, **_kwargs: self.fail('cleanup must hold'),
                                         after_deploy=True)
        self.assertEqual(code, 0)
        self.assertEqual(status['status'], 'held')
        run.assert_not_called()
        self.assertFalse(wrapper.marker_path(self.root).exists())

    def test_cli_forwards_explicit_root_and_default_is_the_script_checkout(self):
        self.assertEqual(wrapper.ROOT, Path(wrapper.__file__).resolve().parents[1])
        with patch.object(wrapper.os, 'umask'), patch.object(wrapper, 'run', return_value=0) as run:
            self.assertEqual(wrapper.main(['--root', str(self.root), '--after-deploy']), 0)
        run.assert_called_once_with(self.root, after_deploy=True, queued=False)

    def receipt(self, suffix='1', *, completed=None):
        recovery = self.root / '.deploy-backups' / 'registry-20261002T110000Z'
        recovery.mkdir(parents=True, exist_ok=True)
        completed = completed or self.NOW - timedelta(hours=1)
        completed_at = completed if isinstance(completed, str) else completed.isoformat()
        return {'image': 'sha256:' + suffix * 64, 'version': '2.18.' + suffix,
                'revision': suffix * 40, 'completed_at': completed_at,
                'recovery': str(recovery)}

    def write_receipt(self, receipt):
        (self.root / '.registry-state/deployed.json').write_text(json.dumps(receipt))

    def status(self, capsys_stream):
        return json.loads(capsys_stream.getvalue().strip().splitlines()[-1])

    def execute(self, side_effect, *, after_deploy=False, queued=False):
        from contextlib import redirect_stdout
        import io
        output = io.StringIO()
        with patch.object(wrapper, '_now', return_value=self.NOW), \
             patch.object(wrapper.subprocess, 'run', side_effect=side_effect) as run, \
             redirect_stdout(output):
            code = wrapper.run(self.root, after_deploy=after_deploy, queued=queued)
        return code, self.status(output), run

    def test_new_successful_receipt_runs_cleanup_then_writes_private_idempotency_marker(self):
        before, after = self.receipt('1'), self.receipt('2', completed=self.NOW.isoformat())
        self.write_receipt(before)

        def subprocess_run(command, **_kwargs):
            if command[0] == sys.executable and command[1].endswith('update_registry.py'):
                self.write_receipt(after)
                return type('Result', (), {'returncode': 0})()
            self.assertTrue(command[1].endswith('retain_registry.py'))
            self.assertEqual(command[2:5], ['--execute', '--refresh-artifacts', '--root'])
            return type('Result', (), {'returncode': 0})()

        code, status, run = self.execute(subprocess_run)
        self.assertEqual(code, 0)
        self.assertEqual(status['status'], 'retained')
        self.assertEqual(run.call_count, 2)
        marker = wrapper.marker_path(self.root)
        marker_data = json.loads(marker.read_text())
        self.assertEqual(marker_data, {'schema': wrapper.MARKER_SCHEMA, 'receipt': after})
        self.assertEqual(marker.stat().st_mode & 0o777, 0o600)

        code, status, run = self.execute(lambda *_args, **_kwargs: self.fail('after-deploy must skip updater'),
                                         after_deploy=True)
        self.assertEqual(code, 0)
        self.assertEqual(status['status'], 'already-retained')
        run.assert_not_called()

    def test_updater_failure_and_unchanged_receipt_never_run_cleanup(self):
        before = self.receipt('1')
        self.write_receipt(before)
        code, status, run = self.execute(lambda *_args, **_kwargs: type('Result', (), {'returncode': 23})())
        self.assertEqual(code, 23)
        self.assertEqual(status['status'], 'update-failed')
        self.assertEqual(run.call_count, 1)
        self.assertFalse(wrapper.marker_path(self.root).exists())

        unchanged_cases = (
            before,
            {**before, 'completed_at': (self.NOW - timedelta(hours=2)).isoformat()},
            {**before, 'completed_at': self.NOW.isoformat()},
        )
        for after in unchanged_cases:
            with self.subTest(after=after['completed_at']):
                self.write_receipt(before)

                def no_op(_command, **_kwargs):
                    self.write_receipt(after)
                    return type('Result', (), {'returncode': 0})()

                code, status, run = self.execute(no_op)
                self.assertEqual(code, 0)
                self.assertEqual(status['status'], 'unchanged')
                self.assertEqual(run.call_count, 1)
                self.assertFalse(wrapper.marker_path(self.root).exists())

    def test_deployment_hold_skips_cleanup_and_preserves_successful_receipt(self):
        before, after = self.receipt('1'), self.receipt('2', completed=self.NOW.isoformat())
        self.write_receipt(before)

        def updater(command, **_kwargs):
            self.write_receipt(after)
            (self.root / '.registry-state/update-request').touch()
            return type('Result', (), {'returncode': 0})()

        code, status, run = self.execute(updater)
        self.assertEqual(code, 0)
        self.assertEqual(status['status'], 'held')
        self.assertEqual(run.call_count, 1)
        self.assertEqual(json.loads((self.root / '.registry-state/deployed.json').read_text()), after)
        self.assertFalse(wrapper.marker_path(self.root).exists())

    def test_cleanup_failure_stays_deployment_success_and_current_receipt_mutation_is_not_marked(self):
        before, after = self.receipt('1'), self.receipt('2', completed=self.NOW.isoformat())
        self.write_receipt(before)

        def cleanup_failure(command, **_kwargs):
            if command[1].endswith('update_registry.py'):
                self.write_receipt(after)
                return type('Result', (), {'returncode': 0})()
            return type('Result', (), {'returncode': 9})()

        code, status, run = self.execute(cleanup_failure)
        self.assertEqual(code, 0)
        self.assertEqual(status['status'], 'held')
        self.assertEqual(run.call_count, 2)
        self.assertEqual(json.loads((self.root / '.registry-state/deployed.json').read_text()), after)
        self.assertFalse(wrapper.marker_path(self.root).exists())

        self.write_receipt(before)
        changed = self.receipt('3', completed=self.NOW.isoformat())

        def receipt_changes_during_cleanup(command, **_kwargs):
            if command[1].endswith('update_registry.py'):
                self.write_receipt(after)
                return type('Result', (), {'returncode': 0})()
            self.write_receipt(changed)
            return type('Result', (), {'returncode': 0})()

        code, status, run = self.execute(receipt_changes_during_cleanup)
        self.assertEqual(code, 0)
        self.assertEqual(status['status'], 'held')
        self.assertEqual(run.call_count, 2)
        self.assertFalse(wrapper.marker_path(self.root).exists())

    def test_malformed_new_receipt_is_held_and_queued_flag_only_reaches_updater(self):
        before = self.receipt('1')
        self.write_receipt(before)
        malformed = dict(self.receipt('2', completed=self.NOW.isoformat()))
        malformed['unexpected'] = 'field'

        def updater(command, **_kwargs):
            self.assertTrue(command[-1] == '--queued')
            self.write_receipt(malformed)
            return type('Result', (), {'returncode': 0})()

        code, status, run = self.execute(updater, queued=True)
        self.assertEqual(code, 0)
        self.assertEqual(status['status'], 'held')
        self.assertEqual(run.call_count, 1)
        self.assertFalse(wrapper.marker_path(self.root).exists())

        # A malformed old receipt does not block the operator-authorized updater,
        # but cannot provide proof that the new deployment is a transition.
        (self.root / '.registry-state/deployed.json').write_text('{broken')
        valid_after = self.receipt('3', completed=self.NOW.isoformat())

        def repair(command, **_kwargs):
            self.assertTrue(command[1].endswith('update_registry.py'))
            self.write_receipt(valid_after)
            return type('Result', (), {'returncode': 0})()

        code, status, run = self.execute(repair)
        self.assertEqual(code, 0)
        self.assertEqual(status['status'], 'held')
        self.assertEqual(run.call_count, 1)
        self.assertFalse(wrapper.marker_path(self.root).exists())

    def test_read_receipt_rejects_future_stale_and_unzoned_timestamps(self):
        for timestamp in ((self.NOW + timedelta(minutes=1)).isoformat(),
                          (self.NOW - timedelta(days=2)).isoformat(), '2026-10-02T11:00:00'):
            with self.subTest(timestamp=timestamp):
                self.write_receipt(self.receipt('1', completed=timestamp))
                with patch.object(wrapper, '_now', return_value=self.NOW):
                    with self.assertRaises(wrapper.Hold):
                        wrapper.read_receipt(self.root, fresh=True)


if __name__ == '__main__':
    unittest.main()
