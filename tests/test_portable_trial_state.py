"""Exact recovery snapshots and mutable observations from the real worker."""
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import textwrap
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

import background_jobs
import portable_backup
import portable_trial as fixture

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import portable_container_trial as runner


def fingerprint(path):
    output = io.StringIO()
    with redirect_stdout(output):
        fixture.fingerprints(SimpleNamespace(KEEP_DB_PATH=path))
    return json.loads(output.getvalue())


class PortableTrialStateTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.database = self.root / 'keep.sqlite3'
        self.store = background_jobs.Store(self.database)
        with sqlite3.connect(self.database) as db:
            db.execute('CREATE TABLE portable_trial_marker (fixture_id TEXT PRIMARY KEY)')
            db.execute('INSERT INTO portable_trial_marker VALUES (?)', (fixture.FIXTURE_ID,))
            db.execute('''CREATE TABLE keep_attribution
                (collection_id TEXT, media_id TEXT, user_id TEXT, username TEXT, kept_at TEXT)''')
            db.execute("INSERT INTO keep_attribution VALUES ('901','991001','local-trial','Trial Local','2026-10-01 12:00:00')")
        self.store.run('keep-expiry', lambda: None,
                       result_fn=lambda _: ('success', 'Released 2 Keeps'))
        self.store.run('seerr-history', lambda: None, scope='a' * 64,
                       result_fn=lambda _: ('failed', 'Connection unavailable'))
        self.before = fingerprint(self.database)
        self.snapshot = self.root / 'snapshot.sqlite3'
        portable_backup.backup(self.database, self.snapshot)

    def test_restore_is_exact_before_worker_then_allows_new_observations(self):
        restored = self.root / 'restored.sqlite3'
        portable_backup.restore(self.snapshot, restored)
        runner.Trial.compare_fingerprints(self.before, fingerprint(restored), label='before startup')
        jobs = background_jobs.Store(restored)
        jobs.run('keep-expiry', lambda: None,
                 result_fn=lambda _: ('success', 'Released 0 Keeps'))
        jobs.run('email-digest', lambda: None,
                 result_fn=lambda _: ('disabled', 'Email is disabled'))
        after = fingerprint(restored)
        with self.assertRaisesRegex(runner.TrialError, 'background_jobs'):
            runner.Trial.compare_fingerprints(self.before, after, label='stopped recovery')
        result = runner.Trial.compare_fingerprints(self.before, after, label='after startup',
                                                   worker_started=True)
        self.assertNotIn('background_jobs', result['common_tables'])
        self.assertIn('keep_attribution', result['common_tables'])
        self.assertTrue(result['worker_observations_may_advance'])

    def test_stopped_restore_detects_every_job_observation_column(self):
        changes = {
            'job_id': 'different-job', 'run_token': 'different-run',
            'started': 1, 'finished': 2, 'last_success': 3,
            'duration': 4, 'status': 'waiting', 'result': 'No changes', 'next_run': 5,
            'scope': 'b' * 64,
        }
        for column, value in changes.items():
            with self.subTest(column=column):
                restored = self.root / (column + '.sqlite3')
                portable_backup.restore(self.snapshot, restored)
                with sqlite3.connect(restored) as db:
                    db.execute(f'UPDATE background_jobs SET {column}=? WHERE job_id=?',
                               (value, 'seerr-history'))
                with self.assertRaisesRegex(runner.TrialError, 'background_jobs'):
                    runner.Trial.compare_fingerprints(self.before, fingerprint(restored),
                                                       label='stopped recovery')

    def test_worker_updates_do_not_allow_keep_loss(self):
        with sqlite3.connect(self.database) as db:
            db.execute('DELETE FROM keep_attribution')
        with self.assertRaisesRegex(runner.TrialError, 'keep_attribution'):
            runner.Trial.compare_fingerprints(self.before, fingerprint(self.database),
                                               label='after startup', worker_started=True)

    def test_worker_updates_do_not_allow_observation_table_loss(self):
        with sqlite3.connect(self.database) as db:
            db.execute('DROP TABLE background_jobs')
        with self.assertRaisesRegex(runner.TrialError, 'removed fingerprinted tables: background_jobs'):
            runner.Trial.compare_fingerprints(self.before, fingerprint(self.database),
                                               label='after startup', worker_started=True)

    def test_trial_compares_each_stopped_snapshot_before_starting_worker(self):
        candidate = {'reference': 'keep:test', 'runtime_reference': 'sha256:' + 'a' * 64,
                     'image_id': 'sha256:' + 'a' * 64, 'version': '2.20.0',
                     'revision': 'b' * 40, 'architecture': 'amd64', 'os': 'linux'}
        instance = MagicMock(spec=runner.Trial)
        instance.project = 'keep-recovery-012345abcdef'
        instance.temp = self.root
        instance.volume_names = {name: instance.project + '-' + name for name in
                                 ('fresh-data', 'fixture-data', 'restore-data', 'rollback-data')}
        instance.report = {'cleanup': {'containers_removed': True,
                                      'volumes_removed': list(instance.volume_names.values())}}
        instance.phase.return_value = 'synthetic phase passed'
        instance.compose_run.return_value = SimpleNamespace(returncode=0)
        instance.compare_fingerprints.side_effect = runner.Trial.compare_fingerprints
        # The real worker advances observations after each startup. A full
        # comparison after starting it would fail, or hide a missing prestart check.
        snapshots = []
        for generation in ('baseline', 'baseline', 'restored', 'restored',
                           'recreated', 'baseline', 'rollback'):
            snapshots.append({'global_sha256': 'c' * 64, 'tables': {
                'portable_trial_marker': {'rows': 1, 'sha256': 'd' * 64},
                'background_jobs': {'rows': 8, 'sha256': generation},
            }})
        instance.fingerprint.side_effect = snapshots
        args = SimpleNamespace(candidate_image='keep:test', previous_image=None,
                               evidence=self.root / 'evidence.json', health_timeout=30,
                               url='https://keep-recovery.invalid')
        with patch.object(runner, '_run', return_value=SimpleNamespace(stdout='2.24.4')), \
             patch.object(runner, '_image_metadata', return_value=candidate), \
             patch.object(runner, 'Trial', return_value=instance):
            report = runner.run_trial(args)
        self.assertEqual(report['outcome'], 'passed')
        for key in ('restore_comparison', 'candidate_recreate_comparison', 'rollback_comparison'):
            self.assertIn('background_jobs', report[key]['common_tables'])
            self.assertFalse(report[key]['worker_observations_may_advance'])
        calls = instance.mock_calls
        for comparison, start_label in (
            ('restored candidate before startup', 'restored candidate'),
            ('candidate recreation before startup', 'candidate recreation'),
            ('pre-upgrade recovery before startup', 'rollback image'),
        ):
            compared = next(i for i, call in enumerate(calls)
                            if call[0] == 'compare_fingerprints' and call.kwargs['label'] == comparison)
            started = next(i for i, call in enumerate(calls)
                           if call[0] == 'start' and call.kwargs['label'] == start_label)
            self.assertLess(compared, started)

    def test_full_fixture_verifies_after_actual_worker_observation_pass(self):
        # A separate interpreter keeps the full application's synthetic fixture
        # isolated from the database and environment shared by the main suite.
        code = textwrap.dedent('''
            from contextlib import redirect_stdout
            import io
            import json
            from pathlib import Path
            import sys
            import tempfile
            from unittest.mock import patch
            sys.path[:0] = ['tests', 'scripts']
            import portable_trial as fixture
            from portable_container_trial import Trial
            with tempfile.TemporaryDirectory() as tmp:
                fixture.configure_synthetic_environment(Path(tmp) / 'keep.sqlite3')
                app = fixture.app_module()
                blocked = app.requests.ConnectionError('Synthetic offline recovery trial')
                with patch.object(app.requests, 'get', side_effect=blocked), \\
                     patch.object(app.requests, 'post', side_effect=blocked), \\
                     patch.object(app.requests, 'delete', side_effect=blocked), \\
                     redirect_stdout(io.StringIO()):
                    fixture.seed(app)
                    fixture.verify(app)
                    before = io.StringIO()
                    with redirect_stdout(before):
                        fixture.fingerprints(app)
                    try:
                        app.background_maintenance_once({'plex_sync': 0, 'reminder_scan': None})
                    except app.requests.ConnectionError:
                        # The actual worker catches this unavailable-integration
                        # failure and retries; its observation is still persisted.
                        pass
                    try:
                        fixture.verify(app)
                    except fixture.TrialError as error:
                        assert str(error) == 'trial background job observations were not restored'
                    else:
                        raise AssertionError('Stopped verification accepted changed job observations')
                    fixture.verify(app, worker_started=True)
                    after = io.StringIO()
                    with redirect_stdout(after):
                        fixture.fingerprints(app)
                    Trial.compare_fingerprints(json.loads(before.getvalue()),
                        json.loads(after.getvalue()), label='actual offline worker',
                        worker_started=True)
            print('Full recovery fixture and observed worker pass verified.')
        ''')
        result = subprocess.run([sys.executable, '-B', '-c', code], cwd=ROOT,
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Full recovery fixture and observed worker pass verified.', result.stdout)


if __name__ == '__main__':
    unittest.main()
