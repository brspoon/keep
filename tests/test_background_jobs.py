import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import Mock, patch

import background_jobs
from connection_settings import ConnectionSettings
import seerr


class BackgroundJobTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / 'jobs.sqlite3'
        self.heartbeat = Path(self.directory.name) / 'worker.heartbeat'
        self.store = background_jobs.Store(self.path)
        self.environment = patch.dict(os.environ, {}, clear=True)
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.connections = ConnectionSettings(self.path)
        self.settings = {
            'PLEX_SERVER_URL': 'http://plex:32400', 'PLEX_MACHINE_IDENTIFIER': 'synthetic-id',
            'PLEX_ADMIN_TOKEN': 'synthetic-token', 'MAINTAINERR_URL': 'http://maintainerr:6246',
            'RADARR_URL': 'http://radarr:7878', 'RADARR_API_KEY': 'synthetic-key',
            'SEERR_URL': 'http://seerr:5055', 'SEERR_API_KEY': 'synthetic-seerr-key',
            'EMAIL_ENABLED': 'false',
        }

    def alive(self, now=100):
        self.heartbeat.touch()
        os.utime(self.heartbeat, (now, now))

    def snapshot(self, now=100):
        return self.store.snapshot(self.settings.get, self.connections,
                                   heartbeat_path=self.heartbeat, now=now)

    def row(self, job_id, now=100):
        return next(row for row in self.snapshot(now)['jobs'] if row['id'] == job_id)

    def test_records_survive_restart_and_use_monotonic_duration(self):
        callback_result = object()
        with patch.object(background_jobs.time, 'time', side_effect=[100, 110]), \
             patch.object(background_jobs.time, 'monotonic', side_effect=[50, 52]):
            self.assertIs(self.store.run('keep-expiry', lambda: callback_result), callback_result)
        restarted = background_jobs.Store(self.path)
        record = restarted.records()['keep-expiry']
        self.assertEqual(record['started'], 100)
        self.assertEqual(record['finished'], 110)
        self.assertEqual(record['duration'], 2)
        self.assertEqual(record['last_success'], 110)
        self.assertEqual(record['next_run'], 140)
        self.assertEqual(record['status'], 'success')

    def test_exception_is_reraised_without_persisting_its_message(self):
        error = RuntimeError('https://private.example.invalid?token=DO-NOT-RECORD')
        with patch.object(background_jobs.time, 'time', side_effect=[100, 110]), \
             patch.object(background_jobs.time, 'monotonic', side_effect=[50, 52]):
            with self.assertRaises(RuntimeError) as raised:
                self.store.run('reminder-scan', Mock(side_effect=error), interval=900)
        self.assertIs(raised.exception, error)
        record = self.store.records()['reminder-scan']
        self.assertEqual(record['status'], 'failed')
        self.assertEqual(record['next_run'], 140)
        self.assertNotIn('private.example', str(record))
        self.assertNotIn('DO-NOT-RECORD', str(record))
        self.assertEqual(record['result'], 'Failed; will retry')

    def test_partial_failure_and_successful_counts_are_explicit(self):
        with patch.object(background_jobs.time, 'time', return_value=100):
            self.store.run('keep-expiry', lambda: {'failed': 1},
                           result_fn=lambda value: ('failed', 'Some Keeps will be retried'))
            self.store.run('plex-access-sync', lambda: 3, interval=900,
                           result_fn=lambda value: ('success', f'Updated {value} accounts'))
        records = self.store.records()
        self.assertEqual(records['keep-expiry']['status'], 'failed')
        self.assertIsNone(records['keep-expiry']['last_success'])
        self.assertEqual(records['plex-access-sync']['next_run'], 1000)
        self.assertEqual(records['plex-access-sync']['result'], 'Updated 3 accounts')

    def test_observation_and_logger_failure_cannot_block_callback(self):
        logger = Mock()
        logger.warning.side_effect = RuntimeError('logger unavailable')
        with patch.object(background_jobs.sqlite3, 'connect', side_effect=OSError('database unavailable')):
            broken = background_jobs.Store(self.path, logger)
            callback = Mock(return_value='work completed')
            self.assertEqual(broken.run('queue-cleanup', callback), 'work completed')
        callback.assert_called_once_with()
        self.assertTrue(logger.warning.called)

    def test_invalid_summary_or_classifier_failure_never_changes_callback_result(self):
        logger = Mock()
        self.store.logger = logger
        for classifier in (lambda value: ('success', 'token=DO-NOT-RECORD'),
                           Mock(side_effect=RuntimeError('DO-NOT-RECORD'))):
            value = object()
            self.assertIs(self.store.run('queue-cleanup', lambda: value, result_fn=classifier), value)
            record = self.store.records()['queue-cleanup']
            self.assertEqual(record['status'], 'waiting')
            self.assertEqual(record['result'], 'Result unavailable')
            self.assertIsNone(record['last_success'])
            self.assertNotIn('DO-NOT-RECORD', str(record))
        self.assertEqual(logger.warning.call_count, 2)

    def test_initial_database_lock_recovers_without_restarting_the_store(self):
        path = Path(self.directory.name) / 'initial-lock.sqlite3'
        with patch.object(background_jobs.sqlite3, 'connect', side_effect=sqlite3.OperationalError('locked')):
            locked = background_jobs.Store(path)
            callback = Mock(return_value='real work')
            self.assertEqual(locked.run('queue-cleanup', callback), 'real work')
        self.assertEqual(locked.run('queue-cleanup', lambda: 'next pass'), 'next pass')
        self.assertEqual(locked.records()['queue-cleanup']['status'], 'success')

    def test_fresh_heartbeat_does_not_hide_jobs_skipped_after_an_upstream_failure(self):
        with patch.object(background_jobs.time, 'time', return_value=1):
            self.store.run('queue-cleanup', lambda: 0)
            self.store.run('reminder-scan', lambda: 0, interval=900)
            self.store.run('email-digest', lambda: 'review',
                           result_fn=lambda value: ('review', 'Delivery needs review'))
        self.settings['EMAIL_ENABLED'] = 'true'
        self.alive(now=400)
        self.assertEqual(self.row('queue-cleanup', now=400)['label'], 'Overdue')
        self.assertEqual(self.row('reminder-scan', now=400)['label'], 'Completed')
        self.assertEqual(self.row('email-digest', now=400)['label'], 'Needs review')

    def test_fixed_catalogue_bounds_storage_and_rejects_unknown_jobs(self):
        callback = Mock()
        with self.assertRaises(ValueError):
            self.store.run('user-controlled-job', callback)
        callback.assert_not_called()
        for job_id in background_jobs.JOB_IDS:
            for attempt in range(3):
                self.store.run(job_id, lambda: None)
        self.assertEqual(len(self.store.records()), len(background_jobs.JOB_IDS))

    def test_old_completion_cannot_overwrite_a_newer_run(self):
        self.store._start('keep-expiry', 'first', 100)
        self.store._start('keep-expiry', 'second', 105)
        self.store._finish('keep-expiry', 'first', 106, 6, 'failed', 'Connection unavailable', 30)
        self.assertEqual(self.store.records()['keep-expiry']['run_token'], 'second')
        self.assertEqual(self.store.records()['keep-expiry']['status'], 'running')
        self.store._finish('keep-expiry', 'second', 110, 5, 'success', 'Completed', 30)
        self.assertEqual(self.store.records()['keep-expiry']['status'], 'success')

    def test_new_install_has_no_invented_last_run_or_seerr_schedule(self):
        self.alive()
        snapshot = self.snapshot()
        self.assertEqual(len(snapshot['jobs']), 16)
        self.assertTrue(snapshot['worker']['available'])
        self.assertEqual(self.row('keep-expiry')['label'], 'Not run yet')
        self.assertIsNone(self.row('keep-expiry')['last_run'])
        self.assertIsNone(self.row('seerr-history')['next_run'])
        self.assertEqual(self.row('email-digest')['label'], 'Disabled')
        self.assertEqual(self.row('probe-sonarr')['label'], 'Setup needed')

    def test_stopped_worker_marks_unfinished_run_interrupted(self):
        self.store._start('keep-expiry', 'interrupted', 1)
        self.alive(now=1)
        row = self.row('keep-expiry', now=400)
        self.assertEqual(row['label'], 'Interrupted')
        self.assertEqual(row['status'], 'stale')
        self.assertIsNone(row['last_run'])
        self.assertIsNone(row['duration'])
        self.assertFalse(self.snapshot(now=400)['worker']['available'])

    def test_new_worker_marks_old_running_jobs_interrupted_even_with_fresh_heartbeat(self):
        self.store._start('keep-expiry', 'old-worker', 1)
        self.store.run('queue-cleanup', lambda: None)
        new_worker = background_jobs.Store(self.path)
        new_worker.interrupt_running()
        self.alive()
        row = self.row('keep-expiry')
        self.assertEqual(row['label'], 'Interrupted')
        self.assertIsNone(row['last_run'])
        self.assertIsNone(row['duration'])
        self.assertEqual(new_worker.records()['queue-cleanup']['status'], 'success')

    def test_current_probes_use_fingerprint_and_exact_due_time(self):
        self.alive()
        fingerprint = self.connections.connection_fingerprint('radarr', self.settings.get)
        self.connections.record_automatic_check('radarr', fingerprint, True, now=90)
        row = self.row('probe-radarr')
        self.assertEqual(row['label'], 'Healthy')
        self.assertEqual(row['last_run'], background_jobs.timestamp(90))
        self.assertEqual(row['next_run'], background_jobs.timestamp(3690))
        self.settings['RADARR_API_KEY'] = 'changed'
        row = self.row('probe-radarr')
        self.assertEqual(row['label'], 'Not run yet')
        self.assertIsNone(row['last_run'])
        self.assertIsNone(row['next_run'])

    def test_seerr_uses_only_current_scoped_schedule_and_hides_private_payload(self):
        self.alive()
        seerr.Store(self.path)
        scope = seerr.namespace(self.settings.get)
        with sqlite3.connect(self.path) as db:
            db.execute('INSERT INTO seerr_refresh VALUES (?,?,?)', (scope, 300, 1))
            db.execute('INSERT INTO seerr_availability_queue VALUES (?,?,?,?)', (scope, 1, 200, 1))
            db.execute('INSERT INTO seerr_cache VALUES (?,?,?,?)', (scope, '{"private":"DO-NOT-RECORD"}', 80, 1))
        snapshot = self.snapshot()
        self.assertEqual(self.row('seerr-history')['next_run'], background_jobs.timestamp(300))
        self.assertEqual(self.row('seerr-history')['label'], 'Retrying')
        self.assertEqual(self.row('seerr-history')['last_success'], background_jobs.timestamp(80))
        self.assertEqual(self.row('seerr-availability')['next_run'], background_jobs.timestamp(200))
        self.assertNotIn('DO-NOT-RECORD', str(snapshot))
        self.assertNotIn('synthetic-seerr-key', str(snapshot))
        self.settings['SEERR_API_KEY'] = 'replacement'
        self.assertIsNone(self.row('seerr-history')['next_run'])
        self.assertIsNone(self.row('seerr-history')['last_success'])
        self.assertIsNone(self.row('seerr-availability')['next_run'])

    def test_replacing_seerr_settings_suppresses_previous_scope_observations(self):
        self.alive()
        seerr.Store(self.path)
        scope = seerr.namespace(self.settings.get)
        with patch.object(background_jobs.time, 'time', return_value=80):
            self.store.run('seerr-history', lambda: None, interval=900, scope=scope)
            self.store.run('seerr-availability', lambda: None, scope=scope)
        with sqlite3.connect(self.path) as db:
            db.execute('INSERT INTO seerr_cache VALUES (?,?,?,0)', (scope, '{}', 80))
            db.execute('INSERT INTO seerr_refresh VALUES (?,?,0)', (scope, 980))
        self.assertEqual(self.row('seerr-history')['label'], 'Completed')
        self.settings['SEERR_API_KEY'] = 'replacement'
        for job_id in ('seerr-history', 'seerr-availability'):
            row = self.row(job_id)
            self.assertEqual(row['label'], 'Not run yet')
            self.assertIsNone(row['last_run'])
            self.assertIsNone(row['last_success'])
            self.assertIsNone(row['next_run'])
            self.assertIsNone(row['duration'])

    def test_unknown_legacy_seerr_scope_does_not_claim_a_current_connection_result(self):
        self.alive()
        with patch.object(background_jobs.time, 'time', return_value=80):
            self.store.run('seerr-history', lambda: None, interval=900)
        row = self.row('seerr-history')
        self.assertEqual(row['label'], 'Not run yet')
        self.assertIsNone(row['last_success'])
        self.assertIsNone(row['next_run'])

    def test_newer_manual_seerr_success_clears_previous_automatic_failure(self):
        self.alive()
        seerr.Store(self.path)
        scope = seerr.namespace(self.settings.get)
        with patch.object(background_jobs.time, 'time', return_value=90):
            self.store.run('seerr-history', lambda: None, interval=900, scope=scope,
                           result_fn=lambda value: ('failed', 'Connection unavailable'))
        with sqlite3.connect(self.path) as db:
            db.execute('INSERT INTO seerr_cache VALUES (?,?,?,0)', (scope, '{}', 95))
            db.execute('INSERT INTO seerr_refresh VALUES (?,?,0)', (scope, 995))
        row = self.row('seerr-history')
        self.assertEqual(row['label'], 'Completed')
        self.assertEqual(row['status'], 'success')
        self.assertEqual(row['result'], 'Completed')
        self.assertEqual(row['last_run'], background_jobs.timestamp(95))
        self.assertEqual(row['last_success'], background_jobs.timestamp(95))
        self.assertEqual(row['next_run'], background_jobs.timestamp(995))
        self.assertIsNone(row['duration'])
        self.heartbeat.unlink()
        self.assertEqual(self.row('seerr-history')['label'], 'Worker unavailable')

    def test_seerr_scope_change_clears_old_success_when_the_new_job_fails(self):
        first = seerr.namespace(self.settings.get)
        with patch.object(background_jobs.time, 'time', return_value=80):
            self.store.run('seerr-history', lambda: None, scope=first)
        self.settings['SEERR_API_KEY'] = 'replacement'
        second = seerr.namespace(self.settings.get)
        with patch.object(background_jobs.time, 'time', return_value=90):
            self.store.run('seerr-history', lambda: None, scope=second,
                           result_fn=lambda value: ('failed', 'Connection unavailable'))
        record = self.store.records()['seerr-history']
        self.assertEqual(record['scope'], second)
        self.assertIsNone(record['last_success'])

    def test_scope_migration_is_additive_and_preserves_legacy_regular_jobs(self):
        path = Path(self.directory.name) / 'legacy-jobs.sqlite3'
        with sqlite3.connect(path) as db:
            db.execute('''CREATE TABLE background_jobs (
                job_id TEXT PRIMARY KEY,run_token TEXT NOT NULL,started REAL NOT NULL,
                finished REAL,last_success REAL,duration REAL,status TEXT NOT NULL,
                result TEXT NOT NULL,next_run REAL)''')
            db.execute('INSERT INTO background_jobs VALUES (?,?,?,?,?,?,?,?,?)',
                       ('queue-cleanup', 'old-run', 70, 80, 80, 10, 'success', 'Completed', 110))
        migrated = background_jobs.Store(path)
        record = migrated.records()['queue-cleanup']
        self.assertIsNone(record['scope'])
        self.assertEqual(record['finished'], 80)
        self.assertEqual(record['duration'], 10)
        self.assertEqual(record['result'], 'Completed')
        migrated.run('queue-cleanup', lambda: None)
        self.assertEqual(len(migrated.records()), 1)

    def test_failed_probes_do_not_hide_a_missing_worker(self):
        fingerprint = self.connections.connection_fingerprint('radarr', self.settings.get)
        self.connections.record_automatic_check('radarr', fingerprint, False, now=90)
        self.assertEqual(self.row('probe-radarr')['label'], 'Worker unavailable')


if __name__ == '__main__':
    unittest.main()
