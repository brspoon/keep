import fcntl
from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

import background_jobs
import connection_monitor
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
        self.assertEqual(self.row('seerr-history')['label'], 'Unavailable')

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
        self.assertEqual(self.row('probe-radarr')['label'], 'Unavailable')

    def test_manual_requests_are_bounded_coalesced_and_survive_restart(self):
        for job_id in background_jobs.JOB_IDS:
            self.assertTrue(self.store.request_run(job_id))
            self.assertFalse(self.store.request_run(job_id))
        restarted = background_jobs.Store(self.path)
        self.assertEqual(set(restarted.pending()), background_jobs.JOB_IDS)
        with self.assertRaises(ValueError):
            restarted.request_run('arbitrary-command')
        restarted.run('queue-cleanup', lambda: 0)
        self.assertNotIn('queue-cleanup', restarted.pending())

    def test_request_during_execution_remains_after_the_old_completion(self):
        self.store.request_run('queue-cleanup')
        first = self.store.pending()['queue-cleanup']
        def callback():
            self.assertTrue(self.store.request_run('queue-cleanup'))
            self.assertFalse(self.store.request_run('queue-cleanup'))
        self.store.run('queue-cleanup', callback)
        second = self.store.pending()['queue-cleanup']
        self.assertNotEqual(first, second)
        self.store.acknowledge('queue-cleanup', first)
        self.assertEqual(self.store.pending()['queue-cleanup'], second)
        self.store.run('queue-cleanup', lambda: None)
        self.assertNotIn('queue-cleanup', self.store.pending())

    def test_failed_manual_work_and_interrupted_claims_remain_retryable(self):
        self.store.request_run('reminder-scan')
        with self.assertRaises(RuntimeError):
            self.store.run('reminder-scan', Mock(side_effect=RuntimeError('private details')))
        self.assertIn('reminder-scan', self.store.pending())
        self.assertFalse(self.store.requested('reminder-scan', first_attempt=True))
        self.assertIsNotNone(self.store.claim('reminder-scan'))
        restarted = background_jobs.Store(self.path)
        restarted.interrupt_running()
        self.assertTrue(restarted.requested('reminder-scan', first_attempt=True))
        restarted.run('reminder-scan', lambda: 0)
        self.assertNotIn('reminder-scan', restarted.pending())

    def test_scoped_request_cannot_run_against_replacement_connection(self):
        self.alive()
        first = self.connections.connection_fingerprint('radarr', self.settings.get)
        self.store.request_run('probe-radarr', scope=first)
        self.assertTrue(self.row('probe-radarr')['queued'])
        self.settings['RADARR_API_KEY'] = 'replacement'
        second = self.connections.connection_fingerprint('radarr', self.settings.get)
        self.assertFalse(self.row('probe-radarr')['queued'])
        self.assertFalse(self.store.requested('probe-radarr', first_attempt=True, scope=second))
        self.assertIsNone(self.store.claim('probe-radarr', scope=second))
        self.assertTrue(self.store.request_run('probe-radarr', scope=second))
        self.assertTrue(self.store.requested('probe-radarr', first_attempt=True, scope=second))

    def test_old_worker_snapshot_cannot_erase_replacement_connection_request(self):
        first = self.connections.connection_fingerprint('radarr', self.settings.get)
        self.settings['RADARR_API_KEY'] = 'replacement'
        second = self.connections.connection_fingerprint('radarr', self.settings.get)
        self.store.request_run('probe-radarr', scope=second)
        token = self.store.pending()['probe-radarr']
        self.assertFalse(self.store.requested('probe-radarr', first_attempt=True, scope=first))
        self.assertIsNone(self.store.claim('probe-radarr', scope=first))
        self.assertEqual(self.store.pending()['probe-radarr'], token)
        self.assertEqual(self.store.claim('probe-radarr', scope=second), token)
        self.store.acknowledge('probe-radarr', token)
        self.assertNotIn('probe-radarr', self.store.pending())

    def test_frequency_edit_changes_due_time_survives_restart_and_preserves_retry(self):
        with patch.object(background_jobs.time, 'time', return_value=100):
            self.store.run('plex-access-sync', lambda: 0, interval=900)
        self.store.set_interval('plex-access-sync', 300)
        restarted = background_jobs.Store(self.path)
        self.assertEqual(restarted.interval('plex-access-sync', 900), 300)
        self.assertEqual(restarted.records()['plex-access-sync']['next_run'], 400)
        with patch.object(background_jobs.time, 'time', return_value=399):
            self.assertFalse(restarted.due('plex-access-sync'))
        with patch.object(background_jobs.time, 'time', return_value=400):
            self.assertTrue(restarted.due('plex-access-sync', False))
            restarted.run('plex-access-sync', lambda: None, interval=300,
                          result_fn=lambda value: ('failed', 'Connection unavailable'))
        restarted.set_interval('plex-access-sync', 3600)
        self.assertEqual(restarted.records()['plex-access-sync']['next_run'], 430)
        for job_id, interval in (('email-digest', 300), ('plex-access-sync', 1),
                                 ('plex-access-sync', True)):
            with self.assertRaises(ValueError):
                restarted.set_interval(job_id, interval)

    def test_frequency_edit_during_work_is_used_by_completion(self):
        with patch.object(background_jobs.time, 'time', return_value=100):
            self.store.run('reminder-scan', lambda: self.store.set_interval('reminder-scan', 3600),
                           interval=900)
        self.assertEqual(self.store.records()['reminder-scan']['next_run'], 3700)

    def test_manual_probe_uses_same_callback_and_preserves_retry_and_fingerprint(self):
        logger = Mock()
        # Limit this scenario to Radarr so unrelated configured services do no I/O.
        settings = {'RADARR_URL': 'http://radarr:7878', 'RADARR_API_KEY': 'key'}
        getter = settings.get
        fingerprint = self.connections.connection_fingerprint('radarr', getter)
        self.connections.record_automatic_check('radarr', fingerprint, True, now=100)
        self.store.set_interval('probe-radarr', 900)
        self.store.request_run('probe-radarr', scope=fingerprint)
        with patch.object(background_jobs.time, 'time', return_value=200), \
             patch.object(connection_monitor, 'probe', side_effect=ValueError('private response')) as check:
            self.assertFalse(connection_monitor.run_due(self.connections, getter, Mock(), logger, jobs=self.store))
            check.assert_called_once()
        self.assertIn('probe-radarr', self.store.pending())
        with patch.object(background_jobs.time, 'time', return_value=499), \
             patch.object(connection_monitor, 'probe') as check:
            connection_monitor.run_due(self.connections, getter, Mock(), logger, jobs=self.store)
            check.assert_not_called()
        with patch.object(background_jobs.time, 'time', return_value=500), \
             patch.object(connection_monitor, 'probe') as check:
            self.assertTrue(connection_monitor.run_due(self.connections, getter, Mock(), logger, jobs=self.store))
            check.assert_called_once()
        self.assertNotIn('probe-radarr', self.store.pending())
        self.assertEqual(self.store.records()['probe-radarr']['next_run'], 1400)
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute("SELECT next_attempt FROM automatic_connection_checks WHERE service='radarr'").fetchone()[0], 1400)

    def test_seerr_cadence_edit_updates_native_schedule_and_completion(self):
        store = seerr.Store(self.path)
        payload = {'users': [], 'requests': []}
        with patch.object(background_jobs.time, 'time', return_value=100), \
             patch.object(seerr.Client, 'snapshot', return_value=payload):
            store.refresh(self.settings.get, automatic=True)
        self.store.set_interval('seerr-history', 3600)
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute('SELECT next_attempt FROM seerr_refresh').fetchone()[0], 3700)
        with patch.object(background_jobs.time, 'time', return_value=3699), \
             patch.object(seerr.Client, 'snapshot') as fetch:
            self.assertIsNone(seerr.Store(self.path).refresh(self.settings.get, automatic=True))
            fetch.assert_not_called()
        def fetching():
            self.store.set_interval('seerr-history', 600)
            return payload
        with patch.object(background_jobs.time, 'time', return_value=3700), \
             patch.object(seerr.Client, 'snapshot', side_effect=fetching):
            store.refresh(self.settings.get, automatic=True)
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute('SELECT next_attempt FROM seerr_refresh').fetchone()[0], 4300)

    def test_manual_availability_dispatch_preserves_deletion_during_io(self):
        store = seerr.Store(self.path)
        self.store.request_run('seerr-availability', scope=seerr.namespace(self.settings.get))
        def dispatch():
            store.queue_availability(self.settings.get)
            return True
        with patch.object(background_jobs.time, 'time', return_value=100), \
             patch.object(seerr.Client, 'sync_availability', side_effect=dispatch) as fetch:
            self.assertTrue(self.store.run('seerr-availability',
                lambda: store.process_availability(self.settings.get, force=True),
                scope=seerr.namespace(self.settings.get)))
            fetch.assert_called_once()
        self.assertNotIn('seerr-availability', self.store.pending())
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute('SELECT generation,due FROM seerr_availability_queue').fetchone(), (2, 130))

    def test_busy_seerr_lock_keeps_manual_request_ready_without_bypassing_native_retry(self):
        store = seerr.Store(self.path)
        self.store.request_run('seerr-history')
        with open(str(self.path) + '.seerr-refresh.lock', 'a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(seerr.RefreshBusy):
                self.store.run('seerr-history', lambda: store.refresh(self.settings.get))
        self.assertTrue(self.store.requested('seerr-history', first_attempt=True))
        with patch.object(background_jobs.time, 'time', return_value=100), \
             patch.object(seerr.Client, 'snapshot', side_effect=ValueError('private response')):
            with self.assertRaises(ValueError):
                self.store.run('seerr-history', lambda: store.refresh(self.settings.get))
        self.assertFalse(self.store.requested('seerr-history', first_attempt=True))
        with patch.object(background_jobs.time, 'time', return_value=159), \
             patch.object(seerr.Client, 'snapshot') as fetch:
            self.assertIsNone(store.refresh(self.settings.get, automatic=True))
            fetch.assert_not_called()

    def test_completion_frequency_reads_cannot_race_a_saved_edit(self):
        """Every final cadence read shares the writer lock with its completion."""
        self.store.set_interval('reminder-scan', 3600)
        self.store.set_interval('probe-radarr', 3600)
        self.store.set_interval('seerr-history', 3600)
        seerr_store = seerr.Store(self.path)
        self.store._start('reminder-scan', 'run', 100)
        original_connect = sqlite3.connect
        observed = []
        class Connection:
            def __init__(self, connection):
                self.connection = connection
            def __enter__(self):
                self.connection.__enter__()
                return self
            def __exit__(self, *args):
                return self.connection.__exit__(*args)
            def close(self):
                self.connection.close()
            def execute(proxy, query, *args):
                if query.startswith('SELECT interval_seconds'):
                    locked = proxy.connection.in_transaction
                    observed.append(locked)
                    if locked:
                        # A save cannot commit between this read and its write.
                        with original_connect(self.path, timeout=0) as writer:
                            with self.assertRaises(sqlite3.OperationalError):
                                writer.execute('BEGIN IMMEDIATE')
                return proxy.connection.execute(query, *args)
        with patch.object(background_jobs.sqlite3, 'connect',
                          side_effect=lambda *args, **kwargs: Connection(original_connect(*args, **kwargs))), \
             patch.object(seerr.Client, 'snapshot', return_value={'users': [], 'requests': []}):
            self.store._finish('reminder-scan', 'run', 200, 100, 'success', 'Completed', 900)
            self.connections.record_automatic_check('radarr', 'fingerprint', True, now=200)
            seerr_store.refresh(self.settings.get)
        # Seerr's preliminary due check reads freely; all final reads hold locks.
        self.assertEqual(observed, [True, True, False, True])

    def test_locked_completion_recovers_before_due_without_replaying_manual_work(self):
        self.store.request_run('plex-access-sync')
        writer = sqlite3.connect(self.path)
        self.addCleanup(writer.close)
        def completed():
            writer.execute('BEGIN IMMEDIATE')
            return 2
        callback = Mock(side_effect=completed)
        with patch.object(background_jobs.time, 'time', return_value=100):
            self.assertEqual(self.store.run('plex-access-sync', callback, interval=900), 2)
            # Even while the durable completion is blocked, completed work does
            # not become another forced manual invocation.
            self.assertFalse(self.store.requested('plex-access-sync'))
            self.assertFalse(self.store.due('plex-access-sync', True))
            writer.rollback()
            self.store.set_interval('plex-access-sync', 3600)
            self.assertFalse(self.store.due('plex-access-sync', True))
        callback.assert_called_once()
        self.assertNotIn('plex-access-sync', self.store.pending())
        record = self.store.records()['plex-access-sync']
        self.assertEqual(record['status'], 'success')
        self.assertEqual(record['finished'], 100)
        self.assertEqual(record['next_run'], 3700)
        self.assertFalse(self.store._retry_operations)

    def test_locked_failed_release_recovers_and_retains_retry_without_restart(self):
        self.store.request_run('reminder-scan')
        token = self.store.pending()['reminder-scan']
        writer = sqlite3.connect(self.path)
        self.addCleanup(writer.close)
        def failing():
            writer.execute('BEGIN IMMEDIATE')
            raise RuntimeError('synthetic callback failure')
        with patch.object(background_jobs.time, 'time', return_value=100):
            with self.assertRaises(RuntimeError):
                self.store.run('reminder-scan', failing, interval=900)
            writer.rollback()
            self.assertFalse(self.store.requested('reminder-scan', first_attempt=True))
        self.assertEqual(self.store.pending()['reminder-scan'], token)
        self.assertEqual(self.store.records()['reminder-scan']['next_run'], 130)
        self.assertEqual(self.store.claim('reminder-scan'), token)
        self.store._release('reminder-scan', token)
        self.store.run('reminder-scan', lambda: 0, interval=900)
        self.assertNotIn('reminder-scan', self.store.pending())

    def test_locked_startup_reset_is_retried_before_manual_claim(self):
        self.store.request_run('queue-cleanup')
        token = self.store.claim('queue-cleanup')
        self.store._start('queue-cleanup', 'old-worker', 1)
        restarted = background_jobs.Store(self.path)
        writer = sqlite3.connect(self.path)
        self.addCleanup(writer.close)
        writer.execute('BEGIN IMMEDIATE')
        restarted.interrupt_running()
        writer.rollback()
        self.assertTrue(restarted.requested('queue-cleanup', first_attempt=True))
        self.assertEqual(restarted.records()['queue-cleanup']['status'], 'interrupted')
        self.assertFalse(restarted._startup_recovery)
        self.assertEqual(restarted.claim('queue-cleanup'), token)
        restarted.acknowledge('queue-cleanup', token)
        self.assertNotIn('queue-cleanup', restarted.pending())

    def test_failed_claim_settles_only_captured_request_and_keeps_replacement(self):
        first = self.connections.connection_fingerprint('radarr', self.settings.get)
        self.store.request_run('probe-radarr', scope=first)
        writer = sqlite3.connect(self.path)
        self.addCleanup(writer.close)
        writer.execute('BEGIN IMMEDIATE')
        replacement = 'b' * 64
        def callback():
            writer.rollback()
            external = background_jobs.Store(self.path)
            external.request_run('probe-radarr', scope=replacement)
            return True
        self.store.run('probe-radarr', callback, interval=3600, scope=first)
        self.assertTrue(self.store.requested('probe-radarr', first_attempt=True, scope=replacement))
        self.assertFalse(self.store.requested('probe-radarr', scope=first))
        self.store.run('probe-radarr', lambda: True, interval=3600, scope=replacement)
        self.assertNotIn('probe-radarr', self.store.pending())

    def test_failed_fresh_claim_does_not_leave_completed_request_as_first_attempt(self):
        self.store.request_run('seerr-history')
        writer = sqlite3.connect(self.path)
        self.addCleanup(writer.close)
        writer.execute('BEGIN IMMEDIATE')
        callback = Mock(side_effect=lambda: writer.rollback())
        self.store.run('seerr-history', callback, interval=3600)
        self.assertFalse(self.store.requested('seerr-history', first_attempt=True))
        callback.assert_called_once()
        self.assertFalse(self.store.pending())
        self.assertEqual(self.store.records()['seerr-history']['status'], 'success')

    def test_exclusive_lock_uses_only_request_token_seen_before_callback(self):
        scope = 'a' * 64
        self.store.request_run('probe-radarr', scope=scope)
        self.assertTrue(self.store.requested('probe-radarr', first_attempt=True, scope=scope))
        writer = sqlite3.connect(self.path)
        self.addCleanup(writer.close)
        writer.execute('BEGIN EXCLUSIVE')
        callback = Mock(side_effect=lambda: writer.rollback())
        self.store.run('probe-radarr', callback, interval=3600, scope=scope)
        callback.assert_called_once()
        self.assertFalse(self.store.requested('probe-radarr', first_attempt=True, scope=scope))
        self.assertFalse(self.store.pending())

    def test_cached_request_does_not_cross_scope_when_claim_read_is_locked(self):
        first, second = 'a' * 64, 'b' * 64
        self.store.request_run('probe-radarr', scope=first)
        self.assertTrue(self.store.requested('probe-radarr', first_attempt=True, scope=first))
        external = background_jobs.Store(self.path)
        external.request_run('probe-radarr', scope=second)
        writer = sqlite3.connect(self.path)
        self.addCleanup(writer.close)
        writer.execute('BEGIN EXCLUSIVE')
        self.store.run('probe-radarr', lambda: writer.rollback(), interval=3600, scope=second)
        self.assertTrue(self.store.requested('probe-radarr', first_attempt=True, scope=second))

    def test_busy_availability_release_retry_keeps_unstarted_manual_work_ready(self):
        self.store.request_run('seerr-availability')
        writer = sqlite3.connect(self.path)
        self.addCleanup(writer.close)
        def busy():
            writer.execute('BEGIN IMMEDIATE')
            return None
        self.store.run('seerr-availability', busy,
                       result_fn=lambda result: ('failed', 'Connection unavailable'))
        self.store.retry_unstarted('seerr-availability')
        writer.rollback()
        self.assertTrue(self.store.requested('seerr-availability', first_attempt=True))

    def test_shared_store_recovery_does_not_hold_callback_io_or_reset_active_jobs(self):
        jobs = ('plex-access-sync', 'reminder-scan')
        for job_id in jobs:
            self.store.request_run(job_id)
        entered = threading.Barrier(3)
        finish = threading.Event()
        def callback():
            entered.wait(timeout=5)
            self.assertTrue(finish.wait(timeout=5))
            return 0
        writer = sqlite3.connect(self.path)
        self.addCleanup(writer.close)
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(self.store.run, job_id, callback, interval=900) for job_id in jobs]
            entered.wait(timeout=5)
            # Recovery from another thread cannot interrupt jobs doing I/O.
            self.store.interrupt_running()
            for job_id in jobs:
                self.assertEqual(self.store.records()[job_id]['status'], 'running')
            writer.execute('BEGIN IMMEDIATE')
            finish.set()
            for future in futures:
                self.assertEqual(future.result(timeout=10), 0)
        writer.rollback()
        self.assertFalse(self.store.pending())
        for job_id in jobs:
            self.assertEqual(self.store.records()[job_id]['status'], 'success')
        self.assertFalse(self.store._startup_recovery)
        self.assertFalse(self.store._retry_operations)

    def test_queued_failure_retains_attempt_outcome_for_announcements(self):
        self.alive()
        self.store.request_run('plex-access-sync')
        with patch.object(background_jobs.time, 'time', return_value=90):
            self.store.run('plex-access-sync', lambda: None,
                           result_fn=lambda result: ('failed', 'Connection unavailable'))
        row = self.row('plex-access-sync')
        self.assertEqual(row['status'], 'queued')
        self.assertEqual(row['last_attempt_status'], 'failed')
        self.assertEqual(row['last_run'], background_jobs.timestamp(90))
        self.store._start('plex-access-sync', 'next-run', 100)
        self.assertIsNone(self.row('plex-access-sync')['last_attempt_status'])

    def test_newer_native_success_replaces_old_attempt_metadata(self):
        self.alive()
        scope = seerr.namespace(self.settings.get)
        seerr.Store(self.path)
        with patch.object(background_jobs.time, 'time', return_value=90):
            self.store.run('seerr-history', lambda: None, scope=scope,
                           result_fn=lambda result: ('failed', 'Connection unavailable'))
        with sqlite3.connect(self.path) as db:
            db.execute('INSERT INTO seerr_cache VALUES (?,?,?,0)', (scope, '{}', 95))
            db.execute('INSERT INTO seerr_refresh VALUES (?,?,0)', (scope, 995))
        row = self.row('seerr-history')
        self.assertEqual(row['last_run'], background_jobs.timestamp(95))
        self.assertEqual(row['last_attempt_status'], 'success')
        fingerprint = self.connections.connection_fingerprint('radarr', self.settings.get)
        self.connections.record_automatic_check('radarr', fingerprint, True, now=95)
        self.assertEqual(self.row('probe-radarr')['last_attempt_status'], 'success')

    def test_probe_native_write_failure_retries_manual_before_previous_schedule(self):
        settings = {'RADARR_URL': 'http://radarr:7878', 'RADARR_API_KEY': 'key'}
        fingerprint = self.connections.connection_fingerprint('radarr', settings.get)
        self.connections.record_automatic_check('radarr', fingerprint, True, now=100)
        self.store.request_run('probe-radarr', scope=fingerprint)
        self.alive(now=200)
        with patch.object(background_jobs.time, 'time', return_value=200), \
             patch.object(connection_monitor, 'probe') as probe, \
             patch.object(self.connections, 'record_automatic_check',
                          side_effect=sqlite3.OperationalError('synthetic canonical write failure')):
            self.assertFalse(connection_monitor.run_due(self.connections, settings.get, Mock(), Mock(), jobs=self.store))
            probe.assert_called_once()
        self.assertTrue(self.store.requested('probe-radarr', first_attempt=True, scope=fingerprint))
        row = next(row for row in self.store.snapshot(settings.get, self.connections,
            heartbeat_path=self.heartbeat, now=200)['jobs'] if row['id'] == 'probe-radarr')
        self.assertEqual(row['status'], 'queued')
        self.assertEqual(row['last_attempt_status'], 'failed')
        self.assertEqual(row['last_run'], background_jobs.timestamp(200))
        self.assertEqual(row['next_run'], background_jobs.timestamp(230))
        with patch.object(background_jobs.time, 'time', return_value=240), \
             patch.object(connection_monitor, 'probe') as probe:
            self.assertTrue(connection_monitor.run_due(self.connections, settings.get, Mock(), Mock(), jobs=self.store))
            probe.assert_called_once()
        self.assertNotIn('probe-radarr', self.store.pending())

    def test_aggregate_retries_unrecorded_probe_without_repeating_initial_force(self):
        settings = {'RADARR_URL': 'http://radarr:7878', 'RADARR_API_KEY': 'key'}
        fingerprint = self.connections.connection_fingerprint('radarr', settings.get)
        self.connections.record_automatic_check('radarr', fingerprint, True, now=100)
        self.store.request_run('connection-monitor')
        classifier = lambda passed: ('success', 'Completed') if passed else ('failed', 'Connection unavailable')
        with patch.object(background_jobs.time, 'time', return_value=200), \
             patch.object(connection_monitor, 'probe'), \
             patch.object(self.connections, 'record_automatic_check',
                          side_effect=sqlite3.OperationalError('synthetic canonical write failure')):
            self.assertFalse(self.store.run('connection-monitor', lambda: connection_monitor.run_due(
                self.connections, settings.get, Mock(), Mock(), jobs=self.store, force=True),
                result_fn=classifier))
        self.assertFalse(self.store.requested('connection-monitor', first_attempt=True))
        with patch.object(background_jobs.time, 'time', return_value=240), \
             patch.object(connection_monitor, 'probe') as probe:
            self.store.run('connection-monitor', lambda: connection_monitor.run_due(
                self.connections, settings.get, Mock(), Mock(), jobs=self.store), result_fn=classifier)
            probe.assert_called_once()
        self.assertNotIn('connection-monitor', self.store.pending())

    def test_mixed_aggregate_retry_preserves_recorded_failure_backoff(self):
        settings = {'RADARR_URL': 'http://radarr:7878', 'RADARR_API_KEY': 'radarr-key',
                    'SONARR_URL': 'http://sonarr:8989', 'SONARR_API_KEY': 'sonarr-key'}
        for service in ('radarr', 'sonarr'):
            fingerprint = self.connections.connection_fingerprint(service, settings.get)
            self.connections.record_automatic_check(service, fingerprint, True, now=100)
        self.store.request_run('connection-monitor')
        classifier = lambda passed: ('success', 'Completed') if passed else ('failed', 'Connection unavailable')
        recorded = self.connections.record_automatic_check
        def write(service, *args, **kwargs):
            if service == 'sonarr':
                raise sqlite3.OperationalError('synthetic canonical write failure')
            return recorded(service, *args, **kwargs)
        def initial_probe(service, *args):
            if service == 'radarr':
                raise ValueError('synthetic service failure')
        with patch.object(background_jobs.time, 'time', return_value=200), \
             patch.object(connection_monitor, 'probe', side_effect=initial_probe), \
             patch.object(self.connections, 'record_automatic_check', side_effect=write):
            self.assertFalse(self.store.run('connection-monitor', lambda: connection_monitor.run_due(
                self.connections, settings.get, Mock(), Mock(), jobs=self.store, force=True),
                result_fn=classifier))
        self.assertFalse(self.store.requested('connection-monitor', first_attempt=True))
        with patch.object(background_jobs.time, 'time', return_value=240), \
             patch.object(connection_monitor, 'probe') as probe:
            self.assertFalse(self.store.run('connection-monitor', lambda: connection_monitor.run_due(
                self.connections, settings.get, Mock(), Mock(), jobs=self.store), result_fn=classifier))
            self.assertEqual([call.args[0] for call in probe.call_args_list], ['sonarr'])
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute("SELECT failures,next_attempt FROM automatic_connection_checks WHERE service='radarr'").fetchone(), (1, 500))
        self.assertIn('connection-monitor', self.store.pending())
        with patch.object(background_jobs.time, 'time', return_value=500), \
             patch.object(connection_monitor, 'probe') as probe:
            self.assertTrue(self.store.run('connection-monitor', lambda: connection_monitor.run_due(
                self.connections, settings.get, Mock(), Mock(), jobs=self.store), result_fn=classifier))
            self.assertEqual([call.args[0] for call in probe.call_args_list], ['radarr'])
        self.assertNotIn('connection-monitor', self.store.pending())

    def native_write_failure(self, prefix):
        original_connect = sqlite3.connect
        class Connection:
            def __init__(self, connection):
                self.connection = connection
            def __enter__(self):
                self.connection.__enter__()
                return self
            def __exit__(self, *args):
                return self.connection.__exit__(*args)
            def close(self):
                self.connection.close()
            def execute(self, query, *args):
                if query.startswith(prefix):
                    raise sqlite3.OperationalError('synthetic canonical write failure')
                return self.connection.execute(query, *args)
        return patch.object(background_jobs.sqlite3, 'connect',
            side_effect=lambda *args, **kwargs: Connection(original_connect(*args, **kwargs)))

    def test_availability_queue_creation_failure_rearms_without_native_work(self):
        native = seerr.Store(self.path)
        scope = seerr.namespace(self.settings.get)
        self.store.request_run('seerr-availability', scope=scope)
        with self.native_write_failure('INSERT INTO seerr_availability_queue'), \
             patch.object(seerr.Client, 'sync_availability') as dispatch:
            with self.assertRaises(background_jobs.RetryUnstarted):
                self.store.run('seerr-availability', lambda: native.process_availability(
                    self.settings.get, force=True), scope=scope)
            dispatch.assert_not_called()
        with sqlite3.connect(self.path) as db:
            self.assertIsNone(db.execute('SELECT scope FROM seerr_availability_queue').fetchone())
        self.assertTrue(self.store.requested('seerr-availability', first_attempt=True, scope=scope))
        with patch.object(seerr.Client, 'sync_availability', return_value=True) as dispatch:
            self.store.run('seerr-availability', lambda: native.process_availability(
                self.settings.get, force=True), scope=scope)
            dispatch.assert_called_once()
        self.assertNotIn('seerr-availability', self.store.pending())

    def test_history_native_write_failure_does_not_wait_for_previous_future_schedule(self):
        native = seerr.Store(self.path)
        scope = seerr.namespace(self.settings.get)
        payload = {'users': [], 'requests': []}
        with patch.object(background_jobs.time, 'time', return_value=100), \
             patch.object(seerr.Client, 'snapshot', return_value=payload):
            native.refresh(self.settings.get)
        self.store.request_run('seerr-history', scope=scope)
        with patch.object(background_jobs.time, 'time', return_value=200), \
             patch.object(seerr.Client, 'snapshot', return_value=payload), \
             self.native_write_failure('INSERT INTO seerr_cache'):
            with self.assertRaises(background_jobs.RetryUnstarted):
                self.store.run('seerr-history', lambda: native.refresh(self.settings.get), scope=scope)
        self.assertTrue(self.store.requested('seerr-history', first_attempt=True, scope=scope))
        with patch.object(background_jobs.time, 'time', return_value=240), \
             patch.object(seerr.Client, 'snapshot', return_value=payload) as fetch:
            self.store.run('seerr-history', lambda: native.refresh(self.settings.get), scope=scope)
            fetch.assert_called_once()
        self.assertNotIn('seerr-history', self.store.pending())

    def test_recovery_state_stays_bounded_while_automatic_callbacks_continue(self):
        callback = Mock()
        with patch.object(background_jobs.sqlite3, 'connect',
                          side_effect=sqlite3.OperationalError('synthetic database failure')):
            for job_id in background_jobs.JOB_IDS:
                self.store.run(job_id, callback)
        self.assertEqual(callback.call_count, len(background_jobs.JOB_IDS))
        self.assertEqual(set(self.store._retry_operations), background_jobs.JOB_IDS)
        self.assertEqual(len(self.store.records()), len(background_jobs.JOB_IDS))
        self.assertFalse(self.store._retry_operations)


if __name__ == '__main__':
    unittest.main()
