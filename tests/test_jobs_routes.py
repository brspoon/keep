"""Owner boundaries and observations around the real maintenance callbacks."""
from contextlib import closing
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch

import background_jobs
import test_keep

keep = test_keep.keep


class JobsRouteTests(TestCase):
    setUp = test_keep.KeepTests.setUp

    def test_owner_page_is_read_only_and_never_exposes_connection_credentials(self):
        with patch.object(keep, 'background_maintenance_once') as run, \
             patch.dict(keep.os.environ, RADARR_API_KEY='do-not-show-this-key'):
            response = self.client.get('/settings/jobs')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers['Cache-Control'], 'no-store')
        self.assertIn(b'Jobs', response.data)
        self.assertNotIn(b'do-not-show-this-key', response.data)
        run.assert_not_called()
        self.assertEqual(self.client.post('/settings/jobs').status_code, 405)

    def test_direct_access_requires_owner_even_for_local_managers(self):
        with closing(keep.attribution_db()) as db, db:
            db.execute("""INSERT INTO user_profiles
                (plex_id,email,display_name,auth_type,status,can_remove_any,
                 can_keep_indefinitely,can_delete_media,can_delete_any)
                VALUES ('local-jobs','jobs@example.test','Jobs manager','local','active',1,1,1,1)""")
        with self.client.session_transaction() as state:
            state['plex_user'] = {'id': 'local-jobs', 'username': 'Jobs manager',
                                  'auth_type': 'local', 'session_version': 0}
        self.assertEqual(self.client.get('/settings/jobs').status_code, 403)
        with self.client.session_transaction() as state:
            state.clear()
        self.assertEqual(self.client.get('/settings/jobs').status_code, 302)


class MaintenanceObservationTests(TestCase):
    def setUp(self):
        self.directory = TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.store = background_jobs.Store(str(Path(self.directory.name) / 'jobs.sqlite3'))
        store_patch = patch.object(keep, 'job_store', return_value=self.store)
        store_patch.start()
        self.addCleanup(store_patch.stop)
        self.state = {'plex_sync': 0, 'reminder_scan': None}
        self.callbacks = {}
        for name, result in (
            ('sync_plex_user_access', 2), ('expire_due_keeps', {'released': 1, 'missing': 0, 'failed': 0}),
            ('queue_due_reminders', 3), ('reconcile_reminder_queue', None),
            ('prune_notification_queue', 1), ('process_digest', 'sent'),
        ):
            callback_patch = patch.object(keep, name, return_value=result)
            self.callbacks[name] = callback_patch.start()
            self.addCleanup(callback_patch.stop)
        for target, name, result in (
            (keep.onboarding, 'cleanup', None), (keep.connection_settings, 'snapshot', {}),
        ):
            callback_patch = patch.object(target, name, return_value=result)
            callback_patch.start()
            self.addCleanup(callback_patch.stop)
        clock_patch = patch.object(keep.time, 'monotonic', return_value=10000)
        clock_patch.start()
        self.addCleanup(clock_patch.stop)

    def test_callbacks_and_existing_cadence_are_preserved_with_persistent_results(self):
        keep.background_maintenance_once(self.state)
        records = self.store.records()
        self.assertEqual(records['plex-access-sync']['result'], 'Updated 2 accounts')
        self.assertEqual(records['keep-expiry']['result'], 'Released 1 Keeps')
        self.assertEqual(records['reminder-scan']['result'], 'Queued 3 reminders')
        self.assertEqual(records['email-digest']['status'], 'success')
        keep.background_maintenance_once(self.state)
        self.callbacks['sync_plex_user_access'].assert_called_once_with()
        self.callbacks['queue_due_reminders'].assert_called_once_with()
        self.assertEqual(self.callbacks['expire_due_keeps'].call_count, 2)
        self.assertEqual(self.callbacks['process_digest'].call_count, 2)

    def test_failed_reminders_retry_next_pass_without_blocking_email(self):
        self.callbacks['queue_due_reminders'].side_effect = RuntimeError('private upstream response')
        keep.background_maintenance_once(self.state)
        self.assertIsNone(self.state['reminder_scan'])
        records = self.store.records()
        self.assertEqual(records['reminder-scan']['status'], 'failed')
        self.assertNotIn('private upstream', str(records))
        self.callbacks['process_digest'].assert_called_once_with()
        self.callbacks['queue_due_reminders'].side_effect = None
        keep.background_maintenance_once(self.state)
        self.assertEqual(self.callbacks['queue_due_reminders'].call_count, 2)

    def test_partial_expiry_access_failure_and_held_email_are_not_success(self):
        self.callbacks['sync_plex_user_access'].return_value = None
        self.callbacks['expire_due_keeps'].return_value = {'released': 0, 'missing': 0, 'failed': 1}
        self.callbacks['process_digest'].return_value = 'review'
        keep.background_maintenance_once(self.state)
        records = self.store.records()
        self.assertEqual(records['plex-access-sync']['status'], 'failed')
        self.assertEqual(records['keep-expiry']['status'], 'failed')
        self.assertEqual(records['email-digest']['status'], 'review')

    def test_completed_empty_digest_is_not_reported_as_waiting(self):
        self.callbacks['process_digest'].return_value = 'empty'
        keep.background_maintenance_once(self.state)
        self.assertEqual(self.store.records()['email-digest']['status'], 'success')
        self.assertEqual(self.store.records()['email-digest']['result'], 'No changes')

    def test_observations_do_not_reject_existing_plex_sync_intervals(self):
        for interval in (0, -1, 30 * 86400):
            with self.subTest(interval=interval), patch.object(keep, 'PLEX_ACCESS_SYNC_SECONDS', interval):
                keep.background_maintenance_once({'plex_sync': 0, 'reminder_scan': None})
        self.assertEqual(self.callbacks['process_digest'].call_count, 3)
