"""Owner boundaries and observations around the real maintenance callbacks."""
from contextlib import closing
from pathlib import Path
import re
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch

import background_jobs
from connection_settings import ConnectionSettings
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


class JobsActionTests(TestCase):
    def setUp(self):
        test_keep.KeepTests.setUp(self)
        self.directory = TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        path = str(Path(self.directory.name) / 'jobs.sqlite3')
        self.store = background_jobs.Store(path)
        ConnectionSettings(path)
        keep.seerr.Store(path)
        environment = patch.dict(keep.os.environ, PLEX_ADMIN_TOKEN='synthetic-plex-key')
        environment.start()
        self.addCleanup(environment.stop)
        heartbeat = Path(self.directory.name) / 'heartbeat'
        heartbeat.touch()
        for target, value in (('job_store', lambda: self.store),
                              ('DIGEST_WORKER_HEARTBEAT_PATH', str(heartbeat))):
            mocked = patch.object(keep, target, value)
            mocked.start()
            self.addCleanup(mocked.stop)
        self.headers = {'Accept': 'application/json'}

    def action(self, job_id='onboarding-cleanup', action='run', **data):
        return self.client.post(f'/settings/jobs/{job_id}/{action}',
            data={'csrf_token': 'test-csrf', **data}, headers=self.headers)

    def test_manual_request_is_durable_and_http_does_not_execute_jobs(self):
        with patch.object(self.store, 'run') as execute:
            first = self.action()
            token = self.store.pending()['onboarding-cleanup']
            second = self.action()
        self.assertEqual(first.status_code, 202)
        self.assertEqual(second.status_code, 202)
        self.assertIn('last_run', first.json)
        self.assertIsNone(first.json['last_run'])
        self.assertIsNone(second.json['last_run'])
        execute.assert_not_called()
        self.assertEqual(self.store.pending()['onboarding-cleanup'], token)
        self.assertEqual(background_jobs.Store(self.store.path).pending()['onboarding-cleanup'], token)
        self.assertIn('no-store', first.headers['Cache-Control'])
        snapshot = self.client.get('/settings/jobs?format=json')
        row = next(row for row in snapshot.json['jobs'] if row['id'] == 'onboarding-cleanup')
        self.assertTrue(row['queued'])
        self.assertFalse(row['can_run'])
        self.assertIn('no-store', snapshot.headers['Cache-Control'])

    def test_run_responses_return_the_current_completed_attempt_as_the_announcement_baseline(self):
        self.store.run('onboarding-cleanup', lambda: None,
                       result_fn=lambda result: ('failed', 'Connection unavailable'))
        finished = background_jobs.timestamp(self.store.records()['onboarding-cleanup']['finished'])
        first = self.action()
        already_queued = self.action()
        self.assertEqual(first.status_code, 202)
        self.assertEqual(already_queued.status_code, 202)
        self.assertEqual(first.json['last_run'], finished)
        self.assertEqual(already_queued.json['last_run'], finished)

    def test_actions_require_owner_and_csrf_and_only_known_jobs(self):
        self.assertEqual(self.action(csrf_token='wrong').status_code, 403)
        self.assertEqual(self.action('unknown').status_code, 404)
        self.assertEqual(self.action('unknown', 'schedule', interval='900').status_code, 404)
        self.assertEqual(self.store.pending(), {})
        with closing(keep.attribution_db()) as db, db:
            db.execute("""INSERT INTO user_profiles (plex_id,email,display_name,auth_type,status)
                VALUES ('local-jobs','jobs@example.test','Other','local','active')""")
        with self.client.session_transaction() as state:
            state['plex_user'] = {'id': 'local-jobs', 'username': 'Other',
                'auth_type': 'local', 'session_version': 0}
        for action in ('run', 'schedule'):
            self.assertEqual(self.action(action=action, interval='900').status_code, 403)
        self.assertEqual(self.store.pending(), {})

    def test_frequency_is_validated_and_saved_without_running_work(self):
        for value in ('0', '-300', '301', '900.0', '99999999999', 'bad'):
            with self.subTest(value=value):
                self.assertEqual(self.action('plex-access-sync', 'schedule', interval=value).status_code, 400)
        self.assertEqual(self.action('email-digest', 'schedule', interval='900').status_code, 400)
        response = self.action('plex-access-sync', 'schedule', interval='1800')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(background_jobs.Store(self.store.path).interval('plex-access-sync', 900), 1800)
        self.assertEqual(self.store.pending(), {})
        snapshot = self.client.get('/settings/jobs?format=json').json
        row = next(row for row in snapshot['jobs'] if row['id'] == 'plex-access-sync')
        self.assertEqual(row['schedule'], 'Every 30 minutes')

    def test_stopped_runner_has_clear_feedback_and_schedule_can_still_be_saved(self):
        Path(keep.DIGEST_WORKER_HEARTBEAT_PATH).unlink()
        response = self.action()
        self.assertEqual(response.status_code, 409)
        self.assertIn('error', response.json)
        self.assertEqual(self.store.pending(), {})
        self.assertEqual(self.action('plex-access-sync', 'schedule', interval='900').status_code, 200)

    def test_regular_forms_redirect_with_readable_feedback(self):
        response = self.client.post('/settings/jobs/onboarding-cleanup/run',
            data={'csrf_token': 'test-csrf'})
        self.assertEqual(response.status_code, 303)
        page = self.client.get(response.headers['Location'])
        self.assertIn(b'queued to run shortly', page.data)
        self.assertNotIn(b'Background worker</h3>', page.data)

    def test_unconfigured_editable_jobs_retain_hidden_controls_for_later_configuration(self):
        with patch.object(keep, 'connection_value', return_value=None):
            page = self.client.get('/settings/jobs')
            snapshot = self.client.get('/settings/jobs?format=json').json
        row = next(row for row in snapshot['jobs'] if row['id'] == 'plex-access-sync')
        self.assertFalse(row['editable'])
        self.assertTrue(row['interval_options'])
        markup = re.search(r'<article\b[^>]*data-job-id="plex-access-sync".*?</article>',
                           page.data.decode(), re.S).group()
        self.assertRegex(markup, r'<button(?=[^>]*data-edit-job)(?=[^>]*hidden)(?=[^>]*disabled)[^>]*>')
        self.assertRegex(markup, r'<details(?=[^>]*data-schedule-fallback)(?=[^>]*hidden)[^>]*>')
        self.assertRegex(markup, r'<select(?=[^>]*name="interval")(?=[^>]*disabled)[^>]*>')
        self.assertIn('data-job-announcement role="status" aria-live="polite" aria-atomic="true"', markup)
        fixed = re.search(r'<article\b[^>]*data-job-id="onboarding-cleanup".*?</article>',
                          page.data.decode(), re.S).group()
        self.assertNotIn('data-edit-job', fixed)

    def test_configured_jobs_keep_the_regular_schedule_form_available_without_javascript(self):
        page = self.client.get('/settings/jobs')
        markup = re.search(r'<article\b[^>]*data-job-id="plex-access-sync".*?</article>',
                           page.data.decode(), re.S).group()
        self.assertIn('data-schedule-fallback', markup)
        self.assertNotRegex(markup, r'<details(?=[^>]*data-schedule-fallback)(?=[^>]*hidden)[^>]*>')
        self.assertNotRegex(markup, r'<select(?=[^>]*name="interval")(?=[^>]*disabled)[^>]*>')


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
