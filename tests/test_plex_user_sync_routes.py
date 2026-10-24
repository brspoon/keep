"""User discovery controls queue work without importing users in an HTTP request."""
from contextlib import closing
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch

import background_jobs
from connection_settings import ConnectionSettings
import test_keep

keep = test_keep.keep


class PlexUserSyncRouteTests(TestCase):
    def setUp(self):
        test_keep.KeepTests.setUp(self)
        self.directory = TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = str(Path(self.directory.name) / 'jobs.sqlite3')
        self.store = background_jobs.Store(self.path)
        ConnectionSettings(self.path)
        keep.seerr.Store(self.path)
        self.heartbeat = Path(self.directory.name) / 'heartbeat'
        self.heartbeat.touch()
        for target, value in (('job_store', lambda: self.store),
                              ('DIGEST_WORKER_HEARTBEAT_PATH', str(self.heartbeat))):
            patched = patch.object(keep, target, value)
            patched.start()
            self.addCleanup(patched.stop)
        environment = patch.dict(keep.os.environ, PLEX_ADMIN_TOKEN='private-discovery-token')
        environment.start()
        self.addCleanup(environment.stop)
        # The read-only helper uses a fresh Store on KEEP_DB_PATH. Point just
        # the job snapshot at the isolated job database, leaving auth unchanged.
        def snapshot(**kwargs):
            return self.store.snapshot(keep.connection_value, keep.connection_settings,
                heartbeat_path=str(self.heartbeat), read_only=kwargs.get('read_only', False))
        patched = patch.object(keep, 'jobs_snapshot', side_effect=snapshot)
        patched.start()
        self.addCleanup(patched.stop)

    def post(self, csrf='test-csrf', json=True):
        return self.client.post('/settings/users/plex-sync', data={'csrf_token': csrf},
                                headers={'Accept': 'application/json'} if json else {})

    def test_gets_are_read_only_and_users_page_explains_discovery(self):
        with patch.object(keep, 'sync_plex_user_access') as sync, \
             patch.object(keep.requests, 'get') as network:
            status = self.client.get('/settings/users/plex-sync')
            page = self.client.get('/settings/users')
        self.assertEqual(status.status_code, 200)
        self.assertEqual(status.json['job']['id'], 'plex-access-sync')
        self.assertTrue(status.json['job']['can_run'])
        self.assertIn('no-store', status.headers['Cache-Control'])
        body = page.get_data(as_text=True)
        self.assertIn('Sync Plex users', body)
        self.assertIn('class="admin-toolbar-actions"', body)
        self.assertNotIn('class="panel plex-user-sync"', body)
        self.assertNotIn('Display names appear publicly; full names stay here.', body)
        self.assertNotIn('Refresh status', body)
        self.assertNotIn('Reload users', body)
        self.assertIn('class="admin-sync-button"', body)
        self.assertIn('Never signed in', body)
        self.assertIn('/static/keep-plex-users.js?v=' + keep.APP_VERSION, body)
        self.assertNotIn('private-discovery-token', body + status.get_data(as_text=True))
        self.assertFalse(self.store.pending())
        sync.assert_not_called()
        network.assert_not_called()

    def test_post_queues_durable_request_once_without_network_or_discovery(self):
        with patch.object(keep, 'sync_plex_user_access') as sync, \
             patch.object(keep.requests, 'get') as network:
            first = self.post()
            token = self.store.pending()['plex-access-sync']
            second = self.post()
        self.assertEqual(first.status_code, 202)
        self.assertTrue(first.json['job']['queued'])
        self.assertEqual(second.status_code, 202)
        self.assertEqual(background_jobs.Store(self.path).pending()['plex-access-sync'], token)
        sync.assert_not_called()
        network.assert_not_called()
        with closing(keep.attribution_db()) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM activity_log WHERE action='job-requested'").fetchone()[0], 1)

    def test_initial_job_marker_cannot_get_ahead_of_the_rendered_user_list(self):
        snapshot = keep.plex_user_sync_snapshot
        def complete_before_snapshot_returns():
            def import_user():
                with closing(keep.attribution_db()) as db, db:
                    db.execute("""INSERT INTO user_profiles(plex_id,plex_username,plex_checked_at)
                        VALUES ('12','race-viewer',CURRENT_TIMESTAMP)""")
                return 1
            self.store.run('plex-access-sync', import_user, interval=900,
                           result_fn=lambda count: ('success', f'Updated {count} accounts'))
            return snapshot()
        with patch.object(keep, 'plex_user_sync_snapshot', side_effect=complete_before_snapshot_returns):
            response = self.client.get('/settings/users')
        self.assertEqual(response.status_code, 200)
        body = response.get_data(as_text=True)
        self.assertIn('Edit race-viewer', body)
        self.assertIn('Plex users synced.', body)

    def test_post_without_javascript_redirects_back_to_users_with_toast_notice(self):
        response = self.post(json=False)
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers['Location'], '/settings/users')
        page = self.client.get('/settings/users').get_data(as_text=True)
        self.assertIn('Plex user sync queued.', page)

    def test_csrf_rejection_does_not_queue_work(self):
        for csrf in ('', 'wrong'):
            response = self.post(csrf)
            self.assertEqual(response.status_code, 403)
            self.assertIn('session changed', response.json['error'])
        self.assertFalse(self.store.pending())

    def test_missing_worker_or_plex_setup_cannot_queue_work(self):
        self.heartbeat.unlink()
        response = self.post()
        self.assertEqual(response.status_code, 409)
        self.assertFalse(self.store.pending())
        self.heartbeat.touch()
        with patch.dict(keep.os.environ, PLEX_ADMIN_TOKEN=''):
            response = self.post()
        self.assertEqual(response.status_code, 409)
        self.assertIn('Configure Plex first', response.json['error'])
        self.assertFalse(self.store.pending())

    def test_owner_required_even_for_local_accounts_with_all_extra_permissions(self):
        with closing(keep.attribution_db()) as db, db:
            db.execute("""INSERT INTO user_profiles(plex_id,auth_type,status,display_name,
                can_keep_indefinitely,can_remove_any,can_delete_media,can_delete_any)
                VALUES ('local:sync','local','active','Manager',1,1,1,1)""")
        with self.client.session_transaction() as state:
            state['plex_user'] = {'id': 'local:sync', 'auth_type': 'local', 'session_version': 0}
        self.assertEqual(self.client.get('/settings/users/plex-sync').status_code, 403)
        self.assertEqual(self.post().status_code, 403)
        self.assertFalse(self.store.pending())
        with self.client.session_transaction() as state:
            state.clear()
        self.assertEqual(self.client.get('/settings/users/plex-sync').status_code, 302)
        self.assertEqual(self.post().status_code, 302)

    def test_queue_database_failure_is_retryable_and_not_reported_as_success(self):
        import sqlite3
        with patch.object(self.store, 'request_run', side_effect=sqlite3.OperationalError('private detail')):
            response = self.post()
        self.assertEqual(response.status_code, 503)
        self.assertNotIn('private detail', response.get_data(as_text=True))
        self.assertFalse(self.store.pending())

    def test_snapshot_failure_is_unavailable_without_writing_or_exposing_error(self):
        import sqlite3
        with patch.object(keep, 'jobs_snapshot', side_effect=sqlite3.OperationalError('private detail')):
            response = self.client.get('/settings/users/plex-sync')
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json['job']['can_run'])
        self.assertNotIn('private detail', response.get_data(as_text=True))
        self.assertFalse(self.store.pending())
