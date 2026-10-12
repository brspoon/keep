"""Owner controls, recorded state and safe support information for About."""
from contextlib import closing
from pathlib import Path
import re
import sqlite3
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch

import test_keep

keep = test_keep.keep


class AboutRoutesTests(TestCase):
    def setUp(self):
        test_keep.KeepTests.setUp(self)
        with closing(keep.attribution_db()) as db, db:
            for table in ('background_jobs', 'background_job_requests', 'background_job_settings'):
                db.execute('DELETE FROM ' + table)
            db.execute('DROP TABLE IF EXISTS release_checks')
        extensions = patch.dict(keep.app.extensions)
        extensions.start()
        self.addCleanup(extensions.stop)
        keep.app.extensions.pop('keep_release_updates', None)
        self.directory = TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.heartbeat = Path(self.directory.name) / 'worker-heartbeat'
        self.heartbeat.touch()
        mocked = patch.object(keep, 'DIGEST_WORKER_HEARTBEAT_PATH', str(self.heartbeat))
        mocked.start()
        self.addCleanup(mocked.stop)
        self.headers = {'Accept': 'application/json'}

    def check(self, csrf='test-csrf'):
        return self.client.post('/settings/about/check', data={'csrf_token': csrf}, headers=self.headers)

    def test_opening_and_polling_about_never_fetches_or_initializes_release_state(self):
        with patch.object(keep.release_updates.Store, 'check') as check:
            page = self.client.get('/settings/about')
            state = self.client.get('/settings/about/status')
        self.assertEqual(page.status_code, 200)
        self.assertEqual(state.status_code, 200)
        check.assert_not_called()
        self.assertEqual(state.json['snapshot']['status'], 'never')
        self.assertIsNone(state.json['snapshot']['latest_version'])
        for response in (page, state):
            self.assertEqual(response.headers['Cache-Control'], 'no-store')
        with closing(keep.attribution_db()) as db:
            self.assertIsNone(db.execute("SELECT name FROM sqlite_master WHERE name='release_checks'").fetchone())
        navigation = re.search(r'<nav class="admin-nav".*?</nav>', page.data.decode(), re.S).group()
        self.assertEqual(re.findall(r'href="([^"]+)"', navigation)[-1], '/settings/about')

    def test_manual_check_is_durable_and_deduplicated_without_running_in_http(self):
        with patch.object(keep.release_updates.Store, 'check') as check:
            first = self.check()
            token = keep.job_store().pending()['release-check']
            second = self.check()
        self.assertEqual(first.status_code, 202)
        self.assertEqual(second.status_code, 202)
        check.assert_not_called()
        self.assertEqual(keep.job_store().pending()['release-check'], token)
        self.assertEqual(first.json['snapshot']['check_state'], 'queued')
        self.assertFalse(first.json['snapshot']['can_check'])
        self.assertEqual(self.check('wrong').status_code, 403)

    def test_claimed_manual_check_reports_running_while_its_request_remains_durable(self):
        self.assertEqual(self.check().status_code, 202)
        store = keep.job_store()
        self.assertIn('release-check', store.pending())
        observed = []
        def check():
            snapshot = keep.about_snapshot()
            observed.append(snapshot)
            self.assertIn('release-check', store.pending())
            return {'status': 'success'}
        store.run('release-check', check, result_fn=keep.release_updates.job_result)
        self.assertEqual(observed[0]['check_state'], 'running')
        self.assertFalse(observed[0]['can_check'])
        self.assertEqual(observed[0]['reason'], 'A check is running.')

    def test_unavailable_worker_prevents_queueing_without_becoming_an_update_result(self):
        self.heartbeat.unlink()
        response = self.check()
        self.assertEqual(response.status_code, 409)
        self.assertEqual(keep.job_store().pending(), {})
        self.assertIn('unavailable', response.json['error'])
        self.assertIsNone(response.json['snapshot']['update_available'])

    def test_unavailable_database_returns_action_error_without_repeating_the_failed_read(self):
        with patch.object(keep, 'about_snapshot', side_effect=sqlite3.OperationalError('private database path')):
            response = self.check()
        self.assertEqual(response.status_code, 503)
        self.assertIsNone(response.json['snapshot'])
        self.assertNotIn('private database', response.get_data(as_text=True))

    def test_release_store_reuses_initialized_store_for_the_same_database(self):
        first = keep.release_store()
        self.assertIs(keep.release_store(), first)

    def test_diagnostics_allowlist_rejects_unexpected_stored_job_status(self):
        snapshot = keep.about_snapshot()
        jobs = keep.jobs_snapshot(read_only=True)
        next(row for row in jobs['jobs'] if row['id'] == 'probe-radarr')['status'] = 'private-token-data'
        with patch.object(keep, 'jobs_snapshot', return_value=jobs):
            diagnostics = keep.about_diagnostics(snapshot)
        self.assertNotIn('private-token-data', diagnostics)
        self.assertIn('unknown', diagnostics)

    def test_account_boundaries_cover_actions_status_and_installed_notices(self):
        with closing(keep.attribution_db()) as db, db:
            db.execute("""INSERT INTO user_profiles(plex_id,email,display_name,auth_type,status)
                          VALUES ('local-about','viewer@example.test','Viewer','local','active')""")
        with self.client.session_transaction() as state:
            state['plex_user'] = {'id': 'local-about', 'username': 'Viewer',
                                  'auth_type': 'local', 'session_version': 0}
        for path in ('/settings/about', '/settings/about/status', '/settings/about/notices/license',
                     '/settings/about/notices/third-party'):
            self.assertEqual(self.client.get(path).status_code, 403)
        self.assertEqual(self.check().status_code, 403)
        with self.client.session_transaction() as state:
            state.clear()
        self.assertEqual(self.client.get('/settings/about').status_code, 302)

    def test_support_copy_excludes_configuration_and_personal_information(self):
        with patch.dict(keep.os.environ, RADARR_API_KEY='private-api-secret',
                        KEEP_URL='https://private-host.example.test'), \
             patch.object(keep.platform, 'system', return_value='Linux'), \
             patch.object(keep.platform, 'machine', return_value='x86_64'):
            response = self.client.get('/settings/about/status')
        copy = response.json['diagnostics']
        for private in ('private-api-secret', 'private-host.example.test', 'Viewer',
                        'test-token', 'test-csrf', 'example.com', 'PLEX_ADMIN_TOKEN', 'SMTP_PASSWORD'):
            self.assertNotIn(private, copy)
        self.assertIn('keep_version', copy)
        self.assertIn('Linux', copy)
        self.assertIn('last_heartbeat', copy)

    def test_installed_notices_are_fixed_text_files_and_the_jobs_footer_is_removed(self):
        for document, name in (('license', 'LICENSE'), ('third-party', 'THIRD_PARTY.md')):
            response = self.client.get('/settings/about/notices/' + document)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.mimetype, 'text/plain')
            self.assertEqual(response.get_data(as_text=True), (Path(keep.__file__).parent / name).read_text())
        self.assertEqual(self.client.get('/settings/about/notices/VERSION').status_code, 404)
        jobs = self.client.get('/settings/jobs').get_data(as_text=True)
        self.assertNotIn('Run now performs one check.', jobs)
