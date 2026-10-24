"""Owner controls, recorded state and safe support information for About."""
from contextlib import closing, ExitStack
from contextvars import copy_context
import json
from pathlib import Path
import re
import sqlite3
import time
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import Mock, call, patch

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

    def test_about_keeps_release_checks_and_update_guide_without_execution_controls(self):
        page=self.client.get('/settings/about').get_data(as_text=True)
        self.assertIn('Check for updates',page)
        self.assertIn('https://github.com/brspoon/keep/blob/main/docs/MIGRATION.md#upgrade-an-installation',page)
        self.assertIn('Recent releases',page)
        self.assertIn('Copy diagnostics',page)
        for removed in ('maintenance-install','maintenance-restart','keep-maintenance.js',
                        'keep-maintenance.css','maintenance-snapshot','Install update'):
            self.assertNotIn(removed,page)

    def test_retired_execution_endpoints_cannot_queue_or_modify_an_installation(self):
        with closing(keep.attribution_db()) as db:
            before='\n'.join(db.iterdump())
        with patch.object(keep.requests,'get') as get,patch.object(keep.requests,'post') as post:
            status=self.client.get('/settings/about/maintenance/status',headers=self.headers)
            start=self.client.post('/settings/about/maintenance/start',json={'operation':'install'},headers=self.headers)
        self.assertEqual(status.status_code,404)
        self.assertEqual(start.status_code,404)
        get.assert_not_called();post.assert_not_called()
        with closing(keep.attribution_db()) as db:
            self.assertEqual('\n'.join(db.iterdump()),before)

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

    def test_manual_release_check_still_runs_with_the_ordinary_background_jobs(self):
        self.assertEqual(self.check().status_code,202)
        callbacks={'sync_plex_user_access':0,'expire_due_keeps':{'released':0,'missing':0,'failed':0},
                   'queue_due_reminders':0,'reconcile_reminder_queue':None,'prune_notification_queue':0,
                   'observe_notification_status':None,'process_digest':'disabled'}
        with ExitStack() as stack:
            check=stack.enter_context(patch.object(keep.release_updates.Store,'check',return_value={'status':'success'}))
            mocked={name:stack.enter_context(patch.object(keep,name,return_value=result))
                    for name,result in callbacks.items()}
            stack.enter_context(patch.object(keep.time,'monotonic',return_value=1000))
            copy_context().run(keep.background_maintenance_once,{'plex_sync':0,'reminder_scan':None})
        check.assert_called_once_with(force=True)
        self.assertNotIn('release-check',keep.job_store().pending())
        self.assertEqual(keep.job_store().records()['release-check']['status'],'success')
        for name in ('expire_due_keeps','queue_due_reminders','reconcile_reminder_queue','prune_notification_queue','process_digest'):
            mocked[name].assert_called_once()

    def test_worker_startup_recovers_notifications_and_interrupted_jobs(self):
        runtime,jobs=Mock(),Mock()
        sequence=Mock();sequence.attach_mock(runtime.recover_after_lock,'recover');sequence.attach_mock(jobs.interrupt_running,'interrupt')
        with patch.object(keep,'notification_runtime',return_value=runtime),patch.object(keep,'job_store',return_value=jobs):
            self.assertIsNone(keep.worker_startup_recovery())
        self.assertEqual(sequence.mock_calls,[call.recover(),call.interrupt()])

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

    def test_native_check_feedback_is_neutral_while_queued(self):
        page = self.client.post('/settings/about/check', data={'csrf_token': 'test-csrf'},
                                follow_redirects=True).get_data(as_text=True)
        feedback = re.search(r'<p id="about-feedback".*?</p>', page, re.S).group()
        self.assertIn('data-feedback-status="neutral"', feedback)
        self.assertIn('Update check queued.', feedback)
        self.assertNotIn('is-error', feedback)

    def test_server_badges_compare_installed_version_and_identify_stale_latest_data(self):
        original = keep.about_snapshot()
        for changes, label, tone, stale_latest in (
            ({'status': 'success', 'stale': False, 'comparison': 'unknown'}, '', 'neutral', False),
            ({'status': 'success', 'stale': False, 'comparison': 'unexpected'}, '', 'neutral', False),
            ({'status': 'success', 'stale': False, 'comparison': 'up_to_date'}, 'Up to date', 'ok', False),
            ({'status': 'success', 'stale': False, 'comparison': 'update_available'}, 'Update available', 'warn', False),
            ({'status': 'success', 'stale': False, 'comparison': 'ahead'}, 'Ahead of latest stable', 'neutral', False),
            ({'status': 'success', 'stale': True, 'comparison': 'up_to_date'}, '', 'neutral', True),
            ({'status': 'failed', 'stale': True, 'comparison': 'up_to_date'}, '', 'neutral', True),
            ({'status': 'rate_limited', 'stale': True, 'comparison': 'up_to_date'}, '', 'neutral', True),
            ({'status': 'never', 'stale': True, 'comparison': 'unknown', 'latest_version': None}, '', 'neutral', False),
        ):
            with self.subTest(changes=changes), patch.object(keep, 'about_snapshot', return_value={
                    **original, 'latest_version': keep.APP_VERSION, **changes}):
                page = self.client.get('/settings/about').get_data(as_text=True)
                installed = re.search(r'<div><dt>Installed</dt><dd>(.*?)</dd></div>', page, re.S).group(1)
                latest = re.search(r'<div><dt>Latest stable</dt><dd>(.*?)</dd></div>', page, re.S).group(1)
                self.assertIn(f'<span id="about-installed">{keep.APP_VERSION}</span>', installed)
                self.assertNotIn('about-comparison', latest)
                self.assertNotIn('about-latest-stale', installed)
                badge = re.search(r'<span id="about-comparison".*?</span>', installed, re.S).group()
                self.assertIn('data-status="' + tone + '"', badge)
                self.assertIn('>' + label + '</span>', badge)
                self.assertEqual('hidden' in badge, not bool(label))
                stale_badge = re.search(r'<span id="about-latest-stale".*?</span>', latest, re.S).group()
                self.assertIn('data-status="neutral"', stale_badge)
                self.assertIn('>Last known</span>', stale_badge)
                self.assertEqual('hidden' in stale_badge, not stale_latest)
                if changes['status'] == 'failed':
                    feedback = re.search(r'<p id="about-feedback".*?</p>', page, re.S).group()
                    self.assertIn('data-feedback-status="error"', feedback)
                    self.assertIn('is-error', feedback)
                    self.assertNotIn('hidden', feedback)

    def test_server_check_badge_reports_success_even_when_release_data_is_stale(self):
        original = keep.about_snapshot()
        for status, stale, check_state, label, tone in (
            ('success', False, 'idle', 'Checked', 'ok'),
            ('success', True, 'idle', 'Checked', 'ok'),
            ('success', True, 'queued', 'Queued', 'neutral'),
            ('success', True, 'running', 'Checking', 'neutral'),
            ('failed', True, 'idle', 'Failed', 'error'),
            ('rate_limited', True, 'idle', 'Rate limited', 'warn'),
            ('never', True, 'idle', 'Not checked', 'neutral'),
        ):
            with self.subTest(status=status, stale=stale, check_state=check_state), patch.object(
                    keep, 'about_snapshot', return_value={**original, 'latest_version': keep.APP_VERSION,
                        'status': status, 'stale': stale, 'check_state': check_state}):
                page = self.client.get('/settings/about').get_data(as_text=True)
                badge = re.search(r'<span id="about-check-state".*?</span>', page, re.S).group()
                self.assertIn(f'data-status="{tone}"', badge)
                self.assertIn(f'>{label}</span>', badge)
                if stale:
                    comparison = re.search(r'<span id="about-comparison".*?</span>', page, re.S).group()
                    self.assertIn('hidden', comparison)
                    latest = re.search(r'<span id="about-latest-stale".*?</span>', page, re.S).group()
                    self.assertIn('data-status="neutral"', latest)
                    self.assertNotIn('hidden', latest)

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
        self.assertEqual(first.installed_version, keep.APP_VERSION)
        with patch.object(keep, 'APP_VERSION', '9.9.9'):
            replaced = keep.release_store()
        self.assertIsNot(replaced, first)
        self.assertEqual(replaced.installed_version, '9.9.9')

    def test_new_version_does_not_render_the_previous_check_as_a_fresh_ahead_comparison(self):
        keep.release_updates.Store(keep.KEEP_DB_PATH, installed_version='1.0.0')
        release = {'version': '1.0.0', 'tag': '1.0.0', 'name': 'Release 1.0.0',
                   'published_at': '2026-10-11T12:00:00Z'}
        now = time.time()
        with closing(keep.attribution_db()) as db, db:
            db.execute('''UPDATE release_checks SET latest_json=?,recent_json=?,last_attempt=?,last_success=?,
                next_attempt=?,outcome='success',attempted_version='1.0.0',checked_version='1.0.0' WHERE id=1''',
                (json.dumps(release), json.dumps([release]), now - 120, now - 120,
                 now + keep.release_updates.CHECK_INTERVAL))
        before = Path(keep.KEEP_DB_PATH).read_bytes()
        with patch.object(keep.release_updates.Store, 'check') as check:
            response = self.client.get('/settings/about/status')
        self.assertEqual(response.json['snapshot']['comparison'], 'unknown')
        self.assertTrue(response.json['snapshot']['stale'])
        self.assertTrue(response.json['snapshot']['version_refresh_pending'])
        self.assertEqual(response.json['snapshot']['latest_version'], '1.0.0')
        check.assert_not_called()
        self.assertEqual(Path(keep.KEEP_DB_PATH).read_bytes(), before)
        self.assertTrue(keep.release_store().due())

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
