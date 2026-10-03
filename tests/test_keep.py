import atexit
import os
import copy
import json
import struct
import tempfile
import unittest
from contextlib import closing
from datetime import datetime, timedelta, timezone
from unittest.mock import patch, Mock

_db_dir = tempfile.TemporaryDirectory()
atexit.register(_db_dir.cleanup)
os.environ.update(FLASK_SECRET_KEY='test-only-secret-not-for-production-0000', PLEX_CLIENT_IDENTIFIER='test',
                  PLEX_SERVER_URL='http://plex', PLEX_MACHINE_IDENTIFIER='test',
                  KEEP_DB_PATH=os.path.join(_db_dir.name, 'keep.sqlite3'),
                  PLEX_OWNER_ID='7', EMAIL_ENABLED='true', SMTP_HOST='smtp.example.com', SMTP_FROM='keep@example.com', KEEP_COLLECTIONS=json.dumps({'1': 'Movies Leaving Plex Soon', '3': 'Shows Leaving Plex Soon', '5': 'Kids Movies Leaving Plex Soon', '6': 'Kids Shows Leaving Plex Soon'}))
import app as keep
keep.COLLECTIONS = keep.get_collections()

class KeepTests(unittest.TestCase):
    def setUp(self):
        keep.app.config.update(TESTING=True)
        deletion_patch = patch.object(keep.requests, 'delete')
        self.delete = deletion_patch.start()
        self.addCleanup(deletion_patch.stop)
        self.client = keep.app.test_client()
        self.cid = next(iter(keep.COLLECTIONS))
        self.item = {'id': 91, 'mediaServerId': '42',
                     'mediaData': {'title': 'Test Movie', 'year': 2026}}
        with closing(keep.attribution_db()) as db, db:
            db.execute('DELETE FROM keep_attribution')
            db.execute('DELETE FROM keep_schedules')
            db.execute('DELETE FROM activity_log')
            db.execute('DELETE FROM user_library_permissions')
            db.execute('DELETE FROM user_feature_acknowledgements')
            db.execute('DELETE FROM media_libraries')
            db.execute("""UPDATE keep_migrations
                SET started_at='2026-09-10 12:00:00', completed_at='2026-09-10 12:00:01'
                WHERE name=?""", (keep.TEMPORARY_KEEP_MIGRATION,))
            db.execute("DELETE FROM user_profiles")
            db.execute("""INSERT INTO user_profiles
                (plex_id, plex_username, email, auth_type, status, plex_access, plex_checked_at)
                VALUES ('7', 'owner', 'owner@example.com', 'plex', 'active', 'active', CURRENT_TIMESTAMP)""")
        with self.client.session_transaction() as session:
            session['plex_user'] = {'id': 7, 'username': '<Alice>', 'thumb': ''}
            session['csrf_token'] = 'test-csrf'

    def post(self, path, data):
        return self.client.post(path, json=data, headers={'X-CSRF-Token': 'test-csrf'})

    def keep_title(self, duration=None):
        payload = {'mediaId': '42', 'collectionId': self.cid, 'username': 'Forged name'}
        if duration:
            payload['duration'] = duration
        return self.post('/api/keep', payload)

    @patch.object(keep, 'get_collection_exclusions')
    @patch.object(keep, 'get_collection_media')
    def test_live_counts_are_read_only_and_not_cached(self, media, exclusions):
        media.return_value = {'items': [self.item]}
        exclusions.return_value = {'items': [self.item, self.item]}
        with patch.object(keep.requests, 'post') as post:
            response = self.client.get('/api/counts')
        self.assertEqual(response.json, {'leaving': 4, 'kept': 8})
        self.assertIn('no-store', response.headers['Cache-Control'])
        post.assert_not_called()
        self.delete.assert_not_called()
        with self.client.session_transaction() as session:
            session.clear()
        self.assertEqual(self.client.get('/api/counts').status_code, 302)

    @patch.object(keep, 'get_collection_media', side_effect=keep.requests.ConnectionError('offline'))
    def test_live_counts_failure_does_not_report_zero(self, media):
        response = self.client.get('/api/counts')
        self.assertEqual(response.status_code, 502)
        self.assertNotIn('leaving', response.json)

    @patch.object(keep, 'plex_user_has_server_access', return_value=False)
    @patch.object(keep, 'get_plex_user', return_value={'id': 99})
    @patch.object(keep.requests, 'get')
    def test_access_denied_uses_login_style_and_clears_session(self, get, user, access):
        get.return_value.json.return_value = {'authToken': 'test-token'}
        with self.client.session_transaction() as session:
            session['plex_binding'] = 'test-binding'
        state = keep.onboarding.put_flow('test-binding', 'login', {'pin': 123, 'code': 'test-code'})
        response = self.client.get('/auth/plex/callback?state=' + state)
        self.assertEqual(response.status_code, 403)
        body = response.get_data(as_text=True)
        self.assertIn('Access denied', body)
        self.assertIn('class="login-card"', body)
        self.assertIn('Back to sign in', body)
        with self.client.session_transaction() as session:
            self.assertNotIn('plex_user', session)
        self.assertEqual(self.client.get('/kept').status_code, 302)
        login = self.client.get('/login').get_data(as_text=True)
        self.assertIn('Sign in with Plex', login)
        self.assertNotIn('Access denied', login)

    def test_login_and_csrf_required(self):
        self.assertEqual(self.client.post('/api/keep', json={}).status_code, 403)
        with self.client.session_transaction() as session:
            session.clear()
        self.assertEqual(self.keep_title().status_code, 302)

    def test_brand_icons_and_manifest_are_public(self):
        with self.client.session_transaction() as session:
            session.clear()
        login = self.client.get('/login').get_data(as_text=True)
        self.assertIn('rel="apple-touch-icon" sizes="180x180"', login)
        self.assertIn('href="/static/site.webmanifest"', login)

        expected_sizes = {
            '/static/favicon-32.png': 32,
            '/static/apple-touch-icon.png': 180,
            '/static/keep-icon-192.png': 192,
            '/static/keep-icon-512.png': 512,
        }
        for path, expected in expected_sizes.items():
            response = self.client.get(path)
            try:
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.mimetype, 'image/png')
                self.assertEqual(struct.unpack('>II', response.data[16:24]),
                                 (expected, expected))
            finally:
                response.close()

        manifest = self.client.get('/static/site.webmanifest')
        try:
            self.assertEqual(manifest.status_code, 200)
            self.assertEqual(json.loads(manifest.data)['name'], 'Keep')
        finally:
            manifest.close()

    def test_authenticated_login_page_redirects_to_leaving(self):
        response = self.client.get('/login')
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers['Location'], '/')

    def test_unknown_signed_session_is_rejected_without_creating_profile(self):
        client = keep.app.test_client()
        with client.session_transaction() as session:
            session['plex_user'] = {'id': 'not-owner', 'username': 'standard'}
        response = client.get('/')
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers['Location'], '/login')
        with closing(keep.attribution_db()) as db:
            profile = db.execute(
                "SELECT 1 FROM user_profiles WHERE plex_id = 'not-owner'"
            ).fetchone()
        self.assertIsNone(profile)

    @patch.object(keep, 'plex_user_has_server_access', return_value=True)
    @patch.object(keep, 'get_plex_user', return_value={
        'id': 8, 'username': 'Plex Friend', 'email': 'friend@example.com', 'thumb': ''
    })
    @patch.object(keep.requests, 'get')
    def test_plex_login_redirects_to_leaving(self, get, user, access):
        get.return_value.json.return_value = {'authToken': 'test-token'}
        with self.client.session_transaction() as session:
            session['plex_binding'] = 'test-binding'
        state = keep.onboarding.put_flow('test-binding', 'login', {'pin': 123, 'code': 'test-code'})
        response = self.client.get('/auth/plex/callback?state=' + state)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers['Location'], '/')

    @patch.object(keep, 'plex_user_has_server_access', return_value=True)
    @patch.object(keep, 'get_plex_user', return_value={
        'id': 8, 'username': 'Plex Friend', 'email': 'friend@example.com', 'thumb': ''
    })
    @patch.object(keep.requests, 'get')
    def test_manually_disabled_plex_user_cannot_log_in(self, get, user, access):
        with closing(keep.attribution_db()) as db, db:
            db.execute("""INSERT INTO user_profiles
                (plex_id, plex_username, auth_type, status, plex_access)
                VALUES ('8', 'Plex Friend', 'plex', 'disabled', 'active')""")
        get.return_value.json.return_value = {'authToken': 'test-token'}
        with self.client.session_transaction() as session:
            session['plex_binding'] = 'test-binding'
        state = keep.onboarding.put_flow('test-binding', 'login', {'pin': 123, 'code': 'test-code'})
        response = self.client.get('/auth/plex/callback?state=' + state)
        self.assertEqual(response.status_code, 403)
        self.assertIn('Access disabled', response.get_data(as_text=True))
        with self.client.session_transaction() as session:
            self.assertNotIn('plex_user', session)

    @patch.object(keep, 'get_collection_media')
    @patch.object(keep.requests, 'post')
    def test_attribution_persistence_badge_and_removal(self, post, media):
        media.return_value = {'items': [self.item]}
        self.assertEqual(self.keep_title().status_code, 200)
        with closing(keep.attribution_db()) as db, db:
            row = db.execute('SELECT * FROM keep_attribution').fetchone()
            self.assertEqual(row['user_id'], '7')
            self.assertEqual(row['username'], '<Alice>')
            self.assertTrue(row['kept_at'])
        with patch.object(keep, 'get_collection_exclusions', side_effect=lambda cid: {'items': [copy.deepcopy(self.item)]}), \
             patch.object(keep, 'get_kept_item_poster', return_value=''), \
             patch.object(keep.requests, 'delete'):
            page = self.client.get('/kept').get_data(as_text=True)
            self.assertIn('Kept by &lt;Alice&gt;', page)
            self.assertNotIn('Kept by <Alice>', page)
            self.assertEqual(self.post('/api/remove-kept', {'exclusionId': 91, 'collectionId': self.cid}).status_code, 200)
            page = self.client.get('/kept').get_data(as_text=True)
            self.assertIn('Keeper not recorded', page)
        with closing(keep.attribution_db()) as db, db:
            db.execute("INSERT INTO user_profiles(plex_id, plex_username, plex_checked_at) VALUES ('8', 'Bob', CURRENT_TIMESTAMP)")
        with self.client.session_transaction() as session:
            session['plex_user'] = {'id': 8, 'username': 'Bob'}
        self.assertEqual(self.keep_title().status_code, 200)
        with closing(keep.attribution_db()) as db, db:
            self.assertEqual(db.execute('SELECT username FROM keep_attribution').fetchone()[0], 'Bob')

    @patch.object(keep, 'get_collection_media')
    @patch.object(keep.requests, 'post')
    def test_keep_changes_only_selected_title_without_rule_execution(self, post, media):
        media.return_value = {'items': [self.item]}
        keep.queue_notifications(self.cid, ['42'], 'MEDIA_ADDED_TO_COLLECTION', now=1000)
        self.assertEqual(self.keep_title().status_code, 200)
        post.assert_called_once_with(f'{keep.MAINTAINERR_URL}/api/rules/exclusion',
                                    json={'mediaId': '42', 'collectionId': self.cid, 'action': 0}, timeout=10)
        self.delete.assert_called_once_with(f'{keep.MAINTAINERR_URL}/api/collections/media',
                                           params={'mediaId': '42', 'collectionId': self.cid}, timeout=30)
        with closing(keep.attribution_db()) as db, db:
            self.assertEqual(db.execute(
                'SELECT COUNT(*) FROM notification_queue WHERE collection_id=? AND media_id=?',
                (self.cid, '42')).fetchone()[0], 0)

    @patch.object(keep.requests, 'post')
    @patch.object(keep.requests, 'delete')
    @patch.object(keep, 'get_collection_exclusions')
    def test_remove_only_clears_exclusion_and_attribution(self, exclusions, delete, post):
        exclusions.return_value = {'items': [self.item]}
        keep.record_keeper(self.cid, '42', {'id': 7, 'username': 'Alice'})
        response = self.post('/api/remove-kept', {'exclusionId': 91, 'collectionId': self.cid})
        self.assertEqual(response.status_code, 200)
        post.assert_called_once_with(f'{keep.MAINTAINERR_URL}/api/rules/exclusion',
                                    json={'mediaId': '42', 'collectionId': self.cid, 'action': 1}, timeout=10)
        delete.assert_not_called()
        with closing(keep.attribution_db()) as db, db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM keep_attribution').fetchone()[0], 0)

    @patch.object(keep.requests, 'post')
    @patch.object(keep.requests, 'delete')
    @patch.object(keep, 'get_collection_exclusions')
    def test_only_keeper_or_manager_can_remove(self, exclusions, delete, post):
        exclusions.return_value = {'items': [self.item]}
        keep.record_keeper(self.cid, '42', {'id': 8, 'username': 'Alice'})
        with closing(keep.attribution_db()) as db, db:
            db.execute("INSERT INTO user_profiles(plex_id, plex_username, plex_checked_at) VALUES ('9', 'Bob', CURRENT_TIMESTAMP)")
        with self.client.session_transaction() as session:
            session['plex_user'] = {'id': 9, 'username': 'Bob'}
        self.assertEqual(self.post('/api/remove-kept', {
            'exclusionId': 91, 'collectionId': self.cid}).status_code, 403)
        delete.assert_not_called()
        self.assertEqual(post.call_count, 0)

        with closing(keep.attribution_db()) as db, db:
            db.execute("""INSERT INTO user_profiles(plex_id, plex_username, can_remove_any)
                          VALUES ('9', 'Bob', 1)
                          ON CONFLICT(plex_id) DO UPDATE SET can_remove_any = 1""")
        self.assertEqual(self.post('/api/remove-kept', {
            'exclusionId': 91, 'collectionId': self.cid}).status_code, 200)
        self.assertEqual(post.call_count, 1)

    @patch.object(keep, 'get_kept_item_poster', return_value='')
    @patch.object(keep, 'get_collection_media', return_value={'items': []})
    @patch.object(keep, 'get_collection_exclusions')
    def test_kept_removal_controls_follow_server_permissions(self, exclusions, media, poster):
        from html.parser import HTMLParser
        class Buttons(HTMLParser):
            def __init__(self):
                super().__init__()
                self.actions = []
            def handle_starttag(self, tag, attrs):
                attrs = dict(attrs)
                if tag == 'button' and 'keep-button' in attrs.get('class', '').split():
                    self.actions.append(attrs)
        exclusions.side_effect = lambda cid: {'items': [copy.deepcopy(self.item)] if cid == self.cid else []}
        name = '<Keeper & "Family">' + 'LongName' * 12
        keep.record_keeper(self.cid, '42', {'id': 8, 'username': name})
        keep.remember_plex_user({'id': 8, 'username': name}, access_verified=True)
        with closing(keep.attribution_db()) as db, db:
            db.execute("INSERT INTO user_profiles(plex_id, plex_username, plex_checked_at) VALUES ('9', 'Viewer', CURRENT_TIMESTAMP)")
        for viewer, can_remove, can_manage in [(8, True, True), (7, True, True), (9, False, False)]:
            with self.subTest(viewer=viewer):
                with self.client.session_transaction() as session:
                    session['plex_user'] = {'id': viewer, 'username': 'Preview'}
                page = self.client.get('/kept').get_data(as_text=True)
                self.assertEqual('data-kept-by-viewer="true"' in page, viewer == 8)
                parser = Buttons()
                parser.feed(page)
                self.assertEqual(len(parser.actions), int(can_remove))
                if can_remove:
                    self.assertIn('remove-kept-button', parser.actions[0]['class'].split())
                self.assertEqual('class="keep-manage-button"' in page, can_manage)
                self.assertNotIn('removal-info-button', page)
        with closing(keep.attribution_db()) as db, db:
            db.execute('DELETE FROM keep_attribution')
        parser = Buttons()
        parser.feed(self.client.get('/kept').get_data(as_text=True))
        self.assertEqual(parser.actions, [])
        self.assertEqual(self.post('/api/remove-kept', {
            'exclusionId': 91, 'collectionId': self.cid}).status_code, 403)
        self.delete.assert_not_called()

    @patch.object(keep.requests, 'post')
    @patch.object(keep.requests, 'delete')
    @patch.object(keep, 'get_collection_exclusions')
    def test_keeper_can_remove_own_item(self, exclusions, delete, post):
        exclusions.return_value = {'items': [self.item]}
        keep.record_keeper(self.cid, '42', {'id': 8, 'username': 'Alice'})
        keep.remember_plex_user({'id': 8, 'username': 'Alice'}, access_verified=True)
        with self.client.session_transaction() as session:
            session['plex_user'] = {'id': 8, 'username': 'Alice'}
        self.assertEqual(self.post('/api/remove-kept', {
            'exclusionId': 91, 'collectionId': self.cid}).status_code, 200)
        delete.assert_not_called()

    @patch.object(keep.requests, 'post')
    @patch.object(keep.requests, 'delete')
    @patch.object(keep, 'get_collection_exclusions')
    def test_failed_removal_preserves_attribution(self, exclusions, delete, post):
        exclusions.return_value = {'items': [self.item]}
        post.return_value.raise_for_status.side_effect = keep.requests.HTTPError('delete failed')
        keep.record_keeper(self.cid, '42', {'id': 7, 'username': 'Alice'})
        response = self.post('/api/remove-kept', {'exclusionId': 91, 'collectionId': self.cid})
        self.assertEqual(response.status_code, 502)
        post.assert_called_once()
        with closing(keep.attribution_db()) as db, db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM keep_attribution').fetchone()[0], 1)

    @patch.object(keep, 'get_collection_media')
    @patch.object(keep.requests, 'post')
    def test_new_keeps_default_to_30_days_and_can_be_indefinite(self, post, media):
        media.return_value = {'items': [self.item]}
        before = datetime.now(timezone.utc) + timedelta(days=29, hours=23)
        response = self.keep_title()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json['duration'], 'temporary')
        with closing(keep.attribution_db()) as db:
            expires_at = db.execute('SELECT expires_at FROM keep_schedules').fetchone()[0]
        expiry = datetime.strptime(expires_at, '%Y-%m-%d %H:%M:%S').replace(tzinfo=timezone.utc)
        self.assertGreater(expiry, before)

        with closing(keep.attribution_db()) as db, db:
            db.execute('DELETE FROM keep_attribution')
            db.execute('DELETE FROM keep_schedules')
        response = self.keep_title('indefinite')
        self.assertEqual(response.json['duration'], 'indefinite')
        with closing(keep.attribution_db()) as db:
            self.assertIsNone(db.execute('SELECT expires_at FROM keep_schedules').fetchone()[0])

    @patch.object(keep, 'get_collection_media')
    @patch.object(keep.requests, 'post')
    def test_keep_rejects_unknown_duration_and_business_failure(self, post, media):
        media.return_value = {'items': [self.item]}
        self.assertEqual(self.keep_title('surprise').status_code, 400)
        post.assert_not_called()
        post.return_value.json.return_value = {'code': 0, 'message': 'Failed'}
        with self.assertRaises(keep.requests.RequestException):
            self.keep_title('temporary')
        with closing(keep.attribution_db()) as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM keep_schedules').fetchone()[0], 0)

    @patch.object(keep, 'get_collection_exclusions')
    def test_existing_keeps_receive_fresh_grace_period_once(self, exclusions):
        legacy = copy.deepcopy(self.item)
        scoped = copy.deepcopy(self.item)
        scoped['mediaServerId'] = '43'
        scoped['ruleGroupId'] = 12
        global_item = copy.deepcopy(self.item)
        global_item['mediaServerId'] = '44'
        global_item['ruleGroupId'] = None
        exclusions.return_value = {'items': [legacy, scoped, global_item]}
        with closing(keep.attribution_db()) as db, db:
            db.execute("""UPDATE keep_migrations
                SET started_at='2026-09-10 12:00:00', completed_at=NULL WHERE name=?""",
                (keep.TEMPORARY_KEEP_MIGRATION,))

        migrated = keep.migrate_existing_keep_schedules({self.cid: exclusions.return_value['items']})
        self.assertEqual(migrated, 2)
        with closing(keep.attribution_db()) as db:
            rows = [tuple(row) for row in db.execute(
                'SELECT media_id, expires_at FROM keep_schedules ORDER BY media_id')]
            completed = db.execute('SELECT completed_at FROM keep_migrations WHERE name=?',
                                   (keep.TEMPORARY_KEEP_MIGRATION,)).fetchone()[0]
        self.assertEqual(rows, [('42', '2026-10-10 12:00:00'), ('43', '2026-10-10 12:00:00')])
        self.assertTrue(completed)
        self.assertEqual(keep.migrate_existing_keep_schedules({self.cid: []}), 0)

    @patch.object(keep, 'get_collection_exclusions')
    def test_keeper_can_extend_or_make_keep_indefinite(self, exclusions):
        exclusions.return_value = {'items': [self.item]}
        initial = datetime(2026, 9, 10, 12, tzinfo=timezone.utc)
        keep.record_keeper(self.cid, '42', {'id': 7, 'username': 'Alice'}, now=initial)
        with patch.object(keep, 'datetime') as clock:
            clock.now.return_value = initial + timedelta(days=1)
            clock.strptime.side_effect = datetime.strptime
            response = self.post('/api/update-keep', {
                'mediaId': '42', 'collectionId': self.cid, 'duration': 'temporary'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json['expiresAt'], '2026-11-09 12:00:00')
        self.assertEqual(response.json['extensionAvailableAt'], '2026-10-10 12:00:00')

        with patch.object(keep, 'datetime') as clock:
            clock.now.return_value = initial + timedelta(days=2)
            clock.strptime.side_effect = datetime.strptime
            response = self.post('/api/update-keep', {
                'mediaId': '42', 'collectionId': self.cid, 'duration': 'temporary'})
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json['availableAt'], '2026-10-10 12:00:00')

        response = self.post('/api/update-keep', {
            'mediaId': '42', 'collectionId': self.cid, 'duration': 'indefinite'})
        self.assertEqual(response.status_code, 200)
        with closing(keep.attribution_db()) as db:
            self.assertIsNone(db.execute('SELECT expires_at FROM keep_schedules').fetchone()[0])

        with patch.object(keep, 'datetime') as clock:
            clock.now.return_value = initial + timedelta(days=2)
            response = self.post('/api/update-keep', {
                'mediaId': '42', 'collectionId': self.cid, 'duration': 'temporary'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json['expiresAt'], '2026-10-12 12:00:00')

    @patch.object(keep, 'get_collection_media')
    @patch.object(keep.requests, 'post')
    def test_basic_user_cannot_create_indefinite_keep(self, post, media):
        media.return_value = {'items': [self.item]}
        with closing(keep.attribution_db()) as db, db:
            db.execute("INSERT INTO user_profiles(plex_id, plex_username, plex_checked_at) VALUES ('8', 'Basic', CURRENT_TIMESTAMP)")
        with self.client.session_transaction() as session:
            session['plex_user'] = {'id': 8, 'username': 'Basic'}
        self.assertEqual(self.keep_title('indefinite').status_code, 403)
        self.assertEqual(self.keep_title('temporary').status_code, 200)

    @patch.object(keep, 'get_collection_exclusions')
    def test_other_viewer_cannot_change_keep_duration(self, exclusions):
        exclusions.return_value = {'items': [self.item]}
        keep.record_keeper(self.cid, '42', {'id': 8, 'username': 'Alice'})
        with closing(keep.attribution_db()) as db, db:
            db.execute("INSERT INTO user_profiles(plex_id, plex_username, plex_checked_at) VALUES ('9', 'Bob', CURRENT_TIMESTAMP)")
        with self.client.session_transaction() as session:
            session['plex_user'] = {'id': 9, 'username': 'Bob'}
        response = self.post('/api/update-keep', {
            'mediaId': '42', 'collectionId': self.cid, 'duration': 'indefinite'})
        self.assertEqual(response.status_code, 403)
        with closing(keep.attribution_db()) as db:
            self.assertTrue(db.execute('SELECT expires_at FROM keep_schedules').fetchone()[0])

        with closing(keep.attribution_db()) as db, db:
            db.execute("UPDATE user_profiles SET can_remove_any=1 WHERE plex_id='9'")
        response = self.post('/api/update-keep', {
            'mediaId': '42', 'collectionId': self.cid, 'duration': 'temporary'})
        self.assertEqual(response.status_code, 200)
        response = self.post('/api/update-keep', {
            'mediaId': '42', 'collectionId': self.cid, 'duration': 'indefinite'})
        self.assertEqual(response.status_code, 403)

    @patch.object(keep, 'get_kept_item_poster', return_value='')
    @patch.object(keep, 'get_collection_media', return_value={'items': []})
    @patch.object(keep, 'get_collection_exclusions')
    def test_basic_users_see_only_actions_for_their_own_temporary_keeps(self, exclusions, media, poster):
        exclusions.side_effect = lambda cid: {'items': [copy.deepcopy(self.item)] if cid == self.cid else []}
        keep.record_keeper(self.cid, '42', {'id': 8, 'username': 'Basic'})
        keep.remember_plex_user({'id': 8, 'username': 'Basic'}, access_verified=True)
        with closing(keep.attribution_db()) as db, db:
            db.execute("INSERT INTO user_profiles(plex_id, plex_username, plex_checked_at) VALUES ('9', 'Viewer', CURRENT_TIMESTAMP)")
        with self.client.session_transaction() as session:
            session['plex_user'] = {'id': 8, 'username': 'Basic'}
        own = self.client.get('/kept').get_data(as_text=True)
        self.assertIn('class="keep-manage-button"', own)
        self.assertIn('class="keep-button remove-kept-button"', own)
        self.assertNotIn('data-duration="indefinite"', own)

        media.return_value = {'items': [copy.deepcopy(self.item)]}
        with patch.object(keep, 'get_collection_delete_after_days', return_value=30):
            leaving = self.client.get('/').get_data(as_text=True)
        self.assertIn('data-direct-temporary="true"', leaving)
        self.assertNotIn('id="keep-duration-dialog"', leaving)

        with self.client.session_transaction() as session:
            session['plex_user'] = {'id': 9, 'username': 'Viewer'}
        other = self.client.get('/kept').get_data(as_text=True)
        self.assertNotIn('class="keep-manage-button"', other)
        self.assertNotIn('class="keep-button remove-kept-button"', other)
        self.assertNotIn('removal-info-button', other)

    @patch.object(keep, 'get_kept_item_poster', return_value='')
    @patch.object(keep, 'get_collection_media', return_value={'items': []})
    @patch.object(keep, 'get_collection_exclusions')
    def test_kept_page_shows_compact_badge_and_manage_dialog(self, exclusions, media, poster):
        exclusions.side_effect = lambda cid: {'items': [copy.deepcopy(self.item)] if cid == self.cid else []}
        keep.record_keeper(self.cid, '42', {'id': 7, 'username': 'Alice'})
        page = self.client.get('/kept').get_data(as_text=True)
        self.assertRegex(page, r'aria-label="30 days remaining\. Expires [A-Z][a-z]+ \d{1,2}, \d{4}\."')
        self.assertIn('30d', page)
        self.assertIn('class="keep-manage-button"', page)
        self.assertNotIn('class="keep-duration-status"', page)
        self.assertNotIn('class="keep-secondary-button', page)
        self.assertIn('id="keep-duration-dialog"', page)
        self.assertIn('id="manage-keep-dialog"', page)
        self.assertIn('data-option-title', page)
        self.assertIn('Keep for 30 days', page)
        self.assertIn('Recommended · expires automatically', page)
        self.assertIn('A 30-day Keep protects this title. When it expires, the title may return to Leaving if it still meets the library’s rules.', page)
        self.assertNotIn('Maintainerr', page)
        with patch.object(keep, 'get_collection_delete_after_days', return_value=30):
            leaving_page = self.client.get('/').get_data(as_text=True)
        self.assertNotIn('Maintainerr', leaving_page)

        with closing(keep.attribution_db()) as db, db:
            db.execute('UPDATE keep_schedules SET expires_at=NULL')
        page = self.client.get('/kept').get_data(as_text=True)
        self.assertIn('aria-label="Kept indefinitely"', page)
        self.assertIn('<span aria-hidden="true">∞</span>', page)
        self.assertIn('data-is-temporary="false"', page)

    @patch.object(keep.requests, 'post')
    @patch.object(keep, 'get_collection_exclusions')
    def test_expiry_releases_scoped_exclusion_and_cleans_local_state(self, exclusions, post):
        exclusions.return_value = {'items': [self.item]}
        keep.record_keeper(
            self.cid, '42', {'id': 7, 'username': 'Alice'},
            now=datetime(2026, 8, 1, tzinfo=timezone.utc),
        )
        result = keep.expire_due_keeps(datetime(2026, 9, 10, tzinfo=timezone.utc))
        self.assertEqual(result, {'released': 1, 'missing': 0, 'failed': 0})
        post.assert_called_once_with(
            f'{keep.MAINTAINERR_URL}/api/rules/exclusion',
            json={'mediaId': '42', 'collectionId': self.cid, 'action': 1}, timeout=10)
        with closing(keep.attribution_db()) as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM keep_schedules').fetchone()[0], 0)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM keep_attribution').fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM activity_log WHERE action='keep-expired'").fetchone()[0], 1)

    @patch.object(keep.requests, 'post')
    @patch.object(keep, 'get_collection_exclusions')
    def test_deselected_temporary_keep_expires_on_schedule(self, exclusions, post):
        exclusions.return_value = {'items': [self.item]}
        keep.record_keeper(self.cid, '42', {'id': 7, 'username': 'Alice'},
                           now=datetime(2026, 8, 1, tzinfo=timezone.utc))
        with patch.object(keep, 'get_collections', return_value={}):
            result = keep.expire_due_keeps(datetime(2026, 9, 10, tzinfo=timezone.utc))
        self.assertEqual(result, {'released': 1, 'missing': 0, 'failed': 0})
        exclusions.assert_called_once_with(self.cid)
        self.assertEqual(post.call_args.kwargs['json']['collectionId'], self.cid)
        with closing(keep.attribution_db()) as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM keep_schedules').fetchone()[0], 0)

    @patch.object(keep.requests, 'post')
    @patch.object(keep, 'get_collection_exclusions')
    def test_expiry_failure_retains_state_for_retry(self, exclusions, post):
        exclusions.return_value = {'items': [self.item]}
        post.return_value.raise_for_status.side_effect = keep.requests.HTTPError('offline')
        keep.record_keeper(
            self.cid, '42', {'id': 7, 'username': 'Alice'},
            now=datetime(2026, 8, 1, tzinfo=timezone.utc),
        )
        result = keep.expire_due_keeps(datetime(2026, 9, 10, tzinfo=timezone.utc))
        self.assertEqual(result, {'released': 0, 'missing': 0, 'failed': 1})
        with closing(keep.attribution_db()) as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM keep_schedules').fetchone()[0], 1)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM keep_attribution').fetchone()[0], 1)

    @patch.object(keep, 'get_collection_media')
    @patch.object(keep.requests, 'post')
    def test_failure_does_not_credit_user(self, post, media):
        media.return_value = {'items': [self.item]}
        post.return_value.raise_for_status.side_effect = keep.requests.HTTPError('failed')
        with self.assertRaises(keep.requests.HTTPError):
            self.keep_title()
        with closing(keep.attribution_db()) as db, db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM keep_attribution').fetchone()[0], 0)

    @patch.object(keep, 'get_collection_media')
    @patch.object(keep.requests, 'post')
    def test_membership_failure_preserves_successful_keep(self, post, media):
        media.return_value = {'items': [self.item]}
        self.delete.return_value.raise_for_status.side_effect = keep.requests.HTTPError('membership removal failed')
        with self.assertRaises(keep.requests.HTTPError):
            self.keep_title()
        with closing(keep.attribution_db()) as db, db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM keep_attribution').fetchone()[0], 1)

if __name__ == '__main__':
    unittest.main()
