"""Plex proof ages independently of sessions, keys and ordinary Keep activity."""
import unittest
import threading
from contextlib import closing
from unittest.mock import Mock, patch

import test_api_v1

keep = test_api_v1.keep
api = keep.app.extensions['keep_api']


class PlexAccessLeaseTests(unittest.TestCase):
    setUp = test_api_v1.ApiV1Tests.setUp
    login = test_api_v1.ApiV1Tests.login
    make_key = test_api_v1.ApiV1Tests.make_key
    bearer_client = test_api_v1.ApiV1Tests.bearer_client
    auth = test_api_v1.ApiV1Tests.auth

    def expire(self, visible=0):
        with closing(keep.attribution_db()) as db, db:
            db.execute("""UPDATE user_profiles SET plex_checked_at='2000-01-01 00:00:00',
                          plex_sync_visible=? WHERE plex_id='8'""", (visible,))

    def profile(self, user_id='8'):
        with closing(keep.attribution_db()) as db:
            return db.execute('SELECT * FROM user_profiles WHERE plex_id=?', (user_id,)).fetchone()

    def test_expired_proof_blocks_browser_keys_and_management_without_worker(self):
        for visible in (0, 1):
            with self.subTest(visible=visible):
                keep.remember_plex_user({'id': '8'}, access_verified=True)
                with closing(keep.attribution_db()) as db, db:
                    db.execute("UPDATE user_profiles SET session_version=0 WHERE plex_id='8'")
                token = self.make_key(user_id='8')
                self.expire(visible)
                with patch.object(keep, 'get_authorized_plex_user_ids', return_value=None):
                    self.assertIsNone(keep.sync_plex_user_access())
                response = self.auth(token, path='/api/v1/keeps')
                self.assertEqual(response.status_code, 401)
                self.assertEqual(response.json['error']['code'], 'invalid_token')
                self.assertEqual(self.client.get('/account/api-keys').status_code, 302)
                with self.client.session_transaction() as session:
                    self.assertNotIn('plex_user', session)

    def test_current_omitted_account_survives_feed_absence(self):
        token = self.make_key(user_id='8')
        before = self.profile()['plex_checked_at']
        with patch.object(keep, 'get_authorized_plex_user_ids', return_value={'7'}):
            self.assertEqual(keep.sync_plex_user_access(), 0)
        profile = self.profile()
        self.assertEqual(profile['plex_access'], 'active')
        self.assertEqual(profile['plex_sync_visible'], 0)
        self.assertEqual(profile['plex_checked_at'], before)
        self.assertEqual(self.client.get('/settings/api-keys').status_code, 403)
        self.assertEqual(self.client.get('/help').status_code, 200)
        self.assertEqual(self.auth(token, path='/api/v1/keeps').status_code, 200)

    def test_expired_omitted_account_is_revoked_and_version_changes(self):
        self.expire()
        with patch.object(keep, 'get_authorized_plex_user_ids', return_value={'7'}):
            self.assertEqual(keep.sync_plex_user_access(), 1)
        profile = self.profile()
        self.assertEqual(profile['plex_access'], 'revoked')
        self.assertEqual(profile['session_version'], 1)
        self.assertEqual(profile['plex_sync_visible'], 0)

    def test_keep_metadata_does_not_renew_or_restore_authorization(self):
        self.expire()
        before = self.profile()['plex_checked_at']
        keep.record_keeper(1, '42', {'id': '8', 'username': 'member'})
        self.assertEqual(self.profile()['plex_checked_at'], before)
        self.assertFalse(keep.plex_account_access_active(self.profile()))
        keep.mark_plex_access('8', 'revoked')
        before = self.profile()['plex_checked_at']
        keep.remember_plex_user({'id': '8', 'username': 'new label'})
        self.assertEqual(self.profile()['plex_access'], 'revoked')
        self.assertEqual(self.profile()['plex_checked_at'], before)
        self.assertEqual(self.profile()['plex_username'], 'new label')

    def test_fresh_verified_callback_renews_access_but_old_keys_stay_invalid(self):
        token = self.make_key(user_id='8')
        self.expire()
        with self.client.session_transaction() as session:
            session['plex_binding'] = 'lease-test-binding'
        state = keep.onboarding.put_flow('lease-test-binding', 'login', {'pin': 123, 'code': 'test-code'})
        pin = Mock()
        pin.json.return_value = {'authToken': 'synthetic-plex-token'}
        user = {'id': 8, 'username': 'member', 'email': 'member@example.com', 'thumb': ''}
        with patch.object(keep.requests, 'get', return_value=pin), \
             patch.object(keep, 'get_plex_user', return_value=user), \
             patch.object(keep, 'plex_user_has_server_access', return_value=True):
            response = self.client.get('/auth/plex/callback?state=' + state)
        self.assertEqual(response.status_code, 302)
        self.assertTrue(keep.plex_account_access_active(self.profile()))
        self.assertEqual(self.profile()['session_version'], 1)
        self.assertEqual(self.auth(token, path='/api/v1/keeps').status_code, 401)
        self.assertEqual(self.client.get('/settings/api-keys').status_code, 403)
        self.assertEqual(self.client.get('/help').status_code, 200)
        with self.client.session_transaction() as session:
            session['csrf_token'] = 'test-csrf'
        new = self.client.post('/account/api-keys', data={'csrf_token': 'test-csrf',
            'action': 'create', 'name': 'renewed integration', 'expiry_days': '90', 'scope': 'keeps:read'})
        self.assertEqual(new.status_code, 403)
        self.assertNotIn('id="new-api-key"', new.get_data(as_text=True))

    def test_positive_sync_after_expiry_cannot_resurrect_old_credentials(self):
        token = self.make_key(user_id='8')
        self.expire(1)
        with patch.object(keep, 'get_authorized_plex_user_ids', return_value={'7', '8'}):
            keep.sync_plex_user_access()
        self.assertTrue(keep.plex_account_access_active(self.profile()))
        self.assertEqual(self.profile()['session_version'], 1)
        self.assertEqual(self.auth(token, path='/api/v1/keeps').status_code, 401)

    def test_missing_malformed_or_future_proof_fails_closed(self):
        for value in (None, '', 'invalid', '2999-01-01 00:00:00'):
            with self.subTest(value=value):
                with closing(keep.attribution_db()) as db, db:
                    db.execute("UPDATE user_profiles SET plex_checked_at=? WHERE plex_id='8'", (value,))
                self.assertFalse(keep.plex_account_access_active(self.profile()))
        self.assertTrue(keep.plex_account_access_active(self.profile('7')))
        with closing(keep.attribution_db()) as db, db:
            db.execute("UPDATE user_profiles SET auth_type='local' WHERE plex_id='8'")
        self.assertTrue(keep.plex_account_access_active(self.profile()))

    def test_proof_expiry_during_api_lookup_prevents_remote_mutation(self):
        token = self.make_key(user_id='8')
        def feed(cid, resource, deadline):
            self.expire()
            return [] if resource == 'exclusions' else [{'mediaServerId': '42'}]
        with patch.object(api, 'feed', side_effect=feed), patch.object(api, 'exclusion_write') as write:
            response = self.auth(token, method='POST', path='/api/v1/keeps',
                json={'collection_id': 1, 'media_id': '42'},
                headers={'Idempotency-Key': 'lease-expiry-request-0001'})
        self.assertEqual(response.status_code, 401)
        write.assert_not_called()

    def test_proof_expiry_during_browser_lookup_prevents_keep_changes(self):
        for path in ('/api/keep', '/api/remove-kept', '/api/update-keep'):
            with self.subTest(path=path):
                keep.remember_plex_user({'id': '8'}, access_verified=True)
                version = self.profile()['session_version']
                with self.client.session_transaction() as session:
                    session['plex_user'] = {'id': '8', 'username': 'member', 'session_version': version}
                    session['csrf_token'] = 'test-csrf'
                def loader(cid):
                    self.expire()
                    return {'items': [{'id': 91, 'mediaServerId': '42'}]}
                with patch.object(keep, 'get_collection_media', side_effect=loader), \
                     patch.object(keep, 'get_collection_exclusions', side_effect=loader), \
                     patch.object(keep, 'change_maintainerr_exclusion') as write:
                    response = self.client.post(path, json={'collectionId': 1, 'mediaId': '42',
                        'exclusionId': 91, 'duration': 'temporary'}, headers={'X-CSRF-Token': 'test-csrf'})
                self.assertEqual(response.status_code, 403)
                write.assert_not_called()

    def test_login_renewal_serializes_with_access_sync_snapshot(self):
        self.expire()
        read = threading.Event()
        release = threading.Event()
        login_started = threading.Event()
        login_finished = threading.Event()
        failures = []
        original = keep.plex_account_access_active
        def pause_before_first_write(profile):
            if threading.current_thread().name == 'lease-sync' and profile['plex_id'] == '7':
                read.set()
                if not release.wait(3):
                    raise AssertionError('Access sync was not released')
            return original(profile)
        def sync():
            try:
                keep.sync_plex_user_access()
            except BaseException as error:
                failures.append(error)
        def login():
            try:
                login_started.set()
                keep.remember_plex_user({'id': '8'}, access_verified=True)
                login_finished.set()
            except BaseException as error:
                failures.append(error)
        worker = threading.Thread(target=sync, name='lease-sync')
        renewal = threading.Thread(target=login, name='lease-login')
        with patch.object(keep, 'get_authorized_plex_user_ids', return_value={'7'}), \
             patch.object(keep, 'plex_account_access_active', side_effect=pause_before_first_write):
            worker.start()
            try:
                self.assertTrue(read.wait(3))
                renewal.start()
                self.assertTrue(login_started.wait(3))
                self.assertFalse(login_finished.wait(0.2))
            finally:
                release.set()
                worker.join(3)
                if renewal.ident is not None:
                    renewal.join(3)
        self.assertFalse(worker.is_alive())
        self.assertFalse(renewal.is_alive())
        self.assertEqual(failures, [])
        self.assertTrue(login_finished.is_set())
        self.assertTrue(keep.plex_account_access_active(self.profile()))
        self.assertEqual(self.profile()['session_version'], 1)
