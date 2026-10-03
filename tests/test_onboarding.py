import concurrent.futures
import json
import sqlite3
import tempfile
import time
import unittest
from unittest.mock import patch
from onboarding import Onboarding, digest


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = self.directory.name + '/test.sqlite3'
        self.store = Onboarding(self.path)

    def test_code_is_hashed_rotated_and_single_use(self):
        old = self.store.issue()
        code = self.store.issue()
        self.assertFalse(self.store.valid_code(old))
        with sqlite3.connect(self.path) as db:
            self.assertNotIn(code, str(db.execute('SELECT * FROM bootstrap').fetchall()))
        self.store.claim(digest(code), '7')
        self.assertEqual(self.store.owner(), '7')
        self.assertTrue(self.store.pending())
        with self.assertRaises(ValueError):
            self.store.claim(digest(code), '8')
        with self.assertRaises(ValueError):
            self.store.issue()
        self.store.finish()
        self.assertFalse(Onboarding(self.path).pending())

    def test_concurrent_claims_have_exactly_one_winner(self):
        code = self.store.issue()
        def claim(owner):
            try:
                self.store.claim(digest(code), owner)
                return True
            except ValueError:
                return False
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            self.assertEqual(sum(executor.map(claim, ['7', '8'])), 1)

    def test_expiry_and_invalid_identity_do_not_claim(self):
        code = self.store.issue()
        with self.assertRaises(ValueError):
            self.store.claim(digest(code), 'local:7')
        self.assertTrue(self.store.valid_code(code))
        with patch('onboarding.time.time', return_value=time.time() + 601):
            with self.assertRaises(ValueError):
                self.store.claim(digest(code), '7')
        self.assertEqual(self.store.owner(), '')

    def test_legacy_owner_is_complete_and_cannot_be_reassigned(self):
        existing = Onboarding(self.path, '7')
        self.assertFalse(existing.pending())
        with self.assertRaises(ValueError):
            Onboarding(self.path, '8')
        self.assertEqual(Onboarding(self.path).owner(), '7')

    def test_legacy_profiles_prevent_bootstrap(self):
        with sqlite3.connect(self.path) as db:
            db.execute('CREATE TABLE user_profiles (id TEXT)')
            db.execute("INSERT INTO user_profiles VALUES ('retained')")
        with self.assertRaises(ValueError):
            self.store.issue()

    def test_profiles_added_after_code_issuance_prevent_claim(self):
        code = self.store.issue()
        with sqlite3.connect(self.path) as db:
            db.execute('CREATE TABLE user_profiles (id TEXT)')
            db.execute("INSERT INTO user_profiles VALUES ('retained')")
        with self.assertRaises(ValueError):
            self.store.claim(digest(code), '7')
        self.assertEqual(self.store.owner(), '')

    def test_flow_binding_expiry_and_atomic_replay_protection(self):
        key = self.store.put_flow('browser-one', 'connect', {'token': 'private'})
        self.assertIsNone(self.store.take_flow(key, 'browser-two'))
        self.assertEqual(self.store.take_flow(key, 'browser-one')[0], 'connect')
        self.assertIsNone(self.store.take_flow(key, 'browser-one'))
        key = self.store.put_flow('browser-one', 'connect', {})
        with patch('onboarding.time.time', return_value=time.time() + 601):
            self.assertIsNone(self.store.take_flow(key, 'browser-one'))


# Reuse the isolated application fixture, never live services.
from test_keep import keep, KeepTests


class PlexFlowTests(unittest.TestCase):
    setUp = KeepTests.setUp
    def test_login_requires_csrf_and_callback_requires_binding(self):
        self.assertEqual(self.client.post('/auth/plex').status_code, 403)
        with patch.object(keep.requests, 'get') as get:
            self.assertEqual(self.client.get('/auth/plex/callback?state=forged').status_code, 400)
            get.assert_not_called()

    def test_owned_resource_filter_and_no_account_token_fallback(self):
        row = {'owned': True, 'provides': 'server', 'product': 'Plex Media Server',
               'clientIdentifier': 'machine', 'accessToken': 'resource-secret',
               'connections': [{'uri': 'https://plex.example:32400'}, {'uri': 'http://plex:32400'}]}
        rows = [row, {**row, 'owned': False}, {**row, 'accessToken': ''}, {**row, 'owned': 'false'}]
        with patch('service_discovery.read_service', return_value=json.dumps(rows).encode()):
            servers = keep.owned_plex_servers('broad-account-secret')
        self.assertEqual(len(servers), 1)
        self.assertEqual(servers[0]['urls'], ['https://plex.example:32400'])
        self.assertNotIn('broad-account-secret', str(servers))

    def selection(self):
        key = keep.onboarding.put_flow('selection-browser', 'selection', {'owner': '7', 'servers': [
            {'id': 'machine', 'name': '<Server>', 'token': 'resource-private-secret', 'urls': ['https://plex.example']}]})
        with self.client.session_transaction() as session:
            session['plex_selection'] = key
            session['plex_selection_binding'] = 'selection-browser'
        return key

    def test_selection_html_cookie_and_failures_never_contain_token(self):
        self.selection()
        response = self.client.get('/settings/connections/plex/select')
        self.assertEqual(response.status_code, 200)
        self.assertIn('no-store', response.headers['Cache-Control'])
        self.assertNotIn('resource-private-secret', response.get_data(as_text=True) + str(response.headers))
        self.assertIn('&lt;Server&gt;', response.get_data(as_text=True))
        with patch.dict(keep.os.environ, {}, clear=True), patch.object(keep, 'test_plex', side_effect=ValueError('resource-private-secret')):
            response = self.client.post('/settings/connections/plex/select', data={'csrf_token': 'test-csrf', 'server': '0'})
        self.assertEqual(response.status_code, 400)
        self.assertNotIn('resource-private-secret', response.get_data(as_text=True))
        self.assertEqual(self.client.get('/settings/connections/plex/select').status_code, 400)

    def test_environment_fallback_does_not_block_connection_and_selection(self):
        with patch.dict(keep.os.environ, KEEP_URL='https://keep.example.test'), patch.object(keep.requests, 'post') as post:
            post.return_value.json.return_value = {'id': 123, 'code': 'synthetic-pin'}
            self.assertEqual(self.client.post('/settings/connections/plex/connect', data={'csrf_token': 'test-csrf'}).status_code, 302)
        self.selection()
        with patch.object(keep, 'test_plex') as probe, patch.object(keep.connection_settings, 'save') as save:
            response = self.client.post('/settings/connections/plex/select', data={'csrf_token': 'test-csrf', 'server': '0'})
        self.assertEqual(response.status_code, 302)
        probe.assert_called_once_with('https://plex.example', 'resource-private-secret', 'machine')
        save.assert_called_once_with({'PLEX_SERVER_URL': 'https://plex.example',
            'PLEX_MACHINE_IDENTIFIER': 'machine', 'PLEX_ADMIN_TOKEN': 'resource-private-secret'},
            plex_override=True)

    def test_non_owner_cannot_connect(self):
        with self.client.session_transaction() as session:
            session['plex_user']['id'] = '8'
        with patch.object(keep.requests, 'post') as post:
            self.assertNotEqual(self.client.post('/settings/connections/plex/connect', data={'csrf_token': 'test-csrf'}).status_code, 200)
            post.assert_not_called()

    def test_wrong_plex_identity_cannot_reconnect(self):
        key = keep.onboarding.put_flow('browser', 'connect', {'pin': 1, 'code': 'code', 'owner': '7'})
        with self.client.session_transaction() as session:
            session['plex_binding'] = 'browser'
        with patch.object(keep.requests, 'get') as get, patch.object(keep, 'get_plex_user', return_value={'id': '8'}), patch.object(keep, 'owned_plex_servers') as resources:
            get.return_value.json.return_value = {'authToken': 'private'}
            response = self.client.get('/auth/plex/callback?state=' + key)
        self.assertEqual(response.status_code, 403)
        resources.assert_not_called()

    def test_verify_before_save_and_replay_does_not_save(self):
        self.selection()
        with patch.dict(keep.os.environ, {}, clear=True), patch.object(keep, 'test_plex') as probe, patch.object(keep.connection_settings, 'save') as save:
            response = self.client.post('/settings/connections/plex/select', data={'csrf_token': 'test-csrf', 'server': '0'})
            self.assertEqual(response.status_code, 302)
            probe.assert_called_once_with('https://plex.example', 'resource-private-secret', 'machine')
            save.assert_called_once()
            response = self.client.post('/settings/connections/plex/select', data={'csrf_token': 'test-csrf', 'server': '0'})
            self.assertEqual(response.status_code, 400)
            save.assert_called_once()



# The imported fixture class must not be discovered a second time.
del KeepTests

class FirstRunJourneyTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.store = Onboarding(self.directory.name + '/setup.db')
        self.patch = patch.object(keep, 'onboarding', self.store)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.client = keep.app.test_client()
        with self.client.session_transaction() as session:
            session['csrf_token'] = 'bootstrap-csrf'
        with keep.attribution_db() as db:
            db.execute("DELETE FROM user_profiles WHERE plex_id='12345'")
            db.commit()

    def callback(self, code, user=None, resources=None):
        state = self.store.put_flow('browser', 'bootstrap', {'pin': 1, 'code': 'pin-code', 'bootstrap': digest(code)})
        with self.client.session_transaction() as session:
            session['plex_binding'] = 'browser'
        user = user or {'id': '12345', 'username': 'Synthetic Owner', 'email': '', 'thumb': ''}
        if resources is None:
            resources = [{'id': 'machine', 'name': 'Synthetic Plex', 'token': 'resource-secret', 'urls': ['https://plex.example']}]
        with patch.object(keep.requests, 'get') as get, patch.object(keep, 'get_plex_user', return_value=user), patch.object(keep, 'owned_plex_servers', return_value=resources):
            get.return_value.json.return_value = {'authToken': 'broad-secret'}
            return self.client.get('/auth/plex/callback?state=' + state)

    def test_first_visitor_cannot_claim_and_no_server_does_not_consume(self):
        self.assertEqual(self.client.get('/').location, '/setup')
        self.assertEqual(self.client.post('/setup', data={'bootstrap_code': 'guess'}).status_code, 403)
        code = self.store.issue()
        self.assertEqual(self.callback(code, resources=[]).status_code, 400)
        self.assertTrue(self.store.valid_code(code))
        self.assertEqual(self.store.owner(), '')

    def test_claim_selection_resume_and_verified_finish(self):
        code = self.store.issue()
        response = self.callback(code)
        self.assertEqual(response.location, '/settings/connections/plex/select')
        self.assertEqual(self.store.owner(), '12345')
        self.assertFalse(self.store.valid_code(code))
        self.assertEqual(self.client.get('/').location, '/setup')
        self.assertEqual(self.client.get('/setup').status_code, 200)
        with self.client.session_transaction() as session:
            self.assertNotIn('broad-secret', str(dict(session)))
            self.assertNotIn('resource-secret', str(dict(session)))
            session['csrf_token'] = 'bootstrap-csrf'
        with patch.object(keep, 'test_plex'), patch.object(keep, 'discover_collections', return_value={1: 'Movies'}), patch.object(keep, 'get_collections', return_value={1: 'Movies'}), patch.object(keep, 'email_enabled', return_value=False):
            response = self.client.post('/setup', data={'csrf_token': 'bootstrap-csrf'})
        self.assertEqual(response.status_code, 200)
        self.assertIn('Setup verified', response.get_data(as_text=True))
        self.assertFalse(self.store.pending())
        self.assertEqual(self.store.owner(), '12345')
        self.assertEqual(self.client.get('/setup').location, '/settings/connections')

    def test_expired_bootstrap_after_authentication_cannot_claim(self):
        code = self.store.issue()
        with self.store.db() as db:
            db.execute('UPDATE bootstrap SET expires=0')
        self.assertEqual(self.callback(code).status_code, 400)
        self.assertFalse(self.store.owner())

    def test_failed_service_verification_keeps_setup_resumable(self):
        self.callback(self.store.issue())
        with self.client.session_transaction() as session:
            session['csrf_token'] = 'bootstrap-csrf'
        with patch.object(keep, 'test_plex', side_effect=ValueError('private-secret')):
            response = self.client.post('/setup', data={'csrf_token': 'bootstrap-csrf'})
        self.assertTrue(self.store.pending())
        self.assertNotIn('private-secret', response.get_data(as_text=True))
        self.assertIn('Verification failed', response.get_data(as_text=True))

class CallbackSessionTests(unittest.TestCase):
    setUp = PlexFlowTests.setUp

    def test_revoked_owner_session_cannot_finish_reconnect(self):
        client = keep.app.test_client()
        owner = keep.owner_id()
        with keep.attribution_db() as db:
            row = db.execute('SELECT session_version FROM user_profiles WHERE plex_id=?', (owner,)).fetchone()
        key = keep.onboarding.put_flow('revoked-browser', 'connect', {'pin': 1, 'code': 'code', 'owner': owner})
        with client.session_transaction() as session:
            session['plex_user'] = {'id': owner, 'session_version': row[0] - 1}
            session['plex_binding'] = 'revoked-browser'
        with patch.object(keep.requests, 'get') as get:
            self.assertEqual(client.get('/auth/plex/callback?state=' + key).status_code, 403)
            get.assert_not_called()

    def test_login_page_posts_with_csrf_without_extra_confirmation(self):
        client = keep.app.test_client()
        response = client.get('/login')
        self.assertIn('method="post" action="/auth/plex"', response.get_data(as_text=True))
        self.assertIn('name="csrf_token"', response.get_data(as_text=True))
