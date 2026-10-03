"""Local HTTP session/Plex journeys without contacting integrations."""
import json
import os
import re
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlsplit

from deployment_transport import cookie_policy, private_ipv4, validate_origin
from connection_settings import ConnectionSettings
from onboarding import Onboarding
import test_keep
from test_keep import keep


class DeploymentTransportTests(unittest.TestCase):
    def test_existing_https_default_is_secure_without_an_origin(self):
        self.assertTrue(cookie_policy())
        self.assertTrue(cookie_policy('https', 'https://keep.example.test/'))
        self.assertEqual(validate_origin('https://keep.example.test/'), 'https://keep.example.test')

    def test_lan_http_requires_explicit_mode_and_private_origin(self):
        for address in ('10.0.0.2', '172.16.0.2', '192.168.50.10', '127.0.0.1'):
            with self.subTest(address=address):
                self.assertTrue(private_ipv4(address))
                self.assertFalse(cookie_policy('lan-http', f'http://{address}:5000'))
        for mode, origin in (
            ('https', 'http://192.168.1.2:5000'), ('lan-http', ''),
            ('lan-http', 'https://192.168.1.2'), ('auto', 'https://keep.example.test'),
            ('lan-http', 'http://8.8.8.8'), ('lan-http', 'http://0.0.0.0'),
            ('lan-http', 'http://169.254.1.2'), ('lan-http', 'http://100.64.0.2'),
            ('lan-http', 'http://keep.example.test'), ('lan-http', 'http://[::1]'),
            ('lan-http', 'http://user:secret@192.168.1.2'),
            ('lan-http', 'http://192.168.1.2/path'), ('lan-http', 'http://192.168.1.2?x=1'),
            ('lan-http', 'http://192.168.1.2#x'), ('lan-http', 'http://192.168.1.2:65536'),
        ):
            with self.subTest(mode=mode, origin=origin), self.assertRaises(ValueError):
                cookie_policy(mode, origin)

    def test_actual_startup_cookie_policy_and_untrusted_host(self):
        # Read the real import-time config in separate processes. No global test
        # fixture change can make an HTTPS deployment silently use HTTP cookies.
        script = """
import json
import app
client = app.app.test_client()
response = client.get('/login', base_url='http://localhost')
cookie = response.headers.get('Set-Cookie', '')
invalid = client.get('/health', base_url='http://attacker.example.test')
print(json.dumps({'secure': app.app.config['SESSION_COOKIE_SECURE'],
                  'cookie': cookie, 'invalid_host': invalid.status_code}))
"""
        for mode, origin, secure in (('https', 'https://keep.example.test', True),
                                     ('lan-http', 'http://192.168.50.10:5000', False)):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                env = {key: value for key, value in os.environ.items()
                       if not key.startswith(('KEEP_', 'PLEX_', 'SMTP_', 'EMAIL_', 'FLASK_'))}
                env.update(FLASK_SECRET_KEY='synthetic-transport-test-secret-00000',
                           KEEP_DB_PATH=directory + '/test.sqlite3', PLEX_OWNER_ID='7',
                           KEEP_URL=origin, KEEP_TRANSPORT_MODE=mode)
                result = subprocess.run([sys.executable, '-B', '-c', script], env=env,
                                        cwd=Path(__file__).resolve().parents[1],
                                        capture_output=True, text=True, timeout=30, check=True)
                data = json.loads(result.stdout)
                self.assertEqual(data['secure'], secure)
                self.assertEqual('; Secure' in data['cookie'], secure)
                self.assertIn('HttpOnly', data['cookie'])
                self.assertIn('SameSite=Lax', data['cookie'])
                if not secure:
                    self.assertEqual(data['invalid_host'], 400)


class LanHttpJourneyTests(unittest.TestCase):
    def setUp(self):
        test_keep.KeepTests.setUp(self)
        config = patch.dict(keep.app.config, KEEP_TRANSPORT_MODE='lan-http', SESSION_COOKIE_SECURE=False)
        config.start()
        self.addCleanup(config.stop)
        environment = patch.dict(os.environ, KEEP_URL='http://192.168.50.10:5000')
        environment.start()
        self.addCleanup(environment.stop)
        self.origin = 'http://192.168.50.10:5000'

    def test_first_install_cookie_survives_plex_callback_and_verified_finish(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Onboarding(directory + '/onboarding.sqlite3')
            settings = ConnectionSettings(directory + '/onboarding.sqlite3')
            with patch.object(keep, 'onboarding', store), patch.object(keep, 'connection_settings', settings):
                client = keep.app.test_client()
                code = store.issue()
                opened = client.get('/setup', base_url=self.origin)
                self.assertEqual(opened.status_code, 200)
                cookie = opened.headers['Set-Cookie']
                self.assertNotIn('; Secure', cookie)
                self.assertIn('HttpOnly', cookie)
                self.assertIn('SameSite=Lax', cookie)
                with client.session_transaction(base_url=self.origin) as session:
                    csrf = session['csrf_token']
                pin = Mock()
                pin.json.return_value = {'id': 123, 'code': 'synthetic-pin'}
                with patch.object(keep.requests, 'post', return_value=pin) as post:
                    started = client.post('/setup', base_url=self.origin,
                        data={'csrf_token': csrf, 'bootstrap_code': code})
                self.assertEqual(started.status_code, 302)
                self.assertEqual(post.call_args.args[0], 'https://plex.tv/api/v2/pins')
                self.assertFalse(post.call_args.kwargs['allow_redirects'])
                self.assertTrue(started.location.startswith('https://app.plex.tv/auth'))
                callback = parse_qs(urlsplit(started.location).fragment.lstrip('?'))['forwardUrl'][0]
                self.assertEqual(urlsplit(callback).netloc, '192.168.50.10:5000')
                state = parse_qs(urlsplit(callback).query)['state'][0]
                path = '/auth/plex/callback?state=' + state
                # A second browser cannot claim the session-bound authorization.
                with patch.object(keep.requests, 'get') as get:
                    self.assertEqual(keep.app.test_client().get(path, base_url=self.origin).status_code, 400)
                    get.assert_not_called()
                pin.json.return_value = {'authToken': 'synthetic-broad-token'}
                server = {'id': 'synthetic-machine', 'name': 'Test server',
                          'token': 'synthetic-resource-token', 'urls': ['https://plex.example.test']}
                with patch.object(keep.requests, 'get', return_value=pin) as get, \
                     patch.object(keep, 'get_plex_user', return_value={'id': '12345', 'username': 'Synthetic owner'}), \
                     patch.object(keep, 'owned_plex_servers', return_value=[server]):
                    returned = client.get(path, base_url=self.origin)
                self.assertEqual(get.call_args.args[0], 'https://plex.tv/api/v2/pins/123')
                self.assertEqual(returned.location, '/settings/connections/plex/select')
                self.assertEqual(store.owner(), '12345')
                with client.session_transaction(base_url=self.origin) as session:
                    self.assertEqual(session['plex_user']['id'], '12345')
                    self.assertNotIn('synthetic-broad-token', str(dict(session)))
                    self.assertNotIn('synthetic-resource-token', str(dict(session)))
                client.get(returned.location, base_url=self.origin)
                with client.session_transaction(base_url=self.origin) as session:
                    csrf = session['csrf_token']
                with patch.object(keep, 'test_plex') as verify, patch.object(settings, 'save', wraps=settings.save) as save:
                    chosen = client.post(returned.location, base_url=self.origin,
                        data={'csrf_token': csrf, 'server': '0'})
                self.assertEqual(chosen.location, '/setup')
                verify.assert_called_once_with('https://plex.example.test', 'synthetic-resource-token', 'synthetic-machine')
                self.assertTrue(save.call_args.kwargs['plex_override'])
                settings.save({'MAINTAINERR_URL': 'http://maintainerr'})
                with patch.object(keep, 'test_plex'), \
                     patch.object(keep, 'discover_collections', return_value={1: 'Movies'}), \
                     patch.object(keep, 'get_collections', return_value={1: 'Movies'}), \
                     patch.object(keep, 'email_enabled', return_value=False):
                    finished = client.post('/setup', base_url=self.origin, data={'csrf_token': csrf})
                self.assertEqual(finished.status_code, 200)
                self.assertFalse(store.pending())
                self.assertFalse(store.valid_code(code))
                self.assertEqual(client.get(path, base_url=self.origin).status_code, 400)
                with self.assertRaises(ValueError):
                    store.issue()

    def test_http_connect_preserves_csrf_and_owner_requirements(self):
        with patch.object(keep.requests, 'post') as post:
            self.assertEqual(self.client.post('/settings/connections/plex/connect').status_code, 403)
            post.assert_not_called()
        with keep.attribution_db() as db, db:
            db.execute("INSERT INTO user_profiles(plex_id,plex_username,plex_checked_at) VALUES ('8','Basic',CURRENT_TIMESTAMP)")
        with self.client.session_transaction() as session:
            session['plex_user'] = {'id': '8', 'username': 'Basic'}
        with patch.object(keep.requests, 'post') as post:
            self.assertEqual(self.client.post('/settings/connections/plex/connect', data={'csrf_token': 'test-csrf'}).status_code, 403)
            post.assert_not_called()

    def test_local_setup_link_and_password_login_work_on_lan_without_email(self):
        with patch.dict(os.environ, EMAIL_ENABLED='false'), patch.object(keep, 'send_email') as mail:
            created = self.client.post('/settings/users/local', data={
                'csrf_token': 'test-csrf', 'email': 'lan-member@example.test',
                'full_name': 'LAN Member', 'display_name': 'Member'})
        self.assertEqual(created.status_code, 200)
        self.assertIn('no-store', created.headers['Cache-Control'])
        self.assertEqual(created.headers['Referrer-Policy'], 'no-referrer')
        link = re.search(r'value="(http://192\.168\.50\.10:5000/auth/local/setup/[A-Za-z0-9_-]+)"',
                         created.get_data(as_text=True)).group(1)
        mail.assert_not_called()
        member = keep.app.test_client()
        setup_path = urlsplit(link).path
        opened = member.get(setup_path, base_url=self.origin)
        self.assertEqual(opened.status_code, 200)
        self.assertNotIn('; Secure', opened.headers['Set-Cookie'])
        with member.session_transaction(base_url=self.origin) as session:
            csrf = session['csrf_token']
        password = 'synthetic LAN password only'
        saved = member.post(setup_path, base_url=self.origin, data={
            'csrf_token': csrf, 'password': password, 'confirm_password': password})
        self.assertEqual(saved.status_code, 200)
        self.assertEqual(member.get(setup_path, base_url=self.origin).status_code, 400)
        faq = member.get('/help', base_url=self.origin).get_data(as_text=True)
        self.assertNotIn('id="api"', faq)
        self.assertNotIn('href="#api"', faq)
        member.get('/logout', base_url=self.origin)
        member.get('/login', base_url=self.origin)
        with member.session_transaction(base_url=self.origin) as session:
            csrf = session['csrf_token']
        signed_in = member.post('/auth/local', base_url=self.origin, data={
            'csrf_token': csrf, 'email': 'lan-member@example.test', 'password': password})
        self.assertEqual(signed_in.location, '/')
        self.assertIn('HttpOnly', signed_in.headers['Set-Cookie'])
        self.assertNotIn('; Secure', signed_in.headers['Set-Cookie'])
        self.assertEqual(member.get('/settings/api-keys', base_url=self.origin).status_code, 403)

    def test_forwarded_headers_cannot_enable_http_in_https_mode(self):
        with patch.dict(keep.app.config, KEEP_TRANSPORT_MODE='https', SESSION_COOKIE_SECURE=True), \
             patch.object(keep.requests, 'post') as post:
            response = self.client.post('/settings/connections/plex/connect',
                data={'csrf_token': 'test-csrf'}, headers={'X-Forwarded-Proto': 'http'})
        self.assertEqual(response.status_code, 400)
        post.assert_not_called()


if __name__ == '__main__':
    unittest.main()
