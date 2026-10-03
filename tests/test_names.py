import copy
import os
import unittest
from contextlib import closing
from html.parser import HTMLParser
from unittest.mock import Mock, patch
from test_keep import keep


class SettingsTests(unittest.TestCase):
    def setUp(self):
        keep.app.config.update(TESTING=True)
        self.client = keep.app.test_client()
        with closing(keep.attribution_db()) as db, db:
            db.execute('DELETE FROM user_library_permissions')
            db.execute('DELETE FROM user_feature_acknowledgements')
            db.execute('DELETE FROM media_libraries')
            db.execute('DELETE FROM recipient_subscriptions')
            db.execute('DELETE FROM user_profiles')
            db.execute('DELETE FROM email_recipients')
            db.execute('DELETE FROM auth_rate_limits')
            db.execute('DELETE FROM activity_log')
            db.execute("""INSERT INTO user_profiles
                (plex_id, plex_username, email, full_name, display_name, plex_checked_at)
                VALUES ('7', 'testowner', 'owner@example.com',
                        'Alex Morgan', 'Alex W', CURRENT_TIMESTAMP)""")
            db.execute("INSERT INTO email_recipients(email) VALUES ('one@example.com')")
            keep.ensure_recipient_subscriptions(db, 'one@example.com')
            db.execute('DELETE FROM keep_attribution')
        with self.client.session_transaction() as session:
            session['plex_user'] = {'id': 7, 'username': 'testowner', 'email': 'owner@example.com'}
            session['csrf_token'] = 'test-csrf'

    def form(self, path, **data):
        return self.client.post(path, data={'csrf_token': 'test-csrf', **data})

    def create_local(self, email='local@example.com', add_recipient=False):
        with patch.object(keep, 'send_local_setup_email') as mail:
            fields = dict(email=email, full_name='Local Person', display_name='Local P')
            if add_recipient:
                fields['add_recipient'] = '1'
            response = self.form('/settings/users/local', **fields)
        self.assertEqual(response.status_code, 302)
        token = mail.call_args.args[1]
        with closing(keep.attribution_db()) as db:
            profile = db.execute(
                "SELECT * FROM user_profiles WHERE auth_type='local' AND email=?", (email,)
            ).fetchone()
        return profile, token

    def test_account_disclosures_keep_action_forms_independent_and_copy_matches_delivery(self):
        from html.parser import HTMLParser
        class Forms(HTMLParser):
            def __init__(self):
                super().__init__()
                self.depth = 0
                self.nested = False
                self.forms = {}
                self.buttons = []
            def handle_starttag(self, tag, attrs):
                attrs = dict(attrs)
                if tag == 'form':
                    self.nested |= self.depth > 0
                    self.depth += 1
                    if 'id' in attrs:
                        self.forms[attrs['id']] = attrs.get('action')
                if tag == 'button' and 'form' in attrs:
                    self.buttons.append(attrs['form'])
            def handle_endtag(self, tag):
                if tag == 'form':
                    self.depth -= 1
        self.create_local()
        for enabled in (False, True):
            with patch.object(keep, 'email_enabled', return_value=enabled):
                body = self.client.get('/settings/users').get_data(as_text=True)
            self.assertIn('<article class="user-card">', body)
            self.assertIn('Keep emails a single-use setup link.' if enabled else
                          'Keep provides a private, single-use setup link for you to share.', body)
            self.assertIn('Resend setup link' if enabled else 'Get setup link', body)
            parser = Forms()
            parser.feed(body)
            self.assertFalse(parser.nested)
            self.assertGreater(len(parser.buttons), 0)
            for target in parser.buttons:
                self.assertIn(target, parser.forms)
                self.assertTrue(parser.forms[target].endswith('/access'))

    def test_owner_settings_page_and_name_update(self):
        landing = self.client.get('/settings')
        self.assertEqual(landing.status_code, 302)
        self.assertEqual(landing.headers['Location'], '/settings/users')
        page = self.client.get('/settings/users')
        self.assertEqual(page.status_code, 200)
        body = page.get_data(as_text=True)
        self.assertIn('Keep Admin', body)
        self.assertIn('href="/settings/users" class="active"', body)
        self.assertNotIn('Active recipients', body)
        self.assertNotIn('Recent activity', body)
        self.assertIn('Alex Morgan', body)
        self.assertIn('class="source source-plex">plex</span>', body)
        self.assertRegex(body, r'class="source source-owner"><svg[^>]+aria-hidden="true">.*?</svg>Owner</span>')
        self.assertIn('class="status on">Active</span>', body)
        self.assertIn('Can manage anyone’s keeps', body)
        self.assertIn('Can keep titles indefinitely', body)
        self.assertIn('Library access', body)
        self.assertIn('Delete any title', body)
        self.assertIn('Owner permission is permanent', body)
        response = self.form('/settings/users/7', full_name=' Alex Ray Morgan ',
                             display_name=' Alex W ')
        self.assertEqual(response.status_code, 302)
        with closing(keep.attribution_db()) as db:
            row = db.execute("SELECT * FROM user_profiles WHERE plex_id='7'").fetchone()
        self.assertEqual(row['full_name'], 'Alex Ray Morgan')
        self.assertEqual(row['display_name'], 'Alex W')

    def test_admin_saved_notice_is_one_time_and_auto_dismisses(self):
        response = self.form('/settings/users/7', full_name='Alex Morgan',
                             display_name='Alex W')
        self.assertEqual(response.headers['Location'], '/settings/users')
        first_page = self.client.get('/settings/users').get_data(as_text=True)
        self.assertIn('id="settings-saved-notice"', first_page)
        self.assertIn('User names saved.', first_page)
        self.assertIn('savedNotice.classList.add("dismissed")', first_page)
        self.assertIn('}, 3500);', first_page)
        refreshed_page = self.client.get('/settings/users').get_data(as_text=True)
        self.assertNotIn('id="settings-saved-notice"', refreshed_page)
        self.assertNotIn('User names saved.', refreshed_page)

    def test_owner_can_grant_and_revoke_remove_any_permission(self):
        with closing(keep.attribution_db()) as db, db:
            db.execute("""INSERT INTO user_profiles(plex_id, plex_username)
                          VALUES ('8', 'friend')""")
        response = self.form('/settings/users/8', full_name='Friend Person',
                             display_name='Friend P', can_remove_any='1')
        self.assertEqual(response.status_code, 302)
        self.assertTrue(keep.can_remove_any_keep({'id': 8}))
        response = self.form('/settings/users/8', full_name='Friend Person',
                             display_name='Friend P')
        self.assertEqual(response.status_code, 302)
        self.assertFalse(keep.can_remove_any_keep({'id': 8}))

    def test_owner_can_grant_indefinite_and_scoped_library_permissions(self):
        with closing(keep.attribution_db()) as db, db:
            db.execute("INSERT INTO user_profiles(plex_id, plex_username) VALUES ('8', 'friend')")
            db.execute("""INSERT INTO media_libraries
                (library_key, service, external_id, name, path)
                VALUES ('radarr:4', 'radarr', '4', 'Movies', '/media/movies'),
                       ('sonarr:7', 'sonarr', '7', 'TV Shows', '/media/tv')""")
        response = self.form('/settings/users/8', full_name='Friend Person',
                             display_name='Friend P', can_keep_indefinitely='1',
                             can_delete_media='1', library_key='radarr:4')
        self.assertEqual(response.status_code, 302)
        capabilities = keep.user_capabilities({'id': 8})
        self.assertTrue(capabilities['keep_indefinitely'])
        self.assertTrue(capabilities['delete_media'])
        self.assertFalse(capabilities['delete_any'])
        self.assertEqual(keep.granted_library_keys({'id': 8}), {'radarr:4'})
        page = self.client.get('/settings/users').get_data(as_text=True)
        self.assertIn('value="radarr:4"', page)
        self.assertIn('Movies<small>Radarr</small>', page)
        self.assertIn('.library-permissions[hidden] { display:none; }', page)
        self.assertIn('data-library-permission-toggle', page)

        self.form('/settings/users/8', full_name='Friend Person', display_name='Friend P',
                  can_delete_media='1', can_delete_any='1', library_key='radarr:4')
        self.assertTrue(keep.user_capabilities({'id': 8})['delete_any'])
        self.assertEqual(keep.granted_library_keys({'id': 8}), {'radarr:4'})

        self.form('/settings/users/8', full_name='Friend Person', display_name='Friend P')
        self.assertFalse(keep.user_capabilities({'id': 8})['keep_indefinitely'])
        self.assertFalse(keep.user_capabilities({'id': 8})['delete_media'])
        self.assertFalse(keep.user_capabilities({'id': 8})['delete_any'])
        self.assertEqual(keep.granted_library_keys({'id': 8}), set())

    def test_non_owner_cannot_view_or_modify_settings(self):
        with closing(keep.attribution_db()) as db, db:
            db.execute("INSERT INTO user_profiles(plex_id, plex_username, plex_checked_at) VALUES ('8', 'friend', CURRENT_TIMESTAMP)")
        with self.client.session_transaction() as session:
            session['plex_user'] = {'id': 8, 'username': 'friend'}
        self.assertEqual(self.client.get('/settings').status_code, 403)
        self.assertEqual(self.client.get('/settings/users').status_code, 403)
        self.assertEqual(self.client.get('/settings/email').status_code, 403)
        self.assertEqual(self.client.get('/settings/activity').status_code, 403)
        self.assertEqual(self.form('/settings/users/7', full_name='Changed', display_name='Bad').status_code, 403)
        self.assertEqual(self.form('/settings/recipients', action='add', email='bad@example.com').status_code, 403)
        self.assertEqual(self.form('/settings/recipients/preferences', email='one@example.com',
                                   collection_id='1').status_code, 403)
        self.assertEqual(self.form('/settings/users/local', email='x@example.com',
                                   full_name='X Person', display_name='X').status_code, 403)
        with closing(keep.attribution_db()) as db:
            self.assertEqual(db.execute("SELECT full_name FROM user_profiles WHERE plex_id='7'").fetchone()[0],
                             'Alex Morgan')
            self.assertEqual(db.execute('SELECT COUNT(*) FROM email_recipients').fetchone()[0], 1)

    def test_csrf_required_for_settings_writes(self):
        self.assertEqual(self.client.post('/settings/users/7', data={}).status_code, 403)
        self.assertEqual(self.client.post('/settings/recipients', data={}).status_code, 403)
        self.assertEqual(self.client.post('/settings/recipients/preferences', data={}).status_code, 403)
        self.assertEqual(self.client.post('/settings/users/local', data={}).status_code, 403)

    def test_local_user_email_setup_and_login(self):
        profile, token = self.create_local()
        self.assertEqual(profile['status'], 'pending')
        self.assertFalse(profile['password_hash'])
        self.assertEqual(profile['invite_token_hash'], keep.token_digest(token))
        self.assertNotEqual(profile['invite_token_hash'], token)
        self.assertEqual(self.client.get('/auth/local/setup/' + token).status_code, 200)
        password = 'a long local password'
        response = self.form('/auth/local/setup/' + token,
                             password=password, confirm_password=password)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Password saved', response.get_data(as_text=True))
        with closing(keep.attribution_db()) as db:
            saved = db.execute("SELECT * FROM user_profiles WHERE plex_id=?",
                               (profile['plex_id'],)).fetchone()
        self.assertEqual(saved['status'], 'active')
        self.assertIsNone(saved['invite_token_hash'])
        self.assertTrue(keep.password_hasher.verify(saved['password_hash'], password))
        self.assertEqual(self.client.get('/auth/local/setup/' + token).status_code, 400)

        self.client.get('/logout')
        with self.client.session_transaction() as session:
            session['csrf_token'] = 'test-csrf'
        response = self.form('/auth/local', email='LOCAL@EXAMPLE.COM', password=password)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers['Location'], '/')
        with self.client.session_transaction() as session:
            self.assertEqual(session['plex_user']['id'], profile['plex_id'])
            self.assertEqual(session['plex_user']['auth_type'], 'local')

    def test_local_user_recipient_checkbox_is_optional(self):
        self.create_local()
        self.assertEqual(keep.get_email_recipients(), ['one@example.com'])
        self.create_local(email='digest@example.com', add_recipient=True)
        self.assertEqual(keep.get_email_recipients(), ['digest@example.com', 'one@example.com'])

    def test_email_disabled_local_user_setup_and_login_without_smtp(self):
        class SetupLink(HTMLParser):
            link = None
            attributes = {}

            def handle_starttag(self, tag, attrs):
                attrs = dict(attrs)
                if tag == 'input' and attrs.get('id') == 'private-setup-url':
                    self.link = attrs.get('value')
                    self.attributes = attrs

        with patch.dict(os.environ, {'EMAIL_ENABLED': 'false', 'KEEP_URL': 'https://keep.example.com'}), \
                patch.object(keep, 'send_email') as mail:
            response = self.form('/settings/users/local', email='manual@example.com',
                                 full_name='Manual Person', display_name='Manual', add_recipient='1')
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.headers['Cache-Control'], 'no-store')
            self.assertEqual(response.headers['Referrer-Policy'], 'no-referrer')
            body = response.get_data(as_text=True)
            self.assertIn('id="copy-setup-url" type="button"', body)
            self.assertIn('role="status" aria-live="polite"', body)
            page = SetupLink()
            page.feed(body)
            self.assertIn('readonly', page.attributes)
            self.assertTrue(page.link.startswith('https://keep.example.com/auth/local/setup/'))
            token = page.link.rsplit('/', 1)[1]
            with closing(keep.attribution_db()) as db:
                profile = db.execute("SELECT * FROM user_profiles WHERE email='manual@example.com'").fetchone()
                actions = [row[0] for row in db.execute('SELECT action FROM activity_log')]
            self.assertEqual(profile['status'], 'pending')
            self.assertEqual(profile['invite_token_hash'], keep.token_digest(token))
            self.assertNotEqual(profile['invite_token_hash'], token)
            self.assertEqual(actions.count('user-created'), 1)
            self.assertEqual(actions.count('recipient-added'), 1)
            self.assertIn('manual@example.com', keep.get_email_recipients())

            setup_path = '/auth/local/setup/' + token
            self.assertEqual(self.client.get(setup_path).status_code, 200)
            password = 'a long manual password'
            saved = self.form(setup_path, password=password, confirm_password=password)
            self.assertEqual(saved.status_code, 200)
            self.assertIn('Password saved', saved.get_data(as_text=True))
            self.assertEqual(self.client.get(setup_path).status_code, 400)
            self.assertEqual(self.form(setup_path, password=password,
                                       confirm_password=password).status_code, 400)
            with closing(keep.attribution_db()) as db:
                active = db.execute('SELECT * FROM user_profiles WHERE plex_id=?',
                                    (profile['plex_id'],)).fetchone()
            self.assertEqual(active['status'], 'active')
            self.assertIsNone(active['invite_token_hash'])
            self.assertTrue(keep.password_hasher.verify(active['password_hash'], password))
            self.client.get('/logout')
            with self.client.session_transaction() as session:
                session['csrf_token'] = 'test-csrf'
            signed_in = self.form('/auth/local', email='MANUAL@EXAMPLE.COM', password=password)
            self.assertEqual(signed_in.status_code, 302)
            self.assertEqual(signed_in.headers['Location'], '/')
            with self.client.session_transaction() as session:
                self.assertEqual(session['plex_user']['id'], profile['plex_id'])
                self.assertEqual(session['plex_user']['auth_type'], 'local')
            mail.assert_not_called()

    def test_email_enabled_creation_redirects_after_one_setup_email_and_records_activity(self):
        with patch.dict(os.environ, {'EMAIL_ENABLED': 'true'}), \
                patch.object(keep, 'send_local_setup_email') as mail:
            response = self.form('/settings/users/local', email='emailed@example.com',
                                 full_name='Emailed Person', display_name='Emailed')
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.headers['Location'].startswith('/settings/users'))
        mail.assert_called_once()
        with closing(keep.attribution_db()) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM activity_log WHERE action='user-created'").fetchone()[0], 1)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM activity_log WHERE action='recipient-added'").fetchone()[0], 0)

    def test_smtp_failure_retains_created_account_recipient_and_activity(self):
        with patch.dict(os.environ, {'EMAIL_ENABLED': 'true'}), \
                patch.object(keep, 'send_local_setup_email', side_effect=RuntimeError('SMTP unavailable')) as mail:
            response = self.form('/settings/users/local', email='retry@example.com',
                                 full_name='Retry Person', display_name='Retry', add_recipient='1')
        self.assertEqual(response.status_code, 502)
        self.assertIn('account was created', response.get_data(as_text=True))
        mail.assert_called_once()
        with closing(keep.attribution_db()) as db:
            profile = db.execute("SELECT * FROM user_profiles WHERE email='retry@example.com'").fetchone()
            actions = [row[0] for row in db.execute('SELECT action FROM activity_log')]
        self.assertEqual(profile['status'], 'pending')
        self.assertTrue(profile['invite_token_hash'])
        self.assertEqual(actions.count('user-created'), 1)
        self.assertEqual(actions.count('recipient-added'), 1)
        self.assertIn('retry@example.com', keep.get_email_recipients())

    def test_local_login_is_generic_and_pending_account_cannot_login(self):
        self.create_local()
        self.client.get('/logout')
        with self.client.session_transaction() as session:
            session['csrf_token'] = 'test-csrf'
        missing = self.form('/auth/local', email='missing@example.com', password='anything')
        pending = self.form('/auth/local', email='local@example.com', password='anything')
        self.assertEqual(missing.status_code, 401)
        self.assertEqual(pending.status_code, 401)
        self.assertIn('email address or password is incorrect', missing.get_data(as_text=True))
        self.assertIn('email address or password is incorrect', pending.get_data(as_text=True))

    def test_active_local_user_can_request_password_reset(self):
        profile, original_token = self.create_local()
        with closing(keep.attribution_db()) as db, db:
            db.execute("""UPDATE user_profiles SET status='active', password_hash=?
                          WHERE plex_id=?""",
                       (keep.password_hasher.hash('a long local password'), profile['plex_id']))
        self.client.get('/logout')
        with self.client.session_transaction() as session:
            session['csrf_token'] = 'test-csrf'

        with patch.object(keep, 'send_local_setup_email') as mail:
            response = self.form('/auth/local/forgot', email='LOCAL@EXAMPLE.COM')

        self.assertEqual(response.status_code, 200)
        self.assertIn('If an active household account exists', response.get_data(as_text=True))
        mail.assert_called_once()
        self.assertTrue(mail.call_args.kwargs['reset'])
        with closing(keep.attribution_db()) as db:
            saved = db.execute("SELECT * FROM user_profiles WHERE plex_id=?",
                               (profile['plex_id'],)).fetchone()
        self.assertNotEqual(saved['invite_token_hash'], keep.token_digest(original_token))
        self.assertGreater(saved['invite_expires_at'], keep.time.time())

    def test_forgot_password_does_not_email_plex_unknown_pending_or_disabled_users(self):
        self.create_local(email='pending@example.com')
        with closing(keep.attribution_db()) as db, db:
            db.execute("""INSERT INTO user_profiles
                (plex_id, plex_username, email, auth_type, status)
                VALUES ('8', 'plexfriend', 'plex@example.com', 'plex', 'active')""")
            db.execute("""INSERT INTO user_profiles
                (plex_id, email, full_name, display_name, auth_type, status, password_hash)
                VALUES ('local:disabled', 'disabled@example.com', 'Disabled User',
                        'Disabled U', 'local', 'disabled', ?)""",
                       (keep.password_hasher.hash('a long local password'),))
        self.client.get('/logout')
        with self.client.session_transaction() as session:
            session['csrf_token'] = 'test-csrf'

        with patch.object(keep, 'send_local_setup_email') as mail:
            for email in ('missing@example.com', 'plex@example.com',
                          'pending@example.com', 'disabled@example.com'):
                response = self.form('/auth/local/forgot', email=email)
                self.assertEqual(response.status_code, 200)
                self.assertIn('If an active household account exists',
                              response.get_data(as_text=True))
        mail.assert_not_called()

    def test_forgot_password_link_and_csrf_protection(self):
        self.client.get('/logout')
        login = self.client.get('/login').get_data(as_text=True)
        self.assertIn('Forgot your password?', login)
        self.assertEqual(self.client.get('/auth/local/forgot').status_code, 200)
        self.assertEqual(self.client.post('/auth/local/forgot',
                                          data={'email': 'local@example.com'}).status_code, 403)

    def test_owner_can_disable_local_user_and_invalidate_session(self):
        profile, token = self.create_local()
        password_hash = keep.password_hasher.hash('a long local password')
        with closing(keep.attribution_db()) as db, db:
            db.execute("""UPDATE user_profiles SET status='active', password_hash=?,
                          invite_token_hash=NULL, invite_expires_at=NULL WHERE plex_id=?""",
                       (password_hash, profile['plex_id']))
            active = db.execute("SELECT * FROM user_profiles WHERE plex_id=?",
                                (profile['plex_id'],)).fetchone()
        local_client = keep.app.test_client()
        with local_client.session_transaction() as session:
            session['plex_user'] = keep.local_session_user(active)
        response = self.form(f"/settings/users/{profile['plex_id']}/access", action='disable')
        self.assertEqual(response.status_code, 302)
        self.assertEqual(local_client.get('/').status_code, 302)
        with local_client.session_transaction() as session:
            self.assertNotIn('plex_user', session)

    def test_owner_can_disable_plex_user_and_invalidate_session(self):
        with closing(keep.attribution_db()) as db, db:
            db.execute("""INSERT INTO user_profiles
                (plex_id, plex_username, auth_type, status, plex_access)
                VALUES ('8', 'plexfriend', 'plex', 'active', 'active')""")
            profile = db.execute("SELECT * FROM user_profiles WHERE plex_id='8'").fetchone()
        plex_client = keep.app.test_client()
        with plex_client.session_transaction() as session:
            session['plex_user'] = {
                'id': 8, 'username': 'plexfriend',
                'session_version': profile['session_version']
            }
        response = self.form('/settings/users/8/access', action='disable')
        self.assertEqual(response.status_code, 302)
        self.assertEqual(plex_client.get('/').status_code, 302)
        with closing(keep.attribution_db()) as db:
            disabled = db.execute("SELECT * FROM user_profiles WHERE plex_id='8'").fetchone()
        self.assertEqual(disabled['status'], 'disabled')
        self.assertEqual(disabled['session_version'], profile['session_version'] + 1)

        self.assertEqual(self.form('/settings/users/8/access', action='enable').status_code, 302)
        with closing(keep.attribution_db()) as db:
            enabled = db.execute("SELECT * FROM user_profiles WHERE plex_id='8'").fetchone()
        self.assertEqual(enabled['status'], 'active')

    def test_owner_access_cannot_be_disabled(self):
        response = self.form('/settings/users/7/access', action='disable')
        self.assertEqual(response.status_code, 400)
        self.assertIn('Owner access cannot be changed', response.get_data(as_text=True))

    def test_plex_access_sync_tracks_authorization_without_overriding_manual_disable(self):
        with closing(keep.attribution_db()) as db, db:
            db.execute("""INSERT INTO user_profiles
                (plex_id, plex_username, auth_type, status, plex_access, plex_sync_visible)
                VALUES ('8', 'plexfriend', 'plex', 'disabled', 'active', 1)""")
            db.execute("""INSERT INTO user_profiles
                (plex_id, plex_username, auth_type, status, plex_access, plex_sync_visible, plex_checked_at)
                VALUES ('9', 'directlogin', 'plex', 'active', 'active', 0, CURRENT_TIMESTAMP)""")

        server_accounts = Mock(content=b'<MediaContainer><Account id="7"/></MediaContainer>')
        shared_users = Mock(content=b'<MediaContainer></MediaContainer>')
        server_accounts.raise_for_status.return_value = None
        shared_users.raise_for_status.return_value = None
        with patch.object(keep, 'PLEX_ADMIN_TOKEN', 'owner-token'), \
             patch.object(keep.requests, 'get', side_effect=[server_accounts, shared_users]):
            self.assertEqual(keep.sync_plex_user_access(), 1)
        with closing(keep.attribution_db()) as db:
            revoked = db.execute("SELECT * FROM user_profiles WHERE plex_id='8'").fetchone()
        self.assertEqual(revoked['plex_access'], 'revoked')
        self.assertEqual(revoked['status'], 'disabled')
        with closing(keep.attribution_db()) as db:
            direct_login = db.execute("SELECT * FROM user_profiles WHERE plex_id='9'").fetchone()
        self.assertEqual(direct_login['plex_access'], 'active')
        self.assertEqual(direct_login['plex_sync_visible'], 0)

        shared_users.content = (b'<MediaContainer><User id="8"><Server machineIdentifier="test"/>'
                                b'</User></MediaContainer>')
        with patch.object(keep, 'PLEX_ADMIN_TOKEN', 'owner-token'), \
             patch.object(keep.requests, 'get', side_effect=[server_accounts, shared_users]):
            self.assertEqual(keep.sync_plex_user_access(), 1)
        with closing(keep.attribution_db()) as db:
            restored = db.execute("SELECT * FROM user_profiles WHERE plex_id='8'").fetchone()
        self.assertEqual(restored['plex_access'], 'active')
        self.assertEqual(restored['status'], 'disabled')

    def test_duplicate_local_email_and_expired_setup_are_rejected(self):
        profile, token = self.create_local()
        with patch.object(keep, 'send_local_setup_email'):
            duplicate = self.form('/settings/users/local', email='LOCAL@example.com',
                                  full_name='Other Person', display_name='Other P')
        self.assertEqual(duplicate.status_code, 409)
        with closing(keep.attribution_db()) as db, db:
            db.execute("UPDATE user_profiles SET invite_expires_at=? WHERE plex_id=?",
                       (keep.time.time() - 1, profile['plex_id']))
        self.assertEqual(self.client.get('/auth/local/setup/' + token).status_code, 400)

    def test_recipient_add_disable_enable_remove_and_last_enabled_guard(self):
        self.assertEqual(self.form('/settings/recipients', action='add', email='TWO@Example.com').status_code, 302)
        self.assertEqual(self.form('/settings/recipients', action='disable', email='two@example.com').status_code, 302)
        self.assertEqual(keep.get_email_recipients(), ['one@example.com'])
        self.assertEqual(self.form('/settings/recipients', action='disable', email='one@example.com').status_code, 400)
        self.assertEqual(self.form('/settings/recipients', action='enable', email='two@example.com').status_code, 302)
        self.assertEqual(self.form('/settings/recipients', action='remove', email='one@example.com').status_code, 302)
        self.assertEqual(keep.get_email_recipients(), ['two@example.com'])

    def test_recipient_collection_preferences(self):
        response = self.form('/settings/recipients/preferences', email='one@example.com',
                             collection_id=['1', '6'])
        self.assertEqual(response.status_code, 302)
        self.assertEqual(keep.get_recipient_delivery_preferences(),
                         {'one@example.com': {1, 6}})
        response = self.form('/settings/recipients/preferences', email='one@example.com')
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers['Location'], '/settings/email')
        page = self.client.get('/settings/email').get_data(as_text=True)
        self.assertIn('Choose at least one email topic for this recipient.', page)
        self.assertIn('class="subscriptions invalid"', page)
        self.assertIn('form.classList.toggle("invalid", !valid)', page)
        self.assertIn('event.preventDefault()', page)
        self.assertEqual(keep.get_recipient_delivery_preferences(),
                         {'one@example.com': {1, 6}})

    def test_disabled_recipient_topics_reflect_preferences_and_are_greyed_out(self):
        self.form('/settings/recipients/preferences', email='one@example.com',
                  collection_id=['1', '6'])
        with closing(keep.attribution_db()) as db, db:
            db.execute("UPDATE email_recipients SET enabled=0 WHERE email='one@example.com'")
        page = self.client.get('/settings/email').get_data(as_text=True)
        self.assertIn('class="subscriptions disabled"', page)
        self.assertIn('aria-disabled="true"', page)
        self.assertRegex(page, r'value="1"\s+checked disabled')
        self.assertRegex(page, r'value="3"\s+disabled')
        self.assertRegex(page, r'value="5"\s+disabled')
        self.assertRegex(page, r'value="6"\s+checked disabled')
        self.assertIn('type="submit" disabled>Save</button>', page)
        self.assertIn('.subscriptions.disabled { opacity:.48; }', page)

    def test_user_can_manage_only_their_own_email_preferences(self):
        with closing(keep.attribution_db()) as db, db:
            db.execute("""INSERT INTO user_profiles
                (plex_id, plex_username, email, full_name, display_name, plex_checked_at)
                VALUES ('8', 'friend', 'friend@example.com', 'Friend Person', 'Friend P', CURRENT_TIMESTAMP)""")
        with self.client.session_transaction() as session:
            session['plex_user'] = {'id': 8, 'username': 'friend', 'email': 'friend@example.com'}
            session['csrf_token'] = 'test-csrf'

        page = self.client.get('/preferences')
        self.assertEqual(page.status_code, 200)
        self.assertIn('friend@example.com', page.get_data(as_text=True))
        self.assertNotIn('one@example.com', page.get_data(as_text=True))
        response = self.form('/preferences', email='one@example.com', receive_email='1',
                             collection_id=['3', '6'])
        self.assertEqual(response.status_code, 302)
        with closing(keep.attribution_db()) as db:
            friend = db.execute("SELECT enabled FROM email_recipients WHERE email=?",
                                ('friend@example.com',)).fetchone()
            original = db.execute("SELECT enabled FROM email_recipients WHERE email=?",
                                  ('one@example.com',)).fetchone()
        self.assertEqual(friend['enabled'], 1)
        self.assertEqual(original['enabled'], 1)
        self.assertEqual(keep.get_recipient_delivery_preferences()['friend@example.com'], {3, 6})

    def test_user_can_opt_out_and_preferences_require_csrf(self):
        response = self.form('/preferences', receive_email='1', collection_id='1')
        self.assertEqual(response.status_code, 302)
        self.assertIn('owner@example.com', keep.get_email_recipients())
        self.assertEqual(self.form('/preferences').status_code, 302)
        self.assertNotIn('owner@example.com', keep.get_email_recipients())
        self.assertEqual(self.client.post('/preferences', data={}).status_code, 403)

    def test_preferences_fragment_roundtrip_and_csrf(self):
        response = self.client.get('/preferences?fragment=1')
        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertNotIn('<html', body)
        self.assertIn('name="csrf_token"', body)
        self.assertEqual(self.client.post('/preferences?fragment=1', data={}).status_code, 403)
        response = self.form('/preferences?fragment=1', receive_email='1', collection_id=['1', '3'])
        self.assertEqual(response.status_code, 302)
        self.assertIn('fragment=1', response.location)
        saved = self.client.get(response.location).get_data(as_text=True)
        self.assertIn('Your preferences were saved.', saved)
        self.assertEqual(keep.get_recipient_delivery_preferences()['owner@example.com'], {1, 3})
        invalid = self.form('/preferences?fragment=1', receive_email='1', collection_id='999')
        self.assertIn('Select at least one collection', invalid.get_data(as_text=True))

    def test_appearance_is_saved_per_account_and_validated(self):
        fragment = self.client.get('/preferences?fragment=1').get_data(as_text=True)
        self.assertIn('name="theme_mode" value="system" checked', fragment)
        self.assertEqual(self.form('/preferences', theme_mode='light').status_code, 302)
        with closing(keep.attribution_db()) as db, db:
            self.assertEqual(db.execute("SELECT theme_mode FROM user_profiles WHERE plex_id='7'").fetchone()[0], 'light')
        self.assertIn('data-theme="light"', self.client.get('/help').get_data(as_text=True))
        invalid = self.form('/preferences', theme_mode='invalid')
        self.assertIn('Choose System, Light, or Dark', invalid.get_data(as_text=True))
        with closing(keep.attribution_db()) as db, db:
            self.assertEqual(db.execute("SELECT theme_mode FROM user_profiles WHERE plex_id='7'").fetchone()[0], 'light')
            db.execute("INSERT INTO user_profiles(plex_id, plex_username, plex_checked_at) VALUES ('8', 'friend', CURRENT_TIMESTAMP)")
        with self.client.session_transaction() as session:
            session['plex_user'] = {'id': 8, 'username': 'friend'}
        self.assertEqual(self.form('/preferences', theme_mode='dark').status_code, 302)
        with closing(keep.attribution_db()) as db:
            self.assertEqual(db.execute("SELECT theme_mode FROM user_profiles WHERE plex_id='7'").fetchone()[0], 'light')
            self.assertEqual(db.execute("SELECT theme_mode FROM user_profiles WHERE plex_id='8'").fetchone()[0], 'dark')

    def test_preferences_handle_account_without_email(self):
        with closing(keep.attribution_db()) as db, db:
            db.execute("INSERT INTO user_profiles(plex_id, plex_username, plex_checked_at) VALUES ('8', 'friend', CURRENT_TIMESTAMP)")
        with self.client.session_transaction() as session:
            session['plex_user'] = {'id': 8, 'username': 'friend'}
            session['csrf_token'] = 'test-csrf'
        page = self.client.get('/preferences')
        self.assertIn('No email address available', page.get_data(as_text=True))
        response = self.form('/preferences', receive_email='1', collection_id='1')
        self.assertEqual(response.status_code, 200)
        self.assertIn('does not have an email address', response.get_data(as_text=True))

    def test_main_header_links_every_user_to_preferences(self):
        with patch.object(keep, 'build_review_collections', return_value=[]), \
             patch.object(keep, 'build_kept_collections', return_value=[]), \
             patch.object(keep, 'get_collection_media', return_value={'items': []}), \
             patch.object(keep, 'get_collection_exclusions', return_value={'items': []}):
            page = self.client.get('/').get_data(as_text=True)
            kept_page = self.client.get('/kept').get_data(as_text=True)
        self.assertIn('href="/preferences" aria-haspopup="dialog" aria-controls="preferences-dialog">Preferences</a>', page)
        self.assertRegex(page, r'href="/settings/users"[^>]*>Admin</a>')
        self.assertIn('class="user-links"', page)
        self.assertIn('grid-template-columns: auto minmax(0, 1fr);', page)
        self.assertIn('grid-column: 1 / -1;', page)
        self.assertIn('background: #2a2d35;', page)
        self.assertNotIn('background: linear-gradient(145deg, #ffbe52, #e78712);', page)
        self.assertIn('.user-avatar.fallback', page)
        self.assertIn('class="user-avatar fallback"', page)
        self.assertIn('id="media-search" type="search"', page)
        self.assertIn('placeholder="Search leaving movies and shows"', page)
        self.assertIn('function applyMediaSearch()', page)
        self.assertIn('`${title} ${year}`.toLocaleLowerCase().includes(query)', page)
        self.assertIn('No movies or shows match your search.', page)
        self.assertIn('placeholder="Search kept movies and shows"', kept_page)
        self.assertIn('aria-label="Filter kept titles"', kept_page)
        self.assertIn('data-keep-scope="all" aria-pressed="true">All Keeps</button>', kept_page)
        self.assertIn('data-keep-scope="mine" aria-pressed="false">My Keeps</button>', kept_page)
        self.assertIn('card.dataset.keptByViewer === "true"', kept_page)
        self.assertIn('No titles in My Keeps match your search.', kept_page)
        self.assertNotIn('aria-label="Filter kept titles"', page)
        self.assertIn('rel="apple-touch-icon" sizes="180x180"', page)
        self.assertIn('href="/static/site.webmanifest"', page)

        with closing(keep.attribution_db()) as db, db:
            db.execute("INSERT INTO user_profiles(plex_id, plex_username, plex_checked_at) VALUES ('8', 'friend', CURRENT_TIMESTAMP)")
        with self.client.session_transaction() as session:
            session['plex_user'] = {'id': 8, 'username': 'friend'}
        with patch.object(keep, 'build_review_collections', return_value=[]), \
             patch.object(keep, 'get_collection_media', return_value={'items': []}), \
             patch.object(keep, 'get_collection_exclusions', return_value={'items': []}):
            page = self.client.get('/').get_data(as_text=True)
        self.assertIn('href="/preferences" aria-haspopup="dialog" aria-controls="preferences-dialog">Preferences</a>', page)
        self.assertNotIn('href="/settings/users">Admin</a>', page)

    def test_preferences_use_plain_email_notification_label(self):
        page = self.client.get('/preferences').get_data(as_text=True)
        self.assertIn('Receive Keep email notifications', page)
        self.assertNotIn('Receive consolidated Keep emails', page)
        self.assertIn('id="email-topics" disabled', page)

        self.form('/preferences', receive_email='1', collection_id='1')
        page = self.client.get('/preferences').get_data(as_text=True)
        self.assertNotIn('id="email-topics" disabled', page)

    def test_owner_can_delete_local_user_without_removing_recipient(self):
        profile, _ = self.create_local(email='delete@example.com', add_recipient=True)
        with closing(keep.attribution_db()) as db, db:
            db.execute("""INSERT INTO media_libraries
                (library_key, service, external_id, name, path)
                VALUES ('radarr:4', 'radarr', '4', 'Movies', '/media/movies')""")
            db.execute("INSERT INTO user_library_permissions(user_id, library_key) VALUES (?, 'radarr:4')",
                       (profile['plex_id'],))
            db.execute("""INSERT INTO user_feature_acknowledgements
                (user_id, feature_key, version) VALUES (?, 'how-keep-works', 'test')""",
                (profile['plex_id'],))
        response = self.form(f"/settings/users/{profile['plex_id']}/access", action='delete')
        self.assertEqual(response.status_code, 302)
        with closing(keep.attribution_db()) as db:
            self.assertIsNone(db.execute("SELECT 1 FROM user_profiles WHERE plex_id=?",
                                         (profile['plex_id'],)).fetchone())
            self.assertIsNotNone(db.execute("SELECT 1 FROM email_recipients WHERE email=?",
                                            ('delete@example.com',)).fetchone())
            self.assertEqual(db.execute("SELECT COUNT(*) FROM user_library_permissions WHERE user_id=?",
                                        (profile['plex_id'],)).fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM user_feature_acknowledgements WHERE user_id=?",
                                        (profile['plex_id'],)).fetchone()[0], 0)

    def test_admin_sections_separate_users_email_and_activity(self):
        profile, _ = self.create_local()
        users_page = self.client.get('/settings/users').get_data(as_text=True)
        self.assertIn('class="source source-local">local</span>', users_page)
        self.assertIn('Last sign-in:', users_page)
        self.assertIn('Setup link expires in', users_page)
        self.assertIn('Delete user', users_page)
        self.assertNotIn('Active recipients', users_page)
        self.assertNotIn('Recent activity', users_page)

        email_page = self.client.get('/settings/email').get_data(as_text=True)
        self.assertIn('href="/settings/email" class="active"', email_page)
        self.assertIn('Active recipients', email_page)
        self.assertIn('Queued titles', email_page)
        self.assertIn('Next digest', email_page)
        self.assertIn('Email recipients', email_page)
        self.assertIn('Add email recipient', email_page)
        self.assertIn('New recipients receive all configured collection topics by default.', email_page)
        self.assertNotIn('Add local user', email_page)
        self.assertNotIn('Recent activity', email_page)

        activity_page = self.client.get('/settings/activity').get_data(as_text=True)
        self.assertIn('href="/settings/activity" class="active"', activity_page)
        self.assertIn('Recent activity', activity_page)
        self.assertIn('Added local user Local Person', activity_page)
        self.assertIn('Users &amp; access', activity_page)
        self.assertNotIn('Email recipients', activity_page)
        self.assertNotIn('Add local user', activity_page)

    def test_activity_filters_and_pagination(self):
        with closing(keep.attribution_db()) as db, db:
            db.executemany("""INSERT INTO activity_log(actor_id, actor_name, action, description)
                VALUES ('7', 'Owner', 'keep-added', ?)""",
                [(f'Kept title {index}',) for index in range(55)])
            db.execute("""INSERT INTO activity_log(actor_id, actor_name, action, description)
                VALUES ('7', 'Owner', 'recipient-added', 'Added email recipient')""")
        first = self.client.get('/settings/activity?filter=keeps').get_data(as_text=True)
        self.assertIn('Page 1 of 2', first)
        self.assertIn('filter=keeps&amp;page=2', first)
        self.assertNotIn('Added email recipient', first)
        second = self.client.get('/settings/activity?filter=keeps&page=2').get_data(as_text=True)
        self.assertIn('Page 2 of 2', second)
        self.assertIn('filter=keeps&amp;page=1', second)

    def test_persistent_rate_limit_survives_requests(self):
        with self.client.application.test_request_context('/auth/local',
                                                          environ_base={'REMOTE_ADDR': '10.0.0.5'}):
            for _ in range(5):
                self.assertIsNone(keep.persistent_rate_limit('test-login', 5, 60))
            limited = keep.persistent_rate_limit('test-login', 5, 60)
        self.assertEqual(limited.status_code, 429)
        self.assertIn('Retry-After', limited.headers)

    def test_invalid_recipient_and_unknown_user_rejected(self):
        self.assertEqual(self.form('/settings/recipients', action='add', email='not-an-email').status_code, 400)
        self.assertEqual(self.form('/settings/users/999', full_name='Nobody', display_name='N').status_code, 404)

    def test_login_observation_preserves_owner_managed_names(self):
        keep.remember_plex_user({'id': 7, 'username': 'updated-handle', 'email': 'new@example.com'})
        with closing(keep.attribution_db()) as db:
            row = db.execute("SELECT * FROM user_profiles WHERE plex_id='7'").fetchone()
        self.assertEqual(row['plex_username'], 'updated-handle')
        self.assertEqual(row['email'], 'new@example.com')
        self.assertEqual(row['full_name'], 'Alex Morgan')
        self.assertEqual(row['display_name'], 'Alex W')

    def test_display_name_updates_existing_badges(self):
        cid = next(iter(keep.COLLECTIONS))
        keep.record_keeper(cid, '1', {'id': 7, 'username': 'testowner'})
        item = {'mediaServerId': '1', 'mediaData': {'title': 'Title'}}
        with patch.object(keep, 'get_collection_exclusions',
                          side_effect=lambda collection: {'items': [copy.deepcopy(item)] if collection == cid else []}), \
             patch.object(keep, 'get_kept_item_poster', return_value=''), \
             patch.object(keep, 'get_collection_media', return_value={'items': []}):
            page = self.client.get('/kept').get_data(as_text=True)
        self.assertIn('Kept by Alex W', page)
        self.form('/settings/users/7', full_name='Alex Morgan', display_name='A Morgan')
        with patch.object(keep, 'get_collection_exclusions',
                          side_effect=lambda collection: {'items': [copy.deepcopy(item)] if collection == cid else []}), \
             patch.object(keep, 'get_kept_item_poster', return_value=''), \
             patch.object(keep, 'get_collection_media', return_value={'items': []}):
            page = self.client.get('/kept').get_data(as_text=True)
        self.assertIn('Kept by A Morgan', page)


if __name__ == '__main__':
    unittest.main()
