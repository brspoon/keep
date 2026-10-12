"""Isolated Flask routes with real notification storage and synthetic senders."""
from contextlib import closing
import os
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from flask import Flask, jsonify, request, session

from connection_settings import ConnectionSettings
import notification_settings
import notifications
import notifications_routes


class NotificationRoutesTests(unittest.TestCase):
    def setUp(self):
        environment = patch.dict(os.environ, {}, clear=True)
        environment.start()
        self.addCleanup(environment.stop)
        self.directory = TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / 'routes.sqlite3'
        self.connections = ConnectionSettings(self.path)
        with sqlite3.connect(self.path) as db:
            db.executescript('''
                CREATE TABLE user_profiles(plex_id TEXT PRIMARY KEY,email TEXT,full_name TEXT,
                    display_name TEXT,plex_username TEXT,status TEXT,auth_type TEXT,plex_access TEXT);
                INSERT INTO user_profiles VALUES ('owner','owner@example.test','Owner Full','Owner','owner','active','plex','active');
                INSERT INTO user_profiles VALUES ('viewer','viewer@example.test','<b>Viewer</b>','Viewer','viewer','active','plex','active');
                CREATE TABLE email_recipients(email TEXT PRIMARY KEY,enabled INTEGER);
                INSERT INTO email_recipients VALUES ('owner@example.test',1);
                INSERT INTO email_recipients VALUES ('viewer@example.test',1);
                CREATE TABLE recipient_subscriptions(email TEXT,collection_id INTEGER,enabled INTEGER);
                INSERT INTO recipient_subscriptions VALUES ('owner@example.test',1,1);
                INSERT INTO recipient_subscriptions VALUES ('viewer@example.test',2,1);
                CREATE TABLE notification_queue(id INTEGER PRIMARY KEY AUTOINCREMENT,
                    collection_id INTEGER,media_id TEXT,kind TEXT,received_at REAL,batch_id TEXT);
                CREATE TABLE notification_batches(id TEXT PRIMARY KEY,status TEXT,created_at REAL,detail TEXT);
                CREATE TABLE notification_deliveries(batch_id TEXT,email TEXT,sent_at REAL,PRIMARY KEY(batch_id,email));
            ''')
        self.clock = 1000
        self.collections = {1: 'Movies Leaving Plex Soon', 2: 'Shows Leaving Plex Soon'}
        self.access = lambda profile: profile['status'] == 'active' and profile['plex_access'] == 'active'
        self.settings = notification_settings.Settings(self.path, connections=self.connections,
            owner_id=lambda: 'owner', profile_access=self.access)
        self.core = notifications.Store(self.path)
        self.connections.save({'EMAIL_ENABLED': 'true', 'SMTP_HOST': 'smtp.example.test', 'SMTP_FROM': 'keep@example.test'})
        self.app = Flask(__name__, template_folder=str(Path(__file__).resolve().parents[1] / 'templates'))
        self.app.secret_key = 'synthetic-test-secret'
        self.app.config['TESTING'] = True
        self.email_send = Mock(return_value=notifications.Outcome('accepted'))
        self.push_send = Mock(return_value=notifications.Outcome('accepted'))
        self.activity = Mock()

        def db():
            connection = sqlite3.connect(self.path)
            connection.row_factory = sqlite3.Row
            return connection

        def active():
            with closing(db()) as connection:
                profile = connection.execute('SELECT * FROM user_profiles WHERE plex_id=?', (session.get('user_id', ''),)).fetchone()
            return bool(profile and self.access(profile))

        def csrf():
            return None if request.form.get('csrf_token') == session.get('csrf_token') else ('Invalid request token', 403)

        self.adapter = SimpleNamespace(require_owner=lambda: None if session.get('user_id') == 'owner' else ('Owner only', 403),
            require_csrf=csrf, current_account_session=active,
            actor=lambda: notification_settings.Actor(session.get('user_id', ''), active(), session.get('user_id') == 'owner'),
            settings_store=lambda initialize=False: notification_settings.Settings(self.path, initialize=initialize,
                connections=self.connections, owner_id=lambda: 'owner', profile_access=self.access),
            core_store=lambda read_only=False: notifications.Store(self.path, initialize=not read_only), db=db,
            collections=lambda: self.collections, csrf_token=lambda: 'synthetic-csrf', log_activity=self.activity,
            connections=self.connections, quiet_seconds=300, send_email_test=self.email_send,
            send_push_test=self.push_send, now=lambda: self.clock)
        self.routes = notifications_routes.register_routes(self.app, self.adapter)

        @self.app.context_processor
        def shared():
            return dict(theme_mode='dark', app_version='test', owner=session.get('user_id') == 'owner',
                plex_user={'thumb': '', 'username': 'Synthetic'}, capabilities={'delete_media': False}, granted_libraries=[])

        @self.app.post('/test-preferences')
        def personal():
            result = self.routes.handle_personal(request.form.get('action', 'email'))
            response = result.pop('response')
            return response if response else jsonify(result)

        self.client = self.app.test_client()
        self.login('owner')

    def login(self, user_id):
        with self.client.session_transaction() as saved:
            saved['user_id'] = user_id
            saved['csrf_token'] = 'synthetic-csrf'
            saved['plex_user'] = {'id': user_id}

    def post(self, path, **data):
        return self.client.post(path, data={'csrf_token': 'synthetic-csrf', **data})

    def install(self):
        self.settings.save_installation(notification_settings.Actor('owner', True, True),
            enabled=True, token_mode='replace', token='A' * 30, now=100)

    def push_preferences(self, user_id='owner'):
        self.settings.save_preferences(notification_settings.Actor(user_id, True, user_id == 'owner'),
            enabled=True, collections={1}, events=notifications.MEDIA_EVENTS, available_collections=self.collections,
            key_mode='replace', user_key='B' * 30, now=200)

    def query(self, statement, values=()):
        with sqlite3.connect(self.path) as db:
            return db.execute(statement, values).fetchall()

    def held_delivery(self, state='review', provider='email', destination='viewer@example.test', batch='held'):
        with sqlite3.connect(self.path) as db:
            db.execute("INSERT OR IGNORE INTO notification_batches VALUES (?,'review',100,NULL)", (batch,))
            db.execute('INSERT OR IGNORE INTO notification_runs(batch_id) VALUES (?)', (batch,))
            db.execute('''INSERT INTO notification_dispatches
                (batch_id,provider,destination_id,generation,state,created_at,last_attempt,error_code)
                VALUES (?,?,?,'generation',?,100,110,'email_uncertain')''', (batch, provider, destination, state))

    def test_owner_page_and_preferences_reads_do_not_send_or_write_storage(self):
        self.install()
        self.push_preferences()
        before = self.path.read_bytes()
        response = self.client.get('/settings/notifications')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers['Cache-Control'], 'no-store')
        with self.app.test_request_context('/preferences'):
            session['user_id'] = 'owner'
            context = self.routes.preferences_context('owner@example.test')
        self.assertTrue(context['push_preferences']['can_test'])
        self.assertEqual(self.path.read_bytes(), before)
        self.email_send.assert_not_called()
        self.push_send.assert_not_called()
        self.assertNotIn('A' * 30, response.text)
        self.assertNotIn('B' * 30, response.text)
        self.assertIn('&lt;b&gt;Viewer&lt;/b&gt;', response.text)

    def test_only_current_owner_can_read_or_change_owner_notifications(self):
        for user in ('viewer', 'missing'):
            self.login(user)
            self.assertEqual(self.client.get('/settings/notifications').status_code, 403)
            self.assertEqual(self.post('/settings/notifications/email', enabled='1').status_code, 403)
            self.assertEqual(self.post('/settings/notifications/test/email').status_code, 403)
        self.login('owner')
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE user_profiles SET auth_type='local' WHERE plex_id='owner'")
        self.assertEqual(self.client.get('/settings/notifications').status_code, 403)
        self.assertEqual(self.post('/settings/notifications/review').status_code, 403)
        self.email_send.assert_not_called()

    def test_all_owner_mutations_require_csrf_before_any_mutation(self):
        before = self.path.read_bytes()
        for path in ('email', 'pushover', 'test/email', 'test/pushover', 'review'):
            self.assertEqual(self.client.post('/settings/notifications/' + path, data={'csrf_token': 'wrong'}).status_code, 403)
        self.assertEqual(self.path.read_bytes(), before)
        self.email_send.assert_not_called()
        self.push_send.assert_not_called()

    def test_legacy_email_page_redirects_to_notifications_without_losing_notice(self):
        with self.client.session_transaction() as saved:
            saved['settings_notice'] = 'subscriptions'
        response = self.client.get('/settings/email')
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers['Location'], '/settings/notifications')
        self.assertIn('Email collection preferences saved.', self.client.get(response.headers['Location']).text)

    def test_registration_preserves_an_existing_legacy_email_handler(self):
        app = Flask('legacy')
        app.add_url_rule('/settings/email', 'settings_email', lambda: 'existing')
        notifications_routes.register_routes(app, self.adapter)
        self.assertEqual(app.test_client().get('/settings/email').text, 'existing')

    def test_email_provider_can_be_disabled_without_removing_any_recipients(self):
        recipients = self.query('SELECT * FROM email_recipients')
        response = self.post('/settings/notifications/email')
        self.assertEqual(response.status_code, 303)
        self.assertEqual(self.connections.get('EMAIL_ENABLED'), 'false')
        self.assertEqual(self.query('SELECT * FROM email_recipients'), recipients)
        with patch.dict(os.environ, {'EMAIL_ENABLED': 'true'}):
            self.assertEqual(self.post('/settings/notifications/email', enabled='1').status_code, 400)

    def test_installation_replacement_is_saved_and_never_echoed_in_errors_or_success(self):
        response = self.post('/settings/notifications/pushover', enabled='1', token_mode='replace', app_token='A' * 30)
        self.assertEqual(response.status_code, 303)
        self.assertEqual(self.connections.get('PUSHOVER_APP_TOKEN'), 'A' * 30)
        response = self.post('/settings/notifications/pushover', enabled='1', token_mode='replace', app_token='<secret>')
        self.assertEqual(response.status_code, 400)
        self.assertNotIn('<secret>', response.text)
        self.assertNotIn('A' * 30, response.text)
        self.assertEqual(self.connections.get('PUSHOVER_APP_TOKEN'), 'A' * 30)

    def test_managed_enabled_field_remains_unchanged_when_only_token_is_edited(self):
        with patch.dict(os.environ, {'PUSHOVER_ENABLED': 'false'}):
            response = self.post('/settings/notifications/pushover', token_mode='replace', app_token='A' * 30)
            self.assertEqual(response.status_code, 303)
            self.assertFalse(self.settings.installation_view()['enabled'])
            self.assertEqual(self.post('/settings/notifications/pushover', enabled='1').status_code, 400)

    def test_email_test_uses_saved_own_address_and_ignores_arbitrary_request_targets(self):
        response = self.post('/settings/notifications/test/email', email='other@example.test', message='arbitrary', subject='arbitrary')
        self.assertEqual(response.status_code, 303)
        self.email_send.assert_called_once_with('owner@example.test')
        self.assertEqual(self.query('SELECT kind,state FROM notification_test_attempts'), [('email', 'accepted')])
        self.assertEqual(self.post('/settings/notifications/test/email').status_code, 400)
        self.assertEqual(self.email_send.call_count, 1)

    def test_push_test_uses_saved_credentials_even_with_provider_disabled(self):
        self.install()
        self.push_preferences()
        self.settings.save_installation(notification_settings.Actor('owner', True, True), enabled=False)
        response = self.post('/settings/notifications/test/pushover', app_token='C' * 30, user_key='D' * 30, device='other')
        self.assertEqual(response.status_code, 303)
        credentials = self.push_send.call_args.args[0]
        self.assertEqual((credentials.app_token, credentials.user_key, credentials.device), ('A' * 30, 'B' * 30, ''))
        self.assertNotIn('A' * 30, str(credentials))

    def test_unconfigured_or_unknown_tests_never_call_a_sender(self):
        self.assertEqual(self.post('/settings/notifications/test/pushover').status_code, 400)
        self.assertEqual(self.post('/settings/notifications/test/unknown').status_code, 404)
        self.push_send.assert_not_called()
        self.email_send.assert_not_called()

    def test_key_changed_after_reservation_prevents_send_and_cancels_saved_attempt(self):
        self.install()
        self.push_preferences()
        reserve = notification_settings.Settings.reserve_test
        def changed(store, *args, **kwargs):
            reservation = reserve(store, *args, **kwargs)
            with sqlite3.connect(self.path) as db:
                db.execute("UPDATE pushover_preferences SET user_key=?,generation='new-generation' WHERE user_id='owner'", ('C' * 30,))
            return reservation
        with patch.object(notification_settings.Settings, 'reserve_test', changed):
            response = self.post('/settings/notifications/test/pushover')
        self.assertEqual(response.status_code, 400)
        self.push_send.assert_not_called()
        self.assertEqual(self.query('SELECT state,error_code FROM notification_test_attempts'), [('cancelled', 'preferences_changed')])

    def test_access_revoked_after_reservation_prevents_transport(self):
        reserve = notification_settings.Settings.reserve_test
        def changed(store, *args, **kwargs):
            reservation = reserve(store, *args, **kwargs)
            with sqlite3.connect(self.path) as db:
                db.execute("UPDATE user_profiles SET plex_access='revoked' WHERE plex_id='owner'")
            return reservation
        with patch.object(notification_settings.Settings, 'reserve_test', changed):
            response = self.post('/settings/notifications/test/email')
        self.assertEqual(response.status_code, 403)
        self.email_send.assert_not_called()
        self.assertEqual(self.query('SELECT state FROM notification_test_attempts'), [('cancelled',)])

    def test_transport_exceptions_are_uncertain_and_never_echo_private_errors(self):
        self.email_send.side_effect = RuntimeError('private-password-provider-response')
        response = self.post('/settings/notifications/test/email')
        self.assertEqual(response.status_code, 400)
        self.assertIn('Test delivery needs review.', response.text)
        self.assertNotIn('private-password', response.text)
        self.assertEqual(self.query('SELECT state,error_code FROM notification_test_attempts'), [('review', 'email_uncertain')])
        self.clock += 200
        self.assertEqual(self.post('/settings/notifications/test/email').status_code, 400)
        self.assertEqual(self.email_send.call_count, 1)

    def test_failed_result_recording_does_not_claim_success_or_resend(self):
        with patch.object(notification_settings.Settings, 'complete_test', side_effect=sqlite3.OperationalError('private database path')):
            response = self.post('/settings/notifications/test/email')
        self.assertEqual(response.status_code, 503)
        self.assertNotIn('private database path', response.text)
        self.assertNotIn('sent.', response.text)
        self.assertEqual(self.query('SELECT state FROM notification_test_attempts'), [('reserved',)])
        self.assertEqual(self.post('/settings/notifications/test/email').status_code, 400)
        self.assertEqual(self.email_send.call_count, 1)

    def test_review_retry_requires_server_side_duplicate_confirmation_and_never_sends_in_http(self):
        self.held_delivery()
        args=dict(batch_id='held', provider='email', destination_id='viewer@example.test', action='retry')
        self.assertEqual(self.post('/settings/notifications/review', **args).status_code, 400)
        self.assertEqual(self.query('SELECT state FROM notification_dispatches'), [('review',)])
        self.assertEqual(self.post('/settings/notifications/review', **args, confirm_duplicate='1').status_code, 303)
        self.assertEqual(self.query('SELECT state FROM notification_dispatches'), [('pending',)])
        self.email_send.assert_not_called()
        self.push_send.assert_not_called()

    def test_review_never_changes_accepted_or_unknown_or_legacy_held_resends(self):
        self.held_delivery(state='accepted')
        args=dict(batch_id='held', provider='email', destination_id='viewer@example.test', action='discard')
        self.assertEqual(self.post('/settings/notifications/review', **args).status_code, 404)
        self.held_delivery(destination='legacy-held', batch='legacy')
        self.assertEqual(self.post('/settings/notifications/review', batch_id='legacy', provider='email', destination_id='legacy-held', action='retry', confirm_duplicate='1').status_code, 404)
        self.assertEqual(self.post('/settings/notifications/review', batch_id='legacy', provider='email', destination_id='legacy-held', action='discard').status_code, 303)
        self.assertEqual(self.query("SELECT state FROM notification_dispatches WHERE batch_id='held'"), [('accepted',)])

    def test_owner_test_review_only_discards_own_record_and_does_not_resend(self):
        reservation = self.settings.reserve_test(notification_settings.Actor('owner', True, True), 'email', now=900)
        self.settings.complete_test(reservation.id, notifications.Outcome('review', 'email_uncertain'), now=901)
        self.assertEqual(self.post('/settings/notifications/review', batch_id='test:' + reservation.id, provider='email', destination_id='viewer', action='discard').status_code, 404)
        self.assertEqual(self.post('/settings/notifications/review', batch_id='test:' + reservation.id, provider='email', destination_id='owner', action='discard').status_code, 303)
        self.assertEqual(self.query('SELECT state FROM notification_test_attempts'), [('cancelled',)])
        self.email_send.assert_not_called()

    def test_stale_test_discard_requires_own_attempt_and_strict_deadline(self):
        owner = notification_settings.Actor('owner', True, True)
        reservation = self.settings.reserve_test(owner, 'email', now=1000)
        self.assertFalse(self.settings.discard_test(owner, reservation.id, now=1045))
        self.assertFalse(self.settings.discard_test(notification_settings.Actor('viewer', True), reservation.id, now=1046))
        self.assertEqual(self.query('SELECT state FROM notification_test_attempts'), [('reserved',)])
        self.assertTrue(self.settings.discard_test(owner, reservation.id, now=1046))
        self.assertEqual(self.query('SELECT state,finished_at FROM notification_test_attempts'), [('cancelled', 1046)])
        self.assertFalse(self.settings.complete_test(reservation.id, notifications.Outcome('accepted'), now=1047))

    def test_stale_test_can_be_discarded_after_key_removal_without_sending_or_restoring_key(self):
        self.install()
        self.push_preferences()
        owner = notification_settings.Actor('owner', True, True)
        reservation = self.settings.reserve_test(owner, 'notification', now=1000)
        self.settings.save_preferences(owner, enabled=False, collections={1}, events=notifications.MEDIA_EVENTS,
            available_collections=self.collections, key_mode='clear', now=1010)
        self.clock = 1046
        with self.app.test_request_context('/preferences'):
            session['user_id'] = 'owner'
            context = self.routes.preferences_context('owner@example.test')
        self.assertEqual(context['test_reviews'][0]['batch_id'], 'test:' + reservation.id)
        self.assertTrue(context['test_reviews'][0]['review_needed'])
        response = self.post('/settings/notifications/review', batch_id='test:' + reservation.id,
            provider='pushover', destination_id='owner', action='discard')
        self.assertEqual(response.status_code, 303)
        self.assertEqual(self.query('SELECT user_key FROM pushover_preferences'), [('',)])
        self.push_send.assert_not_called()

    def test_discard_never_cancels_active_send_accepted_proof_or_old_validation(self):
        self.install()
        self.push_preferences()
        owner = notification_settings.Actor('owner', True, True)
        accepted = self.settings.reserve_test(owner, 'email', now=1000)
        self.settings.complete_test(accepted.id, notifications.Outcome('accepted'), now=1001)
        validation = self.settings.reserve_test(owner, 'validation', now=1100)
        self.assertFalse(self.settings.discard_test(owner, accepted.id, now=1200))
        self.assertFalse(self.settings.discard_test(owner, validation.id, now=1200))
        self.clock = 1200
        fresh = self.settings.reserve_test(owner, 'notification', now=1200)
        response = self.post('/settings/notifications/review', batch_id='test:' + fresh.id,
            provider='pushover', destination_id='owner', action='discard')
        self.assertEqual(response.status_code, 409)
        self.assertEqual(self.query('SELECT state FROM notification_test_attempts WHERE id=?', (fresh.id,)), [('reserved',)])

    def test_readonly_test_availability_matches_unconfigured_ready_and_cooldown_gates(self):
        owner = notification_settings.Actor('owner', True, True)
        before = self.path.read_bytes()
        view = self.settings.test_availability(owner, 'notification', now=1000)
        self.assertEqual(view, {'can_test': False, 'state': 'unconfigured', 'retry_after_seconds': 0})
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(self.settings.reserve_test(owner, 'notification', now=1000).state, view['state'])
        self.install()
        self.push_preferences()
        before = self.path.read_bytes()
        self.assertTrue(self.settings.test_availability(owner, 'notification', now=1000)['can_test'])
        self.assertEqual(self.path.read_bytes(), before)
        self.settings.reserve_test(owner, 'notification', now=1000)
        before = self.path.read_bytes()
        view = self.settings.test_availability(owner, 'notification', now=1001)
        self.assertEqual(self.path.read_bytes(), before)
        reservation = self.settings.reserve_test(owner, 'notification', now=1001)
        self.assertEqual((view['state'], view['retry_after_seconds']), (reservation.state, reservation.retry_after_seconds))

    def test_readonly_availability_sees_global_tests_from_other_accounts(self):
        self.install()
        self.push_preferences()
        self.push_preferences('viewer')
        owner, viewer = notification_settings.Actor('owner', True, True), notification_settings.Actor('viewer', True)
        self.settings.reserve_test(viewer, 'validation', now=1000)
        before = self.path.read_bytes()
        view = self.settings.test_availability(owner, 'notification', now=1001)
        self.assertEqual(view['state'], 'busy')
        self.assertEqual(self.path.read_bytes(), before)
        reserve = self.settings.reserve_test(owner, 'notification', now=1001)
        self.assertEqual((reserve.state, reserve.retry_after_seconds), (view['state'], view['retry_after_seconds']))
        response = self.client.get('/settings/notifications')
        self.assertIn('A notification test is already running.', response.text)
        self.assertNotIn('test:' + self.query('SELECT id FROM notification_test_attempts')[0][0], response.text)

    def test_readonly_availability_marks_stale_send_review_without_recovery_writes(self):
        owner = notification_settings.Actor('owner', True, True)
        self.settings.reserve_test(owner, 'email', now=1000)
        before = self.path.read_bytes()
        view = self.settings.test_availability(owner, 'email', now=1046)
        self.assertEqual(view['state'], 'review')
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(self.query('SELECT state FROM notification_test_attempts'), [('reserved',)])
        self.assertEqual(self.settings.reserve_test(owner, 'email', now=1046).state, view['state'])
        self.assertEqual(self.query('SELECT state FROM notification_test_attempts'), [('review',)])

    def test_readonly_availability_matches_quota_after_provider_toggle(self):
        self.install()
        self.push_preferences()
        owner = notification_settings.Actor('owner', True, True)
        reserved = self.settings.reserve_test(owner, 'notification', now=1000)
        self.settings.complete_test(reserved.id, notifications.Outcome('retry', 'quota', retry_at=4000), now=1001)
        self.settings.save_installation(owner, enabled=False, now=1002)
        before = self.path.read_bytes()
        view = self.settings.test_availability(owner, 'notification', now=1100)
        self.assertEqual(view, {'can_test': False, 'state': 'quota', 'retry_after_seconds': 2900})
        self.assertEqual(self.path.read_bytes(), before)
        reserve = self.settings.reserve_test(owner, 'notification', now=1100)
        self.assertEqual((reserve.state, reserve.retry_after_seconds), (view['state'], view['retry_after_seconds']))
        self.assertTrue(self.settings.test_availability(owner, 'validation', now=1100)['can_test'])
        with self.app.test_request_context('/preferences'):
            session['user_id'] = 'owner'
            context = self.routes.preferences_context('owner@example.test')
        self.assertFalse(context['push_preferences']['can_test'])

    def test_readonly_availability_does_not_create_missing_attempt_table_and_rechecks_access(self):
        owner = notification_settings.Actor('owner', True, True)
        with sqlite3.connect(self.path) as db:
            db.execute('DROP TABLE notification_test_attempts')
        before = self.path.read_bytes()
        self.assertTrue(self.settings.test_availability(owner, 'email', now=1000)['can_test'])
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(self.query("SELECT name FROM sqlite_master WHERE name='notification_test_attempts'"), [])
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE user_profiles SET status='disabled' WHERE plex_id='owner'")
        with self.assertRaises(PermissionError):
            self.settings.test_availability(owner, 'email', now=1000)

    def test_history_masks_push_keys_and_formats_labels_without_provider_errors(self):
        self.install()
        self.push_preferences('viewer')
        self.held_delivery(provider='pushover', destination='viewer')
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE notification_dispatches SET error_code='private-token',request_id=?", ('B' * 30,))
        response = self.client.get('/settings/notifications')
        self.assertIn('Pushover · Viewer', response.text)
        self.assertIn('Delivery needs review', response.text)
        self.assertNotIn('private-token', response.text)
        self.assertNotIn('B' * 30, response.text)

    def test_personal_push_save_is_independent_and_retains_disabled_selections(self):
        self.install()
        self.push_preferences('viewer')
        self.login('viewer')
        before_email = self.query('SELECT * FROM email_recipients')
        result = self.post('/test-preferences', action='pushover', key_mode='keep', device='phone')
        self.assertTrue(result.json['saved'])
        view = self.settings.preferences_view(notification_settings.Actor('viewer', True), available_collections=self.collections)
        self.assertFalse(view['enabled'])
        self.assertEqual(view['collections'], {1})
        self.assertEqual(view['events'], notifications.MEDIA_EVENTS)
        self.assertEqual(self.query('SELECT * FROM email_recipients'), before_email)

    def test_personal_push_rejects_invalid_choices_owner_events_and_missing_csrf(self):
        self.install()
        self.push_preferences('viewer')
        self.login('viewer')
        before = self.query('SELECT * FROM pushover_preferences')
        self.assertEqual(self.client.post('/test-preferences', data={'action':'pushover','csrf_token':'wrong'}).status_code, 403)
        for values in ({'pushover_collection_id':'bad'}, {'pushover_collection_id':'99'}, {'pushover_event':'JOB_FAILED'}):
            response = self.post('/test-preferences', action='pushover', receive_pushover='1', key_mode='keep', **values)
            self.assertFalse(response.json['saved'])
            self.assertIsNotNone(response.json['error'])
        self.assertEqual(self.query('SELECT * FROM pushover_preferences'), before)

    def test_personal_test_uses_only_saved_own_credentials_and_feedback_does_not_mark_saved(self):
        self.install()
        self.push_preferences('viewer')
        self.login('viewer')
        response = self.post('/test-preferences', action='test-pushover', user_key='C' * 30, email='owner@example.test')
        self.assertFalse(response.json['saved'])
        self.assertEqual(response.json['test_feedback'], 'Test notification sent.')
        self.assertEqual(self.push_send.call_args.args[0].user_key, 'B' * 30)
        self.assertNotIn('B' * 30, response.text)

    def test_personal_discard_reviews_only_own_test_and_preserves_preferences(self):
        self.install()
        self.push_preferences('viewer')
        actor = notification_settings.Actor('viewer', True)
        reserved = self.settings.reserve_test(actor, 'notification', now=900)
        self.settings.complete_test(reserved.id, notifications.Outcome('review'), now=901)
        before = self.query('SELECT * FROM pushover_preferences')
        response = self.post('/test-preferences', action='discard-pushover-test', test_id=reserved.id)
        self.assertIsNotNone(response.json['error'])
        self.assertEqual(self.query('SELECT state FROM notification_test_attempts'), [('review',)])
        self.login('viewer')
        response = self.post('/test-preferences', action='discard-pushover-test', test_id=reserved.id)
        self.assertIsNone(response.json['error'])
        self.assertFalse(response.json['saved'])
        self.assertEqual(response.json['test_feedback'], 'Test delivery discarded.')
        self.assertEqual(self.query('SELECT * FROM pushover_preferences'), before)
        self.assertEqual(self.query('SELECT state FROM notification_test_attempts'), [('cancelled',)])
        self.push_send.assert_not_called()

    def test_account_lookup_storage_failure_returns_fixed_no_store_response(self):
        with patch.object(self.adapter, 'current_account_session', side_effect=sqlite3.OperationalError('private-path-secret')):
            response = self.client.get('/settings/notifications')
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.headers['Cache-Control'], 'no-store')
        self.assertNotIn('private-path-secret', response.text)

    def test_personal_context_filters_owner_events_and_test_reviews_to_current_account(self):
        self.install()
        self.push_preferences('viewer')
        self.push_preferences('owner')
        reservation = self.settings.reserve_test(notification_settings.Actor('owner', True, True), 'notification', now=900)
        self.settings.complete_test(reservation.id, notifications.Outcome('review'), now=901)
        self.settings.save_email_events(notification_settings.Actor('owner', True, True), 'owner@example.test', notifications.EVENTS)
        with self.app.test_request_context('/preferences'):
            session['user_id'] = 'viewer'
            context = self.routes.preferences_context('owner@example.test')
        self.assertEqual(context['test_reviews'], [])
        self.assertEqual(context['email_events'], set(notifications.MEDIA_EVENTS))

    def test_legacy_email_action_is_unhandled_for_root_atomic_appearance_email_save(self):
        response = self.post('/test-preferences', action='email')
        self.assertFalse(response.json['handled'])
        self.assertFalse(response.json['saved'])

    def test_storage_errors_produce_fixed_service_response(self):
        with patch.object(notification_settings.Settings, 'preferences_view', side_effect=sqlite3.OperationalError('private-path-secret')):
            response = self.client.get('/settings/notifications')
        self.assertEqual(response.status_code, 503)
        self.assertNotIn('private-path-secret', response.text)


if __name__ == '__main__':
    unittest.main()
