"""Notification integration through Keep's real authenticated Flask routes."""
from contextlib import closing
from html.parser import HTMLParser
import os
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import Mock, patch

from connection_settings import ConnectionSettings
from onboarding import Onboarding
import notification_settings
import notifications
import pushover
import test_keep

keep = test_keep.keep


class Forms(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.forms, self.current = [], None
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == 'form':
            self.current = {'attrs': values, 'fields': []}
            self.forms.append(self.current)
        elif self.current and tag in ('input', 'select', 'button'):
            self.current['fields'].append({'tag': tag, **values})

    def handle_endtag(self, tag):
        if tag == 'form':
            self.current = None


class NotificationAppRoutesTests(TestCase):
    def setUp(self):
        # Keep's shared test fixture already points at a temporary test database.
        # Copy its complete schema so this suite neither shares rows nor production state.
        self.directory = TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / 'app-routes.sqlite3'
        with sqlite3.connect(keep.KEEP_DB_PATH) as source, sqlite3.connect(self.path) as destination:
            source.backup(destination)
        self.connections = ConnectionSettings(self.path)
        for target, name, value in ((keep, 'KEEP_DB_PATH', str(self.path)),
                                    (keep, 'connection_settings', self.connections),
                                    (keep, 'onboarding', Onboarding(self.path)),
                                    (keep.notification_routes.adapter, 'connections', self.connections)):
            mocked = patch.object(target, name, value)
            mocked.start()
            self.addCleanup(mocked.stop)
        test_keep.KeepTests.setUp(self)
        with closing(keep.attribution_db()) as db, db:
            for table in ('notification_test_attempts', 'pushover_preferences', 'notification_provider_generations',
                          'notification_email_events', 'notification_dispatches', 'notification_runs',
                          'notification_destination_epochs', 'notification_cooldowns', 'notification_operational_events',
                          'notification_transitions', 'notification_deliveries', 'notification_queue',
                          'notification_batches', 'recipient_subscriptions', 'email_recipients'):
                db.execute('DELETE FROM ' + table)
            db.execute("INSERT INTO email_recipients(email,enabled) VALUES ('owner@example.com',1)")
            keep.ensure_recipient_subscriptions(db, 'owner@example.com')
            db.execute("""INSERT INTO user_profiles
                (plex_id,plex_username,email,auth_type,status,plex_access,plex_checked_at)
                VALUES ('8','Viewer','viewer@example.com','plex','active','active',CURRENT_TIMESTAMP),
                       ('local-test','Local','local@example.com','local','active','active',CURRENT_TIMESTAMP)""")
        self.clock = 1000
        mocked = patch.object(keep.notification_routes.adapter, 'now', lambda: self.clock, create=True)
        mocked.start()
        self.addCleanup(mocked.stop)
        self.email_send = Mock()
        self.push_send = Mock(return_value=pushover.Result('accepted'))
        for target, name, value in ((keep, 'send_notification_email', self.email_send), (keep.pushover, 'send', self.push_send)):
            mocked = patch.object(target, name, value)
            mocked.start()
            self.addCleanup(mocked.stop)
        blocked = patch.object(keep.requests.sessions.Session, 'request', side_effect=AssertionError('Unexpected network call'))
        blocked.start()
        self.addCleanup(blocked.stop)

    def login(self, user_id, auth_type='plex'):
        with self.client.session_transaction() as saved:
            saved['plex_user'] = {'id': user_id, 'username': 'Synthetic', 'auth_type': auth_type, 'session_version': 0}
            saved['csrf_token'] = 'test-csrf'

    def post(self, path, **data):
        return self.client.post(path, data={'csrf_token': 'test-csrf', **data})

    def query(self, sql, args=()):
        with closing(keep.attribution_db()) as db:
            return [tuple(row) for row in db.execute(sql, args)]

    def settings(self):
        return keep.notification_settings_store()

    def install(self):
        self.settings().save_installation(notification_settings.Actor('7', True, True),
            enabled=True, token_mode='replace', token='A' * 30, now=100)

    def push(self, user_id='7'):
        self.settings().save_preferences(notification_settings.Actor(user_id, True, user_id == '7'),
            enabled=True, key_mode='replace', user_key='B' * 30, collections={self.cid},
            events=notifications.MEDIA_EVENTS, available_collections=keep.get_collections(), now=200)

    def test_owner_and_viewer_full_and_fragment_preferences_render_two_independent_channels(self):
        self.install()
        self.push()
        self.push('8')
        for user_id in ('7', '8'):
            self.login(user_id)
            for path in ('/preferences', '/preferences?fragment=1'):
                with self.subTest(user=user_id, path=path):
                    response = self.client.get(path)
                    self.assertEqual(response.status_code, 200)
                    html = response.text
                    forms = Forms(html).forms
                    channels = [form for form in forms if 'data-notification-channel' in form['attrs']]
                    self.assertEqual([form['attrs']['data-notification-channel'] for form in channels], ['email', 'pushover'])
                    self.assertTrue(any(field.get('name') == 'email_event_present' for field in channels[0]['fields']))
                    self.assertNotIn('A' * 30, html)
                    self.assertNotIn('B' * 30, html)
                    self.assertTrue(all('value' not in field for form in forms for field in form['fields'] if field.get('type') == 'password'))
                    self.assertEqual('value="JOB_FAILED"' in html, user_id == '7')
                    if 'fragment' in path:
                        self.assertNotIn('<html', html)
                    else:
                        self.assertEqual(html.count('/static/keep-notifications.css?'), 1)
        self.email_send.assert_not_called()
        self.push_send.assert_not_called()

    def test_owner_notifications_get_and_legacy_redirect_are_safe_and_readonly(self):
        self.install()
        self.push()
        before = self.query('SELECT * FROM notification_test_attempts')
        for path in ('/settings/notifications', '/settings/email'):
            response = self.client.get(path)
            self.assertEqual(response.headers['Cache-Control'], 'no-store')
            if path.endswith('/email'):
                self.assertEqual(response.status_code, 302)
                self.assertEqual(response.headers['Location'], '/settings/notifications')
            else:
                self.assertEqual(response.status_code, 200)
                self.assertIn('href="/settings/notifications" class="active"', response.text)
                self.assertEqual(response.text.count('/static/keep-notifications.css?'), 1)
                self.assertEqual(response.text.count('/static/keep-notifications.js?'), 1)
                self.assertNotIn('A' * 30, response.text)
                self.assertNotIn('B' * 30, response.text)
        self.assertEqual(self.query('SELECT * FROM notification_test_attempts'), before)
        self.email_send.assert_not_called()
        self.push_send.assert_not_called()
        self.login('8')
        self.assertEqual(self.client.get('/settings/notifications').status_code, 403)
        self.assertEqual(self.client.get('/settings/email').status_code, 403)

    def test_email_theme_and_events_save_atomically_without_changing_push(self):
        self.install()
        self.push()
        push = self.query('SELECT * FROM pushover_preferences')
        response = self.post('/preferences', action='email', theme_mode='light', receive_email='1',
            collection_id=str(self.cid), email_event_present='1', email_event='MEDIA_ABOUT_TO_BE_HANDLED')
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.query("SELECT theme_mode FROM user_profiles WHERE plex_id='7'"), [('light',)])
        self.assertEqual(self.settings().email_event_preferences('owner@example.com')['events'], frozenset({notifications.REMINDER}))
        self.assertEqual(self.query('SELECT * FROM pushover_preferences'), push)
        with patch.object(notification_settings.Settings, 'save_email_events', side_effect=ValueError('private-token-error')):
            response = self.post('/preferences', action='email', theme_mode='dark', receive_email='1',
                collection_id='3', email_event_present='1', email_event='MEDIA_ADDED_TO_COLLECTION')
        self.assertEqual(response.status_code, 200)
        self.assertIn('Your account changed.', response.text)
        self.assertNotIn('private-token-error', response.text)
        self.assertEqual(self.query("SELECT theme_mode FROM user_profiles WHERE plex_id='7'"), [('light',)])
        self.assertEqual(self.settings().email_event_preferences('owner@example.com')['events'], frozenset({notifications.REMINDER}))
        self.assertEqual(self.query("SELECT collection_id FROM recipient_subscriptions WHERE email='owner@example.com' AND enabled=1"), [(self.cid,)])

    def test_appearance_only_save_for_an_account_without_an_email_recipient_still_succeeds(self):
        self.login('8')
        response = self.post('/preferences', action='email', theme_mode='light')
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.query("SELECT theme_mode FROM user_profiles WHERE plex_id='8'"), [('light',)])
        self.assertNotEqual(self.query("SELECT enabled FROM email_recipients WHERE email='viewer@example.com'"), [(1,)])

    def test_legacy_email_save_preserves_events_and_disabled_collection_choices(self):
        self.settings().save_email_events(notification_settings.Actor('7', True, True), 'owner@example.com', {notifications.REMINDER})
        selected = self.query("SELECT collection_id FROM recipient_subscriptions WHERE email='owner@example.com' AND enabled=1")
        response = self.post('/preferences', theme_mode='dark')
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.query("SELECT enabled FROM email_recipients WHERE email='owner@example.com'"), [(0,)])
        self.assertEqual(self.query("SELECT collection_id FROM recipient_subscriptions WHERE email='owner@example.com' AND enabled=1"), selected)
        self.assertEqual(self.settings().email_event_preferences('owner@example.com')['events'], frozenset({notifications.REMINDER}))

    def test_intentionally_unchecked_events_are_rejected_while_email_is_enabled(self):
        before = self.query('SELECT * FROM user_profiles')
        response = self.post('/preferences?fragment=1', action='email', theme_mode='light', receive_email='1',
            collection_id=str(self.cid), email_event_present='1')
        self.assertEqual(response.status_code, 200)
        self.assertIn('Select at least one event', response.text)
        self.assertEqual(self.query('SELECT * FROM user_profiles'), before)

    def test_push_save_does_not_change_email_or_appearance_even_if_forged_fields_are_supplied(self):
        self.install()
        self.push()
        email = self.query('SELECT * FROM email_recipients')
        response = self.post('/preferences', action='pushover', receive_pushover='1', key_mode='keep',
            pushover_collection_id=str(self.cid), pushover_event='MEDIA_ADDED_TO_COLLECTION',
            device='phone', theme_mode='light', receive_email='1', email_event='JOB_FAILED')
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.query("SELECT theme_mode FROM user_profiles WHERE plex_id='7'"), [('system',)])
        self.assertEqual(self.query('SELECT * FROM email_recipients'), email)
        self.assertEqual(self.query("SELECT device FROM pushover_preferences WHERE user_id='7'"), [('phone',)])
        self.assertEqual(self.settings().email_event_preferences('owner@example.com')['events'], notifications.MEDIA_EVENTS)

    def test_viewers_cannot_opt_in_to_owner_operational_events_on_either_channel(self):
        self.install()
        self.push('8')
        self.login('8')
        for values in ({'action':'email','receive_email':'1','collection_id':str(self.cid),'email_event':'JOB_FAILED'},
                       {'action':'pushover','receive_pushover':'1','pushover_collection_id':str(self.cid),'pushover_event':'JOB_FAILED'}):
            before = self.query('SELECT * FROM pushover_preferences')
            response = self.post('/preferences?fragment=1', **values)
            self.assertEqual(response.status_code, 200)
            self.assertIn('role="alert"', response.text)
            self.assertEqual(self.query('SELECT * FROM pushover_preferences'), before)
        self.assertEqual(self.query("SELECT email FROM email_recipients WHERE email='viewer@example.com'"), [])

    def test_recipient_create_errors_and_notices_use_notifications_and_preserve_edit_state(self):
        response = self.post('/settings/recipients', action='add', email='bad-address')
        self.assertEqual(response.status_code, 400)
        self.assertIn('href="/settings/notifications" class="active"', response.text)
        self.assertIn('data-refresh-url="/settings/notifications"', response.text)
        self.assertIn('value="bad-address"', response.text)
        response = self.post('/settings/recipients', action='add', email='friend@example.com')
        self.assertEqual(response.headers['Location'], '/settings/notifications')
        self.assertIn('Recipient settings saved.', self.client.get(response.headers['Location']).text)
        response = self.post('/settings/recipients/preferences', email='friend@example.com')
        self.assertEqual(response.headers['Location'], '/settings/notifications')
        page = self.client.get(response.headers['Location']).text
        self.assertIn('Close settings for friend@example.com', page)
        self.assertIn('Choose at least one email topic', page)

    def test_last_enabled_email_recipient_can_be_disabled_and_removed(self):
        response = self.post('/settings/recipients', action='disable', email='owner@example.com')
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.query('SELECT COUNT(*) FROM email_recipients WHERE enabled=1'), [(0,)])
        response = self.post('/settings/recipients', action='remove', email='owner@example.com')
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.query('SELECT * FROM email_recipients'), [])

    def test_owner_tests_and_personal_push_actions_require_csrf(self):
        self.install()
        self.push()
        for path, data in (('/settings/notifications/test/email', {}),
                           ('/settings/notifications/test/pushover', {}),
                           ('/preferences?fragment=1', {'action':'test-pushover'}),
                           ('/preferences', {'action':'pushover','key_mode':'clear'})):
            self.assertEqual(self.client.post(path, data={'csrf_token':'wrong', **data}).status_code, 403)
        self.email_send.assert_not_called()
        self.push_send.assert_not_called()

    def test_real_sender_wrappers_use_fixed_body_and_saved_own_credentials_with_durable_cooldown(self):
        self.install()
        self.push()
        response = self.post('/settings/notifications/test/email', email='other@example.com', subject='Injected', message='Injected')
        self.assertEqual(response.status_code, 303)
        args = self.email_send.call_args.args
        self.assertEqual(args[0], ['owner@example.com'])
        self.assertEqual(args[1], 'Keep: Keep test notification')
        self.assertNotIn('Injected', ' '.join(map(str, args)))
        self.assertEqual(self.post('/settings/notifications/test/email').status_code, 400)
        self.assertEqual(self.email_send.call_count, 1)
        response = self.post('/preferences?fragment=1', action='test-pushover', app_token='C'*30, user_key='D'*30, device='forged', message='Injected')
        self.assertEqual(response.status_code, 200)
        args, values = self.push_send.call_args
        self.assertEqual(args[:2], ('A'*30, 'B'*30))
        self.assertEqual(args[2], 'Your Keep Pushover notifications are working.')
        self.assertEqual(values['title'], 'Keep test notification')
        self.assertEqual(values['device'], '')
        self.assertIn('Test notification sent.', response.text)
        self.assertNotIn('Your preferences were saved.', response.text)
        self.assertNotIn('B'*30, response.text)
        self.assertEqual(self.post('/preferences?fragment=1', action='test-pushover').status_code, 200)
        self.assertEqual(self.push_send.call_count, 1)

    def test_fresh_key_change_between_reservation_and_real_test_send_blocks_transport(self):
        self.install()
        self.push()
        reserve = notification_settings.Settings.reserve_test
        def changed(store, *args, **kwargs):
            reservation = reserve(store, *args, **kwargs)
            with closing(keep.attribution_db()) as db, db:
                db.execute("UPDATE pushover_preferences SET generation='changed',user_key=? WHERE user_id='7'", ('C'*30,))
            return reservation
        with patch.object(notification_settings.Settings, 'reserve_test', changed):
            response = self.post('/settings/notifications/test/pushover')
        self.assertEqual(response.status_code, 400)
        self.push_send.assert_not_called()
        self.assertEqual(self.query('SELECT state,error_code FROM notification_test_attempts'), [('cancelled','preferences_changed')])

    def test_deleting_local_account_removes_push_key_but_retains_standalone_email_recipient(self):
        self.install()
        self.push('local-test')
        with closing(keep.attribution_db()) as db, db:
            db.execute("INSERT INTO email_recipients(email,enabled) VALUES ('local@example.com',1)")
            keep.ensure_recipient_subscriptions(db, 'local@example.com')
        response = self.post('/settings/users/local-test/access', action='delete')
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.query("SELECT * FROM user_profiles WHERE plex_id='local-test'"), [])
        self.assertEqual(self.query("SELECT * FROM pushover_preferences WHERE user_id='local-test'"), [])
        self.assertEqual(self.query("SELECT enabled FROM email_recipients WHERE email='local@example.com'"), [(1,)])


if __name__ == '__main__':
    import unittest
    unittest.main()
