"""Write-boundary authority regressions through isolated real Flask routes."""
from contextlib import closing
import os
from unittest import TestCase
from unittest.mock import patch

from connection_settings import ConnectionSettings
import notification_settings
import notifications
import test_notification_app_routes as fixture

keep = fixture.keep


class NotificationSessionRaceTests(TestCase):
    setUp = fixture.NotificationAppRoutesTests.setUp
    login = fixture.NotificationAppRoutesTests.login
    post = fixture.NotificationAppRoutesTests.post
    query = fixture.NotificationAppRoutesTests.query
    settings = fixture.NotificationAppRoutesTests.settings
    install = fixture.NotificationAppRoutesTests.install
    push = fixture.NotificationAppRoutesTests.push

    def revoke(self, user_id='7'):
        with closing(keep.attribution_db()) as db, db:
            db.execute('UPDATE user_profiles SET session_version=session_version+1 WHERE plex_id=?', (user_id,))

    def test_viewer_session_revoked_between_provider_sync_and_personal_save_preserves_key_and_preferences(self):
        self.install()
        self.push('8')
        self.login('8')
        before = self.query("SELECT * FROM pushover_preferences WHERE user_id='8'")
        synchronize = notification_settings.Settings.synchronize
        def revoked(store, **kwargs):
            result = synchronize(store, **kwargs)
            self.revoke('8')
            return result
        with patch.object(notification_settings.Settings, 'synchronize', revoked):
            response = self.post('/preferences?fragment=1', action='pushover', receive_pushover='1',
                pushover_collection_id=str(self.cid), pushover_event=notifications.REMINDER,
                key_mode='replace', user_key='C' * 30, device='phone')
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.query("SELECT * FROM pushover_preferences WHERE user_id='8'"), before)
        self.email_send.assert_not_called()
        self.push_send.assert_not_called()

    def test_owner_revocation_before_pushover_write_cannot_replace_token_or_disable_provider(self):
        self.install()
        before = self.query('SELECT * FROM connection_settings ORDER BY name')
        save = ConnectionSettings.save
        def revoked(connection, *args, **kwargs):
            self.revoke()
            return save(connection, *args, **kwargs)
        with patch.object(ConnectionSettings, 'save', revoked):
            response = self.post('/settings/notifications/pushover', token_mode='replace', app_token='C' * 30)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.query('SELECT * FROM connection_settings ORDER BY name'), before)
        self.email_send.assert_not_called()
        self.push_send.assert_not_called()

    def test_owner_revocation_before_email_provider_write_cannot_disable_email(self):
        environment = {name: value for name, value in os.environ.items() if name != 'EMAIL_ENABLED'}
        with patch.dict(os.environ, environment, clear=True):
            self.connections.save({'EMAIL_ENABLED': 'true'})
            before = self.query('SELECT * FROM connection_settings ORDER BY name')
            save = ConnectionSettings.save
            def revoked(connection, *args, **kwargs):
                self.revoke()
                return save(connection, *args, **kwargs)
            with patch.object(ConnectionSettings, 'save', revoked):
                response = self.post('/settings/notifications/email')
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.query('SELECT * FROM connection_settings ORDER BY name'), before)

    def test_owner_revocation_before_review_write_cannot_queue_resend_or_discard(self):
        for action in ('retry', 'discard'):
            with self.subTest(action=action):
                with closing(keep.attribution_db()) as db, db:
                    db.execute("UPDATE user_profiles SET session_version=0 WHERE plex_id='7'")
                    db.execute("INSERT OR IGNORE INTO notification_batches VALUES ('held','review',100,NULL)")
                    db.execute("INSERT OR IGNORE INTO notification_runs(batch_id) VALUES ('held')")
                    db.execute('''INSERT OR REPLACE INTO notification_dispatches
                        (batch_id,provider,destination_id,generation,state,created_at,last_attempt,error_code)
                        VALUES ('held','email','viewer@example.com','generation','review',100,110,'email_uncertain')''')
                before = self.query('SELECT * FROM notification_dispatches')
                resolve = notifications.Store.resolve_review
                def revoked(store, *args, **kwargs):
                    self.revoke()
                    return resolve(store, *args, **kwargs)
                with patch.object(notifications.Store, 'resolve_review', revoked):
                    response = self.post('/settings/notifications/review', batch_id='held', provider='email',
                        destination_id='viewer@example.com', action=action, confirm_duplicate='1')
                self.assertEqual(response.status_code, 403)
                self.assertEqual(self.query('SELECT * FROM notification_dispatches'), before)
                self.assertEqual(self.query("SELECT status FROM notification_batches WHERE id='held'"), [('review',)])
        self.email_send.assert_not_called()
        self.push_send.assert_not_called()

    def test_revoked_email_off_save_without_account_address_cannot_change_appearance(self):
        with closing(keep.attribution_db()) as db, db:
            db.execute("UPDATE user_profiles SET email='' WHERE plex_id='8'")
        self.login('8')
        before = self.query("SELECT theme_mode FROM user_profiles WHERE plex_id='8'")
        collections = keep.recipient_collection_ids
        def revoked():
            result = collections()
            self.revoke('8')
            return result
        with patch.object(keep, 'recipient_collection_ids', revoked):
            response = self.post('/preferences?fragment=1', action='email', theme_mode='light')
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.query("SELECT theme_mode FROM user_profiles WHERE plex_id='8'"), before)

    def test_actor_uses_cookie_version_and_missing_version_fails_closed(self):
        with keep.app.test_request_context('/preferences'):
            keep.session['plex_user'] = {'id': '7', 'session_version': 1}
            actor = keep.notification_actor()
            self.assertEqual(actor.session_version, 1)
            with self.assertRaises(PermissionError):
                self.settings().preferences_view(actor, available_collections=keep.get_collections())
            keep.session['plex_user'].pop('session_version')
            actor = keep.notification_actor()
            self.assertEqual(actor.session_version, -1)
            with self.assertRaises(PermissionError):
                self.settings().preferences_view(actor, available_collections=keep.get_collections())

    def test_pushover_token_is_not_revealed_by_the_existing_connection_secret_endpoint(self):
        self.install()
        response = self.post('/settings/connections/reveal', name='PUSHOVER_APP_TOKEN')
        self.assertEqual(response.status_code, 403)
        self.assertNotIn('A' * 30, response.text)
        self.assertEqual(response.headers['Cache-Control'], 'no-store')
        self.connections.save({'RADARR_API_KEY': 'synthetic-existing-secret'})
        response = self.post('/settings/connections/reveal', name='RADARR_API_KEY')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json, {'value': 'synthetic-existing-secret'})

    def test_invalid_optional_push_configuration_keeps_about_preferences_email_and_reminders_available(self):
        self.install()
        self.push()
        self.connections.save({'KEEP_URL': 'https://keep.example.test'})
        invalid = 'invalid-private-token'
        with patch.dict(os.environ, {'PUSHOVER_APP_TOKEN': invalid}):
            for path in ('/settings/about', '/settings/notifications', '/preferences', '/preferences?fragment=1'):
                with self.subTest(path=path):
                    response = self.client.get(path)
                    self.assertEqual(response.status_code, 200)
                    self.assertNotIn(invalid, response.text)
            self.assertEqual(keep.notification_runtime().enabled_providers(), {'email'})
            self.assertEqual(keep.notification_enabled_providers(), {'email'})
            with patch.object(keep, 'digest_collection_items', return_value={}) as items, \
                 patch.object(keep, 'get_collection_delete_after_days', return_value=30):
                self.assertEqual(keep.queue_due_reminders(now=1000), 0)
                items.assert_called()
            keep.queue_notifications(self.cid, {'one'}, notifications.ADDED, now=1000)
            resolved = [{'collection_id': self.cid, 'media_id': 'one', 'title': 'One',
                         'collection': 'Movies', 'year': 2026, 'days': 30, 'urgent': False}]
            with patch.object(keep, 'resolve_digest', return_value=resolved):
                self.assertEqual(keep.process_digest(now=2000), 'sent')
            self.email_send.assert_called_once()
            self.push_send.assert_not_called()
            self.assertEqual(self.query('SELECT * FROM notification_queue'), [])
            response = self.post('/settings/notifications/test/email')
            self.assertEqual(response.status_code, 303)
            self.assertEqual(self.email_send.call_count, 2)
            self.assertEqual(self.email_send.call_args.args[0], ['owner@example.com'])
            self.assertEqual(self.query('SELECT kind,state FROM notification_test_attempts'), [('email', 'accepted')])
            self.push_send.assert_not_called()
