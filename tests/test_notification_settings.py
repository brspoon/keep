from dataclasses import replace
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from connection_settings import ConnectionSettings
import notification_settings as settings
import notifications


class NotificationSettingTests(unittest.TestCase):
    def setUp(self):
        self.environment = patch.dict(os.environ, {}, clear=True)
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / 'preferences.sqlite3'
        self.connections = ConnectionSettings(self.path)
        with sqlite3.connect(self.path) as db:
            db.executescript('''
                CREATE TABLE user_profiles(plex_id TEXT PRIMARY KEY,status TEXT,auth_type TEXT,plex_access TEXT,email TEXT);
                INSERT INTO user_profiles VALUES ('owner','active','plex','active','Owner@Example.test');
                INSERT INTO user_profiles VALUES ('user','active','plex','active','shared@example.test');
                INSERT INTO user_profiles VALUES ('local','active','local','active','shared@example.test');
                CREATE TABLE notification_queue(id INTEGER PRIMARY KEY AUTOINCREMENT,
                    collection_id INTEGER,media_id TEXT,kind TEXT,received_at REAL,batch_id TEXT);
                CREATE TABLE notification_batches(id TEXT PRIMARY KEY,status TEXT,created_at REAL,detail TEXT);
                CREATE TABLE notification_deliveries(batch_id TEXT,email TEXT,sent_at REAL,PRIMARY KEY(batch_id,email));
                CREATE TABLE email_recipients(email TEXT PRIMARY KEY,enabled INTEGER);
                CREATE TABLE recipient_subscriptions(email TEXT,collection_id INTEGER,enabled INTEGER);
                INSERT INTO email_recipients VALUES ('OriginalCase@Example.test',1);
                INSERT INTO recipient_subscriptions VALUES ('OriginalCase@Example.test',1,1);
            ''')
        self.access = lambda profile: profile['auth_type'] == 'local' or profile['plex_access'] == 'active'
        self.store = settings.Settings(self.path, connections=self.connections, owner_id=lambda: 'owner', profile_access=self.access)
        self.owner = settings.Actor('owner', True, True)
        self.user = settings.Actor('user', True)
        self.collections = {1, 2}

    def query(self, sql, args=()):
        with sqlite3.connect(self.path) as db:
            return db.execute(sql, args).fetchall()

    def install(self, **kwargs):
        return self.store.save_installation(self.owner, enabled=True, token_mode='replace', token='A' * 30, now=100, **kwargs)

    def preferences(self, actor=None, **kwargs):
        values = {'enabled': True, 'collections': {1}, 'events': notifications.MEDIA_EVENTS,
                  'available_collections': self.collections, 'key_mode': 'replace',
                  'user_key': 'B' * 30, 'now': 200, **kwargs}
        return self.store.save_preferences(actor or self.user, **values)

    def destinations(self):
        return self.store.destinations(available_collections=self.collections)

    def test_disabled_defaults_and_safe_masks_never_echo_provider_or_personal_secrets(self):
        self.assertFalse(self.store.installation_view()['enabled'])
        self.assertFalse(self.store.preferences_view(self.user, available_collections=self.collections)['enabled'])
        view = self.install()
        preferences = self.preferences()
        self.assertTrue(view['configured'])
        self.assertTrue(preferences['configured'])
        self.assertEqual(view['app_token'], '')
        self.assertEqual(preferences['user_key'], '')
        self.assertNotIn('A' * 30, str(view))
        self.assertNotIn('B' * 30, str(preferences))
        destination = self.destinations()[0]
        self.assertNotIn('B' * 30, str(destination))
        credentials = self.store.sending_credentials(destination, available_collections=self.collections)
        self.assertEqual(credentials.app_token, 'A' * 30)
        self.assertEqual(credentials.user_key, 'B' * 30)
        self.assertNotIn('A' * 30, str(credentials))
        self.assertNotIn('B' * 30, str(credentials))
        self.store.save_installation(self.owner, enabled=True, token_mode='clear')
        self.assertFalse(self.store.installation_view()['ready'])
        self.assertFalse(self.store.preferences_view(self.user, available_collections=self.collections)['provider_available'])

    def test_environment_precedence_and_managed_fields_cannot_be_written_or_cleared(self):
        self.install()
        with patch.dict(os.environ, {'PUSHOVER_APP_TOKEN': 'C' * 30, 'PUSHOVER_ENABLED': 'false'}):
            view = self.store.installation_view()
            self.assertFalse(view['enabled'])
            self.assertTrue(all(field['managed'] for field in view['fields'].values()))
            for values in ({'enabled': True}, {'token_mode': 'replace', 'token': 'D' * 30}, {'token_mode': 'clear'}):
                with self.assertRaises(ValueError):
                    self.store.save_installation(self.owner, **values)
            self.assertNotIn('C' * 30, str(view))
        self.assertEqual(self.connections.get('PUSHOVER_APP_TOKEN'), 'A' * 30)

    def test_invalid_optional_push_configuration_is_masked_in_views_but_strict_for_credentials_and_saves(self):
        self.install()
        self.preferences()
        destination = self.destinations()[0]
        for values in ({'PUSHOVER_APP_TOKEN': 'invalid-secret'}, {'PUSHOVER_ENABLED': 'invalid-enabled'}):
            with self.subTest(values=values), patch.dict(os.environ, values):
                snapshot = self.connections.snapshot()
                self.assertEqual(snapshot[next(iter(values))], '' if 'PUSHOVER_APP_TOKEN' in values else 'false')
                view = self.store.installation_view()
                self.assertFalse(view['enabled'])
                self.assertFalse(view['configured'])
                self.assertFalse(view['ready'])
                self.assertTrue(view['configuration_error'])
                self.assertNotIn(next(iter(values.values())), str(view))
                owner = self.store.preferences_view(self.owner, available_collections=self.collections)
                user = self.store.preferences_view(self.user, available_collections=self.collections)
                self.assertFalse(owner['provider_available'])
                self.assertTrue(owner['configuration_error'])
                self.assertEqual(user['configuration_error'], '')
                self.assertFalse(user['provider_available'])
                with self.assertRaises(ValueError):
                    self.store.sending_credentials(destination, available_collections=self.collections)
                with self.assertRaises(ValueError):
                    self.preferences()
                before = self.query('SELECT * FROM connection_settings ORDER BY name')
                with self.assertRaises(ValueError):
                    self.store.save_installation(self.owner, token_mode='keep')
                self.assertEqual(self.query('SELECT * FROM connection_settings ORDER BY name'), before)
        with patch.dict(os.environ, {'PLEX_SERVER_URL': 'invalid-url'}):
            with self.assertRaises(ValueError):
                self.connections.snapshot()

    def test_safe_push_views_do_not_hide_database_failures(self):
        with patch.object(self.store, '_connect', side_effect=sqlite3.OperationalError('unavailable')):
            with self.assertRaises(sqlite3.OperationalError):
                self.store.installation_view()

    def test_valid_provider_replacement_or_clear_can_repair_a_malformed_saved_token(self):
        self.install()
        for values in ({'token_mode': 'replace', 'token': 'C' * 30}, {'token_mode': 'clear'}):
            with self.subTest(values=values):
                with sqlite3.connect(self.path) as db:
                    db.execute("UPDATE connection_settings SET value='malformed' WHERE name='PUSHOVER_APP_TOKEN'")
                self.assertTrue(self.store.installation_view()['configuration_error'])
                view = self.store.save_installation(self.owner, **values)
                self.assertFalse(view['configuration_error'])
                self.assertEqual(self.connections.get('PUSHOVER_APP_TOKEN'), values.get('token', ''))

    def test_secret_blank_keep_replace_clear_and_validation_are_atomic(self):
        self.install()
        self.store.save_installation(self.owner, token_mode='replace', token='')
        self.assertEqual(self.connections.get('PUSHOVER_APP_TOKEN'), 'A' * 30)
        with self.assertRaises(ValueError):
            self.store.save_installation(self.owner, enabled=False, token_mode='replace', token='bad')
        self.assertEqual(self.connections.get('PUSHOVER_ENABLED'), 'true')
        self.preferences()
        self.preferences(key_mode='replace', user_key='', device='iphone')
        self.assertEqual(self.query('SELECT user_key,device FROM pushover_preferences'), [('B' * 30, 'iphone')])
        with self.assertRaises(ValueError):
            self.preferences(key_mode='clear')
        self.assertEqual(self.query('SELECT user_key FROM pushover_preferences'), [('B' * 30,)])
        self.preferences(enabled=False, key_mode='clear')
        self.assertFalse(self.store.preferences_view(self.user, available_collections=self.collections)['configured'])
        self.store.save_installation(self.owner, enabled=False, token_mode='clear')
        self.assertEqual(self.connections.get('PUSHOVER_APP_TOKEN'), '')

    def test_only_current_active_owner_can_change_installation_and_viewers_cannot_add_owner_events(self):
        for actor in (self.user, settings.Actor('owner', False, True), settings.Actor('user', True, True)):
            with self.assertRaises(PermissionError):
                self.store.save_installation(actor, enabled=True, token_mode='replace', token='A' * 30)
        with self.assertRaises(PermissionError):
            self.preferences(events=notifications.EVENTS)
        self.preferences(self.owner, events=notifications.EVENTS)
        self.assertTrue(self.destinations()[0].owner_verified)
        self.preferences(settings.Actor('local', True))
        self.assertFalse(next(target for target in self.destinations() if target.id == 'local').owner_verified)

    def test_inactive_or_revoked_profiles_cannot_read_save_or_send_with_a_stale_actor(self):
        self.install()
        self.preferences()
        destination = self.destinations()[0]
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE user_profiles SET plex_access='revoked' WHERE plex_id='user'")
        with self.assertRaises(PermissionError):
            self.preferences(key_mode='keep')
        with self.assertRaises(PermissionError):
            self.store.preferences_view(self.user, available_collections=self.collections)
        self.assertEqual(self.destinations(), [])
        self.assertIsNone(self.store.sending_credentials(destination, available_collections=self.collections))

    def test_session_authority_is_strict_and_legacy_profile_version_defaults_to_zero(self):
        self.assertFalse(self.store.preferences_view(self.user, available_collections=self.collections)['enabled'])
        for version in (None, True, False, -1, '0', 0.0, 1):
            with self.subTest(version=version), self.assertRaises(PermissionError):
                self.store.preferences_view(replace(self.user, session_version=version), available_collections=self.collections)
        with sqlite3.connect(self.path) as db:
            db.execute('ALTER TABLE user_profiles ADD COLUMN session_version INTEGER NOT NULL DEFAULT 0')
            db.execute("UPDATE user_profiles SET session_version=1 WHERE plex_id='user'")
        with self.assertRaises(PermissionError):
            self.preferences(key_mode='keep', enabled=False)
        current = replace(self.user, session_version=1)
        self.assertFalse(self.store.preferences_view(current, available_collections=self.collections)['enabled'])
        self.preferences(current)

    def test_session_revoked_after_synchronization_cannot_replace_personal_credentials_or_preferences(self):
        self.install()
        self.preferences()
        with sqlite3.connect(self.path) as db:
            db.execute('ALTER TABLE user_profiles ADD COLUMN session_version INTEGER NOT NULL DEFAULT 0')
        before = self.query('SELECT * FROM pushover_preferences')
        synchronize = self.store.synchronize
        def revoke(**kwargs):
            generation = synchronize(**kwargs)
            with sqlite3.connect(self.path) as db:
                db.execute("UPDATE user_profiles SET session_version=session_version+1 WHERE plex_id='user'")
            return generation
        with patch.object(self.store, 'synchronize', side_effect=revoke), self.assertRaises(PermissionError):
            self.preferences(user_key='C' * 30, device='phone', collections={2}, events={notifications.REMINDER})
        self.assertEqual(self.query('SELECT * FROM pushover_preferences'), before)

    def test_provider_mutations_revalidate_session_and_owner_under_the_connection_write_lock(self):
        self.install()
        with sqlite3.connect(self.path) as db:
            db.execute('ALTER TABLE user_profiles ADD COLUMN session_version INTEGER NOT NULL DEFAULT 0')
        save = self.connections.save
        for change in ({'session_version': 1}, {'status': 'disabled'}, {'plex_access': 'revoked'}, {'auth_type': 'local'}):
            for values in ({'token_mode': 'replace', 'token': 'C' * 30}, {'token_mode': 'clear'}, {'enabled': False}):
                with self.subTest(change=change, values=values):
                    with sqlite3.connect(self.path) as db:
                        db.execute("UPDATE user_profiles SET session_version=0,status='active',plex_access='active',auth_type='plex' WHERE plex_id='owner'")
                    before = self.query('SELECT * FROM connection_settings ORDER BY name')
                    def revoke_then_save(*args, **kwargs):
                        with sqlite3.connect(self.path) as db:
                            for name, value in change.items():
                                db.execute(f"UPDATE user_profiles SET {name}=? WHERE plex_id='owner'", (value,))
                        return save(*args, **kwargs)
                    with patch.object(self.connections, 'save', side_effect=revoke_then_save), self.assertRaises(PermissionError):
                        self.store.save_installation(self.owner, **values)
                    self.assertEqual(self.query('SELECT * FROM connection_settings ORDER BY name'), before)

    def test_connection_write_guard_is_locked_and_failure_rolls_back_secret_clearing(self):
        self.install()
        def guard(db):
            self.assertTrue(db.in_transaction)
            with sqlite3.connect(self.path, timeout=0) as concurrent:
                with self.assertRaises(sqlite3.OperationalError):
                    concurrent.execute("UPDATE user_profiles SET status='disabled' WHERE plex_id='owner'")
            raise PermissionError('revoked')
        with self.assertRaises(PermissionError):
            self.connections.save({'PUSHOVER_ENABLED': 'false'}, clear={'PUSHOVER_APP_TOKEN'}, guard=guard)
        self.assertEqual(self.connections.get('PUSHOVER_ENABLED'), 'true')
        self.assertEqual(self.connections.get('PUSHOVER_APP_TOKEN'), 'A' * 30)

    def test_invalid_collection_event_or_key_preferences_never_change_saved_data(self):
        self.install()
        self.preferences()
        before = self.query('SELECT * FROM pushover_preferences')
        for values in ({'collections': {99}}, {'collections': {True}}, {'events': {'unknown'}},
                       {'events': set()}, {'user_key': 'invalid'}, {'device': 'bad device'}, {'collections': set()}):
            with self.subTest(values=values):
                with self.assertRaises(ValueError):
                    self.preferences(**values)
                self.assertEqual(self.query('SELECT * FROM pushover_preferences'), before)

    def test_activation_reenable_rekey_and_provider_change_use_new_generation_and_boundaries(self):
        self.install()
        with sqlite3.connect(self.path) as db:
            db.execute("INSERT INTO notification_queue(collection_id,media_id,kind,received_at) VALUES (1,'old','MEDIA_ADDED_TO_COLLECTION',100)")
        self.preferences()
        initial = self.destinations()[0]
        self.assertEqual(initial.after_queue_id, 1)
        self.preferences(key_mode='keep', user_key='', collections={2})
        self.assertEqual(self.destinations()[0].generation, initial.generation)
        self.preferences(enabled=False, key_mode='keep')
        with sqlite3.connect(self.path) as db:
            db.execute("INSERT INTO notification_queue(collection_id,media_id,kind,received_at) VALUES (1,'while-disabled','MEDIA_ADDED_TO_COLLECTION',300)")
        self.preferences(key_mode='keep')
        reenabled = self.destinations()[0]
        self.assertNotEqual(reenabled.generation, initial.generation)
        self.assertEqual(reenabled.after_queue_id, 2)
        self.preferences(user_key='C' * 30)
        rekeyed = self.destinations()[0]
        self.assertNotEqual(rekeyed.generation, reenabled.generation)
        self.store.save_installation(self.owner, token_mode='replace', token='D' * 30)
        current = self.destinations()[0]
        self.assertNotEqual(current.provider_generation, rekeyed.provider_generation)
        self.assertIsNone(self.store.sending_credentials(rekeyed, available_collections=self.collections))

    def test_changed_environment_fails_closed_until_explicit_worker_synchronization(self):
        self.install()
        self.preferences()
        old = self.destinations()[0]
        with patch.dict(os.environ, {'PUSHOVER_APP_TOKEN': 'C' * 30}):
            before = self.path.read_bytes()
            self.assertEqual(self.destinations(), [])
            self.assertIsNone(self.store.sending_credentials(old, available_collections=self.collections))
            self.assertEqual(self.path.read_bytes(), before)
            self.store.synchronize(now=300)
            current = self.destinations()[0]
            self.assertNotEqual(current.generation, old.generation)
            self.assertEqual(self.store.sending_credentials(current, available_collections=self.collections).app_token, 'C' * 30)

    def test_provider_off_on_starts_fresh_without_affecting_email_settings(self):
        self.install()
        self.preferences()
        old = self.destinations()[0]
        self.store.save_installation(self.owner, enabled=False)
        with sqlite3.connect(self.path) as db:
            db.execute("INSERT INTO notification_queue(collection_id,media_id,kind,received_at) VALUES (1,'offline','MEDIA_ADDED_TO_COLLECTION',300)")
        self.store.save_installation(self.owner, enabled=True)
        current = self.destinations()[0]
        self.assertNotEqual(current.generation, old.generation)
        self.assertEqual(current.after_queue_id, 1)
        self.assertEqual(self.query('SELECT * FROM email_recipients'), [('OriginalCase@Example.test', 1)])
        self.assertEqual(self.query('SELECT * FROM recipient_subscriptions'), [('OriginalCase@Example.test', 1, 1)])

    def test_read_only_views_and_destination_loader_never_initialize_or_make_network(self):
        self.install()
        self.preferences()
        observer = settings.Settings(self.path, initialize=False, owner_id=lambda: 'owner', profile_access=self.access)
        before = self.path.read_bytes()
        with patch.object(settings.Settings, 'initialize', side_effect=AssertionError('read initializes')), \
             patch.object(settings.pushover.requests, 'Session', side_effect=AssertionError('read sends')):
            observer.installation_view()
            observer.preferences_view(self.user, available_collections=self.collections)
            observer.destinations(available_collections=self.collections)
        self.assertEqual(self.path.read_bytes(), before)

    def test_concurrent_keep_credential_form_does_not_restore_an_old_user_key(self):
        self.install()
        self.preferences()
        synchronize = self.store.synchronize
        def concurrent_update(**kwargs):
            generation = synchronize(**kwargs)
            with sqlite3.connect(self.path) as db:
                db.execute("UPDATE pushover_preferences SET user_key=? WHERE user_id='user'", ('C' * 30,))
            return generation
        with patch.object(self.store, 'synchronize', side_effect=concurrent_update):
            self.preferences(key_mode='keep', user_key='', device='iphone')
        self.assertEqual(self.query('SELECT user_key,device FROM pushover_preferences'), [('C' * 30, 'iphone')])

    def test_fresh_sender_guard_can_cancel_without_a_provider_call_when_preferences_change(self):
        self.install()
        self.preferences()
        delivery = notifications.Store(self.path)
        with sqlite3.connect(self.path) as db:
            db.execute("INSERT INTO notification_queue(collection_id,media_id,kind,received_at) VALUES (1,'new','MEDIA_ADDED_TO_COLLECTION',300)")
        def sender(target, message):
            with sqlite3.connect(self.path) as db:
                db.execute("UPDATE pushover_preferences SET enabled=0 WHERE user_id='user'")
            credentials = self.store.sending_credentials(target, available_collections=self.collections)
            self.assertIsNone(credentials)
            return notifications.Outcome('cancelled', 'preferences_changed')
        callbacks = notifications.Callbacks(lambda: {'pushover'}, self.destinations,
            lambda events: [{'collection_id': event['collection_id'], 'media_id': event['media_id'], 'title': 'Title'} for event in events],
            lambda target, items: 'Message', sender)
        report = delivery.process(callbacks, now=1000)
        self.assertEqual(report['cancelled'], 1)
        self.assertEqual(delivery.snapshot()[0]['state'], 'cancelled')

    def test_concurrent_provider_save_cannot_leave_personal_preferences_on_a_retired_generation(self):
        self.install()
        self.preferences()
        synchronize = self.store.synchronize
        def concurrent_provider_save(**kwargs):
            old_generation = synchronize(**kwargs)
            self.connections.save({'PUSHOVER_APP_TOKEN': 'C' * 30})
            synchronize(now=300)
            return old_generation
        with patch.object(self.store, 'synchronize', side_effect=concurrent_provider_save):
            self.preferences(key_mode='keep', user_key='', collections={2})
        destination = self.destinations()[0]
        credentials = self.store.sending_credentials(destination, available_collections=self.collections)
        self.assertIsNotNone(credentials)
        self.assertEqual(credentials.app_token, 'C' * 30)
        self.assertEqual(destination.collections, frozenset((2,)))

    def test_saved_own_validation_credentials_work_while_disabled_without_revealing_them(self):
        self.install()
        self.preferences(enabled=False)
        self.store.save_installation(self.owner, enabled=False)
        credentials = self.store.validation_credentials(self.user)
        self.assertEqual(credentials.user_key, 'B' * 30)
        self.assertNotIn('B' * 30, str(credentials))
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE user_profiles SET status='disabled' WHERE plex_id='user'")
        with self.assertRaises(PermissionError):
            self.store.validation_credentials(self.user)

    def test_test_reservation_is_durable_per_user_kind_and_serialized_across_accounts(self):
        self.install()
        self.preferences()
        self.preferences(self.owner)
        first = self.store.reserve_test(self.user, 'validation', now=1000)
        self.assertEqual(first.state, 'reserved')
        self.assertEqual(self.store.reserve_test(self.user, 'validation', now=1001).state, 'cooldown')
        self.assertEqual(self.store.reserve_test(self.owner, 'notification', now=1001).state, 'busy')
        self.assertTrue(self.store.complete_test(first.id, notifications.Outcome('accepted'), now=1002))
        second = self.store.reserve_test(self.user, 'notification', now=1002)
        self.assertEqual(second.state, 'reserved')
        self.store.complete_test(second.id, notifications.Outcome('accepted'), now=1003)
        restarted = settings.Settings(self.path, initialize=False, owner_id=lambda: 'owner', profile_access=self.access)
        self.assertEqual(restarted.reserve_test(self.user, 'validation', now=1059).state, 'cooldown')
        self.assertEqual(restarted.reserve_test(self.user, 'validation', now=1060).state, 'reserved')

    def test_interrupted_test_notification_is_held_and_never_replayed_without_discard(self):
        self.install()
        self.preferences()
        first = self.store.reserve_test(self.user, 'notification', now=1000)
        restarted = settings.Settings(self.path, initialize=False, owner_id=lambda: 'owner', profile_access=self.access)
        result = restarted.reserve_test(self.user, 'notification', now=1100)
        self.assertEqual((result.state, result.id), ('review', first.id))
        self.assertEqual(self.query("SELECT state,error_code FROM notification_test_attempts"), [('review', 'worker_interrupted')])
        self.assertFalse(restarted.discard_test(self.owner, first.id))
        self.assertTrue(restarted.discard_test(self.user, first.id))
        self.assertEqual(restarted.reserve_test(self.user, 'notification', now=1100).state, 'reserved')

    def test_uncertain_test_results_are_safe_owned_and_cannot_overwrite_accepted_proof(self):
        self.install()
        self.preferences()
        first = self.store.reserve_test(self.user, 'notification', now=1000)
        self.store.complete_test(first.id, notifications.Outcome('review', 'SECRET-ERROR', request_id='B' * 30), now=1001)
        self.assertEqual(self.store.reserve_test(self.user, 'notification', now=1100).state, 'review')
        views = self.store.test_views(self.user)
        self.assertNotIn('SECRET-ERROR', str(views))
        self.assertNotIn('B' * 30, str(views))
        self.assertEqual(views[0]['state'], 'review')
        self.assertEqual(self.store.test_views(self.owner), [])
        self.assertFalse(self.store.complete_test(first.id, notifications.Outcome('accepted')))

    def test_test_reservation_refuses_changed_credentials_and_results_mark_changed_settings(self):
        self.install()
        self.preferences()
        first = self.store.reserve_test(self.user, 'validation', now=1000)
        self.assertIsNotNone(self.store.validation_credentials(self.user, reservation_id=first.id))
        self.preferences(user_key='C' * 30)
        self.assertIsNone(self.store.validation_credentials(self.user, reservation_id=first.id))
        self.store.complete_test(first.id, notifications.Outcome('cancelled', 'preferences_changed'))
        self.assertFalse(self.store.test_views(self.user)[0]['current'])

    def test_provider_toggle_preserves_application_quota_for_delivery_and_test_reservations(self):
        self.install()
        self.preferences()
        scope = self.destinations()[0].provider_generation
        first = self.store.reserve_test(self.user, 'notification', now=1000)
        self.store.complete_test(first.id, notifications.Outcome('retry', 'quota', retry_at=4000), now=1001)
        self.store.save_installation(self.owner, enabled=False)
        self.store.save_installation(self.owner, enabled=True)
        self.assertEqual(self.destinations()[0].provider_generation, scope)
        self.assertEqual(self.store.reserve_test(self.user, 'notification', now=1100).state, 'quota')
        self.assertEqual(self.store.reserve_test(self.user, 'validation', now=1100).state, 'reserved')

    def test_email_event_defaults_and_changes_preserve_original_recipient_and_subscription_data(self):
        original = self.query('SELECT * FROM email_recipients')
        subscriptions = self.query('SELECT * FROM recipient_subscriptions')
        default = self.store.email_event_preferences('OriginalCase@Example.test')
        self.assertEqual(default['events'], notifications.MEDIA_EVENTS)
        self.assertFalse(default['owner_verified'])
        self.store.save_email_events(self.owner, 'originalcase@example.test', {notifications.REMINDER}, now=1000)
        self.assertEqual(self.store.email_event_preferences('OriginalCase@Example.test')['events'], frozenset((notifications.REMINDER,)))
        self.assertEqual(self.query('SELECT * FROM email_recipients'), original)
        self.assertEqual(self.query('SELECT * FROM recipient_subscriptions'), subscriptions)
        self.assertEqual(self.store.email_event_preferences('OriginalCase@Example.test')['generation'], default['generation'])

    def test_personal_email_events_are_own_address_only_and_never_operational_for_viewers(self):
        with sqlite3.connect(self.path) as db:
            db.execute("INSERT INTO email_recipients VALUES ('shared@example.test',1)")
        self.store.save_email_events(self.user, 'shared@example.test', {notifications.ADDED})
        self.assertEqual(self.store.email_event_preferences('shared@example.test')['events'], frozenset((notifications.ADDED,)))
        with self.assertRaises(PermissionError):
            self.store.save_email_events(self.user, 'OriginalCase@Example.test', notifications.MEDIA_EVENTS)
        with self.assertRaises(PermissionError):
            self.store.save_email_events(self.user, 'shared@example.test', notifications.EVENTS)
        with self.assertRaises(PermissionError):
            self.store.save_email_events(self.owner, 'shared@example.test', notifications.EVENTS)

    def test_first_owner_alert_email_opt_in_sets_only_operational_boundary_without_losing_media_backlog(self):
        with sqlite3.connect(self.path) as db:
            db.execute("INSERT INTO email_recipients VALUES ('Owner@Example.test',1)")
            db.execute("INSERT INTO notification_queue(collection_id,media_id,kind,received_at) VALUES (1,'old-media','MEDIA_ADDED_TO_COLLECTION',100)")
        delivery = notifications.Store(self.path)
        delivery.observe_update('2.10.0', now=100)
        before = self.store.email_event_preferences('Owner@Example.test')
        self.store.save_email_events(self.owner, 'owner@example.test', notifications.EVENTS, now=200)
        after = self.store.email_event_preferences('Owner@Example.test')
        self.assertEqual(before['generation'], after['generation'])
        self.assertTrue(after['owner_verified'])
        self.assertEqual(self.query("SELECT after_queue_id,after_event_id FROM notification_destination_epochs WHERE provider='email'"), [(0, 1)])
        self.assertEqual(self.query('SELECT media_id FROM notification_queue'), [('old-media',)])
        delivery.observe_update('2.11.0', now=300)
        self.store.save_email_events(self.owner, 'owner@example.test', notifications.MEDIA_EVENTS, now=400)
        self.store.save_email_events(self.owner, 'owner@example.test', notifications.EVENTS, now=500)
        self.assertEqual(self.query("SELECT after_event_id FROM notification_destination_epochs WHERE provider='email'"), [(1,)])
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE user_profiles SET status='disabled' WHERE plex_id='owner'")
        current = self.store.email_event_preferences('Owner@Example.test')
        self.assertFalse(current['owner_verified'])
        self.assertEqual(current['events'], notifications.MEDIA_EVENTS)

    def test_caller_email_transaction_commits_and_rolls_back_recipient_and_event_changes_together(self):
        with self.assertRaises(RuntimeError):
            with sqlite3.connect(self.path) as db, db:
                db.execute('BEGIN IMMEDIATE')
                db.execute("UPDATE email_recipients SET enabled=0 WHERE email='OriginalCase@Example.test'")
                self.store.save_email_events(self.owner, 'OriginalCase@Example.test', {notifications.REMINDER}, db=db)
                self.assertTrue(db.in_transaction)
                self.assertEqual(self.query('SELECT * FROM notification_email_events'), [])
                raise RuntimeError('caller abort')
        self.assertEqual(self.query('SELECT enabled FROM email_recipients'), [(1,)])
        self.assertEqual(self.query('SELECT * FROM notification_email_events'), [])
        with sqlite3.connect(self.path) as db, db:
            db.execute('BEGIN IMMEDIATE')
            db.execute("UPDATE email_recipients SET enabled=0 WHERE email='OriginalCase@Example.test'")
            view = self.store.save_email_events(self.owner, 'OriginalCase@Example.test', {notifications.REMINDER}, db=db)
            self.assertEqual(view['events'], frozenset((notifications.REMINDER,)))
        self.assertEqual(self.query('SELECT enabled FROM email_recipients'), [(0,)])
        self.assertEqual(self.store.email_event_preferences('OriginalCase@Example.test')['events'], frozenset((notifications.REMINDER,)))

    def test_invalid_email_events_roll_back_the_callers_existing_preferences_changes(self):
        with self.assertRaises(PermissionError):
            with sqlite3.connect(self.path) as db, db:
                db.execute("INSERT INTO email_recipients VALUES ('shared@example.test',1)")
                self.store.save_email_events(self.user, 'shared@example.test', notifications.EVENTS, db=db)
        self.assertEqual(self.query("SELECT * FROM email_recipients WHERE email='shared@example.test'"), [])

    def test_smtp_test_uses_only_saved_own_account_address_without_any_push_configuration(self):
        with sqlite3.connect(self.path) as db:
            db.execute("INSERT INTO email_recipients VALUES ('SHARED@Example.test',0)")
        with patch.dict(os.environ, {'PUSHOVER_APP_TOKEN': 'invalid'}):
            reservation = self.store.reserve_test(self.user, 'email', now=1000)
            self.assertEqual(reservation.state, 'reserved')
            self.assertEqual(self.store.email_test_recipient(self.user, reservation_id=reservation.id), 'SHARED@Example.test')
            self.assertIsNone(self.store.email_test_recipient(self.owner, reservation_id=reservation.id))
            self.store.complete_test(reservation.id, notifications.Outcome('accepted'), now=1001)
            self.assertTrue(self.store.test_views(self.user)[0]['current'])
        self.assertEqual(self.store.reserve_test(self.user, 'email', now=1059).state, 'cooldown')
        self.assertEqual(self.store.reserve_test(self.user, 'email', now=1060).state, 'reserved')

    def test_smtp_test_interruption_and_uncertainty_never_automatically_replay(self):
        with sqlite3.connect(self.path) as db:
            db.execute("INSERT INTO email_recipients VALUES ('shared@example.test',1)")
        reservation = self.store.reserve_test(self.user, 'email', now=1000)
        interrupted = self.store.reserve_test(self.user, 'email', now=1100)
        self.assertEqual((interrupted.state, interrupted.id), ('review', reservation.id))
        self.store.discard_test(self.user, reservation.id)
        next_reservation = self.store.reserve_test(self.user, 'email', now=1200)
        self.store.complete_test(next_reservation.id, notifications.Outcome('review', 'email_uncertain'), now=1201)
        self.assertEqual(self.store.reserve_test(self.user, 'email', now=1300).state, 'review')

    def test_late_definite_completion_records_proof_without_replaying_an_interrupted_test(self):
        with sqlite3.connect(self.path) as db:
            db.execute("INSERT INTO email_recipients VALUES ('shared@example.test',1)")
        reservation = self.store.reserve_test(self.user, 'email', now=1000)
        self.assertEqual(self.store.reserve_test(self.user, 'email', now=1100).state, 'review')
        self.assertTrue(self.store.complete_test(reservation.id, notifications.Outcome('accepted'), now=1101))
        self.assertEqual(self.store.test_views(self.user)[0]['state'], 'accepted')
        self.assertFalse(self.store.complete_test(reservation.id, notifications.Outcome('review', 'email_uncertain'), now=1102))

    def test_smtp_reservation_rechecks_saved_profile_address_before_transmission(self):
        with sqlite3.connect(self.path) as db:
            db.execute("INSERT INTO email_recipients VALUES ('shared@example.test',1)")
            db.execute("INSERT INTO email_recipients VALUES ('new@example.test',1)")
        reservation = self.store.reserve_test(self.user, 'email', now=1000)
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE user_profiles SET email='new@example.test' WHERE plex_id='user'")
        self.assertIsNone(self.store.email_test_recipient(self.user, reservation_id=reservation.id))
        self.assertFalse(self.store.test_views(self.user)[0]['current'])

    def test_test_schema_upgrade_preserves_prior_receipts_without_assuming_current_credentials(self):
        with sqlite3.connect(self.path) as db:
            db.execute('DROP TABLE notification_test_attempts')
            db.execute('''CREATE TABLE notification_test_attempts(id TEXT PRIMARY KEY,user_id TEXT,kind TEXT,
                credential_scope TEXT,reserved_at REAL,finished_at REAL,state TEXT,error_code TEXT,request_id TEXT)''')
            db.execute("INSERT INTO notification_test_attempts VALUES ('older','user','notification','scope',1000,1001,'accepted',NULL,NULL)")
        self.store.initialize()
        view = self.store.test_views(self.user)[0]
        self.assertEqual(view['state'], 'accepted')
        self.assertFalse(view['current'])

    def test_credential_scope_upgrade_carries_a_valid_prior_application_quota_hold(self):
        self.install()
        self.preferences()
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE notification_provider_generations SET generation='old-opaque-generation' WHERE provider='pushover'")
            db.execute("INSERT INTO notification_cooldowns VALUES ('pushover','old-opaque-generation',4000)")
        generation = self.store.synchronize(now=1000)
        self.assertEqual(self.query("SELECT until_at FROM notification_cooldowns WHERE provider='pushover' AND generation=?", (generation,)), [(4000,)])
        self.assertEqual(self.store.reserve_test(self.user, 'notification', now=1100).state, 'quota')


if __name__ == '__main__':
    unittest.main()
