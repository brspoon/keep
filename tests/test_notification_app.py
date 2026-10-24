from dataclasses import replace
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import Mock, patch

from connection_settings import ConnectionSettings
import notification_settings
import notifications
import notifications_app
import pushover


class NotificationAppTests(unittest.TestCase):
    def setUp(self):
        environment = patch.dict(os.environ, {}, clear=True)
        environment.start()
        self.addCleanup(environment.stop)
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / 'app.sqlite3'
        self.connections = ConnectionSettings(self.path)
        with sqlite3.connect(self.path) as db:
            db.executescript('''
                CREATE TABLE user_profiles(plex_id TEXT PRIMARY KEY,status TEXT,auth_type TEXT,plex_access TEXT,email TEXT);
                INSERT INTO user_profiles VALUES ('owner','active','plex','active','Owner@Example.test');
                INSERT INTO user_profiles VALUES ('user','active','plex','active','User@Example.test');
                CREATE TABLE notification_queue(id INTEGER PRIMARY KEY AUTOINCREMENT,
                    collection_id INTEGER,media_id TEXT,kind TEXT,received_at REAL,batch_id TEXT);
                CREATE TABLE notification_batches(id TEXT PRIMARY KEY,status TEXT,created_at REAL,detail TEXT);
                CREATE TABLE notification_deliveries(batch_id TEXT,email TEXT,sent_at REAL,PRIMARY KEY(batch_id,email));
                CREATE TABLE notification_reminders(collection_id INTEGER,media_id TEXT,episode TEXT,
                    queue_id INTEGER,queued_at REAL,PRIMARY KEY(collection_id,media_id,episode));
                CREATE TABLE email_recipients(email TEXT PRIMARY KEY,enabled INTEGER);
                CREATE TABLE recipient_subscriptions(email TEXT,collection_id INTEGER,enabled INTEGER);
                INSERT INTO email_recipients VALUES ('Owner@Example.test',1);
                INSERT INTO recipient_subscriptions VALUES ('Owner@Example.test',1,1);
            ''')
        self.store = notifications.Store(self.path)
        self.settings = notification_settings.Settings(self.path, connections=self.connections,
            owner_id=lambda: 'owner', profile_access=lambda p: p['plex_access'] == 'active')
        self.owner = notification_settings.Actor('owner', True, True)
        self.user = notification_settings.Actor('user', True)
        self.selected = {1, 2}
        self.emails = {'Owner@Example.test': {1}}
        self.email_on = True
        self.values = {'KEEP_URL': 'https://keep.example.test'}
        self.resolve = Mock(side_effect=lambda events: [{'collection_id': e['collection_id'],
            'media_id': e['media_id'], 'title': 'Title ' + e['media_id'], 'urgent': False}
            for e in events])
        self.reconcile = Mock()
        self.build_email = Mock(side_effect=lambda items, url: ('Keep digest', '<p>Digest</p>',
            ', '.join(item['media_id'] for item in items)))
        self.send_email = Mock()
        self.send_push = Mock(return_value=pushover.Result('accepted'))
        self.helpers = notifications_app.Helpers(lambda: self.store, lambda: self.settings,
            lambda: self.selected, lambda: self.emails, lambda: self.email_on,
            lambda name: self.values.get(name, ''), self.reconcile, self.resolve,
            self.build_email, self.send_email, self.send_push)
        self.runtime = notifications_app.Runtime(self.helpers)

    def query(self, sql, args=()):
        with sqlite3.connect(self.path) as db:
            return db.execute(sql, args).fetchall()

    def queue(self, media_id='1', *, collection=1, now=100, batch=None, kind=notifications.ADDED):
        with sqlite3.connect(self.path) as db:
            return db.execute('INSERT INTO notification_queue(collection_id,media_id,kind,received_at,batch_id) VALUES (?,?,?,?,?)',
                              (collection, media_id, kind, now, batch)).lastrowid

    def install_push(self, actor=None, *, events=notifications.MEDIA_EVENTS, collections=None):
        self.settings.save_installation(self.owner, enabled=True, token_mode='replace', token='A' * 30, now=100)
        self.settings.save_preferences(actor or self.owner, enabled=True, key_mode='replace', user_key='B' * 30,
            device='phone', collections={1} if collections is None else collections, events=events,
            available_collections=self.selected, now=100)

    def enable_owner_alerts(self):
        self.settings.save_email_events(self.owner, 'Owner@Example.test', notifications.EVENTS, now=100)
        self.install_push(self.owner, events=notifications.EVENTS)

    def test_constructing_adapter_performs_no_database_work_or_send(self):
        helpers = notifications_app.Helpers(*(Mock() for _ in range(10)))
        notifications_app.Runtime(helpers)
        for value in vars(helpers).values():
            if isinstance(value, Mock):
                value.assert_not_called()

    def test_uncertain_email_does_not_block_push_or_later_batches_and_keeps_reminder_claim(self):
        self.install_push()
        row_id = self.queue(kind=notifications.REMINDER)
        with sqlite3.connect(self.path) as db:
            db.execute("INSERT INTO notification_reminders VALUES (1,'1','episode',?,100)", (row_id,))
        self.send_email.side_effect = RuntimeError('private SMTP failure')
        self.assertEqual(self.runtime.process_digest(now=100, quiet_seconds=0), 'review')
        self.assertEqual(self.send_push.call_count, 1)
        self.queue('2', now=200)
        self.assertEqual(self.runtime.process_digest(now=200, quiet_seconds=0), 'review')
        self.assertEqual(self.send_push.call_count, 2)
        self.assertEqual(self.send_email.call_count, 2)
        self.assertEqual(self.query('SELECT queue_id FROM notification_reminders'), [(row_id,)])
        self.runtime.process_digest(now=300, quiet_seconds=0)
        self.assertEqual(self.send_email.call_count, 2)
        self.assertNotIn('private SMTP', str(self.store.snapshot()))

    def test_email_off_still_reconciles_and_delivers_push_with_current_saved_credentials(self):
        self.install_push()
        self.email_on = False
        self.queue()
        self.assertEqual(self.runtime.process_digest(now=100, quiet_seconds=0), 'sent')
        self.reconcile.assert_called_once_with()
        self.send_email.assert_not_called()
        self.assertEqual(self.send_push.call_args.args[:2], ('A' * 30, 'B' * 30))
        self.assertEqual(self.send_push.call_args.kwargs['device'], 'phone')
        self.assertEqual(self.send_push.call_args.kwargs['url'], self.values['KEEP_URL'])
        self.assertEqual(self.query('SELECT media_id FROM notification_queue'), [('1',)])
        self.email_on = True
        self.assertEqual(self.runtime.process_digest(now=200, quiet_seconds=0), 'sent')
        self.send_email.assert_called_once()
        self.assertEqual(self.send_email.call_args.args[0], ['Owner@Example.test'])
        self.assertEqual(self.send_email.call_args.args[3], '1')
        self.assertEqual(self.send_push.call_count, 1)
        self.assertEqual(self.query('SELECT * FROM notification_queue'), [])

    def test_disabled_providers_preserve_queue_without_reconciliation(self):
        self.email_on = False
        self.queue()
        self.assertEqual(self.runtime.process_digest(now=100, quiet_seconds=0), 'disabled')
        self.reconcile.assert_not_called()
        self.assertEqual(len(self.query('SELECT * FROM notification_queue')), 1)

    def test_original_email_address_and_canonical_case_dedup_preserve_collection_selection(self):
        self.emails = {'Owner@Example.test': {1}, 'owner@example.test': {2, 999}}
        self.queue('one', collection=1)
        self.queue('two', collection=2)
        self.runtime.process_digest(now=100, quiet_seconds=0)
        self.send_email.assert_called_once()
        self.assertEqual(self.send_email.call_args.args[0], ['Owner@Example.test'])
        self.assertEqual(set(self.send_email.call_args.args[3].split(', ')), {'one', 'two'})

    def test_email_event_preferences_filter_digest_but_do_not_change_original_subscriptions(self):
        self.settings.save_email_events(self.owner, 'Owner@Example.test', {notifications.REMINDER}, now=100)
        self.queue('added')
        self.queue('reminder', kind=notifications.REMINDER)
        self.runtime.process_digest(now=100, quiet_seconds=0)
        self.assertEqual(self.send_email.call_args.args[3], 'reminder')
        self.assertEqual(self.query('SELECT * FROM recipient_subscriptions'), [('Owner@Example.test', 1, 1)])

    def test_final_push_send_guard_rejects_revoked_access_and_rekeyed_credentials(self):
        self.install_push()
        target = next(t for t in self.runtime.destinations() if t.provider == 'pushover')
        message = self.runtime.render(target, [{'title': 'One'}])
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE user_profiles SET plex_access='revoked' WHERE plex_id='owner'")
        self.assertEqual(self.runtime.send(target, message).state, 'cancelled')
        self.send_push.assert_not_called()
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE user_profiles SET plex_access='active' WHERE plex_id='owner'")
        self.settings.save_preferences(self.owner, enabled=True, key_mode='replace', user_key='C' * 30,
            collections={1}, events=notifications.MEDIA_EVENTS, available_collections=self.selected, now=200)
        self.assertEqual(self.runtime.send(target, message).state, 'cancelled')
        self.send_push.assert_not_called()

    def test_final_email_send_guard_rechecks_current_event_selection_and_owner(self):
        self.enable_owner_alerts()
        target = next(t for t in self.runtime.destinations() if t.provider == 'email')
        message = self.runtime.render_event(target, {'kind': 'CONNECTION_FAILED', 'entity': 'plex'})
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE user_profiles SET plex_access='revoked' WHERE plex_id='owner'")
        self.assertEqual(self.runtime.send(target, message).state, 'cancelled')
        self.send_email.assert_not_called()

    def test_owner_role_change_cancels_prepared_operational_email_and_push_before_transport(self):
        self.enable_owner_alerts()
        targets = self.runtime.destinations()
        messages = [(target, self.runtime.render_event(target, {'kind': 'JOB_FAILED', 'entity': 'keep-expiry'}))
                    for target in targets]
        self.settings.owner_id = lambda: 'user'
        for target, message in messages:
            self.assertEqual(self.runtime.send(target, message).state, 'cancelled')
        self.send_email.assert_not_called()
        self.send_push.assert_not_called()
        email = next(target for target in self.runtime.destinations() if target.provider == 'email')
        self.assertEqual(email.events, notifications.MEDIA_EVENTS)
        self.assertFalse(email.owner_verified)

    def test_stored_nonowner_operational_email_choices_are_filtered_for_delivery(self):
        with sqlite3.connect(self.path) as db:
            db.execute("INSERT INTO notification_email_events VALUES ('user@example.test',?,100)",
                       ('["MEDIA_ADDED_TO_COLLECTION","MEDIA_ABOUT_TO_BE_HANDLED","JOB_FAILED","UPDATE_AVAILABLE"]',))
        self.emails['User@Example.test'] = {1}
        self.store.observe_update('2.27.0', now=200)
        self.runtime.process_operational(now=200)
        self.send_email.assert_not_called()
        viewer = next(target for target in self.runtime.destinations() if target.id == 'user@example.test')
        self.assertEqual(viewer.events, notifications.MEDIA_EVENTS)
        self.assertFalse(viewer.owner_verified)

    def test_legacy_nonowner_single_event_still_delivers_both_media_events_for_selected_lists(self):
        self.emails = {'User@Example.test': {1}}
        with sqlite3.connect(self.path) as db:
            db.execute("INSERT INTO notification_email_events VALUES ('user@example.test',?,NULL)",
                       ('["MEDIA_ADDED_TO_COLLECTION"]',))
        self.queue('leaving', kind=notifications.ADDED)
        self.queue('reminder', kind=notifications.REMINDER)
        self.queue('other-list', collection=2)
        self.store.observe_update('2.27.0', now=100)
        self.runtime.process_digest(now=100, quiet_seconds=0)
        self.send_email.assert_called_once()
        self.assertEqual(self.send_email.call_args.args[0], ['User@Example.test'])
        self.assertEqual(set(self.send_email.call_args.args[3].split(', ')), {'leaving', 'reminder'})
        self.assertEqual(self.query('SELECT events_json FROM notification_email_events'), [('["MEDIA_ADDED_TO_COLLECTION"]',)])

    def test_former_owner_single_event_becomes_both_media_events_after_owner_change(self):
        self.settings.save_email_events(self.owner, 'Owner@Example.test', {notifications.REMINDER, 'UPDATE_AVAILABLE'}, now=50)
        self.settings.owner_id = lambda: 'user'
        self.queue('leaving', kind=notifications.ADDED)
        self.queue('reminder', kind=notifications.REMINDER)
        self.store.observe_update('2.27.0', now=100)
        self.runtime.process_digest(now=100, quiet_seconds=0)
        self.send_email.assert_called_once()
        self.assertEqual(set(self.send_email.call_args.args[3].split(', ')), {'leaving', 'reminder'})
        target = self.runtime.destinations()[0]
        self.assertFalse(target.owner_verified)
        self.assertEqual(target.events, notifications.MEDIA_EVENTS)

    def test_media_render_rechecks_subscription_changes_before_sender(self):
        self.install_push()
        self.queue()
        def change_preferences(items, url):
            self.emails['Owner@Example.test'] = set()
            return 'Keep digest', '<p>Digest</p>', 'One'
        self.build_email.side_effect = change_preferences
        self.runtime.process_digest(now=100, quiet_seconds=0)
        self.send_email.assert_not_called()
        self.send_push.assert_called_once()

    def test_missing_digest_link_defers_email_preparation_without_blocking_push(self):
        self.install_push()
        self.values['KEEP_URL'] = ''
        self.queue()
        self.runtime.process_digest(now=100, quiet_seconds=0)
        self.send_email.assert_not_called()
        self.send_push.assert_called_once()
        self.assertEqual({(row['provider'], row['state']) for row in self.store.snapshot()},
                         {('email', 'pending'), ('pushover', 'accepted')})

    def test_invalid_push_environment_does_not_block_email(self):
        self.install_push()
        self.queue()
        with patch.dict(os.environ, {'PUSHOVER_APP_TOKEN': 'invalid'}):
            self.assertEqual(self.runtime.process_digest(now=100, quiet_seconds=0), 'sent')
        self.send_email.assert_called_once()
        self.send_push.assert_not_called()

    def test_default_push_sender_is_resolved_at_delivery_time_for_injected_provider_tests(self):
        self.install_push()
        self.email_on = False
        self.queue()
        runtime = notifications_app.Runtime(replace(self.helpers, send_push=None))
        with patch('notifications_app.pushover.send', return_value=pushover.Result('accepted')) as sender:
            self.assertEqual(runtime.process_digest(now=100, quiet_seconds=0), 'sent')
        sender.assert_called_once()
        self.send_push.assert_not_called()

    def test_owner_operational_email_without_media_collections_and_no_replay_before_optin(self):
        self.store.observe_update('2.26.0', now=50)
        self.emails['Owner@Example.test'] = set()
        self.settings.save_email_events(self.owner, 'Owner@Example.test', {'UPDATE_AVAILABLE'}, now=100)
        self.store.observe_update('2.27.0', now=200)
        self.assertEqual(self.runtime.process_operational(now=200), 'sent')
        self.send_email.assert_called_once()
        self.assertIn('2.27.0', self.send_email.call_args.args[3])
        self.assertNotIn('2.26.0', self.send_email.call_args.args[3])
        self.reconcile.assert_not_called()

    def test_reconciliation_failure_sends_owner_alerts_and_preserves_all_media_then_raises_original(self):
        self.enable_owner_alerts()
        self.queue('unreconciled')
        with sqlite3.connect(self.path) as db:
            db.execute("INSERT INTO notification_batches VALUES ('legacy','sent',100,'old')")
        self.queue('legacy-leftover', batch='legacy')
        before = self.query('SELECT * FROM notification_queue')
        self.store.observe_connection('seerr', 'failed', scope='current', now=200)
        original = RuntimeError('private reconciliation failure')
        self.reconcile.side_effect = original
        with self.assertRaises(RuntimeError) as caught:
            self.runtime.process_digest(now=200, quiet_seconds=0)
        self.assertIs(caught.exception, original)
        self.assertEqual(self.query('SELECT * FROM notification_queue'), before)
        self.assertEqual(self.query("SELECT * FROM notification_runs WHERE batch_id='legacy'"), [])
        self.resolve.assert_not_called()
        self.send_email.assert_called_once()
        self.send_push.assert_called_once()
        self.assertNotIn('private reconciliation', str(self.store.snapshot()))

    def test_reconciliation_exception_is_not_masked_by_failed_operational_storage(self):
        primary = RuntimeError('reconcile')
        secondary = sqlite3.OperationalError('locked')
        self.reconcile.side_effect = primary
        with patch.object(self.store, 'process', side_effect=secondary):
            with self.assertRaises(RuntimeError) as caught:
                self.runtime.process_digest(now=200)
        self.assertIs(caught.exception, primary)

    def test_worker_recovery_imports_legacy_receipt_and_holds_inflight_without_any_send(self):
        with sqlite3.connect(self.path) as db:
            db.execute("INSERT INTO notification_batches VALUES ('legacy','sending',100,NULL)")
            db.execute("INSERT INTO notification_deliveries VALUES ('legacy','Owner@Example.test',100)")
        self.queue(batch='legacy')
        self.runtime.recover_after_lock(now=200)
        rows = self.store.snapshot(batch_id='legacy')
        self.assertEqual({(row['destination_id'], row['state']) for row in rows},
                         {('owner@example.test', 'accepted'), ('legacy-held', 'review')})
        with sqlite3.connect(self.path) as db:
            db.execute("INSERT INTO notification_dispatches(batch_id,provider,destination_id,generation,state,created_at) VALUES ('legacy','pushover','user','gen','sending',100)")
        recovered = self.runtime.recover_after_lock(now=300)
        self.assertEqual(recovered['interrupted'], 1)
        self.assertEqual(next(row for row in self.store.snapshot() if row['provider'] == 'pushover')['error_code'], 'worker_interrupted')
        self.send_email.assert_not_called()
        self.send_push.assert_not_called()

    def test_recorded_observations_ignore_stale_scopes_pending_jobs_and_duplicates_and_sanitize_alerts(self):
        self.enable_owner_alerts()
        connections = {'seerr': {'fingerprint': 'active', 'checked': 200, 'failures': 2,
            'raw_error': 'private URL and token'}, 'plex': {'fingerprint': 'old', 'checked': 200, 'failures': 3}}
        jobs = {'keep-expiry': {'scope': None, 'finished': 200, 'status': 'failed'},
                'seerr-history': {'scope': 'old', 'finished': 200, 'status': 'failed'},
                'email-digest': {'scope': None, 'finished': 200, 'status': 'review'},
                'probe-email': {'scope': 'smtp', 'finished': 200, 'status': 'failed'},
                'reminder-scan': {'scope': None, 'finished': None, 'status': 'running'}}
        releases = {'status': 'success', 'stale': False, 'comparison': 'update_available',
                    'update_available': True, 'latest_version': '2.26.0', 'raw_error': 'private'}
        kwargs = dict(connections=connections, jobs=jobs, releases=releases,
            current_connection_scopes={'seerr': 'active', 'plex': 'new'},
            current_job_scopes={'keep-expiry': None, 'seerr-history': 'new', 'email-digest': None,
                                'probe-email': 'smtp', 'reminder-scan': None}, now=200)
        self.assertEqual(self.runtime.observe_recorded(**kwargs), 3)
        self.assertEqual(self.runtime.observe_recorded(**kwargs), 0)
        connections['seerr'].update(failures=0, checked=300)
        jobs['keep-expiry'].update(status='success', finished=300)
        self.assertEqual(self.runtime.observe_recorded(**{**kwargs, 'now': 300}), 2)
        self.runtime.process_operational(now=300)
        self.assertEqual(self.send_push.call_count, 5)
        combined = str(self.send_push.call_args_list) + str(self.send_email.call_args_list)
        self.assertNotIn('private', combined)
        self.assertNotIn('active', combined)
        self.assertIn('Seerr', combined)
        self.assertIn('Temporary Keeps', combined)

    def test_connection_alerts_match_two_failure_threshold_and_only_restore_on_definite_success(self):
        row = {'fingerprint': 'active', 'checked': 100, 'failures': 1}
        kwargs = dict(connections={'seerr': row}, jobs={}, releases={},
                      current_connection_scopes={'seerr': 'active'}, current_job_scopes={}, now=100)
        self.assertEqual(self.runtime.observe_recorded(**kwargs), 0)
        self.assertEqual(self.query('SELECT * FROM notification_transitions'), [])
        row['failures'] = 2
        self.assertEqual(self.runtime.observe_recorded(**kwargs), 1)
        row['failures'] = 1
        self.assertEqual(self.runtime.observe_recorded(**kwargs), 0)
        self.assertEqual(self.query('SELECT state FROM notification_transitions'), [('failed',)])
        row['failures'] = 0
        self.assertEqual(self.runtime.observe_recorded(**kwargs), 1)
        self.assertEqual([r[0] for r in self.query('SELECT kind FROM notification_operational_events')],
                         ['CONNECTION_FAILED', 'CONNECTION_RESTORED'])

    def test_observations_skip_nonstable_stale_unknown_and_future_data(self):
        self.assertEqual(self.runtime.observe_recorded(
            connections={'plex': {'fingerprint': 'current', 'checked': 999, 'failures': 1},
                         'unknown': {'fingerprint': 'current', 'checked': 100, 'failures': 1}},
            jobs={'keep-expiry': {'scope': None, 'finished': 100, 'status': 'waiting'}},
            releases={'status': 'success', 'stale': False, 'comparison': 'update_available',
                      'update_available': True, 'latest_version': '2.26.0-rc1'},
            current_connection_scopes={'plex': 'current', 'unknown': 'current'},
            current_job_scopes={'keep-expiry': None}, now=100), 0)
        self.assertEqual(self.query('SELECT * FROM notification_operational_events'), [])

    def test_message_repr_and_event_rendering_never_include_extra_payload_or_credentials(self):
        target = self.runtime.destinations()[0]
        message = self.runtime.render_event(target, {'kind': 'CONNECTION_FAILED', 'entity': 'seerr',
            'raw_error': '<script>secret</script>', 'token': 'A' * 30})
        self.assertNotIn('secret', message.text + message.html)
        self.assertNotIn('A' * 30, str(message))
        self.assertNotIn(self.values['KEEP_URL'], repr(message))
        self.values['KEEP_URL'] = 'https://user:password@keep.example.test'
        with self.assertRaises(ValueError):
            self.runtime.render_event(target, {'kind': 'UPDATE_AVAILABLE', 'version': '2.26.0'})

    def test_scoped_media_rechecks_original_items_and_rebuilds_only_fresh_subset(self):
        allowed = {'one', 'two'}
        scoped = Mock(side_effect=lambda target, items: [item for item in items if item['media_id'] in allowed])
        runtime = notifications_app.Runtime(replace(self.helpers, filter_email_items=scoped,
            email_generation=lambda address: 'scoped-one'))
        target = runtime.destinations()[0]
        originals = [{'collection_id': 1, 'media_id': 'one', 'title': 'Private one'},
                     {'collection_id': 1, 'media_id': 'two', 'title': 'Private two'}]
        message = runtime.render(target, originals)
        self.assertTrue(message.media)
        self.assertEqual(message.items, tuple(originals))
        self.assertNotIn('Private', repr(message))
        allowed.remove('one')
        self.assertEqual(runtime.send(target, message).state, 'accepted')
        self.assertEqual(self.send_email.call_args.args[3], 'two')
        self.assertEqual(scoped.call_count, 2)
        self.assertEqual(self.build_email.call_count, 2)

    def test_empty_scope_cancels_without_building_or_sending_empty_mail(self):
        scoped = Mock(return_value=[])
        runtime = notifications_app.Runtime(replace(self.helpers, filter_email_items=scoped))
        target = runtime.destinations()[0]
        message = runtime.render(target, [{'collection_id': 1, 'media_id': 'one'}])
        self.assertEqual(runtime.send(target, message), notifications.Outcome('cancelled', 'preferences_changed'))
        self.build_email.assert_not_called()
        self.send_email.assert_not_called()

    def test_lost_item_section_after_render_cancels_at_send_time(self):
        scoped = Mock(side_effect=lambda target, items: items)
        runtime = notifications_app.Runtime(replace(self.helpers, filter_email_items=scoped))
        target = runtime.destinations()[0]
        message = runtime.render(target, [{'collection_id': 1, 'media_id': 'one'}])
        scoped.side_effect = lambda target, items: []
        self.assertEqual(runtime.send(target, message).state, 'cancelled')
        self.send_email.assert_not_called()

    def test_scope_filter_cannot_inject_or_modify_private_items(self):
        def changed(target, items):
            items[0]['title'] = 'Different private title'
            return items
        runtime = notifications_app.Runtime(replace(self.helpers, filter_email_items=changed))
        with self.assertRaises(ValueError):
            runtime.render(runtime.destinations()[0], [{'collection_id': 1, 'media_id': 'one', 'title': 'Original'}])
        self.send_email.assert_not_called()

    def test_pretransport_filter_failure_retries_without_smtp_uncertainty(self):
        scoped = Mock(side_effect=lambda target, items: items)
        runtime = notifications_app.Runtime(replace(self.helpers, filter_email_items=scoped))
        target = runtime.destinations()[0]
        message = runtime.render(target, [{'collection_id': 1, 'media_id': 'one'}])
        scoped.side_effect = sqlite3.OperationalError('private scope database unavailable')
        self.assertEqual(runtime.send(target, message), notifications.Outcome('retry', 'connect_failed'))
        self.send_email.assert_not_called()
        scoped.side_effect = ValueError('scope changed')
        self.assertEqual(runtime.send(target, message), notifications.Outcome('cancelled', 'preferences_changed'))

    def test_scope_revocation_during_queued_media_batch_cancels_without_smtp(self):
        self.queue()
        calls = []
        def scoped(target, items):
            calls.append(items)
            return items if len(calls) == 1 else []
        runtime = notifications_app.Runtime(replace(self.helpers, filter_email_items=scoped))
        result = self.store.process(runtime.callbacks(), now=100, quiet_seconds=0)
        self.assertEqual(result['cancelled'], 1)
        self.assertEqual(self.store.snapshot()[0]['state'], 'cancelled')
        self.assertEqual(self.store.snapshot()[0]['error_code'], 'preferences_changed')
        self.send_email.assert_not_called()

    def test_queued_pretransport_failure_is_retryable_and_never_email_uncertain(self):
        self.queue()
        calls = []
        def scoped(target, items):
            calls.append(items)
            if len(calls) > 1:
                raise sqlite3.OperationalError('private verification failure')
            return items
        runtime = notifications_app.Runtime(replace(self.helpers, filter_email_items=scoped))
        result = self.store.process(runtime.callbacks(), now=100, quiet_seconds=0)
        self.assertEqual(result['retry'], 1)
        self.assertEqual(result['review'], 0)
        self.assertEqual(self.store.snapshot()[0]['state'], 'retry')
        self.assertEqual(self.store.snapshot()[0]['error_code'], 'connect_failed')
        self.send_email.assert_not_called()

    def test_topic_generation_edit_cancels_prepared_and_queued_old_destination(self):
        generation = ['map-one']
        runtime = notifications_app.Runtime(replace(self.helpers,
            email_generation=lambda address: generation[0]))
        target = runtime.destinations()[0]
        message = runtime.render(target, [{'collection_id': 1, 'media_id': 'one'}])
        generation[0] = 'map-two'
        self.assertEqual(runtime.send(target, message).state, 'cancelled')
        self.send_email.assert_not_called()
        self.queue()
        self.build_email.side_effect = lambda items, url: (generation.__setitem__(0, 'map-three') or
                                                          ('Keep digest', '<p>Digest</p>', 'One'))
        self.store.process(runtime.callbacks(), now=100, quiet_seconds=0)
        self.store.process(runtime.callbacks(), now=200, quiet_seconds=0)
        self.assertEqual(self.store.snapshot()[0]['state'], 'cancelled')
        self.send_email.assert_not_called()

    def test_auto_email_targets_never_receive_owner_operational_events(self):
        self.enable_owner_alerts()
        scoped = Mock(side_effect=AssertionError('Operational items must not enter media filtering'))
        runtime = notifications_app.Runtime(replace(self.helpers, email_generation=lambda address: 'auto-scope',
                                                    filter_email_items=scoped))
        target = next(target for target in runtime.destinations() if target.provider == 'email')
        self.assertEqual(target.events, notifications.MEDIA_EVENTS)
        self.assertFalse(target.owner_verified)
        self.store.observe_update('2.30.0', now=200)
        runtime.process_operational(now=200)
        self.send_email.assert_not_called()
        scoped.assert_not_called()
        self.send_push.assert_called_once()

    def test_manual_owner_operational_email_does_not_use_media_filter(self):
        self.enable_owner_alerts()
        scoped = Mock(side_effect=AssertionError('Operational email is not media'))
        runtime = notifications_app.Runtime(replace(self.helpers, filter_email_items=scoped,
                                                    email_generation=lambda address: ''))
        self.store.observe_update('2.30.0', now=200)
        runtime.process_operational(now=200)
        self.send_email.assert_called_once()
        scoped.assert_not_called()


class RecordedConnectionTests(unittest.TestCase):
    def test_missing_file_and_schema_are_readonly_and_database_unavailability_raises(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'checks.sqlite3'
            self.assertEqual(notifications_app.recorded_connections(path), {})
            self.assertFalse(path.exists())
            with sqlite3.connect(path) as db:
                db.execute('CREATE TABLE unrelated(id INTEGER)')
            before = path.read_bytes()
            self.assertEqual(notifications_app.recorded_connections(path), {})
            self.assertEqual(path.read_bytes(), before)
            with self.assertRaises(sqlite3.Error):
                notifications_app.recorded_connections(directory)

    def test_reads_only_fixed_connection_ids_without_running_any_probe(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'checks.sqlite3'
            with sqlite3.connect(path) as db:
                db.execute('CREATE TABLE automatic_connection_checks(service TEXT,fingerprint TEXT,checked REAL,failures INTEGER)')
                db.executemany('INSERT INTO automatic_connection_checks VALUES (?,?,?,?)',
                               [('seerr', 'scope', 100, 1), ('unknown', 'other', 100, 1)])
            before = path.read_bytes()
            with patch('requests.Session.get', side_effect=AssertionError('No HTTP reads')):
                self.assertEqual(set(notifications_app.recorded_connections(path)), {'seerr'})
            self.assertEqual(path.read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
