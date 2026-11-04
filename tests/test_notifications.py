from dataclasses import replace
from contextlib import closing
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import sqlite3
import tempfile
import unittest
from unittest.mock import Mock
from unittest.mock import patch

import notifications as notifications


class NotificationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / 'notifications.sqlite3'
        with closing(sqlite3.connect(self.path)) as db, db:
            db.executescript('''
                CREATE TABLE notification_queue(id INTEGER PRIMARY KEY AUTOINCREMENT,
                    collection_id INTEGER,media_id TEXT,kind TEXT,received_at REAL,batch_id TEXT);
                CREATE TABLE notification_batches(id TEXT PRIMARY KEY,status TEXT,created_at REAL,detail TEXT);
                CREATE TABLE notification_deliveries(batch_id TEXT,email TEXT,sent_at REAL,PRIMARY KEY(batch_id,email));
                CREATE TABLE notification_reminders(collection_id INTEGER,media_id TEXT,episode TEXT,
                    queue_id INTEGER,queued_at REAL,PRIMARY KEY(collection_id,media_id,episode));
                CREATE TABLE email_recipients(email TEXT PRIMARY KEY,enabled INTEGER);
                CREATE TABLE recipient_subscriptions(email TEXT,collection_id INTEGER,enabled INTEGER);
                INSERT INTO email_recipients VALUES ('a@example.test',1);
                INSERT INTO recipient_subscriptions VALUES ('a@example.test',1,1);
            ''')
        self.store = notifications.Store(self.path)
        self.email = notifications.Destination('email', 'a@example.test', 'email-v1', frozenset((1, 2)), provider_generation='smtp-v1')
        self.push = notifications.Destination('pushover', 'profile-1', 'push-v1', frozenset((1, 2)), provider_generation='app-v1')
        self.destinations = [self.email, self.push]
        self.enabled = {'email', 'pushover'}
        self.resolve = Mock(side_effect=lambda events: [{'collection_id': event['collection_id'],
            'media_id': event['media_id'], 'title': 'Title ' + event['media_id'], 'urgent': False}
            for event in events])
        self.render = Mock(side_effect=lambda target, items: [item['media_id'] for item in items])
        self.send = Mock(return_value=notifications.Outcome('accepted'))
        self.callbacks = notifications.Callbacks(lambda: self.enabled, lambda: self.destinations,
            self.resolve, self.render, self.send)

    def query(self, sql, args=()):
        with closing(sqlite3.connect(self.path)) as db, db:
            return db.execute(sql, args).fetchall()

    def queue(self, media_id='1', collection=1, kind=notifications.ADDED, now=100, batch=None):
        with closing(sqlite3.connect(self.path)) as db, db:
            return db.execute('INSERT INTO notification_queue(collection_id,media_id,kind,received_at,batch_id) VALUES (?,?,?,?,?)',
                              (collection, media_id, kind, now, batch)).lastrowid

    def process(self, now=1000):
        return self.store.process(self.callbacks, now=now, quiet_seconds=600)

    def test_shared_quiet_window_and_one_delivery_per_destination_are_preserved(self):
        self.queue('1', now=100)
        self.queue('2', collection=2, now=600)
        self.assertEqual(self.process(now=1199)['state'], 'waiting')
        self.send.assert_not_called()
        report = self.process(now=1200)
        self.assertEqual(report['accepted'], 2)
        self.assertEqual(self.send.call_count, 2)
        self.assertEqual([call.args[1] for call in self.send.call_args_list], [['1', '2'], ['1', '2']])
        self.assertEqual(self.query('SELECT * FROM notification_queue'), [])
        self.process(now=2000)
        self.assertEqual(self.send.call_count, 2)
        self.assertEqual(len(self.store.snapshot()), 2)

    def test_explicit_zero_quiet_interval_delivers_immediately_without_clamping(self):
        self.queue(now=100)
        report = self.store.process(self.callbacks, now=100, quiet_seconds=0)
        self.assertEqual(report['accepted'], 2)

    def test_uncertain_email_does_not_block_push_or_new_batches(self):
        self.queue()
        self.send.side_effect = lambda target, message: notifications.Outcome('review', 'email_uncertain') if target.provider == 'email' else notifications.Outcome('accepted', request_id='push-request')
        report = self.process()
        self.assertEqual((report['review'], report['accepted']), (1, 1))
        self.assertEqual(self.send.call_count, 2)
        self.queue('2', now=1100)
        report = self.process(now=1700)
        self.assertEqual((report['review'], report['accepted']), (1, 1))
        self.assertEqual(self.send.call_count, 4)
        self.assertEqual(len(self.query("SELECT * FROM notification_dispatches WHERE provider='pushover' AND state='accepted'")), 2)
        self.process(now=2000)
        self.assertEqual(self.send.call_count, 4)
        self.assertEqual(self.resolve.call_count, 2)

    def test_media_email_receipt_survives_partial_delivery_then_cleans_up_with_durable_dispatch_proof(self):
        other = replace(self.email, id='b@example.test')
        self.destinations = [self.email, other, self.push]
        self.queue()
        self.send.side_effect = lambda target, message: notifications.Outcome('review', 'email_uncertain') if target.id == other.id else notifications.Outcome('accepted')
        report = self.process()
        self.assertEqual((report['accepted'], report['review']), (2, 1))
        batch_id = self.query('SELECT id FROM notification_batches')[0][0]
        self.assertEqual(self.query('SELECT email FROM notification_deliveries WHERE batch_id=?', (batch_id,)), [(self.email.id,)])
        self.assertEqual({(row['provider'], row['state']) for row in self.store.snapshot() if row['destination_id'] == self.push.id}, {('pushover', 'accepted')})
        self.process(now=1100)
        self.assertEqual(self.send.call_count, 3)
        self.store.resolve_review(batch_id, 'email', other.id, action='retry', now=1200)
        self.send.side_effect = None
        self.send.return_value = notifications.Outcome('accepted')
        self.process(now=1200)
        self.assertEqual(self.send.call_count, 4)
        self.assertEqual(self.send.call_args.args[0].id, other.id)
        self.assertEqual(self.query('SELECT * FROM notification_deliveries'), [])
        self.assertEqual({row['state'] for row in self.store.snapshot()}, {'accepted'})
        self.assertEqual(self.query('SELECT * FROM notification_queue'), [])

    def test_operational_email_does_not_write_a_legacy_media_receipt(self):
        self.owner_destinations()
        self.store.observe_update('2.10.0', now=200)
        self.send.side_effect = lambda target, message: notifications.Outcome('review', 'response_uncertain') if target.provider == 'pushover' else notifications.Outcome('accepted')
        self.process(now=200)
        self.assertEqual(self.query('SELECT * FROM notification_deliveries'), [])

    def test_email_disabled_still_delivers_push_and_retains_reminder_claims(self):
        self.enabled = {'pushover'}
        row_id = self.queue(kind=notifications.REMINDER)
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("INSERT INTO notification_reminders VALUES (1,'1','episode-1',?,100)", (row_id,))
        self.assertEqual(self.process()['accepted'], 1)
        self.assertEqual(self.send.call_args.args[0].provider, 'pushover')
        self.assertEqual(self.query('SELECT queue_id FROM notification_reminders'), [(row_id,)])
        self.assertEqual(self.query('SELECT id FROM notification_queue'), [(row_id,)])
        self.assertEqual({(row['provider'], row['state']) for row in self.store.snapshot()},
                         {('email', 'pending'), ('pushover', 'accepted')})
        self.enabled = {'email', 'pushover'}
        self.assertEqual(self.process(now=1100)['accepted'], 1)
        self.assertEqual(self.send.call_args.args[0].provider, 'email')
        self.assertEqual(self.query('SELECT * FROM notification_queue'), [])
        self.assertEqual(self.query('SELECT queue_id FROM notification_reminders'), [(row_id,)])

    def test_all_providers_disabled_preserves_pending_queue(self):
        self.enabled = set()
        self.queue()
        self.assertEqual(self.process()['state'], 'disabled')
        self.assertEqual(len(self.query('SELECT * FROM notification_queue')), 1)
        self.send.assert_not_called()

    def test_disabled_provider_legacy_review_import_preserves_original_rows_and_detail(self):
        self.enabled = set()
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("INSERT INTO notification_batches VALUES ('held','review',100,'Original SMTP review detail')")
            db.execute("INSERT INTO notification_deliveries VALUES ('held','a@example.test',100)")
        self.queue(batch='held')
        before = {table: self.query('SELECT * FROM ' + table) for table in
                  ('notification_batches', 'notification_queue', 'notification_deliveries')}
        self.assertEqual(self.process()['state'], 'disabled')
        for table, rows in before.items():
            self.assertEqual(self.query('SELECT * FROM ' + table), rows)
        self.assertEqual({(row['destination_id'], row['state']) for row in self.store.snapshot()},
                         {('a@example.test', 'accepted'), ('legacy-held', 'review')})
        self.assertEqual(self.store.recover_interrupted(), 0)
        for table, rows in before.items():
            self.assertEqual(self.query('SELECT * FROM ' + table), rows)
        self.send.assert_not_called()

    def test_no_subscribed_destinations_settles_the_batch_without_any_send(self):
        self.destinations = [replace(self.email, collections=frozenset((2,)))]
        self.enabled = {'email'}
        self.queue()
        self.assertEqual(self.process()['state'], 'empty')
        self.assertEqual(self.query('SELECT * FROM notification_queue'), [])
        self.send.assert_not_called()

    def test_push_activation_and_rekey_do_not_replay_old_queue_or_inflight_batches(self):
        self.queue('old')
        watermark = self.store.activate_destination('pushover', 'profile-1', 'push-v1', now=200)
        self.push = replace(self.push, after_queue_id=watermark)
        self.destinations = [self.push]
        self.enabled = {'pushover'}
        self.queue('new', now=300)
        self.process(now=1000)
        self.assertEqual(self.send.call_args.args[1], ['new'])
        self.assertEqual(self.store.activate_destination('pushover', 'profile-1', 'push-v1', now=1200), watermark)
        self.queue('before-rekey', now=1200)
        watermark = self.store.activate_destination('pushover', 'profile-1', 'push-v2', now=1300)
        self.destinations = [replace(self.push, generation='push-v2', after_queue_id=watermark)]
        self.queue('after-rekey', now=1400)
        self.process(now=2000)
        self.assertEqual(self.send.call_args.args[1], ['after-rekey'])
        self.assertEqual(self.send.call_count, 2)

    def test_event_and_collection_preferences_are_live_and_warning_status_is_per_destination(self):
        self.email = replace(self.email, collections=frozenset((1,)), events=frozenset((notifications.ADDED,)))
        self.push = replace(self.push, collections=frozenset((2,)), events=frozenset((notifications.REMINDER,)))
        self.destinations = [self.email, self.push]
        self.queue('1', kind=notifications.ADDED)
        self.queue('2', collection=2, kind=notifications.REMINDER)
        self.process()
        self.assertEqual(self.send.call_args_list[0].args[1], ['1'])
        self.assertEqual(self.send.call_args_list[1].args[1], ['2'])
        self.assertFalse(self.render.call_args_list[0].args[1][0]['urgent'])
        self.assertTrue(self.render.call_args_list[1].args[1][0]['urgent'])

    def test_preferences_changed_during_resolution_or_render_never_use_old_destination(self):
        for stage in ('resolve', 'render'):
            with self.subTest(stage=stage):
                self.destinations = [self.push]
                self.enabled = {'pushover'}
                self.queue(stage)
                original = getattr(self, stage).side_effect
                def change(*args):
                    self.destinations = [replace(self.push, generation='rekeyed')]
                    return original(*args)
                getattr(self, stage).side_effect = change
                self.process(now=1000)
                self.send.assert_not_called()
                getattr(self, stage).side_effect = original
                self.process(now=1100)
                self.send.assert_not_called()

    def test_keep_cancellation_during_render_prevents_sending_cancelled_title(self):
        self.destinations = [self.push]
        self.queue('kept')
        self.queue('remaining')
        def render(target, items):
            with closing(sqlite3.connect(self.path)) as db, db:
                db.execute("DELETE FROM notification_queue WHERE media_id='kept'")
            return [item['media_id'] for item in items]
        self.render.side_effect = render
        self.process()
        self.send.assert_not_called()
        self.process(now=1100)
        self.assertEqual(self.send.call_args.args[1], ['remaining'])

    def test_preparation_failure_is_safe_to_retry_without_marking_sending(self):
        self.queue()
        self.resolve.side_effect = RuntimeError('private URL and token')
        report = self.process()
        self.assertEqual(report['accepted'], 0)
        self.send.assert_not_called()
        self.assertEqual({row['state'] for row in self.store.snapshot()}, {'pending'})
        self.assertNotIn('private URL', str(self.store.snapshot()))
        self.resolve.side_effect = lambda events: [{'collection_id': row['collection_id'], 'media_id': row['media_id'], 'title': row['media_id']} for row in events]
        self.assertEqual(self.process(now=1100)['accepted'], 2)

    def test_sender_exceptions_are_uncertain_per_destination_and_no_secrets_are_recorded(self):
        self.queue()
        self.send.side_effect = lambda target, message: (_ for _ in ()).throw(RuntimeError('SECRET-PUSH-KEY')) if target.provider == 'pushover' else notifications.Outcome('accepted')
        report = self.process()
        self.assertEqual((report['accepted'], report['review']), (1, 1))
        self.assertNotIn('SECRET-PUSH-KEY', str(self.store.snapshot()))
        self.process(now=1100)
        self.assertEqual(self.send.call_count, 2)

    def test_crash_after_reserved_send_never_resends_automatically(self):
        self.queue()
        self.send.side_effect = KeyboardInterrupt
        with self.assertRaises(KeyboardInterrupt):
            self.process()
        self.assertEqual(self.query("SELECT provider FROM notification_dispatches WHERE state='sending'"), [('email',)])
        restarted = notifications.Store(self.path)
        # Constructing a Store, as a web process might, cannot recover an active send.
        self.assertEqual(self.query("SELECT COUNT(*) FROM notification_dispatches WHERE state='sending'"), [(1,)])
        self.assertEqual(restarted.recover_interrupted(), 1)
        self.send.side_effect = None
        self.send.return_value = notifications.Outcome('accepted')
        self.store = restarted
        self.process(now=1100)
        self.assertEqual(self.send.call_count, 2)
        self.assertEqual(self.send.call_args.args[0].provider, 'pushover')

    def test_quota_cooldown_is_shared_by_application_generation_and_durable(self):
        other = replace(self.push, id='profile-2')
        self.destinations = [self.push, other]
        self.enabled = {'pushover'}
        self.queue()
        self.send.return_value = notifications.Outcome('retry', 'quota', retry_at=4000)
        self.process()
        self.assertEqual(self.send.call_count, 1)
        self.store = notifications.Store(self.path)
        self.process(now=3999)
        self.assertEqual(self.send.call_count, 1)
        self.send.return_value = notifications.Outcome('accepted')
        self.process(now=4000)
        self.assertEqual(self.send.call_count, 3)

    def test_safe_connect_retries_back_off_and_stop_after_five_attempts(self):
        self.destinations = [self.push]
        self.enabled = {'pushover'}
        self.queue()
        self.send.return_value = notifications.Outcome('retry', 'connect_failed')
        now, delays = 1000, []
        for _ in range(5):
            self.process(now=now)
            row = self.store.snapshot()[0]
            if row['state'] == 'retry':
                delays.append(row['next_attempt'] - now)
                now = row['next_attempt']
        self.assertEqual(delays, [60, 120, 240, 480])
        self.assertEqual(row['state'], 'rejected')
        self.process(now=10000)
        self.assertEqual(self.send.call_count, 5)

    def test_unknown_retry_reason_is_uncertain_and_never_automatically_repeated(self):
        self.destinations = [self.push]
        self.enabled = {'pushover'}
        self.queue()
        self.send.return_value = notifications.Outcome('retry', 'RAW-PROVIDER-ERROR')
        self.process()
        self.assertEqual(self.store.snapshot()[0]['state'], 'review')
        self.process(now=10000)
        self.assertEqual(self.send.call_count, 1)

    def test_explicit_review_retry_resends_only_selected_destination_and_never_accepted_ones(self):
        self.queue()
        self.send.side_effect = lambda target, message: notifications.Outcome('review', 'email_uncertain') if target.provider == 'email' else notifications.Outcome('accepted')
        self.process()
        batch = self.query('SELECT id FROM notification_batches')[0][0]
        self.assertFalse(self.store.resolve_review(batch, 'pushover', self.push.id, action='retry', now=1100))
        self.assertTrue(self.store.resolve_review(batch, 'email', self.email.id, action='retry', now=1100))
        self.send.side_effect = None
        self.send.return_value = notifications.Outcome('accepted')
        self.process(now=1100)
        self.assertEqual(self.send.call_count, 3)
        self.assertEqual(self.send.call_args.args[0].provider, 'email')
        self.assertEqual(self.query('SELECT * FROM notification_queue'), [])

    def test_legacy_migration_never_resends_sent_or_uncertain_and_imports_partial_receipts(self):
        for batch, state in (('sent', 'sent'), ('uncertain', 'sending'), ('partial', 'building')):
            with closing(sqlite3.connect(self.path)) as db, db:
                db.execute('INSERT INTO notification_batches VALUES (?,?,100,NULL)', (batch, state))
            self.queue(batch, batch=batch)
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("INSERT INTO notification_deliveries VALUES ('partial','a@example.test',200)")
        other = replace(self.email, id='b@example.test')
        self.destinations = [self.email, other, self.push]
        self.process()
        self.assertEqual(self.send.call_count, 1)
        self.assertEqual(self.send.call_args.args[0].id, 'b@example.test')
        self.assertEqual(self.query("SELECT state FROM notification_dispatches WHERE batch_id='partial' AND destination_id='a@example.test'"), [('accepted',)])
        self.assertEqual(self.query("SELECT state FROM notification_dispatches WHERE batch_id='uncertain'"), [('review',)])
        self.assertEqual(self.query("SELECT * FROM notification_dispatches WHERE provider='pushover'"), [])
        self.assertEqual(self.query("SELECT * FROM notification_queue WHERE batch_id='sent'"), [])
        self.assertEqual(self.store.migrate_legacy(self.destinations, now=1100), 0)
        self.assertFalse(self.store.resolve_review('uncertain', 'email', 'legacy-held', action='retry', now=1100))
        self.assertTrue(self.store.resolve_review('uncertain', 'email', 'legacy-held', action='discard', now=1100))
        self.assertEqual(self.query("SELECT * FROM notification_queue WHERE batch_id='uncertain'"), [])

    def test_legacy_recipient_subscription_and_claim_tables_are_not_changed(self):
        before = {table: self.query('SELECT * FROM ' + table) for table in ('email_recipients', 'recipient_subscriptions', 'notification_reminders')}
        self.queue()
        self.process()
        for table in before:
            self.assertEqual(self.query('SELECT * FROM ' + table), before[table])

    def test_disabled_email_preserves_a_safe_legacy_batch_and_does_not_block_new_push(self):
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("INSERT INTO notification_batches VALUES ('legacy','building',100,NULL)")
        self.queue('old-email', batch='legacy')
        self.enabled = {'pushover'}
        self.queue('new-push', now=300)
        self.process(now=1000)
        self.assertEqual(self.send.call_count, 1)
        self.assertEqual(self.send.call_args.args[1], ['new-push'])
        self.assertEqual(self.query("SELECT media_id FROM notification_queue WHERE batch_id='legacy'"), [('old-email',)])
        self.enabled = {'email', 'pushover'}
        self.process(now=1100)
        self.assertEqual(self.send.call_count, 3)
        self.assertEqual([call.args[1] for call in self.send.call_args_list[1:]], [['old-email'], ['new-push']])
        self.assertTrue(all(call.args[0].provider == 'email' for call in self.send.call_args_list[1:]))

    def test_paused_email_cohort_resumes_once_after_push_acceptance_without_new_recipients_joining(self):
        self.enabled = {'pushover'}
        self.queue('paused')
        self.assertEqual(self.process()['accepted'], 1)
        self.assertEqual(self.query('SELECT media_id FROM notification_queue'), [('paused',)])
        self.destinations.append(replace(self.email, id='new@example.test'))
        self.enabled = {'email', 'pushover'}
        self.assertEqual(self.process(now=1100)['accepted'], 1)
        self.assertEqual([(call.args[0].provider, call.args[0].id, call.args[1]) for call in self.send.call_args_list],
                         [('pushover', self.push.id, ['paused']), ('email', self.email.id, ['paused'])])
        self.assertEqual(self.query('SELECT * FROM notification_queue'), [])
        self.process(now=2000)
        self.assertEqual(self.send.call_count, 2)

    def test_paused_email_can_resume_while_uncertain_push_stays_held_without_replaying_push(self):
        self.enabled = {'pushover'}
        self.queue('paused')
        self.send.return_value = notifications.Outcome('review', 'response_uncertain')
        self.assertEqual(self.process()['review'], 1)
        self.enabled = {'email', 'pushover'}
        self.send.return_value = notifications.Outcome('accepted')
        report = self.process(now=1100)
        self.assertEqual(report['accepted'], 1)
        self.assertEqual([call.args[0].provider for call in self.send.call_args_list], ['pushover', 'email'])
        self.assertEqual({(row['provider'], row['state']) for row in self.store.snapshot()},
                         {('pushover', 'review'), ('email', 'accepted')})
        self.assertEqual(self.query('SELECT media_id FROM notification_queue'), [('paused',)])
        self.process(now=2000)
        self.assertEqual(self.send.call_count, 2)

    def test_new_push_activation_does_not_consume_older_unbatched_email_work(self):
        self.queue('before-push')
        watermark = self.store.activate_destination('pushover', self.push.id, self.push.generation, now=200)
        self.push = replace(self.push, after_queue_id=watermark)
        self.destinations = [self.email, self.push]
        self.enabled = {'pushover'}
        self.assertEqual(self.process()['state'], 'waiting')
        self.send.assert_not_called()
        self.assertEqual(self.query('SELECT media_id FROM notification_queue'), [('before-push',)])
        self.assertEqual([(row['provider'], row['state']) for row in self.store.snapshot()], [('email', 'pending')])
        self.enabled = {'email', 'pushover'}
        self.assertEqual(self.process(now=1100)['accepted'], 1)
        self.assertEqual(self.send.call_args.args[1], ['before-push'])
        self.assertEqual(self.send.call_args.args[0].provider, 'email')

    def test_disabled_push_has_no_backlog_when_email_delivers_and_push_reenables(self):
        self.enabled = {'email'}
        self.queue('email-only')
        self.assertEqual(self.process()['accepted'], 1)
        self.assertEqual([(row['provider'], row['state']) for row in self.store.snapshot()], [('email', 'accepted')])
        self.assertEqual(self.query('SELECT * FROM notification_queue'), [])
        self.enabled = {'email', 'pushover'}
        self.process(now=1100)
        self.assertEqual(self.send.call_count, 1)

    def test_removed_paused_email_cohort_cancels_and_settles_without_a_provider_call(self):
        self.enabled = {'pushover'}
        self.queue('paused')
        self.process()
        self.destinations = [self.push]
        report = self.process(now=1100)
        self.assertEqual(report['cancelled'], 1)
        self.assertEqual(self.send.call_count, 1)
        self.assertEqual(self.query('SELECT * FROM notification_queue'), [])
        self.assertEqual({(row['provider'], row['state']) for row in self.store.snapshot()},
                         {('email', 'cancelled'), ('pushover', 'accepted')})

    def test_changed_paused_email_scope_or_preferences_cancels_only_the_frozen_cohort(self):
        for changed in (replace(self.email, generation='replacement'),
                        replace(self.email, provider_generation='smtp-v2'),
                        replace(self.email, collections=frozenset((2,))),
                        replace(self.email, events=frozenset((notifications.REMINDER,)))):
            with self.subTest(destination=changed):
                self.destinations = [self.email, self.push]
                self.enabled = {'pushover'}
                self.queue('paused')
                self.process()
                before = self.send.call_count
                self.destinations = [changed, self.push]
                self.assertEqual(self.process(now=1100)['cancelled'], 1)
                self.assertEqual(self.send.call_count, before)
                self.assertEqual(self.query('SELECT * FROM notification_queue'), [])

    def test_snapshot_does_not_initialize_or_write_and_propagates_database_unavailability(self):
        missing = Path(self.directory.name) / 'missing.sqlite3'
        self.assertEqual(notifications.Store(missing, initialize=False).snapshot(), [])
        self.assertFalse(missing.exists())
        self.queue()
        self.process()
        before = self.path.read_bytes()
        self.store.snapshot()
        self.assertEqual(before, self.path.read_bytes())
        with patch.object(notifications.sqlite3, 'connect', side_effect=sqlite3.OperationalError('private DB path')):
            with self.assertRaises(sqlite3.OperationalError):
                self.store.snapshot()

    def test_untrusted_result_fields_are_not_stored_as_status_or_raw_errors(self):
        self.queue()
        self.send.return_value = notifications.Outcome('accepted', code='SECRET-ERROR', request_id='A' * 30)
        self.process()
        snapshot = self.store.snapshot()
        self.assertNotIn('SECRET-ERROR', str(snapshot))
        self.assertNotIn('A' * 30, str(snapshot))
        self.assertTrue(all(row['request_id'] is None for row in snapshot))

    def owner_destinations(self, *, email=True, push=True):
        self.destinations = []
        for include, target in ((email, self.email), (push, self.push)):
            if include:
                self.store.activate_destination(target.provider, target.id, target.generation, now=100)
                self.destinations.append(replace(target, events=notifications.EVENTS, owner_verified=True))
        self.callbacks = replace(self.callbacks, render_event=Mock(side_effect=lambda target, event: event))

    def job(self, state, *, at, token=None, scope='', observed_at=None):
        return self.store.observe_job('keep-expiry', state, allowed_job_ids={'keep-expiry'},
            run_token=token or 'run-' + str(at), finished_at=at, scope=scope,
            now=at if observed_at is None else observed_at)

    def failed_job(self, *, start=200, scope=''):
        self.assertFalse(self.job('failed', at=start, scope=scope))
        self.assertTrue(self.job('failed', at=start + 300, scope=scope))

    def legacy_job(self, state='failed', *, scope='', target=None, dispatch_state=None):
        self.store._observe_transition('job', 'keep-expiry', 'failed', scope, 200)
        if state == 'healthy':
            self.store._observe_transition('job', 'keep-expiry', 'healthy', scope, 300)
        if dispatch_state is not None:
            target = target or self.destinations[0]
            key = self.store._job_key('keep-expiry', scope, 1, 'failed')
            with closing(sqlite3.connect(self.path)) as db, db:
                db.execute("INSERT INTO notification_batches VALUES ('legacy-job','building',200,NULL)")
                db.execute("INSERT INTO notification_runs(batch_id) VALUES ('legacy-job')")
                db.execute("UPDATE notification_operational_events SET batch_id='legacy-job' WHERE event_key=?", (key,))
                self.store._seed(db, 'legacy-job', target, dispatch_state, 200,
                    accepted_at=200 if dispatch_state == 'accepted' else None)

    def test_brief_job_failure_and_recovery_never_queue_alert_or_recovery(self):
        self.owner_destinations()
        self.assertFalse(self.job('failed', at=200))
        self.assertFalse(self.job('healthy', at=380))
        self.assertEqual(self.query('SELECT * FROM notification_operational_events'), [])
        self.process(now=500)
        self.send.assert_not_called()

    def test_job_grace_needs_distinct_ordered_completions_and_survives_restart(self):
        self.assertFalse(self.job('failed', at=200))
        self.store = notifications.Store(self.path)
        self.assertFalse(self.job('failed', at=200, observed_at=1000))
        self.assertFalse(self.job('failed', at=199, observed_at=1000))
        self.assertFalse(self.job('healthy', at=199, observed_at=1000))
        self.assertFalse(self.job('failed', at=499))
        self.assertEqual(self.query('SELECT * FROM notification_operational_events'), [])
        self.assertTrue(self.job('failed', at=500))
        self.assertFalse(self.job('failed', at=500, observed_at=1000))
        self.assertEqual(self.query('SELECT failed_runs,first_failed_at FROM notification_job_observations'), [(3, 200)])
        self.assertEqual(self.query('SELECT kind FROM notification_operational_events'), [('JOB_FAILED',)])

    def test_job_grace_uses_actual_finish_time_instead_of_observation_time(self):
        self.assertFalse(self.job('failed', at=200, observed_at=1000))
        self.assertFalse(self.job('failed', at=499, observed_at=1000))
        self.assertTrue(self.job('failed', at=500, observed_at=1000))

    def test_completed_job_observations_reject_missing_malformed_and_future_evidence(self):
        for kwargs in ({'run_token': ''}, {'run_token': 'private\nvalue'}, {'run_token': 'x' * 129},
                       {'finished_at': None}, {'finished_at': float('nan')}, {'finished_at': True},
                       {'finished_at': -1}, {'finished_at': 131}, {'now': float('inf')}):
            values = dict(allowed_job_ids={'keep-expiry'}, run_token='run', finished_at=100, now=100)
            values.update(kwargs)
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                self.store.observe_job('keep-expiry', 'failed', **values)
        self.assertEqual(self.query('SELECT * FROM notification_job_observations'), [])

    def test_a_repeated_run_token_cannot_advance_grace_even_with_a_changed_timestamp(self):
        self.assertFalse(self.job('failed', at=200, token='same-run'))
        self.assertFalse(self.job('failed', at=600, token='same-run'))
        self.assertEqual(self.query('SELECT failed_runs,finished_at FROM notification_job_observations'), [(1, 200)])
        self.assertEqual(self.query('SELECT * FROM notification_operational_events'), [])

    def test_success_resets_pending_failure_time_and_recovery_is_queued_once(self):
        self.owner_destinations(email=False)
        self.job('failed', at=200)
        self.job('healthy', at=250)
        self.assertFalse(self.job('failed', at=300))
        self.assertFalse(self.job('failed', at=500))
        self.assertTrue(self.job('failed', at=600))
        self.process(now=600)
        self.assertTrue(self.job('healthy', at=700))
        self.assertFalse(self.job('healthy', at=800))
        self.process(now=800)
        self.assertEqual([call.args[1]['kind'] for call in self.send.call_args_list], ['JOB_FAILED', 'JOB_RESTORED'])

    def test_concurrent_legacy_store_initialization_adds_the_job_schema_once(self):
        path = Path(self.directory.name) / 'legacy-notifications.sqlite3'
        with closing(sqlite3.connect(path)) as db, db:
            db.execute('''CREATE TABLE notification_operational_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,event_key TEXT UNIQUE NOT NULL,
                kind TEXT NOT NULL,payload_json TEXT NOT NULL,created_at REAL NOT NULL,batch_id TEXT UNIQUE)''')
        with ThreadPoolExecutor(max_workers=2) as pool:
            list(pool.map(lambda _: notifications.Store(path), range(2)))
        with closing(sqlite3.connect(path)) as db, db:
            columns = [row[1] for row in db.execute('PRAGMA table_info(notification_operational_events)')]
            self.assertEqual(columns.count('invalidated_at'), 1)
            self.assertEqual(db.execute("SELECT count(*) FROM sqlite_master WHERE name='notification_job_observations'").fetchone()[0], 1)

    def test_job_scopes_do_not_share_grace_or_accepted_failure_proof(self):
        self.owner_destinations(email=False)
        self.failed_job(scope='scope-a')
        self.assertEqual(self.process(now=500)['accepted'], 1)
        self.failed_job(start=250, scope='scope-b')
        self.assertFalse(self.job('healthy', at=560, scope='scope-b'))
        self.assertTrue(self.job('healthy', at=600, scope='scope-a'))
        self.assertEqual(self.process(now=600)['accepted'], 1)
        self.assertEqual([c.args[1]['kind'] for c in self.send.call_args_list], ['JOB_FAILED', 'JOB_RESTORED'])
        self.assertEqual(self.query("SELECT episode FROM notification_transitions WHERE scope='scope-b'"), [(1,)])

    def test_recovery_only_targets_exact_accepted_failure_provider_and_destination(self):
        self.owner_destinations()
        self.failed_job()
        self.send.side_effect = lambda target, event: notifications.Outcome('review', 'email_uncertain') if target.provider == 'email' else notifications.Outcome('accepted')
        self.process(now=500)
        self.assertTrue(self.job('healthy', at=600))
        self.send.side_effect = None
        self.assertEqual(self.process(now=600)['accepted'], 1)
        self.assertEqual(self.send.call_args.args[0].provider, 'pushover')
        self.assertEqual(self.send.call_args.args[1]['kind'], 'JOB_RESTORED')
        self.assertEqual(self.query("SELECT state,error_code FROM notification_dispatches WHERE provider='email'"), [('review', 'email_uncertain')])

    def test_recovery_cancels_disabled_provider_retries_without_orphan_recovery(self):
        self.owner_destinations()
        self.failed_job()
        self.send.return_value = notifications.Outcome('retry', 'connect_failed')
        self.process(now=500)
        self.enabled = set()
        self.assertFalse(self.job('healthy', at=600))
        self.assertEqual(self.query('SELECT state,error_code FROM notification_dispatches'), [('cancelled', None), ('cancelled', None)])
        self.assertEqual(self.query('SELECT kind FROM notification_operational_events'), [('JOB_FAILED',)])
        self.enabled = {'email', 'pushover'}
        self.process(now=1000)
        self.assertEqual(self.send.call_count, 2)

    def test_unclaimed_job_failure_is_invalidated_when_job_recovers(self):
        self.owner_destinations()
        self.failed_job()
        self.assertFalse(self.job('healthy', at=600))
        self.process(now=600)
        self.send.assert_not_called()
        self.assertEqual(self.query('SELECT * FROM notification_dispatches'), [])

    def test_sending_review_and_rejected_failures_are_preserved_on_recovery(self):
        self.owner_destinations()
        self.failed_job()
        self.send.return_value = notifications.Outcome('review', 'response_uncertain')
        self.process(now=500)
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("UPDATE notification_dispatches SET state='sending' WHERE provider='email'")
        before = self.query('SELECT provider,state,error_code FROM notification_dispatches ORDER BY provider')
        self.assertFalse(self.job('healthy', at=600))
        self.assertEqual(self.query('SELECT provider,state,error_code FROM notification_dispatches ORDER BY provider'), before)
        self.assertEqual(self.query('SELECT kind FROM notification_operational_events'), [('JOB_FAILED',)])

    def test_job_recovery_cannot_join_a_new_destination_or_rekeyed_generation(self):
        self.owner_destinations(email=False)
        self.failed_job(); self.process(now=500)
        original = self.destinations[0]
        other = replace(original, id='new-owner-profile')
        rekeyed = replace(original, generation='new-pref', provider_generation='new-app')
        for target in (other, rekeyed):
            self.store.activate_destination(target.provider, target.id, target.generation, now=550)
        self.destinations = [other, rekeyed]
        self.job('healthy', at=600)
        self.process(now=600)
        self.assertEqual(self.send.call_count, 1)

    def test_recovery_during_failure_render_cancels_before_transport_reservation(self):
        self.owner_destinations(email=False); self.failed_job()
        def recover(target, event):
            self.job('healthy', at=600)
            return event
        self.callbacks = replace(self.callbacks, render_event=recover)
        self.process(now=500)
        self.send.assert_not_called()
        self.assertEqual(self.query('SELECT state,error_code FROM notification_dispatches'), [('cancelled', None)])

    def test_new_job_episode_cancels_old_recovery_retry_before_reservation(self):
        self.owner_destinations(email=False); self.failed_job(); self.process(now=500)
        self.job('healthy', at=600)
        self.send.return_value = notifications.Outcome('retry', 'connect_failed')
        self.process(now=600)
        self.failed_job(start=700)
        self.assertEqual(self.query("SELECT d.state,d.error_code FROM notification_dispatches d JOIN notification_operational_events e ON e.batch_id=d.batch_id WHERE e.kind='JOB_RESTORED'"), [('cancelled', None)])
        self.send.return_value = notifications.Outcome('accepted')
        self.process(now=1000)
        self.assertEqual([c.args[1]['kind'] for c in self.send.call_args_list], ['JOB_FAILED', 'JOB_RESTORED', 'JOB_FAILED'])

    def test_first_new_failure_cancels_old_unsent_recovery_without_reviving_it(self):
        self.owner_destinations(email=False); self.failed_job(); self.process(now=500)
        self.job('healthy', at=600)
        self.assertFalse(self.job('failed', at=700))
        self.process(now=700)
        self.assertEqual(self.send.call_count, 1)
        self.assertFalse(self.job('healthy', at=800))
        self.process(now=800)
        self.assertEqual(self.send.call_count, 1)
        self.assertEqual(self.query("SELECT invalidated_at FROM notification_operational_events WHERE kind='JOB_RESTORED'"), [(700,)])

    def test_new_failure_during_recovery_render_cancels_before_reservation(self):
        self.owner_destinations(email=False); self.failed_job(); self.process(now=500)
        self.job('healthy', at=600)
        def fail_again(target, event):
            self.job('failed', at=700)
            return event
        self.callbacks = replace(self.callbacks, render_event=fail_again)
        self.process(now=600)
        self.assertEqual(self.send.call_count, 1)
        self.assertEqual(self.query("SELECT d.state FROM notification_dispatches d JOIN notification_operational_events e ON e.batch_id=d.batch_id WHERE e.kind='JOB_RESTORED'"), [('cancelled',)])

    def test_authoritative_job_scope_change_cancels_old_scope_work_only(self):
        self.owner_destinations(email=False)
        self.store.synchronize_job_scopes({'keep-expiry': 'scope-a'}, allowed_job_ids={'keep-expiry'}, now=100)
        self.failed_job(scope='scope-a')
        self.send.return_value = notifications.Outcome('retry', 'connect_failed'); self.process(now=500)
        self.store.observe_connection('plex', 'failed', scope='connection-a', now=500)
        self.store.synchronize_job_scopes({'keep-expiry': 'scope-b'}, allowed_job_ids={'keep-expiry'}, now=550)
        self.assertEqual(self.query('SELECT state,error_code FROM notification_dispatches'), [('cancelled', None)])
        self.send.return_value = notifications.Outcome('accepted'); self.process(now=600)
        self.assertEqual(self.send.call_args.args[1]['kind'], 'CONNECTION_FAILED')
        self.assertEqual(self.send.call_count, 2)

    def test_missing_job_scope_disables_unscoped_job_and_reservation_rechecks_scope(self):
        self.owner_destinations(email=False)
        self.store.synchronize_job_scopes({'keep-expiry': None}, allowed_job_ids={'keep-expiry'}, now=100)
        self.failed_job()
        def disable(target, event):
            self.store.synchronize_job_scopes({}, allowed_job_ids={'keep-expiry'}, now=550)
            return event
        self.callbacks = replace(self.callbacks, render_event=disable)
        self.process(now=500)
        self.send.assert_not_called()
        self.assertEqual(self.query('SELECT state,error_code FROM notification_dispatches'), [('cancelled', None)])

    def test_scope_reconciliation_preserves_confirmed_and_uncertain_dispatches(self):
        self.owner_destinations()
        self.store.synchronize_job_scopes({'keep-expiry': 'scope-a'}, allowed_job_ids={'keep-expiry'}, now=100)
        self.failed_job(scope='scope-a')
        self.send.side_effect = lambda target, event: notifications.Outcome('accepted') if target.provider == 'pushover' else notifications.Outcome('review', 'email_uncertain')
        self.process(now=500)
        before = self.query('SELECT * FROM notification_dispatches')
        self.store.synchronize_job_scopes({}, allowed_job_ids={'keep-expiry'}, now=600)
        self.assertEqual(self.query('SELECT * FROM notification_dispatches'), before)

    def test_scope_cycle_restarts_grace_and_new_episode_without_replaying_old_work(self):
        self.owner_destinations(email=False)
        sync = lambda scopes, now: self.store.synchronize_job_scopes(scopes, allowed_job_ids={'keep-expiry'}, now=now)
        sync({'keep-expiry': 'scope-a'}, 100)
        self.failed_job(scope='scope-a')
        sync({'keep-expiry': 'scope-b'}, 550)
        sync({'keep-expiry': 'scope-a'}, 575)
        self.assertFalse(self.job('failed', at=500, scope='scope-a', observed_at=600))
        self.assertFalse(self.job('failed', at=600, scope='scope-a'))
        self.process(now=600); self.send.assert_not_called()
        self.assertTrue(self.job('failed', at=900, scope='scope-a'))
        self.process(now=900)
        self.assertEqual(self.send.call_count, 1)
        self.assertEqual(self.send.call_args.args[1]['episode'], 2)

    def test_disable_and_reenable_same_scope_resets_unqualified_failure_evidence(self):
        sync = lambda scopes, now: self.store.synchronize_job_scopes(scopes, allowed_job_ids={'keep-expiry'}, now=now)
        sync({'keep-expiry': None}, 100)
        self.job('failed', at=200)
        sync({}, 300)
        sync({'keep-expiry': None}, 600)
        self.assertFalse(self.job('failed', at=200, observed_at=700))
        self.assertFalse(self.job('failed', at=700))
        self.assertFalse(self.job('failed', at=900))
        self.assertTrue(self.job('failed', at=1000))
        self.assertEqual(self.query('SELECT first_failed_at,failed_runs FROM notification_job_observations'), [(700, 3)])

    def test_accepted_old_scope_failure_does_not_create_recovery_after_reenable(self):
        self.owner_destinations(email=False)
        sync = lambda scopes, now: self.store.synchronize_job_scopes(scopes, allowed_job_ids={'keep-expiry'}, now=now)
        sync({'keep-expiry': None}, 100)
        self.failed_job(); self.process(now=500)
        accepted = self.query('SELECT * FROM notification_dispatches')
        sync({}, 550); sync({'keep-expiry': None}, 575)
        self.assertFalse(self.job('healthy', at=600))
        self.process(now=600)
        self.assertEqual(self.send.call_count, 1)
        self.assertEqual(self.query('SELECT * FROM notification_dispatches'), accepted)
        self.assertEqual(self.query("SELECT * FROM notification_operational_events WHERE kind='JOB_RESTORED'"), [])

    def test_owner_retry_cannot_resurrect_a_recovered_uncertain_failure(self):
        self.owner_destinations(email=False); self.failed_job()
        self.send.return_value = notifications.Outcome('review', 'response_uncertain'); self.process(now=500)
        batch = self.query('SELECT batch_id FROM notification_dispatches')[0][0]
        self.job('healthy', at=600)
        self.assertTrue(self.store.resolve_review(batch, self.push.provider, self.push.id, action='retry', now=700))
        self.process(now=700)
        self.assertEqual(self.send.call_count, 1)
        self.assertEqual(self.query('SELECT state,error_code FROM notification_dispatches'), [('cancelled', None)])

    def test_legacy_unannounced_failures_cannot_send_before_observation_or_bypass_grace(self):
        self.owner_destinations(email=False); self.legacy_job(dispatch_state='pending')
        self.store = notifications.Store(self.path)
        self.process(now=300)
        self.send.assert_not_called()
        self.assertFalse(self.job('failed', at=400))
        self.assertTrue(self.job('failed', at=700))
        self.process(now=700)
        self.assertEqual(self.send.call_count, 1)
        self.assertEqual(self.send.call_args.args[1]['episode'], 2)

    def test_legacy_accepted_job_episode_restores_only_its_confirmed_destination(self):
        self.owner_destinations(); self.legacy_job(target=self.destinations[1], dispatch_state='accepted')
        before = self.query("SELECT * FROM notification_dispatches WHERE state='accepted'")
        self.store = notifications.Store(self.path)
        self.assertTrue(self.job('healthy', at=400))
        self.process(now=400)
        self.assertEqual(self.send.call_count, 1)
        self.assertEqual(self.send.call_args.args[0].provider, 'pushover')
        self.assertEqual(self.send.call_args.args[1]['kind'], 'JOB_RESTORED')
        self.assertEqual(self.query("SELECT * FROM notification_dispatches WHERE batch_id='legacy-job'"), before)

    def test_legacy_orphan_recoveries_do_not_send_without_accepted_failure(self):
        self.owner_destinations(); self.legacy_job('healthy')
        self.process(now=400)
        self.send.assert_not_called()

    def test_connection_and_job_events_are_deduplicated_per_transition_and_scope_after_restart(self):
        self.assertFalse(self.store.observe_connection('plex', 'healthy', scope='plex-v1', now=100))
        self.assertTrue(self.store.observe_connection('plex', 'failed', scope='plex-v1', now=200))
        self.assertFalse(self.store.observe_connection('plex', 'failed', scope='plex-v1', now=300))
        self.store = notifications.Store(self.path)
        self.assertFalse(self.store.observe_connection('plex', 'failed', scope='plex-v1', now=400))
        self.assertTrue(self.store.observe_connection('plex', 'healthy', scope='plex-v1', now=500))
        self.assertTrue(self.store.observe_connection('plex', 'failed', scope='plex-v1', now=600))
        self.assertFalse(self.store.observe_connection('plex', 'healthy', scope='plex-v2', now=700))
        self.assertFalse(self.job('failed', at=800))
        self.assertFalse(self.job('failed', at=800, observed_at=1000))
        self.assertTrue(self.job('failed', at=1100))
        self.assertFalse(self.job('failed', at=1100, observed_at=1200))
        rows = self.query('SELECT kind,payload_json FROM notification_operational_events ORDER BY id')
        self.assertEqual([row[0] for row in rows], ['CONNECTION_FAILED', 'CONNECTION_RESTORED', 'CONNECTION_FAILED', 'JOB_FAILED'])
        self.assertIn('"episode": 2', rows[2][1])
        self.assertEqual(self.query('SELECT * FROM notification_queue'), [])

    def test_seerr_recorded_connection_has_the_same_transition_deduplication(self):
        self.assertTrue(self.store.observe_connection('seerr', 'failed', scope='configured', now=100))
        self.assertFalse(self.store.observe_connection('seerr', 'failed', scope='configured', now=200))
        self.assertTrue(self.store.observe_connection('seerr', 'healthy', scope='configured', now=300))
        self.assertEqual([row[0] for row in self.query('SELECT kind FROM notification_operational_events')],
                         ['CONNECTION_FAILED', 'CONNECTION_RESTORED'])

    def test_operational_only_processing_leaves_unreconciled_media_and_legacy_receipts_untouched(self):
        self.owner_destinations()
        self.queue('unclaimed', now=100)
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("INSERT INTO notification_batches VALUES ('legacy','sent',100,'old')")
            db.execute("INSERT INTO notification_deliveries VALUES ('legacy','a@example.test',100)")
        self.queue('legacy-leftover', now=100, batch='legacy')
        before = {table: self.query('SELECT * FROM ' + table) for table in
                  ('notification_queue', 'notification_deliveries', 'notification_batches', 'notification_runs')}
        self.store.observe_update('2.10.0', now=200)
        report = self.store.process(self.callbacks, now=200, quiet_seconds=0, include_media=False)
        self.assertEqual(report['accepted'], 2)
        self.resolve.assert_not_called()
        for table in ('notification_queue', 'notification_deliveries'):
            self.assertEqual(self.query('SELECT * FROM ' + table), before[table])
        self.assertEqual(self.query("SELECT * FROM notification_batches WHERE id='legacy'"), before['notification_batches'])
        self.assertEqual(self.query("SELECT * FROM notification_runs WHERE batch_id='legacy'"), [])

    def test_operational_event_sources_reject_unknown_ids_states_and_nonstable_versions(self):
        with self.assertRaises(ValueError):
            self.store.observe_connection('https://private.example/?token=secret', 'failed')
        with self.assertRaises(ValueError):
            self.store.observe_job('unknown-job', 'failed', allowed_job_ids={'keep-expiry'}, run_token='run', finished_at=100, now=100)
        with self.assertRaises(ValueError):
            self.store.observe_connection('plex', 'waiting')
        for version in ('2.9', 'v2.10.0', '2.10.0-rc1', '<script>', '02.10.0'):
            with self.assertRaises(ValueError):
                self.store.observe_update(version)
        self.assertTrue(self.store.observe_update('2.10.0', now=100))
        self.assertFalse(self.store.observe_update('2.10.0', now=200))
        self.store = notifications.Store(self.path)
        self.assertFalse(self.store.observe_update('2.10.0', now=300))

    def test_only_fresh_owner_verified_destinations_receive_selected_operational_events(self):
        self.owner_destinations()
        viewer = replace(self.push, id='viewer-profile', events=notifications.EVENTS, owner_verified=False)
        self.store.activate_destination(viewer.provider, viewer.id, viewer.generation, now=100)
        self.destinations.append(viewer)
        self.store.observe_connection('plex', 'failed', now=200)
        report = self.process(now=200)
        self.assertEqual(report['accepted'], 2)
        self.assertEqual({call.args[0].id for call in self.send.call_args_list}, {self.email.id, self.push.id})
        self.assertEqual(self.send.call_args.args[1]['kind'], 'CONNECTION_FAILED')
        self.assertEqual(self.resolve.call_count, 0)
        self.assertEqual(self.query('SELECT * FROM notification_queue'), [])
        self.process(now=300)
        self.assertEqual(self.send.call_count, 2)

    def test_operational_activation_excludes_old_events_for_both_providers(self):
        self.store.observe_update('2.10.0', now=100)
        self.owner_destinations()
        self.store.observe_update('2.11.0', now=200)
        self.process(now=200)
        self.assertEqual(self.send.call_count, 2)
        self.assertEqual({call.args[1]['version'] for call in self.send.call_args_list}, {'2.11.0'})
        self.assertEqual(len(self.query('SELECT * FROM notification_operational_events')), 2)

    def test_owner_revocation_during_operational_render_never_sends_the_alert(self):
        self.owner_destinations(email=False)
        self.store.observe_connection('plex', 'failed', now=200)
        def revoke(target, event):
            self.destinations = [replace(target, owner_verified=False)]
            return event
        self.callbacks = replace(self.callbacks, render_event=revoke)
        self.process(now=200)
        self.send.assert_not_called()
        self.process(now=300)
        self.send.assert_not_called()
        self.assertEqual(self.store.snapshot()[0]['state'], 'cancelled')

    def test_uncertain_operational_email_does_not_block_push_or_later_media(self):
        self.owner_destinations()
        self.store.observe_update('2.10.0', now=200)
        self.send.side_effect = lambda target, message: notifications.Outcome('review', 'email_uncertain') if target.provider == 'email' else notifications.Outcome('accepted')
        report = self.process(now=200)
        self.assertEqual((report['review'], report['accepted']), (1, 1))
        self.queue('media', now=300)
        report = self.process(now=1000)
        self.assertEqual((report['review'], report['accepted']), (1, 1))
        self.assertEqual(self.send.call_count, 4)

    def test_operational_event_payload_does_not_forward_untrusted_fields(self):
        self.owner_destinations(email=False)
        self.store.observe_update('2.10.0', now=200)
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute('''UPDATE notification_operational_events SET payload_json=
                '{"version":"2.10.0","token":"SECRET","exception":"private url"}' ''')
        self.process(now=200)
        message = self.send.call_args.args[1]
        self.assertNotIn('SECRET', str(message))
        self.assertNotIn('private url', str(message))
        self.assertEqual(set(message), {'id', 'kind', 'created_at', 'version'})

    def test_pending_operational_alert_cannot_join_a_new_destination_cohort(self):
        self.owner_destinations(email=False)
        self.store.observe_update('2.10.0', now=200)
        self.send.return_value = notifications.Outcome('retry', 'connect_failed')
        self.process(now=200)
        other = replace(self.destinations[0], id='new-owner-profile')
        self.store.activate_destination(other.provider, other.id, other.generation, now=300)
        self.destinations.append(other)
        self.send.return_value = notifications.Outcome('accepted')
        self.process(now=300)
        self.assertEqual(self.send.call_count, 2)
        self.assertEqual({call.args[0].id for call in self.send.call_args_list}, {self.push.id})


if __name__ == '__main__':
    unittest.main()
