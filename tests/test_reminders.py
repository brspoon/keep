"""Reminder catch-up, aggregate webhook routing, and durable deduplication."""
import unittest
from contextlib import closing
from datetime import datetime, timezone
from unittest.mock import patch
from test_keep import keep


class ReminderTests(unittest.TestCase):
    now = datetime(2026, 9, 30, 18, tzinfo=timezone.utc).timestamp()

    def setUp(self):
        with closing(keep.attribution_db()) as db, db:
            for table in ('notification_queue', 'notification_reminders', 'notification_deliveries', 'notification_batches'):
                db.execute('DELETE FROM ' + table)
        self.items = {}
        self.settings = patch.object(keep, 'get_collections', return_value={1: 'Movies Leaving Plex Soon', 3: 'Shows Leaving Plex Soon'})
        self.current = patch.object(keep, 'digest_collection_items', side_effect=lambda cid: self.items.get(cid, {}))
        self.retention = patch.object(keep, 'get_collection_delete_after_days', return_value=30)
        self.enabled = patch.object(keep, 'email_enabled', return_value=True)
        for name in ('settings', 'current', 'retention', 'enabled'):
            patcher = getattr(self, name)
            setattr(self, name, patcher.start())
            self.addCleanup(patcher.stop)

    def item(self, days, title='Movie'):
        return {'addDate': datetime.fromtimestamp(self.now - (30-days)*86400, timezone.utc).isoformat(),
                'mediaData': {'title': title}}

    def rows(self, table='notification_queue'):
        with closing(keep.attribution_db()) as db:
            return [dict(row) for row in db.execute('SELECT * FROM ' + table)]

    def test_exact_seven_days_and_missed_window_catch_up_only_future_deadlines(self):
        self.items = {1: {str(days): self.item(days) for days in (8, 7, 4, 1, 0, -1)}}
        self.items[1]['invalid'] = {'addDate': 'not-a-date'}
        self.items[1]['naive'] = {'addDate': '2026-09-06T18:00:00'}
        self.assertEqual(keep.queue_due_reminders(self.now), 3)
        self.assertEqual({r['media_id'] for r in self.rows()}, {'7', '4', '1'})
        first = self.rows()
        self.assertEqual(keep.queue_due_reminders(self.now + 60), 0)
        self.assertEqual(self.rows(), first)  # No repeated postponement of quiet window.

    def test_aggregate_warning_resolves_all_configured_collections_without_http_io(self):
        self.items = {1: {'movie': self.item(4)}, 3: {'show': self.item(6, 'Show')}}
        with patch.object(keep, 'KEEP_WEBHOOK_SECRET', 'test'), patch.object(keep, 'send_email') as mail:
            response = keep.app.test_client().post('/api/webhooks/maintainerr', json={
                'notificationType': keep.REMINDER_KIND, 'collectionName': '',
                'mediaItems': [{'mediaServerId': 'movie'}, {'mediaServerId': 'show'}]},
                headers={'Authorization': 'Bearer test'})
            self.assertEqual(response.status_code, 200)
            self.current.assert_not_called()
            mail.assert_not_called()
        keep.reconcile_reminder_queue()
        self.assertEqual({(r['collection_id'], r['media_id']) for r in self.rows()}, {(1, 'movie'), (3, 'show')})
        self.assertEqual(len(self.rows('notification_reminders')), 2)

    def test_upstream_failure_keeps_aggregate_event_for_retry(self):
        keep.queue_notifications(0, ['movie'], keep.REMINDER_KIND, self.now)
        self.current.side_effect = RuntimeError('upstream offline')
        with self.assertRaises(RuntimeError):
            keep.reconcile_reminder_queue()
        self.assertEqual(self.rows()[0]['collection_id'], 0)
        self.assertEqual(self.rows('notification_reminders'), [])

    def test_duplicate_webhook_does_not_reset_window_or_repeat_after_send(self):
        self.items = {1: {'movie': self.item(4)}}
        keep.queue_due_reminders(self.now)
        first = self.rows()
        keep.queue_notifications(1, ['movie'], keep.REMINDER_KIND, self.now + 20)
        keep.reconcile_reminder_queue()
        self.assertEqual(self.rows(), first)
        # Successful batches remove queue events but must retain reminder claims.
        with closing(keep.attribution_db()) as db, db:
            db.execute('DELETE FROM notification_queue')
        keep.queue_notifications(0, ['movie'], keep.REMINDER_KIND, self.now + 1000)
        keep.reconcile_reminder_queue()
        self.assertEqual(self.rows(), [])
        self.assertEqual(keep.queue_due_reminders(self.now + 1000), 0)
        # A new Leaving episode permits a new reminder for the same title.
        self.items[1]['movie'] = self.item(5)
        self.assertEqual(keep.queue_due_reminders(self.now + 1000), 1)
        self.assertEqual(len(self.rows('notification_reminders')), 2)

    def test_existing_review_batch_takes_precedence_and_still_blocks_sending(self):
        self.items = {1: {'movie': self.item(4)}}
        keep.queue_notifications(1, ['movie'], keep.REMINDER_KIND, self.now - 1000)
        with closing(keep.attribution_db()) as db, db:
            db.execute("INSERT INTO notification_batches VALUES ('uncertain', 'review', ?, 'SMTP uncertain')", (self.now,))
            db.execute("UPDATE notification_queue SET batch_id = 'uncertain'")
        keep.queue_notifications(1, ['movie'], keep.REMINDER_KIND, self.now)
        self.assertEqual(keep.queue_due_reminders(self.now), 0)
        self.assertEqual(len(self.rows()), 1)
        with patch.object(keep, 'send_email') as mail:
            self.assertEqual(keep.process_digest(self.now + 1000), 'review')
            mail.assert_not_called()

    def test_retention_failure_does_not_partially_enqueue_a_scan(self):
        self.items = {1: {'movie': self.item(4)}}
        self.retention.side_effect = [30, None]
        with self.assertRaises(ValueError):
            keep.queue_due_reminders(self.now)
        self.assertEqual(self.rows(), [])

    def test_missing_timestamp_warning_cannot_send_untracked(self):
        self.items = {1: {'movie': {'mediaData': {'title': 'Movie'}}}}
        keep.queue_notifications(1, ['movie'], keep.REMINDER_KIND, self.now)
        with patch.object(keep, 'send_email') as mail, self.assertRaises(ValueError):
            keep.process_digest(self.now + 1000)
        mail.assert_not_called()
        self.assertEqual(len(self.rows()), 1)

    def test_kept_removed_and_disabled_email_do_not_queue(self):
        self.assertEqual(keep.queue_due_reminders(self.now), 0)
        self.items = {1: {'movie': self.item(4)}}
        self.enabled.return_value = False
        self.assertEqual(keep.queue_due_reminders(self.now), 0)
        self.current.assert_called()  # Only the first, enabled empty scan accessed data.
        self.assertEqual(self.rows(), [])

    def test_warning_batch_send_retains_claim_and_cannot_resend(self):
        self.items = {1: {'movie': self.item(4)}}
        keep.queue_due_reminders(self.now)
        with patch.object(keep, 'get_recipient_delivery_preferences', return_value={'a@example.com': {1}}), \
             patch.object(keep, 'connection_value', return_value='https://keep.example'), \
             patch.object(keep, 'send_email') as mail:
            self.assertEqual(keep.process_digest(self.now + 1000), 'sent')
            self.assertEqual(len(self.rows('notification_reminders')), 1)
            keep.queue_notifications(0, ['movie'], keep.REMINDER_KIND, self.now + 1100)
            self.assertEqual(keep.process_digest(self.now + 2100), 'waiting')
            self.assertEqual(mail.call_count, 1)
