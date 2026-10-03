import json
import os
import tempfile
import unittest
from contextlib import closing
from unittest.mock import patch, Mock
from test_keep import keep

class DigestTests(unittest.TestCase):
    def setUp(self):
        self.client = keep.app.test_client()
        keep.app.config['TESTING'] = True
        with closing(keep.attribution_db()) as db, db:
            db.execute('DELETE FROM notification_queue')
            db.execute('DELETE FROM notification_batches')
            db.execute('DELETE FROM notification_deliveries')
            db.execute('DELETE FROM notification_reminders')
        self.cid, self.name = next(iter(keep.COLLECTIONS.items()))

    def enqueue(self, ids, cid=None, now=1000, kind='MEDIA_ADDED_TO_COLLECTION'):
        keep.queue_notifications(cid or self.cid, ids, kind, now)

    def count(self, table):
        with closing(keep.attribution_db()) as db, db:
            return db.execute('SELECT COUNT(*) FROM ' + table).fetchone()[0]

    def test_worker_heartbeat_creates_and_refreshes_file(self):
        with tempfile.TemporaryDirectory() as directory:
            heartbeat = os.path.join(directory, 'digest-worker.heartbeat')
            with patch.object(keep, 'DIGEST_WORKER_HEARTBEAT_PATH', heartbeat):
                keep.update_digest_worker_heartbeat(now=1000)
                self.assertTrue(os.path.isfile(heartbeat))
                self.assertEqual(os.path.getmtime(heartbeat), 1000)
                keep.update_digest_worker_heartbeat(now=1100)
                self.assertEqual(os.path.getmtime(heartbeat), 1100)

    def test_webhooks_queue_all_items_and_never_send(self):
        with patch.object(keep, 'KEEP_WEBHOOK_SECRET', 'test'), patch.object(keep, 'send_email') as mail:
            data = dict(notificationType='MEDIA_ADDED_TO_COLLECTION', collectionName=self.name,
                        mediaServerId='1', mediaItems=json.dumps([{'mediaServerId': '2'}, {'mediaServerId': '3'}]))
            self.assertEqual(self.client.post('/api/webhooks/maintainerr', json=data).status_code, 401)
            for _ in range(2):
                response = self.client.post('/api/webhooks/maintainerr', json=data, headers={'Authorization': 'Bearer test'})
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.json['items'], 3)
            self.assertEqual(self.count('notification_queue'), 3)
            mail.assert_not_called()

    def test_all_collections_share_quiet_window(self):
        self.enqueue(['1', '2'])
        self.enqueue(['3'], cid=3, now=1500)
        with patch.object(keep, 'resolve_digest') as resolve:
            self.assertEqual(keep.process_digest(now=2000), 'waiting')
            resolve.assert_not_called()

    @patch.object(keep, 'SMTP_PASSWORD', 'test')
    @patch.object(keep, 'KEEP_URL', 'https://keep.example')
    @patch.object(keep, 'get_recipient_delivery_preferences',
                  return_value={'a@example.com': {1, 3, 5, 6}, 'b@example.com': {1, 3, 5, 6}})
    @patch.object(keep, 'send_email')
    def test_multiple_collections_one_mail_per_recipient_then_no_resend(self, mail, recipients):
        self.enqueue([str(i) for i in range(125)])
        self.enqueue(['show'], cid=3)
        def resolve(events):
            self.assertEqual(len(events), 126)
            return [dict(collection_id=1, collection='Movies', title='<Movie>', year=2026, days=30, urgent=False),
                    dict(collection_id=3, collection='Shows', title='Show', year=None, days=2, urgent=True)]
        with patch.object(keep, 'resolve_digest', side_effect=resolve):
            self.assertEqual(keep.process_digest(now=1700), 'sent')
            self.assertEqual(keep.process_digest(now=1800), 'waiting')
        self.assertEqual(mail.call_count, 2)
        args = mail.call_args_list[0].args
        self.assertEqual(mail.call_args_list[0].args[0], ['a@example.com'])
        self.assertEqual(mail.call_args_list[1].args[0], ['b@example.com'])
        self.assertIn('2 titles', args[1])
        self.assertIn('&lt;Movie&gt;', args[2])
        self.assertIn('30 days left', args[3])
        self.assertIn('Show', args[3])
        self.assertEqual(self.count('notification_queue'), 0)

    @patch.object(keep, 'SMTP_PASSWORD', 'test')
    @patch.object(keep, 'KEEP_URL', 'https://keep.example')
    @patch.object(keep, 'get_recipient_delivery_preferences', return_value={'a@example.com': {1}})
    @patch.object(keep, 'send_email', side_effect=OSError('SMTP disconnected'))
    def test_uncertain_delivery_is_held_not_resent(self, mail, recipients):
        self.enqueue(['1'])
        item = dict(collection_id=1, collection='Movies', title='One', year=None, days=30, urgent=False)
        with patch.object(keep, 'resolve_digest', return_value=[item]):
            self.assertEqual(keep.process_digest(now=1700), 'review')
            self.assertEqual(keep.process_digest(now=1800), 'review')
        mail.assert_called_once()
        self.assertEqual(self.count('notification_queue'), 1)

    @patch.object(keep, 'SMTP_PASSWORD', 'test')
    @patch.object(keep, 'KEEP_URL', 'https://keep.example')
    @patch.object(keep, 'get_recipient_delivery_preferences',
                  return_value={'a@example.com': {1}, 'b@example.com': {1}})
    def test_partial_delivery_records_success_and_does_not_resend_it(self, recipients):
        self.enqueue(['1'])
        item = dict(collection_id=1, collection='Movies', title='One', year=None,
                    days=30, urgent=False)
        with patch.object(keep, 'resolve_digest', return_value=[item]), \
             patch.object(keep, 'send_email', side_effect=[None, OSError('SMTP'), None]) as mail:
            self.assertEqual(keep.process_digest(now=1700), 'review')
            with closing(keep.attribution_db()) as db, db:
                batch_id = db.execute("SELECT id FROM notification_batches").fetchone()[0]
                delivered = db.execute("SELECT email FROM notification_deliveries").fetchall()
                db.execute("UPDATE notification_batches SET status='building' WHERE id=?", (batch_id,))
            self.assertEqual([row['email'] for row in delivered], ['a@example.com'])
            self.assertEqual(keep.process_digest(now=1800), 'sent')
        self.assertEqual([call.args[0] for call in mail.call_args_list],
                         [['a@example.com'], ['b@example.com'], ['b@example.com']])

    @patch.object(keep, 'SMTP_PASSWORD', 'test')
    @patch.object(keep, 'KEEP_URL', 'https://keep.example')
    @patch.object(keep, 'get_recipient_delivery_preferences',
                  return_value={'movies@example.com': {1}, 'shows@example.com': {3}})
    @patch.object(keep, 'send_email')
    def test_each_recipient_gets_only_subscribed_collections(self, mail, recipients):
        self.enqueue(['movie'])
        self.enqueue(['show'], cid=3)
        items = [
            dict(collection_id=1, collection='Movies', title='Movie title', year=None,
                 days=30, urgent=False),
            dict(collection_id=3, collection='Shows', title='Show title', year=None,
                 days=30, urgent=False),
        ]
        with patch.object(keep, 'resolve_digest', return_value=items):
            self.assertEqual(keep.process_digest(now=1700), 'sent')
        movie_mail, show_mail = mail.call_args_list
        self.assertEqual(movie_mail.args[0], ['movies@example.com'])
        self.assertIn('Movie title', movie_mail.args[3])
        self.assertNotIn('Show title', movie_mail.args[3])
        self.assertEqual(show_mail.args[0], ['shows@example.com'])
        self.assertIn('Show title', show_mail.args[3])
        self.assertNotIn('Movie title', show_mail.args[3])

    @patch.object(keep, 'get_recipient_delivery_preferences', return_value={})
    @patch.object(keep, 'send_email')
    def test_no_subscribed_recipients_clears_batch_without_email(self, mail, recipients):
        self.enqueue(['1'])
        item = dict(collection_id=1, collection='Movies', title='One', year=None,
                    days=30, urgent=False)
        with patch.object(keep, 'resolve_digest', return_value=[item]):
            self.assertEqual(keep.process_digest(now=1700), 'empty')
        mail.assert_not_called()
        self.assertEqual(self.count('notification_queue'), 0)

    def test_preparation_failure_retries_durable_batch(self):
        self.enqueue(['1'])
        with patch.object(keep, 'resolve_digest', side_effect=RuntimeError('Maintainerr unavailable')):
            with self.assertRaises(RuntimeError):
                keep.process_digest(now=1700)
        self.assertEqual(self.count('notification_queue'), 1)
        with patch.object(keep, 'resolve_digest', return_value=[]), patch.object(keep, 'send_email') as mail:
            self.assertEqual(keep.process_digest(now=1800), 'empty')
            mail.assert_not_called()

    def test_pagination_includes_more_than_100_and_filters_kept(self):
        def response(url, **kwargs):
            if '/exclusions/' in url:
                items = [{'mediaServerId': '0'}]
            elif url.endswith('/1'):
                items = [{'mediaServerId': str(i)} for i in range(100)]
            else:
                items = [{'mediaServerId': '100'}]
            return Mock(json=lambda: {'items': items})
        with patch.object(keep.requests, 'get', side_effect=response):
            items = keep.digest_collection_items(self.cid)
        self.assertEqual(len(items), 100)
        self.assertIn('100', items)
        self.assertNotIn('0', items)

    def test_poster_rows_and_missing_artwork(self):
        items = [dict(collection='Shows', title='A & B', year=2026, days=30, urgent=False,
                      removal_date='2026-10-05',
                      poster_url='https://image.tmdb.org/test.jpg?a=1&b=2'),
                 dict(collection='Shows', title='Missing', year=None, days=1, urgent=False)]
        subject, body, plain = keep.build_digest_email(items, 'https://keep.example')
        self.assertIn('width="72" height="108"', body)
        self.assertIn('test.jpg?a=1&amp;b=2', body)
        self.assertIn('A &amp; B', body)
        self.assertIn('No poster', body)
        self.assertIn('Missing', plain)
        self.assertIn('1 day left', plain)
        self.assertIn('2 titles are leaving Plex', body)
        self.assertIn('Earliest deadline', body)
        self.assertIn('Scheduled for removal October 5, 2026', body)
        self.assertIn('Shows (2)', plain)
        self.assertIn('Review titles in Keep', body)
        self.assertNotIn('Maintainerr', body)
        self.assertNotIn('Maintainerr', plain)

    def test_removal_date_uses_collection_add_date_and_retention(self):
        removal_date = keep.calculate_removal_date('2026-09-05T12:00:00Z', 30)
        self.assertEqual(removal_date.isoformat(), '2026-10-05')

    def test_resolution_skips_removed_and_merges_warning(self):
        events = [dict(collection_id=self.cid, media_id='1', kind=kind) for kind in keep.DIGEST_TYPES]
        events.append(dict(collection_id=self.cid, media_id='2', kind='MEDIA_ADDED_TO_COLLECTION'))
        with patch.object(keep, 'digest_collection_items', return_value={'1': {'mediaData': {'title': 'One'}}}), \
             patch.object(keep, 'get_collection_delete_after_days', return_value=30):
            items = keep.resolve_digest(events)
        self.assertEqual(len(items), 1)
        self.assertTrue(items[0]['urgent'])

    def test_prune_removes_titles_no_longer_in_collection(self):
        self.enqueue(['1', '2', '3'])
        with patch.object(keep, 'digest_collection_items', return_value={'1': {}}):
            self.assertEqual(keep.prune_notification_queue(), 2)
        with closing(keep.attribution_db()) as db, db:
            rows = db.execute(
                'SELECT media_id FROM notification_queue ORDER BY media_id'
            ).fetchall()
        self.assertEqual([row['media_id'] for row in rows], ['1'])

if __name__ == '__main__':
    unittest.main()
