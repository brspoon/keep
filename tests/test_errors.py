import sqlite3
import unittest
from contextlib import closing
from unittest.mock import patch
import test_keep
from test_keep import keep


class ErrorPageTests(unittest.TestCase):
    def setUp(self):
        test_keep.KeepTests.setUp(self)
        with closing(keep.attribution_db()) as db, db:
            db.execute("INSERT INTO media_libraries(library_key,service,external_id,name,path) VALUES ('radarr:4','radarr','4','Movies','/movies')")

    def test_unexpected_html_error_is_branded_private_and_recoverable(self):
        with patch.dict(keep.app.config, PROPAGATE_EXCEPTIONS=False), \
             patch.object(keep, 'build_library_sections', side_effect=RuntimeError('private secret')):
            response = self.client.get('/library')
        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 500)
        self.assertIn('A little interruption.', body)
        self.assertIn('/static/keep-ui.css', body)
        self.assertIn('href="/library">Try again', body)
        self.assertNotIn('private secret', body)
        self.assertNotIn('Internal Server Error', body)
        self.assertEqual(response.headers['Cache-Control'], 'no-store')
        self.assertEqual(response.headers['X-Content-Type-Options'], 'nosniff')

    def test_database_context_failure_does_not_break_fallback(self):
        with patch.dict(keep.app.config, PROPAGATE_EXCEPTIONS=False), \
             patch.object(keep, 'build_library_sections', return_value=[]), \
             patch.object(keep, 'current_profile', side_effect=sqlite3.OperationalError('private DB path')):
            response = self.client.get('/library')
        self.assertEqual(response.status_code, 500)
        self.assertIn(b'A little interruption.', response.data)
        self.assertNotIn(b'private DB path', response.data)

    def test_api_errors_are_json_not_html(self):
        with patch.dict(keep.app.config, PROPAGATE_EXCEPTIONS=False), \
             patch.object(keep, 'get_collection_media', side_effect=RuntimeError('private endpoint')):
            response = self.client.get('/api/counts')
        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.mimetype, 'application/json')
        self.assertIn('Check the latest state', response.json['error'])
        self.assertNotIn('private', response.json['error'])

    def test_failed_post_does_not_offer_resubmission(self):
        with keep.app.test_request_context('/settings/users/8', method='POST'):
            response = keep.unexpected_error(RuntimeError('private'))
        body = response.get_data(as_text=True)
        self.assertIn('Check the latest state', body)
        self.assertNotIn('Try again</a>', body)
        self.assertNotIn('href="/settings/users/8"', body)


if __name__ == '__main__':
    unittest.main()
