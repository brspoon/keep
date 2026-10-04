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

    def test_missing_page_is_branded_private_and_offers_valid_recovery_links(self):
        for method in ('get', 'post'):
            with self.subTest(method=method):
                response = getattr(self.client, method)('/missing-private-page?token=private-token')
                body = response.get_data(as_text=True)
                self.assertEqual(response.status_code, 404)
                self.assertEqual(response.mimetype, 'text/html')
                self.assertIn('<title>Page not found · Keep</title>', body)
                self.assertIn('This page isn’t on the shelf.', body)
                self.assertIn(f'/static/keep-icon.svg?v={keep.APP_VERSION}', body)
                self.assertIn('rel="apple-touch-icon" sizes="180x180"', body)
                self.assertIn('href="/static/site.webmanifest"', body)
                self.assertIn('href="/">Back to Keep', body)
                self.assertIn('href="/help">Open FAQ', body)
                self.assertNotIn('missing-private-page', body)
                self.assertNotIn('private-token', body)
                self.assertNotIn('Try again</a>', body)
                self.assertEqual(response.headers['Cache-Control'], 'no-store')
                self.assertEqual(response.headers['X-Content-Type-Options'], 'nosniff')

    def test_missing_page_uses_saved_appearance(self):
        for mode in ('light', 'dark'):
            with self.subTest(mode=mode):
                with closing(keep.attribution_db()) as db, db:
                    db.execute("UPDATE user_profiles SET theme_mode=? WHERE plex_id='7'", (mode,))
                response = self.client.get('/missing-page')
                self.assertEqual(response.status_code, 404)
                self.assertIn(f'data-theme="{mode}"', response.get_data(as_text=True))

    def test_missing_api_page_preserves_json_error_contracts(self):
        for path in ('/api/v1', '/api/v1/missing-page'):
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 404)
                self.assertEqual(response.mimetype, 'application/json')
                self.assertEqual(response.json, {'error': {'code': 'not_found', 'message': 'Not Found.'}})
                self.assertEqual(response.headers['Cache-Control'], 'no-store')
        for path in ('/api', '/api/missing-page'):
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 404)
                self.assertEqual(response.json, {'error': 'Page not found.'})

    def test_missing_page_requested_as_json_does_not_return_html(self):
        for response in (self.client.get('/missing-page', headers={'Accept': 'application/json'}),
                         self.client.post('/missing-page', json={'private': 'payload'})):
            self.assertEqual(response.status_code, 404)
            self.assertEqual(response.mimetype, 'application/json')
            self.assertEqual(response.json, {'error': 'Page not found.'})
            self.assertEqual(response.headers['Cache-Control'], 'no-store')

    def test_error_rendering_does_not_read_database_context(self):
        for status, handler in ((404, keep.missing_page), (500, keep.unexpected_error)):
            with self.subTest(status=status), keep.app.test_request_context('/missing-page'), \
                 patch.object(keep, 'current_profile', side_effect=sqlite3.OperationalError('private DB path')) as profile, \
                 patch.object(keep, 'attribution_db', side_effect=sqlite3.OperationalError('private DB path')) as db:
                response = handler(RuntimeError('private detail'))
                self.assertEqual(response.status_code, status)
                self.assertIn('data-theme="system"', response.get_data(as_text=True))
                self.assertNotIn('private', response.get_data(as_text=True))
                profile.assert_not_called()
                db.assert_not_called()

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
