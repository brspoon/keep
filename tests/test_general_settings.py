"""Owner-only duration settings and preservation of existing Keep schedules."""
from contextlib import closing
from html.parser import HTMLParser
from unittest import TestCase
from unittest.mock import patch

import test_keep

keep = test_keep.keep


class Inputs(HTMLParser):
    def __init__(self, body):
        super().__init__()
        self.fields = {}
        self.feed(body)

    def handle_starttag(self, tag, attributes):
        attributes = dict(attributes)
        if tag == 'input' and attributes.get('name'):
            self.fields[attributes['name']] = attributes


class GeneralSettingsTests(TestCase):
    def setUp(self):
        test_keep.KeepTests.setUp(self)

    def save(self, days, csrf='test-csrf', client=None):
        data = {'keep_duration_days': days}
        if csrf is not None:
            data['csrf_token'] = csrf
        return (client or self.client).post('/settings/general', data=data)

    def stored(self):
        with closing(keep.attribution_db()) as db:
            rows = [tuple(row) for row in db.execute(
                'SELECT id, keep_duration_days, typeof(keep_duration_days) FROM general_settings')]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][0], 1)
        self.assertEqual(rows[0][2], 'integer')
        return rows[0][1]

    def test_owner_can_read_default_and_form_bounds_without_changing_settings(self):
        with patch.object(keep.requests, 'post') as post:
            response = self.client.get('/settings/general')
        self.assertEqual(response.status_code, 200)
        fields = Inputs(response.get_data(as_text=True)).fields
        self.assertEqual(fields['keep_duration_days']['value'], '30')
        self.assertEqual(fields['keep_duration_days']['min'], '1')
        self.assertEqual(fields['keep_duration_days']['max'], '365')
        self.assertEqual(fields['csrf_token']['value'], 'test-csrf')
        self.assertIn(f'/static/keep-toast.js?v={keep.APP_VERSION}', response.get_data(as_text=True))
        self.assertEqual(self.stored(), 30)
        post.assert_not_called()
        self.delete.assert_not_called()

    def test_save_persists_integer_setting_across_clients_and_database_connections(self):
        for days in ('1', '45', '365'):
            with self.subTest(days=days), patch.object(keep.requests, 'post') as post:
                response = self.save(days)
                self.assertIn(response.status_code, (302, 303))
                self.assertEqual(response.headers['Location'], '/settings/general')
                self.assertEqual(self.stored(), int(days))
                saved_page = self.client.get('/settings/general').get_data(as_text=True)
                self.assertIn('<p id="settings-saved-notice" hidden>Keep duration saved.</p>', saved_page)
                self.assertNotIn('class="general-feedback"', saved_page)
                self.assertEqual(keep.temporary_keep_days(), int(days))
                other = keep.app.test_client()
                with other.session_transaction() as session:
                    session['plex_user'] = {'id': 7, 'username': 'Owner'}
                page = other.get('/settings/general')
                self.assertEqual(page.status_code, 200)
                self.assertEqual(Inputs(page.get_data(as_text=True)).fields['keep_duration_days']['value'], days)
                post.assert_not_called()
        self.delete.assert_not_called()

    def test_schema_initialization_sets_default_once_and_preserves_saved_duration(self):
        with closing(keep.attribution_db()) as db, db:
            db.execute('DELETE FROM general_settings')
        with patch.object(keep.api_v1, 'ApiV1'):
            keep._initialize_application_schema()
        self.assertEqual(self.stored(), 30)
        test_keep.set_keep_duration_days(45)
        with patch.object(keep.api_v1, 'ApiV1'):
            keep._initialize_application_schema()
        self.assertEqual(self.stored(), 45)
        self.assertEqual(keep.temporary_keep_days(), 45)

    def test_invalid_values_and_missing_field_cannot_change_saved_duration(self):
        test_keep.set_keep_duration_days(45)
        for value in ('', '0', '366', '-1', '1.5', '1e2', 'thirty', '30 days', 'true'):
            with self.subTest(value=value):
                self.assertEqual(self.save(value).status_code, 400)
                self.assertEqual(self.stored(), 45)
        response = self.client.post('/settings/general', data={'csrf_token': 'test-csrf'})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.stored(), 45)

    def test_save_requires_form_csrf_and_leaves_setting_unchanged(self):
        for csrf in (None, '', 'incorrect'):
            with self.subTest(csrf=csrf):
                self.assertEqual(self.save('90', csrf=csrf).status_code, 403)
                self.assertEqual(self.stored(), 30)
        response = self.client.post('/settings/general', data={'keep_duration_days': '90'},
                                    headers={'X-CSRF-Token': 'test-csrf'})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.stored(), 30)

    def test_keep_manager_still_cannot_read_or_save_owner_settings(self):
        with closing(keep.attribution_db()) as db, db:
            db.execute("""INSERT INTO user_profiles
                (plex_id, plex_username, can_remove_any, can_keep_indefinitely, plex_checked_at)
                VALUES ('8', 'Manager', 1, 1, CURRENT_TIMESTAMP)""")
        with self.client.session_transaction() as session:
            session['plex_user'] = {'id': 8, 'username': 'Manager'}
        self.assertEqual(self.client.get('/settings/general').status_code, 403)
        self.assertEqual(self.save('90').status_code, 403)
        self.assertEqual(self.stored(), 30)

    def test_signed_out_users_must_sign_in_before_reading_or_saving(self):
        with self.client.session_transaction() as session:
            session.clear()
        for response in (self.client.get('/settings/general'), self.save('90')):
            self.assertEqual(response.status_code, 302)
            self.assertIn('/login', response.headers['Location'])
        self.assertEqual(self.stored(), 30)

    def test_reducing_and_lengthening_duration_preserves_all_existing_schedule_dates(self):
        with closing(keep.attribution_db()) as db, db:
            db.executemany("""INSERT INTO keep_schedules
                (collection_id, media_id, expires_at, extension_available_at, created_at)
                VALUES (?, ?, ?, ?, ?)""", [
                (self.cid, '42', '2026-12-01 12:00:00', '2026-11-01 12:00:00', '2026-10-01 12:00:00'),
                (self.cid, '43', '2026-09-01 12:00:00', None, '2026-08-01 12:00:00'),
                (self.cid, '44', None, None, '2026-10-01 12:00:00'),
            ])
            before = [tuple(row) for row in db.execute('SELECT * FROM keep_schedules ORDER BY media_id')]
        for days in ('7', '365'):
            with self.subTest(days=days):
                self.assertIn(self.save(days).status_code, (302, 303))
                self.assertEqual(self.stored(), int(days))
                with closing(keep.attribution_db()) as db:
                    after = [tuple(row) for row in db.execute('SELECT * FROM keep_schedules ORDER BY media_id')]
                self.assertEqual(after, before)
