import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

import test_names
from test_keep import keep


class HelpFaqTests(unittest.TestCase):
    def setUp(self):
        test_names.SettingsTests.setUp(self)
        for name in ('build_review_collections', 'build_kept_collections'):
            mock = patch.object(keep, name, return_value=[])
            mock.start()
            self.addCleanup(mock.stop)
        for name in ('get_collection_media', 'get_collection_exclusions'):
            mock = patch.object(keep, name, return_value={'items': []})
            mock.start()
            self.addCleanup(mock.stop)

    def seen(self, user='7'):
        with closing(keep.attribution_db()) as db:
            row = db.execute("""SELECT version FROM user_feature_acknowledgements
                WHERE user_id = ? AND feature_key = 'whats-new'""", (user,)).fetchone()
        return row['version'] if row else None

    def mark_seen(self, version=None, csrf='test-csrf'):
        return self.client.post('/api/announcements/seen',
                                json={'version': version or keep.ANNOUNCEMENT_VERSION},
                                headers={'X-CSRF-Token': csrf})

    def test_help_is_full_page_and_announcement_is_brief(self):
        with patch.object(keep, 'granted_library_keys', return_value={'radarr:1'}):
            page = self.client.get('/help')
            html = page.get_data(as_text=True)
            self.assertEqual(page.status_code, 200)
            self.assertIn('private, no-store', page.headers['Cache-Control'])
            self.assertIn('<title>FAQ · Keep</title>', html)
            self.assertIn('id="faq-criteria"', html)
            self.assertIn('/static/keep-faq.js?v=', html)
            self.assertEqual(html.count('/static/keep-interactions.js?v='), 1)
            self.assertEqual(html.count('id="back-to-top"'), 1)
            self.assertIn('id="faq-search"', html)
            self.assertIn('id="faq-search-empty"', html)
            self.assertIn('class="faq-topics"', html)
            self.assertIn('class="faq-popular"', html)
            self.assertIn('class="faq-question"', html)
            self.assertNotIn('class="faq-card"', html)
            self.assertIn('How much do I need to watch?', html)
            self.assertIn('If another rule still applies, it stays in Leaving.', html)
            self.assertNotIn('A watch that counts may change', html)
            self.assertIn('How does Leaving work?', html)
            self.assertIn('What does each connection do?', html)
            self.assertIn('Why is information missing when a connection passed its test?', html)
            self.assertIn('Why link Seerr accounts?', html)
            self.assertIn('<h2 id="api-heading">API access</h2>', html)
            self.assertIn('href="#api" data-faq-topic="api">API access', html)
            self.assertIn('What can Keep’s API do?', html)
            self.assertIn('Are API keys the same as connected services?', html)
            self.assertIn('Plex sign-in and connections such as Maintainerr and Seerr', html)
            self.assertIn('Your current Keep account permissions still apply', html)
            self.assertIn('choose 30, 90 or 365 days, or Never expires', html)
            self.assertIn('Only the Keep owner can manage API keys', html)
            self.assertIn('copy it to a protected credential store', html)
            self.assertIn('while keeping the audit history', html)
            self.assertIn('href="/settings/api-keys">Manage API keys', html)
            self.assertIn('href="/settings/api-reference">Go to API reference', html)
            self.assertIn('Removing a Keep removes protection only.', html)
            self.assertIn('Can I manage someone else’s Keep?', html)
            self.assertIn('What can I remove from Manage Library?', html)
            self.assertIn('<h2 id="keeps-heading">Keeps</h2>', html)
            self.assertIn('href="/">Go to Leaving', html)
            self.assertIn('href="/kept">Go to Kept', html)
            self.assertIn('href="/library">Go to Manage Library', html)
            self.assertIn('href="/preferences">Go to Preferences', html)
            for page in ('users', 'email', 'connections', 'activity'):
                self.assertIn(f'href="/settings/{page}">Go to {page.title()}', html)
            self.assertNotIn('Back to Leaving', html)
            self.assertIn('data-auto-open="false"', html)
            self.assertNotIn('id="welcome-dialog"', html)
            self.assertNotIn('How Keep works', html)
            announcement = self.client.get('/').get_data(as_text=True)
            self.assertIn('id="whats-new-dialog"', announcement)
            self.assertIn('data-auto-open="true"', announcement)
            self.assertIn('Explore FAQ', announcement)
            self.assertNotIn('Why titles appear in Leaving', announcement)
            self.assertIn('When Keep can verify playback and rule data', announcement)
            self.assertIn('when the required inputs are available', announcement)

    def test_faq_and_announcement_follow_current_permissions(self):
        with closing(keep.attribution_db()) as db, db:
            db.execute("INSERT INTO user_profiles(plex_id, plex_username, plex_checked_at) VALUES ('8', 'Basic', CURRENT_TIMESTAMP)")
        with self.client.session_transaction() as session:
            session['plex_user'] = {'id': 8, 'username': 'Basic'}
        basic = self.client.get('/help').get_data(as_text=True)
        self.assertNotIn('API access', basic)
        self.assertNotIn('id="api"', basic)
        self.assertNotIn('data-faq-topic="api"', basic)
        self.assertNotIn('What can Keep’s API do?', basic)
        self.assertNotIn('Are API keys the same as connected services?', basic)
        self.assertNotIn('href="/settings/api-keys"', basic)
        self.assertNotIn('href="/settings/api-reference"', basic)
        self.assertNotIn('Only the Keep owner can manage API keys', basic)
        self.assertNotIn('Plex sign-in', basic)
        self.assertNotIn('Maintainerr', basic)
        self.assertNotIn('Seerr', basic)
        self.assertNotIn('Radarr', basic)
        self.assertNotIn('Sonarr', basic)
        self.assertNotIn('Tautulli', basic)
        self.assertNotIn('Can I keep a title indefinitely?', basic)
        self.assertNotIn('Can I manage someone else’s Keep?', basic)
        self.assertNotIn('What can I remove from Manage Library?', basic)
        self.assertNotIn('Where do the rules and watched percentages come from?', basic)
        self.assertNotIn('What does each connection do?', basic)
        self.assertNotIn('href="/settings/connections">Go to Connections', basic)
        for service in ('Maintainerr', 'Radarr', 'Sonarr', 'Seerr', 'Tautulli'):
            self.assertNotIn(service, basic)
        for page in ('users', 'email', 'connections', 'activity'):
            self.assertNotIn(f'href="/settings/{page}">Go to', basic)
        self.assertNotIn('href="/library">Go to Manage Library', basic)
        self.assertIn('href="/preferences">Go to Preferences', basic)
        self.assertIn('<h2 id="keeps-heading">Keeps</h2>', basic)
        self.assertIn('<h2 id="library-account-heading">Library &amp; account</h2>', basic)
        self.assertNotIn('id="admin-connections"', basic)
        self.assertNotIn('Manage Library shows status and time left', self.client.get('/').get_data(as_text=True))
        with closing(keep.attribution_db()) as db, db:
            db.execute("UPDATE user_profiles SET can_keep_indefinitely=1, can_remove_any=1 WHERE plex_id='8'")
        expanded = self.client.get('/help').get_data(as_text=True)
        self.assertIn('Can I keep a title indefinitely?', expanded)
        self.assertIn('Can I manage someone else’s Keep?', expanded)
        with closing(keep.attribution_db()) as db, db:
            db.execute("UPDATE user_profiles SET can_delete_media=1 WHERE plex_id='8'")
        with patch.object(keep, 'granted_library_keys', return_value={'radarr:1'}):
            restricted = self.client.get('/help').get_data(as_text=True)
            self.assertIn('requested only by you', restricted)
            self.assertIn('What can I remove from Manage Library?', restricted)
            self.assertIn('Manage Library shows status and time left', self.client.get('/').get_data(as_text=True))

    def test_local_nonowner_cannot_see_owner_faq_topics_even_with_library_permissions(self):
        with closing(keep.attribution_db()) as db, db:
            db.execute("""INSERT INTO user_profiles
                (plex_id, auth_type, email, can_keep_indefinitely, can_remove_any, can_delete_media)
                VALUES ('local-test', 'local', 'local@example.com', 1, 1, 1)""")
        with self.client.session_transaction() as session:
            session['plex_user'] = {'id': 'local-test', 'auth_type': 'local', 'username': 'Local'}
        with patch.object(keep, 'granted_library_keys', return_value={'radarr:1'}):
            response = self.client.get('/help')
        self.assertEqual(response.status_code, 200)
        html = response.get_data(as_text=True)
        for owner_content in ('API access', 'id="api"', 'data-faq-topic="api"',
                              'id="admin-connections"', 'data-faq-topic="admin-connections"',
                              'href="/settings/api-keys"', 'href="/settings/api-reference"',
                              'How do I create or replace an API key?'):
            self.assertNotIn(owner_content, html)
        self.assertIn('What can I remove from Manage Library?', html)
        self.assertIn('Can I keep a title indefinitely?', html)
        self.assertIn('Can I manage someone else’s Keep?', html)

    def test_closing_or_got_it_records_one_meaningful_release_not_every_version(self):
        self.assertIsNone(self.seen())
        self.assertEqual(self.mark_seen().json['status'], 'seen')
        self.assertEqual(self.mark_seen().status_code, 200)
        self.assertEqual(self.seen(), keep.ANNOUNCEMENT_VERSION)
        self.assertIn('data-auto-open="false"', self.client.get('/kept').get_data(as_text=True))
        with patch.object(keep, 'APP_VERSION', '99.0.0'):
            self.assertIn('data-auto-open="false"', self.client.get('/').get_data(as_text=True))
        with closing(keep.attribution_db()) as db, db:
            db.execute("UPDATE user_profiles SET can_keep_indefinitely=1 WHERE plex_id='7'")
        self.assertIn('data-auto-open="false"', self.client.get('/').get_data(as_text=True))
        with patch.object(keep, 'ANNOUNCEMENT_VERSION', 'next-meaningful-release'):
            self.assertIn('data-auto-open="true"', self.client.get('/').get_data(as_text=True))
            self.assertEqual(self.mark_seen(version='old-release').status_code, 409)
        self.assertEqual(self.seen(), keep.ANNOUNCEMENT_VERSION)

    def test_csrf_and_invalid_versions_cannot_mark_seen(self):
        self.assertEqual(self.mark_seen(csrf='wrong').status_code, 403)
        for payload in (None, [], '1', {'version': 'unknown'}):
            response = self.client.post('/api/announcements/seen', json=payload,
                                        headers={'X-CSRF-Token': 'test-csrf'})
            self.assertEqual(response.status_code, 409)
        self.assertIsNone(self.seen())

    def test_seen_is_bound_to_current_user_including_local_accounts(self):
        with closing(keep.attribution_db()) as db, db:
            db.execute("INSERT INTO user_profiles(plex_id, auth_type, email) VALUES ('local-test', 'local', 'local@example.com')")
        with self.client.session_transaction() as session:
            session['plex_user'] = {'id': 'local-test', 'auth_type': 'local', 'username': 'Local'}
        self.assertEqual(self.mark_seen().status_code, 200)
        self.assertEqual(self.seen('local-test'), keep.ANNOUNCEMENT_VERSION)
        self.assertIsNone(self.seen('7'))

    def test_anonymous_users_cannot_get_faq_or_mark_seen(self):
        self.client = keep.app.test_client()
        self.assertEqual(self.client.get('/help').status_code, 302)
        self.assertEqual(self.mark_seen().status_code, 302)
        self.assertIsNone(self.seen())

    def test_release_version_still_appears_on_authentication_pages(self):
        self.assertEqual(keep.APP_VERSION, Path(keep.__file__).with_name('VERSION').read_text().strip())
        with keep.app.test_request_context('/'), patch.object(keep, 'APP_VERSION', '9.8.7'):
            for options in ({}, {'title': 'Access denied'}, {'forgot_password': True}):
                self.assertIn('Keep v9.8.7</footer>', keep.render_auth_page(**options))
            for options in ({}, {'complete': True}, {'profile': {'display_name': 'Test'}}):
                self.assertIn('Keep v9.8.7</footer>', keep.render_local_setup_page(**options).get_data(as_text=True))
