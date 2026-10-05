import re
import tempfile
import unittest
from contextlib import closing
from html.parser import HTMLParser
from unittest.mock import Mock, patch
from onboarding import Onboarding, digest
import test_keep
keep = test_keep.keep


class BrandAssets(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self.images = []
        self.scripts = []

    def handle_starttag(self, tag, attrs):
        if tag == 'link':
            self.links.append(dict(attrs))
        elif tag == 'img':
            self.images.append(dict(attrs))
        elif tag == 'script':
            self.scripts.append(dict(attrs))


class SharedNavigationTests(unittest.TestCase):
    def setUp(self):
        test_keep.KeepTests.setUp(self)

    def assert_refresh_assets(self, page, refresh_url=None):
        assets = BrandAssets()
        assets.feed(page)
        scripts = [script for script in assets.scripts
                   if 'keep-pull-refresh.js' in script.get('src', '')]
        self.assertEqual(len(scripts), 1)
        self.assertEqual(scripts[0]['src'], f'/static/keep-pull-refresh.js?v={keep.APP_VERSION}')
        self.assertIn('defer', scripts[0])
        self.assertEqual(scripts[0].get('data-refresh-url'), refresh_url)
        self.assertEqual([link['href'] for link in assets.links
                          if 'keep-pull-refresh.css' in link.get('href', '')],
                         [f'/static/keep-pull-refresh.css?v={keep.APP_VERSION}'])
        self.assertNotIn('id="pull-refresh"', page)

    def assert_menu_groups(self, page, *, library=False, owner=False):
        menu = re.search(r'<div class="user-links".*?</div>', page, re.S).group()
        self.assertEqual(menu.count('<hr class="account-menu-divider">'), 1)
        browse, account = menu.split('<hr class="account-menu-divider">')
        labels = lambda section: re.findall(r'>([^<>]+)</a>', section)
        self.assertEqual(labels(browse), ['Leaving', 'Kept'] + (['Manage Library'] if library else []))
        self.assertEqual(labels(account), ['Preferences'] + (['Admin'] if owner else []) + ['FAQ', 'Logout'])
        self.assertNotIn('/settings/api-', menu)
        self.assertIn('id="preferences-open"', account)
        self.assertIn('aria-haspopup="dialog" aria-controls="preferences-dialog">Preferences', account)

    def test_menu_and_announcement_are_shared(self):
        with patch.object(keep, 'get_collection_media', return_value={'items': []}), \
             patch.object(keep, 'get_collection_exclusions', return_value={'items': []}), \
             patch.object(keep, 'get_collection_delete_after_days', return_value=30), \
             patch.object(keep, 'build_library_sections', return_value=[]), \
             patch.object(keep, 'granted_library_keys', return_value=['radarr:1']):
            for path in ('/', '/kept', '/library', '/help', '/settings/users', '/settings/email',
                         '/settings/connections', '/settings/activity', '/settings/jobs',
                         '/settings/api-keys', '/settings/api-reference', '/preferences'):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 200, path)
                page = response.get_data(as_text=True)
                self.assertEqual(page.count('id="account-menu"'), 1, path)
                if path not in ('/settings/jobs', '/settings/api-keys', '/settings/api-reference'):
                    self.assertEqual(page.count('id="whats-new-dialog"'), 1, path)
                self.assertEqual(page.count('id="preferences-dialog"'), 1, path)
                self.assertIn('aria-haspopup="dialog" aria-controls="preferences-dialog">Preferences', page)
                self.assertEqual(page.count('/static/keep-preferences.js?'), 1, path)
                with self.subTest(path=path):
                    self.assert_menu_groups(page, library=True, owner=True)
                    self.assert_refresh_assets(page)
                    assets = BrandAssets()
                    assets.feed(page)
                    for attributes, href in (
                        ({'rel': 'icon', 'type': 'image/svg+xml'}, f'/static/keep-icon.svg?v={keep.APP_VERSION}'),
                        ({'rel': 'icon', 'type': 'image/png', 'sizes': '32x32'}, f'/static/favicon-32.png?v={keep.APP_VERSION}'),
                        ({'rel': 'apple-touch-icon', 'sizes': '180x180'}, f'/static/apple-touch-icon.png?v={keep.APP_VERSION}'),
                        ({'rel': 'manifest'}, '/static/site.webmanifest'),
                    ):
                        links = [link.get('href') for link in assets.links
                                 if all(link.get(key) == value for key, value in attributes.items())]
                        self.assertEqual(links, [href])
                    logos = [image['src'] for image in assets.images
                             if image.get('src', '').startswith('/static/keep-icon.svg')]
                    self.assertTrue(logos)
                    self.assertEqual(set(logos), {f'/static/keep-icon.svg?v={keep.APP_VERSION}'})

    def test_public_and_setup_views_include_mobile_refresh(self):
        missing = self.client.get('/missing-preview-page')
        self.assertEqual(missing.status_code, 404)
        self.assert_refresh_assets(missing.get_data(as_text=True))
        with self.client.session_transaction() as session:
            session.clear()
        for path in ('/login', '/auth/plex', '/auth/local/forgot',
                     '/auth/local/setup/invalid-preview-token'):
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertNotEqual(response.status_code, 500)
                self.assert_refresh_assets(response.get_data(as_text=True))
        with keep.app.test_request_context('/setup'):
            self.assert_refresh_assets(keep.render_template('setup.html', mode='bootstrap'))
            self.assert_refresh_assets(keep.render_template('private_setup_link.html',
                link='http://keep.example/auth/local/setup/synthetic-token'))

    def test_post_rendered_views_refresh_with_get_without_repeating_the_action(self):
        cases = (
            ('/preferences?source=mobile', {'theme_mode': 'invalid'}, 200, '/preferences?source=mobile'),
            ('/settings/recipients', {'action': 'add', 'email': 'invalid'}, 400, '/settings/email'),
            ('/auth/local', {'email': 'absent@example.com', 'password': 'synthetic-wrong-password'}, 401, '/'),
        )
        for path, data, status, refresh_url in cases:
            with self.subTest(path=path):
                response = self.client.post(path, data={'csrf_token': 'test-csrf', **data})
                self.assertEqual(response.status_code, status)
                self.assert_refresh_assets(response.get_data(as_text=True), refresh_url)

    def test_nonowner_menu_uses_current_local_and_plex_permissions(self):
        with closing(keep.attribution_db()) as db, db:
            db.execute("""INSERT INTO user_profiles(plex_id, plex_username, auth_type, plex_checked_at)
                VALUES ('8', 'Plex Friend', 'plex', CURRENT_TIMESTAMP),
                       ('local-test', 'Local Friend', 'local', CURRENT_TIMESTAMP)""")
        for user_id, auth_type in (('8', 'plex'), ('local-test', 'local')):
            with self.client.session_transaction() as session:
                session['plex_user'] = {'id': user_id, 'auth_type': auth_type, 'username': 'Friend'}
            for can_delete, grants in ((False, ['radarr:1']), (True, []), (True, ['radarr:1'])):
                with self.subTest(auth_type=auth_type, can_delete=can_delete, grants=grants):
                    with closing(keep.attribution_db()) as db, db:
                        db.execute('UPDATE user_profiles SET can_delete_media=? WHERE plex_id=?',
                                   (int(can_delete), user_id))
                    with patch.object(keep, 'granted_library_keys', return_value=grants):
                        response = self.client.get('/help')
                    self.assertEqual(response.status_code, 200)
                    self.assert_menu_groups(response.get_data(as_text=True), library=bool(can_delete and grants))

    def test_creation_forms_precede_lists(self):
        for path, creation, listing in (('/settings/users', 'Add local user', '<article class="user-card">'),
                                        ('/settings/email', 'Add email recipient', '<h2>Email recipients</h2>')):
            page = self.client.get(path).get_data(as_text=True)
            self.assertLess(page.index(creation), page.index(listing))
            self.assertIn('class="panel creation-panel"', page)
            self.assertIn('class="panel creation-panel" hidden', page)
            self.assertEqual(page.count('class="admin-toolbar"'), 1)
            self.assertEqual(page.count('class="admin-add-button"'), 1)
            self.assertIn('type="search" placeholder="Search ', page)
            self.assertIn('class="admin-search-clear" aria-label="Clear search" hidden', page)
        users = self.client.get('/settings/users').get_data(as_text=True)
        self.assertNotIn('<details class="user-card">', users)
        self.assertIn('data-user-toggle aria-expanded="false"', users)
        self.assertIn('<article class="user-card">', users)
        self.assertIn('class="panel admin-card-list"', users)
        self.assertIn('class="admin-card-header"', users)
        self.assertNotIn('class="user-summary"', users)

    def test_connections_and_activity_render_final_controls_without_javascript(self):
        page = self.client.get('/settings/connections').get_data(as_text=True)
        for service in ('plex', 'radarr', 'sonarr', 'maintainerr'):
            self.assertIn(f'/static/service-icons/{service}.svg', page)
        page = self.client.get('/settings/activity').get_data(as_text=True)
        self.assertIn('class="activity-mobile-filter"', page)

    def test_connections_setup_return_is_only_available_to_pending_owner(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Onboarding(directory + '/onboarding.sqlite3')
            store.claim(digest(store.issue()), '7')
            with patch.object(keep, 'onboarding', store):
                response = self.client.get('/settings/connections')
                self.assertEqual(response.status_code, 200)
                self.assertRegex(response.get_data(as_text=True),
                                 r'<a\b[^>]*href="/setup"[^>]*>\s*Return to Setup\s*</a>')
                self.assertEqual(self.client.get('/setup').status_code, 200)

                with closing(keep.attribution_db()) as db, db:
                    db.execute("""INSERT INTO user_profiles
                        (plex_id, plex_username, auth_type, plex_checked_at)
                        VALUES ('8', 'Plex Friend', 'plex', CURRENT_TIMESTAMP)""")
                with self.client.session_transaction() as session:
                    session['plex_user'] = {'id': '8', 'username': 'Friend', 'auth_type': 'plex'}
                response = self.client.get('/settings/connections')
                self.assertEqual(response.status_code, 403)
                self.assertNotIn('Return to Setup', response.get_data(as_text=True))
                viewer_page = self.client.get('/help')
                self.assertEqual(viewer_page.status_code, 200)
                self.assertNotIn('Return to Setup', viewer_page.get_data(as_text=True))

                with self.client.session_transaction() as session:
                    session['plex_user'] = {'id': '7', 'username': 'Owner', 'auth_type': 'plex'}
                store.finish()
                response = self.client.get('/settings/connections')
                self.assertEqual(response.status_code, 200)
                self.assertNotIn('Return to Setup', response.get_data(as_text=True))
                self.assertEqual(self.client.get('/setup').location, '/settings/connections')

    def test_library_order_follows_configured_collections_and_normalizes_tv_names(self):
        libraries = [{'library_key':str(i),'service':'radarr','name':name}
                     for i, name in enumerate(('Kids TV Shows','Kids Movies','TV Shows','Movies','Other'))]
        with keep.app.test_request_context('/'), \
             patch.object(keep, 'granted_library_keys', return_value=[str(i) for i in range(5)]), \
             patch.object(keep, 'media_libraries', return_value=libraries), \
             patch.object(keep.media_services, 'list_media', return_value=[]), \
             patch.object(keep, 'get_collections', return_value={1:'Movies Leaving Plex Soon',2:'Shows Leaving Plex Soon',3:'Kids Movies Leaving Plex Soon',4:'Kids Shows Leaving Plex Soon'}):
            self.assertEqual([s['name'] for s in keep.build_library_sections()],
                             ['Movies','TV Shows','Kids Movies','Kids TV Shows','Other'])

    def test_preferences_fragment_is_not_a_full_page_and_has_distinct_ids(self):
        response = self.client.get('/preferences?fragment=1')
        page = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertNotIn('app-header', page)
        self.assertNotIn('keep-pull-refresh', page)
        self.assertIn('id="dialog-receive-email"', page)
        self.assertIn('id="dialog-email-topics"', page)

    def test_collection_reads_reused_only_within_one_request(self):
        response = Mock()
        response.json.side_effect = lambda: {'items': []}
        with patch.object(keep.requests, 'get', return_value=response) as get:
            for _ in range(2):
                with keep.app.test_request_context('/'):
                    keep.get_collection_media('1')
                    keep.get_collection_media('1')
                    keep.get_collection_exclusions('1')
            self.assertEqual(get.call_count, 4)

    def test_kept_html_does_not_wait_for_poster_requests(self):
        item = {'id': 91, 'mediaServerId': 42, 'mediaData': {'title': 'Example', 'year': 2026}}
        with patch.object(keep, 'get_collection_exclusions', return_value={'items': [item]}), \
             patch.object(keep, 'get_collection_media', return_value={'items': []}), \
             patch.object(keep, 'get_kept_item_poster') as poster:
            response = self.client.get('/kept')
            self.assertEqual(response.status_code, 200)
            self.assertIn('/kept/artwork/42', response.get_data(as_text=True))
            poster.assert_not_called()
        with patch.object(keep, 'get_kept_item_poster', return_value='https://image.example/poster.jpg'):
            response = self.client.get('/kept/artwork/42')
            self.assertEqual(response.status_code, 302)
            self.assertEqual(response.location, 'https://image.example/poster.jpg')
        with patch.object(keep, 'get_kept_item_poster', return_value=None):
            self.assertEqual(self.client.get('/kept/artwork/42').status_code, 404)
