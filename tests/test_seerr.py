import json
import tempfile
import unittest
from unittest.mock import Mock, patch

import seerr
import test_keep
from test_keep import keep


def config(name):
    return {'SEERR_URL': 'https://seerr.example/base', 'SEERR_API_KEY': 'private-key'}[name]


def request(rid=1, user=10, kind='movie', seasons=None, status=2):
    return {'id': rid, 'type': kind, 'media': {'tmdbId': 100, 'tvdbId': 200},
            'requestedBy': {'id': user, 'email': 'private@example.test', 'plexToken': 'SECRET'},
            'status': status, 'seasons': seasons or []}


def snapshot():
    client = seerr.Client(config)
    with patch.object(client, 'test'), patch.object(client, 'pages', side_effect=[
            [{'id': 10, 'plexId': 7, 'username': 'Owner', 'email': 'private', 'plexToken': 'SECRET'},
             {'id': 11, 'username': 'Other'}],
            [request(), request(2, 10, 'tv', [{'seasonNumber': 1, 'status': 2}]),
             request(3, 11, 'tv', [{'seasonNumber': 2, 'status': 5}])]]):
        return client.snapshot()


class SeerrTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.store = seerr.Store(directory.name + '/cache.sqlite')
        self.profiles = [{'plex_id': '7', 'auth_type': 'plex', 'display_name': 'Owner K'},
                         {'plex_id': 'local:1', 'auth_type': 'local', 'display_name': 'Other K'}]

    def refresh(self):
        with patch.object(seerr.Client, 'snapshot', return_value=snapshot()):
            self.store.refresh(config)
        return self.store.read(config)

    def test_allowlist_never_persists_credentials_or_emails(self):
        data = self.refresh()
        self.assertNotIn('SECRET', json.dumps(data))
        self.assertNotIn('private', json.dumps(data))

    def test_movie_series_and_season_attribution(self):
        data = self.refresh()
        identities = self.store.identities(config, data, self.profiles)
        self.assertEqual(seerr.attribution(data, identities, 'movie', 100)['names'], ['Owner K'])
        self.assertEqual(seerr.attribution(data, identities, 'tv', 200)['state'], 'shared')
        self.assertEqual(seerr.attribution(data, identities, 'tv', 200, season=1)['names'], ['Owner K'])
        self.assertEqual(seerr.attribution(data, identities, 'tv', 200, season=2)['names'], ['Unlinked requester'])
        self.assertEqual(seerr.attribution(data, identities, 'tv', 200, season=3)['state'], 'unknown')
        self.assertEqual(seerr.attribution(data, identities, 'movie', 999)['state'], 'unknown')

    def test_pending_declined_failed_are_not_attributed(self):
        data = self.refresh()
        for status in (1, 3, 4):
            data['requests'][0]['status'] = status
            self.assertEqual(seerr.attribution(data, {}, 'movie', 100)['state'], 'unknown')

    def test_malformed_snapshot_rejected_and_email_labels_not_retained(self):
        client = seerr.Client(config)
        with patch.object(client, 'test'), patch.object(client, 'pages', side_effect=[
                [{'id':10,'username':'private@example.test'}], [request()]]):
            self.assertEqual(client.snapshot()['users'][0]['label'], 'Seerr user #10')
        for bad in ({}, {'id':1,'type':'tv'}, request(status=True), request(kind='audio')):
            with patch.object(client, 'test'), patch.object(client, 'pages', side_effect=[[], [bad]]):
                with self.assertRaises(ValueError):
                    client.snapshot()

    def test_failed_refresh_preserves_snapshot_but_marks_unavailable(self):
        previous = self.refresh()
        with patch.object(seerr.Client, 'snapshot', side_effect=ValueError('failed')):
            with self.assertRaises(ValueError):
                self.store.refresh(config)
        current = self.store.read(config)
        self.assertEqual(current['requests'], previous['requests'])
        self.assertEqual(current['state'], 'unavailable')
        with self.assertRaises(ValueError):
            self.store.link(config, 'local:1', 11, self.profiles)

    def test_scope_changes_and_expiry(self):
        self.refresh()
        self.assertEqual(self.store.read(lambda n: config(n) + 'changed')['state'], 'unavailable')
        with patch('seerr.time.time', return_value=9999999999):
            self.assertEqual(self.store.read(config)['state'], 'stale')

    def test_link_only_local_known_accounts_and_unlink(self):
        data = self.refresh()
        for target, user in [('7', 11), ('local:1', 10), ('local:1', 999)]:
            with self.assertRaises(ValueError):
                self.store.link(config, target, user, self.profiles)
        self.store.link(config, 'local:1', 11, self.profiles)
        identities = self.store.identities(config, data, self.profiles)
        self.assertEqual(identities[11]['display_name'], 'Other K')
        self.store.link(config, 'local:1', None, self.profiles)
        self.assertNotIn(11, self.store.identities(config, data, self.profiles))

    def test_no_name_matching_and_conflicting_ids_fail_closed(self):
        data = self.refresh()
        data['users'][1]['label'] = 'Other K'
        self.assertNotIn(11, self.store.identities(config, data, self.profiles))
        data['users'][1]['plex_id'] = '7'
        self.assertEqual(self.store.identities(config, data, self.profiles), {})

    def test_read_does_not_contact_seerr(self):
        self.refresh()
        with patch.object(seerr.requests, 'get') as get:
            self.store.read(config)
            get.assert_not_called()

    def test_permission_probe_rejects_partial_visibility(self):
        client = seerr.Client(config)
        for permissions in (0, 8, 16, 16384):
            with patch.object(client, 'get', return_value={'id': 1, 'permissions': permissions}):
                with self.assertRaises(ValueError):
                    client.test()
        for permissions in (2, 8 | 16, 8 | 16384):
            with patch.object(client, 'get', return_value={'id': 1, 'permissions': permissions}):
                client.test()

    def test_pagination_detects_duplicate_and_changed_count(self):
        client = seerr.Client(config)
        first = {'pageInfo': {'results': 2}, 'results': [{'id': 1}]}
        for second in (first, {'pageInfo': {'results': 3}, 'results': [{'id': 2}]},
                       {'pageInfo': {'results': 2}, 'results': []}):
            with patch.object(client, 'get', side_effect=[first, second]):
                with self.assertRaises(ValueError):
                    client.pages('request')
        with patch.object(client, 'get', side_effect=[first, {'pageInfo': {'results': 2}, 'results': [{'id': 2}]}]):
            self.assertEqual(len(client.pages('request')), 2)

    def test_supported_default_pagination_imports_all_four_pages(self):
        for endpoint, total in (('user', 9), ('request', 304)):
            def page(path, **params):
                self.assertEqual(path, endpoint)
                self.assertEqual(set(params), {'take', 'skip'})
                start = params['skip']
                return {'pageInfo': {'results': total},
                        'results': [{'id': i + 1} for i in range(start, min(start + params['take'], total))]}
            with patch.object(seerr.Client, 'get', side_effect=page) as get:
                rows = seerr.Client(config).pages(endpoint)
                self.assertEqual(len(rows), total)
                self.assertEqual(get.call_count, (total + 99) // 100)

    def test_transport_is_read_only_bounded_no_redirects(self):
        response = Mock(status_code=200)
        response.iter_content.return_value = [b'{"id":1}']
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        with patch.object(seerr.requests, 'get', return_value=response) as get:
            self.assertEqual(seerr.Client(config).get('auth/me'), {'id': 1})
            self.assertFalse(get.call_args.kwargs['allow_redirects'])
            self.assertLessEqual(get.call_args.kwargs['timeout'], 10)
            self.assertEqual(get.call_args.args[0], 'https://seerr.example/base/api/v1/auth/me')
        response.status_code = 302
        with patch.object(seerr.requests, 'get', return_value=response), self.assertRaises(ValueError):
            seerr.Client(config).get('auth/me')


class SeerrRouteTests(unittest.TestCase):
    setUp = test_keep.KeepTests.setUp

    def test_batch_form_action_survives_disabled_submit_button(self):
        response = self.client.get('/settings/connections')
        self.assertIn(b'name="action" value="save-seerr-links"', response.data)
        with patch.object(seerr.Store, 'save_links') as save:
            response = self.client.post('/settings/connections', data={
                'action': 'save-seerr-links', 'csrf_token': 'test-csrf',
                'seerr_scope': 'scope', 'seerr-link-local:1': '11'})
            self.assertEqual(response.status_code, 200)
            self.assertEqual(save.call_args.args[1], {'local:1': 11})
            self.assertIn(b'Account links saved', response.data)

    def test_owner_and_csrf_required_for_refresh_and_link(self):
        with patch.object(seerr.Store, 'refresh') as refresh, patch.object(seerr.Store, 'link') as link:
            for action in ('refresh-seerr', 'link-seerr', 'save-seerr-links'):
                self.assertEqual(self.client.post('/settings/connections', data={'action': action}).status_code, 403)
                with patch.object(keep, 'is_owner', return_value=False):
                    self.assertEqual(self.client.post('/settings/connections', data={'action': action, 'csrf_token': 'test-csrf'}).status_code, 403)
            refresh.assert_not_called()
            link.assert_not_called()

    def test_test_and_refresh_are_separate_and_errors_sanitized(self):
        with patch.dict('os.environ', SEERR_URL='https://seerr.example', SEERR_API_KEY='key'), patch.object(seerr.Client, 'test') as test, patch.object(seerr.Store, 'refresh') as refresh:
            response = self.client.post('/settings/connections', data={'action': 'seerr', 'csrf_token': 'test-csrf'})
            self.assertEqual(response.status_code, 200)
            test.assert_called_once()
            refresh.assert_not_called()
        with patch.object(seerr.Store, 'refresh', side_effect=ValueError('private-api-key')):
            response = self.client.post('/settings/connections', data={'action': 'refresh-seerr', 'csrf_token': 'test-csrf'})
            self.assertNotIn(b'private-api-key', response.data)
            self.assertIn(b'Seerr request history could not be imported', response.data)

    def test_refresh_http_error_is_actionable_and_first_import_not_unmatched(self):
        with patch.object(seerr.Store, 'refresh', side_effect=seerr.ResponseError(400)):
            response = self.client.post('/settings/connections', data={'action': 'refresh-seerr', 'csrf_token': 'test-csrf'})
            self.assertIn(b'Seerr rejected the request (HTTP 400)', response.data)
        response = self.client.get('/settings/connections')
        self.assertIn(b'Account matches will appear after the first successful refresh', response.data)
        self.assertNotIn(b'No unambiguous Plex ID match', response.data)

    def test_settings_secret_masked_and_no_deletion_permissions_changed(self):
        from contextlib import closing
        with closing(keep.attribution_db()) as db:
            before = list(db.execute('SELECT plex_id,can_remove_any,can_delete_media FROM user_profiles'))
            before = [tuple(r) for r in before]
        with patch.dict('os.environ', SEERR_API_KEY='private-seerr-key', SEERR_URL='https://seerr.example'):
            response = self.client.get('/settings/connections')
            self.assertIn(b'Seerr API key', response.data)
            self.assertNotIn(b'private-seerr-key', response.data)
        with closing(keep.attribution_db()) as db:
            self.assertEqual(before, [tuple(r) for r in db.execute('SELECT plex_id,can_remove_any,can_delete_media FROM user_profiles')])

    def test_library_cards_only_use_cached_permission_hints_not_requester_labels(self):
        data = {**snapshot(), 'state':'current','updated':1}
        inventory = [{'id':1,'title':'Test','tmdbId':100,'hasFile':True,'rootFolderPath':'/movies'}]
        libraries = [{'library_key':'radarr:1','service':'radarr','name':'Movies','path':'/movies'}]
        with keep.app.test_request_context('/library'):
            with patch.object(keep, 'granted_library_keys', return_value={'radarr:1'}), \
                    patch.object(keep, 'media_libraries', return_value=libraries), \
                    patch.object(keep.media_services, 'list_media', return_value=inventory), \
                    patch.object(keep, 'library_artwork_cache'), \
                    patch.dict('os.environ', SEERR_URL='https://seerr.example', SEERR_API_KEY='test'), \
                    patch.object(seerr.Store, 'read', return_value=data) as read, \
                    patch.object(seerr.Client, 'get') as upstream:
                with patch.object(keep, 'user_capabilities', return_value={'delete_any': True, 'delete_media': True}):
                    sections = keep.build_library_sections()
                    self.assertNotIn('requester', sections[0]['items'][0])
                    self.assertNotIn('season_requesters', sections[0]['items'][0])
                    read.assert_not_called()
                with patch.object(keep, 'user_capabilities', return_value={'delete_any': False, 'delete_media': True}):
                    sections = keep.build_library_sections()
                    self.assertEqual(sections[0]['items'], [])
                    read.assert_called_once()
                upstream.assert_not_called()
