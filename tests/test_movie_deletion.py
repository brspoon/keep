"""Synthetic permission/transport tests. Never delete real media."""
import unittest
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from contextlib import closing
from unittest.mock import patch

import seerr
import test_keep
from test_keep import keep


def history(user=10, status=2):
    return {'state': 'current', 'users': [{'id': 10, 'plex_id': '8', 'label': 'Private label'}],
            'requests': [{'id': 1, 'kind': 'movie', 'tmdb': 100, 'tvdb': None,
                          'user': user, 'status': status, 'is4k': False, 'seasons': []}]}


class MovieDeletionPolicyTests(unittest.TestCase):
    def allowed(self, data, tmdb=100, identities=None):
        identities = {10: {'plex_id': '8'}} if identities is None else identities
        return seerr.movie_deletion_access(data, identities, tmdb, '8')[0]

    def test_exclusive_approved_and_completed_only(self):
        for status in (1, 2, 3, 4, 5):
            self.assertEqual(self.allowed(history(status=status)), status in (2, 5))
        self.assertFalse(self.allowed(history(user=11)))

    def test_every_other_requester_blocks_even_pending_failed_and_4k(self):
        for status in (1, 2, 3, 4, 5):
            data = history()
            data['requests'].append({**data['requests'][0], 'id': 2, 'user': 11,
                                     'status': status, 'is4k': True})
            self.assertFalse(self.allowed(data))
        data['requests'][1]['user'] = 10
        self.assertTrue(self.allowed(data))

    def test_unknown_stale_unavailable_invalid_and_unlinked_deny(self):
        for state in ('stale', 'unavailable', None):
            self.assertFalse(self.allowed({**history(), 'state': state}))
        for tmdb in (None, 0, -1, True, '100', 999):
            self.assertFalse(self.allowed(history(), tmdb=tmdb))
        self.assertFalse(self.allowed({**history(), 'requests': []}))
        self.assertFalse(self.allowed(history(), identities={}))
        self.assertFalse(self.allowed(history(), identities={10: {'plex_id': '8'}, 11: {'plex_id': '8'}}))

    def test_tv_request_never_authorizes_movie(self):
        data = history()
        data['requests'][0]['kind'] = 'tv'
        self.assertFalse(self.allowed(data))

    def test_upgrade_does_not_grant_override_or_remove_library_grants(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            env = {**os.environ, 'KEEP_DB_PATH': directory + '/upgrade.sqlite3'}
            before = """
import app
with app.attribution_db() as db:
 db.execute("INSERT INTO user_profiles(plex_id,can_delete_media) VALUES ('8',1)")
 db.execute("INSERT INTO user_library_permissions VALUES ('8','radarr:4')")
 db.execute('ALTER TABLE user_profiles DROP COLUMN can_delete_any')
"""
            after = """
import app
with app.attribution_db() as db:
 assert tuple(db.execute("SELECT can_delete_media,can_delete_any FROM user_profiles WHERE plex_id='8'").fetchone())==(1,0)
 assert db.execute("SELECT library_key FROM user_library_permissions WHERE user_id='8'").fetchone()[0]=='radarr:4'
assert app.user_capabilities({'id':'7'})['delete_any']
"""
            for code in (before, after):
                result = subprocess.run([sys.executable, '-c', code], cwd=root, env=env,
                                        capture_output=True, text=True, timeout=20)
                self.assertEqual(result.returncode, 0, result.stderr)


class DeletionKeepInventoryTests(unittest.TestCase):
    def setUp(self):
        test_keep.KeepTests.setUp(self)

    def test_deselected_scheduled_and_legacy_keeps_still_protect(self):
        for table in ('keep_schedules', 'keep_attribution'):
            with self.subTest(table=table):
                with closing(keep.attribution_db()) as db, db:
                    db.execute('DELETE FROM keep_schedules')
                    db.execute('DELETE FROM keep_attribution')
                    if table == 'keep_schedules':
                        db.execute("INSERT INTO keep_schedules(collection_id,media_id) VALUES ('9','42')")
                    else:
                        db.execute("INSERT INTO keep_attribution(collection_id,media_id,user_id,username) VALUES ('9','42','8','Keeper')")
                with patch.object(keep, 'get_collections', return_value={}), \
                     patch.object(keep, 'deletion_keep_inventory', return_value=[
                         {'mediaServerId': '42', 'mediaData': {'tmdbId': 999}}]) as inventory:
                    self.assertTrue(keep.media_matches_active_keep('radarr', {'tmdbId': 999}))
                    inventory.assert_called_once()
                    self.assertEqual(inventory.call_args.args[0], 9)

    def test_deselected_keep_inventory_failure_blocks_verification(self):
        with closing(keep.attribution_db()) as db, db:
            db.execute("INSERT INTO keep_schedules(collection_id,media_id) VALUES ('9','42')")
        with patch.object(keep, 'get_collections', return_value={}), \
             patch.object(keep, 'deletion_keep_inventory', side_effect=keep.requests.ConnectionError):
            with self.assertRaises(keep.requests.ConnectionError):
                keep.media_matches_active_keep('radarr', {'tmdbId': 999})

    def test_protection_checks_beyond_first_page(self):
        from unittest.mock import Mock
        first = [{'mediaServerId': i+1, 'mediaData': {'title': 'Other', 'tmdbId': i+1}} for i in range(100)]
        last = [{'mediaServerId': 999, 'mediaData': {'title': 'Protected', 'tmdbId': 999}}]
        with patch.object(keep, 'get_collections', return_value={1:'Movies'}), \
             patch.object(keep.requests, 'get', side_effect=[Mock(status_code=200,json=lambda:{'items':first}),
                                                            Mock(status_code=200,json=lambda:{'items':last})]) as fetch:
            self.assertTrue(keep.media_matches_active_keep('radarr', {'tmdbId':999,'title':'Protected'}))
            self.assertEqual(fetch.call_count, 2)
            self.assertIn('/content/2', fetch.call_args.args[0])

    def test_incomplete_or_repeated_inventory_and_timeout_fail_closed(self):
        from unittest.mock import Mock
        for payload in ({}, {'items':None}, {'items':[{}]}, {'items':[{'mediaData':{}}]}):
            with patch.object(keep.requests, 'get', return_value=Mock(status_code=200,json=lambda:payload)):
                with self.assertRaises(ValueError):
                    list(keep.deletion_keep_inventory(1,time.monotonic()+20))
        rows = [{'mediaServerId':i+1,'mediaData':{}} for i in range(100)]
        with patch.object(keep.requests, 'get', return_value=Mock(status_code=200,json=lambda:{'items':rows})):
            with self.assertRaises(ValueError):
                list(keep.deletion_keep_inventory(1,time.monotonic()+20))
        with patch.object(keep.requests, 'get') as fetch:
            with self.assertRaises(ValueError):
                list(keep.deletion_keep_inventory(1,time.monotonic()-1))
            fetch.assert_not_called()


class MovieDeletionRouteTests(unittest.TestCase):
    def setUp(self):
        test_keep.KeepTests.setUp(self)
        self.settings = patch.dict('os.environ', SEERR_URL='https://seerr.example', SEERR_API_KEY='test')
        self.settings.start()
        self.addCleanup(self.settings.stop)
        with closing(keep.attribution_db()) as db, db:
            db.execute("INSERT INTO user_profiles(plex_id,can_delete_media,plex_checked_at) VALUES ('8',1,CURRENT_TIMESTAMP)")
            db.execute("INSERT INTO media_libraries(library_key,service,external_id,name,path) VALUES ('radarr:4','radarr','4','Movies','/movies')")
            db.execute("INSERT INTO media_libraries(library_key,service,external_id,name,path) VALUES ('sonarr:5','sonarr','5','Shows','/shows')")
            db.execute("INSERT INTO user_library_permissions VALUES ('8','radarr:4')")
            db.execute("INSERT INTO user_library_permissions VALUES ('8','sonarr:5')")
        with self.client.session_transaction() as session:
            session['plex_user'] = {'id': 8, 'username': 'User', 'session_version': 0}
        self.item = {'id': 22, 'title': 'A movie', 'tmdbId': 100, 'hasFile': True,
                     'rootFolderPath': '/movies', 'path': '/movies/A movie'}
        self.live = self.mock(seerr.Client, 'snapshot', return_value=history())
        self.fetch = self.mock(keep.media_services, 'get_media', return_value=self.item)
        self.remove = self.mock(keep.media_services, 'delete_media')
        self.real_keep_check = keep.media_matches_active_keep
        self.kept = self.mock(keep, 'media_matches_active_keep', return_value=False)

    def mock(self, obj, name, **kwargs):
        p = patch.object(obj, name, **kwargs)
        self.addCleanup(p.stop)
        return p.start()

    def post(self, **extra):
        return self.client.post('/api/library/delete', json={
            'service': 'radarr', 'itemId': 22, 'libraryKey': 'radarr:4', **extra},
            headers={'X-CSRF-Token': 'test-csrf'})

    def update(self, sql):
        with closing(keep.attribution_db()) as db, db:
            db.execute(sql)

    def test_own_movie_uses_live_data_not_cache_or_payload(self):
        queued = self.mock(keep, 'queue_seerr_availability')
        cached = self.mock(seerr.Store, 'read', side_effect=AssertionError('Never authorize from cache'))
        response = self.post(requesterId=999, canDeleteAny=True)
        self.assertEqual(response.status_code, 200)
        self.live.assert_called_once()
        cached.assert_not_called()
        self.remove.assert_called_once_with('radarr', 22, keep.connection_value)
        self.assertEqual(self.fetch.call_count, 2)
        queued.assert_called_once_with()

    def test_other_unknown_shared_and_unlinked_requests_deny(self):
        queued = self.mock(keep, 'queue_seerr_availability')
        for data in (history(user=11), {**history(), 'requests': []},
                     {**history(), 'users': []},
                     {**history(), 'requests': history()['requests'] + history(user=11)['requests']}):
            with self.subTest(data=data):
                self.live.return_value = data
                self.assertEqual(self.post().status_code, 403)
                self.remove.assert_not_called()
                queued.assert_not_called()

    def test_unavailable_never_falls_back_to_saved_success(self):
        self.live.side_effect = keep.requests.ConnectionError('secret upstream detail')
        response = self.post()
        self.assertEqual(response.status_code, 503)
        self.assertIn('Nothing was deleted', response.json['error'])
        self.assertNotIn('secret', response.get_data(as_text=True))
        self.remove.assert_not_called()

    def test_series_requires_elevated_permission(self):
        self.fetch.return_value = {'id': 22, 'rootFolderPath': '/shows', 'statistics': {'episodeFileCount': 8}}
        self.assertEqual(self.post(service='sonarr', libraryKey='sonarr:5').status_code, 403)
        self.live.assert_not_called()
        self.remove.assert_not_called()

    def test_elevated_permission_bypasses_seerr_but_not_library_or_keeps(self):
        self.update("UPDATE user_profiles SET can_delete_any=1 WHERE plex_id='8'")
        self.live.side_effect = AssertionError('Elevated deletion must work without Seerr')
        self.assertEqual(self.post().status_code, 200)
        self.remove.reset_mock()
        self.kept.return_value = True
        self.assertEqual(self.post().status_code, 409)
        self.kept.return_value = False
        self.update("DELETE FROM user_library_permissions WHERE user_id='8'")
        self.assertEqual(self.post().status_code, 403)
        self.remove.assert_not_called()

    def test_actual_delete_route_blocks_a_keep_in_a_deselected_collection(self):
        self.update("UPDATE user_profiles SET can_delete_any=1 WHERE plex_id='8'")
        self.update("INSERT INTO keep_schedules(collection_id,media_id) VALUES ('9','42')")
        self.kept.side_effect = self.real_keep_check
        self.mock(keep, 'get_collections', return_value={})
        self.mock(keep, 'deletion_keep_inventory', return_value=[
            {'mediaServerId': '42', 'mediaData': {'tmdbId': 100}}])
        self.assertEqual(self.post().status_code, 409)
        self.remove.assert_not_called()

    def test_actual_delete_route_fails_closed_when_hidden_keep_check_is_offline(self):
        self.update("UPDATE user_profiles SET can_delete_any=1 WHERE plex_id='8'")
        self.update("INSERT INTO keep_schedules(collection_id,media_id) VALUES ('9','42')")
        self.kept.side_effect = self.real_keep_check
        self.mock(keep, 'get_collections', return_value={})
        self.mock(keep, 'deletion_keep_inventory', side_effect=keep.requests.ConnectionError('offline'))
        self.assertEqual(self.post().status_code, 502)
        self.remove.assert_not_called()

    def test_owner_retains_override(self):
        with self.client.session_transaction() as session:
            session['plex_user'] = {'id': 7, 'session_version': 0}
        self.assertEqual(self.post().status_code, 200)
        self.live.assert_not_called()

    def test_eligible_artwork_works_with_inventory_cache_and_rechecks_identity(self):
        self.mock(keep.media_services, 'list_media', side_effect=lambda service, _: [self.item] if service == 'radarr' else [])
        cached = self.mock(seerr.Store, 'read', return_value=history())
        art = self.mock(keep.media_services, 'artwork', return_value=(b'poster','image/png'))
        self.assertEqual(self.client.get('/library').status_code, 200)
        self.assertEqual(self.client.get('/library/artwork/radarr/22').status_code, 200)
        self.fetch.assert_not_called()
        art.assert_called_once()
        cached.return_value = history(user=11)
        self.assertEqual(self.client.get('/library/artwork/radarr/22').status_code, 404)
        art.assert_called_once()

    def test_invalid_payload_csrf_and_wrong_library_do_not_delete(self):
        for payload in ([], ['bad'], {'service': [], 'itemId': 22},
                        {'service': 'radarr', 'itemId': True}, {'service': 'radarr', 'itemId': -1}):
            response = self.client.post('/api/library/delete', json=payload,
                                        headers={'X-CSRF-Token': 'test-csrf'})
            self.assertEqual(response.status_code, 400)
        self.assertEqual(self.client.post('/api/library/delete', json={}).status_code, 403)
        self.assertEqual(self.post(libraryKey='radarr:999').status_code, 403)
        self.remove.assert_not_called()
        self.live.assert_not_called()

    def test_revocation_during_verification_prevents_deletion(self):
        for sql in ("UPDATE user_profiles SET can_delete_media=0 WHERE plex_id='8'",
                    "UPDATE user_profiles SET status='disabled' WHERE plex_id='8'",
                    "UPDATE user_profiles SET plex_access='revoked' WHERE plex_id='8'",
                    "UPDATE user_profiles SET session_version=1 WHERE plex_id='8'",
                    "DELETE FROM user_library_permissions WHERE user_id='8'"):
            with self.subTest(sql=sql):
                self.update("UPDATE user_profiles SET can_delete_media=1,status='active',plex_access='active',session_version=0 WHERE plex_id='8'")
                self.update("INSERT OR IGNORE INTO user_library_permissions VALUES ('8','radarr:4')")
                def revoke():
                    self.update(sql)
                    return history()
                self.live.side_effect = revoke
                self.assertEqual(self.post().status_code, 403)
                self.remove.assert_not_called()

    def test_changed_target_or_settings_deny(self):
        self.fetch.side_effect = [self.item, {**self.item, 'tmdbId': 101}]
        self.assertEqual(self.post().status_code, 409)
        self.fetch.side_effect = None
        real = keep.connection_settings.snapshot
        # before_request gets the initial settings; the final check gets changed settings.
        with patch.object(keep.connection_settings, 'snapshot', side_effect=[real(), {**real(), 'SEERR_URL': 'https://changed.example'}]):
            self.assertEqual(self.post().status_code, 409)
        self.remove.assert_not_called()

    def test_keep_verification_failure_does_not_delete(self):
        self.kept.side_effect = ValueError('Incomplete Keep verification')
        self.assertEqual(self.post().status_code, 502)
        self.remove.assert_not_called()

    def test_new_protection_during_final_lookup_blocks_whole_title_delete(self):
        self.kept.side_effect = [False, True]
        self.assertEqual(self.post().status_code, 409)
        self.assertEqual(self.fetch.call_count, 2)
        self.remove.assert_not_called()

    def test_keep_creation_cannot_succeed_during_final_deletion_lookup(self):
        keeper = keep.app.test_client()
        with keeper.session_transaction() as session:
            session['plex_user'] = {'id': 7, 'session_version': 0}
            session['csrf_token'] = 'keeper-csrf'
        protection = self.mock(keep, 'change_maintainerr_exclusion')
        inventory = self.mock(keep, 'get_collection_media', return_value={'items': [
            {'mediaServerId': '42', 'mediaData': {'title': 'A movie', 'tmdbId': 100}}]})
        attempts = []
        def lookup(*args):
            if self.fetch.call_count == 2:
                attempts.append(keeper.post('/api/keep', json={
                    'mediaId': '42', 'collectionId': self.cid},
                    headers={'X-CSRF-Token': 'keeper-csrf'}).status_code)
            return self.item
        self.fetch.side_effect = lookup
        self.assertEqual(self.post().status_code, 200)
        self.assertEqual(attempts, [409])
        protection.assert_not_called()
        inventory.assert_not_called()
        self.remove.assert_called_once()

    def test_revocation_during_final_protection_lookup_prevents_deletion(self):
        def protection(*args):
            if self.kept.call_count == 2:
                self.update("UPDATE user_profiles SET can_delete_media=0 WHERE plex_id='8'")
            return False
        self.kept.side_effect = protection
        self.assertEqual(self.post().status_code, 403)
        self.remove.assert_not_called()

    def test_nested_library_cannot_bypass_its_grant(self):
        self.update("INSERT INTO media_libraries(library_key,service,external_id,name,path) VALUES ('radarr:6','radarr','6','Private','/movies/private')")
        self.fetch.return_value = {**self.item,'rootFolderPath':'/movies/private','path':'/movies/private/Title'}
        self.assertEqual(self.post().status_code, 409)
        self.remove.assert_not_called()
        self.live.assert_not_called()

    def test_local_link_is_resolved_live_and_unlink_during_check_denies(self):
        self.update("UPDATE user_profiles SET auth_type='local' WHERE plex_id='8'")
        store = keep.seerr_store()
        scope = seerr.namespace(keep.connection_value)
        with closing(keep.attribution_db()) as db, db:
            db.execute('DELETE FROM seerr_links WHERE scope=?', (scope,))
            db.execute('INSERT INTO seerr_links VALUES (?,?,?)', (scope, '8', 10))
        self.assertEqual(self.post().status_code, 200)
        self.remove.reset_mock()
        def unlink(*args):
            self.update('DELETE FROM seerr_links')
            return False
        self.kept.side_effect = unlink
        self.assertEqual(self.post().status_code, 403)
        self.remove.assert_not_called()

    def test_library_filters_entire_cards_without_exposing_requesters(self):
        self.mock(keep.media_services, 'list_media', side_effect=lambda service, _: [self.item] if service == 'radarr' else [])
        cached = self.mock(seerr.Store, 'read', return_value=history())
        page = self.client.get('/library').get_data(as_text=True)
        self.assertIn('class="keep-button delete-media-button"', page)
        self.assertNotIn('Private label', page)
        self.assertNotIn('We’ll verify your request and library access', page)
        self.assertNotIn('If verification is unavailable', page)
        cached.return_value = history(user=11)
        page = self.client.get('/library').get_data(as_text=True)
        self.assertNotIn('class="keep-button delete-media-button"', page)
        self.assertNotIn('Details for A movie', page)
        self.assertIn('No titles requested only by you are available here.', page)
        self.assertIn('href="#library-2"', page)
        cached.return_value = {**history(), 'state': 'stale'}
        self.assertNotIn('class="keep-button delete-media-button"', self.client.get('/library').get_data(as_text=True))
        self.live.assert_not_called()

    def test_popup_has_no_permission_notice_or_secret_labels(self):
        self.mock(seerr.Store, 'read', return_value=history())
        page = self.client.get('/api/title-details/radarr/22').get_data(as_text=True)
        self.assertNotIn('Deletion access', page)
        self.assertNotIn('You can delete this movie', page)
        self.assertNotIn('Private label', page)

    def test_direct_artwork_and_details_cannot_reveal_hidden_movies(self):
        cached = self.mock(seerr.Store, 'read', return_value=history(user=11))
        self.mock(keep, 'library_artwork_cache')
        # No cached metadata; force the mocked real service item for this check.
        keep.library_artwork_cache.return_value.get.return_value = None
        artwork = self.mock(keep.media_services, 'artwork')
        for data in (history(user=11), {**history(),'requests':[]}, {**history(),'state':'stale'},
                     {**history(),'state':'unavailable'}, {**history(),'users':[]}):
            cached.return_value = data
            self.assertEqual(self.client.get('/api/title-details/radarr/22').status_code, 404)
            self.assertEqual(self.client.get('/library/artwork/radarr/22').status_code, 404)
        artwork.assert_not_called()
        self.live.assert_not_called()


if __name__ == '__main__':
    unittest.main()
