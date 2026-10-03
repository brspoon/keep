import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import Mock, patch

import media_services
import test_keep
from test_keep import keep


class MediaServiceClientTests(unittest.TestCase):
    def test_media_client_is_in_the_container_build_context(self):
        root = Path(__file__).resolve().parents[1]
        self.assertIn('!media_services.py', (root / '.dockerignore').read_text())
        self.assertIn('media_services.py', (root / 'Dockerfile').read_text())

    def settings(self, name):
        return {
            'RADARR_URL': 'http://radarr:7878', 'RADARR_API_KEY': 'radarr-secret',
            'SONARR_URL': 'http://sonarr:8989', 'SONARR_API_KEY': 'sonarr-secret',
        }.get(name, '')

    @patch.object(media_services.requests, 'request')
    def test_delete_matches_native_radarr_and_sonarr_file_deletion(self, request):
        request.return_value.status_code = 200
        request.return_value.raise_for_status.return_value = None
        media_services.delete_media('radarr', 12, self.settings)
        self.assertEqual(request.call_args.args[:2], ('DELETE', 'http://radarr:7878/api/v3/movie/12'))
        self.assertEqual(request.call_args.kwargs['params'],
                         {'deleteFiles': 'true', 'addImportExclusion': 'false'})
        self.assertEqual(request.call_args.kwargs['headers']['X-Api-Key'], 'radarr-secret')
        media_services.delete_media('sonarr', 34, self.settings)
        self.assertEqual(request.call_args.args[:2], ('DELETE', 'http://sonarr:8989/api/v3/series/34'))
        self.assertEqual(request.call_args.kwargs['params'],
                         {'deleteFiles': 'true', 'addImportListExclusion': 'false'})

    @patch.object(media_services.requests, 'request')
    def test_discovery_uses_root_folder_ids_without_exposing_credentials(self, request):
        request.return_value.status_code = 200
        request.return_value.raise_for_status.return_value = None
        request.return_value.json.return_value = [
            {'id': 4, 'path': '/mnt/synology/Movies'}, {'id': 5, 'path': '/mnt/synology/4K Movies'}]
        self.assertEqual(media_services.discover_libraries('radarr', self.settings), [
            {'key': 'radarr:4', 'service': 'radarr', 'external_id': '4',
             'name': 'Movies', 'path': '/mnt/synology/Movies'},
            {'key': 'radarr:5', 'service': 'radarr', 'external_id': '5',
             'name': '4K Movies', 'path': '/mnt/synology/4K Movies'},
        ])

    @patch.object(media_services.requests, 'request')
    def test_redirect_is_failure_instead_of_false_delete_success(self, request):
        request.return_value.status_code = 302
        request.return_value.raise_for_status.return_value = None
        with self.assertRaises(media_services.requests.HTTPError):
            media_services.delete_media('radarr', 12, self.settings)

    @patch.object(media_services.requests, 'request')
    def test_artwork_is_type_checked_size_bounded_and_closed(self, request):
        response = request.return_value
        response.status_code = 200
        response.raise_for_status.return_value = None
        response.headers = {'Content-Type': 'image/jpeg'}
        response.iter_content.return_value = [b'poster']
        self.assertEqual(media_services.artwork('radarr', 12, self.settings),
                         (b'poster', 'image/jpeg'))
        self.assertEqual(request.call_args.args[1],
                         'http://radarr:7878/api/v3/mediacover/12/poster.jpg')
        response.close.assert_called_once()

    @patch.object(media_services, '_request')
    def test_thumbnail_falls_back_only_when_missing(self, request):
        from unittest.mock import Mock
        missing = Mock(status_code=404)
        response = Mock(headers={'Content-Type': 'image/jpeg'})
        response.iter_content.return_value = [b'small']
        request.side_effect = [media_services.requests.HTTPError(response=missing), response]
        self.assertEqual(media_services.artwork('sonarr', 12, self.settings, thumbnail=True)[0], b'small')
        self.assertEqual(request.call_args_list[0].args[3], '/api/v3/mediacover/12/poster-500.jpg')
        self.assertEqual(request.call_args_list[1].args[3], '/api/v3/mediacover/12/poster.jpg')
        missing.close.assert_called_once()
        request.reset_mock()
        request.side_effect = media_services.requests.HTTPError(response=Mock(status_code=401))
        with self.assertRaises(media_services.requests.HTTPError):
            media_services.artwork('sonarr', 12, self.settings, thumbnail=True)
        self.assertEqual(request.call_count, 1)

    @patch.object(media_services.requests, 'request')
    def test_artwork_uses_only_the_service_supplied_local_poster_path(self, request):
        response = request.return_value
        response.status_code = 200
        response.raise_for_status.return_value = None
        response.headers = {'Content-Type': 'image/webp'}
        response.iter_content.return_value = [b'poster']
        item = {'images': [
            {'coverType': 'banner', 'url': '/MediaCover/12/banner.jpg'},
            {'coverType': 'poster', 'url': '/MediaCover/12/poster-500.jpg?lastWrite=1'},
        ]}
        media_services.artwork('radarr', 12, self.settings, item=item)
        self.assertEqual(request.call_args.args[1],
                         'http://radarr:7878/api/v3/mediacover/12/poster-500.jpg?lastWrite=1')

        item['images'][1]['url'] = 'https://attacker.example/poster.jpg'
        media_services.artwork('radarr', 12, self.settings, item=item)
        self.assertEqual(request.call_args.args[1],
                         'http://radarr:7878/api/v3/mediacover/12/poster.jpg')

        item['images'][1]['url'] = '/MediaCover/12/../../system/status'
        media_services.artwork('radarr', 12, self.settings, item=item)
        self.assertEqual(request.call_args.args[1],
                         'http://radarr:7878/api/v3/mediacover/12/poster.jpg')

        response.reset_mock()
        response.status_code = 200
        response.headers = {'Content-Type': 'text/html'}
        with self.assertRaises(ValueError):
            media_services.artwork('radarr', 12, self.settings)
        response.close.assert_called_once()


class LibraryManagementTests(unittest.TestCase):
    def setUp(self):
        test_keep.KeepTests.setUp(self)
        keep.library_artwork_cache().forget('')
        with closing(keep.attribution_db()) as db, db:
            db.execute("DELETE FROM user_library_permissions")
            db.execute("DELETE FROM media_libraries")
            db.execute("""INSERT INTO media_libraries
                (library_key, service, external_id, name, path)
                VALUES ('radarr:4', 'radarr', '4', 'Movies', '/mnt/synology/Movies')""")
            db.execute("""INSERT INTO user_profiles
                (plex_id, plex_username, can_delete_media, plex_checked_at)
                VALUES ('8', 'Basic', 0, CURRENT_TIMESTAMP)""")
        with self.client.session_transaction() as session:
            session['plex_user'] = {'id': 8, 'username': 'Basic', 'thumb': ''}
            session['csrf_token'] = 'test-csrf'

    def grant(self):
        with closing(keep.attribution_db()) as db, db:
            db.execute("UPDATE user_profiles SET can_delete_media=1, can_delete_any=1 WHERE plex_id='8'")
            db.execute("""INSERT INTO user_library_permissions(user_id, library_key)
                VALUES ('8', 'radarr:4')""")

    @patch.object(keep.media_services, 'discover_libraries')
    def test_successful_discovery_removes_stale_library_grants(self, discover):
        self.grant()
        discover.return_value = [{
            'key': 'radarr:9', 'service': 'radarr', 'external_id': '9',
            'name': 'New Movies', 'path': '/mnt/synology/New Movies',
        }]
        keep.refresh_media_libraries('radarr')
        with closing(keep.attribution_db()) as db:
            libraries = [row[0] for row in db.execute(
                "SELECT library_key FROM media_libraries ORDER BY library_key")]
            grants = db.execute("SELECT COUNT(*) FROM user_library_permissions").fetchone()[0]
        self.assertEqual(libraries, ['radarr:9'])
        self.assertEqual(grants, 0)

    def post_delete(self, **changes):
        payload = {'service': 'radarr', 'itemId': 22, 'libraryKey': 'radarr:4', **changes}
        return self.client.post('/api/library/delete', json=payload,
                                headers={'X-CSRF-Token': 'test-csrf'})

    @patch.object(keep, 'build_review_collections', return_value=[])
    @patch.object(keep, 'get_collection_media', return_value={'items': []})
    @patch.object(keep, 'get_collection_exclusions', return_value={'items': []})
    def test_profile_link_and_route_are_hidden_without_permission(self, exclusions, media, review):
        self.assertEqual(self.client.get('/library').status_code, 403)
        self.assertNotIn('href="/library"', self.client.get('/').get_data(as_text=True))

    @patch.object(keep.media_services, 'list_media')
    def test_library_page_groups_downloaded_media_and_preserves_shared_ui(self, inventory):
        self.grant()
        inventory.return_value = [
            {'id': 22, 'title': 'Example Movie', 'year': 2026, 'hasFile': True,
             'path': '/mnt/synology/Movies/Example Movie (2026)',
             'rootFolderPath': '/mnt/synology/Movies', 'statistics': {'sizeOnDisk': 5 * 1024**3}},
            {'id': 23, 'title': 'Missing Movie', 'hasFile': False,
             'rootFolderPath': '/mnt/synology/Movies'},
        ]
        page = self.client.get('/library')
        body = page.get_data(as_text=True)
        self.assertEqual(page.status_code, 200)
        self.assertIn('Manage Library', body)
        self.assertIn('href="#library-1">Movies</a>', body)
        self.assertIn('Search your media libraries', body)
        self.assertIn('Example Movie', body)
        self.assertNotIn('Missing Movie', body)
        self.assertIn('5.0 GB', body)
        self.assertNotIn('/mnt/synology', body)
        self.assertNotIn('Radarr', body)
        self.assertNotIn('data-service="sonarr"', body)
        self.assertNotIn('Sonarr', body)
        self.assertIn('Deleting a title permanently removes it and its files.', body)
        self.assertIn('id="back-to-top"', body)
        self.assertEqual(page.headers['Cache-Control'], 'no-store')

    @patch.object(keep.media_services, 'artwork', return_value=(b'poster', 'image/jpeg'))
    @patch.object(keep.media_services, 'get_media')
    @patch.object(keep.media_services, 'list_media')
    def test_inventory_seeds_metadata_and_expiry_rechecks_moved_title(self, inventory, get_media, artwork):
        self.grant()
        inventory.return_value = [{'id': 22, 'title': 'Example', 'hasFile': True,
                                   'rootFolderPath': '/mnt/synology/Movies'}]
        self.assertEqual(self.client.get('/library').status_code, 200)
        self.assertEqual(self.client.get('/library/artwork/radarr/22').status_code, 200)
        get_media.assert_not_called()
        get_media.return_value = {'id': 22, 'rootFolderPath': '/private'}
        with closing(keep.library_artwork_cache().connect()) as db, db:
            db.execute("UPDATE entries SET expires=0 WHERE kind='application/json'")
        self.assertEqual(self.client.get('/library/artwork/radarr/22').status_code, 404)
        self.assertEqual(artwork.call_count, 1)

    @patch.object(keep.media_services, 'artwork', return_value=(b'poster', 'image/jpeg'))
    @patch.object(keep.media_services, 'get_media')
    def test_artwork_proxy_rechecks_library_and_uses_inventory_poster(self, get_media, artwork):
        item = {'id': 22, 'rootFolderPath': '/mnt/synology/Movies',
                'images': [{'coverType': 'poster', 'url': '/MediaCover/22/poster.jpg'}]}
        get_media.return_value = item
        self.assertEqual(self.client.get('/library/artwork/radarr/22').status_code, 404)
        self.grant()
        response = self.client.get('/library/artwork/radarr/22')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, b'poster')
        self.assertEqual(response.mimetype, 'image/jpeg')
        artwork.assert_called_once_with('radarr', 22, keep.connection_value, item=item, thumbnail=True)
        again = self.client.get('/library/artwork/radarr/22', headers={'If-None-Match': response.headers['ETag']})
        self.assertEqual(again.status_code, 304)
        self.assertEqual(get_media.call_count, 1)
        self.assertEqual(artwork.call_count, 1)
        with closing(keep.attribution_db()) as db, db:
            db.execute('DELETE FROM user_library_permissions')
        self.assertEqual(self.client.get('/library/artwork/radarr/22').status_code, 404)

    @patch.object(keep, 'media_matches_active_keep', return_value=False)
    @patch.object(keep.media_services, 'delete_media')
    @patch.object(keep.media_services, 'get_media')
    def test_delete_revalidates_library_and_logs_success(self, get_media, delete_media, kept):
        self.grant()
        get_media.return_value = {
            'id': 22, 'title': 'Example Movie', 'hasFile': True,
            'path': '/mnt/synology/Movies/Example Movie',
            'rootFolderPath': '/mnt/synology/Movies',
        }
        response = self.post_delete()
        self.assertEqual(response.status_code, 200)
        delete_media.assert_called_once_with('radarr', 22, keep.connection_value)
        with closing(keep.attribution_db()) as db:
            activity = db.execute("SELECT action, description FROM activity_log").fetchone()
        self.assertEqual(activity['action'], 'media-deleted')
        self.assertIn('Example Movie', activity['description'])
        self.assertIn('folder', activity['description'])

    @patch.object(keep.media_services, 'delete_media')
    def test_delete_requires_grant_csrf_and_non_kept_title(self, delete_media):
        self.assertEqual(self.post_delete().status_code, 403)
        self.grant()
        self.assertEqual(self.client.post('/api/library/delete', json={}).status_code, 403)
        item = {'id': 22, 'title': 'Example Movie', 'hasFile': True,
                'path': '/mnt/synology/Movies/Example Movie',
                'rootFolderPath': '/mnt/synology/Movies'}
        with patch.object(keep.media_services, 'get_media', return_value=item), \
             patch.object(keep, 'media_matches_active_keep', return_value=True):
            response = self.post_delete()
        self.assertEqual(response.status_code, 409)
        self.assertIn('Kept', response.json['error'])
        delete_media.assert_not_called()


if __name__ == '__main__':
    unittest.main()
