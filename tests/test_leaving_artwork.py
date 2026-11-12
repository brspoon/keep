import unittest
from unittest.mock import Mock, patch

import requests
import test_keep

keep = test_keep.keep


class LeavingArtworkTests(unittest.TestCase):
    setUp = test_keep.KeepTests.setUp

    def test_missing_posters_load_lazily_and_existing_posters_are_preserved(self):
        items = [
            {'mediaServerId': '14580', 'image_path': None,
             'mediaData': {'title': '1992', 'year': 2022}},
            {'mediaServerId': '5678',
             'mediaData': {'title': 'Bubble Guppies', 'year': 2006}},
            {'mediaServerId': '99', 'image_path': 'https://images.example/existing.jpg',
             'mediaData': {'title': 'Existing poster'}},
        ]
        with patch.object(keep, 'get_collections', return_value={1: 'Leaving'}), \
             patch.object(keep, 'get_collection_media', return_value={'items': items}), \
             patch.object(keep, 'get_collection_exclusions', return_value={'items': []}), \
             patch.object(keep, 'get_collection_delete_after_days', return_value=30), \
             patch.object(keep, 'get_kept_item_poster') as poster:
            response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        page = response.get_data(as_text=True)
        self.assertIn('src="/leaving/artwork/14580"', page)
        self.assertIn('src="/leaving/artwork/5678"', page)
        self.assertIn('src="https://images.example/existing.jpg"', page)
        poster.assert_not_called()

    def test_provider_lookup_uses_ids_without_rejecting_plex_year(self):
        for item_id, media_type, tmdb_id, year in (
                (14580, 'movie', '413846', 2022),
                (5678, 'show', '39107', 2006)):
            with self.subTest(media_type=media_type):
                metadata = Mock()
                metadata.json.return_value = {
                    'type': media_type, 'year': year,
                    'providerIds': {'tmdb': [tmdb_id]},
                }
                image = Mock()
                image.json.return_value = {'url': 'https://images.example/poster.jpg'}
                with patch.object(keep.requests, 'get', side_effect=[metadata, image]) as get:
                    response = self.client.get(f'/leaving/artwork/{item_id}')
                self.assertEqual(response.status_code, 302)
                self.assertEqual(response.location, 'https://images.example/poster.jpg')
                self.assertEqual(response.headers['Cache-Control'], 'private, max-age=300')
                self.assertTrue(get.call_args.args[0].endswith(f'/api/metadata/image/{media_type}'))
                self.assertEqual(get.call_args.kwargs['params'], {'tmdbId': tmdb_id})

    def test_unavailable_posters_and_upstream_failures_return_not_found(self):
        for result in (None, 'javascript:alert(1)'):
            with patch.object(keep, 'get_kept_item_poster', return_value=result):
                self.assertEqual(self.client.get('/leaving/artwork/14580').status_code, 404)
        with patch.object(keep.requests, 'get', side_effect=requests.Timeout):
            self.assertEqual(self.client.get('/leaving/artwork/14580').status_code, 404)

    def test_artwork_requires_sign_in_before_lookup(self):
        with self.client.session_transaction() as session:
            session.clear()
        with patch.object(keep, 'get_kept_item_poster') as poster:
            response = self.client.get('/leaving/artwork/14580')
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.location.endswith('/login'))
        poster.assert_not_called()
