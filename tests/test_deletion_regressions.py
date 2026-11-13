"""Deletion regression coverage; all external services and disk reads are mocked."""
import time
import unittest
from unittest.mock import Mock, patch

import media_services
import test_keep

keep = test_keep.keep


class DeletionRegressionTests(unittest.TestCase):
    setUp = test_keep.KeepTests.setUp

    def test_provider_identity_blocks_movie_and_series_despite_display_differences(self):
        for service, field, provider in [('radarr', 'tmdbId', 'tmdb'), ('sonarr', 'tvdbId', 'tvdb')]:
            for row in [{'mediaData': {field: 99}}, {field: 99, 'mediaData': {}},
                        {'mediaData': {'providerIds': {provider: ['99']}}}]:
                row['mediaServerId'] = '42'
                row['mediaData'].update(title='Alternate title', year=1999)
                with self.subTest(service=service, row=row), \
                     patch.object(keep, 'get_collections', return_value={1: 'Collection'}), \
                     patch.object(keep, 'deletion_keep_inventory', return_value=[row]):
                    self.assertTrue(keep.media_matches_active_keep(service, {
                        field: 99, 'title': 'Original title', 'year': 2024}))

    def test_cleanup_removes_all_matching_memberships_only(self):
        target = {'mediaServerId': '42', 'mediaData': {'type': 'movie', 'providerIds': {'tmdb': ['99']}}}
        unrelated = {'mediaServerId': '43', 'mediaData': {'tmdbId': 100}}
        with patch.object(keep, 'get_collections', return_value={1: 'Movies', 2: 'Other'}), \
             patch.object(keep, 'deletion_keep_inventory', side_effect=[[target, unrelated], [unrelated], [target], []]) as inventory, \
             patch.object(keep.requests, 'delete', return_value=Mock(status_code=200)) as remove:
            keep.remove_deleted_from_leaving('radarr', {'tmdbId': 99})
            self.assertEqual(remove.call_count, 2)
            self.assertEqual([c.kwargs['params'] for c in remove.call_args_list], [
                {'mediaId': '42', 'collectionId': 1}, {'mediaId': '42', 'collectionId': 2}])
            self.assertTrue(all(c.kwargs['kind'] == 'media' for c in inventory.call_args_list))

    def test_cleanup_requires_membership_to_disappear(self):
        target = {'mediaServerId': '42', 'mediaData': {'type': 'movie', 'tmdbId': 99}}
        with patch.object(keep, 'get_collections', return_value={1: 'Movies'}), \
             patch.object(keep, 'deletion_keep_inventory', return_value=[target]), \
             patch.object(keep.requests, 'delete', return_value=Mock(status_code=200)):
            with self.assertRaisesRegex(ValueError, 'remains in Leaving'):
                keep.remove_deleted_from_leaving('radarr', {'tmdbId': 99})

    def test_leaving_inventory_reads_beyond_first_page(self):
        first = [{'mediaServerId': str(n), 'mediaData': {}} for n in range(100)]
        with patch.object(keep.requests, 'get', side_effect=[
                Mock(status_code=200, json=lambda: {'items': first}),
                Mock(status_code=200, json=lambda: {'items': []})]) as get:
            self.assertEqual(len(list(keep.deletion_keep_inventory(1, time.monotonic()+20, kind='media'))), 100)
            self.assertIn('/media/1/content/2', get.call_args.args[0])


class PhysicalDeletionTests(unittest.TestCase):
    def test_waits_for_async_disk_removal_in_both_services(self):
        for service in ('radarr', 'sonarr'):
            with self.subTest(service=service), patch.object(media_services, '_request', side_effect=[
                    Mock(json=lambda: [{'path': '/media/title/movie.mkv'}]), Mock(json=lambda: [])]) as request, \
                 patch.object(media_services.time, 'sleep') as sleep:
                media_services.wait_for_file_removal(service, '/media/title', lambda _: '')
                self.assertEqual(request.call_count, 2)
                sleep.assert_called_once_with(1)
                self.assertEqual(request.call_args.args[3], '/api/v3/filesystem/mediafiles')

    def test_leftover_files_and_malformed_disk_results_never_confirm_success(self):
        for rows in ([{'path': '/media/title/movie.mkv'}], {}, [None], [{'path': None}]):
            with self.subTest(rows=rows), patch.object(media_services, '_request', return_value=Mock(json=lambda: rows)):
                with self.assertRaises(ValueError):
                    media_services.wait_for_file_removal('radarr', '/media/title', lambda _: '', attempts=1)

    def test_season_check_ignores_other_seasons_but_rejects_selected_leftovers(self):
        with patch.object(media_services, '_request', return_value=Mock(json=lambda: [
                {'path': '/shows/title/season2.mkv'}])):
            media_services.wait_for_file_removal('sonarr', '/shows/title', lambda _: '',
                paths={'/shows/title/season1.mkv'}, attempts=1)
            with self.assertRaises(ValueError):
                media_services.wait_for_file_removal('sonarr', '/shows/title', lambda _: '',
                    paths={'/shows/title/season2.mkv'}, attempts=1)

    def test_tracked_files_are_deleted_before_title_record(self):
        for service, owner, resource in [('radarr', 'movieId', 'movie'), ('sonarr', 'seriesId', 'series')]:
            with self.subTest(service=service), patch.object(media_services, '_request', side_effect=[
                    Mock(json=lambda: [{'id': 8, owner: 22}]), Mock(), Mock()]) as request:
                media_services.delete_media(service, 22, lambda _: '')
                self.assertEqual(request.call_args_list[0].args[2], 'GET')
                self.assertEqual(request.call_args_list[1].args[2], 'DELETE')
                self.assertEqual(request.call_args_list[2].args[3], f'/api/v3/{resource}/22')

    def test_file_failure_preserves_title_record(self):
        for service, owner in [('radarr', 'movieId'), ('sonarr', 'seriesId')]:
            with self.subTest(service=service), patch.object(media_services, '_request', side_effect=[
                    Mock(json=lambda: [{'id': 8, owner: 22}]), ValueError('Disk failure')]) as request:
                with self.assertRaises(ValueError):
                    media_services.delete_media(service, 22, lambda _: '')
                self.assertEqual(request.call_count, 2)
                self.assertNotIn(request.call_args.args[3], ('/api/v3/movie/22', '/api/v3/series/22'))

    def test_foreign_file_inventory_never_deleted(self):
        with patch.object(media_services, '_request', return_value=Mock(json=lambda: [{'id': 8, 'movieId': 23}])) as request:
            with self.assertRaises(ValueError):
                media_services.delete_media('radarr', 22, lambda _: '')
            request.assert_called_once()
