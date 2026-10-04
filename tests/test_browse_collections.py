import copy
import re
import unittest
from unittest.mock import patch

import test_keep

keep = test_keep.keep


class BrowseCollectionsTests(unittest.TestCase):
    setUp = test_keep.KeepTests.setUp

    def page(self, path, items):
        def collection(collection_id):
            return {'items': copy.deepcopy(items if collection_id == self.cid else [])}

        with patch.object(keep, 'get_collection_media', side_effect=collection), \
             patch.object(keep, 'get_collection_exclusions', side_effect=collection), \
             patch.object(keep, 'get_collection_delete_after_days', return_value=30):
            response = self.client.get(path)
        self.assertEqual(response.status_code, 200)
        return response.get_data(as_text=True)

    def test_leaving_and_kept_hide_empty_collections_and_jump_buttons(self):
        for path in ('/', '/kept'):
            with self.subTest(path=path):
                page = self.page(path, [self.item])
                self.assertEqual(re.findall(r'<section id="collection-([^\"]+)"', page),
                                 [str(self.cid)])
                self.assertEqual(re.findall(r'href="#collection-([^\"]+)"', page),
                                 [str(self.cid)])
                self.assertRegex(page, r'id="browse-empty"[^>]* hidden')

    def test_empty_browse_pages_render_one_page_note_and_no_collections(self):
        for path, note in (('/', 'The coast is clear'), ('/kept', 'Nothing kept just yet')):
            with self.subTest(path=path):
                page = self.page(path, [])
                self.assertNotIn('<section id="collection-', page)
                self.assertNotIn('class="section-nav"', page)
                self.assertIn(f'<h2 data-browse-empty-title>{note}</h2>', page)
                self.assertNotRegex(page, r'id="browse-empty"[^>]* hidden')
                self.assertNotIn('No titles are currently', page)

    def test_leaving_and_kept_use_library_case_insensitive_title_year_order(self):
        items = [{**self.item, 'mediaServerId': str(index),
                  'mediaData': {'title': title, 'year': year}}
                 for index, (title, year) in enumerate((('Zulu', 2026), ('beta', 2025),
                                                        ('Alpha', 2024), ('alpha', 2023)))]
        for path in ('/', '/kept'):
            with self.subTest(path=path):
                page = self.page(path, items)
                self.assertEqual(re.findall(r'class="title-details-name"[^>]*>([^<]+)', page),
                                 ['alpha', 'Alpha', 'beta', 'Zulu'])

    def library_page(self, sections):
        with patch.object(keep, 'granted_library_keys', return_value=['radarr:1']), \
             patch.object(keep, 'build_library_sections', return_value=sections):
            response = self.client.get('/library')
        self.assertEqual(response.status_code, 200)
        return response.get_data(as_text=True)

    def test_missing_or_null_titles_sort_like_library_untitled_fallback(self):
        items = [{**self.item, 'mediaServerId': '1', 'mediaData': {'title': 'Zulu'}},
                 {**self.item, 'mediaServerId': '2', 'mediaData': {'title': None, 'year': 2026}},
                 {**self.item, 'mediaServerId': '3', 'mediaData': {'title': 'Alpha'}},
                 {**self.item, 'mediaServerId': '4', 'mediaData': {'year': 2025}}]
        for build in (keep.build_review_collections, keep.build_kept_collections):
            with self.subTest(builder=build.__name__), keep.app.test_request_context('/'), \
                 patch.object(keep, 'get_collections', return_value={self.cid: 'Movies'}), \
                 patch.object(keep, 'get_collection_media', return_value={'items': copy.deepcopy(items)}), \
                 patch.object(keep, 'get_collection_exclusions', return_value={'items': copy.deepcopy(items)}), \
                 patch.object(keep, 'get_collection_delete_after_days', return_value=30):
                self.assertEqual([item['mediaServerId'] for item in build()[0]['items']],
                                 ['3', '4', '2', '1'])

    def test_manage_library_only_renders_sections_and_links_with_items(self):
        item = {'id': 1, 'title': 'Alpha', 'year': 2026, 'service': 'radarr',
                'library_key': 'radarr:2', 'size': '1 GB', 'episode_count': None,
                'can_delete': True, 'badge': None}
        sections = [{'library_key': 'radarr:1', 'name': 'Empty', 'items': [],
                     'error': '', 'access_unavailable': False},
                    {'library_key': 'radarr:2', 'name': 'Movies', 'items': [item],
                     'error': '', 'access_unavailable': False}]
        page = self.library_page(sections)
        self.assertNotIn('<h2>Empty</h2>', page)
        self.assertEqual(re.findall(r'<section id="library-([^\"]+)"', page), ['1'])
        self.assertEqual(re.findall(r'href="#library-([^\"]+)"', page), ['1'])

    def test_manage_library_empty_and_unavailable_have_distinct_notes(self):
        section = {'library_key': 'radarr:1', 'name': 'Movies', 'items': [],
                   'error': '', 'access_unavailable': False}
        page = self.library_page([section])
        self.assertNotIn('class="section-nav"', page)
        self.assertNotIn('<section id="library-', page)
        self.assertNotRegex(page, r'id="browse-empty"[^>]* hidden')
        self.assertIn('No downloaded movies or shows are available here right now.', page)
        page = self.library_page([{**section, 'error': 'Offline'}])
        self.assertIn('Could not load Movies.', page)
        self.assertIn('role="alert"', page)
        self.assertRegex(page, r'id="browse-empty"[^>]* hidden')
        page = self.library_page([{**section, 'access_unavailable': True}])
        self.assertIn('Your requests can’t be verified right now', page)
        self.assertRegex(page, r'id="browse-empty"[^>]* hidden')


if __name__ == '__main__':
    unittest.main()
