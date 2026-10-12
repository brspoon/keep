import copy
import re
import unittest
from html.parser import HTMLParser
from unittest.mock import patch

import test_keep

keep = test_keep.keep


class AlphabetMarkup(HTMLParser):
    def __init__(self, page):
        super().__init__()
        self.current_section = None
        self.sections = {}
        self.feed(page)

    def handle_starttag(self, tag, attributes):
        attrs = dict(attributes)
        if tag == 'section' and attrs.get('id', '').startswith(('collection-', 'library-')):
            self.current_section = attrs['id']
            self.sections[self.current_section] = {'navigation': [], 'titles': []}
        if self.current_section and tag == 'nav' and 'data-alphabet-nav' in attrs:
            self.sections[self.current_section]['navigation'].append(attrs)
        if self.current_section and tag == 'article' and 'card' in attrs.get('class', '').split():
            self.sections[self.current_section]['titles'].append(attrs.get('data-title'))

    def handle_endtag(self, tag):
        if tag == 'section':
            self.current_section = None


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

    def test_browse_alphabet_context_and_title_metadata_preserve_escaped_names(self):
        title = '"Alpha <Beta> & Gamma"'
        item = {**self.item, 'mediaData': {'title': title, 'year': 2026}}
        for path, context in (('/', 'Movies Leaving Plex Soon'), ('/kept', 'Movies Kept')):
            with self.subTest(path=path):
                markup = AlphabetMarkup(self.page(path, [item]))
                self.assertEqual(list(markup.sections), [f'collection-{self.cid}'])
                section = markup.sections[f'collection-{self.cid}']
                self.assertEqual(section['titles'], [title])
                self.assertEqual(len(section['navigation']), 1)
                self.assertEqual(section['navigation'][0]['aria-label'], f'{context} title initials')
                self.assertIn('hidden', section['navigation'][0])

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

    def test_library_alphabet_context_is_independent_for_each_rendered_section(self):
        def section(name, key, title, item_id):
            return {'library_key': key, 'name': name, 'error': '', 'access_unavailable': False,
                    'items': [{'id': item_id, 'title': title, 'year': 2026, 'service': 'radarr',
                               'library_key': key, 'size': '1 GB', 'episode_count': None,
                               'can_delete': True, 'badge': None}]}

        markup = AlphabetMarkup(self.library_page([
            section('Movies & More', 'radarr:1', 'Alpha', 1),
            section('Shows', 'radarr:2', 'Zulu', 2),
        ]))
        self.assertEqual(list(markup.sections), ['library-1', 'library-2'])
        for section_id, name, title in (('library-1', 'Movies & More', 'Alpha'),
                                        ('library-2', 'Shows', 'Zulu')):
            rendered = markup.sections[section_id]
            self.assertEqual(rendered['titles'], [title])
            self.assertEqual(len(rendered['navigation']), 1)
            self.assertEqual(rendered['navigation'][0]['aria-label'], f'{name} title initials')
            self.assertIn('hidden', rendered['navigation'][0])

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
