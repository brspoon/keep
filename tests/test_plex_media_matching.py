import copy
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import requests

import leaving_forecast as forecast


def settings(name):
    return {'MAINTAINERR_URL': 'http://maintainerr'}.get(name)


def group(library='7', kind='movie'):
    return {'kind': kind, 'library_id': library}


def movie(plex_id, tmdb_id):
    return {'id': str(plex_id), 'type': 'movie',
            'providerIds': {'tmdb': [str(tmdb_id)]}}


def page(items, total=None, offset=0, limit=100):
    return {'items': items, 'totalSize': len(items) if total is None else total,
            'offset': offset, 'limit': limit}


class PlexMediaMatchingTests(unittest.TestCase):
    def lookup(self, pages, *, groups=None, kind='movie', external_id=31):
        with patch.object(forecast, '_get_json', side_effect=pages) as fetch:
            result = forecast.find_plex_media(
                settings, groups if groups is not None else {1: group()}, kind, external_id)
        return result, fetch.call_args_list

    def assert_unavailable(self, pages, *, groups=None):
        with patch.object(forecast, '_get_json', side_effect=pages):
            with self.assertRaises(forecast.ForecastUnavailable):
                forecast.find_plex_media(settings, groups or {1: group()}, 'movie', 31)

    def test_provider_identity_does_not_require_a_title(self):
        result, calls = self.lookup([page([movie(42, 31)])])
        self.assertEqual(result, (1, '42'))
        request = urlsplit(calls[0].args[0])
        self.assertEqual(request.path, '/api/media-server/library/7/content')
        self.assertEqual(parse_qs(request.query),
                         {'page': ['1'], 'limit': ['100'], 'type': ['movie']})

    def test_display_title_variations_do_not_change_provider_matching(self):
        titles = ('Sample and Example', "Sample's Alternate Name", 'Sample 2',
                  'Sample Four: A Chapter', 'Sample Series', 'Sample/Example', 'S' * 201)
        for title in titles:
            with self.subTest(title=title):
                row = {**movie(42, 31), 'title': title}
                self.assertEqual(self.lookup([page([row])])[0], (1, '42'))

    def test_integer_and_string_provider_ids_match(self):
        for external_id in (31, '31'):
            for provider_id in (31, '31'):
                with self.subTest(external_id=external_id, provider_id=provider_id):
                    row = movie(42, 31)
                    row['providerIds']['tmdb'] = [provider_id]
                    self.assertEqual(self.lookup([page([row])], external_id=external_id)[0],
                                     (1, '42'))

    def test_show_uses_tvdb_in_selected_show_library(self):
        row = {'id': '42', 'type': 'show',
               'providerIds': {'tmdb': ['999'], 'tvdb': ['31']}}
        result, calls = self.lookup([page([row])], kind='tv',
                                    groups={1: group('7'), 3: group('4', 'tv')})
        self.assertEqual(result, (3, '42'))
        self.assertEqual(len(calls), 1)
        self.assertEqual(urlsplit(calls[0].args[0]).path,
                         '/api/media-server/library/4/content')
        self.assertEqual(parse_qs(urlsplit(calls[0].args[0]).query)['type'], ['show'])

    def test_other_provider_namespace_cannot_establish_match(self):
        row = {'id': '42', 'type': 'movie',
               'providerIds': {'tmdb': ['999'], 'tvdb': ['31']}}
        self.assertIsNone(self.lookup([page([row])])[0])

    def test_match_on_later_page_is_found(self):
        first = [movie(i, 1000 + i) for i in range(1, 101)]
        result, calls = self.lookup([page(first, total=101),
                                     page([movie(101, 31)], total=101, offset=100)])
        self.assertEqual(result, (1, '101'))
        self.assertEqual(len(calls), 2)
        self.assertEqual(parse_qs(urlsplit(calls[1].args[0]).query)['page'], ['2'])

    def test_later_duplicate_provider_makes_early_match_ambiguous(self):
        first = [movie(1, 31)] + [movie(i, 1000 + i) for i in range(2, 101)]
        result, calls = self.lookup([page(first, total=101),
                                     page([movie(101, 31)], total=101, offset=100)])
        self.assertIsNone(result)
        self.assertEqual(len(calls), 2)

    def test_selected_library_matches_are_ambiguous(self):
        result, calls = self.lookup([page([movie(42, 31)]), page([movie(43, 31)])],
                                    groups={1: group('7'), 5: group('5')})
        self.assertIsNone(result)
        self.assertEqual(len(calls), 2)

    def test_same_plex_item_in_two_selected_rules_is_ambiguous(self):
        result, _ = self.lookup([page([movie(42, 31)]), page([movie(42, 31)])],
                                groups={1: group('7'), 5: group('7')})
        self.assertIsNone(result)

    def test_no_match_checks_all_selected_libraries(self):
        result, calls = self.lookup([page([movie(42, 999)]), page([])],
                                    groups={1: group('7'), 5: group('5')})
        self.assertIsNone(result)
        self.assertEqual(len(calls), 2)

    def test_later_library_failure_prevents_using_an_earlier_match(self):
        with patch.object(forecast, '_get_json',
                          side_effect=[page([movie(42, 31)]), requests.Timeout()]):
            with self.assertRaises((forecast.ForecastUnavailable, requests.RequestException)):
                forecast.find_plex_media(settings, {1: group('7'), 5: group('5')},
                                         'movie', 31)

    def test_invalid_external_identity_does_not_query_services(self):
        for external_id in (None, True, False, 0, -1, 3.1, '', '0', '-1', 'invalid', []):
            with self.subTest(external_id=external_id), \
                    patch.object(forecast, '_get_json') as fetch:
                self.assertIsNone(forecast.find_plex_media(
                    settings, {1: group()}, 'movie', external_id))
                fetch.assert_not_called()

    def test_invalid_relevant_library_is_unavailable(self):
        for library in ('', '0', '-1', 'invalid'):
            with self.subTest(library=library):
                self.assert_unavailable([], groups={1: group(library)})

    def test_invalid_page_envelope_is_unavailable(self):
        valid = page([movie(42, 31)])
        payloads = [None, [], {**valid, 'items': {}}, {**valid, 'totalSize': True},
                    {**valid, 'totalSize': -1}, {**valid, 'totalSize': '1'},
                    {**valid, 'offset': 1}, {**valid, 'offset': False},
                    {**valid, 'limit': 99}, {**valid, 'limit': '100'}]
        payloads.extend({key: value for key, value in valid.items() if key != missing}
                        for missing in ('items', 'totalSize', 'offset', 'limit'))
        for payload in payloads:
            with self.subTest(payload=payload):
                self.assert_unavailable([payload])

    def test_short_empty_or_oversized_page_is_unavailable(self):
        payloads = [page([movie(42, 31)], total=2), page([], total=1),
                    page([movie(i, 1000 + i) for i in range(1, 102)], total=101)]
        for payload in payloads:
            with self.subTest(count=len(payload['items'])):
                self.assert_unavailable([payload])

    def test_changed_total_or_incorrect_later_offset_is_unavailable(self):
        first = [movie(i, 1000 + i) for i in range(1, 101)]
        for second in (page([movie(101, 31)], total=102, offset=100),
                       page([movie(101, 31)], total=101, offset=0)):
            with self.subTest(second=second):
                self.assert_unavailable([page(first, total=101), second])

    def test_repeated_item_within_page_is_unavailable(self):
        self.assert_unavailable([page([movie(42, 31), movie(42, 31)])])

    def test_repeated_item_across_pages_is_unavailable(self):
        first = [movie(i, 1000 + i) for i in range(1, 101)]
        self.assert_unavailable([page(first, total=101),
                                 page([movie(1, 31)], total=101, offset=100)])

    def test_malformed_inventory_item_is_unavailable(self):
        invalid = [None, [], {**movie(42, 31), 'id': True},
                   {**movie(42, 31), 'id': '0'}, {**movie(42, 31), 'id': 'bad'},
                   {**movie(42, 31), 'type': 'show'},
                   {**movie(42, 31), 'type': 'episode'},
                   {**movie(42, 31), 'providerIds': []},
                   {**movie(42, 31), 'providerIds': {'tmdb': '31'}}]
        invalid.extend({**movie(42, 31), 'providerIds': {'tmdb': [value]}}
                       for value in (None, True, 0, -1, 3.1, '', '0', '-1', 'bad'))
        for row in invalid:
            with self.subTest(row=row):
                self.assert_unavailable([page([row])])

    def test_empty_provider_list_cannot_establish_match(self):
        row = {**movie(42, 31), 'providerIds': {'tmdb': []}}
        self.assertIsNone(self.lookup([page([row])])[0])

    def test_page_budget_applies_across_selected_libraries(self):
        with patch.object(forecast, 'PLEX_LOOKUP_MAX_PAGES', 1), \
                patch.object(forecast, '_get_json',
                             side_effect=[page([movie(42, 31)]), page([])]) as fetch:
            with self.assertRaises(forecast.ForecastUnavailable):
                forecast.find_plex_media(settings, {1: group('7'), 5: group('5')},
                                         'movie', 31)
        self.assertEqual(fetch.call_count, 1)

    def test_page_budget_allows_a_complete_last_page(self):
        with patch.object(forecast, 'PLEX_LOOKUP_MAX_PAGES', 1):
            self.assertEqual(self.lookup([page([movie(42, 31)])])[0], (1, '42'))

    def test_elapsed_budget_stops_before_another_request(self):
        clock = {'now': 0}
        first = [movie(1, 31)] + [movie(i, 1000 + i) for i in range(2, 101)]

        def fetch_page(_url):
            clock['now'] = 11
            return copy.deepcopy(page(first, total=101))

        with patch.object(forecast.time, 'monotonic', side_effect=lambda: clock['now']), \
                patch.object(forecast, 'PLEX_LOOKUP_SECONDS', 10), \
                patch.object(forecast, '_get_json', side_effect=fetch_page) as fetch:
            with self.assertRaises(forecast.ForecastUnavailable):
                forecast.find_plex_media(settings, {1: group()}, 'movie', 31)
        self.assertEqual(fetch.call_count, 1)

    def test_elapsed_budget_rejects_a_slow_complete_final_page(self):
        clock = {'now': 0}

        def fetch_page(_url):
            clock['now'] = 11
            return page([movie(42, 31)])

        with patch.object(forecast.time, 'monotonic', side_effect=lambda: clock['now']), \
                patch.object(forecast, 'PLEX_LOOKUP_SECONDS', 10), \
                patch.object(forecast, '_get_json', side_effect=fetch_page) as fetch:
            with self.assertRaises(forecast.ForecastUnavailable):
                forecast.find_plex_media(settings, {1: group()}, 'movie', 31)
        self.assertEqual(fetch.call_count, 1)


if __name__ == '__main__':
    unittest.main()
