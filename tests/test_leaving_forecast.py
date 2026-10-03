import json
import unittest
from datetime import datetime, timezone
from unittest.mock import Mock, patch

import leaving_forecast as forecast
import test_keep
from test_keep import keep


def rule(first, action, seconds, section, operator, row_id):
    return {'id': row_id, 'section': section, 'isActive': True,
            'ruleJson': json.dumps({'firstVal': first, 'action': action,
                                    'customVal': {'value': seconds}, 'operator': operator})}


class ForecastTests(unittest.TestCase):
    def group(self, kind='movie'):
        added = [1, 0] if kind == 'movie' else [2, 0]
        views = [4, 3] if kind == 'movie' else [4, 6]
        rows = [rule(added, 5, 548 * 86400, 0, None, 1),
                rule(views, 2, 0, 0, 0, 2)]
        if kind == 'tv':
            rows.append(rule([0, 16], 5, 180 * 86400, 0, 0, 3))
        rows.append(rule([4, 4], 5, 730 * 86400, 1, 1, 4))
        if kind == 'tv':
            rows.append(rule([0, 16], 5, 365 * 86400, 1, 0, 5))
        return forecast.parse_group({'name': kind, 'libraryId': 7, 'dataType': 'show' if kind == 'tv' else 'movie',
                                     'rules': rows, 'collection': {}})

    def test_movie_or_rule_uses_earliest_eligible_path(self):
        group = self.group()
        now = datetime(2026, 9, 23, tzinfo=timezone.utc)
        values = {'arr_added': datetime(2025, 3, 24, tzinfo=timezone.utc),
                  'views': 0, 'last_viewed': None}
        # The no-play path has a known date; no last watch is needed for its alternative.
        self.assertEqual(forecast.estimate(group, values, now)['days'], 0)
        values['views'] = 1
        values['last_viewed'] = datetime(2025, 9, 23, tzinfo=timezone.utc)
        self.assertEqual(forecast.estimate(group, values, now)['days'], 365)

    def test_tv_requires_episode_age_and_history(self):
        group = self.group('tv')
        now = datetime(2026, 9, 23, tzinfo=timezone.utc)
        values = {'arr_added': datetime(2025, 1, 1, tzinfo=timezone.utc),
                  'views': 0, 'last_viewed': None,
                  'last_episode_added': datetime(2026, 1, 1, tzinfo=timezone.utc)}
        self.assertEqual(forecast.estimate(group, values, now)['days'], 0)
        values['views'] = 1
        values['last_viewed'] = datetime(2025, 9, 23, tzinfo=timezone.utc)
        self.assertEqual(forecast.estimate(group, values, now)['days'], 365)

    def test_missing_input_suppresses_forecast(self):
        with self.assertRaises(forecast.ForecastUnavailable):
            forecast.estimate(self.group(), {'views': 0, 'last_viewed': None})

    def test_unsupported_rule_fails_closed(self):
        group = {'name': 'unexpected', 'libraryId': 7, 'dataType': 'movie',
                 'rules': [rule([4, 4], 4, 730 * 86400, 0, None, 1)]}
        with self.assertRaises(forecast.ForecastUnavailable):
            forecast.parse_group(group)

    def test_live_threshold_filters_short_plays(self):
        settings = lambda key: {'TAUTULLI_URL': 'http://tautulli',
                                'TAUTULLI_API_KEY': 'key'}.get(key)
        pages = [{'response': {'result': 'success', 'data': {'Monitoring': {'movie_watched_percent': '85', 'tv_watched_percent': '90'}}}},
                 {'response': {'result': 'success', 'data': {'data': [{'rating_key': '42', 'percent_complete': 84, 'date': 1,
                            'watched_status': 1},
                           {'rating_key': '42', 'percent_complete': 85, 'date': 2}],
                  'recordsFiltered': 2}}}]
        with patch.object(forecast, '_get_json', side_effect=pages):
            thresholds = forecast.tautulli_thresholds(settings)
            rows = forecast.watched_history(settings, 42, 'movie', thresholds['movie'])
        self.assertEqual(thresholds, {'movie': 85, 'tv': 90})
        self.assertEqual([row['date'] for row in rows], [2])

    def test_plain_criteria_uses_human_scale_durations(self):
        movie = forecast.criteria(self.group())
        show = forecast.criteria(self.group('tv'))
        self.assertIn('about a year and a half', movie[0])
        self.assertIn('2 years', movie[1])
        self.assertIn('about 6 months', show[0])
        self.assertIn('1 year', show[1])
        self.assertNotIn('548 days', ' '.join(movie + show))
        self.assertEqual(movie[0], 'The movie was added to the library about a year and a half ago or earlier and it has never been watched.')
        self.assertEqual(movie[1], 'The movie was last watched 2 years ago or earlier.')
        self.assertEqual(show[0], 'The show was added to the library about a year and a half ago or earlier, none of its episodes have been watched, and its newest episode was added about 6 months ago or earlier.')
        self.assertEqual(show[1], 'The show was last watched 2 years ago or earlier and its newest episode was added 1 year ago or earlier.')
        self.assertNotIn('Radarr', ' '.join(movie + show))
        self.assertNotIn('Sonarr', ' '.join(movie + show))
        self.assertNotIn('Plex', ' '.join(movie + show))

    def test_forecast_countdown_uses_days_nearby_and_years_months_later(self):
        self.assertEqual(forecast.countdown_label(0), 'now')
        self.assertEqual(forecast.countdown_label(1), 'in 1 day')
        self.assertEqual(forecast.countdown_label(59), 'in 59 days')
        self.assertEqual(forecast.countdown_label(60), 'in about 2 months')
        self.assertEqual(forecast.countdown_label(496), 'in about 1 year and 4 months')
        self.assertEqual(forecast.countdown_label(750), 'in about 2 years and 1 month')


class MembershipTests(unittest.TestCase):
    setUp = test_keep.KeepTests.setUp

    def test_kept_provider_ids_and_media_type_drive_badges(self):
        movie = {'mediaServerId': '1', 'mediaData': {'type': 'movie',
                 'providerIds': {'tmdb': ['12'], 'tvdb': ['99']}}}
        show = {'mediaServerId': '2', 'mediaData': {'type': 'show',
                'providerIds': {'tmdb': ['12'], 'tvdb': ['99']}}}
        with keep.app.test_request_context('/library'), \
             patch.object(keep, 'get_collections', return_value={1: 'Movies', 3: 'Shows'}), \
             patch.object(keep, 'get_collection_media', return_value={'items': []}), \
             patch.object(keep, 'get_collection_exclusions', side_effect=lambda cid: {'items': [movie if cid == 1 else show]}), \
             patch.object(keep, 'connection_value', side_effect=lambda key: 'http://maintainerr' if key == 'MAINTAINERR_URL' else None):
            matches = keep.leaving_membership()
        self.assertEqual(matches[('movie', '12')]['state'], 'kept')
        self.assertEqual(matches[('tv', '99')]['state'], 'kept')
        self.assertEqual(len(matches), 2)

    def test_popup_uses_live_threshold_and_last_qualifying_viewer(self):
        group = ForecastTests().group()
        row = {'mediaServerId': '42', 'addDate': '2026-09-01T00:00:00Z'}
        history = [{'rating_key': '42', 'percent_complete': 85, 'date': 1758585600,
                    'friendly_name': 'Alex'}]
        settings = lambda key: {'TAUTULLI_URL': 'http://tautulli',
                                'TAUTULLI_API_KEY': 'key'}.get(key)
        with patch.object(keep, 'connection_value', side_effect=settings), \
             patch.object(keep, 'get_collection_delete_after_days', return_value=30), \
             patch.object(keep, 'get_collections', return_value={1: 'Movies'}), \
             patch.object(forecast, 'read_rules', return_value={1: group}), \
             patch.object(forecast, 'tautulli_thresholds', return_value={'movie': 85, 'tv': 85}), \
             patch.object(forecast, 'watched_history', return_value=history) as watched:
            status = keep.title_forecast({'kind': 'movie', 'external_id': 12, 'title': 'Movie'},
                                         'leaving', 42, 1, {'added': '2025-01-01T00:00:00Z'}, row)
        self.assertEqual(watched.call_args.args[1:], (42, 'movie', 85))
        self.assertEqual(status['state'], 'leaving')
        self.assertEqual(status['viewer'], 'Alex')
        self.assertEqual(status['played'].date().isoformat(), '2025-09-23')

    def test_tv_forecast_requests_plex_xml_episode_dates(self):
        group = ForecastTests().group('tv')
        settings = lambda key: {'TAUTULLI_URL': 'http://tautulli', 'TAUTULLI_API_KEY': 'key',
                                'PLEX_SERVER_URL': 'http://plex', 'PLEX_ADMIN_TOKEN': 'token'}.get(key)
        response = Mock(content=b'<MediaContainer><Video addedAt="1735689600"/></MediaContainer>')
        with patch.object(keep, 'connection_value', side_effect=settings), \
             patch.object(keep, 'get_collections', return_value={3: 'Shows'}), \
             patch.object(forecast, 'read_rules', return_value={3: group}), \
             patch.object(forecast, 'tautulli_thresholds', return_value={'movie': 85, 'tv': 85}), \
             patch.object(forecast, 'watched_history', return_value=[]), \
             patch.object(keep.requests, 'get', return_value=response) as fetch:
            status = keep.title_forecast({'kind': 'tv', 'external_id': 99, 'title': 'Show'},
                                         'leaving', 42, 3, {'added': '2025-01-01T00:00:00Z'},
                                         {'mediaServerId': '42'})
        self.assertEqual(fetch.call_args.kwargs['headers']['Accept'], 'application/xml')
        self.assertIsNotNone(status['forecast'])


if __name__ == '__main__':
    unittest.main()
