import unittest
from pathlib import Path
import xml.etree.ElementTree as ET
from unittest.mock import Mock, patch
import test_keep
from test_keep import keep
import title_details
from flask import render_template


class TitleDetailsTests(unittest.TestCase):
    setUp = test_keep.KeepTests.setUp

    def test_forecast_copy_uses_a_readable_long_wait(self):
        details = title_details.normalize({'title': 'A movie', 'type': 'movie'})
        status = {'state': '', 'forecast': {'days': 496, 'time_label': 'in about 1 year and 4 months'},
                  'connected': True, 'reason': None, 'played': None}
        with keep.app.test_request_context():
            html = render_template('title_details.html', details=details, title_status=status,
                                   keep_status='Not kept', history={'freshness': 'current',
                                   'label': 'No request recorded', 'state': ''})
        self.assertIn('May qualify for Leaving in about 1 year and 4 months', html)
        self.assertIn('Keep checks daily', html)
        self.assertNotIn('next rule check', html)

    def test_missing_watch_history_has_plain_language_explanation(self):
        details = title_details.normalize({'title': 'A movie', 'type': 'movie'})
        status = {'state': '', 'forecast': None, 'connected': False,
                  'reason': "A Leaving estimate needs watch history, which Keep can't check right now.",
                  'played': None}
        with keep.app.test_request_context():
            html = render_template('title_details.html', details=details, title_status=status,
                                   keep_status='Not kept', history={'freshness': 'current',
                                   'label': 'No request recorded', 'state': ''})
        self.assertIn('A Leaving estimate needs watch history', html)
        self.assertNotIn('Tautulli', html)

    def request_details(self, source='leaving', data=None, view=''):
        title_details._cache.clear()
        store = Mock()
        store.read.return_value = {'state':'current', 'requests':[], 'users':[]}
        store.identities.return_value = {}
        with patch.object(keep, 'get_collection_media', return_value={'items':[self.item]}), \
                patch.object(keep, 'get_collection_exclusions', return_value={'items':[self.item]}), \
                patch.object(keep.requests, 'get', return_value=Mock(json=lambda: data or {'title':'A movie', 'summary':'Description', 'type':'movie', 'providerIds':{'tmdb':['100']}})), \
                patch.object(keep, 'seerr_store', return_value=store):
            return self.client.get(f'/api/title-details/{source}/42?collection={self.cid}&view={view}')

    def test_browse_sources_and_escaped_metadata(self):
        for source in ('leaving', 'kept'):
            response = self.request_details(source, {'title':'<script>bad</script>', 'overview':'<img onerror=bad>', 'genres':['Drama']})
            self.assertEqual(response.status_code, 200)
            self.assertIn(b'&lt;script&gt;', response.data)
            self.assertNotIn(b'<script>', response.data)
            self.assertIn('no-store', response.headers['Cache-Control'])

    def test_unknown_collection_and_nonmember_do_not_fetch_metadata(self):
        with patch.object(keep.requests, 'get') as fetch:
            for view in ('', 'core', 'status'):
                self.assertEqual(self.client.get(f'/api/title-details/leaving/42?collection=999&view={view}').status_code, 404)
                with patch.object(keep, 'get_collection_media', return_value={'items':[]}):
                    self.assertEqual(self.client.get(f'/api/title-details/leaving/42?collection={self.cid}&view={view}').status_code, 404)
            fetch.assert_not_called()

    def test_live_maintainerr_genre_shape_on_both_browse_views(self):
        fixtures = [
            ('Wind River', ['Drama', 'Mystery', 'Crime', 'Thriller', 'Western']),
            ('Smokey and the Bandit', ['Comedy', 'Action', 'Adventure']),
        ]
        for source in ('leaving', 'kept'):
            for title, names in fixtures:
                with self.subTest(source=source, title=title):
                    response = self.request_details(source, {'title':title, 'type':'movie',
                        'genres':[{'id':index + 1, 'name':name} for index, name in enumerate(names)]})
                    self.assertEqual(response.status_code, 200)
                    self.assertIn('<p class="details-genres">' + ' · '.join(names) + '</p>', response.get_data(as_text=True))

    def test_empty_and_invalid_genres_do_not_render_separators(self):
        for genres in ([], [None, False, 17, {}, {'name':None}, {'tag':' '}, '', '\t'], 'Drama', {'name':'Drama'}):
            with self.subTest(genres=genres):
                response = self.request_details(data={'title':'No genres','genres':genres})
                self.assertEqual(response.status_code, 200)
                self.assertNotIn('details-genres', response.get_data(as_text=True))

    def test_genre_formats_trim_filter_and_escape(self):
        data = {'genres':[' Drama ', {'name':'Crime'}, {'tag':'Thriller'},
                          {'name':' ', 'tag':' Western '}, None, {}, {'name':42},
                          {'name':'<script>alert(1)</script>'}]}
        self.assertEqual(title_details.normalize(data)['genres'],
                         ['Drama','Crime','Thriller','Western','<script>alert(1)</script>'])
        response = self.request_details(data=data)
        self.assertIn(b'&lt;script&gt;', response.data)
        self.assertNotIn(b'<script>', response.data)
        self.assertEqual(title_details.normalize({'Genre':[{'tag':'Action'}]})['genres'], ['Action'])

    def test_library_permission_checked_before_service_lookup(self):
        with patch.object(keep, 'user_capabilities', return_value={'delete_media':False}), patch.object(keep.media_services, 'get_media') as fetch:
            self.assertEqual(self.client.get('/api/title-details/radarr/1').status_code, 404)
            fetch.assert_not_called()

    def test_library_outside_grant_denied(self):
        library = {'library_key':'radarr:1','service':'radarr','path':'/allowed'}
        with patch.object(keep, 'granted_library_keys', return_value={'radarr:1'}), patch.object(keep, 'media_libraries', return_value=[library]), patch.object(keep.media_services, 'get_media', return_value={'id':1,'hasFile':True,'path':'/private/movie'}):
            self.assertEqual(self.client.get('/api/title-details/radarr/1').status_code, 404)

    def test_seasons_privacy_and_failed_refresh(self):
        store = Mock()
        store.read.return_value = {'state':'unavailable','requests':[
            {'id':1,'kind':'tv','tvdb':200,'user':10,'status':2,'seasons':[{'number':1,'status':2}]},
            {'id':2,'kind':'tv','tvdb':200,'user':11,'status':5,'seasons':[{'number':2,'status':5}]}], 'users':[]}
        store.identities.return_value = {10:{'display_name':'Alex K','email':'secret@example.test','plex_username':'Private Full Name'}}
        library = {'library_key':'sonarr:1','service':'sonarr','path':'/allowed'}
        with patch.object(keep, 'granted_library_keys', return_value={'sonarr:1'}), patch.object(keep, 'media_libraries', return_value=[library]), patch.object(keep.media_services, 'get_media', return_value={'id':1,'title':'Series','tvdbId':200,'path':'/allowed/show','statistics':{'episodeFileCount':12}}), patch.object(keep,'seerr_store',return_value=store):
            response = self.client.get('/api/title-details/sonarr/1')
        self.assertEqual(response.status_code, 200)
        for text in (b'Season 1', b'Season 2', b'Alex K', b'Unlinked requester', b'currently unavailable', b'Multiple people'):
            self.assertIn(text, response.data)
        for text in (b'secret@example', b'Private Full Name', b'delete-media', b'keep-button'):
            self.assertNotIn(text, response.data)
        self.assertNotIn(b'Requests are historical', response.data)
        self.assertNotIn(b'whole-series ownership', response.data)

    def test_guest_redirects(self):
        with self.client.session_transaction() as session:
            session.clear()
        self.assertEqual(self.client.get('/api/title-details/leaving/42?collection=1').status_code, 302)

    def test_normalization_uses_ids_not_titles(self):
        self.assertIsNone(title_details.normalize({'title':'Matching Title'})['external_id'])
        self.assertEqual(title_details.normalize({'title':'Matching Title','tmdbId':100})['kind'], 'unknown')
        self.assertEqual(title_details.normalize({'type':'show','providerIds':{'tvdb':['200']}})['external_id'], 200)
        self.assertIsNone(title_details.positive_id(True))

    def test_runtime_units_and_invalid_values(self):
        for data, expected in (({'runtime':107}, '1h 47m'), ({'duration':6420000}, '1h 47m'),
                               ({'runtime':42,'type':'show'}, '42m per episode'),
                               ({'runtime':True}, ''), ({'runtime':-2}, ''),
                               ({'duration':'bad'}, ''), ({'runtime':float('nan')}, '')):
            self.assertEqual(title_details.normalize(data)['runtime'], expected)

    def test_season_availability_and_request_absence_are_distinct(self):
        import seerr
        data = title_details.normalize({'type':'show','tvdbId':200,'seasons':[
            {'seasonNumber':n,'statistics':{'episodeFileCount':8 if n==1 else 0}} for n in range(4)]})
        snapshot = {'state':'current','requests':[{'id':1,'kind':'tv','tvdb':200,'user':10,'status':2,
                     'seasons':[{'number':2,'status':2}]}]}
        rows = title_details.season_rows(data,snapshot,{},seerr.attribution)
        self.assertEqual([r['number'] for r in rows],[1,2])
        self.assertEqual(rows[0]['availability'],'In library')
        self.assertEqual(rows[0]['history']['label'],'No request recorded')
        self.assertEqual(rows[1]['availability'],'Not in library')
        self.assertIn('Unlinked requester',rows[1]['history']['label'])
        snapshot['state']='unavailable'
        rows = title_details.season_rows(data,snapshot,{},seerr.attribution)
        self.assertEqual(len(rows),4)
        self.assertEqual(rows[0]['history']['label'],'Request history unavailable')

    def test_pending_and_unscoped_seasons_do_not_claim_no_request(self):
        import seerr
        data = title_details.normalize({'type':'show','tvdbId':200,'seasons':[{'seasonNumber':1}]})
        snapshot={'state':'current','requests':[{'id':1,'kind':'tv','tvdb':200,'user':10,'status':1,
                    'seasons':[{'number':1,'status':1}]}]}
        self.assertEqual(title_details.season_rows(data,snapshot,{},seerr.attribution)[0]['history']['label'],
                         'No approved request recorded')
        snapshot['requests'][0]['seasons']=[]
        self.assertEqual(title_details.season_rows(data,snapshot,{},seerr.attribution)[0]['history']['label'],
                         'Season request details unavailable')

    def test_display_cache_ttl_scope_copy_and_bound(self):
        title_details._cache.clear()
        loader=Mock(return_value={'title':'Cached','runtime':90})
        with patch.object(title_details.time,'monotonic',return_value=100):
            first=title_details.cached_metadata(('scope',1),loader)
            first['title']='mutated'
            self.assertEqual(title_details.cached_metadata(('scope',1),loader)['title'],'Cached')
            self.assertEqual(loader.call_count,1)
            title_details.cached_metadata(('different',1),loader)
            self.assertEqual(loader.call_count,2)
        with patch.object(title_details.time,'monotonic',return_value=161):
            title_details.cached_metadata(('scope',1),loader)
            self.assertEqual(loader.call_count,3)
            for number in range(140): title_details.cached_metadata(('scope',number),loader)
            self.assertEqual(len(title_details._cache),128)
        title_details._cache.clear()

    def test_browse_status_reuses_membership_without_unused_keep_inventory_sweeps(self):
        with patch.object(keep,'media_matches_active_keep') as scan:
            self.assertIn(b'details-state-badge leaving">Leaving</span>',self.request_details().data)
            self.item['addDate'] = '2026-09-23T00:00:00Z'
            with patch.object(keep,'get_collection_delete_after_days',return_value=30):
                page = self.request_details().data
                self.assertNotIn(b'>Not kept</span>',page)
                self.assertIn(b'watches enough to count',page)
            self.assertIn(b'details-state-badge kept">Kept</span>',self.request_details('kept').data)
            scan.assert_not_called()

    def test_cached_metadata_never_bypasses_removed_membership(self):
        self.assertEqual(self.request_details().status_code,200)
        with patch.object(keep,'get_collection_media',return_value={'items':[]}), patch.object(keep.requests,'get') as fetch:
            self.assertEqual(self.client.get(f'/api/title-details/leaving/42?collection={self.cid}').status_code,404)
            fetch.assert_not_called()

    def test_repeated_browse_open_reuses_only_metadata_not_membership_or_history(self):
        title_details._cache.clear()
        store=Mock()
        store.read.return_value={'state':'current','requests':[],'users':[]}
        store.identities.return_value={}
        with patch.object(keep,'get_collection_media',return_value={'items':[self.item]}) as membership, \
                patch.object(keep.requests,'get',return_value=Mock(json=lambda:{'title':'Cached movie','type':'movie','runtime':90})) as fetch, \
                patch.object(keep,'seerr_store',return_value=store), \
                patch.object(keep,'media_matches_active_keep') as scan:
            url=f'/api/title-details/leaving/42?collection={self.cid}'
            first=self.client.get(url)
            second=self.client.get(url)
            self.assertNotIn(b'>Not kept</span>',first.data)
            self.assertNotIn(b'details-keep-status',second.data)
            scan.assert_not_called()
            self.assertEqual(fetch.call_count,1)
            self.assertEqual(membership.call_count,2)
            self.assertEqual(store.read.call_count,2)
        title_details._cache.clear()

    def test_core_details_do_not_wait_for_optional_live_status(self):
        with patch.object(keep, 'title_forecast') as forecast, \
                patch.object(keep, 'media_matches_active_keep') as scan:
            for source in ('leaving', 'kept'):
                response = self.request_details(source, view='core')
                self.assertEqual(response.status_code, 200)
                self.assertIn(b'Description', response.data)
                self.assertIn(b'Request history', response.data)
                self.assertIn(b'data-status-url=', response.data)
                self.assertIn(b'view=status', response.data)
                self.assertIn('no-store', response.headers['Cache-Control'])
            forecast.assert_not_called()
            scan.assert_not_called()

    def test_library_core_does_not_wait_for_keep_sweeps_or_watch_forecast(self):
        library = {'library_key':'radarr:1', 'service':'radarr', 'path':'/allowed'}
        with patch.object(keep, 'granted_library_keys', return_value={'radarr:1'}), \
                patch.object(keep, 'media_libraries', return_value=[library]), \
                patch.object(keep.media_services, 'get_media', return_value={'id':1, 'title':'Library movie', 'hasFile':True, 'path':'/allowed/movie'}), \
                patch.object(keep, 'title_forecast') as forecast, \
                patch.object(keep, 'media_matches_active_keep') as scan:
            response = self.client.get('/api/title-details/radarr/1?view=core')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Library movie', response.data)
        self.assertIn(b'Checking Keep status and watch history', response.data)
        forecast.assert_not_called()
        scan.assert_not_called()

    def test_status_followup_rechecks_membership_without_reloading_request_history(self):
        self.assertEqual(self.request_details(view='core').status_code, 200)
        status = {'state':'leaving', 'days':5, 'played':None, 'forecast':None, 'reason':None}
        with patch.object(keep, 'get_collection_media', return_value={'items':[self.item]}) as membership, \
                patch.object(keep, 'seerr_store') as store, \
                patch.object(keep, 'title_forecast', return_value=status), \
                patch.object(keep, 'media_matches_active_keep') as scan:
            response = self.client.get(f'/api/title-details/leaving/42?collection={self.cid}&view=status')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'5 days until possible removal', response.data)
        self.assertNotIn(b'Request history', response.data)
        self.assertIn('no-store', response.headers['Cache-Control'])
        membership.assert_called_once_with(self.cid)
        store.assert_not_called()
        scan.assert_not_called()
        with patch.object(keep, 'get_collection_media', return_value={'items':[]}), \
                patch.object(keep, 'title_forecast') as forecast:
            self.assertEqual(self.client.get(f'/api/title-details/leaving/42?collection={self.cid}&view=status').status_code, 404)
            forecast.assert_not_called()

    def test_library_status_preserves_fresh_keep_checks_and_unknown_on_failure(self):
        library = {'library_key':'radarr:1', 'service':'radarr', 'path':'/allowed'}
        with patch.object(keep, 'granted_library_keys', return_value={'radarr:1'}), \
                patch.object(keep, 'media_libraries', return_value=[library]), \
                patch.object(keep.media_services, 'get_media', return_value={'id':1, 'title':'Library movie', 'tmdbId':100, 'hasFile':True, 'path':'/allowed/movie'}), \
                patch.object(keep, 'title_forecast', return_value={'state':None}), \
                patch.object(keep, 'media_matches_active_keep', side_effect=[False, True, ValueError('offline')]) as scan:
            for label in (b'Not kept', b'Kept', b'Keep status unavailable'):
                response = self.client.get('/api/title-details/radarr/1?view=status')
                self.assertEqual(response.status_code, 200)
                self.assertIn(label, response.data)
            self.assertEqual(scan.call_count, 3)
        with patch.object(keep, 'granted_library_keys', return_value=set()), \
                patch.object(keep.media_services, 'get_media') as fetch:
            self.assertEqual(self.client.get('/api/title-details/radarr/1?view=status').status_code, 404)
            fetch.assert_not_called()

    def test_failed_and_oversized_metadata_are_not_cached(self):
        title_details._cache.clear()
        with self.assertRaises(ValueError):
            title_details.cached_metadata('failure',Mock(side_effect=ValueError('offline')))
        self.assertNotIn('failure',title_details._cache)
        title_details.cached_metadata('large',lambda:{'overview':'x'*70000})
        self.assertNotIn('large',title_details._cache)

    def test_seerr_logo_is_local_versioned_and_passive(self):
        root = Path(__file__).resolve().parents[1]
        svg = ET.fromstring((root / 'static/service-icons/seerr.svg').read_text())
        self.assertEqual(svg.attrib['viewBox'], '0 0 96 96')
        allowed = {'svg', 'path', 'defs', 'linearGradient', 'stop'}
        for node in svg.iter():
            self.assertIn(node.tag.rsplit('}', 1)[-1], allowed)
            self.assertFalse(any(key.lower().startswith('on') or 'href' in key for key in node.attrib))
        self.assertIn('Copyright (c) 2020 sct', (root / 'static/service-icons/seerr-LICENSE.txt').read_text())
        self.assertIn('/static/service-icons/{{ key }}.svg?v={{ app_version }}',
                      (root / 'templates/connections.html').read_text())


if __name__ == '__main__':
    unittest.main()
