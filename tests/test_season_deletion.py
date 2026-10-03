import copy
import time
import unittest
import fcntl
from pathlib import Path
from unittest.mock import Mock, patch

import media_services
import seerr
from test_keep import keep
import test_movie_deletion as movie_tests


def history():
    return {'state': 'current', 'users': [{'id':10,'plex_id':'8','label':'Private'}, {'id':11,'plex_id':'9','label':'Other'}],
            'requests': [{'id':1,'kind':'tv','tmdb':200,'tvdb':300,'user':10,'status':2,'is4k':False,
                          'seasons':[{'number':0,'status':2},{'number':1,'status':2}]},
                         {'id':2,'kind':'tv','tmdb':200,'tvdb':300,'user':11,'status':2,'is4k':False,
                          'seasons':[{'number':2,'status':2}]}]}


def series():
    return {'id':22,'title':'A show','tvdbId':300,'path':'/shows/A show','rootFolderPath':'/shows',
            'statistics':{'episodeFileCount':4,'sizeOnDisk':400},
            'seasons':[{'seasonNumber':n,'monitored':True,'statistics':{'episodeFileCount':1}} for n in (0,1,2,3)]}


def inventory():
    return {n:{'number':n,'fileIds':[n+100],'episodeIds':[n+200],'monitoredEpisodeIds':[n+200],
               'episodes':2 if n==1 else 1,'bytes':100,'fingerprint':str(n)} for n in (0,1,2,3)}


class SeasonPolicyTests(unittest.TestCase):
    def allowed(self, data=None, number=1, identities=None):
        return seerr.season_deletion_access(data or history(), {10:{'plex_id':'8'}} if identities is None else identities,
                                           300, number, '8')[0]

    def test_explicit_scope_not_series_ownership_and_specials(self):
        self.assertTrue(self.allowed(number=0))
        self.assertTrue(self.allowed())
        self.assertFalse(self.allowed(number=2))
        self.assertFalse(self.allowed(number=3))
        for value in (-1, True, '1', None):
            self.assertFalse(self.allowed(number=value))

    def test_shared_season_all_statuses_and_quality_variants(self):
        for status in range(1,6):
            data=history()
            data['requests'].append({**data['requests'][0],'id':3,'user':11,'status':status,'is4k':True})
            self.assertFalse(self.allowed(data))

    def test_both_request_and_season_must_be_approved(self):
        for request_status in range(1,6):
            for season_status in range(1,6):
                data=history(); data['requests'][0]['status']=request_status
                data['requests'][0]['seasons'][1]['status']=season_status
                self.assertEqual(self.allowed(data), request_status in (2,5) and season_status in (2,5))

    def test_ambiguous_unlinked_stale_empty_and_wrong_ids(self):
        for state in ('stale','unavailable',None):
            self.assertFalse(self.allowed({**history(),'state':state}))
        self.assertFalse(self.allowed(identities={}))
        self.assertFalse(self.allowed(identities={10:{'plex_id':'8'},11:{'plex_id':'8'}}))
        data=history(); data['requests'][1]['seasons']=[]
        self.assertFalse(self.allowed(data))
        data=history(); data['requests'][0]['tvdb']=None
        self.assertFalse(self.allowed(data))


class SeasonInventoryTests(unittest.TestCase):
    def setUp(self):
        self.files=[{'id':101,'seriesId':22,'seasonNumber':1,'size':100,'path':'/shows/A/season1.mkv'}]
        self.episodes=[{'id':i,'seriesId':22,'seasonNumber':1,'episodeFileId':101,'hasFile':True,'monitored':True} for i in (1,2)]

    def get(self):
        with patch.object(media_services,'_request',side_effect=[Mock(json=lambda:self.files),Mock(json=lambda:self.episodes)]):
            return media_services.season_inventory(22,lambda _: '')

    def test_multi_episode_file_counted_and_deleted_once(self):
        result=self.get()[1]
        self.assertEqual(result['episodes'],2)
        self.assertEqual(result['fileIds'],[101])
        self.assertEqual(result['bytes'],100)

    def test_cross_season_file_is_denied(self):
        self.episodes[1]['seasonNumber']=2
        with self.assertRaises(ValueError): self.get()

    def test_orphan_duplicate_foreign_and_incomplete_inventories_deny(self):
        original_files, original_episodes=copy.deepcopy(self.files),copy.deepcopy(self.episodes)
        for mutation in ('orphan','duplicate-file','duplicate-episode','foreign-file','foreign-episode','missing-file','bad-size','bad-path'):
            self.files,self.episodes=copy.deepcopy(original_files),copy.deepcopy(original_episodes)
            if mutation=='orphan': self.episodes=[]
            if mutation=='duplicate-file': self.files*=2
            if mutation=='duplicate-episode': self.episodes*=2
            if mutation=='foreign-file': self.files[0]['seriesId']=99
            if mutation=='foreign-episode': self.episodes[0]['seriesId']=99
            if mutation=='missing-file': self.files=[]
            if mutation=='bad-size': self.files[0]['size']='100'
            if mutation=='bad-path': self.files[0]['path']=None
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): self.get()

    def test_mutation_changes_preview_fingerprint(self):
        original=self.get()[1]['fingerprint']
        self.files[0]['size']=101
        self.assertNotEqual(original,self.get()[1]['fingerprint'])

    def test_missing_episodes_are_in_monitoring_scope_not_file_count(self):
        self.episodes.append({'id':3,'seriesId':22,'seasonNumber':1,'episodeFileId':0,'hasFile':False,'monitored':True})
        result=self.get()[1]
        self.assertEqual(result['episodes'],2)
        self.assertEqual(result['episodeIds'],[1,2,3])
        self.assertEqual(result['monitoredEpisodeIds'],[1,2,3])
        for row in self.episodes: row['monitored']=False
        self.assertEqual(self.get()[1]['fingerprint'],result['fingerprint'])
        self.assertEqual(self.get()[1]['monitoredEpisodeIds'],[])

    @patch.object(media_services,'_request')
    def test_only_selected_seasons_and_files_are_written(self, request):
        getter=lambda _: ''
        media_services.unmonitor_seasons(22,[0,2],getter)
        self.assertEqual(request.call_args.args[2:4],('POST','/api/v3/seasonpass'))
        self.assertEqual(request.call_args.kwargs['json'],{'series':[{'id':22,'seasons':[
            {'seasonNumber':0,'monitored':False},{'seasonNumber':2,'monitored':False}]}]})
        media_services.delete_episode_files([101,102],getter)
        self.assertEqual(request.call_args.args[2:4],('DELETE','/api/v3/episodefile/bulk'))
        self.assertEqual(request.call_args.kwargs['json'],{'episodeFileIds':[101,102]})
        media_services.unmonitor_episodes([1,2,3],getter)
        self.assertEqual(request.call_args.args[2:4],('PUT','/api/v3/episode/monitor'))
        self.assertEqual(request.call_args.kwargs['json'],{'episodeIds':[1,2,3],'monitored':False})

    def test_request_budget_prevents_writes_after_deadline(self):
        with media_services.request_budget(-1), patch.object(media_services.requests,'request') as request:
            with self.assertRaises(ValueError):
                media_services.delete_episode_files([1],lambda _: 'configured')
            request.assert_not_called()


class SeasonRouteTests(unittest.TestCase):
    mock=movie_tests.MovieDeletionRouteTests.mock
    update=movie_tests.MovieDeletionRouteTests.update

    def setUp(self):
        movie_tests.MovieDeletionRouteTests.setUp(self)
        self.item=series(); self.fetch.return_value=self.item
        self.live.return_value=history()
        self.cached=self.mock(seerr.Store,'read',return_value=history())
        self.files=inventory()
        self.inv=self.mock(media_services,'season_inventory',side_effect=lambda *a:copy.deepcopy(self.files))
        def unmonitor(sid, numbers, getter):
            for row in self.item['seasons']:
                if row['seasonNumber'] in numbers: row['monitored']=False
        self.unmonitor=self.mock(media_services,'unmonitor_seasons',side_effect=unmonitor)
        def unmonitor_episodes(ids,getter):
            for row in self.files.values():
                row['monitoredEpisodeIds']=[eid for eid in row['monitoredEpisodeIds'] if eid not in ids]
        self.unmonitor_episodes=self.mock(media_services,'unmonitor_episodes',side_effect=unmonitor_episodes)
        def delete(ids, getter):
            for n in list(self.files):
                if set(self.files[n]['fileIds']).issubset(ids): del self.files[n]
        self.delete=self.mock(media_services,'delete_episode_files',side_effect=delete)

    def preview(self):
        response=self.client.get('/api/library/sonarr/22/seasons')
        self.assertEqual(response.status_code,200,response.get_data(as_text=True))
        return response.json

    def post(self, token=None, seasons=None, **extras):
        if token is None: token=self.preview()['token']
        return self.client.post('/api/library/delete',json={'service':'sonarr','itemId':22,'libraryKey':'sonarr:5',
            'previewToken':token,'seasons':[1] if seasons is None else seasons,**extras},headers={'X-CSRF-Token':'test-csrf'})

    def test_filtered_preview_and_success_never_delete_series(self):
        queued=self.mock(keep,'queue_seerr_availability')
        preview=self.preview()
        self.assertEqual([s['number'] for s in preview['seasons']],[0,1])
        self.live.assert_not_called()
        response=self.post(preview['token'])
        self.assertEqual(response.status_code,200,response.json)
        self.assertEqual(response.json['status'],'seasons-deleted')
        queued.assert_called_once_with()
        self.live.assert_called_once()
        self.unmonitor.assert_called_once_with(22,[1],keep.connection_value)
        self.unmonitor_episodes.assert_called_once_with([201],keep.connection_value)
        self.delete.assert_called_once_with([101],keep.connection_value)
        self.remove.assert_not_called()
        self.assertIn(2,self.files); self.assertIn(0,self.files)
        self.assertFalse(self.item['seasons'][1]['monitored'])
        self.assertTrue(self.item['seasons'][2]['monitored'])

    def test_multiple_seasons_and_specials_ignore_client_file_claims(self):
        response=self.post(seasons=[0,1],episodeFileIds=[999],requesterId=999,canDeleteAny=True)
        self.assertEqual(response.status_code,200)
        self.delete.assert_called_once_with([100,101],keep.connection_value)
        self.assertEqual(set(self.files),{2,3})

    def test_changed_live_request_denies_before_any_write(self):
        token=self.preview()['token']
        self.live.return_value['requests'][0]['user']=11
        self.assertEqual(self.post(token).status_code,403)
        self.delete.assert_not_called(); self.unmonitor.assert_not_called()

    def test_tampering_foreign_selection_expiry_and_other_user(self):
        token=self.preview()['token']
        for seasons in ([],[True],[-1],[1,1],['1']):
            self.assertEqual(self.post(token,seasons=seasons).status_code,400)
        self.assertEqual(self.post(token+'x').status_code,409)
        self.assertEqual(self.post(token,seasons=[2]).status_code,409)
        with patch('itsdangerous.timed.time.time',return_value=time.time()+700):
            self.assertEqual(self.post(token).status_code,409)
        with self.client.session_transaction() as session:
            session['plex_user']={**session['plex_user'], 'id':7}
        self.assertEqual(self.post(token).status_code,409)
        self.delete.assert_not_called(); self.unmonitor.assert_not_called()

    def test_changed_files_and_keep_block_without_writes(self):
        token=self.preview()['token']; self.files[1]['fingerprint']='changed'
        self.assertEqual(self.post(token).status_code,409)
        token=self.preview()['token']; self.kept.return_value=True
        self.assertEqual(self.post(token).status_code,409)
        self.delete.assert_not_called(); self.unmonitor.assert_not_called()

    def test_outage_and_revoked_permissions_fail_closed(self):
        token=self.preview()['token']; self.live.side_effect=ValueError('unavailable')
        self.assertEqual(self.post(token).status_code,503)
        self.update("DELETE FROM user_library_permissions WHERE library_key='sonarr:5'")
        self.assertEqual(self.post(token).status_code,403)
        self.delete.assert_not_called(); self.unmonitor.assert_not_called()

    def test_elevated_can_select_unknown_seasons_but_keeps_still_block(self):
        self.update("UPDATE user_profiles SET can_delete_any=1 WHERE plex_id='8'")
        self.assertEqual(len(self.preview()['seasons']),4)
        self.assertEqual(self.post(seasons=[3]).status_code,200)
        self.live.assert_not_called()
        self.kept.return_value=True
        self.assertEqual(self.post(seasons=[2]).status_code,409)

    def test_uncertain_partial_failure_never_claims_success_or_retries(self):
        queued=self.mock(keep,'queue_seerr_availability')
        self.delete.side_effect=keep.requests.Timeout('unknown outcome')
        response=self.post()
        self.assertEqual(response.status_code,502)
        self.assertTrue(response.json['refreshRequired'])
        self.assertIn('some files may have been deleted',response.json['error'])
        queued.assert_not_called()
        self.delete.assert_called_once()
        self.remove.assert_not_called()

    def test_unmonitor_failure_prevents_file_deletion(self):
        self.unmonitor.side_effect=keep.requests.Timeout()
        self.assertEqual(self.post().status_code,502)
        self.delete.assert_not_called()

    def test_revocation_during_unmonitor_prevents_file_deletion(self):
        previous=self.unmonitor.side_effect
        def revoke(*args):
            previous(*args)
            self.update("UPDATE user_profiles SET can_delete_media=0 WHERE plex_id='8'")
        self.unmonitor.side_effect=revoke
        self.assertEqual(self.post().status_code,502)
        self.delete.assert_not_called()

    def test_remaining_files_after_success_response_are_not_success(self):
        self.delete.side_effect=None
        self.assertEqual(self.post().status_code,502)

    def test_episode_monitoring_must_be_verified_before_delete(self):
        self.unmonitor_episodes.side_effect=None
        self.assertEqual(self.post().status_code,502)
        self.delete.assert_not_called()

    def test_changed_files_during_unmonitor_are_never_deleted(self):
        previous=self.unmonitor.side_effect
        def change(*args):
            previous(*args); self.files[1]['fingerprint']='new-file'
        self.unmonitor.side_effect=change
        self.assertEqual(self.post().status_code,502)
        self.delete.assert_not_called()

    def test_new_keep_during_monitoring_change_stops_deletion(self):
        self.kept.side_effect=[False,False,True]
        self.assertEqual(self.post().status_code,502)
        self.delete.assert_not_called()

    def test_stale_history_hides_series_and_denies_preview(self):
        self.cached.return_value['state']='stale'
        self.assertEqual(self.client.get('/api/library/sonarr/22/seasons').status_code,404)
        self.assertEqual(self.client.get('/api/title-details/sonarr/22').status_code,404)
        self.assertEqual(self.client.get('/library/artwork/sonarr/22').status_code,404)

    def test_nested_library_does_not_bypass_scope(self):
        self.update("INSERT INTO media_libraries(library_key,service,external_id,name,path) VALUES ('sonarr:6','sonarr','6','Private','/shows/private')")
        self.item['path']='/shows/private/A show'; self.item['rootFolderPath']='/shows/private'
        self.assertEqual(self.client.get('/api/library/sonarr/22/seasons').status_code,404)
        self.delete.assert_not_called()

    def test_concurrent_deletion_is_rejected_without_writes(self):
        token=self.preview()['token']
        with open(Path(keep.KEEP_DB_PATH).with_suffix('.deletion.lock'),'a') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            self.assertEqual(self.post(token).status_code,409)
        self.delete.assert_not_called(); self.unmonitor.assert_not_called()

    def test_replay_after_deletion_and_missing_csrf_are_rejected(self):
        token=self.preview()['token']
        self.assertEqual(self.post(token).status_code,200)
        self.assertEqual(self.post(token).status_code,409)
        self.assertEqual(self.client.post('/api/library/delete',json={}).status_code,403)
        self.delete.assert_called_once()

    def test_browsing_filters_series_cards_and_direct_access(self):
        self.mock(media_services,'list_media',side_effect=lambda service,_:[self.item] if service=='sonarr' else [])
        page=self.client.get('/library').get_data(as_text=True)
        self.assertIn('Manage seasons',page); self.assertNotIn('>Delete series</button>',page)
        self.assertIn('Details for A show',page)
        self.cached.return_value['requests'][0]['user']=11
        page=self.client.get('/library').get_data(as_text=True)
        self.assertNotIn('Details for A show',page)
        self.assertEqual(self.client.get('/api/library/sonarr/22/seasons').status_code,404)
        self.assertEqual(self.client.get('/api/title-details/sonarr/22').status_code,404)
        self.assertEqual(self.client.get('/library/artwork/sonarr/22').status_code,404)
