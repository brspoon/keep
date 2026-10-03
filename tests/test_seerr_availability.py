import fcntl
import sqlite3
import tempfile
import unittest
from unittest.mock import Mock, patch

import requests
import seerr
from test_keep import keep


def config(key):
    return {'SEERR_URL': 'https://seerr.test/base', 'SEERR_API_KEY': 'secret'}[key]


class AvailabilityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = self.tmp.name + '/queue.sqlite'
        self.store = seerr.Store(self.path)
        self.clock = patch.object(seerr.time, 'time', return_value=100).start()
        self.addCleanup(patch.stopall)

    def rows(self):
        with sqlite3.connect(self.path) as db:
            return db.execute('SELECT generation,due,failures FROM seerr_availability_queue').fetchall()

    def test_burst_is_durable_coalesced_and_delayed(self):
        for _ in range(3):
            self.store.queue_availability(config)
        with patch.object(seerr.Client, 'sync_availability', return_value=True) as call:
            self.assertIsNone(self.store.process_availability(config))
            call.assert_not_called()
            self.clock.return_value = 131
            self.assertTrue(seerr.Store(self.path).process_availability(config))
            call.assert_called_once()
            self.assertEqual(self.rows(), [])

    def test_running_job_is_not_counted_as_new_sync(self):
        self.store.queue_availability(config)
        self.clock.return_value = 131
        with patch.object(seerr.Client, 'sync_availability', return_value=False):
            self.assertFalse(self.store.process_availability(config))
        self.assertEqual(self.rows(), [(1,161,0)])

    def test_concurrent_deletion_is_not_lost(self):
        self.store.queue_availability(config)
        self.clock.return_value = 131
        def dispatch():
            self.store.queue_availability(config)
            return True
        with patch.object(seerr.Client, 'sync_availability', side_effect=dispatch):
            self.store.process_availability(config)
        self.assertEqual(self.rows(), [(2,161,0)])

    def test_outage_retries_with_bounded_backoff(self):
        self.store.queue_availability(config)
        with patch.object(seerr.Client, 'sync_availability', side_effect=requests.Timeout):
            for attempt in range(9):
                self.clock.return_value = self.rows()[0][1]
                now = self.clock.return_value
                with self.assertRaises(requests.Timeout):
                    self.store.process_availability(config)
                self.assertEqual(self.rows()[0][1], now + min(60*2**attempt,3600))

    def test_unconfigured_and_changed_connection(self):
        self.assertFalse(self.store.queue_availability(lambda _: ''))
        self.store.queue_availability(config)
        self.clock.return_value = 131
        with patch.object(seerr.Client, 'sync_availability') as call:
            self.store.process_availability(lambda _: '')
            call.assert_not_called()
        self.assertEqual(self.rows(), [])

    def test_worker_lock_blocks_duplicate_dispatch(self):
        self.store.queue_availability(config)
        self.clock.return_value = 131
        with open(self.path+'.seerr-availability.lock','a') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            with patch.object(seerr.Client,'sync_availability') as call:
                self.assertIsNone(self.store.process_availability(config))
                call.assert_not_called()

    def test_job_api_only_posts_allowlisted_job_when_idle(self):
        client=seerr.Client(config)
        response=Mock(status_code=200)
        response.__enter__=Mock(return_value=response)
        response.__exit__=Mock(return_value=False)
        with patch.object(client,'get',return_value=[{'id':'availability-sync','running':False}]) as get, patch.object(seerr.requests,'post',return_value=response) as post:
            self.assertTrue(client.sync_availability())
            get.assert_called_once_with('settings/jobs',_list=True)
            self.assertEqual(post.call_args.args[0],'https://seerr.test/base/api/v1/settings/jobs/availability-sync/run')
            self.assertFalse(post.call_args.kwargs['allow_redirects'])
            get.return_value=[{'id':'availability-sync','running':True}]
            self.assertFalse(client.sync_availability())
            self.assertEqual(post.call_count,1)
            for value in ([],[{'id':'availability-sync','running':'false'}]):
                get.return_value=value
                with self.assertRaises(ValueError): client.sync_availability()

    def test_queue_failure_does_not_fail_completed_deletion(self):
        with patch.object(keep,'seerr_store',side_effect=sqlite3.OperationalError('private')):
            keep.queue_seerr_availability()

    def test_jobs_list_response_and_post_failure(self):
        response=Mock(status_code=200)
        response.__enter__=Mock(return_value=response)
        response.__exit__=Mock(return_value=False)
        response.iter_content.return_value=[b'[{"id":"availability-sync","running":false}]']
        client=seerr.Client(config)
        with patch.object(seerr.requests,'get',return_value=response), patch.object(seerr.requests,'post',return_value=response):
            self.assertTrue(client.sync_availability())
        with patch.object(client,'get',return_value=[{'id':'availability-sync','running':False}]), patch.object(seerr.requests,'post',return_value=response):
            response.status_code=403
            with self.assertRaises(seerr.ResponseError): client.sync_availability()
