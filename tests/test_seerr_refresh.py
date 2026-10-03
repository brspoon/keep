import fcntl
import sqlite3
import unittest
from unittest.mock import patch

import seerr
import test_seerr
from test_seerr import config, snapshot


class AutoRefreshTests(unittest.TestCase):
    setUp = test_seerr.SeerrTests.setUp
    refresh = test_seerr.SeerrTests.refresh

    def test_worker_uses_fresh_settings_and_automatic_refresh(self):
        keep = test_seerr.keep
        with patch.object(keep.connection_settings, 'snapshot', return_value={'SEERR_URL': 'fresh', 'SEERR_API_KEY': 'synthetic'}), patch.object(keep, 'seerr_store') as store, patch.object(keep.connection_settings, 'record_automatic_check', return_value=(0, 0)) as record, patch.object(keep.time, 'sleep', side_effect=RuntimeError('stop')):
            store.return_value.refresh.return_value = {'users': [], 'requests': []}
            with self.assertRaisesRegex(RuntimeError, 'stop'):
                keep.seerr_refresh_worker()
            getter = store.return_value.refresh.call_args.args[0]
            self.assertEqual(getter('SEERR_URL'), 'fresh')
            self.assertEqual(store.return_value.refresh.call_args.kwargs, {'automatic': True})
            self.assertEqual(record.call_args.args[0], 'seerr')
            self.assertTrue(record.call_args.args[2])
    def test_initial_interval_restart_and_changed_connection(self):
        payload = snapshot()
        with patch.object(seerr.Client, 'snapshot', return_value=payload) as fetch, patch('seerr.time.time', return_value=1000):
            self.store.refresh(config, automatic=True)
            self.assertIsNone(seerr.Store(self.store.path).refresh(config, automatic=True))
            self.assertEqual(fetch.call_count, 1)
        with patch.object(seerr.Client, 'snapshot', return_value=payload) as fetch, patch('seerr.time.time', return_value=1900):
            self.store.refresh(config, automatic=True)
            self.assertEqual(fetch.call_count, 1)
            self.store.refresh(lambda k: config(k) + 'changed', automatic=True)
            self.assertEqual(fetch.call_count, 2)

    def test_backoff_retains_history_and_manual_retry_resets(self):
        self.refresh()
        with patch.object(seerr.Client, 'snapshot', side_effect=ValueError('failed')):
            for attempt in range(8):
                with patch('seerr.time.time', return_value=10000 + attempt):
                    with self.assertRaises(ValueError):
                        self.store.refresh(config)
                with sqlite3.connect(self.store.path) as db:
                    due, failures = db.execute('SELECT next_attempt,failures FROM seerr_refresh').fetchone()
                self.assertEqual(failures, attempt + 1)
                self.assertEqual(due, 10000 + attempt + min(60 * 2 ** attempt, 3600))
        self.assertTrue(self.store.read(config)['requests'])
        with patch.object(seerr.Client, 'snapshot', return_value=snapshot()) as fetch, patch('seerr.time.time', return_value=10010):
            self.assertIsNone(self.store.refresh(config, automatic=True))
            fetch.assert_not_called()
            self.store.refresh(config)
        with sqlite3.connect(self.store.path) as db:
            self.assertEqual(db.execute('SELECT failures FROM seerr_refresh').fetchone()[0], 0)

    def test_overlap_and_unconfigured_never_contact_seerr(self):
        with open(self.store.path + '.seerr-refresh.lock', 'a') as lock, patch.object(seerr.Client, 'snapshot') as fetch:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertIsNone(self.store.refresh(config, automatic=True))
            with self.assertRaises(seerr.RefreshBusy):
                self.store.refresh(config)
            fetch.assert_not_called()
        with patch.object(seerr.Client, 'snapshot') as fetch:
            self.assertIsNone(self.store.refresh(lambda key: '', automatic=True))
            fetch.assert_not_called()

    def test_batch_links_validate_before_writing_and_allow_swaps(self):
        self.refresh()
        self.store.save_links(config, {'local:1': 11}, self.profiles, seerr.namespace(config))
        for links, scope in (({'local:1': 10}, seerr.namespace(config)), ({'local:1': 999}, seerr.namespace(config)), ({}, seerr.namespace(config)), ({'local:1': None}, 'old')):
            with self.assertRaises(ValueError):
                self.store.save_links(config, links, self.profiles, scope)
            with sqlite3.connect(self.store.path) as db:
                self.assertEqual(db.execute('SELECT seerr_id FROM seerr_links').fetchone()[0], 11)
        self.store.save_links(config, {'local:1': None}, self.profiles, seerr.namespace(config))
        with sqlite3.connect(self.store.path) as db:
            self.assertEqual(db.execute('SELECT count(*) FROM seerr_links').fetchone()[0], 0)
