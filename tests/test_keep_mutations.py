"""Protection/deletion races with synthetic services and disposable state only."""
import fcntl
import subprocess
import sys
import unittest
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import test_keep
from test_keep import keep


class ProtectionCoordinationTests(unittest.TestCase):
    setUp = test_keep.KeepTests.setUp
    post = test_keep.KeepTests.post

    def test_contended_lock_rejects_all_web_mutations_before_service_writes(self):
        with open(Path(keep.KEEP_DB_PATH).with_suffix('.deletion.lock'), 'a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with patch.object(keep, 'change_maintainerr_exclusion') as change, \
                 patch.object(keep, 'get_collection_media') as inventory:
                for route in ('/api/keep', '/api/update-keep', '/api/remove-kept', '/api/library/delete'):
                    self.assertEqual(self.post(route, {}).status_code, 409, route)
                change.assert_not_called()
                inventory.assert_not_called()

    def test_lock_coordinates_separate_processes_and_releases_after_error(self):
        probe = """
import fcntl, sys
with open(sys.argv[1], 'a') as lock:
 try:
  fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
 except BlockingIOError:
  raise SystemExit(9)
"""
        path = str(Path(keep.KEEP_DB_PATH).with_suffix('.deletion.lock'))
        with self.assertRaisesRegex(RuntimeError, 'synthetic failure'):
            with keep.keep_mutation_lock():
                child = subprocess.run([sys.executable, '-c', probe, path], timeout=5)
                self.assertEqual(child.returncode, 9)
                raise RuntimeError('synthetic failure')
        child = subprocess.run([sys.executable, '-c', probe, path], timeout=5)
        self.assertEqual(child.returncode, 0)

    def test_successful_renewal_survives_stale_expiry_snapshot(self):
        for duration in ('temporary', 'indefinite'):
            with self.subTest(duration=duration):
                keep.record_keeper(self.cid, '42', {'id': 7, 'username': 'Owner'},
                                   now=datetime(2026, 8, 1, tzinfo=timezone.utc))
                renewed = False
                exclusion = {'id': 91, 'mediaServerId': '42', 'mediaData': {'title': 'Synthetic movie'}}
                def read_exclusions(*args):
                    nonlocal renewed
                    if not renewed:
                        renewed = True
                        response = self.post('/api/update-keep', {
                            'collectionId': self.cid, 'mediaId': '42', 'duration': duration})
                        self.assertEqual(response.status_code, 200)
                    return {'items': [exclusion]}
                with patch.object(keep, 'get_collection_exclusions', side_effect=read_exclusions), \
                     patch.object(keep, 'change_maintainerr_exclusion') as release:
                    result = keep.expire_due_keeps(datetime(2026, 9, 10, tzinfo=timezone.utc))
                self.assertEqual(result, {'released': 0, 'missing': 0, 'failed': 0})
                release.assert_not_called()
                with closing(keep.attribution_db()) as db:
                    row = db.execute('SELECT expires_at FROM keep_schedules WHERE collection_id=? AND media_id=?',
                                     (str(self.cid), '42')).fetchone()
                    self.assertIsNotNone(row)
                    if duration == 'indefinite':
                        self.assertIsNone(row['expires_at'])
                    else:
                        self.assertGreater(row['expires_at'], '2026-09-10 00:00:00')
                    self.assertIsNotNone(db.execute('SELECT 1 FROM keep_attribution WHERE collection_id=? AND media_id=?',
                                                   (str(self.cid), '42')).fetchone())

    def test_busy_expiration_preserves_due_state_for_retry(self):
        keep.record_keeper(self.cid, '42', {'id': 7}, now=datetime(2026, 8, 1, tzinfo=timezone.utc))
        with keep.keep_mutation_lock(), \
             patch.object(keep, 'get_collection_exclusions', return_value={'items': [{'mediaServerId': '42'}]}), \
             patch.object(keep, 'change_maintainerr_exclusion') as release:
            result = keep.expire_due_keeps(datetime(2026, 9, 10, tzinfo=timezone.utc))
        self.assertEqual(result, {'released': 0, 'missing': 0, 'failed': 1})
        release.assert_not_called()
        with closing(keep.attribution_db()) as db:
            self.assertIsNotNone(db.execute('SELECT 1 FROM keep_schedules WHERE media_id=?', ('42',)).fetchone())
