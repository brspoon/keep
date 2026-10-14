"""Retiring a helper cannot discard or bypass unfinished recovery state."""
from contextlib import closing
import hashlib
import hmac
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
import uuid

import helper_retirement as retirement


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')


class RetirementTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='keep-retirement-test-')
        self.addCleanup(self.temporary.cleanup)
        self.parent = Path(self.temporary.name).resolve()
        self.root = self.parent / '.maintenance'
        self.root.mkdir(mode=0o700)
        self.database = self.root / 'control.sqlite3'
        with closing(sqlite3.connect(self.database)) as db, db:
            db.executescript('''
                CREATE TABLE enrollment(id INTEGER PRIMARY KEY CHECK(id=1),
                    install_id TEXT NOT NULL,owner_id TEXT NOT NULL,epoch INTEGER NOT NULL,
                    image_json TEXT NOT NULL,target_json TEXT,helper_seen REAL,host_active_request TEXT);
                CREATE TABLE operations(request_id TEXT PRIMARY KEY,payload BLOB NOT NULL,
                    payload_sha256 TEXT UNIQUE NOT NULL,nonce TEXT UNIQUE NOT NULL,state TEXT NOT NULL,
                    config_generation TEXT NOT NULL,created_at REAL NOT NULL);
                CREATE TABLE gate(id INTEGER PRIMARY KEY CHECK(id=1),closed INTEGER NOT NULL,
                    request_id TEXT,drained INTEGER NOT NULL);
                INSERT INTO gate VALUES(1,0,NULL,0);
                CREATE TABLE progress(request_id TEXT PRIMARY KEY,sequence INTEGER NOT NULL,envelope BLOB NOT NULL);
            ''')
        self.database.chmod(0o600)
        self.install_id = str(uuid.uuid4())
        self.request_id = str(uuid.uuid4())
        self.key = bytes.fromhex('a' * 64)

    def write(self, statement, parameters=()):
        with closing(sqlite3.connect(self.database)) as db, db:
            db.execute(statement, parameters)

    def enroll(self, *, epoch=1):
        document = {'install_id': self.install_id, 'owner_id': '7', 'epoch': epoch, 'key': self.key.hex()}
        path = self.root / ('key-' + str(epoch) + '.json')
        path.write_bytes(canonical(document))
        path.chmod(0o600)
        image = {'index_digest': 'sha256:' + 'a' * 64, 'native_digest': 'sha256:' + 'b' * 64,
                 'image_id': 'sha256:' + 'c' * 64, 'version': '2.26.2', 'revision': 'd' * 40,
                 'architecture': 'amd64'}
        self.write('INSERT OR REPLACE INTO enrollment VALUES(1,?,?,?, ?,NULL,NULL,NULL)',
                   (self.install_id, '7', epoch, canonical(image).decode()))

    def signed(self, payload):
        return canonical({'payload': payload, 'mac': hmac.new(self.key, canonical(payload), hashlib.sha256).hexdigest()})

    def operation(self, *, state='completed', phase='success', epoch=1):
        payload = {'protocol': 'keep.maintenance.v1', 'install_id': self.install_id,
            'owner_id': '7', 'epoch': epoch, 'request_id': self.request_id, 'operation': 'restart',
            'credential_version': 3, 'issued_at': 1000, 'expires_at': 1600, 'nonce': '1' * 64,
            'expected': {'index_digest': 'sha256:' + 'a' * 64, 'native_digest': 'sha256:' + 'b' * 64,
                         'image_id': 'sha256:' + 'c' * 64, 'version': '2.26.2', 'revision': 'd' * 40,
                         'architecture': 'amd64'}, 'target': None}
        self.write('INSERT INTO operations VALUES(?,?,?,?,?,?,?)',
            (self.request_id, self.signed(payload), hashlib.sha256(canonical(payload)).hexdigest(),
             payload['nonce'], state, 'e' * 64, 1000))
        if phase is not None:
            progress = {'protocol': 'keep.maintenance.status.v1', 'install_id': self.install_id,
                        'request_id': self.request_id, 'sequence': 7, 'phase': phase, 'result_code': None}
            self.write('INSERT INTO progress VALUES(?,?,?)', (self.request_id, 7, self.signed(progress)))

    def snapshot(self):
        return {path.name: (path.read_bytes(), path.stat().st_mode, path.stat().st_mtime_ns)
                for path in self.root.iterdir() if path.is_file()}

    def check_unchanged(self, *, held=False):
        before = self.snapshot()
        if held:
            with self.assertRaises(retirement.HelperRetirementError):
                retirement.check_retired_helper_state(self.root)
        else:
            retirement.check_retired_helper_state(self.root)
        self.assertEqual(self.snapshot(), before)

    def test_fresh_installation_creates_no_legacy_state(self):
        missing = self.parent / 'fresh' / '.maintenance'
        retirement.check_retired_helper_state(missing)
        self.assertFalse(missing.parent.exists())

    def test_unenrolled_initialized_state_is_passive_and_not_rewritten(self):
        self.check_unchanged()

    def test_idle_enrollment_preserves_identity_key_and_backups(self):
        self.enroll()
        backup = self.parent / 'recovery-backup.sqlite3'
        backup.write_bytes(b'synthetic-protected-database')
        self.check_unchanged()
        self.assertEqual(backup.read_bytes(), b'synthetic-protected-database')

    def test_signed_terminal_success_recovery_and_failure_allow_manual_upgrade(self):
        for phase in ('success', 'recovered', 'failed'):
            with self.subTest(phase=phase):
                self.write('DELETE FROM operations'); self.write('DELETE FROM progress')
                self.enroll(); self.operation(phase=phase)
                self.check_unchanged()

    def test_aborted_pre_cutover_request_is_passive(self):
        self.enroll(); self.operation(state='aborted', phase=None)
        self.check_unchanged()

    def test_completed_recovery_snapshots_and_failed_attempts_are_preserved(self):
        self.enroll(); self.operation(phase='recovered')
        recovery = self.root / 'recovery' / self.request_id
        recovery.mkdir(parents=True, mode=0o700)
        recovery.parent.chmod(0o700)
        failed = recovery / 'failed' / str(uuid.uuid4())
        failed.mkdir(parents=True, mode=0o700)
        failed.parent.chmod(0o700)
        for path in (recovery / 'database.sqlite3', failed / 'keep.sqlite3', failed / 'keep.sqlite3-wal'):
            path.write_bytes(b'synthetic-protected-recovery'); path.chmod(0o600)
        before = {str(path): path.read_bytes() for path in recovery.rglob('*') if path.is_file()}
        self.check_unchanged()
        self.assertEqual({str(path): path.read_bytes() for path in recovery.rglob('*') if path.is_file()}, before)

    def test_foreign_recovery_or_linked_backup_is_held_without_removal(self):
        self.enroll(); self.operation()
        recovery = self.root / 'recovery' / str(uuid.uuid4())
        recovery.mkdir(parents=True, mode=0o700); recovery.parent.chmod(0o700)
        with self.assertRaises(retirement.HelperRetirementError):
            retirement.check_retired_helper_state(self.root)
        self.assertTrue(recovery.is_dir())
        recovery.rmdir()
        recovery = recovery.parent / self.request_id
        recovery.mkdir(mode=0o700)
        outside = self.parent / 'private-backup'
        outside.write_bytes(b'preserve'); outside.chmod(0o600)
        (recovery / 'database.sqlite3').symlink_to(outside)
        with self.assertRaises(retirement.HelperRetirementError):
            retirement.check_retired_helper_state(self.root)
        self.assertEqual(outside.read_bytes(), b'preserve')

    def test_historical_epoch_is_verified_after_key_rotation(self):
        self.enroll(); self.operation()
        self.enroll(epoch=2)
        self.check_unchanged()
        (self.root / 'key-1.json').unlink()
        self.check_unchanged(held=True)

    def test_queued_claimed_unknown_and_unenrolled_operations_hold(self):
        self.enroll()
        for state in ('queued', 'claimed', 'uncertain'):
            with self.subTest(state=state):
                self.write('DELETE FROM operations'); self.write('DELETE FROM progress')
                self.operation(state=state)
                self.check_unchanged(held=True)
        self.write('DELETE FROM enrollment')
        self.check_unchanged(held=True)

    def test_open_gate_with_host_uncertainty_or_inconsistent_gate_holds(self):
        self.enroll()
        self.write('UPDATE enrollment SET host_active_request=?', (self.request_id,))
        self.check_unchanged(held=True)
        self.write('UPDATE enrollment SET host_active_request=NULL')
        for statement in ('UPDATE gate SET closed=1', 'UPDATE gate SET drained=1',
                          "UPDATE gate SET request_id='unfinished'"):
            self.write('UPDATE gate SET closed=0,drained=0,request_id=NULL')
            self.write(statement)
            self.check_unchanged(held=True)

    def test_completed_without_final_signed_progress_is_held(self):
        self.enroll(); self.operation(phase='committed')
        self.check_unchanged(held=True)
        self.write('DELETE FROM progress')
        self.check_unchanged(held=True)

    def test_aborted_post_stop_progress_is_uncertain(self):
        self.enroll(); self.operation(state='aborted', phase='stopping')
        self.check_unchanged(held=True)

    def test_tampered_terminal_progress_and_request_hash_are_held(self):
        self.enroll(); self.operation()
        with closing(sqlite3.connect(self.database)) as db:
            original = db.execute('SELECT envelope FROM progress').fetchone()[0]
        forged = json.loads(original)
        forged['payload']['phase'] = 'recovered'
        self.write('UPDATE progress SET envelope=?', (canonical(forged),))
        self.check_unchanged(held=True)
        self.write('UPDATE progress SET envelope=?', (original,))
        self.write('UPDATE operations SET payload_sha256=?', ('0' * 64,))
        self.check_unchanged(held=True)

    def test_foreign_progress_identity_and_sequence_hold_even_with_valid_mac(self):
        self.enroll(); self.operation()
        progress = {'protocol': 'keep.maintenance.status.v1', 'install_id': self.install_id,
                    'request_id': str(uuid.uuid4()), 'sequence': 7, 'phase': 'success', 'result_code': None}
        self.write('UPDATE progress SET envelope=?', (self.signed(progress),))
        self.check_unchanged(held=True)
        progress['request_id'] = self.request_id
        self.write('UPDATE progress SET sequence=8,envelope=?', (self.signed(progress),))
        self.check_unchanged(held=True)

    def test_malformed_signed_history_cannot_bypass_the_retirement_hold(self):
        self.enroll(); self.operation()
        with closing(sqlite3.connect(self.database)) as db:
            original = json.loads(db.execute('SELECT payload FROM operations').fetchone()[0])['payload']
        for changes in ({'credential_version': True}, {'nonce': 'unknown'}, {'target': {}},
                        {'expires_at': 999}, {'operation': 'other'}, {'unexpected': 'command'}):
            with self.subTest(changes=changes):
                payload = {**original, **changes}
                self.write('UPDATE operations SET payload=?,payload_sha256=?,nonce=?',
                    (self.signed(payload), hashlib.sha256(canonical(payload)).hexdigest(), payload['nonce']))
                self.check_unchanged(held=True)

    def test_existing_empty_sidecar_growth_is_held_after_readonly_inspection(self):
        sidecar = self.root / 'control.sqlite3-wal'
        sidecar.write_bytes(b''); sidecar.chmod(0o600)
        original = retirement._check_records
        def concurrent(db, root):
            result = original(db, root)
            sidecar.write_bytes(b'uncertain-concurrent-write')
            return result
        with patch.object(retirement, '_check_records', side_effect=concurrent), \
             self.assertRaises(retirement.HelperRetirementError):
            retirement.check_retired_helper_state(self.root)
        self.assertEqual(sidecar.read_bytes(), b'uncertain-concurrent-write')

    def test_orphan_progress_missing_gate_and_unknown_schema_are_held(self):
        self.write('INSERT INTO progress VALUES(?,?,?)', (self.request_id, 0, b'{}'))
        self.check_unchanged(held=True)
        self.write('DELETE FROM progress'); self.write('DELETE FROM gate')
        self.check_unchanged(held=True)
        self.write('INSERT INTO gate VALUES(1,0,NULL,0)')
        self.write('CREATE TABLE future_state(value TEXT)')
        self.check_unchanged(held=True)

    def test_pending_wal_is_not_ignored_or_checkpointed(self):
        self.enroll()
        with closing(sqlite3.connect(self.database)) as db, db:
            db.execute('PRAGMA journal_mode=WAL')
            db.execute('UPDATE enrollment SET host_active_request=?', (self.request_id,))
            db.commit()
            self.check_unchanged(held=True)

    def test_unresolved_journal_unknown_file_and_missing_database_hold(self):
        journal = self.root / 'control.sqlite3-journal'
        journal.write_bytes(b'synthetic-pending-recovery'); journal.chmod(0o600)
        self.check_unchanged(held=True)
        journal.unlink()
        unknown = self.root / 'unfinished-state'
        unknown.write_bytes(b'preserve'); unknown.chmod(0o600)
        self.check_unchanged(held=True)
        unknown.unlink(); self.database.unlink()
        self.check_unchanged(held=True)

    def test_corrupt_database_and_key_are_held_without_disclosing_secrets(self):
        self.enroll()
        key = self.root / 'key-1.json'
        key.write_bytes(b'{"key":"synthetic-private-secret"}')
        with self.assertRaises(retirement.HelperRetirementError) as caught:
            retirement.check_retired_helper_state(self.root)
        self.assertNotIn('synthetic-private-secret', str(caught.exception))
        self.database.write_bytes(b'corrupt-records')
        self.check_unchanged(held=True)

    def test_invalid_idle_image_metadata_and_unknown_progress_result_are_held(self):
        self.enroll()
        self.write('UPDATE enrollment SET target_json=?', ('{"version":"2.27.0"}',))
        self.check_unchanged(held=True)
        self.write('UPDATE enrollment SET target_json=NULL,image_json=?', ('{}',))
        self.check_unchanged(held=True)
        self.enroll(); self.operation()
        progress = {'protocol': 'keep.maintenance.status.v1', 'install_id': self.install_id,
                    'request_id': self.request_id, 'sequence': 7, 'phase': 'success', 'result_code': 'unknown'}
        self.write('UPDATE progress SET envelope=?', (self.signed(progress),))
        self.check_unchanged(held=True)

    @unittest.skipUnless(os.name == 'posix', 'POSIX app-container file policy')
    def test_symlink_hardlink_and_untrusted_permissions_are_held(self):
        self.enroll()
        self.root.chmod(0o755)
        self.check_unchanged(held=True)
        self.root.chmod(0o700)
        self.database.chmod(0o644)
        self.check_unchanged(held=True)
        self.database.chmod(0o600)
        target = self.parent / 'outside-control'
        self.database.rename(target)
        self.database.symlink_to(target)
        self.check_unchanged(held=True)
        self.database.unlink(); os.link(target, self.database)
        self.check_unchanged(held=True)

    @unittest.skipUnless(os.name == 'posix', 'POSIX app-container lock policy')
    def test_busy_legacy_helper_lock_prevents_retirement(self):
        import fcntl
        lock = self.root / 'authority.lock'
        lock.write_bytes(b''); lock.chmod(0o600)
        with lock.open('rb') as held:
            fcntl.flock(held.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.check_unchanged(held=True)
        self.check_unchanged()

    def test_database_and_operation_limits_preserve_state(self):
        with patch.object(retirement, 'MAX_DATABASE', 1):
            self.check_unchanged(held=True)
        self.enroll(); self.operation()
        with patch.object(retirement, 'MAX_OPERATIONS', 0):
            self.check_unchanged(held=True)


if __name__ == '__main__':
    unittest.main()
