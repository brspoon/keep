import os
from pathlib import Path
import sqlite3
import stat
import tempfile
import unittest

import portable_backup


class PortableBackupTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.root.chmod(0o700)
        self.database = self.root / 'keep.sqlite3'
        with sqlite3.connect(self.database) as connection:
            connection.execute('CREATE TABLE state (key TEXT PRIMARY KEY, value TEXT)')
            connection.execute('INSERT INTO state VALUES (?, ?)', ('account', 'before'))

    def tearDown(self):
        self.directory.cleanup()

    def test_backup_includes_live_wal_and_is_private_and_restorable(self):
        writer = sqlite3.connect(self.database)
        self.addCleanup(writer.close)
        writer.execute('PRAGMA journal_mode=WAL')
        writer.execute('INSERT INTO state VALUES (?, ?)', ('pending', 'committed-in-wal'))
        writer.commit()
        self.assertTrue(Path(str(self.database) + '-wal').exists())

        snapshot = self.root / 'keep-backup.sqlite3'
        portable_backup.backup(self.database, snapshot)
        self.assertEqual(stat.S_IMODE(snapshot.stat().st_mode), 0o600)
        with sqlite3.connect(snapshot) as connection:
            self.assertEqual(connection.execute('PRAGMA integrity_check').fetchone(), ('ok',))
            self.assertEqual(connection.execute('SELECT value FROM state WHERE key="pending"').fetchone(),
                             ('committed-in-wal',))

        restored = self.root / 'restored.sqlite3'
        portable_backup.restore(snapshot, restored)
        with sqlite3.connect(restored) as connection:
            rows = connection.execute('SELECT key, value FROM state ORDER BY key').fetchall()
        self.assertEqual(rows, [('account', 'before'), ('pending', 'committed-in-wal')])
        self.assertEqual(stat.S_IMODE(restored.stat().st_mode), 0o600)

    def test_existing_destinations_are_never_overwritten(self):
        existing = self.root / 'keep-backup.sqlite3'
        existing.write_bytes(b'preserve this file')
        with self.assertRaisesRegex(portable_backup.BackupError, 'already exists'):
            portable_backup.backup(self.database, existing)
        self.assertEqual(existing.read_bytes(), b'preserve this file')

        with self.assertRaisesRegex(portable_backup.BackupError, 'already exists'):
            portable_backup.restore(self.database, self.database)
        self.assertTrue(self.database.is_file())

    def test_symlinked_source_and_destination_are_rejected(self):
        source_link = self.root / 'source-link.sqlite3'
        source_link.symlink_to(self.database)
        with self.assertRaisesRegex(portable_backup.BackupError, 'symlink'):
            portable_backup.backup(source_link, self.root / 'snapshot.sqlite3')

        destination_link = self.root / 'destination-link.sqlite3'
        destination_link.symlink_to(self.root / 'missing.sqlite3')
        with self.assertRaisesRegex(portable_backup.BackupError, 'already exists'):
            portable_backup.backup(self.database, destination_link)
        self.assertFalse((self.root / 'missing.sqlite3').exists())

    def test_restore_rejects_symlink_input_and_non_private_directory(self):
        snapshot = self.root / 'snapshot.sqlite3'
        portable_backup.backup(self.database, snapshot)
        input_link = self.root / 'input-link.sqlite3'
        input_link.symlink_to(snapshot)
        with self.assertRaisesRegex(portable_backup.BackupError, 'symlink'):
            portable_backup.restore(input_link, self.root / 'restored.sqlite3')

        self.root.chmod(0o755)
        with self.assertRaisesRegex(portable_backup.BackupError, 'mode 0700'):
            portable_backup.backup(self.database, self.root / 'another.sqlite3')

    def test_relative_paths_work_for_backup_and_restore(self):
        previous_directory = Path.cwd()
        try:
            os.chdir(self.root)
            relative_database = Path('keep.sqlite3')
            relative_snapshot = Path('relative-backup.sqlite3')
            relative_restore = Path('relative-restore.sqlite3')
            portable_backup.backup(relative_database, relative_snapshot)
            portable_backup.restore(relative_snapshot, relative_restore)
            with sqlite3.connect(relative_restore) as connection:
                self.assertEqual(connection.execute('PRAGMA integrity_check').fetchone(), ('ok',))
                self.assertEqual(connection.execute('SELECT value FROM state WHERE key="account"').fetchone(),
                                 ('before',))
        finally:
            os.chdir(previous_directory)

    def test_restore_refuses_orphaned_database_sidecars_without_modifying_them(self):
        snapshot = self.root / 'snapshot.sqlite3'
        portable_backup.backup(self.database, snapshot)
        for suffix in ('-wal', '-shm', '-journal'):
            with self.subTest(suffix=suffix):
                target = self.root / 'restored.sqlite3'
                sidecar = Path(str(target) + suffix)
                sidecar.write_bytes(b'preserve orphaned sidecar')
                with self.assertRaisesRegex(portable_backup.BackupError, 'sidecars'):
                    portable_backup.restore(snapshot, target)
                self.assertFalse(target.exists())
                self.assertEqual(sidecar.read_bytes(), b'preserve orphaned sidecar')
                sidecar.unlink()

    def test_restore_refuses_symlinked_database_sidecars(self):
        snapshot = self.root / 'snapshot.sqlite3'
        portable_backup.backup(self.database, snapshot)
        target = self.root / 'restored.sqlite3'
        sidecar = Path(str(target) + '-wal')
        sidecar.symlink_to(self.root / 'missing-wal')
        with self.assertRaisesRegex(portable_backup.BackupError, 'sidecars'):
            portable_backup.restore(snapshot, target)
        self.assertFalse(target.exists())
        self.assertTrue(sidecar.is_symlink())

    def test_invalid_sqlite_source_fails_without_publishing_partial_file(self):
        invalid = self.root / 'invalid.sqlite3'
        invalid.write_text('not a SQLite database')
        output = self.root / 'snapshot.sqlite3'
        with self.assertRaises(portable_backup.BackupError):
            portable_backup.backup(invalid, output)
        self.assertFalse(output.exists())
        self.assertFalse(list(self.root.glob('.keep-snapshot-*')))

    def test_cli_output_does_not_expose_database_contents(self):
        secret = 'credential-marker-must-not-be-printed'
        with sqlite3.connect(self.database) as connection:
            connection.execute('INSERT INTO state VALUES (?, ?)', ('secret', secret))
        from io import StringIO
        from unittest.mock import patch

        output = StringIO()
        with patch('sys.stdout', output):
            self.assertEqual(portable_backup.main([
                'backup', '--database', str(self.database),
                '--output', str(self.root / 'snapshot.sqlite3')]), 0)
        self.assertNotIn(secret, output.getvalue())


if __name__ == '__main__':
    unittest.main()
