import importlib.util
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path


spec = importlib.util.spec_from_file_location("backup_keep", "scripts/backup_keep.py")
backup_keep = importlib.util.module_from_spec(spec)
spec.loader.exec_module(backup_keep)


class BackupTests(unittest.TestCase):
    def test_backup_copy_integrity_and_retention(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.sqlite3"
            local = root / "local"
            remote = root / "remote"
            with closing(sqlite3.connect(source)) as database, database:
                database.execute("CREATE TABLE example(value TEXT)")
                database.execute("INSERT INTO example VALUES ('preserved')")

            first = local / "keep-2026-01-01_00-00-00.sqlite3"
            backup_keep.atomic_sqlite_backup(source, first)
            backup_keep.verify_database(first)
            with closing(sqlite3.connect(first)) as database:
                self.assertEqual(database.execute("SELECT value FROM example").fetchone()[0],
                                 "preserved")

            copied = remote / first.name
            backup_keep.atomic_copy(first, copied)
            backup_keep.verify_database(copied)

            for index in range(1, 5):
                path = local / f"keep-2026-01-0{index + 1}_00-00-00.sqlite3"
                backup_keep.atomic_copy(first, path)
                path.touch()
            backup_keep.prune(local, 3)
            self.assertEqual(len(list(local.glob("keep-*.sqlite3"))), 3)


if __name__ == "__main__":
    unittest.main()
