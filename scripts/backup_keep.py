#!/usr/bin/env python3
"""Create verified, atomic backups of Keep's SQLite database."""

import argparse
import fcntl
import os
import shutil
import sqlite3
import sys
from contextlib import closing
from datetime import datetime
from pathlib import Path


def verify_database(path):
    with closing(sqlite3.connect(f"file:{path}?mode=ro", uri=True)) as database:
        result = database.execute("PRAGMA integrity_check").fetchone()[0]
    if result != "ok":
        raise RuntimeError(f"integrity check failed for {path}: {result}")


def atomic_sqlite_backup(source, destination):
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    temporary.unlink(missing_ok=True)
    try:
        with closing(sqlite3.connect(f"file:{source}?mode=ro", uri=True)) as source_db, \
                closing(sqlite3.connect(temporary)) as backup_db, source_db, backup_db:
            source_db.backup(backup_db)
        verify_database(temporary)
        os.chmod(temporary, 0o600)
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def atomic_copy(source, destination):
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    temporary.unlink(missing_ok=True)
    try:
        shutil.copy2(source, temporary)
        verify_database(temporary)
        os.chmod(temporary, 0o600)
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def prune(directory, keep):
    backups = sorted(directory.glob("keep-*.sqlite3"), key=lambda path: path.stat().st_mtime,
                     reverse=True)
    for expired in backups[keep:]:
        expired.unlink()


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--local-dir", type=Path, required=True)
    parser.add_argument("--nas-dir", type=Path, required=True)
    parser.add_argument("--nas-mount", type=Path, required=True)
    parser.add_argument("--keep", type=int, default=14)
    return parser.parse_args()


def main():
    args = parse_args()
    if args.keep < 1:
        raise ValueError("--keep must be at least 1")
    if not args.source.is_file():
        raise FileNotFoundError(args.source)

    args.local_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    lock_path = args.local_dir / ".backup.lock"
    with lock_path.open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        stamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        filename = f"keep-{stamp}.sqlite3"
        local_backup = args.local_dir / filename
        atomic_sqlite_backup(args.source, local_backup)
        prune(args.local_dir, args.keep)
        print(f"Verified local backup: {local_backup}")

        if not os.path.ismount(args.nas_mount):
            raise RuntimeError(f"Synology mount is unavailable: {args.nas_mount}")
        nas_backup = args.nas_dir / filename
        atomic_copy(local_backup, nas_backup)
        prune(args.nas_dir, args.keep)
        print(f"Verified Synology backup: {nas_backup}")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"Keep backup failed: {error}", file=sys.stderr)
        raise SystemExit(1)
