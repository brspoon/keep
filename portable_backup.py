"""Create and restore private SQLite snapshots for portable Keep."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import sqlite3
import stat
import tempfile


class BackupError(Exception):
    """A safe backup or restore could not be completed."""


def _regular_file(path: Path, label: str) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError as error:
        raise BackupError(f'{label} does not exist') from error
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise BackupError(f'{label} must be a regular file, not a symlink')


def _private_directory(path: Path) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError as error:
        raise BackupError('Destination directory does not exist') from error
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise BackupError('Destination must be a real directory, not a symlink')
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise BackupError('Destination directory must be owned by this user and have mode 0700')


def _integrity_check(connection: sqlite3.Connection) -> None:
    rows = connection.execute('PRAGMA integrity_check').fetchall()
    if rows != [('ok',)]:
        raise BackupError('SQLite integrity check failed')


def _readonly_connection(path: Path) -> sqlite3.Connection:
    return sqlite3.connect(path.absolute().as_uri() + '?mode=ro', uri=True, timeout=30)


def _snapshot(source: Path, target: Path) -> None:
    _regular_file(source, 'SQLite source')
    _private_directory(target.parent)
    try:
        target.lstat()
    except FileNotFoundError:
        pass
    else:
        raise BackupError('Destination already exists; refusing to overwrite it')

    source_connection = None
    temporary_path = None
    try:
        source_connection = _readonly_connection(source)
        _integrity_check(source_connection)
        descriptor, name = tempfile.mkstemp(prefix='.keep-snapshot-', dir=target.parent)
        temporary_path = Path(name)
        os.fchmod(descriptor, 0o600)
        os.close(descriptor)
        destination_connection = sqlite3.connect(temporary_path, timeout=30)
        try:
            source_connection.backup(destination_connection)
            _integrity_check(destination_connection)
        finally:
            destination_connection.close()
        os.chmod(temporary_path, 0o600)
        with temporary_path.open('rb') as snapshot_file:
            os.fsync(snapshot_file.fileno())
        # A hard link publishes atomically and fails if another process created
        # the destination after the initial existence check.
        os.link(temporary_path, target, follow_symlinks=False)
        temporary_path.unlink()
        temporary_path = None
        directory_fd = os.open(target.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except FileExistsError as error:
        raise BackupError('Destination already exists; refusing to overwrite it') from error
    except sqlite3.Error as error:
        raise BackupError('SQLite backup operation failed') from error
    finally:
        if source_connection is not None:
            source_connection.close()
        if temporary_path is not None:
            try:
                temporary_path.unlink()
            except FileNotFoundError:
                pass


def backup(database: Path, output: Path) -> None:
    """Write an integrity-checked, mode-0600 snapshot without overwriting."""
    _snapshot(database, output)


def restore(input_path: Path, database: Path) -> None:
    """Restore an integrity-checked snapshot to a new database path."""
    for suffix in ('-wal', '-shm', '-journal'):
        sidecar = Path(str(database) + suffix)
        if sidecar.exists() or sidecar.is_symlink():
            raise BackupError('Preserve existing database sidecars before restoring')
    _snapshot(input_path, database)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='operation', required=True)
    backup_parser = commands.add_parser('backup', help='create a private consistent SQLite snapshot')
    backup_parser.add_argument('--database', type=Path, required=True)
    backup_parser.add_argument('--output', type=Path, required=True)
    restore_parser = commands.add_parser('restore', help='restore a verified snapshot to a new database')
    restore_parser.add_argument('--input', type=Path, required=True)
    restore_parser.add_argument('--database', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.operation == 'backup':
            backup(args.database, args.output)
            print('Backup created and integrity checked.')
        else:
            restore(args.input, args.database)
            print('Restore created and integrity checked.')
    except (BackupError, OSError) as error:
        parser.exit(1, f'portable_backup: {error}\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
