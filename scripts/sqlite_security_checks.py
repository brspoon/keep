"""Bounded SQLite expression-depth checks and ordinary database controls.

The caller must separately bind the default-loaded library to its reviewed build.
These checks establish behavior, not package signatures or source provenance.
The COLLATE checks adapt upstream sqllimits1-9.1b using a reduced depth limit.
"""
import argparse
from contextlib import closing
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


EXPRESSION_LIMIT = 64
COLLATE_COUNT = 256
MAXIMUM_SECONDS = 12
MAXIMUM_OUTPUT_BYTES = 4096
PROBES = ('collate_depth_raw', 'collate_depth_quoted', 'collate_view_reparse',
          'collation_controls', 'transaction_rollback', 'wal', 'backup_integrity')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def expected_report():
    return {'schema': 1, 'expression_limit': EXPRESSION_LIMIT,
            'collate_count': COLLATE_COUNT, **dict.fromkeys(PROBES, True)}


def validate_report(report):
    expected = expected_report()
    require(type(report) is dict and set(report) == set(expected),
            'SQLite security-probe report fields are incomplete or unexpected')
    for field, value in expected.items():
        require(type(report[field]) is type(value) and report[field] == value,
                'SQLite security-probe report has invalid ' + field)


def unique_object(items):
    result = {}
    for key, value in items:
        require(key not in result, 'SQLite probe output contains duplicate fields')
        result[key] = value
    return result


def collate_expression(quoted=False, count=COLLATE_COUNT):
    require(type(count) is int and 0 < count <= COLLATE_COUNT,
            'SQLite COLLATE probe exceeds its input bound')
    name = '"nocase"' if quoted else 'nocase'
    return "('abc'='ABC'" + (' COLLATE ' + name) * count + ')'


def expect_depth_rejection(database, query):
    import sqlite3
    try:
        database.execute(query).fetchall()
    except sqlite3.Error as error:
        require(getattr(error, 'sqlite_errorcode', None) in
                (sqlite3.SQLITE_ERROR, sqlite3.SQLITE_CORRUPT)
                and 'Expression tree is too large' in str(error),
                'SQLite rejected the COLLATE probe for an unrelated reason')
    else:
        raise ValueError('SQLite did not enforce COLLATE expression depth')


def exercise_collate_depth():
    import sqlite3
    with closing(sqlite3.connect(':memory:')) as database:
        database.setlimit(sqlite3.SQLITE_LIMIT_EXPR_DEPTH, EXPRESSION_LIMIT)
        require(database.getlimit(sqlite3.SQLITE_LIMIT_EXPR_DEPTH) == EXPRESSION_LIMIT,
                'SQLite expression-depth limit is unavailable')
        for quoted in (False, True):
            require(database.execute('SELECT ' + collate_expression(quoted, 4)).fetchone() == (1,),
                    'SQLite short COLLATE expression failed')
            expect_depth_rejection(database, 'SELECT ' + collate_expression(quoted))


def exercise_view_reparse(directory):
    import sqlite3
    path = Path(directory) / 'view.sqlite3'
    with closing(sqlite3.connect(path)) as database:
        # Save a valid view under the ordinary larger limit, then reparse it
        # through a fresh connection with the lower limit already in effect.
        require(database.getlimit(sqlite3.SQLITE_LIMIT_EXPR_DEPTH) > COLLATE_COUNT,
                'SQLite ordinary expression-depth limit is unexpectedly small')
        database.execute('CREATE VIEW keep_collate_view AS SELECT '
                         + collate_expression(True) + ' AS value')
        database.commit()
    with closing(sqlite3.connect(path)) as database:
        database.setlimit(sqlite3.SQLITE_LIMIT_EXPR_DEPTH, EXPRESSION_LIMIT)
        expect_depth_rejection(database, 'SELECT value FROM keep_collate_view')


def exercise_database_controls(directory):
    import sqlite3
    path = Path(directory) / 'ordinary.sqlite3'
    with closing(sqlite3.connect(path)) as database:
        require(database.execute('SELECT ? = ? COLLATE NOCASE, ? = ? COLLATE BINARY',
                ('abc', 'ABC', 'abc', 'ABC')).fetchone() == (1, 0),
                'SQLite collation or parameter control failed')
        require(database.execute('PRAGMA journal_mode=WAL').fetchone() == ('wal',),
                'SQLite WAL mode is unavailable')
        database.execute('CREATE TABLE keep_probe (value TEXT NOT NULL)')
        database.execute('INSERT INTO keep_probe VALUES (?)', ('committed',))
        database.commit()
        database.execute('INSERT INTO keep_probe VALUES (?)', ('rolled back',))
        database.rollback()
        require(database.execute('SELECT value FROM keep_probe').fetchall() == [('committed',)],
                'SQLite transaction rollback failed')
        with closing(sqlite3.connect(':memory:')) as backup:
            database.backup(backup, pages=1, sleep=0)
            require(backup.execute('SELECT value FROM keep_probe').fetchall() == [('committed',)]
                    and backup.execute('PRAGMA integrity_check').fetchone() == ('ok',)
                    and database.execute('PRAGMA integrity_check').fetchone() == ('ok',),
                    'SQLite backup or integrity control failed')


def _exercise():
    exercise_collate_depth()
    with tempfile.TemporaryDirectory(prefix='keep-sqlite-probes-') as directory:
        exercise_view_reparse(directory)
        exercise_database_controls(directory)
    return expected_report()


def exercise_sqlite_security(*, expected_version=None, expected_source_id=None):
    """Use the active Python interpreter in a bounded, isolated child process."""
    require(not any(name in os.environ for name in ('LD_LIBRARY_PATH', 'LD_PRELOAD')),
            'SQLite qualification requires ordinary loading without loader overrides')
    import sqlite3
    with closing(sqlite3.connect(':memory:')) as database:
        version, source_id = database.execute('SELECT sqlite_version(), sqlite_source_id()').fetchone()
    expected_version = version if expected_version is None else expected_version
    expected_source_id = source_id if expected_source_id is None else expected_source_id
    require((version, source_id) == (expected_version, expected_source_id),
            'SQLite probe parent differs from the reviewed runtime identity')
    try:
        result = subprocess.run([sys.executable, '-B', str(Path(__file__).resolve()), '--probe-child'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=MAXIMUM_SECONDS,
            check=True)
    except (OSError, subprocess.SubprocessError) as error:
        raise ValueError('SQLite bounded security or compatibility probes failed') from error
    require(not result.stderr and 0 < len(result.stdout) <= MAXIMUM_OUTPUT_BYTES,
            'SQLite security-probe output is invalid or oversized')
    try:
        output = json.loads(result.stdout, object_pairs_hook=unique_object)
    except (ValueError, UnicodeError) as error:
        raise ValueError('SQLite security-probe output is not valid JSON') from error
    require(type(output) is dict and set(output) == {'version', 'source_id', 'probes'}
            and (output['version'], output['source_id']) == (expected_version, expected_source_id),
            'SQLite probe child differs from the reviewed runtime identity')
    validate_report(output['probes'])
    return output['probes']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--probe-child', action='store_true', required=True)
    parser.parse_args()
    require(not any(name in os.environ for name in ('LD_LIBRARY_PATH', 'LD_PRELOAD')),
            'SQLite probe child refuses loader overrides')
    if sys.platform == 'linux':
        import resource
        resource.setrlimit(resource.RLIMIT_CPU, (8, 8))
        resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024, 256 * 1024 * 1024))
        resource.setrlimit(resource.RLIMIT_FSIZE, (8 * 1024 * 1024, 8 * 1024 * 1024))
    import sqlite3
    with closing(sqlite3.connect(':memory:')) as database:
        version, source_id = database.execute('SELECT sqlite_version(), sqlite_source_id()').fetchone()
    print(json.dumps({'version': version, 'source_id': source_id, 'probes': _exercise()}, sort_keys=True))


if __name__ == '__main__':
    main()
