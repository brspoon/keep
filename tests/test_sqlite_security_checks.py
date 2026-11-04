"""Bounded COLLATE regression probes and ordinary SQLite compatibility."""
from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from scripts import sqlite_security_checks as checks


class SQLiteSecurityTests(unittest.TestCase):
    def setUp(self):
        # Hosted Python may use LD_LIBRARY_PATH for its own interpreter. The
        # fixture exercises a clean container environment; dedicated cases
        # below add overrides and verify that the runtime guard rejects them.
        environment = {key: value for key, value in os.environ.items()
                       if key not in {'LD_LIBRARY_PATH', 'LD_PRELOAD'}}
        self.enterContext(patch.dict(os.environ, environment, clear=True))

    def identity(self):
        with closing(sqlite3.connect(':memory:')) as database:
            return database.execute('SELECT sqlite_version(), sqlite_source_id()').fetchone()

    def child_output(self):
        version, source_id = self.identity()
        return {'version': version, 'source_id': source_id, 'probes': checks.expected_report()}

    def test_retained_report_requires_every_probe_and_exact_types(self):
        checks.validate_report(checks.expected_report())
        for field, value in checks.expected_report().items():
            for mutation in (None, 1 if type(value) is bool else True):
                report = checks.expected_report(); report[field] = mutation
                with self.subTest(field=field, mutation=mutation), self.assertRaises(ValueError):
                    checks.validate_report(report)
        report = checks.expected_report(); report['unreviewed'] = True
        with self.assertRaises(ValueError): checks.validate_report(report)
        report = checks.expected_report(); del report['wal']
        with self.assertRaises(ValueError): checks.validate_report(report)

    def test_collate_input_is_bounded_for_both_parser_forms(self):
        for quoted in (False, True):
            sql = checks.collate_expression(quoted)
            self.assertLess(len(sql), 5000)
            self.assertEqual(sql.count(' COLLATE '), checks.COLLATE_COUNT)
            self.assertIn('COLLATE "nocase"' if quoted else 'COLLATE nocase', sql)
        for value in (0, -1, True, checks.COLLATE_COUNT + 1):
            with self.subTest(count=value), self.assertRaises(ValueError):
                checks.collate_expression(count=value)

    def test_database_controls_use_real_collations_parameters_rollback_wal_and_backup(self):
        with tempfile.TemporaryDirectory() as directory:
            checks.exercise_database_controls(directory)

    def test_an_accepted_or_unrelated_error_is_not_depth_rejection(self):
        with closing(sqlite3.connect(':memory:')) as database:
            with self.assertRaisesRegex(ValueError, 'did not enforce'):
                checks.expect_depth_rejection(database, 'SELECT 1')
            with self.assertRaisesRegex(ValueError, 'unrelated reason'):
                checks.expect_depth_rejection(database, 'SELECT missing_column')

    @unittest.skipUnless(sqlite3.sqlite_version_info >= (3, 54, 0),
                         'Requires a SQLite library containing the COLLATE correction')
    def test_fixed_default_library_rejects_raw_and_quoted_collate_depth(self):
        checks.exercise_collate_depth()

    @unittest.skipUnless(sqlite3.sqlite_version_info >= (3, 54, 0),
                         'Requires a SQLite library containing the COLLATE correction')
    def test_fixed_default_library_rejects_persisted_view_reparse(self):
        with tempfile.TemporaryDirectory() as directory:
            checks.exercise_view_reparse(directory)

    def test_child_uses_active_interpreter_deadline_and_identity(self):
        result = subprocess.CompletedProcess([], 0, json.dumps(self.child_output()).encode(), b'')
        with patch.dict(os.environ, {}, clear=True), patch.object(checks.subprocess, 'run', return_value=result) as run:
            self.assertEqual(checks.exercise_sqlite_security(), checks.expected_report())
        self.assertEqual(run.call_args.args[0], [sys.executable, '-B', str(Path(checks.__file__).resolve()), '--probe-child'])
        self.assertEqual(run.call_args.kwargs['timeout'], checks.MAXIMUM_SECONDS)
        self.assertTrue(run.call_args.kwargs['check'])

    def test_mismatched_parent_or_child_identity_cannot_supply_probe_success(self):
        with patch.object(checks.subprocess, 'run') as run, self.assertRaisesRegex(ValueError, 'parent differs'):
            checks.exercise_sqlite_security(expected_source_id='unreviewed')
        run.assert_not_called()
        for field in ('version', 'source_id'):
            output = self.child_output(); output[field] = 'unreviewed'
            result = subprocess.CompletedProcess([], 0, json.dumps(output).encode(), b'')
            with self.subTest(field=field), patch.object(checks.subprocess, 'run', return_value=result), \
                    self.assertRaisesRegex(ValueError, 'child differs'):
                checks.exercise_sqlite_security()

    def test_child_failures_malformed_output_and_loader_overrides_fail_closed(self):
        for error in (subprocess.TimeoutExpired('probe', checks.MAXIMUM_SECONDS),
                      subprocess.CalledProcessError(1, 'probe')):
            with patch.object(checks.subprocess, 'run', side_effect=error), self.assertRaises(ValueError):
                checks.exercise_sqlite_security()
        for stdout, stderr in ((b'not-json', b''), (b'{}', b''),
                               (b'{"version":"a","version":"b"}', b''),
                               (b'x' * (checks.MAXIMUM_OUTPUT_BYTES + 1), b''),
                               (json.dumps(self.child_output()).encode(), b'unexpected')):
            result = subprocess.CompletedProcess([], 0, stdout, stderr)
            with self.subTest(stdout=stdout[:20]), patch.object(checks.subprocess, 'run', return_value=result), \
                    self.assertRaises(ValueError):
                checks.exercise_sqlite_security()
        for name in ('LD_PRELOAD', 'LD_LIBRARY_PATH'):
            with patch.dict(os.environ, {name: ''}, clear=True), \
                    patch.object(checks.subprocess, 'run') as run, self.assertRaises(ValueError):
                checks.exercise_sqlite_security()
            run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
