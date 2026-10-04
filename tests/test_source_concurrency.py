"""Source acquisition concurrency is explicit, bounded and compatible with serial replay."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from source_concurrency import source_workers


class SourceConcurrencyTests(unittest.TestCase):
    def test_default_and_environment_override_are_bounded(self):
        with patch.dict('os.environ', {}, clear=True):
            self.assertEqual(source_workers(), 4)
        for value in ('1', '2', '3', '4'):
            with self.subTest(value=value), patch.dict('os.environ', {'KEEP_SOURCE_DOWNLOAD_WORKERS': value}):
                self.assertEqual(source_workers(), int(value))

    def test_explicit_worker_count_overrides_environment(self):
        with patch.dict('os.environ', {'KEEP_SOURCE_DOWNLOAD_WORKERS': 'invalid'}):
            self.assertEqual(source_workers(1), 1)

    def test_invalid_counts_fail_closed(self):
        for value in (0, 5, -1, True, False, 4.0, '1.5', '', 'unlimited'):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'workers'):
                source_workers(value)
        with patch.dict('os.environ', {'KEEP_SOURCE_DOWNLOAD_WORKERS': '5'}):
            with self.assertRaisesRegex(ValueError, 'workers'):
                source_workers()


if __name__ == '__main__':
    unittest.main()
