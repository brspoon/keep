import sys
from pathlib import Path
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from require_clean_image import require_clean


class CleanImageTests(unittest.TestCase):
    def test_empty_reports_pass(self):
        require_clean({'matches': []}, {'runs': [{'results': []}]})

    def test_even_low_or_unknown_blocks(self):
        for severity in ('Low', 'Unknown', 'Negligible'):
            with self.subTest(severity=severity), self.assertRaises(ValueError):
                require_clean({'matches': [{'vulnerability': {'severity': severity}}]}, {'runs': [{'results': []}]})

    def test_scout_only_finding_blocks(self):
        with self.assertRaises(ValueError):
            require_clean({'matches': []}, {'runs': [{'results': [{'ruleId': 'CVE-test'}]}]})

    def test_missing_report_blocks(self):
        with self.assertRaises((ValueError, KeyError)):
            require_clean({'matches': []}, {'runs': []})
        for run in ({}, {'results': None}, {'results': {}}):
            with self.subTest(run=run), self.assertRaises(ValueError):
                require_clean({'matches': []}, {'runs': [run]})
