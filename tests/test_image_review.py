import datetime
import hashlib
import json
from pathlib import Path
import sys
import unittest
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from review_image import assess


class ImageReviewTests(unittest.TestCase):
    def setUp(self):
        self.policy = json.loads((ROOT / 'docs/image-exceptions.json').read_text())
        self.report = {'matches': [{'vulnerability': {'id': 'CVE-2026-17084', 'severity': 'Medium'}, 'artifact': {'name': 'python-3.14', 'type': 'apk', 'version': '3.14.7-r1'}}]}
        self.scout = {'runs': [{'results': []}]}
        self.evidence = {'success': True, 'tests': 9, 'failures': 0, 'errors': 0, 'skipped': 0, 'arch': 'amd64', 'patch_manifest_sha256': self.policy['reviewed_sources']['scripts/python_security_patches.json']}

    def result(self, day=datetime.date(2026, 9, 7)):
        return assess(self.report, self.scout, self.evidence, self.policy, 'amd64', day)

    def test_exact_fixed_package_passes(self):
        self.assertEqual(len(self.result()['accepted_fixed']), 1)
        self.assertFalse(self.result()['blocked'])

    def test_exact_patched_zlib_passes(self):
        self.report['matches'][0] = {
            'vulnerability': {'id': 'CVE-2026-85091', 'severity': 'High'},
            'artifact': {'name': 'zlib', 'type': 'apk', 'version': '1.3.2-r0'},
        }
        self.assertEqual(len(self.result()['accepted_fixed']), 1)
        self.assertFalse(self.result()['blocked'])

    def test_every_reviewed_source_digest_matches_before_ci(self):
        for name, expected in self.policy['reviewed_sources'].items():
            self.assertEqual(hashlib.sha256((ROOT / name).read_bytes()).hexdigest(), expected, name)

    def test_new_finding_even_low_blocks(self):
        self.report['matches'][0]['vulnerability'] = {'id': 'CVE-2099-1234', 'severity': 'Low'}
        self.assertEqual(len(self.result()['blocked']), 1)

    def test_changed_package_or_version_blocks(self):
        for key in ('name', 'version', 'type'):
            package = self.report['matches'][0]['artifact']
            original = package[key]; package[key] = 'changed'
            self.assertEqual(len(self.result()['blocked']), 1)
            package[key] = original

    def test_regression_failure_or_wrong_arch_rejected(self):
        for key, value in (('success', False), ('tests', 7), ('skipped', 1), ('arch', 'arm64'), ('patch_manifest_sha256', 'changed')):
            original = self.evidence[key]; self.evidence[key] = value
            with self.assertRaises(ValueError): self.result()
            self.evidence[key] = original

    def test_expired_review_rejected(self):
        with self.assertRaises(ValueError): self.result(datetime.date(2026, 10, 8))

    def test_any_scout_finding_blocks(self):
        self.scout['runs'][0]['results'] = [{'ruleId': 'CVE-2026-17084'}]
        self.assertTrue(self.result()['scout_blocked'])

    def test_missing_scout_results_rejected(self):
        self.scout['runs'] = [{}]
        with self.assertRaises(ValueError): self.result()

    def test_scanner_download_retries_network_resets_before_checksum_verification(self):
        script = (ROOT / 'scripts/scan_image.sh').read_text()
        self.assertIn('--retry 4 --retry-all-errors --retry-delay 2', script)
        self.assertLess(script.index('--retry 4'), script.index('sha256sum --check --status'))

    def test_read_only_runtime_disables_unused_gunicorn_control_socket(self):
        dockerfile = (ROOT / 'Dockerfile').read_text()
        self.assertIn('CMD ["gunicorn", "--no-control-socket",', dockerfile)
        smoke = (ROOT / 'scripts/smoke_container.sh').read_text()
        self.assertIn('assert_no_control_server_error', smoke)
        self.assertIn('*"Control server error"*)', smoke)
