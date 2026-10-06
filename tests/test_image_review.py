import datetime
import copy
import hashlib
import io
import json
import os
from contextlib import chdir, redirect_stdout
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import review_image
from review_image import assess, deadline_warnings, review_candidate
from inspect_candidate import DIRECT


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

    def test_changed_severity_blocks(self):
        self.report['matches'][0]['vulnerability']['severity'] = 'High'
        self.assertEqual(self.result()['blocked'][0]['reason'], 'exception_mismatch')

    def test_regression_failure_or_wrong_arch_rejected(self):
        for key, value in (('success', False), ('tests', 7), ('failures', 1), ('errors', 1), ('skipped', 1), ('arch', 'arm64'), ('patch_manifest_sha256', 'changed')):
            original = self.evidence[key]; self.evidence[key] = value
            with self.assertRaises(ValueError): self.result()
            self.evidence[key] = original

    def test_needed_exception_passes_on_deadline_and_blocks_afterward(self):
        self.assertFalse(self.result(datetime.date(2026, 10, 7))['blocked'])
        result = self.result(datetime.date(2026, 10, 8))
        self.assertFalse(result['accepted_fixed'])
        self.assertEqual(result['blocked'][0]['reason'], 'exception_expired')
        self.assertEqual(result['blocked'][0]['deadline'], '2026-10-07')

    def test_clean_scan_passes_after_deadline_with_unused_expired_exceptions(self):
        self.report['matches'] = []
        for day in (datetime.date(2026, 10, 8), datetime.date(2099, 1, 1)):
            with self.subTest(day=day):
                self.assertFalse(self.result(day)['blocked'])

    def test_clean_scan_passes_after_deadline_with_no_exceptions(self):
        self.policy['exceptions'] = {}
        self.report['matches'] = []
        self.assertFalse(self.result(datetime.date(2026, 10, 8))['blocked'])

    def test_expired_unused_exception_does_not_block_a_needed_current_exception(self):
        self.policy['exceptions']['CVE-2026-85091']['review']['deadline'] = '2026-09-01'
        self.assertFalse(self.result(datetime.date(2026, 10, 7))['blocked'])

    def test_each_exception_uses_its_own_deadline(self):
        self.policy['exceptions']['CVE-2026-17084']['review']['deadline'] = '2026-09-07'
        self.assertFalse(self.result()['blocked'])
        self.assertEqual(self.result(datetime.date(2026, 9, 8))['blocked'][0]['reason'], 'exception_expired')

    def test_original_approval_limits_and_deadlines_are_preserved(self):
        self.assertNotIn('expires', self.policy)
        self.assertEqual(len(self.policy['exceptions']), 9)
        for rule in self.policy['exceptions'].values():
            self.assertEqual(rule['status'], 'fixed')
            self.assertEqual(rule['review']['deadline'], '2026-10-07')
            self.assertIn('No additional risk acceptance or deadline extension', rule['review']['approval'])

    def test_missing_or_invalid_review_metadata_is_rejected(self):
        original = copy.deepcopy(self.policy)
        for field in ('deadline', 'approval', 'remove_when'):
            with self.subTest(field=field):
                del self.policy['exceptions']['CVE-2026-17084']['review'][field]
                with self.assertRaises(ValueError): self.result()
                self.policy = copy.deepcopy(original)
        self.policy['exceptions']['CVE-2026-17084']['review']['deadline'] = 'invalid'
        with self.assertRaisesRegex(ValueError, 'invalid review deadline'): self.result()

    def test_unfixed_exception_is_rejected(self):
        self.policy['exceptions']['CVE-2026-17084']['status'] = 'accepted-risk'
        with self.assertRaisesRegex(ValueError, 'only verified-fixed'): self.result()

    def test_unreviewed_base_and_architecture_are_rejected(self):
        self.policy['base'] = 'sha256:' + '0' * 64
        with self.assertRaisesRegex(ValueError, 'Unreviewed base'): self.result()
        self.policy['base'] = json.loads((ROOT / 'docs/image-exceptions.json').read_text())['base']
        with self.assertRaisesRegex(ValueError, 'architecture'):
            assess(self.report, self.scout, self.evidence, self.policy, 'other')

    def test_any_scout_finding_blocks(self):
        self.scout['runs'][0]['results'] = [{'ruleId': 'CVE-2026-17084'}]
        self.assertTrue(self.result()['scout_blocked'])

    def test_missing_scout_results_rejected(self):
        self.scout['runs'] = [{}]
        with self.assertRaises(ValueError): self.result()

    def test_incomplete_scans_are_rejected_even_when_no_findings_remain(self):
        self.report['matches'] = []
        for report in (None, {}, {'matches': None}, {'matches': {}}, {'matches': [{}]},
                       {'matches': [], 'ignoredMatches': [{'vulnerability': {}}]}):
            with self.subTest(report=report):
                with self.assertRaises(ValueError):
                    assess(report, self.scout, self.evidence, self.policy, 'amd64', datetime.date(2026, 10, 8))
        for scout in (None, {}, {'runs': []}, {'runs': {}}, {'runs': [None]},
                      {'runs': [{'results': None}]},
                      {'runs': [{'results': [], 'invocations': [None]}]},
                      {'runs': [{'results': [], 'invocations': {}}]},
                      {'runs': [{'results': [], 'invocations': [{'executionSuccessful': False}]}]}):
            with self.subTest(scout=scout):
                with self.assertRaises(ValueError):
                    assess(self.report, scout, self.evidence, self.policy, 'amd64', datetime.date(2026, 10, 8))

    def test_clean_scan_still_requires_successful_runtime_probes(self):
        self.report['matches'] = []
        self.evidence['success'] = False
        with self.assertRaisesRegex(ValueError, 'regression evidence'):
            self.result(datetime.date(2026, 10, 8))

    def test_deadline_warnings_start_fourteen_days_ahead_and_include_expired(self):
        original = copy.deepcopy(self.policy)
        self.assertFalse(deadline_warnings(self.policy, datetime.date(2026, 9, 22)))
        for day, remaining in ((datetime.date(2026, 9, 23), 14),
                               (datetime.date(2026, 10, 7), 0),
                               (datetime.date(2026, 10, 8), -1)):
            with self.subTest(day=day):
                warnings = deadline_warnings(self.policy, day)
                self.assertEqual(len(warnings), 9)
                self.assertTrue(all(w['days_remaining'] == remaining for w in warnings))
        self.assertEqual(self.policy, original)

    def test_warning_window_can_be_configured_and_empty_policy_is_quiet(self):
        self.assertFalse(deadline_warnings(self.policy, datetime.date(2026, 10, 5), 1))
        self.assertEqual(len(deadline_warnings(self.policy, datetime.date(2026, 10, 5), 2)), 9)
        with self.assertRaises(ValueError): deadline_warnings(self.policy, warning_days=-1)
        self.policy['exceptions'] = {}
        self.assertEqual(deadline_warnings(self.policy, datetime.date(2026, 10, 8)), [])

    def test_deadline_check_rejects_malformed_top_level_policy(self):
        for field in ('base', 'approval', 'reviewed_sources', 'exceptions'):
            with self.subTest(field=field):
                policy = copy.deepcopy(self.policy)
                del policy[field]
                with self.assertRaises(ValueError): deadline_warnings(policy)
        with self.assertRaises(ValueError): deadline_warnings({'exceptions': {}})
        self.policy['reviewed_sources']['Dockerfile'] = 'invalid'
        with self.assertRaisesRegex(ValueError, 'source hashes'): deadline_warnings(self.policy)

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


class CandidateReviewTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.policy = json.loads((ROOT / 'docs/image-exceptions.json').read_text())
        self.write('docs/image-exceptions.json', self.policy)
        for name in self.policy['reviewed_sources']:
            destination = self.root / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes((ROOT / name).read_bytes())
        for arch in DIRECT:
            self.write(f'candidate-{arch}.json', {'matches': []})
            self.write(f'candidate-scout-{arch}.json', {'runs': [{'results': []}]})
            self.write(f'candidate-provenance-{arch}.json', {
                'predicateType': 'https://slsa.dev/provenance/v1',
                'subject': [{'digest': {'sha256': DIRECT[arch][0]}}]})
            self.write(f'candidate-regression-{arch}.json', {
                'success': True, 'tests': 9, 'failures': 0, 'errors': 0,
                'skipped': 0, 'arch': arch,
                'patch_manifest_sha256': self.policy['reviewed_sources']['scripts/python_security_patches.json']})

    def write(self, name, record):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(record))

    def test_clean_candidate_requires_valid_source_hashes_on_both_architectures(self):
        for name in self.policy['reviewed_sources']:
            original = (self.root / name).read_bytes()
            (self.root / name).write_bytes(original + b'changed')
            for arch in DIRECT:
                with self.subTest(source=name, arch=arch):
                    with self.assertRaisesRegex(ValueError, 'changed; verified-fixed review'):
                        review_candidate(arch, self.root, datetime.date(2026, 10, 8))
            (self.root / name).write_bytes(original)

    def test_invalid_provenance_rejected_on_both_architectures(self):
        for arch in DIRECT:
            for provenance in ({}, {'predicateType': 'wrong', 'subject': [{'digest': {'sha256': DIRECT[arch][0]}}]},
                               {'predicateType': 'https://slsa.dev/provenance/v1', 'subject': []},
                               {'predicateType': 'https://slsa.dev/provenance/v1', 'subject': [{'digest': {'sha256': 'changed'}}]}):
                with self.subTest(arch=arch, provenance=provenance):
                    self.write(f'candidate-provenance-{arch}.json', provenance)
                    with self.assertRaisesRegex(ValueError, 'provenance'):
                        review_candidate(arch, self.root, datetime.date(2026, 10, 8))

    def test_check_only_preserves_original_bytes_for_pass_and_failure(self):
        for arch in DIRECT:
            for finding in (None, 'CVE-2026-17084', 'CVE-2099-1234'):
                with self.subTest(arch=arch, finding=finding):
                    matches = [] if finding is None else [{
                        'vulnerability': {'id': finding, 'severity': 'Medium'},
                        'artifact': {'type': 'apk', 'name': 'python-3.14', 'version': '3.14.7-r1'}}]
                    self.write(f'candidate-{arch}.json', {'matches': matches})
                    review = self.root / f'candidate-review-{arch}.json'
                    review.write_bytes(b'{ "original": true }\n\n')
                    files = {p: p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
                    with chdir(self.root), patch.object(review_image, 'current_day', return_value=datetime.date(2026, 10, 8)), redirect_stdout(io.StringIO()):
                        self.assertEqual(review_image.main([arch, '--check-only']), int(finding is not None))
                    self.assertEqual(files, {p: p.read_bytes() for p in self.root.rglob('*') if p.is_file()})

    def test_check_only_does_not_create_review_evidence(self):
        with chdir(self.root), redirect_stdout(io.StringIO()):
            self.assertEqual(review_image.main(['amd64', '--check-only']), 0)
        self.assertFalse((self.root / 'candidate-review-amd64.json').exists())

    def test_expired_deadline_cli_warns_without_blocking_or_changing_policy(self):
        original = (self.root / 'docs/image-exceptions.json').read_bytes()
        summary = self.root / 'summary.md'
        output = io.StringIO()
        with chdir(self.root), patch.object(review_image, 'current_day', return_value=datetime.date(2026, 10, 8)), patch.dict(os.environ, {'GITHUB_STEP_SUMMARY': str(summary)}), redirect_stdout(output):
            self.assertEqual(review_image.main(['--check-deadlines']), 0)
        self.assertEqual(output.getvalue().count('::warning::'), 9)
        self.assertIn('review deadline 2026-10-07', summary.read_text())
        self.assertIn('Unused exceptions do not block a clean scan', summary.read_text())
        self.assertEqual((self.root / 'docs/image-exceptions.json').read_bytes(), original)
