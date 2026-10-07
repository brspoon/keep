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
from tests.native_dependency_fixture import dependency_report


PYTHON_FINDINGS = {
    'CVE-2026-87910': 'Medium',
    'CVE-2026-17084': 'Medium',
    'CVE-2026-19672': 'Medium',
    'CVE-2026-15806': 'Medium',
    'CVE-2025-15367': 'Medium',
    'CVE-2026-15310': 'Low',
    'CVE-2026-12345': 'Medium',
}


class ImageReviewTests(unittest.TestCase):
    def setUp(self):
        self.policy = json.loads((ROOT / 'docs/image-exceptions.json').read_text())
        # These fixtures exercise the historical exception matching/deadline rules.
        self.policy['require_zero_findings'] = False
        self.report = {'matches': [{'vulnerability': {'id': 'CVE-2026-17084', 'severity': 'Medium'}, 'artifact': {'name': 'python-3.14', 'type': 'apk', 'version': '3.14.7-r2'}}]}
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

    def test_missing_zero_finding_requirement_preserves_legacy_exception_rules(self):
        del self.policy['require_zero_findings']
        self.assertEqual(len(self.result()['accepted_fixed']), 1)
        self.assertFalse(self.result()['blocked'])

    def test_zero_finding_requirement_must_be_a_boolean_even_for_clean_scans(self):
        self.report['matches'] = []
        for value in (None, 0, 1, 'true', 'false', [], {}):
            with self.subTest(value=value):
                self.policy['require_zero_findings'] = value
                with self.assertRaisesRegex(ValueError, 'must be a boolean'):
                    self.result()
                with self.assertRaisesRegex(ValueError, 'must be a boolean'):
                    deadline_warnings(self.policy)

    def test_zero_finding_policy_blocks_current_and_expired_exact_matches(self):
        self.policy['require_zero_findings'] = True
        for arch in DIRECT:
            for day in (datetime.date(2026, 10, 19), datetime.date(2026, 10, 20),
                        datetime.date(2026, 10, 21)):
                with self.subTest(arch=arch, day=day):
                    result = assess(self.report, self.scout, {**self.evidence, 'arch': arch},
                                    self.policy, arch, day)
                    self.assertFalse(result['accepted_fixed'])
                    self.assertEqual(result['raw_matches'], 1)
                    self.assertEqual(result['blocked'], [{
                        'id': 'CVE-2026-17084', 'package': 'python-3.14',
                        'version': '3.14.7-r2', 'deadline': '2026-10-20',
                        'reason': 'finding_not_permitted',
                    }])

    def test_zero_finding_policy_preserves_unmatched_and_mismatched_rejections(self):
        self.policy['require_zero_findings'] = True
        original = copy.deepcopy(self.report)
        for section, field, value, reason in (
            ('vulnerability', 'id', 'CVE-unknown', 'unmatched_finding'),
            ('vulnerability', 'severity', 'High', 'exception_mismatch'),
            ('artifact', 'name', 'other-python', 'exception_mismatch'),
            ('artifact', 'version', '3.14.7-r1', 'exception_mismatch'),
            ('artifact', 'type', 'python', 'exception_mismatch'),
        ):
            self.report = copy.deepcopy(original)
            self.report['matches'][0][section][field] = value
            with self.subTest(field=field):
                result = self.result(datetime.date(2026, 10, 21))
                self.assertFalse(result['accepted_fixed'])
                self.assertEqual(result['blocked'][0]['reason'], reason)

    def test_zero_finding_policy_clean_scan_passes_with_unused_expired_or_no_exceptions(self):
        self.policy['require_zero_findings'] = True
        self.report['matches'] = []
        for empty in (False, True):
            if empty:
                self.policy['exceptions'] = {}
            with self.subTest(empty_exceptions=empty):
                result = self.result(datetime.date(2026, 10, 21))
                self.assertFalse(result['accepted_fixed'])
                self.assertFalse(result['blocked'])
                self.assertFalse(result['scout_blocked'])

    def test_zero_finding_policy_still_requires_complete_scans_and_runtime_probes(self):
        self.policy['require_zero_findings'] = True
        self.report['matches'] = []
        with self.assertRaisesRegex(ValueError, 'Incomplete Grype finding'):
            assess({'matches': [{}]}, self.scout, self.evidence, self.policy, 'amd64')
        with self.assertRaisesRegex(ValueError, 'Incomplete scan report'):
            assess({'matches': [], 'ignoredMatches': [{}]}, self.scout, self.evidence,
                   self.policy, 'amd64')
        with self.assertRaisesRegex(ValueError, 'Incomplete Scout report'):
            assess(self.report, {'runs': [{'results': [], 'invocations': [
                {'executionSuccessful': False}]}]}, self.evidence, self.policy, 'amd64')
        with self.assertRaisesRegex(ValueError, 'regression evidence'):
            assess(self.report, self.scout, {**self.evidence, 'success': False},
                   self.policy, 'amd64')
        self.scout['runs'][0]['results'] = [{'ruleId': 'any-finding'}]
        self.assertTrue(self.result()['scout_blocked'])

    def test_every_reviewed_source_digest_matches_before_ci(self):
        for name, expected in self.policy['reviewed_sources'].items():
            self.assertEqual(hashlib.sha256((ROOT / name).read_bytes()).hexdigest(), expected, name)

    def test_new_finding_even_low_blocks(self):
        self.report['matches'][0]['vulnerability'] = {'id': 'CVE-2099-1234', 'severity': 'Low'}
        self.assertEqual(len(self.result()['blocked']), 1)

    def test_retired_hardlink_finding_is_unmatched_and_blocks(self):
        self.assertNotIn('CVE-2026-4360', self.policy['exceptions'])
        self.report['matches'][0]['vulnerability']['id'] = 'CVE-2026-4360'
        for version in ('3.14.7-r1', '3.14.7-r2'):
            with self.subTest(version=version):
                self.report['matches'][0]['artifact']['version'] = version
                result = self.result()
                self.assertFalse(result['accepted_fixed'])
                self.assertEqual(len(result['blocked']), 1)
                self.assertEqual(result['blocked'][0]['reason'], 'unmatched_finding')

    def test_changed_package_or_version_blocks(self):
        for key in ('name', 'version', 'type'):
            package = self.report['matches'][0]['artifact']
            original = package[key]; package[key] = 'changed'
            self.assertEqual(len(self.result()['blocked']), 1)
            package[key] = original

    def test_changed_severity_blocks(self):
        self.report['matches'][0]['vulnerability']['severity'] = 'High'
        self.assertEqual(self.result()['blocked'][0]['reason'], 'exception_mismatch')

    def test_old_or_future_vendor_revision_cannot_use_exact_r2_approvals(self):
        for finding, severity in PYTHON_FINDINGS.items():
            for version in ('3.14.7-r1', '3.14.7-r3'):
                with self.subTest(finding=finding, version=version):
                    self.report['matches'][0]['vulnerability'] = {'id': finding, 'severity': severity}
                    self.report['matches'][0]['artifact']['version'] = version
                    result = self.result(datetime.date(2026, 10, 20))
                    self.assertFalse(result['accepted_fixed'])
                    self.assertEqual(result['blocked'][0]['reason'], 'exception_mismatch')

    def test_regression_failure_or_wrong_arch_rejected(self):
        for key, value in (('success', False), ('tests', 7), ('failures', 1), ('errors', 1), ('skipped', 1), ('arch', 'arm64'), ('patch_manifest_sha256', 'changed')):
            original = self.evidence[key]; self.evidence[key] = value
            with self.assertRaises(ValueError): self.result()
            self.evidence[key] = original

    def test_historical_october_seven_deadline_is_inclusive(self):
        self.policy['exceptions']['CVE-2026-17084']['review']['deadline'] = '2026-10-07'
        self.assertFalse(self.result(datetime.date(2026, 10, 7))['blocked'])
        result = self.result(datetime.date(2026, 10, 8))
        self.assertFalse(result['accepted_fixed'])
        self.assertEqual(result['blocked'][0]['reason'], 'exception_expired')
        self.assertEqual(result['blocked'][0]['deadline'], '2026-10-07')

    def test_all_approved_findings_pass_on_october_twenty_and_block_afterward(self):
        self.report['matches'] = [{
            'vulnerability': {'id': finding, 'severity': severity},
            'artifact': {'name': 'python-3.14', 'type': 'apk', 'version': '3.14.7-r2'},
        } for finding, severity in PYTHON_FINDINGS.items()]
        self.report['matches'].append({
            'vulnerability': {'id': 'CVE-2026-85091', 'severity': 'High'},
            'artifact': {'name': 'zlib', 'type': 'apk', 'version': '1.3.2-r0'},
        })
        for arch in DIRECT:
            evidence = {**self.evidence, 'arch': arch}
            for day, expired in ((datetime.date(2026, 10, 20), False),
                                 (datetime.date(2026, 10, 21), True)):
                with self.subTest(arch=arch, day=day):
                    result = assess(self.report, self.scout, evidence, self.policy, arch, day)
                    self.assertEqual(len(result['accepted_fixed']), 0 if expired else 8)
                    self.assertEqual(len(result['blocked']), 8 if expired else 0)
                    for entry in result['blocked']:
                        self.assertEqual(entry['reason'], 'exception_expired')
                        self.assertEqual(entry['deadline'], '2026-10-20')

    def test_clean_scan_passes_after_deadline_with_unused_expired_exceptions(self):
        self.report['matches'] = []
        for day in (datetime.date(2026, 10, 8), datetime.date(2026, 10, 21),
                    datetime.date(2099, 1, 1)):
            with self.subTest(day=day):
                self.assertFalse(self.result(day)['blocked'])

    def test_clean_scan_passes_after_deadline_with_no_exceptions(self):
        self.policy['exceptions'] = {}
        self.report['matches'] = []
        for day in (datetime.date(2026, 10, 8), datetime.date(2026, 10, 21)):
            with self.subTest(day=day):
                self.assertFalse(self.result(day)['blocked'])

    def test_expired_unused_exception_does_not_block_a_needed_current_exception(self):
        self.policy['exceptions']['CVE-2026-85091']['review']['deadline'] = '2026-09-01'
        self.assertFalse(self.result(datetime.date(2026, 10, 20))['blocked'])

    def test_each_exception_uses_its_own_deadline(self):
        self.policy['exceptions']['CVE-2026-17084']['review']['deadline'] = '2026-09-07'
        self.assertFalse(self.result()['blocked'])
        self.assertEqual(self.result(datetime.date(2026, 9, 8))['blocked'][0]['reason'], 'exception_expired')

    def test_approved_scope_and_review_dates_are_exact(self):
        self.assertNotIn('expires', self.policy)
        expected = {finding: (severity, 'apk', 'python-3.14', '3.14.7-r2')
                    for finding, severity in PYTHON_FINDINGS.items()}
        expected['CVE-2026-85091'] = ('High', 'apk', 'zlib', '1.3.2-r0')
        self.assertEqual({finding: tuple(rule[field] for field in
                                        ('severity', 'type', 'package', 'version'))
                          for finding, rule in self.policy['exceptions'].items()}, expected)
        for rule in self.policy['exceptions'].values():
            self.assertEqual(rule['status'], 'fixed')
            self.assertEqual(rule['review']['reviewed_on'], '2026-10-06')
            self.assertEqual(rule['review']['deadline'], '2026-10-20')
            self.assertTrue(rule['review']['approval'].strip())
            self.assertTrue(rule['review']['remove_when'].strip())

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
        self.assertFalse(deadline_warnings(self.policy, datetime.date(2026, 10, 5)))
        for day, remaining in ((datetime.date(2026, 10, 6), 14),
                               (datetime.date(2026, 10, 20), 0),
                               (datetime.date(2026, 10, 21), -1)):
            with self.subTest(day=day):
                warnings = deadline_warnings(self.policy, day)
                self.assertEqual(len(warnings), 8)
                self.assertTrue(all(w['days_remaining'] == remaining for w in warnings))
        self.assertEqual(self.policy, original)

    def test_warning_window_can_be_configured_and_empty_policy_is_quiet(self):
        self.assertFalse(deadline_warnings(self.policy, datetime.date(2026, 10, 18), 1))
        self.assertEqual(len(deadline_warnings(self.policy, datetime.date(2026, 10, 18), 2)), 8)
        with self.assertRaises(ValueError): deadline_warnings(self.policy, warning_days=-1)
        self.policy['exceptions'] = {}
        self.assertEqual(deadline_warnings(self.policy, datetime.date(2026, 10, 21)), [])

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
        self.policy['require_zero_findings'] = False
        self.write('docs/image-exceptions.json', self.policy)
        for name in self.policy['reviewed_sources']:
            destination = self.root / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes((ROOT / name).read_bytes())
        for arch in DIRECT:
            self.write(f'candidate-dependencies-{arch}.json', dependency_report(arch))
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

    def test_zero_finding_candidate_still_requires_provenance_source_and_dependency_evidence(self):
        self.policy['require_zero_findings'] = True
        self.write('docs/image-exceptions.json', self.policy)
        day = datetime.date(2026, 10, 21)
        for arch in DIRECT:
            with self.subTest(arch=arch, evidence='complete'):
                self.assertFalse(review_candidate(arch, self.root, day)['blocked'])
            for name, record, message in (
                (f'candidate-provenance-{arch}.json',
                 {'predicateType': 'https://slsa.dev/provenance/v1',
                  'subject': [{'digest': {'sha256': '0' * 64}}]}, 'provenance'),
                (f'candidate-dependencies-{arch}.json',
                 {**dependency_report(arch), 'success': False, 'failures': 1},
                 'failed native dependency qualification'),
            ):
                path = self.root / name
                original = path.read_bytes()
                self.write(name, record)
                with self.subTest(arch=arch, evidence=name), self.assertRaisesRegex(ValueError, message):
                    review_candidate(arch, self.root, day)
                path.write_bytes(original)
            source = self.root / 'scripts/python_security_patches.json'
            original = source.read_bytes()
            source.write_bytes(original + b'changed')
            with self.subTest(arch=arch, evidence='source'), \
                 self.assertRaisesRegex(ValueError, 'changed; verified-fixed review'):
                review_candidate(arch, self.root, day)
            source.write_bytes(original)

    def test_clean_scan_still_requires_original_dependency_qualification(self):
        for arch in DIRECT:
            path = self.root / f'candidate-dependencies-{arch}.json'
            record = json.loads(path.read_bytes())
            for mutation in ('failed', 'hash', 'architecture'):
                changed = copy.deepcopy(record)
                if mutation == 'failed':
                    changed.update(success=False, failures=1)
                elif mutation == 'hash':
                    changed['loaded_libraries']['expat']['sha256'] = '0' * 64
                else:
                    changed['arch'] = 'unreviewed'
                self.write(path.name, changed)
                with self.subTest(arch=arch, mutation=mutation), self.assertRaises(ValueError):
                    review_candidate(arch, self.root, datetime.date(2026, 10, 8))
            self.write(path.name, record)

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
            for day, finding, version, status in (
                (datetime.date(2026, 10, 20), None, '3.14.7-r2', 0),
                (datetime.date(2026, 10, 20), 'CVE-2026-17084', '3.14.7-r2', 0),
                (datetime.date(2026, 10, 21), None, '3.14.7-r2', 0),
                (datetime.date(2026, 10, 21), 'CVE-2026-17084', '3.14.7-r2', 1),
                (datetime.date(2026, 10, 20), 'CVE-2099-1234', '3.14.7-r2', 1),
                (datetime.date(2026, 10, 20), 'CVE-2026-17084', '3.14.7-r1', 1),
            ):
                with self.subTest(arch=arch, day=day, finding=finding, version=version):
                    matches = [] if finding is None else [{
                        'vulnerability': {'id': finding, 'severity': 'Medium'},
                        'artifact': {'type': 'apk', 'name': 'python-3.14', 'version': version}}]
                    self.write(f'candidate-{arch}.json', {'matches': matches})
                    review = self.root / f'candidate-review-{arch}.json'
                    review.write_bytes(b'{ "original": true }\n\n')
                    files = {p: p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
                    with chdir(self.root), patch.object(review_image, 'current_day', return_value=day), redirect_stdout(io.StringIO()):
                        self.assertEqual(review_image.main([arch, '--check-only']), status)
                    self.assertEqual(files, {p: p.read_bytes() for p in self.root.rglob('*') if p.is_file()})

    def test_check_only_does_not_create_review_evidence(self):
        with chdir(self.root), redirect_stdout(io.StringIO()):
            self.assertEqual(review_image.main(['amd64', '--check-only']), 0)
        self.assertFalse((self.root / 'candidate-review-amd64.json').exists())

    def test_expired_deadline_cli_warns_without_blocking_or_changing_policy(self):
        original = (self.root / 'docs/image-exceptions.json').read_bytes()
        summary = self.root / 'summary.md'
        output = io.StringIO()
        with chdir(self.root), patch.object(review_image, 'current_day', return_value=datetime.date(2026, 10, 21)), patch.dict(os.environ, {'GITHUB_STEP_SUMMARY': str(summary)}), redirect_stdout(output):
            self.assertEqual(review_image.main(['--check-deadlines']), 0)
        self.assertEqual(output.getvalue().count('::warning::'), 8)
        self.assertIn('review deadline 2026-10-20', summary.read_text())
        self.assertIn('Unused exceptions do not block a clean scan', summary.read_text())
        self.assertEqual((self.root / 'docs/image-exceptions.json').read_bytes(), original)
