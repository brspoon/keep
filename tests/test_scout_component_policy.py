"""Synthetic absent-code approval; no checked-in SQLite approval is created."""
import copy
import datetime
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import build_patched_sqlite as build
import hub_analysis_review
import review_image
from scout_exception_policy import (COMPONENT_SOURCE_BINDINGS, canonical_scout_finding,
                                     component_deadlines, finding_decision, scout_deadlines)
from tests.native_dependency_fixture import dependency_report
from tests.test_runtime_dependency_checks import write_synthetic_dependency_locks
from tests.test_sqlite_component_review import SQLiteComponentReviewTests


FINDING = {'id': 'CVE-2026-119586', 'severity': 'HIGH',
           'purl': 'pkg:apk/alpine/sqlite@3.53.4-r0?os_name=alpine&os_version=3.24',
           'affected_version': '<=3.53.4-r0', 'fixed_version': 'not fixed'}
DAY = datetime.date(2026, 11, 4)


class ScoutComponentPolicyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.policy = json.loads((ROOT / 'docs/image-exceptions.json').read_bytes())
        self.policy.update(exceptions={}, scout_exceptions={}, require_zero_findings=False)
        paths = set(self.policy['reviewed_sources']) | COMPONENT_SOURCE_BINDINGS
        for name in paths:
            target = self.root / name; target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((ROOT / name).read_bytes())
        write_synthetic_dependency_locks(self.root)
        self.policy['reviewed_sources'] = {name: hashlib.sha256((self.root / name).read_bytes()).hexdigest()
                                           for name in paths}
        self.rule = {**{key: value for key, value in FINDING.items() if key != 'id'},
            'type': 'apk', 'package': 'sqlite', 'version': '3.53.4-r0',
            'distribution': 'alpine', 'distribution_version': '3.24',
            'status': 'not_affected', 'justification': 'vulnerable_code_not_present',
            'component': 'sqlite-command-line-shell',
            'evidence': 'Synthetic component proof for isolated tests, not a release approval.',
            'source_bindings': {name: self.policy['reviewed_sources'][name] for name in COMPONENT_SOURCE_BINDINGS},
            'review': {'reviewed_on': DAY.isoformat(), 'deadline': '2026-11-11',
                       'approval': 'Synthetic isolated test approval only.',
                       'remove_when': 'Corrected reports no longer match the absent C shell.'}}
        self.policy['scout_component_reviews'] = {FINDING['id']: self.rule}
        self.save_policy()

    def save_policy(self):
        (self.root / 'docs/image-exceptions.json').write_text(json.dumps(self.policy))

    def proof(self, arch='amd64'):
        inventory, layers = SQLiteComponentReviewTests().fixture()
        layers['architecture'] = arch
        spec = build.reviewed_spec(self.root); manifest = build.expected_manifest(arch, self.root)
        inventory['sqlite_replacement'] = {
            'build_lock': spec, 'build_lock_sha256': build.digest(build.json_bytes(spec)),
            'manifest': manifest, 'manifest_sha256': build.digest(build.json_bytes(manifest)),
            'library': {'path': manifest['library']['path'], 'sha256': manifest['library']['sha256']}}
        return inventory, layers

    def scout(self):
        return {'runs': [{'tool': {'driver': {'rules': [{'id': FINDING['id'], 'properties': {
            'cvssV3_severity': FINDING['severity'], 'purls': [FINDING['purl']],
            'affected_version': FINDING['affected_version'], 'fixed_version': FINDING['fixed_version']}}]}},
            'invocations': [{'executionSuccessful': True}],
            'results': [{'ruleId': FINDING['id'], 'ruleIndex': 0, 'kind': 'fail', 'level': 'error'}]}]}

    def context(self, arch='amd64'):
        inventory, layers = self.proof(arch)
        return {'root': self.root, 'report': {'matches': [], 'source': {'type': 'image',
                    'target': {'imageID': 'sha256:' + 'e' * 64, 'os': 'linux', 'architecture': arch}}},
            'scout': self.scout(),
            'evidence': {'success': True, 'tests': 10, 'failures': 0, 'errors': 0,
                         'skipped': 0, 'arch': arch,
                         'patch_manifest_sha256': self.policy['reviewed_sources']['scripts/python_security_patches.json']},
            'provenance': {'predicateType': 'https://slsa.dev/provenance/v1',
                'subject': [{'digest': {'sha256': review_image.DIRECT[arch][0]}}]},
            'dependencies': dependency_report(arch, root=self.root), 'inventory': inventory, 'layers': layers,
            'expected_image_config': 'sha256:' + 'e' * 64}

    def decision(self, inventory=None, layers=None, *, arch='amd64', finding=None, day=DAY):
        return finding_decision(FINDING if finding is None else finding, self.policy, day,
                                inventory=inventory, layers=layers, arch=arch, root=self.root,
                                image_config_sha256='e' * 64)

    def receipt(self):
        return {'format': 'keep-hub-analysis-review-v2', 'review_source': 'docker-hub-ui',
            'image': 'example/keep', 'revision': 'a' * 40, 'reviewed_at': '2026-11-04T12:00:00Z',
            'reviewed_by': 'maintainer', 'architectures': {arch: {'platform': 'linux/' + arch,
                'digest': 'sha256:' + digit * 64, 'status': 'complete', 'unfiltered': True,
                'counts': {'critical': 0, 'high': 1, 'medium': 0, 'low': 0, 'unspecified': 0},
                'findings': [copy.deepcopy(FINDING)]} for arch, digit in (('amd64', 'b'), ('arm64', 'c'))}}

    def hub(self, contexts):
        value = self.receipt()
        return hub_analysis_review.validate_review(json.dumps(value).encode(), value['image'], value['revision'],
            {arch: row['digest'] for arch, row in value['architectures'].items()}, security_reviews=contexts,
            now=datetime.datetime(2026, 11, 4, 12, tzinfo=datetime.timezone.utc))

    def test_real_policy_has_no_active_sqlite_component_or_grype_rule(self):
        policy = json.loads((ROOT / 'docs/image-exceptions.json').read_bytes())
        self.assertEqual(policy.get('scout_component_reviews', {}), {})
        self.assertNotIn(FINDING['id'], policy['exceptions'])
        self.assertEqual(finding_decision(FINDING, policy, DAY), 'unmatched_finding')

    def test_complete_same_arch_original_proof_passes_without_changing_reports_or_counts(self):
        for arch in ('amd64', 'arm64'):
            context = self.context(arch); original = copy.deepcopy(context)
            result = review_image.review_reports(arch, today=DAY, **context)
            self.assertFalse(result['blocked'] or result['scout_blocked'])
            self.assertEqual(result['scout_accepted_false_positive'], [])
            self.assertEqual(result['scout_not_affected'][0]['justification'], 'vulnerable_code_not_present')
            self.assertEqual(context, original)
        value = self.receipt(); contexts = {arch: self.context(arch) for arch in ('amd64', 'arm64')}
        self.assertEqual(self.hub(contexts), value)
        self.assertEqual(value['architectures']['amd64']['counts']['high'], 1)

    def test_missing_wrong_arch_incomplete_layer_cli_and_unqualified_build_proof_deny(self):
        mutations = (
            lambda i, l: i.pop('sqlite_cli'), lambda i, l: l.pop('sqlite_cli'),
            lambda i, l: l.update(architecture='arm64'), lambda i, l: l.update(findings=[{}]),
            lambda i, l: l['sqlite_cli'].update(layers_scanned=0),
            lambda i, l: l['sqlite_cli']['apk_metadata'][0]['packages'][0]['payloads'].append('usr/bin/sqlite3'),
            lambda i, l: i['sqlite_cli']['apk_metadata'].update(sha256='0' * 64),
            lambda i, l: i['sqlite_replacement']['manifest'].update(qualified=False),
            lambda i, l: i['sqlite_replacement']['library'].update(sha256='0' * 64))
        self.assertEqual(self.decision(), 'missing_component_proof')
        for mutate in mutations:
            inventory, layers = self.proof(); mutate(inventory, layers)
            with self.subTest(mutation=mutate):
                self.assertEqual(self.decision(inventory, layers), 'invalid_component_proof')
        inventory, layers = self.proof()
        self.assertEqual(self.decision(inventory, None), 'missing_component_proof')
        self.assertEqual(self.decision(None, layers), 'missing_component_proof')
        self.assertEqual(self.decision(inventory, layers, arch='unknown'), 'missing_component_proof')

    def test_finding_identity_start_expiry_and_zero_policy_remain_exact(self):
        inventory, layers = self.proof()
        for field in FINDING:
            finding = {**FINDING, field: 'different'}
            with self.subTest(field=field): self.assertIsNotNone(self.decision(inventory, layers, finding=finding))
        self.assertIsNone(self.decision(inventory, layers, day=datetime.date(2026, 11, 11)))
        self.assertEqual(self.decision(inventory, layers, day=datetime.date(2026, 11, 12)), 'exception_expired')
        self.assertEqual(self.decision(inventory, layers, day=DAY - datetime.timedelta(days=1)), 'component_review_not_started')
        self.policy['require_zero_findings'] = True
        self.assertEqual(self.decision(inventory, layers), 'finding_not_permitted')

    def test_malformed_or_reclassified_policy_never_becomes_an_approval(self):
        original = copy.deepcopy(self.rule)
        mutations = (lambda r: r.update(status='fixed_false_positive'),
            lambda r: r.update(justification='accepted_risk'), lambda r: r.update(component='sqlite-library'),
            lambda r: r.update(version='3.54.1-r0'), lambda r: r.update(extra=True),
            lambda r: r.update(source_bindings={}),
            lambda r: r['review'].pop('approval'), lambda r: r['review'].pop('deadline'),
            lambda r: r['review'].update(reviewed_on='2026-11-12'))
        for mutate in mutations:
            rule = copy.deepcopy(original); mutate(rule)
            self.policy['scout_component_reviews'] = {FINDING['id']: rule}
            with self.subTest(mutation=mutate), self.assertRaises(ValueError): scout_deadlines(self.policy)

    def test_high_error_is_structured_but_suppression_absence_wrong_kind_or_level_deny(self):
        scout = self.scout(); run = scout['runs'][0]; result = run['results'][0]
        self.assertEqual(canonical_scout_finding(run, result), FINDING)
        for field, value in (('level', 'none'), ('level', 'warning'), ('kind', 'review'),
                             ('baselineState', 'absent'), ('suppressions', [{}])):
            with self.subTest(field=field):
                self.assertIsNone(canonical_scout_finding(run, {**result, field: value}))
        malformed = copy.deepcopy(run); malformed['tool']['driver']['rules'][0].pop('id')
        self.assertIsNone(canonical_scout_finding(malformed, {**result, 'ruleId': None}))

    def test_hub_requires_same_arch_proof_and_a_matching_original_scout_result(self):
        for removed in ('inventory', 'layers'):
            contexts = {arch: self.context(arch) for arch in ('amd64', 'arm64')}
            contexts['arm64'].pop(removed)
            with self.subTest(removed=removed), self.assertRaises(ValueError): self.hub(contexts)
        contexts = {arch: self.context(arch) for arch in ('amd64', 'arm64')}
        contexts['arm64']['scout']['runs'][0]['results'] = []
        with self.assertRaisesRegex(ValueError, 'differs from original native Scout'): self.hub(contexts)

    def test_layers_must_match_original_same_arch_grype_image_config_identity(self):
        mutations = (
            lambda c: c['report'].pop('source'),
            lambda c: c['report']['source'].update(type='directory'),
            lambda c: c['report']['source']['target'].update(os='windows'),
            lambda c: c['report']['source']['target'].update(architecture='arm64'),
            lambda c: c['report']['source']['target'].update(imageID='e' * 64),
            lambda c: c['report']['source']['target'].update(imageID='sha256:' + 'd' * 64),
            lambda c: c['layers'].update(config_sha256='d' * 64))
        for mutate in mutations:
            context = self.context(); mutate(context)
            with self.subTest(mutation=mutate), self.assertRaises(ValueError):
                review_image.review_reports('amd64', today=DAY, **context)
        contexts = {arch: self.context(arch) for arch in ('amd64', 'arm64')}
        contexts['arm64']['layers']['config_sha256'] = 'd' * 64
        with self.assertRaises(ValueError): self.hub(contexts)

    def test_inner_pair_cannot_replace_the_independently_expected_config(self):
        context = self.context()
        context['report']['source']['target']['imageID'] = 'sha256:' + 'd' * 64
        context['layers']['config_sha256'] = 'd' * 64
        with self.assertRaisesRegex(ValueError, 'expected image config'):
            review_image.review_reports('amd64', today=DAY, **context)
        context = self.context(); context.pop('expected_image_config')
        self.assertTrue(review_image.review_reports('amd64', today=DAY, **context)['scout_blocked'])
        contexts = {arch: self.context(arch) for arch in ('amd64', 'arm64')}
        contexts['amd64'].pop('expected_image_config')
        with self.assertRaises(ValueError): self.hub(contexts)

    def test_grype_library_finding_and_changed_source_bytes_stay_blocking(self):
        context = self.context()
        context['report']['matches'] = [{'vulnerability': {'id': 'CVE-2026-119376', 'severity': 'High'},
            'artifact': {'type': 'apk', 'name': 'sqlite-libs', 'version': '3.53.4-r0'}}]
        result = review_image.review_reports('amd64', today=DAY, **context)
        self.assertEqual(result['blocked'][0]['reason'], 'unmatched_finding')
        path = self.root / 'scripts/sqlite_security_checks.py'; path.write_bytes(path.read_bytes() + b'\n# changed\n')
        with self.assertRaisesRegex(ValueError, 'changed; verified-fixed review'):
            review_image.review_reports('amd64', today=DAY, **self.context())

    def test_candidate_reads_original_inventory_layers_and_explicit_deadline_warnings(self):
        context = self.context()
        for field, filename in {'report': 'candidate', 'scout': 'candidate-scout',
                'evidence': 'candidate-regression', 'provenance': 'candidate-provenance',
                'dependencies': 'candidate-dependencies', 'inventory': 'candidate-notices',
                'layers': 'candidate-layers'}.items():
            (self.root / (filename + '-amd64.json')).write_text(json.dumps(context[field]))
        result = review_image.review_candidate('amd64', self.root, DAY,
                                               expected_image_config=context['expected_image_config'])
        self.assertEqual(len(result['scout_not_affected']), 1)
        before = copy.deepcopy(self.policy)
        warnings = review_image.deadline_warnings(self.policy, DAY)
        self.assertEqual([row['id'] for row in warnings], [FINDING['id']])
        self.assertEqual(self.policy, before)
        (self.root / 'candidate-layers-amd64.json').unlink()
        with self.assertRaises(OSError):
            review_image.review_candidate('amd64', self.root, DAY,
                                           expected_image_config=context['expected_image_config'])


if __name__ == '__main__': unittest.main()
