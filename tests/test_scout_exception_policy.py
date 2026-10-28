"""Exact Scout false-positive scope and original native proof requirements."""
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

import review_image
from inspect_candidate import DIRECT
from scout_exception_policy import canonical_scout_finding, finding_decision, scout_deadlines
from tests.image_review_policy_fixture import RENEWED_FINDINGS, renewed_review_policy
from tests.native_dependency_fixture import dependency_report, musl_failure_reports


FINDING_ID = 'CVE-2026-107891'
PURL = 'pkg:apk/alpine/musl@1.2.6-r3?os_name=alpine&os_version=3.24'
FINDING = {
    'id': FINDING_ID, 'severity': 'UNSPECIFIED', 'purl': PURL,
    'affected_version': '<1.2.6-r6', 'fixed_version': '1.2.6-r6',
}
DEADLINE = datetime.date(2026, 10, 25)


def scout_report(arch='amd64'):
    """Representative structured fields from the retained Scout 1.27.0 report."""
    loader = 'x86_64' if arch == 'amd64' else 'aarch64'
    return {
        'version': '2.1.0',
        'runs': [{
            'tool': {'driver': {
                'name': 'docker scout', 'version': '1.27.0',
                'rules': [{
                    'id': FINDING_ID, 'name': 'OsPackageVulnerability',
                    'properties': {
                        'affected_version': '<1.2.6-r6',
                        'cvssV3_severity': 'UNSPECIFIED',
                        'fixed_version': '1.2.6-r6', 'purls': [PURL],
                        'security-severity': '3.1', 'tags': ['UNSPECIFIED'],
                    },
                }],
            }},
            'results': [{
                'ruleId': FINDING_ID, 'ruleIndex': 0, 'kind': 'fail', 'level': 'none',
                'message': {'text': 'Vulnerability   :' + FINDING_ID},
                'locations': [
                    {'physicalLocation': {'artifactLocation': {'uri': '/lib/apk/db/installed'}}},
                    {'physicalLocation': {'artifactLocation': {'uri': '/lib/ld-musl-' + loader + '.so.1'}}},
                ],
            }],
        }],
    }


def policy_fixture():
    policy = renewed_review_policy()
    names = set(policy['reviewed_sources']) | {'scripts/scout_exception_policy.py'}
    policy['reviewed_sources'] = {
        name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in names
    }
    policy['scout_exceptions'] = {
        FINDING_ID: {
            **{field: value for field, value in FINDING.items() if field != 'id'},
            'status': 'fixed_false_positive', 'type': 'apk', 'package': 'musl',
            'version': '1.2.6-r3', 'distribution': 'alpine', 'distribution_version': '3.24',
            'evidence': 'Synthetic exact signed source and loaded-libc evidence.',
            'source_bindings': {
                name: policy['reviewed_sources'][name]
                for name in ('scripts/alpine_musl_sources.py', 'scripts/runtime_dependency_checks.py')
            },
            'review': {
                'approval': 'Synthetic approval limited to the exact corrected package.',
                'deadline': DEADLINE.isoformat(),
                'remove_when': 'Complete unsuppressed Scout reports recognize the correct fixed package.',
            },
        },
    }
    return policy


def regression_report(policy, arch):
    return {
        'success': True, 'tests': 10, 'failures': 0, 'errors': 0, 'skipped': 0,
        'arch': arch,
        'patch_manifest_sha256': policy['reviewed_sources']['scripts/python_security_patches.json'],
    }


class ScoutExceptionPolicyTests(unittest.TestCase):
    def test_current_joint_review_preserves_three_exact_scopes_and_new_boundary(self):
        policy = json.loads((ROOT / 'docs/image-exceptions.json').read_text())
        self.assertEqual(set(policy['exceptions']), set(RENEWED_FINDINGS))
        self.assertEqual(set(policy['scout_exceptions']), {FINDING_ID})
        rules = [*policy['exceptions'].values(), *policy['scout_exceptions'].values()]
        self.assertTrue(all(rule['review']['reviewed_on'] == '2026-10-28' for rule in rules))
        self.assertTrue(all(rule['review']['deadline'] == '2026-11-11' for rule in rules))
        matches = [{'vulnerability': {'id': finding, 'severity': 'Medium'},
                    'artifact': {'name': 'python-3.14', 'type': 'apk', 'version': '3.14.8-r0'}}
                   for finding in RENEWED_FINDINGS]
        for arch in DIRECT:
            original = scout_report(arch)
            for day, expired in ((datetime.date(2026, 11, 2), False),
                                 (datetime.date(2026, 11, 11), False),
                                 (datetime.date(2026, 11, 12), True)):
                result = self.assess(copy.deepcopy(original), arch=arch, day=day,
                                     policy=policy, matches=matches)
                with self.subTest(arch=arch, day=day):
                    self.assertEqual(len(result['blocked']) + len(result['scout_blocked']),
                                     3 if expired else 0)
                    self.assertEqual(len(result['accepted_fixed']), 0 if expired else 2)
                    self.assertEqual(len(result['scout_accepted_false_positive']), 0 if expired else 1)
                    self.assertEqual(original, scout_report(arch))
            clean = self.assess({'runs': [{'results': []}]}, arch=arch,
                                day=datetime.date(2026, 11, 12), policy=policy, matches=[])
            self.assertFalse(clean['blocked'] or clean['scout_blocked'])

    def setUp(self):
        self.policy = policy_fixture()

    def assess(self, scout=None, *, arch='amd64', day=DEADLINE, policy=None, matches=None):
        policy = self.policy if policy is None else policy
        return review_image.assess(
            {'matches': [] if matches is None else matches},
            scout_report(arch) if scout is None else scout,
            regression_report(policy, arch), policy, arch, day,
        )

    def test_actual_structured_report_identity_is_exact_on_both_architectures(self):
        for arch in DIRECT:
            report = scout_report(arch)
            run = report['runs'][0]
            result = run['results'][0]
            with self.subTest(arch=arch):
                self.assertEqual(canonical_scout_finding(run, result), FINDING)
                # Message text never supplies or overrides structured identity.
                result['message']['text'] = 'CVE-2099-9999; musl 1.2.6-r2; HIGH'
                self.assertEqual(canonical_scout_finding(run, result), FINDING)

    def test_exact_approval_is_inclusive_and_only_blocks_when_needed_after_expiry(self):
        for day, accepted in ((datetime.date(2026, 10, 22), True),
                              (DEADLINE, True), (datetime.date(2026, 10, 26), False)):
            with self.subTest(day=day):
                self.assertEqual(finding_decision(FINDING, self.policy, day),
                                 None if accepted else 'exception_expired')
                for arch in DIRECT:
                    report = scout_report(arch)
                    original = copy.deepcopy(report)
                    result = self.assess(report, arch=arch, day=day)
                    self.assertEqual(result['scout_accepted_false_positive'],
                                     [{**FINDING, 'deadline': '2026-10-25'}] if accepted else [])
                    self.assertEqual(result['scout_blocked'],
                                     [] if accepted else report['runs'][0]['results'])
                    self.assertEqual(report, original)
        clean = {'runs': [{'results': []}]}
        for arch in DIRECT:
            result = self.assess(clean, arch=arch, day=datetime.date(2026, 10, 26))
            self.assertFalse(result['scout_blocked'])

    def test_fresh_same_scope_review_changes_only_its_deadline_and_preserves_raw_reports(self):
        renewed = copy.deepcopy(self.policy)
        renewed['scout_exceptions'][FINDING_ID]['review'].update(
            reviewed_on='2026-10-23', deadline='2026-11-01')
        self.assertEqual(renewed['exceptions'], self.policy['exceptions'])
        for arch in DIRECT:
            report = scout_report(arch)
            original = json.dumps(report, sort_keys=True).encode()
            for day, accepted in ((datetime.date(2026, 10, 26), True),
                                  (datetime.date(2026, 11, 1), True),
                                  (datetime.date(2026, 11, 2), False)):
                result = self.assess(report, arch=arch, policy=renewed, day=day)
                with self.subTest(arch=arch, day=day):
                    self.assertEqual(result['scout_accepted_false_positive'],
                                     [{**FINDING, 'deadline': '2026-11-01'}] if accepted else [])
                    self.assertEqual(result['scout_blocked'],
                                     [] if accepted else report['runs'][0]['results'])
                    self.assertEqual(json.dumps(report, sort_keys=True).encode(), original)
            changed = {**FINDING, 'severity': 'HIGH'}
            self.assertEqual(finding_decision(changed, renewed, datetime.date(2026, 10, 26)),
                             'exception_mismatch')
            self.assertFalse(result['scout_accepted_false_positive'])

    def test_absent_or_empty_scout_policy_preserves_zero_findings_default(self):
        for absent in (False, True):
            policy = copy.deepcopy(self.policy)
            if absent:
                policy.pop('scout_exceptions')
            else:
                policy['scout_exceptions'] = {}
            for arch in DIRECT:
                with self.subTest(absent=absent, arch=arch):
                    result = self.assess(arch=arch, policy=policy)
                    self.assertFalse(result['scout_accepted_false_positive'])
                    self.assertEqual(result['scout_blocked'], scout_report(arch)['runs'][0]['results'])
                    clean = self.assess({'runs': [{'results': []}]}, arch=arch, policy=policy)
                    self.assertFalse(clean['scout_blocked'])

    def test_zero_finding_policy_still_overrides_exact_scout_approval(self):
        self.policy['require_zero_findings'] = True
        self.assertEqual(finding_decision(FINDING, self.policy, DEADLINE), 'finding_not_permitted')
        result = self.assess()
        self.assertFalse(result['scout_accepted_false_positive'])
        self.assertEqual(result['scout_blocked'], scout_report()['runs'][0]['results'])

    def test_each_finding_field_is_bound_to_the_approved_false_positive(self):
        mutations = {
            'id': ('CVE-2099-9999',),
            'severity': ('LOW', 'HIGH', 'unspecified'),
            'purl': (
                PURL.replace('1.2.6-r3', '1.2.6-r2'),
                PURL.replace('1.2.6-r3', '1.2.6-r4'),
                PURL.replace('/musl@', '/musl-dev@'),
                PURL.replace('os_version=3.24', 'os_version=3.23'),
                PURL.replace('os_version=3.24', 'os_version=edge'),
                PURL.replace('pkg:apk/', 'pkg:deb/'),
            ),
            'affected_version': ('<1.2.6-r3', '<1.2.6-r7'),
            'fixed_version': ('1.2.6-r3', '1.2.6-r7'),
        }
        for field, values in mutations.items():
            for value in values:
                finding = {**FINDING, field: value}
                with self.subTest(field=field, value=value):
                    self.assertEqual(finding_decision(finding, self.policy, DEADLINE),
                                     'unmatched_finding' if field == 'id' else 'exception_mismatch')
        for field in FINDING:
            finding = dict(FINDING)
            finding.pop(field)
            with self.subTest(missing=field):
                self.assertEqual(finding_decision(finding, self.policy, DEADLINE),
                                 'incomplete_scout_finding')
        for value in (None, [], {}, 1):
            with self.subTest(invalid_id=value):
                self.assertEqual(finding_decision({**FINDING, 'id': value}, self.policy, DEADLINE),
                                 'incomplete_scout_finding')

    def test_malformed_sarif_cannot_consume_the_exception(self):
        mutations = [
            ('rule_id', lambda run, result: result.update(ruleId='CVE-2099-9999')),
            ('rule_identity', lambda run, result: run['tool']['driver']['rules'][0].update(id='CVE-2099-9999')),
            ('negative_index', lambda run, result: result.update(ruleIndex=-1)),
            ('out_of_range_index', lambda run, result: result.update(ruleIndex=1)),
            ('boolean_index', lambda run, result: result.update(ruleIndex=False)),
            ('string_index', lambda run, result: result.update(ruleIndex='0')),
            ('missing_index', lambda run, result: result.pop('ruleIndex')),
            ('multiple_purls', lambda run, result: run['tool']['driver']['rules'][0]['properties'].update(purls=[PURL, PURL])),
            ('missing_purls', lambda run, result: run['tool']['driver']['rules'][0]['properties'].pop('purls')),
            ('string_purls', lambda run, result: run['tool']['driver']['rules'][0]['properties'].update(purls=PURL)),
            ('empty_purls', lambda run, result: run['tool']['driver']['rules'][0]['properties'].update(purls=[])),
            ('missing_severity', lambda run, result: run['tool']['driver']['rules'][0]['properties'].pop('cvssV3_severity')),
            ('missing_range', lambda run, result: run['tool']['driver']['rules'][0]['properties'].pop('affected_version')),
            ('missing_fix', lambda run, result: run['tool']['driver']['rules'][0]['properties'].pop('fixed_version')),
            ('suppressed', lambda run, result: result.update(suppressions=[{'kind': 'external'}])),
            ('invalid_suppressions', lambda run, result: result.update(suppressions=None)),
            ('absent', lambda run, result: result.update(baselineState='absent')),
            ('kind', lambda run, result: result.update(kind='review')),
            ('missing_kind', lambda run, result: result.pop('kind')),
            ('level', lambda run, result: result.update(level='warning')),
            ('missing_level', lambda run, result: result.pop('level')),
            ('invalid_tool', lambda run, result: run.update(tool=None)),
            ('invalid_driver', lambda run, result: run['tool'].update(driver=None)),
        ]
        for name, mutation in mutations:
            report = scout_report()
            run = report['runs'][0]
            raw = run['results'][0]
            mutation(run, raw)
            original = copy.deepcopy(report)
            with self.subTest(mutation=name):
                self.assertIsNone(canonical_scout_finding(run, raw))
                result = self.assess(report)
                self.assertFalse(result['scout_accepted_false_positive'])
                self.assertEqual(result['scout_blocked'], [raw])
                self.assertEqual(report, original)

    def test_additional_unmatched_result_blocks_even_beside_an_accepted_finding(self):
        report = scout_report()
        run = report['runs'][0]
        rule = copy.deepcopy(run['tool']['driver']['rules'][0])
        rule['id'] = 'CVE-2099-9999'
        run['tool']['driver']['rules'].append(rule)
        extra = {**copy.deepcopy(run['results'][0]), 'ruleId': rule['id'], 'ruleIndex': 1}
        run['results'].append(extra)
        original = copy.deepcopy(report)
        result = self.assess(report)
        self.assertEqual(result['scout_accepted_false_positive'], [{**FINDING, 'deadline': '2026-10-25'}])
        self.assertEqual(result['scout_blocked'], [extra])
        self.assertEqual(report, original)

    def test_scout_scope_does_not_approve_a_grype_match_or_change_python_deadlines(self):
        matches = [{
            'vulnerability': {'id': finding, 'severity': 'Medium'},
            'artifact': {'name': 'python-3.14', 'type': 'apk', 'version': '3.14.8-r0'},
        } for finding in RENEWED_FINDINGS]
        matches.append({
            'vulnerability': {'id': FINDING_ID, 'severity': 'Unknown'},
            'artifact': {'name': 'musl', 'type': 'apk', 'version': '1.2.6-r3'},
        })
        for arch in DIRECT:
            result = self.assess(arch=arch, matches=matches)
            with self.subTest(arch=arch):
                self.assertEqual([row['id'] for row in result['accepted_fixed']], list(RENEWED_FINDINGS))
                self.assertTrue(all(row['deadline'] == '2026-11-01' for row in result['accepted_fixed']))
                self.assertEqual(result['blocked'], [{
                    'id': FINDING_ID, 'package': 'musl', 'version': '1.2.6-r3', 'reason': 'unmatched_finding',
                }])
                self.assertEqual(result['raw_matches'], 3)
        result = self.assess({'runs': [{'results': []}]}, day=datetime.date(2026, 11, 1), matches=matches[:2])
        self.assertEqual(len(result['accepted_fixed']), 2)
        result = self.assess({'runs': [{'results': []}]}, day=datetime.date(2026, 11, 2), matches=matches[:2])
        self.assertEqual([row['reason'] for row in result['blocked']], ['exception_expired'] * 2)

    def test_scout_review_deadline_is_included_in_advisory_warnings(self):
        original = copy.deepcopy(self.policy)
        for day, remaining in ((DEADLINE, 0), (datetime.date(2026, 10, 26), -1)):
            warnings = review_image.deadline_warnings(self.policy, day, warning_days=0)
            with self.subTest(day=day):
                self.assertEqual([row for row in warnings if row['id'] == FINDING_ID], [{
                    'id': FINDING_ID, 'package': 'musl', 'version': '1.2.6-r3',
                    'deadline': '2026-10-25', 'days_remaining': remaining,
                }])
        self.assertEqual(self.policy, original)

    def test_malformed_approval_or_source_binding_fails_even_for_clean_scans(self):
        mutations = [
            lambda policy, rule: policy.update(scout_exceptions=None),
            lambda policy, rule: rule.update(status='accepted-risk'),
            lambda policy, rule: rule.update(distribution_version='edge'),
            lambda policy, rule: rule.update(purl=PURL.replace('1.2.6-r3', '1.2.6-r2')),
            lambda policy, rule: rule.update(source_bindings={}),
            lambda policy, rule: rule['source_bindings'].update({'scripts/alpine_musl_sources.py': '0' * 64}),
            lambda policy, rule: rule['review'].update(deadline='2026-10-25T23:59:59Z'),
            lambda policy, rule: rule['review'].update(deadline='2026-02-30'),
            lambda policy, rule: rule['review'].pop('approval'),
            lambda policy, rule: rule['review'].pop('remove_when'),
        ]
        for number, mutation in enumerate(mutations):
            policy = copy.deepcopy(self.policy)
            mutation(policy, policy['scout_exceptions'][FINDING_ID])
            with self.subTest(mutation=number):
                with self.assertRaises(ValueError):
                    scout_deadlines(policy)
                with self.assertRaises(ValueError):
                    self.assess({'runs': [{'results': []}]}, policy=policy)
                with self.assertRaises(ValueError):
                    review_image.deadline_warnings(policy, DEADLINE)


class ScoutOriginalProofTests(unittest.TestCase):
    def test_exception_requires_original_source_provenance_and_runtime_proof(self):
        policy = policy_fixture()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in policy['reviewed_sources']:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes((ROOT / name).read_bytes())
            (root / 'docs/image-exceptions.json').write_text(json.dumps(policy))
            for arch in DIRECT:
                original = {
                    'report': {'matches': []}, 'scout': scout_report(arch),
                    'evidence': regression_report(policy, arch),
                    'provenance': {'predicateType': 'https://slsa.dev/provenance/v1',
                                   'subject': [{'digest': {'sha256': DIRECT[arch][0]}}]},
                    'dependencies': dependency_report(arch),
                }
                result = review_image.review_reports(arch, root=root, today=DEADLINE, **original)
                self.assertFalse(result['scout_blocked'])
                self.assertEqual(result['scout_accepted_false_positive'],
                                 [{**FINDING, 'deadline': '2026-10-25'}])
                invalid = [
                    ('provenance', {'predicateType': 'https://slsa.dev/provenance/v1',
                                    'subject': [{'digest': {'sha256': '0' * 64}}]}),
                    ('dependencies', None),
                    ('evidence', {**original['evidence'], 'success': False}),
                    *[('dependencies', report) for _, report, _ in musl_failure_reports(arch)],
                ]
                for index, (name, replacement) in enumerate(invalid):
                    reports = {**copy.deepcopy(original), name: replacement}
                    retained = copy.deepcopy(reports)
                    with self.subTest(arch=arch, proof=name, mutation=index), self.assertRaises(ValueError):
                        review_image.review_reports(arch, root=root, today=DEADLINE, **reports)
                    self.assertEqual(reports, retained)
                for name in ('scripts/scout_exception_policy.py', 'scripts/alpine_musl_sources.py',
                             'scripts/runtime_dependency_checks.py'):
                    path = root / name
                    body = path.read_bytes()
                    path.write_bytes(body + b'\n# Changed after review\n')
                    with self.subTest(arch=arch, changed_source=name), self.assertRaisesRegex(ValueError, 'changed'):
                        review_image.review_reports(arch, root=root, today=DEADLINE, **original)
                    path.write_bytes(body)


if __name__ == '__main__':
    unittest.main()
