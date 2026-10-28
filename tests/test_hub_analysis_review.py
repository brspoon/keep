"""Offline validation of exact-digest recorded Hub review receipts."""
import datetime
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import hub_analysis_review
import candidate_publication
import review_image
from tests.native_dependency_fixture import dependency_report, musl_failure_reports, certificate_failure_reports
from tests.test_release_publish import SHA, DIGESTS, hub_review


class HubAnalysisReviewTests(unittest.TestCase):
    NOW = datetime.datetime(2026, 10, 7, 12, 0, tzinfo=datetime.timezone.utc)

    def validate(self, value):
        return hub_analysis_review.validate_review(json.dumps(value).encode(), 'example/keep', SHA,
                                                  DIGESTS, now=self.NOW)

    def test_both_exact_completed_unfiltered_zero_results_pass_at_freshness_boundary(self):
        for age in (0, 3599, 3600):
            with self.subTest(age=age):
                self.validate(hub_review(self.NOW - datetime.timedelta(seconds=age)))

    def test_incomplete_nonzero_unknown_or_mismatched_review_never_means_zero(self):
        mutations = [
            lambda value: value.update(image='different/keep'),
            lambda value: value.update(revision='b' * 40),
            lambda value: value.update(review_source='scout-cli'),
            lambda value: value.update(reviewed_by=''),
            lambda value: value['architectures'].pop('arm64'),
            lambda value: value['architectures']['amd64'].update(digest=DIGESTS['arm64']),
            lambda value: value['architectures']['arm64'].update(platform='linux/amd64'),
            lambda value: value['architectures']['arm64'].update(status='pending'),
            lambda value: value['architectures']['arm64'].pop('status'),
            lambda value: value['architectures']['arm64'].update(unfiltered=False),
            lambda value: value['architectures']['arm64']['counts'].pop('unspecified'),
            lambda value: value['architectures']['arm64'].update(counts=None),
            lambda value: value['architectures']['arm64']['counts'].update(unknown=0),
            lambda value: value['architectures']['arm64']['counts'].update(high=1),
            lambda value: value['architectures']['arm64']['counts'].update(high=-1),
            lambda value: value['architectures']['arm64']['counts'].update(high=False),
            lambda value: value['architectures']['arm64']['counts'].update(high=0.0),
            lambda value: value['architectures']['arm64']['counts'].update(high='0'),
        ]
        for mutation in mutations:
            value = hub_review(self.NOW)
            mutation(value)
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.validate(value)

    def test_stale_future_invalid_or_non_utc_review_time_is_rejected(self):
        for timestamp in ('2026-10-07T10:59:59Z', '2026-10-07T12:00:01Z',
                          '2026-02-30T12:00:00Z', '2026-10-07T12:00:00',
                          '2026-10-07T12:00:00-05:00', '2026-10-07'):
            value = hub_review(self.NOW)
            value['reviewed_at'] = timestamp
            with self.subTest(timestamp=timestamp), self.assertRaises(ValueError):
                self.validate(value)

    def test_duplicate_fields_malformed_and_oversized_receipts_are_rejected(self):
        body = json.dumps(hub_review(self.NOW)).encode()
        for value in (body[:-1] + b', "image": "example/keep"}', b'{}', b'{', b'\xff',
                      json.dumps(hub_review(self.NOW)).encode('utf-16'),
                      b'x' * (hub_analysis_review.MAX_BYTES + 1)):
            with self.subTest(value=value[:60]), self.assertRaises(ValueError):
                hub_analysis_review.validate_review(value, 'example/keep', SHA, DIGESTS, now=self.NOW)

    def test_retention_preserves_original_review_bytes_and_reads_back_both_assets(self):
        body = json.dumps(hub_review(self.NOW), indent=3).encode() + b'\n'
        retained = {}
        def upload(_release, path):
            retained[path.name] = path.read_bytes()
            return {'name': path.name}
        material_api = MagicMock()
        material_api.upload.side_effect = upload
        material_api.asset_body.side_effect = lambda asset: retained[asset['name']]
        with patch.dict(os.environ, {'GITHUB_RUN_ID': '999', 'GITHUB_RUN_ATTEMPT': '1'}):
            hub_analysis_review.retain_review(material_api, {'id': 7}, '2.23.3', body)

        name = 'keep-2.23.3-hub-analysis-review-999-1.json'
        self.assertEqual(retained[name], body)
        self.assertEqual(material_api.guard.call_count, 2)
        self.assertEqual(material_api.asset_body.call_count, 2)
        self.assertTrue(retained[name + '.sha256'].endswith(('  ' + name + '\n').encode()))
        material_api.asset_body.side_effect = lambda _asset: b'changed'
        with patch.dict(os.environ, {'GITHUB_RUN_ID': '999', 'GITHUB_RUN_ATTEMPT': '1'}), \
             self.assertRaisesRegex(ValueError, 'bytes or checksum differ'):
            hub_analysis_review.retain_review(material_api, {'id': 7}, '2.23.3', body)

    def test_receipt_attribution_requires_the_dispatching_github_actor(self):
        with patch.dict(os.environ, {'KEEP_HUB_ANALYSIS_REVIEW': json.dumps(hub_review(self.NOW)),
                                     'GITHUB_ACTOR': 'different-maintainer'}), \
             patch.object(hub_analysis_review, 'utc_now', return_value=self.NOW), \
             self.assertRaisesRegex(ValueError, 'dispatching GitHub actor'):
            hub_analysis_review.review_body('example/keep', SHA, DIGESTS)


class HubFalsePositiveReviewTests(unittest.TestCase):
    NOW = datetime.datetime(2026, 10, 25, 12, 0, tzinfo=datetime.timezone.utc)
    FINDING = {'id': 'CVE-2026-107891', 'severity': 'UNSPECIFIED',
               'purl': 'pkg:apk/alpine/musl@1.2.6-r3?os_name=alpine&os_version=3.24',
               'affected_version': '<1.2.6-r6', 'fixed_version': '1.2.6-r6'}

    @classmethod
    def scout_report(cls, finding=None):
        finding = finding or cls.FINDING
        return {'runs': [{'tool': {'driver': {'rules': [{
            'id': finding['id'], 'properties': {
                'cvssV3_severity': finding['severity'], 'purls': [finding['purl']],
                'affected_version': finding['affected_version'],
                'fixed_version': finding['fixed_version']}}]}},
            'invocations': [{'executionSuccessful': True}],
            'results': [{'ruleId': finding['id'], 'ruleIndex': 0, 'kind': 'fail', 'level': 'none'}]}]}

    @classmethod
    def receipt(cls, now=None):
        value = hub_review(now or cls.NOW)
        value['format'] = 'keep-hub-analysis-review-v2'
        for result in value['architectures'].values():
            result['counts']['unspecified'] = 1
            result['findings'] = [copy.deepcopy(cls.FINDING)]
        return value

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        repository = Path(__file__).resolve().parents[1]
        # Use a synthetic approval so a future renewal or removal does not
        # rewrite this historical October 25 deadline test.
        policy = json.loads((repository / 'docs/image-exceptions.json').read_text())
        policy['exceptions'] = {}
        policy['require_zero_findings'] = False
        policy['scout_exceptions'] = {self.FINDING['id']: {
            **{key: value for key, value in self.FINDING.items() if key != 'id'},
            'type': 'apk', 'package': 'musl', 'version': '1.2.6-r3',
            'distribution': 'alpine', 'distribution_version': '3.24',
            'status': 'fixed_false_positive', 'evidence': 'Synthetic complete native evidence.',
            'review': {'deadline': '2026-10-25', 'approval': 'Synthetic narrow review.',
                       'remove_when': 'Both scanners and native proof confirm the correction.'},
            'source_bindings': {},
        }}
        for name in policy['reviewed_sources']:
            body = (repository / name).read_bytes()
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(body)
            policy['reviewed_sources'][name] = hashlib.sha256(body).hexdigest()
        for name in ('scripts/alpine_musl_sources.py', 'scripts/runtime_dependency_checks.py'):
            policy['scout_exceptions'][self.FINDING['id']]['source_bindings'][name] = policy['reviewed_sources'][name]
        (self.root / 'docs/image-exceptions.json').write_text(json.dumps(policy))
        self.context = {arch: {
            'root': self.root, 'report': {'matches': []}, 'scout': self.scout_report(),
            'evidence': {'success': True, 'tests': 10, 'failures': 0, 'errors': 0,
                         'skipped': 0, 'arch': arch,
                         'patch_manifest_sha256': policy['reviewed_sources']['scripts/python_security_patches.json']},
            'provenance': {'predicateType': 'https://slsa.dev/provenance/v1',
                           'subject': [{'digest': {'sha256': review_image.DIRECT[arch][0]}}]},
            'dependencies': dependency_report(arch),
        } for arch in DIGESTS}

    def validate(self, value=None, *, context=None, now=None):
        return hub_analysis_review.validate_review(
            json.dumps(value or self.receipt()).encode(), 'example/keep', SHA, DIGESTS,
            security_reviews=self.context if context is None else context, now=now or self.NOW)

    def test_truthful_exact_false_positive_passes_both_architectures_on_deadline_without_mutation(self):
        original = copy.deepcopy(self.context)
        value = self.receipt()
        body = json.dumps(value, indent=3).encode() + b'\n'
        self.assertEqual(hub_analysis_review.validate_review(
            body, 'example/keep', SHA, DIGESTS, security_reviews=self.context, now=self.NOW), value)
        self.assertEqual(self.context, original)
        self.assertEqual(value['architectures']['amd64']['counts']['unspecified'], 1)
        self.assertEqual(body, json.dumps(value, indent=3).encode() + b'\n')

    def test_nonzero_without_both_original_native_contexts_is_rejected(self):
        incomplete = copy.deepcopy(self.context)
        incomplete['arm64'].pop('dependencies')
        for context in ({}, {'amd64': self.context['amd64']}, {'amd64': None, 'arm64': None}, incomplete):
            with self.subTest(context=context), self.assertRaisesRegex(ValueError, 'original native'):
                self.validate(context=context)
        with self.assertRaisesRegex(ValueError, 'original native'):
            hub_analysis_review.validate_review(json.dumps(self.receipt()).encode(),
                                               'example/keep', SHA, DIGESTS, now=self.NOW)

    def test_unknown_package_distro_revision_severity_and_affected_range_cannot_use_approval(self):
        changes = [('id', 'CVE-unreviewed'), ('purl', self.FINDING['purl'].replace('musl@', 'other@')),
                   ('purl', self.FINDING['purl'].replace('r3?', 'r2?')),
                   ('purl', self.FINDING['purl'].replace('3.24', 'edge')),
                   ('severity', 'HIGH'), ('affected_version', '<1.2.6-r7'),
                   ('fixed_version', '1.2.6-r7')]
        for arch in DIGESTS:
            for field, different in changes:
                value = self.receipt()
                value['architectures'][arch]['findings'][0][field] = different
                if field == 'severity':
                    value['architectures'][arch]['counts'].update(unspecified=0, high=1)
                with self.subTest(arch=arch, field=field, value=different), self.assertRaisesRegex(ValueError, 'blocks'):
                    self.validate(value)

    def test_counts_must_match_each_complete_unique_finding_exactly(self):
        changes = [lambda result: result['counts'].update(unspecified=0),
                   lambda result: result['counts'].update(critical=1),
                   lambda result: result['counts'].update(unspecified=-1),
                   lambda result: result['counts'].update(unspecified=True),
                   lambda result: result['counts'].update(unspecified=1.0),
                   lambda result: result.update(findings=[]),
                   lambda result: result.update(findings=None),
                   lambda result: result['findings'].append(copy.deepcopy(self.FINDING)),
                   lambda result: result['findings'][0].update(extra='unreviewed'),
                   lambda result: result['findings'][0].pop('purl')]
        for change in changes:
            value = self.receipt()
            change(value['architectures']['amd64'])
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.validate(value)

    def test_receipt_time_does_not_extend_exception_past_current_utc_deadline(self):
        reviewed = datetime.datetime(2026, 10, 25, 23, 59, 59, tzinfo=datetime.timezone.utc)
        self.validate(self.receipt(reviewed), now=reviewed)
        with self.assertRaisesRegex(ValueError, 'successful native security review|exception_expired'):
            self.validate(self.receipt(reviewed), now=reviewed + datetime.timedelta(seconds=2))

    def test_v2_zero_stays_zero_and_unused_expired_approval_needs_no_exception_context(self):
        now = datetime.datetime(2026, 10, 26, 12, 0, tzinfo=datetime.timezone.utc)
        value = self.receipt(now)
        for result in value['architectures'].values():
            result['findings'] = []
            result['counts']['unspecified'] = 0
        self.validate(value, context={}, now=now)

    def test_all_native_source_provenance_completeness_and_runtime_gates_still_apply(self):
        for arch in DIGESTS:
            mutations = [
                lambda context: context['provenance'].update(subject=[]),
                lambda context: context['report'].update(matches=None),
                lambda context: context['report'].update(ignoredMatches=[{}]),
                lambda context: context['scout'].update(runs=[]),
                lambda context: context['scout']['runs'][0]['invocations'][0].update(executionSuccessful=False),
                lambda context: context['evidence'].update(success=False),
                lambda context: context['dependencies'].update(success=False),
            ]
            for mutation in mutations:
                context = copy.deepcopy(self.context)
                mutation(context[arch])
                with self.subTest(arch=arch, mutation=mutation), self.assertRaises(ValueError):
                    self.validate(context=context)
            for failure, report, message in (*musl_failure_reports(arch), *certificate_failure_reports(arch)):
                context = copy.deepcopy(self.context)
                context[arch]['dependencies'] = report
                with self.subTest(arch=arch, failure=failure), self.assertRaisesRegex(ValueError, message):
                    self.validate(context=context)
        source = self.root / 'scripts/alpine_musl_sources.py'
        source.write_bytes(source.read_bytes() + b'\n# changed\n')
        with self.assertRaisesRegex(ValueError, 'changed; verified-fixed review'):
            self.validate()

    def test_unmatched_original_native_scout_or_grype_findings_still_block(self):
        for arch in DIGESTS:
            context = copy.deepcopy(self.context)
            context[arch]['scout']['runs'][0]['results'].append({'ruleId': 'unreviewed'})
            with self.subTest(arch=arch, scanner='scout'), self.assertRaisesRegex(ValueError, 'successful native'):
                self.validate(context=context)
            context = copy.deepcopy(self.context)
            context[arch]['report']['matches'] = [{'vulnerability': {'id': 'unknown', 'severity': 'Low'},
                                                 'artifact': {'type': 'apk', 'name': 'musl', 'version': '1.2.6-r3'}}]
            with self.subTest(arch=arch, scanner='grype'), self.assertRaisesRegex(ValueError, 'successful native'):
                self.validate(context=context)

    def test_original_scout_identity_is_compared_even_after_native_review_acceptance(self):
        context = copy.deepcopy(self.context)
        context['amd64']['scout'] = self.scout_report({**self.FINDING, 'fixed_version': 'different'})
        # Isolate the independent identity-binding layer from the native
        # adjudicator, which also rejects this mismatch in normal operation.
        with patch.object(review_image, 'review_reports', return_value={'blocked': [], 'scout_blocked': []}), \
             self.assertRaisesRegex(ValueError, 'differs from original native Scout'):
            self.validate(context=context)

    def test_review_body_keeps_original_nonzero_bytes_and_actor_attribution(self):
        body = json.dumps(self.receipt(), indent=3) + '\n'
        with patch.dict(os.environ, {'KEEP_HUB_ANALYSIS_REVIEW': body, 'GITHUB_ACTOR': 'maintainer'}), \
             patch.object(hub_analysis_review, 'utc_now', return_value=self.NOW):
            self.assertEqual(hub_analysis_review.review_body('example/keep', SHA, DIGESTS,
                            security_reviews=self.context), body.encode())
