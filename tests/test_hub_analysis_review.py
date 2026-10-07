"""Offline validation of exact-digest recorded Hub review receipts."""
import datetime
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import hub_analysis_review
import candidate_publication
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
