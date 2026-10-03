"""Offline validation of paired native image transfer aggregation."""
import json
import os
from contextlib import chdir
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import registry_transfer as transfer


class RegistryTransferAggregationTests(unittest.TestCase):
    REVISION = 'a' * 40
    DIGESTS = {'amd64': 'sha256:' + 'b' * 64, 'arm64': 'sha256:' + 'c' * 64}

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.output = self.root / 'github-output'
        self.output.write_text('before\n')
        self.env = patch.dict(os.environ, {
            'GITHUB_EVENT_NAME': 'workflow_dispatch', 'GITHUB_REF': 'refs/heads/main',
            'KEEP_RELEASE_PUBLISH': 'true', 'KEEP_RELEASE_CONFIRMATION': 'release-stable',
            'GITHUB_SHA': self.REVISION, 'GITHUB_RUN_ID': '123456', 'GITHUB_RUN_ATTEMPT': '2',
            'DOCKERHUB_IMAGE': 'brspoon/keep', 'DOCKERHUB_USERNAME': 'synthetic',
            'DOCKERHUB_TOKEN': 'synthetic-token', 'GITHUB_OUTPUT': str(self.output),
        })
        self.env.start()
        self.addCleanup(self.env.stop)
        (self.root / 'VERSION').write_text('2.18.0\n')

    def records(self, mutation=None):
        mutation = mutation or {}
        for arch in ('amd64', 'arm64'):
            row = {'architecture': arch, 'digest': self.DIGESTS[arch], 'revision': self.REVISION,
                   'run_id': '123456', 'run_attempt': '2'}
            row.update(mutation.get(arch, {}))
            (self.root / f'transfer-{arch}.json').write_text(json.dumps(row))

    def hub_mock(self, *, private=True, tag_mutation=None):
        def hub(path, token=None, payload=None):
            if path == 'auth/token':
                return {'access_token': 'offline-token'}
            if path == 'repositories/brspoon/keep/':
                return {'is_private': private}
            arch = 'amd64' if '/transfer-123456-2-amd64/' in path else 'arm64'
            digest = self.DIGESTS[arch]
            if tag_mutation and arch in tag_mutation:
                digest = tag_mutation[arch]
            return {'digest': digest}
        return hub

    def run_aggregate(self, **hub_options):
        with chdir(self.root), patch.object(transfer, 'hub', side_effect=self.hub_mock(**hub_options)), \
             patch.object(transfer, 'require_manual_dispatch') as manual, \
             patch.object(transfer, 'require_current_source') as current:
            transfer.aggregate()
        manual.assert_called_once_with(True)
        current.assert_called_once_with(self.REVISION, True)

    def test_success_emits_both_verified_digests_together(self):
        self.records()
        for private in (False, True):
            with self.subTest(private=private):
                self.output.write_text('before\n')
                self.run_aggregate(private=private)
                self.assertEqual(self.output.read_text(),
                                 'before\namd64=' + self.DIGESTS['amd64'] + '\narm64=' + self.DIGESTS['arm64'] + '\n')

    def test_rejects_foreign_records_tags_or_missing_architecture_before_output(self):
        cases = (
            ({'amd64': {'run_id': '999'}}, 'Native transfer record differs'),
            ({'arm64': {'run_attempt': '1'}}, 'Native transfer record differs'),
            ({'amd64': {'revision': 'f' * 40}}, 'Native transfer record differs'),
            ({'arm64': {'architecture': 'amd64'}}, 'Native transfer record differs'),
            ({'amd64': {'extra': 'unexpected'}}, 'Native transfer record differs'),
        )
        for mutation, message in cases:
            with self.subTest(mutation=mutation):
                self.records(mutation)
                with chdir(self.root), patch.object(transfer, 'require_manual_dispatch'), \
                     patch.object(transfer, 'require_current_source'), \
                     patch.object(transfer, 'hub', side_effect=self.hub_mock()):
                    with self.assertRaisesRegex(ValueError, message):
                        transfer.aggregate()
                self.assertEqual(self.output.read_text(), 'before\n')

        self.records()
        (self.root / 'transfer-arm64.json').unlink()
        with chdir(self.root), patch.object(transfer, 'require_manual_dispatch'), \
             patch.object(transfer, 'require_current_source'), \
             patch.object(transfer, 'hub', side_effect=self.hub_mock()):
            with self.assertRaisesRegex(ValueError, 'Both original native transfer records'):
                transfer.aggregate()
        self.assertEqual(self.output.read_text(), 'before\n')

        self.records()
        with chdir(self.root), patch.object(transfer, 'require_manual_dispatch'), \
             patch.object(transfer, 'require_current_source'), \
             patch.object(transfer, 'hub', side_effect=self.hub_mock(tag_mutation={'arm64': 'sha256:' + '0' * 64})):
            with self.assertRaisesRegex(ValueError, 'transfer tag differs'):
                transfer.aggregate()
        self.assertEqual(self.output.read_text(), 'before\n')

    def test_manual_current_main_and_visibility_metadata_gates_precede_output(self):
        self.records()
        with chdir(self.root), patch.object(transfer, 'require_manual_dispatch', side_effect=ValueError('manual gate')), \
             patch.object(transfer, 'hub') as hub:
            with self.assertRaisesRegex(ValueError, 'manual gate'):
                transfer.aggregate()
        hub.assert_not_called()
        self.assertEqual(self.output.read_text(), 'before\n')

        with chdir(self.root), patch.object(transfer, 'require_manual_dispatch'), \
             patch.object(transfer, 'require_current_source', side_effect=ValueError('stale main')), \
             patch.object(transfer, 'hub') as hub:
            with self.assertRaisesRegex(ValueError, 'stale main'):
                transfer.aggregate()
        hub.assert_not_called()
        self.assertEqual(self.output.read_text(), 'before\n')

        with chdir(self.root), patch.object(transfer, 'require_manual_dispatch'), \
             patch.object(transfer, 'require_current_source'), \
             patch.object(transfer, 'hub', side_effect=self.hub_mock(private='false')) as hub:
            with self.assertRaisesRegex(ValueError, 'visibility metadata'):
                transfer.aggregate()
        self.assertEqual(hub.call_count, 2)
        self.assertEqual(self.output.read_text(), 'before\n')


if __name__ == '__main__':
    unittest.main()
