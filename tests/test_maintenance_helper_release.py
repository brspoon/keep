"""Immutable helper publication from exact local release source, offline."""
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import helper_bundle
import release_materials as materials
import package_maintenance_helper as packager


class HelperReleaseTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name).resolve()
        for name in helper_bundle.FILES:
            (self.root / name).write_text('# synthetic reviewed helper source: ' + name + '\n')
        (self.root / '.env').write_text('SECRET=synthetic-private-value\n')
        self.cwd = Path.cwd()
        os.chdir(self.root)
        self.addCleanup(os.chdir, self.cwd)
        self.environment = patch.dict(os.environ, {'GITHUB_SHA': 'a' * 40})
        self.environment.start()
        self.addCleanup(self.environment.stop)
        with tempfile.TemporaryDirectory() as temporary:
            path, _ = packager.write_asset(self.root, temporary, '2.26.0', 'a' * 40)
            self.assets = [{'name': item.name, 'digest': 'sha256:' + hashlib.sha256(item.read_bytes()).hexdigest(),
                           'size': item.stat().st_size, 'payload': item.read_bytes()}
                          for item in (path, path.with_name(path.name + '.sha256'))]

    def verify(self, assets=None):
        with patch.object(materials, 'asset_body', side_effect=lambda asset: asset['payload']):
            return materials.verify_helper('2.26.0', {'assets': self.assets if assets is None else assets})

    def test_complete_published_bytes_match_reviewed_revision_without_private_files(self):
        proof = self.verify()
        self.assertEqual(proof['sha256'], self.assets[0]['digest'][7:])
        contents, manifest = helper_bundle.inspect_bundle(self.assets[0]['payload'], version='2.26.0',
            revision='a' * 40, expected_sha256=proof['sha256'])
        self.assertEqual(set(contents), set(helper_bundle.FILES))
        self.assertNotIn(b'synthetic-private-value', b''.join(contents.values()))
        self.assertEqual(proof['manifest_sha256'], hashlib.sha256(helper_bundle.canonical(manifest)).hexdigest())

    def test_missing_duplicate_or_wrong_checksum_asset_is_rejected(self):
        for assets in (self.assets[:1], self.assets + [self.assets[0]],
                       [self.assets[0], {**self.assets[1], 'payload': b'changed checksum'}]):
            with self.subTest(assets=len(assets)), self.assertRaises(ValueError):
                self.verify(assets)

    def test_asset_metadata_and_response_tamper_are_rejected(self):
        for change in ({'digest': 'sha256:' + '0' * 64}, {'size': 1}, {'payload': b'tampered archive'}):
            with self.subTest(change=next(iter(change))), self.assertRaises(ValueError):
                self.verify([{**self.assets[0], **change}, self.assets[1]])

    def test_changed_revision_or_source_is_rejected(self):
        with patch.dict(os.environ, {'GITHUB_SHA': 'b' * 40}), self.assertRaises(ValueError):
            self.verify()
        (self.root / helper_bundle.FILES[0]).write_text('# changed source\n')
        with self.assertRaises(ValueError):
            self.verify()

    def test_publication_uploads_only_original_bundle_and_checksum(self):
        uploaded = []
        with patch.object(materials, 'guard', return_value='2.26.0'), \
             patch.object(materials, 'draft', return_value={'id': 1}), \
             patch.object(materials, 'upload', side_effect=lambda release, path: uploaded.append((path.name, path.read_bytes()))):
            materials.archive_helper()
        self.assertEqual(uploaded, [(item['name'], item['payload']) for item in self.assets])

    def test_existing_asset_reuse_is_deterministic_and_cannot_replace_revision(self):
        with tempfile.TemporaryDirectory() as temporary:
            first, _ = packager.write_asset(self.root, temporary, '2.26.0', 'a' * 40)
            body = first.read_bytes()
            second, _ = packager.write_asset(self.root, temporary, '2.26.0', 'a' * 40)
            self.assertEqual(second.read_bytes(), body)
            with self.assertRaises(ValueError):
                packager.write_asset(self.root, temporary, '2.26.0', 'b' * 40)
            self.assertEqual(first.read_bytes(), body)


if __name__ == '__main__':
    unittest.main()
