"""The SQLite overlay and preferred sources have a separate native identity."""
import copy
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import build_patched_sqlite as build
import collect_package_sources as collection
import package_source_notices as notices


class SQLiteSourceDistributionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        (self.root / 'docs').mkdir()
        spec = copy.deepcopy(build.reviewed_spec())
        for number, field in enumerate(('expected_library_sha256', 'compiler_sha256',
                                        'expected_vendor_library_sha256'), 1):
            spec[field] = {arch: str(number) * 64 for arch in build.TARGETS}
        (self.root / 'docs/sqlite-build.json').write_bytes(build.json_bytes(spec))
        self.spec = build.reviewed_spec(self.root)
        self.manifest = build.expected_manifest('amd64', self.root)
        self.replacement = {'build_lock': self.spec,
            'build_lock_sha256': build.digest(build.json_bytes(self.spec)),
            'manifest': self.manifest,
            'manifest_sha256': build.digest(build.json_bytes(self.manifest)),
            'library': {'path': '/usr/lib/' + build.LIBRARY,
                        'sha256': self.manifest['library']['sha256']}}

    def test_runtime_overlay_matches_native_lock_and_never_claims_vendor_signature(self):
        inventory = {'sqlite_replacement': self.replacement}
        result = collection.verify_sqlite_replacement(inventory, 'amd64', root=self.root)
        self.assertFalse(result['manifest']['vendor_apk_signature_applies_to_replacement'])
        for field in ('build_lock_sha256', 'manifest_sha256', 'library'):
            changed = copy.deepcopy(inventory)
            changed['sqlite_replacement'][field] = 'f' * 64
            with self.subTest(field=field), self.assertRaises(ValueError):
                collection.verify_sqlite_replacement(changed, 'amd64', root=self.root)
        for arch, qualified in (('arm64', True), ('amd64', False)):
            changed = copy.deepcopy(inventory)
            changed['sqlite_replacement']['manifest']['qualified'] = qualified
            with self.subTest(arch=arch, qualified=qualified), self.assertRaises(ValueError):
                collection.verify_sqlite_replacement(changed, arch, root=self.root)
        with self.assertRaises(ValueError):
            collection.verify_sqlite_replacement({}, 'amd64', root=self.root)

    def archive(self):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode='w:gz') as archive:
            for name, body in (('fixture/Makefile', b'all: library\n'),
                               ('fixture/fixture.c', b'int fixture(void) { return 1; }\n'),
                               ('fixture/LICENSE', b'Copyright Fixture. Permission is hereby granted to use this fixture.\n')):
                member = tarfile.TarInfo(name)
                member.size = len(body)
                archive.addfile(member, io.BytesIO(body))
        return stream.getvalue()

    def test_notice_collection_checks_both_original_archives_without_an_oci_claim(self):
        source = self.root / 'preferred-source'
        source.mkdir()
        records = []
        for name in ('first.tar.gz', 'second.tar.gz'):
            body = self.archive()
            (source / name).write_bytes(body)
            records.append({'path': name, 'url': 'https://example.invalid/' + name,
                'sha256': hashlib.sha256(body).hexdigest(), 'role': 'upstream-source'})
        with patch.object(build, 'source_download_records', return_value=records):
            report = notices.inspect_sqlite_overlay_sources(source, self.root / 'notices',
                architecture='amd64', root=self.root,
                replacement_manifest_sha256=self.replacement['manifest_sha256'])
            self.assertTrue(report['success'])
            self.assertFalse(report['provider_oci_binding'])
            self.assertIsNone(report['source_image_digest'])
            self.assertEqual(report['origin'], 'sqlite-overlay')
            (source / records[0]['path']).write_bytes(b'tampered')
            with self.assertRaisesRegex(ValueError, 'differs from reviewed inputs'):
                notices.inspect_sqlite_overlay_sources(source, self.root / 'rejected',
                    architecture='amd64', root=self.root,
                    replacement_manifest_sha256=self.replacement['manifest_sha256'])
