import copy
import hashlib
import io
import json
import lzma
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from package_source_notices import inspect_package_materials, merge_notice_bundles
from package_source_notices import GPL2_SHA256, MPL2_SHA256, import_public_notices, leading_notice
from package_source_notices import inspect_build_provenance_sources
import package_source_notices as notices


SOURCE_DIGEST = 'sha256:' + 'a' * 64
LICENSE = b'Full copyright and permission notice\nPermission is hereby granted to use this software.\n'
POSIXTZ_HEADER = (b'/* ripped from uclibc \n*\n'
    b'* Copyright (C) 2010 Denys Vlasenko <vda.linux@googlemail.com>\n'
    b'* Copyright (C) 2011 Natanael Copa <ncopa@alpinelinux.org>\n*\n'
    b'* GNU Library General Public License (LGPL) version 2 or later.\n*\n*/')


def archive(files, compressed=True):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w:gz' if compressed else 'w') as bundle:
        for name, value in files.items():
            member = tarfile.TarInfo(name)
            if isinstance(value, tuple):
                member.type = tarfile.SYMTYPE
                member.linkname = value[0]
                bundle.addfile(member)
            else:
                member.size = len(value)
                bundle.addfile(member, io.BytesIO(value))
    return output.getvalue()


class PackageNoticeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.materials = self.root / 'materials'
        self.materials.mkdir()
        self.records = []

    def tearDown(self):
        self.temp.cleanup()

    def add(self, source_path, body):
        relative = 'files/' + str(len(self.records))
        path = self.materials / relative
        path.parent.mkdir(exist_ok=True)
        path.write_bytes(body)
        record = {'type': 'file', 'path': relative, 'source_path': source_path,
                  'sha256': hashlib.sha256(body).hexdigest(), 'bytes': len(body)}
        self.records.append(record)
        return record

    def write_manifest(self):
        (self.materials / 'material-manifest.json').write_text(json.dumps({
            'schema': 1, 'binding_verified': True, 'source_image_digest': SOURCE_DIGEST,
            'files': self.records}))

    def inspect(self, output='notices', **kwargs):
        self.write_manifest()
        return inspect_package_materials(self.materials, self.root / output,
            origin='example', version='1.0-r0', architecture='amd64',
            expected_digest=SOURCE_DIGEST, **kwargs)

    def add_source(self):
        self.add('opt/docker/materials/sha256:source', archive({
            'project-1.0/LICENSE': LICENSE,
            'project-1.0/source.c': b'int main(void) { return 0; }\n',
            'project-1.0/Makefile': b'all:\n\tcc source.c\n'}))

    def test_hash_named_source_archive_and_full_notice(self):
        self.add_source()
        report = self.inspect()
        self.assertTrue(report['success'])
        self.assertTrue(report['preferred_source_present'])
        notice = next(n for n in report['notices'] if n['path'].endswith('LICENSE'))
        self.assertEqual((self.root / 'notices' / notice['notice_file']).read_bytes(), LICENSE)
        self.assertEqual(notice['provenance']['source_image_digest'], SOURCE_DIGEST)
        self.assertTrue(report['archives'])
        self.assertCountEqual((self.root / 'notices').glob('*'), [self.root / 'notices' / 'notices', self.root / 'notices' / 'package-material-inventory.json'])

    def test_numbered_gnu_copying_files_retain_full_license_and_provenance(self):
        self.add('source.tar.gz', archive({'project/source.c': b'int source;\n',
            'project/Makefile': b'all: source\n',
            'project/COPYING3': b'Complete GNU GPL version 3 license text\n',
            'project/COPYING3.LIB': b'Complete GNU LGPL version 3 license text\n'}))
        report = self.inspect()
        self.assertTrue(report['success'])
        self.assertEqual(report['standalone_notice_count'], 2)
        for notice in report['notices']:
            self.assertEqual(notice['provenance']['source_image_digest'], SOURCE_DIGEST)
            self.assertTrue((self.root / 'notices' / notice['notice_file']).read_bytes().startswith(b'Complete GNU'))

    def test_apk_wrapper_is_not_preferred_source(self):
        self.add('opt/docker/materials/sha256:binary', archive({
            '.PKGINFO': b'pkgname = example\n',
            'usr/lib/source.py': b'print("bundled bytecode wrapper")\n',
            'usr/share/licenses/example/LICENSE': LICENSE,
            'usr/lib/Makefile': b'all: bundled\n'}))
        report = self.inspect()
        self.assertFalse(report['success'])
        self.assertFalse(report['preferred_source_present'])
        self.assertFalse(report['notices'])
        self.assertTrue(any('APK' in item['reason'] for item in report['warnings']))

    def test_matching_digest_alone_and_git_objects_do_not_pass(self):
        self.add('opt/docker/git/aports/.git/objects/aa/bb', b'git compressed object')
        self.add('opt/docker/def/.def.yaml', b'image: dhi.io/pkg-example\n')
        report = self.inspect()
        self.assertFalse(report['success'])
        self.assertFalse(report['preferred_source_present'])

    def test_unrelated_aports_code_does_not_establish_package_source(self):
        self.add('opt/docker/git/aports/main/another-package/source.c', b'int other;\n')
        self.add('opt/docker/git/aports/main/example/APKBUILD', b'pkgname=example\n')
        self.add('opt/docker/git/aports/LICENSE', LICENSE)
        report = self.inspect()
        self.assertFalse(report['success'])
        self.assertFalse(report['preferred_source_present'])
        self.assertEqual(report['notices'], [])

    def test_unrelated_aports_recipe_and_notice_do_not_get_exported(self):
        self.add_source()
        self.add('opt/docker/git/aports/main/another/APKBUILD', b'pkgname=other\n')
        self.add('opt/docker/git/aports/main/another/COPYING', b'Other package license\n')
        report = self.inspect()
        self.assertTrue(report['success'])
        self.assertTrue(all('/another/' not in row['path'] for row in report['notices']))
        self.assertTrue(all('/another/' not in row['path'] for row in report['build_inputs']))

    def test_binary_notice_of_unrelated_aports_package_does_not_block_origin(self):
        self.add_source()
        self.add('opt/docker/git/aports/testing/another/LICENSE.pdf', b'%PDF\x00binary notice')
        report = self.inspect()
        self.assertTrue(report['success'])
        self.assertEqual(report['warnings'], [])

    def test_retained_material_checksum_is_rechecked(self):
        self.add_source()
        (self.materials / self.records[0]['path']).write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'checksum'):
            self.inspect()

    def test_source_image_digest_is_bound(self):
        self.add_source()
        self.write_manifest()
        with self.assertRaisesRegex(ValueError, 'source image'):
            inspect_package_materials(self.materials, self.root / 'notice',
                origin='example', version='1', architecture='amd64',
                expected_digest='sha256:' + 'b' * 64)

    def build_manifest(self):
        self.add_source()
        manifest = {'schema': 1, 'origin': 'example', 'version': '1.0-r0',
            'architecture': 'amd64', 'provider_oci_binding': True,
            'binding_method': 'signed-build-provenance', 'source_image_digest': None,
            'native_image_digest': SOURCE_DIGEST,
            'signed_statement_sha256': {'slsa': 'b' * 64, 'scout': 'c' * 64},
            'files': [{key: value for key, value in row.items() if key != 'type'}
                      for row in self.records]}
        body = json.dumps(manifest).encode()
        (self.materials / 'manifest.json').write_bytes(body)
        return manifest, hashlib.sha256(body).hexdigest()

    def inspect_build(self, manifest_sha, **kwargs):
        return inspect_build_provenance_sources(self.materials, self.root / 'build-notices',
            origin='example', version='1.0-r0', architecture='amd64',
            native_image_digest=SOURCE_DIGEST, source_manifest_sha256=manifest_sha, **kwargs)

    def test_build_provenance_inventory_has_actual_native_and_no_fake_source_digest(self):
        manifest, sha = self.build_manifest()
        report = self.inspect_build(sha)
        self.assertTrue(report['success'])
        self.assertIsNone(report['source_image_digest'])
        self.assertEqual(report['native_image_digest'], SOURCE_DIGEST)
        self.assertEqual(report['signed_statement_sha256'], manifest['signed_statement_sha256'])
        merged = merge_notice_bundles([self.root / 'build-notices'], self.root / 'runtime')
        self.assertEqual(merged['packages'][0]['native_image_digest'], SOURCE_DIGEST)

    def test_verified_replay_manifest_sha_must_match(self):
        manifest, sha = self.build_manifest()
        with self.assertRaisesRegex(ValueError, 'manifest checksum'):
            self.inspect_build('0' * 64)

    def test_build_provenance_native_identity_must_match(self):
        manifest, sha = self.build_manifest()
        manifest['native_image_digest'] = 'sha256:' + '0' * 64
        body = json.dumps(manifest).encode()
        (self.materials / 'manifest.json').write_bytes(body)
        with self.assertRaisesRegex(ValueError, 'native build binding'):
            self.inspect_build(hashlib.sha256(body).hexdigest())

    def test_build_provenance_retained_sources_are_rehashed(self):
        manifest, sha = self.build_manifest()
        (self.materials / self.records[0]['path']).write_bytes(b'changed sources')
        with self.assertRaisesRegex(ValueError, 'checksum'):
            self.inspect_build(sha)

    def test_catalog_other_package_cannot_substitute_for_python_sources(self):
        self.add('context/catalog-pinned/package/apk/main/another/LICENSE', LICENSE)
        self.add('context/catalog-pinned/package/apk/main/another/source.py', b'print("other")\n')
        self.add('context/catalog-pinned/package/apk/main/python/patch/fix.patch', b'--- a/source.c\n')
        self.add('build/provider.yaml', b'image: dhi.io/pkg-python-3.14\n')
        self.write_manifest()
        report = inspect_package_materials(self.materials, self.root / 'python-notices',
            origin='python-3.14', version='3.14.7-r2', architecture='amd64',
            expected_digest=SOURCE_DIGEST)
        self.assertFalse(report['success'])
        self.assertFalse(report['preferred_source_present'])
        self.assertFalse(report['notices'])

    def fixture_lock(self, *, fixture_sha=None, outer_sha=None, origin='example'):
        fixture = archive({'../deliberately-unsafe-test-entry': b'fixture'})
        body = archive({'example/source.c': b'int source;\n',
            'example/LICENSE': LICENSE, 'example/Makefile': b'all: source\n',
            'example/testdata/unsafe.tar.gz': fixture})
        record = self.add('example-source.tar.gz', body)
        lock = {'schema': 1, 'archives': [{'origin': origin, 'version': '1.0-r0',
            'upstream_archive_sha256': outer_sha or record['sha256'],
            'fixtures': [{'path': 'example/testdata/unsafe.tar.gz', 'bytes': len(fixture),
                'sha256': fixture_sha or hashlib.sha256(fixture).hexdigest(),
                'classification': 'upstream-archive-or-compression-test-fixture'}]}]}
        (self.root / 'docs').mkdir()
        (self.root / 'docs/source-archive-fixtures.json').write_text(json.dumps(lock))

    def test_exact_fixture_bytes_remain_in_outer_archive_without_unsafe_recursion(self):
        self.fixture_lock()
        with patch('package_source_notices.ROOT', self.root):
            report = self.inspect()
        self.assertTrue(report['success'])
        self.assertEqual(len(report['preserved_archive_fixtures']), 1)
        fixture = report['preserved_archive_fixtures'][0]
        self.assertTrue(fixture['bytes_preserved_in_original_source_archive'])
        self.assertFalse(fixture['recursively_interpreted'])
        self.assertFalse((self.root / 'deliberately-unsafe-test-entry').exists())

    def test_fixture_inner_sha_is_rechecked(self):
        self.fixture_lock(fixture_sha='0' * 64)
        with patch('package_source_notices.ROOT', self.root):
            with self.assertRaisesRegex(ValueError, 'fixture checksum'):
                self.inspect()

    def test_fixture_exception_cannot_apply_to_another_outer_archive(self):
        self.fixture_lock(outer_sha='0' * 64)
        with patch('package_source_notices.ROOT', self.root):
            with self.assertRaisesRegex(ValueError, 'Unsafe'):
                self.inspect()

    def test_fixture_exception_cannot_apply_to_another_origin(self):
        self.fixture_lock(origin='other')
        with patch('package_source_notices.ROOT', self.root):
            with self.assertRaisesRegex(ValueError, 'Unsafe'):
                self.inspect()

    def test_unsafe_nested_member_rejected_without_extraction(self):
        self.add('opt/docker/materials/sha256:source', archive({'../../outside': LICENSE}))
        with self.assertRaisesRegex(ValueError, 'Unsafe'):
            self.inspect()
        self.assertFalse((self.root / 'outside').exists())

    def test_archive_and_material_links_are_not_followed(self):
        self.add('opt/docker/materials/sha256:source', archive({
            'project/source.c': b'int n;\n', 'project/Makefile': b'all: source\n',
            'project/LICENSE': LICENSE, 'project/link': ('/etc/passwd',)}))
        self.records.append({'type': 'symlink', 'source_path': 'opt/docker/git/link',
                             'target': '/etc/passwd'})
        report = self.inspect()
        self.assertTrue(report['success'])
        self.assertEqual(report['links_not_followed'], 1)

    def test_nested_scan_limits_fail_coverage_instead_of_silent_success(self):
        self.add_source()
        report = self.inspect(max_archive_bytes=10)
        self.assertFalse(report['success'])
        self.assertFalse(report['notice_inventory_complete'])

    def test_excluded_binary_has_exact_provenance_and_no_payload(self):
        self.add_source()
        self.records.append({'type': 'excluded-binary', 'sha256': 'c' * 64, 'bytes': 100,
            'source_path': 'opt/docker/materials/sha256:' + 'c' * 64,
            'provenance': {'uri': 'https://dhi.io/apk/example.apk',
                           'digest': {'sha256': 'c' * 64}}})
        report = self.inspect()
        self.assertTrue(report['success'])
        self.assertEqual(len(report['excluded_binaries']), 1)
        self.records[-1]['provenance']['digest']['sha256'] = 'd' * 64
        with self.assertRaisesRegex(ValueError, 'provenance'):
            self.inspect(output='rejected')

    def test_complete_leading_header_is_copied_without_source_code(self):
        comment = b'/* Copyright Example\n * Licensed under the full notice above.\n */'
        self.add('opt/docker/context/source.c', comment + b'\nint main(void) {return 0;}\n')
        self.add('opt/docker/context/Makefile', b'all: source\n')
        report = self.inspect()
        self.assertTrue(report['success'])
        notice = report['notices'][0]
        self.assertEqual((self.root / 'notices' / notice['notice_file']).read_bytes(), comment)

    def test_notice_named_source_helpers_do_not_become_runtime_fulltexts(self):
        self.add_source()
        self.add('project/util/copyright.pm', b'# Copyright Example\n# All permission conditions.\npackage Copyright;\n')
        self.add('project/LICENCE.py', b'# Copyright Example\n# Full license conditions.\nprint("helper")\n')
        report = self.inspect()
        self.assertTrue(report['success'])
        self.assertTrue(all(not row['path'].endswith(('.pm', '.py')) for row in report['notices']))
        merged = merge_notice_bundles([self.root / 'notices'], self.root / 'runtime')
        self.assertEqual(len(merged['notices']), 1)

    def test_truncated_line_comment_is_not_called_complete(self):
        prefix = b'# Copyright Example\n# License conditions continue past the read cap'
        self.assertIsNone(leading_notice(prefix))
        self.assertEqual(leading_notice(prefix, complete_file=True), prefix)
        self.assertEqual(leading_notice(prefix + b'\nint code;\n'), prefix + b'\n')

    def test_multiple_complete_c_comments_include_the_actual_copyright(self):
        body = b'/* Description. */\n\n/* Copyright Example\n * Full redistribution terms. */'
        self.assertEqual(leading_notice(body + b'\nint code;\n'), body)
        self.assertIsNone(leading_notice(body + b'\n/* Additional copyright terms cut off'))

    def test_cpp_notice_stops_before_preprocessor_code(self):
        body = b'// Copyright Example\n// Full license conditions.\n\n'
        self.assertEqual(leading_notice(body + b'#include <vector>\n#define CODE 1\n'), body)

    def test_runtime_export_requires_explicit_source_header_selection(self):
        comment = b'/* Copyright Example\n * Licensed under the full notice above.\n */'
        self.add('opt/docker/context/source.c', comment + b'\nint code;\n')
        self.add('opt/docker/context/Makefile', b'all: code\n')
        report = self.inspect()
        self.assertTrue(report['success'])
        exported = merge_notice_bundles([self.root / 'notices'], self.root / 'without-header')
        self.assertEqual(exported['notices'], [])
        self.assertFalse(exported['ready_for_runtime_distribution'])
        exported = merge_notice_bundles([self.root / 'notices'], self.root / 'with-header',
            selected_comment_paths=[report['notices'][0]['path']])
        self.assertEqual(len(exported['notices']), 1)
        self.assertTrue(exported['ready_for_runtime_distribution'])

    def test_merged_notices_deduplicate_text_and_preserve_each_attribution(self):
        self.add_source()
        self.inspect()
        self.inspect(output='other-architecture')
        manifest = self.root / 'other-architecture' / 'package-material-inventory.json'
        report = json.loads(manifest.read_text())
        report['architecture'] = 'arm64'
        for notice in report['notices']:
            notice['provenance']['architecture'] = 'arm64'
        manifest.write_text(json.dumps(report))
        result = merge_notice_bundles([self.root / 'notices', self.root / 'other-architecture'],
                                     self.root / 'merged')
        self.assertEqual(len(result['notices']), 1)
        self.assertEqual(len(result['notices'][0]['provenance']), 2)
        self.assertEqual({path.suffix for path in (self.root / 'merged').iterdir()}, {'.txt', '.json'})

    def public_fixture(self):
        root = self.root / 'public'
        root.mkdir()
        records = []
        for name, body, role in [('source.tar.gz', b'retained source', 'upstream-source'),
                                 ('LICENSE', LICENSE, 'upstream-notice')]:
            (root / name).write_bytes(body)
            records.append({'path': name, 'bytes': len(body),
                'sha256': hashlib.sha256(body).hexdigest(), 'role': role,
                'url': 'https://example.test/' + name})
        manifest = {'schema': 1, 'origin': 'tzdata', 'version': '2026c-r0',
            'architecture': 'amd64', 'provider_oci_binding': False,
            'binding_method': 'Pinned public inputs, not an OCI claim',
            'files': records, 'coverage': 'Exact checked public sources'}
        (root / 'manifest.json').write_text(json.dumps(manifest))
        return root, manifest

    def test_public_import_replays_checker_and_has_no_invented_oci_digest(self):
        root, manifest = self.public_fixture()
        def replay(spec, arch, output, fetch):
            self.assertEqual(fetch('https://example.test/source.tar.gz'), b'retained source')
            return manifest
        with patch('tzdata_distribution_sources.collect_sources', side_effect=replay) as collector:
            report = import_public_notices(root, self.root / 'checked-public',
                origin='tzdata', architecture='amd64', package_spec={'origin': 'tzdata'})
        self.assertEqual(collector.call_count, 1)
        self.assertTrue(report['success'])
        self.assertIsNone(report['source_image_digest'])
        self.assertFalse(report['provider_oci_binding'])
        self.assertEqual(len(report['notices']), 1)

    def test_public_import_rejects_changed_notice_bytes(self):
        root, manifest = self.public_fixture()
        (root / 'LICENSE').write_bytes(b'changed terms')
        with self.assertRaisesRegex(ValueError, 'checksum'):
            import_public_notices(root, self.root / 'rejected-public',
                origin='tzdata', architecture='amd64', package_spec={'origin': 'tzdata'})

    def test_public_import_rejects_checker_manifest_disagreement(self):
        root, manifest = self.public_fixture()
        changed = {**manifest, 'version': '2026d-r0'}
        with patch('tzdata_distribution_sources.collect_sources', return_value=changed):
            with self.assertRaisesRegex(ValueError, 'verified inputs'):
                import_public_notices(root, self.root / 'rejected-public',
                    origin='tzdata', architecture='amd64', package_spec={'origin': 'tzdata'})

    def baselayout(self, *, source=True, license_name='GPL-2.0-only'):
        if source:
            self.add('opt/docker/git/aports/main/alpine-baselayout/usr_merge_nag.sh', b'#!/bin/sh\necho source\n')
        body = ('# Maintainer: Example\npkgname=alpine-baselayout\npkgver=3.7.2\n'
                'pkgrel=1\nlicense="' + license_name + '"\n').encode()
        self.add('opt/docker/git/aports/main/alpine-baselayout/APKBUILD', body)
        self.write_manifest()
        return inspect_package_materials(self.materials, self.root / 'baselayout-notices',
            origin='alpine-baselayout', version='3.7.2-r1', architecture='amd64',
            expected_digest=SOURCE_DIGEST)

    def test_baselayout_supplement_requires_exact_recipe_and_actual_own_source(self):
        report = self.baselayout()
        self.assertTrue(report['success'])
        notice = next(row for row in report['notices'] if row['sha256'] == GPL2_SHA256)
        self.assertEqual(notice['recipe_license_evidence'][0]['declarations']['license'], 'GPL-2.0-only')
        result = merge_notice_bundles([self.root / 'baselayout-notices'], self.root / 'runtime')
        self.assertEqual(result['notices'][0]['provenance'][0]['license_source_url'], notice['license_source_url'])

    def test_generic_gpl2_text_never_substitutes_for_missing_baselayout_source(self):
        report = self.baselayout(source=False)
        self.assertFalse(report['success'])
        self.assertTrue(all(row['sha256'] != GPL2_SHA256 for row in report['notices']))

    def test_baselayout_license_declaration_mismatch_cannot_receive_supplement(self):
        report = self.baselayout(license_name='GPL-3.0-only')
        self.assertFalse(report['success'])
        self.assertTrue(all(row['sha256'] != GPL2_SHA256 for row in report['notices']))

    def ca_certificates(self, *, version='20260909-r0', matching_source=True):
        comment = b'# This source is subject to Mozilla Public License v2.0.\n# Copyright Authors.\n\n'
        name = 'sources/ca-certificates-20260909.tar.bz2'
        data = archive({'ca-certificates-20260909/certdata.txt': comment + b'BEGINDATA\n',
                        'ca-certificates-20260909/Makefile': b'all: certdata.txt\n'})
        record = self.add(name, data)
        old = self.materials / record['path']; dest = self.materials / name
        dest.parent.mkdir(parents=True, exist_ok=True); old.rename(dest);record['path']=name
        self.write_manifest()
        constants = {'CA_SOURCE_SHA256': hashlib.sha256(data).hexdigest() if matching_source else '0' * 64,
                     'CA_CERTDATA_NOTICE_SHA256': hashlib.sha256(comment).hexdigest()}
        with patch.multiple('package_source_notices', **constants):
            return inspect_package_materials(self.materials, self.root / 'ca-notices',
                origin='ca-certificates', version=version, architecture='amd64', expected_digest=SOURCE_DIGEST)

    def test_ca_full_mpl_terms_require_exact_matching_certdata_source_and_header(self):
        report = self.ca_certificates()
        self.assertTrue(report['success'])
        full = next(row for row in report['notices'] if row['sha256'] == MPL2_SHA256)
        self.assertEqual(full['recipe_license_evidence'][0]['path'],
            'sources/ca-certificates-20260909.tar.bz2!ca-certificates-20260909/certdata.txt#leading-comment')
        merged = merge_notice_bundles([self.root / 'ca-notices'], self.root / 'ca-runtime')
        self.assertEqual(merged['notices'][0]['provenance'][0]['origin'], 'ca-certificates')

    def test_ca_mpl_supplement_cannot_apply_to_another_version(self):
        report = self.ca_certificates(version='20260611-r0')
        self.assertTrue(all(row['sha256'] != MPL2_SHA256 for row in report['notices']))

    def test_ca_mpl_supplement_cannot_apply_to_another_source_archive(self):
        report = self.ca_certificates(matching_source=False)
        self.assertTrue(all(row['sha256'] != MPL2_SHA256 for row in report['notices']))


class PosixTimezoneLicenseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.license = (notices.ROOT / notices.LGPL2_PATH).read_bytes()
        self.proof = {'schema': 1, 'origin': 'tzdata', 'version': '2026d-r0',
            'architecture': 'amd64', 'provider_oci_binding': True,
            'binding_method': 'signed-build-provenance', 'source_image_digest': None,
            'native_image_digest': SOURCE_DIGEST, 'source_manifest_sha256': 'b' * 64,
            'signed_statement_sha256': {'slsa': 'c' * 64, 'scout': 'd' * 64},
            'proof_architecture': 'amd64', 'for_packages': ['tzdata']}
        self.report = {**copy.deepcopy(self.proof), 'success': True,
            'retained_files': [{'path': notices.POSIXTZ_ARCHIVE_PATH,
                'source_path': notices.POSIXTZ_ARCHIVE_PATH,
                'sha256': notices.POSIXTZ_ARCHIVE_SHA256, 'bytes': notices.POSIXTZ_ARCHIVE_BYTES}],
            'readable_source_files': [{'path': notices.POSIXTZ_SOURCE_PATH, 'bytes': 1575}],
            'notices': [{'path': notices.POSIXTZ_NOTICE_PATH,
                'notice_file': 'notices/' + notices.POSIXTZ_NOTICE_SHA256 + '.txt',
                'sha256': notices.POSIXTZ_NOTICE_SHA256, 'bytes': notices.POSIXTZ_NOTICE_BYTES,
                'encoding': 'utf-8', 'discovery': 'complete-leading-legal-comment',
                'provenance': copy.deepcopy(self.proof)}],
            'standalone_notice_count': 0, 'reviewable_comment_count': 1,
            'requires_runtime_comment_selection': True}

    def supplement(self, report=None, **kwargs):
        return notices.supplement_posixtz_license(report if report is not None else self.report,
            license_bytes=kwargs.get('license_bytes', self.license),
            header_bytes=kwargs.get('header_bytes', POSIXTZ_HEADER))

    def test_exact_checked_full_license_is_derived_without_changing_original_proofs(self):
        original = copy.deepcopy(self.report)
        result = self.supplement()
        self.assertEqual(self.report, original)
        self.assertEqual(result['notices'][0], original['notices'][0])
        for key in self.proof:
            self.assertEqual(result[key], original[key])
        self.assertEqual(result['retained_files'], original['retained_files'])
        self.assertEqual(result['readable_source_files'], original['readable_source_files'])
        supplemental = result['notices'][-1]
        self.assertEqual(supplemental['license_source_url'], notices.LGPL2_SOURCE_URL)
        self.assertEqual(supplemental['recipe_license_evidence'], [{
            'path': notices.POSIXTZ_NOTICE_PATH, 'sha256': notices.POSIXTZ_NOTICE_SHA256,
            'bytes': notices.POSIXTZ_NOTICE_BYTES}])
        self.assertEqual(supplemental['provenance'], {
            **self.proof, 'license_text_provider_signature_verified': False})
        self.assertEqual(result['standalone_notice_count'], 1)
        self.assertEqual(result['reviewable_comment_count'], 1)
        self.assertFalse(result['requires_runtime_comment_selection'])
        self.assertEqual(self.supplement(result), result)

    def test_public_license_provenance_survives_runtime_notice_merge(self):
        result = self.supplement()
        directory = self.root / 'derived'
        (directory / 'notices').mkdir(parents=True)
        for row, body in zip(result['notices'], (POSIXTZ_HEADER, self.license)):
            (directory / row['notice_file']).write_bytes(body)
        (directory / 'package-material-inventory.json').write_text(json.dumps(result))
        merged = merge_notice_bundles([directory], self.root / 'runtime')
        self.assertTrue(merged['ready_for_runtime_distribution'])
        self.assertEqual(len(merged['notices']), 1)
        provenance = merged['notices'][0]['provenance'][0]
        self.assertFalse(provenance['license_text_provider_signature_verified'])
        self.assertEqual(provenance['license_source_url'], notices.LGPL2_SOURCE_URL)
        self.assertEqual(provenance['source_manifest_sha256'], self.proof['source_manifest_sha256'])
        self.assertEqual(provenance['signed_statement_sha256'], self.proof['signed_statement_sha256'])

    def test_other_package_version_or_incomplete_unsigned_inventory_is_rejected(self):
        for field, value in [('origin', 'other'), ('version', '2026c-r0'),
                             ('architecture', 'unknown'), ('success', False),
                             ('provider_oci_binding', False), ('binding_method', 'unsigned-source')]:
            report = copy.deepcopy(self.report)
            report[field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'reviewed signed tzdata 2026d'):
                self.supplement(report)

    def test_missing_duplicate_or_changed_source_archive_is_rejected(self):
        for mutation in ('missing', 'duplicate', 'path', 'source_path', 'hash', 'size'):
            report = copy.deepcopy(self.report)
            if mutation == 'missing':
                report['retained_files'] = []
            elif mutation == 'duplicate':
                report['retained_files'] *= 2
            elif mutation == 'hash':
                report['retained_files'][0]['sha256'] = 'f' * 64
            elif mutation == 'size':
                report['retained_files'][0]['bytes'] += 1
            else:
                report['retained_files'][0][mutation] = 'sources/another.tar.xz'
            with self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError, 'exact retained source archive'):
                self.supplement(report)

    def test_missing_or_changed_readable_preferred_source_is_rejected(self):
        for mutation in ('missing', 'duplicate', 'path'):
            report = copy.deepcopy(self.report)
            if mutation == 'missing':
                report['readable_source_files'] = []
            elif mutation == 'duplicate':
                report['readable_source_files'] *= 2
            else:
                report['readable_source_files'][0]['path'] = 'sources/other/source.c'
            with self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError, 'exact readable preferred source'):
                self.supplement(report)

    def test_full_header_record_and_actual_bytes_are_mandatory(self):
        for mutation in ('missing', 'duplicate', 'hash', 'size', 'discovery', 'encoding', 'notice_file'):
            report = copy.deepcopy(self.report)
            if mutation == 'missing':
                report['notices'] = []
            elif mutation == 'duplicate':
                report['notices'] *= 2
            else:
                field, value = {
                    'hash': ('sha256', 'f' * 64), 'size': ('bytes', 216),
                    'discovery': ('discovery', 'notice-file'), 'encoding': ('encoding', 'latin-1'),
                    'notice_file': ('notice_file', '../unreviewed.txt')}[mutation]
                report['notices'][0][field] = value
            with self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError, 'complete checked LGPL source header'):
                self.supplement(report)
        for body in (None, POSIXTZ_HEADER[:-1], b'x' + POSIXTZ_HEADER[1:]):
            with self.subTest(body_type=type(body).__name__), self.assertRaisesRegex(ValueError, 'complete checked LGPL source header'):
                self.supplement(header_bytes=body)

    def test_header_cannot_change_original_source_or_signed_proof_identity(self):
        for field, value in [('version', '2026c-r0'), ('architecture', 'arm64'),
                             ('source_manifest_sha256', 'f' * 64), ('native_image_digest', 'sha256:' + 'f' * 64),
                             ('signed_statement_sha256', {'slsa': 'f' * 64, 'scout': 'd' * 64}),
                             ('proof_architecture', 'arm64'), ('for_packages', ['other'])]:
            report = copy.deepcopy(self.report)
            report['notices'][0]['provenance'][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'original signed source provenance'):
                self.supplement(report)

    def test_missing_truncated_or_changed_full_license_is_rejected(self):
        for body in (None, self.license[:-1], b'x' + self.license[1:]):
            with self.subTest(body_type=type(body).__name__), self.assertRaisesRegex(ValueError, 'full LGPL license checksum or size'):
                self.supplement(license_bytes=body)

    def test_existing_license_supplement_cannot_have_a_different_derivation(self):
        report = self.supplement()
        report['notices'][-1]['provenance']['license_text_provider_signature_verified'] = True
        with self.assertRaisesRegex(ValueError, 'supplement differs from the checked derivation'):
            self.supplement(report)

    def test_fresh_signed_source_collection_uses_the_same_checked_supplement(self):
        source = lzma.compress(archive({'posixtz-0.5/posixtz.c': POSIXTZ_HEADER + b'\nint source;\n',
                                       'posixtz-0.5/Makefile': b'all: posixtz.c\n'}, compressed=False))
        directory = self.root / 'preferred'
        (directory / 'sources').mkdir(parents=True)
        (directory / notices.POSIXTZ_ARCHIVE_PATH).write_bytes(source)
        record = {'path': notices.POSIXTZ_ARCHIVE_PATH, 'source_path': notices.POSIXTZ_ARCHIVE_PATH,
                  'sha256': hashlib.sha256(source).hexdigest(), 'bytes': len(source), 'role': 'signed-upstream-source'}
        manifest = {key: value for key, value in self.proof.items()
                    if key not in ('source_manifest_sha256', 'proof_architecture', 'for_packages')}
        manifest['files'] = [record]
        body = json.dumps(manifest).encode()
        (directory / 'manifest.json').write_bytes(body)
        output = self.root / 'fresh-notices'
        with patch.multiple(notices, POSIXTZ_ARCHIVE_SHA256=record['sha256'], POSIXTZ_ARCHIVE_BYTES=record['bytes']), \
                patch.object(notices, 'supplement_posixtz_license', wraps=notices.supplement_posixtz_license) as helper:
            report = inspect_build_provenance_sources(directory, output, origin='tzdata', version='2026d-r0',
                architecture='amd64', native_image_digest=SOURCE_DIGEST,
                source_manifest_sha256=hashlib.sha256(body).hexdigest())
        helper.assert_called_once()
        self.assertTrue(report['success'])
        supplemental = next(row for row in report['notices'] if row['sha256'] == notices.LGPL2_SHA256)
        self.assertEqual((output / supplemental['notice_file']).read_bytes(), self.license)
        self.assertFalse(supplemental['provenance']['license_text_provider_signature_verified'])
        self.assertEqual(report['source_manifest_sha256'], hashlib.sha256(body).hexdigest())


if __name__ == '__main__':
    unittest.main()
