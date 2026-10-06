"""Source packaging must match reviewed releases and actual native wheel bytes."""
import importlib.util
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
spec = importlib.util.spec_from_file_location('build_distribution_bundle', ROOT / 'scripts/build_distribution_bundle.py')
bundle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bundle)


class DistributionBundleTests(unittest.TestCase):
    def test_replaced_source_release_is_rejected(self):
        lock = {'python': [{'name': 'fixture', 'version': '1.0', 'filename': 'fixture-1.0.tar.gz',
                            'url': 'https://files.pythonhosted.org/fixture.tar.gz', 'sha256': 'a' * 64}]}
        release = {'info': {'name': 'fixture', 'version': '1.0'}, 'urls': [{
            'packagetype': 'sdist', 'filename': 'fixture-1.0.tar.gz',
            'url': lock['python'][0]['url'], 'digests': {'sha256': 'b' * 64}}]}
        fetch = bundle.source_fetch(lock, fetch=lambda url: json.dumps(release).encode())
        with self.assertRaisesRegex(ValueError, 'reviewed source lock'):
            fetch('https://pypi.org/pypi/fixture/1.0/json')

    def native_fixture(self):
        wheels = [{'package': name, 'version': '1.0', 'architecture': 'x86_64',
                   'binary_path': name + '.so', 'binary_sha256': 'a' * 64}
                  for name in ('cffi', 'argon2-cffi-bindings')]
        inventory = {'python': [{'name': w['package'], 'version': w['version'], 'native_files': [{
            'path': w['binary_path'], 'sha256': w['binary_sha256']}]} for w in wheels]}
        return inventory, {'native_wheels': {'native_wheels': wheels}}

    def test_modified_installed_native_binary_is_rejected(self):
        inventory, lock = self.native_fixture()
        bundle.check_native_wheels(inventory, lock, 'amd64')
        inventory['python'][0]['native_files'][0]['sha256'] = 'b' * 64
        with self.assertRaisesRegex(ValueError, 'Runtime native wheel differs'):
            bundle.check_native_wheels(inventory, lock, 'amd64')

    def test_missing_native_source_identity_is_rejected(self):
        inventory, lock = self.native_fixture()
        lock['native_wheels']['native_wheels'].pop()
        with self.assertRaisesRegex(ValueError, 'Both embedded native'):
            bundle.check_native_wheels(inventory, lock, 'amd64')


# These use real content-addressed OCI archives for the APK and source checks;
# only the independently tested public-key verifier is substituted in orchestration.
import copy
import base64
import gzip
import hashlib
import io
import tarfile
import tempfile
import shutil
import subprocess
import os
from unittest.mock import patch


def oci_fixture(root, entries, arch='amd64'):
    root.mkdir(parents=True)
    (root / 'oci-layout').write_text('{"imageLayoutVersion":"1.0.0"}')
    blobs = root / 'blobs/sha256'
    blobs.mkdir(parents=True)

    def blob(body, media):
        value = hashlib.sha256(body).hexdigest()
        (blobs / value).write_bytes(body)
        return {'digest': 'sha256:' + value, 'size': len(body), 'mediaType': media}
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w:gz') as archive:
        for name, body in entries:
            member = tarfile.TarInfo(name)
            member.size = len(body)
            archive.addfile(member, io.BytesIO(body))
    layer = blob(stream.getvalue(), 'application/vnd.oci.image.layer.v1.tar+gzip')
    config = blob(json.dumps({'os': 'linux', 'architecture': arch}).encode(),
                  'application/vnd.oci.image.config.v1+json')
    raw = json.dumps({'schemaVersion': 2, 'config': config, 'layers': [layer]}).encode()
    manifest = blob(raw, 'application/vnd.oci.image.manifest.v1+json')
    (root / 'index.json').write_text(json.dumps({'schemaVersion': 2, 'manifests': [manifest]}))
    return manifest['digest'], raw


class BundleCoverageTests(DistributionBundleTests):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def runtime_fixture(self):
        inventory, lock = self.native_fixture()
        lock['python'] = [{'name': row['name'], 'version': row['version']} for row in inventory['python']]
        package = {'name': 'fixture', 'version': '1-r0', 'build_commit': 'abc', 'license': 'MIT',
                   'binaries': {'amd64': {'sha256': 'a' * 64}}}
        os_lock = {'origins': [{'origin': 'fixture', 'version': '1-r0', 'packages': [package]}]}
        inventory['os_packages'] = [{**{key: package[key] for key in ('name', 'version', 'build_commit', 'license')},
                                     'origin': 'fixture'}]
        return inventory, lock, os_lock

    def test_runtime_inventory_covers_os_and_python_exactly(self):
        inventory, lock, os_lock = self.runtime_fixture()
        self.assertEqual(bundle.check_runtime(inventory, lock, os_lock, 'amd64')['os_packages'], 1)
        for field, value in [('version', '2-r0'), ('origin', 'other'), ('build_commit', 'changed')]:
            modified = copy.deepcopy(inventory)
            modified['os_packages'][0][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'Runtime OS packages'):
                bundle.check_runtime(modified, lock, os_lock, 'amd64')
        inventory['python'].append({'name': 'uncovered', 'version': '1.0'})
        with self.assertRaisesRegex(ValueError, 'Runtime Python packages'):
            bundle.check_runtime(inventory, lock, os_lock, 'amd64')

    def test_inventory_is_mandatory(self):
        with self.assertRaisesRegex(ValueError, 'runtime inventory is required'):
            bundle.build_bundle(self.root, 'amd64', None, self.root / 'output')

    def test_each_origin_must_complete_once_and_on_the_correct_architecture(self):
        os_lock = {'origins': [{'origin': name} for name in ('one', 'two')]}
        report = {'format': 'keep-os-package-source-acquisition-v1', 'architecture': 'amd64',
                  'success': True, 'pending_origins': [],
                  'origins': [{'origin': name, 'success': True} for name in ('one', 'two')]}
        self.assertEqual(set(bundle.report_origins(report, os_lock, 'amd64')), {'one', 'two'})
        for mutation in ('missing', 'duplicate', 'pending', 'failed', 'architecture'):
            modified = copy.deepcopy(report)
            if mutation == 'missing':
                modified['origins'].pop()
            elif mutation == 'duplicate':
                modified['origins'].append(modified['origins'][0])
            elif mutation == 'pending':
                modified['pending_origins'] = ['two']
            elif mutation == 'failed':
                modified['origins'][1]['success'] = False
            else:
                modified['architecture'] = 'arm64'
            with self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError, 'Every reviewed OS origin'):
                bundle.report_origins(modified, os_lock, 'amd64')

    def package_fixture(self):
        acquisition_root = self.root / 'acquisition'
        package_root = acquisition_root / 'fixture'
        binary = b'actual reviewed APK bytes'
        binary_sha = hashlib.sha256(binary).hexdigest()
        native, index = oci_fixture(package_root / 'package-output-oci', [('output/fixture.apk', binary)])
        (package_root / 'package-image-index.json').write_bytes(index)
        recipe = b'complete build recipe'
        (package_root / 'recipe.yaml').write_bytes(recipe)
        origin = {'origin': 'fixture', 'version': '1-r0', 'image': 'dhi.io/pkg-fixture',
                  'predicate_image_name': 'dhi/pkg-fixture', 'recipe': {'sha256': hashlib.sha256(recipe).hexdigest()},
                  'packages': [{'name': 'fixture', 'version': '1-r0',
                                'binaries': {'amd64': {'sha256': binary_sha}}}]}
        matched = bundle.match_package_output(package_root / 'package-output-oci', native, 'amd64',
                                               bundle.expected_packages(origin, 'amd64'))
        bundle.write_json(package_root / 'package-output-match.json', matched)
        source_root = package_root / 'sources/proof'
        tool = b'out of scope tool APK bytes'
        tool_sha = hashlib.sha256(tool).hexdigest()
        provenance = {'predicate': {'buildDefinition': {'resolvedDependencies': [
            {'uri': 'https://example.test/tool-1.apk', 'digest': {'sha256': tool_sha}}]}}}
        source_digest, _ = oci_fixture(source_root / 'dhi-source-oci', [
            ('bin/busybox', b'bootstrap ELF'), ('opt/docker/dhi/source', b'vendor bootstrap ELF'),
            ('opt/docker/context/source.c', b'/* Copyright Fixture Authors */\nint main(void) {return 0;}\n'),
            ('opt/docker/context/Makefile', b'all:\n\tcc source.c\n'),
            ('opt/docker/context/LICENSE', b'Copyright Fixture Authors. Permission is hereby granted to use this fixture.'),
            ('opt/docker/materials/hash-named-tool', tool),
            ('opt/docker/materials/keep-input', b'preferred build input retained'),
            ('opt/docker/provenance/.prov.json', json.dumps(provenance).encode())])
        proof = {'source_image_digest': source_digest, 'attestation_digest': 'sha256:' + 'b' * 64,
                 'native_image_digest': native, 'signature_verified': True}
        result = {'origin': 'fixture', 'version': '1-r0', 'architecture': 'amd64', 'success': True,
                  'provider_oci_binding': True, 'native_image_digest': native, 'image_index_digest': bundle.digest(index),
                  'index_is_native_manifest': True, 'apk_matches': matched['apk_matches'],
                  'source_results': [{'directory': 'sources/proof', 'source_image_digest': source_digest,
                                      'attestation_digest': proof['attestation_digest'],
                                      'signature_verified': True, 'provider_oci_binding': True}]}
        report = {'format': 'keep-os-package-source-acquisition-v1', 'architecture': 'amd64',
                  'success': True, 'origins': [result], 'pending_origins': []}
        bundle.write_json(package_root / 'acquisition.json', result)
        bundle.write_json(acquisition_root / 'package-sources.json', report)
        return acquisition_root, origin, result, proof, tool_sha

    def test_source_curation_checks_real_apks_and_excludes_only_provenance_bound_tools(self):
        source, origin, result, proof, tool_sha = self.package_fixture()
        target = self.root / 'curated'
        with patch.object(bundle, 'verify_source_proof', return_value=proof) as verifier, \
                patch.object(bundle, 'copy_proof'):
            coverage = bundle.retain_packages(source, target, {'origins': [origin]}, 'amd64')
        verifier.assert_called_once_with(source / 'fixture/sources/proof', 'amd64',
            expected_base_digest=result['image_index_digest'], expected_native_digest=result['native_image_digest'],
            index_is_native_manifest=True, expected_repository=origin['image'],
            expected_source_name=origin['predicate_image_name'])
        self.assertTrue(coverage[0]['apk_binary_match_verified'])
        records = bundle.file_records(target)
        contents = b''.join((target / row['path']).read_bytes() for row in records)
        self.assertIn(b'preferred build input retained', contents)
        self.assertIn(b'Copyright Fixture Authors', contents)
        self.assertNotIn(b'out of scope tool APK bytes', contents)
        self.assertNotIn(b'bootstrap ELF', contents)
        self.assertFalse(any('package-output-oci/' in row['path'] or 'dhi-source-oci/' in row['path'] for row in records))
        manifest = bundle.read_json(target / 'fixture/sources/proof/materials', 'material-manifest.json')
        self.assertEqual(manifest['excluded_binary_digests'], [tool_sha])
        self.assertTrue(any(row['type'] == 'excluded-binary' for row in manifest['files']))

    def test_success_flags_cannot_replace_actual_binary_matching(self):
        source, origin, result, proof, _ = self.package_fixture()
        origin['packages'][0]['binaries']['amd64']['sha256'] = 'f' * 64
        with self.assertRaisesRegex(ValueError, 'does not contain reviewed APK bytes'):
            bundle.retain_packages(source, self.root / 'curated', {'origins': [origin]}, 'amd64')

    def test_tampered_match_report_is_rejected_even_with_original_binary(self):
        source, origin, result, proof, _ = self.package_fixture()
        manifest = bundle.read_json(source / 'fixture', 'package-output-match.json')
        manifest['apk_matches'][0]['matches'][0]['path'] = 'invented.apk'
        bundle.write_json(source / 'fixture/package-output-match.json', manifest)
        with self.assertRaisesRegex(ValueError, 'APK matches differ'):
            bundle.retain_packages(source, self.root / 'curated', {'origins': [origin]}, 'amd64')

    def test_timezone_fallback_cannot_claim_provider_signature_or_skip_reviewed_hashes(self):
        origin = {'origin': 'tzdata', 'version': '2026c-r0', 'packages': [
            {'name': 'tzdata', 'version': '2026c-r0', 'binaries': {'amd64': {'sha256': 'a' * 64}}}]}
        result = {'provider_oci_binding': False, 'source_results': [],
                  'reviewed_apks': bundle.expected_packages(origin, 'amd64'),
                  'candidate_failures': [{'failure_kind': 'apk-binary-mismatch'}]}
        for mutation in ('signature', 'invented_native', 'hash', 'missing_tag_mismatch'):
            modified = copy.deepcopy(result)
            if mutation == 'signature':
                modified['provider_oci_binding'] = True
            elif mutation == 'invented_native':
                modified['native_image_digest'] = 'sha256:' + 'b' * 64
            elif mutation == 'hash':
                modified['reviewed_apks'][0]['sha256'] = 'f' * 64
            else:
                modified['candidate_failures'] = []
            with self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError, 'Invalid unsigned timezone'):
                bundle.retain_timezone(self.root, self.root / 'timezone', origin, modified, 'amd64')

    def test_manifest_and_archive_cover_actual_bytes_reproducibly(self):
        stage = self.root / 'stage'
        stage.mkdir()
        (stage / 'source.c').write_bytes(b'complete source')
        (stage / 'recipe.sh').write_bytes(b'build recipe')
        (stage / 'recipe.sh').chmod(0o755)
        records = bundle.file_records(stage)
        bundle.write_json(stage / 'MANIFEST.json', {'files': records})
        first, second = self.root / 'first.gz', self.root / 'second.gz'
        bundle.archive_tree(stage, first, 'bundle')
        bundle.archive_tree(stage, second, 'bundle')
        self.assertEqual(first.read_bytes(), second.read_bytes())
        with tarfile.open(first) as archive:
            manifest = json.load(archive.extractfile('bundle/MANIFEST.json'))
            for row in manifest['files']:
                body = archive.extractfile('bundle/' + row['path']).read()
                self.assertEqual(hashlib.sha256(body).hexdigest(), row['sha256'])
                self.assertEqual(len(body), row['bytes'])
            self.assertEqual(archive.getmember('bundle/recipe.sh').mode, 0o755)
        (stage / 'escape').symlink_to(self.root / 'outside')
        with self.assertRaisesRegex(ValueError, 'symlinks'):
            bundle.file_records(stage)

    def test_checked_source_paths_reject_symlinks_and_parent_escape(self):
        (self.root / 'outside').write_text('outside source')
        (self.root / 'source').symlink_to(self.root / 'outside')
        with self.assertRaisesRegex(ValueError, 'symlinks'):
            bundle.regular(self.root, 'source')
        with self.assertRaisesRegex(ValueError, 'Unsafe archive'):
            bundle.regular(self.root, '../outside')


class NoarchBundleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def fixture(self):
        body = io.BytesIO()
        with tarfile.open(fileobj=body, mode='w:gz') as apk:
            pkginfo = b'pkgname = ncurses-terminfo-base\npkgver = 6.6_p20260516-r0\narch = noarch\n'
            entry = tarfile.TarInfo('.PKGINFO')
            entry.size = len(pkginfo)
            apk.addfile(entry, io.BytesIO(pkginfo))
        compiled, noarch = b'compiled amd64 APK bytes', body.getvalue()
        origin = {'origin': 'ncurses', 'version': '6.6_p20260516-r0',
                  'architecture_independent_outputs': {'ncurses-terminfo-base': 'arm64'},
                  'packages': [{'name': name, 'version': '6.6_p20260516-r0',
                                'binaries': {'amd64': {'sha256': hashlib.sha256(value).hexdigest()}}}
                               for name, value in [('ncurses', compiled), ('ncurses-terminfo-base', noarch)]]}
        from collect_package_sources import reviewed_output_groups
        plans = reviewed_output_groups(origin, 'amd64')
        outputs, proofs = [], []
        for plan, value in zip(plans, [compiled, noarch]):
            arch = plan['architecture']
            directory = 'package-output-oci' if arch == 'amd64' else 'package-output-arm64-oci'
            native, index = oci_fixture(self.root / directory, [('output/package.apk', value)], arch)
            matched = bundle.match_package_output(self.root / directory, native, arch, plan['packages'],
                                                   allow_noarch=plan['allow_noarch'])
            proof_directory = 'sources/' + arch
            path = self.root / proof_directory / 'pinned-base-index.json'
            path.parent.mkdir(parents=True)
            path.write_bytes(index)
            outputs.append({'architecture': arch, 'directory': directory, 'allow_noarch': plan['allow_noarch'],
                            'native_image_digest': native, 'image_index_digest': bundle.digest(index),
                            'index_is_native_manifest': True, 'apk_matches': matched['apk_matches']})
            proofs.append({'proof_architecture': arch, 'directory': proof_directory,
                           'for_packages': [package['name'] for package in plan['packages']]})
        return origin, {'output_groups': outputs, 'source_results': proofs}

    def test_reviewed_noarch_group_is_bound_to_its_actual_original_apk_and_signed_platform(self):
        origin, result = self.fixture()
        verified = bundle.retain_output_groups(self.root, self.root / 'retained', origin, result, 'amd64')
        self.assertEqual([row['architecture'] for row in verified], ['amd64', 'arm64'])
        self.assertTrue(verified[1]['allow_noarch'])
        identity = verified[1]['matched']['apk_matches'][0]['matches'][0]['package_identity']
        self.assertEqual(identity['arch'], 'noarch')

    def test_missing_cross_platform_proof_and_relaxed_noarch_flag_are_rejected(self):
        origin, result = self.fixture()
        for mutation in ('missing_proof', 'noarch_flag', 'package_overlap'):
            modified = copy.deepcopy(result)
            if mutation == 'missing_proof':
                modified['source_results'].pop()
            elif mutation == 'noarch_flag':
                modified['output_groups'][1]['allow_noarch'] = False
            else:
                modified['source_results'][1]['for_packages'] = ['ncurses']
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                bundle.retain_output_groups(self.root, self.root / mutation, origin, modified, 'amd64')


class NoticeInputRetentionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.inputs = self.root / 'checked-package-notices'
        self.inputs.mkdir()
        self.bodies = [b'Copyright Fixture Authors. Complete permission terms.\n',
                       b'/* Copyright Other Authors. Permission is granted. */\n']
        proof = {'origin': 'fixture', 'version': '1-r0', 'architecture': 'amd64',
                 'proof_architecture': 'arm64', 'for_packages': ['fixture-data'],
                 'native_image_digest': 'sha256:' + 'a' * 64,
                 'source_image_digest': None, 'provider_oci_binding': True,
                 'binding_method': 'signed-build-provenance',
                 'source_manifest_sha256': 'b' * 64,
                 'signed_statement_sha256': {'slsa': 'c' * 64, 'scout': 'd' * 64}}
        self.report = {**proof, 'schema': 1, 'success': True, 'notices': []}
        for number, body in enumerate(self.bodies):
            digest = hashlib.sha256(body).hexdigest()
            name = 'notices/' + digest + '.txt'
            target = self.inputs / name
            target.parent.mkdir(exist_ok=True)
            target.write_bytes(body)
            self.report['notices'].append({'notice_file': name, 'sha256': digest,
                'bytes': len(body), 'encoding': 'utf-8', 'path': 'source/' + str(number),
                'discovery': 'complete-leading-legal-comment' if number else 'notice-file',
                'provenance': proof})
        self.write_report()

    def write_report(self):
        body = (json.dumps(self.report, indent=3) + '\n\n').encode()
        (self.inputs / 'package-material-inventory.json').write_bytes(body)
        return body

    def test_retained_bytes_include_unselected_headers_and_replay_explicit_merge(self):
        from package_source_notices import merge_notice_bundles
        inventory = (self.inputs / 'package-material-inventory.json').read_bytes()
        (self.inputs / 'source.tar.gz').write_bytes(b'archive must stay outside notice inputs')
        (self.inputs / 'binary.apk').write_bytes(b'binary must stay outside notice inputs')
        output = self.root / 'notice-inputs'
        result = bundle.retain_notice_inputs([self.inputs, self.inputs], output, 'amd64')
        self.assertEqual(len(result['bundles']), 1)
        self.assertEqual(result['notice_files'], 2)
        retained = output / result['bundles'][0]['directory']
        self.assertEqual((retained / 'package-material-inventory.json').read_bytes(), inventory)
        self.assertEqual(result['bundles'][0]['inventory_sha256'], hashlib.sha256(inventory).hexdigest())
        self.assertEqual(result['bundles'][0]['inventory_bytes'], len(inventory))
        for notice, body in zip(self.report['notices'], self.bodies):
            self.assertEqual((retained / notice['notice_file']).read_bytes(), body)
        self.assertFalse((retained / 'source.tar.gz').exists())
        self.assertFalse((retained / 'binary.apk').exists())
        default = merge_notice_bundles([retained], self.root / 'default-merge')
        self.assertEqual(len(default['notices']), 1)
        explicit = merge_notice_bundles([retained], self.root / 'explicit-merge',
                                       selected_comment_paths=['source/1'])
        self.assertEqual(len(explicit['notices']), 2)
        proof = explicit['notices'][1]['provenance'][0]
        self.assertEqual(proof['architecture'], 'amd64')
        self.assertEqual(proof['proof_architecture'], 'arm64')
        self.assertEqual(proof['signed_statement_sha256'], self.report['signed_statement_sha256'])

    def test_large_full_inventory_retains_exact_bytes_without_relaxing_other_metadata(self):
        # Preserve a full inventory larger than ordinary metadata, including
        # insignificant whitespace that must not be rewritten during retention.
        inventory = self.write_report() + b' ' * (32 * 1024 * 1024)
        (self.inputs / 'package-material-inventory.json').write_bytes(inventory)
        with self.assertRaisesRegex(ValueError, 'Source metadata exceeds size limit'):
            bundle.read_json(self.inputs, 'package-material-inventory.json')
        output = self.root / 'large-notice-inputs'
        result = bundle.retain_notice_inputs([self.inputs], output, 'amd64')
        retained = output / result['bundles'][0]['directory'] / 'package-material-inventory.json'
        self.assertEqual(retained.read_bytes(), inventory)
        self.assertEqual(result['bundles'][0]['inventory_bytes'], len(inventory))
        self.assertEqual(result['bundles'][0]['inventory_sha256'], hashlib.sha256(inventory).hexdigest())

    def test_full_notice_inventory_limit_rejects_oversize_before_reading(self):
        path = self.inputs / 'package-material-inventory.json'
        with path.open('wb') as stream:
            stream.truncate(bundle.MAX_NOTICE_INVENTORY + 1)
        with patch.object(Path, 'open') as opened:
            with self.assertRaisesRegex(ValueError, 'Package notice inventory exceeds size limit'):
                bundle.read_notice_inventory(self.inputs)
        opened.assert_not_called()

    def test_full_notice_inventory_growth_still_has_a_bounded_read(self):
        inventory_path = unittest.mock.Mock()
        inventory_path.stat.return_value.st_size = 1
        stream = unittest.mock.Mock(wraps=io.BytesIO(b' ' * 257))
        manager = unittest.mock.MagicMock()
        manager.__enter__.return_value = stream
        inventory_path.open.return_value = manager
        with patch.object(bundle, 'MAX_NOTICE_INVENTORY', 256), \
                patch.object(bundle, 'regular', return_value=inventory_path):
            with self.assertRaisesRegex(ValueError, 'Package notice inventory exceeds size limit'):
                bundle.read_notice_inventory(self.inputs)
        inventory_path.open.assert_called_once_with('rb')
        stream.read.assert_called_once_with(257)

    def test_unselected_header_hash_and_length_are_rechecked(self):
        notice = self.report['notices'][1]
        path = self.inputs / notice['notice_file']
        for number, body in enumerate([b'x' * notice['bytes'], self.bodies[1] + b'truncated']):
            path.write_bytes(body)
            with self.subTest(mutation=number), self.assertRaisesRegex(ValueError, 'checksum or size'):
                bundle.retain_notice_inputs([self.inputs], self.root / ('changed-' + str(number)), 'amd64')

    def test_missing_unselected_header_is_rejected(self):
        (self.inputs / self.report['notices'][1]['notice_file']).unlink()
        with self.assertRaisesRegex(ValueError, 'input is missing'):
            bundle.retain_notice_inputs([self.inputs], self.root / 'missing', 'amd64')

    def test_unsafe_paths_and_linked_notice_inputs_are_rejected(self):
        original = self.report['notices'][1]['notice_file']
        self.report['notices'][1]['notice_file'] = '../escape.txt'
        self.write_report()
        with self.assertRaisesRegex(ValueError, 'Unsafe'):
            bundle.retain_notice_inputs([self.inputs], self.root / 'unsafe', 'amd64')
        self.report['notices'][1]['notice_file'] = original
        self.write_report()
        path = self.inputs / original
        path.unlink()
        path.symlink_to(self.inputs / self.report['notices'][0]['notice_file'])
        with self.assertRaisesRegex(ValueError, 'symlinks'):
            bundle.retain_notice_inputs([self.inputs], self.root / 'linked', 'amd64')

    def test_incomplete_or_other_native_inventory_is_rejected(self):
        original = copy.deepcopy(self.report)
        for number, mutation in enumerate([{'schema': 2}, {'success': False},
                                           {'architecture': 'arm64'}, {'notices': []}]):
            self.report = {**original, **mutation}
            self.write_report()
            with self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError, 'checked native inventory'):
                bundle.retain_notice_inputs([self.inputs], self.root / ('invalid-' + str(number)), 'amd64')

    def test_binary_or_empty_body_and_linked_output_are_rejected(self):
        for number, body in enumerate([b'\x7fELF\x00binary', b'BZhcompressed', b' \n']):
            digest = hashlib.sha256(body).hexdigest()
            notice = self.report['notices'][1]
            notice.update(notice_file='notices/' + digest + '.txt', sha256=digest, bytes=len(body))
            (self.inputs / notice['notice_file']).write_bytes(body)
            self.write_report()
            with self.subTest(body=body), self.assertRaisesRegex(ValueError, 'readable text'):
                bundle.retain_notice_inputs([self.inputs], self.root / ('binary-' + str(number)), 'amd64')
        output = self.root / 'linked-output'
        output.symlink_to(self.inputs, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'empty safe output'):
            bundle.retain_notice_inputs([self.inputs], output, 'amd64')

    def test_prepare_notices_exports_replay_inputs_without_automatic_header_selection(self):
        fixture_root = self.root / 'keep'
        bundle.write_json(fixture_root / 'docs/distribution-sources.json', {})
        bundle.write_json(fixture_root / 'docs/os-package-sources.json',
                          {'origins': [], 'original_base_origins': []})
        inventory = self.root / 'candidate.json'
        bundle.write_json(inventory, {})
        source = self.root / 'sources'
        output = self.root / 'preparation'

        def packages(_source, destination, *_args, **_kwargs):
            shutil.copytree(self.inputs, destination / 'fixture')
            return []

        def original(_source, destination, *_args, **_kwargs):
            bundle.write_json(destination / 'base-provenance.json', {})
            return {}

        with patch.object(bundle, 'check_runtime', return_value={}), \
                patch.object(bundle, 'retain_packages', side_effect=packages), \
                patch.object(bundle, 'retain_original_base', side_effect=original):
            report = bundle.prepare_notices(source, 'amd64', inventory, output, root=fixture_root)
        self.assertEqual(report['notice_inputs_directory'], 'notice-inputs')
        self.assertEqual(report['notice_input_bundles'], 1)
        self.assertEqual(report['notice_input_files'], 2)
        self.assertEqual(report['notices'], 1)
        manifest = bundle.read_json(output / 'os-notices', 'manifest.json')
        self.assertEqual(manifest['selected_source_comments'], [])
        index = bundle.read_json(output / 'notice-inputs', 'index.json')
        retained = output / 'notice-inputs' / index['bundles'][0]['directory']
        self.assertEqual(bundle.read_json(retained, 'package-material-inventory.json'), self.report)


class RuntimeNoticeBundleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.directory = self.root / 'docs/licenses/os'
        self.directory.mkdir(parents=True)
        self.lock = {'origins': [{'origin': 'fixture', 'version': '1-r0'}],
                     'original_base_origins': [{'origin': 'expat', 'version': '2.8.5-r0'}]}
        body = b'Copyright Fixture Authors. Complete permission and license notice.'
        name = hashlib.sha256(body).hexdigest() + '.txt'
        (self.directory / name).write_bytes(body)
        self.manifest = {'schema': 1, 'ready_for_runtime_distribution': True, 'notices': [
            {'notice_file': name, 'sha256': hashlib.sha256(body).hexdigest(), 'bytes': len(body),
             'provenance': [{'origin': 'fixture', 'version': '1-r0', 'architecture': 'amd64'},
                            {'origin': 'expat-original-base', 'version': '2.8.5-r0', 'architecture': 'amd64'}]}]}
        self.inventory = {'notices': [{'path': '/app/licenses/os/' + name,
                                       'sha256': hashlib.sha256(body).hexdigest(), 'bytes': len(body)}]}
        self.write_manifest(self.manifest)

    def write_manifest(self, manifest):
        bundle.write_json(self.directory / 'manifest.json', manifest)
        body = (self.directory / 'manifest.json').read_bytes()
        self.inventory['notices'] = [row for row in self.inventory['notices']
                                     if row['path'] != '/app/licenses/os/manifest.json']
        self.inventory['notices'].append({'path': '/app/licenses/os/manifest.json',
                                         'sha256': hashlib.sha256(body).hexdigest(), 'bytes': len(body)})

    def test_committed_notice_union_and_candidate_bytes_cover_original_layers(self):
        result = bundle.check_runtime_notices(self.root, self.inventory, self.lock, 'amd64')
        self.assertEqual(result['origins'], 2)
        self.assertTrue(result['runtime_bytes_verified'])
        self.assertEqual(result['manifest_sha256'], self.inventory['notices'][-1]['sha256'])

    def test_missing_or_changed_installed_notice_manifest_is_rejected(self):
        for mutation in ('missing', 'hash', 'size'):
            inventory = copy.deepcopy(self.inventory)
            if mutation == 'missing':
                inventory['notices'].pop()
            elif mutation == 'hash':
                inventory['notices'][-1]['sha256'] = 'f' * 64
            else:
                inventory['notices'][-1]['bytes'] += 1
            with self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError, 'exact committed OS notice manifest bytes'):
                bundle.check_runtime_notices(self.root, inventory, self.lock, 'amd64')

    def test_installed_manifest_must_match_original_bytes_not_reserialized_json(self):
        path = self.directory / 'manifest.json'
        original = path.read_bytes()
        path.write_bytes(original + b'\n')
        self.assertEqual(json.loads(path.read_bytes()), self.manifest)
        with self.assertRaisesRegex(ValueError, 'exact committed OS notice manifest bytes'):
            bundle.check_runtime_notices(self.root, self.inventory, self.lock, 'amd64')

    def test_missing_runtime_notice_and_changed_notice_bytes_are_rejected(self):
        with self.assertRaisesRegex(ValueError, 'runtime lacks'):
            bundle.check_runtime_notices(self.root, {'notices': []}, self.lock, 'amd64')
        (self.directory / self.manifest['notices'][0]['notice_file']).write_bytes(b'truncated')
        with self.assertRaisesRegex(ValueError, 'differs from its manifest'):
            bundle.check_runtime_notices(self.root, self.inventory, self.lock, 'amd64')

    def test_stale_version_architecture_or_original_layer_coverage_is_rejected(self):
        for mutation in ('version', 'architecture', 'original_layer'):
            modified = copy.deepcopy(self.manifest)
            if mutation == 'version':
                modified['notices'][0]['provenance'][0]['version'] = '0-r0'
            elif mutation == 'architecture':
                modified['notices'][0]['provenance'][0]['architecture'] = 'arm64'
            else:
                modified['notices'][0]['provenance'].pop()
            self.write_manifest(modified)
            with self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError, 'every reviewed OS origin'):
                bundle.check_runtime_notices(self.root, self.inventory, self.lock, 'amd64')

    def test_original_ensurepip_notices_remain_required_after_final_layer_deletion(self):
        self.lock['origins'].append({'origin': 'python-3.14', 'version': '3.14.7-r1'})
        self.manifest['notices'][0]['provenance'].append(
            {'origin': 'python-3.14', 'version': '3.14.7-r1', 'architecture': 'amd64'})
        self.write_manifest(self.manifest)
        with self.assertRaisesRegex(ValueError, 'every reviewed OS origin'):
            bundle.check_runtime_notices(self.root, self.inventory, self.lock, 'amd64')
        self.manifest['notices'][0]['provenance'].append(
            {'origin': 'python-3.14-ensurepip', 'version': '3.14.7-r1', 'architecture': 'amd64'})
        self.write_manifest(self.manifest)
        self.assertEqual(bundle.check_runtime_notices(self.root, self.inventory, self.lock, 'amd64')['origins'], 4)

    def test_actual_source_notice_bytes_and_attribution_must_be_committed(self):
        for provenance in self.manifest['notices'][0]['provenance']:
            provenance['source_path'] = 'sources/source.tar.gz!package/COPYING'
        self.write_manifest(self.manifest)
        actual = copy.deepcopy(self.manifest)
        bundle.check_generated_notices(self.root, actual, 'amd64')
        for mutation in ('hash', 'source_path', 'ready'):
            changed = copy.deepcopy(actual)
            if mutation == 'hash':
                changed['notices'][0]['sha256'] = 'f' * 64
            elif mutation == 'source_path':
                changed['notices'][0]['provenance'][0]['source_path'] = 'unreviewed/source.c'
            else:
                changed['ready_for_runtime_distribution'] = False
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                bundle.check_generated_notices(self.root, changed, 'amd64')

    def test_complete_generated_proof_matches_exact_committed_attribution(self):
        proof = self.manifest['notices'][0]['provenance'][0]
        proof.update(source_path='sources/archive.tar.gz!fixture/COPYING', schema=1,
            provider_oci_binding=True, binding_method='signed-build-provenance',
            source_image_digest=None, source_manifest_sha256='a' * 64,
            native_image_digest='sha256:' + 'b' * 64, proof_architecture='arm64',
            for_packages=['fixture-data'], discovery='notice-file',
            signed_statement_sha256={'slsa': 'c' * 64, 'scout': 'd' * 64})
        self.write_manifest(self.manifest)
        actual = copy.deepcopy(self.manifest)
        original = copy.deepcopy(actual)
        bundle.check_generated_notices(self.root, actual, 'amd64')
        self.assertEqual(actual, original)
        mutations = {
            'source_manifest_sha256': 'e' * 64,
            'native_image_digest': 'sha256:' + 'e' * 64,
            'source_image_digest': 'sha256:' + 'e' * 64,
            'provider_oci_binding': False,
            'binding_method': 'unsigned-source-only',
            'proof_architecture': 'amd64',
            'for_packages': ['unreviewed-data'],
            'discovery': 'complete-leading-legal-comment',
            'signed_statement_sha256': {'slsa': 'e' * 64, 'scout': 'd' * 64},
            'schema': True,
        }
        for field, value in mutations.items():
            changed = copy.deepcopy(actual)
            changed['notices'][0]['provenance'][0][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'differs from committed runtime provenance'):
                bundle.check_generated_notices(self.root, changed, 'amd64')
        for mutation in ('missing', 'added'):
            changed = copy.deepcopy(actual)
            if mutation == 'missing':
                del changed['notices'][0]['provenance'][0]['source_manifest_sha256']
            else:
                changed['notices'][0]['provenance'][0]['license_source_url'] = 'https://example.org/unreviewed-license'
            with self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError, 'differs from committed runtime provenance'):
                bundle.check_generated_notices(self.root, changed, 'amd64')

    def test_generated_attribution_must_have_requested_native_architecture(self):
        actual = copy.deepcopy(self.manifest)
        actual['notices'][0]['provenance'][0]['architecture'] = 'arm64'
        # Even a byte-for-byte committed attribution from another native image
        # cannot satisfy this architecture's source qualification.
        self.write_manifest(actual)
        with self.assertRaisesRegex(ValueError, 'wrong native architecture'):
            bundle.check_generated_notices(self.root, actual, 'amd64')

    def test_source_comment_review_is_architecture_bound_and_explicit(self):
        provenance = self.manifest['notices'][0]['provenance'][0]
        provenance.update(source_path='sources/archive.tar.gz!package/source.c',
                          discovery='complete-leading-legal-comment')
        self.write_manifest(self.manifest)
        with self.assertRaisesRegex(ValueError, 'explicit committed review'):
            bundle.reviewed_notice_comments(self.root, 'amd64')
        self.manifest['selected_source_comments'] = [provenance['source_path']]
        self.write_manifest(self.manifest)
        self.assertEqual(bundle.reviewed_notice_comments(self.root, 'amd64'), [provenance['source_path']])
        self.assertEqual(bundle.reviewed_notice_comments(self.root, 'arm64'), [])


class OriginalBaseProvenanceBundleTests(unittest.TestCase):
    def test_original_base_provenance_bytes_must_equal_original_signed_statement(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            native = 'sha256:' + 'a' * 64
            statement = b'{"subject": [{"digest": {"sha256": "' + b'a' * 64 + b'"}}]}\n'
            proof = {'attestation_digest': 'sha256:' + 'b' * 64, 'signature_verified': True}
            bundle.write_json(root / 'base-build-provenance/statement.json', json.loads(statement))
            # Identical JSON semantics are insufficient; keep the signed bytes.
            exact = (root / 'base-build-provenance/statement.json').read_bytes()
            (root / 'base-provenance.json').write_bytes(exact)
            os_lock = {'base_native_digests': {'amd64': native}}
            with patch.object(bundle, 'verify_attestation_proof', return_value=proof) as verifier:
                value, checked = bundle.verify_base_provenance(root, os_lock, 'amd64')
                self.assertEqual(checked, proof)
                verifier.assert_called_with(root / 'base-build-provenance', 'amd64',
                    expected_base_digest=bundle.BASE_DIGEST, expected_repository='dhi.io/python',
                    expected_source_name='dhi/python', expected_native_digest=native,
                    expected_predicate_type='https://slsa.dev/provenance/v1')
                (root / 'base-provenance.json').write_bytes(statement)
                with self.assertRaisesRegex(ValueError, 'differs from its signed native statement'):
                    bundle.verify_base_provenance(root, os_lock, 'amd64')

    def test_original_package_retention_does_not_replace_ensurepip_source_fetcher(self):
        import base_python_distribution_sources
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, repo = root / 'source', root / 'repo'
            source.mkdir()
            native = 'sha256:' + 'a' * 64
            apk = b'original Python APK fixture'
            apk_sha = hashlib.sha256(apk).hexdigest()
            package = {'name': 'libexpat', 'version': '2.8.5-r0',
                       'license': 'MIT', 'build_commit': 'c' * 40,
                       'binaries': {'amd64': {'url': 'https://dhi.io/expat.apk', 'sha256': 'd' * 64}}}
            original = {'origin': 'expat', 'version': '2.8.5-r0', 'packages': [package]}
            provenance = {'predicateType': 'https://slsa.dev/provenance/v1',
                          'subject': [{'digest': {'sha256': native.split(':')[1]}}],
                          'predicate': {'buildDefinition': {'resolvedDependencies': [
                              {'uri': 'https://dhi.io/expat.apk', 'digest': {'sha256': 'd' * 64}}]}}}
            bundle.write_json(source / 'base-provenance.json', provenance)
            bundle.write_json(source / 'base-runtime-inventory.json', {'os_packages': [
                {'name': 'libexpat', 'version': '2.8.5-r0', 'license': 'MIT',
                 'origin': 'expat', 'build_commit': 'c' * 40}]})
            bundle.write_json(repo / 'docs/base-python-sources.json', {'package': {'apk_sha256': {'amd64': apk_sha}}})
            proof = {'source_image_digest': 'sha256:' + 'b' * 64, 'native_image_digest': native}

            def retain(layout, expected, output):
                output.mkdir(parents=True)
                (output / 'python.apk').write_bytes(apk)
                return {'files': [{'type': 'file', 'source_path': 'opt/docker/materials/python.apk',
                                  'path': 'python.apk', 'sha256': apk_sha}]}

            fetched = []
            def python_fetch(url):
                fetched.append(url)
                self.assertEqual(url, 'https://pypi.org/pypi/distlib/0.4.2/json')
                return b'ensurepip source release'

            def original_python(apk, arch, output, *, lock, fetch):
                self.assertEqual(fetch('https://pypi.org/pypi/distlib/0.4.2/json'), b'ensurepip source release')
                return {'source_packages': [], 'wheels': [], 'native_resources': [], 'native_build_sources': []}

            os_lock = {'base_index': 'dhi.io/python@' + bundle.BASE_DIGEST, 'base_native_digests': {'amd64': native},
                       'original_base_origins': [original]}
            with patch.object(bundle, 'verify_source_proof', return_value=proof), \
                    patch.object(bundle, 'verify_base_provenance', return_value=(provenance, proof)), \
                    patch.object(bundle, 'copy_proof'), patch.object(bundle, 'copy_attestation_proof'), \
                    patch.object(bundle, 'retain_materials', side_effect=retain), patch.object(bundle, 'omit_apk_materials'), \
                    patch.object(bundle, 'retain_packages', return_value=[]) as packages, \
                    patch.object(base_python_distribution_sources, 'collect_sources', side_effect=original_python):
                bundle.retain_original_base(source, root / 'curated', os_lock, 'amd64', root=repo, fetch=python_fetch)
            self.assertEqual(fetched, ['https://pypi.org/pypi/distlib/0.4.2/json'])
            self.assertEqual(packages.call_args.args[0], source / 'original-base-packages')


class MatchingSourceDownloadTests(unittest.TestCase):
    def test_pinned_native_github_source_can_redirect_to_official_archive_host(self):
        class Response(io.BytesIO):
            def geturl(self):
                return 'https://codeload.github.com/libffi/libffi/tar.gz/v3.4.6'
        with patch.object(bundle.urllib.request, 'urlopen', return_value=Response(b'locked source archive')):
            self.assertEqual(bundle.fetch_source('https://github.com/libffi/libffi/archive/v3.4.6.tar.gz'),
                             b'locked source archive')

    def test_unexpected_hosts_credentials_and_redirects_are_rejected(self):
        with patch.object(bundle.urllib.request, 'urlopen') as opener:
            for url in ('http://github.com/libffi.tar.gz', 'https://private.example/source.tar.gz',
                        'https://secret:token@github.com/libffi.tar.gz'):
                with self.subTest(url=url), self.assertRaisesRegex(ValueError, 'download URL'):
                    bundle.fetch_source(url)
            opener.assert_not_called()
        class Response(io.BytesIO):
            def geturl(self):
                return 'https://private.example/source.tar.gz'
        with patch.object(bundle.urllib.request, 'urlopen', return_value=Response(b'bytes')):
            with self.assertRaisesRegex(ValueError, 'download URL'):
                bundle.fetch_source('https://github.com/libffi/libffi/archive/v3.4.6.tar.gz')


@unittest.skipUnless(shutil.which('git'), 'Source packaging runs on a host with Git')
class CommittedKeepSourceTests(unittest.TestCase):
    """Use a real isolated Git snapshot rather than trusting mocked diff flags."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'checkout'
        self.root.mkdir()
        self.output = Path(self.temp.name) / 'sources'
        self.files = ('Dockerfile', '.dockerignore', 'requirements.txt', 'LICENSE', 'VERSION',
            'scripts/build_patched_zlib.py', 'scripts/patch_python_runtime.py',
            'scripts/alpine_expat_sources.py', 'scripts/runtime_dependency_checks.py',
            'scripts/python_security_patches.json', 'docs/PYTHON_LICENSE.txt',
            'docs/distribution-sources.json', 'docs/os-package-sources.json',
            'docs/aports-source-lock.json', 'docs/base-python-sources.json', 'app.py')
        for name in self.files:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('Committed source bytes: ' + name + '\n')
        self.git('init')
        self.git('add', '.')
        self.git('-c', 'user.name=Source packaging test', '-c', 'user.email=source-test@example.test',
                 '-c', 'commit.gpgsign=false', 'commit', '-m', 'Source fixture')

    def git(self, *args):
        environment = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
        return subprocess.check_output(['git', *args], cwd=self.root, env=environment,
                                       stderr=subprocess.STDOUT, text=True).strip()

    def test_clean_snapshot_contains_committed_build_source_and_excludes_local_runtime_files(self):
        (self.root / '.env').write_text('local runtime credential fixture')
        revision = bundle.keep_source(self.root, self.output)
        self.assertEqual(revision, self.git('rev-parse', 'HEAD'))
        with tarfile.open(self.output / 'keep-source.tar') as archive:
            self.assertNotIn('.env', archive.getnames())
            self.assertNotIn('.git', archive.getnames())
            for name in self.files:
                self.assertEqual(archive.extractfile(name).read(), (self.root / name).read_bytes())
        self.assertEqual((self.output / 'build/Dockerfile').read_bytes(), (self.root / 'Dockerfile').read_bytes())

    def test_modified_and_staged_source_cannot_produce_a_matching_source_archive(self):
        original = (self.root / 'app.py').read_bytes()
        for staged in (False, True):
            with self.subTest(staged=staged):
                (self.root / 'app.py').write_bytes(original + b'Uncommitted runtime change\n')
                if staged:
                    self.git('add', 'app.py')
                with self.assertRaisesRegex(ValueError, 'Commit Keep changes'):
                    bundle.keep_source(self.root, self.output)
                self.assertFalse(self.output.exists())
                (self.root / 'app.py').write_bytes(original)
                if staged:
                    self.git('add', 'app.py')


class SignedBuildSourceBundleTests(unittest.TestCase):
    """Real preferred-source replay; original crypto is tested independently."""
    setUp = BundleCoverageTests.setUp
    package_fixture = BundleCoverageTests.package_fixture
    def build_fixture(self):
        import package_provenance_sources as preferred
        source, origin, result, old_proof, _ = self.package_fixture()
        package = source / 'fixture'
        native = result['native_image_digest']
        commit = 'a' * 40
        source_url = 'https://example.org/fixture-1.tar.gz'
        source_stream = io.BytesIO()
        with tarfile.open(fileobj=source_stream, mode='w:gz') as archive:
            for name, body in [('fixture-1/source.c', b'int fixture(void) { return 1; }\n'),
                               ('fixture-1/COPYING', b'Copyright Fixture Authors. Permission is hereby granted to use this fixture.')]:
                member = tarfile.TarInfo(name)
                member.size = len(body)
                archive.addfile(member, io.BytesIO(body))
        source_body = source_stream.getvalue()
        recipe = ('image: dhi/pkg-fixture\nvars:\n  VERSION: "1"\n  REL: "0"\n'
            '  COMMIT_SHA: ' + commit + '\ncontents:\n  files:\n'
            '    - url: git+https://github.com/alpinelinux/aports.git#' + commit + '\n'
            '      path: /src/aports\n    - url: ' + source_url + '\n'
            '      path: /cache/fixture-1.tar.gz\n').encode()
        apkbuild = ('pkgname=fixture\npkgver=1\npkgrel=0\nsha512sums="\n'
            + hashlib.sha512(source_body).hexdigest() + '  fixture-1.tar.gz\n"\n').encode()
        context_stream = io.BytesIO()
        with tarfile.open(fileobj=context_stream, mode='w:gz') as archive:
            member = tarfile.TarInfo('aports-' + commit + '/main/fixture/APKBUILD')
            member.size = len(apkbuild)
            archive.addfile(member, io.BytesIO(apkbuild))
        context = context_stream.getvalue()
        public_url = 'https://example.org/provider.yaml'
        aports_url = 'https://github.com/alpinelinux/aports/archive/' + commit + '.tar.gz'
        origin['recipe'].update({'url': public_url, 'sha256': hashlib.sha256(recipe).hexdigest(),
                                  'revision': 'c' * 40, 'upstream_commit': commit})
        (package / 'recipe.yaml').write_bytes(recipe)
        bundle.write_json(self.root / 'docs/aports-source-lock.json', {'aports': [{
            'origin': 'fixture', 'commit': commit, 'url': aports_url,
            'sha256': hashlib.sha256(context).hexdigest(),
            'apkbuild_sha256': hashlib.sha256(apkbuild).hexdigest()}]})
        subject = [{'name': 'pkg:docker/dhi/pkg-fixture', 'digest': {'sha256': native.split(':')[1]}}]
        slsa = {'predicateType': 'https://slsa.dev/provenance/v0.2', 'subject': subject,
            'predicate': {'materials': [
                {'uri': source_url, 'digest': {'sha256': hashlib.sha256(source_body).hexdigest()}},
                {'uri': 'https://github.com/alpinelinux/aports.git#' + commit, 'digest': {'sha256': ''}}]}}
        scout = {'predicateType': 'https://scout.docker.com/provenance/v0.1', 'subject': subject,
            'predicate': {'source_map': {'dockerfile': base64.b64encode(recipe).decode()}}}
        relative = 'build-provenance/' + native.split(':')[1]
        proof_root = package / relative
        bundle.write_json(proof_root / 'slsa-proof/statement.json', slsa)
        bundle.write_json(proof_root / 'scout-proof/statement.json', scout)
        downloads = {source_url: source_body, aports_url: context, public_url: recipe}
        with patch.object(preferred, 'ROOT', self.root):
            preferred.collect_sources(origin, 'amd64', slsa, scout, proof_root / 'upstream-sources',
                                      fetch=downloads.__getitem__)
        attestations = [{'directory': name + '-proof', 'predicate_type': statement['predicateType'],
                         'attestation_digest': 'sha256:' + character * 64}
                        for name, statement, character in [('slsa', slsa, 'c'), ('scout', scout, 'd')]]
        row = {'directory': relative, 'binding_method': 'signed-build-provenance',
            'provider_oci_binding': True, 'source_image_attestation': False, 'signature_verified': True,
            'proof_architecture': 'amd64', 'native_image_digest': native, 'for_packages': ['fixture'],
            'upstream_manifest': 'upstream-sources/manifest.json', 'attestations': attestations}
        result['source_results'] = [row]
        bundle.write_json(package / 'acquisition.json', result)
        bundle.write_json(source / 'package-sources.json', {'format': 'keep-os-package-source-acquisition-v1',
            'architecture': 'amd64', 'success': True, 'pending_origins': [], 'origins': [result]})

        def verifier(root, architecture, **expected):
            match = next(value for value in attestations if value['predicate_type'] == expected['expected_predicate_type'])
            self.assertEqual(expected['expected_native_digest'], native)
            return {'attestation_digest': match['attestation_digest'], 'signature_verified': True}
        return source, origin, result, preferred, verifier

    def test_signed_native_inputs_and_full_sources_are_retained_without_source_image_claim(self):
        source, origin, result, preferred, verifier = self.build_fixture()
        with patch.object(bundle, 'verify_attestation_proof', side_effect=verifier) as signatures, \
                patch.object(bundle, 'copy_attestation_proof'), patch.object(preferred, 'ROOT', self.root):
            coverage = bundle.retain_packages(source, self.root / 'curated', {'origins': [origin]}, 'amd64')
        self.assertEqual(signatures.call_count, 2)
        self.assertTrue(coverage[0]['apk_binary_match_verified'])
        proof = coverage[0]['sources'][0]
        self.assertFalse(proof['source_image_attestation'])
        self.assertEqual(proof['binding_method'], 'signed-build-provenance')
        self.assertNotIn('source_image_digest', proof)
        notices = bundle.read_json(self.root / 'curated', proof['notice_inventory'])
        self.assertIsNone(notices['source_image_digest'])
        self.assertTrue(notices['preferred_source_present'])
        self.assertTrue(notices['notice_inventory_complete'])
        paths = {row['path'] for row in bundle.file_records(self.root / 'curated')}
        self.assertTrue(any(path.endswith('/sources/fixture-1.tar.gz') for path in paths))
        self.assertFalse(any('/package-output-oci/' in path for path in paths))

    def test_retained_upstream_archive_tampering_cannot_pass_flags_or_signed_metadata(self):
        source, origin, result, preferred, verifier = self.build_fixture()
        root = source / 'fixture' / result['source_results'][0]['directory']
        (root / 'upstream-sources/sources/fixture-1.tar.gz').write_bytes(b'changed')
        with patch.object(bundle, 'verify_attestation_proof', side_effect=verifier), \
                patch.object(bundle, 'copy_attestation_proof'), patch.object(preferred, 'ROOT', self.root):
            with self.assertRaisesRegex(ValueError, 'Retained source checksum mismatch'):
                bundle.retain_packages(source, self.root / 'curated', {'origins': [origin]}, 'amd64')

    def test_both_original_signatures_are_required_for_preferred_source_replay(self):
        source, origin, result, preferred, verifier = self.build_fixture()

        def reject_scout(root, architecture, **expected):
            if 'scout' in expected['expected_predicate_type']:
                raise ValueError('No valid original Docker signature')
            return verifier(root, architecture, **expected)
        with patch.object(bundle, 'verify_attestation_proof', side_effect=reject_scout), \
                patch.object(bundle, 'copy_attestation_proof'), patch.object(preferred, 'ROOT', self.root):
            with self.assertRaisesRegex(ValueError, 'No valid original Docker signature'):
                bundle.retain_packages(source, self.root / 'curated', {'origins': [origin]}, 'amd64')


class OriginalPackageBindingTests(unittest.TestCase):
    def fixture(self):
        package = {'name': 'libexpat', 'version': '2.8.5-r0', 'build_commit': 'a' * 40,
                   'license': 'MIT', 'binaries': {'amd64': {'url': 'https://dhi.io/exact.apk',
                                                         'sha256': 'b' * 64}}}
        origin = {'origin': 'expat', 'version': package['version'], 'packages': [package]}
        inventory = {'os_packages': [{'name': package['name'], 'version': package['version'],
                     'build_commit': package['build_commit'], 'license': 'MIT', 'origin': 'expat'}]}
        provenance = {'predicate': {'buildDefinition': {'resolvedDependencies': [
            {'uri': package['binaries']['amd64']['url'], 'digest': {'sha256': 'b' * 64}}]}}}
        return [origin], inventory, provenance

    def test_original_bytes_remain_bound_after_runtime_replacement(self):
        origins, inventory, provenance = self.fixture()
        bundle.bind_original_packages(origins, inventory, provenance, 'amd64')
        for field, changed in (('version', '2.9.0-r0'), ('build_commit', 'c' * 40),
                               ('license', 'Unknown'), ('origin', 'other')):
            altered = copy.deepcopy(inventory)
            altered['os_packages'][0][field] = changed
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'inventory identity mismatch'):
                bundle.bind_original_packages(origins, altered, provenance, 'amd64')

    def test_original_signed_apk_hash_and_uniqueness_are_mandatory(self):
        origins, inventory, provenance = self.fixture()
        for mutation in ('hash', 'uri', 'duplicate', 'missing'):
            altered = copy.deepcopy(provenance)
            rows = altered['predicate']['buildDefinition']['resolvedDependencies']
            if mutation == 'hash':
                rows[0]['digest']['sha256'] = 'c' * 64
            elif mutation == 'uri':
                rows[0]['uri'] += '.changed'
            elif mutation == 'duplicate':
                rows.append(copy.deepcopy(rows[0]))
            else:
                rows.clear()
            with self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError, 'signed provenance'):
                bundle.bind_original_packages(origins, inventory, altered, 'amd64')
        with self.assertRaisesRegex(ValueError, 'Duplicate overwritten'):
            bundle.bind_original_packages(origins + origins, inventory, provenance, 'amd64')
