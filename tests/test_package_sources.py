"""Package names/tags never replace exact APK-byte and source-subject binding."""
import hashlib
import gzip
import importlib.util
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import types
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
spec = importlib.util.spec_from_file_location('collect_package_sources', ROOT / 'scripts/collect_package_sources.py')
collection = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collection)


def layer(entries):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w:gz') as archive:
        for name, body in entries:
            member = tarfile.TarInfo(name)
            member.size = len(body)
            archive.addfile(member, io.BytesIO(body))
    return stream.getvalue()


def apk(name, version, architecture):
    # Real APKv2 packages concatenate separately compressed signature,
    # control metadata, and payload tar archives.
    members = [('.SIGN.RSA.reviewed-key.pub', b'signature'),
               ('.PKGINFO', ('pkgname = ' + name + '\npkgver = ' + version
                            + '\narch = ' + architecture + '\n').encode()),
               ('usr/share/terminfo/x/xterm', b'terminal data')]
    result = b''
    for name, body in members:
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode='w') as archive:
            member = tarfile.TarInfo(name)
            member.size = len(body)
            archive.addfile(member, io.BytesIO(body))
        result += gzip.compress(stream.getvalue())
    return result


class PackageSourceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.layout = self.root / 'output-oci'
        (self.layout / 'blobs' / 'sha256').mkdir(parents=True)
        (self.layout / 'oci-layout').write_text('{"imageLayoutVersion":"1.0.0"}')
        self.apk = b'exact reviewed binary package bytes'
        self.expected = [{'name': 'sample-libs', 'version': '1.2-r0',
                          'sha256': hashlib.sha256(self.apk).hexdigest()}]
        self.native, self.layer = self.image(layer([('out/sample-libs-1.2-r0.apk', self.apk)]))

    def blob(self, body, media_type):
        key = hashlib.sha256(body).hexdigest()
        (self.layout / 'blobs' / 'sha256' / key).write_bytes(body)
        return {'digest': 'sha256:' + key, 'size': len(body), 'mediaType': media_type}

    def image(self, body, architecture='amd64', os_name='linux'):
        layer_descriptor = self.blob(body, 'application/vnd.oci.image.layer.v1.tar+gzip')
        config = self.blob(json.dumps({'architecture': architecture, 'os': os_name}).encode(),
                           'application/vnd.oci.image.config.v1+json')
        manifest = self.blob(json.dumps({'schemaVersion': 2, 'config': config,
                            'layers': [layer_descriptor]}).encode(), 'application/vnd.oci.image.manifest.v1+json')
        (self.layout / 'index.json').write_text(json.dumps({'schemaVersion': 2, 'manifests': [manifest]}))
        return manifest['digest'], layer_descriptor

    def match(self):
        return collection.match_package_output(self.layout, self.native, 'amd64', self.expected)

    def test_matching_binary_bytes_are_bound_to_verified_layer_digest(self):
        result = self.match()
        self.assertTrue(result['all_apks_matched'])
        match = result['apk_matches'][0]['matches'][0]
        self.assertEqual(match['layer_digest'], self.layer['digest'])
        self.assertEqual(match['path'], 'out/sample-libs-1.2-r0.apk')
        self.assertEqual(result['native_image_digest'], self.native)

    def test_same_package_filename_and_version_do_not_accept_different_bytes(self):
        self.native, self.layer = self.image(layer([('out/sample-libs-1.2-r0.apk', b'different rebuild')]))
        with self.assertRaisesRegex(ValueError, 'reviewed APK bytes'):
            self.match()

    def test_every_reviewed_subpackage_must_match(self):
        self.expected.append({'name': 'sample', 'version': '1.2-r0', 'sha256': '0' * 64})
        with self.assertRaisesRegex(ValueError, 'sample'):
            self.match()

    def test_wrong_native_config_is_rejected_even_when_bytes_match(self):
        self.native, self.layer = self.image(layer([('out/package.apk', self.apk)]), architecture='arm64')
        with self.assertRaisesRegex(ValueError, 'wrong native platform'):
            self.match()

    def test_mutated_output_layer_is_rejected(self):
        path = self.layout / 'blobs' / 'sha256' / self.layer['digest'].split(':')[1]
        path.write_bytes(b'changed layer')
        with self.assertRaisesRegex(ValueError, 'blob digest mismatch'):
            self.match()

    def test_zstd_package_output_is_matched_by_actual_regular_file_bytes(self):
        plain = io.BytesIO()
        with tarfile.open(fileobj=plain, mode='w') as archive:
            member = tarfile.TarInfo('out/sample-libs-1.2-r0.apk')
            member.size = len(self.apk)
            archive.addfile(member, io.BytesIO(self.apk))
        try:
            from compression import zstd
            compressed = zstd.compress(plain.getvalue())
        except ImportError:
            try:
                import zstandard
                compressed = zstandard.ZstdCompressor().compress(plain.getvalue())
            except ImportError:
                if not shutil.which('zstd'):
                    self.skipTest('Zstandard decoder/encoder not available in this test environment')
                compressed = subprocess.check_output(['zstd', '--compress', '--stdout', '--quiet'],
                                                     input=plain.getvalue())
        descriptor = self.blob(compressed, 'application/vnd.oci.image.layer.v1.tar+zstd')
        config = self.blob(b'{"architecture":"amd64","os":"linux"}',
                           'application/vnd.oci.image.config.v1+json')
        manifest = self.blob(json.dumps({'schemaVersion': 2, 'config': config,
                            'layers': [descriptor]}).encode(), 'application/vnd.oci.image.manifest.v1+json')
        self.native, self.layer = manifest['digest'], descriptor
        (self.layout / 'index.json').write_text(json.dumps({'schemaVersion': 2, 'manifests': [manifest]}))
        self.assertTrue(self.match()['all_apks_matched'])

    def test_retained_source_root_and_every_blob_must_match(self):
        result = collection.verify_retained_source(self.layout, self.native)
        self.assertTrue(result['binding_verified'])
        with self.assertRaisesRegex(ValueError, 'signed package-source digest'):
            collection.verify_retained_source(self.layout, 'sha256:' + '9' * 64)
        path = self.layout / 'blobs' / 'sha256' / self.layer['digest'].split(':')[1]
        path.write_bytes(b'tampered source')
        with self.assertRaisesRegex(ValueError, 'blob digest mismatch'):
            collection.verify_retained_source(self.layout, self.native)

    def test_unsafe_output_paths_are_not_extracted(self):
        self.native, self.layer = self.image(layer([('../sample.apk', self.apk)]))
        with self.assertRaisesRegex(ValueError, 'Unsafe archive member'):
            self.match()

    def test_native_platform_selection_is_unambiguous(self):
        raw = json.dumps({'schemaVersion': 2, 'manifests': [
            {'digest': 'sha256:' + 'a' * 64, 'platform': {'os': 'linux', 'architecture': 'amd64'}},
            {'digest': 'sha256:' + 'b' * 64, 'platform': {'os': 'linux', 'architecture': 'arm64'}}]}).encode()
        native, index_digest, direct = collection.resolve_native(raw, 'arm64')
        self.assertEqual(native, 'sha256:' + 'b' * 64)
        self.assertEqual(index_digest, collection.digest(raw))
        self.assertFalse(direct)
        with self.assertRaisesRegex(ValueError, 'unique native platform'):
            collection.resolve_native(raw, 'riscv64')

    def test_direct_native_reference_uses_actual_manifest_digest(self):
        raw = json.dumps({'schemaVersion': 2, 'layers': [], 'config': {}}).encode()
        native, index, direct = collection.resolve_native(raw, 'amd64')
        self.assertEqual(native, index)
        self.assertEqual(native, collection.digest(raw))
        self.assertTrue(direct)

    def test_source_statement_requires_exact_native_and_repository(self):
        native = 'sha256:' + 'a' * 64
        statement = {'predicateType': collection.PREDICATE,
                     'subject': [{'digest': {'sha256': 'a' * 64}}],
                     'predicate': {'source': {'name': 'dhi/pkg-sample', 'digest': 'sha256:' + 'b' * 64}}}
        raw = json.dumps(statement)
        self.assertEqual(collection.package_statement(raw, native, 'dhi/pkg-sample'), statement)
        with self.assertRaisesRegex(ValueError, 'native subject'):
            collection.package_statement(raw, 'sha256:' + 'c' * 64, 'dhi/pkg-sample')
        with self.assertRaisesRegex(ValueError, 'source repository'):
            collection.package_statement(raw, native, 'dhi/pkg-other')

    def test_missing_pin_and_duplicate_subpackage_are_rejected(self):
        row = {'version': '1.2-r0', 'packages': [
            {'name': 'sample', 'version': '1.2-r0', 'binaries': {'amd64': {'sha256': 'a' * 64}}}]}
        self.assertEqual(len(collection.expected_packages(row, 'amd64')), 1)
        with self.assertRaisesRegex(ValueError, 'reviewed APK identity'):
            collection.expected_packages(row, 'arm64')
        row['packages'].append(row['packages'][0])
        with self.assertRaisesRegex(ValueError, 'reviewed APK identity'):
            collection.expected_packages(row, 'amd64')

    def ncurses_origin(self):
        packages = []
        for name in ('ncurses-libs', 'ncurses-terminfo-base'):
            packages.append({'name': name, 'version': '6.6_p20260516-r0',
                'binaries': {'amd64': {'sha256': hashlib.sha256(name.encode()).hexdigest()},
                             'arm64': {'sha256': hashlib.sha256((name + '-arm64').encode()).hexdigest()}}})
        return {'origin': 'ncurses', 'version': '6.6_p20260516-r0', 'packages': packages,
                'architecture_independent_outputs': {'ncurses-terminfo-base': 'arm64'}}

    def test_reviewed_noarch_groups_preserve_target_apk_hash_and_partition(self):
        row = self.ncurses_origin()
        groups = collection.reviewed_output_groups(row, 'amd64')
        self.assertEqual([group['architecture'] for group in groups], ['amd64', 'arm64'])
        self.assertEqual([group['directory'] for group in groups],
                         ['package-output-oci', 'package-output-arm64-oci'])
        self.assertEqual([group['allow_noarch'] for group in groups], [False, True])
        self.assertEqual(groups[1]['packages'][0]['sha256'],
                         row['packages'][1]['binaries']['amd64']['sha256'])
        self.assertEqual({package['name'] for group in groups for package in group['packages']},
                         {package['name'] for package in row['packages']})
        arm_groups = collection.reviewed_output_groups(row, 'arm64')
        self.assertEqual(len(arm_groups), 1)
        self.assertFalse(arm_groups[0]['allow_noarch'])

    def test_cross_architecture_exception_cannot_apply_to_compiled_package_or_other_version(self):
        row = self.ncurses_origin()
        row['architecture_independent_outputs'] = {'ncurses-libs': 'arm64'}
        with self.assertRaisesRegex(ValueError, 'Unreviewed architecture-independent'):
            collection.reviewed_output_groups(row, 'amd64')
        row = self.ncurses_origin()
        row['origin'] = 'unreviewed'
        with self.assertRaisesRegex(ValueError, 'Unreviewed architecture-independent'):
            collection.reviewed_output_groups(row, 'amd64')

    def test_cross_architecture_match_requires_exact_noarch_metadata(self):
        body = apk('ncurses-terminfo-base', '6.6_p20260516-r0', 'noarch')
        expected = [{'name': 'ncurses-terminfo-base', 'version': '6.6_p20260516-r0',
                     'sha256': hashlib.sha256(body).hexdigest()}]
        native, _ = self.image(layer([('out/terminfo.apk', body)]), architecture='arm64')
        result = collection.match_package_output(self.layout, native, 'arm64', expected,
                                                 allow_noarch=True)
        identity = result['apk_matches'][0]['matches'][0]['package_identity']
        self.assertEqual(identity['arch'], 'noarch')
        self.assertEqual(identity['pkgname'], expected[0]['name'])

    def test_exact_apk_checksum_does_not_allow_compiled_cross_architecture_binary(self):
        body = apk('ncurses-terminfo-base', '6.6_p20260516-r0', 'aarch64')
        expected = [{'name': 'ncurses-terminfo-base', 'version': '6.6_p20260516-r0',
                     'sha256': hashlib.sha256(body).hexdigest()}]
        native, _ = self.image(layer([('out/terminfo.apk', body)]), architecture='arm64')
        with self.assertRaisesRegex(ValueError, 'arch=noarch'):
            collection.match_package_output(self.layout, native, 'arm64', expected,
                                            allow_noarch=True)

    def test_noarch_metadata_must_match_exact_package_identity(self):
        body = apk('other-package', '6.6_p20260516-r0', 'noarch')
        with self.assertRaisesRegex(ValueError, 'exact name/version'):
            collection.noarch_identity(io.BytesIO(body),
                {'name': 'ncurses-terminfo-base', 'version': '6.6_p20260516-r0'})

    def test_grouped_acquisition_requires_signed_sources_for_every_output_platform(self):
        origin = {**self.ncurses_origin(), 'image': 'dhi.io/pkg-ncurses',
                  'predicate_image_name': 'dhi/pkg-ncurses',
                  'reference': 'dhi.io/pkg-ncurses:6.6-r0-alpine3.24'}
        raw = json.dumps({'schemaVersion': 2, 'manifests': [
            {'digest': 'sha256:' + 'a' * 64, 'platform': {'os': 'linux', 'architecture': 'amd64'}},
            {'digest': 'sha256:' + 'b' * 64, 'platform': {'os': 'linux', 'architecture': 'arm64'}}]}).encode()

        class MultiPlatformRegistry:
            def manifest(self, reference):
                return raw

            def copy(self, reference, destination):
                pass

        def matched(layout, native, architecture, packages, **kwargs):
            return {'apk_matches': packages}

        with patch.object(collection, 'match_package_output', side_effect=matched), \
             patch.object(collection, 'acquire_signed_sources',
                          side_effect=[([{'proof_architecture': 'amd64'}], []),
                                       ValueError('ARM source signature missing')]) as proofs, \
             patch.object(collection, 'retain_recipe') as recipe:
            result = collection.acquire_origin(origin, 'amd64', self.root / 'ncurses', MultiPlatformRegistry())
        self.assertFalse(result['success'])
        self.assertEqual(proofs.call_count, 2)
        self.assertEqual(proofs.call_args_list[1].args[1]['architecture'], 'arm64')
        recipe.assert_not_called()
        self.assertIn('ARM source signature missing', result['candidate_failures'][0]['error'])

    def test_registry_tag_discovery_retains_listing_and_uses_only_existing_reviewed_family(self):
        tags = ['latest', '3.5.8-r1-alpine3.24-fips', '3.5.8-alpine3.24',
                '3.5.9-r0-alpine3.24', '3.5.8-r1-alpine3.23', '../unsafe-alpine3.24']

        class Listing:
            def tags(self, repository):
                return tags

        result = collection.discover_openssl_candidates({'image': 'dhi.io/pkg-openssl'},
                                                        Listing(), self.root)
        self.assertEqual(result, ['dhi.io/pkg-openssl:3.5.8-alpine3.24',
                                 'dhi.io/pkg-openssl:3.5.8-r1-alpine3.24-fips'])
        retained = json.loads((self.root / 'registry-tag-listing.json').read_text())
        self.assertEqual(retained['tags'], tags)

    def test_openssl_discovery_after_404_still_rejects_mismatched_apk_bytes(self):
        test = self
        seen = []

        class MissingThenCandidate:
            def manifest(self, reference):
                seen.append(reference)
                if reference.endswith(':3.5.8-r1-alpine3.24'):
                    raise subprocess.CalledProcessError(1, 'regctl', stderr=b'404 not found')
                return (test.layout / 'blobs' / 'sha256' / test.native.split(':')[1]).read_bytes()

            def tags(self, repository):
                return ['3.5.8-alpine3.24']

            def copy(self, reference, destination):
                shutil.copytree(test.layout, destination)

        origin = {'origin': 'openssl', 'version': '3.5.8-r1', 'image': 'dhi.io/pkg-openssl',
                  'reference': 'dhi.io/pkg-openssl:3.5.8-r1-alpine3.24',
                  'predicate_image_name': 'dhi/pkg-openssl', 'packages': [
                      {'name': 'libcrypto3', 'version': '3.5.8-r1',
                       'binaries': {'amd64': {'sha256': '0' * 64}}}]}
        result = collection.acquire_origin(origin, 'amd64', self.root / 'openssl', MissingThenCandidate())
        self.assertFalse(result['success'])
        self.assertEqual(seen, [origin['reference'], 'dhi.io/pkg-openssl:3.5.8-alpine3.24'])
        self.assertEqual(result['candidate_failures'][-1]['failure_kind'], 'apk-binary-mismatch')

    def test_authentication_failure_does_not_trigger_registry_tag_discovery(self):
        error = subprocess.CalledProcessError(1, 'regctl', stderr=b'401 unauthorized')
        self.assertFalse(collection.registry_not_found(error))
        self.assertTrue(collection.registry_not_found(
            subprocess.CalledProcessError(1, 'regctl', stderr=b'MANIFEST_UNKNOWN')))

    def test_discovery_retains_external_and_embedded_statements_without_claiming_completion(self):
        native = 'sha256:' + 'a' * 64
        statement = json.dumps({'predicateType': collection.PREDICATE,
            'subject': [{'digest': {'sha256': 'a' * 64}}],
            'predicate': {'source': {'name': 'dhi/pkg-sample', 'digest': 'sha256:' + 'b' * 64}}}).encode()
        artifact = json.dumps({'schemaVersion': 2, 'config': {}, 'layers': [
            {'digest': collection.digest(statement), 'size': len(statement),
             'mediaType': 'application/vnd.in-toto+json'}]}).encode()
        descriptor = {'digest': collection.digest(artifact), 'size': len(artifact),
                      'platform': {'os': 'unknown', 'architecture': 'unknown'},
                      'annotations': {'vnd.docker.reference.type': 'attestation-manifest'}}
        raw = json.dumps({'schemaVersion': 2, 'manifests': [
            {'digest': native, 'platform': {'os': 'linux', 'architecture': 'amd64'}},
            descriptor]}).encode()
        origin = {'origin': 'sample', 'version': '1-r0', 'image': 'dhi.io/pkg-sample',
                  'predicate_image_name': 'dhi/pkg-sample', 'reference': 'dhi.io/pkg-sample:1-r0-alpine3.24'}
        calls = []

        class MetadataRegistry:
            def manifest(self, reference):
                if '@' in reference:
                    return artifact
                return raw

            def referrers(self, reference, *, external=None):
                calls.append((reference, external))
                return {'manifests': [descriptor] if external else []}

            def statement(self, reference):
                return statement

            def copy(self, *args, **kwargs):
                raise AssertionError('Discovery must not copy OCI output or source layers')

        destination = self.root / 'discovery'
        result = collection.discover_origin(origin, 'amd64', destination, MetadataRegistry())
        self.assertFalse(result['acquisition_complete'])
        self.assertEqual(len(calls), 4)
        self.assertEqual({reference.split('@', 1)[1] for reference, _ in calls},
                         {native, collection.digest(raw)})
        self.assertEqual({external for _, external in calls},
                         {None, 'registry.scout.docker.com/dhi/pkg-sample'})
        self.assertEqual({row['route'] for row in result['artifacts']},
                         {'embedded-index', 'native-external'})
        self.assertTrue((destination / 'referrers-index-external.json').is_file())
        for item in result['artifacts']:
            self.assertEqual(item['predicate_type'], collection.PREDICATE)
            self.assertFalse(item['signature_verified'])
            self.assertEqual((destination / item['statement']).read_bytes(), statement)

    def test_discovery_rejects_statement_bytes_that_differ_from_manifest_layer(self):
        raw = json.dumps({'schemaVersion': 2, 'config': {}, 'layers': []}).encode()
        artifact = json.dumps({'schemaVersion': 2, 'config': {}, 'layers': [
            {'digest': 'sha256:' + 'a' * 64, 'size': 3}]}).encode()
        descriptor = {'digest': collection.digest(artifact), 'size': len(artifact)}
        origin = {'origin': 'sample', 'version': '1-r0', 'image': 'dhi.io/pkg-sample',
                  'predicate_image_name': 'dhi/pkg-sample', 'reference': 'dhi.io/pkg-sample:1-r0-alpine3.24'}

        class AlteredMetadataRegistry:
            def manifest(self, reference):
                return artifact if '@' in reference else raw

            def referrers(self, reference, **kwargs):
                return {'manifests': [descriptor]}

            def statement(self, reference):
                return b'{}'

        result = collection.discover_origin(origin, 'amd64', self.root / 'discovery', AlteredMetadataRegistry())
        self.assertFalse(result['acquisition_complete'])
        self.assertTrue(all('differs from retained manifest layer' in item['error']
                            for item in result['artifacts']))

    def test_registry_external_referrer_command_keeps_native_subject_and_repository_explicit(self):
        registry = collection.Registry('/regctl', '/cosign', '/key', {})
        with patch.object(collection.subprocess, 'check_output', return_value=b'{"manifests": []}') as command:
            registry.referrers('dhi.io/pkg-gdbm@sha256:' + 'a' * 64,
                              external='registry.scout.docker.com/dhi/pkg-gdbm')
        self.assertEqual(command.call_args.args[0], ['/regctl', 'artifact', 'list',
            'dhi.io/pkg-gdbm@sha256:' + 'a' * 64, '--format', 'body',
            '--external', 'registry.scout.docker.com/dhi/pkg-gdbm'])

    def test_real_tag_listing_captures_stderr_needed_to_prove_repository_absence(self):
        registry = collection.Registry('/regctl', '/cosign', '/key', {})

        def failed_command(command, **kwargs):
            # check_output only attaches stderr to CalledProcessError when the
            # command explicitly captures it. An inherited stream lost the
            # repository404 and prevented the reviewed OpenSSL fallback.
            stderr = b'404 repository not found' if kwargs.get('stderr') == subprocess.PIPE else None
            raise subprocess.CalledProcessError(1, command, stderr=stderr)

        with patch.object(collection.subprocess, 'check_output', side_effect=failed_command):
            with self.assertRaises(subprocess.CalledProcessError) as caught:
                registry.tags('dhi.io/pkg-openssl')
        self.assertTrue(collection.registry_not_found(caught.exception))

    def test_build_sources_require_both_original_build_input_and_recipe_proofs(self):
        group = {'native_image_digest': 'sha256:' + 'a' * 64, 'architecture': 'amd64',
                 'apk_matches': self.expected}
        helper = types.ModuleType('package_provenance_sources')
        helper.collect_sources = lambda *args: self.fail('Must not fetch sources with unsigned recipe')
        slsa = {'predicateType': collection.SLSA_PREDICATES[0]}
        with patch.dict(sys.modules, {'package_provenance_sources': helper}), \
             patch.object(collection, 'acquire_build_attestation',
                          side_effect=[(slsa, {'directory': 'slsa-proof'}, []),
                                       ValueError('original Scout signature missing')]):
            with self.assertRaisesRegex(ValueError, 'original Scout signature missing'):
                collection.acquire_build_provenance_sources({}, group, b'{}', self.root,
                    object(), {'manifests': []})

    def test_signed_build_acquisition_reports_actual_provenance_without_source_image_claim(self):
        group = {'native_image_digest': 'sha256:' + 'a' * 64, 'architecture': 'amd64',
                 'apk_matches': self.expected}
        helper = types.ModuleType('package_provenance_sources')
        calls = []
        helper.collect_sources = lambda *args: calls.append(args) or {'source_materials': [{'sha256': 'b' * 64}]}
        slsa = {'predicateType': collection.SLSA_PREDICATES[0]}
        scout = {'predicateType': collection.SCOUT_PROVENANCE}
        with patch.dict(sys.modules, {'package_provenance_sources': helper}), \
             patch.object(collection, 'acquire_build_attestation', side_effect=[
                 (slsa, {'directory': 'slsa-proof', 'predicate_type': collection.SLSA_PREDICATES[0]}, []),
                 (scout, {'directory': 'scout-proof', 'predicate_type': collection.SCOUT_PROVENANCE}, [])]):
            results, failures = collection.acquire_build_provenance_sources({'origin': 'sample'}, group,
                b'{}', self.root, object(), {'manifests': []})
        self.assertEqual(failures, [])
        result = results[0]
        self.assertEqual(result['binding_method'], 'signed-build-provenance')
        self.assertFalse(result['source_image_attestation'])
        self.assertNotIn('source_image_digest', result)
        self.assertEqual(result['for_packages'], ['sample-libs'])
        self.assertEqual(len(result['attestations']), 2)
        self.assertEqual(calls[0][2:4], (slsa, scout))

    def test_openssl_public_reconstruction_requires_proven_repo_absence_and_base_inputs(self):
        origin = {'origin': 'openssl', 'version': '3.5.8-r1', 'image': 'dhi.io/pkg-openssl',
                  'reference': 'dhi.io/pkg-openssl:3.5.8-r1-alpine3.24',
                  'predicate_image_name': 'dhi/pkg-openssl', 'packages': [
                      {'name': 'libcrypto3', 'version': '3.5.8-r1',
                       'binaries': {'amd64': {'sha256': '0' * 64}}}]}

        class AbsentRepository:
            def manifest(self, reference):
                raise subprocess.CalledProcessError(1, 'regctl', stderr=b'404 manifest not found')

            def tags(self, repository):
                raise subprocess.CalledProcessError(1, 'regctl', stderr=b'404 repository not found')

        helper = types.ModuleType('openssl_distribution_sources')
        calls = []
        helper.collect_sources = lambda *args: calls.append(args) or {
            'binding_method': 'pinned-public-openssl-reconstruction', 'files': []}
        with patch.dict(sys.modules, {'openssl_distribution_sources': helper}):
            result = collection.acquire_origin(origin, 'amd64', self.root / 'openssl', AbsentRepository(),
                base_provenance={'signed': True}, runtime_inventory={'observed': True})
        self.assertTrue(result['success'])
        self.assertFalse(result['provider_oci_binding'])
        self.assertEqual(result['source_results'], [])
        self.assertEqual(result['public_source_fallback']['binding_method'], 'pinned-public-openssl-reconstruction')
        self.assertEqual(len(calls), 1)

    def test_openssl_authentication_failure_cannot_trigger_public_reconstruction(self):
        origin = {'origin': 'openssl', 'version': '3.5.8-r1', 'image': 'dhi.io/pkg-openssl',
                  'reference': 'dhi.io/pkg-openssl:3.5.8-r1-alpine3.24',
                  'predicate_image_name': 'dhi/pkg-openssl', 'packages': [
                      {'name': 'libcrypto3', 'version': '3.5.8-r1',
                       'binaries': {'amd64': {'sha256': '0' * 64}}}]}
        registry = self.fallback_registry(manifest_error=
            subprocess.CalledProcessError(1, 'regctl', stderr=b'401 unauthorized'))
        helper = types.ModuleType('openssl_distribution_sources')
        helper.collect_sources = lambda *args: self.fail('Authentication failure cannot authorize fallback')
        with patch.dict(sys.modules, {'openssl_distribution_sources': helper}):
            result = collection.acquire_origin(origin, 'amd64', self.root / 'openssl', registry,
                base_provenance={'signed': True}, runtime_inventory={'observed': True})
        self.assertFalse(result['success'])

    def test_reconstruction_base_json_must_equal_original_signed_bytes(self):
        proof = self.root / 'base-proof'
        proof.mkdir()
        (proof / 'statement.json').write_text('{"actual_signed_materials":true}')
        provenance = self.root / 'base.json'
        provenance.write_text('{"different_materials":true}')
        inventory = self.root / 'inventory.json'
        inventory.write_text('{}')
        with patch.object(collection, 'verify_attestation_proof', return_value={'signature_verified': True}) as verifier:
            with self.assertRaisesRegex(ValueError, 'original signed provenance bytes'):
                collection.verified_base_inputs(provenance, inventory, proof, 'amd64')
        self.assertEqual(verifier.call_args.kwargs['expected_native_digest'],
                         'sha256:' + collection.DIRECT['amd64'][0])

    def test_failed_origin_does_not_erase_other_acquisitions_or_report_success(self):
        lock = {'schema_version': 1, 'architectures': ['amd64'],
                'source_predicate_type': collection.PREDICATE,
                'origins': [{'origin': 'first'}, {'origin': 'second'}]}
        responses = [{'origin': 'first', 'success': True}, ValueError('binary mismatch')]
        with patch.object(collection, 'acquire_origin', side_effect=responses):
            report = collection.collect_packages(lock, 'amd64', self.root / 'partial', object())
        self.assertFalse(report['success'])
        self.assertTrue(report['origins'][0]['success'])
        self.assertFalse(report['origins'][1]['success'])
        self.assertTrue((self.root / 'partial/package-sources.json').exists())

    def test_all_layer_regular_file_matches_include_overwritten_binary(self):
        first = self.layer
        second = self.blob(layer([('out/.wh.sample-libs-1.2-r0.apk', b'')]),
                           'application/vnd.oci.image.layer.v1.tar+gzip')
        config = self.blob(b'{"architecture":"amd64","os":"linux"}',
                           'application/vnd.oci.image.config.v1+json')
        manifest = self.blob(json.dumps({'schemaVersion': 2, 'config': config,
                            'layers': [first, second]}).encode(), 'application/vnd.oci.image.manifest.v1+json')
        self.native = manifest['digest']
        (self.layout / 'index.json').write_text(json.dumps({'schemaVersion': 2, 'manifests': [manifest]}))
        self.assertTrue(self.match()['all_apks_matched'])

    def fallback_origin(self, name='tzdata', *, expected=None, mutable=True):
        return {'origin': name, 'version': '2026c-r0', 'image': 'dhi.io/pkg-' + name,
                'reference': 'dhi.io/pkg-' + name + ':2026-r0-alpine3.24',
                'predicate_image_name': 'dhi/pkg-' + name,
                'mutable_tag_reused_across_upstream_versions': mutable,
                'packages': [{'name': name, 'version': '2026c-r0',
                              'binaries': {'amd64': {'sha256': expected or '0' * 64}}}]}

    def fallback_registry(self, *, manifest_error=None):
        test = self

        class FakeRegistry:
            def manifest(self, reference):
                if manifest_error:
                    raise manifest_error
                return (test.layout / 'blobs' / 'sha256' / test.native.split(':')[1]).read_bytes()

            def copy(self, reference, destination):
                shutil.copytree(test.layout, destination)

            def referrers(self, reference):
                return {'manifests': []}

        return FakeRegistry()

    def test_timezone_public_sources_only_after_proven_mutable_tag_binary_mismatch(self):
        fallback = {'provider_oci_binding': False, 'binding_method': 'checked IANA release and pinned recipes',
                    'files': [{'path': 'tzdata2026c.tar.gz', 'sha256': 'a' * 64}]}
        origin = self.fallback_origin()
        with patch.object(collection, 'collect_timezone_sources', return_value=fallback) as helper:
            result = collection.acquire_origin(origin, 'amd64', self.root / 'tzdata', self.fallback_registry())
        self.assertTrue(result['success'])
        self.assertFalse(result['provider_oci_binding'])
        self.assertEqual(result['source_results'], [])
        self.assertEqual(result['public_source_fallback']['directory'], 'tzdata-public-sources')
        self.assertEqual(result['candidate_failures'][0]['failure_kind'], 'apk-binary-mismatch')
        self.assertNotIn('native_image_digest', result)
        helper.assert_called_once()

    def test_timezone_fallback_does_not_accept_other_origins(self):
        with patch.object(collection, 'collect_timezone_sources') as helper:
            result = collection.acquire_origin(self.fallback_origin('gdbm'), 'amd64',
                self.root / 'gdbm', self.fallback_registry())
        self.assertFalse(result['success'])
        helper.assert_not_called()

    def test_timezone_network_failure_does_not_trigger_public_source_fallback(self):
        with patch.object(collection, 'collect_timezone_sources') as helper:
            result = collection.acquire_origin(self.fallback_origin(), 'amd64', self.root / 'tzdata',
                self.fallback_registry(manifest_error=OSError('registry unavailable')))
        self.assertFalse(result['success'])
        helper.assert_not_called()

    def test_timezone_matching_apks_with_missing_signature_are_not_rescued(self):
        with patch.object(collection, 'collect_timezone_sources') as helper:
            result = collection.acquire_origin(self.fallback_origin(expected=hashlib.sha256(self.apk).hexdigest()),
                'amd64', self.root / 'tzdata', self.fallback_registry())
        self.assertFalse(result['success'])
        helper.assert_not_called()

    def test_timezone_nonmutable_tag_cannot_trigger_fallback(self):
        with patch.object(collection, 'collect_timezone_sources') as helper:
            result = collection.acquire_origin(self.fallback_origin(mutable=False), 'amd64',
                self.root / 'tzdata', self.fallback_registry())
        self.assertFalse(result['success'])
        helper.assert_not_called()


if __name__ == '__main__':
    unittest.main()
