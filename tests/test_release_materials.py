"""Offline integrity and release-asset lifecycle tests."""
import base64
import copy
import datetime
import hashlib
import io
import json
import os
import subprocess
import urllib.parse
from contextlib import chdir, redirect_stdout
from pathlib import Path
import tarfile
import tempfile
import unittest
import urllib.error
from unittest.mock import MagicMock, patch

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import release_materials as materials
import registry_transfer
import review_image
from native_dependency_fixture import dependency_report


def tar_bytes(entries):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w:gz') as archive:
        for name, body in entries:
            info = tarfile.TarInfo(name)
            if isinstance(body, tarfile.TarInfo):
                body.name = name
                archive.addfile(body)
            else:
                info.size = len(body)
                archive.addfile(info, io.BytesIO(body))
    return output.getvalue()


class HttpResponse:
    def __init__(self, body):
        self.body = body
        self.limits = []

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, limit=-1):
        self.limits.append(limit)
        return self.body


class ReleaseMaterialsTests(unittest.TestCase):
    VERSION = '2.18.0'
    REVISION = 'a' * 40
    DIGEST = 'sha256:' + 'b' * 64

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.distribution = self.root / 'distribution'
        self.distribution.mkdir()
        (self.root / 'VERSION').write_text(self.VERSION + '\n')
        self.environ = patch.dict(os.environ, {
            'GITHUB_SHA': self.REVISION,
            'GITHUB_REPOSITORY': 'brspoon/keep',
            'GITHUB_TOKEN': 'test-token',
            'GITHUB_RUN_ID': '123456',
            'GITHUB_RUN_ATTEMPT': '3',
            'TESTED_DIGESTS': json.dumps({'amd64': self.DIGEST, 'arm64': 'sha256:' + 'c' * 64}),
            'DOCKERHUB_IMAGE': 'brspoon/keep',
            'DOCKERHUB_USERNAME': 'test-user',
            'DOCKERHUB_TOKEN': 'test-registry-token',
        })
        self.environ.start()
        self.addCleanup(self.environ.stop)

    def write_transfer_record(self, arch='amd64', *, digest=None, revision=None,
                              run_id='123456', run_attempt='3', architecture=None):
        record = {
            'architecture': architecture or arch,
            'digest': digest or self.DIGEST,
            'revision': revision or self.REVISION,
            'run_id': run_id,
            'run_attempt': run_attempt,
        }
        path = self.root / f'transfer-{arch}.json'
        path.write_text(json.dumps(record, sort_keys=True) + '\n')
        return path

    def write_bundle(self, *, arch='amd64', files=None, manifest_overrides=None,
                     archive_entries=None, checksum_ok=True):
        files = files if files is not None else {'LICENSE.txt': b'license bytes'}
        prefix_name = f'keep-{self.VERSION}-source-materials-{arch}.tar.gz'
        prefix = prefix_name.removesuffix('.tar.gz') + '/'
        records = [{'path': name, 'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest()}
                   for name, body in files.items()]
        manifest = {'format': 'keep-container-source-bundle-v1', 'revision': self.REVISION,
                    'version': self.VERSION, 'architecture': arch, 'files': records}
        if manifest_overrides:
            manifest.update(manifest_overrides)
        entries = [(prefix + 'MANIFEST.json', json.dumps(manifest).encode())]
        entries.extend((prefix + name, body) for name, body in files.items())
        if archive_entries is not None:
            entries = [(prefix + 'MANIFEST.json', json.dumps(manifest).encode())] + [
                ((name if name.startswith(prefix) else prefix + name), body)
                for name, body in archive_entries]
        path = self.distribution / prefix_name
        path.write_bytes(tar_bytes(entries))
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        (path.with_name(path.name + '.sha256')).write_text(
            (digest if checksum_ok else '0' * 64) + '  ' + path.name + '\n')
        return path, manifest, files

    def call_bundle(self, arch='amd64', *, verify_files=False):
        with chdir(self.root):
            return materials.bundle(arch, verify_files=verify_files)

    def portable_proof(self, *, project='keep-recovery-012345abcdef', outcome='passed',
                       identity_overrides=None, cleanup_overrides=None, proof_overrides=None):
        identity = {'version': self.VERSION, 'revision': self.REVISION, 'architecture': 'amd64',
                    'native_digest': self.DIGEST, 'config_digest': 'sha256:' + 'd' * 64}
        candidate = {'version': self.VERSION, 'revision': self.REVISION, 'architecture': 'amd64',
                     'os': 'linux', 'image_id': identity['config_digest']}
        if identity_overrides:
            candidate.update(identity_overrides)
        cleanup = {'containers_removed': True,
                   'volumes_removed': [project + '-' + name for name in
                                       ('fresh-data', 'fixture-data', 'restore-data', 'rollback-data')]}
        if cleanup_overrides:
            cleanup.update(cleanup_overrides)
        proof = {'schema': 'keep.portable-container-trial.v1', 'outcome': outcome,
                 'project': project, 'candidate': candidate, 'cleanup': cleanup}
        if proof_overrides:
            proof.update(proof_overrides)
        return proof, identity

    def installer_proof(self):
        return {'schema': 'keep.installer-container-trial.v1', 'outcome': 'passed',
                'runner_sha256': hashlib.sha256(Path(materials.__file__).with_name('installer_container_trial.py').read_bytes()).hexdigest(),
                'candidate': {'version': self.VERSION, 'revision': self.REVISION, 'architecture': 'amd64',
                              'image_id': 'sha256:' + 'd' * 64},
                'cleanup': {'preexisting_resources': {'containers': [], 'volumes': [], 'networks': []},
                            'resources_absent': True, 'removed_volume': True},
                'phases': [
                    {'name': 'fresh-install', 'status': 'passed', 'both_services_healthy': True, 'http_setup': True,
                     'cookie_http_only': True, 'cookie_same_site': 'Lax', 'cookie_secure': False},
                    {'name': 'installer-rerun', 'status': 'passed', 'environment_unchanged': True,
                     'resources_unchanged': True, 'bootstrap_rotated': True},
                    {'name': 'owner-preservation', 'status': 'passed', 'owner_preserved': True,
                     'bootstrap_disabled': True, 'database_integrity': 'ok'}]}

    def prepare_archive_inputs(self, *, missing_report=None, portable=True, manifest_override=None,
                               report_symlink=False, portable_symlink=False, portable_mutation=None,
                               installer=True):
        source, manifest, _ = self.write_bundle(arch='amd64')
        digest = hashlib.sha256(source.read_bytes()).hexdigest()
        proof = {'archive': source.name, 'sha256': digest, 'bytes': source.stat().st_size,
                 'manifest': manifest if manifest_override is None else manifest_override}
        (self.distribution / 'source-bundle-amd64.json').write_text(json.dumps(proof))
        identity = {'version': self.VERSION, 'revision': self.REVISION, 'architecture': 'amd64',
                    'native_digest': self.DIGEST, 'config_digest': 'sha256:' + 'd' * 64}
        (self.root / 'release-image-amd64.json').write_text(json.dumps(identity))
        report_paths = []
        for name in materials.evidence_names('amd64'):
            if name == missing_report:
                continue
            path = self.root / name
            path.write_text(json.dumps({'report': name, 'architecture': 'amd64'}))
            report_paths.append(path)
        portable_path = self.root / 'portable-recovery-amd64.json'
        if installer:
            (self.root / 'installer-trial-amd64.json').write_text(json.dumps(self.installer_proof()))
        if portable:
            if portable_mutation:
                portable_data, _ = self.portable_proof(**portable_mutation)
            else:
                portable_data, _ = self.portable_proof()
            portable_path.write_text(json.dumps(portable_data) + '\n')
            if portable_symlink:
                target = self.root / 'portable-target.json'
                target.write_bytes(portable_path.read_bytes())
                portable_path.unlink()
                portable_path.symlink_to(target)
        if report_symlink and report_paths:
            target = self.root / 'report-target.json'
            target.write_bytes(report_paths[0].read_bytes())
            report_paths[0].unlink()
            report_paths[0].symlink_to(target)
        return source, proof, report_paths, portable_path

    def archive_call(self):
        return materials.archive('amd64')

    def verify_fixture(self, *, sidecar_error=None, identity_error=None, evidence_error=False,
                       inventory_error=None, review_changes=None, matches=None,
                       empty_exceptions=False, native_digests=None, config_digests=None,
                       validation=False):
        policy = self.write_reviewed_policy(empty_exceptions=empty_exceptions)
        rows, bodies = [], {}
        native_digests = native_digests or {'amd64': self.DIGEST, 'arm64': 'sha256:' + 'c' * 64}
        for arch, native_digest in native_digests.items():
            source_name = f'keep-{self.VERSION}-source-materials-{arch}.tar.gz'
            source_body = ('synthetic source ' + arch).encode()
            source_digest = hashlib.sha256(source_body).hexdigest()
            security_name = f'keep-{self.VERSION}-security-evidence-{arch}.tar.gz'
            evidence_payloads = {
                name: ('report ' + name).encode()
                for name in [*materials.evidence_names(arch), f'portable-recovery-{arch}.json',
                             f'installer-trial-{arch}.json', f'source-bundle-{arch}.json']}
            reports = self.security_reports(arch, policy, matches)
            if review_changes:
                for name, changes in review_changes.items():
                    if name in reports:
                        reports[name].update(changes)
            evidence_payloads.update({name: (json.dumps(body, indent=3) + '\r\n').encode()
                                      for name, body in reports.items()})
            if validation:
                evidence_payloads[f'validation-provenance-{arch}.json'] = b'{}\n'
            evidence = [{'path': name, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
                        for name, data in evidence_payloads.items()]
            if evidence_error and arch == 'amd64':
                evidence[0]['sha256'] = '0' * 64
            if inventory_error == 'missing' and arch == 'amd64':
                evidence.pop()
            elif inventory_error == 'duplicate' and arch == 'amd64':
                evidence.append(dict(evidence[0]))
            identity = {'version': self.VERSION, 'revision': self.REVISION,
                        'architecture': arch, 'native_digest': native_digest,
                        'config_digest': (config_digests or {}).get(arch, 'sha256:' + 'd' * 64), 'run_id': '123456',
                        'run_attempt': 3,
                        'source': {'name': source_name, 'sha256': source_digest,
                                   'bytes': len(source_body)}, 'evidence': evidence}
            if identity_error and arch == 'amd64':
                identity.update(identity_error)
            prefix = security_name.removesuffix('.tar.gz') + '/'
            members = [(prefix + 'IDENTITY.json', json.dumps(identity).encode())]
            for name, data in evidence_payloads.items():
                if inventory_error == 'symlink' and arch == 'amd64' and name == materials.evidence_names(arch)[0]:
                    link = tarfile.TarInfo(name)
                    link.type = tarfile.SYMTYPE
                    link.linkname = '../outside'
                    members.append((prefix + name, link))
                else:
                    members.append((prefix + name, data))
            if inventory_error == 'extra' and arch == 'amd64':
                members.append((prefix + 'unlisted-extra.json', b'extra'))
            security_body = tar_bytes(members)
            security_digest = hashlib.sha256(security_body).hexdigest()
            for name, body, digest in ((source_name, source_body, source_digest),
                                       (security_name, security_body, security_digest)):
                rows.append({'id': len(rows) + 1, 'name': name, 'digest': 'sha256:' + digest,
                             'size': len(body)})
                bodies[name] = body
                sidecar_name = name + '.sha256'
                sidecar_body = f'{digest}  {name}\n'.encode()
                if sidecar_error == name:
                    sidecar_body = b'wrong digest  wrong-name\n'
                sidecar_digest = hashlib.sha256(sidecar_body).hexdigest()
                rows.append({'id': len(rows) + 1, 'name': sidecar_name,
                             'digest': 'sha256:' + sidecar_digest, 'size': len(sidecar_body)})
                bodies[sidecar_name] = sidecar_body
        return rows, bodies

    def write_reviewed_policy(self, *, empty_exceptions=False):
        repository = Path(materials.__file__).resolve().parents[1]
        policy = json.loads((repository / 'docs/image-exceptions.json').read_text())
        if empty_exceptions:
            policy['exceptions'] = {}
        policy_path = self.root / 'docs/image-exceptions.json'
        policy_path.parent.mkdir(parents=True, exist_ok=True)
        policy_path.write_text(json.dumps(policy))
        for name in policy['reviewed_sources']:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((repository / name).read_bytes())
        return policy

    def security_reports(self, arch, policy, matches=None):
        return {
            f'candidate-dependencies-{arch}.json': dependency_report(arch),
            f'candidate-{arch}.json': {'matches': matches or []},
            f'candidate-scout-{arch}.json': {'runs': [{'results': []}]},
            f'candidate-regression-{arch}.json': {
                'success': True, 'tests': 9, 'failures': 0, 'errors': 0,
                'skipped': 0, 'arch': arch,
                'patch_manifest_sha256': policy['reviewed_sources']['scripts/python_security_patches.json'],
            },
            f'candidate-provenance-{arch}.json': {
                'predicateType': 'https://slsa.dev/provenance/v1',
                'subject': [{'digest': {'sha256': review_image.DIRECT[arch][0]}}],
            },
        }

    def test_bundle_requires_checksum_and_exact_source_identity(self):
        self.write_bundle(checksum_ok=False)
        with self.assertRaisesRegex(ValueError, 'checksum differs'):
            self.call_bundle()

        self.write_bundle(manifest_overrides={'revision': 'd' * 40})
        with self.assertRaisesRegex(ValueError, 'identity differs'):
            self.call_bundle()

        self.write_bundle(manifest_overrides={'version': '9.9.9'})
        with self.assertRaisesRegex(ValueError, 'identity differs'):
            self.call_bundle()

        self.write_bundle(manifest_overrides={'architecture': 'arm64'})
        with self.assertRaisesRegex(ValueError, 'identity differs'):
            self.call_bundle()

    def test_bundle_full_verification_checks_member_hash_length_and_inventory(self):
        self.write_bundle()
        path, proof = self.call_bundle(verify_files=True)
        self.assertEqual(path.name, proof['archive'])
        self.assertEqual(proof['manifest']['files'][0]['path'], 'LICENSE.txt')

        self.write_bundle(archive_entries=[('LICENSE.txt', b'bad body')])
        with self.assertRaisesRegex(ValueError, 'member checksum differs'):
            self.call_bundle(verify_files=True)

        self.write_bundle(files={'LICENSE.txt': b'x'}, archive_entries=[('LICENSE.txt', b'x'),
                                                                      ('extra.txt', b'unexpected')])
        with self.assertRaisesRegex(ValueError, 'Unexpected source archive member'):
            self.call_bundle(verify_files=True)

        self.write_bundle(files={'LICENSE.txt': b'x'}, archive_entries=[('LICENSE.txt', b'x'),
                                                                      ('LICENSE.txt', b'x')])
        with self.assertRaisesRegex(ValueError, 'Unexpected source archive member'):
            self.call_bundle(verify_files=True)

        self.write_bundle(files={'LICENSE.txt': b'x'}, archive_entries=[])
        with self.assertRaisesRegex(ValueError, 'Incomplete corresponding-source archive'):
            self.call_bundle(verify_files=True)

    def test_bundle_rejects_duplicate_missing_and_unsafe_manifest_inventory(self):
        self.write_bundle(archive_entries=[('MANIFEST.json', b'{}')])
        with self.assertRaisesRegex(ValueError, 'Require one source manifest'):
            self.call_bundle(verify_files=True)

        self.write_bundle(files={'LICENSE.txt': b'x', 'COPYING.txt': b'y'},
                          manifest_overrides={'files': [
                              {'path': 'LICENSE.txt', 'bytes': 1, 'sha256': hashlib.sha256(b'x').hexdigest()},
                              {'path': 'LICENSE.txt', 'bytes': 1, 'sha256': hashlib.sha256(b'x').hexdigest()}]})
        with self.assertRaisesRegex(ValueError, 'Duplicate source inventory member'):
            self.call_bundle(verify_files=True)

        self.write_bundle(files={'LICENSE.txt': b'x'}, archive_entries=[('../escape', b'x')])
        with self.assertRaisesRegex(ValueError, 'Unsafe source archive member'):
            self.call_bundle(verify_files=True)

        link = tarfile.TarInfo('LICENSE.txt')
        link.type = tarfile.SYMTYPE
        link.linkname = '../outside'
        self.write_bundle(files={'LICENSE.txt': b'x'}, archive_entries=[('LICENSE.txt', link)])
        with self.assertRaisesRegex(ValueError, 'Unexpected source archive member'):
            self.call_bundle(verify_files=True)

    def test_manual_current_guard_precedes_all_archive_writes(self):
        with chdir(self.root), patch.object(materials, 'require_manual_dispatch') as manual, \
             patch.object(materials, 'require_current_source') as current:
            self.assertEqual(materials.guard(), self.VERSION)
        manual.assert_called_once_with(True)
        current.assert_called_once_with(self.REVISION, True)

        with chdir(self.root), patch.object(materials, 'guard', side_effect=ValueError('guarded')), \
             patch.object(materials, 'draft') as draft, patch.object(materials, 'upload') as upload:
            with self.assertRaisesRegex(ValueError, 'guarded'):
                materials.archive('amd64')
        draft.assert_not_called()
        upload.assert_not_called()

    def test_draft_reuses_only_one_matching_source_and_prepare_creates_once(self):
        matching = {'id': 44, 'tag_name': self.VERSION, 'target_commitish': self.REVISION,
                    'draft': True}
        with patch.object(materials, 'api', return_value=[matching]) as api:
            self.assertEqual(materials.draft(self.VERSION), matching)
        api.assert_called_once_with('/releases?per_page=100&page=1')

        for rows, message in (
                ([{**matching, 'target_commitish': 'f' * 40}], 'differs from the confirmed source'),
                ([{**matching, 'draft': False}], 'differs from the confirmed source'),
                ([matching, {**matching, 'id': 45}], 'Multiple release drafts')):
            with self.subTest(message=message), patch.object(materials, 'api', return_value=rows):
                with self.assertRaisesRegex(ValueError, message):
                    materials.draft(self.VERSION)

        with patch.object(materials, 'api', return_value=[]) as api:
            with self.assertRaisesRegex(ValueError, 'prepared release draft'):
                materials.draft(self.VERSION)
        api.assert_called_once_with('/releases?per_page=100&page=1')

        with patch.object(materials, 'api', side_effect=[[], {'id': 46, 'tag_name': self.VERSION,
                                                               'target_commitish': self.REVISION,
                                                               'draft': True}]) as api:
            created = materials.draft(self.VERSION, create=True)
        self.assertEqual(created['id'], 46)
        api.assert_has_calls([
            unittest.mock.call('/releases?per_page=100&page=1'),
            unittest.mock.call('/releases', method='POST', data={
                'tag_name': self.VERSION, 'target_commitish': self.REVISION,
                'name': 'Keep ' + self.VERSION + ' candidate', 'draft': True,
                'body': 'Release candidate. Corresponding sources and native security evidence are retained here. Release acceptance and finalization are pending.'})])

    def test_upload_streams_and_refuses_overwrite_or_redirect(self):
        path = self.root / 'candidate.json'
        path.write_bytes(b'{"synthetic":true}')
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        release = {'id': 77}
        existing = {'name': path.name, 'digest': 'sha256:' + '0' * 64, 'size': path.stat().st_size}
        with patch.object(materials, 'api', return_value=[existing]), \
             patch.object(materials.http.client, 'HTTPSConnection') as connection:
            with self.assertRaisesRegex(ValueError, 'refusing overwrite'):
                materials.upload(release, path)
        connection.assert_not_called()

        connection.return_value.getresponse.return_value.status = 302
        connection.return_value.getresponse.return_value.read.return_value = b''
        with patch.object(materials, 'api', return_value=[]), \
             patch.object(materials.http.client, 'HTTPSConnection', return_value=connection.return_value) as connect:
            with self.assertRaisesRegex(ValueError, 'HTTP 302'):
                materials.upload(release, path)
        connect.assert_called_once_with('uploads.github.com', timeout=300)
        connection.return_value.putrequest.assert_called_once()
        headers = {call.args[0]: call.args[1] for call in connection.return_value.putheader.call_args_list}
        self.assertEqual(headers['Authorization'], 'Bearer test-token')
        self.assertEqual(headers['Content-Length'], str(path.stat().st_size))
        self.assertEqual(connection.return_value.send.call_args.args[0], path.read_bytes())
        connection.return_value.close.assert_called_once()

        matching = {'name': path.name, 'digest': 'sha256:' + digest, 'size': path.stat().st_size}
        with patch.object(materials, 'api', return_value=[matching]), \
             patch.object(materials.http.client, 'HTTPSConnection') as connection:
            self.assertEqual(materials.upload(release, path), matching)
        connection.assert_not_called()

        response = MagicMock(status=201)
        response.read.return_value = json.dumps(matching).encode()
        connection.return_value.getresponse.return_value = response
        with patch.object(materials, 'api', return_value=[]), \
             patch.object(materials.http.client, 'HTTPSConnection', return_value=connection.return_value):
            self.assertEqual(materials.upload(release, path), matching)

    def test_archive_requires_original_reports_portable_evidence_and_unchanged_manifest(self):
        setups = (
            {'missing_report': 'source-acquisition-packages-amd64.log', 'portable': True,
             'error': 'twelve original native security reports'},
            {'portable': True, 'report_symlink': True,
             'error': 'twelve original native security reports'},
            {'portable': False, 'error': 'portable recovery evidence'},
            {'portable': True, 'portable_symlink': True,
             'error': 'portable recovery evidence'},
            {'portable': True, 'portable_mutation': {'outcome': 'failed'},
             'error': 'Portable recovery proof differs'},
            {'portable': True, 'portable_mutation': {'cleanup_overrides': {'volumes_removed': []}},
             'error': 'Portable recovery resources were not verified clean'},
            {'installer': False, 'error': 'one-command installer evidence'},
            {'portable': True, 'manifest_override': {'changed': True},
             'error': 'original native CI bundle'},
        )
        for case in setups:
            with self.subTest(error=case['error']):
                for path in self.root.glob('candidate-*amd64.json'):
                    path.unlink()
                for path in self.root.glob('candidate-*-amd64.json'):
                    path.unlink()
                for path in self.root.glob('source-*-amd64.log'):
                    path.unlink()
                (self.root / 'portable-recovery-amd64.json').unlink(missing_ok=True)
                (self.root / 'installer-trial-amd64.json').unlink(missing_ok=True)
                args = {key: value for key, value in case.items()
                        if key in ('missing_report', 'portable', 'manifest_override', 'report_symlink', 'portable_symlink', 'installer')}
                if 'portable_mutation' in case:
                    args['portable_mutation'] = case['portable_mutation']
                self.prepare_archive_inputs(**args)
                with chdir(self.root), patch.object(materials, 'guard', return_value=self.VERSION), \
                     patch.object(materials, 'tested_digests', return_value={'amd64': self.DIGEST, 'arm64': 'sha256:' + 'c' * 64}), \
                     patch.object(materials.subprocess, 'run') as review, \
                     patch.object(materials, 'draft') as draft, patch.object(materials, 'upload') as upload:
                    with self.assertRaisesRegex(ValueError, case['error']):
                        self.archive_call()
                if case['error'] in ('twelve original native security reports', 'original native CI bundle'):
                    review.assert_not_called()
                else:
                    review.assert_called_once()
                draft.assert_not_called()
                upload.assert_not_called()

    def test_archive_uploads_native_identity_and_hashed_evidence_after_validation(self):
        source, proof, reports, portable = self.prepare_archive_inputs()
        pushed = []
        release = {'id': 44, 'draft': True, 'tag_name': self.VERSION,
                   'target_commitish': self.REVISION}

        def record_upload(_release, path):
            path = Path(path)
            pushed.append(path.name)
            if 'security-evidence' in path.name and path.name.endswith('.tar.gz'):
                with tarfile.open(path, 'r:gz') as archive:
                    prefix = path.name.removesuffix('.tar.gz') + '/'
                    identity = json.load(archive.extractfile(prefix + 'IDENTITY.json'))
                    self.assertEqual(identity['architecture'], 'amd64')
                    self.assertEqual(identity['revision'], self.REVISION)
                    self.assertEqual(identity['native_digest'], self.DIGEST)
                    self.assertEqual(identity['run_id'], '123456')
                    self.assertEqual(identity['source'], {
                        'name': source.name, 'sha256': proof['sha256'], 'bytes': proof['bytes']})
                    records = {row['path']: row for row in identity['evidence']}
                    installer = self.root / 'installer-trial-amd64.json'
                    expected_paths = {path.name for path in reports} | {portable.name, installer.name, 'source-bundle-amd64.json'}
                    self.assertEqual(set(records), expected_paths)
                    for evidence_path in [*reports, portable, installer, self.distribution / 'source-bundle-amd64.json']:
                        row = records[evidence_path.name]
                        body = evidence_path.read_bytes()
                        self.assertEqual(row['bytes'], len(body))
                        self.assertEqual(row['sha256'], hashlib.sha256(body).hexdigest())
            return {'name': path.name}

        with chdir(self.root), patch.object(materials, 'guard', return_value=self.VERSION) as guard, \
             patch.object(materials, 'tested_digests', return_value={'amd64': self.DIGEST, 'arm64': 'sha256:' + 'c' * 64}), \
             patch.object(materials.subprocess, 'run'), \
             patch.object(materials, 'draft', return_value=release), \
             patch.object(materials, 'upload', side_effect=record_upload):
            self.archive_call()
        self.assertEqual(pushed, [source.name, source.name + '.sha256',
                                  f'keep-{self.VERSION}-security-evidence-amd64.tar.gz',
                                  f'keep-{self.VERSION}-security-evidence-amd64.tar.gz.sha256'])
        self.assertEqual(guard.call_count, 5)

    def test_portable_evidence_requires_exact_candidate_identity_project_and_clean_resources(self):
        valid, identity = self.portable_proof()
        evidence = self.root / 'portable.json'
        evidence.write_text(json.dumps(valid))
        materials.portable_evidence(evidence, 'amd64', identity)

        cases = (
            (self.portable_proof(outcome='failed')[0], 'Portable recovery proof differs'),
            (self.portable_proof(project='other-project')[0], 'Portable recovery proof differs'),
            (self.portable_proof(identity_overrides={'version': '9.9.9'})[0], 'Portable recovery proof differs'),
            (self.portable_proof(identity_overrides={'revision': 'f' * 40})[0], 'Portable recovery proof differs'),
            (self.portable_proof(identity_overrides={'architecture': 'arm64'})[0], 'Portable recovery proof differs'),
            (self.portable_proof(identity_overrides={'image_id': 'sha256:' + '0' * 64})[0], 'Portable recovery proof differs'),
            (self.portable_proof(identity_overrides={'os': 'windows'})[0], 'Portable recovery proof differs'),
            (self.portable_proof(cleanup_overrides={'containers_removed': False})[0],
             'Portable recovery resources were not verified clean'),
            (self.portable_proof(cleanup_overrides={'volumes_removed': ['keep-recovery-012345abcdef-fresh-data']})[0],
             'Portable recovery resources were not verified clean'),
            (self.portable_proof(cleanup_overrides={'preserved_networks': ['unexpected']})[0],
             'Portable recovery resources were not verified clean'),
            (self.portable_proof(cleanup_overrides={'network_inventory_error': 'failed'})[0],
             'Portable recovery resources were not verified clean'),
            (self.portable_proof(proof_overrides={'failure': 'cleanup failed'})[0],
             'Portable recovery resources were not verified clean'),
            (self.portable_proof(proof_overrides={'report_error': 'write failed'})[0],
             'Portable recovery resources were not verified clean'),
        )
        for proof, message in cases:
            with self.subTest(message=message, proof=proof):
                evidence.write_text(json.dumps(proof))
                with self.assertRaisesRegex(ValueError, message):
                    materials.portable_evidence(evidence, 'amd64', identity)

    def test_installer_evidence_requires_candidate_complete_lifecycle_and_verified_cleanup(self):
        _, identity = self.portable_proof()
        proof = self.installer_proof()
        path = self.root / 'installer.json'
        path.write_text(json.dumps(proof))
        materials.installer_evidence(path, 'amd64', identity)
        mutations = (
            lambda row: row.update(outcome='failed'),
            lambda row: row.update(runner_sha256='f' * 64),
            lambda row: row['candidate'].update(image_id='sha256:' + 'f' * 64),
            lambda row: row['candidate'].update(architecture='arm64'),
            lambda row: row['cleanup'].update(resources_absent=False),
            lambda row: row['cleanup'].update(removed_volume=False),
            lambda row: row['cleanup']['preexisting_resources'].update(volumes=['existing-volume']),
            lambda row: row['phases'].pop(),
            lambda row: row['phases'][0].update(cookie_secure=True),
            lambda row: row['phases'][0].update(cookie_secure=0),
            lambda row: row['phases'][1].update(bootstrap_rotated=False),
            lambda row: row['phases'][2].update(owner_preserved=False),
        )
        for mutate in mutations:
            invalid = copy.deepcopy(proof)
            mutate(invalid)
            with self.subTest(proof=invalid):
                path.write_text(json.dumps(invalid))
                with self.assertRaises(ValueError):
                    materials.installer_evidence(path, 'amd64', identity)

    def test_asset_download_redirect_is_allowlisted_and_drops_authorization(self):
        body = b'sealed evidence'
        asset = {'id': 9, 'name': 'evidence.bin', 'size': len(body),
                 'digest': 'sha256:' + hashlib.sha256(body).hexdigest()}
        from email.message import Message
        headers = Message()
        headers['Location'] = 'https://release-assets.githubusercontent.com/private/blob?sig=synthetic'
        redirected = urllib.error.HTTPError('https://api.github.com/asset', 302, 'redirect', headers, None)
        final_response = MagicMock()
        final_response.read.return_value = body
        opener = MagicMock()
        opener.open.side_effect = [redirected, final_response]
        with patch.object(materials.urllib.request, 'build_opener', return_value=opener):
            self.assertEqual(materials.asset_body(asset), body)
        first, second = (call.args[0] for call in opener.open.call_args_list)
        self.assertEqual(first.get_header('Authorization'), 'Bearer test-token')
        self.assertEqual(second.full_url, headers['Location'])
        self.assertIsNone(second.get_header('Authorization'))

        for location in (
                'https://attacker.example/blob',
                'http://release-assets.githubusercontent.com/blob',
                'https://attacker@release-assets.githubusercontent.com/blob',
                'https://release-assets.githubusercontent.com.attacker.example/blob',
            'https://release-assets.githubusercontent.com:443/blob',
            'https://release-assets.githubusercontent.com/blob#fragment'):
            with self.subTest(location=location):
                bad_headers = Message()
                bad_headers['Location'] = location
                rejected = urllib.error.HTTPError('https://api.github.com/asset', 302, 'redirect', bad_headers, None)
                opener.reset_mock()
                opener.open.side_effect = [rejected]
                with patch.object(materials.urllib.request, 'build_opener', return_value=opener):
                    with self.assertRaises(urllib.error.HTTPError):
                        materials.asset_body(asset)
                self.assertEqual(opener.open.call_count, 1)

        valid_response = MagicMock()
        valid_response.__enter__ = MagicMock(return_value=valid_response)
        valid_response.__exit__ = MagicMock(return_value=False)
        valid_response.read.return_value = body
        with patch.object(materials.urllib.request, 'build_opener', return_value=MagicMock(open=MagicMock(return_value=valid_response))):
            with self.assertRaisesRegex(ValueError, 'checksum or length differs'):
                materials.asset_body({**asset, 'size': len(body) + 1})
        with patch.object(materials.urllib.request, 'build_opener', return_value=MagicMock(open=MagicMock(return_value=valid_response))):
            with self.assertRaisesRegex(ValueError, 'checksum or length differs'):
                materials.asset_body({**asset, 'digest': 'sha256:' + '0' * 64})

    def test_verify_checks_both_native_evidence_archives_and_sidecars_before_identity_upload(self):
        rows, bodies = self.verify_fixture()
        release = {'id': 88, 'draft': True, 'tag_name': self.VERSION,
                   'target_commitish': self.REVISION}
        uploaded = {}

        def record_identity(_release, path):
            path = Path(path)
            uploaded.update(json.loads(path.read_text()))
            return {'name': path.name}

        with chdir(self.root), patch.object(materials, 'guard', return_value=self.VERSION), \
             patch.object(materials, 'tested_digests', return_value={'amd64': self.DIGEST, 'arm64': 'sha256:' + 'c' * 64}), \
             patch.object(materials, 'draft', return_value=release), \
             patch.object(materials, 'api', return_value=rows), \
             patch.object(materials, 'asset_body', side_effect=lambda asset: bodies[asset['name']]), \
             patch.object(materials, 'upload', side_effect=record_identity) as upload:
            materials.verify()
        upload.assert_called_once()
        self.assertEqual(upload.call_args.args[0], release)
        self.assertEqual(uploaded['run_id'], '123456')
        self.assertEqual(uploaded['revision'], self.REVISION)
        self.assertEqual(uploaded['images']['amd64']['architecture'], 'amd64')
        self.assertEqual(uploaded['images']['arm64']['architecture'], 'arm64')
        self.assertEqual(uploaded['images']['amd64']['native_digest'], self.DIGEST)
        self.assertEqual(uploaded['images']['arm64']['native_digest'], 'sha256:' + 'c' * 64)
        for arch in materials.ARCHES:
            image = uploaded['images'][arch]
            self.assertEqual(image['source']['name'], f'keep-{self.VERSION}-source-materials-{arch}.tar.gz')
            self.assertEqual(image['run_id'], '123456')

    def test_verify_rejects_wrong_sidecar_identity_or_evidence_before_upload(self):
        cases = (
            {'sidecar_error': f'keep-{self.VERSION}-source-materials-amd64.tar.gz',
             'message': 'asset checksum sidecar differs'},
            {'sidecar_error': f'keep-{self.VERSION}-security-evidence-arm64.tar.gz',
             'message': 'asset checksum sidecar differs'},
            {'identity_error': {'run_id': 'wrong-run'},
             'message': 'evidence identity differs'},
            {'identity_error': {'architecture': 'arm64'},
             'message': 'evidence identity differs'},
            {'identity_error': {'native_digest': 'sha256:' + '0' * 64},
             'message': 'evidence identity differs'},
            {'identity_error': {'source': {'name': f'keep-{self.VERSION}-source-materials-amd64.tar.gz',
                                           'sha256': '0' * 64, 'bytes': 1}},
             'message': 'source asset differs'},
            {'evidence_error': True, 'message': 'evidence member differs'},
            {'inventory_error': 'missing', 'message': 'evidence inventory is incomplete'},
            {'inventory_error': 'duplicate', 'message': 'evidence inventory is incomplete'},
            {'inventory_error': 'symlink', 'message': 'Unexpected durable evidence archive member'},
            {'inventory_error': 'extra', 'message': 'Unexpected durable evidence archive member'},
        )
        for case in cases:
            with self.subTest(message=case['message']):
                rows, bodies = self.verify_fixture(**{key: value for key, value in case.items()
                                                      if key != 'message'})
                release = {'id': 88, 'draft': True, 'tag_name': self.VERSION,
                           'target_commitish': self.REVISION}
                with chdir(self.root), patch.object(materials, 'guard', return_value=self.VERSION), \
                     patch.object(materials, 'tested_digests', return_value={'amd64': self.DIGEST, 'arm64': 'sha256:' + 'c' * 64}), \
                     patch.object(materials, 'draft', return_value=release), \
                     patch.object(materials, 'api', return_value=rows), \
                     patch.object(materials, 'asset_body', side_effect=lambda asset: bodies[asset['name']]), \
                     patch.object(materials, 'upload') as upload:
                    with self.assertRaisesRegex(ValueError, case['message']):
                        materials.verify()
                upload.assert_not_called()

    def native_image(self, arch='amd64', *, version=None, revision=None,
                     os_name='linux', user='10001:10001', config_digest=None,
                     source='https://github.com/brspoon/keep'):
        return [{
            'Id': config_digest or 'sha256:' + 'd' * 64,
            'Architecture': arch, 'Os': os_name,
            'Config': {'User': user, 'Labels': {
                'org.opencontainers.image.version': version or self.VERSION,
                'org.opencontainers.image.revision': revision or self.REVISION,
                'org.opencontainers.image.source': source,
            }},
        }]

    def native_hub(self, *, private=True, tag_digest=None):
        def hub(path, token=None, payload=None):
            if path == 'auth/token':
                return {'access_token': 'synthetic-hub-access-token'}
            if path == 'repositories/brspoon/keep/':
                return {'is_private': private}
            if path == 'repositories/brspoon/keep/tags/transfer-123456-3-amd64/':
                return {'digest': tag_digest or self.DIGEST}
            raise AssertionError('Unexpected registry endpoint: ' + path)
        return hub

    def test_archive_native_requires_exact_current_transfer_before_writing_identity(self):
        self.write_transfer_record()
        release_image = self.root / 'release-image-amd64.json'
        valid = json.loads((self.root / 'transfer-amd64.json').read_text())
        with chdir(self.root), patch.object(materials, 'guard', side_effect=ValueError('guarded')), \
             patch.object(materials, 'hub') as hub, \
             patch.object(materials.subprocess, 'check_output') as inspect, \
             patch.object(materials, 'archive') as archive:
            with self.assertRaisesRegex(ValueError, 'guarded'):
                materials.archive_native('amd64')
        hub.assert_not_called()
        inspect.assert_not_called()
        archive.assert_not_called()
        self.assertFalse(release_image.exists())

        bad_records = (
            {**valid, 'architecture': 'arm64'},
            {**valid, 'revision': 'f' * 40},
            {**valid, 'run_id': '999'},
            {**valid, 'run_attempt': '2'},
            {**valid, 'digest': 'sha256:' + 'z' * 64},
            {**valid, 'extra': 'unexpected'},
        )
        with chdir(self.root):
            for record in bad_records:
                with self.subTest(record=record):
                    release_image.unlink(missing_ok=True)
                    (self.root / 'transfer-amd64.json').write_text(json.dumps(record))
                    with patch.object(materials, 'guard', return_value=self.VERSION), \
                         patch.object(materials, 'hub', side_effect=AssertionError('registry queried')), \
                         patch.object(materials.subprocess, 'check_output', side_effect=AssertionError('image inspected')), \
                         patch.object(materials, 'archive') as archive:
                        with self.assertRaises(ValueError):
                            materials.archive_native('amd64')
                    self.assertFalse(release_image.exists())
                    archive.assert_not_called()

    def test_archive_native_requires_valid_visibility_unchanged_tag_and_exact_image_identity(self):
        self.write_transfer_record()
        release_image = self.root / 'release-image-amd64.json'
        with chdir(self.root), patch.object(materials, 'guard', return_value=self.VERSION), \
             patch.object(materials, 'hub', side_effect=self.native_hub(tag_digest='sha256:' + '0' * 64)), \
             patch.object(materials.subprocess, 'check_output') as inspect, \
             patch.object(materials, 'archive') as archive:
            with self.assertRaisesRegex(ValueError, 'transfer tag changed'):
                materials.archive_native('amd64')
        inspect.assert_not_called()
        archive.assert_not_called()
        self.assertFalse(release_image.exists())

        with chdir(self.root), patch.object(materials, 'guard', return_value=self.VERSION), \
             patch.object(materials, 'hub', side_effect=self.native_hub(private='false')), \
             patch.object(materials.subprocess, 'check_output') as inspect, \
             patch.object(materials, 'archive') as archive:
            with self.assertRaisesRegex(ValueError, 'visibility metadata'):
                materials.archive_native('amd64')
        inspect.assert_not_called()
        archive.assert_not_called()

        wrong_images = (
            self.native_image(arch='arm64'),
            self.native_image(os_name='windows'),
            self.native_image(user='root'),
            self.native_image(version='9.9.9'),
            self.native_image(revision='f' * 40),
            self.native_image(source='https://github.com/attacker/keep'),
            self.native_image(config_digest='missing-config-digest'),
        )
        for inspected in wrong_images:
            with self.subTest(image=inspected), chdir(self.root), \
                 patch.object(materials, 'guard', return_value=self.VERSION), \
                 patch.object(materials, 'hub', side_effect=self.native_hub()), \
                 patch.object(materials.subprocess, 'check_output', return_value=json.dumps(inspected).encode()), \
                 patch.object(materials, 'archive') as archive:
                release_image.unlink(missing_ok=True)
                with self.assertRaises(ValueError):
                    materials.archive_native('amd64')
                archive.assert_not_called()
                self.assertFalse(release_image.exists())

    def test_archive_native_binds_only_its_own_verified_digest(self):
        self.write_transfer_record()
        release_image = self.root / 'release-image-amd64.json'
        for private in (False, True):
            with self.subTest(private=private), chdir(self.root), \
                 patch.object(materials, 'guard', return_value=self.VERSION), \
                 patch.object(materials, 'hub', side_effect=self.native_hub(private=private)) as hub, \
                 patch.object(materials.subprocess, 'check_output',
                              return_value=json.dumps(self.native_image()).encode()) as inspect, \
                 patch.object(materials, 'registry_config', return_value='sha256:' + 'd' * 64) as registry_config, \
                 patch.object(materials, 'tested_digests', side_effect=AssertionError('cross-architecture digest read')), \
                 patch.object(materials, 'archive') as archive:
                materials.archive_native('amd64')
            hub.assert_any_call('repositories/brspoon/keep/tags/transfer-123456-3-amd64/',
                                'synthetic-hub-access-token')
            inspect.assert_called_once_with(['docker', 'image', 'inspect', 'keep-ci'])
            registry_config.assert_called_once_with(self.DIGEST)
            archive.assert_called_once_with('amd64', native_digest=self.DIGEST)
            self.assertEqual(json.loads(release_image.read_text()), {
                'version': self.VERSION, 'revision': self.REVISION, 'architecture': 'amd64',
                'native_digest': self.DIGEST, 'config_digest': 'sha256:' + 'd' * 64,
            })

    def test_registry_config_detects_changed_manifest_config_before_archive_or_identity(self):
        self.write_transfer_record()
        release_image = self.root / 'release-image-amd64.json'
        with chdir(self.root), patch.object(materials, 'guard', return_value=self.VERSION), \
             patch.object(materials, 'hub', side_effect=self.native_hub()), \
             patch.object(materials.subprocess, 'check_output',
                          return_value=json.dumps(self.native_image()).encode()), \
             patch.object(materials, 'registry_config', return_value='sha256:' + '0' * 64), \
             patch.object(materials, 'archive') as archive:
            with self.assertRaisesRegex(ValueError, 'manifest differs from the original tested image config'):
                materials.archive_native('amd64')
        archive.assert_not_called()
        self.assertFalse(release_image.exists())

    def test_registry_config_uses_fixed_pull_only_hosts_and_binds_raw_manifest_sha(self):
        manifest = {'schemaVersion': 2, 'config': {'digest': 'sha256:' + 'd' * 64},
                    'layers': [{'digest': 'sha256:' + 'e' * 64}]}
        body = json.dumps(manifest, separators=(',', ':')).encode()
        native = 'sha256:' + hashlib.sha256(body).hexdigest()
        opener = MagicMock()
        opener.open.side_effect = [
            HttpResponse(json.dumps({'token': 'syntheticRegistryReadToken_0123456789'}).encode()),
            HttpResponse(body),
        ]
        with patch.object(materials.urllib.request, 'build_opener', return_value=opener) as build_opener:
            config = materials.registry_config(native)

        self.assertEqual(config, manifest['config']['digest'])
        self.assertEqual(build_opener.call_count, 1)
        handlers = build_opener.call_args.args
        self.assertEqual(len(handlers), 1)
        self.assertIsInstance(handlers[0], materials.NoRedirect)
        auth_request, manifest_request = [call.args[0] for call in opener.open.call_args_list]
        self.assertEqual(auth_request.full_url, 'https://auth.docker.io/token?' + urllib.parse.urlencode({
            'service': 'registry.docker.io', 'scope': 'repository:brspoon/keep:pull'}))
        self.assertEqual(auth_request.get_method(), 'GET')
        self.assertEqual(auth_request.data, None)
        self.assertEqual(base64.b64decode(auth_request.get_header('Authorization').split()[1]).decode(),
                         'test-user:test-registry-token')
        self.assertEqual(manifest_request.full_url, 'https://registry-1.docker.io/v2/brspoon/keep/manifests/' + native)
        self.assertEqual(manifest_request.get_method(), 'GET')
        self.assertEqual(manifest_request.get_header('Authorization'), 'Bearer syntheticRegistryReadToken_0123456789')
        self.assertIn('application/vnd.oci.image.manifest.v1+json', manifest_request.get_header('Accept'))
        self.assertEqual([call.kwargs['timeout'] for call in opener.open.call_args_list], [30, 30])
        self.assertIsNone(materials.NoRedirect().redirect_request(
            auth_request, object(), 302, 'Found', {}, 'https://attacker.invalid/'))

    def test_registry_config_rejects_raw_hash_mismatch_index_subject_bad_schema_and_config(self):
        ordinary = {'schemaVersion': 2, 'config': {'digest': 'sha256:' + 'd' * 64}, 'layers': []}
        malformed = (
            ({**ordinary, 'manifests': [{'digest': 'sha256:' + 'e' * 64}]}, 'Require one native image manifest'),
            ({**ordinary, 'subject': {'digest': 'sha256:' + 'e' * 64}}, 'Require one native image manifest'),
            ({**ordinary, 'schemaVersion': 1}, 'Require one native image manifest'),
            ({**ordinary, 'config': {'digest': 'bad'}}, 'Missing or invalid tested image digest'),
        )
        for manifest, message in malformed:
            body = json.dumps(manifest, separators=(',', ':')).encode()
            native = 'sha256:' + hashlib.sha256(body).hexdigest()
            opener = MagicMock()
            opener.open.side_effect = [HttpResponse(b'{"token":"syntheticRegistryReadToken_0123456789"}'),
                                       HttpResponse(body)]
            with self.subTest(message=message), patch.object(
                    materials.urllib.request, 'build_opener', return_value=opener):
                with self.assertRaisesRegex(ValueError, message):
                    materials.registry_config(native)
                self.assertEqual(opener.open.call_count, 2)

        body = json.dumps(ordinary, separators=(',', ':')).encode()
        opener = MagicMock()
        opener.open.side_effect = [HttpResponse(b'{"token":"syntheticRegistryReadToken_0123456789"}'),
                                   HttpResponse(body)]
        with patch.object(materials.urllib.request, 'build_opener', return_value=opener):
            with self.assertRaisesRegex(ValueError, 'manifest bytes differ'):
                materials.registry_config('sha256:' + '0' * 64)

    def test_registry_config_rejects_oversized_or_invalid_auth_and_manifest_responses(self):
        oversized_auth = MagicMock()
        oversized_auth_response = HttpResponse(b'x' * (64 * 1024 + 1))
        oversized_auth.open.return_value = oversized_auth_response
        with patch.object(materials.urllib.request, 'build_opener', return_value=oversized_auth):
            with self.assertRaisesRegex(ValueError, 'read token response exceeds its limit'):
                materials.registry_config(self.DIGEST)
        self.assertEqual(oversized_auth_response.limits, [64 * 1024 + 1])
        self.assertEqual(oversized_auth.open.call_count, 1)

        for auth_body, message in (
            (b'{"token":"invalid!token"}', 'Registry returned an invalid read token'),
        ):
            opener = MagicMock()
            opener.open.return_value = HttpResponse(auth_body)
            with self.subTest(message=message), patch.object(
                    materials.urllib.request, 'build_opener', return_value=opener):
                with self.assertRaisesRegex(ValueError, message):
                    materials.registry_config(self.DIGEST)
                self.assertEqual(opener.open.call_count, 1)

        valid_manifest = json.dumps({'schemaVersion': 2,
                                     'config': {'digest': 'sha256:' + 'd' * 64},
                                     'layers': []}, separators=(',', ':')).encode()
        oversized_manifest = MagicMock()
        oversized_manifest.open.side_effect = [
            HttpResponse(b'{"token":"syntheticRegistryReadToken_0123456789"}'),
            HttpResponse(b'x' * (2 * 1024 * 1024 + 1)),
        ]
        with patch.object(materials.urllib.request, 'build_opener', return_value=oversized_manifest):
            with self.assertRaisesRegex(ValueError, 'manifest bytes differ'):
                materials.registry_config(self.DIGEST)
        self.assertEqual(oversized_manifest.open.call_count, 2)

    def test_actual_stage_record_flows_into_native_archive_with_string_attempt(self):
        output = self.root / 'transfer-output.txt'
        os.environ['GITHUB_OUTPUT'] = str(output)
        pushed_digest = 'sha256:' + 'e' * 64
        transfer_calls = []

        def transfer_hub(path, token=None, payload=None):
            transfer_calls.append((path, token, payload))
            if path == 'auth/token':
                return {'access_token': 'synthetic-transfer-token'}
            if path == 'repositories/brspoon/keep/':
                return {'is_private': True}
            raise AssertionError('Unexpected transfer registry endpoint: ' + path)

        def docker_run(command, **kwargs):
            if command[1:3] == ['manifest', 'inspect']:
                return subprocess.CompletedProcess(command, 0,
                    stdout=json.dumps({'Descriptor': {'digest': pushed_digest}}))
            return subprocess.CompletedProcess(command, 0, stdout='')

        with chdir(self.root), \
             patch.object(registry_transfer, 'require_manual_dispatch') as manual, \
             patch.object(registry_transfer, 'require_current_source') as current, \
             patch.object(registry_transfer, 'validate_release') as validate, \
             patch.object(registry_transfer, 'require_new_tags') as new_tags, \
             patch.object(registry_transfer, 'hub', side_effect=transfer_hub), \
             patch.object(registry_transfer.subprocess, 'run', side_effect=docker_run):
            registry_transfer.execute('stage', 'amd64')

        record_path = self.root / 'transfer-amd64.json'
        record = json.loads(record_path.read_text())
        self.assertEqual(record, {
            'architecture': 'amd64', 'digest': pushed_digest, 'revision': self.REVISION,
            'run_id': '123456', 'run_attempt': '3',
        })
        self.assertEqual(output.read_text(), 'amd64=' + pushed_digest + '\n')
        manual.assert_called_once_with(True)
        current.assert_called_once_with(self.REVISION, True)
        validate.assert_called_once_with('brspoon/keep', self.VERSION, self.REVISION)
        new_tags.assert_called_once_with(
            {'images': {'amd64': 'brspoon/keep:transfer-123456-3-amd64'}, 'manifests': []},
            'brspoon/keep', 'synthetic-transfer-token')

        native_calls = []
        def native_hub(path, token=None, payload=None):
            native_calls.append((path, token, payload))
            return self.native_hub(tag_digest=pushed_digest)(path, token=token, payload=payload)

        with chdir(self.root), patch.object(materials, 'guard', return_value=self.VERSION), \
             patch.object(materials, 'hub', side_effect=native_hub), \
             patch.object(materials.subprocess, 'check_output',
                          return_value=json.dumps(self.native_image()).encode()), \
             patch.object(materials, 'registry_config', return_value='sha256:' + 'd' * 64), \
             patch.object(materials, 'archive') as archive:
            materials.archive_native('amd64')
        archive.assert_called_once_with('amd64', native_digest=pushed_digest)
        self.assertTrue(any(path.endswith('/tags/transfer-123456-3-amd64/')
                            for path, _token, _payload in native_calls))
        identity = json.loads((self.root / 'release-image-amd64.json').read_text())
        self.assertEqual(identity['native_digest'], pushed_digest)
        self.assertEqual(identity['architecture'], 'amd64')

    def test_archive_accepts_one_bound_native_digest_without_reading_other_arch_digest(self):
        self.prepare_archive_inputs()
        release_image = self.root / 'release-image-amd64.json'
        release_image.write_text(json.dumps({
            'version': self.VERSION, 'revision': self.REVISION, 'architecture': 'amd64',
            'native_digest': self.DIGEST, 'config_digest': 'sha256:' + 'd' * 64,
        }))
        release = {'id': 44, 'draft': True, 'tag_name': self.VERSION,
                   'target_commitish': self.REVISION}
        with chdir(self.root), patch.object(materials, 'guard', return_value=self.VERSION), \
             patch.object(materials, 'tested_digests', side_effect=AssertionError('read other architecture')), \
             patch.object(materials.subprocess, 'run'), patch.object(materials, 'draft', return_value=release), \
             patch.object(materials, 'upload', return_value={'name': 'asset'}):
            materials.archive('amd64', native_digest=self.DIGEST)

    def test_verify_identities_can_derive_native_identity_without_global_digest_map(self):
        rows, bodies = self.verify_fixture()
        release = {'id': 88, 'draft': True, 'tag_name': self.VERSION,
                   'target_commitish': self.REVISION}
        with chdir(self.root), patch.object(materials, 'api', return_value=rows), \
             patch.object(materials, 'asset_body', side_effect=lambda asset: bodies[asset['name']]):
            identities = materials.verify_identities(self.VERSION, release)
        self.assertEqual(set(identities), {'amd64', 'arm64'})
        self.assertEqual(identities['amd64']['native_digest'], self.DIGEST)
        self.assertEqual(identities['arm64']['native_digest'], 'sha256:' + 'c' * 64)
        self.assertEqual(identities['amd64']['run_attempt'], 3)

    def assert_readback_security_review(self, *, day, expected_error=None, source_change=False, **options):
        rows, bodies = self.verify_fixture(**options)
        original = dict(bodies)
        if source_change:
            (self.root / 'scripts/python_security_patches.json').write_bytes(b'changed source')
        held = {}
        with chdir(self.root), patch.object(materials, 'api', return_value=rows), \
             patch.object(materials, 'asset_body', side_effect=lambda asset: bodies[asset['name']]), \
             patch.object(review_image, 'current_day', return_value=day):
            if expected_error:
                with self.assertRaisesRegex(ValueError, expected_error):
                    materials.verify_identities(self.VERSION, {'id': 88}, security_reviews=held)
                self.assertEqual(held, {})
            else:
                identities = materials.verify_identities(self.VERSION, {'id': 88}, security_reviews=held)
                self.assertEqual(set(identities), set(materials.ARCHES))
                self.assertEqual(set(held), set(materials.ARCHES))
                for arch in materials.ARCHES:
                    name = f'keep-{self.VERSION}-security-evidence-{arch}.tar.gz'
                    prefix = name.removesuffix('.tar.gz') + '/'
                    with tarfile.open(fileobj=io.BytesIO(bodies[name])) as package:
                        for key, report_name in (
                            ('report', f'candidate-{arch}.json'),
                            ('scout', f'candidate-scout-{arch}.json'),
                            ('evidence', f'candidate-regression-{arch}.json'),
                            ('provenance', f'candidate-provenance-{arch}.json'),
                            ('dependencies', f'candidate-dependencies-{arch}.json'),
                        ):
                            self.assertEqual(held[arch][key], json.load(package.extractfile(prefix + report_name)))
                        # The producer's review is retained even though the current
                        # assessment is made from its original underlying reports.
                        self.assertEqual(package.extractfile(prefix + f'candidate-review-{arch}.json').read(),
                                         f'report candidate-review-{arch}.json'.encode())
        self.assertEqual(bodies, original)

    def test_readback_clean_scan_passes_after_deadline_with_empty_or_unused_exceptions(self):
        for empty in (False, True):
            with self.subTest(empty_exceptions=empty):
                self.assert_readback_security_review(day=datetime.date(2026, 10, 8), empty_exceptions=empty)

    def test_readback_needed_exception_passes_on_deadline_and_blocks_afterward(self):
        matches = [{'vulnerability': {'id': 'CVE-2026-17084', 'severity': 'Medium'},
                    'artifact': {'name': 'python-3.14', 'type': 'apk', 'version': '3.14.7-r1'}}]
        self.assert_readback_security_review(day=datetime.date(2026, 10, 7), matches=matches)
        self.assert_readback_security_review(day=datetime.date(2026, 10, 8), matches=matches,
                                            expected_error='exception_expired')

    def test_readback_unknown_or_mismatched_findings_cannot_use_original_approval(self):
        match = {'vulnerability': {'id': 'CVE-2026-17084', 'severity': 'Medium'},
                 'artifact': {'name': 'python-3.14', 'type': 'apk', 'version': '3.14.7-r1'}}
        for section, field, value, reason in (
            ('vulnerability', 'id', 'CVE-unknown', 'unmatched_finding'),
            ('vulnerability', 'severity', 'High', 'exception_mismatch'),
            ('artifact', 'name', 'other-python', 'exception_mismatch'),
            ('artifact', 'version', '3.14.8-r0', 'exception_mismatch'),
            ('artifact', 'type', 'python', 'exception_mismatch'),
        ):
            changed = copy.deepcopy(match)
            changed[section][field] = value
            with self.subTest(field=field):
                self.assert_readback_security_review(day=datetime.date(2026, 10, 7),
                                                    matches=[changed], expected_error=reason)

    def test_readback_rejects_incomplete_scans_runtime_failure_and_bad_base_provenance(self):
        for changes, message in (
            ({'candidate-amd64.json': {'ignoredMatches': [{}]}}, 'Incomplete scan report'),
            ({'candidate-scout-amd64.json': {'runs': []}}, 'Incomplete scan report'),
            ({'candidate-scout-amd64.json': {'runs': [{'results': [], 'invocations': [
                {'executionSuccessful': False}]}]}}, 'Incomplete Scout report'),
            ({'candidate-scout-amd64.json': {'runs': [{'results': [{'ruleId': 'new-finding'}]}]}},
             'blocked Scout findings'),
            ({'candidate-regression-amd64.json': {'success': False, 'failures': 1}},
             'unsuccessful security regression'),
            ({'candidate-provenance-amd64.json': {'subject': [{'digest': {'sha256': '0' * 64}}]}},
             'Base provenance does not cover'),
        ):
            with self.subTest(changes=changes):
                self.assert_readback_security_review(day=datetime.date(2026, 10, 8),
                                                    review_changes=changes, expected_error=message)

    def test_readback_rejects_changed_reviewed_source_hash(self):
        self.assert_readback_security_review(day=datetime.date(2026, 10, 8), source_change=True,
                                            expected_error='verified-fixed review must be refreshed')

    def test_readback_rechecks_original_dependency_report_before_promotion(self):
        for changes, message in (
            ({'candidate-dependencies-amd64.json': {'success': False, 'failures': 1}},
             'failed native dependency qualification'),
            ({'candidate-dependencies-arm64.json': {'expat_source_manifest_sha256': '0' * 64}},
             'source or install manifest differs'),
        ):
            with self.subTest(changes=changes):
                self.assert_readback_security_review(day=datetime.date(2026, 10, 8),
                    review_changes=changes, expected_error=message)

    def test_aggregate_emits_both_digests_only_after_asset_and_tag_checks(self):
        rows, bodies = self.verify_fixture()
        output = self.root / 'github-output.txt'
        os.environ['GITHUB_OUTPUT'] = str(output)
        release = {'id': 88, 'draft': True, 'tag_name': self.VERSION,
                   'target_commitish': self.REVISION}

        def hub(path, token=None, payload=None):
            if path == 'auth/token':
                return {'access_token': 'synthetic-hub-access-token'}
            if path == 'repositories/brspoon/keep/':
                return {'is_private': private}
            if path == 'repositories/brspoon/keep/tags/transfer-123456-3-amd64/':
                return {'digest': self.DIGEST}
            if path == 'repositories/brspoon/keep/tags/transfer-123456-3-arm64/':
                return {'digest': 'sha256:' + 'c' * 64}
            raise AssertionError('Unexpected registry endpoint: ' + path)

        for private in (False, True):
            output.unlink(missing_ok=True)
            with self.subTest(private=private), chdir(self.root), patch.object(materials, 'guard', return_value=self.VERSION), \
                 patch.object(materials, 'draft', return_value=release), \
                 patch.object(materials, 'api', return_value=rows), \
                 patch.object(materials, 'asset_body', side_effect=lambda asset: bodies[asset['name']]), \
                 patch.object(materials, 'hub', side_effect=hub) as registry:
                materials.aggregate()
            self.assertEqual(output.read_text(), 'amd64=' + self.DIGEST + '\namd64_config=sha256:' + 'd' * 64 +
                             '\narm64=sha256:' + 'c' * 64 + '\narm64_config=sha256:' + 'd' * 64 + '\n')
            registry.assert_any_call('repositories/brspoon/keep/tags/transfer-123456-3-amd64/',
                                     'synthetic-hub-access-token')
            registry.assert_any_call('repositories/brspoon/keep/tags/transfer-123456-3-arm64/',
                                     'synthetic-hub-access-token')

    def test_aggregate_rejects_wrong_run_attempt_visibility_or_tag_before_output(self):
        release = {'id': 88, 'draft': True, 'tag_name': self.VERSION,
                   'target_commitish': self.REVISION}
        output = self.root / 'github-output.txt'
        os.environ['GITHUB_OUTPUT'] = str(output)
        cases = (
            ({'identity_error': {'run_id': '999'}}, 'Durable release evidence identity differs'),
            ({'identity_error': {'run_attempt': 2}}, 'Durable release evidence identity differs'),
            ({'inventory_error': 'missing'}, 'Durable evidence inventory is incomplete'),
        )
        for options, message in cases:
            rows, bodies = self.verify_fixture(**options)
            with self.subTest(options=options), chdir(self.root), \
                 patch.object(materials, 'guard', return_value=self.VERSION), \
                 patch.object(materials, 'draft', return_value=release), \
                 patch.object(materials, 'api', return_value=rows), \
                 patch.object(materials, 'asset_body', side_effect=lambda asset: bodies[asset['name']]), \
                 patch.object(materials, 'hub') as registry:
                output.unlink(missing_ok=True)
                with self.assertRaisesRegex(ValueError, message):
                    materials.aggregate()
                registry.assert_not_called()
                self.assertFalse(output.exists())

        rows, bodies = self.verify_fixture()
        rows = [row for row in rows if 'arm64' not in row['name']]
        with chdir(self.root), patch.object(materials, 'guard', return_value=self.VERSION), \
             patch.object(materials, 'draft', return_value=release), \
             patch.object(materials, 'api', return_value=rows), \
             patch.object(materials, 'asset_body', side_effect=lambda asset: bodies[asset['name']]), \
             patch.object(materials, 'hub') as registry:
            output.unlink(missing_ok=True)
            with self.assertRaises((KeyError, ValueError)):
                materials.aggregate()
            registry.assert_not_called()
            self.assertFalse(output.exists())

        rows, bodies = self.verify_fixture()
        for private, wrong_arch in (('false', False), (None, False), (0, False), (False, True), (True, True)):
            def hub(path, token=None, payload=None):
                if path == 'auth/token':
                    return {'access_token': 'synthetic-hub-access-token'}
                if path == 'repositories/brspoon/keep/':
                    return {'is_private': private}
                if path.endswith('/tags/transfer-123456-3-arm64/') and wrong_arch:
                    return {'digest': 'sha256:' + '0' * 64}
                if path.endswith('/tags/transfer-123456-3-amd64/'):
                    return {'digest': self.DIGEST}
                if path.endswith('/tags/transfer-123456-3-arm64/'):
                    return {'digest': 'sha256:' + 'c' * 64}
                raise AssertionError(path)
            with self.subTest(private=private, wrong_arch=wrong_arch), chdir(self.root), \
                 patch.object(materials, 'guard', return_value=self.VERSION), \
                 patch.object(materials, 'draft', return_value=release), \
                 patch.object(materials, 'api', return_value=rows), \
                 patch.object(materials, 'asset_body', side_effect=lambda asset: bodies[asset['name']]), \
                 patch.object(materials, 'hub', side_effect=hub):
                output.unlink(missing_ok=True)
                with self.assertRaises(ValueError):
                    materials.aggregate()
                self.assertFalse(output.exists())

    def main_validation_fixture(self, *, prepare=True):
        import validated_build
        if prepare:
            self.prepare_archive_inputs()
        with chdir(self.root):
            records = []
            for number, name in enumerate(validated_build.input_paths('amd64')):
                path = Path(name)
                body = b'original docker save' if name.endswith('.tar') else path.read_bytes()
                records.append({'path': name, 'id': 200 + number,
                                'name': 'build-100-2-amd64--' + path.name,
                                'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest()})
        index = {'schema': validated_build.SCHEMA, 'repository': 'brspoon/keep',
                 'version': self.VERSION, 'revision': self.REVISION, 'architecture': 'amd64',
                 'config_digest': 'sha256:' + 'd' * 64,
                 'build': {'run_id': 100, 'run_attempt': 2, 'job_id': 50, 'job_name': validated_build.job_name('amd64'),
                           'workflow_id': 40},
                 'candidate': {'id': 70, 'tag_name': 'candidate-' + self.REVISION + '-100'}, 'assets': records}
        proof = {'schema': validated_build.PROVENANCE_SCHEMA, 'architecture': 'amd64', 'index': index,
                 'artifact': {'id': 500, 'name': 'validated-build-100-2-amd64', 'size_in_bytes': 400,
                              'digest': 'sha256:' + 'e' * 64, 'expired': False,
                              'workflow_run': {'id': 100, 'head_sha': self.REVISION}}}
        (self.root / 'validation-provenance-amd64.json').write_text(json.dumps(proof))
        os.environ['KEEP_VALIDATION_RUN_ID'] = '100'
        return index, proof

    def current_review_fixture(self, *, matches=None, empty_exceptions=False):
        self.prepare_archive_inputs()
        policy = self.write_reviewed_policy(empty_exceptions=empty_exceptions)
        reports = self.security_reports('amd64', policy, matches)
        for name, body in reports.items():
            (self.root / name).write_text(json.dumps(body, indent=3) + '\n')
        # Original producer bytes deliberately differ from a newly formatted review.
        original_review = {
            'accepted_fixed': [{'id': match['vulnerability']['id'],
                                'package': match['artifact']['name'],
                                'version': match['artifact']['version']}
                               for match in matches or []],
            'blocked': [], 'scout_blocked': [], 'raw_matches': len(matches or []),
            'expires': '2026-10-07',
        }
        (self.root / 'candidate-review-amd64.json').write_bytes(
            ('  ' + json.dumps(original_review, indent=3) + '\r\n').encode())
        index, _ = self.main_validation_fixture(prepare=False)
        paths = [self.root / name for name in materials.evidence_names('amd64')]
        paths += [self.root / 'portable-recovery-amd64.json',
                  self.root / 'installer-trial-amd64.json',
                  self.root / 'validation-provenance-amd64.json',
                  self.distribution / 'source-bundle-amd64.json']
        return index, {path: path.read_bytes() for path in paths}

    def current_review_runner(self, day):
        def run(command, *, check):
            self.assertEqual(command, ['python3', 'scripts/review_image.py', 'amd64', '--check-only'])
            self.assertTrue(check)
            with patch.object(review_image, 'current_day', return_value=day), redirect_stdout(io.StringIO()):
                status = review_image.main(command[2:])
            if status:
                raise subprocess.CalledProcessError(status, command)
            return subprocess.CompletedProcess(command, status)
        return run

    def assert_current_review_promotion(self, *, day, matches=None, empty_exceptions=False,
                                       blocked=False):
        import validated_build
        index, original = self.current_review_fixture(matches=matches, empty_exceptions=empty_exceptions)
        with chdir(self.root), patch.object(materials, 'guard', return_value=self.VERSION), \
             patch.object(validated_build, 'verify_provenance', return_value=index), \
             patch.object(materials.subprocess, 'run', side_effect=self.current_review_runner(day)) as review, \
             patch.object(materials, 'draft', return_value={'id': 44}) as draft, \
             patch.object(materials, 'upload') as upload:
            if blocked:
                with self.assertRaises(subprocess.CalledProcessError):
                    materials.archive('amd64', native_digest=self.DIGEST)
            else:
                materials.archive('amd64', native_digest=self.DIGEST)
        review.assert_called_once()
        for path, body in original.items():
            self.assertEqual(path.read_bytes(), body, path.name)
        if blocked:
            draft.assert_not_called()
            upload.assert_not_called()
            self.assertFalse((self.distribution / f'keep-{self.VERSION}-security-evidence-amd64.tar.gz').exists())
        else:
            draft.assert_called_once()
            self.assertEqual(upload.call_count, 4)
            security = self.distribution / f'keep-{self.VERSION}-security-evidence-amd64.tar.gz'
            with tarfile.open(security) as package:
                prefix = security.name.removesuffix('.tar.gz') + '/'
                for path, body in original.items():
                    self.assertEqual(package.extractfile(prefix + path.name).read(), body, path.name)

    def test_archive_clean_scan_with_empty_exceptions_passes_after_previous_deadline(self):
        self.assert_current_review_promotion(day=datetime.date(2026, 10, 8), empty_exceptions=True)

    def test_archive_unused_expired_exceptions_do_not_block_promotion(self):
        self.assert_current_review_promotion(day=datetime.date(2026, 10, 8))

    def test_archive_needed_exception_passes_on_review_deadline(self):
        matches = [{'vulnerability': {'id': 'CVE-2026-17084', 'severity': 'Medium'},
                    'artifact': {'name': 'python-3.14', 'type': 'apk', 'version': '3.14.7-r1'}}]
        self.assert_current_review_promotion(day=datetime.date(2026, 10, 7), matches=matches)

    def test_archive_expired_needed_exception_blocks_without_changing_original_evidence(self):
        matches = [{'vulnerability': {'id': 'CVE-2026-17084', 'severity': 'Medium'},
                    'artifact': {'name': 'python-3.14', 'type': 'apk', 'version': '3.14.7-r1'}}]
        self.assert_current_review_promotion(day=datetime.date(2026, 10, 8), matches=matches, blocked=True)

    def test_archive_retains_original_main_provenance_and_review_bytes(self):
        import validated_build
        index, proof = self.main_validation_fixture()
        review = self.root / 'candidate-review-amd64.json'
        original = review.read_bytes()
        captured = {}

        def upload(_release, path):
            path = Path(path)
            if path.name.endswith('.tar.gz') and 'security-evidence' in path.name:
                with tarfile.open(path) as package:
                    prefix = path.name.removesuffix('.tar.gz') + '/'
                    captured['identity'] = json.load(package.extractfile(prefix + 'IDENTITY.json'))
                    captured['proof'] = json.load(package.extractfile(prefix + 'validation-provenance-amd64.json'))
                    captured['review'] = package.extractfile(prefix + review.name).read()
            return {'name': path.name}

        with chdir(self.root), patch.object(materials, 'guard', return_value=self.VERSION), \
             patch.object(materials, 'draft', return_value={'id': 44}), \
             patch.object(materials, 'upload', side_effect=upload), \
             patch.object(validated_build, 'verify_provenance', return_value=index) as origin, \
             patch.object(materials.subprocess, 'run') as revalidation:
            materials.archive('amd64', native_digest=self.DIGEST)
        revalidation.assert_called_once_with(
            ['python3', 'scripts/review_image.py', 'amd64', '--check-only'], check=True)
        origin.assert_called_once_with(proof, 'amd64', 'sha256:' + 'd' * 64)
        self.assertEqual(review.read_bytes(), original)
        self.assertEqual(captured['review'], original)
        self.assertEqual(captured['proof'], proof)
        self.assertEqual(captured['identity']['run_id'], '123456')
        self.assertEqual(captured['identity']['run_attempt'], 3)
        self.assertEqual(captured['identity']['main_validation']['run_id'], 100)
        self.assertEqual(captured['identity']['main_validation']['run_attempt'], 2)

    def test_archive_blocks_missing_provenance_or_mutated_original_evidence(self):
        import validated_build
        index, _ = self.main_validation_fixture()
        (self.root / 'candidate-scout-amd64.json').write_bytes(b'changed report')
        with chdir(self.root), patch.object(materials, 'guard', return_value=self.VERSION), \
             patch.object(validated_build, 'verify_provenance', return_value=index), \
             patch.object(materials.subprocess, 'run') as review, patch.object(materials, 'upload') as upload:
            with self.assertRaisesRegex(ValueError, 'bytes changed'):
                materials.archive('amd64', native_digest=self.DIGEST)
            (self.root / 'validation-provenance-amd64.json').unlink()
            with self.assertRaisesRegex(ValueError, 'main validation provenance'):
                materials.archive('amd64', native_digest=self.DIGEST)
        review.assert_not_called()
        upload.assert_not_called()

    def test_failed_current_review_preserves_original_review_and_blocks_archival(self):
        self.prepare_archive_inputs()
        review = self.root / 'candidate-review-amd64.json'
        original = review.read_bytes()

        def blocked(*args, **kwargs):
            self.assertEqual(args[0], ['python3', 'scripts/review_image.py', 'amd64', '--check-only'])
            raise subprocess.CalledProcessError(1, args[0])

        with chdir(self.root), patch.object(materials, 'guard', return_value=self.VERSION), \
             patch.object(materials.subprocess, 'run', side_effect=blocked), patch.object(materials, 'upload') as upload:
            with self.assertRaises(subprocess.CalledProcessError):
                materials.archive('amd64', native_digest=self.DIGEST)
        self.assertEqual(review.read_bytes(), original)
        upload.assert_not_called()

    def test_durable_provenance_rejects_substituted_sources_reports_or_producer(self):
        import validated_build
        index, proof = self.main_validation_fixture()
        original_source = next(row for row in index['assets'] if row['path'].endswith('.tar.gz'))
        identity = {'version': self.VERSION, 'config_digest': index['config_digest'],
                    'source': {'name': Path(original_source['path']).name, 'sha256': original_source['sha256'],
                               'bytes': original_source['bytes']},
                    'main_validation': materials.validation_summary(proof),
                    'evidence': [{'path': Path(row['path']).name, 'sha256': row['sha256'], 'bytes': row['bytes']}
                                 for row in index['assets'] if not row['path'].endswith(('.tar', '.tar.gz', '.sha256'))]}
        with patch.object(validated_build, 'verify_provenance', return_value=index) as origin:
            materials.verify_durable_validation(identity, proof, 'amd64')
            for field in ('source', 'main_validation', 'evidence'):
                invalid = copy.deepcopy(identity)
                if field == 'source':
                    invalid[field]['sha256'] = '0' * 64
                elif field == 'main_validation':
                    invalid[field]['run_id'] = 101
                else:
                    invalid[field][0]['sha256'] = '0' * 64
                with self.subTest(field=field), self.assertRaises(ValueError):
                    materials.verify_durable_validation(invalid, proof, 'amd64')
        self.assertEqual(origin.call_count, 4)

    def test_publication_readback_cannot_accept_legacy_evidence_without_main_provenance(self):
        rows, bodies = self.verify_fixture()
        os.environ['KEEP_VALIDATION_RUN_ID'] = '100'
        with chdir(self.root), patch.object(materials, 'api', return_value=rows), \
             patch.object(materials, 'asset_body', side_effect=lambda asset: bodies[asset['name']]):
            with self.assertRaisesRegex(ValueError, 'inventory is incomplete'):
                materials.verify_identities(self.VERSION, {'id': 44})
