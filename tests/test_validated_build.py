"""Offline trust-boundary tests for reuse of successful main validation."""
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import unittest
import urllib.error
import zipfile
from contextlib import chdir
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import validated_build as builds


class FakeClock:
    def __init__(self):
        self.now = 0
        self.sleeps = []

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        assert seconds > 0
        self.sleeps.append(seconds)
        self.now += seconds


class NativeWorkflowContractTests(unittest.TestCase):
    @staticmethod
    def workflow_steps():
        path = Path(__file__).resolve().parents[1] / '.github/workflows/native-image.yml'
        workflow = path.read_text()
        matches = list(re.finditer(r'^      - name: ([^\r\n]+)\r?\n', workflow, re.M))
        return [(match.group(1), workflow[match.end():matches[index + 1].start()
                 if index + 1 < len(matches) else len(workflow)])
                for index, match in enumerate(matches)]

    def test_real_native_workflow_supplies_each_required_evidence_gate_once(self):
        names = [name for name, _ in self.workflow_steps()]
        required = (*builds.NATIVE_STEPS, builds.RETAIN_STEP, builds.INDEX_STEP)
        self.assertEqual(len(required), len(set(required)))
        for name in required:
            with self.subTest(name=name):
                self.assertEqual(names.count(name), 1,
                                 'The native workflow must emit this exact evidence gate once')

    def test_dependency_evidence_gate_still_runs_the_complete_runtime_probe(self):
        name = 'Verify default Expat and OpenSSL library loading'
        blocks = [block for step, block in self.workflow_steps() if step == name]
        self.assertEqual(len(blocks), 1)
        self.assertEqual(re.findall(r'^        run: ([^\r\n]+)$', blocks[0], re.M), [
            'docker run --rm --network none --read-only '
            '--tmpfs /tmp:rw,noexec,nosuid,size=64m -v "$PWD/scripts:/checks:ro" '
            'keep-ci python -B /checks/runtime_dependency_checks.py --report '
            '> candidate-dependencies-${{ matrix.arch }}.json'])
        self.assertNotRegex(blocks[0], r'(?m)^        (?:if|continue-on-error):')


class ValidatedBuildTests(unittest.TestCase):
    def legacy_index(self, arch='amd64'):
        index = self.indexes[arch]
        index['schema'] = builds.LEGACY_SCHEMA
        proof = {'schema': 'keep.maintenance-native-trial.v1', 'outcome': 'passed',
                 'architecture': arch, 'candidate': {'version': index['version'], 'revision': index['revision'],
                 'architecture': arch, 'os': 'linux', 'image_id': index['config_digest']}}
        body = (json.dumps(proof, indent=3) + '\r\n').encode()
        asset_id = 9999
        path = f'maintenance-native-{arch}.json'
        name = f"build-100-{index['build']['run_attempt']}-{arch}--" + path
        row = {'path': path, 'id': asset_id, 'name': name, 'bytes': len(body),
               'sha256': hashlib.sha256(body).hexdigest()}
        index['assets'].append(row)
        self.assets.append({'id': asset_id, 'name': name, 'size': len(body), 'digest': 'sha256:' + row['sha256']})
        self.blobs[f'/releases/assets/{asset_id}'] = body
        for step in builds.LEGACY_NATIVE_STEPS:
            if not any(row['name'] == step for row in self.native[arch]['steps']):
                self.native[arch]['steps'].append({'name': step, 'status': 'completed', 'conclusion': 'success'})
        archive = self.zip_bytes({'index.json': json.dumps(index).encode()})
        self.artifacts[0].update(size_in_bytes=len(archive), digest='sha256:' + hashlib.sha256(archive).hexdigest())
        self.blobs['/actions/artifacts/500/zip'] = archive
        return body

    def test_future_index_requires_new_layout_without_helper_evidence(self):
        self.assertEqual(builds.SCHEMA, 'keep.validated-native-build.v2')
        self.assertNotIn('maintenance-native-amd64.json', builds.input_paths('amd64'))
        self.assertTrue(set(builds.NATIVE_STEPS) < set(builds.LEGACY_NATIVE_STEPS))
        with patch.object(builds, 'api', side_effect=self.api):
            builds.validate_index(self.indexes['amd64'], self.run, 11, self.artifacts[0], 'amd64')

    def test_legacy_index_retains_exact_inventory_and_original_extra_native_gates(self):
        self.legacy_index()
        with patch.object(builds, 'api', side_effect=self.api):
            builds.validate_index(self.indexes['amd64'], self.run, 11, self.artifacts[0], 'amd64')
            name = next(step for step in builds.LEGACY_NATIVE_STEPS if step not in builds.NATIVE_STEPS)
            next(step for step in self.native['amd64']['steps'] if step['name'] == name)['conclusion'] = 'skipped'
            with self.assertRaisesRegex(ValueError, 'Native validation gate'):
                builds.validate_index(self.indexes['amd64'], self.run, 11, self.artifacts[0], 'amd64')

    def test_legacy_inventory_is_readable_but_cannot_qualify_current_publication(self):
        original = self.legacy_index()
        with patch.object(builds, 'api', side_effect=self.api), patch.object(builds, 'download', side_effect=self.download), \
             patch.object(builds.subprocess, 'run') as docker:
            builds.validate_index(self.indexes['amd64'], self.run, 11, self.artifacts[0], 'amd64')
            with self.assertRaisesRegex(ValueError, 'v2 validation evidence layout'):
                builds.restore('amd64')
            with self.assertRaisesRegex(ValueError, 'v2 validation evidence layout'):
                builds.check()
        self.assertEqual(self.blobs['/releases/assets/9999'], original)
        docker.assert_not_called()
        self.assertFalse(Path('validation-provenance-amd64.json').exists())

    def test_explicit_historical_provenance_rechecks_original_v1_index_and_native_gates(self):
        self.legacy_index()
        proof = builds.provenance('amd64', self.indexes['amd64'], self.artifacts[0])
        original = copy.deepcopy(proof)
        with patch.object(builds, 'api', side_effect=self.api), patch.object(builds, 'download', side_effect=self.download):
            with self.assertRaisesRegex(ValueError, 'v2 validation evidence layout'):
                builds.verify_provenance(proof, 'amd64', self.indexes['amd64']['config_digest'])
            index = builds.verify_provenance(proof, 'amd64', self.indexes['amd64']['config_digest'], allow_legacy=True)
        self.assertEqual(index, self.indexes['amd64'])
        self.assertEqual(proof, original)

    def test_all_remaining_native_gates_are_required_for_new_indexes(self):
        for name in (*builds.NATIVE_STEPS, builds.RETAIN_STEP, builds.INDEX_STEP):
            job = copy.deepcopy(self.native['amd64'])
            next(step for step in job['steps'] if step['name'] == name)['conclusion'] = 'skipped'
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'Native validation gate'):
                builds.job_success(job, native=True)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        (self.root / 'VERSION').write_text('2.21.4\n')
        self.directory = chdir(self.root)
        self.directory.__enter__()
        self.addCleanup(self.directory.__exit__, None, None, None)
        self.env = patch.dict(os.environ, {
            'GITHUB_REPOSITORY': 'brspoon/keep', 'GITHUB_SHA': 'a' * 40,
            'GITHUB_TOKEN': 'fake-token', 'GITHUB_REF': 'refs/heads/main',
            'GITHUB_EVENT_NAME': 'workflow_dispatch', 'GITHUB_RUN_ID': '900',
            'GITHUB_RUN_ATTEMPT': '1', 'KEEP_VALIDATION_RUN_ID': '100',
            'KEEP_RELEASE_PUBLISH': 'true', 'KEEP_RELEASE_CONFIRMATION': 'release-stable'}, clear=True)
        self.env.start()
        self.addCleanup(self.env.stop)
        self.run = {'id': 100, 'workflow_id': 40, 'path': builds.WORKFLOW,
                    'event': 'push', 'head_branch': 'main', 'head_sha': 'a' * 40,
                    'run_attempt': 3, 'status': 'completed', 'conclusion': 'success',
                    'repository': {'id': 11, 'full_name': builds.REPOSITORY},
                    'head_repository': {'id': 11, 'full_name': builds.REPOSITORY}}
        self.release = {'id': 70, 'draft': True, 'tag_name': builds.candidate_tag(100),
                        'target_commitish': 'a' * 40}
        self.native = {arch: self.native_job(arch, 3 if arch == 'amd64' else 1)
                       for arch in builds.ARCHES}
        self.latest_jobs = [{'id': 20 + number, 'name': name, 'status': 'completed', 'conclusion': 'success',
                             'run_id': 100, 'run_attempt': 1, 'head_sha': 'a' * 40}
                            for number, name in enumerate(('prepare-candidate', 'installer-windows',
                                                          'contributor-tests', 'required-checks'))]
        self.latest_jobs.extend(self.native.values())
        self.indexes, self.artifacts, self.blobs, self.assets = {}, [], {}, []
        for number, arch in enumerate(builds.ARCHES):
            attempt = self.native[arch]['run_attempt']
            records = []
            for offset, name in enumerate(builds.input_paths(arch)):
                body = ('original bytes of ' + name).encode()
                asset_id = 1000 + number * 100 + offset
                asset_name = f'build-100-{attempt}-{arch}--' + Path(name).name
                record = {'path': name, 'id': asset_id, 'name': asset_name, 'bytes': len(body),
                          'sha256': hashlib.sha256(body).hexdigest()}
                records.append(record)
                self.assets.append({'id': asset_id, 'name': asset_name, 'size': len(body),
                                    'digest': 'sha256:' + record['sha256']})
                self.blobs[f'/releases/assets/{asset_id}'] = body
            index = {'schema': builds.SCHEMA, 'repository': builds.REPOSITORY,
                     'version': '2.21.4', 'revision': 'a' * 40, 'architecture': arch,
                     'config_digest': 'sha256:' + ('b' if arch == 'amd64' else 'c') * 64,
                     'build': {'run_id': 100, 'run_attempt': attempt, 'job_id': self.native[arch]['id'],
                               'job_name': builds.job_name(arch), 'workflow_id': 40},
                     'candidate': {'id': 70, 'tag_name': self.release['tag_name']}, 'assets': records}
            self.indexes[arch] = index
            archive = self.zip_bytes({'index.json': json.dumps(index).encode()})
            artifact_id = 500 + number
            artifact = {'id': artifact_id, 'name': builds.artifact_name(100, attempt, arch),
                        'expired': False, 'size_in_bytes': len(archive),
                        'digest': 'sha256:' + hashlib.sha256(archive).hexdigest(),
                        'workflow_run': {'id': 100, 'repository_id': 11, 'head_repository_id': 11,
                                         'head_branch': 'main', 'head_sha': 'a' * 40}}
            self.artifacts.append(artifact)
            self.blobs[f'/actions/artifacts/{artifact_id}/zip'] = archive

    def native_job(self, arch, attempt):
        return {'id': 30 if arch == 'amd64' else 31, 'run_id': 100, 'run_attempt': attempt,
                'name': builds.job_name(arch), 'head_sha': 'a' * 40,
                'status': 'completed', 'conclusion': 'success',
                'steps': [{'name': name, 'status': 'completed', 'conclusion': 'success'}
                          for name in (*builds.NATIVE_STEPS, builds.RETAIN_STEP, builds.INDEX_STEP)]}

    @staticmethod
    def zip_bytes(entries):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, 'w') as package:
            for name, body in entries.items():
                package.writestr(name, body)
        return stream.getvalue()

    def api(self, path, **kwargs):
        route = path.partition('?')[0]
        if path == '':
            return {'id': 11, 'full_name': builds.REPOSITORY, 'private': False}
        if route == '/actions/workflows/image.yml':
            return {'id': 40, 'path': builds.WORKFLOW}
        if route == '/git/ref/heads/main':
            return {'object': {'sha': 'a' * 40}}
        if route == '/actions/runs/100':
            return self.run
        if route == '/actions/runs/100/jobs':
            return {'jobs': self.latest_jobs}
        if route.startswith('/actions/runs/100/attempts/'):
            attempt = int(route.split('/')[5])
            return {'jobs': [job for job in self.native.values() if job['run_attempt'] == attempt]}
        if route.startswith('/actions/jobs/'):
            job_id = int(route.split('/')[3])
            return next(job for job in self.native.values() if job['id'] == job_id)
        if route == '/actions/runs/100/artifacts':
            return {'artifacts': self.artifacts}
        if route.startswith('/actions/artifacts/'):
            artifact_id = int(route.split('/')[3])
            return next(row for row in self.artifacts if row['id'] == artifact_id)
        if route == '/releases':
            return [self.release]
        if route == '/releases/70/assets':
            return self.assets
        raise AssertionError('Unexpected provider request: ' + path)

    def download(self, path, target, size, digest, **kwargs):
        body = self.blobs[path]
        self.assertEqual(size, len(body))
        self.assertEqual(digest, 'sha256:' + hashlib.sha256(body).hexdigest())
        Path(target).write_bytes(body)

    def test_check_accepts_failed_job_rerun_with_older_successful_arm64(self):
        with patch.object(builds, 'api', side_effect=self.api) as provider, \
             patch.object(builds, 'download', side_effect=self.download) as download, \
             patch.object(builds.subprocess, 'run') as docker:
            builds.check()
        self.assertEqual(download.call_count, 2)
        self.assertTrue(all(call.args[0].startswith('/actions/artifacts/') for call in download.call_args_list))
        self.assertTrue(all(call.kwargs.get('method', 'GET') == 'GET' for call in provider.call_args_list))
        docker.assert_not_called()

    def test_origin_rejects_untrusted_or_incomplete_run(self):
        changes = [{'event': 'pull_request'}, {'event': 'workflow_dispatch'}, {'head_branch': 'feature'},
                   {'head_sha': 'd' * 40}, {'path': '.github/workflows/other.yml'}, {'workflow_id': 41},
                   {'head_repository': {'id': 12, 'full_name': 'attacker/keep'}},
                   {'repository': {'id': 12, 'full_name': 'attacker/keep'}},
                   {'status': 'in_progress'}, {'conclusion': 'failure'}, {'conclusion': 'cancelled'}]
        original = copy.deepcopy(self.run)
        for change in changes:
            self.run = {**original, **change}
            with self.subTest(change=change), patch.object(builds, 'api', side_effect=self.api):
                with self.assertRaises(ValueError):
                    builds.check()

    def test_requires_explicit_successful_selected_run_and_current_main(self):
        with patch.object(builds, 'api', side_effect=self.api):
            os.environ.pop('KEEP_VALIDATION_RUN_ID')
            with self.assertRaises(ValueError):
                builds.check()
        os.environ['KEEP_VALIDATION_RUN_ID'] = '100'
        with patch.object(builds, 'api', side_effect=lambda path, **kw:
                          {'object': {'sha': 'e' * 40}} if path == '/git/ref/heads/main' else self.api(path, **kw)):
            with self.assertRaisesRegex(ValueError, 'current main'):
                builds.check()

    def test_required_jobs_cannot_be_missing_skipped_or_failed(self):
        original = copy.deepcopy(self.latest_jobs)
        for name in ('prepare-candidate', 'installer-windows', 'contributor-tests', 'required-checks', builds.job_name('arm64')):
            for result in ('skipped', 'failure', 'missing'):
                self.latest_jobs = copy.deepcopy(original)
                row = next(job for job in self.latest_jobs if job['name'] == name)
                if result == 'missing':
                    self.latest_jobs.remove(row)
                else:
                    row['conclusion'] = result
                with self.subTest(name=name, result=result), patch.object(builds, 'api', side_effect=self.api):
                    with self.assertRaises(ValueError):
                        builds.check()

    def test_native_job_success_cannot_hide_failed_or_skipped_critical_steps(self):
        job = copy.deepcopy(self.native['amd64'])
        for name in (builds.NATIVE_STEPS[1], builds.RETAIN_STEP, builds.INDEX_STEP):
            for result in ('failure', 'skipped', None):
                for step in job['steps']:
                    step['conclusion'] = 'success'
                next(step for step in job['steps'] if step['name'] == name)['conclusion'] = result
                with self.subTest(name=name, result=result), self.assertRaises(ValueError):
                    builds.job_success(job, native=True)


    def test_artifact_rejects_expiry_wrong_origin_digest_size_and_duplicates(self):
        changes = [{'expired': True}, {'digest': ''}, {'size_in_bytes': builds.ZIP_LIMIT + 1},
                   {'workflow_run': {**self.artifacts[0]['workflow_run'], 'id': 101}},
                   {'workflow_run': {**self.artifacts[0]['workflow_run'], 'head_repository_id': 12}},
                   {'workflow_run': {**self.artifacts[0]['workflow_run'], 'head_sha': 'd' * 40}}]
        for change in changes:
            invalid = {**self.artifacts[0], **change}
            with self.subTest(change=change), self.assertRaises(ValueError):
                builds.select_artifact([invalid], self.run, 11, 'amd64')
        with self.assertRaisesRegex(ValueError, 'Duplicate'):
            builds.select_artifact([self.artifacts[0], self.artifacts[0]], self.run, 11, 'amd64')
        with self.assertRaisesRegex(ValueError, 'explicit main validation'):
            builds.select_artifact([], self.run, 11, 'amd64')

    def test_validate_index_rejects_cross_run_attempt_job_config_and_inventory(self):
        index = self.indexes['amd64']
        changes = [{'revision': 'd' * 40}, {'config_digest': 'bad'}, {'architecture': 'arm64'},
                   {'build': {**index['build'], 'run_id': 101}},
                   {'build': {**index['build'], 'run_attempt': 2}},
                   {'build': {**index['build'], 'job_id': 99}},
                   {'candidate': {'id': 71, 'tag_name': self.release['tag_name']}},
                   {'assets': index['assets'][:-1]}, {'assets': [*index['assets'][:-1], index['assets'][0]]}]
        with patch.object(builds, 'api', side_effect=self.api):
            for change in changes:
                with self.subTest(change=change), self.assertRaises(ValueError):
                    builds.validate_index({**index, **change}, self.run, 11, self.artifacts[0], 'amd64')
            self.assertEqual(builds.validate_index(index, self.run, 11, self.artifacts[0], 'amd64'), index)

    def test_validate_index_rejects_changed_bulk_metadata_and_published_candidate(self):
        with patch.object(builds, 'api', side_effect=self.api):
            self.assets[0]['digest'] = 'sha256:' + 'e' * 64
            with self.assertRaisesRegex(ValueError, 'immutable index'):
                builds.validate_index(self.indexes['amd64'], self.run, 11, self.artifacts[0], 'amd64')
            self.release['draft'] = False
            with self.assertRaisesRegex(ValueError, 'unpublished draft'):
                builds.candidate(100)

    def test_index_zip_rejects_paths_extras_symlinks_and_oversize(self):
        archives = [self.zip_bytes({'../index.json': b'{}'}), self.zip_bytes({'index.json': b'{}', 'extra': b'a'}),
                    self.zip_bytes({'index.json': b'x' * (builds.INDEX_LIMIT + 1)})]
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, 'w') as package:
            info = zipfile.ZipInfo('index.json')
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            package.writestr(info, 'elsewhere')
        archives.append(stream.getvalue())
        for body in archives:
            artifact = {**self.artifacts[0], 'size_in_bytes': len(body),
                        'digest': 'sha256:' + hashlib.sha256(body).hexdigest()}
            with self.subTest(size=len(body)), patch.object(builds, 'download', side_effect=lambda path, target, *a, **kw:
                                                    Path(target).write_bytes(body)):
                with self.assertRaises(ValueError):
                    builds.read_index(artifact)

    def test_binary_download_negotiates_endpoint_media_type(self):
        opener, response = MagicMock(), MagicMock()
        opener.open.return_value = response
        with patch.object(builds.urllib.request, 'build_opener', return_value=opener):
            for artifact, path, media_type in (
                    (True, '/actions/artifacts/500/zip', 'application/vnd.github+json'),
                    (False, '/releases/assets/1', 'application/octet-stream')):
                with self.subTest(artifact=artifact):
                    self.assertIs(builds.binary_response(path, artifact=artifact), response)
                    request = opener.open.call_args.args[0]
                    self.assertEqual(request.get_header('Accept'), media_type)
                    self.assertEqual(request.get_header('X-github-api-version'), '2022-11-28')

    def test_binary_download_reports_api_errors_without_redirect_or_secret_details(self):
        opener = MagicMock()
        with patch.object(builds.urllib.request, 'build_opener', return_value=opener):
            for status in (403, 410, 415):
                opener.open.reset_mock()
                opener.open.side_effect = urllib.error.HTTPError(
                    'https://api.github.com/example?sig=secret', status, 'secret body',
                    {'Location': 'https://attacker.example/x?sig=secret'}, None)
                with self.subTest(status=status), self.assertRaisesRegex(
                        ValueError, rf'^GitHub binary download request failed \(HTTP {status}\)$'):
                    builds.binary_response('/actions/artifacts/500/zip', artifact=True)
                self.assertEqual(opener.open.call_count, 1)

    def test_binary_redirect_drops_auth_and_rejects_non_github_signed_hosts(self):
        response = MagicMock()
        opener = MagicMock()
        valid = ('https://release-assets.githubusercontent.com/example?sig=secret',
                 'https://productionresultssa1.blob.core.windows.net/example?sig=secret')
        with patch.object(builds.urllib.request, 'build_opener', return_value=opener):
            for url in valid:
                error = urllib.error.HTTPError('unused', 302, '', {'Location': url}, None)
                opener.open.side_effect = [error, response]
                self.assertIs(builds.binary_response('/actions/artifacts/500/zip', artifact=True), response)
                request = opener.open.call_args_list[-1].args[0]
                self.assertNotIn('Authorization', request.headers)
            for url in ('http://release-assets.githubusercontent.com/x', 'https://attacker.example/x',
                        'https://release-assets.githubusercontent.com.attacker.example/x',
                        'https://release-assets.githubusercontent.com:443/x',
                        'https://user@release-assets.githubusercontent.com/x',
                        'https://productionresultssa1.blob.core.windows.net/x#fragment'):
                opener.open.side_effect = urllib.error.HTTPError('unused', 302, '', {'Location': url}, None)
                with self.subTest(url=url), self.assertRaises(ValueError):
                    builds.binary_response('/actions/artifacts/500/zip', artifact=True)

    def test_download_checks_hash_length_bounds_and_removes_partial_file(self):
        target = self.root / 'download'
        for body, size, digest in [(b'original', 8, 'sha256:' + 'd' * 64),
                                   (b'too long', 3, 'sha256:' + 'd' * 64),
                                   (b'short', 9, 'sha256:' + 'd' * 64)]:
            with patch.object(builds, 'binary_response', return_value=io.BytesIO(body)), self.assertRaises(ValueError):
                builds.download('/releases/assets/1', target, size, digest)
            self.assertFalse(target.exists())
        with patch.object(builds, 'binary_response', return_value=io.BytesIO(b'original')):
            builds.download('/releases/assets/1', target, 8, 'sha256:' + hashlib.sha256(b'original').hexdigest())
        self.assertEqual(target.read_bytes(), b'original')

    def test_restore_preserves_original_report_bytes_and_config_without_build(self):
        with patch.object(builds, 'api', side_effect=self.api), \
             patch.object(builds, 'download', side_effect=self.download), \
             patch.object(builds.materials, 'bundle'), patch.object(builds.materials, 'portable_evidence'), \
             patch.object(builds.materials, 'installer_evidence'), patch.object(builds, 'inspect_image') as inspect, \
             patch.object(builds.subprocess, 'run') as docker:
            builds.restore('amd64')
        for row in self.indexes['amd64']['assets']:
            if not row['path'].endswith('.tar'):
                self.assertEqual(Path(row['path']).read_bytes(), self.blobs[f"/releases/assets/{row['id']}"])
        docker.assert_called_once()
        self.assertEqual(docker.call_args.args[0][:3], ['docker', 'image', 'load'])
        inspect.assert_called_once_with('amd64', self.indexes['amd64']['config_digest'])
        proof = json.loads(Path('validation-provenance-amd64.json').read_text())
        self.assertEqual(proof['index'], self.indexes['amd64'])
        self.assertEqual(proof['artifact'], self.artifacts[0])
        self.assertEqual(proof['index']['build']['run_id'], 100)
        self.assertNotEqual(proof['index']['build']['run_id'], int(os.environ['GITHUB_RUN_ID']))

    def test_failed_restore_has_no_build_or_scan_fallback(self):
        self.assets[0]['size'] += 1
        with patch.object(builds, 'api', side_effect=self.api), patch.object(builds, 'download', side_effect=self.download), \
             patch.object(builds.subprocess, 'run') as docker:
            with self.assertRaises(ValueError):
                builds.restore('amd64')
        docker.assert_not_called()
        self.assertFalse(Path('validation-provenance-amd64.json').exists())


    def test_durable_provenance_rechecks_origin_artifact_and_index(self):
        proof = builds.provenance('amd64', self.indexes['amd64'], self.artifacts[0])
        with patch.object(builds, 'api', side_effect=self.api), patch.object(builds, 'download', side_effect=self.download):
            self.assertEqual(builds.verify_provenance(proof, 'amd64', self.indexes['amd64']['config_digest']),
                             self.indexes['amd64'])
            self.run['conclusion'] = 'failure'
            with self.assertRaises(ValueError):
                builds.verify_provenance(proof, 'amd64', self.indexes['amd64']['config_digest'])

    def test_push_retention_allows_newer_main_but_not_pr_or_wrong_attempt(self):
        os.environ.update(GITHUB_EVENT_NAME='push', GITHUB_RUN_ID='100', GITHUB_RUN_ATTEMPT='3')
        self.run.update(status='in_progress', conclusion=None)
        with patch.object(builds, 'api', side_effect=self.api) as provider:
            builds.push_guard()
            self.assertNotIn('/git/ref/heads/main', [call.args[0] for call in provider.call_args_list])
            os.environ['GITHUB_RUN_ATTEMPT'] = '2'
            with self.assertRaises(ValueError):
                builds.push_guard()
            os.environ['GITHUB_EVENT_NAME'] = 'pull_request'
            with self.assertRaises(ValueError):
                builds.prepare()

    def test_upload_reuses_identical_asset_and_never_overwrites_changed_asset(self):
        path = self.root / 'report.json'
        path.write_bytes(b'original')
        row = {'id': 1, 'name': 'build-100-3-amd64--report.json', 'size': 8,
               'digest': 'sha256:' + hashlib.sha256(b'original').hexdigest()}
        with patch.object(builds, 'pages', return_value=[row]), patch.object(builds.http.client, 'HTTPSConnection') as upload:
            self.assertEqual(builds.upload(self.release, path, row['name']), row)
            row['size'] = 7
            with self.assertRaisesRegex(ValueError, 'refusing overwrite'):
                builds.upload(self.release, path, row['name'])
        upload.assert_not_called()

    def test_repository_api_allows_empty_root_and_limits_metadata(self):
        opener = MagicMock()
        response = MagicMock()
        response.__enter__.return_value = response
        response.read.return_value = b'{"id":11}'
        opener.open.return_value = response
        with patch.object(builds.urllib.request, 'build_opener', return_value=opener):
            self.assertEqual(builds.api(''), {'id': 11})
            self.assertEqual(opener.open.call_args.args[0].full_url, 'https://api.github.com/repos/brspoon/keep')
            response.read.return_value = b'a' * (builds.JSON_LIMIT + 1)
            with self.assertRaises(ValueError):
                builds.api('')

    def test_paginated_lists_do_not_omit_later_run_artifacts(self):
        with patch.object(builds, 'api', side_effect=[{'artifacts': [{'id': n} for n in range(100)]},
                                                     {'artifacts': [{'id': 100}]}]) as provider:
            rows = builds.pages('/actions/runs/100/artifacts', 'artifacts')
        self.assertEqual(len(rows), 101)
        self.assertEqual(provider.call_args_list[1].args[0], '/actions/runs/100/artifacts?per_page=100&page=2')

    def test_latest_job_uses_all_attempts_without_superseded_success_fallback(self):
        old = self.native_job('amd64', 1)
        old['id'] = 29
        self.latest_jobs.append(old)
        with patch.object(builds, 'api', side_effect=self.api) as provider, \
             patch.object(builds, 'download', side_effect=self.download):
            builds.check()
        self.assertTrue(any('?filter=all&' in call.args[0] for call in provider.call_args_list))
        self.native['amd64']['conclusion'] = 'failure'
        with patch.object(builds, 'api', side_effect=self.api), self.assertRaises(ValueError):
            builds.check()

    def test_old_successful_artifact_cannot_replace_missing_newest_native_index(self):
        old = self.native_job('amd64', 1)
        old['id'] = 29
        self.latest_jobs.append(old)
        artifact = copy.deepcopy(self.artifacts[0])
        artifact['name'] = builds.artifact_name(100, 1, 'amd64')
        index = copy.deepcopy(self.indexes['amd64'])
        index['build'].update(run_attempt=1, job_id=29)
        with patch.object(builds, 'api', side_effect=self.api), \
             patch.object(builds, 'native_job', return_value=old):
            with self.assertRaisesRegex(ValueError, 'latest native validation job'):
                builds.validate_index(index, self.run, 11, artifact, 'amd64')

    def test_expired_older_index_does_not_block_new_valid_index(self):
        old = copy.deepcopy(self.artifacts[0])
        old.update(id=499, name=builds.artifact_name(100, 1, 'amd64'), expired=True)
        attempt, selected = builds.select_artifact([old, self.artifacts[0]], self.run, 11, 'amd64')
        self.assertEqual(attempt, 3)
        self.assertEqual(selected['id'], 500)

    def retention_jobs(self):
        ready = copy.deepcopy(self.native['amd64'])
        ready.update(status='in_progress', conclusion=None)
        pending = copy.deepcopy(ready)
        pending['steps'][0].update(status='in_progress', conclusion=None)
        return pending, ready

    def test_retention_ready_metadata_returns_without_sleep(self):
        _, ready = self.retention_jobs()
        clock = FakeClock()

        def provider(path, **options):
            return {'jobs': [ready]} if '/attempts/' in path else ready

        with patch.object(builds, 'api', side_effect=provider) as requests, \
             patch.object(builds.time, 'monotonic', side_effect=clock.monotonic), \
             patch.object(builds.time, 'sleep', side_effect=clock.sleep):
            self.assertEqual(builds.native_job(self.run, 'amd64', 3, completed=False), ready)
        self.assertEqual(clock.sleeps, [])
        self.assertEqual(clock.now, 0)
        self.assertEqual(requests.call_count, 2)

    def test_retention_waits_past_the_old_ten_seconds_for_the_pinned_job(self):
        pending, ready = self.retention_jobs()
        clock = FakeClock()
        requests = []

        def provider(path, **options):
            requests.append((path, options['metadata_deadline']))
            if '/attempts/' in path:
                return {'jobs': [pending]}
            self.assertEqual(path, '/actions/jobs/30')
            return ready if clock.now >= 75 else pending

        with patch.object(builds, 'api', side_effect=provider), \
             patch.object(builds.time, 'monotonic', side_effect=clock.monotonic), \
             patch.object(builds.time, 'sleep', side_effect=clock.sleep):
            self.assertEqual(builds.native_job(self.run, 'amd64', 3, completed=False), ready)
        self.assertEqual(clock.sleeps, [15] * 5)
        self.assertEqual(len(requests), 7)
        self.assertTrue(all(deadline == 1800 for _, deadline in requests))
        self.assertEqual(sum('/attempts/' in path for path, _ in requests), 1)

    def test_retention_queries_canonical_job_even_when_attempt_list_says_ready(self):
        pending, ready = self.retention_jobs()
        clock = FakeClock()

        def provider(path, **options):
            if '/attempts/' in path:
                return {'jobs': [ready]}
            return ready if clock.now >= 15 else pending

        with patch.object(builds, 'api', side_effect=provider) as requests, \
             patch.object(builds.time, 'monotonic', side_effect=clock.monotonic), \
             patch.object(builds.time, 'sleep', side_effect=clock.sleep):
            self.assertEqual(builds.native_job(self.run, 'amd64', 3, completed=False), ready)
        self.assertEqual(clock.sleeps, [15])
        self.assertEqual([c.args[0] for c in requests.call_args_list][1:],
                         ['/actions/jobs/30', '/actions/jobs/30'])

    def test_retention_stops_at_monotonic_deadline_without_an_extra_request(self):
        pending, _ = self.retention_jobs()
        clock = FakeClock()

        def provider(path, **options):
            return {'jobs': [pending]} if '/attempts/' in path else pending

        with patch.object(builds, 'api', side_effect=provider) as requests, \
             patch.object(builds.time, 'monotonic', side_effect=clock.monotonic), \
             patch.object(builds.time, 'sleep', side_effect=clock.sleep), \
             self.assertRaisesRegex(ValueError, 'metadata did not settle before deadline'):
            builds.native_job(self.run, 'amd64', 3, completed=False)
        self.assertEqual(clock.now, 1800)
        self.assertEqual(clock.sleeps, [15] * 120)
        self.assertEqual(requests.call_count, 121)

    def test_retention_honors_longer_provider_interval_inside_deadline(self):
        pending, ready = self.retention_jobs()
        clock = FakeClock()

        def provider(path, **options):
            options['poll_intervals'].append(45)
            return {'jobs': [pending]} if '/attempts/' in path else (ready if clock.now >= 45 else pending)

        with patch.object(builds, 'api', side_effect=provider), \
             patch.object(builds.time, 'monotonic', side_effect=clock.monotonic), \
             patch.object(builds.time, 'sleep', side_effect=clock.sleep):
            self.assertEqual(builds.native_job(self.run, 'amd64', 3, completed=False), ready)
        self.assertEqual(clock.sleeps, [45])

    def test_retention_provider_interval_cannot_extend_deadline(self):
        pending, _ = self.retention_jobs()
        clock = FakeClock()

        def provider(path, **options):
            options['poll_intervals'].append(2700)
            return {'jobs': [pending]} if '/attempts/' in path else pending

        with patch.object(builds, 'api', side_effect=provider) as requests, \
             patch.object(builds.time, 'monotonic', side_effect=clock.monotonic), \
             patch.object(builds.time, 'sleep', side_effect=clock.sleep), \
             self.assertRaisesRegex(ValueError, 'deadline'):
            builds.native_job(self.run, 'amd64', 3, completed=False)
        self.assertEqual(clock.sleeps, [1800])
        self.assertEqual(clock.now, 1800)
        self.assertEqual(requests.call_count, 2)

    def test_retention_rejects_success_arriving_at_deadline(self):
        pending, ready = self.retention_jobs()
        clock = FakeClock()

        def provider(path, **options):
            if '/attempts/' in path:
                return {'jobs': [pending]}
            clock.now = 1800
            return ready

        with patch.object(builds, 'api', side_effect=provider), \
             patch.object(builds.time, 'monotonic', side_effect=clock.monotonic), \
             patch.object(builds.time, 'sleep', side_effect=clock.sleep), \
             self.assertRaisesRegex(ValueError, 'deadline'):
            builds.native_job(self.run, 'amd64', 3, completed=False)
        self.assertEqual(clock.sleeps, [])

    def test_retention_request_time_reduces_the_remaining_retry_window(self):
        pending, _ = self.retention_jobs()
        clock = FakeClock()

        def provider(path, **options):
            if '/attempts/' in path:
                clock.now += 600
                return {'jobs': [pending]}
            clock.now += 1195
            return pending

        with patch.object(builds, 'api', side_effect=provider) as requests, \
             patch.object(builds.time, 'monotonic', side_effect=clock.monotonic), \
             patch.object(builds.time, 'sleep', side_effect=clock.sleep), \
             self.assertRaisesRegex(ValueError, 'deadline'):
            builds.native_job(self.run, 'amd64', 3, completed=False)
        self.assertEqual(clock.sleeps, [5])
        self.assertEqual(clock.now, 1800)
        self.assertEqual(requests.call_count, 2)

    def test_retention_failed_or_skipped_gate_is_terminal_on_every_poll(self):
        for conclusion in ('failure', 'skipped', 'cancelled', 'timed_out', 'neutral', 'action_required'):
            with self.subTest(conclusion=conclusion):
                pending, ready = self.retention_jobs()
                failed = copy.deepcopy(ready)
                failed['steps'][0].update(conclusion=conclusion)
                clock = FakeClock()

                def provider(path, **options):
                    if '/attempts/' in path:
                        return {'jobs': [pending]}
                    return failed if clock.now >= 15 else pending

                with patch.object(builds, 'api', side_effect=provider) as requests, \
                     patch.object(builds.time, 'monotonic', side_effect=clock.monotonic), \
                     patch.object(builds.time, 'sleep', side_effect=clock.sleep), \
                     self.assertRaisesRegex(ValueError, 'failed or was skipped'):
                    builds.native_job(self.run, 'amd64', 3, completed=False)
                self.assertEqual(clock.sleeps, [15])
                self.assertEqual(requests.call_count, 3)

    def test_retention_rejects_failed_attempt_list_before_canonical_lookup(self):
        pending, _ = self.retention_jobs()
        pending['steps'][0].update(status='completed', conclusion='failure')
        with patch.object(builds, 'api', return_value={'jobs': [pending]}) as requests, \
             patch.object(builds.time, 'sleep') as sleep, \
             self.assertRaisesRegex(ValueError, 'failed or was skipped'):
            builds.native_job(self.run, 'amd64', 3, completed=False)
        self.assertEqual(requests.call_count, 1)
        sleep.assert_not_called()

    def test_retention_rejects_terminal_or_requeued_producer_immediately(self):
        for status, conclusion in (('completed', 'failure'), ('completed', 'success'),
                                   ('completed', 'cancelled'), ('queued', None),
                                   ('in_progress', 'failure')):
            with self.subTest(status=status, conclusion=conclusion):
                pending, ready = self.retention_jobs()
                ready.update(status=status, conclusion=conclusion)

                def provider(path, **options):
                    return {'jobs': [pending]} if '/attempts/' in path else ready

                with patch.object(builds, 'api', side_effect=provider) as requests, \
                     patch.object(builds.time, 'sleep') as sleep, \
                     self.assertRaisesRegex(ValueError, 'original native job'):
                    builds.native_job(self.run, 'amd64', 3, completed=False)
                self.assertEqual(requests.call_count, 2)
                sleep.assert_not_called()

    def test_retention_never_switches_producer_identity_while_waiting(self):
        for field, value in (('id', 31), ('run_id', 101), ('run_attempt', 2),
                             ('head_sha', 'b' * 40), ('name', builds.job_name('arm64'))):
            with self.subTest(field=field):
                pending, ready = self.retention_jobs()
                changed = copy.deepcopy(ready)
                changed[field] = value
                clock = FakeClock()

                def provider(path, **options):
                    if '/attempts/' in path:
                        return {'jobs': [pending]}
                    self.assertEqual(path, '/actions/jobs/30')
                    return changed if clock.now >= 15 else pending

                with patch.object(builds, 'api', side_effect=provider), \
                     patch.object(builds.time, 'monotonic', side_effect=clock.monotonic), \
                     patch.object(builds.time, 'sleep', side_effect=clock.sleep), \
                     self.assertRaisesRegex(ValueError, 'identity differs'):
                    builds.native_job(self.run, 'amd64', 3, completed=False)
                self.assertEqual(clock.sleeps, [15])

    def test_retention_requires_unique_job_and_unambiguous_gate_metadata(self):
        pending, _ = self.retention_jobs()
        for jobs in ([], [pending, pending]):
            with self.subTest(jobs=len(jobs)), \
                 patch.object(builds, 'api', return_value={'jobs': jobs}), \
                 patch.object(builds.time, 'sleep') as sleep, \
                 self.assertRaisesRegex(ValueError, 'one original native producer'):
                builds.native_job(self.run, 'amd64', 3, completed=False)
            sleep.assert_not_called()
        for steps in (None, [None], pending['steps'] + [pending['steps'][0]]):
            bad = copy.deepcopy(pending)
            bad['steps'] = steps
            with self.subTest(steps=steps), \
                 patch.object(builds, 'api', return_value={'jobs': [bad]}), \
                 patch.object(builds.time, 'sleep') as sleep, \
                 self.assertRaises(ValueError):
                builds.native_job(self.run, 'amd64', 3, completed=False)
            sleep.assert_not_called()

    def test_completed_native_audits_do_not_wait_or_use_retention_transport(self):
        job = self.native['amd64']
        with patch.object(builds, 'pages', return_value=[job]) as pages, \
             patch.object(builds.time, 'sleep') as sleep:
            self.assertEqual(builds.native_job(self.run, 'amd64', 3), job)
        self.assertEqual(pages.call_args.kwargs, {})
        sleep.assert_not_called()
        job['steps'][0]['conclusion'] = 'skipped'
        with patch.object(builds, 'pages', return_value=[job]), \
             patch.object(builds.time, 'sleep') as sleep, self.assertRaises(ValueError):
            builds.native_job(self.run, 'amd64', 3)
        sleep.assert_not_called()

    def test_retention_cannot_inspect_save_or_upload_before_gate_acceptance(self):
        for outcome in ('deadline', 'failed', 'identity'):
            with self.subTest(outcome=outcome):
                pending, ready = self.retention_jobs()
                clock = FakeClock()
                if outcome == 'failed':
                    ready['steps'][0]['conclusion'] = 'skipped'
                if outcome == 'identity':
                    ready['id'] = 31

                def provider(path, **options):
                    if '/attempts/' in path:
                        return {'jobs': [pending]}
                    return pending if outcome == 'deadline' else ready

                with patch.object(builds, 'api', side_effect=provider), \
                     patch.object(builds, 'push_guard', return_value=self.run), \
                     patch.object(builds, 'context', return_value=('2.21.4', 'a' * 40)), \
                     patch.object(builds.time, 'monotonic', side_effect=clock.monotonic), \
                     patch.object(builds.time, 'sleep', side_effect=clock.sleep), \
                     patch.object(builds, 'inspect_image') as image, \
                     patch.object(builds.subprocess, 'run') as save, \
                     patch.object(builds.materials, 'bundle') as bundle, \
                     patch.object(builds, 'candidate') as candidate, \
                     patch.object(builds, 'upload') as upload, self.assertRaises(ValueError):
                    builds.retain('amd64')
                for operation in (image, save, bundle, candidate, upload):
                    operation.assert_not_called()

    def test_retention_get_requests_are_uncached_and_use_remaining_timeout(self):
        clock = FakeClock()
        clock.now = 1790
        intervals = []
        response = MagicMock()
        response.read.return_value = b'{"id":30}'
        response.headers = {'X-Poll-Interval': '45'}
        opener = MagicMock()
        opener.open.return_value.__enter__.return_value = response
        with patch.object(builds.time, 'monotonic', side_effect=clock.monotonic), \
             patch.object(builds.urllib.request, 'build_opener', return_value=opener):
            self.assertEqual(builds.api('/actions/jobs/30', metadata_deadline=1800,
                                       poll_intervals=intervals), {'id': 30})
        request = opener.open.call_args.args[0]
        headers = {k.lower(): v for k, v in request.header_items()}
        self.assertEqual(headers['cache-control'], 'no-cache, no-store')
        self.assertEqual(headers['pragma'], 'no-cache')
        self.assertEqual(opener.open.call_args.kwargs['timeout'], 10)
        self.assertEqual(intervals, [45])

    def test_metadata_transport_preserves_normal_get_and_write_behavior(self):
        response = MagicMock()
        response.read.return_value = b'{"id":30}'
        opener = MagicMock()
        opener.open.return_value.__enter__.return_value = response
        with patch.object(builds.urllib.request, 'build_opener', return_value=opener):
            for method, data in (('GET', None), ('POST', {'draft': True})):
                builds.api('/releases', method=method, data=data)
                request = opener.open.call_args.args[0]
                self.assertEqual(request.get_method(), method)
                self.assertEqual(request.full_url, 'https://api.github.com/repos/brspoon/keep/releases')
                self.assertEqual(dict(request.header_items()), {
                    'Authorization': 'Bearer fake-token', 'Accept': 'application/vnd.github+json',
                    'Content-type': 'application/json', 'X-github-api-version': '2022-11-28',
                    'User-agent': 'Keep-validated-build'})
                self.assertEqual(request.data, json.dumps(data).encode() if data is not None else None)
                self.assertEqual(opener.open.call_args.kwargs['timeout'], 60)
            with self.assertRaisesRegex(ValueError, 'read-only'):
                builds.api('/releases', method='POST', data={}, metadata_deadline=1800)
        self.assertEqual(opener.open.call_count, 2)
        failure = urllib.error.HTTPError('https://api.github.com/', 503, 'unavailable', {}, None)
        opener.open.side_effect = failure
        with patch.object(builds.urllib.request, 'build_opener', return_value=opener), \
             patch.object(builds.time, 'sleep') as sleep, self.assertRaises(urllib.error.HTTPError):
            builds.api('/releases', method='POST', data={})
        self.assertEqual(opener.open.call_count, 3)
        sleep.assert_not_called()

    def test_retention_transport_rejects_response_returned_at_deadline(self):
        clock = FakeClock()
        response = MagicMock()

        def read(limit):
            self.assertEqual(limit, builds.JSON_LIMIT + 1)
            clock.now = 1800
            return b'{"id":30}'

        response.read.side_effect = read
        response.headers = {}
        opener = MagicMock()
        opener.open.return_value.__enter__.return_value = response
        with patch.object(builds.time, 'monotonic', side_effect=clock.monotonic), \
             patch.object(builds.urllib.request, 'build_opener', return_value=opener), \
             self.assertRaisesRegex(ValueError, 'deadline'):
            builds.api('/actions/jobs/30', metadata_deadline=1800)
        self.assertEqual(opener.open.call_count, 1)

    def test_retain_archives_exact_bytes_only_after_all_native_gates(self):
        os.environ.update(GITHUB_EVENT_NAME='push', GITHUB_RUN_ID='100', GITHUB_RUN_ATTEMPT='3')
        self.run.update(status='in_progress', conclusion=None)
        self.native['amd64'].update(status='in_progress', conclusion=None)
        original = {}
        for record in self.indexes['amd64']['assets']:
            if record['path'].endswith('.tar'):
                continue
            path = Path(record['path'])
            path.parent.mkdir(parents=True, exist_ok=True)
            original[record['path']] = self.blobs[f"/releases/assets/{record['id']}"]
            path.write_bytes(original[record['path']])
        proof = {'archive': 'source', 'sha256': 'b' * 64, 'bytes': 4, 'manifest': {'architecture': 'amd64'}}
        Path('distribution/source-bundle-amd64.json').write_text(json.dumps(proof))
        original['distribution/source-bundle-amd64.json'] = Path('distribution/source-bundle-amd64.json').read_bytes()

        def docker(args, **kwargs):
            self.assertEqual(args[:4], ['docker', 'image', 'save', '--output'])
            Path(args[4]).write_bytes(b'exact docker save bytes')

        def upload(release, path, name):
            self.assertEqual(release['id'], 70)
            self.assertTrue(name.startswith('build-100-3-amd64--'))
            return {'id': 1000 + builds.input_paths('amd64').index(next(
                item for item in builds.input_paths('amd64') if Path(item).name == path.name)),
                    'name': name, 'size': path.stat().st_size,
                    'digest': 'sha256:' + hashlib.sha256(path.read_bytes()).hexdigest()}

        with patch.object(builds, 'api', side_effect=self.api), \
             patch.object(builds, 'inspect_image', return_value='sha256:' + 'b' * 64), \
             patch.object(builds.subprocess, 'run', side_effect=docker), \
             patch.object(builds.materials, 'bundle', return_value=(Path('source'), proof)), \
             patch.object(builds.materials, 'portable_evidence'), patch.object(builds.materials, 'installer_evidence'), \
             patch.object(builds, 'upload', side_effect=upload):
            builds.retain('amd64')
        index = json.loads(Path('validated-build/amd64/index.json').read_text())
        self.assertEqual(index['build']['run_id'], 100)
        self.assertEqual(index['build']['run_attempt'], 3)
        self.assertEqual(len(index['assets']), len(builds.input_paths('amd64')))
        for path, body in original.items():
            self.assertEqual(Path(path).read_bytes(), body)
            row = next(row for row in index['assets'] if row['path'] == path)
            self.assertEqual(row['sha256'], hashlib.sha256(body).hexdigest())


if __name__ == '__main__':
    unittest.main()
