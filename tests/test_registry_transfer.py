import json
import itertools
import os
import re
from contextlib import chdir
from pathlib import Path
import sys
import tempfile
import textwrap
import unittest
import urllib.error
from unittest.mock import patch

sys.path.insert(0, str(Path('scripts').resolve()))
import registry_transfer as transfer


class RegistryTransferTests(unittest.TestCase):
    def test_delete_permission_defers_explicitly_but_other_errors_fail(self):
        for code in (403, 500):
            with patch.object(transfer.urllib.request, 'urlopen', side_effect=urllib.error.HTTPError('test', code, 'test', {}, None)), patch('builtins.print') as output:
                if code == 403:
                    self.assertFalse(transfer.delete_transfer_tag('repositories/example/keep/tags/transfer-1-1-amd64/', 'test'))
                    self.assertIn('cleanup required', output.call_args.args[0])
                else:
                    with self.assertRaises(urllib.error.HTTPError):
                        transfer.delete_transfer_tag('test', 'test')

    def test_run_scoped_tags_and_invalid_identity(self):
        with patch.dict(os.environ, GITHUB_RUN_ID='123', GITHUB_RUN_ATTEMPT='2'):
            self.assertEqual(transfer.transfer_tag('arm64'), 'transfer-123-2-arm64')
            with self.assertRaises(ValueError):
                transfer.transfer_tag('stable')
        with patch.dict(os.environ, GITHUB_RUN_ID='../stable', GITHUB_RUN_ATTEMPT='2'):
            with self.assertRaises(ValueError):
                transfer.transfer_tag('amd64')

    def test_only_immutable_digests_accepted(self):
        self.assertEqual(transfer.checked_digest('sha256:' + 'a' * 64), 'sha256:' + 'a' * 64)
        for value in ('stable', '', None, 'sha256:abc'):
            with self.assertRaises(ValueError):
                transfer.checked_digest(value)

    def test_feature_branch_refused_before_registry(self):
        with patch.dict(os.environ, GITHUB_EVENT_NAME='push', GITHUB_REF='refs/heads/brspoon/test', KEEP_DEV_CONFIRMATION='release-stable'), patch.object(transfer, 'hub') as hub:
            with self.assertRaises(ValueError):
                transfer.execute('stage', 'amd64')
            hub.assert_not_called()

    def test_main_push_refused_before_registry(self):
        with patch.dict(os.environ, GITHUB_EVENT_NAME='push', GITHUB_REF='refs/heads/main',
                        KEEP_RELEASE_PUBLISH='true', KEEP_RELEASE_CONFIRMATION='release-stable'), patch.object(transfer, 'hub') as hub:
            with self.assertRaises(ValueError):
                transfer.execute('stage', 'amd64')
            hub.assert_not_called()

    def test_invalid_registry_visibility_refused_before_docker(self):
        for metadata in ({}, {'is_private': None}, {'is_private': 'false'}, {'is_private': 0}, []):
            with self.subTest(metadata=metadata), \
                 patch.dict(os.environ, DOCKERHUB_IMAGE='example/keep', GITHUB_SHA='a' * 40, DOCKERHUB_USERNAME='test', DOCKERHUB_TOKEN='test'), \
                 patch.object(transfer, 'require_manual_dispatch'), patch.object(transfer, 'require_current_source'), \
                 patch.object(transfer, 'hub', side_effect=[{'access_token': 'test'}, metadata]), \
                 patch.object(transfer.subprocess, 'run') as docker:
                with self.assertRaisesRegex(ValueError, 'visibility metadata'):
                    transfer.execute('stage', 'amd64')
                docker.assert_not_called()

    def test_public_and_private_transfer_keep_exact_run_tag_cleanup(self):
        version = Path('VERSION').read_text()
        digests = {'amd64': 'sha256:' + 'a' * 64, 'arm64': 'sha256:' + 'b' * 64}
        for private in (False, True):
            with self.subTest(private=private), tempfile.TemporaryDirectory() as directory, chdir(directory):
                Path('VERSION').write_text(version)
                output = Path(directory) / 'output'
                environment = {
                    'GITHUB_EVENT_NAME': 'workflow_dispatch', 'GITHUB_REF': 'refs/heads/main',
                    'KEEP_RELEASE_PUBLISH': 'true', 'KEEP_RELEASE_CONFIRMATION': 'release-stable',
                    'DOCKERHUB_IMAGE': 'example/keep', 'GITHUB_SHA': 'a' * 40,
                    'DOCKERHUB_USERNAME': 'test', 'DOCKERHUB_TOKEN': 'synthetic',
                    'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '2',
                    'GITHUB_OUTPUT': str(output), 'TESTED_DIGESTS': json.dumps(digests),
                }
                def hub(path, token=None, payload=None):
                    if path == 'auth/token':
                        return {'access_token': 'synthetic-access-token'}
                    if path == 'repositories/example/keep/':
                        return {'is_private': private}
                    arch = 'amd64' if path.endswith('amd64/') else 'arm64'
                    return {'digest': digests[arch]}
                from subprocess import CompletedProcess
                docker_reply = CompletedProcess([], 0, json.dumps({'Descriptor': {'digest': digests['amd64']}}))
                with patch.dict(os.environ, environment), patch.object(transfer, 'require_current_source'), \
                     patch.object(transfer, 'require_new_tags'), patch.object(transfer, 'hub', side_effect=hub), \
                     patch.object(transfer.subprocess, 'run', return_value=docker_reply) as docker, \
                     patch.object(transfer, 'delete_transfer_tag', return_value=True) as delete, patch('builtins.print'):
                    transfer.execute('stage', 'amd64')
                    record = json.loads(Path('transfer-amd64.json').read_text())
                    self.assertEqual(record['digest'], digests['amd64'])
                    self.assertEqual(record['run_id'], '123')
                    self.assertEqual(record['run_attempt'], '2')
                    transfer.execute('cleanup')
                self.assertEqual([call.args[0] for call in delete.call_args_list], [
                    'repositories/example/keep/tags/transfer-123-2-amd64/',
                    'repositories/example/keep/tags/transfer-123-2-arm64/'])
                self.assertIn(['docker', 'push', 'example/keep:transfer-123-2-amd64'],
                              [call.args[0] for call in docker.call_args_list])

    def test_missing_architecture_fails_before_docker(self):
        with patch.dict(os.environ, DOCKERHUB_IMAGE='example/keep', GITHUB_SHA='a' * 40, DOCKERHUB_USERNAME='test', DOCKERHUB_TOKEN='test', TESTED_DIGESTS=json.dumps({'amd64': 'sha256:' + 'a' * 64})), patch.object(transfer, 'require_manual_dispatch'), patch.object(transfer, 'require_current_source'), patch.object(transfer, 'hub', side_effect=[{'access_token': 'test'}, {'is_private': True}]), patch.object(transfer.subprocess, 'run') as docker:
            with self.assertRaisesRegex(ValueError, 'Both'):
                transfer.execute('fetch')
            docker.assert_not_called()

    def workflow_jobs(self):
        workflow = Path('.github/workflows/image.yml').read_text()
        matches = list(re.finditer(r'^  ([a-z][a-z-]+):\s*$', workflow.split('jobs:\n', 1)[1], re.M))
        body = workflow.split('jobs:\n', 1)[1]
        return workflow, {match.group(1): body[match.start():matches[index + 1].start() if index + 1 < len(matches) else len(body)]
                          for index, match in enumerate(matches)}

    def test_pr_checks_are_read_only_and_only_main_builds_native_images(self):
        workflow, jobs = self.workflow_jobs()
        self.assertNotIn('pull_request_target', workflow)
        self.assertNotIn('continue-on-error', workflow)
        self.assertIn('branches: [main]', workflow)
        self.assertEqual(workflow.count('uses: ./.github/workflows/native-image.yml'), 1)
        for name in ('installer-windows', 'contributor-tests'):
            job = jobs[name]
            self.assertIn("if: github.event_name != 'workflow_dispatch'", job)
            self.assertIn('contents: read', job)
            for credential in ('secrets:', '${{ secrets.', 'DOCKERHUB_TOKEN', 'GITHUB_TOKEN', 'contents: write'):
                self.assertNotIn(credential, job)
        self.assertIn("if: github.event_name == 'pull_request'\n        run: git diff --check", jobs['contributor-tests'])
        for name in ('prepare-candidate', 'image'):
            self.assertIn("if: github.event_name == 'push' && github.ref == 'refs/heads/main'", jobs[name])
            self.assertIn('contents: write', jobs[name])
        self.assertIn('needs: [installer-windows, contributor-tests]', jobs['prepare-candidate'])
        self.assertIn('needs: [prepare-candidate]', jobs['image'])
        self.assertIn('scripts/validated_build.py prepare', jobs['prepare-candidate'])
        native = Path('.github/workflows/native-image.yml').read_text()
        self.assertIn("if: github.event_name == 'push' && github.ref == 'refs/heads/main'", native)
        self.assertIn('name: image (${{ matrix.arch }})', native)

    def test_native_checks_all_precede_retention_and_upload_only_small_index(self):
        native = Path('.github/workflows/native-image.yml').read_text()
        self.assertNotIn('continue-on-error', native)
        stages = [native.index(command) for command in (
            'scripts/portable_container_trial.py', 'scripts/installer_container_trial.py',
            'scripts/inspect_candidate.py', 'scripts/image_distribution.py --archive',
            'scripts/scan_image.sh', '/checks/python_security_checks.py',
            'scripts/review_image.py', 'scripts/collect_image_sources.py',
            'scripts/collect_package_sources.py', 'scripts/build_distribution_bundle.py',
            'scripts/release_materials.py report', 'scripts/validated_build.py retain',
            'Retain immutable validation index')]
        self.assertEqual(stages, sorted(stages))
        self.assertIn('--runtime-inventory candidate-notices-${{ matrix.arch }}.json', native)
        self.assertIn('sha256sum --check keep-', native)
        self.assertIn('actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02', native)
        self.assertIn('name: validated-build-${{ github.run_id }}-${{ github.run_attempt }}-${{ matrix.arch }}', native)
        self.assertIn('path: validated-build/${{ matrix.arch }}/index.json', native)
        self.assertIn('if-no-files-found: error', native)
        self.assertIn('retention-days: 90', native)
        self.assertNotIn('registry_transfer.py stage', native)
        self.assertNotIn('scripts/release_materials.py archive-native', native)
        launcher = native.split('      - name: Test installation launcher on the native host', 1)[1].split('      - name: Test Python application and release tools', 1)[0]
        self.assertIn('sh -n install.sh', launcher)
        self.assertIn('python3 -B -m unittest discover -s tests -p test_install_launcher.py', launcher)
        runtime_suite = native.split('      - name: Test Python application and release tools', 1)[1].split('      - name: Test JavaScript', 1)[0]
        self.assertIn("p.name not in ('test_deploy.py', 'test_install_launcher.py')", runtime_suite)
        source_workflow = Path('.github/workflows/source-materials.yml').read_text()
        self.assertNotIn('path: source-materials\n', source_workflow)
        for metadata in ('source-materials/**/*.json', 'source-materials/**/*.yaml',
                         'source-materials/**/*.yml', 'source-materials/**/*.pem'):
            self.assertIn(metadata, source_workflow)
        self.assertIn('retention-days: 7', source_workflow)
        self.assertIn('compression-level: 6', source_workflow)

    def test_manual_publication_restores_and_verifies_without_retesting(self):
        workflow, jobs = self.workflow_jobs()
        self.assertIn('validation_run_id:', workflow)
        self.assertIn('required: true', workflow.split('validation_run_id:', 1)[1].split('confirmation:', 1)[0])
        guard = "github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main' && inputs.publish_release && inputs.confirmation == 'release-stable'"
        for name in ('validated-main', 'prepare-release', 'release-native', 'tested-images', 'publish-release'):
            job = jobs[name]
            self.assertIn(guard, job)
            self.assertIn("needs.release-needed.outputs.publish == 'true'", job)
            self.assertIn('persist-credentials: false', job)
            for expensive_command in ('docker build', 'scripts/review_image.py', 'scripts/inspect_candidate.py',
                                      'scripts/scan_image.sh', 'scripts/collect_image_sources.py',
                                      'scripts/collect_package_sources.py', 'scripts/build_distribution_bundle.py',
                                      'scripts/portable_container_trial.py', 'scripts/installer_container_trial.py',
                                      'unittest discover', 'node --test', 'uses: ./.github/workflows/native-image.yml'):
                self.assertNotIn(expensive_command, job)
        self.assertIn('needs: [release-needed, validated-main]', jobs['prepare-release'])
        self.assertIn('scripts/validated_build.py check', jobs['validated-main'])
        promotion = jobs['release-native']
        stages = [promotion.index(command) for command in (
            'scripts/validated_build.py restore', 'scripts/registry_transfer.py stage',
            'scripts/release_materials.py archive-native')]
        self.assertEqual(stages, sorted(stages))
        for name in ('validated-main', 'release-native', 'tested-images', 'publish-release'):
            self.assertIn('actions: read', jobs[name])
            self.assertIn('KEEP_VALIDATION_RUN_ID: ${{ inputs.validation_run_id }}', jobs[name])
        for arch in ('amd64', 'arm64'):
            self.assertIn(f'{arch}: ${{{{ steps.aggregate.outputs.{arch} }}}}', jobs['tested-images'])
            self.assertIn(f'{arch}_config: ${{{{ steps.aggregate.outputs.{arch}_config }}}}', jobs['tested-images'])
        publisher = jobs['publish-release']
        stages = [publisher.index(command) for command in (
            'scripts/release_materials.py verify', 'scripts/registry_transfer.py fetch',
            'scripts/publish_release.py --image', 'scripts/registry_transfer.py cleanup')]
        self.assertEqual(stages, sorted(stages))
        self.assertIn('TESTED_CONFIG_DIGESTS:', publisher)
        self.assertNotIn('toJSON(needs.tested-images.outputs)', workflow)
        self.assertIn('group: keep-release-stable', publisher)

    def test_windows_installer_remains_a_separate_native_check(self):
        _, jobs = self.workflow_jobs()
        windows = jobs['installer-windows']
        self.assertIn('runs-on: windows-latest', windows)
        self.assertIn('shell: powershell', windows)
        self.assertIn('test_install_platform.py', windows)
        self.assertIn('Parser]::ParseFile', windows)
        self.assertNotIn('unittest discover -s tests\n', windows)

    def test_required_merge_check_rejects_failed_cancelled_or_missing_prerequisites(self):
        _, jobs = self.workflow_jobs()
        gate = jobs['required-checks']
        self.assertIn('needs: [installer-windows, contributor-tests, image]', gate)
        self.assertIn("if: ${{ always() && github.event_name != 'workflow_dispatch' }}", gate)
        self.assertNotIn('${{ secrets.', gate)
        self.assertNotIn('uses: actions/checkout', gate)
        script = compile(textwrap.dedent(gate.split("          python3 - <<'PYCHECK'\n", 1)[1].split('          PYCHECK', 1)[0]), '<required-checks>', 'exec')
        statuses = ('success', 'failure', 'cancelled', 'skipped', '')
        for event, installer, contributor, image in itertools.product(('pull_request', 'push', 'workflow_dispatch', ''), statuses, statuses, statuses):
            with self.subTest(event=event, installer=installer, contributor=contributor, image=image):
                with patch.dict(os.environ, {
                    'VALIDATION_EVENT': event,
                    'INSTALLER_RESULT': installer, 'CONTRIBUTOR_RESULT': contributor,
                    'IMAGE_RESULT': image,
                }):
                    try:
                        exec(script, {})
                    except SystemExit:
                        passed = False
                    else:
                        passed = True
                expected_image = {'pull_request': 'skipped', 'push': 'success'}.get(event)
                expected = installer == contributor == 'success' and expected_image is not None and image == expected_image
                self.assertEqual(passed, expected)
