import json
import os
from contextlib import chdir
from pathlib import Path
import sys
import tempfile
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

    def test_workflow_keeps_security_gates_and_digest_transfer(self):
        workflow = Path('.github/workflows/image.yml').read_text()
        self.assertNotIn('continue-on-error', workflow)
        self.assertIn('branches: [main]', workflow)
        self.assertNotIn("branches: [main, 'brspoon/**']", workflow)
        self.assertIn("github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main' && inputs.publish_release && inputs.confirmation == 'release-stable'", workflow)
        self.assertIn('KEEP_RELEASE_PUBLISH: ${{ inputs.publish_release }}', workflow)
        self.assertIn('KEEP_RELEASE_CONFIRMATION: ${{ inputs.confirmation }}', workflow)
        self.assertNotIn('pull_request_target', workflow)
        contributor = workflow.split('  contributor-tests:', 1)[1].split('  image:', 1)[0]
        self.assertIn('github.event.pull_request.head.repo.full_name != github.repository', contributor)
        self.assertIn('contents: read', contributor)
        for secret_reference in ('secrets:', '${{ secrets.', 'DOCKERHUB_TOKEN', 'GITHUB_TOKEN'):
            self.assertNotIn(secret_reference, contributor)
        self.assertIn("github.event.pull_request.head.repo.full_name == github.repository", workflow)
        native = Path('.github/workflows/native-image.yml').read_text()
        self.assertNotIn('continue-on-error', native)
        stages = [native.index(command) for command in (
            'scripts/review_image.py', 'scripts/collect_package_sources.py',
            'scripts/build_distribution_bundle.py', 'scripts/release_materials.py report',
            'registry_transfer.py stage', 'scripts/release_materials.py archive-native')]
        self.assertEqual(stages, sorted(stages))
        self.assertIn('--runtime-inventory candidate-notices-${{ matrix.arch }}.json', native)
        self.assertIn('sha256sum --check keep-', native)
        for text in (workflow, native):
            self.assertNotIn('actions/upload-artifact@', text)
            self.assertNotIn('actions/download-artifact@', text)
            self.assertNotIn('actions: read', text)
        image_job = workflow.split('  image:', 1)[1].split('  release-native:', 1)[0]
        self.assertIn('contents: read', image_job)
        self.assertIn('publish_release: false', image_job)
        self.assertNotIn('contents: write', image_job)
        release_native = workflow.split('  release-native:', 1)[1].split('  tested-images:', 1)[0]
        self.assertIn('needs: [release-needed, prepare-release]', release_native)
        self.assertIn('contents: write', release_native)
        self.assertIn('publish_release: true', release_native)
        tested_images = workflow.split('  tested-images:', 1)[1].split('  prepare-release:', 1)[0]
        self.assertIn('needs: [release-native, release-needed, prepare-release]', tested_images)
        self.assertIn('contents: write', tested_images)
        self.assertIn('amd64: ${{ steps.aggregate.outputs.amd64 }}', tested_images)
        self.assertIn('arm64: ${{ steps.aggregate.outputs.arm64 }}', tested_images)
        self.assertIn('scripts/release_materials.py aggregate', tested_images)
        prepare = workflow.split('  prepare-release:', 1)[1].split('  publish-release:', 1)[0]
        self.assertIn('needs: [release-needed, installer-windows]', prepare)
        self.assertIn('contents: write', prepare)
        self.assertIn('scripts/release_materials.py prepare', prepare)
        self.assertNotIn('  release-materials:', workflow)
        verify = workflow.index('scripts/release_materials.py verify')
        publish = workflow.index('scripts/publish_release.py --image')
        self.assertLess(verify, publish)
        publisher = workflow.split('  publish-release:', 1)[1].split('  release-needed:', 1)[0]
        self.assertIn('needs: [release-native, release-needed, tested-images, prepare-release]', publisher)
        self.assertIn('contents: write', publisher)
        for job in (release_native, tested_images, prepare, publisher):
            self.assertIn("needs.release-needed.outputs.publish == 'true'", job)
        for job in (native, tested_images, prepare, publisher):
            self.assertIn('persist-credentials: false', job)
            self.assertIn('GITHUB_TOKEN: ${{ github.token }}', job)
            self.assertIn('KEEP_RELEASE_PUBLISH: ${{ inputs.publish_release }}', job)
            self.assertIn('KEEP_RELEASE_CONFIRMATION: ${{ inputs.confirmation }}', job)
        source_workflow = Path('.github/workflows/source-materials.yml').read_text()
        self.assertNotIn('path: source-materials\n', source_workflow)
        for metadata in ('source-materials/**/*.json', 'source-materials/**/*.yaml',
                         'source-materials/**/*.yml', 'source-materials/**/*.pem'):
            self.assertIn(metadata, source_workflow)
        self.assertIn('retention-days: 7', source_workflow)
        self.assertIn('compression-level: 6', source_workflow)
        self.assertNotIn('toJSON(needs.image.outputs)', workflow)
        self.assertGreaterEqual(workflow.count('toJSON(needs.tested-images.outputs)'), 3)
        self.assertLess(publish, workflow.index('registry_transfer.py cleanup'))
        windows = workflow.split('  installer-windows:', 1)[1].split('  contributor-tests:', 1)[0]
        self.assertIn('runs-on: windows-latest', windows)
        self.assertIn('shell: powershell', windows)
        self.assertIn('test_install_platform.py', windows)
        self.assertIn('Parser]::ParseFile', windows)
        self.assertNotIn('unittest discover -s tests\n', windows)
        self.assertNotIn('${{ secrets.', windows)
        launcher = native.split('      - name: Test installation launcher on the native host', 1)[1].split('      - name: Test Python application and release tools', 1)[0]
        self.assertIn('sh -n install.sh', launcher)
        self.assertIn('python3 -B -m unittest discover -s tests -p test_install_launcher.py', launcher)
        runtime_suite = native.split('      - name: Test Python application and release tools', 1)[1].split('      - name: Test JavaScript', 1)[0]
        self.assertIn("p.name not in ('test_deploy.py', 'test_install_launcher.py')", runtime_suite)
        self.assertLess(native.index('Test installation launcher on the native host'), native.index('Test Python application and release tools'))
        self.assertLess(native.index('scripts/installer_container_trial.py'), native.index('scripts/collect_image_sources.py'))
