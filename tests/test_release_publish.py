import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import urllib.error
from unittest.mock import patch

sys.path.insert(0, str(Path('scripts').resolve()))
import publish_release as publisher

SHA = 'a' * 40
ENV = {'GITHUB_EVENT_NAME': 'workflow_dispatch', 'GITHUB_REF': publisher.BRANCH,
       'GITHUB_SHA': SHA, 'GITHUB_REPOSITORY': 'example/keep',
       'KEEP_RELEASE_PUBLISH': 'true', 'KEEP_RELEASE_CONFIRMATION': 'release-stable',
       'DOCKERHUB_USERNAME': 'example', 'DOCKERHUB_TOKEN': 'test-secret'}


class ReleasePublishTests(unittest.TestCase):
    def test_pushes_and_invalid_inputs_never_contact_registry(self):
        cases = [
            {'GITHUB_EVENT_NAME': 'push', 'GITHUB_REF': 'refs/heads/main'},
            {'GITHUB_EVENT_NAME': 'push', 'GITHUB_REF': 'refs/heads/brspoon/test'},
            {'KEEP_RELEASE_PUBLISH': 'false'},
            {'KEEP_RELEASE_PUBLISH': ''},
            {'KEEP_RELEASE_PUBLISH': None},
            {'KEEP_RELEASE_CONFIRMATION': ''},
            {'KEEP_RELEASE_CONFIRMATION': None},
            {'KEEP_RELEASE_CONFIRMATION': 'private-dev-only'},
            {'GITHUB_REF': 'refs/heads/brspoon/test'},
        ]
        for changes in cases:
            with self.subTest(changes=changes), patch.dict(os.environ, ENV):
                for key, value in changes.items():
                    if value is None:
                        os.environ.pop(key, None)
                    else:
                        os.environ[key] = value
                with patch.object(publisher, 'hub') as hub:
                    with self.assertRaises(ValueError):
                        publisher.execute('example/keep', SHA, Path('missing'), release=True)
                    hub.assert_not_called()

    def test_exact_confirmed_manual_dispatch_is_allowed(self):
        with patch.dict(os.environ, ENV):
            publisher.require_manual_dispatch(True)

    def test_non_release_mode_is_rejected(self):
        with patch.dict(os.environ, ENV), patch.object(publisher, 'hub') as hub:
            with self.assertRaises(ValueError):
                publisher.execute('example/keep', SHA, Path('missing'))
            hub.assert_not_called()

    def test_invalid_registry_visibility_rejected_before_docker(self):
        for metadata in ({}, {'is_private': None}, {'is_private': 'false'}, {'is_private': 0}, [], None):
            with self.subTest(metadata=metadata), patch.dict(os.environ, ENV), \
                 patch.object(publisher, 'require_current_source'), \
                 patch.object(publisher, 'hub', side_effect=[{'access_token': 'token'}, metadata]), \
                 patch.object(publisher.subprocess, 'run') as docker:
                with self.assertRaisesRegex(ValueError, 'visibility metadata'):
                    publisher.execute('example/keep', SHA, Path('missing'), release=True)
                docker.assert_not_called()

    def test_existing_commit_tag_is_never_overwritten(self):
        plan = publisher.release_plan('example/keep', Path('VERSION').read_text().strip(), SHA)
        with patch.object(publisher, 'hub', return_value={}):
            with self.assertRaisesRegex(ValueError, 'overwrite'):
                publisher.require_new_tags(plan, 'example/keep', 'token')

    def test_invalid_github_visibility_or_stale_source_is_rejected(self):
        for metadata in ({}, {'private': None}, {'private': 'true'}, {'private': 1}, [], None):
            with self.subTest(metadata=metadata), patch.object(publisher, 'github', return_value=metadata) as github:
                with self.assertRaisesRegex(ValueError, 'visibility metadata'):
                    publisher.require_current_source(SHA, release=True)
                self.assertEqual(github.call_count, 1)
        for private in (False, True):
            with self.subTest(private=private), \
                 patch.object(publisher, 'github', side_effect=[{'private': private}, {'object': {'sha': 'b' * 40}}]), \
                 self.assertRaisesRegex(ValueError, 'stale'):
                publisher.require_current_source(SHA, release=True)

    def test_exact_artifacts_publish_by_digest_and_promote_alias_last(self):
        calls = []
        digests = {'amd64': 'sha256:' + '1' * 64, 'arm64': 'sha256:' + '2' * 64}
        def docker(command, **kwargs):
            calls.append(command)
            output = ''
            if command[1:3] == ['image', 'inspect']:
                arch = command[-1].removeprefix('keep-ci-')
                output = json.dumps([{'Id': 'sha256:' + arch, 'Architecture': arch, 'Os': 'linux', 'Config': {'User': '10001:10001', 'Labels': {
                    'org.opencontainers.image.revision': SHA, 'org.opencontainers.image.version': Path('VERSION').read_text().strip(),
                    'org.opencontainers.image.source': 'https://github.com/example/keep'}}}])
            elif command[1:4] == ['manifest', 'inspect', '--verbose']:
                arch = 'amd64' if command[-1].endswith('-amd64') else 'arm64'
                output = json.dumps({'Descriptor': {'digest': digests[arch]}})
            elif command[1:3] == ['manifest', 'inspect']:
                output = json.dumps({'manifests': [{'platform': {'os': 'linux', 'architecture': arch}, 'digest': digest} for arch, digest in digests.items()]})
            return subprocess.CompletedProcess(command, 0, output)
        for github_private in (False, True):
            for hub_private in (False, True):
                with self.subTest(github_private=github_private, hub_private=hub_private), tempfile.TemporaryDirectory() as directory:
                    calls.clear()
                    for arch in digests:
                        (Path(directory) / ('keep-' + arch + '.tar')).write_bytes(b'test-only')
                    def github(path):
                        return {'private': github_private} if not path else {'object': {'sha': SHA}}
                    with patch.dict(os.environ, ENV), patch.object(publisher, 'github', side_effect=github), \
                         patch.object(publisher, 'require_new_tags'), \
                         patch.object(publisher, 'hub', side_effect=[{'access_token': 'token'}, {'is_private': hub_private}]), \
                         patch.object(publisher.subprocess, 'run', side_effect=docker), patch('builtins.print'):
                        publisher.execute('example/keep', SHA, Path(directory), release=True)
                    pushes = [c[-1] for c in calls if c[1] == 'push' or c[1:3] == ['manifest', 'push']]
                    self.assertEqual(pushes[-1], 'example/keep:stable')
                    creates = [c for c in calls if c[1:3] == ['manifest', 'create']]
                    self.assertTrue(all(ref.startswith('example/keep@sha256:') for c in creates for ref in c[4:]))

    def test_release_refuses_wrong_ref_or_confirmation_before_registry(self):
        for changes in ({'GITHUB_REF': 'refs/heads/brspoon/test'},
                        {'KEEP_RELEASE_CONFIRMATION': 'private-dev-only'}):
            with patch.dict(os.environ, {**ENV, **changes}), patch.object(publisher, 'hub') as hub:
                with self.assertRaises(ValueError):
                    publisher.execute('example/keep', SHA, Path('missing'), release=True)
                hub.assert_not_called()

    def test_release_checks_current_main_for_both_visibilities(self):
        for private in (False, True):
            with self.subTest(private=private), \
                 patch.object(publisher, 'github', side_effect=[{'private': private}, {'object': {'sha': SHA}}]) as github:
                publisher.require_current_source(SHA, release=True)
            self.assertEqual(github.call_args.args[0], '/git/ref/heads/main')
        for reference in ({}, {'object': None}, {'object': {'sha': ''}}, {'object': {'sha': 1}}, None):
            with self.subTest(reference=reference), \
                 patch.object(publisher, 'github', side_effect=[{'private': True}, reference]), \
                 self.assertRaisesRegex(ValueError, 'main'):
                publisher.require_current_source(SHA, release=True)

    def test_wrong_digest_or_duplicate_platform_is_rejected(self):
        bad = {'manifests': [{'platform': {'os': 'linux', 'architecture': 'amd64'}, 'digest': 'wrong'}] * 2}
        with self.assertRaises(ValueError):
            publisher.verify_manifest(bad, {'amd64': 'a', 'arm64': 'b'})


class ReleaseEligibilityTests(unittest.TestCase):
    def test_existing_version_skips_and_missing_version_publishes(self):
        import release_needed
        for private in (False, True):
            for reply, expected in [({}, False), (urllib.error.HTTPError('test', 404, 'missing', {}, None), True)]:
                with self.subTest(private=private, expected=expected), \
                     patch.object(release_needed, 'hub', side_effect=[{'access_token': 'test'}, {'is_private': private}, reply]):
                    self.assertEqual(release_needed.release_needed('example/keep', '2.0.2', SHA, 'test', 'test'), expected)

    def test_visibility_must_be_explicit_before_checking_version(self):
        import release_needed
        for metadata in ({}, {'is_private': None}, {'is_private': 0}, {'is_private': 'false'}):
            with self.subTest(metadata=metadata), \
                 patch.object(release_needed, 'hub', side_effect=[{'access_token': 'test'}, metadata]) as hub:
                with self.assertRaisesRegex(ValueError, 'visibility metadata'):
                    release_needed.release_needed('example/keep', '2.0.2', SHA, 'test', 'test')
                self.assertEqual(hub.call_count, 2)

    def test_registry_errors_do_not_trigger_publication(self):
        import release_needed
        with patch.object(release_needed, 'hub', side_effect=[{'access_token': 'test'}, {'is_private': True}, urllib.error.HTTPError('test', 403, 'denied', {}, None)]):
            with self.assertRaises(urllib.error.HTTPError):
                release_needed.release_needed('example/keep', '2.0.2', SHA, 'test', 'test')

    def test_no_push_can_use_release_guard(self):
        for ref in ('refs/heads/main', 'refs/heads/brspoon/test'):
            with patch.dict(os.environ, {**ENV, 'GITHUB_EVENT_NAME': 'push', 'GITHUB_REF': ref}):
                with self.assertRaises(ValueError):
                    publisher.require_manual_dispatch(True)
