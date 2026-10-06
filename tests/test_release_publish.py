from contextlib import chdir, contextmanager
import datetime
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
import release_materials as materials
import review_image

SHA = 'a' * 40
DIGESTS = {'amd64': 'sha256:' + '1' * 64, 'arm64': 'sha256:' + '2' * 64}
CONFIGS = {'amd64': 'sha256:' + '3' * 64, 'arm64': 'sha256:' + '4' * 64}
ENV = {'GITHUB_EVENT_NAME': 'workflow_dispatch', 'GITHUB_REF': publisher.BRANCH,
       'GITHUB_SHA': SHA, 'GITHUB_REPOSITORY': 'example/keep',
       'KEEP_RELEASE_PUBLISH': 'true', 'KEEP_RELEASE_CONFIRMATION': 'release-stable',
       'DOCKERHUB_USERNAME': 'example', 'DOCKERHUB_TOKEN': 'test-secret',
       'TESTED_DIGESTS': json.dumps(DIGESTS), 'TESTED_CONFIG_DIGESTS': json.dumps(CONFIGS)}


def inspected_image(arch, config=None):
    return {'Id': config or CONFIGS[arch], 'Architecture': arch, 'Os': 'linux',
            'Config': {'User': '10001:10001', 'Labels': {
                'org.opencontainers.image.revision': SHA,
                'org.opencontainers.image.version': Path('VERSION').read_text().strip(),
                'org.opencontainers.image.source': 'https://github.com/example/keep'}}}


class ReleasePublishTests(unittest.TestCase):
    @contextmanager
    def original_release_evidence(self, *, matches=None, config_digests=None,
                                  empty_exceptions=False, day=None):
        import tests.test_release_materials as fixtures
        fixture = fixtures.ReleaseMaterialsTests()
        fixture.VERSION = Path('VERSION').read_text().strip()
        fixture.setUp()
        # Preserve the caller's publisher environment; only the asset producer
        # run fields are supplied by this fixture below.
        fixture.environ.stop()
        try:
            rows, bodies = fixture.verify_fixture(
                matches=matches, native_digests=DIGESTS,
                config_digests=config_digests or CONFIGS,
                empty_exceptions=empty_exceptions, validation=True,
            )
            original = dict(bodies)
            downloads = []

            def asset_body(asset):
                downloads.append(asset['name'])
                return bodies[asset['name']]

            release = {'id': 88, 'draft': True, 'tag_name': fixture.VERSION,
                       'target_commitish': SHA}
            with chdir(fixture.root), \
                 patch.dict(os.environ, {'GITHUB_RUN_ID': '123456', 'GITHUB_RUN_ATTEMPT': '3'}), \
                 patch.object(materials, 'draft', return_value=release) as draft, \
                 patch.object(materials, 'api', return_value=rows) as assets, \
                 patch.object(materials, 'asset_body', side_effect=asset_body), \
                 patch.object(materials, 'verify_durable_validation'), \
                 patch.object(review_image, 'current_day', return_value=day or datetime.date(2026, 10, 7)):
                yield fixture.root, downloads
            draft.assert_called_once_with(fixture.VERSION)
            assets.assert_called_once_with('/releases/88/assets?per_page=100')
            self.assertEqual(bodies, original)
            for arch in DIGESTS:
                name = f'keep-{fixture.VERSION}-security-evidence-{arch}.tar.gz'
                self.assertEqual(downloads.count(name), 1)
        finally:
            fixture.doCleanups()

    def test_pushes_and_invalid_inputs_never_contact_registry(self):
        cases = [
            {'GITHUB_EVENT_NAME': 'push', 'GITHUB_REF': 'refs/heads/main'},
            {'GITHUB_EVENT_NAME': 'push', 'GITHUB_REF': 'refs/heads/feature/test'},
            {'KEEP_RELEASE_PUBLISH': 'false'},
            {'KEEP_RELEASE_PUBLISH': ''},
            {'KEEP_RELEASE_PUBLISH': None},
            {'KEEP_RELEASE_CONFIRMATION': ''},
            {'KEEP_RELEASE_CONFIRMATION': None},
            {'KEEP_RELEASE_CONFIRMATION': 'private-dev-only'},
            {'GITHUB_REF': 'refs/heads/feature/test'},
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
        configs = []
        digests = DIGESTS
        def docker(command, **kwargs):
            calls.append(command)
            configs.append(kwargs['env']['DOCKER_CONFIG'])
            output = ''
            if command[1:3] == ['image', 'inspect']:
                arch = command[-1].removeprefix('keep-ci-')
                output = json.dumps([inspected_image(arch)])
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
                    configs.clear()
                    for arch in digests:
                        (Path(directory) / ('keep-' + arch + '.tar')).write_bytes(b'test-only')
                    def github(path):
                        return {'private': github_private} if not path else {'object': {'sha': SHA}}
                    with patch.dict(os.environ, ENV), patch.object(publisher, 'github', side_effect=github), \
                         patch.object(publisher, 'require_new_tags'), \
                         patch.object(publisher, 'hub', side_effect=[{'access_token': 'token'}, {'is_private': hub_private}]), \
                         patch.object(publisher.subprocess, 'run', side_effect=docker), patch('builtins.print'), \
                         self.original_release_evidence():
                        publisher.execute('example/keep', SHA, Path(directory), release=True)
                    pushes = [c[-1] for c in calls if c[1] == 'push' or c[1:3] == ['manifest', 'push']]
                    self.assertEqual(pushes[-1], 'example/keep:stable')
                    creates = [c for c in calls if c[1:3] == ['manifest', 'create']]
                    self.assertTrue(all(ref.startswith('example/keep@sha256:') for c in creates for ref in c[4:]))
                    self.assertEqual(len(set(configs)), 1)
                    self.assertFalse(Path(configs[0]).exists())

    def test_missing_or_malformed_verified_identity_blocks_registry_and_docker(self):
        for name in ('TESTED_DIGESTS', 'TESTED_CONFIG_DIGESTS'):
            for value in (None, '', 'broken-json', 'null', '[]',
                          json.dumps({'amd64': DIGESTS['amd64']}),
                          json.dumps({**DIGESTS, 'extra': DIGESTS['amd64']}),
                          json.dumps({**DIGESTS, 'arm64': 'sha256:wrong'}),
                          json.dumps({**DIGESTS, 'arm64': 1})):
                with self.subTest(name=name, value=value), patch.dict(os.environ, ENV), \
                     patch.object(publisher, 'hub') as hub, \
                     patch.object(publisher.subprocess, 'run') as docker:
                    if value is None:
                        os.environ.pop(name, None)
                    else:
                        os.environ[name] = value
                    with self.assertRaisesRegex(ValueError, 'verified architecture identities'):
                        publisher.execute('example/keep', SHA, Path('missing'), release=True)
                    hub.assert_not_called()
                    docker.assert_not_called()

    def test_image_config_mismatch_blocks_all_registry_pushes(self):
        for wrong_arch in ('amd64', 'arm64'):
            calls = []
            def docker(command, **kwargs):
                calls.append(command)
                output = ''
                if command[1:3] == ['image', 'inspect']:
                    arch = command[-1].removeprefix('keep-ci-')
                    config = 'sha256:' + '0' * 64 if arch == wrong_arch else CONFIGS[arch]
                    output = json.dumps([inspected_image(arch, config)])
                return subprocess.CompletedProcess(command, 0, output)
            with self.subTest(architecture=wrong_arch), tempfile.TemporaryDirectory() as directory:
                for arch in DIGESTS:
                    (Path(directory) / ('keep-' + arch + '.tar')).write_bytes(b'offline-only')
                with patch.dict(os.environ, ENV), patch.object(publisher, 'require_current_source'), \
                     patch.object(publisher, 'require_new_tags'), \
                     patch.object(publisher, 'hub', side_effect=[{'access_token': 'token'}, {'is_private': False}]), \
                     patch.object(publisher.subprocess, 'run', side_effect=docker):
                    with self.assertRaisesRegex(ValueError, 'artifact identity'):
                        publisher.execute('example/keep', SHA, Path(directory), release=True)
                self.assertFalse(any(c[1] in ('login', 'push') or c[1] == 'manifest' for c in calls))

    def test_changed_native_digest_blocks_every_multiarch_manifest(self):
        for wrong_arch in ('amd64', 'arm64'):
            calls = []
            def docker(command, **kwargs):
                calls.append(command)
                output = ''
                if command[1:3] == ['image', 'inspect']:
                    arch = command[-1].removeprefix('keep-ci-')
                    output = json.dumps([inspected_image(arch)])
                elif command[1:4] == ['manifest', 'inspect', '--verbose']:
                    arch = 'amd64' if command[-1].endswith('-amd64') else 'arm64'
                    digest = 'sha256:' + '0' * 64 if arch == wrong_arch else DIGESTS[arch]
                    output = json.dumps({'Descriptor': {'digest': digest}})
                return subprocess.CompletedProcess(command, 0, output)
            with self.subTest(architecture=wrong_arch), tempfile.TemporaryDirectory() as directory:
                for arch in DIGESTS:
                    (Path(directory) / ('keep-' + arch + '.tar')).write_bytes(b'offline-only')
                with patch.dict(os.environ, ENV), patch.object(publisher, 'require_current_source'), \
                     patch.object(publisher, 'require_new_tags'), \
                     patch.object(publisher, 'hub', side_effect=[{'access_token': 'token'}, {'is_private': False}]), \
                     patch.object(publisher.subprocess, 'run', side_effect=docker), \
                     self.original_release_evidence():
                    with self.assertRaisesRegex(ValueError, 'native digest differs'):
                        publisher.execute('example/keep', SHA, Path(directory), release=True)
                self.assertFalse(any(c[1:3] in (['manifest', 'create'], ['manifest', 'push']) for c in calls))
                self.assertNotIn(['docker', 'push', 'example/keep:stable'], calls)

    def publishing_docker(self, calls, before_command=None):
        def docker(command, **kwargs):
            calls.append(command)
            if before_command:
                before_command(command)
            output = ''
            if command[1:3] == ['image', 'inspect']:
                output = json.dumps([inspected_image(command[-1].removeprefix('keep-ci-'))])
            elif command[1:4] == ['manifest', 'inspect', '--verbose']:
                arch = 'amd64' if command[-1].endswith('-amd64') else 'arm64'
                output = json.dumps({'Descriptor': {'digest': DIGESTS[arch]}})
            elif command[1:3] == ['manifest', 'inspect']:
                output = json.dumps({'manifests': [
                    {'platform': {'os': 'linux', 'architecture': arch}, 'digest': digest}
                    for arch, digest in DIGESTS.items()]})
            return subprocess.CompletedProcess(command, 0, output)
        return docker

    @contextmanager
    def publication_fixture(self, calls, *, before_command=None, **evidence_options):
        with tempfile.TemporaryDirectory() as directory:
            for arch in DIGESTS:
                (Path(directory) / ('keep-' + arch + '.tar')).write_bytes(b'offline-only')
            with patch.dict(os.environ, ENV), patch.object(publisher, 'require_current_source'), \
                 patch.object(publisher, 'require_new_tags'), \
                 patch.object(publisher, 'hub', side_effect=[{'access_token': 'token'}, {'is_private': False}]), \
                 patch.object(publisher.subprocess, 'run', side_effect=self.publishing_docker(calls, before_command)), \
                 patch('builtins.print'), self.original_release_evidence(**evidence_options) as evidence:
                yield Path(directory), evidence

    def needed_exception(self):
        return [{'vulnerability': {'id': 'CVE-2026-17084', 'severity': 'Medium'},
                 'artifact': {'name': 'python-3.14', 'type': 'apk', 'version': '3.14.7-r1'}}]

    def test_clean_publication_with_empty_or_unused_expired_exceptions_passes(self):
        for empty in (False, True):
            calls = []
            with self.subTest(empty_exceptions=empty), self.publication_fixture(
                    calls, empty_exceptions=empty, day=datetime.date(2026, 10, 8)) as (artifacts, _evidence):
                publisher.execute('example/keep', SHA, artifacts, release=True)
            self.assertIn(['docker', 'manifest', 'push', '--purge', 'example/keep:stable'], calls)

    def test_needed_exception_passes_publication_on_deadline(self):
        calls = []
        with self.publication_fixture(calls, matches=self.needed_exception(),
                                      day=datetime.date(2026, 10, 7)) as (artifacts, _evidence):
            publisher.execute('example/keep', SHA, artifacts, release=True)
        self.assertIn(['docker', 'manifest', 'push', '--purge', 'example/keep:stable'], calls)

    def test_expired_needed_exception_blocks_before_any_publication(self):
        calls = []
        with self.publication_fixture(calls, matches=self.needed_exception(),
                                      day=datetime.date(2026, 10, 8)) as (artifacts, _evidence):
            with self.assertRaisesRegex(ValueError, 'exception_expired'):
                publisher.execute('example/keep', SHA, artifacts, release=True)
        self.assertFalse(any(command[1] in ('login', 'tag', 'push', 'manifest') for command in calls))

    def test_crossing_utc_deadline_blocks_stable_immediately_before_push(self):
        calls = []
        day = datetime.date(2026, 10, 7)

        def cross_deadline(command):
            nonlocal day
            if command[1:3] == ['manifest', 'create'] and command[3] == 'example/keep:stable':
                day = datetime.date(2026, 10, 8)

        with self.publication_fixture(calls, matches=self.needed_exception(),
                                      before_command=cross_deadline) as (artifacts, _evidence), \
             patch.object(review_image, 'current_day', side_effect=lambda: day):
            with self.assertRaisesRegex(ValueError, 'exception_expired'):
                publisher.execute('example/keep', SHA, artifacts, release=True)
        pushes = [command for command in calls if command[1] == 'push' or command[1:3] == ['manifest', 'push']]
        self.assertEqual(len(pushes), 4)
        self.assertFalse(any(command[-1] == 'example/keep:stable' for command in pushes))

    def test_crossing_deadline_before_native_push_is_also_blocked(self):
        calls = []
        day = datetime.date(2026, 10, 7)

        def cross_deadline(command):
            nonlocal day
            if command[1] == 'tag':
                day = datetime.date(2026, 10, 8)

        with self.publication_fixture(calls, matches=self.needed_exception(),
                                      before_command=cross_deadline) as (artifacts, _evidence), \
             patch.object(review_image, 'current_day', side_effect=lambda: day):
            with self.assertRaisesRegex(ValueError, 'exception_expired'):
                publisher.execute('example/keep', SHA, artifacts, release=True)
        self.assertFalse(any(command[1] == 'push' for command in calls))

    def test_archived_config_mismatch_blocks_before_publication(self):
        for arch in DIGESTS:
            calls = []
            changed = {**CONFIGS, arch: 'sha256:' + '0' * 64}
            with self.subTest(arch=arch), self.publication_fixture(
                    calls, config_digests=changed) as (artifacts, _evidence):
                with self.assertRaisesRegex(ValueError, 'release evidence config differs'):
                    publisher.execute('example/keep', SHA, artifacts, release=True)
            self.assertFalse(any(command[1] in ('login', 'tag', 'push', 'manifest') for command in calls))

    def test_reviewed_source_change_before_stable_push_is_blocked(self):
        calls = []

        def change_source(command):
            if command[1:3] == ['manifest', 'create'] and command[3] == 'example/keep:stable':
                Path('scripts/python_security_patches.json').write_bytes(b'changed source')

        with self.publication_fixture(calls, before_command=change_source) as (artifacts, _evidence):
            with self.assertRaisesRegex(ValueError, 'verified-fixed review must be refreshed'):
                publisher.execute('example/keep', SHA, artifacts, release=True)
        self.assertNotIn(['docker', 'manifest', 'push', '--purge', 'example/keep:stable'], calls)

    def test_release_refuses_wrong_ref_or_confirmation_before_registry(self):
        for changes in ({'GITHUB_REF': 'refs/heads/feature/test'},
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
        for ref in ('refs/heads/main', 'refs/heads/feature/test'):
            with patch.dict(os.environ, {**ENV, 'GITHUB_EVENT_NAME': 'push', 'GITHUB_REF': ref}):
                with self.assertRaises(ValueError):
                    publisher.require_manual_dispatch(True)
