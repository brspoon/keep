from dataclasses import dataclass, replace
import hashlib
import io
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import uuid

import host_cli as cli
import helper_bundle
from maintenance_protocol import Enrollment, ImageIdentity, ProtocolError, canonical, signed, verify_request
from private_store import Journal, Profile, StorageError, create_private_paths


@dataclass
class Observation:
    image: ImageIdentity
    hello: dict
    configuration: dict
    containers: dict


class CliTests(unittest.TestCase):
    def setUp(self):
        # Transport/state fixtures exercise the qualified Linux contract.
        # Native host rejection is tested separately without this substitution.
        qualification = patch.object(cli, 'require_qualified_host')
        qualification.start()
        self.addCleanup(qualification.stop)
        self.directory = tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve())
        self.addCleanup(self.directory.cleanup)
        self.paths = create_private_paths()
        self.root = helper_bundle.create_root(self.paths, Path(self.directory.name).resolve() / 'private')
        self.state = self.paths.mkdir(self.root / 'state')
        self.installation = self.paths.mkdir(self.root / 'installation')
        self.config = self.paths.mkdir(self.root / 'docker-config')
        for name, body in (('.env', b'KEEP_IMAGE=brspoon/keep:2.26.0\n'), ('compose.yml', b'name: keep\n')):
            self.paths.publish(self.installation / name, body)
        # Docker transport is mocked; the enrolled executable belongs to this
        # fixture rather than depending on hosted Python's installation mode.
        self.executable = self.root / ('docker.exe' if os.name == 'nt' else 'docker')
        self.paths.publish(self.executable, b'#!/bin/sh\nexit 99\n')
        os.chmod(self.executable, 0o500)
        self.profile = Profile(self.installation, self.state, self.executable, self.config, 'default',
            'npipe:////./pipe/docker_engine' if os.name == 'nt' else 'unix:///private/tmp/synthetic-docker.sock',
            'synthetic-daemon', 'keep', 'keep_keep-data', (self.installation / 'compose.yml',), self.installation / '.env')
        self.image = ImageIdentity('sha256:' + 'a' * 64, 'sha256:' + 'b' * 64, 'sha256:' + 'c' * 64, '2.26.0', 'd' * 40, 'amd64')
        self.observed = Observation(self.image, {'owner_id': 'owner', 'credential_version': 0,
            'owner_active': True, 'supported': True, 'enrolled': False, 'config_generation': 'e' * 64},
            {str(self.installation / name): hashlib.sha256(body).hexdigest()
             for name, body in (('.env', b'KEEP_IMAGE=brspoon/keep:2.26.0\n'), ('compose.yml', b'name: keep\n'))},
            {'keep-app': '1' * 64, 'keep-digest': '2' * 64})
        self.proof = {'version': self.image.version, 'revision': self.image.revision, 'archive_sha256': 'f' * 64}
        self.created = []
        class Mailbox:
            def __init__(inner):
                inner.probe = Mock(return_value=self.observed)
                inner.advisory = Mock()
                inner.poll = Mock(return_value=None)
                inner.publish_status = Mock()
                inner.resolver = SimpleNamespace(latest=Mock(return_value=None))
                inner.enroll = Mock(side_effect=lambda enrollment, observation: replace(observation,
                    hello={**observation.hello, 'enrolled': True}))
        def factory(paths, profile, enrollment=None):
            value = SimpleNamespace(mailbox=Mailbox(), target=None,
                engine=Mock(return_value=SimpleNamespace(execute=Mock(), resume=Mock())))
            self.created.append(value)
            return value
        self.factory = factory

    def enroll(self):
        return cli.enroll(self.paths, self.profile, source_proof=self.proof, backend_factory=self.factory)

    def test_key_is_created_only_after_successful_probe_and_never_returned(self):
        with patch.object(Enrollment, 'create', wraps=Enrollment.create) as create:
            result = self.enroll()
            create.assert_called_once_with('owner')
        state = cli.HostState(self.paths, self.state)
        pending = state.pending()
        self.assertEqual(len(pending['enrollment']['key']), 64)
        self.assertNotIn(pending['enrollment']['key'], str(result))
        self.assertTrue(state.active())
        self.paths.check(self.state / 'enrollment-pending.json')
        self.paths.check(self.state / 'enrollment-active.json')

    def test_failed_probe_never_creates_credentials_or_activation(self):
        backend = self.factory(self.paths, self.profile)
        backend.mailbox.probe.side_effect = ProtocolError('synthetic topology failure')
        with patch.object(Enrollment, 'create') as create, self.assertRaises(ProtocolError):
            cli.enroll(self.paths, self.profile, source_proof=self.proof, backend_factory=lambda *args: backend)
        create.assert_not_called()
        self.assertFalse((self.state / 'enrollment-pending.json').exists())

    def test_owner_inactive_or_unsupported_never_creates_credentials(self):
        for name in ('owner_active', 'supported'):
            backend = self.factory(self.paths, self.profile)
            backend.mailbox.probe.return_value = replace(self.observed, hello={**self.observed.hello, name: False})
            with self.subTest(name=name), self.assertRaises(StorageError):
                cli.enroll(self.paths, self.profile, source_proof=self.proof, backend_factory=lambda *args: backend)
            self.assertFalse((self.state / 'enrollment-pending.json').exists())

    def test_pending_record_is_durable_before_secret_is_provisioned_and_lost_reply_is_held(self):
        backend = self.factory(self.paths, self.profile)
        def enroll(enrollment, observation):
            pending = cli.HostState(self.paths, self.state).pending()
            self.assertEqual(pending['enrollment']['key'], enrollment.key.hex())
            raise ProtocolError('lost reply')
        backend.mailbox.enroll.side_effect = enroll
        with self.assertRaises(ProtocolError):
            cli.enroll(self.paths, self.profile, source_proof=self.proof, backend_factory=lambda *args: backend)
        self.assertTrue((self.state / 'enrollment-pending.json').exists())
        self.assertFalse((self.state / 'enrollment-active.json').exists())

    def test_changed_activation_topology_holds_enrollment_without_touching_installation(self):
        original = {path.name: path.read_bytes() for path in (self.profile.env_file, *self.profile.compose_files)}
        backend = self.factory(self.paths, self.profile)
        backend.mailbox.enroll.side_effect = None
        backend.mailbox.enroll.return_value = replace(self.observed, containers={'keep-app': '3' * 64, 'keep-digest': '2' * 64})
        with self.assertRaises(StorageError):
            cli.enroll(self.paths, self.profile, source_proof=self.proof, backend_factory=lambda *args: backend)
        self.assertFalse((self.state / 'enrollment-active.json').exists())
        self.assertEqual({path.name: path.read_bytes() for path in (self.profile.env_file, *self.profile.compose_files)}, original)

    def test_enrollment_rerun_preserves_key_and_existing_profile(self):
        first = self.enroll()
        pending = self.paths.read(self.state / 'enrollment-pending.json')
        result = self.enroll()
        self.assertEqual(result['install_id'], first['install_id'])
        self.assertEqual(result['state'], 'already_enrolled')
        self.assertEqual(self.paths.read(self.state / 'enrollment-pending.json'), pending)
        with self.assertRaises(StorageError):
            cli.enroll(self.paths, replace(self.profile, project='another'), source_proof=self.proof, backend_factory=self.factory)

    def test_activation_tampering_and_missing_private_key_fail_closed(self):
        self.enroll()
        self.paths.publish(self.state / 'enrollment-active.json', canonical({'schema': 'keep.host-activation.v1'}), overwrite=True)
        with self.assertRaises(StorageError):
            cli.load_backend(self.paths, self.state, backend_factory=self.factory)

    def test_remote_context_is_rejected_before_daemon_contact(self):
        runner = SimpleNamespace(run=Mock(return_value=canonical('tcp://remote.example:2375')))
        with self.assertRaises(StorageError):
            cli.capture_profile(self.paths, installation=self.installation, state=self.state,
                docker_executable=self.executable, docker_config=self.config, runner=runner)
        self.assertEqual(runner.run.call_count, 1)
        self.assertIn('context', runner.run.call_args.args[0].argv)

    def test_python_minimum_is_explicit_and_does_not_change_the_normal_installer_minimum(self):
        cli.require_python((3, 12))
        for version in ((3, 9), (3, 10), (3, 11)):
            with self.assertRaises(helper_bundle.BundleError):
                cli.require_python(version)

    def test_check_failure_keeps_local_restart_advisory_available(self):
        self.enroll()
        state, backend = cli.load_backend(self.paths, self.state, backend_factory=self.factory)
        backend.mailbox.resolver.latest.side_effect = cli.EngineError('synthetic network outage')
        self.assertEqual(cli.poll_once(state, backend, check_update=True)['state'], 'ready')
        backend.mailbox.advisory.assert_called_once_with(target=None, active_request_id=None)

    def test_verified_target_survives_ordinary_polls_without_extra_release_requests(self):
        self.enroll()
        state, backend = cli.load_backend(self.paths, self.state, backend_factory=self.factory)
        target = replace(self.image, version='2.27.0')
        backend.mailbox.resolver.latest.return_value = target
        cli.poll_once(state, backend, check_update=True)
        cli.poll_once(state, backend)
        backend.mailbox.resolver.latest.assert_called_once()
        self.assertEqual(backend.mailbox.advisory.call_args.kwargs['target'], target)

    def test_installed_cached_target_is_cleared_before_next_advisory(self):
        self.enroll()
        state, backend = cli.load_backend(self.paths, self.state, backend_factory=self.factory)
        backend.target = self.image
        cli.poll_once(state, backend)
        self.assertIsNone(backend.target)
        backend.mailbox.advisory.assert_called_once_with(target=None, active_request_id=None)

    def accepted(self):
        enrollment = Enrollment.create('owner')
        body = {'protocol': 'keep.maintenance.v1', 'install_id': enrollment.install_id,
            'owner_id': enrollment.owner_id, 'epoch': enrollment.epoch,
            'request_id': str(uuid.uuid4()), 'operation': 'restart', 'credential_version': 0,
            'issued_at': 1000, 'expires_at': 1300, 'nonce': '1' * 64,
            'expected': self.image.as_dict(), 'target': None}
        raw = signed(enrollment, body)
        request = verify_request(enrollment, raw, now=1100)
        mailbox = SimpleNamespace(request_envelope=lambda candidate: raw,
            accepted_request=lambda data: verify_request(enrollment, data, now=1000),
            verify_live=lambda data: verify_request(enrollment, data, now=2000))
        state = cli.HostState(self.paths, self.state)
        state.retain_request(mailbox, request)
        journal = Journal(self.paths, self.state, request.request_id, request.payload_sha256)
        return state, mailbox, request, journal

    def test_terminal_operation_retries_only_missing_final_progress_delivery(self):
        state, mailbox, request, journal = self.accepted()
        journal.append('accepted')
        final = journal.append('failed')
        self.assertEqual(state.unfinished(mailbox), [request])
        receipt = {'request_id': request.request_id, 'payload_sha256': request.payload_sha256,
            'sequence': final['sequence'], 'phase': final['phase']}
        path = self.state / 'operations' / request.request_id / 'app-progress-receipt.json'
        self.paths.publish(path, canonical({**receipt, 'sequence': 0}))
        self.assertEqual(state.unfinished(mailbox), [request])
        self.paths.publish(path, canonical(receipt), overwrite=True)
        self.assertEqual(state.unfinished(mailbox), [])

    def test_recovery_keeps_original_expired_request_and_duplicate_retention_is_exact(self):
        state, mailbox, request, journal = self.accepted()
        journal.append('accepted')
        state.retain_request(mailbox, request)
        self.assertEqual(state.unfinished(mailbox), [request])
        # A freshly submitted expired envelope is rejected, while its original
        # authenticated journal remains eligible for bounded crash recovery.
        raw = mailbox.request_envelope(request)
        with self.assertRaises(ProtocolError):
            mailbox.verify_live(raw)
        original = self.paths.read(self.state / 'accepted-requests' / (request.request_id + '.json'))
        mailbox.request_envelope = lambda candidate: b'changed'
        with self.assertRaises(ProtocolError):
            state.retain_request(mailbox, request)
        self.assertEqual(self.paths.read(self.state / 'accepted-requests' / (request.request_id + '.json')), original)



class HostQualificationTests(unittest.TestCase):
    def test_unqualified_hosts_cannot_enroll_or_poll_services(self):
        for platform in ('darwin', 'win32'):
            with self.subTest(platform=platform), patch.object(cli.sys, 'platform', platform), \
                 patch.object(cli, 'HostState') as state, patch.object(cli, 'capture_profile') as capture, \
                 patch.object(cli, 'create_private_paths') as paths, patch.object(cli, 'load_backend') as load:
                with self.assertRaisesRegex(StorageError, 'qualified Linux Docker host'):
                    cli.enroll(Mock(), Mock(), source_proof={}, backend_factory=Mock())
                for args in (
                    ['worker', '--state', '/synthetic/private', '--once'],
                    ['enroll', '--state', '/synthetic/private', '--installation', '/synthetic/keep',
                     '--docker-executable', '/synthetic/docker', '--docker-config', '/synthetic/config'],
                ):
                    with patch('sys.stderr', new=io.StringIO()):
                        self.assertEqual(cli.main(args), 2)
                state.assert_not_called(); capture.assert_not_called()
                paths.assert_not_called(); load.assert_not_called()

    def test_linux_qualification_does_not_touch_docker_or_state(self):
        with patch.object(cli.sys, 'platform', 'linux'), patch.object(cli.os, 'name', 'posix'), \
             patch.object(cli, 'BoundedRunner') as runner, patch.object(cli, 'HostState') as state:
            self.assertIsNone(cli.require_qualified_host())
            runner.assert_not_called(); state.assert_not_called()


if __name__ == '__main__':
    unittest.main()
