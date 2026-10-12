#!/usr/bin/env python3
"""Optional local Keep maintenance helper; Python 3.12+, no ambient credentials.

Install stages verified source only. Enrollment is a distinct operator action
after owner setup. Importing this module performs no Docker or host operation.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict
import hashlib
import os
from pathlib import Path
import re
import sys
import time
from types import SimpleNamespace
import uuid

from maintenance_protocol import (Enrollment, ImageIdentity, ProtocolError, TERMINAL,
                                  canonical, canonical_uuid, exact_fields, parse_json)
from private_store import (Journal, Profile, StorageError, create_private_paths, operation_lock)
from host_engine import BoundedRunner, EngineError, HostEngine, Plan
from helper_bundle import (BundleError, FILES, MAX_FILE, create_root, published_bundle, stage_bundle)

MINIMUM_PYTHON = (3, 12)
MAX_ACCEPTED = 2048


def require_python(version=None):
    if tuple((version or sys.version_info)[:2]) < MINIMUM_PYTHON:
        raise BundleError('The optional maintenance helper requires Python 3.12 or newer')


def require_qualified_host():
    if sys.platform != 'linux' or os.name != 'posix':
        raise StorageError('In-app maintenance requires a qualified Linux Docker host')


def profile_document(profile):
    return {name: ([str(value) for value in getattr(profile, name)] if name == 'compose_files'
                   else str(getattr(profile, name)) if isinstance(getattr(profile, name), Path)
                   else getattr(profile, name)) for name in Profile.__dataclass_fields__}


def read_profile(value, paths):
    exact_fields(value, Profile.__dataclass_fields__)
    if not isinstance(value['compose_files'], list) or not all(isinstance(item, str) for item in value['compose_files']):
        raise StorageError('Enrolled profile configuration is invalid')
    path_names = ('installation', 'state', 'docker_executable', 'docker_config', 'env_file')
    if any(not isinstance(value[name], str) for name in path_names):
        raise StorageError('Enrolled profile paths are invalid')
    result = dict(value)
    for name in path_names:
        result[name] = Path(result[name])
    result['compose_files'] = tuple(Path(item) for item in value['compose_files'])
    if result['legacy_lock'] is not None:
        if not isinstance(result['legacy_lock'], str):
            raise StorageError('Enrolled legacy lock is invalid')
        result['legacy_lock'] = Path(result['legacy_lock'])
    return Profile(**result).validate(paths)


def pin_executable(paths, path):
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise StorageError('Docker executable must be an absolute canonical file')
    if os.name == 'nt':
        paths.check(path, private=False)
    else:
        info = path.lstat()
        import stat
        if (not stat.S_ISREG(info.st_mode) or info.st_uid not in (0, os.geteuid())
                or info.st_mode & 0o022 or not info.st_mode & 0o111):
            raise StorageError('Docker executable is untrusted')
        for ancestor in path.parents:
            metadata = ancestor.lstat()
            if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid not in (0, os.geteuid())
                    or metadata.st_mode & 0o022 and not metadata.st_mode & stat.S_ISVTX):
                raise StorageError('Docker executable ancestor is untrusted')
    return path


def capture_profile(paths, *, installation, state, docker_executable, docker_config,
                    context='default', project='keep', volume='keep_keep-data', runner=None):
    """Capture operator-selected local configuration, before any daemon request."""
    installation = paths.check(installation, directory=True, private=False)
    state = create_root(paths, state)
    executable = pin_executable(paths, docker_executable)
    config = paths.check(docker_config, directory=True, private=False)
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', context):
        raise StorageError('Docker context is invalid')
    for name in ('compose.yml', '.env'):
        paths.check(installation / name)
    bootstrap = SimpleNamespace(installation=installation, state=state,
        docker_executable=executable, docker_config=config)
    runner = runner or BoundedRunner(bootstrap, paths=paths)
    base = (str(executable), '--context', context)
    endpoint = parse_json(runner.run(Plan('local context endpoint', (*base, 'context', 'inspect', context,
        '--format', '{{json .Endpoints.docker.Host}}'), 30, 4096)))
    if (not isinstance(endpoint, str) or not (endpoint.startswith('unix:///') or endpoint.startswith('npipe:////./pipe/'))
            or any(ord(character) < 32 for character in endpoint)):
        raise StorageError('Only a local Docker engine may be enrolled')
    daemon = parse_json(runner.run(Plan('local daemon identity', (*base, 'info', '--format', '{{json .ID}}'), 30, 4096)))
    legacy = installation / '.git' / 'keep-deploy.lock' if (installation / '.git').exists() else None
    return Profile(installation, state, executable, config, context, endpoint, daemon,
        project, volume, (installation / 'compose.yml',), installation / '.env', legacy).validate(paths)


def observation_document(observation):
    return {'image': observation.image.as_dict(), 'hello': observation.hello,
            'configuration': observation.configuration, 'containers': observation.containers}


class HostState:
    def __init__(self, paths, root):
        self.paths, self.root = paths, paths.check(root, directory=True)

    def source_proof(self, source=None):
        source = self.paths.check(source or Path(__file__).parent, directory=True)
        proof = parse_json(self.paths.read(source / 'bundle-proof.json', limit=MAX_FILE), MAX_FILE)
        exact_fields(proof, ('format', 'version', 'revision', 'archive_sha256', 'manifest'))
        if source != self.root / 'releases' / proof['revision']:
            raise StorageError('Helper source is outside its verified private staging directory')
        manifest = proof['manifest']
        if (not isinstance(manifest, dict) or manifest.get('revision') != proof['revision']
                or manifest.get('version') != proof['version'] or manifest.get('minimum_python') != '3.12'
                or not isinstance(manifest.get('files'), dict) or set(manifest['files']) != set(FILES)):
            raise StorageError('Helper source proof is invalid')
        for name in FILES:
            body = self.paths.read(source / name, limit=MAX_FILE)
            if manifest['files'][name] != {'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest()}:
                raise StorageError('Staged helper source changed')
        return proof

    def pending(self):
        path = self.root / 'enrollment-pending.json'
        return parse_json(self.paths.read(path, limit=65536), 65536) if path.exists() or path.is_symlink() else None

    def active(self):
        path = self.root / 'enrollment-active.json'
        if not path.exists() and not path.is_symlink():
            return None
        active, pending = parse_json(self.paths.read(path, limit=65536), 65536), self.pending()
        if (not isinstance(active, dict) or active.get('schema') != 'keep.host-activation.v1'
                or not pending or active.get('enrollment_sha256') != hashlib.sha256(canonical(pending)).hexdigest()
                or active.get('install_id') != pending['enrollment']['install_id']):
            raise StorageError('Host activation proof is unavailable')
        return active, pending

    def credentials(self, pending):
        exact_fields(pending, ('schema', 'profile', 'enrollment', 'observation', 'source_proof'))
        value = pending['enrollment']
        exact_fields(value, ('install_id', 'owner_id', 'epoch', 'key'))
        if pending['schema'] != 'keep.host-enrollment.v1' or not isinstance(value['key'], str) or not re.fullmatch(r'[a-f0-9]{64}', value['key']):
            raise StorageError('Private enrollment record is invalid')
        return read_profile(pending['profile'], self.paths), Enrollment(value['install_id'], value['owner_id'], value['epoch'], bytes.fromhex(value['key']))

    def retain_request(self, mailbox, request):
        data = mailbox.request_envelope(request)
        if mailbox.accepted_request(data) != request:
            raise ProtocolError('Original request identity differs')
        root = self.root / 'accepted-requests'
        if not root.exists():
            self.paths.mkdir(root)
        self.paths.check(root, directory=True)
        files = list(root.iterdir())
        path = root / (canonical_uuid(request.request_id) + '.json')
        if path.exists() or path.is_symlink():
            if self.paths.read(path, limit=65536) != data:
                raise StorageError('Accepted request may not be replaced')
        else:
            if len(files) >= MAX_ACCEPTED:
                raise StorageError('Accepted request retention requires operator review')
            self.paths.publish(path, data)

    def unfinished(self, mailbox):
        root = self.root / 'operations'
        if not root.exists():
            return []
        self.paths.check(root, directory=True)
        entries = list(root.iterdir())
        if len(entries) > MAX_ACCEPTED:
            raise StorageError('Operation retention requires operator review')
        unfinished = []
        for entry in entries:
            identifier = canonical_uuid(entry.name)
            self.paths.check(entry, directory=True)
            data = self.paths.read(self.root / 'accepted-requests' / (identifier + '.json'), limit=65536)
            request = mailbox.accepted_request(data)
            if request.request_id != identifier:
                raise StorageError('Recovery request identity differs')
            records = Journal(self.paths, self.root, identifier, request.payload_sha256).records()
            delivered = False
            receipt_path = entry / 'app-progress-receipt.json'
            if records and records[-1]['phase'] in TERMINAL and receipt_path.exists():
                receipt = parse_json(self.paths.read(receipt_path, limit=65536), 65536)
                delivered = (isinstance(receipt, dict) and type(receipt.get('sequence')) is int
                    and receipt == {'request_id': identifier,
                    'payload_sha256': request.payload_sha256,
                    'sequence': records[-1]['sequence'], 'phase': records[-1]['phase']})
            if not records or records[-1]['phase'] not in TERMINAL or not delivered:
                unfinished.append(request)
        if len(unfinished) > 1:
            raise StorageError('Multiple unfinished maintenance operations require operator review')
        return unfinished


class Backend:
    def __init__(self, paths, profile, enrollment=None):
        from host_mailbox import HostMailbox
        self.mailbox = HostMailbox(paths, profile, enrollment)
        self.paths, self.profile, self.enrollment = paths, profile, enrollment
        self.target = None

    def engine(self):
        from docker_adapter import create_docker_adapter
        adapter = create_docker_adapter(self.paths, self.profile, self.enrollment, mailbox=self.mailbox)
        return HostEngine(self.paths, self.profile, adapter)


def enroll(paths, profile, *, source_proof, backend_factory=Backend):
    require_qualified_host()
    state = HostState(paths, profile.state)
    with operation_lock(paths, profile.state / 'agent.lock'):
        active = state.active()
        if active:
            saved_profile, enrollment = state.credentials(active[1])
            if profile_document(saved_profile) != profile_document(profile):
                raise StorageError('Existing enrollment profile differs and was retained')
            backend_factory(paths, profile, enrollment).mailbox.probe()
            return {'enrolled': True, 'install_id': enrollment.install_id, 'state': 'already_enrolled'}
        pending = state.pending()
        if pending:
            saved_profile, enrollment = state.credentials(pending)
            if profile_document(saved_profile) != profile_document(profile):
                raise StorageError('Pending enrollment profile differs and was retained')
            backend = backend_factory(paths, profile, enrollment)
            original = pending['observation']
            from host_mailbox import Observation
            observation = Observation(ImageIdentity.from_dict(original['image']), original['hello'],
                                      original['configuration'], original['containers'])
        else:
            backend = backend_factory(paths, profile)
            observation = backend.mailbox.probe()
            if (observation.hello.get('owner_active') is not True or observation.hello.get('supported') is not True
                    or observation.hello.get('enrolled') is not False
                    or observation.image.version != source_proof['version'] or observation.image.revision != source_proof['revision']):
                raise StorageError('Current installation is not eligible for helper enrollment')
            enrollment = Enrollment.create(observation.hello['owner_id'])
            pending = {'schema': 'keep.host-enrollment.v1', 'profile': profile_document(profile),
                'enrollment': {'install_id': enrollment.install_id, 'owner_id': enrollment.owner_id,
                               'epoch': enrollment.epoch, 'key': enrollment.key.hex()},
                'observation': observation_document(observation), 'source_proof': source_proof}
            paths.publish(profile.state / 'enrollment-pending.json', canonical(pending))
        observed = backend.mailbox.enroll(enrollment, observation)
        if (observed.image != observation.image or observed.configuration != observation.configuration
                or observed.containers != observation.containers or observed.hello.get('owner_id') != enrollment.owner_id
                or observed.hello.get('credential_version') != observation.hello.get('credential_version')
                or observed.hello.get('config_generation') != observation.hello.get('config_generation')):
            raise StorageError('Enrollment activation observation differs')
        configuration = profile.state / 'configuration.json'
        encoded = canonical(observed.configuration)
        if configuration.exists() or configuration.is_symlink():
            if paths.read(configuration) != encoded:
                raise StorageError('Existing enrolled configuration differs and was retained')
        else:
            paths.publish(configuration, encoded)
        proof = {'schema': 'keep.host-activation.v1', 'install_id': enrollment.install_id,
            'epoch': enrollment.epoch, 'enrollment_sha256': hashlib.sha256(canonical(pending)).hexdigest(),
            'profile_sha256': hashlib.sha256(canonical(profile_document(profile))).hexdigest(),
            'docker_context': profile.docker_context, 'daemon_id': profile.daemon_id,
            'architecture': observed.image.architecture, 'project': profile.project, 'volume': profile.volume,
            'image': observed.image.as_dict(), 'containers': observed.containers, 'configuration': observed.configuration}
        paths.publish(profile.state / 'enrollment-active.json', canonical(proof))
        return {'enrolled': True, 'install_id': enrollment.install_id, 'state': 'enrolled'}


def load_backend(paths, root, *, backend_factory=Backend):
    state = HostState(paths, root)
    active = state.active()
    if not active:
        raise StorageError('Helper enrollment is not active')
    profile, enrollment = state.credentials(active[1])
    if profile.state != state.root:
        raise StorageError('Helper state path differs from its enrollment')
    return state, backend_factory(paths, profile, enrollment)


def poll_once(state, backend, *, check_update=False):
    mailbox = backend.mailbox
    unfinished = state.unfinished(mailbox)
    if unfinished:
        request = unfinished[0]
        record = backend.engine().resume(request)
        mailbox.publish_status(request, record)
        return {'state': record['phase'], 'request_id': request.request_id}
    observed = mailbox.probe()
    if (backend.target is not None and backend.target.architecture == observed.image.architecture
            and tuple(map(int, backend.target.version.split('.'))) <= tuple(map(int, observed.image.version.split('.')))):
        backend.target = None
    if check_update:
        try:
            backend.target = mailbox.resolver.latest(observed.image.architecture, observed.image.version)
        except EngineError:
            backend.target = None
    mailbox.advisory(target=backend.target, active_request_id=None)
    request = mailbox.poll()
    if request is None:
        return {'state': 'ready', 'version': observed.image.version}
    state.retain_request(mailbox, request)
    record = backend.engine().execute(request)
    mailbox.publish_status(request, record)
    return {'state': record['phase'], 'request_id': request.request_id}


def main(argv=None, *, paths=None, backend_factory=Backend, sleep=time.sleep, now=time.monotonic):
    require_python()
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    install = sub.add_parser('install', help='stage verified optional helper source; never enroll or start services')
    install.add_argument('--state', type=Path, required=True)
    install.add_argument('--version', required=True)
    for name in ('enroll', 'status', 'worker'):
        command = sub.add_parser(name)
        command.add_argument('--state', type=Path, required=True)
        if name == 'enroll':
            command.add_argument('--installation', type=Path, required=True)
            command.add_argument('--docker-executable', type=Path, required=True)
            command.add_argument('--docker-config', type=Path, required=True)
            command.add_argument('--context', default='default')
            command.add_argument('--project', default='keep')
            command.add_argument('--volume', default='keep_keep-data')
        if name == 'worker':
            command.add_argument('--once', action='store_true')
    args = parser.parse_args(argv)
    try:
        if args.action in ('enroll', 'worker'):
            require_qualified_host()
        paths = paths or create_private_paths()
        if args.action == 'install':
            body, version, revision, digest = published_bundle(args.version)
            staged = stage_bundle(paths, args.state, body, version=version, revision=revision, expected_sha256=digest)
            print(canonical({'state': 'staged', 'version': version, 'revision': revision}).decode())
            return 0
        if args.action == 'enroll':
            profile = capture_profile(paths, installation=args.installation, state=args.state,
                docker_executable=args.docker_executable, docker_config=args.docker_config,
                context=args.context, project=args.project, volume=args.volume)
            proof = HostState(paths, args.state).source_proof()
            result = enroll(paths, profile, source_proof=proof, backend_factory=backend_factory)
            print(canonical(result).decode())
            return 0
        state, backend = load_backend(paths, args.state, backend_factory=backend_factory)
        if args.action == 'status':
            observed = backend.mailbox.probe()
            unfinished = state.unfinished(backend.mailbox)
            result = {'enrolled': True, 'state': 'operation_pending' if unfinished else 'ready',
                      'version': observed.image.version,
                      'request_id': unfinished[0].request_id if unfinished else None}
            print(canonical(result).decode())
            return 0
        with operation_lock(paths, args.state / 'agent.lock'):
            next_check = 0
            while True:
                try:
                    checking = now() >= next_check
                    result = poll_once(state, backend, check_update=checking)
                    if checking:
                        next_check = now() + 3600
                    if args.once:
                        print(canonical(result).decode())
                        return 0
                except (ProtocolError, StorageError, EngineError, BundleError, OSError):
                    if args.once:
                        raise
                    # Fixed message only: no command output, paths, keys or env.
                    print('Keep maintenance helper is held; inspect private status.', file=sys.stderr)
                    next_check = max(next_check, now() + 3600)
                sleep(15)
    except (ProtocolError, StorageError, EngineError, BundleError, OSError, ValueError):
        print('Keep maintenance helper is unavailable; enrollment and recovery records were retained.', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
