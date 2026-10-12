"""Fixed mailbox, durable admission, and owner maintenance controls.

The control database and signing key survive main-database restoration.
This module imports no application or host Docker access.
"""
from __future__ import annotations

from contextlib import closing, contextmanager, nullcontext
from contextvars import ContextVar
from dataclasses import dataclass
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import sqlite3
import stat
import time

from maintenance_protocol import (Enrollment, HASH, ImageIdentity, MAX_ENVELOPE,
    PHASES, ProtocolError, canonical, canonical_uuid, exact_fields, parse_json,
    signed, verify, verify_request)
from private_store import ALLOWED_TRANSITIONS, PrivatePaths, StorageError


FIXED_ROOT = Path('/app/data/.maintenance')
MAX_DRAIN = 20
HELPER_FRESH_SECONDS = 90
_depth = ContextVar('keep_maintenance_leases', default={})


class MaintenanceError(RuntimeError):
    def __init__(self, code, status=503):
        self.code, self.status = code, status
        super().__init__(code)


@dataclass(frozen=True)
class Authority:
    owner_id: str
    credential_version: int
    active: bool


@dataclass(frozen=True)
class Hooks:
    authority: object                 # Fresh read-only active Plex owner record.
    config_generation: object         # Fixed effective-settings digest, no secrets.
    version: object                   # Packaged VERSION, not a request argument.
    supported: object = lambda: False # Enabled only after topology/native qualification.


class Store:
    def __init__(self, *, root=FIXED_ROOT, initialize=False, paths=None):
        self.root, self.paths = Path(root), paths or PrivatePaths()
        if initialize:
            self.initialize()

    def initialize(self):
        if not self.root.exists():
            try:
                self.paths.mkdir(self.root)
            except FileExistsError:
                # Paired services may initialize their shared control state
                # concurrently; validate the winner before taking its lock.
                self.paths.check(self.root, directory=True)
        self.paths.check(self.root, directory=True)
        with self._lock('initialize.lock', exclusive=True, timeout=MAX_DRAIN):
            if (self.root / 'control.sqlite3').exists():
                _, gate = self._rows()
                if not gate:
                    raise MaintenanceError('state_unavailable')
                return
            if set(path.name for path in self.root.iterdir()) - {'initialize.lock'}:
                raise MaintenanceError('state_unavailable')
            self._initialize_control()

    def _initialize_control(self):
        with closing(self._connect()) as db, db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS enrollment(id INTEGER PRIMARY KEY CHECK(id=1),
                    install_id TEXT NOT NULL,owner_id TEXT NOT NULL,epoch INTEGER NOT NULL,
                    image_json TEXT NOT NULL,target_json TEXT,helper_seen REAL,
                    host_active_request TEXT);
                CREATE TABLE IF NOT EXISTS operations(request_id TEXT PRIMARY KEY,
                    payload BLOB NOT NULL,payload_sha256 TEXT UNIQUE NOT NULL,nonce TEXT UNIQUE NOT NULL,
                    state TEXT NOT NULL,config_generation TEXT NOT NULL,created_at REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS gate(id INTEGER PRIMARY KEY CHECK(id=1),
                    closed INTEGER NOT NULL,request_id TEXT,drained INTEGER NOT NULL);
                INSERT OR IGNORE INTO gate VALUES (1,0,NULL,0);
                CREATE TABLE IF NOT EXISTS progress(request_id TEXT PRIMARY KEY,
                    sequence INTEGER NOT NULL,envelope BLOB NOT NULL);
            ''')

    def _connect(self, *, read_only=False):
        self.paths.check(self.root, directory=True)
        path = self.root / 'control.sqlite3'
        if path.exists() or path.is_symlink():
            self.paths.check(path)
        db = sqlite3.connect(path.absolute().as_uri() + '?mode=ro', uri=True, timeout=.25) if read_only else sqlite3.connect(path, timeout=.25)
        db.row_factory = sqlite3.Row
        if not read_only:
            os.chmod(path, 0o600)
            db.execute('PRAGMA synchronous=FULL')
        return db

    @contextmanager
    def _lock(self, name, *, exclusive=False, timeout=0):
        if name not in ('initialize.lock', 'work.lock', 'authority.lock', 'startup.lock'):
            raise MaintenanceError('state_unavailable')
        self.paths.check(self.root, directory=True)
        path = self.root / name
        if path.exists() or path.is_symlink():
            self.paths.check(path)
        fd = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0), 0o600)
        try:
            self.paths.check(path)
            info, current = os.fstat(fd), path.lstat()
            if not stat.S_ISREG(info.st_mode) or (info.st_dev, info.st_ino) != (current.st_dev, current.st_ino):
                raise MaintenanceError('state_unavailable')
            deadline = time.monotonic() + timeout
            while True:
                try:
                    fcntl.flock(fd, (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH) | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise MaintenanceError('busy', 409)
                    time.sleep(.01)
            yield
        finally:
            os.close(fd)

    def _exists(self):
        # Missing unenrolled feature state is passive. Unsafe/corrupt existing
        # state raises rather than silently reopening maintenance admission.
        if not self.root.exists() and not self.root.is_symlink():
            return False
        self.paths.check(self.root, directory=True)
        if not (self.root / 'control.sqlite3').exists():
            raise MaintenanceError('state_unavailable')
        return True

    def _rows(self):
        if not self._exists():
            return None, None
        with closing(self._connect(read_only=True)) as db:
            enrollment = db.execute('SELECT * FROM enrollment WHERE id=1').fetchone()
            gate = db.execute('SELECT * FROM gate WHERE id=1').fetchone()
        return dict(enrollment) if enrollment else None, dict(gate) if gate else None

    def enrollment(self, row=None):
        if row is None:
            row, _ = self._rows()
        if row is None:
            raise MaintenanceError('not_enrolled', 409)
        # Validate the stored epoch before it participates in a fixed key name.
        Enrollment(row['install_id'], row['owner_id'], row['epoch'], bytes(32))
        record = parse_json(self.paths.read(self.root / ('key-' + str(row['epoch']) + '.json')))
        exact_fields(record, ('install_id', 'owner_id', 'epoch', 'key'))
        if any(record[field] != row[field] for field in ('install_id', 'owner_id', 'epoch')):
            raise MaintenanceError('state_unavailable')
        key = record['key']
        if not isinstance(key, str) or not HASH.fullmatch(key):
            raise MaintenanceError('state_unavailable')
        return Enrollment(record['install_id'], record['owner_id'], record['epoch'], bytes.fromhex(key))

    @contextmanager
    def work(self, *, authority=False):
        """Hold across a complete request/callback, including upstream I/O.

        Nesting reuses the same lease; never release before SMTP/Seerr/probe
        completion. Authority-changing work additionally takes the exclusive
        authority lock so a queued request observes fresh stable ownership.
        """
        key = str(self.root)
        current = _depth.get()
        if key in current:
            if authority and not current[key]:
                raise MaintenanceError('authority_lock_required')
            yield
            return
        if not self._exists():
            yield
            return
        with self._lock('work.lock'), self._lock('authority.lock', exclusive=authority, timeout=MAX_DRAIN):
            _, gate = self._rows()
            if not gate or gate['closed']:
                raise MaintenanceError('maintenance_in_progress')
            token = _depth.set({**current, key: authority})
            try:
                yield
            finally:
                _depth.reset(token)

    @contextmanager
    def startup_schema(self, version):
        """Serialize schema initialization while recreated services stay gated.

        This permits only the caller's explicit schema-init block. It never
        permits HTTP, worker recovery, SMTP, probes or service mutations.
        """
        if not self._exists():
            yield
            return
        with self._lock('work.lock'), self._lock('startup.lock', exclusive=True, timeout=MAX_DRAIN):
            _, gate = self._rows()
            if not gate:
                raise MaintenanceError('state_unavailable')
            if gate['closed']:
                if gate['drained'] != 1:
                    raise MaintenanceError('state_unavailable')
                with closing(self._connect(read_only=True)) as db:
                    row = db.execute('SELECT payload,state FROM operations WHERE request_id=?', (gate['request_id'],)).fetchone()
                if not row or row['state'] != 'claimed':
                    raise MaintenanceError('state_unavailable')
                payload = verify(self.enrollment(), bytes(row['payload']))
                permitted = {payload['expected']['version']}
                if payload['target']:
                    permitted.add(payload['target']['version'])
                if version not in permitted:
                    raise MaintenanceError('state_unavailable')
            yield


class Controller:
    def __init__(self, store, hooks):
        self.store, self.hooks = store, hooks

    def _authority(self, enrollment=None, credential_version=None):
        actual = self.hooks.authority()
        if (not isinstance(actual, Authority) or type(actual.active) is not bool or not actual.active
                or type(actual.credential_version) is not int or actual.credential_version < 0
                or enrollment is not None and actual.owner_id != enrollment.owner_id
                or credential_version is not None and actual.credential_version != credential_version):
            raise MaintenanceError('owner_unavailable', 403)
        return actual

    def browser_authority(self, user):
        actual = self._authority()
        if (not isinstance(user, dict) or str(user.get('id', '')) != actual.owner_id
                or type(user.get('session_version')) is not int
                or user['session_version'] != actual.credential_version):
            raise MaintenanceError('owner_unavailable', 403)
        return actual

    def _generation(self):
        try:
            generation = self.hooks.config_generation()
        except ValueError:
            raise MaintenanceError('state_unavailable') from None
        if not isinstance(generation, str) or not HASH.fullmatch(generation):
            raise MaintenanceError('state_unavailable')
        return generation

    def _payload(self, row, enrollment):
        # Epoch keys and completed records are retained together. Owner/key
        # rotation must not make historical request reconciliation disappear.
        data = bytes(row['payload'])
        envelope = parse_json(data)
        exact_fields(envelope, ('payload', 'mac'))
        value = envelope['payload']
        if not isinstance(value, dict) or value.get('install_id') != enrollment.install_id:
            raise MaintenanceError('state_unavailable')
        historical = self.store.enrollment({field: value.get(field) for field in ('install_id', 'owner_id', 'epoch')})
        verify_request(historical, data, now=value.get('issued_at'))
        return verify(historical, data), historical

    def _unfinished(self, db, enrollment):
        for row in db.execute("SELECT * FROM operations WHERE state!='aborted' ORDER BY created_at"):
            if row['state'] not in ('queued', 'claimed', 'completed'):
                raise MaintenanceError('state_unavailable')
            if row['state'] != 'completed':
                return row
            _, historical = self._payload(row, enrollment)
            progress = db.execute('SELECT envelope FROM progress WHERE request_id=?', (row['request_id'],)).fetchone()
            phase = verify(historical, bytes(progress[0]))['phase'] if progress else None
            if phase not in ('success', 'recovered', 'failed'):
                return row
        return None

    def enroll(self, data, *, now=None):
        """Local Docker-exec stdin only; never registered as an HTTP route."""
        value = parse_json(data)
        exact_fields(value, ('protocol', 'install_id', 'owner_id', 'epoch', 'key', 'challenge', 'expected'))
        if value['protocol'] != 'keep.enrollment.v1' or not isinstance(value['key'], str) or not HASH.fullmatch(value['key']):
            raise ProtocolError('Invalid enrollment')
        enrollment = Enrollment(value['install_id'], value['owner_id'], value['epoch'], bytes.fromhex(value['key']))
        canonical_uuid(value['challenge'])
        expected = ImageIdentity.from_dict(value['expected'])
        self._authority(enrollment)
        if not self.hooks.supported() or expected.version != self.hooks.version():
            raise MaintenanceError('unsupported', 409)
        if not self.store._exists():
            raise MaintenanceError('state_unavailable')
        with self.store._lock('authority.lock', exclusive=True), closing(self.store._connect()) as db, db:
            db.execute('BEGIN IMMEDIATE')
            self._authority(enrollment)
            previous = db.execute('SELECT * FROM enrollment WHERE id=1').fetchone()
            if previous and self._unfinished(db, self.store.enrollment(dict(previous))):
                raise MaintenanceError('busy', 409)
            if previous and previous['epoch']==enrollment.epoch:
                if (self.store.enrollment(dict(previous))!=enrollment
                        or json.loads(previous['image_json'])!=expected.as_dict()):
                    raise MaintenanceError('state_unavailable')
                # A locally persisted enrollment may have succeeded before its
                # challenge reply was lost. Reconcile the identical key/image
                # without replacing state or resetting an active advisory.
                return signed(enrollment, {'protocol':'keep.enrolled.v1','install_id':enrollment.install_id,
                    'owner_id':enrollment.owner_id,'epoch':enrollment.epoch,'challenge':value['challenge']})
            if previous and (previous['install_id'] != enrollment.install_id or enrollment.epoch <= previous['epoch']):
                raise MaintenanceError('state_unavailable')
            key_path=self.store.root / ('key-' + str(enrollment.epoch) + '.json')
            key_data=canonical({field: value[field] for field in ('install_id', 'owner_id', 'epoch', 'key')})
            if key_path.exists() or key_path.is_symlink():
                if self.store.paths.read(key_path)!=key_data:raise MaintenanceError('state_unavailable')
            else:self.store.paths.publish(key_path,key_data)
            db.execute('INSERT OR REPLACE INTO enrollment VALUES (1,?,?,?,?,NULL,NULL,NULL)',
                (enrollment.install_id, enrollment.owner_id, enrollment.epoch,
                 canonical(expected.as_dict()).decode()))
        return signed(enrollment, {'protocol': 'keep.enrolled.v1', 'install_id': enrollment.install_id,
            'owner_id': enrollment.owner_id, 'epoch': enrollment.epoch, 'challenge': value['challenge']})

    def advisory(self, data, *, now=None):
        """Fixed signed host hello after independently resolving the release."""
        enrollment = self.store.enrollment()
        value = verify(enrollment, data)
        exact_fields(value, ('protocol', 'install_id', 'epoch', 'target', 'host_active_request'))
        if (value['protocol'] != 'keep.host-advisory.v1' or value['install_id'] != enrollment.install_id
                or type(value['epoch']) is not int or value['epoch'] != enrollment.epoch):
            raise ProtocolError('Enrollment does not match')
        self._authority(enrollment)
        target = ImageIdentity.from_dict(value['target']) if value['target'] is not None else None
        if value['host_active_request'] is not None:
            canonical_uuid(value['host_active_request'])
        row, _ = self.store._rows()
        expected = ImageIdentity.from_dict(json.loads(row['image_json']))
        if target and (target.architecture != expected.architecture
                or tuple(map(int, target.version.split('.'))) <= tuple(map(int, expected.version.split('.')))):
            raise ProtocolError('Release does not match installation')
        with closing(self.store._connect()) as db, db:
            db.execute('UPDATE enrollment SET target_json=?,helper_seen=?,host_active_request=? WHERE id=1',
                (canonical(target.as_dict()).decode() if target else None,
                 time.time() if now is None else now, value['host_active_request']))

    def _operation(self, row, enrollment):
        if not row:
            return None
        payload, historical = self._payload(row, enrollment)
        progress = None
        with closing(self.store._connect(read_only=True)) as db:
            record = db.execute('SELECT envelope FROM progress WHERE request_id=?', (row['request_id'],)).fetchone()
        if record:
            progress = verify(historical, bytes(record[0]))
        return {'request_id': row['request_id'], 'operation': payload['operation'], 'state': row['state'],
            'target_version': (payload['target'] or payload['expected'])['version'],
            'phase': progress['phase'] if progress else 'queued',
            'sequence': progress['sequence'] if progress else None,
            'result_code': progress['result_code'] if progress else None}

    def snapshot(self, *, user, request_id=None, now=None):
        actual = self.browser_authority(user)
        if request_id is not None:
            canonical_uuid(request_id)
        now = time.time() if now is None else now
        result = dict(supported=bool(self.hooks.supported()), enrolled=False, helper_available=False,
            can_install=False, can_restart=False, reason='not_enrolled', installed_version=self.hooks.version(),
            latest_version=None, confirmation=None, operation=None,
            requested_request_id=request_id, request_state='unknown' if request_id else None)
        row, gate = self.store._rows()
        if not result['supported']:
            result['reason'] = 'unsupported'
            return result
        if not row:
            return result
        enrollment = self.store.enrollment(row)
        self._authority(enrollment)
        with closing(self.store._connect(read_only=True)) as db:
            operation = db.execute('SELECT * FROM operations WHERE request_id=?', (request_id,)).fetchone() if request_id else None
            active = self._unfinished(db, enrollment)
        fresh = type(row['helper_seen']) in (int, float) and 0 <= now - row['helper_seen'] <= HELPER_FRESH_SECONDS
        target = ImageIdentity.from_dict(json.loads(row['target_json'])) if row['target_json'] else None
        confirmation = hmac.new(enrollment.key, canonical((enrollment.install_id, enrollment.epoch,
            actual.owner_id, actual.credential_version, row['image_json'], row['target_json'], self._generation())), hashlib.sha256).hexdigest()
        blocked = bool(active or row['host_active_request'] or not gate or gate['closed'])
        result.update(enrolled=True, helper_available=fresh, latest_version=target.version if target else None,
            confirmation=confirmation, operation=self._operation(operation or active, enrollment),
            can_restart=fresh and not blocked, can_install=fresh and not blocked and target is not None,
            reason='busy' if blocked else 'helper_unavailable' if not fresh else 'ready' if target else 'target_unavailable')
        if request_id:
            # Control state is not restored with keep.sqlite3 and is never
            # pruned. Missing rows are definitive only with a fresh host mirror
            # declaring no outstanding operation; otherwise uncertainty remains.
            result['request_state'] = operation['state'] if operation else 'not_received' if fresh and not row['host_active_request'] else 'unknown'
        return result

    def enqueue(self, body, *, user, now=None):
        exact_fields(body, ('request_id', 'operation', 'confirmation'))
        canonical_uuid(body['request_id'])
        if body['operation'] not in ('install', 'restart') or not isinstance(body['confirmation'], str) or not HASH.fullmatch(body['confirmation']):
            raise MaintenanceError('invalid_request', 400)
        now = time.time() if now is None else now
        with self.store.work(authority=True), closing(self.store._connect()) as db, db:
            db.execute('BEGIN IMMEDIATE')
            self.browser_authority(user)
            enrollment = self.store.enrollment()
            old = db.execute('SELECT * FROM operations WHERE request_id=?', (body['request_id'],)).fetchone()
            if old:
                original, _ = self._payload(old, enrollment)
                if original['operation'] != body['operation']:
                    raise MaintenanceError('invalid_request', 409)
                return body['request_id']
            snapshot = self.snapshot(user=user, now=now)
            if not hmac.compare_digest(body['confirmation'], snapshot['confirmation'] or ''):
                raise MaintenanceError('confirmation_changed', 409)
            if not snapshot['can_' + body['operation']]:
                raise MaintenanceError(snapshot['reason'], 409)
            row = db.execute('SELECT * FROM enrollment WHERE id=1').fetchone()
            actual = self._authority(enrollment)
            payload = {'protocol': 'keep.maintenance.v1', 'install_id': enrollment.install_id,
                'owner_id': enrollment.owner_id, 'epoch': enrollment.epoch, 'request_id': body['request_id'],
                'operation': body['operation'], 'credential_version': actual.credential_version,
                'issued_at': int(now), 'expires_at': int(now) + 600, 'nonce': secrets.token_hex(32),
                'expected': json.loads(row['image_json']),
                'target': json.loads(row['target_json']) if body['operation'] == 'install' else None}
            data = signed(enrollment, payload)
            verified = verify_request(enrollment, data, now=now)
            db.execute('INSERT INTO operations VALUES (?,?,?,?,?,?,?)',
                (verified.request_id, data, verified.payload_sha256, verified.nonce, 'queued', self._generation(), now))
        return body['request_id']

    def pending_request(self):
        """Private local host polling only, never browser JSON."""
        with closing(self.store._connect(read_only=True)) as db:
            row = db.execute("SELECT payload FROM operations WHERE state IN ('queued','claimed') ORDER BY created_at LIMIT 1").fetchone()
        return bytes(row[0]) if row else None

    def local_queue(self,data,*,now=None):
        """Signed local operator request; fixed Docker-exec stdin only.

        Uses the same request ledger as owner browser admission. The local
        caller selects only an operation/UUID; owner, session, configuration
        and immutable target come from current server state.
        """
        enrollment=self.store.enrollment()
        value=verify(enrollment,data)
        exact_fields(value,('protocol','install_id','epoch','request_id','operation'))
        if (value['protocol']!='keep.host-queue.v1' or value['install_id']!=enrollment.install_id
                or type(value['epoch']) is not int or value['epoch']!=enrollment.epoch
                or value['operation'] not in ('install','restart')):
            raise ProtocolError('Local operation does not match enrollment')
        canonical_uuid(value['request_id'])
        with self.store.work(authority=True):
            actual=self._authority(enrollment)
            user={'id':actual.owner_id,'session_version':actual.credential_version}
            snapshot=self.snapshot(user=user,now=now)
            self.enqueue({'request_id':value['request_id'],'operation':value['operation'],
                'confirmation':snapshot['confirmation']},user=user,now=now)
            result=self.snapshot(user=user,request_id=value['request_id'],now=now)
        return signed(enrollment,{'protocol':'keep.host-queued.v1','install_id':enrollment.install_id,
            'epoch':enrollment.epoch,'request_id':value['request_id'],'operation':value['operation'],
            'state':result['request_state']})

    def mailbox(self, verb, data, *, now=None, drain_timeout=MAX_DRAIN):
        if verb not in ('claim', 'revalidate', 'drain', 'status', 'complete', 'abort'):
            raise ProtocolError('Mailbox operation is not allowed')
        enrollment = self.store.enrollment()
        command = verify(enrollment, data)
        fields = ('protocol', 'install_id', 'epoch', 'request_id', 'verb', 'payload_sha256', 'credential_version')
        exact_fields(command, (*fields, 'progress') if verb == 'status' and 'progress' in command else fields)
        if (command['protocol'] != 'keep.host-command.v1' or command['install_id'] != enrollment.install_id
                or type(command['epoch']) is not int or command['epoch'] != enrollment.epoch
                or command['verb'] != verb or not isinstance(command['payload_sha256'], str)
                or not HASH.fullmatch(command['payload_sha256']) or type(command['credential_version']) is not int):
            raise ProtocolError('Host command does not match enrollment')
        canonical_uuid(command['request_id'])
        now = time.time() if now is None else now
        authority_lock = nullcontext() if verb == 'drain' else self.store._lock('authority.lock', exclusive=True, timeout=MAX_DRAIN)
        with authority_lock, closing(self.store._connect()) as db, db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT * FROM operations WHERE request_id=?', (command['request_id'],)).fetchone()
            if not row or row['payload_sha256'] != command['payload_sha256']:
                raise MaintenanceError('state_unavailable')
            payload = verify(enrollment, bytes(row['payload']))
            if command['credential_version'] != payload['credential_version']:
                raise MaintenanceError('owner_unavailable', 403)
            if verb in ('claim', 'revalidate', 'drain'):
                try:
                    verify_request(enrollment, bytes(row['payload']), now=now)
                    self._authority(enrollment, payload['credential_version'])
                except (MaintenanceError, ProtocolError):
                    if not db.execute('SELECT closed FROM gate WHERE id=1').fetchone()[0]:
                        db.execute("UPDATE operations SET state='aborted' WHERE request_id=? AND state IN ('queued','claimed')", (row['request_id'],))
                        db.commit()
                    raise
                if row['state'] not in ('queued', 'claimed') or row['config_generation'] != self._generation():
                    raise MaintenanceError('authority_changed', 409)
                if self.hooks.version() != payload['expected']['version']:
                    raise MaintenanceError('state_unavailable')
            if verb == 'claim':
                db.execute("UPDATE operations SET state='claimed' WHERE request_id=? AND state='queued'", (row['request_id'],))
            if verb == 'drain':
                if row['state'] != 'claimed':
                    raise MaintenanceError('state_unavailable')
                db.execute('UPDATE gate SET closed=1,request_id=?,drained=0 WHERE id=1', (row['request_id'],))
            if verb in ('complete', 'abort'):
                gate = db.execute('SELECT * FROM gate WHERE id=1').fetchone()
                if gate['request_id'] not in (None, row['request_id']):
                    raise MaintenanceError('busy', 409)
                if verb == 'complete':
                    self._authority(enrollment)
                    progress = db.execute('SELECT envelope FROM progress WHERE request_id=?', (row['request_id'],)).fetchone()
                    phase = verify(enrollment, bytes(progress[0]))['phase'] if progress else None
                    if row['state'] != 'completed' and (row['state'] != 'claimed' or not gate['closed']
                            or not gate['drained'] or phase not in ('committed', 'recovery-committed')):
                        raise MaintenanceError('state_unavailable')
                    permitted = {(payload['target'] or payload['expected'])['version'], payload['expected']['version']}
                    if self.hooks.version() not in permitted:
                        raise MaintenanceError('state_unavailable')
                    identity = payload['target'] if payload['target'] and self.hooks.version() == payload['target']['version'] else payload['expected']
                    db.execute('UPDATE enrollment SET image_json=?,target_json=NULL WHERE id=1', (canonical(identity).decode(),))
                else:
                    progress = db.execute('SELECT envelope FROM progress WHERE request_id=?', (row['request_id'],)).fetchone()
                    phase = verify(enrollment, bytes(progress[0]))['phase'] if progress else None
                    if (self.hooks.version() != payload['expected']['version'] or row['state'] == 'completed'
                            or phase not in (None, 'accepted', 'resolving', 'pulling', 'draining', 'held', 'failed')):
                        raise MaintenanceError('state_unavailable')
                db.execute('UPDATE gate SET closed=0,request_id=NULL,drained=0 WHERE id=1')
                db.execute('UPDATE operations SET state=? WHERE request_id=?', ('completed' if verb == 'complete' else 'aborted', row['request_id']))
            if 'progress' in command:
                self._progress(db, enrollment, row['request_id'], command['progress'])
            db.execute('UPDATE enrollment SET helper_seen=? WHERE id=1', (now,))
        if verb == 'drain':
            if type(drain_timeout) not in (int, float) or not 0 <= drain_timeout <= MAX_DRAIN:
                raise MaintenanceError('invalid_request', 400)
            # Do not hold authority.lock while waiting: admitted work takes
            # work.lock before authority.lock. Preserve that global lock order.
            with self.store._lock('work.lock', exclusive=True, timeout=drain_timeout), self.store._lock('authority.lock', exclusive=True):
                self._authority(enrollment, payload['credential_version'])
                if row['config_generation'] != self._generation():
                    raise MaintenanceError('authority_changed', 409)
                with closing(self.store._connect()) as db, db:
                    db.execute('UPDATE gate SET drained=1 WHERE id=1 AND closed=1 AND request_id=?', (row['request_id'],))
        actual = self.hooks.authority()
        _, gate = self.store._rows()
        return signed(enrollment, {'protocol': 'keep.host-result.v1', 'install_id': enrollment.install_id,
            'epoch': enrollment.epoch, 'request_id': row['request_id'], 'verb': verb, 'ok': True,
            'owner_id': actual.owner_id, 'credential_version': actual.credential_version,
            'config_generation': self._generation(), 'gate': 'closed' if gate['closed'] else 'open',
            'drained': bool(gate['drained']), 'version': self.hooks.version()})

    def _progress(self, db, enrollment, request_id, envelope):
        data = canonical(envelope)
        value = verify(enrollment, data)
        exact_fields(value, ('protocol', 'install_id', 'request_id', 'sequence', 'phase', 'result_code'))
        if (value['protocol'] != 'keep.maintenance.status.v1' or value['install_id'] != enrollment.install_id
                or value['request_id'] != request_id or type(value['sequence']) is not int
                or not 0 <= value['sequence'] <= 128 or value['phase'] not in PHASES
                or value['result_code'] not in (None, 'complete', 'unavailable', 'authority-changed', 'recovered', 'manual-review')):
            raise ProtocolError('Invalid operation progress')
        previous = db.execute('SELECT sequence,envelope FROM progress WHERE request_id=?', (request_id,)).fetchone()
        if previous and (value['sequence'] < previous[0] or value['sequence'] == previous[0] and data != bytes(previous[1])):
            raise ProtocolError('Operation progress may not regress')
        if previous and value['sequence'] > previous[0]:
            prior = verify(enrollment, bytes(previous[1]))['phase']
            reachable, pending = set(), list(ALLOWED_TRANSITIONS.get(prior, ()))
            while pending:
                phase = pending.pop()
                if phase not in reachable:
                    reachable.add(phase)
                    pending.extend(ALLOWED_TRANSITIONS.get(phase, ()))
            if value['phase'] not in reachable:
                raise ProtocolError('Operation progress phase may not regress')
        db.execute('INSERT INTO progress VALUES (?,?,?) ON CONFLICT(request_id) DO UPDATE SET sequence=excluded.sequence,envelope=excluded.envelope',
            (request_id, value['sequence'], data))


def register_flask(app, controller, *, read_only_about=None):
    """Install first, before onboarding cleanup/auth/API middleware is registered.

    Status and start are dispatched here to bypass middleware with incidental
    DB writes. All other requests retain a lease until teardown, not just POST.
    """
    from flask import g, jsonify, request, session
    from werkzeug.exceptions import SecurityError
    status_path, start_path = '/settings/about/maintenance/status', '/settings/about/maintenance/start'

    def admission():
        if isinstance(request.routing_exception, SecurityError):
            raise request.routing_exception
        try:
            if request.path == status_path and request.method == 'GET':
                if set(request.args) - {'request_id'}:
                    raise MaintenanceError('invalid_request', 400)
                if 'request_id' in request.args:
                    try:
                        canonical_uuid(request.args['request_id'])
                    except ProtocolError:
                        raise MaintenanceError('invalid_request', 400) from None
                return jsonify(snapshot=controller.snapshot(user=session.get('plex_user'), request_id=request.args.get('request_id')))
            if request.path == start_path and request.method == 'POST':
                provided, expected = request.headers.get('X-CSRF-Token', ''), session.get('csrf_token', '')
                if (not isinstance(expected, str) or not provided or not expected
                        or len(provided) > 256 or len(expected) > 256
                        or not hmac.compare_digest(provided.encode(), expected.encode())):
                    raise MaintenanceError('csrf_failed', 403)
                if not request.is_json or (request.content_length or 0) > 4096:
                    raise MaintenanceError('invalid_request', 400)
                try:
                    body = parse_json(request.stream.read(4097), limit=4096)
                    exact_fields(body, ('request_id', 'operation', 'confirmation'))
                    canonical_uuid(body['request_id'])
                except ProtocolError:
                    raise MaintenanceError('invalid_request', 400) from None
                controller.enqueue(body, user=session.get('plex_user'))
                response = jsonify(snapshot=controller.snapshot(user=session.get('plex_user')), message='Maintenance queued.')
                response.status_code = 202
                return response
            if request.method in ('GET', 'HEAD') and request.path == '/health':
                return app.make_response(app.view_functions['health']())
            if request.method in ('GET', 'HEAD') and request.path.startswith('/static/'):
                return app.send_static_file(request.path.removeprefix('/static/'))
            if request.path == '/settings/about' and request.method == 'GET' and read_only_about:
                _, gate = controller.store._rows()
                if gate and gate['closed']:
                    snapshot = controller.snapshot(user=session.get('plex_user'))
                    return app.make_response(read_only_about(snapshot))
            mutates_authority = request.method not in ('GET', 'HEAD', 'OPTIONS') or request.path in ('/auth/plex/callback', '/logout')
            lease = controller.store.work(authority=mutates_authority)
            lease.__enter__()
            g.keep_maintenance_lease = lease
        except (ProtocolError, MaintenanceError, sqlite3.Error, StorageError, OSError) as failure:
            code = failure.code if isinstance(failure, MaintenanceError) else 'state_unavailable'
            status = failure.status if isinstance(failure, MaintenanceError) else 503
            response = jsonify(error={'code': code, 'message': 'Keep maintenance is unavailable. Check the recorded status before retrying.'})
            response.status_code = status
            response.headers['Retry-After'] = '5'
            return response

    # Returning a response here also prevents later before_request middleware.
    app.before_request_funcs.setdefault(None, []).insert(0, admission)

    @app.teardown_request
    def release(error):
        lease = g.pop('keep_maintenance_lease', None)
        if lease:
            lease.__exit__(None, None, None)

    @app.after_request
    def private_response(response):
        if request.path in (status_path, start_path):
            response.headers['Cache-Control'] = 'no-store'
            response.headers['Referrer-Policy'] = 'no-referrer'
        return response


def worker_step(store, callback, *, authority=False):
    """Pause gated worker work without claiming jobs or recovering deliveries."""
    try:
        with store.work(authority=authority):
            return True, callback()
    except MaintenanceError as failure:
        if failure.code in ('maintenance_in_progress', 'busy'):
            return False, None
        raise


def dispatch(controller, verb, data, *, now=None):
    """Fixed CLI verbs over bounded stdin/stdout; never an HTTP endpoint."""
    if verb == 'enroll':
        return controller.enroll(data, now=now)
    if verb == 'queue':
        return controller.local_queue(data, now=now)
    if verb == 'hello':
        if data:
            controller.advisory(data, now=now)
        actual = controller.hooks.authority()
        row, _ = controller.store._rows()
        value = {'protocol': 'keep.app-hello.v1', 'owner_id': actual.owner_id,
            'credential_version': actual.credential_version, 'owner_active': actual.active,
            'config_generation': controller._generation(), 'version': controller.hooks.version(),
            'supported': bool(controller.hooks.supported()), 'enrolled': bool(row), 'pending': None}
        if row:
            enrollment = controller.store.enrollment(row)
            pending = controller.pending_request()
            value['pending'] = parse_json(pending) if pending else None
            return signed(enrollment, value)
        return canonical(value)
    return controller.mailbox(verb, data, now=now)


def configuration_fingerprint(values):
    """Match optional-provider isolation while detecting every raw change."""
    from connection_settings import FIELDS, PUSHOVER_FIELDS, validate
    normalized, invalid_optional = {}, {}
    for name, value in values.items():
        if name not in FIELDS:
            continue
        try:
            normalized[name] = validate(name, value)
        except ValueError:
            if name not in PUSHOVER_FIELDS:
                raise
            normalized[name] = 'false' if name == 'PUSHOVER_ENABLED' else ''
            invalid_optional[name] = value
    if invalid_optional:
        normalized['_ignored_push_configuration'] = hashlib.sha256(canonical(invalid_optional)).hexdigest()
    for name in ('FLASK_SECRET_KEY', 'KEEP_WEBHOOK_SECRET'):
        normalized[name] = os.environ.get(name, '')
    return hashlib.sha256(canonical(normalized)).hexdigest()


def fixed_hooks(*, qualified=False):
    """Neutral runtime callbacks for the fixed Linux-container installation.

    Qualification is a code-level integration decision, never a browser value.
    All paths below are fixed package/data paths; custom layouts stay unsupported.
    """
    database, version_path = Path('/app/data/keep.sqlite3'), Path('/app/VERSION')
    from connection_settings import FIELDS, PLEX_FIELDS, validate

    def connect():
        return sqlite3.connect(database.as_uri() + '?mode=ro', uri=True, timeout=.25)

    def authority():
        with closing(connect()) as db:
            row = db.execute('''SELECT p.plex_id,p.session_version,p.status,p.auth_type,p.plex_access
                FROM installation i JOIN user_profiles p ON p.plex_id=i.owner
                WHERE i.id=1 AND i.complete=1''').fetchone()
        return Authority(str(row[0]), row[1], row[2:] == ('active', 'plex', 'active')) if row else Authority('', 0, False)

    def generation():
        with closing(connect()) as db:
            values = dict(db.execute('SELECT name,value FROM connection_settings'))
            overrides = {row[0] for row in db.execute('SELECT name FROM plex_connection_overrides')}
        for name in FIELDS:
            if name in os.environ and not (name in PLEX_FIELDS and name in overrides):
                values[name] = os.environ[name]
        return configuration_fingerprint(values)

    return Hooks(authority, generation, lambda: version_path.read_text().strip(),
        lambda: qualified is True and os.environ.get('KEEP_DB_PATH', str(database)) == str(database))
