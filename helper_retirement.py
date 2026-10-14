"""Read-only upgrade check for state left by the retired host helper.

This module cannot enroll, queue work, execute Docker, recover an operation, or
change legacy records. An unfinished operation must be resolved with its matching
older release before starting this release.
"""
from contextlib import ExitStack, closing
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import time
import uuid

FIXED_ROOT = Path('/app/data/.maintenance')
MAX_DATABASE = 32 * 1024 * 1024
MAX_RECORD = 65536
MAX_OPERATIONS = 2048
LOCKS = ('initialize.lock', 'work.lock', 'authority.lock', 'startup.lock')
TABLES = {
    'enrollment': ('id', 'install_id', 'owner_id', 'epoch', 'image_json', 'target_json', 'helper_seen', 'host_active_request'),
    'operations': ('request_id', 'payload', 'payload_sha256', 'nonce', 'state', 'config_generation', 'created_at'),
    'gate': ('id', 'closed', 'request_id', 'drained'),
    'progress': ('request_id', 'sequence', 'envelope'),
}
MESSAGE = ('The retired Keep helper has unfinished or unverifiable recovery state. '
           'Stop this upgrade, finish or recover the operation with the previous release, '
           'and stop its host helper before retrying. Preserve its state and backups; '
           'see docs/MAINTENANCE.md.')


class HelperRetirementError(RuntimeError):
    def __init__(self):
        super().__init__(MESSAGE)


def _require(condition):
    if not condition:
        raise HelperRetirementError()


def _identity(path, *, directory=False):
    info = path.lstat()
    _require(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
    _require(not getattr(info, 'st_file_attributes', 0) & 0x400)
    if os.name == 'posix':
        _require(info.st_uid == os.geteuid() and not stat.S_IMODE(info.st_mode) & 0o077)
    if not directory:
        _require(info.st_nlink == 1)
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)


def _read(path):
    before = _identity(path)
    _require(0 < before[2] <= MAX_RECORD)
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0))
    try:
        info = os.fstat(fd)
        _require((info.st_dev, info.st_ino) == before[:2])
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            data = stream.read(MAX_RECORD + 1)
        _require(len(data) <= MAX_RECORD and _identity(path) == before)
        return data
    finally:
        os.close(fd)


def _json(data):
    _require(isinstance(data, bytes) and 0 < len(data) <= MAX_RECORD)
    def fields(pairs):
        result = {}
        for name, value in pairs:
            _require(name not in result)
            result[name] = value
        return result
    return json.loads(data.decode('utf-8'), object_pairs_hook=fields,
                      parse_constant=lambda value: (_ for _ in ()).throw(HelperRetirementError()))


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')


def _uuid(value):
    _require(isinstance(value, str))
    parsed = uuid.UUID(value)
    _require(parsed.version == 4 and str(parsed) == value)


def _key(root, install_id, owner_id, epoch):
    _uuid(install_id)
    _require(isinstance(owner_id, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}', owner_id))
    _require(type(epoch) is int and 1 <= epoch <= 2**31 - 1)
    document = _json(_read(root / ('key-' + str(epoch) + '.json')))
    _require(isinstance(document, dict) and set(document) == {'install_id', 'owner_id', 'epoch', 'key'})
    _require(document['install_id'] == install_id and document['owner_id'] == owner_id
             and type(document['epoch']) is int and document['epoch'] == epoch)
    _require(isinstance(document['key'], str) and re.fullmatch(r'[a-f0-9]{64}', document['key']))
    return bytes.fromhex(document['key'])


def _verified(envelope, key):
    _require(isinstance(envelope, dict) and set(envelope) == {'payload', 'mac'})
    _require(isinstance(envelope['payload'], dict) and isinstance(envelope['mac'], str)
             and re.fullmatch(r'[a-f0-9]{64}', envelope['mac']))
    expected = hmac.new(key, _canonical(envelope['payload']), hashlib.sha256).hexdigest()
    _require(hmac.compare_digest(expected, envelope['mac']))
    return envelope['payload']


def _image(document):
    _require(isinstance(document, dict) and set(document) == {
        'index_digest', 'native_digest', 'image_id', 'version', 'revision', 'architecture'})
    for name in ('index_digest', 'native_digest', 'image_id'):
        _require(isinstance(document[name], str) and re.fullmatch(r'sha256:[a-f0-9]{64}', document[name]))
    _require(isinstance(document['version'], str) and re.fullmatch(r'(?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8})', document['version']))
    _require(isinstance(document['revision'], str) and re.fullmatch(r'[a-f0-9]{40}', document['revision'])
             and document['architecture'] in ('amd64', 'arm64'))


def _request(document):
    _require(set(document) == {'protocol', 'install_id', 'owner_id', 'epoch', 'request_id',
        'operation', 'credential_version', 'issued_at', 'expires_at', 'nonce', 'expected', 'target'})
    _require(document['protocol'] == 'keep.maintenance.v1' and document['operation'] in ('install', 'restart'))
    for name in ('credential_version', 'issued_at', 'expires_at'):
        _require(type(document[name]) is int and 0 <= document[name] < 2**53)
    _require(1 <= document['expires_at'] - document['issued_at'] <= 900)
    _require(isinstance(document['nonce'], str) and re.fullmatch(r'[a-f0-9]{64}', document['nonce']))
    _image(document['expected'])
    if document['operation'] == 'restart':
        _require(document['target'] is None)
    else:
        _image(document['target'])
        _require(document['target'] != document['expected']
                 and document['target']['architecture'] == document['expected']['architecture'])


def _check_records(db, root):
    _require(db.execute('PRAGMA quick_check').fetchall() == [('ok',)])
    objects = db.execute("SELECT type,name FROM sqlite_master WHERE type IN ('table','view','trigger')").fetchall()
    _require(set(objects) == {('table', name) for name in TABLES})
    for name, columns in TABLES.items():
        _require(tuple(row[1] for row in db.execute('PRAGMA table_info(' + name + ')')) == columns)
    gates = db.execute('SELECT id,closed,request_id,drained FROM gate').fetchall()
    _require(gates == [(1, 0, None, 0)])
    enrollments = db.execute('SELECT id,install_id,owner_id,epoch,host_active_request,image_json,target_json FROM enrollment').fetchall()
    _require(len(enrollments) <= 1)
    if enrollments:
        row = enrollments[0]
        _require(row[0] == 1 and row[4] is None)
        _key(root, row[1], row[2], row[3])
        _require(isinstance(row[5], str) and (row[6] is None or isinstance(row[6], str)))
        _image(_json(row[5].encode('utf-8')))
        if row[6] is not None:
            _image(_json(row[6].encode('utf-8')))
    rows = db.execute('SELECT request_id,state,payload,payload_sha256,nonce FROM operations LIMIT ?',
                      (MAX_OPERATIONS + 1,)).fetchall()
    _require(len(rows) <= MAX_OPERATIONS and (not rows or bool(enrollments)))
    identifiers = set()
    for request_id, state, data, digest, nonce in rows:
        _uuid(request_id)
        _require(state in ('completed', 'aborted'))
        identifiers.add(request_id)
        envelope = _json(data)
        value = envelope.get('payload') if isinstance(envelope, dict) else None
        _require(isinstance(value, dict) and value.get('install_id') == enrollments[0][1])
        key = _key(root, value.get('install_id'), value.get('owner_id'), value.get('epoch'))
        value = _verified(envelope, key)
        _request(value)
        _require(value.get('protocol') == 'keep.maintenance.v1' and value.get('request_id') == request_id
                 and value.get('nonce') == nonce and value.get('operation') in ('install', 'restart')
                 and digest == hashlib.sha256(_canonical(value)).hexdigest())
        progress = db.execute('SELECT sequence,envelope FROM progress WHERE request_id=?', (request_id,)).fetchone()
        if progress:
            sequence, body = progress
            value = _verified(_json(body), key)
            _require(set(value) == {'protocol', 'install_id', 'request_id', 'sequence', 'phase', 'result_code'})
            _require(value['protocol'] == 'keep.maintenance.status.v1'
                     and value['install_id'] == enrollments[0][1] and value['request_id'] == request_id
                     and type(sequence) is int and 0 <= sequence <= 128
                     and type(value['sequence']) is int and value['sequence'] == sequence
                     and value['result_code'] in (None, 'complete', 'unavailable', 'authority-changed', 'recovered', 'manual-review'))
            permitted = ('success', 'recovered', 'failed') if state == 'completed' else (
                'accepted', 'resolving', 'pulling', 'draining', 'held', 'failed')
            _require(value['phase'] in permitted)
        else:
            _require(state == 'aborted')
    _require(all(row[0] in identifiers for row in db.execute('SELECT request_id FROM progress')))
    return identifiers


def _check_recovery(root, identifiers):
    recovery = root / 'recovery'
    if not recovery.exists() and not recovery.is_symlink():
        return
    _identity(recovery, directory=True)
    operations = list(recovery.iterdir())
    _require(len(operations) <= MAX_OPERATIONS)
    count = 0
    for operation in operations:
        _uuid(operation.name)
        _require(operation.name in identifiers)
        _identity(operation, directory=True)
        pending = [(operation, 0)]
        while pending:
            directory, depth = pending.pop()
            _require(depth <= 8)
            for path in directory.iterdir():
                count += 1
                _require(count <= MAX_OPERATIONS * 16)
                is_directory = stat.S_ISDIR(path.lstat().st_mode)
                _identity(path, directory=is_directory)
                if is_directory:
                    pending.append((path, depth + 1))


def check_retired_helper_state(root=FIXED_ROOT):
    """Allow fresh or idle installations; preserve and reject uncertain state.

    Legacy WAL/journal contents are held rather than ignored or replayed. The
    immutable read-only connection creates no SQLite sidecars or recovery writes.
    Existing locks are opened read-only and never created.
    """
    root = Path(root)
    try:
        _require(root.is_absolute() and '..' not in root.parts)
        if not root.exists() and not root.is_symlink():
            return
        original_root = _identity(root, directory=True)
        for ancestor in root.parents:
            info = ancestor.lstat()
            _require(stat.S_ISDIR(info.st_mode) and not getattr(info, 'st_file_attributes', 0) & 0x400)
            if os.name == 'posix':
                _require(info.st_uid in (0, os.geteuid())
                         and (not info.st_mode & 0o022 or info.st_mode & stat.S_ISVTX))
        members = list(root.iterdir())
        _require(len(members) <= MAX_OPERATIONS + 10)
        member_identities = {}
        allowed = {'control.sqlite3', 'control.sqlite3-wal', 'control.sqlite3-shm', 'control.sqlite3-journal', 'recovery', *LOCKS}
        for path in members:
            _require(path.name in allowed or re.fullmatch(r'key-[1-9][0-9]{0,9}\.json', path.name))
            identity = _identity(path, directory=path.name == 'recovery')
            member_identities[path.name] = identity
            if path.name in ('control.sqlite3-wal', 'control.sqlite3-shm', 'control.sqlite3-journal'):
                _require(identity[2] == 0)
        database = root / 'control.sqlite3'
        original_database = _identity(database)
        _require(0 < original_database[2] <= MAX_DATABASE)
        with ExitStack() as stack:
            if os.name == 'posix':
                import fcntl
                for name in LOCKS:
                    path = root / name
                    if path.exists():
                        before = _identity(path)
                        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
                        stack.callback(os.close, fd)
                        _require((os.fstat(fd).st_dev, os.fstat(fd).st_ino) == before[:2])
                        fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
            uri = database.as_uri() + '?mode=ro&immutable=1'
            with closing(sqlite3.connect(uri, uri=True, timeout=.25)) as db:
                deadline = time.monotonic() + 5
                db.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
                db.execute('PRAGMA query_only=ON')
                identifiers = _check_records(db, root)
                _check_recovery(root, identifiers)
            _require(_identity(database) == original_database)
            for name, identity in member_identities.items():
                _require(_identity(root / name, directory=name == 'recovery') == identity)
        _require(_identity(root, directory=True) == original_root)
    except HelperRetirementError:
        raise
    except (OSError, ValueError, TypeError, KeyError, sqlite3.Error, RecursionError):
        raise HelperRetirementError() from None
