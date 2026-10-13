"""Fixed stdlib volume operations, injected as audited source by the host helper.

The real adapter runs this in an isolated prior-image container, on the one
enrolled named data volume, while both Keep services are stopped. Tests call
dispatch with private synthetic directories only. No host path comes from Keep.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import stat
import tempfile
import uuid

TABLES = frozenset((
    'installation','installation_metadata','user_profiles','keep_attribution','keep_schedules',
    'connection_settings','plex_connection_overrides','api_keys','api_idempotency',
    'email_recipients','recipient_subscriptions','media_libraries','user_library_permissions',
    'user_feature_acknowledgements','background_job_settings','background_job_requests',
    'notification_queue','notification_batches','notification_deliveries','notification_reminders',
    'seerr_links','seerr_availability_queue','notification_provider_generations','pushover_preferences',
    'notification_email_events','notification_test_attempts','notification_runs','notification_dispatches',
    'notification_destination_epochs','notification_cooldowns','notification_operational_events','notification_transitions',
))
VOLATILE = {'user_profiles':frozenset(('plex_checked_at','last_login')),
            'api_keys':frozenset(('last_used_at',))}
MAX_DB = 4*1024**3
DIAGNOSTIC_PREFIX = 'Fixed Keep volume operation failed '


class VolumeError(RuntimeError):
    pass


def error_diagnostic(error):
    """Only fixed exception names and this audited worker's line numbers."""
    names={VolumeError:'VolumeError',json.JSONDecodeError:'JSONDecodeError',
           OSError:'OSError',FileNotFoundError:'FileNotFoundError',PermissionError:'PermissionError',
           FileExistsError:'FileExistsError',IsADirectoryError:'IsADirectoryError',NotADirectoryError:'NotADirectoryError',
           sqlite3.Error:'Error',sqlite3.DatabaseError:'DatabaseError',sqlite3.OperationalError:'OperationalError',
           sqlite3.IntegrityError:'IntegrityError',ValueError:'ValueError',TypeError:'TypeError',
           UnicodeDecodeError:'UnicodeDecodeError',MemoryError:'MemoryError',OverflowError:'OverflowError',
           RecursionError:'RecursionError',RuntimeError:'RuntimeError',AssertionError:'AssertionError'}
    lines=[];trace=error.__traceback__;remaining=64
    while trace is not None and remaining:
        if trace.tb_frame.f_code.co_filename==error_diagnostic.__code__.co_filename and 1<=trace.tb_lineno<=65536:
            lines.append(trace.tb_lineno);lines=lines[-8:]
        trace=trace.tb_next;remaining-=1
    return {'type':names.get(type(error),'Exception'),'lines':lines}


def identifier(value):
    if not isinstance(value, str) or str(uuid.UUID(value)) != value or uuid.UUID(value).version != 4:
        raise VolumeError("Invalid recovery identity")
    return value


def private(path, directory=False):
    info = path.lstat()
    if (stat.S_ISLNK(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077
            or not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
            or not directory and info.st_size > MAX_DB):
        raise VolumeError("Volume paths must be private and owned by Keep")
    return path


def mkdir(path):
    private(path.parent, True)
    if not path.exists():
        path.mkdir(mode=0o700)
        flush(path.parent)
    return private(path, True)


def flush(path):
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def digest(path):
    private(path)
    result, size = hashlib.sha256(), 0
    with path.open("rb") as stream:
        while data := stream.read(1048576):
            size += len(data)
            if size > MAX_DB:
                raise VolumeError("Database artifact exceeds its bound")
            result.update(data)
    return {"sha256": result.hexdigest(), "bytes": size}


def integrity(db):
    if db.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
        raise VolumeError("Database integrity check failed")


def fingerprint(database, columns=None):
    private(database)
    result = {}
    with sqlite3.connect(database.as_uri()+"?mode=ro", uri=True, timeout=5) as db:
        integrity(db)
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if columns is not None and (not isinstance(columns, dict) or not set(columns) <= TABLES):
            raise VolumeError("Fingerprint tables are not allowed")
        for table in sorted(TABLES if columns is None else columns):
            if table not in tables:
                if columns is not None:
                    raise VolumeError("A protected table is missing")
                continue
            actual = [row[1] for row in db.execute(f'PRAGMA table_info("{table}")')]
            names = [name for name in actual if name not in VOLATILE.get(table,())] if columns is None else columns[table]
            if (not isinstance(names, list) or not names or len(names) > 128 or len(set(names)) != len(names)
                    or not set(names) <= set(actual) or any(not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", name) for name in names)):
                raise VolumeError("Fingerprint columns are invalid")
            hashes = []
            query = 'SELECT '+','.join('"'+name+'"' for name in names)+' FROM "'+table+'"'
            for row in db.execute(query):
                if len(hashes) >= 1000000:
                    raise VolumeError("Protected records exceed their bound")
                # Retain only hashes, never user/configuration/key values.
                cells = [[type(value).__name__, value.hex() if isinstance(value, bytes) else repr(value)] for value in row]
                hashes.append(hashlib.sha256(json.dumps(cells,separators=(',',':'),ensure_ascii=True).encode()).hexdigest())
            result[table] = {"columns": names, "rows": len(hashes), "sha256": hashlib.sha256(''.join(sorted(hashes)).encode()).hexdigest()}
    return result


def snapshot(database, target):
    private(database)
    if target.exists() or target.is_symlink():
        # A retry cannot silently resnapshot a migrated or changed database.
        raise VolumeError("Snapshot already exists; reconcile the original operation")
    with sqlite3.connect(database.as_uri()+'?mode=ro',uri=True,timeout=5) as source:
        size=source.execute('PRAGMA page_count').fetchone()[0]*source.execute('PRAGMA page_size').fetchone()[0]
    if not 1<=size<=MAX_DB or shutil.disk_usage(target.parent).free<size*2+64*1024**2:
        raise VolumeError('Insufficient bounded space for the database snapshot')
    fd, name = tempfile.mkstemp(prefix='.snapshot-',dir=target.parent)
    stage = Path(name)
    os.fchmod(fd,0o600); os.close(fd)
    try:
        with sqlite3.connect(database.as_uri()+"?mode=ro",uri=True,timeout=5) as source:
            integrity(source)
            with sqlite3.connect(stage) as output:
                source.backup(output); integrity(output)
        flush(stage)
        os.link(stage,target,follow_symlinks=False); flush(target.parent)
    finally:
        stage.unlink(missing_ok=True)
    return {**digest(target),"fingerprint":fingerprint(target)}


def preserve(root, recovery, attempt_id):
    attempts = mkdir(recovery/'failed')
    failed = mkdir(attempts/identifier(attempt_id))
    artifacts = []
    for name in ('keep.sqlite3','keep.sqlite3-wal','keep.sqlite3-shm','keep.sqlite3-journal'):
        source,destination = root/name,failed/name
        if source.exists() or source.is_symlink():
            private(source)
            if destination.exists() or destination.is_symlink():
                raise VolumeError("Failed database preservation would overwrite evidence")
            os.rename(source,destination); flush(failed); flush(root)
        if destination.exists():
            artifacts.append({"name":name,**digest(destination)})
    return {"attempt_id":attempt_id,"artifacts":artifacts}


def restore(root, recovery, expected):
    if not isinstance(expected,str) or not re.fullmatch(r"[a-f0-9]{64}",expected):
        raise VolumeError("Snapshot identity is invalid")
    source = recovery/'database.sqlite3'
    identity=digest(source)
    if identity['sha256'] != expected:
        raise VolumeError("Snapshot bytes changed")
    if shutil.disk_usage(root).free<identity['bytes']+64*1024**2:
        raise VolumeError('Insufficient space to stage the matching database')
    baseline = fingerprint(source)
    for suffix in ('','-wal','-shm','-journal'):
        path = root/('keep.sqlite3'+suffix)
        if path.exists() or path.is_symlink():
            raise VolumeError("Preserve the current database and sidecars before restoring")
    fd,name = tempfile.mkstemp(prefix='.restore-',dir=root)
    stage = Path(name);os.fchmod(fd,0o600)
    try:
        with os.fdopen(fd,'wb') as output, source.open('rb') as input_file:
            while data:=input_file.read(1048576):output.write(data)
            output.flush();os.fsync(output.fileno())
        if digest(stage)['sha256'] != expected or fingerprint(stage) != baseline:
            raise VolumeError("Staged database does not match the snapshot")
        os.link(stage,root/'keep.sqlite3',follow_symlinks=False);flush(root)
    finally:
        stage.unlink(missing_ok=True)
    return {**digest(root/'keep.sqlite3'),"fingerprint":baseline}


def upload(recovery,command,stream):
    size,expected=command['expected_bytes'],command['expected_sha256']
    if type(size) is not int or not 1<=size<=MAX_DB or not isinstance(expected,str) or not re.fullmatch(r'[a-f0-9]{64}',expected):
        raise VolumeError('Uploaded snapshot identity is invalid')
    if shutil.disk_usage(recovery).free<size+64*1024**2:
        raise VolumeError('Insufficient space to stage the verified snapshot')
    target=recovery/'database.sqlite3'
    if target.exists() or target.is_symlink():raise VolumeError('An uploaded snapshot may not overwrite recovery evidence')
    fd,name=tempfile.mkstemp(prefix='.upload-',dir=recovery);os.fchmod(fd,0o600);stage=Path(name)
    try:
        total=0
        with os.fdopen(fd,'wb') as output:
            while total<size:
                data=stream.read(min(1048576,size-total))
                if not data:raise VolumeError('Uploaded snapshot was incomplete')
                output.write(data);total+=len(data)
            if stream.read(1):raise VolumeError('Uploaded snapshot exceeded its declared size')
            output.flush();os.fsync(output.fileno())
        if digest(stage)['sha256']!=expected:raise VolumeError('Uploaded snapshot bytes did not match')
        value=fingerprint(stage)
        os.link(stage,target,follow_symlinks=False);flush(recovery)
    finally:stage.unlink(missing_ok=True)
    return {**digest(target),'fingerprint':value}


def dispatch(command, root=Path('/app/data'), upload_stream=None):
    fields = {'operation','request_id','attempt_id','expected_sha256','expected_bytes','columns'}
    if not isinstance(command,dict) or set(command)!=fields:
        raise VolumeError("Unsupported volume command")
    operation = command['operation']
    if operation not in ('snapshot','prepare-restore','preserve','restore','fingerprint','upload'):
        raise VolumeError("Volume operation is not allowed")
    identifier(command['request_id']);private(root,True)
    if operation=='fingerprint':
        result={'fingerprint':fingerprint(root/'keep.sqlite3',command['columns'])}
    else:
        maintenance=mkdir(root/'.maintenance');all_recovery=mkdir(maintenance/'recovery')
        recovery=mkdir(all_recovery/command['request_id'])
        if operation=='snapshot':result=snapshot(root/'keep.sqlite3',recovery/'database.sqlite3')
        elif operation=='prepare-restore':result={'snapshot':digest(recovery/'database.sqlite3') if (recovery/'database.sqlite3').exists() else None}
        elif operation=='preserve':result=preserve(root,recovery,command['attempt_id'])
        elif operation=='upload':result=upload(recovery,command,upload_stream)
        else:result=restore(root,recovery,command['expected_sha256'])
    return {'schema':'keep.volume-result.v1','operation':operation,'request_id':command['request_id'],**result}


def main(root=Path('/app/data')):
    try:
        data = __import__('sys').stdin.buffer.readline(65537)
        if len(data)>65536:raise VolumeError('Volume command exceeds its bound')
        result=dispatch(json.loads(data),root,upload_stream=__import__('sys').stdin.buffer)
        print(json.dumps(result,separators=(',',':'),sort_keys=True))
    except Exception as error:
        # Keep the fixed failure and exit status. The bounded operator diagnostic
        # contains no exception messages, function/path names, SQL or values.
        __import__('sys').stderr.write(DIAGNOSTIC_PREFIX+json.dumps(error_diagnostic(error),separators=(',',':'),sort_keys=True)+'\n')
        __import__('sys').stderr.flush()
        raise SystemExit(1)


if __name__=='__main__':main()
