"""Private host storage, fixed profile and durable append-only journal.

POSIX behavior is executable here. Windows requires a native ACL/reparse check
and durable directory-flush adapter; it fails closed without those adapters.
Synthetic adapter tests are not evidence of native Windows filesystem support.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile

from maintenance_protocol import ProtocolError, PHASES, TERMINAL, canonical, canonical_uuid, parse_json


class StorageError(RuntimeError):
    pass


def create_private_paths():
    """Select the real platform adapter; import itself performs no host action."""
    if os.name=='nt':
        from windows_native import WindowsPrivatePaths
        return WindowsPrivatePaths()
    return PrivatePaths()


class PrivatePaths:
    def __init__(self, *, windows_acl=None, windows_flush=None):
        self.windows_acl = windows_acl
        self.windows_flush = windows_flush

    def check(self, path, *, directory=False, private=True):
        path = Path(path)
        if not path.is_absolute() or ".." in path.parts:
            raise StorageError("Path must be an enrolled absolute path")
        try:
            info = path.lstat()
        except OSError as error:
            raise StorageError("Enrolled path is unavailable") from error
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise StorageError("Symlinks and reparse points are not allowed")
        if not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)):
            raise StorageError("Enrolled path has the wrong file type")
        if os.name == "nt":
            if self.windows_acl is None:
                raise StorageError("Native Windows ACL verification is required")
            self.windows_acl(path, private=private)
        else:
            if info.st_uid != os.geteuid():
                raise StorageError("Enrolled path must belong to this operator")
            if stat.S_IMODE(info.st_mode) & (0o077 if private else 0o022):
                raise StorageError("Enrolled path permissions are not private")
            for ancestor in path.parents:
                ancestor_info = ancestor.lstat()
                if stat.S_ISLNK(ancestor_info.st_mode) or not stat.S_ISDIR(ancestor_info.st_mode):
                    raise StorageError("Enrolled path ancestor is unsafe")
                if ancestor_info.st_uid not in (0, os.geteuid()):
                    raise StorageError("Enrolled path ancestor is untrusted")
                if ancestor_info.st_mode & 0o022 and not ancestor_info.st_mode & stat.S_ISVTX:
                    raise StorageError("Enrolled path ancestor is writable by others")
        return path

    def mkdir(self, path):
        path = Path(path)
        self.check(path.parent, directory=True)
        path.mkdir(mode=0o700)
        self.check(path, directory=True)
        self.flush_directory(path.parent)
        return path

    def read(self, path, *, limit=65536, private=True):
        path = self.check(path, private=private)
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
        fd = os.open(path, flags)
        try:
            info = os.fstat(fd)
            current = path.lstat()
            if not stat.S_ISREG(info.st_mode) or (info.st_dev, info.st_ino) != (current.st_dev, current.st_ino):
                raise StorageError("Enrolled file identity changed")
            if info.st_size > limit:
                raise StorageError("Enrolled file exceeds the size limit")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                data = stream.read(limit + 1)
            if len(data) > limit:
                raise StorageError("Enrolled file exceeds the size limit")
            return data
        finally:
            os.close(fd)

    def flush_directory(self, path):
        if os.name == "nt":
            if self.windows_flush is None:
                raise StorageError("Native Windows durable directory flush is required")
            self.windows_flush(Path(path))
            return
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def publish(self, path, data, *, overwrite=False):
        path = Path(path)
        self.check(path.parent, directory=True)
        if not isinstance(data, bytes):
            raise StorageError("Private file content must be bytes")
        if path.exists() or path.is_symlink():
            self.check(path)
            if not overwrite:
                raise StorageError("Recovery records may not be overwritten")
        fd, name = tempfile.mkstemp(prefix=".pending-", dir=path.parent)
        pending = Path(name)
        try:
            if os.name == "nt":
                # Creation protection must precede writing any secret bytes.
                if self.windows_acl is None:
                    raise StorageError("Native Windows ACL verification is required")
                self.windows_acl(pending, private=True, protect=True)
            else:
                os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb", closefd=False) as stream:
                stream.write(data)
                stream.flush()
                os.fsync(fd)
            os.close(fd)
            fd = -1
            if overwrite:
                os.replace(pending, path)
            else:
                os.link(pending, path, follow_symlinks=False)
                self.flush_directory(path.parent)
                pending.unlink()
            self.flush_directory(path.parent)
            self.check(path)
        finally:
            if fd != -1:
                os.close(fd)
            if pending.exists():
                pending.unlink()


@dataclass(frozen=True)
class Profile:
    installation: Path
    state: Path
    docker_executable: Path
    docker_config: Path
    docker_context: str
    docker_endpoint: str
    daemon_id: str
    project: str
    volume: str
    compose_files: tuple[Path, ...]
    env_file: Path
    legacy_lock: Path | None = None

    def validate(self, paths: PrivatePaths):
        paths.check(self.installation, directory=True, private=False)
        paths.check(self.state, directory=True)
        paths.check(self.docker_config, directory=True, private=False)
        for path in (*self.compose_files, self.env_file):
            if path.parent != self.installation:
                raise StorageError("Configuration must be enrolled under the installation")
            paths.check(path)
        if not 1 <= len(self.compose_files) <= 4 or len(set(self.compose_files)) != len(self.compose_files):
            raise StorageError("Invalid enrolled Compose configuration")
        if (not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", self.docker_context)
                or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", self.project)
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", self.volume)
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9:-]{0,127}", self.daemon_id)):
            raise StorageError("Invalid enrolled Docker identity")
        if not (self.docker_endpoint.startswith("unix:///") or self.docker_endpoint.startswith("npipe:////./pipe/")):
            raise StorageError("Only a local Docker engine may be enrolled")
        if any(ord(c) < 32 for c in self.docker_endpoint):
            raise StorageError("Invalid enrolled Docker endpoint")
        executable = self.docker_executable.lstat()
        if not self.docker_executable.is_absolute() or stat.S_ISLNK(executable.st_mode) or not stat.S_ISREG(executable.st_mode):
            raise StorageError("Docker executable must be pinned to a canonical regular file")
        if os.name != "nt" and (executable.st_uid not in (0, os.geteuid()) or executable.st_mode & 0o022):
            raise StorageError("Docker executable is untrusted")
        if os.name=='nt':paths.check(self.docker_executable,private=False)
        if self.legacy_lock is not None:
            if self.legacy_lock != self.installation / ".git" / "keep-deploy.lock":
                raise StorageError("Legacy deployment lock must use the fixed enrolled path")
            paths.check(self.legacy_lock.parent, directory=True, private=False)
            if self.legacy_lock.exists() or self.legacy_lock.is_symlink():
                paths.check(self.legacy_lock, private=False)
        return self


@contextmanager
def operation_lock(paths, path, *, legacy=False):
    """Acquire nonblocking, descriptor-bound lock; never unlink a lock inode."""
    path = Path(path)
    if hasattr(paths,'native_lock'):
        with paths.native_lock(path,legacy=legacy):yield
        return
    paths.check(path.parent, directory=True, private=not legacy)
    if path.exists() or path.is_symlink():
        paths.check(path, private=not legacy)
    fd = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise StorageError("Invalid deployment lock")
        if os.name == "nt":
            if paths.windows_acl is None:
                raise StorageError("Native Windows ACL verification is required")
            paths.windows_acl(path, private=True, protect=True)
            import msvcrt
            if not info.st_size:
                os.write(fd, b"0")
                os.fsync(fd)
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            paths.check(path, private=not legacy)
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    except BlockingIOError as error:
        raise StorageError("Another maintenance operation holds the deployment lock") from error
    finally:
        os.close(fd)


ALLOWED_TRANSITIONS = {
    "accepted": {"resolving", "held", "failed"},
    "held": {"resolving", "failed"},
    "resolving": {"pulling", "draining", "failed"},
    "pulling": {"draining", "failed"},
    "draining": {"stopping", "failed"},
    "stopping": {"backing-up", "failed", "recovery-needed"},
    "backing-up": {"prepared", "failed", "recovery-needed"},
    "prepared": {"activating", "failed", "recovery-needed"},
    "activating": {"verifying", "recovery-needed"},
    "verifying": {"committed", "recovery-needed"},
    "committed": {"success"},
    "recovery-needed": {"recovering"},
    "recovering": {"recovery-committed", "recovery-needed"},
    "recovery-committed": {"recovered"},
}


class Journal:
    """Immutable bounded records, no pointer file and no journal in migrated DB.

An incomplete temp file is never a committed record. Committed gaps, duplicate
or corrupt records hold maintenance; no automatic repair erases evidence.
All app-to-host request IDs become directories only after canonical UUID checks.
"""
    def __init__(self, paths, root, request_id, payload_sha256):
        self.paths = paths
        operation = Path(root) / "operations" / canonical_uuid(request_id)
        for directory in (operation.parent, operation):
            if not directory.exists():
                paths.mkdir(directory)
            paths.check(directory, directory=True)
        self.root = operation / "journal"
        self.request_id = request_id
        self.payload_sha256 = payload_sha256
        if not re.fullmatch(r"[a-f0-9]{64}", payload_sha256):
            raise StorageError("Invalid request fingerprint")
        if not self.root.exists():
            paths.mkdir(self.root)
        paths.check(self.root, directory=True)

    def records(self):
        records = []
        for path in sorted(self.root.iterdir()):
            if path.name.startswith(".pending-"):
                self.paths.check(path)
                continue
            if not re.fullmatch(r"[0-9]{3}\.json", path.name):
                raise StorageError("Unexpected journal member")
            if len(records) >= 128:
                raise StorageError("Operation journal exceeds its bound")
            try:
                record = parse_json(self.paths.read(path), 65536)
            except ProtocolError as error:
                raise StorageError("Journal record is invalid") from error
            expected_fields = {"schema", "request_id", "payload_sha256", "sequence", "phase", "previous_sha256", "details"}
            if not isinstance(record, dict) or set(record) != expected_fields:
                raise StorageError("Journal fields are invalid")
            previous = hashlib.sha256(canonical(records[-1])).hexdigest() if records else None
            if (path.name != f"{len(records):03}.json" or type(record["sequence"]) is not int
                    or record["sequence"] != len(records) or record["schema"] != "keep.host-journal.v1"
                    or record["request_id"] != self.request_id or record["payload_sha256"] != self.payload_sha256
                    or record["previous_sha256"] != previous or record["phase"] not in PHASES
                    or not isinstance(record["details"], dict)):
                raise StorageError("Journal chain or request identity is invalid")
            if records and record["phase"] not in ALLOWED_TRANSITIONS.get(records[-1]["phase"], set()):
                raise StorageError("Journal phase transition is invalid")
            if not records and record["phase"] != "accepted":
                raise StorageError("Journal must begin with acceptance")
            records.append(record)
        return records

    def append(self, phase, **details):
        records = self.records()
        previous_phase = records[-1]["phase"] if records else None
        if (len(records) >= 128 or phase not in PHASES
                or (previous_phase is None and phase != "accepted")
                or (previous_phase is not None and phase not in ALLOWED_TRANSITIONS.get(previous_phase, set()))):
            raise StorageError("Journal phase transition is invalid")
        record = {"schema": "keep.host-journal.v1", "request_id": self.request_id,
                  "payload_sha256": self.payload_sha256, "sequence": len(records), "phase": phase,
                  "previous_sha256": hashlib.sha256(canonical(records[-1])).hexdigest() if records else None,
                  "details": details}
        encoded = canonical(record)
        if len(encoded) > 65536:
            raise StorageError("Journal record exceeds its size bound")
        self.paths.publish(self.root / f"{len(records):03}.json", encoded)
        return record

    def disposition_after_crash(self):
        records = self.records()
        if not records:
            return "unaccepted"
        phase = records[-1]["phase"]
        if phase in TERMINAL:
            return "terminal"
        if phase in ("committed", "recovery-committed"):
            return "finish-commit-without-rollback"
        if phase in ("activating", "verifying", "recovery-needed", "recovering"):
            return "reconcile-and-recover"
        if phase in ("stopping", "backing-up", "prepared"):
            return "reconcile-stopped-state"
        return "revalidate-before-resume"


class ReplayIndex:
    """A bounded durable nonce ledger; preserve records when rotating enrollment."""
    def __init__(self, paths, root):
        self.paths, self.root = paths, Path(root) / "replay"
        if not self.root.exists():
            paths.mkdir(self.root)
        paths.check(self.root, directory=True)

    def accept(self, request):
        if not re.fullmatch(r"[a-f0-9]{64}", request.nonce):
            raise StorageError("Invalid request nonce")
        path = self.root / (request.nonce + ".json")
        value = {"request_id": request.request_id, "payload_sha256": request.payload_sha256}
        if path.exists() or path.is_symlink():
            if parse_json(self.paths.read(path)) != value:
                raise StorageError("A request nonce may not authorize a different operation")
            return
        entries = list(self.root.iterdir())
        if len(entries) >= 2048 or any(not re.fullmatch(r"[a-f0-9]{64}\.json", item.name) for item in entries):
            raise StorageError("Enrollment replay ledger requires operator review")
        self.paths.publish(path, canonical(value))
