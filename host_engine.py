"""Host transaction engine and bounded fixed Docker command construction.

Importing this file performs no host operation.
"""
from __future__ import annotations

from contextlib import ExitStack
from dataclasses import dataclass
import os
from pathlib import Path
import re
import signal
import subprocess
import threading
import time

from maintenance_protocol import ImageIdentity, ProtocolError, TERMINAL, canonical, parse_json
from private_store import Journal, PrivatePaths, Profile, ReplayIndex, StorageError, create_private_paths, operation_lock


class EngineError(RuntimeError):
    pass


@dataclass(frozen=True)
class Plan:
    label: str
    argv: tuple[str, ...]
    timeout: int
    output_limit: int = 1048576
    stdin: bytes = b""
    artifact: Path | None = None
    artifact_limit: int = 0
    stdin_file: Path | None = None
    stdin_file_limit: int = 0


class BoundedRunner:
    """No shell, bounded stdin/stdout/stderr, bounded process and pipe lifetime.

POSIX process groups are killed on timeout/output overflow. The concrete Windows
Job Object adapter is implemented separately and still needs native CI proof.
Docker daemon operations can outlive a killed CLI: every failure is uncertain
and must be reconciled by immutable container/image/volume identity afterward.
"""
    def __init__(self, profile, *, paths=None):
        self.profile = profile
        self.paths=paths or create_private_paths()
        self.windows=None
        if os.name=='nt':
            from windows_native import WindowsBoundedRunner
            self.windows=WindowsBoundedRunner(profile,paths=self.paths)

    def environment(self):
        allowed = ("PATH", "HOME", "USERPROFILE", "SYSTEMROOT", "WINDIR", "TEMP", "TMP")
        env = {name: os.environ[name] for name in allowed if name in os.environ}
        env["DOCKER_CONFIG"] = str(self.profile.docker_config)
        env["COMPOSE_DISABLE_ENV_FILE"] = "1"
        return env

    def run(self, plan):
        if self.windows:return self.windows.run(plan)
        if (type(plan.timeout) is not int or not 1 <= plan.timeout <= 1800
                or type(plan.output_limit) is not int or not 1 <= plan.output_limit <= 1048576
                or not isinstance(plan.stdin, bytes) or len(plan.stdin) > 65536):
            raise EngineError("Docker command bounds are invalid")
        if plan.artifact is not None:
            self.paths.check(plan.artifact.parent, directory=True)
            if (self.profile.state not in plan.artifact.parents or plan.artifact.exists()
                    or plan.artifact.is_symlink() or not 1 <= plan.artifact_limit <= 32*1024**3):
                raise EngineError("Docker artifact destination is invalid")
        if plan.stdin_file is not None:
            self.paths.check(plan.stdin_file)
            if (self.profile.state not in plan.stdin_file.parents or not 1<=plan.stdin_file_limit<=4*1024**3
                    or plan.stdin_file.stat().st_size>plan.stdin_file_limit):
                raise EngineError("Docker streaming input is invalid")
        options = {"umask": 0o077} if os.name != "nt" else {}
        proc = subprocess.Popen(plan.argv, cwd=self.profile.installation,
            env=self.environment(), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, shell=False, bufsize=0, start_new_session=os.name != "nt", **options)
        overflow = threading.Event()
        io_error = threading.Event()
        stdout = bytearray()

        def read(stream, retained):
            total = 0
            while True:
                data = stream.read(65536)
                if not data:
                    return
                total += len(data)
                if total > plan.output_limit:
                    overflow.set()
                    return
                if retained is not None:
                    retained.extend(data)

        def write():
            try:
                def send(data):
                    remaining=memoryview(data)
                    while remaining:
                        count=proc.stdin.write(remaining)
                        if not count:raise BrokenPipeError()
                        remaining=remaining[count:]
                send(plan.stdin)
                if plan.stdin_file is not None:
                    fd=os.open(plan.stdin_file,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
                    total=0
                    with os.fdopen(fd,'rb') as stream:
                        while data:=stream.read(1048576):
                            total+=len(data)
                            if total>plan.stdin_file_limit:
                                overflow.set();break
                            send(data)
                proc.stdin.close()
            except (BrokenPipeError, OSError):
                io_error.set()
            finally:
                try:proc.stdin.close()
                except OSError:pass

        threads = [threading.Thread(target=read, args=(proc.stdout, stdout), daemon=True),
                   threading.Thread(target=read, args=(proc.stderr, None), daemon=True),
                   threading.Thread(target=write, daemon=True)]
        for thread in threads:
            thread.start()
        deadline = time.monotonic() + plan.timeout
        failure = None
        while proc.poll() is None:
            if plan.artifact is not None and (plan.artifact.exists() or plan.artifact.is_symlink()):
                try:
                    self.paths.check(plan.artifact)
                    if plan.artifact.stat().st_size > plan.artifact_limit:
                        overflow.set()
                except (OSError, StorageError):
                    overflow.set()
            if overflow.is_set() or time.monotonic() >= deadline:
                failure = "Docker output exceeded its bound" if overflow.is_set() else "Docker command timed out"
                if os.name == "nt":
                    proc.kill()
                else:
                    try:os.killpg(proc.pid, signal.SIGKILL)
                    except ProcessLookupError:pass  # Child exited after poll.
                    except PermissionError:
                        failure='Docker process-tree stop is unavailable; operation needs reconciliation'
                        # Reap the original child if permitted. This does not
                        # claim descendants stopped or make the operation safe.
                        try:proc.kill()
                        except (ProcessLookupError,PermissionError):pass
                break
            time.sleep(0.01)
        try:proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            failure='Docker process stop is unavailable; operation needs reconciliation'
        for thread in threads:
            thread.join(timeout=1)
        for stream in (proc.stdout, proc.stderr, proc.stdin):
            try:
                stream.close()
            except OSError:
                pass
        if failure or overflow.is_set():
            raise EngineError(failure or "Docker output exceeded its bound")
        if any(thread.is_alive() for thread in threads):
            raise EngineError("Docker output stream did not close")
        if io_error.is_set():
            raise EngineError("Docker input delivery failed; operation needs reconciliation")
        if proc.returncode:
            # Never propagate raw process output, which may contain configuration.
            raise EngineError("Docker command failed; operation needs reconciliation")
        if plan.artifact is not None:
            self.paths.check(plan.artifact)
            if plan.artifact.stat().st_size > plan.artifact_limit:
                raise EngineError("Docker artifact exceeded its bound")
            fd=os.open(plan.artifact,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
            try:os.fsync(fd)
            finally:os.close(fd)
            self.paths.flush_directory(plan.artifact.parent)
        return bytes(stdout)


class DockerPlans:
    SERVICES = ("keep-app", "keep-digest")
    MAILBOX_VERBS = frozenset(("hello", "enroll", "queue", "claim", "revalidate", "drain", "status", "complete", "abort"))

    def __init__(self, paths: PrivatePaths, profile: Profile):
        self.paths = paths
        self.profile = profile.validate(paths)
        self.base = (str(profile.docker_executable), "--context", profile.docker_context)
        self.compose = (*self.base, "compose", "--project-name", profile.project,
            "--project-directory", str(profile.installation), "--env-file", str(profile.env_file))
        for path in profile.compose_files:
            self.compose += ("--file", str(path))

    def identity(self):
        return Plan("daemon identity", (*self.base, "info", "--format", "{{json .ID}}"), 30, 4096)

    def context_endpoint(self):
        return Plan("context endpoint", (*self.base, "context", "inspect", self.profile.docker_context,
                    "--format", "{{json .Endpoints.docker.Host}}"), 30, 4096)

    def container_ids(self):
        return Plan("enrolled containers", (*self.compose, "ps", "--all", "--quiet", *self.SERVICES), 30, 4096)

    def mailbox(self, container_id, verb, data=b""):
        if not re.fullmatch(r"[a-f0-9]{64}", container_id) or verb not in self.MAILBOX_VERBS:
            raise EngineError("Mailbox operation is not allowed")
        if not isinstance(data, bytes) or len(data) > 65536:
            raise EngineError("Mailbox input exceeded its bound")
        return Plan("fixed mailbox operation", (*self.base, "exec", "--interactive", container_id,
            "python", "-B", "/app/maintenance_mailbox.py", verb), 30, 65536, data)

    def pull(self, identity):
        identity = ImageIdentity.from_dict(identity.as_dict())
        return Plan("official immutable image pull", (*self.base, "pull", identity.reference), 900)

    def stop(self):
        return Plan("stop both Keep services", (*self.compose, "stop", "--timeout", "90", *self.SERVICES), 150)

    def activate(self, override):
        override = self.paths.check(override)
        if override.parent.parent != self.profile.state / "operations" or override.name not in ("activate.json", "restore.json"):
            raise EngineError("Activation configuration is not in enrolled private state")
        canonical_uuid = __import__("maintenance_protocol").canonical_uuid
        canonical_uuid(override.parent.name)
        document = parse_json(self.paths.read(override))
        if not isinstance(document, dict) or set(document) != {"services"} or set(document["services"]) != set(self.SERVICES):
            raise EngineError("Activation override contains unsupported settings")
        values = []
        for service in self.SERVICES:
            settings = document["services"][service]
            if (not isinstance(settings, dict) or set(settings) != {"image"} or not isinstance(settings['image'],str)
                    or not re.fullmatch(r"(?:brspoon/keep@)?sha256:[a-f0-9]{64}", settings["image"])):
                raise EngineError("Activation override must contain only a fixed immutable image")
            values.append(settings["image"])
        if len(set(values)) != 1:
            raise EngineError("Both Keep services must use the same image")
        return Plan("activate matched services", (*self.compose, "--file", str(override),
            "up", "--detach", "--no-build", "--pull", "never", "--force-recreate", *self.SERVICES), 180)

    def save_image(self, identity, recovery_directory):
        identity = ImageIdentity.from_dict(identity.as_dict())
        recovery_directory = self.paths.check(recovery_directory, directory=True)
        if recovery_directory.parent.parent != self.profile.state / "operations" or recovery_directory.name != "recovery":
            raise EngineError("Image archive destination is outside enrolled recovery state")
        # Preserve the original immutable index. Selecting --platform here
        # changes Docker29's export root to the native manifest and loses it.
        return Plan("save prior immutable image", (*self.base, "image", "save", "--output",
                    str(recovery_directory / "image.tar"), identity.reference), 900, 4096)


class HostEngine:
    """Ports are host-only adapters, never browser-selected actions or parameters.

Adapter requirements are specified in TRIALS.md. Unknown/crashed cutover state
is held until reconcile() proves the original operation's actual side effects.
Explicit resume reads the original accepted journal and reconciles uncertain
effects; it never repeats an install based solely on a phase label.
"""
    def __init__(self, paths, profile, adapter):
        self.paths, self.profile, self.adapter = paths, profile.validate(paths), adapter

    def append(self, journal, request, phase, **details):
        record = journal.append(phase, **details)
        if phase in ('success', 'recovered'):
            # Keep terminal delivery pending if cleanup needs a retry. Resume
            # then retires workers without reopening a committed transaction.
            self.adapter.cleanup_completed_helpers(request)
        # The host journal is authoritative. Mirror only after its durable
        # publication, synchronously at the commit/open/reuse boundaries.
        self.adapter.publish_status(request, record)
        return record

    def execute(self, request):
        journal = Journal(self.paths, self.profile.state, request.request_id, request.payload_sha256)
        with ExitStack() as stack:
            stack.enter_context(operation_lock(self.paths, self.profile.state / "operation.lock"))
            if self.profile.legacy_lock:
                stack.enter_context(operation_lock(self.paths, self.profile.legacy_lock, legacy=True))
            ReplayIndex(self.paths, self.profile.state).accept(request)
            records = journal.records()
            if records:
                if records[-1]["phase"] in TERMINAL:
                    self.adapter.bind(request)
                    if records[-1]['phase'] in ('success', 'recovered'):
                        self.adapter.cleanup_completed_helpers(request)
                    self.adapter.publish_status(request, records[-1])
                    return records[-1]
                if records[-1]["phase"] in ("committed", "recovery-committed"):
                    self.adapter.bind(request)
                    return self.finish_commit(journal, request)
                raise EngineError("Unfinished operation requires reconciliation")
            self.append(journal, request, "accepted", operation=request.operation)
            try:
                self.append(journal, request, "resolving")
                self.adapter.revalidate_authority(request, self.profile)
                self.adapter.assert_runtime(request.expected, self.profile)
                self.adapter.assert_configuration_unchanged(self.profile)
                target = request.expected
                if request.operation == "install":
                    target = self.adapter.resolve_published_release(request.target)
                    if target != request.target:
                        raise EngineError("Published image does not match requested release")
                    self.append(journal, request, "pulling", image=target.as_dict())
                    self.adapter.pull_and_verify(target)
                self.append(journal, request, "draining")
                self.adapter.close_gate_and_drain(request)
                self.adapter.revalidate_authority(request, self.profile)
                self.adapter.assert_runtime(request.expected, self.profile)
                self.adapter.assert_configuration_unchanged(self.profile)
                self.append(journal, request, "stopping")
                self.adapter.stop_and_verify_both(self.profile)
                self.append(journal, request, "backing-up", previous_image=request.expected.as_dict())
                recovery = self.adapter.snapshot_matched_state(request, self.profile)
                self.adapter.verify_matched_recovery(recovery, request.expected, self.profile)
                self.append(journal, request, "prepared", recovery_id=recovery)
                # Every external side-effect intent is durable before it starts.
                self.append(journal, request, "activating", image=target.as_dict())
                self.adapter.activate_both_paused(target, self.profile)
                self.append(journal, request, "verifying")
                self.adapter.verify_both_and_protected_data(target, self.profile)
                self.append(journal, request, "committed", image=target.as_dict())
                return self.finish_commit(journal, request)
            except Exception as error:
                records = journal.records()
                phase = records[-1]["phase"]
                if any(row['phase'] in ('committed', 'recovery-committed') for row in records):
                    # Admission may already be open. Never roll back now.
                    pass
                elif phase in ("activating", "verifying"):
                    self.append(journal, request, "recovery-needed", reason=type(error).__name__)
                    self.recover(journal, request)
                elif phase in ("stopping", "backing-up", "prepared"):
                    # A stop/backup failure can leave a partial stop or snapshot.
                    # Keep the gate closed until a fresh inspection reconciles it.
                    self.append(journal, request, "recovery-needed", reason=type(error).__name__)
                else:
                    self.adapter.abort_gate_without_cutover(request)
                    self.append(journal, request, "failed", reason=type(error).__name__)
                raise EngineError("Maintenance did not complete; inspect durable progress") from error

    def recover(self, journal, request):
        """Reconcile uncertain activation before a matching rollback, under locks."""
        self.adapter.reconcile(request, journal.records(), self.profile)
        if journal.records()[-1]['phase']!='recovering':self.append(journal, request, "recovering")
        try:
            self.adapter.stop_and_verify_both(self.profile)
            self.adapter.preserve_failed_state(request, self.profile)
            self.adapter.restore_matched_database_config_and_image(request, self.profile)
            self.adapter.verify_both_and_protected_data(request.expected, self.profile)
            self.append(journal, request, "recovery-committed", image=request.expected.as_dict())
            return self.finish_commit(journal, request)
        except Exception as error:
            if not any(row['phase'] == 'recovery-committed' for row in journal.records()):
                self.append(journal, request, "recovery-needed", reason=type(error).__name__)
            raise EngineError("Recovery remains held; preserve all recovery files") from error

    def resume(self,request):
        """Fixed crash recovery of an already accepted operation, under both locks.

Expired accepted requests may finish recovery/delivery, never start a new
cutover. Missing/partial backup seals fail closed. Pre-cutover phases only
abort after proving the original runtime/config; no CLI side effect is replayed.
"""
        journal=Journal(self.paths,self.profile.state,request.request_id,request.payload_sha256)
        with ExitStack() as stack:
            stack.enter_context(operation_lock(self.paths,self.profile.state/'operation.lock'))
            if self.profile.legacy_lock:
                stack.enter_context(operation_lock(self.paths,self.profile.legacy_lock,legacy=True))
            records=journal.records()
            if not records:raise EngineError('An unaccepted operation cannot be resumed')
            ReplayIndex(self.paths,self.profile.state).accept(request)
            self.adapter.bind(request)
            phase=records[-1]['phase']
            if phase in TERMINAL:
                if phase in ('success', 'recovered'):
                    self.adapter.cleanup_completed_helpers(request)
                self.adapter.publish_status(request, records[-1])
                return records[-1]
            if phase in ('committed','recovery-committed'):return self.finish_commit(journal,request)
            if phase in ('accepted','resolving','pulling','draining','held'):
                self.adapter.abort_gate_without_cutover(request)
                return self.append(journal, request, 'failed',reason='InterruptedBeforeCutover')
            if phase not in ('stopping','backing-up','prepared','activating','verifying','recovering','recovery-needed'):
                raise EngineError('Unknown unfinished state requires operator review')
            # A missing seal or unexpected helper/topology/configuration holds here.
            self.adapter.reconcile(request,records,self.profile)
            if phase not in ('recovering','recovery-needed'):
                self.append(journal, request, 'recovery-needed',reason='InterruptedBeforeCommit')
            return self.recover(journal,request)

    def finish_commit(self, journal, request):
        last = journal.records()[-1]
        if last["phase"] not in ("committed", "recovery-committed"):
            raise EngineError("Operation has no durable commit decision")
        image = ImageIdentity.from_dict(last["details"]["image"])
        # A prior publication may have become visible before its directory/
        # volume flush failed. Reestablish durability before admission opens.
        self.paths.flush_directory(journal.root)
        self.adapter.publish_status(request, last)
        # Admission might have opened before the previous helper crashed.
        # Current legitimate data may differ from the pre-cutover fingerprints.
        self.adapter.verify_committed_runtime(image, self.profile)
        self.adapter.open_gate_and_verify(request)
        return self.append(journal, request, "success" if last["phase"] == "committed" else "recovered", image=image.as_dict())
