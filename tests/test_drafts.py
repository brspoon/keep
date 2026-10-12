"""Offline maintenance protocol and recovery tests. Synthetic files/processes only; never invoke Docker."""
from __future__ import annotations

from dataclasses import replace
import hashlib
import io
import json
import os
from pathlib import Path
import sqlite3
import sys
import tarfile
import tempfile
import unittest
import uuid

from host_engine import BoundedRunner, DockerPlans, EngineError, HostEngine, Plan
from maintenance_protocol import (Enrollment, ImageIdentity, ProtocolError, canonical,
                                  parse_json, public_status, signed, verify, verify_request)
from private_store import Journal, PrivatePaths, Profile, ReplayIndex, StorageError, operation_lock
from recovery_set import RecoverySet, verify_docker_save

DRAFT = Path(__file__).parent


def image(version="2.26.0", value="a"):
    return ImageIdentity("sha256:" + value*64, "sha256:" + "b"*64,
                         "sha256:" + "c"*64, version, value*40, "amd64")


def request(enrollment, *, operation="install", nonce="1"*64, request_id=None):
    return {"protocol": "keep.maintenance.v1", "install_id": enrollment.install_id,
            "owner_id": enrollment.owner_id, "epoch": enrollment.epoch,
            "request_id": request_id or str(uuid.uuid4()), "operation": operation,
            "credential_version": 3, "issued_at": 1000, "expires_at": 1600, "nonce": nonce,
            "expected": image("2.25.0", "d").as_dict(),
            "target": image().as_dict() if operation == "install" else None}


class DraftFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve())
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.paths = PrivatePaths()
        self.install = self.paths.mkdir(self.root / "installation")
        self.state = self.paths.mkdir(self.root / "state")
        self.config = self.paths.mkdir(self.root / "docker-config")
        self.paths.publish(self.install / "compose.yml", b"services: {}\n")
        self.paths.publish(self.install / ".env", b"SYNTHETIC_SECRET=do-not-log\n")
        self.paths.publish(self.root / "docker", b"not-an-executable")
        self.profile = Profile(self.install, self.state, self.root / "docker", self.config,
            "synthetic-local", "unix:///synthetic-local.sock", "synthetic-daemon", "keep-trial",
            "keep-trial-data", (self.install / "compose.yml",), self.install / ".env")
        self.enrollment = Enrollment.create("local-owner")

    def command(self, **kwargs):
        return verify_request(self.enrollment, signed(self.enrollment, request(self.enrollment, **kwargs)), now=1200)


class ProtocolTests(DraftFixture):
    def test_signed_install_and_restart_accept_only_enrolled_fixed_contract(self):
        self.assertEqual(self.command().operation, "install")
        self.assertIsNone(self.command(operation="restart").target)

    def test_foreign_enrollment_signature_and_extra_fields_fail(self):
        body = request(self.enrollment)
        foreign = Enrollment.create("local-owner")
        with self.assertRaises(ProtocolError):
            verify_request(foreign, signed(self.enrollment, body), now=1200)
        for field, value in (("path", "/etc/passwd"), ("project", "other-app"), ("options", ["--privileged"])):
            changed = {**body, field: value}
            with self.subTest(field=field), self.assertRaises(ProtocolError):
                verify_request(self.enrollment, signed(self.enrollment, changed), now=1200)

    def test_duplicate_json_fields_and_invalid_numbers_fail(self):
        for raw in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}'):
            with self.subTest(raw=raw), self.assertRaises(ProtocolError):
                parse_json(raw)

    def test_time_credential_and_uuid_validation_is_strict(self):
        for field, value in (("issued_at", True), ("expires_at", 900), ("expires_at", 3000),
                             ("credential_version", -1), ("request_id", "../escape"),
                             ("nonce", "a"*64 + "\n")):
            body = {**request(self.enrollment), field: value}
            with self.subTest(field=field, value=value), self.assertRaises(ProtocolError):
                verify_request(self.enrollment, signed(self.enrollment, body), now=1200)

    def test_authenticated_status_contains_no_host_configuration(self):
        command = self.command()
        payload = verify(self.enrollment, public_status(self.enrollment, command,
                         sequence=2, phase="draining"))
        self.assertEqual(set(payload), {"protocol", "install_id", "request_id", "sequence", "phase", "result_code"})
        self.assertNotIn("do-not-log", str(payload))


class PrivateStoreTests(DraftFixture):
    def test_private_files_do_not_overwrite_and_symlinks_are_rejected(self):
        target = self.root / "private"
        self.paths.publish(target, b"original")
        with self.assertRaises(StorageError):
            self.paths.publish(target, b"replacement")
        link = self.root / "link"
        link.symlink_to(target)
        with self.assertRaises(StorageError):
            self.paths.read(link)
        self.assertEqual(self.paths.read(target), b"original")

    @unittest.skipIf(os.name == "nt", "POSIX mode test; native Windows ACL cases are specified separately")
    def test_world_readable_private_file_and_untrusted_ancestor_fail(self):
        self.paths.publish(self.root / "visible", b"synthetic")
        os.chmod(self.root / "visible", 0o644)
        with self.assertRaises(StorageError):
            self.paths.read(self.root / "visible")
        unsafe = self.root / "unsafe"
        unsafe.mkdir(mode=0o777)
        os.chmod(unsafe, 0o777)
        inner = unsafe / "inner"
        inner.mkdir(mode=0o700)
        with self.assertRaises(StorageError):
            self.paths.check(inner, directory=True)

    def test_legacy_lock_uses_exact_fixed_path_and_conflicts(self):
        git = self.paths.mkdir(self.install / ".git")
        profile = replace(self.profile, legacy_lock=git / "keep-deploy.lock")
        profile.validate(self.paths)
        with operation_lock(self.paths, profile.legacy_lock, legacy=True):
            with self.assertRaises(StorageError):
                with operation_lock(self.paths, profile.legacy_lock, legacy=True):
                    self.fail("A second holder must not acquire the same inode")
        with self.assertRaises(StorageError):
            replace(profile, legacy_lock=self.root / "arbitrary.lock").validate(self.paths)

    def test_profile_rejects_remote_context_and_configuration_outside_install(self):
        with self.assertRaises(StorageError):
            replace(self.profile, docker_endpoint="tcp://remote.example:2376").validate(self.paths)
        with self.assertRaises(StorageError):
            replace(self.profile, env_file=self.root / "elsewhere").validate(self.paths)

    def test_journal_hash_chain_rejects_tamper_gaps_and_request_reuse(self):
        command = self.command()
        journal = Journal(self.paths, self.state, command.request_id, command.payload_sha256)
        journal.append("accepted")
        journal.append("resolving")
        self.assertEqual(journal.disposition_after_crash(), "revalidate-before-resume")
        with self.assertRaises(StorageError):
            journal.append("success")
        body = parse_json(self.paths.read(journal.root / "000.json"))
        self.paths.publish(journal.root / "000.json", canonical({**body, "details": {"tampered": True}}), overwrite=True)
        with self.assertRaises(StorageError):
            journal.records()

    def test_nonce_replay_ledger_allows_same_request_and_rejects_another(self):
        first = self.command()
        ledger = ReplayIndex(self.paths, self.state)
        ledger.accept(first)
        ledger.accept(first)
        with self.assertRaises(StorageError):
            ledger.accept(self.command())


class RunnerTests(DraftFixture):
    def test_environment_cannot_redirect_context_or_compose(self):
        runner = BoundedRunner(self.profile)
        saved = dict(os.environ)
        try:
            os.environ.update(DOCKER_HOST="tcp://wrong", COMPOSE_FILE="wrong", KEEP_IMAGE="wrong", FLASK_SECRET_KEY="do-not-log")
            environment = runner.environment()
        finally:
            os.environ.clear()
            os.environ.update(saved)
        self.assertNotIn("DOCKER_HOST", environment)
        self.assertNotIn("COMPOSE_FILE", environment)
        self.assertNotIn("KEEP_IMAGE", environment)
        self.assertNotIn("FLASK_SECRET_KEY", environment)
        self.assertEqual(environment["DOCKER_CONFIG"], str(self.config))

    def test_bounded_runner_handles_full_stdin_without_a_shell(self):
        data = b"x"*65536
        plan = Plan("synthetic echo", (sys.executable, "-c", "import sys;sys.stdout.buffer.write(sys.stdin.buffer.read())"), 5, 65536, data)
        self.assertEqual(BoundedRunner(self.profile).run(plan), data)

    def test_output_overflow_and_timeout_fail_with_static_diagnostics(self):
        for code, timeout in (("import sys;sys.stdout.write('x'*65536)", 5), ("import time;time.sleep(5)", 1)):
            plan = Plan("synthetic boundary", (sys.executable, "-c", code), timeout, 32)
            with self.subTest(code=code), self.assertRaises(EngineError):
                BoundedRunner(self.profile).run(plan)
        plan = Plan("synthetic failure", (sys.executable, "-c", "import sys;sys.stderr.write('do-not-log');sys.exit(1)"), 5)
        with self.assertRaises(EngineError) as result:
            BoundedRunner(self.profile).run(plan)
        self.assertNotIn("do-not-log", str(result.exception))

    def test_fixed_docker_plans_cannot_select_another_repository_or_mailbox_program(self):
        plans = DockerPlans(self.paths, self.profile)
        self.assertEqual(plans.pull(image()).argv[-1], "brspoon/keep@" + "sha256:" + "a"*64)
        self.assertEqual(plans.stop().argv[-2:], ("keep-app", "keep-digest"))
        with self.assertRaises(EngineError):
            plans.mailbox("a"*64, "shell", b"arbitrary")
        with self.assertRaises(EngineError):
            plans.mailbox("a"*64 + "\n", "hello")
        self.assertEqual(plans.mailbox("a"*64, "hello").argv[-3:], ("-B", "/app/maintenance_mailbox.py", "hello"))

    def test_activation_override_contains_only_the_matching_image_for_both_services(self):
        command = self.command()
        journal = Journal(self.paths, self.state, command.request_id, command.payload_sha256)
        path = journal.root.parent / "activate.json"
        valid = {"services": {name: {"image": image().image_id} for name in DockerPlans.SERVICES}}
        self.paths.publish(path, canonical(valid))
        plan = DockerPlans(self.paths, self.profile).activate(path)
        self.assertIn("never", plan.argv)
        self.assertNotIn("--build", plan.argv)
        valid["services"]["keep-app"]["volumes"] = ["/:/host"]
        self.paths.publish(path, canonical(valid), overwrite=True)
        with self.assertRaises(EngineError):
            DockerPlans(self.paths, self.profile).activate(path)


class FakeAdapter:
    """Synthetic side effects; crashes may happen before or after durable intent."""
    def __init__(self, fail=None):
        self.calls, self.fail = [], fail
        self.image = None
        self.gate = "open"
        self.database = "original database"
        self.preserved = []

    def __getattr__(self, name):
        def action(*args):
            self.calls.append(name)
            if name == "close_gate_and_drain": self.gate = "closed"
            if name == "activate_both_paused": self.image, self.database = args[0], "migrated database"
            if name == "preserve_failed_state": self.preserved.append(self.database)
            if name == "restore_matched_database_config_and_image": self.image, self.database = args[0].expected, "original database"
            if name == "open_gate_and_verify": self.gate = "open"
            if name == self.fail:
                self.fail = None
                raise EngineError("synthetic error must not become public output")
            if name == "resolve_published_release": return args[0]
            if name == "snapshot_matched_state": return args[0].request_id
        return action


class EngineTests(DraftFixture):
    def test_successful_install_is_durable_before_gate_opens_and_replay_does_no_work(self):
        command, adapter = self.command(), FakeAdapter()
        engine = HostEngine(self.paths, self.profile, adapter)
        result = engine.execute(command)
        self.assertEqual(result["phase"], "success")
        journal = Journal(self.paths, self.state, command.request_id, command.payload_sha256)
        self.assertEqual([row["phase"] for row in journal.records()][-2:], ["committed", "success"])
        calls = list(adapter.calls)
        self.assertEqual(engine.execute(command), result)
        self.assertEqual(adapter.calls[len(calls):], ['bind', 'publish_status'])

    def test_restart_never_pulls_or_resolves_another_image(self):
        adapter = FakeAdapter()
        self.assertEqual(HostEngine(self.paths, self.profile, adapter).execute(self.command(operation="restart"))["phase"], "success")
        self.assertNotIn("pull_and_verify", adapter.calls)
        self.assertNotIn("resolve_published_release", adapter.calls)

    def test_activation_failure_restores_database_config_and_image_after_preserving_failed_state(self):
        command, adapter = self.command(), FakeAdapter("activate_both_paused")
        with self.assertRaises(EngineError):
            HostEngine(self.paths, self.profile, adapter).execute(command)
        self.assertEqual(adapter.preserved, ["migrated database"])
        self.assertEqual(adapter.database, "original database")
        self.assertEqual(adapter.image, command.expected)
        self.assertLess(adapter.calls.index("preserve_failed_state"), adapter.calls.index("restore_matched_database_config_and_image"))
        self.assertEqual(Journal(self.paths, self.state, command.request_id, command.payload_sha256).records()[-1]["phase"], "recovered")

    def test_gate_delivery_failure_after_commit_never_rolls_back_user_writes(self):
        command, adapter = self.command(), FakeAdapter("open_gate_and_verify")
        engine = HostEngine(self.paths, self.profile, adapter)
        with self.assertRaises(EngineError): engine.execute(command)
        journal = Journal(self.paths, self.state, command.request_id, command.payload_sha256)
        self.assertEqual(journal.disposition_after_crash(), "finish-commit-without-rollback")
        adapter.database = "new user writes after gate opened"
        self.assertEqual(engine.execute(command)["phase"], "success")
        self.assertEqual(adapter.database, "new user writes after gate opened")
        self.assertNotIn("restore_matched_database_config_and_image", adapter.calls)

    def test_unknown_prepared_state_is_held_instead_of_repeating_cutover(self):
        command, adapter = self.command(), FakeAdapter()
        journal = Journal(self.paths, self.state, command.request_id, command.payload_sha256)
        for phase in ("accepted", "resolving", "pulling", "draining", "stopping", "backing-up", "prepared"):
            journal.append(phase)
        with self.assertRaises(EngineError): HostEngine(self.paths, self.profile, adapter).execute(command)
        self.assertEqual(adapter.calls, [])

    def test_backup_failure_keeps_services_gated_until_reconciliation(self):
        command, adapter = self.command(), FakeAdapter("snapshot_matched_state")
        with self.assertRaises(EngineError): HostEngine(self.paths, self.profile, adapter).execute(command)
        self.assertEqual(adapter.gate, "closed")
        self.assertEqual(Journal(self.paths, self.state, command.request_id, command.payload_sha256).records()[-1]["phase"], "recovery-needed")


class RecoveryTests(DraftFixture):
    def archive(self, root, *, unsafe=False):
        layer = b"synthetic uncompressed layer bytes"
        config = canonical({"architecture": "amd64", "os": "linux",
            "config": {"User":"10001:10001","Labels": {"org.opencontainers.image.version": "2.25.0", "org.opencontainers.image.revision": "d"*40,
                "org.opencontainers.image.source":"https://github.com/brspoon/keep"}},
            "rootfs": {"type":"layers","diff_ids": ["sha256:" + hashlib.sha256(layer).hexdigest()]}})
        identifier = "sha256:" + hashlib.sha256(config).hexdigest()
        previous = replace(image("2.25.0", "d"), image_id=identifier)
        config_name = identifier.removeprefix("sha256:") + ".json"
        members = {"manifest.json": canonical([{"Config": config_name, "RepoTags": [], "Layers": ["layer/layer.tar"]}]), config_name: config, "layer/layer.tar": layer}
        if unsafe: members["../escape"] = b"unsafe"
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w") as archive:
            for name, content in members.items():
                member = tarfile.TarInfo(name); member.size = len(content)
                archive.addfile(member, io.BytesIO(content))
        self.paths.publish(root / "image.tar", stream.getvalue())
        return previous

    def recovery(self):
        request_id = str(uuid.uuid4())
        root = self.paths.mkdir(self.root / ("recovery-" + uuid.uuid4().hex))
        database = root / "database.sqlite3"
        with sqlite3.connect(database) as db:
            db.execute("CREATE TABLE protected(value TEXT)")
            db.execute("INSERT INTO protected VALUES ('synthetic protected data')")
            db.execute("PRAGMA user_version=4")
        os.chmod(database, 0o600)
        self.paths.publish(root / "config-0", b"SYNTHETIC_SECRET=preserved\n")
        self.paths.publish(root / "config-1", b"services: {}\n")
        previous = self.archive(root)
        recovery = RecoverySet(self.paths, root, request_id)
        manifest = recovery.seal(previous, (".env", "compose.yml"), daemon_id="synthetic-daemon", project="keep-trial", volume="keep-trial-data")
        return recovery, previous, manifest

    def test_recovery_plan_binds_database_configuration_and_image_to_same_install(self):
        recovery, previous, manifest = self.recovery()
        proof = {"daemon_id": "synthetic-daemon", "project": "keep-trial", "volume": "keep-trial-data",
                 "services": {"keep-app": "stopped", "keep-digest": "stopped"}}
        plan = recovery.restoration_plan(manifest, current_stop_proof=proof)
        self.assertEqual(plan["image"], previous.as_dict())
        self.assertTrue(plan["preserve_failed_database_sidecars"])
        self.assertTrue(plan["preserve_all_recovery_files"])
        self.assertEqual(plan["configuration_slots"], ("config-0", "config-1"))
        self.assertEqual(manifest["database"]["user_version"], 4)
        with self.assertRaises(StorageError):
            recovery.restoration_plan(manifest, current_stop_proof={**proof, "volume": "another-volume"})

    def test_changed_database_configuration_or_archive_blocks_restore_before_mutation(self):
        for artifact in ("database.sqlite3", "config-0", "image.tar"):
            with self.subTest(artifact=artifact):
                recovery, previous, manifest = self.recovery()
                self.paths.publish(recovery.root / artifact, b"damaged", overwrite=True)
                with self.assertRaises((StorageError, sqlite3.Error, tarfile.TarError)):
                    recovery.verify(manifest)

    def test_tar_traversal_and_mismatched_image_metadata_are_rejected_without_extraction(self):
        root = self.paths.mkdir(self.root / "archive")
        previous = self.archive(root, unsafe=True)
        with self.assertRaises(StorageError): verify_docker_save(self.paths, root / "image.tar", previous)
        self.assertFalse((self.root / "escape").exists())


if __name__ == "__main__":
    unittest.main()
