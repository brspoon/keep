#!/usr/bin/env python3
"""Run an isolated, offline container backup/restore and rollback trial.

The candidate and optional previous image must already be present locally.
This tool never pulls images, contacts application integrations, or uses an
existing Compose project or data volume.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import uuid


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "scripts" / "install_keep.py"
COMPOSE_SOURCE = ROOT / "compose.yml"
FIXTURE = ROOT / "tests" / "portable_trial.py"
IMAGE_REF = re.compile(
    r"^(?:[A-Za-z0-9._-]+(?::[0-9]+)?/)?[A-Za-z0-9._/-]+"
    r"(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}|@sha256:[a-fA-F0-9]{64})$"
)
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
HEX256 = re.compile(r"^[0-9a-f]{64}$")
REVISION = re.compile(r"^[0-9a-f]{40}$")
VERSION = re.compile(r"^\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?$")
COMPOSE_MINIMUM = (2, 24, 4)
HEALTH_TIMEOUT = 180
DB_PATH = "/app/data/keep.sqlite3"
BACKUP_PATH = "/app/data/.portable-trial-preupgrade.sqlite3"
RESTORE_SOURCE = "/recovery-source/.portable-trial-preupgrade.sqlite3"


class TrialError(RuntimeError):
    pass


def _run(argv, *, label, cwd=None, timeout=120, expected_codes=(0,), env=None,
         include_stderr=False):
    try:
        result = subprocess.run(
            [str(part) for part in argv], cwd=cwd, env=env,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            timeout=timeout, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise TrialError(f"{label} could not complete ({type(error).__name__})") from error
    if result.returncode not in expected_codes:
        detail = ""
        if include_stderr:
            # portable_backup emits fixed, data-free validation messages. Bound
            # this diagnostic and strip controls before it reaches CI logs.
            safe_stderr = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", result.stderr)
            safe_stderr = safe_stderr[-1200:].strip()
            if safe_stderr:
                detail = f": {safe_stderr}"
        raise TrialError(f"{label} failed with exit code {result.returncode}{detail}")
    return result


def _parse_compose_version(text):
    match = re.search(r"(?:Docker Compose version )?v?(\d+)\.(\d+)\.(\d+)", text)
    if not match:
        raise TrialError("Could not identify Docker Compose v2 version")
    version = tuple(int(part) for part in match.groups())
    if version < COMPOSE_MINIMUM:
        raise TrialError("Docker Compose 2.24.4 or later is required for !reset/!override")
    return version


def _image_metadata(reference):
    if not IMAGE_REF.fullmatch(reference):
        raise TrialError("Image reference must be an explicit tag or sha256 digest")
    result = _run(["docker", "image", "inspect", reference], label="local image inspection")
    try:
        records = json.loads(result.stdout)
        image = records[0]
        labels = image.get("Config", {}).get("Labels") or {}
    except (json.JSONDecodeError, IndexError, AttributeError, TypeError) as error:
        raise TrialError("Docker returned incomplete local image metadata") from error
    image_id = image.get("Id")
    version = labels.get("org.opencontainers.image.version")
    revision = labels.get("org.opencontainers.image.revision")
    if not isinstance(image_id, str) or not SHA256.fullmatch(image_id):
        raise TrialError("Image does not have a valid immutable Docker image ID")
    if not isinstance(version, str) or not VERSION.fullmatch(version):
        raise TrialError("Image is missing a valid version label")
    if not isinstance(revision, str) or not REVISION.fullmatch(revision):
        raise TrialError("Image is missing a full source revision label")
    return {
        "reference": reference,
        "runtime_reference": image_id,
        "image_id": image_id,
        "version": version,
        "revision": revision,
        "architecture": image.get("Architecture"),
        "os": image.get("Os"),
    }


def _safe_component(value, label):
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,49}", value):
        raise TrialError(f"Invalid {label} identity")
    return value


class Trial:
    def __init__(self, candidate, previous, evidence_path, health_timeout):
        self.candidate = candidate
        self.previous = previous
        self.health_timeout = health_timeout
        self.project = _safe_component("keep-recovery-" + uuid.uuid4().hex[:12], "project")
        self.temp = Path(tempfile.mkdtemp(prefix=self.project + "-"))
        os.chmod(self.temp, 0o700)
        self.compose_file = self.temp / "compose.yml"
        shutil.copyfile(COMPOSE_SOURCE, self.compose_file)
        os.chmod(self.compose_file, 0o600)
        self.fixture = FIXTURE.resolve(strict=True)
        self.volume_names = {
            name: f"{self.project}-{name}" for name in
            ("fresh-data", "fixture-data", "restore-data", "rollback-data")
        }
        self.evidence_path = evidence_path
        self.report = {
            "schema": "keep.portable-container-trial.v1",
            "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "fixture_sha256": hashlib.sha256(FIXTURE.read_bytes()).hexdigest(),
            "compose_source_sha256": hashlib.sha256(COMPOSE_SOURCE.read_bytes()).hexdigest(),
            "project": self.project,
            "candidate": candidate,
            "previous": previous,
            "images": {},
            "phases": [],
            "cleanup": {"containers_removed": False, "volumes_removed": []},
            "limitations": [
                "Synthetic Plex owner session is verified; no live Plex authorization is attempted.",
                "The failed-upgrade probe adds only a dedicated fixture marker table and exits nonzero; it is not a production migration.",
                "A previous image with incompatible fixture schemas can prevent cross-version verification; this is recorded as a failed trial.",
            ],
            "outcome": "running",
        }
        self.report["images"]["candidate"] = candidate
        if previous:
            self.report["images"]["previous"] = previous
        self.overlays = []
        self.overlay_images = {}

    def assert_trial_names_unused(self):
        for volume_name in self.volume_names.values():
            result = subprocess.run(["docker", "volume", "inspect", volume_name],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    text=True, check=False)
            if result.returncode == 0:
                raise TrialError("Generated trial volume name already exists; refusing to reuse it")
            if "no such volume" not in result.stderr.lower():
                raise TrialError("Could not verify that generated trial volume names are unused")
        for kind, argv in (
            ("container", ["docker", "ps", "-aq", "--filter", f"label=com.docker.compose.project={self.project}"]),
            ("network", ["docker", "network", "ls", "-q", "--filter", f"label=com.docker.compose.project={self.project}"]),
        ):
            result = _run(argv, label=f"trial {kind} collision check")
            if result.stdout.strip():
                raise TrialError(f"Generated trial {kind} project identity already exists")

    def phase(self, name, action):
        entry = {"name": name, "status": "running"}
        self.report["phases"].append(entry)
        try:
            details = action()
            if isinstance(details, dict):
                entry.update(details)
            entry["status"] = "passed"
            return details
        except Exception as error:
            entry["status"] = "failed"
            entry["error"] = f"{type(error).__name__}: {error}"
            self.report["outcome"] = "failed"
            raise

    def write_overlay(self, image, data_volume, recovery_source=None):
        image_metadata = image if isinstance(image, dict) else None
        image = image_metadata["runtime_reference"] if image_metadata else image
        data_volume = _safe_component(data_volume, "data volume")
        overlay = self.temp / f"compose-{len(self.overlays)}.yml"
        extra_mount = ""
        volume_decl = ""
        if recovery_source:
            recovery_source = _safe_component(recovery_source, "recovery source volume")
            extra_mount = (
                "\n      - type: volume\n"
                "        source: recovery-source\n"
                "        target: /recovery-source\n"
                "        read_only: true\n"
            )
            volume_decl = (
                "\n  recovery-source:\n"
                f"    name: {recovery_source}\n"
                "    external: true\n"
            )
        content = f'''services:
  keep-app:
    image: {image}
    restart: "no"
    network_mode: none
    ports: !reset []
    healthcheck:
      interval: 1s
      timeout: 5s
      retries: 3
      start_period: 1s
    volumes: !override
      - type: volume
        source: keep-data
        target: /app/data
      - type: bind
        source: {self.fixture}
        target: /trial/portable_trial.py
        read_only: true{extra_mount}
  keep-digest:
    image: {image}
    restart: "no"
    network_mode: none
    ports: !reset []
    healthcheck:
      interval: 1s
      timeout: 5s
      retries: 3
      start_period: 1s
    volumes: !override
      - type: volume
        source: keep-data
        target: /app/data
volumes:
  keep-data:
    name: {data_volume}
{volume_decl}'''
        overlay.write_text(content, encoding="utf-8")
        os.chmod(overlay, 0o600)
        self.overlays.append(overlay)
        _run(self.compose(overlay) + ["config", "--quiet"], label="validate isolated offline Compose overlay",
             cwd=self.temp)
        self.overlay_images[overlay] = image_metadata
        return overlay

    def compose(self, overlay):
        return ["docker", "compose", "--project-directory", str(self.temp),
                "--project-name", self.project, "-f", str(self.compose_file),
                "-f", str(overlay)]

    def compose_run(self, overlay, args, *, label, expected_codes=(0,), timeout=120,
                    include_stderr=False):
        return _run(self.compose(overlay) + ["run", "--rm", "--no-deps", "--pull", "never",
                                               "--entrypoint", args[0], "keep-app", *args[1:]],
                    label=label, cwd=self.temp, timeout=timeout, expected_codes=expected_codes,
                    include_stderr=include_stderr)

    def compose_exec(self, overlay, args, *, label, timeout=60):
        return _run(self.compose(overlay) + ["exec", "-T", "keep-app", *args],
                    label=label, cwd=self.temp, timeout=timeout)

    def start(self, overlay, *, label):
        _run(self.compose(overlay) + ["up", "-d", "--no-build", "--pull", "never",
                                      "keep-app", "keep-digest"],
             label=f"{label} start", cwd=self.temp, timeout=120)
        self.wait_healthy(overlay, label=label)

    def wait_healthy(self, overlay, *, label):
        compose = self.compose(overlay)
        deadline = time.monotonic() + self.health_timeout
        last = {}
        while time.monotonic() < deadline:
            all_healthy = True
            for service in ("keep-app", "keep-digest"):
                ids = _run(compose + ["ps", "-q", service], label=f"{label} container query",
                           cwd=self.temp).stdout.split()
                if len(ids) != 1:
                    last[service] = "missing-or-duplicate-container"
                    all_healthy = False
                    continue
                health = _run(["docker", "inspect", "--format", "{{if .State.Health}}{{.State.Health.Status}}{{else}}missing{{end}}", ids[0]],
                              label=f"{label} health query").stdout.strip()
                last[service] = health
                if health == "unhealthy" or health == "missing":
                    raise TrialError(f"{label} {service} health is {health}")
                if health != "healthy":
                    all_healthy = False
            if all_healthy:
                expected = self.overlay_images.get(overlay)
                if expected:
                    for service in ("keep-app", "keep-digest"):
                        container_id = _run(compose + ["ps", "-q", service],
                                            label=f"{label} immutable image query",
                                            cwd=self.temp).stdout.split()[0]
                        actual_id = _run(["docker", "inspect", "--format", "{{.Image}}", container_id],
                                         label=f"{label} immutable image inspection").stdout.strip()
                        if actual_id != expected["image_id"]:
                            raise TrialError(f"{label} {service} is not running the initially inspected immutable image ID")
                return last
            time.sleep(2)
        raise TrialError(f"{label} services did not become healthy before timeout: {last}")

    def stop(self, overlay, *, label):
        compose = self.compose(overlay)
        _run(compose + ["stop", "-t", "20", "keep-app", "keep-digest"],
             label=f"{label} stop", cwd=self.temp, timeout=45)
        ids = _run(compose + ["ps", "-aq"], label=f"{label} stopped-container query",
                    cwd=self.temp).stdout.split()
        for container_id in ids:
            state = _run(["docker", "inspect", "--format", "{{.State.Status}}", container_id],
                         label=f"{label} stopped-state query").stdout.strip()
            if state == "running":
                raise TrialError(f"{label} left a service running")
        return {"stopped_services": ["keep-app", "keep-digest"]}

    def remove_containers(self, overlay):
        _run(self.compose(overlay) + ["rm", "-sf"], label="remove exact trial containers",
             cwd=self.temp, timeout=90)

    def check_fresh_setup(self, overlay):
        code = (
            "import urllib.request; r=urllib.request.urlopen('http://127.0.0.1:5000/setup',timeout=5); "
            "body=r.read(); assert r.status==200 and b'name=\\\"bootstrap_code\\\"' in body"
        )
        self.compose_exec(overlay, ["python", "-c", code], label="check fresh unowned setup")
        return {"unowned_setup_page": "200 bootstrap form"}

    def fingerprint(self, overlay, *, label):
        result = self.compose_run(overlay, ["python", "/trial/portable_trial.py", "fingerprint"],
                                  label=label)
        try:
            data = json.loads(result.stdout.strip().splitlines()[-1])
        except (json.JSONDecodeError, IndexError) as error:
            raise TrialError(f"{label} returned no valid JSON fingerprint") from error
        if data.get("integrity") != "ok" or not HEX256.fullmatch(str(data.get("global_sha256", ""))):
            raise TrialError(f"{label} returned an incomplete fingerprint")
        return data

    @staticmethod
    def compare_fingerprints(expected, actual, *, label, worker_started=False):
        old_tables = expected.get("tables", {})
        new_tables = actual.get("tables", {})
        common = sorted(set(old_tables) & set(new_tables))
        if not common:
            raise TrialError(f"{label} has no comparable fixture tables")
        removed = sorted(set(old_tables) - set(new_tables))
        if removed:
            raise TrialError(f"{label} removed fingerprinted tables: {', '.join(removed)}")
        # All columns, including job observations, must survive restore exactly
        # before startup. Afterward the real worker may replace its observations;
        # every other table still has to match the stopped snapshot.
        compared = [table for table in common if not (worker_started and table == "background_jobs")]
        changed = [table for table in compared if old_tables[table] != new_tables[table]]
        if changed:
            raise TrialError(f"{label} changed fixture state in tables: {', '.join(changed)}")
        return {"common_tables": compared,
                "worker_observations_may_advance": worker_started,
                "tables_added": sorted(set(new_tables) - set(old_tables)),
                "tables_removed": sorted(set(old_tables) - set(new_tables)),
                "global_sha256": actual["global_sha256"]}

    def seed_fixture(self, overlay):
        self.compose_run(overlay, ["python", "/trial/portable_trial.py", "seed"],
                         label="seed synthetic recovery fixture")
        self.compose_run(overlay, ["python", "/trial/portable_trial.py", "verify"],
                         label="verify seeded fixture before worker startup")
        return {"fixture": "seeded", "stopped_fixture_verification": "passed"}

    def verify_fixture(self, overlay, *, label):
        self.compose_exec(overlay, ["python", "/trial/portable_trial.py", "verify", "--worker-started"],
                          label=label)
        return {"fixture_verification": "passed", "login": "synthetic local account verified"}

    def fresh_install(self, overlay):
        self.start(overlay, label="fresh install")
        setup = self.check_fresh_setup(overlay)
        self.stop(overlay, label="fresh install")
        return {"services_healthy": True, **setup, "unowned": True}

    def backup(self, overlay, *, label):
        self.compose_run(overlay, ["python", "-m", "portable_backup", "backup",
                                   "--database", DB_PATH, "--output", BACKUP_PATH], label=label,
                         include_stderr=True)
        snapshot = self.compose_run(overlay, ["python", "-c",
            "import hashlib,os; p='" + BACKUP_PATH + "'; print(hashlib.sha256(open(p,'rb').read()).hexdigest())"],
            label=f"{label} checksum")
        digest = snapshot.stdout.strip().splitlines()[-1]
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise TrialError(f"{label} returned an invalid snapshot hash")
        return digest

    def prepare_existing_data_directory(self, overlay):
        # Earlier images copied up a 0755 directory. Perform the documented
        # stopped-service migration only on this trial's freshly seeded volume.
        # The container keeps its ordinary non-root UID; no recursive changes.
        code = '''import json, os, stat
path = "/app/data"
info = os.lstat(path)
if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
    raise SystemExit("Trial data directory must be a real directory owned by the runtime user")
before = stat.S_IMODE(info.st_mode)
os.chmod(path, 0o700)
after = os.lstat(path)
assert stat.S_IMODE(after.st_mode) == 0o700 and after.st_uid == info.st_uid
print(json.dumps({"previous_mode": oct(before), "mode": "0o700", "uid": info.st_uid,
                  "recursive": False}, sort_keys=True))
'''
        result = self.compose_run(overlay, ["python", "-c", code],
                                  label="prepare the stopped trial data directory")
        return json.loads(result.stdout.strip().splitlines()[-1])

    def preserve_failed_database(self, overlay, suffix):
        code = '''import hashlib, json
from pathlib import Path
base = Path("/app/data/keep.sqlite3")
suffix = "''' + suffix + '''"
extensions = ("", "-wal", "-shm", "-journal")
pairs = [(Path(str(base) + ext), Path(str(base) + "." + suffix + ext)) for ext in extensions]
for source, target in pairs:
    if source.is_symlink() or target.is_symlink() or target.exists():
        raise SystemExit(41)
for source, target in pairs:
    if source.exists():
        source.rename(target)
print(json.dumps([{"name": target.name, "sha256": hashlib.sha256(target.read_bytes()).hexdigest()}
                  for source, target in pairs if target.exists()], sort_keys=True))
'''
        result = self.compose_run(overlay, ["python", "-c", code], label="preserve failed candidate database")
        try:
            files = json.loads(result.stdout.strip().splitlines()[-1])
        except (json.JSONDecodeError, IndexError) as error:
            raise TrialError("Could not verify preserved database and sidecar hashes") from error
        if not any(item["name"].endswith("." + suffix) for item in files):
            raise TrialError("Failed-upgrade database was not preserved")
        return files

    def fail_upgrade(self, overlay):
        code = (
            "import sqlite3,sys; db=sqlite3.connect('/app/data/keep.sqlite3'); "
            "db.execute('CREATE TABLE IF NOT EXISTS portable_trial_failed_upgrade (trial_id TEXT PRIMARY KEY)'); "
            "db.execute('INSERT OR REPLACE INTO portable_trial_failed_upgrade VALUES (?)',('" + self.project + "',)); "
            "db.commit(); db.close(); sys.exit(73)"
        )
        result = self.compose_run(overlay, ["python", "-c", code], label="intentional failed-upgrade probe",
                                  expected_codes=(73, 0))
        if result.returncode != 73:
            raise TrialError("Intentional failed-upgrade probe did not exit with its expected failure code")
        return {"exit_code": 73, "mutation": "dedicated synthetic marker table only"}

    def remove_and_cleanup(self, overlay):
        try:
            self.remove_containers(overlay)
            self.report["cleanup"]["containers_removed"] = True
        except Exception as error:
            self.report["cleanup"]["container_cleanup_error"] = f"{type(error).__name__}: {error}"
        networks = subprocess.run(
            ["docker", "network", "ls", "--filter", f"label=com.docker.compose.project={self.project}", "--format", "{{.Name}}"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
        if networks.returncode != 0:
            self.report['cleanup']['network_inventory_error'] = 'Could not verify exact trial network inventory'
        if networks.returncode == 0:
            for network_name in networks.stdout.splitlines():
                inspected_network = subprocess.run(["docker", "network", "inspect", network_name],
                                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                                   text=True, check=False)
                try:
                    network = json.loads(inspected_network.stdout)[0]
                    if (network.get("Name") != network_name or
                            (network.get("Labels") or {}).get("com.docker.compose.project") != self.project):
                        raise ValueError("network ownership mismatch")
                except (json.JSONDecodeError, IndexError, TypeError, ValueError):
                    self.report["cleanup"].setdefault("preserved_networks", []).append(network_name)
                    continue
                removed_network = subprocess.run(["docker", "network", "rm", network_name],
                                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                                 text=True, check=False)
                if removed_network.returncode == 0:
                    self.report["cleanup"].setdefault("networks_removed", []).append(network_name)
                else:
                    self.report["cleanup"].setdefault("preserved_networks", []).append(network_name)
        for volume_name in self.volume_names.values():
            inspected = subprocess.run(["docker", "volume", "inspect", volume_name],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       text=True, check=False)
            if inspected.returncode != 0:
                continue
            try:
                record = json.loads(inspected.stdout)[0]
                labels = record.get("Labels") or {}
                if record.get("Name") != volume_name or labels.get("com.docker.compose.project") != self.project:
                    self.report["cleanup"].setdefault("preserved_volumes", []).append(volume_name)
                    continue
            except (json.JSONDecodeError, IndexError, TypeError):
                self.report["cleanup"].setdefault("preserved_volumes", []).append(volume_name)
                continue
            result = subprocess.run(["docker", "volume", "rm", volume_name],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    text=True, check=False)
            if result.returncode == 0:
                self.report["cleanup"]["volumes_removed"].append(volume_name)
            else:
                self.report["cleanup"].setdefault("preserved_volumes", []).append(volume_name)
        shutil.rmtree(self.temp, ignore_errors=True)

    def write_report(self, path):
        path = Path(path).expanduser().absolute()
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.report["evidence_path"] = str(path)
        report_bytes = (json.dumps(self.report, sort_keys=True, indent=2) + "\n").encode()
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        try:
            descriptor = os.open(path, flags, 0o600)
        except FileExistsError:
            self.report.setdefault("report_error", "evidence path already exists")
            self.report.pop("evidence_path", None)
            return
        try:
            with os.fdopen(descriptor, "wb") as output:
                output.write(report_bytes)
                output.flush()
                os.fsync(output.fileno())
            os.chmod(path, 0o600)
        except OSError as error:
            self.report.setdefault("report_error", type(error).__name__)
            raise


def _network_safe_url(value):
    if not value.startswith("https://") or not value.endswith(".invalid"):
        raise TrialError("Trial KEEP_URL must be a synthetic .invalid HTTPS origin")
    if any(char.isspace() or ord(char) < 32 for char in value):
        raise TrialError("Trial KEEP_URL contains invalid characters")


def run_trial(args):
    _parse_compose_version(_run(["docker", "compose", "version", "--short"],
                                label="Docker Compose version check").stdout)
    _network_safe_url(args.url)
    candidate = _image_metadata(args.candidate_image)
    previous = _image_metadata(args.previous_image) if args.previous_image else None
    if previous and previous["image_id"] == candidate["image_id"]:
        raise TrialError("Previous image resolves to the same immutable image ID as candidate")
    trial = Trial(candidate, previous, args.evidence, args.health_timeout)
    latest_overlay = None
    seed_image = previous or candidate
    try:
        trial.assert_trial_names_unused()
        env_path = trial.temp / ".env"
        install = [sys.executable, str(INSTALLER), "--url", args.url,
                   "--image", candidate["reference"], "--env", str(env_path)]

        def install_twice():
            first = _run(install, label="first real installer run", cwd=ROOT)
            before = env_path.read_bytes()
            if stat.S_IMODE(env_path.stat().st_mode) != 0o600:
                raise TrialError("Installer did not restrict .env to mode 0600")
            second = _run(install, label="idempotent real installer rerun", cwd=ROOT)
            after = env_path.read_bytes()
            if stat.S_IMODE(env_path.stat().st_mode) != 0o600:
                raise TrialError("Installer rerun did not retain .env mode 0600")
            if before != after:
                raise TrialError("Installer rerun changed the existing generated .env")
            values = dict(line.split("=", 1) for line in after.decode().splitlines() if "=" in line)
            flask, webhook = values.get("FLASK_SECRET_KEY"), values.get("KEEP_WEBHOOK_SECRET")
            if not flask or not webhook or flask == webhook or values.get("KEEP_IMAGE") != candidate["reference"]:
                raise TrialError("Installer did not generate distinct secrets and select the candidate image")
            output = first.stdout + second.stdout
            if any(secret in output for secret in (flask, webhook)):
                raise TrialError("Installer output unexpectedly displayed a generated secret")
            return {"env_mode": "0600", "rerun_unchanged": True,
                    "distinct_secrets": True, "secrets_printed": False}

        trial.phase("installer-idempotence", install_twice)

        latest_overlay = trial.write_overlay(candidate, trial.volume_names["fresh-data"])
        trial.phase("fresh-install", lambda: trial.fresh_install(latest_overlay))
        trial.remove_containers(latest_overlay)

        fixture_overlay = trial.write_overlay(seed_image, trial.volume_names["fixture-data"])
        latest_overlay = fixture_overlay
        trial.phase("seed-recovery-fixture", lambda: trial.seed_fixture(fixture_overlay))
        trial.start(fixture_overlay, label="fixture baseline")
        trial.phase("verify-recovery-fixture", lambda: trial.verify_fixture(
            fixture_overlay, label="verify original fixture"))
        trial.stop(fixture_overlay, label="fixture baseline")
        baseline = trial.fingerprint(fixture_overlay, label="fingerprint original fixture")
        trial.report["fixture_baseline"] = baseline
        trial.remove_containers(fixture_overlay)

        candidate_fixture_overlay = trial.write_overlay(candidate, trial.volume_names["fixture-data"])
        latest_overlay = candidate_fixture_overlay
        if previous:
            trial.phase("existing-data-directory-migration", lambda:
                trial.prepare_existing_data_directory(candidate_fixture_overlay))
        backup_hash = trial.phase("preupgrade-backup", lambda: trial.backup(
            candidate_fixture_overlay, label="create pre-upgrade SQLite backup"))
        trial.report["preupgrade_backup_sha256"] = backup_hash

        restore_overlay = trial.write_overlay(candidate, trial.volume_names["restore-data"],
                                              recovery_source=trial.volume_names["fixture-data"])
        latest_overlay = restore_overlay
        trial.phase("restore-to-new-volume", lambda: trial.compose_run(
            restore_overlay, ["python", "-m", "portable_backup", "restore",
                              "--input", RESTORE_SOURCE, "--database", DB_PATH],
            label="restore to the isolated new data volume"))
        restored_before_start = trial.fingerprint(restore_overlay, label="fingerprint restored candidate before startup")
        trial.report["restore_comparison"] = trial.compare_fingerprints(
            baseline, restored_before_start, label="restored candidate before startup")
        trial.start(restore_overlay, label="restored candidate")
        trial.phase("verify-restored-state", lambda: trial.verify_fixture(
            restore_overlay, label="verify restored local login and saved state"))
        trial.stop(restore_overlay, label="restored candidate")
        restored = trial.fingerprint(restore_overlay, label="fingerprint restored candidate")
        trial.report["restore_after_worker_comparison"] = trial.compare_fingerprints(
            baseline, restored, label="restored candidate after worker startup", worker_started=True)
        trial.remove_containers(restore_overlay)

        recreated_before_start = trial.fingerprint(restore_overlay, label="fingerprint candidate before recreation")
        trial.report["candidate_recreate_comparison"] = trial.compare_fingerprints(
            restored, recreated_before_start, label="candidate recreation before startup")
        trial.start(restore_overlay, label="candidate recreation")
        trial.phase("candidate-recreate", lambda: trial.verify_fixture(
            restore_overlay, label="verify candidate after recreation"))
        trial.stop(restore_overlay, label="candidate recreation")
        recreated = trial.fingerprint(restore_overlay, label="fingerprint candidate after recreation")
        trial.report["candidate_recreate_after_worker_comparison"] = trial.compare_fingerprints(
            restored, recreated, label="candidate recreation after worker startup", worker_started=True)
        trial.remove_containers(restore_overlay)

        failure_overlay = trial.write_overlay(candidate, trial.volume_names["fixture-data"])
        latest_overlay = failure_overlay
        failed = trial.phase("intentional-failed-upgrade", lambda: trial.fail_upgrade(failure_overlay))
        trial.report["failed_upgrade_probe"] = failed
        sidecar_suffix = "failed-" + uuid.uuid4().hex[:8]
        preserved = trial.phase("preserve-failed-database", lambda: trial.preserve_failed_database(
            failure_overlay, sidecar_suffix))
        trial.report["preserved_pre-restore_files"] = preserved
        trial.remove_containers(failure_overlay)

        rollback_image = previous or candidate
        rollback_restore_overlay = trial.write_overlay(candidate, trial.volume_names["rollback-data"],
                                                       recovery_source=trial.volume_names["fixture-data"])
        latest_overlay = rollback_restore_overlay
        trial.phase("rollback-restore", lambda: trial.compose_run(
            rollback_restore_overlay, ["python", "-m", "portable_backup", "restore",
                                       "--input", RESTORE_SOURCE, "--database", DB_PATH],
            label="restore pre-upgrade backup after failed candidate"))
        trial.remove_containers(rollback_restore_overlay)
        rollback_overlay = trial.write_overlay(rollback_image, trial.volume_names["rollback-data"],
                                               recovery_source=trial.volume_names["fixture-data"])
        latest_overlay = rollback_overlay
        rollback_before_start = trial.fingerprint(rollback_overlay, label="fingerprint recovered fixture before startup")
        trial.report["rollback_comparison"] = trial.compare_fingerprints(
            baseline, rollback_before_start, label="pre-upgrade recovery before startup")
        trial.start(rollback_overlay, label="rollback image")
        trial.phase("verify-rollback-state", lambda: trial.verify_fixture(
            rollback_overlay, label="verify recovered pre-upgrade fixture"))
        trial.stop(rollback_overlay, label="rollback image")
        rollback_fingerprint = trial.fingerprint(rollback_overlay, label="fingerprint recovered fixture")
        marker_check = trial.compose_run(rollback_overlay, ["python", "-c",
            "import sqlite3; db=sqlite3.connect('file:" + DB_PATH + "?mode=ro',uri=True); "
            "assert db.execute(\"SELECT 1 FROM sqlite_master WHERE type='table' AND name='portable_trial_failed_upgrade'\").fetchone() is None"],
            label="confirm failed-upgrade marker was rolled back")
        trial.report["failed_upgrade_marker_absent_after_restore"] = marker_check.returncode == 0
        trial.report["rollback_after_worker_comparison"] = trial.compare_fingerprints(
            baseline, rollback_fingerprint, label="pre-upgrade recovery after worker startup", worker_started=True)
        trial.report["outcome"] = "passed"
    except Exception as error:
        trial.report["outcome"] = "failed"
        trial.report.setdefault("failure", f"{type(error).__name__}: {error}")
        raise
    finally:
        if latest_overlay:
            trial.remove_and_cleanup(latest_overlay)
        else:
            shutil.rmtree(trial.temp, ignore_errors=True)
        cleanup = trial.report["cleanup"]
        if (not cleanup.get("containers_removed") or cleanup.get("preserved_volumes") or
                cleanup.get("preserved_networks") or cleanup.get("container_cleanup_error") or
                cleanup.get("network_inventory_error") or
                set(cleanup.get('volumes_removed', [])) != set(trial.volume_names.values())):
            trial.report["outcome"] = "failed"
            trial.report.setdefault("failure", "one or more exact trial resources could not be cleaned")
        evidence = args.evidence or (Path.cwd() / f"portable-recovery-trial-{trial.project}.json")
        trial.write_report(evidence)
    return trial.report

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-image", required=True, help="already-present explicit image tag or sha256 digest")
    parser.add_argument("--previous-image", help="optional already-present prior packaged image tag or digest")
    parser.add_argument("--url", default="https://keep-recovery.invalid", help="synthetic installer HTTPS origin")
    parser.add_argument("--health-timeout", type=int, default=HEALTH_TIMEOUT,
                        help=f"per-start health timeout in seconds (default {HEALTH_TIMEOUT})")
    parser.add_argument("--evidence", type=Path, help="new JSON evidence path; defaults to a unique file in the current directory")
    args = parser.parse_args(argv)
    if not 15 <= args.health_timeout <= 600:
        parser.error("--health-timeout must be between 15 and 600 seconds")
    if args.evidence and args.evidence.exists():
        parser.error("--evidence path already exists; refusing to overwrite")
    try:
        report = run_trial(args)
        print(json.dumps(report, sort_keys=True))
        return 0 if report.get('outcome') == 'passed' else 1
    except (TrialError, OSError) as error:
        print(f"portable container trial failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
