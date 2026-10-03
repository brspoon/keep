#!/usr/bin/env python3
"""Exercise the real installer using a disposable local Compose installation.

The candidate image must already exist locally. An existing Keep project,
volume, or network prevents the trial. No Plex requests or image pulls occur.
"""
from __future__ import annotations

import argparse
import hashlib
from http.cookies import SimpleCookie
import json
import os
from pathlib import Path
import re
import shutil
import socket
import stat
import subprocess
import tempfile
import urllib.request

import install_keep

ROOT = Path(__file__).resolve().parents[1]
PROJECT = "keep"
VOLUME = "keep_keep-data"
NETWORK = "keep_default"
SERVICES = {"keep-app", "keep-digest"}
SHA256 = re.compile(r"sha256:[0-9a-f]{64}\Z")
CONTAINER_ID = re.compile(r"[0-9a-f]{64}\Z")
RESOURCE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*\Z")


class TrialError(RuntimeError):
    pass


class NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


def command(argv, *, cwd=None, timeout=120, input=None):
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith(("KEEP_", "COMPOSE_")) and key != "FLASK_SECRET_KEY"}
    try:
        return subprocess.run(argv, cwd=cwd, timeout=timeout, input=input,
                              capture_output=True, text=True, check=False, env=environment)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise TrialError("A local Docker operation could not complete") from error


def private_evidence(path, report):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "w") as output:
        json.dump(report, output, indent=2, sort_keys=True)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())


PROBE_CODES = """import json, os, sys
from onboarding import Onboarding
codes = json.loads(sys.stdin.read(512))
store = Onboarding(os.environ.get('KEEP_DB_PATH', '/app/data/keep.sqlite3'))
print(json.dumps({'old_valid': store.valid_code(codes[0]), 'new_valid': store.valid_code(codes[1])}))
"""

CLAIM_OWNER = """import json, os, sqlite3, sys
from onboarding import Onboarding, digest
code = sys.stdin.read(128).strip()
path = os.environ.get('KEEP_DB_PATH', '/app/data/keep.sqlite3')
store = Onboarding(path)
store.claim(digest(code), '987654321')
with sqlite3.connect(path) as db:
    integrity = db.execute('PRAGMA integrity_check').fetchone()[0]
    bootstrap = db.execute('SELECT count(*) FROM bootstrap').fetchone()[0]
print(json.dumps({'owner_matches': store.owner() == '987654321', 'integrity': integrity, 'bootstrap_count': bootstrap}))
"""

CHECK_OWNER = """import json, os, sqlite3
from onboarding import Onboarding
path = os.environ.get('KEEP_DB_PATH', '/app/data/keep.sqlite3')
store = Onboarding(path)
with sqlite3.connect(path) as db:
    integrity = db.execute('PRAGMA integrity_check').fetchone()[0]
    bootstrap = db.execute('SELECT count(*) FROM bootstrap').fetchone()[0]
print(json.dumps({'owner_matches': store.owner() == '987654321', 'integrity': integrity, 'bootstrap_count': bootstrap}))
"""


class InstallerTrial:
    def __init__(self, candidate, *, source_directory=ROOT, runner=command, health_timeout=300):
        self.candidate = candidate
        self.source = Path(source_directory).resolve(strict=True)
        self.runner = runner
        self.health_timeout = health_timeout
        self.directory = Path(tempfile.mkdtemp(prefix="keep-install-trial-")).resolve()
        self.directory.chmod(0o700)
        self.admitted = False
        self.report = {"schema": "keep.installer-container-trial.v1", "outcome": "running",
                       "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                       "phases": [], "cleanup": {"preexisting_resources": None, "resources_absent": False},
                       "limitations": ["Owner claim is synthetic; live Plex consent is not exercised."]}

    def run(self, argv, *, input=None):
        result = self.runner(argv, cwd=self.directory, timeout=180, input=input)
        if result.returncode:
            # Docker output may include environment values. Report fixed messages.
            raise TrialError("A disposable installation Docker operation failed")
        return result.stdout.strip()

    def json(self, argv, *, input=None):
        try:
            return json.loads(self.run(argv, input=input))
        except (ValueError, TypeError) as error:
            raise TrialError("Docker returned invalid trial evidence") from error

    def inventory(self):
        containers = self.run(["docker", "ps", "--all", "--quiet", "--no-trunc", "--filter",
                               "label=com.docker.compose.project=" + PROJECT]).split()
        volumes = self.run(["docker", "volume", "ls", "--quiet", "--filter",
                            "label=com.docker.compose.project=" + PROJECT]).split()
        named = self.run(["docker", "volume", "ls", "--quiet", "--filter", "name=" + VOLUME]).split()
        networks = self.run(["docker", "network", "ls", "--format", "{{.Name}}", "--filter",
                             "label=com.docker.compose.project=" + PROJECT]).split()
        named_networks = self.run(["docker", "network", "ls", "--format", "{{.Name}}", "--filter",
                                   "name=" + NETWORK]).split()
        volumes = sorted(set(volumes) | ({VOLUME} if VOLUME in named else set()))
        networks = sorted(set(networks) | ({NETWORK} if NETWORK in named_networks else set()))
        if (any(not CONTAINER_ID.fullmatch(value) for value in containers)
                or any(not RESOURCE_NAME.fullmatch(value) for value in [*volumes, *networks])):
            raise TrialError("Docker returned an invalid resource inventory")
        return {"containers": containers, "volumes": volumes, "networks": networks}

    def preflight(self):
        endpoint = os.environ.get("DOCKER_HOST")
        if not endpoint:
            endpoint = self.json(["docker", "context", "inspect", "--format", "{{json .Endpoints.docker.Host}}"])
        if not isinstance(endpoint, str) or not endpoint.startswith("unix:///"):
            raise TrialError("Installer trial requires a local Unix Docker daemon")
        before = self.inventory()
        self.report["cleanup"]["preexisting_resources"] = before
        if any(before.values()):
            raise TrialError("Existing Keep containers, volumes, or networks prevent the trial")
        images = self.json(["docker", "image", "inspect", self.candidate])
        if not isinstance(images, list) or len(images) != 1:
            raise TrialError("The trial candidate image is missing or ambiguous")
        image = images[0]
        labels = image.get("Config", {}).get("Labels") or {}
        version = (self.source / "VERSION").read_text().strip()
        if (not isinstance(image.get("Id"), str) or not SHA256.fullmatch(image["Id"])
                or labels.get("org.opencontainers.image.version") != version
                or not re.fullmatch(r"[0-9a-f]{40}", labels.get("org.opencontainers.image.revision", ""))
                or image.get("Os") != "linux" or image.get("Architecture") not in ("amd64", "arm64")):
            raise TrialError("The trial candidate does not match this release")
        self.report["candidate"] = {"image_id": image["Id"], "version": version,
                                    "revision": labels["org.opencontainers.image.revision"],
                                    "architecture": image["Architecture"]}
        self.admitted = True

    def resources(self, *, complete):
        inventory = self.inventory()
        if set(inventory["volumes"]) - {VOLUME} or set(inventory["networks"]) - {NETWORK}:
            raise TrialError("Unexpected Keep resources must be preserved")
        records = self.json(["docker", "inspect", *inventory["containers"]]) if inventory["containers"] else []
        if not isinstance(records, list) or len(records) != len(inventory["containers"]):
            raise TrialError("Container inspection did not match the inventory")
        services = set()
        for record in records:
            labels = record.get("Config", {}).get("Labels") or {}
            service = labels.get("com.docker.compose.service")
            directory = labels.get("com.docker.compose.project.working_dir", "")
            if (record.get("Id") not in inventory["containers"] or service not in SERVICES or service in services
                    or labels.get("com.docker.compose.project") != PROJECT
                    or not directory or Path(directory).resolve() != self.directory):
                raise TrialError("A Keep container belongs to another installation; preserving resources")
            services.add(service)
            if complete and (not record.get("State", {}).get("Running")
                             or record.get("State", {}).get("Health", {}).get("Status") != "healthy"):
                raise TrialError("The installer did not leave both services healthy")
        volumes = self.json(["docker", "volume", "inspect", *inventory["volumes"]]) if inventory["volumes"] else []
        if not isinstance(volumes, list) or len(volumes) != len(inventory["volumes"]):
            raise TrialError("Volume inspection did not match the inventory")
        for record in volumes:
            labels = record.get("Labels") or {}
            if (record.get("Name") != VOLUME or labels.get("com.docker.compose.project") != PROJECT
                    or labels.get("com.docker.compose.volume") != "keep-data" or not record.get("CreatedAt")):
                raise TrialError("Keep data volume ownership is not verified; preserving it")
        networks = self.json(["docker", "network", "inspect", *inventory["networks"]]) if inventory["networks"] else []
        if not isinstance(networks, list) or len(networks) != len(inventory["networks"]):
            raise TrialError("Network inspection did not match the inventory")
        for record in networks:
            labels = record.get("Labels") or {}
            if (record.get("Name") != NETWORK or labels.get("com.docker.compose.project") != PROJECT
                    or not isinstance(record.get("Id"), str) or not CONTAINER_ID.fullmatch(record["Id"])):
                raise TrialError("Keep network ownership is not verified; preserving it")
        if complete and (services != SERVICES or len(volumes) != 1 or len(networks) != 1):
            raise TrialError("The installer did not create the complete isolated resource set")
        return {**inventory, "volume_creation": {record["Name"]: record["CreatedAt"] for record in volumes},
                "network_ids": {record["Name"]: record["Id"] for record in networks}}

    def start(self, port):
        return install_keep.start_installation(
            self.directory, requested_image=self.candidate, bind_address="127.0.0.1", port=port,
            source_directory=self.source, runner=self.runner, skip_pull=True,
            health_timeout=self.health_timeout, progress=lambda _message: None)

    def setup_http(self, url):
        opener = urllib.request.build_opener(NoRedirects())
        with opener.open(url + "/setup", timeout=15) as response:
            body = response.read(1024 * 1024 + 1).decode("utf-8")
            cookie = SimpleCookie()
            for header in response.headers.get_all("Set-Cookie", []):
                cookie.load(header)
            session = cookie.get("session")
            if (response.status != 200 or len(body) > 1024 * 1024 or 'name="bootstrap_code"' not in body
                    or session is None or session["secure"] or not session["httponly"]
                    or session["samesite"].lower() != "lax"):
                raise TrialError("Local HTTP owner setup or session cookie contract failed")

    def exercise(self):
        self.preflight()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        first = self.start(port)
        if first.get("owner_exists") is not False or not first.get("code"):
            raise TrialError("A fresh installer did not issue an owner setup code")
        first_resources = self.resources(complete=True)
        self.setup_http(first["url"])
        environment = (self.directory / ".env").read_bytes()
        if stat.S_IMODE((self.directory / ".env").stat().st_mode) != 0o600:
            raise TrialError("Installer environment permissions are not private")
        self.report["phases"].append({"name": "fresh-install", "status": "passed", "both_services_healthy": True,
                                      "http_setup": True, "cookie_http_only": True, "cookie_same_site": "Lax", "cookie_secure": False})
        second = self.start(port)
        if (environment != (self.directory / ".env").read_bytes() or second.get("owner_exists") is not False
                or not second.get("code") or first["code"] == second["code"]
                or first_resources != self.resources(complete=True)):
            raise TrialError("Installer rerun changed configuration/data resources or failed to rotate bootstrap")
        compose = install_keep._compose_command(self.directory)
        probe = self.json(compose + ["exec", "--no-TTY", "keep-app", "python", "-c", PROBE_CODES],
                          input=json.dumps([first["code"], second["code"]]))
        if probe != {"old_valid": False, "new_valid": True}:
            raise TrialError("Installer rerun did not replace the unclaimed bootstrap code")
        self.report["phases"].append({"name": "installer-rerun", "status": "passed", "environment_unchanged": True,
                                      "resources_unchanged": True, "bootstrap_rotated": True})
        claimed = self.json(compose + ["exec", "--no-TTY", "keep-app", "python", "-c", CLAIM_OWNER], input=second["code"])
        expected = {"owner_matches": True, "integrity": "ok", "bootstrap_count": 0}
        if claimed != expected:
            raise TrialError("Synthetic owner claim failed its database integrity check")
        third = self.start(port)
        check = self.json(compose + ["exec", "--no-TTY", "keep-app", "python", "-c", CHECK_OWNER])
        if (third.get("owner_exists") is not True or "code" in third or check != expected
                or environment != (self.directory / ".env").read_bytes()
                or first_resources != self.resources(complete=True)):
            raise TrialError("Installer rerun failed to preserve established ownership")
        self.report["phases"].append({"name": "owner-preservation", "status": "passed", "owner_preserved": True,
                                      "bootstrap_disabled": True, "database_integrity": "ok"})

    def cleanup(self):
        if not self.admitted:
            shutil.rmtree(self.directory)
            self.report["cleanup"]["trial_not_started"] = True
            return
        before_down = self.resources(complete=False)
        if (self.directory / "compose.yml").exists() and (self.directory / ".env").exists():
            self.run(install_keep._compose_command(self.directory) + ["down", "--timeout", "10"])
        after_down = self.resources(complete=False)
        if after_down["containers"] or after_down["networks"]:
            raise TrialError("Trial containers or networks remain; preserving recovery files")
        if after_down["volume_creation"] != before_down["volume_creation"]:
            raise TrialError("Trial volume changed during cleanup; preserving it")
        if after_down["volumes"]:
            self.run(["docker", "volume", "rm", VOLUME])
        after = self.inventory()
        if any(after.values()):
            raise TrialError("Trial cleanup did not remove exactly its disposable resources")
        self.report["cleanup"].update(resources_absent=True, removed_volume=bool(after_down["volumes"]))
        shutil.rmtree(self.directory)


def run_trial(candidate, evidence, *, source_directory=ROOT, runner=command, health_timeout=300):
    evidence = Path(evidence).absolute()
    if evidence.exists() or evidence.is_symlink():
        raise TrialError("Evidence file already exists; refusing to replace it")
    trial = InstallerTrial(candidate, source_directory=source_directory, runner=runner, health_timeout=health_timeout)
    failure = None
    try:
        trial.exercise()
    except Exception as error:
        failure = error
        trial.report["error_type"] = type(error).__name__
    try:
        trial.cleanup()
    except Exception as error:
        failure = failure or error
        trial.report["cleanup"]["error_type"] = type(error).__name__
    trial.report["outcome"] = "passed" if failure is None and trial.report["cleanup"]["resources_absent"] else "failed"
    private_evidence(evidence, trial.report)
    if failure:
        raise TrialError("Disposable installer trial failed; inspect its bounded evidence report") from failure
    if trial.report["outcome"] != "passed":
        raise TrialError("Disposable installer trial has incomplete cleanup evidence")
    return trial.report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-image", required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--health-timeout", type=int, default=300)
    args = parser.parse_args()
    try:
        report = run_trial(args.candidate_image, args.evidence, health_timeout=args.health_timeout)
    except (TrialError, OSError):
        parser.exit(1, "Installer trial failed; bounded evidence contains no credentials.\n")
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
