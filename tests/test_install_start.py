import json
import errno
import io
import os
import socket
import stat
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import install_keep


class DockerRunner:
    def __init__(self, directory, *, established=False, existing=False, health="healthy", fail=None):
        self.directory = directory
        self.established = established
        self.started = existing
        self.health = health
        self.fail = fail
        self.calls = []
        self.bootstrap_calls = 0

    def containers(self):
        return [{"Id": identifier, "Config": {"Labels": {
            "com.docker.compose.service": name,
            "com.docker.compose.project.working_dir": str(self.directory),
        }}, "State": {"Running": True, "Status": "running", "Health": {"Status": self.health}}}
            for identifier, name in (("a" * 64, "keep-app"), ("b" * 64, "keep-digest"))]

    def __call__(self, command, *, cwd, timeout):
        self.calls.append((command, cwd, timeout))
        code, output = 0, ""
        if self.fail and self.fail in command:
            code = 1
            output = "a private value that must not be echoed"
        elif command[:3] == ["docker", "compose", "version"]:
            output = "2.40.0"
        elif command[:2] == ["docker", "info"]:
            output = "linux" if "{{.OSType}}" in command else "28.3.0"
        elif command[:2] == ["docker", "ps"] or "ps" in command:
            output = "\n".join(("a" * 64, "b" * 64)) if self.started else ""
        elif command[:2] == ["docker", "inspect"]:
            output = json.dumps(self.containers())
        elif "up" in command:
            self.started = True
        elif "exec" in command:
            self.bootstrap_calls += 1
            output = json.dumps({"owner_exists": True, "pending": False} if self.established else
                                {"owner_exists": False, "code": "x" * 43})
        return SimpleNamespace(returncode=code, stdout=output, stderr=output if code else "")


class InstallStartTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.parent = Path(self.temp.name)
        self.directory = self.parent / "installation"
        self.downloads = []
        self.ports = []
        self.progress = []
        self.clock = 0
        self.runner = DockerRunner(self.directory)

    def tearDown(self):
        self.temp.cleanup()

    def download(self, name):
        self.downloads.append(name)
        return {"VERSION": (install_keep.RELEASE_VERSION + "\n").encode(),
                "compose.yml": b"name: keep\nservices: {}\n"}[name]

    def sleep(self, seconds):
        self.clock += seconds

    def start(self, **kwargs):
        options = dict(runner=self.runner, downloader=self.download, address_detector=lambda: "192.168.1.10",
                       port_checker=lambda address, port: self.ports.append((address, port)),
                       sleep=self.sleep, monotonic=lambda: self.clock, progress=self.progress.append)
        options.update(kwargs)
        return install_keep.start_installation(self.directory, **options)

    def existing(self, *, url="https://keep.example.org", version="2.20.0", image="brspoon/keep:2.20.0"):
        self.directory.mkdir(mode=0o700)
        install_keep.install(self.directory / ".env", url, image)
        (self.directory / "VERSION").write_text(version + "\n")
        (self.directory / "compose.yml").write_text("name: keep\nservices: {}\n")

    def test_fresh_lan_start_downloads_fixed_bundle_pins_image_and_issues_code_after_health(self):
        result = self.start()
        self.assertEqual(result["url"], "http://192.168.1.10:5000")
        self.assertEqual(self.downloads, ["VERSION", "compose.yml"])
        self.assertEqual(self.ports, [("192.168.1.10", 5000)])
        self.assertEqual(self.runner.bootstrap_calls, 1)
        self.assertEqual(result["code"], "x" * 43)
        self.assertEqual(stat.S_IMODE(self.directory.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((self.directory / ".env").stat().st_mode), 0o600)
        env = (self.directory / ".env").read_text()
        for line in ("KEEP_URL=http://192.168.1.10:5000", "KEEP_TRANSPORT_MODE=lan-http",
                     "KEEP_BIND_ADDRESS=192.168.1.10", "KEEP_PORT=5000",
                     "KEEP_IMAGE=brspoon/keep:" + install_keep.RELEASE_VERSION):
            self.assertIn(line, env)
        compose_calls = [command for command, _, _ in self.runner.calls if command[:2] == ["docker", "compose"] and "version" not in command]
        for command in compose_calls:
            self.assertIn(str(self.directory / "compose.yml"), command)
            self.assertIn(str(self.directory / ".env"), command)
            self.assertEqual(command[command.index("--project-name") + 1], "keep")
        self.assertLess(next(i for i, call in enumerate(self.runner.calls) if call[0][:2] == ["docker", "inspect"]),
                        next(i for i, call in enumerate(self.runner.calls) if "exec" in call[0]))

    def test_https_start_preserves_secure_mode_and_loopback_default(self):
        result = self.start(requested_url="https://keep.example.org/", port=8788)
        self.assertEqual(result["url"], "https://keep.example.org")
        self.assertEqual(self.ports, [("127.0.0.1", 8788)])
        env = (self.directory / ".env").read_text()
        self.assertIn("KEEP_TRANSPORT_MODE=https", env)
        self.assertIn("KEEP_BIND_ADDRESS=127.0.0.1", env)

    def test_private_http_only_explicit_binding_and_port(self):
        result = self.start(bind_address="10.1.2.3", port=8788)
        self.assertEqual(result["url"], "http://10.1.2.3:8788")
        self.assertEqual(self.ports, [("10.1.2.3", 8788)])
        for address in ("0.0.0.0", "8.8.8.8", "169.254.1.2", "192.0.2.1", "localhost", "::1"):
            with self.subTest(address=address), self.assertRaises(install_keep.InstallError):
                install_keep.validate_bind_address(address)

    def test_public_http_and_mismatched_origin_are_rejected(self):
        for url in ("http://keep.example.org", "http://8.8.8.8:5000", "https://192.168.1.2:5000"):
            with self.subTest(url=url), self.assertRaises(install_keep.InstallError):
                install_keep.validate_url(url, "lan-http")
        self.directory.mkdir(mode=0o700)
        with self.assertRaisesRegex(install_keep.InstallError, "match"):
            install_keep.install(self.directory / ".env", "http://10.1.2.3:5000", transport_mode="lan-http",
                                 bind_address="10.1.2.4", port=5000)
        self.assertFalse((self.directory / ".env").exists())

    def test_rerun_preserves_configuration_bundle_image_and_existing_owner(self):
        self.existing()
        before = {name: (self.directory / name).read_bytes() for name in (".env", "VERSION", "compose.yml")}
        self.runner = DockerRunner(self.directory, established=True, existing=True)
        result = self.start()
        self.assertEqual(result["version"], "2.20.0")
        self.assertTrue(result["owner_exists"])
        self.assertNotIn("code", result)
        self.assertEqual(self.downloads, [])
        self.assertEqual(self.ports, [])
        for name, original in before.items():
            self.assertEqual((self.directory / name).read_bytes(), original)
        self.assertFalse(any("pull" == command[-3] for command, _, _ in self.runner.calls if len(command) >= 3))
        up = next(command for command, _, _ in self.runner.calls if "up" in command)
        self.assertIn("--no-recreate", up)
        self.assertEqual(up[up.index("--pull") + 1], "never")

    def test_lan_rerun_preserves_secrets_and_does_not_depend_on_new_address_detection(self):
        self.start()
        before = (self.directory / ".env").read_bytes()
        self.runner.established = True
        self.downloads.clear()
        with patch.object(install_keep, "detect_lan_address", side_effect=AssertionError("must not autodetect")):
            result = self.start(address_detector=lambda: (_ for _ in ()).throw(AssertionError("must not autodetect")))
        self.assertEqual(result["url"], "http://192.168.1.10:5000")
        self.assertEqual((self.directory / ".env").read_bytes(), before)
        self.assertEqual(self.downloads, [])

    def test_existing_url_and_image_conflicts_are_refused_before_start_or_download(self):
        self.existing()
        before = (self.directory / ".env").read_bytes()
        for request in ({"requested_url": "https://other.example.org"},
                        {"requested_image": "brspoon/keep:2.21.2"}, {"bind_address": "10.1.2.3"}, {"port": 8788}):
            with self.subTest(request=request), self.assertRaisesRegex(install_keep.InstallError, "conflicts"):
                self.start(**request)
        self.assertEqual((self.directory / ".env").read_bytes(), before)
        self.assertEqual(self.downloads, [])
        self.assertFalse(any("pull" in command or "up" in command for command, _, _ in self.runner.calls))

    def test_existing_incomplete_installation_requires_original_files(self):
        self.existing()
        (self.directory / "VERSION").unlink()
        with self.assertRaisesRegex(install_keep.InstallError, "implicit upgrade"):
            self.start()
        self.assertEqual(self.downloads, [])

    def test_foreign_compose_project_is_refused_before_configuration(self):
        self.runner = DockerRunner(self.parent / "someone-else", existing=True)
        with self.assertRaisesRegex(install_keep.InstallError, "another directory"):
            self.start()
        self.assertFalse((self.directory / ".env").exists())
        self.assertEqual(self.downloads, [])

    def test_stale_volume_is_not_adopted_without_original_configuration(self):
        def stale(command, **kwargs):
            if command[:3] == ["docker", "volume", "ls"]:
                return SimpleNamespace(returncode=0, stdout="keep_keep-data\n")
            return self.runner(command, **kwargs)
        with self.assertRaisesRegex(install_keep.InstallError, "existing Keep data"):
            self.start(runner=stale)
        self.assertFalse((self.directory / ".env").exists())
        self.assertEqual(self.downloads, [])

    def test_fresh_occupied_port_is_checked_before_saving_settings(self):
        def occupied(*args):
            raise install_keep.InstallError("port is unavailable")
        with self.assertRaisesRegex(install_keep.InstallError, "unavailable"):
            self.start(port_checker=occupied)
        self.assertFalse((self.directory / ".env").exists())
        self.assertEqual(self.downloads, [])

    def test_missing_container_working_directory_is_not_treated_as_current_directory(self):
        self.runner.started = True
        original = self.runner.containers
        def missing():
            containers = original()
            for container in containers:
                container["Config"]["Labels"].pop("com.docker.compose.project.working_dir")
            return containers
        self.runner.containers = missing
        with self.assertRaisesRegex(install_keep.InstallError, "another directory"):
            self.start()

    def test_compose_version_must_be_v2_or_newer(self):
        def obsolete(command, **kwargs):
            if command[:3] == ["docker", "compose", "version"]:
                return SimpleNamespace(returncode=0, stdout="1.29.2")
            return self.runner(command, **kwargs)
        with patch.object(install_keep.platform, "system", return_value="Darwin"), \
             patch.object(install_keep.shutil, "which", return_value="/opt/homebrew/bin/brew"), \
             self.assertRaisesRegex(install_keep.InstallError, "v2 or newer") as error:
            self.start(runner=obsolete)
        self.assertIn("brew install --cask docker-desktop", str(error.exception))
        self.assertIn("docker compose version", str(error.exception))
        self.assertFalse((self.directory / ".env").exists())
        self.assertEqual(self.downloads, [])
        self.assertFalse(self.runner.started)

    def test_missing_docker_explains_windows_install_without_running_it(self):
        with patch.object(install_keep.platform, "system", return_value="Windows"), \
             patch.object(install_keep.shutil, "which", return_value=r"C:\Windows\winget.exe"), \
             patch.object(install_keep.subprocess, "run", side_effect=FileNotFoundError("private path")) as run, \
             self.assertRaisesRegex(install_keep.InstallError, "Docker is not installed") as error:
            self.start(runner=install_keep.run_command)
        self.assertIn("winget install --id Docker.DockerDesktop --exact", str(error.exception))
        self.assertIn("Linux containers", str(error.exception))
        self.assertNotIn("private path", str(error.exception))
        run.assert_called_once()
        self.assertEqual(run.call_args.args[0], ["docker", "compose", "version", "--short"])
        self.assertFalse((self.directory / ".env").exists())
        self.assertEqual(self.downloads, [])

    def test_missing_linux_compose_explains_repository_requirement_before_package_command(self):
        for package_manager, command in (("apt-get", "sudo apt-get install docker-compose-plugin"),
                                         ("dnf", "sudo dnf install docker-compose-plugin")):
            with self.subTest(package_manager=package_manager):
                self.runner = DockerRunner(self.directory, fail="version")
                with patch.object(install_keep.platform, "system", return_value="Linux"), \
                     patch.object(install_keep.shutil, "which", side_effect=lambda name: "/usr/bin/" + name if name == package_manager else None), \
                     self.assertRaisesRegex(install_keep.InstallError, "v2 or newer") as error:
                    self.start()
                message = str(error.exception)
                self.assertIn("Docker's official repository is already configured", message)
                self.assertIn(command, message)
                self.assertLess(message.index("official repository"), message.index(command))
                self.assertNotIn("private value", message)
                self.assertEqual(len(self.runner.calls), 1)
                self.assertFalse(self.runner.started)
                self.assertEqual(self.runner.bootstrap_calls, 0)
                self.assertFalse((self.directory / ".env").exists())
                self.assertEqual(self.downloads, [])

    def test_unavailable_linux_daemon_has_repair_guidance_and_preserves_existing_configuration(self):
        self.existing()
        originals = {name: (self.directory / name).read_bytes() for name in (".env", "VERSION", "compose.yml")}
        self.runner.fail = "info"
        with patch.object(install_keep.platform, "system", return_value="Linux"), \
             patch.object(install_keep.shutil, "which", return_value="/usr/bin/systemctl"), \
             self.assertRaisesRegex(install_keep.InstallError, "cannot access its daemon") as error:
            self.start()
        message = str(error.exception)
        self.assertIn("sudo systemctl start docker", message)
        self.assertIn("docker info", message)
        self.assertIn("https://docs.docker.com/engine/install/linux-postinstall/", message)
        self.assertNotIn("chmod", message)
        self.assertNotIn("usermod", message)
        self.assertNotIn("private value", message)
        self.assertFalse(any("up" in command or "pull" in command for command, _, _ in self.runner.calls))
        for name, original in originals.items():
            self.assertEqual((self.directory / name).read_bytes(), original)
        self.assertEqual(self.downloads, [])
        self.assertEqual(self.runner.bootstrap_calls, 0)

    def test_unknown_platform_uses_official_links_without_inventing_package_commands(self):
        with patch.object(install_keep.platform, "system", return_value="UnknownOS"), \
             patch.object(install_keep.shutil, "which", side_effect=AssertionError("must not guess a package manager")):
            for requirement in ("docker", "compose", "python"):
                with self.subTest(requirement=requirement):
                    message = install_keep.prerequisite_guidance(requirement)
                    self.assertIn("https://", message)
                    for command in ("apt-get", "dnf", "brew install", "winget install"):
                        self.assertNotIn(command, message)

    def test_missing_package_manager_uses_official_desktop_download_instructions(self):
        for system, platform_path in (("Windows", "windows-install"), ("Darwin", "mac-install")):
            with self.subTest(system=system), \
                 patch.object(install_keep.platform, "system", return_value=system), \
                 patch.object(install_keep.shutil, "which", return_value=None):
                message = install_keep.prerequisite_guidance("docker")
            self.assertIn("https://docs.docker.com/desktop/setup/install/" + platform_path + "/", message)
            self.assertNotIn("winget install", message)
            self.assertNotIn("brew install", message)

    def test_old_python_cli_reports_repair_and_never_starts_installation(self):
        stderr = io.StringIO()
        with patch.object(install_keep.sys, "version_info", (3, 8)), \
             patch.object(install_keep.platform, "system", return_value="Darwin"), \
             patch.object(install_keep.shutil, "which", return_value="/opt/homebrew/bin/brew"), \
             patch.object(install_keep, "start_installation") as start, \
             patch.object(install_keep.subprocess, "run") as run, \
             redirect_stderr(stderr), self.assertRaises(SystemExit) as error:
            install_keep.main(["--start", "--directory", str(self.directory)])
        self.assertEqual(error.exception.code, 2)
        self.assertIn("Keep requires Python 3.9 or newer.", stderr.getvalue())
        self.assertIn("brew install python3", stderr.getvalue())
        start.assert_not_called()
        run.assert_not_called()
        self.assertFalse(self.directory.exists())

    def test_windows_container_mode_is_refused_before_files_or_secrets(self):
        def windows_mode(command, **kwargs):
            if command == ["docker", "info", "--format", "{{.OSType}}"]:
                return SimpleNamespace(returncode=0, stdout="windows")
            return self.runner(command, **kwargs)
        with self.assertRaisesRegex(install_keep.InstallError, "Linux containers") as error:
            self.start(runner=windows_mode)
        self.assertIn("Switch to Linux containers", str(error.exception))
        self.assertIn("docker info --format '{{.OSType}}'", str(error.exception))
        self.assertFalse((self.directory / ".env").exists())
        self.assertEqual(self.downloads, [])
        self.assertFalse(self.runner.started)

    def test_env_only_moving_tag_restore_does_not_implicitly_upgrade(self):
        self.existing(image="brspoon/keep:stable")
        before = (self.directory / ".env").read_bytes()
        with self.assertRaisesRegex(install_keep.InstallError, "moving tag"):
            self.start()
        self.assertEqual((self.directory / ".env").read_bytes(), before)
        self.assertFalse(any("pull" in command or "up" in command for command, _, _ in self.runner.calls))

    def test_pull_failure_retains_settings_for_safe_rerun_and_never_issues_bootstrap(self):
        self.runner.fail = "pull"
        with self.assertRaisesRegex(install_keep.InstallError, "Docker Hub access") as error:
            self.start()
        self.assertNotIn("private value", str(error.exception))
        before = (self.directory / ".env").read_bytes()
        self.assertEqual(self.runner.bootstrap_calls, 0)
        self.runner.fail = None
        self.start()
        self.assertEqual((self.directory / ".env").read_bytes(), before)
        self.assertEqual(self.runner.bootstrap_calls, 1)

    def test_worker_unhealthy_and_health_timeout_do_not_issue_bootstrap(self):
        for health, expected in (("unhealthy", "failed its health"), ("starting", "did not become healthy")):
            with self.subTest(health=health):
                self.runner = DockerRunner(self.directory, health=health)
                with self.assertRaisesRegex(install_keep.InstallError, expected):
                    self.start(health_timeout=2)
                self.assertEqual(self.runner.bootstrap_calls, 0)

    def test_partial_download_failure_does_not_write_runnable_bundle(self):
        def failing(name):
            if name == "compose.yml":
                raise install_keep.InstallError("download interrupted")
            return (install_keep.RELEASE_VERSION + "\n").encode()
        with self.assertRaisesRegex(install_keep.InstallError, "interrupted"):
            self.start(downloader=failing)
        self.assertFalse((self.directory / "VERSION").exists())
        self.assertFalse((self.directory / "compose.yml").exists())
        self.assertFalse((self.directory / ".env").exists())

    def test_partially_written_bundle_is_completed_only_when_existing_file_matches(self):
        self.directory.mkdir(mode=0o700)
        (self.directory / "VERSION").write_bytes((install_keep.RELEASE_VERSION + "\n").encode())
        self.start()
        self.assertTrue((self.directory / "compose.yml").exists())
        other = self.parent / "conflict"
        other.mkdir(mode=0o700)
        (other / "VERSION").write_bytes(b"2.20.0\n")
        with self.assertRaisesRegex(install_keep.InstallError, "conflicts"):
            install_keep.prepare_bundle(other, downloader=self.download)
        self.assertEqual((other / "VERSION").read_bytes(), b"2.20.0\n")
        self.assertFalse((other / "compose.yml").exists())

    def test_bundle_rejects_symlink_and_wrong_release(self):
        self.directory.mkdir(mode=0o700)
        (self.directory / "VERSION").symlink_to(self.parent / "outside")
        with self.assertRaisesRegex(install_keep.InstallError, "non-regular"):
            self.start()
        (self.directory / "VERSION").unlink()
        with self.assertRaisesRegex(install_keep.InstallError, "match release"):
            self.start(downloader=lambda name: b"2.20.0\n" if name == "VERSION" else b"services: {}\n")

    def test_download_uses_only_fixed_https_origin_and_rejects_redirects(self):
        with self.assertRaisesRegex(install_keep.InstallError, "unexpected installation"):
            install_keep.download_release_file("../../.env")
        with self.assertRaisesRegex(install_keep.InstallError, "redirected"):
            install_keep.NoRedirects().redirect_request(None, None, 302, "redirect", {}, "https://other.example")
        self.assertEqual(install_keep.RELEASE_BASE,
                         f"https://raw.githubusercontent.com/brspoon/keep/{install_keep.RELEASE_VERSION}/")

    def test_real_free_port_probe_rejects_an_occupied_port(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            try:
                listener.bind(("127.0.0.1", 0))
            except OSError as error:
                if error.errno in (errno.EPERM, errno.EACCES):
                    self.skipTest("the local sandbox disallows binding sockets; native CI runs this probe")
                raise
            listener.listen()
            with self.assertRaisesRegex(install_keep.InstallError, "unavailable"):
                install_keep.check_port("127.0.0.1", listener.getsockname()[1])

    def test_candidate_skip_pull_requires_local_image_and_never_contacts_registry(self):
        self.start(requested_image="keep-ci:latest", skip_pull=True)
        commands = [command for command, _, _ in self.runner.calls]
        self.assertIn(["docker", "image", "inspect", "--format", "{{.Id}}", "keep-ci:latest"], commands)
        self.assertFalse(any("pull" in command for command in commands))
        self.assertTrue(any("up" in command for command in commands))

    def test_failed_compose_and_occupied_port_do_not_start_services(self):
        self.runner.fail = "config"
        with self.assertRaisesRegex(install_keep.InstallError, "configuration is invalid"):
            self.start()
        self.assertFalse(any("up" in command for command, _, _ in self.runner.calls))
        self.runner.fail = None
        def occupied(*args):
            raise install_keep.InstallError("address or port is unavailable")
        with self.assertRaisesRegex(install_keep.InstallError, "unavailable"):
            self.start(port_checker=occupied)
        self.assertFalse(any("up" in command for command, _, _ in self.runner.calls))

    def test_bootstrap_probe_never_issues_a_code_for_an_existing_owner(self):
        class Store:
            def __init__(self, *args):
                pass

            def owner(self):
                return "1234"

            def pending(self):
                return False

            def issue(self):
                raise AssertionError("existing owner must not get another bootstrap")

        from contextlib import redirect_stdout
        from io import StringIO
        output = StringIO()
        with patch.dict(sys.modules, {"onboarding": SimpleNamespace(Onboarding=Store)}), redirect_stdout(output):
            exec(install_keep.BOOTSTRAP_PROBE, {})
        self.assertEqual(json.loads(output.getvalue()), {"owner_exists": True, "pending": False})

    def test_runner_removes_environment_overrides_but_keeps_docker_connection(self):
        with patch.dict(os.environ, {"KEEP_IMAGE": "other/app:latest", "COMPOSE_PROJECT_NAME": "other",
                                     "FLASK_SECRET_KEY": "private", "DOCKER_HOST": "unix:///docker.sock"}), \
                patch.object(install_keep.subprocess, "run", return_value=SimpleNamespace(returncode=0)) as run:
            install_keep.run_command(["docker", "info"], cwd=self.parent, timeout=60)
        passed = run.call_args.kwargs["env"]
        self.assertNotIn("KEEP_IMAGE", passed)
        self.assertNotIn("COMPOSE_PROJECT_NAME", passed)
        self.assertNotIn("FLASK_SECRET_KEY", passed)
        self.assertEqual(passed["DOCKER_HOST"], "unix:///docker.sock")


if __name__ == "__main__":
    unittest.main()
