"""Unix installation launcher checks run on the native host, outside Keep's shell-free image."""
import json
import os
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class LauncherTests(unittest.TestCase):
    def assert_prerequisite_guidance(self, *, system, manager, missing, old_python=False,
                                     expected):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            binary = directory / 'bin'
            binary.mkdir()
            record = directory / 'executed'

            def stub(name, body):
                file = binary / name
                file.write_text('#!/bin/sh\n' + body + '\n')
                file.chmod(0o700)

            stub('uname', 'printf \'%s\\n\' ' + shlex.quote(system))
            # Detection may inspect these commands, but none may run on an error.
            for command in ('mktemp', 'sudo', manager):
                if command:
                    stub(command, 'printf \'%s\\n\' ' + shlex.quote(command) +
                         ' >> "$KEEP_TEST_EVENTS"\nexit 77')
            if missing != 'curl':
                stub('curl', 'printf \'%s\\n\' curl >> "$KEEP_TEST_EVENTS"\nexit 77')
            if missing != 'python3':
                stub('python3', 'printf \'%s\\n\' python-version >> "$KEEP_TEST_EVENTS"\n' +
                     ('exit 1' if old_python else 'exit 0'))
            result = subprocess.run(['/bin/sh', str(Path(__file__).resolve().parents[1] / 'install.sh')],
                                    env={**os.environ, 'PATH': str(binary), 'TMPDIR': str(directory),
                                         'KEEP_TEST_EVENTS': str(record)},
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertIn(expected, result.stderr)
            self.assertIn('Then rerun the Keep installation command.', result.stderr)
            self.assertIn('No prerequisites were installed automatically.', result.stderr)
            self.assertEqual(result.stdout, '')
            self.assertEqual(record.read_text().splitlines() if record.exists() else [],
                             ['python-version'] if old_python else [])
            self.assertEqual(list(directory.glob('keep-install.*')), [])

    def test_missing_python_explains_platform_installation_without_running_it(self):
        for system, manager, expected in (
            ('Darwin', 'brew', 'brew install python3'),
            ('Darwin', None, 'https://www.python.org/downloads/'),
            ('Linux', 'apt-get', 'sudo apt-get install python3'),
            ('Linux', 'dnf', 'sudo dnf install python3'),
            ('Linux', None, "Install using your distribution's package manager."),
            ('Unknown', None, 'https://www.python.org/downloads/'),
        ):
            with self.subTest(system=system, manager=manager):
                self.assert_prerequisite_guidance(system=system, manager=manager,
                                                  missing='python3', expected=expected)

    def test_old_python_stops_before_download_and_offers_platform_installation(self):
        for system, manager, expected in (
            ('Darwin', 'brew', 'brew install python3'),
            ('Linux', 'apt-get', 'sudo apt-get install python3'),
            ('Linux', 'dnf', 'sudo dnf install python3'),
            ('Unknown', None, 'https://www.python.org/downloads/'),
        ):
            with self.subTest(system=system, manager=manager):
                self.assert_prerequisite_guidance(system=system, manager=manager, missing=None,
                                                  old_python=True, expected=expected)

    def test_missing_curl_stops_before_python_and_offers_platform_installation(self):
        for system, manager, expected in (
            ('Darwin', 'brew', 'brew install curl'),
            ('Linux', 'apt-get', 'sudo apt-get install curl'),
            ('Linux', 'dnf', 'sudo dnf install curl'),
            ('Unknown', None, 'https://curl.se/download.html'),
        ):
            with self.subTest(system=system, manager=manager):
                self.assert_prerequisite_guidance(system=system, manager=manager,
                                                  missing='curl', expected=expected)

    def test_failed_partial_download_does_not_execute_and_cleans_temporary_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            binary = directory / "bin"
            binary.mkdir()
            record = directory / "executed"
            curl = binary / "curl"
            curl.write_text("#!/bin/sh\nwhile [ \"$1\" != '--output' ]; do shift; done\n"
                            "printf 'partial download' > \"$2\"\nexit 22\n")
            python = binary / "python3"
            python.write_text("#!/bin/sh\nif [ \"$1\" = '-c' ]; then exit 0; fi\n"
                              "printf executed > \"$KEEP_TEST_RECORD\"\n")
            for file in (curl, python):
                file.chmod(0o700)
            environment = {**os.environ, "PATH": str(binary) + ":" + os.environ["PATH"],
                           "TMPDIR": str(directory), "KEEP_TEST_RECORD": str(record)}
            result = subprocess.run(["sh", str(Path(__file__).resolve().parents[1] / "install.sh")],
                                    env=environment, capture_output=True, text=True)
            self.assertEqual(result.returncode, 22)
            self.assertFalse(record.exists())
            self.assertEqual(list(directory.glob("keep-install.*")), [])

    def test_successful_download_forwards_literal_arguments_and_cleans_private_temp(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            binary = directory / "bin"
            binary.mkdir()
            record = directory / "arguments.json"
            curl = binary / "curl"
            curl.write_text("#!/bin/sh\nwhile [ \"$1\" != '--output' ]; do shift; done\n"
                            "printf 'complete installer' > \"$2\"\nprintf 200\n")
            python = binary / "python3"
            python.write_text("#!" + sys.executable + "\nimport json, os, sys\n"
                              "from pathlib import Path\n"
                              "if sys.argv[1] != '-c':\n"
                              "    Path(os.environ['KEEP_TEST_RECORD']).write_text(json.dumps(sys.argv[2:]))\n")
            for file in (curl, python):
                file.chmod(0o700)
            arguments = ["--directory", str(directory / "Keep Folder; literal"), "--port", "8788"]
            result = subprocess.run(["sh", str(Path(__file__).resolve().parents[1] / "install.sh"), *arguments],
                                    env={**os.environ, "PATH": str(binary) + ":" + os.environ["PATH"],
                                         "TMPDIR": str(directory), "KEEP_TEST_RECORD": str(record)},
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(record.read_text()), ["--start", *arguments])
            self.assertEqual(list(directory.glob("keep-install.*")), [])

    def test_unexpected_redirect_status_does_not_execute_download(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            binary = directory / "bin"
            binary.mkdir()
            record = directory / "executed"
            curl = binary / "curl"
            curl.write_text("#!/bin/sh\nwhile [ \"$1\" != '--output' ]; do shift; done\n"
                            "printf 'redirect response' > \"$2\"\nprintf 302\n")
            python = binary / "python3"
            python.write_text("#!/bin/sh\nif [ \"$1\" = '-c' ]; then exit 0; fi\n"
                              "printf executed > \"$KEEP_TEST_RECORD\"\n")
            for file in (curl, python):
                file.chmod(0o700)
            result = subprocess.run(["sh", str(Path(__file__).resolve().parents[1] / "install.sh")],
                                    env={**os.environ, "PATH": str(binary) + ":" + os.environ["PATH"],
                                         "TMPDIR": str(directory), "KEEP_TEST_RECORD": str(record)},
                                    capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(record.exists())
            self.assertEqual(list(directory.glob("keep-install.*")), [])


if __name__ == "__main__":
    unittest.main()
