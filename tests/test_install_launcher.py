"""Unix installation launcher checks run on the native host, outside Keep's shell-free image."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class LauncherTests(unittest.TestCase):
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
