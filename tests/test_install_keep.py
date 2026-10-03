import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import install_keep


class InstallKeepTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name)
        self.env = self.directory / ".env"

    def tearDown(self):
        self.temp.cleanup()

    def read(self):
        return self.env.read_bytes()

    def test_first_creation_generates_distinct_secrets_and_restricts_file(self):
        install_keep.install(self.env, "https://keep.example.com")
        data = self.read().decode()
        values = dict(line.split("=", 1) for line in data.splitlines() if "=" in line)
        self.assertEqual(values["KEEP_URL"], "https://keep.example.com")
        self.assertGreaterEqual(len(values["FLASK_SECRET_KEY"]), 64)
        self.assertGreaterEqual(len(values["KEEP_WEBHOOK_SECRET"]), 64)
        self.assertNotEqual(values["FLASK_SECRET_KEY"], values["KEEP_WEBHOOK_SECRET"])
        self.assertNotIn("KEEP_IMAGE=", data)
        self.assertEqual(stat.S_IMODE(self.env.stat().st_mode), 0o600)

    def test_rerun_is_idempotent_and_preserves_existing_bytes_and_image(self):
        original = (b"# keep this comment exactly\r\nUNKNOWN=value with spaces\r\n"
                    b"PLEX_OWNER_ID=1234\r\nKEEP_URL=https://keep.example.com/\r\n"
                    b"FLASK_SECRET_KEY=0123456789abcdefghijklmnopqrstuvwxyzABCDEF\r\n"
                    b"KEEP_WEBHOOK_SECRET=ZYXWVUTSRQPONMLKJIHGFEDCBA9876543210abcd\r\n"
                    b"KEEP_IMAGE=brspoon/keep@sha256:" + b"a" * 64 + b"\r\n")
        self.env.write_bytes(original)
        install_keep.install(self.env, "https://keep.example.com")
        self.assertEqual(self.read(), original)
        self.assertEqual(stat.S_IMODE(self.env.stat().st_mode), 0o600)

    def test_preserves_unknown_entries_and_adds_requested_image(self):
        self.env.write_bytes(b"# owner config\nPLEX_OWNER_ID=42\nCUSTOM=a=b\n")
        install_keep.install(self.env, "https://keep.example.com", "brspoon/keep:2.17.6")
        data = self.read()
        self.assertIn(b"PLEX_OWNER_ID=42\nCUSTOM=a=b\n", data)
        self.assertIn(b"KEEP_IMAGE=brspoon/keep:2.17.6\n", data)

    def test_accepts_digest_reference_and_rejects_invalid_explicit_reference(self):
        digest_ref = "brspoon/keep@sha256:" + "c" * 64
        install_keep.install(self.env, "https://keep.example.com", digest_ref)
        self.assertIn(("KEEP_IMAGE=" + digest_ref).encode(), self.read())
        before = self.read()
        with self.assertRaises(install_keep.InstallError):
            install_keep.install(self.env, "https://keep.example.com", "keep:latest;echo bad")
        self.assertEqual(self.read(), before)

    def test_existing_valid_secrets_are_preserved(self):
        self.env.write_text(
            "FLASK_SECRET_KEY=" + "A" * 48 + "\nKEEP_WEBHOOK_SECRET=" + "B" * 48 + "\n",
            encoding="utf-8")
        install_keep.install(self.env, "https://keep.example.com")
        data = self.read().decode()
        self.assertIn("FLASK_SECRET_KEY=" + "A" * 48, data)
        self.assertIn("KEEP_WEBHOOK_SECRET=" + "B" * 48, data)

    def test_existing_printable_ascii_secrets_at_length_boundaries_are_preserved(self):
        shortest = "!" * 32
        longest = "~" * 4096
        self.env.write_text(
            "KEEP_URL=https://keep.example.com\nFLASK_SECRET_KEY=" + shortest +
            "\nKEEP_WEBHOOK_SECRET=" + longest + "\n", encoding="utf-8")
        before = self.read()
        install_keep.install(self.env, "https://keep.example.com")
        self.assertEqual(self.read(), before)

    def test_existing_secrets_reject_out_of_range_or_non_printable_values(self):
        valid = "A" * 48
        invalid_values = ("A" * 31, "A" * 4097, "A" * 31 + "\n", "A" * 23 + "\t" + "A" * 24,
                          "A" * 47 + "\x7f", "A" * 47 + "é")
        for invalid in invalid_values:
            with self.subTest(length=len(invalid), suffix=repr(invalid[-1])):
                self.env.write_text(
                    "KEEP_URL=https://keep.example.com\nFLASK_SECRET_KEY=" + invalid +
                    "\nKEEP_WEBHOOK_SECRET=" + valid + "\n", encoding="utf-8")
                before = self.read()
                with self.assertRaises(install_keep.InstallError):
                    install_keep.install(self.env, "https://keep.example.com")
                self.assertEqual(self.read(), before)

    def test_parent_directory_must_be_owned_by_user_and_not_group_or_world_writable(self):
        with patch.object(install_keep.os, "getuid", return_value=self.directory.stat().st_uid + 1):
            with self.assertRaisesRegex(install_keep.InstallError, "configuration directory"):
                install_keep.install(self.env, "https://keep.example.com")
        self.assertFalse(self.env.exists())

        self.directory.chmod(0o777)
        try:
            with self.assertRaisesRegex(install_keep.InstallError, "configuration directory"):
                install_keep.install(self.env, "https://keep.example.com")
        finally:
            self.directory.chmod(0o700)
        self.assertFalse(self.env.exists())

    def test_rejects_bad_origins_without_creating_file(self):
        for url in ("http://keep.example.com", "https://u:p@keep.example.com",
                    "https://keep.example.com/path", "https://keep.example.com?q=x",
                    "https://keep.example.com#fragment", "https://keep.example.com:99999"):
            with self.subTest(url=url), self.assertRaises(install_keep.InstallError):
                install_keep.install(self.env, url)
        self.assertFalse(self.env.exists())

    def test_rejects_conflicting_origin_or_image_without_mutating_file(self):
        self.env.write_text("KEEP_URL=https://old.example.com\n", encoding="utf-8")
        before = self.read()
        with self.assertRaisesRegex(install_keep.InstallError, "conflicts"):
            install_keep.install(self.env, "https://new.example.com")
        self.assertEqual(self.read(), before)
        self.env.write_text("KEEP_URL=https://keep.example.com\nKEEP_IMAGE=bad image\n", encoding="utf-8")
        before = self.read()
        with self.assertRaises(install_keep.InstallError):
            install_keep.install(self.env, "https://keep.example.com")
        self.assertEqual(self.read(), before)

    def test_rejects_invalid_existing_secrets_and_duplicate_managed_fields(self):
        for contents in ("FLASK_SECRET_KEY=short\n", "KEEP_URL=https://keep.example.com\n" * 2):
            self.env.write_text(contents, encoding="utf-8")
            before = self.read()
            with self.assertRaises(install_keep.InstallError):
                install_keep.install(self.env, "https://keep.example.com")
            self.assertEqual(self.read(), before)

    def test_rejects_symlink_and_directory_env_files(self):
        target = self.directory / "target"
        target.write_text("KEEP_URL=https://keep.example.com\n", encoding="utf-8")
        self.env.symlink_to(target)
        with self.assertRaises(install_keep.InstallError):
            install_keep.install(self.env, "https://keep.example.com")
        self.env.unlink()
        self.env.mkdir()
        with self.assertRaises(install_keep.InstallError):
            install_keep.install(self.env, "https://keep.example.com")

    def test_rejects_symlink_lock(self):
        lock = self.directory / ".env.install.lock"
        lock.symlink_to(self.directory / "missing")
        with self.assertRaises(install_keep.InstallError):
            install_keep.install(self.env, "https://keep.example.com")
        self.assertFalse(self.env.exists())

    def test_failed_atomic_replace_keeps_previous_configuration(self):
        self.env.write_bytes(b"CUSTOM=preserve me\n")
        before = self.read()
        with patch.object(install_keep.os, "replace", side_effect=OSError("simulated")):
            with self.assertRaises(OSError):
                install_keep.install(self.env, "https://keep.example.com")
        self.assertEqual(self.read(), before)
        self.assertEqual(list(self.directory.glob(".env.*")), [self.directory / ".env.install.lock"])


if __name__ == "__main__":
    unittest.main()
