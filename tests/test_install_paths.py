"""POSIX installation locations must retain trusted directory permissions."""
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import install_keep


@unittest.skipIf(os.name == "nt", "POSIX directory permissions; Windows has native ACL checks")
class InstallPathTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)

    def start_rejected(self, destination):
        runner = Mock()
        downloader = Mock()
        with patch.object(install_keep.secrets, "token_urlsafe") as generate, \
                self.assertRaisesRegex(install_keep.InstallError, "ancestors.*sticky"):
            install_keep.start_installation(destination, runner=runner, downloader=downloader)
        runner.assert_not_called()
        downloader.assert_not_called()
        generate.assert_not_called()

    def test_writable_nonsticky_parent_is_refused_before_mkdir_or_docker(self):
        shared = self.directory / "shared"
        shared.mkdir(mode=0o700)
        shared.chmod(0o777)
        destination = shared / "keep"
        self.start_rejected(destination)
        self.assertFalse(destination.exists())
        self.assertEqual(list(shared.iterdir()), [])

    def test_existing_private_leaf_does_not_override_unsafe_parent_permissions(self):
        shared = self.directory / "shared"
        shared.mkdir(mode=0o700)
        destination = shared / "keep"
        destination.mkdir(mode=0o700)
        shared.chmod(0o777)
        self.start_rejected(destination)
        self.assertEqual(list(destination.iterdir()), [])
        self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o700)

    def test_symlink_target_chain_cannot_hide_a_writable_nonsticky_parent(self):
        shared = self.directory / "shared"
        shared.mkdir(mode=0o700)
        target = shared / "private"
        target.mkdir(mode=0o700)
        shared.chmod(0o777)
        alias = self.directory / "alias"
        alias.symlink_to(target, target_is_directory=True)
        self.start_rejected(alias / "keep")
        self.assertFalse((target / "keep").exists())
        self.assertTrue(alias.is_symlink())

    def test_original_symlink_parent_is_checked_even_when_target_is_private(self):
        shared = self.directory / "shared"
        shared.mkdir(mode=0o700)
        private = self.directory / "private"
        private.mkdir(mode=0o700)
        alias = shared / "alias"
        alias.symlink_to(private, target_is_directory=True)
        shared.chmod(0o777)
        self.start_rejected(alias / "keep")
        self.assertFalse((private / "keep").exists())
        self.assertTrue(alias.is_symlink())

    def test_sticky_temporary_parent_and_owned_alias_remain_supported(self):
        temporary = self.directory / "temporary"
        temporary.mkdir(mode=0o700)
        temporary.chmod(0o1777)
        alias = self.directory / "temporary-alias"
        alias.symlink_to(temporary, target_is_directory=True)
        destination = install_keep._private_directory(alias / "keep")
        env = destination / ".env"
        install_keep.install(env, "https://keep.example.org")
        self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(env.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(temporary.stat().st_mode), 0o1777)

    def test_root_owned_tmp_alias_and_private_configuration_directory_still_work(self):
        with tempfile.TemporaryDirectory(prefix="keep-path-test-", dir="/tmp") as temporary:
            destination = Path(temporary)
            env = destination / ".env"
            install_keep.install(env, "https://keep.example.org")
            before = env.read_bytes()
            install_keep.install(env, "https://keep.example.org")
            self.assertEqual(env.read_bytes(), before)
            self.assertEqual(stat.S_IMODE(env.stat().st_mode), 0o600)

    def test_configuration_only_mode_checks_ancestors_before_creating_secrets(self):
        shared = self.directory / "shared"
        shared.mkdir(mode=0o700)
        private = shared / "private"
        private.mkdir(mode=0o700)
        shared.chmod(0o770)
        env = private / ".env"
        with patch.object(install_keep.secrets, "token_urlsafe") as generate, \
                self.assertRaisesRegex(install_keep.InstallError, "ancestors.*sticky"):
            install_keep.install(env, "https://keep.example.org")
        generate.assert_not_called()
        self.assertFalse(env.exists())
        self.assertEqual(list(private.iterdir()), [])

    def test_configuration_path_navigation_preserves_symlink_ancestor_checks(self):
        shared = self.directory / "shared"
        shared.mkdir(mode=0o700)
        nested = shared / "nested"
        nested.mkdir(mode=0o700)
        actual = shared / "private"
        actual.mkdir(mode=0o700)
        safe = self.directory / "safe"
        safe.mkdir(mode=0o700)
        (safe / "private").mkdir(mode=0o700)
        alias = safe / "alias"
        alias.symlink_to(nested, target_is_directory=True)
        shared.chmod(0o777)
        env = alias / ".." / "private" / ".env"
        with self.assertRaisesRegex(install_keep.InstallError, "ancestors.*sticky"):
            install_keep.install(env, "https://keep.example.org")
        self.assertFalse((actual / ".env").exists())
        self.assertFalse((safe / "private" / ".env").exists())

    def test_start_path_navigation_is_checked_before_normalization_or_creation(self):
        shared = self.directory / "shared"
        shared.mkdir(mode=0o700)
        nested = shared / "nested"
        nested.mkdir(mode=0o700)
        actual = shared / "private"
        actual.mkdir(mode=0o700)
        safe = self.directory / "safe"
        safe.mkdir(mode=0o700)
        normalized = safe / "private"
        normalized.mkdir(mode=0o700)
        alias = safe / "alias"
        alias.symlink_to(nested, target_is_directory=True)
        shared.chmod(0o777)
        self.start_rejected(alias / ".." / "private" / "keep")
        self.assertFalse((actual / "keep").exists())
        self.assertFalse((normalized / "keep").exists())


if __name__ == "__main__":
    unittest.main()
