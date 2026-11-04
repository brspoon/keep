"""Atomic SQLite replacement rejects unexpected vendor bytes and aliases."""
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import build_patched_sqlite as build
from scripts import install_runtime_packages as installer


class InstallSQLiteTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.packages = self.root / 'packages'
        self.output = self.packages / 'sqlite-patched'
        self.output.mkdir(parents=True)
        self.directory = self.root / 'lib'
        self.directory.mkdir()
        self.vendor = self.directory / 'libsqlite3.so.3.53.4'
        self.alias = self.directory / build.ALIAS
        self.library = self.directory / build.LIBRARY
        self.vendor.write_bytes(b'authenticated old library')
        self.alias.symlink_to(self.vendor.name)
        self.replacement = self.output / build.LIBRARY
        self.replacement.write_bytes(b'reviewed corrected library')
        self.manifest = {'library': {'sha256': hashlib.sha256(self.replacement.read_bytes()).hexdigest()}}
        self.spec = {'expected_vendor_library_sha256': {
            'amd64': hashlib.sha256(self.vendor.read_bytes()).hexdigest()}}
        self.enterContext(patch.object(build, 'reviewed_spec', return_value=self.spec))
        self.enterContext(patch.object(build, 'read_build_manifest', return_value=self.manifest))

    def install(self):
        installer.install_sqlite(self.packages, 'amd64', directory=self.directory)

    def assert_original(self):
        self.assertEqual(self.vendor.read_bytes(), b'authenticated old library')
        self.assertEqual(self.alias.resolve(), self.vendor)
        self.assertFalse(self.library.exists())
        self.assertEqual({p.name for p in self.directory.iterdir()}, {self.vendor.name, self.alias.name})

    def test_replacement_changes_inode_and_alias_and_removes_old_loadable_target(self):
        original = self.vendor.stat().st_ino
        self.install()
        self.assertEqual(self.alias.resolve(), self.library)
        self.assertEqual(self.library.read_bytes(), self.replacement.read_bytes())
        self.assertNotEqual(self.library.stat().st_ino, original)
        self.assertEqual(self.library.stat().st_mode & 0o777, 0o755)
        self.assertFalse(self.vendor.exists())
        self.assertEqual({p.name for p in self.directory.iterdir()}, {self.library.name, self.alias.name})

    def test_modified_vendor_or_replacement_is_rejected_before_publication(self):
        for path in (self.vendor, self.replacement):
            with self.subTest(path=path.name):
                original = path.read_bytes()
                path.write_bytes(original + b'changed')
                with self.assertRaisesRegex(ValueError, 'checksum mismatch'):
                    self.install()
                path.write_bytes(original)
                self.assert_original()

    def test_unexpected_family_member_or_alias_is_not_accepted(self):
        fallback = self.directory / 'libsqlite3.so.other'
        fallback.write_bytes(b'obsolete fallback')
        with self.assertRaisesRegex(ValueError, 'library family'):
            self.install()
        fallback.unlink()
        self.alias.unlink()
        self.alias.symlink_to('missing')
        with self.assertRaises((ValueError, FileNotFoundError)):
            self.install()
        self.assertTrue(self.vendor.is_file())
        self.assertFalse(self.library.exists())

    def test_symlink_replacement_input_is_rejected(self):
        body = self.replacement.read_bytes()
        self.replacement.unlink()
        target = self.root / 'replacement'
        target.write_bytes(body)
        self.replacement.symlink_to(target)
        with self.assertRaisesRegex(ValueError, 'regular file'):
            self.install()
        self.assert_original()

    def test_failed_atomic_library_publication_preserves_vendor_and_cleans_temporary(self):
        with patch.object(installer.os, 'replace', side_effect=OSError('publication failed')):
            with self.assertRaisesRegex(OSError, 'publication failed'):
                self.install()
        self.assert_original()
