import errno
import hashlib
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

from scripts.patch_python_runtime import apply_hunks, patch_provenance
from scripts.python_security_checks import verify_loaded_zlib


class RuntimePatchTests(unittest.TestCase):
    def test_exact_upstream_hunk_is_applied_or_already_present(self):
        patch = {'path': 'example.py', 'commit': 'upstream',
                 'hunks': [{'before': 'value = 1', 'after': 'value = 2'}]}
        self.assertEqual(apply_hunks('value = 1\n', patch), 'value = 2\n')
        self.assertEqual(apply_hunks('value = 2\n', patch), 'value = 2\n')

    def test_unknown_or_ambiguous_context_is_rejected(self):
        patch = {'path': 'example.py', 'commit': 'upstream',
                 'hunks': [{'before': 'value = 1', 'after': 'value = 2'}]}
        for source in ('value = 3\n', 'value = 1\nvalue = 1\n',
                       'value = 2\nvalue = 2\n',
                       'value = 1\nvalue = 1\nvalue = 2\n'):
            with self.assertRaises(RuntimeError):
                apply_hunks(source, patch)

    def test_local_patch_provenance_does_not_claim_an_upstream_commit(self):
        patch = {'source_kind': 'keep-local', 'source_id': 'keep-reviewed-change',
                 'commit': None}
        self.assertEqual(patch_provenance(patch), {
            'source_kind': 'keep-local', 'source_id': 'keep-reviewed-change',
            'upstream_commit': None,
        })
        patch['commit'] = 'pretend-upstream'
        with self.assertRaises(ValueError):
            patch_provenance(patch)

    def test_existing_upstream_provenance_is_preserved(self):
        self.assertEqual(patch_provenance({'commit': 'upstream'}), {
            'source_kind': 'upstream', 'upstream_commit': 'upstream',
        })

    def test_missing_local_identifier_or_unknown_source_is_rejected(self):
        for patch in ({'source_kind': 'keep-local', 'commit': None},
                      {'source_kind': 'unknown', 'commit': 'upstream'},
                      {'commit': None}):
            with self.assertRaises(ValueError):
                patch_provenance(patch)

    def local_reset_helpers(self):
        manifest = Path(__file__).resolve().parents[1] / 'scripts/python_security_patches.json'
        local = next(p for p in json.loads(manifest.read_text())
                     if p.get('source_kind') == 'keep-local')
        self.assertEqual(local['source_id'], 'keep-tempfile-bound-permission-reset-v1')
        self.assertIsNone(local['commit'])
        self.assertEqual(len(local['hunks']), 1)
        os_calls = SimpleNamespace(
            O_RDONLY=0, O_NONBLOCK=2048, O_NOFOLLOW=131072,
            supports_follow_symlinks=set(), open=Mock(return_value=41),
            chmod=Mock(), close=Mock(),
        )
        namespace = {'_os': os_calls, '_errno': errno, '_resetflags': Mock()}
        exec(compile(local['hunks'][0]['after'], 'keep-local-cleanup-guard', 'exec'), namespace)
        return namespace, os_calls

    def test_unbound_reset_cannot_call_permission_operations(self):
        namespace, os_calls = self.local_reset_helpers()
        for call in (
            lambda: namespace['_resetperms_fd'](None, '/synthetic-outside'),
            lambda: namespace['_resetperms_at']('entry', None, '/synthetic-outside'),
        ):
            with self.assertRaises(PermissionError):
                call()
        namespace['_resetflags'].assert_not_called()
        os_calls.open.assert_not_called()
        os_calls.chmod.assert_not_called()

    def test_unavailable_nofollow_or_failed_open_cannot_fall_back(self):
        namespace, os_calls = self.local_reset_helpers()
        namespace['_nofollow_mode'] = None
        with self.assertRaises(PermissionError):
            namespace['_resetperms_at']('entry', 31, '/synthetic-entry')
        os_calls.open.assert_not_called()
        namespace['_nofollow_mode'] = os_calls.O_NOFOLLOW
        denied = PermissionError(errno.EACCES, 'synthetic open denial')
        os_calls.open.side_effect = denied
        with self.assertRaises(PermissionError) as caught:
            namespace['_resetperms_at']('entry', 31, '/synthetic-entry')
        self.assertIs(caught.exception, denied)
        os_calls.chmod.assert_not_called()
        os_calls.close.assert_not_called()

    def test_safe_descriptor_is_closed_even_when_chmod_fails(self):
        namespace, os_calls = self.local_reset_helpers()
        os_calls.chmod.side_effect = OSError('synthetic chmod failure')
        with self.assertRaises(OSError):
            namespace['_resetperms_at']('entry', 31, '/synthetic-entry')
        os_calls.open.assert_called_once_with('entry', namespace['_nofollow_mode'], dir_fd=31)
        os_calls.chmod.assert_called_once_with(41, 0o700)
        os_calls.close.assert_called_once_with(41)


class LoadedZlibTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.canonical_directory = self.root / 'usr/lib'
        self.other_directory = self.root / 'lib'
        self.canonical_directory.mkdir(parents=True)
        self.other_directory.mkdir()
        self.library = self.canonical_directory / 'libz.so.1.3.2'
        self.reviewed_bytes = b'synthetic reviewed zlib library'
        self.library.write_bytes(self.reviewed_bytes)
        self.expected_sha256 = hashlib.sha256(self.reviewed_bytes).hexdigest()
        self.soname = self.library.with_name('libz.so.1')
        self.soname.symlink_to(self.library.name)
        self.directories = (self.canonical_directory, self.other_directory)

    def mapping(self, path=None, *, inode=None, device=None, deleted=False):
        info = self.library.stat()
        path = path or self.library
        inode = info.st_ino if inode is None else inode
        device = ((os.major(info.st_dev), os.minor(info.st_dev))
                  if device is None else device)
        suffix = ' (deleted)' if deleted else ''
        return (f'1000-2000 r-xp 00000000 {device[0]:02x}:{device[1]:02x} '
                f'{inode} {path}{suffix}\n')

    def verify(self, maps_text=None, expected_sha256=None):
        verify_loaded_zlib(
            self.library,
            self.expected_sha256 if expected_sha256 is None else expected_sha256,
            self.mapping() if maps_text is None else maps_text,
            self.directories,
        )

    def test_reviewed_canonical_file_soname_and_mapping_pass(self):
        # Linux can list several mappings of the same loaded library.
        self.verify(self.mapping() + self.mapping(self.soname))
        self.assertEqual(self.library.read_bytes(), self.reviewed_bytes)
        self.assertTrue(self.soname.is_symlink())

    def test_misplaced_patched_copy_does_not_approve_vendor_default(self):
        (self.other_directory / self.library.name).write_bytes(self.reviewed_bytes)
        self.library.write_bytes(b'synthetic vendor zlib library')
        with self.assertRaisesRegex(RuntimeError, 'does not match the build manifest'):
            self.verify()

    def test_missing_broken_or_wrong_soname_is_rejected(self):
        for target in (None, 'missing-library', 'other-library'):
            with self.subTest(target=target):
                self.soname.unlink()
                if target is not None:
                    if target == 'other-library':
                        self.library.with_name(target).write_bytes(self.reviewed_bytes)
                    self.soname.symlink_to(target)
                with self.assertRaises((FileNotFoundError, RuntimeError)):
                    self.verify()
                if self.soname.is_symlink():
                    self.soname.unlink()
                self.soname.symlink_to(self.library.name)

    def test_divergent_library_in_either_loader_directory_is_rejected(self):
        for directory in self.directories:
            with self.subTest(directory=directory):
                sibling = directory / 'libz.so.0'
                sibling.write_bytes(b'synthetic different zlib library')
                try:
                    with self.assertRaisesRegex(RuntimeError, 'loader candidate differs'):
                        self.verify()
                finally:
                    sibling.unlink()

    def test_wrong_manifest_hash_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'does not match the build manifest'):
            self.verify(expected_sha256='0' * 64)

    def test_matching_bytes_at_unexpected_mapped_path_are_rejected(self):
        other = self.other_directory / self.library.name
        other.write_bytes(self.reviewed_bytes)
        with self.assertRaisesRegex(RuntimeError, 'mapped a different zlib library'):
            self.verify(self.mapping() + self.mapping(other))

    def test_wrong_mapped_inode_or_device_is_rejected(self):
        info = self.library.stat()
        device = (os.major(info.st_dev), os.minor(info.st_dev))
        for changed in (
            {'inode': info.st_ino + 1},
            {'device': (device[0] + 1, device[1])},
            {'device': (device[0], device[1] + 1)},
        ):
            with self.subTest(changed=changed):
                with self.assertRaisesRegex(RuntimeError, 'mapped zlib identity differs'):
                    self.verify(self.mapping() + self.mapping(**changed))

    def test_missing_zlib_mapping_is_rejected(self):
        for maps_text in ('', '1000-2000 r-xp 00000000 00:00 0\n',
                          '1000-2000 r-xp 00000000 00:00 0 /synthetic/libc.so\n'):
            with self.subTest(maps_text=maps_text):
                with self.assertRaisesRegex(RuntimeError, 'no loaded zlib library'):
                    self.verify(maps_text)

    def test_deleted_mapping_is_rejected_even_if_path_was_recreated(self):
        # The current pathname still exists, but this mapping names a deleted file.
        with self.assertRaises((FileNotFoundError, RuntimeError)):
            self.verify(self.mapping(deleted=True))
