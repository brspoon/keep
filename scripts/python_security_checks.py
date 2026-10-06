"""Behavioral probes for all verified-fixed findings in the runtime candidate.

Run inside that image, with no network. These do not suppress scanner findings.
References: python/cpython commits 16dea1e, a0d023f, 31980e8, 1e54caa,
5e0ef3f, b234a2b, fb2f0bb and 363aec1; zlib commit df84af2.
Keep additionally refuses unbound permission resets and unsafe open fallbacks.
"""
import binascii
import ctypes
import errno
import io
import gzip
import hashlib
import json
import os
import platform
import sys
import pathlib
import poplib
import shutil
import stat
import tarfile
import tempfile
import unicodedata
import unittest
from unittest.mock import Mock, patch
import urllib.request
import zipfile
import zlib


def verify_loaded_zlib(library_path, expected_sha256, maps_text, library_directories):
    """Bind the reviewed file to the actual Linux mappings and loader aliases."""
    expected_path = library_path.resolve(strict=True)
    expected_stat = expected_path.stat()
    if hashlib.sha256(expected_path.read_bytes()).hexdigest() != expected_sha256:
        raise RuntimeError('zlib runtime file does not match the build manifest')
    soname = library_path.with_name('libz.so.1')
    if soname.resolve(strict=True) != expected_path:
        raise RuntimeError('zlib SONAME alias does not select the reviewed library')

    for directory in library_directories:
        for candidate in directory.glob('libz.so*'):
            if hashlib.sha256(candidate.read_bytes()).hexdigest() != expected_sha256:
                raise RuntimeError('a zlib loader candidate differs from the reviewed library')

    found = False
    for line in maps_text.splitlines():
        fields = line.split(None, 5)
        if len(fields) != 6 or not pathlib.Path(fields[5]).name.startswith('libz.so'):
            continue
        mapped_path = pathlib.Path(fields[5])
        if mapped_path.resolve(strict=True) != expected_path:
            raise RuntimeError('default consumers mapped a different zlib library')
        major, minor = (int(part, 16) for part in fields[3].split(':'))
        if (int(fields[4]) != expected_stat.st_ino
                or (major, minor) != (os.major(expected_stat.st_dev), os.minor(expected_stat.st_dev))):
            raise RuntimeError('mapped zlib identity differs from the reviewed file')
        found = True
    if not found:
        raise RuntimeError('no loaded zlib library was found')


class PythonSecurityChecks(unittest.TestCase):
    def test_CVE_2026_12345_cleanup_keeps_sibling_fixture_intact(self):
        self.assertEqual(platform.system(), 'Linux')
        self.assertFalse(hasattr(os, 'chflags'))
        self.assertTrue({os.chmod, os.unlink, os.lstat} <= os.supports_dir_fd)
        self.assertIn(os.chmod, os.supports_fd)
        self.assertTrue(shutil.rmtree.avoids_symlink_attacks)
        self.assertTrue(tempfile._rmtree_use_dir_fd)
        self.assertTrue(tempfile._nofollow_mode & os.O_NOFOLLOW)

        with tempfile.TemporaryDirectory() as fixture:
            root = pathlib.Path(fixture)
            outside = root / 'outside-cleanup-tree'
            outside.mkdir()
            outside_file = outside / 'file'
            outside_file.write_bytes(b'synthetic sibling fixture')
            outside_file.chmod(0o640)
            original = os.lstat(outside_file)

            cleanup = tempfile.TemporaryDirectory(dir=root)
            child = pathlib.Path(cleanup.name) / 'child'
            child.mkdir()
            (child / 'file').write_bytes(b'synthetic cleanup fixture')
            child.chmod(0o500)
            child_stat = os.lstat(child)
            moved = child.with_name('child-moved')
            unlink = os.unlink
            raced = False

            def permission_recovery_race(path, *, dir_fd=None):
                nonlocal raced
                if (not raced and os.path.basename(path) == 'file'
                        and dir_fd is not None
                        and os.path.samestat(os.fstat(dir_fd), child_stat)):
                    # Inject one error so this does not depend on root or DAC
                    # overrides. Every changed path is inside our fixture.
                    raced = True
                    child.chmod(0o700)
                    child.rename(moved)
                    child.symlink_to(outside, target_is_directory=True)
                    raise PermissionError(errno.EACCES, 'synthetic cleanup error', path)
                return unlink(path, dir_fd=dir_fd)

            try:
                with patch('os.unlink', permission_recovery_race):
                    try:
                        cleanup.cleanup()
                    except NotADirectoryError:
                        # The replaced directory entry may now be a symlink.
                        pass
                self.assertTrue(raced, 'the permission-recovery path was not exercised')
                self.assertTrue(outside_file.exists())
                current = os.lstat(outside_file)
                self.assertEqual(current.st_mode, original.st_mode)
                self.assertTrue(os.path.samestat(current, original))
                self.assertEqual(outside_file.read_bytes(), b'synthetic sibling fixture')
                self.assertFalse((moved / 'file').exists())
                self.assertTrue(tempfile._rmtree_use_dir_fd)
            finally:
                if child.is_symlink():
                    unlink(child)
                    if moved.exists():
                        moved.rename(child)
                if child.exists():
                    child.chmod(0o700)
                cleanup.cleanup()
            self.assertFalse(pathlib.Path(cleanup.name).exists())
            self._check_cleanup_permission_guards(root, outside_file, original)

    def _check_cleanup_permission_guards(self, root, outside_file, original):
        def assert_outside_unchanged():
            current = os.lstat(outside_file)
            self.assertTrue(os.path.samestat(current, original))
            self.assertEqual(current.st_mode, original.st_mode)
            self.assertEqual(outside_file.read_bytes(), b'synthetic sibling fixture')

        for reset in (
            lambda: tempfile._resetperms_fd(None, str(outside_file)),
            lambda: tempfile._resetperms_at(outside_file.name, None, str(outside_file)),
        ):
            with self.assertRaises(PermissionError):
                reset()
            assert_outside_unchanged()

        guard_directory = root / 'guard-fixture'
        guard_directory.mkdir()
        readable = guard_directory / 'readable'
        readable.write_bytes(b'synthetic readable fixture')
        readable.chmod(0o640)
        readable_stat = os.lstat(readable)
        unreadable = guard_directory / 'unreadable'
        unreadable.write_bytes(b'synthetic unreadable fixture')
        unreadable.chmod(0)
        unreadable_stat = os.lstat(unreadable)
        link = guard_directory / 'outside-link'
        link.symlink_to(outside_file)
        directory_fd = os.open(guard_directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            # Exercise the nofollow-open branch even if a future Linux build
            # also gains a native non-following chmod implementation.
            with patch.object(os, 'supports_follow_symlinks', set()):
                tempfile._resetperms_at(readable.name, directory_fd, str(readable))
                current = os.lstat(readable)
                self.assertTrue(os.path.samestat(current, readable_stat))
                self.assertEqual(stat.S_IMODE(current.st_mode), 0o700)
                self.assertEqual(readable.read_bytes(), b'synthetic readable fixture')

                with patch.object(tempfile, '_nofollow_mode', None):
                    with self.assertRaises(PermissionError):
                        tempfile._resetperms_at(
                            outside_file.name, directory_fd, str(outside_file))
                assert_outside_unchanged()

                denied = PermissionError(errno.EACCES, 'synthetic unreadable fixture')
                with patch('os.open', side_effect=denied) as safe_open:
                    with self.assertRaises(PermissionError) as caught:
                        tempfile._resetperms_at(
                            unreadable.name, directory_fd, str(unreadable))
                    self.assertIs(caught.exception, denied)
                    safe_open.assert_called_once_with(
                        unreadable.name, tempfile._nofollow_mode, dir_fd=directory_fd)
                current = os.lstat(unreadable)
                self.assertTrue(os.path.samestat(current, unreadable_stat))
                self.assertEqual(current.st_mode, unreadable_stat.st_mode)
                assert_outside_unchanged()

                with self.assertRaises(OSError):
                    tempfile._resetperms_at(link.name, directory_fd, str(link))
                assert_outside_unchanged()
        finally:
            os.close(directory_fd)
            unreadable.chmod(0o600)
        self.assertEqual(unreadable.read_bytes(), b'synthetic unreadable fixture')

    def test_CVE_2026_85091_patched_zlib_is_loaded(self):
        manifest_path = pathlib.Path('/app/ZLIB_SECURITY.json')
        manifest = json.loads(manifest_path.read_text())
        self.assertEqual(manifest['upstream_commit'], 'df84af25dc1942490e1d1c899a07619152a46148')
        self.assertEqual(manifest['archive_sha256'], 'b99a0b86c0ba9360ec7e78c4f1e43b1cbdf1e6936c8fa0f6835c0cd694a495a1')
        self.assertEqual(manifest['version'], '1.3.2')
        library_path = pathlib.Path('/usr/lib/libz.so.1.3.2')
        # Use the normal SONAME lookup, after the ordinary Python imports above.
        # Opening the patched file by absolute path can mask a delivery defect.
        library = ctypes.CDLL('libz.so.1')
        library.zlibVersion.restype = ctypes.c_char_p
        self.assertEqual(library.zlibVersion(), b'1.3.2')
        self.assertEqual(zlib.ZLIB_RUNTIME_VERSION, '1.3.2')
        payload = b'normal compression round trip' * 100
        self.assertEqual(zlib.decompress(zlib.compress(payload)), payload)
        self.assertEqual(gzip.decompress(gzip.compress(payload)), payload)
        self.assertEqual(binascii.crc32(b'123456789'), 0xcbf43926)
        verify_loaded_zlib(
            library_path, manifest['library_sha256'],
            pathlib.Path('/proc/self/maps').read_text(),
            (pathlib.Path('/lib'), pathlib.Path('/usr/lib')),
        )

    def test_CVE_2025_15367_pop_command_injection(self):
        client = poplib.POP3.__new__(poplib.POP3)
        client._debugging = 0
        client.encoding = 'utf-8'
        client._putline = Mock()
        for control in ('\r\n', '\n', '\x00', '\x7f'):
            with self.subTest(control=repr(control)):
                with self.assertRaises(ValueError):
                    client._putcmd('USER example' + control + 'DELE 1')
        client._putline.assert_not_called()

    def test_CVE_2026_15806_credentials_stay_on_https(self):
        manager = urllib.request.HTTPPasswordMgr()
        manager.add_password('realm', 'https://example.com/', 'user', 'password')
        self.assertEqual(manager.find_user_password('realm', 'https://example.com/'), ('user', 'password'))
        self.assertEqual(manager.find_user_password('realm', 'http://example.com/'), (None, None))

    def test_CVE_2026_17084_idna_unicode_32(self):
        for name, encoded in (
            ('\N{CHEROKEE LETTER A}\N{CHEROKEE LETTER A}', b'xn--58da'),
            ('\N{GEORGIAN CAPITAL LETTER AN}.', b'xn--7md.'),
            ('\N{CYRILLIC LETTER PALOCHKA}.example', b'xn--d5a.example'),
            ('\N{ROMAN NUMERAL REVERSED ONE HUNDRED}.example.', b'xn--q5g.example.'),
        ):
            with self.subTest(name=name):
                self.assertEqual(name.encode('idna'), encoded)
        for char in ('\u077f', '\U00010d01'):
            self.assertEqual(unicodedata.ucd_3_2_0.bidirectional(char), '')

    def test_CVE_2026_15310_bounded_zip_read(self):
        modes = [zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA]
        if zipfile.zstd is not None:
            modes.append(zipfile.ZIP_ZSTANDARD)
        for mode in modes:
            with self.subTest(mode=mode):
                buffer = io.BytesIO()
                with zipfile.ZipFile(buffer, 'w', compression=mode) as archive:
                    archive.writestr('payload', b'\0' * (4 * 1024 * 1024))
                with zipfile.ZipFile(io.BytesIO(buffer.getvalue())) as archive:
                    with archive.open('payload') as member:
                        self.assertLessEqual(len(member._read1(100)), member.MIN_READ_SIZE)

    def test_CVE_2026_19672_no_directory_outside_destination(self):
        for extraction_filter in ('tar', 'data'):
            with self.subTest(filter=extraction_filter), tempfile.TemporaryDirectory() as temporary:
                root = pathlib.Path(temporary)
                destination = root / 'destination'
                destination.mkdir()
                buffer = io.BytesIO()
                with tarfile.open(fileobj=buffer, mode='w') as archive:
                    member = tarfile.TarInfo('../escaped/../destination/sub/file')
                    member.size = 1
                    archive.addfile(member, io.BytesIO(b'x'))
                buffer.seek(0)
                with tarfile.open(fileobj=buffer) as archive:
                    archive.extractall(destination, filter=extraction_filter)
                self.assertFalse((root / 'escaped').exists())
                self.assertEqual((destination / 'sub/file').read_bytes(), b'x')

    def test_CVE_2026_4360_hardlink_target_is_filtered(self):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode='w') as archive:
            archive.addfile(tarfile.TarInfo('target'))
            member = tarfile.TarInfo('link')
            member.type = tarfile.LNKTYPE
            member.linkname = 'target'
            archive.addfile(member)
        buffer.seek(0)

        def filter_target(member, path):
            return member.replace(mode=stat.S_IRUSR if member.name == 'target' else None)

        with tempfile.TemporaryDirectory() as temporary, tarfile.open(fileobj=buffer) as archive:
            archive.extract('link', temporary, filter=filter_target)
            self.assertFalse((pathlib.Path(temporary) / 'link').stat().st_mode & stat.S_IWUSR)

    def test_CVE_2026_87910_link_fallback_honors_skipped_filter(self):
        with tarfile.open(fileobj=io.BytesIO(), mode='w') as archive:
            link = tarfile.TarInfo('link')
            link.type = tarfile.LNKTYPE
            link.linkname = 'target'
            link._link_target = 'missing-target'
            target = tarfile.TarInfo('target')
            archive._find_link_target = Mock(return_value=target)
            archive._extract_member = Mock()

            def skip_replaced_target(member, path):
                return None if member.name == 'link' else member

            with patch('os.path.exists', return_value=False):
                archive.makelink_with_filter(
                    link, 'unused-target-path', skip_replaced_target, 'unused-root')
            archive._extract_member.assert_not_called()


if __name__ == '__main__':
    if '--report' in sys.argv:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(PythonSecurityChecks)
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        print(json.dumps({'success': result.wasSuccessful(), 'tests': result.testsRun,
                          'failures': len(result.failures), 'errors': len(result.errors),
                          'skipped': len(result.skipped),
                          'arch': {'x86_64': 'amd64', 'aarch64': 'arm64'}[platform.machine()],
                          'patch_manifest_sha256': hashlib.sha256(pathlib.Path(__file__).with_name('python_security_patches.json').read_bytes()).hexdigest()}))
        raise SystemExit(not result.wasSuccessful())
    unittest.main(verbosity=2)
