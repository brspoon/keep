"""Unqualified source preparations cannot become accepted SQLite runtimes."""
import copy
import ctypes
import hashlib
import io
import json
from pathlib import Path
import struct
import tarfile
import tempfile
import unittest
from unittest.mock import Mock, patch

from scripts import build_patched_sqlite as build


def qualified_fake_spec():
    """Explicit synthetic output pins for fixtures, never native build evidence."""
    spec = build.immutable_spec()
    spec['build_script_sha256'] = build.digest(Path(build.__file__).read_bytes())
    for number, field in enumerate(('expected_library_sha256', 'compiler_sha256',
                                     'expected_vendor_library_sha256'), 1):
        spec[field] = {arch: str(number) * 64 for arch in build.TARGETS}
    return spec


class PatchedSqliteBuildTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name).resolve()
        (self.root / 'docs').mkdir()
        self.spec = copy.deepcopy(build.reviewed_spec())

    def lock(self, pinned=False):
        spec = copy.deepcopy(self.spec)
        for number, field in enumerate(('expected_library_sha256', 'compiler_sha256',
                                         'expected_vendor_library_sha256'), 1):
            spec[field] = {arch: str(number) * 64 if pinned else None for arch in build.TARGETS}
        path = self.root / 'docs/sqlite-build.json'
        path.write_bytes(build.json_bytes(spec))
        return path

    def test_unpinned_lock_fails_before_native_environment_or_download(self):
        self.lock()
        with patch.object(build.platform, 'system') as native, patch.object(build, 'download') as fetch:
            with self.assertRaisesRegex(ValueError, 'both architectures'):
                build.build(self.root / 'output', root=self.root)
            native.assert_not_called(); fetch.assert_not_called()

    def test_each_missing_output_compiler_or_original_vendor_pin_blocks_both_architectures(self):
        for field in ('expected_library_sha256', 'compiler_sha256', 'expected_vendor_library_sha256'):
            path = self.lock(pinned=True)
            spec = json.loads(path.read_bytes()); spec[field]['arm64'] = None
            path.write_bytes(build.json_bytes(spec))
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'both architectures'):
                build.expected_manifest('amd64', self.root)

    def test_qualified_manifest_binds_every_source_and_both_library_identities(self):
        self.lock(pinned=True)
        for arch in build.TARGETS:
            expected = build.expected_manifest(arch, self.root)
            self.assertEqual(build.verify_build_manifest(expected, arch, self.root), expected)
            self.assertFalse(expected['vendor_apk_signature_applies_to_replacement'])
            self.assertTrue(expected['library_only'])
            for key in ('source_sha256', 'preferred_source_sha256', 'patch_manifest_sha256',
                        'build_script_sha256', 'build_lock_sha256', 'source_replay_sha256'):
                with self.subTest(arch=arch, key=key), self.assertRaises(ValueError):
                    build.verify_build_manifest({**expected, key: 'f' * 64}, arch, self.root)
            for key in ('library', 'compiler', 'vendor_library'):
                altered = copy.deepcopy(expected); altered[key]['sha256'] = 'f' * 64
                with self.subTest(key=key), self.assertRaises(ValueError):
                    build.verify_build_manifest(altered, arch, self.root)
            with self.assertRaises(ValueError):
                build.verify_build_manifest({**expected, 'extra': True}, arch, self.root)

    def test_preparation_receipt_cannot_qualify_after_lock_is_pinned(self):
        self.lock(pinned=True)
        spec = build.reviewed_spec(self.root)
        manifest = build._manifest(spec, 'amd64', '1' * 64, '2' * 64, '3' * 64, qualified=False)
        with self.assertRaisesRegex(ValueError, 'preparation or unqualified'):
            build.verify_build_manifest(manifest, 'amd64', self.root)

    def test_explicit_lock_and_both_read_manifest_call_forms(self):
        lock = self.lock(pinned=True); manifest = build.expected_manifest('arm64', self.root)
        path = self.root / 'SQLITE_PATCHED_SECURITY.json'; path.write_bytes(build.json_bytes(manifest))
        self.assertEqual(build.read_build_manifest(path, 'arm64', lock_path=lock), manifest)
        self.assertEqual(build.read_build_manifest('arm64', manifest_path=path, lock_path=lock), manifest)
        with self.assertRaises(ValueError):
            build.read_build_manifest(path, 'amd64', lock_path=lock)

    def test_noncanonical_or_duplicate_manifest_bytes_are_rejected(self):
        lock = self.lock(pinned=True); value = build.expected_manifest('amd64', self.root)
        path = self.root / 'manifest.json'
        for body in (json.dumps(value).encode(), build.json_bytes(value).replace(b'"qualified": true,', b'"qualified": true,\n  "qualified": true,')):
            path.write_bytes(body)
            with self.assertRaisesRegex(ValueError, 'canonical'):
                build.read_build_manifest(path, 'amd64', lock_path=lock)

    def test_modified_source_build_flags_helpers_or_script_cannot_be_approved(self):
        for key in ('source', 'script', 'environment', 'extra', 'format'):
            path = self.lock(pinned=True); spec = json.loads(path.read_bytes())
            if key == 'source': spec['source']['sha256'] = 'f' * 64
            elif key == 'script': spec['build_script_sha256'] = 'f' * 64
            elif key == 'environment': spec['build']['environment']['LD_LIBRARY_PATH'] = '/alternate'
            elif key == 'extra': spec['extra'] = True
            path.write_bytes(json.dumps(spec).encode() if key == 'format' else build.json_bytes(spec))
            with self.subTest(key=key), self.assertRaises(ValueError):
                build.reviewed_spec(self.root)

    def test_build_lock_preserves_exact_existing_toolchain_inputs(self):
        spec = build.reviewed_spec()
        self.assertEqual(spec['fortify_headers'], build.fortify.reviewed_spec())
        self.assertEqual(spec['cpp_packages'], build.cpp.reviewed_spec())
        self.assertEqual(spec['build_tools'], build.build_tools.reviewed_spec())
        self.assertEqual(spec['vendor_package']['version'], '3.53.4-r0')
        self.assertEqual(spec['upstream_version'], '3.54.1')

    def test_compile_is_library_only_and_keeps_features_limits_and_zero_defaults(self):
        self.assertEqual(len(build.REQUIRED_COMPILE_OPTIONS), 54)
        self.assertEqual(tuple(sorted(build.REQUIRED_COMPILE_OPTIONS)), build.REQUIRED_COMPILE_OPTIONS)
        for arch in build.TARGETS:
            command = build.compile_command(arch)
            self.assertEqual([name for name in command if name.endswith('.c')], ['sqlite3.c'])
            self.assertIn('-shared', command)
            self.assertIn('-Wl,-soname,libsqlite3.so.0', command)
            self.assertIn('-DSQLITE_THREADSAFE=1', command)
            self.assertIn('-DSQLITE_MAX_VARIABLE_NUMBER=250000', command)
            self.assertIn('-DSQLITE_DEFAULT_AUTOVACUUM=0', command)
            self.assertIn('-DSQLITE_DEFAULT_RECURSIVE_TRIGGERS=0', command)
            self.assertFalse(any('shell.c' in part or 'sqlite3recover.c' in part for part in command))
            for feature in ('FTS3', 'FTS4', 'FTS5', 'SESSION', 'PREUPDATE_HOOK', 'RTREE', 'GEOPOLY'):
                self.assertIn('-DSQLITE_ENABLE_' + feature, command)

    def test_source_records_retain_both_original_upstream_archives(self):
        records = build.source_download_records()
        upstream = [row for row in records if row['role'] == 'upstream-source' and '/' not in row['path']]
        self.assertEqual({row['sha256'] for row in upstream}, {build.SOURCE_SHA256, build.PREFERRED_SOURCE_SHA256})
        self.assertEqual({row['path'] for row in upstream}, {build.SOURCE_DIRECTORY + '.tar.gz', 'sqlite-src-3540100.zip'})
        self.assertEqual(len({row['path'] for row in records}), len(records))
        self.assertEqual(build.digest((build.ROOT / build.PATCH_PATH).read_bytes()), build.PATCH_SHA256)

    def archive(self, entries):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode='w:gz') as package:
            for name, kind, body in entries:
                entry = tarfile.TarInfo(name); entry.mode = 0o644
                if kind == 'link': entry.type = tarfile.SYMTYPE; entry.linkname = '/etc/passwd'
                else: entry.size = len(body)
                package.addfile(entry, io.BytesIO(body) if kind == 'file' else None)
        return stream.getvalue()

    def test_source_archive_rejects_paths_links_duplicates_and_wrong_release_root(self):
        good = build.SOURCE_DIRECTORY + '/sqlite3.c'
        cases = [[('../outside', 'file', b'x')], [('/absolute', 'file', b'x')],
                 [('other/sqlite3.c', 'file', b'x')], [(good, 'link', b'')],
                 [(good, 'file', b'a'), (good, 'file', b'b')]]
        for entries in cases:
            with self.subTest(entries=entries), self.assertRaises(ValueError):
                build.source_members(self.archive(entries))
        self.assertEqual(build.source_members(self.archive([(good, 'file', b'ordinary source')]))['sqlite3.c'],
                         (b'ordinary source', 0o644))

    def test_oversized_source_file_is_rejected_before_read(self):
        good = build.SOURCE_DIRECTORY + '/sqlite3.c'
        with patch.object(build, 'LIMIT', 1), self.assertRaisesRegex(ValueError, 'bounds'):
            build.source_members(self.archive([(good, 'file', b'large')]))

    def test_original_vendor_source_map_rejects_relabelled_or_changed_package(self):
        original = json.loads((build.ROOT / 'docs/os-package-sources.json').read_bytes())
        for field in ('origin', 'version', 'build_commit', 'binary'):
            mapping = copy.deepcopy(original); row = next(r for r in mapping['origins'] if r['origin'] == 'sqlite')
            if field == 'origin': row['origin'] = 'renamed'
            elif field == 'version': row['version'] = '3.54.1-r0'
            elif field == 'build_commit': row['packages'][0]['build_commit'] = 'f' * 40
            else: row['packages'][0]['binaries']['amd64']['sha256'] = 'f' * 64
            (self.root / 'docs/os-package-sources.json').write_bytes(build.json_bytes(mapping))
            with self.subTest(field=field), self.assertRaises(ValueError):
                build.verify_vendor_source_map(self.root)
        self.assertEqual(build.verify_vendor_source_map(build.ROOT)['version'], '3.53.4-r0')

    def fake_library(self, *, options=None, version=None, source_id=None, threads=1, limits=None):
        library = Mock()
        library.sqlite3_libversion.return_value = (version or build.UPSTREAM_VERSION).encode()
        library.sqlite3_sourceid.return_value = (source_id or build.SOURCE_ID).encode()
        library.sqlite3_threadsafe.return_value = threads
        chosen = list(build.REQUIRED_COMPILE_OPTIONS) if options is None else options
        library.sqlite3_compileoption_get.side_effect = [value.encode() for value in chosen] + [None]
        def opened(name, pointer):
            ctypes.cast(pointer, ctypes.POINTER(ctypes.c_void_p))[0] = ctypes.c_void_p(1)
            return 0
        library.sqlite3_open.side_effect = opened
        library.sqlite3_close.return_value = 0
        values = {13: 10000000, 14: 65000} if limits is None else limits
        library.sqlite3_limit.side_effect = lambda db, number, query: values[number]
        return library

    def test_runtime_features_check_source_identity_threading_options_and_new_default_limits(self):
        with patch.object(build.ctypes, 'CDLL', return_value=self.fake_library()):
            result = build.runtime_features('/synthetic/libsqlite3.so')
        self.assertEqual(result['limit_defaults'], build.REQUIRED_LIMIT_DEFAULTS)
        cases = [dict(version='3.53.4'), dict(source_id='different'), dict(threads=0),
                 dict(options=list(build.REQUIRED_COMPILE_OPTIONS) + ['OMIT_LOAD_EXTENSION']),
                 dict(options=[s for s in build.REQUIRED_COMPILE_OPTIONS if s != 'ENABLE_SESSION']),
                 dict(limits={13: 10000000, 14: 1})]
        for arguments in cases:
            with self.subTest(arguments=arguments), patch.object(build.ctypes, 'CDLL', return_value=self.fake_library(**arguments)), self.assertRaises(ValueError):
                build.runtime_features('/synthetic/libsqlite3.so')

    def test_invalid_architecture_or_truncated_elf_is_rejected(self):
        for body in (b'', b'not an ELF', b'\x7fELF\x02\x01' + bytes(58)):
            with self.subTest(body=body[:8]), self.assertRaises(ValueError):
                build.elf_information(body, 'amd64')


if __name__ == '__main__':
    unittest.main()
