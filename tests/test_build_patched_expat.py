"""A preparation receipt cannot become reviewed Expat runtime evidence."""
import copy
import hashlib
import io
import json
from pathlib import Path
import struct
import subprocess
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from scripts import build_patched_expat as build


class PatchedExpatBuildTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name).resolve()
        (self.root / 'docs').mkdir()
        self.lock = copy.deepcopy(build.reviewed_spec())

    def write_lock(self, *, pinned=False):
        spec = copy.deepcopy(self.lock)
        if pinned:
            spec['expected_library_sha256'] = {'amd64': '1' * 64, 'arm64': '2' * 64}
            spec['compiler_sha256'] = {'amd64': '3' * 64, 'arm64': '4' * 64}
        else:
            spec['expected_library_sha256'] = dict.fromkeys(build.TARGETS)
            spec['compiler_sha256'] = dict.fromkeys(build.TARGETS)
        path = self.root / 'docs/expat-build.json'
        path.write_bytes(build.json_bytes(spec))
        return path

    def test_unpinned_lock_prepares_but_default_build_fails_before_network_or_execution(self):
        self.write_lock()
        for arch in build.TARGETS:
            with self.subTest(arch=arch), self.assertRaisesRegex(ValueError, 'both architectures'):
                build.expected_manifest(arch, self.root)
        with patch.object(build, 'native_architecture') as native, \
                patch.object(build, 'download') as fetch:
            with self.assertRaisesRegex(ValueError, 'both architectures'):
                build.build(self.root / 'output', root=self.root)
            native.assert_not_called()
            fetch.assert_not_called()

    def test_complete_pins_accept_only_the_exact_final_architecture_manifest(self):
        self.write_lock(pinned=True)
        for arch in build.TARGETS:
            with self.subTest(arch=arch):
                manifest = build.expected_manifest(arch, self.root)
                self.assertEqual(build.verify_build_manifest(manifest, arch, self.root), manifest)
                self.assertFalse(manifest['vendor_apk_signature_applies_to_replacement'])
                for key, value in [('source_sha256', 'f' * 64), ('build_lock_sha256', 'f' * 64),
                                   ('build_script_sha256', 'f' * 64), ('qualified', False),
                                   ('source_replay_sha256', 'f' * 64), ('purpose', 'preparation-only')]:
                    changed = {**manifest, key: value}
                    with self.subTest(key=key), self.assertRaises(ValueError):
                        build.verify_build_manifest(changed, arch, self.root)
                changed = copy.deepcopy(manifest)
                changed['library']['sha256'] = 'f' * 64
                with self.assertRaises(ValueError):
                    build.verify_build_manifest(changed, arch, self.root)
                with self.assertRaises(ValueError):
                    build.verify_build_manifest({**manifest, 'extra': True}, arch, self.root)

    def test_preparation_manifest_is_rejected_even_after_outputs_have_been_pinned(self):
        self.write_lock(pinned=True)
        spec = build.reviewed_spec(self.root)
        manifest = build._manifest(spec, 'amd64', '1' * 64, '3' * 64, qualified=False)
        with self.assertRaisesRegex(ValueError, 'preparation or unqualified'):
            build.verify_build_manifest(manifest, 'amd64', self.root)

    def test_one_missing_architecture_or_compiler_pin_cannot_qualify_either_architecture(self):
        for field in ('compiler_sha256', 'expected_library_sha256'):
            path = self.write_lock(pinned=True)
            spec = json.loads(path.read_bytes())
            spec[field]['arm64'] = None
            path.write_bytes(build.json_bytes(spec))
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'both architectures'):
                build.expected_manifest('amd64', self.root)

    def test_explicit_runtime_lock_path_uses_same_compiled_source_facts(self):
        path = self.write_lock(pinned=True)
        self.assertEqual(build.expected_manifest('arm64', lock_path=path),
                         build.expected_manifest('arm64', self.root))
        spec = json.loads(path.read_bytes())
        spec['source']['sha256'] = 'f' * 64
        path.write_bytes(build.json_bytes(spec))
        with self.assertRaisesRegex(ValueError, 'reviewed source or recipe'):
            build.reviewed_spec(lock_path=path)

    def test_script_drift_unknown_inputs_and_noncanonical_lock_bytes_fail_closed(self):
        for mutation in ('script', 'extra', 'environment', 'format'):
            path = self.write_lock(pinned=True)
            spec = json.loads(path.read_bytes())
            if mutation == 'script':
                spec['build_script_sha256'] = 'f' * 64
            elif mutation == 'extra':
                spec['extra'] = True
            elif mutation == 'environment':
                spec['build']['environment']['LD_LIBRARY_PATH'] = '/alternate'
            path.write_bytes(json.dumps(spec).encode() if mutation == 'format' else build.json_bytes(spec))
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                build.reviewed_spec(self.root)

    def test_committed_patch_inputs_have_exact_digest_and_complete_file_hash_chains(self):
        body = (build.ROOT / build.PATCH_PATH).read_bytes()
        self.assertEqual(hashlib.sha256(body).hexdigest(), build.PATCH_SHA256)
        manifest = json.loads(body)
        self.assertEqual([row['commit'] for row in manifest['patches']], list(build.COMMITS))
        hashes = dict(build.ORIGINAL_FILES)
        self.assertEqual([row['source_id'] for row in manifest['local_patches']],
                         list(build.LOCAL_PATCHES))
        self.assertTrue(all(row['source_kind'] == 'keep-local' and row['commit'] is None
                            for row in manifest['local_patches']))
        for row in [*manifest['patches'], *manifest['local_patches']]:
            for file in row['files']:
                self.assertEqual(file['before_sha256'], hashes[file['path']])
                self.assertTrue(file['hunks'])
                self.assertTrue(all(hunk['before'] and hunk['before'] != hunk['after']
                                    for hunk in file['hunks']))
                hashes[file['path']] = file['after_sha256']
        self.assertEqual(hashes, build.PATCHED_FILES)

    def synthetic_patch(self):
        path, before, after = 'lib/xmlparse.c', b'ordinary before source\n', b'ordinary after source\n'
        originals = {path: build.digest(before)}
        patched = {path: build.digest(after)}
        rows = [{'commit': commit, 'files': []} for commit in build.COMMITS]
        rows[0]['files'] = [{'path': path, 'before_sha256': originals[path],
                             'after_sha256': patched[path],
                             'hunks': [{'before': before.decode(), 'after': after.decode()}]}]
        manifest = {'schema': 'keep-expat-patches-v1', 'upstream_version': '2.9.0',
                    'patched_files': patched, 'patches': rows,
                    'local_patches': [{'source_id': source_id, 'source_kind': 'keep-local',
                                       'commit': None, 'files': []}
                                      for source_id in build.LOCAL_PATCHES]}
        return path, before, after, originals, patched, manifest

    def test_exact_patch_replay_preserves_modes_and_unmodified_source(self):
        path, before, after, originals, patched, manifest = self.synthetic_patch()
        files = {path: (before, 0o644), 'configure': (b'complete original build source', 0o755)}
        with patch.object(build, 'ORIGINAL_FILES', originals), patch.object(build, 'PATCHED_FILES', patched):
            result = build.apply_source_patches(files, manifest)
        self.assertEqual(result[path], (after, 0o644))
        self.assertEqual(result['configure'], files['configure'])
        self.assertEqual(files[path][0], before)

    def test_local_correction_cannot_be_dropped_reordered_or_claimed_as_upstream(self):
        for mutation in ('missing', 'identity', 'kind', 'commit'):
            path, before, _, originals, patched, manifest = self.synthetic_patch()
            if mutation == 'missing':
                manifest['local_patches'] = []
            elif mutation == 'identity':
                manifest['local_patches'][0]['source_id'] = 'unreviewed-change'
            elif mutation == 'kind':
                manifest['local_patches'][0]['source_kind'] = 'upstream'
            else:
                manifest['local_patches'][0]['commit'] = build.COMMITS[-1]
            with self.subTest(mutation=mutation), patch.object(build, 'ORIGINAL_FILES', originals), \
                    patch.object(build, 'PATCHED_FILES', patched), \
                    self.assertRaisesRegex(ValueError, 'local patch provenance'):
                build.apply_source_patches({path: (before, 0o644)}, manifest)

    def test_changed_original_context_patch_output_or_target_cannot_replay(self):
        for mutation in ('original', 'context', 'output', 'target'):
            path, before, _, originals, patched, manifest = self.synthetic_patch()
            files = {path: (before, 0o644)}
            if mutation == 'original':
                files[path] = (b'changed original', 0o644)
            elif mutation == 'context':
                manifest['patches'][0]['files'][0]['hunks'][0]['before'] = 'absent context'
            elif mutation == 'output':
                manifest['patches'][0]['files'][0]['hunks'][0]['after'] = 'different fix'
            else:
                manifest['patches'][0]['files'][0]['path'] = '../outside'
            with self.subTest(mutation=mutation), patch.object(build, 'ORIGINAL_FILES', originals), \
                    patch.object(build, 'PATCHED_FILES', patched), self.assertRaises(ValueError):
                build.apply_source_patches(files, manifest)

    @staticmethod
    def archive(entries):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode='w:xz') as archive:
            for name, body, kind in entries:
                member = tarfile.TarInfo(name)
                member.type = kind
                member.size = len(body) if kind == tarfile.REGTYPE else 0
                archive.addfile(member, io.BytesIO(body) if member.isfile() else None)
        return stream.getvalue()

    def test_source_archive_rejects_traversal_links_duplicates_and_wrong_release_root(self):
        good = (build.SOURCE_DIRECTORY + '/COPYING', b'full notice', tarfile.REGTYPE)
        for entries in ([good, good], [(build.SOURCE_DIRECTORY + '/../outside', b'x', tarfile.REGTYPE)],
                        [('/absolute', b'x', tarfile.REGTYPE)], [('other/COPYING', b'x', tarfile.REGTYPE)],
                        [(build.SOURCE_DIRECTORY + '/link', b'', tarfile.SYMTYPE)]):
            with self.subTest(entries=entries), self.assertRaises(ValueError):
                build.source_members(self.archive(entries))
        self.assertEqual(build.source_members(self.archive([good]))['COPYING'][0], b'full notice')

    def test_empty_output_rejects_nonempty_and_symlink_ancestors(self):
        nonempty = self.root / 'nonempty'
        nonempty.mkdir()
        (nonempty / 'evidence').write_bytes(b'preserve')
        with self.assertRaisesRegex(ValueError, 'must be empty'):
            build.empty_directory(nonempty)
        link = self.root / 'link'
        link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'symlinks'):
            build.empty_directory(link / 'new-output')

    def test_elf_native_identity_is_not_inferred_from_filename(self):
        body = bytearray(64)
        body[:6] = b'\x7fELF\x02\x01'
        body[16:18] = (3).to_bytes(2, 'little')
        body[18:20] = (62).to_bytes(2, 'little')
        build.check_library(bytes(body), 'amd64')
        with self.assertRaisesRegex(ValueError, 'architecture or type'):
            build.check_library(bytes(body), 'arm64')
        with self.assertRaisesRegex(ValueError, '64-bit little-endian'):
            build.check_library(b'not an ELF library', 'amd64')

    def test_native_build_environment_preserves_alpine_defaults_and_explicit_hardening(self):
        for arch in build.TARGETS:
            environment = build.build_environment(arch)
            self.assertEqual(environment['CXX'], '/usr/bin/g++')
            for flag in ('-fstack-clash-protection', '-Wformat', '-Werror=format-security',
                         '-fstack-protector-strong'):
                self.assertIn(flag, environment['CFLAGS'].split())
            self.assertIn('-D_FORTIFY_SOURCE=2', environment['CPPFLAGS'].split())
            self.assertIn('-I/opt/keep-expat-build/fortify/include', environment['CPPFLAGS'].split())
            for flag in ('relro', 'now', 'noexecstack', 'pack-relative-relocs'):
                self.assertIn(flag, environment['LDFLAGS'])
            self.assertEqual('-fno-plt' in environment['CFLAGS'].split(), arch == 'amd64')
            self.assertFalse(any(flag in environment['CFLAGS'] for flag in ('-march=native', '-mtune=native')))

    def test_compiler_must_activate_fortify_headers_and_strong_stack_protection(self):
        output = b'#define _FORTIFY_SOURCE 2\n#define _FORTIFY_STRING_H\n#define __SSP_STRONG__ 3\n'
        with patch.object(build.subprocess, 'check_output', return_value=output):
            result = build.compiler_hardening('amd64')
            self.assertTrue(result['fortify_headers_active'])
        for marker in (b'#define _FORTIFY_SOURCE 2\n', b'#define _FORTIFY_STRING_H\n',
                       b'#define __SSP_STRONG__ 3\n'):
            with self.subTest(marker=marker), patch.object(
                    build.subprocess, 'check_output', return_value=output.replace(marker, b'')), \
                    self.assertRaisesRegex(ValueError, 'effective compiler'):
                build.compiler_hardening('arm64')

    def test_failed_compiler_precondition_reports_bounded_macro_and_header_evidence(self):
        output = b'#define _FORTIFY_SOURCE 2\n#define __SSP_STRONG__ 3\n'
        with patch.object(build.subprocess, 'check_output', return_value=output):
            with self.assertRaises(ValueError) as raised:
                build.compiler_hardening('amd64')
        diagnostics = json.loads(str(raised.exception).split('; ', 1)[1])
        self.assertEqual(diagnostics['macros']['_FORTIFY_SOURCE'], '2')
        self.assertEqual(diagnostics['macros']['__SSP_STRONG__'], '3')
        self.assertIsNone(diagnostics['macros']['_FORTIFY_STRING_H'])
        self.assertEqual(set(diagnostics['headers']), {'/usr/include/string.h',
                         '/usr/include/fortify/string.h', '/usr/include/fortify/fortify-headers.h',
                         '/opt/keep-expat-build/fortify/include/string.h',
                         '/opt/keep-expat-build/fortify/include/fortify-headers.h'})
        self.assertLess(len(str(raised.exception)), 3000)

    def test_isolated_headers_are_replayed_and_verified_before_compiler_feature_check(self):
        events = []
        self.write_lock()
        cpp_proof = build.cpp.installation_manifest('amd64')
        (self.root / 'CPP_BUILD_SECURITY.json').write_bytes(build.cpp.json_bytes(cpp_proof))
        tools_proof = build.build_tools.installation_manifest('amd64')
        (self.root / 'BUILD_TOOLS_SECURITY.json').write_bytes(build.json_bytes(tools_proof))
        with patch.object(build, 'native_architecture', return_value='amd64'), \
                patch.object(build, 'compiler_identity', return_value=('a' * 64, 'fixture GCC')), \
                patch.object(build.cpp, 'PREPARED_ROOT', self.root), \
                patch.object(build.cpp, 'verify_installed', return_value=cpp_proof) as cpp_inputs, \
                patch.object(build.build_tools, 'PREPARED_ROOT', self.root), \
                patch.object(build.build_tools, 'verify_installed', return_value=tools_proof), \
                patch.dict(build.os.environ, {'KEEP_EXPAT_BUILD_IMAGE': build.BUILD_IMAGE}), \
                patch.object(build, 'replay_sources', side_effect=lambda *args, **kwargs: events.append('replay')), \
                patch.object(build.fortify, 'verify_prepared_headers',
                             side_effect=lambda *args: events.append('verify')), \
                patch.object(build.subprocess, 'run') as compile_command, \
                patch.object(build, 'compiler_hardening') as hardening:
            def check_after_replay(_):
                events.append('compiler')
                raise ValueError('stop after compiler ordering check')
            hardening.side_effect = check_after_replay
            with self.assertRaisesRegex(ValueError, 'ordering check'):
                build.build(self.root / 'prepared', preparation=True, root=self.root)
            compile_command.assert_not_called()
            cpp_inputs.assert_called_once_with('amd64')
        self.assertEqual(events, ['replay', 'verify', 'compiler'])

    def test_cpp_inputs_are_hardcoded_retained_and_do_not_disable_upstream_tests(self):
        spec = build.reviewed_spec()
        self.assertEqual(spec['cpp_packages'], build.cpp.reviewed_spec())
        self.assertEqual(build.CONFIGURE_OPTIONS, ('--prefix=/usr', '--mandir=/usr/share/man', '--enable-static'))
        self.assertEqual(spec['build']['commands'][-1], ['make', 'check'])
        records = build.source_download_records()
        cpp_records = [row for row in records if row['path'].startswith('cpp/')]
        self.assertEqual(len(cpp_records), 5)
        self.assertEqual(sum(row['path'].endswith('.apk') for row in cpp_records), 4)
        self.assertEqual(build.source_replay_record()['cpp_packages'], build.cpp.reviewed_spec())
        self.assertEqual(build.source_replay_record()['schema'], 'keep-expat-source-replay-v4')
        self.assertEqual(build.source_replay_record()['build_tools'], build.build_tools.reviewed_spec())

    def test_missing_make_and_bash_fail_before_upstream_build_commands(self):
        def which(name, **_):
            return None if name in ('make', 'bash') else build.__file__
        with patch.object(build.shutil, 'which', side_effect=which), \
                patch.object(build.subprocess, 'run') as command, \
                self.assertRaisesRegex(ValueError, 'make, bash'):
            build.required_build_tools(build.build_environment('amd64'))
        command.assert_not_called()

    def test_failed_configure_retains_bounded_original_log_context_without_relaxing_checks(self):
        source = self.root / 'source'
        source.mkdir()
        body = b'ordinary configure context\n' * 3000 + b'config.status: make: not found\n'
        (source / 'config.log').write_bytes(body)
        command = ['./configure', *build.CONFIGURE_OPTIONS]
        error = subprocess.CalledProcessError(127, command)
        with patch.object(build.subprocess, 'run', side_effect=error), \
                patch.object(build.shutil, 'which', return_value=None), \
                patch('builtins.print'), self.assertRaises(subprocess.CalledProcessError):
            build.run_build_command(command, source, build.build_environment('amd64'), self.root)
        diagnostics = json.loads((self.root / 'BUILD_FAILURE.json').read_bytes())
        self.assertEqual(diagnostics['returncode'], 127)
        self.assertEqual(diagnostics['command'], command)
        self.assertEqual(diagnostics['logs']['config.log']['sha256'], build.digest(body))
        self.assertIn('make: not found', diagnostics['logs']['config.log']['excerpt'])
        self.assertLess(len(build.json_bytes(diagnostics)), 18000)
        self.assertNotIn('--disable-dependency-tracking', diagnostics['command'])

    @staticmethod
    def elf_fixture(*, stack_flags=6, relro=True, now=True, stack_protector=True):
        body = bytearray(4096)
        ident = b'\x7fELF\x02\x01\x01' + bytes(9)
        struct.pack_into('<16sHHIQQQIHHHHHH', body, 0, ident, 3, 62, 1, 0,
                         64, 2048, 0, 64, 56, 4, 64, 3, 0)
        base, dynamic_offset, strings_offset, symbols_offset = 0x1000, 288, 512, 1024
        names = ['', 'libexpat.so.1', 'libc.musl-x86_64.so.1', 'XML_Alpha', 'XML_Beta',
                 '__stack_chk_fail' if stack_protector else '__unprotected']
        strings, offsets = b'', {}
        for name in names:
            offsets[name] = len(strings)
            strings += name.encode() + b'\0'
        body[strings_offset:strings_offset + len(strings)] = strings
        tags = [(1, offsets[names[2]]), (5, base + strings_offset), (10, len(strings)),
                (14, offsets['libexpat.so.1']), (30, 8 if now else 0), (0, 0)]
        for number, entry in enumerate(tags):
            struct.pack_into('<qQ', body, dynamic_offset + number * 16, *entry)
        programs = [(1, 6, 0, base, base, len(body), len(body), 4096),
                    (2, 6, dynamic_offset, base + dynamic_offset, base + dynamic_offset,
                     len(tags) * 16, len(tags) * 16, 8),
                    (0x6474e551, stack_flags, 0, 0, 0, 0, 0, 16),
                    (0x6474e552 if relro else 4, 4, dynamic_offset,
                     base + dynamic_offset, base + dynamic_offset, 96, 96, 1)]
        for number, entry in enumerate(programs):
            struct.pack_into('<IIQQQQQQ', body, 64 + number * 56, *entry)
        symbols = [(0, 0, 0, 0, 0, 0), (offsets['XML_Alpha'], 18, 0, 1, 1, 16),
                   (offsets['XML_Beta'], 18, 0, 1, 17, 16), (offsets[names[-1]], 18, 0, 0, 0, 0)]
        for number, entry in enumerate(symbols):
            struct.pack_into('<IBBHQQ', body, symbols_offset + number * 24, *entry)
        sections = [(0,) * 10, (0, 3, 0, base + strings_offset, strings_offset, len(strings), 0, 0, 1, 0),
                    (0, 11, 0, base + symbols_offset, symbols_offset, len(symbols) * 24, 1, 0, 8, 24)]
        for number, entry in enumerate(sections):
            struct.pack_into('<IIQQQQIIQQ', body, 2048 + number * 64, *entry)
        return bytes(body)

    def test_final_elf_checks_require_non_executable_stack_relro_now_ssp_and_exact_exports(self):
        expected = {**build.EXPECTED_ABI, 'export_count': 2,
                    'exports_sha256': build.digest(b'XML_Alpha\nXML_Beta\n')}
        with patch.object(build, 'EXPECTED_ABI', expected):
            result = build.elf_protections(self.elf_fixture(), 'amd64')
            self.assertTrue(result['hardening']['relro'])
            self.assertEqual(result['export_count'], 2)
            for changes in ({'stack_flags': 7}, {'relro': False}, {'now': False},
                            {'stack_protector': False}):
                with self.subTest(changes=changes), self.assertRaises(ValueError):
                    build.elf_protections(self.elf_fixture(**changes), 'amd64')
            with self.assertRaisesRegex(ValueError, 'exported API'):
                build.elf_protections(self.elf_fixture().replace(b'XML_Beta', b'XML_Zeta'), 'amd64')
            with self.assertRaisesRegex(ValueError, 'table bounds'):
                build.elf_protections(self.elf_fixture()[:100], 'amd64')

    def test_built_feature_list_preserves_security_limits_namespace_dtd_and_character_abi(self):
        features = [SimpleNamespace(feature=number, name=name.encode(), value=value)
                    for number, (name, value) in enumerate(build.EXPECTED_ABI['features'].items(), 1)]
        features.append(SimpleNamespace(feature=0, name=None, value=0))
        loaded = SimpleNamespace(XML_GetFeatureList=Mock(return_value=features))
        with patch.object(build.ctypes, 'CDLL', return_value=loaded):
            self.assertEqual(build.runtime_features(Path('/built/expat.so')), build.EXPECTED_ABI['features'])
        for changed in (features[:-2] + features[-1:],
                        [SimpleNamespace(feature=1, name=b'XML_DTD', value=1), *features[1:]]):
            loaded.XML_GetFeatureList.return_value = changed
            with patch.object(build.ctypes, 'CDLL', return_value=loaded), self.assertRaises(ValueError):
                build.runtime_features(Path('/built/expat.so'))


if __name__ == '__main__':
    unittest.main()
