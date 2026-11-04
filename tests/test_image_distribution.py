"""Synthetic archives verify deleted-layer scanning and redacted evidence."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from contextlib import redirect_stderr
from unittest.mock import patch


spec = importlib.util.spec_from_file_location('image_distribution', Path(__file__).resolve().parents[1] / 'scripts/image_distribution.py')
review = importlib.util.module_from_spec(spec)
spec.loader.exec_module(review)


def archive(entries):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w') as package:
        for name, body in entries:
            info = name if isinstance(name, tarfile.TarInfo) else tarfile.TarInfo(name)
            info.size = len(body)
            package.addfile(info, io.BytesIO(body))
    return stream.getvalue()


class ImageDistributionTests(unittest.TestCase):
    def test_notice_text_and_metadata_are_redacted_before_logging(self):
        token = 'ghp_' + 'x' * 36
        data = {'notices': [{'text': 'Copyright public author. ' + token}],
                'url': 'https://account:secret@host.test/', 'license': 'MIT'}
        rendered = json.dumps(review.redacted(data))
        self.assertNotIn(token, rendered)
        self.assertNotIn('account:secret', rendered)
        self.assertIn('sha256=', rendered)
        self.assertEqual(review.redacted(data)['license'], 'MIT')

    def inspect(self, layers, diff_ids=None):
        config = json.dumps({'architecture': 'amd64', 'rootfs': {'diff_ids': diff_ids or [
            'sha256:' + hashlib.sha256(body).hexdigest() for body in layers]}}).encode()
        paths = [f'{number}/layer.tar' for number in range(len(layers))]
        manifest = json.dumps([{'Config': 'config.json', 'Layers': paths}]).encode()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'image.tar'
            path.write_bytes(archive([('manifest.json', manifest), ('config.json', config), *zip(paths, layers)]))
            return review.inspect_archive(path, review.image_patterns(['private.example[dev]?']))

    def test_private_marker_configuration_is_bounded_and_literal(self):
        marker = 'private.example[dev]?'
        self.assertEqual(review.load_private_image_markers(
            required=True, environ={review.PRIVATE_MARKERS_ENV: json.dumps([marker])}), [marker])
        patterns = review.image_patterns([marker])
        self.assertEqual(review.scan_stream(io.BytesIO(marker.encode()), patterns=patterns), ['private-host'])
        self.assertEqual(review.scan_stream(io.BytesIO(b'privateXexample[dev]?'), patterns=patterns), [])
        self.assertEqual(review.scan_stream(io.BytesIO(b'private.exampled'), patterns=patterns), [])
        with self.assertRaisesRegex(ValueError, review.PRIVATE_MARKERS_ENV):
            review.load_private_image_markers(
                required=True, environ={review.PRIVATE_MARKERS_ENV: json.dumps(['🪴' * 129])})
        long_marker = 'x' * 512
        self.assertEqual(review.scan_stream(io.BytesIO(b'y' * (1024 * 1024 - 1)
                            + long_marker.encode()), patterns=review.image_patterns([long_marker])),
                         ['private-host'])

    def test_archive_cli_rejects_missing_and_invalid_markers_without_echoing_values(self):
        invalid_values = [None, '', 'private.example[dev]?', '[]', '[""]',
                          json.dumps(['x' * 513]), json.dumps(['x'] * 33)]
        for value in invalid_values:
            with self.subTest(value_present=value is not None):
                env = {} if value is None else {review.PRIVATE_MARKERS_ENV: value}
                with patch.dict(os.environ, env, clear=True), patch.object(
                        sys, 'argv', ['image_distribution.py', '--archive', 'missing.tar']):
                    stderr = io.StringIO()
                    with redirect_stderr(stderr), self.assertRaises(SystemExit) as error:
                        review.main()
                    self.assertEqual(error.exception.code, 2)
                    self.assertIn(review.PRIVATE_MARKERS_ENV, stderr.getvalue())
                    if value:
                        self.assertNotIn(value, stderr.getvalue())

        marker = 'private.example[dev]?'
        with patch.dict(os.environ, {review.PRIVATE_MARKERS_ENV: json.dumps([marker])}), patch.object(
                sys, 'argv', ['image_distribution.py', '--archive', marker + '.tar']):
            stderr = io.StringIO()
            with redirect_stderr(stderr), self.assertRaises(SystemExit) as error:
                review.main()
            self.assertEqual(error.exception.code, 2)
            self.assertNotIn(marker, stderr.getvalue())

    def test_marker_bearing_paths_and_notice_values_are_redacted(self):
        marker = 'private.example[dev]?'
        result = self.inspect([archive([('app/' + marker + '/LICENSE',
                                        ('Copyright ' + marker).encode())])])
        rendered = json.dumps(result)
        self.assertFalse(result['success'])
        self.assertEqual(result['findings'][0]['rule'], 'private-host')
        self.assertNotIn(marker, rendered)
        self.assertIn('redacted private-host', rendered)
        self.assertEqual(len(result['notice_entries']), 1)

    def test_runtime_redaction_uses_optional_configured_markers(self):
        marker = 'private.example[dev]?'
        with patch.dict(os.environ, {review.PRIVATE_MARKERS_ENV: json.dumps([marker])}):
            self.assertNotIn(marker, json.dumps(review.redacted({'path': '/app/' + marker})))
        self.assertEqual(review.load_private_image_markers(environ={}), [])

    def test_scans_deleted_credential_in_earlier_layer_without_printing_value(self):
        token = b'ghp_' + b'x' * 36
        result = self.inspect([archive([('app/config.txt', token)]), archive([('app/.wh.config.txt', b'')])])
        self.assertFalse(result['success'])
        self.assertEqual(result['findings'][0]['rule'], 'github-token')
        self.assertNotIn(token.decode(), json.dumps(result))
        self.assertEqual(len(result['layers']), 2)

    def test_empty_database_and_environment_file_are_detected(self):
        result = self.inspect([archive([('app/.env', b''), ('app/data/keep.sqlite3', b'')])])
        self.assertEqual({row['rule'] for row in result['findings']}, {'private-runtime-file', 'runtime-database'})

    def test_public_notices_and_source_do_not_trigger(self):
        result = self.inspect([archive([('app/LICENSE', b'MIT public attribution'), ('app/app.py', b'print(1)')])])
        self.assertTrue(result['success'])
        self.assertEqual(result['layers'][0]['files'], 2)

    def test_full_license_directory_is_inventoried(self):
        result = self.inspect([archive([
            ('app/licenses/MPL-2.0.txt', b'Full MPL text'),
            ('app/licenses/os/123abc.txt', b'Upstream attribution'),
            ('usr/share/licenses/package/BSD-3-Clause', b'BSD notice'),
            ('app/assets/123abc.txt', b'Application asset'),
        ])])
        self.assertEqual({row['path'] for row in result['notice_entries']}, {
            'app/licenses/MPL-2.0.txt', 'app/licenses/os/123abc.txt',
            'usr/share/licenses/package/BSD-3-Clause'})

    def test_reviewed_example_requires_exact_file_content(self):
        from unittest.mock import patch
        body = b'http://example:invalid@host.test/'
        reviewed = {('credential-url', hashlib.sha256(body).hexdigest()): 'Synthetic test example'}
        with patch.object(review, 'BENIGN_EXAMPLES', reviewed):
            result = self.inspect([archive([('example.py', body)])])
            self.assertTrue(result['success'])
            self.assertEqual(len(result['benign_examples']), 1)
            changed = self.inspect([archive([('example.py', body + b' modified')])])
            self.assertFalse(changed['success'])

    def test_layer_identity_mismatch_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'match image config'):
            self.inspect([archive([('app/app.py', b'print(1)')])], ['sha256:' + '0' * 64])

    def test_unsafe_tar_paths_are_never_extracted(self):
        with self.assertRaisesRegex(ValueError, 'archive path'):
            self.inspect([archive([('../private.txt', b'unsafe')])])

    def test_token_split_across_chunks_is_detected(self):
        stream = io.BytesIO(b'x' * (1024 * 1024 - 2) + b'ghp_' + b'y' * 36)
        self.assertEqual(review.scan_stream(stream), ['github-token'])

    def test_sqlite_library_and_python_module_are_distinct_from_c_cli(self):
        package = b'P:sqlite-libs\nV:3.53.4-r0\no:sqlite\np:so:libsqlite3.so.0=0\nF:usr/lib\nR:libsqlite3.so.0.8.6\n\n'
        directory = tarfile.TarInfo('usr/lib/python3.14/sqlite3')
        directory.type = tarfile.DIRTYPE
        result = self.inspect([archive([
            ('lib/apk/db/installed', package),
            ('usr/lib/libsqlite3.so.0.8.6', b'\x7fELFsqlite3_libversion\x00sqlite3_prepare_v2\x00'),
            (directory, b''),
            ('usr/lib/python3.14/sqlite3/__main__.py', b'print("SQLite version .recover .system")'),
            ('app/licenses/sqlite/README', b'CLI .recover .shell documentation'),
        ])])
        self.assertTrue(result['success'])
        evidence = result['sqlite_cli']
        self.assertEqual(evidence['scope'], 'all-image-layers')
        self.assertTrue(evidence['success'])
        self.assertEqual(evidence['elf_files_scanned'], 1)
        self.assertEqual(evidence['apk_metadata'][0]['packages'], [{
            'name': 'sqlite-libs', 'version': '3.53.4-r0', 'origin': 'sqlite',
            'provides': ['so:libsqlite3.so.0=0'], 'payloads': ['usr/lib/libsqlite3.so.0.8.6']}])

    def test_deleted_named_cli_and_aliases_remain_in_all_layer_evidence(self):
        symlink = tarfile.TarInfo('usr/local/bin/diagnostic')
        symlink.type, symlink.linkname = tarfile.SYMTYPE, '/usr/bin/sqlite3'
        hardlink = tarfile.TarInfo('usr/local/bin/other')
        hardlink.type, hardlink.linkname = tarfile.LNKTYPE, 'usr/bin/sqlite3'
        result = self.inspect([archive([('usr/bin/sqlite3', b'cli'), (symlink, b''), (hardlink, b'')]),
                               archive([('usr/bin/.wh.sqlite3', b'')])])
        self.assertFalse(result['success'])
        self.assertEqual({row['rule'] for row in result['sqlite_cli']['findings']},
                         {'sqlite-cli-name', 'sqlite-cli-alias'})
        self.assertTrue(all(row['layer'] == 0 for row in result['sqlite_cli']['findings']))
        self.assertEqual(result['sqlite_cli']['layers_scanned'], 2)

    def test_renamed_elf_cli_detected_across_chunks_and_after_whiteout(self):
        body = b'\x7fELF' + b'x' * (1024 * 1024 - 8) + b'.recover\x00.system\x00SQLite version '
        result = self.inspect([archive([('usr/bin/innocent-name', body)]),
                               archive([('usr/bin/.wh.innocent-name', b'')])])
        self.assertFalse(result['success'])
        findings = result['sqlite_cli']['findings']
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['rule'], 'sqlite-cli-elf-markers')
        self.assertEqual(findings[0]['file_sha256'], review.digest(body))
        self.assertIn('.recover', findings[0]['markers'])
        self.assertIn('packed', result['sqlite_cli']['limitations'])

    def test_recovery_api_alone_does_not_claim_a_c_cli_interpreter(self):
        result = self.inspect([archive([('usr/lib/librecover.so',
                              b'\x7fELFsqlite3_recover_init_sql\x00')])])
        self.assertTrue(result['success'])
        self.assertEqual(result['sqlite_cli']['findings'], [])

    def test_cli_apk_identity_payload_and_command_provider_are_blocking(self):
        metadata = (
            b'P:sqlite\nV:3.53.4-r0\no:sqlite\n\n'
            b'P:sqlite-libs\nV:3.53.4-r0\no:sqlite\nF:usr/bin\nR:sqlite3\n\n'
            b'P:renamed-tools\nV:1-r0\no:other\np:cmd:sqlite3=1\n\n')
        result = self.inspect([archive([('lib/apk/db/installed', metadata)]),
                               archive([('lib/apk/db/installed', b'P:sqlite-libs\nV:3.54.1-r0\no:sqlite\n\n')])])
        self.assertFalse(result['success'])
        self.assertEqual({row['rule'] for row in result['sqlite_cli']['findings']},
                         {'sqlite-cli-package', 'sqlite-cli-package-payload'})
        self.assertTrue(all(row['layer'] == 0 for row in result['sqlite_cli']['findings']))
        self.assertEqual(len(result['sqlite_cli']['apk_metadata']), 2)
        result = self.inspect([archive([('.PKGINFO', b'pkgname = sqlite\npkgver = 3.54.1-r0\norigin = sqlite\n')])])
        self.assertFalse(result['success'])

    def test_sqlite_metadata_is_bounded_and_unsafe_payloads_are_rejected(self):
        with patch.object(review, 'SQLITE_METADATA_LIMIT', 32):
            with self.assertRaisesRegex(ValueError, 'bounded'):
                self.inspect([archive([('lib/apk/db/installed', b'x' * 33)])])
        for body in (b'P:sqlite-libs\nF:usr\nR:../../bin/sqlite3\n', b'P:sqlite\x00\n', b'\xff'):
            with self.subTest(body=repr(body)), self.assertRaises(ValueError):
                self.inspect([archive([('lib/apk/db/installed', body)])])
        with self.assertRaisesRegex(ValueError, 'Ambiguous'):
            self.inspect([archive([('lib/apk/db/installed', b'P:sqlite\nP:sqlite-libs\nV:3.54.1-r0\n')])])
        with self.assertRaisesRegex(ValueError, 'Ambiguous'):
            self.inspect([archive([('.PKGINFO', b'pkgname = sqlite\npkgname = sqlite-libs\n')])])

    def test_sqlite_findings_preserve_privacy_redaction(self):
        marker = 'private.example[dev]?'
        symlink = tarfile.TarInfo('usr/bin/' + marker)
        symlink.type, symlink.linkname = tarfile.SYMTYPE, '/private/' + marker + '/sqlite3'
        result = self.inspect([archive([(symlink, b'')])])
        self.assertFalse(result['success'])
        self.assertNotIn(marker, json.dumps(result))


class ExpatReplacementInventoryTests(unittest.TestCase):
    def test_base_has_no_replacement_and_candidate_binds_actual_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            library = root / 'libexpat.so.1.13.1'
            self.assertIsNone(review.expat_replacement_inventory(root, library))
            proofs = ({'lock': True}, {'qualified': True})
            bodies = [(json.dumps(value, indent=2, sort_keys=True) + '\n').encode() for value in proofs]
            for name, body in zip(('EXPAT_BUILD.json', 'EXPAT_PATCHED_SECURITY.json'), bodies):
                (root / name).write_bytes(body)
            library.write_bytes(b'actual replacement')
            actual = review.expat_replacement_inventory(root, library)
            self.assertEqual(actual['build_lock'], proofs[0])
            self.assertEqual(actual['manifest_sha256'], review.digest(bodies[1]))
            self.assertEqual(actual['library'], {'path': str(library), 'sha256': review.digest(library.read_bytes())})

    def test_partial_noncanonical_symlink_and_missing_library_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first, second = root / 'EXPAT_BUILD.json', root / 'EXPAT_PATCHED_SECURITY.json'
            library = root / 'libexpat.so.1.13.1'
            first.write_text('{}\n')
            with self.assertRaises(ValueError):
                review.expat_replacement_inventory(root, library)
            second.write_text('{}\n')
            with self.assertRaises(ValueError):
                review.expat_replacement_inventory(root, library)
            library.write_bytes(b'library')
            second.write_text('{ "qualified": true }')
            with self.assertRaisesRegex(ValueError, 'canonical'):
                review.expat_replacement_inventory(root, library)
            second.unlink()
            second.symlink_to(first)
            with self.assertRaisesRegex(ValueError, 'regular'):
                review.expat_replacement_inventory(root, library)


class SQLiteReplacementInventoryTests(unittest.TestCase):
    def test_untouched_base_returns_none_and_overlay_binds_actual_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            library = root / 'libsqlite3.so.3.54.1'
            self.assertIsNone(review.sqlite_replacement_inventory(root, library))
            values = ({'source': 'reviewed upstream'}, {'library': {'path': '/usr/lib/' + library.name}})
            bodies = [(json.dumps(value, sort_keys=True, indent=2) + '\n').encode() for value in values]
            for name, body in zip(('SQLITE_BUILD.json', 'SQLITE_PATCHED_SECURITY.json'), bodies):
                (root / name).write_bytes(body)
            library.write_bytes(b'actual native SQLite overlay')
            result = review.sqlite_replacement_inventory(root, library)
            self.assertEqual(result, {'build_lock': values[0], 'build_lock_sha256': review.digest(bodies[0]),
                'manifest': values[1], 'manifest_sha256': review.digest(bodies[1]),
                'library': {'path': str(library), 'sha256': review.digest(library.read_bytes())}})
            library.write_bytes(b'changed actual bytes')
            self.assertEqual(review.sqlite_replacement_inventory(root, library)['library']['sha256'],
                             review.digest(library.read_bytes()))

    def test_partial_noncanonical_symlink_and_oversized_inputs_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            library = root / 'libsqlite3.so.3.54.1'
            first, second = root / 'SQLITE_BUILD.json', root / 'SQLITE_PATCHED_SECURITY.json'
            first.write_bytes(b'{}\n')
            with self.assertRaisesRegex(ValueError, 'regular'):
                review.sqlite_replacement_inventory(root, library)
            second.write_bytes(b'{}\n')
            with self.assertRaisesRegex(ValueError, 'library'):
                review.sqlite_replacement_inventory(root, library)
            library.write_bytes(b'library')
            second.write_bytes(b'{ "noncanonical": true }')
            with self.assertRaisesRegex(ValueError, 'canonical'):
                review.sqlite_replacement_inventory(root, library)
            second.unlink()
            second.symlink_to(first)
            with self.assertRaisesRegex(ValueError, 'regular'):
                review.sqlite_replacement_inventory(root, library)
            second.unlink()
            second.write_bytes(b'{}\n')
            actual = root / 'actual.so'
            library.rename(actual)
            library.symlink_to(actual)
            with self.assertRaisesRegex(ValueError, 'canonical'):
                review.sqlite_replacement_inventory(root, library)
            library.unlink()
            library.write_bytes(b'library')
            first.write_bytes(b' ' * (128 * 1024 + 1))
            with self.assertRaisesRegex(ValueError, 'bounded'):
                review.sqlite_replacement_inventory(root, library)


class SQLiteRuntimeComponentTests(unittest.TestCase):
    def test_library_component_and_python_package_directory_are_allowed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'usr/bin').mkdir(parents=True)
            (root / 'usr/bin/sqlite3').mkdir()  # A directory is not the C CLI.
            body = b'P:sqlite-libs\nV:3.53.4-r0\no:sqlite\nF:usr/lib\nR:libsqlite3.so.0.8.6\n\n'
            result = review.sqlite_cli_runtime_inventory(root, body)
            self.assertTrue(result['success'])
            self.assertEqual(result['apk_metadata']['sha256'], review.digest(body))
            self.assertEqual(result['apk_metadata']['packages'][0]['name'], 'sqlite-libs')
            self.assertEqual(result['checked_bin_directories'], ['/usr/bin'])

    def test_cli_package_named_files_and_dangling_aliases_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'usr/bin').mkdir(parents=True)
            (root / 'usr/bin/sqlite3').write_bytes(b'CLI')
            (root / 'usr/bin/renamed').symlink_to('/missing/sqlite3')
            result = review.sqlite_cli_runtime_inventory(root, b'P:sqlite\nV:3.54.1-r0\no:sqlite\n\n')
            self.assertFalse(result['success'])
            self.assertEqual({row['rule'] for row in result['findings']},
                             {'sqlite-cli-package', 'sqlite-cli-name', 'sqlite-cli-alias'})

    def test_runtime_requires_bounded_regular_installed_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(ValueError, 'metadata'):
                review.sqlite_cli_runtime_inventory(root)
            installed = root / 'lib/apk/db/installed'
            installed.parent.mkdir(parents=True)
            target = root / 'packages'
            target.write_bytes(b'P:sqlite-libs\nV:3.53.4-r0\no:sqlite\n\n')
            installed.symlink_to(target)
            with self.assertRaisesRegex(ValueError, 'metadata'):
                review.sqlite_cli_runtime_inventory(root)
