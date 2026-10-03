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
            info = tarfile.TarInfo(name)
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
