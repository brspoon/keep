"""Exact source identity, content integrity and safe notice retention checks."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
import zipfile


spec = importlib.util.spec_from_file_location('python_distribution_sources',
    Path(__file__).resolve().parents[1] / 'scripts/python_distribution_sources.py')
sources = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sources)


def tar(entries):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w:gz') as archive:
        for name, body in entries:
            info = tarfile.TarInfo(name)
            info.size = len(body)
            archive.addfile(info, io.BytesIO(body))
    return buffer.getvalue()


def package(name='sample', version='1.2', entries=()):
    root = f'{name}-{version}'
    return tar([(f'{root}/PKG-INFO', f'Name: {name}\nVersion: {version}\n'.encode()),
                (f'{root}/LICENSE', b'Full public license text'), *entries])


class PythonDistributionSourceTests(unittest.TestCase):
    def collect(self, body=None, modify=None, requirement='Sample==1.2\n'):
        body = package() if body is None else body
        metadata_url = 'https://pypi.org/pypi/sample/1.2/json'
        archive_url = 'https://files.pythonhosted.org/packages/sample-1.2.tar.gz'
        data = {'info': {'name': 'Sample', 'version': '1.2'}, 'urls': [
            {'packagetype': 'sdist', 'filename': 'sample-1.2.tar.gz',
             'url': archive_url, 'digests': {'sha256': hashlib.sha256(body).hexdigest()}}]}
        if modify:
            modify(data)
        seen = []

        def fetch(url):
            seen.append(url)
            return json.dumps(data).encode() if url == metadata_url else body

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            requirements = root / 'requirements.txt'
            requirements.write_text(requirement)
            output = root / 'bundle'
            manifest = sources.collect_sources(requirements, output, fetch)
            contents = {str(path.relative_to(output)): path.read_bytes()
                        for path in output.rglob('*') if path.is_file()}
            return manifest, contents, seen

    def test_exact_sdist_and_nested_native_notice_are_retained(self):
        body = package(entries=[('sample-1.2/extras/native/LICENSE', b'Full native attribution')])
        manifest, files, requests = self.collect(body)
        row = manifest['packages'][0]
        self.assertEqual(row['name'], 'sample')
        self.assertEqual(files[row['archive']], body)
        self.assertEqual(len(row['notices']), 2)
        self.assertEqual(files[row['notices'][1]['path']], b'Full native attribution')
        self.assertEqual(len(requests), 2)
        self.assertIn(row['release_metadata'], files)
        self.assertFalse(any(name.endswith('/PKG-INFO') for name in files))

    def test_checksum_mismatch_rejects_download(self):
        with self.assertRaisesRegex(ValueError, 'checksum mismatch'):
            self.collect(modify=lambda data: data['urls'][0]['digests'].update(sha256='0' * 64))

    def test_archive_identity_must_match_pin_even_when_pypi_hash_matches(self):
        for body in (package(version='1.3'), package(name='other')):
            with self.subTest(body_sha=hashlib.sha256(body).hexdigest()):
                with self.assertRaisesRegex(ValueError, 'archive identity'):
                    self.collect(body)

    def test_metadata_identity_must_match_pin(self):
        with self.assertRaisesRegex(ValueError, 'release identity'):
            self.collect(modify=lambda data: data['info'].update(version='1.3'))

    def test_missing_or_ambiguous_sdist_never_falls_back_to_wheel(self):
        for rows in ([], [{'packagetype': 'bdist_wheel'}],
                     [{'packagetype': 'sdist'}, {'packagetype': 'sdist'}]):
            with self.subTest(rows=rows):
                with self.assertRaisesRegex(ValueError, 'exactly one source'):
                    self.collect(modify=lambda data: data.update(urls=rows))

    def test_unpinned_and_duplicate_requirements_are_rejected(self):
        for line in ('Sample>=1.2', 'Sample==1.2; python_version>="3.0"',
                     'Sample[extra]==1.2', 'Sample==1.2\nsample==1.2', ''):
            with self.subTest(requirement=line):
                with self.assertRaises(ValueError):
                    self.collect(requirement=line)

    def test_malicious_member_paths_are_rejected_without_extraction(self):
        for path in ('../LICENSE', '/LICENSE', 'sample-1.2/../../LICENSE',
                     'sample-1.2\\LICENSE', 'C:/LICENSE'):
            with self.subTest(path=path):
                with self.assertRaisesRegex(ValueError, 'Unsafe source archive path'):
                    self.collect(package(entries=[(path, b'unsafe')]))

    def test_source_url_cannot_contain_credentials_or_change_host(self):
        for url in ('http://files.pythonhosted.org/sample.tar.gz',
                    'https://user:secret@files.pythonhosted.org/sample.tar.gz',
                    'https://private.example/sample.tar.gz'):
            with self.subTest(url=url):
                with self.assertRaisesRegex(ValueError, 'download URL'):
                    self.collect(modify=lambda data: data['urls'][0].update(url=url))

    def test_archive_requires_notice_and_single_pkg_info(self):
        bodies = [tar([('sample-1.2/PKG-INFO', b'Name: sample\nVersion: 1.2\n')]),
                  tar([('sample-1.2/LICENSE', b'notice')]),
                  package(entries=[('other-1.2/PKG-INFO', b'Name: sample\nVersion: 1.2\n')])]
        for body in bodies:
            with self.subTest(body_sha=hashlib.sha256(body).hexdigest()):
                with self.assertRaises(ValueError):
                    self.collect(body)

    def test_tar_links_and_duplicate_regular_paths_are_rejected(self):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode='w:gz') as archive:
            info = tarfile.TarInfo('sample-1.2/LICENSE')
            info.type = tarfile.SYMTYPE
            info.linkname = '../../LICENSE'
            archive.addfile(info)
        with self.assertRaisesRegex(ValueError, 'links are unsupported'):
            self.collect(buffer.getvalue())
        with self.assertRaisesRegex(ValueError, 'Duplicate source archive path'):
            self.collect(package(entries=[('sample-1.2/LICENSE', b'other')]))

    def test_zip_sdist_uses_same_identity_and_safe_notice_checks(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w') as archive:
            archive.writestr('sample-1.2/PKG-INFO', 'Name: sample\nVersion: 1.2\n')
            archive.writestr('sample-1.2/LICENSE.txt', 'Full zip attribution')
        notices = sources.inspect_source(buffer.getvalue(), 'sample-1.2.zip', 'sample', '1.2')
        self.assertEqual(notices, {'sample-1.2/LICENSE.txt': b'Full zip attribution'})

    def test_declared_unpacked_size_limits_reject_archive(self):
        from unittest.mock import patch
        with patch.object(sources, 'MAX_UNPACKED', 5):
            with self.assertRaisesRegex(ValueError, 'inspection limits'):
                self.collect()


if __name__ == '__main__':
    unittest.main()
