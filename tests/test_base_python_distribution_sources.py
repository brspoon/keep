"""Match immutable-layer ensurepip code and launchers to complete sources."""
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
import zipfile


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
spec = importlib.util.spec_from_file_location('base_python_distribution_sources',
    Path(__file__).resolve().parents[1] / 'scripts/base_python_distribution_sources.py')
sources = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sources)


def digest(body):
    return hashlib.sha256(body).hexdigest()


def tar(entries):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w') as archive:
        for name, body in entries:
            member = tarfile.TarInfo(name)
            member.size = len(body)
            archive.addfile(member, io.BytesIO(body))
    return gzip.compress(buffer.getvalue(), mtime=0)


def wheel(name, version, entries):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as archive:
        archive.writestr(f'{name}-{version}.dist-info/METADATA',
                         f'Name: {name}\nVersion: {version}\n')
        archive.writestr(f'{name}-{version}.dist-info/licenses/LICENSE',
                         b'Complete fixture license and attribution.')
        for path, body in entries:
            archive.writestr(path, body)
    return buffer.getvalue()


def fixture(module=b'print("pip source")\n', launcher=b'MZexactlauncher',
            source_module=None, source_launcher=None, omit_build=False):
    """Use concatenated APK members, exact wheel pins and independent sdists."""
    version = '1.2'
    native = 'pip/_vendor/distlib/t64.exe'
    build_file = 'PC/launcher.c'
    wheel_bodies = {
        'pip': wheel('pip', version, [('pip/main.py', module),
            ('pip/_vendor/vendor.txt', b'distlib==0.4.2\n'), (native, launcher)]),
        'wheel': wheel('wheel', version, [('wheel/main.py', b'print("wheel source")\n')]),
    }
    source_bodies = {}
    for name in ('pip', 'wheel', 'distlib'):
        package_version = '0.4.2' if name == 'distlib' else version
        root = f'{name}-{package_version}'
        entries = [(root + '/PKG-INFO', f'Name: {name}\nVersion: {package_version}\n'.encode()),
                   (root + ('/LICENSE.txt' if name == 'distlib' else '/LICENSE'),
                    b'Complete fixture license and attribution.')]
        if name == 'pip':
            entries.append((root + '/src/pip/main.py', module if source_module is None else source_module))
        elif name == 'wheel':
            entries.append((root + '/src/wheel/main.py', b'print("wheel source")\n'))
        else:
            entries.append((root + '/distlib/t64.exe', launcher if source_launcher is None else source_launcher))
            if not omit_build:
                entries.append((root + '/' + build_file, b'int main(void) { return 0; }\n'))
        source_bodies[name] = tar(entries)
    lock = {'format': 'keep-original-base-python-source-lock-v1',
        'package': {'name': 'python-3.14', 'version': '3.14.7-r1',
                    'origin': 'python-3.14', 'build_commit': 'a' * 40, 'apk_sha256': {}},
        'wheels': [], 'sources': [], 'distlib_vendor_version': '0.4.2',
        'native_resources': [{'wheel': 'pip', 'path': native, 'bytes': len(launcher),
                              'sha256': digest(launcher), 'matching_distlib_member':
                              'distlib-0.4.2/distlib/t64.exe'}],
        'required_distlib_build_sources': [build_file]}
    for name, body in wheel_bodies.items():
        filename = f'{name}-{version}-py3-none-any.whl'
        lock['wheels'].append({'name': name, 'version': version, 'filename': filename,
            'apk_path': 'usr/lib/python3.14/ensurepip/_bundled/' + filename,
            'sha256': digest(body), 'bytes': len(body)})
    urls = {}
    for name, body in source_bodies.items():
        package_version = '0.4.2' if name == 'distlib' else version
        filename = f'{name}-{package_version}.tar.gz'
        url = 'https://files.pythonhosted.org/packages/' + filename
        lock['sources'].append({'name': name, 'version': package_version,
            'filename': filename, 'url': url, 'sha256': digest(body), 'bytes': len(body)})
        urls[url] = body
        urls[f'https://pypi.org/pypi/{name}/{package_version}/json'] = json.dumps({
            'info': {'name': name, 'version': package_version}, 'urls': [{
                'filename': filename, 'url': url, 'packagetype': 'sdist',
                'digests': {'sha256': digest(body)}}]}).encode()
    metadata = b'pkgname = python-3.14\npkgver = 3.14.7-r1\norigin = python-3.14\ncommit = ' + b'a' * 40 + b'\narch = x86_64\n'
    apk = tar([('.SIGN.fixture', b'signature')]) + tar([('.PKGINFO', metadata)]) + tar([
        (row['apk_path'], wheel_bodies[row['name']]) for row in lock['wheels']])
    lock['package']['apk_sha256'] = {'amd64': digest(apk), 'arm64': 'f' * 64}
    return apk, lock, urls


class OriginalBasePythonSourceTests(unittest.TestCase):
    def collect(self, data=None, mutate=None):
        apk, lock, urls = fixture() if data is None else data
        if mutate:
            mutate(lock, urls)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = root / 'python.apk'
            package.write_bytes(apk)
            report = sources.collect_sources(package, 'amd64', root / 'output',
                                             lock=lock, fetch=lambda url: urls[url])
            files = {path.relative_to(root / 'output').as_posix(): path.read_bytes()
                     for path in (root / 'output').rglob('*') if path.is_file()}
            return report, files

    def test_exact_concatenated_apk_wheels_sources_and_launcher_build_are_retained(self):
        report, files = self.collect()
        self.assertEqual([len(row['matched_python_modules']) for row in report['wheels']], [1, 1])
        self.assertEqual(len(report['source_packages']), 3)
        self.assertEqual(len(report['native_resources']), 1)
        self.assertEqual(len(report['native_build_sources']), 1)
        self.assertEqual(report['package_identity']['arch'], 'x86_64')
        self.assertIn('base-python-sources.json', files)
        self.assertTrue(all(row['archive'] in files for row in report['source_packages']))
        self.assertTrue(all(row['notices'] for row in report['source_packages']))
        self.assertEqual(len(report['runtime_notice_inventories']), 3)

    def test_original_apk_bytes_and_architecture_must_match_reviewed_pin(self):
        with self.assertRaisesRegex(ValueError, 'architecture-specific bytes'):
            self.collect(mutate=lambda lock, urls: lock['package']['apk_sha256'].update(amd64='0' * 64))

    def test_build_commit_must_match_even_after_apk_digest_is_checked(self):
        with self.assertRaisesRegex(ValueError, 'build metadata'):
            self.collect(mutate=lambda lock, urls: lock['package'].update(build_commit='b' * 40))

    def test_source_archive_python_code_must_match_actual_wheel(self):
        with self.assertRaisesRegex(ValueError, 'Python module differs'):
            self.collect(fixture(source_module=b'changed preferred source\n'))

    def test_prebuilt_launcher_match_does_not_replace_its_native_build_sources(self):
        with self.assertRaisesRegex(ValueError, 'native launcher build source is missing'):
            self.collect(fixture(omit_build=True))

    def test_native_resource_bytes_must_match_independent_distlib_archive(self):
        with self.assertRaisesRegex(ValueError, 'native launcher differs'):
            self.collect(fixture(source_launcher=b'MZotherresource'))

    def test_upstream_release_may_not_silently_replace_reviewed_source_archive(self):
        def mutate(lock, urls):
            metadata_url = 'https://pypi.org/pypi/pip/1.2/json'
            metadata = json.loads(urls[metadata_url])
            metadata['urls'][0]['digests']['sha256'] = 'c' * 64
            urls[metadata_url] = json.dumps(metadata).encode()
        with self.assertRaisesRegex(ValueError, 'source identity differs'):
            self.collect(mutate=mutate)

    def test_wheel_hash_is_independently_checked_inside_matching_apk(self):
        with self.assertRaisesRegex(ValueError, 'wheel differs'):
            self.collect(mutate=lambda lock, urls: lock['wheels'][0].update(sha256='0' * 64))

    def test_wheel_metadata_cannot_claim_another_release(self):
        body = wheel('pip', '1.3', [('pip/main.py', b'code')])
        with self.assertRaisesRegex(ValueError, 'name/version differs'):
            sources.wheel_identity(body, {'name': 'pip', 'version': '1.2'})


if __name__ == '__main__':
    unittest.main()
