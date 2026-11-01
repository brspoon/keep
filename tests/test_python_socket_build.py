"""Fail-closed source and retained evidence checks; native behavior runs in CI."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
import sys
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from scripts import build_patched_socket as build
from scripts.collect_package_sources import verify_socket_replacement
from tests.native_dependency_fixture import dependency_report
from scripts import runtime_dependency_checks as checks
import build_distribution_bundle as distribution

ROOT = Path(__file__).resolve().parents[1]


class SocketBuildTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / 'docs').mkdir()
        self.spec = copy.deepcopy(build.reviewed_spec(ROOT))
        # Synthetic generated header, explicitly pinned only in the temporary lock.
        self.header = '#define PY_SOCKET_FIXTURE 1\n'
        for row in self.spec['native'].values():
            row['pyconfig_sha256'] = build.digest(self.header.encode())
        self.lock = self.root / 'docs/python-socket-build.json'
        self.lock.write_bytes(build.json_bytes(self.spec))

    def inventory(self, arch='amd64'):
        manifest = build.expected_manifest(arch, self.root)
        return {'socket_replacement': {'build_lock': self.spec,
            'build_lock_sha256': build.digest(build.json_bytes(self.spec)),
            'manifest': manifest, 'manifest_sha256': build.digest(build.json_bytes(manifest)),
            'pyconfig': self.header, 'pyconfig_sha256': build.digest(self.header.encode()),
            'library': dict(manifest['library'])}}

    def test_preparation_and_partial_native_pins_never_qualify(self):
        for change in ('missing_arch', 'missing_hash'):
            spec = copy.deepcopy(self.spec)
            if change == 'missing_arch':
                del spec['native']['arm64']
            else:
                spec['native']['arm64']['extension_sha256'] = None
            self.lock.write_bytes(build.json_bytes(spec))
            with self.subTest(change=change), self.assertRaises(ValueError):
                build.expected_manifest('amd64', self.root)
        self.lock.write_bytes(build.json_bytes(self.spec))
        manifest = build.expected_manifest('amd64', self.root)
        manifest['qualified'] = False
        with self.assertRaises(ValueError):
            build.verify_manifest(manifest, 'amd64', self.root)

    def test_source_binding_rejects_missing_mixed_or_tampered_inputs(self):
        verify_socket_replacement(self.inventory(), 'amd64', root=self.root)
        for key in ('build_lock_sha256', 'manifest_sha256', 'pyconfig_sha256', 'pyconfig', 'library'):
            inventory = self.inventory()
            row = inventory['socket_replacement']
            row[key] = {'path': '/tmp/unreviewed.so', 'sha256': '0' * 64} if key == 'library' else 'wrong'
            with self.subTest(key=key), self.assertRaises(ValueError):
                verify_socket_replacement(inventory, 'amd64', root=self.root)
        with self.assertRaises(ValueError):
            verify_socket_replacement(self.inventory('arm64'), 'amd64', root=self.root)
        with self.assertRaises(ValueError):
            verify_socket_replacement({}, 'amd64', root=self.root)

    def test_retained_native_report_requires_new_socket_obligations(self):
        report = dependency_report('amd64')
        checks.validate_report(report, 'amd64', ROOT)
        for key in ('socket_manifest', 'socket_manifest_sha256', 'socket_probes'):
            changed = copy.deepcopy(report)
            changed[key] = None
            with self.subTest(key=key), self.assertRaises(ValueError):
                checks.validate_report(changed, 'amd64', ROOT)
        changed = copy.deepcopy(report)
        changed['loaded_libraries']['python_socket']['sha256'] = '0' * 64
        with self.assertRaises(ValueError):
            checks.validate_report(changed, 'amd64', ROOT)

    def test_source_download_allows_only_the_exact_python_archive_and_host(self):
        class Response:
            def __init__(self, url):
                self.url = url
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
            def geturl(self):
                return self.url
            def read(self, size):
                return b'fixture archive; caller must verify locked hash'
        with patch.object(distribution.urllib.request, 'urlopen',
                          return_value=Response(build.SOURCE_URL)) as fetch:
            self.assertTrue(distribution.fetch_source(build.SOURCE_URL))
            fetch.assert_called_once()
        for url in ('https://www.python.org/ftp/python/other.tar.xz',
                    'http://www.python.org/ftp/python/3.14.8/Python-3.14.8.tar.xz'):
            with self.subTest(url=url), patch.object(distribution.urllib.request, 'urlopen') as fetch:
                with self.assertRaises(ValueError):
                    distribution.fetch_source(url)
                fetch.assert_not_called()
        with patch.object(distribution.urllib.request, 'urlopen',
                          return_value=Response('https://example.org/Python.tar.xz')):
            with self.assertRaises(ValueError):
                distribution.fetch_source(build.SOURCE_URL)


if __name__ == '__main__':
    unittest.main()
