import copy
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from scripts import build_patched_openssl as build


class OpenSSLBackportTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        (self.root / 'docs').mkdir()
        self.spec = build.facts()
        native = {'compiler_sha256': 'a' * 64,
                  'vendor_files': {name: build.digest(('vendor:' + name).encode()) for name in build.FILES},
                  'files': {name: build.digest(('patched:' + name).encode()) for name in build.FILES},
                  'abi': {name: {'exports_sha256': 'b' * 64, 'export_count': 10,
                                  'version_definitions_sha256': 'c' * 64}
                          for name in ('libcrypto.so.3', 'libssl.so.3')}}
        self.spec['native'] = {arch: copy.deepcopy(native) for arch in ('amd64', 'arm64')}
        self.write_lock()

    def write_lock(self):
        (self.root / 'docs/openssl-build.json').write_bytes(build.json_bytes(self.spec))

    def test_both_architectures_and_complete_pins_are_required(self):
        build.reviewed_spec(self.root)
        self.spec['native']['arm64']['files'][build.FILES[0]] = None
        self.write_lock()
        with self.assertRaisesRegex(ValueError, 'pins'):
            build.reviewed_spec(self.root)
        build.reviewed_spec(self.root, preparation=True)

    def test_changed_source_or_build_configuration_is_rejected(self):
        for field in ('source_sha256', 'patch_sha256', 'build_script_sha256', 'perl_lock_sha256'):
            with self.subTest(field=field):
                original = self.spec[field]
                self.spec[field] = '0' * 64
                self.write_lock()
                with self.assertRaisesRegex(ValueError, 'facts differ'):
                    build.reviewed_spec(self.root)
                self.spec[field] = original

    def test_preparation_and_wrong_native_receipts_cannot_install(self):
        manifest = build.expected_manifest('amd64', self.root)
        for field, value in (('qualified', False), ('architecture', 'arm64'), ('upstream_tests', False)):
            changed = {**manifest, field: value}
            with self.subTest(field=field), self.assertRaises(ValueError):
                build.verify_manifest(changed, 'amd64', self.root)

    def install_fixture(self):
        runtime, output = self.root / 'runtime', self.root / 'output'
        output.mkdir()
        for name in build.FILES:
            for directory, prefix in ((runtime, 'vendor:'), (output, 'patched:')):
                path = directory / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes((prefix + name).encode())
        config = runtime / 'etc/ssl/openssl.cnf'
        config.parent.mkdir(parents=True)
        config.write_bytes(b'preserved configuration\n')
        manifest = build.expected_manifest('amd64', self.root)
        (output / 'OPENSSL_SECURITY.json').write_bytes(build.json_bytes(manifest))
        return runtime, output, config

    def test_exact_payload_install_preserves_configuration(self):
        runtime, output, config = self.install_fixture()
        build.install(output, 'amd64', runtime_root=runtime, root=self.root)
        self.assertEqual(config.read_bytes(), b'preserved configuration\n')
        for name in build.FILES:
            self.assertEqual((runtime / name).read_bytes(), ('patched:' + name).encode())
            self.assertEqual((runtime / name).stat().st_mode & 0o777, 0o755)

    def test_every_preimage_is_checked_before_replacement(self):
        runtime, output, _ = self.install_fixture()
        (runtime / build.FILES[-1]).write_bytes(b'unreviewed')
        with self.assertRaises(ValueError):
            build.install(output, 'amd64', runtime_root=runtime, root=self.root)
        self.assertEqual((runtime / build.FILES[0]).read_bytes(), ('vendor:' + build.FILES[0]).encode())

    def test_payload_links_are_rejected_before_any_replacement(self):
        runtime, output, config = self.install_fixture()
        path = runtime / build.FILES[-1]
        path.unlink(); path.symlink_to(config)
        with self.assertRaises(ValueError):
            build.install(output, 'amd64', runtime_root=runtime, root=self.root)
        self.assertEqual(config.read_bytes(), b'preserved configuration\n')
        self.assertEqual((runtime / build.FILES[0]).read_bytes(), ('vendor:' + build.FILES[0]).encode())

    def test_archive_paths_and_links_are_rejected(self):
        for name, kind in (('../outside', tarfile.REGTYPE),
                           ('openssl-3.5.9/link', tarfile.SYMTYPE)):
            body = io.BytesIO()
            with tarfile.open(fileobj=body, mode='w:gz') as archive:
                member = tarfile.TarInfo(name)
                member.type = kind
                member.linkname = '../outside' if kind == tarfile.SYMTYPE else ''
                archive.addfile(member)
            with patch.object(build, 'SOURCE_SHA256', build.digest(body.getvalue())):
                with self.assertRaises(ValueError):
                    build.extract_source(body.getvalue(), self.root / ('archive-' + str(kind)))
        self.assertFalse((self.root / 'outside').exists())


if __name__ == '__main__':
    unittest.main()
