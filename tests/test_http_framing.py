import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
import sys
from unittest.mock import patch

from scripts.patch_python_runtime import apply_hunks, apply_patches
from scripts.http_framing_checks import check_framing


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))


class HttpFramingTests(unittest.TestCase):
    def test_overlapping_corrections_repeat_only_with_exact_final_source(self):
        entries = [{'path': 'module.py', 'commit': 'one',
                    'hunks': [{'before': 'value = 1\n', 'after': 'value = 2\n'}]},
                   {'path': 'module.py', 'source_kind': 'keep-local',
                    'source_id': 'local-correction', 'commit': None,
                    'hunks': [{'before': 'value = 2\n', 'after': 'value = 3\n'}]}]
        final = {'module.py': hashlib.sha256(b'value = 3\n').hexdigest()}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'module.py'
            path.write_text('value = 1\n')
            apply_patches(directory, entries, final_hashes=final)
            self.assertEqual(path.read_text(), 'value = 3\n')
            records = apply_patches(directory, entries, final_hashes=final)
            self.assertTrue(all(row['before_sha256'] == row['after_sha256'] == final['module.py']
                                for row in records))
            path.write_text('value = 4\n')
            with self.assertRaises(RuntimeError):
                apply_patches(directory, entries, final_hashes=final)

    def setUp(self):
        # Contributor tests also run outside the image with original PyPI
        # modules. Test an isolated exact replay without modifying that host.
        import urllib3.response
        source = Path(urllib3.response.__file__).read_text()
        entries = json.loads((ROOT / 'scripts/urllib3_security_patches.json').read_text())
        lock = json.loads((ROOT / 'scripts/http_framing_sources.json').read_text())
        if hashlib.sha256(source.encode()).hexdigest() != lock['urllib3.response']['after_sha256']:
            for entry in entries:
                source = apply_hunks(source, entry)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        path = Path(temporary.name) / 'response.py'
        path.write_text(source)
        spec = importlib.util.spec_from_file_location('urllib3.response', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module_patch = patch.dict(sys.modules, {'urllib3.response': module})
        attribute_patch = patch.object(urllib3, 'response', module)
        module_patch.start()
        self.addCleanup(module_patch.stop)
        attribute_patch.start()
        self.addCleanup(attribute_patch.stop)

    def test_distribution_replay_matches_the_loaded_urllib3_module(self):
        import urllib3.response
        from scripts.build_distribution_bundle import retain_http_framing_sources
        source = Path(urllib3.response.__file__).read_text()
        patches = json.loads((ROOT / 'scripts/urllib3_security_patches.json').read_text())
        for entry in reversed(patches):
            for hunk in reversed(entry['hunks']):
                self.assertEqual(source.count(hunk['after']), 1)
                source = source.replace(hunk['after'], hunk['before'], 1)
        lock = json.loads((ROOT / 'scripts/http_framing_sources.json').read_text())
        inventory = {'http_framing': {name: {'sha256': row['after_sha256']}
                                    for name, row in lock.items()}}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / 'python/urllib3-2.8.0/urllib3-2.8.0.tar.gz'
            archive.parent.mkdir(parents=True)
            with tarfile.open(archive, 'w:gz') as package:
                body = source.encode()
                member = tarfile.TarInfo('urllib3-2.8.0/src/urllib3/response.py')
                member.size = len(body)
                package.addfile(member, io.BytesIO(body))
            self.assertEqual(retain_http_framing_sources(root, inventory, ROOT),
                             inventory['http_framing'])
            self.assertEqual((root / 'python/urllib3-2.8.0/patched/urllib3/response.py').read_bytes(),
                             Path(urllib3.response.__file__).read_bytes())

    def test_upstream_contexts_preserve_separate_commit_provenance(self):
        patches = json.loads((ROOT / 'scripts/python_security_patches.json').read_text())
        http = [p for p in patches if p['path'] == 'http/client.py']
        self.assertEqual([p['commit'] for p in http if p.get('source_kind', 'upstream') == 'upstream'], [
            '2eb2af805c156ca52b316bb4ced5e0ab3971d0ae',
            '9f52b443c002cccfb54bda0706a9276b6b4a109d'])
        self.assertEqual(http[-1]['source_id'], 'keep-http-framing-bounds-v1')
        self.assertIsNone(http[-1]['commit'])
        self.assertEqual(json.loads((ROOT / 'scripts/urllib3_security_patches.json').read_text())[0]['commit'],
                         '5feb993421a48a508bc70c78e745337cc6415265')

    def test_full_stdlib_module_replay_and_response_controls(self):
        # The host interpreter is test infrastructure. Replay only the reviewed
        # framing hunks into its source; native gates use the actual final image.
        import http.client
        source = Path(http.client.__file__).read_text()
        patches = json.loads((ROOT / 'scripts/python_security_patches.json').read_text())
        lock = json.loads((ROOT / 'scripts/http_framing_sources.json').read_text())
        if hashlib.sha256(source.encode()).hexdigest() != lock['http.client']['after_sha256']:
            for entry in patches:
                if entry['path'] == 'http/client.py':
                    source = apply_hunks(source, entry)
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'client.py'
            target.write_text(source)
            spec = importlib.util.spec_from_file_location('reviewed_http_client', target)
            client = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(client)
            check_framing(self, client)

    def test_altered_source_and_missing_runtime_binding_block_distribution(self):
        from scripts.build_distribution_bundle import retain_http_framing_sources
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, 'loaded HTTP parser'):
                retain_http_framing_sources(Path(directory), {}, ROOT)
            lock = json.loads((ROOT / 'scripts/http_framing_sources.json').read_text())
            inventory = {'http_framing': {name: {'sha256': row['after_sha256']}
                                        for name, row in lock.items()}}
            archive = Path(directory) / 'python/urllib3-2.8.0/urllib3-2.8.0.tar.gz'
            archive.parent.mkdir(parents=True)
            with tarfile.open(archive, 'w:gz') as package:
                body = b'unreviewed source'
                member = tarfile.TarInfo('urllib3-2.8.0/src/urllib3/response.py')
                member.size = len(body)
                package.addfile(member, io.BytesIO(body))
            with self.assertRaisesRegex(ValueError, 'patch input'):
                retain_http_framing_sources(Path(directory), inventory, ROOT)


if __name__ == '__main__':
    unittest.main()
