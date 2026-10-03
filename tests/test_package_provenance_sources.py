import base64
import copy
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import package_provenance_sources as sources


def archive(files):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w:gz') as bundle:
        for name, value in files.items():
            member = tarfile.TarInfo(name)
            member.size = len(value)
            bundle.addfile(member, io.BytesIO(value))
    return output.getvalue()


class PreferredSourceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / 'docs').mkdir()
        self.commit = 'a' * 40
        self.native = 'b' * 64
        self.source_url = 'https://example.org/example-1.0.tar.gz'
        self.source = archive({'example-1.0/source.c': b'int example;',
                               'example-1.0/COPYING': b'Copyright and permission notice'})
        self.local_patch = b'--- source.c\n+++ source.c\n'
        self.recipe = ('image: dhi/pkg-example\nvars:\n  VERSION: "1.0"\n  REL: "0"\n'
                       '  COMMIT_SHA: ' + self.commit + '\ncontents:\n  files:\n'
                       '    - url: git+https://github.com/alpinelinux/aports.git#' + self.commit + '\n'
                       '      path: ${source.dir}/aports\n'
                       '    - url: ' + self.source_url + '\n'
                       '      path: /var/cache/distfiles/example-1.0.tar.gz\n')
        self.apkbuild = ('pkgname=example\npkgver=1.0\npkgrel=0\nsha512sums="\n'
                         + hashlib.sha512(self.source).hexdigest() + '  example-1.0.tar.gz\n'
                         + hashlib.sha512(self.local_patch).hexdigest() + '  fix.patch\n"\n').encode()
        self.context = archive({'aports-' + self.commit + '/main/example/APKBUILD': self.apkbuild,
                                'aports-' + self.commit + '/main/example/fix.patch': self.local_patch})
        self.aports_url = 'https://github.com/alpinelinux/aports/archive/' + self.commit + '.tar.gz'
        self.public_url = 'https://example.org/provider.yaml'
        self.downloads = {self.source_url: self.source, self.aports_url: self.context,
                          self.public_url: self.recipe.encode()}
        self.spec = {'origin': 'example', 'version': '1.0-r0', 'recipe': {
            'url': self.public_url, 'revision': 'c' * 40, 'upstream_commit': self.commit,
            'sha256': hashlib.sha256(self.recipe.encode()).hexdigest()}}
        (self.root / 'docs/aports-source-lock.json').write_text(json.dumps({'aports': [{
            'origin': 'example', 'commit': self.commit, 'url': self.aports_url,
            'sha256': hashlib.sha256(self.context).hexdigest(),
            'apkbuild_sha256': hashlib.sha256(self.apkbuild).hexdigest()}]}))
        subject = [{'name': 'pkg:docker/dhi/pkg-example', 'digest': {'sha256': self.native}}]
        self.slsa = {'predicateType': 'https://slsa.dev/provenance/v0.2', 'subject': subject,
            'predicate': {'materials': [
                {'uri': self.source_url, 'digest': {'sha256': hashlib.sha256(self.source).hexdigest()}},
                {'uri': 'https://github.com/alpinelinux/aports.git#' + self.commit, 'digest': {'sha256': ''}}]}}
        self.scout = {'predicateType': 'https://scout.docker.com/provenance/v0.1', 'subject': subject,
            'predicate': {'source_map': {'dockerfile': base64.b64encode(self.recipe.encode()).decode()}}}

    def tearDown(self):
        self.temp.cleanup()

    def collect(self, slsa=None, scout=None):
        with patch.object(sources, 'ROOT', self.root):
            return sources.collect_sources(self.spec, 'amd64', slsa or self.slsa,
                scout or self.scout, self.root / 'output', fetch=self.downloads.__getitem__)

    def test_complete_source_archive_and_indirect_patch_retained(self):
        result = self.collect()
        self.assertIsNone(result['source_image_digest'])
        self.assertEqual(result['native_image_digest'], 'sha256:' + self.native)
        self.assertEqual(result['binding_method'], 'signed-build-provenance')
        paths = {row['path'] for row in result['files']}
        self.assertIn('sources/example-1.0.tar.gz', paths)
        self.assertIn('context/aports/main/example/fix.patch', paths)
        self.assertIn('build/provider-signed.yaml', paths)

    def test_upstream_hash_tampering_blocks_collection(self):
        self.downloads[self.source_url] += b'corrupted'
        with self.assertRaisesRegex(ValueError, 'Signed preferred source sha256 mismatch'):
            self.collect()

    def test_missing_signed_material_is_rejected(self):
        self.slsa['predicate']['materials'] = self.slsa['predicate']['materials'][1:]
        with self.assertRaisesRegex(ValueError, 'lacks a signed source digest'):
            self.collect()

    def test_missing_indirect_patch_is_rejected(self):
        self.context = archive({'aports-' + self.commit + '/main/example/APKBUILD': self.apkbuild})
        self.downloads[self.aports_url] = self.context
        lockpath = self.root / 'docs/aports-source-lock.json'
        lock = json.loads(lockpath.read_text())
        lock['aports'][0]['sha256'] = hashlib.sha256(self.context).hexdigest()
        lockpath.write_text(json.dumps(lock))
        with self.assertRaisesRegex(ValueError, 'Alpine source input is missing: fix.patch'):
            self.collect()

    def test_recipe_release_mismatch_is_rejected(self):
        recipe = self.recipe.replace('REL: "0"', 'REL: "1"')
        self.scout['predicate']['source_map']['dockerfile'] = base64.b64encode(recipe.encode()).decode()
        with self.assertRaisesRegex(ValueError, 'recipe version differs'):
            self.collect()

    def test_other_native_subject_is_rejected(self):
        self.scout = copy.deepcopy(self.scout)
        self.scout['subject'][0]['digest']['sha256'] = 'd' * 64
        with self.assertRaisesRegex(ValueError, 'native subjects differ'):
            self.collect()

    def test_unreviewed_source_context_is_rejected(self):
        self.downloads[self.aports_url] += b'corrupted'
        with self.assertRaisesRegex(ValueError, 'Alpine build source archive sha256 mismatch'):
            self.collect()

    def test_source_archive_paths_are_never_extracted(self):
        bad = archive({'../escape': b'bad'})
        with self.assertRaisesRegex(ValueError, 'Unsafe source path'):
            sources.archive_files(bad, 'aports/')
        self.assertFalse((self.root.parent / 'escape').exists())

    def test_slsa_v1_resolved_dependencies_supported(self):
        slsa = copy.deepcopy(self.slsa)
        slsa['predicateType'] = 'https://slsa.dev/provenance/v1'
        slsa['predicate'] = {'buildDefinition': {'resolvedDependencies': slsa['predicate']['materials']}}
        self.assertEqual(self.collect(slsa=slsa)['origin'], 'example')

    def test_reviewed_mirror_retains_signed_uri_and_identical_hash(self):
        mirror_url = 'https://mirror.example.org/example-1.0.tar.gz'
        self.downloads[mirror_url] = self.source
        del self.downloads[self.source_url]
        row = {'origin': 'example', 'version': '1.0-r0', 'url': mirror_url,
               'sha256': hashlib.sha256(self.source).hexdigest()}
        with patch.object(sources, 'SOURCE_MIRRORS', {self.source_url: row}):
            result = self.collect()
        record = next(row for row in result['files'] if row['role'] == 'signed-upstream-source')
        self.assertEqual(record['declared_url'], self.source_url)
        self.assertEqual(record['url'], mirror_url)

    def test_mirror_cannot_change_signed_source_identity(self):
        row = {'origin': 'example', 'version': '2.0-r0',
               'url': 'https://mirror.example.org/source',
               'sha256': hashlib.sha256(self.source).hexdigest()}
        with patch.object(sources, 'SOURCE_MIRRORS', {self.source_url: row}):
            with self.assertRaisesRegex(ValueError, 'mirror differs'):
                self.collect()


if __name__ == '__main__':
    unittest.main()
