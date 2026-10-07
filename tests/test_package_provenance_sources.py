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
from unittest.mock import Mock, patch
import urllib.error

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

    def collect(self, slsa=None, scout=None, fetch=None, output='output'):
        with patch.object(sources, 'ROOT', self.root):
            return sources.collect_sources(self.spec, 'amd64', slsa or self.slsa,
                scout or self.scout, self.root / output, fetch=fetch or self.downloads.__getitem__)

    def python_provider_context(self):
        revision = self.spec['recipe']['revision']
        self.source_url = 'https://example.org/Python-3.14.8.tar.gz'
        self.source = archive({'Python-3.14.8/Lib/example.py': b'print("example")',
                               'Python-3.14.8/LICENSE': b'Complete Python license'})
        self.recipe = ('image: dhi/pkg-python\nvars:\n  VERSION: "3.14.8"\n  REL: "0"\n'
                       'contents:\n  files:\n    - url: ' + self.source_url + '\n'
                       '      path: /var/cache/distfiles/Python-3.14.8.tar.gz\n')
        self.spec = {'origin': 'python-3.14', 'version': '3.14.8-r0', 'recipe': {
            'url': self.public_url, 'revision': revision,
            'sha256': hashlib.sha256(self.recipe.encode()).hexdigest()}}
        prefix = 'catalog-' + revision + '/'
        self.context = archive({
            prefix + 'package/apk/main/python/patch/3.14/fix.patch': self.local_patch,
            prefix + 'package/apk/main/python/patch/README': b'Patch build instructions',
            prefix + 'package/apk/main/python/alpine-3.24/3.14.yaml': self.recipe.encode(),
            prefix + 'LICENSE': b'Complete provider license'})
        context_url = 'https://github.com/docker-hardened-images/catalog/archive/' + revision + '.tar.gz'
        self.downloads = {self.source_url: self.source, context_url: self.context,
                          self.public_url: self.recipe.encode()}
        (self.root / 'docs/aports-source-lock.json').write_text(json.dumps({
            'provider_contexts': [{'origin': 'python-3.14', 'revision': revision,
                'url': context_url, 'sha256': hashlib.sha256(self.context).hexdigest()}]}))
        self.slsa['predicate']['materials'] = [{'uri': self.source_url,
            'digest': {'sha256': hashlib.sha256(self.source).hexdigest()}}]
        self.scout['predicate']['source_map']['dockerfile'] = base64.b64encode(self.recipe.encode()).decode()
        for statement in (self.slsa, self.scout):
            statement['subject'][0]['name'] = 'pkg:docker/dhi/pkg-python'
        return context_url

    def test_python_provider_context_retains_complete_archive_and_nested_patches(self):
        context_url = self.python_provider_context()
        result = self.collect()
        self.assertEqual(result['origin'], 'python-3.14')
        self.assertEqual(result['version'], '3.14.8-r0')
        self.assertEqual(result['recipe_revision'], self.spec['recipe']['revision'])
        self.assertIsNone(result['aports_commit'])
        self.assertEqual(result['native_image_digest'], 'sha256:' + self.native)
        context = next(row for row in result['files'] if row['role'] == 'complete-provider-build-recipes')
        self.assertEqual(context['url'], context_url)
        self.assertEqual(context['sha256'], hashlib.sha256(self.context).hexdigest())
        self.assertEqual(context['bytes'], len(self.context))
        self.assertEqual((self.root / 'output' / context['path']).read_bytes(), self.context)
        patches = {row['path']: row for row in result['files']
                   if row['role'] == 'pinned-provider-python-patch'}
        self.assertEqual(set(patches), {'context/python/patch/3.14/fix.patch',
                                       'context/python/patch/README'})
        patch_record = patches['context/python/patch/3.14/fix.patch']
        self.assertEqual(patch_record['sha256'], hashlib.sha256(self.local_patch).hexdigest())
        self.assertEqual((self.root / 'output' / patch_record['path']).read_bytes(), self.local_patch)

    def test_python_provider_context_requires_the_reviewed_revision(self):
        context_url = self.python_provider_context()
        lockpath = self.root / 'docs/aports-source-lock.json'
        lock = json.loads(lockpath.read_text())
        lock['provider_contexts'][0]['revision'] = 'd' * 40
        lockpath.write_text(json.dumps(lock))
        fetch = Mock(side_effect=self.downloads.__getitem__)
        with self.assertRaisesRegex(ValueError, 'Python provider patch context is not reviewed and pinned'):
            self.collect(fetch=fetch)
        self.assertNotIn(context_url, [call.args[0] for call in fetch.call_args_list])

    def test_python_provider_context_tampering_is_rejected_before_patch_retention(self):
        context_url = self.python_provider_context()
        self.downloads[context_url] += b'corrupted'
        with self.assertRaisesRegex(ValueError, 'Python provider patch context sha256 mismatch'):
            self.collect()
        self.assertFalse((self.root / 'output/context').exists())

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
        self.assertEqual(record['retrieval_method'],
                         'reviewed-historical-mirror-identical-to-signed-material-hash')
        self.assertNotIn('retrieval_url', record)

    def test_mirror_cannot_change_signed_source_identity(self):
        approved = {'origin': 'example', 'version': '1.0-r0',
               'url': 'https://mirror.example.org/source',
               'sha256': hashlib.sha256(self.source).hexdigest()}
        for field, value in [('origin', 'other'), ('version', '2.0-r0'), ('sha256', 'f' * 64)]:
            row = dict(approved, **{field: value})
            fetch = Mock(side_effect=self.downloads.__getitem__)
            with self.subTest(field=field), patch.object(sources, 'SOURCE_MIRRORS', {self.source_url: row}):
                with self.assertRaisesRegex(ValueError, 'mirror differs'):
                    self.collect(fetch=fetch, output='output-' + field)
            fetch.assert_called_once_with(self.public_url)

    def test_official_source_cache_records_exact_bytes_and_replays_offline(self):
        mirror_url = 'https://distfiles.alpinelinux.org/distfiles/v3.24/example-1.0.tar.gz'
        row = {'origin': 'example', 'version': '1.0-r0', 'url': mirror_url,
               'sha256': hashlib.sha256(self.source).hexdigest(),
               'retrieval_method': sources.OFFICIAL_ALPINE_SOURCE_CACHE}
        self.downloads[mirror_url] = self.source
        del self.downloads[self.source_url]
        fetch = Mock(side_effect=self.downloads.__getitem__)
        with patch.object(sources, 'SOURCE_MIRRORS', {self.source_url: row}):
            result = self.collect(fetch=fetch)
            record = next(value for value in result['files'] if value['role'] == 'signed-upstream-source')
            self.assertEqual(record['declared_url'], self.source_url)
            self.assertEqual(record['retrieval_url'], mirror_url)
            self.assertEqual(record['url'], mirror_url)
            self.assertEqual(record['retrieval_method'], sources.OFFICIAL_ALPINE_SOURCE_CACHE)
            self.assertEqual(record['sha256'], hashlib.sha256(self.source).hexdigest())
            self.assertEqual(record['bytes'], len(self.source))
            self.assertEqual((self.root / 'output' / record['path']).read_bytes(), self.source)
            self.assertNotIn(self.source_url, [call.args[0] for call in fetch.call_args_list])
            cache = {value['url']: (self.root / 'output' / value['path']).read_bytes()
                     for value in result['files'] if value['role'] in {
                         'signed-upstream-source', 'pinned-provider-build-recipe',
                         'complete-alpine-build-recipes'}}
            replayed = self.collect(fetch=cache.__getitem__, output='replayed')
        self.assertEqual(replayed, result)

    def test_wrong_mirrored_bytes_are_rejected_against_signed_digest(self):
        mirror_url = 'https://distfiles.alpinelinux.org/distfiles/v3.24/example-1.0.tar.gz'
        row = {'origin': 'example', 'version': '1.0-r0', 'url': mirror_url,
               'sha256': hashlib.sha256(self.source).hexdigest(),
               'retrieval_method': sources.OFFICIAL_ALPINE_SOURCE_CACHE}
        self.downloads[mirror_url] = self.source + b'corrupted'
        fetch = Mock(side_effect=self.downloads.__getitem__)
        with patch.object(sources, 'SOURCE_MIRRORS', {self.source_url: row}):
            with self.assertRaisesRegex(ValueError, 'Signed preferred source sha256 mismatch'):
                self.collect(fetch=fetch)
        self.assertEqual([call.args[0] for call in fetch.call_args_list], [self.public_url, mirror_url])
        self.assertFalse((self.root / 'output/sources/example-1.0.tar.gz').exists())

    def test_changed_signed_material_hash_is_not_accepted_by_source_cache(self):
        row = {'origin': 'example', 'version': '1.0-r0',
               'url': 'https://distfiles.alpinelinux.org/distfiles/v3.24/example-1.0.tar.gz',
               'sha256': hashlib.sha256(self.source).hexdigest(),
               'retrieval_method': sources.OFFICIAL_ALPINE_SOURCE_CACHE}
        self.slsa['predicate']['materials'][0]['digest']['sha256'] = 'd' * 64
        fetch = Mock(side_effect=self.downloads.__getitem__)
        with patch.object(sources, 'SOURCE_MIRRORS', {self.source_url: row}):
            with self.assertRaisesRegex(ValueError, 'mirror differs'):
                self.collect(fetch=fetch)
        fetch.assert_called_once_with(self.public_url)

    def test_unlisted_declared_source_url_does_not_use_source_cache(self):
        row = {'origin': 'example', 'version': '1.0-r0',
               'url': 'https://distfiles.alpinelinux.org/distfiles/v3.24/example-1.0.tar.gz',
               'sha256': hashlib.sha256(self.source).hexdigest(),
               'retrieval_method': sources.OFFICIAL_ALPINE_SOURCE_CACHE}
        del self.downloads[self.source_url]
        fetch = Mock(side_effect=self.downloads.__getitem__)
        with patch.object(sources, 'SOURCE_MIRRORS', {self.source_url + '.unreviewed': row}):
            with self.assertRaises(KeyError):
                self.collect(fetch=fetch)
        self.assertEqual([call.args[0] for call in fetch.call_args_list], [self.public_url, self.source_url])

    def test_permanent_source_cache_error_is_not_rerouted_or_retried(self):
        mirror_url = 'https://distfiles.alpinelinux.org/distfiles/v3.24/example-1.0.tar.gz'
        row = {'origin': 'example', 'version': '1.0-r0', 'url': mirror_url,
               'sha256': hashlib.sha256(self.source).hexdigest(),
               'retrieval_method': sources.OFFICIAL_ALPINE_SOURCE_CACHE}
        error = urllib.error.HTTPError(mirror_url, 418, 'blocked', {}, None)
        fetch = Mock(side_effect=[self.recipe.encode(), error])
        with patch.object(sources, 'SOURCE_MIRRORS', {self.source_url: row}):
            with self.assertRaises(urllib.error.HTTPError) as raised:
                self.collect(fetch=fetch)
        self.assertIs(raised.exception, error)
        self.assertEqual([call.args[0] for call in fetch.call_args_list], [self.public_url, mirror_url])


if __name__ == '__main__':
    unittest.main()
