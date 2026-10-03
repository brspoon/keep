"""Content binding and safe notice discovery for retained source OCI layouts."""
import hashlib
import gzip
import importlib.util
import io
import json
from pathlib import Path
import stat
import tarfile
import tempfile
import unittest
import zipfile


spec = importlib.util.spec_from_file_location('oci_source_materials', Path(__file__).resolve().parents[1] / 'scripts/oci_source_materials.py')
review = importlib.util.module_from_spec(spec)
spec.loader.exec_module(review)


def tar_bytes(entries, mode='w:gz'):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode=mode) as archive:
        for name, body in entries:
            member = tarfile.TarInfo(name)
            if isinstance(body, tarfile.TarInfo):
                archive.addfile(body)
            else:
                member.size = len(body)
                archive.addfile(member, io.BytesIO(body))
    return stream.getvalue()


class SourceMaterialsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.layout = self.root / 'oci'
        self.layout.mkdir()
        (self.layout / 'oci-layout').write_text('{"imageLayoutVersion":"1.0.0"}')
        (self.layout / 'blobs' / 'sha256').mkdir(parents=True)
        self.output = self.root / 'output'

    def blob(self, body, media_type):
        key = hashlib.sha256(body).hexdigest()
        (self.layout / 'blobs' / 'sha256' / key).write_bytes(body)
        return {'digest': 'sha256:' + key, 'size': len(body), 'mediaType': media_type}

    def image(self, body, wrapper=False):
        layer = self.blob(body, 'application/vnd.oci.image.layer.v1.tar+gzip')
        config = self.blob(b'{}', 'application/vnd.oci.image.config.v1+json')
        manifest = self.blob(json.dumps({'schemaVersion': 2, 'config': config, 'layers': [layer]}).encode(),
                             'application/vnd.oci.image.manifest.v1+json')
        root = manifest
        if wrapper:
            root = self.blob(json.dumps({'schemaVersion': 2, 'manifests': [manifest]}).encode(),
                             'application/vnd.oci.image.index.v1+json')
        (self.layout / 'index.json').write_text(json.dumps({'schemaVersion': 2, 'manifests': [root]}))
        return manifest, layer

    def inspect(self, expected, **limits):
        return review.inspect_layout(self.layout, expected, self.output, **limits)

    def test_nested_tar_copyright_and_build_inputs_with_index_wrapper(self):
        notice = b'Copyright example authors. GPL version 2.'
        source = tar_bytes([('source/COPYING', notice), ('source/configure', b'build steps')], 'w:xz')
        manifest, layer = self.image(tar_bytes([('src/project.tar.xz', source),
                                               ('src/APKBUILD', b'recipe'),
                                               ('src/repository/.git/objects/pack/source.pack', b'git repository')]), wrapper=True)
        layer_path = self.layout / 'blobs' / 'sha256' / layer['digest'].split(':')[1]
        original_layer = layer_path.read_bytes()
        result = self.inspect(manifest['digest'])
        self.assertTrue(result['binding_verified'])
        self.assertTrue(result['notice_inventory_complete'])
        self.assertEqual(len(result['verified_blobs']), 4)
        self.assertEqual(result['notices'][0]['sha256'], hashlib.sha256(notice).hexdigest())
        self.assertEqual((self.output / result['notices'][0]['notice_file']).read_bytes(), notice)
        self.assertTrue(any(row['kind'] == 'build-input' and row['path'].endswith('!src/APKBUILD') for row in result['files']))
        self.assertTrue(any('.git/objects/pack' in row['path'] for row in result['files']))
        self.assertEqual(layer_path.read_bytes(), original_layer)

    def test_compression_magic_finds_hash_named_sources(self):
        for mode in ('w:gz', 'w:xz'):
            with self.subTest(mode=mode):
                source = tar_bytes([('project/COPYRIGHT', b'Copyright source authors')], mode)
                manifest, _ = self.image(tar_bytes([('sources/content-addressed-source', source)]))
                result = self.inspect(manifest['digest'])
                self.assertEqual(len(result['notices']), 1)
                self.assertEqual(result['files'][0]['kind'], 'source-archive')

    def test_concatenated_apk_gzip_members_retain_data_notices(self):
        notice = b'Copyright APK data authors. MIT.'
        signature = gzip.compress(tar_bytes([('.SIGN.RSA.test.pub', b'signature')], 'w'))
        control = gzip.compress(tar_bytes([('.PKGINFO', b'pkgname = sample')], 'w'))
        data = gzip.compress(tar_bytes([('usr/share/sample/LICENSE', notice)], 'w'))
        manifest, _ = self.image(tar_bytes([('materials/content-addressed-apk', signature + control + data)]))
        result = self.inspect(manifest['digest'])
        self.assertTrue(result['notice_inventory_complete'])
        self.assertEqual(len(result['notices']), 1)
        self.assertEqual((self.output / result['notices'][0]['notice_file']).read_bytes(), notice)
        self.assertTrue(any(row['path'].endswith('!.PKGINFO') for row in result['files']))

    def test_rejects_changed_blob_bytes(self):
        manifest, layer = self.image(tar_bytes([('LICENSE', b'MIT')]))
        (self.layout / 'blobs' / 'sha256' / layer['digest'].split(':')[1]).write_bytes(b'tampered')
        with self.assertRaisesRegex(ValueError, 'blob digest mismatch'):
            self.inspect(manifest['digest'])

    def test_rejects_unbound_expected_root(self):
        self.image(tar_bytes([('LICENSE', b'MIT')]))
        with self.assertRaisesRegex(ValueError, 'root digest'):
            self.inspect('sha256:' + 'a' * 64)
        self.assertFalse(self.output.exists())

    def test_rejects_descriptor_size_mismatch(self):
        manifest, _ = self.image(tar_bytes([('LICENSE', b'MIT')]))
        path = self.layout / 'index.json'
        index = json.loads(path.read_text())
        index['manifests'][0]['size'] += 1
        path.write_text(json.dumps(index))
        with self.assertRaisesRegex(ValueError, 'descriptor size mismatch'):
            self.inspect(manifest['digest'])

    def test_rejects_unsafe_member_in_nested_archive(self):
        nested = tar_bytes([('../COPYING', b'outside')])
        manifest, _ = self.image(tar_bytes([('source.tar.gz', nested)]))
        with self.assertRaisesRegex(ValueError, 'Unsafe archive member'):
            self.inspect(manifest['digest'])
        self.assertFalse((self.root / 'COPYING').exists())

    def test_tar_links_never_followed(self):
        symlink = tarfile.TarInfo('LICENSE')
        symlink.type = tarfile.SYMTYPE
        symlink.linkname = '/etc/passwd'
        hardlink = tarfile.TarInfo('COPYING')
        hardlink.type = tarfile.LNKTYPE
        hardlink.linkname = '../../outside'
        manifest, _ = self.image(tar_bytes([('LICENSE', symlink), ('COPYING', hardlink),
                                            ('NOTICE', b'Public attribution')]))
        result = self.inspect(manifest['digest'])
        self.assertEqual(result['links_skipped'], 2)
        self.assertEqual(len(result['notices']), 1)
        self.assertEqual(result['notices'][0]['path'].split('!')[-1], 'NOTICE')

    def test_nested_zip_notice_and_link(self):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, 'w') as archive:
            archive.writestr('package/LICENSES/MIT.txt', b'Copyright ZIP authors. MIT.')
            link = zipfile.ZipInfo('package/LICENSE')
            link.create_system = 3
            link.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(link, '/etc/passwd')
        manifest, _ = self.image(tar_bytes([('source.zip', stream.getvalue())]))
        result = self.inspect(manifest['digest'])
        self.assertEqual(len(result['notices']), 1)
        self.assertEqual(result['links_skipped'], 1)

    def test_depth_and_notice_limits_warn_and_retain_blobs(self):
        manifest, _ = self.image(tar_bytes([('source.tar.gz', tar_bytes([('LICENSE', b'MIT')])),
                                             ('NOTICE', b'long notice')]))
        result = self.inspect(manifest['digest'], max_depth=0, max_notice_bytes=3)
        self.assertFalse(result['notice_inventory_complete'])
        self.assertTrue(any('depth limit' in row['reason'] for row in result['warnings']))
        self.assertTrue(any('text-size limit' in row['reason'] for row in result['warnings']))

    def test_missing_notice_is_reported(self):
        manifest, _ = self.image(tar_bytes([('APKBUILD', b'build inputs')]))
        result = self.inspect(manifest['digest'])
        self.assertFalse(result['notice_inventory_complete'])
        self.assertTrue(any('No readable license notices' in row['reason'] for row in result['warnings']))

    def test_blob_symlink_is_rejected(self):
        manifest, layer = self.image(tar_bytes([('LICENSE', b'MIT')]))
        path = self.layout / 'blobs' / 'sha256' / layer['digest'].split(':')[1]
        target = self.root / 'outside'
        path.replace(target)
        path.symlink_to(target)
        with self.assertRaisesRegex(ValueError, 'blob path symlinks'):
            self.inspect(manifest['digest'])

    def test_output_cannot_mutate_source_layout(self):
        manifest, _ = self.image(tar_bytes([('LICENSE', b'MIT')]))
        with self.assertRaisesRegex(ValueError, 'outside the retained'):
            review.inspect_layout(self.layout, manifest['digest'], self.layout / 'notices')

    def test_retention_keeps_hash_named_sources_git_contexts_and_recipes_without_bootstrap(self):
        upstream = tar_bytes([('upstream/COPYING', b'GPL upstream attribution')])
        manifest, _ = self.image(tar_bytes([
            ('opt/docker/materials/sha256:original', upstream),
            ('opt/docker/git/repo/.git/objects/pack/full.pack', b'complete git pack'),
            ('opt/docker/context/Makefile', b'build commands'),
            ('opt/docker/def/.def.yaml', b'merged package definition'),
            ('opt/docker/provenance/.prov.json', b'package provenance'),
            ('bin/[', b'bootstrap binary'),
            ('opt/docker/dhi/source', b'vendor utility'),
        ]), wrapper=True)
        result = review.retain_materials(self.layout, manifest['digest'], self.output)
        retained = {row['source_path']: row for row in result['files'] if row['type'] == 'file'}
        self.assertEqual(len(retained), 5)
        self.assertNotIn('bin/[', retained)
        self.assertNotIn('opt/docker/dhi/source', retained)
        for row in retained.values():
            body = (self.output / row['path']).read_bytes()
            self.assertEqual(hashlib.sha256(body).hexdigest(), row['sha256'])
        source = retained['opt/docker/materials/sha256:original']
        self.assertEqual((self.output / source['path']).read_bytes(), upstream)

    def test_retention_records_links_without_constructing_or_following_them(self):
        link = tarfile.TarInfo('opt/docker/git/repo/link')
        link.type = tarfile.SYMTYPE
        link.linkname = '/etc/passwd'
        hardlink = tarfile.TarInfo('opt/docker/context/linked')
        hardlink.type = tarfile.LNKTYPE
        hardlink.linkname = '../../outside'
        manifest, _ = self.image(tar_bytes([
            ('opt/docker/git/repo/link', link),
            ('opt/docker/context/linked', hardlink),
            ('opt/docker/context/src.c', b'preferred source')]))
        result = review.retain_materials(self.layout, manifest['digest'], self.output)
        self.assertEqual({row['target'] for row in result['files'] if 'target' in row},
                         {'/etc/passwd', '../../outside'})
        self.assertFalse(any(path.is_symlink() for path in self.output.rglob('*')))
        self.assertEqual(len([row for row in result['files'] if row['type'] == 'file']), 1)

    def test_retention_preserves_overwritten_material_versions_and_whiteout_metadata(self):
        first = self.blob(tar_bytes([('opt/docker/context/source.c', b'original source')]),
                          'application/vnd.oci.image.layer.v1.tar+gzip')
        second = self.blob(tar_bytes([('opt/docker/context/source.c', b'changed source'),
                                      ('opt/docker/context/.wh.deleted.c', b'')]),
                           'application/vnd.oci.image.layer.v1.tar+gzip')
        config = self.blob(b'{}', 'application/vnd.oci.image.config.v1+json')
        manifest = self.blob(json.dumps({'schemaVersion': 2, 'config': config,
                                        'layers': [first, second]}).encode(),
                             'application/vnd.oci.image.manifest.v1+json')
        (self.layout / 'index.json').write_text(json.dumps({'schemaVersion': 2, 'manifests': [manifest]}))
        result = review.retain_materials(self.layout, manifest['digest'], self.output)
        versions = [row for row in result['files'] if row['type'] == 'file']
        self.assertEqual(len(versions), 2)
        self.assertEqual({(self.output / row['path']).read_bytes() for row in versions},
                         {b'original source', b'changed source'})
        self.assertEqual([row['type'] for row in result['files']].count('whiteout'), 1)

    def test_retention_rejects_corrupted_blob_before_writing_files(self):
        manifest, layer = self.image(tar_bytes([('opt/docker/context/LICENSE', b'MIT')]))
        (self.layout / 'blobs' / 'sha256' / layer['digest'].split(':')[1]).write_bytes(b'corrupted')
        with self.assertRaisesRegex(ValueError, 'blob digest mismatch'):
            review.retain_materials(self.layout, manifest['digest'], self.output)
        self.assertFalse(self.output.exists())

    def test_retention_rejects_duplicate_and_unsafe_source_paths(self):
        for entries, message in [([('opt/docker/context/source.c', b'one'),
                                  ('opt/docker/context/source.c', b'two')], 'Duplicate source'),
                                 ([('opt/docker/context/../outside', b'unsafe')], 'Unsafe archive')]:
            with self.subTest(message=message), tempfile.TemporaryDirectory() as directory:
                manifest, _ = self.image(tar_bytes(entries))
                with self.assertRaisesRegex(ValueError, message):
                    review.retain_materials(self.layout, manifest['digest'], Path(directory) / 'retained')

    def test_retention_limit_fails_instead_of_claiming_partial_source_coverage(self):
        manifest, _ = self.image(tar_bytes([('opt/docker/context/source.c', b'long source')]))
        with self.assertRaisesRegex(ValueError, 'byte limit'):
            review.retain_materials(self.layout, manifest['digest'], self.output, max_retained_bytes=3)
        self.assertFalse((self.output / 'material-manifest.json').exists())

    def test_retention_requires_empty_output_and_preserves_executable_mode_without_setid(self):
        script = tarfile.TarInfo('opt/docker/context/build.sh')
        script.size = len(b'build script')
        script.mode = 0o4755
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode='w:gz') as archive:
            archive.addfile(script, io.BytesIO(b'build script'))
        manifest, _ = self.image(stream.getvalue())
        result = review.retain_materials(self.layout, manifest['digest'], self.output)
        row = result['files'][0]
        self.assertEqual(row['mode'], 0o4755)
        self.assertEqual(stat.S_IMODE((self.output / row['path']).stat().st_mode), 0o755)
        with self.assertRaisesRegex(ValueError, 'empty directory'):
            review.retain_materials(self.layout, manifest['digest'], self.output)


if __name__ == '__main__':
    unittest.main()


class LayerDecoderTests(unittest.TestCase):
    def test_plain_and_gzip_layers_are_bounded_after_decoding(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'layer'
            for body, media in [(b'hello layer', 'application/vnd.oci.image.layer.v1.tar'),
                                (gzip.compress(b'hello layer'), 'application/vnd.oci.image.layer.v1.tar+gzip')]:
                path.write_bytes(body)
                with review.open_layer(path, media, max_bytes=11) as stream:
                    self.assertEqual(stream.read(11), b'hello layer')
                with self.assertRaisesRegex(ValueError, 'decompressed byte limit'):
                    with review.open_layer(path, media, max_bytes=5) as stream:
                        stream.read(11)

    def test_zstd_layer_is_read_and_bounded_or_reports_missing_decoder(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'layer'
            path.write_bytes(bytes.fromhex('28b52ffd200b59000068656c6c6f206c61796572'))
            try:
                with review.open_layer(path, 'application/vnd.oci.image.layer.v1.tar+zstd', max_bytes=11) as stream:
                    self.assertEqual(stream.read(11), b'hello layer')
            except ValueError as error:
                if 'require compression.zstd' not in str(error):
                    raise
                self.skipTest('Optional Zstandard decoder is unavailable')
            with self.assertRaisesRegex(ValueError, 'decompressed byte limit'):
                with review.open_layer(path, 'application/vnd.oci.image.layer.v1.tar+zstd', max_bytes=5) as stream:
                    stream.read(11)

    def test_truncated_zstd_and_unsupported_layer_never_claim_completion(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'layer'
            path.write_bytes(bytes.fromhex('28b52ffd200b59000068'))
            with self.assertRaises(ValueError):
                with review.open_layer(path, 'application/vnd.oci.image.layer.v1.tar+zstd') as stream:
                    stream.read(100)
            with self.assertRaisesRegex(ValueError, 'Unsupported source layer'):
                with review.open_layer(path, 'application/vnd.unknown'):
                    pass
