import hashlib
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest

import helper_bundle as bundle
from private_store import StorageError, create_private_paths


class BundleTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve())
        self.addCleanup(self.directory.cleanup)
        self.paths = create_private_paths()
        self.root = bundle.create_root(self.paths, Path(self.directory.name).resolve() / 'private')
        self.source = self.paths.mkdir(self.root / 'source')
        for name in bundle.FILES:
            self.paths.publish(self.source / name, ('# synthetic source: ' + name + '\n').encode())
        self.version, self.revision = '2.26.0', 'a' * 40
        self.body = bundle.source_bundle(self.paths, self.source, version=self.version, revision=self.revision)
        self.digest = hashlib.sha256(self.body).hexdigest()

    def inspect(self, body=None, digest=None):
        return bundle.inspect_bundle(body or self.body, version=self.version, revision=self.revision,
                                     expected_sha256=digest or self.digest)

    def test_deterministic_bundle_and_every_exact_file_are_verified(self):
        self.assertEqual(self.body, bundle.source_bundle(self.paths, self.source, version=self.version, revision=self.revision))
        contents, manifest = self.inspect()
        self.assertEqual(set(contents), set(bundle.FILES))
        self.assertEqual(manifest['revision'], self.revision)
        self.assertEqual(manifest['minimum_python'], '3.12')

    def test_checksum_identity_and_truncation_are_rejected(self):
        for body, digest in ((self.body, 'b' * 64), (self.body[:-10], hashlib.sha256(self.body[:-10]).hexdigest())):
            with self.subTest(body_bytes=len(body)), self.assertRaises((bundle.BundleError, tarfile.TarError, EOFError)):
                self.inspect(body, digest)

    def test_link_traversal_duplicate_and_unknown_members_never_stage(self):
        for name, kind in (('../outside.py', tarfile.REGTYPE),
                           (bundle.PREFIX + bundle.FILES[0], tarfile.SYMTYPE),
                           (bundle.PREFIX + 'unknown.py', tarfile.REGTYPE)):
            with self.subTest(name=name, kind=kind):
                raw = io.BytesIO()
                with tarfile.open(fileobj=raw, mode='w:gz') as archive:
                    member = tarfile.TarInfo(name)
                    member.type = kind
                    if kind == tarfile.REGTYPE:
                        member.size = 1
                        archive.addfile(member, io.BytesIO(b'x'))
                    else:
                        member.linkname = '../outside'
                        archive.addfile(member)
                body = raw.getvalue()
                with self.assertRaises(bundle.BundleError):
                    self.inspect(body, hashlib.sha256(body).hexdigest())
                self.assertFalse((self.root / 'outside.py').exists())

    def test_staging_is_private_idempotent_and_source_collision_preserves_enrollment(self):
        state = bundle.create_root(self.paths, self.root / 'state')
        self.paths.publish(state / 'enrollment-active.json', b'synthetic-protected-enrollment')
        kwargs = dict(version=self.version, revision=self.revision, expected_sha256=self.digest)
        staged = bundle.stage_bundle(self.paths, state, self.body, **kwargs)
        self.assertEqual(staged, bundle.stage_bundle(self.paths, state, self.body, **kwargs))
        for name in (*bundle.FILES, 'bundle-proof.json'):
            self.paths.check(staged / name)
        self.paths.publish(staged / bundle.FILES[0], b'changed', overwrite=True)
        with self.assertRaises(bundle.BundleError):
            bundle.stage_bundle(self.paths, state, self.body, **kwargs)
        self.assertEqual(self.paths.read(state / 'enrollment-active.json'), b'synthetic-protected-enrollment')

    def test_symlink_staging_parent_is_rejected(self):
        (self.root / 'link').symlink_to(self.source, target_is_directory=True)
        with self.assertRaises(StorageError):
            bundle.stage_bundle(self.paths, self.root / 'link', self.body, version=self.version,
                                revision=self.revision, expected_sha256=self.digest)

    def client(self, *, immutable=True, wrong_digest=False, no_helper=False):
        materials = json.dumps({'version': self.version, 'revision': self.revision}).encode()
        name = 'keep-' + self.version + '-maintenance-helper.tar.gz'
        sidecar = (self.digest + '  ' + name + '\n').encode()
        bodies = {'keep-' + self.version + '-release-materials.json': materials,
                  name: self.body, name + '.sha256': sidecar}
        assets = [{'name': filename, 'size': len(body),
                   'digest': 'sha256:' + ('b' * 64 if wrong_digest and filename == name else hashlib.sha256(body).hexdigest())}
                  for filename, body in bodies.items() if not no_helper or filename != name]
        release = json.dumps({'draft': False, 'prerelease': False, 'immutable': immutable,
            'tag_name': self.version, 'published_at': '2026-10-12T00:00:00Z',
            'html_url': 'https://github.com/brspoon/keep/releases/tag/' + self.version,
            'assets': assets}).encode()
        class Client:
            def get(inner, url, *, limit):
                bundle.OfficialBundleClient.allowed(url)
                body = release if url.startswith('https://api.github.com/') else bodies[url.rsplit('/', 1)[1]]
                if len(body) > limit:
                    raise bundle.BundleError('fixture bound')
                return body
        return Client()

    def test_published_helper_is_bound_to_release_asset_digests_and_materials_revision(self):
        self.assertEqual(bundle.published_bundle(self.version, client=self.client()),
                         (self.body, self.version, self.revision, self.digest))

    def test_unpublished_missing_and_changed_assets_are_held_without_raw_branch_fallback(self):
        for values in ({'immutable': False}, {'wrong_digest': True}, {'no_helper': True}):
            with self.subTest(values=values), self.assertRaises(bundle.BundleError):
                bundle.published_bundle(self.version, client=self.client(**values))

    def test_release_transport_rejects_private_credentials_non_https_and_foreign_hosts(self):
        for url in ('http://github.com/brspoon/keep', 'https://github.com@evil.test/data',
                    'https://evil.test/data', 'https://api.github.com:444/data', 'https://github.com/data#extra'):
            with self.subTest(url=url), self.assertRaises(bundle.BundleError):
                bundle.OfficialBundleClient.allowed(url)


if __name__ == '__main__':
    unittest.main()
