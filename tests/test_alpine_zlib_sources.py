"""Signed zlib installation and matching sources stay bound to exact inputs."""
from contextlib import ExitStack
import copy
import gzip
import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from scripts import alpine_zlib_sources as sources


def archive(entries, links=None, directories=()):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w') as package:
        for name in directories:
            member = tarfile.TarInfo(name)
            member.type = tarfile.DIRTYPE
            package.addfile(member)
        for name, body in entries:
            member = tarfile.TarInfo(name)
            member.size = len(body)
            package.addfile(member, io.BytesIO(body))
        for name, target in (links or {}).items():
            member = tarfile.TarInfo(name)
            member.type, member.linkname = tarfile.SYMTYPE, target
            package.addfile(member)
    return stream.getvalue()


@unittest.skipUnless(shutil.which('openssl'), 'Alpine APK verification requires OpenSSL')
class AlpineZlibSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key_directory = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.key_directory.cleanup)
        cls.private = Path(cls.key_directory.name) / 'test-signing.pem'
        subprocess.run(['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt',
                        'rsa_keygen_bits:2048', '-out', str(cls.private)],
                       check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        cls.key = subprocess.check_output(['openssl', 'pkey', '-in', str(cls.private), '-pubout'])

    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        keys = copy.deepcopy(sources.KEYS)
        for key in keys.values():
            key['sha256'] = hashlib.sha256(self.key).hexdigest()
        self.stack.enter_context(patch.object(sources, 'KEYS', keys))
        self.bodies, binaries, metadata_hashes, libraries = {}, {}, {}, {}
        for arch in sources.ARCHES:
            self.bodies['https://alpinelinux.org/keys/' + keys[arch]['name']] = self.key
            libraries[arch] = hashlib.sha256(('ordinary test library ' + arch).encode()).hexdigest()
            body, metadata = self.apk(arch)
            self.bodies[self.url(arch)] = body
            binaries[arch] = hashlib.sha256(body).hexdigest()
            metadata_hashes[arch] = hashlib.sha256(metadata).hexdigest()
        self.stack.enter_context(patch.object(sources, 'BINARY_SHA256', binaries))
        self.stack.enter_context(patch.object(sources, 'PKGINFO_SHA256', metadata_hashes))
        self.stack.enter_context(patch.object(sources, 'LIBRARY_SHA256', libraries))
        self.license_body = b'Complete zlib copyright, license terms and disclaimer'
        upstream = archive([('zlib-1.3.2/LICENSE', self.license_body),
                            ('zlib-1.3.2/gzwrite.c', b'ordinary preferred source')])
        self.stack.enter_context(patch.object(sources, 'SOURCE_SHA256', hashlib.sha256(upstream).hexdigest()))
        self.stack.enter_context(patch.object(sources, 'SOURCE_SHA512', hashlib.sha512(upstream).hexdigest()))
        self.stack.enter_context(patch.object(sources, 'LICENSE_SHA256', hashlib.sha256(self.license_body).hexdigest()))
        self.patch_body = ('From ' + sources.UPSTREAM_COMMIT + ' Mon Sep 17 00:00:00 2001\n'
                           'Reviewed ordinary source correction\n').encode()
        self.stack.enter_context(patch.object(sources, 'PATCH_SHA256', hashlib.sha256(self.patch_body).hexdigest()))
        self.stack.enter_context(patch.object(sources, 'PATCH_SHA512', hashlib.sha512(self.patch_body).hexdigest()))
        self.recipe = self.make_recipe()
        self.recipes = self.make_recipes()
        self.stack.enter_context(patch.object(sources, 'APKBUILD_SHA256', hashlib.sha256(self.recipe).hexdigest()))
        self.stack.enter_context(patch.object(sources, 'APORTS_SHA256', hashlib.sha256(self.recipes).hexdigest()))
        self.bodies.update({sources.APORTS_URL: self.recipes, sources.SOURCE_URL: upstream})
        self.package_spec = sources.reviewed_spec()

    @staticmethod
    def url(arch):
        return f'https://dl-cdn.alpinelinux.org/alpine/v3.24/main/{sources.ARCHES[arch]}/zlib-1.3.2-r1.apk'

    def apk(self, arch, *, changes=None, library=None, alias='libz.so.1.3.2', signer=None,
            dependencies=None, provides=None, extra_payload=(), control_extra=(),
            duplicate_field=None, payload_override=None):
        library = library if library is not None else ('ordinary test library ' + arch).encode()
        payload = payload_override or archive(
            [(sources.LIBRARY_PATH, library), *extra_payload],
            {sources.ALIAS_PATH: alias}, directories=('usr', 'usr/lib'))
        data = gzip.compress(payload, mtime=0)
        native = sources.ARCHES[arch]
        fields = {'pkgname': 'zlib', 'pkgver': sources.VERSION, 'origin': 'zlib', 'arch': native,
                  'commit': sources.BUILD_COMMIT, 'license': 'Zlib', 'url': 'https://zlib.net/',
                  'datahash': hashlib.sha256(data).hexdigest()}
        fields.update(changes or {})
        dependencies = dependencies if dependencies is not None else ['so:libc.musl-' + native + '.so.1']
        provides = provides if provides is not None else ['so:libz.so.1=1.3.2']
        metadata = (''.join(key + ' = ' + value + '\n' for key, value in fields.items())
                    + ''.join('depend = ' + value + '\n' for value in dependencies)
                    + ''.join('provides = ' + value + '\n' for value in provides)
                    + (duplicate_field + ' = ' + fields[duplicate_field] + '\n' if duplicate_field else '')).encode()
        control = gzip.compress(archive([('.PKGINFO', metadata), *control_extra]), mtime=0)
        signature = subprocess.run(['openssl', 'dgst', '-sha1', '-sign', str(self.private)],
                                   input=control, check=True, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE).stdout
        signature_name = '.SIGN.RSA.' + (signer or sources.KEYS[arch]['name'])
        signed = gzip.compress(archive([(signature_name, signature)]), mtime=0)
        return signed + control + data, metadata

    def make_recipe(self):
        return ('pkgname=zlib\npkgver=1.3.2\npkgrel=1\nlicense="Zlib"\n'
                'source="https://zlib.net/fossils/zlib-$pkgver.tar.gz\n\tCVE-2026-85091.patch\n\t"\n'
                '# secfixes:\n#   1.3.2-r1:\n#     - CVE-2026-85091\n'
                f'sha512sums="\n{sources.SOURCE_SHA512}  zlib-1.3.2.tar.gz\n'
                f'{sources.PATCH_SHA512}  CVE-2026-85091.patch\n"\n'
                'build() { ./configure --prefix=/usr; make; }\ncheck() { make check; }\n').encode()

    def make_recipes(self, recipe=None, patch_body=None):
        prefix = f'aports-{sources.BUILD_COMMIT}/main/zlib/'
        return archive([(prefix + 'APKBUILD', self.recipe if recipe is None else recipe),
                        (prefix + 'CVE-2026-85091.patch', self.patch_body if patch_body is None else patch_body),
                        (f'aports-{sources.BUILD_COMMIT}/README.md', b'whole pinned build context')])

    @staticmethod
    def inventory():
        return {'os_packages': [{'name': 'zlib', 'version': sources.VERSION, 'origin': 'zlib',
                                 'license': 'Zlib', 'build_commit': sources.BUILD_COMMIT,
                                 'url': 'https://zlib.net/'}]}

    def collect(self, directory, arch='amd64', inventory=None, package_spec=None):
        return sources.collect_sources(self.package_spec if package_spec is None else package_spec,
                                       arch, self.inventory() if inventory is None else inventory,
                                       directory, fetch=self.bodies.__getitem__)

    def replace_apk(self, arch='amd64', **kwargs):
        body, metadata = self.apk(arch, **kwargs)
        self.bodies[self.url(arch)] = body
        sources.BINARY_SHA256[arch] = hashlib.sha256(body).hexdigest()
        sources.PKGINFO_SHA256[arch] = hashlib.sha256(metadata).hexdigest()
        self.package_spec = sources.reviewed_spec()
        return body

    def test_both_architectures_retain_signed_packages_full_recipes_source_patch_and_license(self):
        for arch in sources.ARCHES:
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as directory:
                result = self.collect(directory, arch)
                self.assertFalse(result['provider_oci_binding'])
                self.assertIsNone(result['source_image_digest'])
                self.assertEqual(result['binding_method'], 'signed-alpine-packages')
                self.assertEqual([row['pkgname'] for row in result['package_inputs']], ['zlib'])
                self.assertTrue(result['package_inputs'][0]['signature_verified'])
                for row in result['files']:
                    self.assertEqual(hashlib.sha256((Path(directory) / row['path']).read_bytes()).hexdigest(), row['sha256'])
                self.assertEqual((Path(directory) / f'aports-{sources.BUILD_COMMIT}.tar.gz').read_bytes(), self.recipes)
                self.assertEqual((Path(directory) / 'context/main/zlib/CVE-2026-85091.patch').read_bytes(), self.patch_body)
                self.assertEqual((Path(directory) / 'zlib-1.3.2-LICENSE').read_bytes(), self.license_body)
                installation = json.loads((Path(directory) / 'ZLIB_SECURITY.json').read_text())
                self.assertEqual(installation, sources.security_manifest(self.package_spec, arch))
                self.assertEqual(result['source_manifest_sha256'], installation['source_manifest_sha256'])
                self.assertEqual(result['installation_manifest_sha256'], hashlib.sha256((Path(directory) / 'ZLIB_SECURITY.json').read_bytes()).hexdigest())

    def test_prepare_packages_fetches_only_signed_native_installation_inputs(self):
        for arch in sources.ARCHES:
            fetched = []
            def fetch(url):
                fetched.append(url)
                return self.bodies[url]
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as directory:
                result = sources.prepare_packages(self.package_spec, arch, directory, fetch=fetch)
                self.assertEqual(set(fetched), {self.url(arch), self.package_spec['signing_keys'][arch]['url']})
                self.assertEqual(result['package_version'], '1.3.2-r1')
                self.assertEqual(result['version'], '1.3.2')
                self.assertEqual(result['library']['sha256'], sources.LIBRARY_SHA256[arch])
                self.assertEqual((Path(directory) / 'source-lock.json').read_bytes(), sources.source_lock_bytes(self.package_spec))

    def test_reviewed_source_map_and_offline_manifest_are_exact(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'docs').mkdir()
            mapping = {'origins': [self.package_spec]}
            path = root / 'docs/os-package-sources.json'
            path.write_text(json.dumps(mapping))
            self.assertEqual(sources.build_security_manifest('amd64', root), sources.security_manifest(self.package_spec, 'amd64'))
            mapping['origins'][0]['version'] = '1.3.2-r0'
            path.write_text(json.dumps(mapping))
            with self.assertRaisesRegex(ValueError, 'source map'):
                sources.build_security_manifest('amd64', root)

    def test_outer_apk_and_key_hashes_reject_changed_bytes(self):
        for target in (self.url('amd64'), self.package_spec['signing_keys']['amd64']['url']):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as directory:
                original = self.bodies[target]
                self.bodies[target] = original + b'changed'
                with self.assertRaisesRegex(ValueError, 'checksum'):
                    self.collect(directory)
                self.bodies[target] = original

    def test_bad_signature_is_rejected_even_with_repinned_outer_hash(self):
        original = self.bodies[self.url('amd64')]
        parts = sources.gzip_parts(original)
        signs = sources.tar_entries(parts[0][1])
        name = next(iter(signs))
        signature = bytearray(signs[name]['body'])
        signature[0] ^= 1
        corrupted = gzip.compress(archive([(name, bytes(signature))]), mtime=0) + parts[1][0] + parts[2][0]
        self.bodies[self.url('amd64')] = corrupted
        sources.BINARY_SHA256['amd64'] = hashlib.sha256(corrupted).hexdigest()
        self.package_spec = sources.reviewed_spec()
        with tempfile.TemporaryDirectory() as directory, self.assertRaisesRegex(ValueError, 'signature verification'):
            self.collect(directory)

    def test_unsigned_control_substitution_is_rejected(self):
        original = sources.gzip_parts(self.bodies[self.url('amd64')])
        replaced = sources.gzip_parts(self.apk('amd64', changes={'arch': 'aarch64'})[0])
        body = original[0][0] + replaced[1][0] + original[2][0]
        self.bodies[self.url('amd64')] = body
        sources.BINARY_SHA256['amd64'] = hashlib.sha256(body).hexdigest()
        self.package_spec = sources.reviewed_spec()
        with tempfile.TemporaryDirectory() as directory, self.assertRaisesRegex(ValueError, 'signature verification'):
            self.collect(directory)

    def test_signed_control_datahash_rejects_payload_substitution(self):
        original = sources.gzip_parts(self.bodies[self.url('amd64')])
        replaced = sources.gzip_parts(self.apk('amd64', library=b'different library')[0])
        body = original[0][0] + original[1][0] + replaced[2][0]
        self.bodies[self.url('amd64')] = body
        sources.BINARY_SHA256['amd64'] = hashlib.sha256(body).hexdigest()
        self.package_spec = sources.reviewed_spec()
        with tempfile.TemporaryDirectory() as directory, self.assertRaisesRegex(ValueError, 'payload hash'):
            self.collect(directory)

    def test_signed_wrong_package_architecture_build_license_or_version_is_rejected(self):
        changes = {'pkgname': 'other', 'pkgver': '1.3.2-r0', 'origin': 'other',
                   'arch': 'aarch64', 'commit': '0' * 40, 'license': 'other', 'url': 'https://example.invalid/'}
        for field, value in changes.items():
            self.replace_apk(changes={field: value})
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory, self.assertRaisesRegex(ValueError, 'identity'):
                self.collect(directory)

    def test_duplicate_signed_metadata_is_rejected(self):
        self.replace_apk(duplicate_field='pkgver')
        with tempfile.TemporaryDirectory() as directory, self.assertRaisesRegex(ValueError, 'identity'):
            self.collect(directory)

    def test_signed_metadata_hash_is_checked_independently(self):
        self.replace_apk()
        sources.PKGINFO_SHA256['amd64'] = '0' * 64
        self.package_spec = sources.reviewed_spec()
        with tempfile.TemporaryDirectory() as directory, self.assertRaisesRegex(ValueError, 'metadata checksum'):
            self.collect(directory)

    def test_signed_unreviewed_dependencies_and_provisions_are_rejected(self):
        for kwargs in ({'dependencies': []}, {'dependencies': ['so:libc.musl-x86_64.so.1', 'other']},
                       {'provides': ['so:libz.so.2=1.3.2']}, {'provides': ['so:libz.so.1=1.3.2'] * 2}):
            self.replace_apk(**kwargs)
            with self.subTest(kwargs=kwargs), tempfile.TemporaryDirectory() as directory, self.assertRaisesRegex(ValueError, 'dependency|SONAME'):
                self.collect(directory)

    def test_library_bytes_alias_and_extra_payload_are_rejected(self):
        for kwargs in ({'library': b'unreviewed library'}, {'alias': '../../other/library'},
                       {'extra_payload': [('usr/lib/libz.so.2', b'extra library')]}):
            self.replace_apk(**kwargs)
            with self.subTest(kwargs=kwargs), tempfile.TemporaryDirectory() as directory, self.assertRaisesRegex(ValueError, 'library|payload'):
                self.collect(directory)

    def test_control_lifecycle_script_is_rejected(self):
        self.replace_apk(control_extra=[('.post-install', b'unreviewed script')])
        with tempfile.TemporaryDirectory() as directory, self.assertRaisesRegex(ValueError, 'only regular package metadata'):
            self.collect(directory)

    def test_wrong_signing_key_name_is_rejected(self):
        self.replace_apk(signer='unreviewed.rsa.pub')
        with tempfile.TemporaryDirectory() as directory, self.assertRaisesRegex(ValueError, 'signing key name'):
            self.collect(directory)

    def test_duplicate_or_unsafe_archive_members_are_rejected(self):
        for payload in (archive([(sources.LIBRARY_PATH, b'a'), (sources.LIBRARY_PATH, b'b')]),
                        archive([('../escape', b'unsafe')])):
            self.replace_apk(payload_override=payload)
            with tempfile.TemporaryDirectory() as directory, self.assertRaises(ValueError):
                self.collect(directory)

    def test_library_parent_symlinks_are_rejected(self):
        payload = archive([(sources.LIBRARY_PATH, b'ordinary test library amd64')],
                          {sources.ALIAS_PATH: 'libz.so.1.3.2', 'usr': '/other'},
                          directories=('usr/lib',))
        self.replace_apk(payload_override=payload)
        with tempfile.TemporaryDirectory() as directory, self.assertRaisesRegex(ValueError, 'parents must be directories'):
            self.collect(directory)

    def test_wrong_runtime_package_or_duplicate_is_rejected_before_download(self):
        original = self.inventory()
        cases = [{'os_packages': []}, {'os_packages': original['os_packages'] * 2}]
        for field, value in {'version': '1.3.2-r0', 'origin': 'other', 'license': 'other',
                             'build_commit': '0' * 40, 'url': 'https://example.invalid/'}.items():
            changed = copy.deepcopy(original)
            changed['os_packages'][0][field] = value
            cases.append(changed)
        for inventory in cases:
            with self.subTest(inventory=inventory), tempfile.TemporaryDirectory() as directory, self.assertRaisesRegex(ValueError, 'runtime'):
                self.collect(directory, inventory=inventory)

    def test_wrong_reviewed_spec_and_unsupported_architecture_are_rejected(self):
        changed = copy.deepcopy(self.package_spec)
        changed['patch']['upstream_commit'] = '0' * 40
        with tempfile.TemporaryDirectory() as directory, self.assertRaisesRegex(ValueError, 'source map'):
            self.collect(directory, package_spec=changed)
        with tempfile.TemporaryDirectory() as directory, self.assertRaisesRegex(ValueError, 'architecture'):
            self.collect(directory, arch='ppc64le')

    def test_recipe_source_and_patch_checksums_are_exact(self):
        for original, replacement in ((b'pkgrel=1', b'pkgrel=0'),
                                      (sources.SOURCE_SHA512.encode(), b'0' * 128),
                                      (sources.PATCH_SHA512.encode(), b'0' * 128),
                                      (b'CVE-2026-85091', b'CVE-2026-other')):
            changed = self.recipe.replace(original, replacement)
            with self.subTest(original=original), self.assertRaises(ValueError):
                sources.recipe_identity(changed)

    def test_changed_aports_or_source_archive_is_rejected(self):
        for url in (sources.APORTS_URL, sources.SOURCE_URL):
            original = self.bodies[url]
            self.bodies[url] += b'changed'
            with self.subTest(url=url), tempfile.TemporaryDirectory() as directory, self.assertRaisesRegex(ValueError, 'checksum'):
                self.collect(directory)
            self.bodies[url] = original

    def test_changed_patch_is_rejected_even_when_context_outer_hash_is_repinned(self):
        changed = self.make_recipes(patch_body=self.patch_body + b'changed')
        self.bodies[sources.APORTS_URL] = changed
        with patch.object(sources, 'APORTS_SHA256', hashlib.sha256(changed).hexdigest()):
            self.package_spec = sources.reviewed_spec()
            with tempfile.TemporaryDirectory() as directory, self.assertRaisesRegex(ValueError, 'security patch checksum'):
                self.collect(directory)

    def test_patch_upstream_commit_is_checked_independently(self):
        changed_patch = self.patch_body.replace(sources.UPSTREAM_COMMIT.encode(), b'0' * 40)
        with patch.object(sources, 'PATCH_SHA256', hashlib.sha256(changed_patch).hexdigest()), \
                patch.object(sources, 'PATCH_SHA512', hashlib.sha512(changed_patch).hexdigest()):
            recipe = self.make_recipe()
            context = self.make_recipes(recipe=recipe, patch_body=changed_patch)
            with patch.object(sources, 'APKBUILD_SHA256', hashlib.sha256(recipe).hexdigest()), \
                    patch.object(sources, 'APORTS_SHA256', hashlib.sha256(context).hexdigest()):
                self.bodies[sources.APORTS_URL] = context
                self.package_spec = sources.reviewed_spec()
                with tempfile.TemporaryDirectory() as directory, self.assertRaisesRegex(ValueError, 'upstream fix identity'):
                    self.collect(directory)

    def test_license_hash_is_independent_of_outer_source_hash(self):
        with patch.object(sources, 'LICENSE_SHA256', '0' * 64):
            self.package_spec = sources.reviewed_spec()
            with tempfile.TemporaryDirectory() as directory, self.assertRaisesRegex(ValueError, 'full notice checksum'):
                self.collect(directory)

    def test_nonempty_or_symlink_output_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'existing').write_text('preserved')
            with self.assertRaisesRegex(ValueError, 'empty'):
                self.collect(root)
            link = root / 'link'
            link.symlink_to(root, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, 'symlinks'):
                self.collect(link)


if __name__ == '__main__':
    unittest.main()
