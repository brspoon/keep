"""Alpine package signatures, runtime identities and matching sources stay bound."""
from contextlib import ExitStack
import copy
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest
import zlib
from unittest.mock import Mock, patch


spec = importlib.util.spec_from_file_location(
    'alpine_expat_sources', Path(__file__).resolve().parents[1] / 'scripts/alpine_expat_sources.py')
sources = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sources)


def archive(entries, links=None):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w') as package:
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
class AlpineExpatSourceTests(unittest.TestCase):
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
        for arch, native in sources.ARCHES.items():
            self.bodies['https://alpinelinux.org/keys/' + keys[arch]['name']] = self.key
            binaries[arch], metadata_hashes[arch] = {}, {}
            libraries[arch] = hashlib.sha256(('ordinary test library ' + arch).encode()).hexdigest()
            for name in ('expat', 'libexpat'):
                body, metadata = self.apk(name, arch)
                url = self.url(name, arch)
                self.bodies[url] = body
                binaries[arch][name] = hashlib.sha256(body).hexdigest()
                metadata_hashes[arch][name] = hashlib.sha256(metadata).hexdigest()
        self.stack.enter_context(patch.object(sources, 'BINARY_SHA256', binaries))
        self.stack.enter_context(patch.object(sources, 'PKGINFO_SHA256', metadata_hashes))
        self.stack.enter_context(patch.object(sources, 'LIBRARY_SHA256', libraries))
        self.copying = b'MIT copyright and complete permission conditions'
        upstream = archive([('expat-2.9.0/COPYING', self.copying),
                            ('expat-2.9.0/lib/xmlparse.c', b'ordinary preferred source')])
        checksum = hashlib.sha512(upstream).hexdigest()
        self.stack.enter_context(patch.object(sources, 'SOURCE_SHA256', hashlib.sha256(upstream).hexdigest()))
        self.stack.enter_context(patch.object(sources, 'SOURCE_SHA512', checksum))
        self.stack.enter_context(patch.object(sources, 'COPYING_SHA256', hashlib.sha256(self.copying).hexdigest()))
        recipe = ('pkgname=expat\npkgver=2.9.0\npkgrel=0\nlicense="MIT"\n'
                  'source="https://github.com/libexpat/libexpat/releases/download/$_tagver/expat-$pkgver.tar.xz"\n'
                  f'sha512sums="\n{checksum}  expat-2.9.0.tar.xz\n"\n'
                  'build() { ./configure --prefix=/usr; make; }\ncheck() { make check; }\n').encode()
        self.recipes = archive([(f'aports-{sources.BUILD_COMMIT}/main/expat/APKBUILD', recipe),
                                (f'aports-{sources.BUILD_COMMIT}/README.md', b'whole pinned context')])
        self.stack.enter_context(patch.object(sources, 'APKBUILD_SHA256', hashlib.sha256(recipe).hexdigest()))
        self.stack.enter_context(patch.object(sources, 'APORTS_SHA256', hashlib.sha256(self.recipes).hexdigest()))
        signature = b'retained upstream detached signature'
        self.stack.enter_context(patch.object(sources, 'SIGNATURE_SHA256', hashlib.sha256(signature).hexdigest()))
        self.bodies.update({sources.APORTS_URL: self.recipes, sources.SOURCE_URL: upstream,
                            sources.SOURCE_URL + '.asc': signature})
        self.package_spec = sources.reviewed_spec()

    @staticmethod
    def url(name, arch):
        return f'https://dl-cdn.alpinelinux.org/alpine/edge/main/{sources.ARCHES[arch]}/{name}-2.9.0-r0.apk'

    def apk(self, name, arch, *, changes=None, library=None, alias='libexpat.so.1.13.0', signer=None):
        if name == 'libexpat':
            library = library if library is not None else ('ordinary test library ' + arch).encode()
            payload = archive([(sources.LIBRARY_PATH, library)],
                              {'usr/lib/libexpat.so.1': alias})
        else:
            payload = archive([('usr/bin/xmlwf', b'ordinary test tool bytes')])
        data = gzip.compress(payload, mtime=0)
        native = sources.ARCHES[arch]
        fields = {'pkgname': name, 'pkgver': '2.9.0-r0', 'origin': 'expat', 'arch': native,
                  'commit': sources.BUILD_COMMIT, 'license': 'MIT', 'url': 'https://libexpat.github.io/',
                  'datahash': hashlib.sha256(data).hexdigest()}
        fields.update(changes or {})
        dependencies = ['so:libc.musl-' + native + '.so.1']
        provides = 'so:libexpat.so.1=1.13.0'
        if name == 'expat':
            dependencies.append('so:libexpat.so.1')
            provides = 'cmd:xmlwf=2.9.0-r0'
        metadata = (''.join(key + ' = ' + value + '\n' for key, value in fields.items())
                    + ''.join('depend = ' + value + '\n' for value in dependencies)
                    + 'provides = ' + provides + '\n').encode()
        control = gzip.compress(archive([('.PKGINFO', metadata)]), mtime=0)
        signature = subprocess.run(['openssl', 'dgst', '-sha1', '-sign', str(self.private)],
                                   input=control, check=True, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE).stdout
        signature_name = '.SIGN.RSA.' + (signer or sources.KEYS[arch]['name'])
        signed = gzip.compress(archive([(signature_name, signature)]), mtime=0)
        return signed + control + data, metadata

    def inventory(self):
        return {'os_packages': [{'name': name, 'version': '2.9.0-r0', 'origin': 'expat',
                                 'license': 'MIT', 'build_commit': sources.BUILD_COMMIT,
                                 'url': 'https://libexpat.github.io/'} for name in ('expat', 'libexpat')]}

    def collect(self, directory, arch='amd64', inventory=None, package_spec=None):
        return sources.collect_sources(package_spec or self.package_spec, arch,
                                       inventory or self.inventory(), directory,
                                       fetch=self.bodies.__getitem__)

    def replace_apk(self, name, arch='amd64', **kwargs):
        body, metadata = self.apk(name, arch, **kwargs)
        self.bodies[self.url(name, arch)] = body
        sources.BINARY_SHA256[arch][name] = hashlib.sha256(body).hexdigest()
        sources.PKGINFO_SHA256[arch][name] = hashlib.sha256(metadata).hexdigest()
        self.package_spec = sources.reviewed_spec()
        return body

    def test_both_architectures_retain_signed_packages_complete_context_and_source_notice(self):
        for arch in sources.ARCHES:
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as directory:
                result = self.collect(directory, arch)
                self.assertFalse(result['provider_oci_binding'])
                self.assertIsNone(result['source_image_digest'])
                self.assertEqual(result['binding_method'], 'signed-alpine-packages')
                self.assertEqual({row['pkgname'] for row in result['package_inputs']}, {'expat', 'libexpat'})
                self.assertTrue(all(row['signature_verified'] for row in result['package_inputs']))
                for row in result['files']:
                    body = (Path(directory) / row['path']).read_bytes()
                    self.assertEqual(hashlib.sha256(body).hexdigest(), row['sha256'])
                context = next(row for row in result['files'] if row['role'] == 'complete-alpine-build-recipes')
                self.assertEqual((Path(directory) / context['path']).read_bytes(), self.recipes)
                installation = json.loads((Path(directory) / 'EXPAT_SECURITY.json').read_text())
                self.assertEqual(installation, sources.security_manifest(self.package_spec, arch))
                self.assertEqual(result['source_manifest_sha256'], installation['source_manifest_sha256'])
                self.assertEqual(json.loads((Path(directory) / 'manifest.json').read_text()), result)

    def test_package_preparation_downloads_no_recipe_or_source_and_has_same_manifest(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(
                sources, 'download', side_effect=AssertionError('network forbidden')):
            fetch = Mock(side_effect=self.bodies.__getitem__)
            result = sources.prepare_packages(self.package_spec, 'amd64', directory, fetch=fetch)
            self.assertEqual(result, sources.security_manifest(self.package_spec, 'amd64'))
            self.assertEqual(fetch.call_count, 3)
            self.assertTrue((Path(directory) / 'keys' / sources.KEYS['amd64']['name']).is_file())
            self.assertFalse((Path(directory) / 'manifest.json').exists())

    def test_offline_expected_manifest_requires_exact_source_map(self):
        with tempfile.TemporaryDirectory() as directory:
            docs = Path(directory) / 'docs'
            docs.mkdir()
            path = docs / 'os-package-sources.json'
            path.write_text(json.dumps({'origins': [self.package_spec]}))
            self.assertEqual(sources.build_security_manifest('amd64', directory),
                             sources.security_manifest(self.package_spec, 'amd64'))
            bad = copy.deepcopy(self.package_spec)
            bad['packages'][0]['version'] = '2.8.5-r0'
            path.write_text(json.dumps({'origins': [bad]}))
            with self.assertRaisesRegex(ValueError, 'source map'):
                sources.build_security_manifest('amd64', directory)

    def test_map_and_actual_runtime_mismatches_fail_before_download(self):
        for field, value in [('version', '2.8.5-r0'), ('origin', 'other'), ('license', 'other'),
                             ('build_commit', 'f' * 40), ('url', 'https://example.test/')]:
            inventory = self.inventory()
            inventory['os_packages'][0][field] = value
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory, \
                    patch.object(sources, 'download') as fetch:
                with self.assertRaisesRegex(ValueError, 'runtime Expat package identity'):
                    sources.collect_sources(self.package_spec, 'amd64', inventory, directory, fetch=fetch)
                fetch.assert_not_called()
        for records in ([self.inventory()['os_packages'][0]],
                        [self.inventory()['os_packages'][0]] * 2):
            with tempfile.TemporaryDirectory() as directory, self.assertRaisesRegex(ValueError, 'both actual'):
                self.collect(directory, inventory={'os_packages': records})
        bad = copy.deepcopy(self.package_spec)
        bad['packages'][0]['binaries']['amd64']['url'] = 'https://example.test/other.apk'
        with tempfile.TemporaryDirectory() as directory, self.assertRaisesRegex(ValueError, 'source map'):
            self.collect(directory, package_spec=bad)

    def test_changed_apk_or_signing_key_hash_cannot_complete(self):
        for url in (self.url('expat', 'amd64'), self.package_spec['signing_keys']['amd64']['url']):
            original = self.bodies[url]
            self.bodies[url] += b'changed'
            with self.subTest(url=url), tempfile.TemporaryDirectory() as directory:
                with self.assertRaisesRegex(ValueError, 'checksum mismatch'):
                    self.collect(directory)
                self.assertFalse((Path(directory) / 'manifest.json').exists())
            self.bodies[url] = original

    def test_invalid_signature_rejected_even_when_outer_hash_is_reviewed(self):
        original = self.bodies[self.url('expat', 'amd64')]
        parts = sources.gzip_parts(original)
        signature_name = '.SIGN.RSA.' + sources.KEYS['amd64']['name']
        body = gzip.compress(archive([(signature_name, b'invalid RSA signature')]), mtime=0) + parts[1][0] + parts[2][0]
        sources.BINARY_SHA256['amd64']['expat'] = hashlib.sha256(body).hexdigest()
        with self.assertRaisesRegex(ValueError, 'RSA signature'):
            sources.verify_apk(body, 'expat', 'amd64', self.key)

    def test_changed_metadata_bytes_require_their_own_reviewed_hash(self):
        body, _ = self.apk('expat', 'amd64', changes={'pkgdesc': 'changed description'})
        sources.BINARY_SHA256['amd64']['expat'] = hashlib.sha256(body).hexdigest()
        with self.assertRaisesRegex(ValueError, 'metadata checksum'):
            sources.verify_apk(body, 'expat', 'amd64', self.key)

    def test_wrong_signer_name_and_payload_hash_rejected(self):
        body = self.replace_apk('expat', signer='unreviewed.rsa.pub')
        with self.assertRaisesRegex(ValueError, 'signing key name'):
            sources.verify_apk(body, 'expat', 'amd64', self.key)
        body = self.replace_apk('expat', changes={'datahash': 'f' * 64})
        with self.assertRaisesRegex(ValueError, 'payload hash mismatch'):
            sources.verify_apk(body, 'expat', 'amd64', self.key)

    def test_package_identity_version_arch_commit_license_and_dependencies_are_exact(self):
        payload_hash = 'a' * 64
        for field, value in [('pkgname', 'other'), ('pkgver', '2.8.5-r0'), ('origin', 'other'),
                             ('arch', 'aarch64'), ('commit', 'f' * 40), ('license', 'other')]:
            _, metadata = self.apk('expat', 'amd64', changes={field: value, 'datahash': payload_hash})
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'identity'):
                sources.package_identity(metadata, 'expat', 'amd64', payload_hash)
        _, metadata = self.apk('expat', 'amd64', changes={'datahash': payload_hash})
        for bad in (metadata + b'license = MIT\n', metadata + b'depend = so:unexpected.so.1\n',
                    metadata.replace(b'so:libexpat.so.1', b'so:libexpat.so.2')):
            with self.assertRaises(ValueError):
                sources.package_identity(bad, 'expat', 'amd64', payload_hash)

    def test_wrong_library_bytes_and_soname_alias_rejected(self):
        for change in ({'library': b'different library'}, {'alias': 'libexpat.so.1.12.5'}):
            body = self.replace_apk('libexpat', **change)
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, 'library|alias'):
                sources.verify_apk(body, 'libexpat', 'amd64', self.key)

    def test_source_context_source_and_notice_hashes_are_mandatory(self):
        for url in (sources.APORTS_URL, sources.SOURCE_URL, sources.SOURCE_URL + '.asc'):
            original = self.bodies[url]
            self.bodies[url] += b'changed'
            with self.subTest(url=url), tempfile.TemporaryDirectory() as directory:
                with self.assertRaisesRegex(ValueError, 'checksum mismatch'):
                    self.collect(directory)
                self.assertFalse((Path(directory) / 'manifest.json').exists())
            self.bodies[url] = original
        with tempfile.TemporaryDirectory() as directory, patch.object(sources, 'COPYING_SHA256', 'f' * 64):
            self.package_spec = sources.reviewed_spec()
            with self.assertRaisesRegex(ValueError, 'full notice checksum'):
                self.collect(directory)

    def test_recipe_checksum_and_source_declaration_cannot_be_substituted_or_executed(self):
        recipe = sources.read_member(self.recipes, f'aports-{sources.BUILD_COMMIT}/main/expat/APKBUILD')
        for bad in (recipe.replace(sources.SOURCE_SHA512.encode(), b'f' * 128),
                    recipe.replace(b'expat-$pkgver.tar.xz', b'other-$pkgver.tar.xz')):
            with self.assertRaisesRegex(ValueError, 'source checksum|source declaration'):
                sources.recipe_identity(bad)
        with tempfile.TemporaryDirectory() as directory, patch.object(
                sources.subprocess, 'run', wraps=subprocess.run) as calls:
            self.collect(directory)
        self.assertTrue(all(call.args[0][:2] == ['openssl', 'dgst'] for call in calls.call_args_list))

    def test_duplicate_unsafe_and_nonregular_source_entries_rejected(self):
        duplicate = archive([('entry', b'one'), ('entry', b'two')])
        unsafe = archive([('../outside', b'ordinary fixture'), ('entry', b'one')])
        link = archive([], {'entry': 'another'})
        for body in (duplicate, unsafe, link):
            with self.assertRaises(ValueError):
                sources.read_member(body, 'entry')

    def test_unexpected_or_bounded_gzip_members_and_nonempty_output_rejected(self):
        body = self.bodies[self.url('expat', 'amd64')]
        for bad in (body[:-1], body + gzip.compress(b'fourth member'), b'not gzip'):
            with self.assertRaises((ValueError, zlib.error)):
                sources.gzip_parts(bad)
        with patch.object(sources, 'APK_DECODE_LIMIT', 10), self.assertRaises(ValueError):
            sources.gzip_parts(body)
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / 'existing').write_bytes(b'preserve')
            with self.assertRaisesRegex(ValueError, 'empty'):
                self.collect(directory)
            self.assertEqual((Path(directory) / 'existing').read_bytes(), b'preserve')


if __name__ == '__main__':
    unittest.main()
