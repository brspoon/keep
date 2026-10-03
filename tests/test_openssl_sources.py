import hashlib
import io
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import openssl_distribution_sources as sources


def digest(body, algorithm='sha256'):
    return hashlib.new(algorithm, body).hexdigest()


def archive(files):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode='w:gz') as bundle:
        for name, body in files.items():
            member = tarfile.TarInfo(name)
            if isinstance(body, tuple):
                member.type, member.linkname = tarfile.SYMTYPE, body[0]
                bundle.addfile(member)
            else:
                member.size = len(body)
                bundle.addfile(member, io.BytesIO(body))
    return out.getvalue()


class OpenSSLSourceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.license = b'Copyright OpenSSL authors\nFull Apache-2.0 license terms\n'
        self.upstream = archive({
            'openssl-3.5.8/LICENSE.txt': self.license,
            'openssl-3.5.8/AUTHORS.md': b'OpenSSL authors\n',
            'openssl-3.5.8/VERSION.dat': b'MAJOR=3\nMINOR=5\nPATCH=8\n',
            'openssl-3.5.8/crypto/source.c': b'int preferred_source;\n'})
        self.build_patch = b'--- a/source.c\n+++ b/source.c\n'
        self.apkbuild = (f'pkgname=openssl\npkgver=3.5.8\npkgrel=0\nlicense="Apache-2.0"\n'
            'source="https://github.com/openssl/openssl/releases/download/openssl-$pkgver/openssl-$pkgver.tar.gz\n'
            '\tauxv.patch\n\t"\nsha512sums="\n'
            f'{digest(self.upstream, "sha512")}  openssl-3.5.8.tar.gz\n'
            f'{digest(self.build_patch, "sha512")}  auxv.patch\n"\n').encode()
        prefix = f'aports-{sources.APORTS_COMMIT}/main/openssl/'
        self.aports = archive({prefix + 'APKBUILD': self.apkbuild,
            prefix + 'auxv.patch': self.build_patch,
            prefix + 'openssl-fips.post-install': b'#!/bin/sh\nexit 0\n'})
        self.provider = ('image: dhi.io/pkg-openssl\nvars:\n'
            f'  COMMIT_SHA: {sources.APORTS_COMMIT}\n  VERSION: 3.5.8\n'
            '  REL: "1"\n  _REL: "0"\n  EXTRA_PATCHES: "false"\n').encode()
        constants = {'RECIPE_SHA256': digest(self.provider),
            'APORTS_SHA256': digest(self.aports), 'APKBUILD_SHA256': digest(self.apkbuild),
            'SOURCE_SHA256': digest(self.upstream), 'SOURCE_SHA512': digest(self.upstream, 'sha512'),
            'PATCH_SHA512': digest(self.build_patch, 'sha512'), 'LICENSE_SHA256': digest(self.license)}
        self.constants = patch.multiple(sources, **constants)
        self.constants.start()
        self.spec = {'origin': 'openssl', 'version': '3.5.8-r1',
            'recipe': {'path': sources.RECIPE_PATH, 'revision': sources.RECIPE_REVISION,
                       'sha256': sources.RECIPE_SHA256, 'upstream_commit': sources.APORTS_COMMIT},
            'packages': []}
        dependencies, installed = [], []
        for number, name in enumerate(('openssl', 'libcrypto3', 'libssl3'), 1):
            binary = {'url': 'https://dhi.io/apk/' + name + '.apk', 'sha256': str(number) * 64}
            self.spec['packages'].append({'name': name, 'version': '3.5.8-r1',
                'license': 'Apache-2.0', 'build_commit': sources.BUILD_COMMIT,
                'binaries': {'amd64': binary, 'arm64': binary}})
            dependencies.append({'uri': binary['url'], 'digest': {'sha256': binary['sha256']}})
            installed.append({'name': name, 'version': '3.5.8-r1', 'origin': 'openssl',
                'license': 'Apache-2.0', 'build_commit': sources.BUILD_COMMIT})
        self.provenance = {'predicateType': 'https://slsa.dev/provenance/v1',
            'subject': [{'digest': {'sha256': sources.NATIVE_DIGESTS['amd64'].split(':')[1]}}],
            'predicate': {'buildDefinition': {'resolvedDependencies': dependencies}}}
        self.inventory = {'os_packages': installed}
        self.downloads = {sources.RECIPE_URL: self.provider, sources.APORTS_URL: self.aports,
                          sources.SOURCE_URL: self.upstream}

    def tearDown(self):
        self.constants.stop()
        self.temp.cleanup()

    def collect(self, **kwargs):
        return sources.collect_sources(self.spec, 'amd64', self.provenance, self.inventory,
            self.root / 'sources', fetch=lambda url: self.downloads[url], **kwargs)

    def test_complete_checked_sources_without_binary_or_fake_provider_claim(self):
        manifest = self.collect()
        self.assertFalse(manifest['provider_oci_binding'])
        self.assertIsNone(manifest['source_image_digest'])
        self.assertEqual(len(manifest['package_inputs']), 3)
        roles = {row['role'] for row in manifest['files']}
        self.assertTrue({'upstream-source', 'upstream-notice', 'matching-apk-build-script',
                         'complete-alpine-build-recipes', 'matching-build-context'} <= roles)
        for row in manifest['files']:
            self.assertEqual(digest((self.root / 'sources' / row['path']).read_bytes()), row['sha256'])
            self.assertFalse(row['path'].endswith('.apk'))
        full_license = next(row for row in manifest['files'] if row['role'] == 'upstream-notice')
        self.assertEqual((self.root / 'sources' / full_license['path']).read_bytes(), self.license)

    def test_wrong_native_base_subject_fails_before_download(self):
        self.provenance['subject'][0]['digest']['sha256'] = 'b' * 64
        with self.assertRaisesRegex(ValueError, 'native subject'):
            self.collect()
        self.assertFalse((self.root / 'sources').exists())

    def test_wrong_actual_runtime_build_commit_fails(self):
        self.inventory['os_packages'][0]['build_commit'] = '0' * 40
        with self.assertRaisesRegex(ValueError, 'runtime.*identity'):
            self.collect()

    def test_wrong_binary_sha_in_base_materials_fails(self):
        self.provenance['predicate']['buildDefinition']['resolvedDependencies'][1]['digest']['sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'exact reviewed OpenSSL APK'):
            self.collect()

    def test_provider_recipe_is_immutable(self):
        self.downloads[sources.RECIPE_URL] += b'# altered\n'
        with self.assertRaisesRegex(ValueError, 'recipe.*checksum'):
            self.collect()

    def test_missing_build_patch_cannot_pass(self):
        prefix = f'aports-{sources.APORTS_COMMIT}/main/openssl/'
        value = archive({prefix + 'APKBUILD': self.apkbuild,
                         prefix + 'openssl-fips.post-install': b'install'})
        self.downloads[sources.APORTS_URL] = value
        with patch.object(sources, 'APORTS_SHA256', digest(value)):
            with self.assertRaisesRegex(ValueError, 'one exact.*entry'):
                self.collect()

    def test_source_checksum_rechecked(self):
        self.downloads[sources.SOURCE_URL] += b'altered'
        with self.assertRaisesRegex(ValueError, 'upstream source.*checksum'):
            self.collect()

    def test_untrusted_paths_rejected_without_extraction(self):
        value = archive({'../escaped': b'bad', 'project/LICENSE': self.license})
        with self.assertRaisesRegex(ValueError, 'Unsafe'):
            sources.read_member(value, 'project/LICENSE')
        self.assertFalse((self.root / 'escaped').exists())

    def test_notice_archive_symlink_never_followed(self):
        value = archive({'project/LICENSE': ('/etc/passwd',)})
        with self.assertRaisesRegex(ValueError, 'regular file'):
            sources.read_member(value, 'project/LICENSE')

    def test_duplicate_selected_archive_member_rejected(self):
        value = io.BytesIO()
        with tarfile.open(fileobj=value, mode='w:gz') as bundle:
            for _ in range(2):
                member = tarfile.TarInfo('LICENSE')
                member.size = len(self.license)
                bundle.addfile(member, io.BytesIO(self.license))
        with self.assertRaisesRegex(ValueError, 'one exact'):
            sources.read_member(value.getvalue(), 'LICENSE')


if __name__ == '__main__':
    unittest.main()
