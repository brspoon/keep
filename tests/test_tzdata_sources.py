"""Version, source checksum and attribution coverage for the timezone fallback."""
import hashlib
import errno
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import urllib.error
import unittest
from unittest.mock import patch
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import source_download


spec = importlib.util.spec_from_file_location('tzdata_distribution_sources', Path(__file__).resolve().parents[1] / 'scripts/tzdata_distribution_sources.py')
review = importlib.util.module_from_spec(spec)
spec.loader.exec_module(review)


def archive(entries):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w:gz') as package:
        for name, body in entries:
            member = tarfile.TarInfo(name)
            if isinstance(body, tarfile.TarInfo):
                package.addfile(body)
            else:
                member.size = len(body)
                package.addfile(member, io.BytesIO(body))
    return stream.getvalue()


class TimezoneSourcesTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.output = Path(self.temporary.name) / 'sources'
        self.notice = b'IANA data is public domain; named BSD exceptions remain.'
        self.sources = {
            'tzcode2026d.tar.gz': archive([('version', b'2026d\n'), ('LICENSE', self.notice),
                                          ('date.c', b'BSD attribution date source'),
                                          ('newstrftime.3', b'BSD attribution manual'),
                                          ('strftime.c', b'BSD attribution strftime source')]),
            'tzdata2026d.tar.gz': archive([('version', b'2026d\n'), ('LICENSE', self.notice)]),
            'posixtz-0.5.tar.xz': archive([('posixtz-0.5/posixtz.c', b'Copyright POSIXtz authors. LGPL2 or later.')]),
        }
        self.inputs = {name: {**review.SOURCE_INPUTS[name], 'sha512': hashlib.sha512(body).hexdigest()}
                       for name, body in self.sources.items()}
        self.patches = {name: ('patch ' + name).encode() for name in review.PATCH_INPUTS}
        patch_hashes = {name: hashlib.sha512(body).hexdigest() for name, body in self.patches.items()}
        checksums = {name: row['sha512'] for name, row in self.inputs.items()} | patch_hashes
        self.apkbuild = ('pkgname=tzdata\npkgver=2026d\n_ptzver=0.5\npkgrel=0\nsha512sums="\n' +
                         '\n'.join(value + '  ' + name for name, value in checksums.items()) + '\n"\n').encode()
        entries = [(f'aports-{review.APORTS_COMMIT}/main/tzdata/APKBUILD', self.apkbuild)]
        entries += [(f'aports-{review.APORTS_COMMIT}/main/tzdata/{name}', body)
                    for name, body in self.patches.items()]
        entries.append((f'aports-{review.APORTS_COMMIT}/scripts/build.sh', b'other complete build inputs'))
        self.aports = archive(entries)
        self.recipe = ('image: dhi.io/pkg-tzdata\nvars:\n  VERSION: 2026d\n  COMMIT_SHA: ' + review.APORTS_COMMIT + '\n').encode()
        self.lgpl = b'GNU LIBRARY GENERAL PUBLIC LICENSE Version2 June1991.'
        self.lgpl_path = Path(self.temporary.name) / 'licenses' / (hashlib.sha256(self.lgpl).hexdigest() + '.txt')
        self.lgpl_path.parent.mkdir()
        self.lgpl_path.write_bytes(self.lgpl)
        overrides = {'SOURCE_INPUTS': self.inputs, 'PATCH_INPUTS': patch_hashes,
                     'APORTS_SHA256': hashlib.sha256(self.aports).hexdigest(),
                     'APKBUILD_SHA256': hashlib.sha256(self.apkbuild).hexdigest(),
                     'RECIPE_SHA256': hashlib.sha256(self.recipe).hexdigest(),
                     'LGPL_SHA256': hashlib.sha256(self.lgpl).hexdigest(),
                     'LGPL_PATH': self.lgpl_path}
        active = patch.multiple(review, **overrides)
        active.start()
        self.addCleanup(active.stop)
        self.downloads = {review.RECIPE_URL: self.recipe, review.APORTS_URL: self.aports}
        self.downloads.update({self.inputs[name]['url']: body for name, body in self.sources.items()})
        self.row = {'origin': 'tzdata', 'version': '2026d-r0',
                    'recipe': {'path': review.RECIPE_PATH, 'revision': review.RECIPE_REVISION,
                               'sha256': review.RECIPE_SHA256, 'upstream_commit': review.APORTS_COMMIT},
                    'packages': [{'name': 'tzdata', 'version': '2026d-r0', 'license': 'Public-Domain',
                                  'build_commit': 'provider-recorded-commit',
                                  'binaries': {'amd64': {'sha256': 'a' * 64, 'url': 'https://dhi.io/recorded.apk'}}}]}

    def collect(self):
        return review.collect_sources(self.row, 'amd64', self.output, fetch=self.downloads.__getitem__)

    def test_keeps_data_build_patches_and_all_license_exceptions_without_binary_fetch(self):
        result = self.collect()
        self.assertFalse(result['provider_oci_binding'])
        self.assertEqual(result['package_input']['binary_sha256'], 'a' * 64)
        self.assertEqual((self.output / 'tzdata2026d-LICENSE').read_bytes(), self.notice)
        self.assertEqual((self.output / 'posixtz-LGPL-2.0.txt').read_bytes(), self.lgpl)
        self.assertTrue((self.output / 'tzcode2026d-BSD-date.c').is_file())
        self.assertTrue((self.output / 'tzcode2026d-BSD-newstrftime.3').is_file())
        self.assertTrue((self.output / 'tzcode2026d-BSD-strftime.c').is_file())
        self.assertEqual((self.output / f'aports-{review.APORTS_COMMIT}.tar.gz').read_bytes(), self.aports)
        self.assertEqual(sum(row['role'] == 'matching-build-patch' for row in result['files']), 2)
        self.assertFalse(any(row['path'].endswith('.apk') for row in result['files']))
        self.assertNotIn('source_image_digest', result)
        lgpl_record = next(row for row in result['files'] if row['path'] == 'posixtz-LGPL-2.0.txt')
        self.assertEqual(lgpl_record['url'], review.LGPL_URL)
        self.assertEqual(lgpl_record['role'], 'upstream-lgpl-license')
        self.assertEqual(lgpl_record['acquisition'], 'verified-repository-notice')
        self.assertEqual(lgpl_record['repository_path'], 'docs/licenses/os/' + review.LGPL_SHA256 + '.txt')
        self.assertNotIn(review.LGPL_URL, self.downloads)

    def test_gnu_unavailable_does_not_block_retained_notice_collection(self):
        requested = []

        def fetch(url):
            requested.append(url)
            if url == review.LGPL_URL:
                raise urllib.error.URLError('GNU unavailable')
            return self.downloads[url]

        result = review.collect_sources(self.row, 'amd64', self.output, fetch=fetch)
        self.assertNotIn(review.LGPL_URL, requested)
        self.assertEqual((self.output / 'posixtz-LGPL-2.0.txt').read_bytes(), self.lgpl)
        lgpl_record = next(row for row in result['files'] if row['path'] == 'posixtz-LGPL-2.0.txt')
        self.assertEqual(lgpl_record['acquisition'], 'verified-repository-notice')

    def test_missing_retained_lgpl_notice_fails_without_manifest(self):
        self.lgpl_path.unlink()
        with self.assertRaisesRegex(ValueError, 'regular file'):
            self.collect()
        self.assertFalse((self.output / 'manifest.json').exists())

    def test_corrupt_retained_lgpl_notice_fails_without_manifest(self):
        self.lgpl_path.write_bytes(b'corrupt retained notice')
        with self.assertRaisesRegex(ValueError, 'GNU LGPL notice sha256 checksum mismatch'):
            self.collect()
        self.assertFalse((self.output / 'manifest.json').exists())

    def test_oversized_retained_lgpl_notice_fails_without_manifest(self):
        self.lgpl_path.write_bytes(b'x' * (128 * 1024 + 1))
        with patch.object(review, 'LGPL_SHA256', hashlib.sha256(self.lgpl_path.read_bytes()).hexdigest()):
            with self.assertRaisesRegex(ValueError, 'size limit'):
                self.collect()
        self.assertFalse((self.output / 'manifest.json').exists())

    def test_symlink_retained_lgpl_notice_fails_without_manifest(self):
        target = Path(self.temporary.name) / 'notice-target.txt'
        target.write_bytes(self.lgpl)
        self.lgpl_path.unlink()
        self.lgpl_path.symlink_to(target)
        with self.assertRaisesRegex(ValueError, 'regular file'):
            self.collect()
        self.assertFalse((self.output / 'manifest.json').exists())

    def test_rejects_download_checksum_mismatch(self):
        self.downloads[self.inputs['tzdata2026d.tar.gz']['url']] = b'tampered sources'
        with self.assertRaisesRegex(ValueError, 'sha512 checksum mismatch'):
            self.collect()
        self.assertFalse((self.output / 'manifest.json').exists())

    def test_transport_recovery_still_requires_reviewed_archive_checksum(self):
        failure = urllib.error.URLError(OSError(errno.ENETUNREACH, 'unreachable'))
        self.downloads[review.APORTS_URL] = b'unreviewed archive from alternate transport'
        with patch.object(source_download.urllib.request, 'urlopen', side_effect=failure), patch.object(source_download.time, 'sleep'), patch.object(source_download.shutil, 'which', return_value='/usr/bin/curl'), patch.object(source_download, 'download_ipv4', side_effect=lambda curl, url, **limits: self.downloads[url]) as recovery:
            with self.assertRaisesRegex(ValueError, 'Complete Alpine recipe archive sha256 checksum mismatch'):
                review.collect_sources(self.row, 'amd64', self.output)
        self.assertEqual(recovery.call_count, 2)
        self.assertFalse((self.output / 'manifest.json').exists())

    def test_verified_transport_recovery_preserves_source_collection(self):
        failure = urllib.error.URLError(OSError(errno.ENETUNREACH, 'unreachable'))
        with patch.object(source_download.urllib.request, 'urlopen', side_effect=failure), patch.object(source_download.time, 'sleep'), patch.object(source_download.shutil, 'which', return_value='/usr/bin/curl'), patch.object(source_download, 'download_ipv4', side_effect=lambda curl, url, **limits: self.downloads[url]):
            result = review.collect_sources(self.row, 'amd64', self.output)
        self.assertFalse(result['provider_oci_binding'])
        self.assertEqual((self.output / f'aports-{review.APORTS_COMMIT}.tar.gz').read_bytes(), self.aports)

    def test_rejects_wrong_iana_release_even_if_blob_checksum_is_updated(self):
        body = archive([('version', b'2026c\n'), ('LICENSE', self.notice)])
        self.downloads[self.inputs['tzdata2026d.tar.gz']['url']] = body
        self.inputs['tzdata2026d.tar.gz']['sha512'] = hashlib.sha512(body).hexdigest()
        with self.assertRaisesRegex(ValueError, 'source checksum mismatch'):
            self.collect()

    def test_rejects_modified_public_recipe(self):
        self.downloads[review.RECIPE_URL] += b'unreviewed recipe change'
        with self.assertRaisesRegex(ValueError, 'DHI timezone recipe sha256 checksum mismatch'):
            self.collect()

    def test_rejects_unreviewed_recipe_revision(self):
        self.row['recipe']['revision'] = '0' * 40
        with self.assertRaisesRegex(ValueError, 'recipe metadata mismatch'):
            self.collect()

    def test_rejects_other_installed_version_and_binary_digest(self):
        self.row['version'] = '2026c-r0'
        with self.assertRaisesRegex(ValueError, 'Fallback only covers'):
            self.collect()
        self.row['version'] = '2026d-r0'
        self.row['packages'][0]['binaries']['amd64']['sha256'] = 'not a digest'
        with self.assertRaisesRegex(ValueError, 'binary digest mismatch'):
            self.collect()

    def test_unsafe_paths_duplicate_members_and_links_are_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Unsafe timezone source'):
            review.read_member(archive([('../LICENSE', b'unsafe')]), 'LICENSE')
        with self.assertRaisesRegex(ValueError, 'exactly one'):
            review.read_member(archive([('LICENSE', b'first'), ('LICENSE', b'second')]), 'LICENSE')
        link = tarfile.TarInfo('LICENSE')
        link.type = tarfile.SYMTYPE
        link.linkname = '/etc/passwd'
        with self.assertRaisesRegex(ValueError, 'regular file'):
            review.read_member(archive([('LICENSE', link)]), 'LICENSE')

    def test_preserves_prior_bundle_by_requiring_empty_destination(self):
        self.output.mkdir()
        (self.output / 'prior-file').write_text('keep')
        with self.assertRaisesRegex(ValueError, 'empty directory'):
            self.collect()
        self.assertEqual((self.output / 'prior-file').read_text(), 'keep')


if __name__ == '__main__':
    unittest.main()
