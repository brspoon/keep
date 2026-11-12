import copy
import datetime
from pathlib import Path
import unittest

from scripts import build_patched_openssl as build
from scripts import review_image
from scripts.scout_exception_policy import OPENSSL_FINDINGS, finding_decision


ROOT = Path(__file__).resolve().parents[1]


class OpenSSLReviewTests(unittest.TestCase):
    def setUp(self):
        self.policy = review_image.reviewed_policy(ROOT)
        spec = build.reviewed_spec(ROOT)
        self.inventory = {}
        self.config = 'a' * 64
        self.layers = {'config_sha256': self.config}
        self.today = datetime.date(2026, 11, 12)
        for arch in ('amd64', 'arm64'):
            manifest = build.expected_manifest(arch)
            self.inventory[arch] = {'openssl_replacement': {
                'build_lock': spec, 'build_lock_sha256': build.digest(build.json_bytes(spec)),
                'manifest': manifest, 'manifest_sha256': build.digest(build.json_bytes(manifest)),
                'files': {name: {'path': '/' + name, 'sha256': checksum}
                          for name, checksum in spec['native'][arch]['files'].items()}}}

    def finding(self, identifier):
        rule = self.policy['scout_exceptions'][identifier]
        return {'id': identifier, **{name: rule[name] for name in (
            'severity', 'purl', 'affected_version', 'fixed_version')}}

    def decision(self, finding, arch='amd64', **kwargs):
        context = {'inventory': self.inventory[arch], 'layers': self.layers, 'arch': arch,
                   'root': ROOT, 'image_config_sha256': self.config}
        context.update(kwargs)
        return finding_decision(finding, self.policy, self.today, **context)

    def test_all_exact_findings_require_both_architectures_complete_native_proof(self):
        for arch in ('amd64', 'arm64'):
            for identifier in sorted(OPENSSL_FINDINGS):
                with self.subTest(arch=arch, identifier=identifier):
                    finding = self.finding(identifier)
                    self.assertIsNone(self.decision(finding, arch))
                    self.assertEqual(self.decision(finding, arch, inventory=None),
                                     'invalid_openssl_replacement_proof')
                    self.assertEqual(self.decision(finding, arch, layers=None),
                                     'missing_openssl_image_binding')

    def test_metadata_severity_and_threshold_changes_remain_blocked(self):
        finding = self.finding('CVE-2026-88822')
        for field, value in (('severity', 'LOW'), ('purl', finding['purl'].replace('-r0', '-r1')),
                             ('fixed_version', '3.5.10-r0'), ('affected_version', '<3.5.10')):
            with self.subTest(field=field):
                self.assertEqual(self.decision({**finding, field: value}), 'exception_mismatch')

    def test_changed_payload_or_receipt_cannot_reuse_the_approval(self):
        finding = self.finding('CVE-2026-95691')
        for field in ('files', 'manifest', 'manifest_sha256', 'build_lock', 'build_lock_sha256'):
            inventory = copy.deepcopy(self.inventory['amd64'])
            replacement = inventory['openssl_replacement']
            if field == 'files':
                replacement[field]['usr/lib/libcrypto.so.3']['sha256'] = '0' * 64
            elif field == 'manifest':
                replacement[field]['upstream_tests'] = False
            elif field == 'build_lock':
                replacement[field]['native']['amd64']['files']['usr/lib/libssl.so.3'] = '0' * 64
            else:
                replacement[field] = '0' * 64
            with self.subTest(field=field):
                self.assertEqual(self.decision(finding, inventory=inventory),
                                 'invalid_openssl_replacement_proof')

    def test_config_identity_and_deadline_are_not_inferred(self):
        finding = self.finding('CVE-2026-107496')
        self.assertEqual(self.decision(finding, image_config_sha256='b' * 64),
                         'missing_openssl_image_binding')
        self.today = datetime.date(2026, 11, 19)
        self.assertEqual(self.decision(finding), 'exception_expired')


if __name__ == '__main__':
    unittest.main()
