"""The Grype SQLite CPE review is exact, image-bound and evidence-gated."""
import copy
import datetime
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import review_image


FINDING = 'CVE-2026-119586'
CONFIG = 'e' * 64
ARCHES = {'amd64': 'x86_64', 'arm64': 'aarch64'}


def grype_match(arch):
    rule = json.loads((ROOT / 'docs/image-exceptions.json').read_bytes())[
        'grype_component_reviews'][FINDING]
    return {
        'vulnerability': {
            'id': FINDING, 'dataSource': 'https://nvd.nist.gov/vuln/detail/CVE-2026-119586',
            'namespace': 'nvd:cpe', 'severity': 'High',
        },
        'relatedVulnerabilities': [],
        'matchDetails': [{
            'type': 'cpe-match', 'matcher': 'apk-matcher',
            'searchedBy': {'namespace': 'nvd:cpe',
                'cpes': [rule['cpe']], 'package': {'name': 'sqlite', 'version': '3.54.1-r0'}},
            'found': {'vulnerabilityID': FINDING,
                'versionConstraint': '<= 3.54.1 (unknown)',
                'cpes': ['cpe:2.3:a:sqlite:sqlite:*:*:*:*:*:*:*:*']},
        }],
        'artifact': {
            'name': 'sqlite-libs', 'version': '3.54.1-r0', 'type': 'apk',
            'purl': rule['purl_by_arch'][arch], 'metadataType': 'ApkMetadata',
            'metadata': {'Arch': ARCHES[arch]},
            'locations': [{'path': '/lib/apk/db/installed',
                'accessPath': '/lib/apk/db/installed',
                'annotations': {'evidence': 'primary'}}],
        },
    }


class GrypeComponentPolicyTests(unittest.TestCase):
    def setUp(self):
        self.policy = json.loads((ROOT / 'docs/image-exceptions.json').read_bytes())
        self.today = datetime.date(2026, 11, 10)

    def assess(self, arch='amd64', *, match=None, day=None, inventory=None, layers=None,
               expected=CONFIG, zero=False, proof_result=None):
        self.policy['require_zero_findings'] = zero
        report = {'matches': [grype_match(arch) if match is None else match],
            'ignoredMatches': [], 'source': {'type': 'image', 'target': {
                'imageID': 'sha256:' + CONFIG, 'os': 'linux', 'architecture': arch}}}
        scout = {'runs': [{'results': []}]}
        evidence = {'success': True, 'tests': 10, 'failures': 0, 'errors': 0,
            'skipped': 0, 'arch': arch,
            'patch_manifest_sha256': self.policy['reviewed_sources']['scripts/python_security_patches.json']}
        layers = layers if layers is not None else {
            'architecture': arch, 'config_sha256': CONFIG, 'success': True, 'findings': []}
        inventory = inventory if inventory is not None else {'sqlite_cli': {'success': True}}
        proof = {'architecture': arch, 'justification': 'vulnerable_code_not_present'}
        with patch('image_distribution.validate_sqlite_cli_review', return_value=proof_result or proof) as validate:
            result = review_image.assess(report, scout, evidence, self.policy, arch,
                day or self.today, inventory=inventory, layers=layers, root=ROOT,
                expected_image_config='sha256:' + CONFIG if expected else None)
        return result, validate

    def test_exact_identity_and_both_architectures_need_bound_component_proof(self):
        for arch in ('amd64', 'arm64'):
            result, validate = self.assess(arch)
            self.assertFalse(result['blocked'])
            self.assertEqual(result['grype_not_affected'], [{
                'id': FINDING, 'package': 'sqlite-libs', 'version': '3.54.1-r0',
                'status': 'not_affected', 'justification': 'vulnerable_code_not_present',
                'component': 'sqlite-command-line-shell', 'deadline': '2026-11-18'}])
            validate.assert_called_once_with({'sqlite_cli': {'success': True}}, {
                'architecture': arch, 'config_sha256': CONFIG, 'success': True, 'findings': []},
                arch, root=ROOT, image_config_sha256=CONFIG)

    def test_changed_cpe_package_severity_purl_arch_or_location_blocks(self):
        mutations = (
            lambda m: m['vulnerability'].update(severity='Medium'),
            lambda m: m['vulnerability'].update(namespace='other'),
            lambda m: m['vulnerability'].update(dataSource='https://example.invalid'),
            lambda m: m['artifact'].update(name='sqlite'),
            lambda m: m['artifact'].update(version='3.54.1-r1'),
            lambda m: m['artifact'].update(purl='pkg:apk/alpine/sqlite-libs@3.54.1-r0'),
            lambda m: m['artifact']['metadata'].update(Arch='aarch64'),
            lambda m: m['artifact']['locations'][0].update(path='/usr/bin/sqlite3'),
            lambda m: m['matchDetails'][0]['searchedBy'].update(cpes=['cpe:unreviewed']),
            lambda m: m['matchDetails'][0]['found'].update(versionConstraint='<= 3.54.2'),
            lambda m: m['matchDetails'][0].update(matcher='other-matcher'),
            lambda m: m['matchDetails'].append(copy.deepcopy(m['matchDetails'][0])),
        )
        for mutate in mutations:
            match = grype_match('amd64')
            mutate(match)
            with self.subTest(mutation=mutate):
                result, validate = self.assess(match=match)
                self.assertEqual(result['blocked'][0]['reason'], 'component_review_mismatch')
                validate.assert_not_called()

    def test_proof_deadline_start_date_and_zero_findings_remain_enforced(self):
        result, validate = self.assess(expected=None)
        self.assertEqual(result['blocked'][0]['reason'], 'missing_component_proof')
        validate.assert_not_called()
        result, validate = self.assess(day=datetime.date(2026, 11, 9))
        self.assertEqual(result['blocked'][0]['reason'], 'component_review_not_started')
        validate.assert_not_called()
        result, validate = self.assess(day=datetime.date(2026, 11, 10))
        self.assertFalse(result['blocked'])
        validate.assert_called_once()
        result, validate = self.assess(day=datetime.date(2026, 11, 19))
        self.assertEqual(result['blocked'][0]['reason'], 'exception_expired')
        validate.assert_not_called()
        result, validate = self.assess(zero=True)
        self.assertEqual(result['blocked'][0]['reason'], 'finding_not_permitted')
        validate.assert_not_called()
        result, validate = self.assess(proof_result={'architecture': 'amd64', 'justification': 'other'})
        self.assertEqual(result['blocked'][0]['reason'], 'invalid_component_proof')

    def test_duplicate_match_and_related_cve_do_not_consume_the_approval(self):
        first = grype_match('amd64')
        report_match = [first, copy.deepcopy(first)]
        report = {'matches': report_match, 'ignoredMatches': [], 'source': {'type': 'image',
            'target': {'imageID': 'sha256:' + CONFIG, 'os': 'linux', 'architecture': 'amd64'}}}
        evidence = {'success': True, 'tests': 10, 'failures': 0, 'errors': 0,
            'skipped': 0, 'arch': 'amd64',
            'patch_manifest_sha256': self.policy['reviewed_sources']['scripts/python_security_patches.json']}
        with patch('image_distribution.validate_sqlite_cli_review', return_value={
                'architecture': 'amd64', 'justification': 'vulnerable_code_not_present'}):
            result = review_image.assess(report, {'runs': [{'results': []}]}, evidence,
                self.policy, 'amd64', self.today, inventory={},
                layers={'architecture': 'amd64', 'config_sha256': CONFIG}, root=ROOT,
                expected_image_config='sha256:' + CONFIG)
        self.assertEqual(result['blocked'][0]['reason'], 'duplicate_component_finding')
        self.assertEqual(len(result['grype_not_affected']), 1)

        first['relatedVulnerabilities'] = [{'id': 'CVE-elsewhere'}]
        result, validate = self.assess(match=first)
        self.assertEqual(result['blocked'][0]['reason'], 'component_review_mismatch')
        validate.assert_not_called()

    def test_retired_sqlite_findings_are_not_accepted_by_the_new_scope(self):
        self.assertNotIn('CVE-2026-119376', self.policy['exceptions'])
        self.assertNotIn(FINDING, self.policy['scout_component_reviews'])


if __name__ == '__main__':
    unittest.main()
