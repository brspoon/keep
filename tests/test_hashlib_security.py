"""Keep version-only CVE acceptance bound to the native vendor implementation."""
import copy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from scripts import hashlib_security_checks as probes
from scripts import runtime_dependency_checks as checks
from tests.native_dependency_fixture import dependency_report

ROOT = Path(__file__).resolve().parents[1]


class HashlibEvidenceTests(unittest.TestCase):
    def test_retained_reports_require_successful_native_boundary_checks(self):
        for arch in ('amd64', 'arm64'):
            report = dependency_report(arch)
            checks.validate_report(report, arch, ROOT)
            for value in (None, {}, {**probes.expected_report(), 'fips_cases': 11}):
                changed = copy.deepcopy(report)
                changed['hashlib_probes'] = value
                with self.subTest(arch=arch, value=value), self.assertRaises(ValueError):
                    checks.validate_report(changed, arch, ROOT)
            changed = copy.deepcopy(report)
            changed['loaded_libraries']['python_hashlib']['sha256'] = '0' * 64
            with self.subTest(arch=arch, proof='module hash'), self.assertRaises(ValueError):
                checks.validate_report(changed, arch, ROOT)

    def test_probe_rejects_secure_hashing_that_bypasses_native_properties(self):
        with patch.object(probes.subprocess, 'check_output', return_value=b'true'), \
             patch.object(probes.subprocess, 'run') as control, self.assertRaises(AssertionError):
            probes.check_hashlib()
        control.assert_not_called()

    def test_probe_rejects_blocked_explicit_nonsecurity_hashing(self):
        with patch.object(probes.subprocess, 'check_output', return_value=b'false'), \
             patch.object(probes.subprocess, 'run') as control, self.assertRaises(AssertionError):
            probes.check_hashlib()
        control.assert_not_called()

    def test_signed_package_checks_include_hashlib_on_both_architectures(self):
        from scripts import dhi_python_packages as packages
        for arch in ('amd64', 'arm64'):
            manifest = packages.build_security_manifest(arch, root=None)
            record = manifest['hashlib_extension']
            self.assertEqual(record, packages.RUNTIME_FILES[arch]['hashlib_extension'])
            self.assertTrue(record['path'].startswith('/usr/lib/python3.14/lib-dynload/_hashlib.'))
            self.assertEqual(len(record['sha256']), 64)
