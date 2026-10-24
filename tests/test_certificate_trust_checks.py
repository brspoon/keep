import base64
import copy
import hashlib
import importlib.util
import os
from pathlib import Path
import ssl
import sys
import tempfile
from types import ModuleType
import unittest
from unittest.mock import patch

from scripts import certificate_trust_checks as checks
from scripts import dhi_certificate_packages as packages
from scripts import runtime_dependency_checks as runtime


# Public CA certificates; no network, private credentials, or local trust store
# is needed to exercise complete PEM parsing and the in-memory TLS exchange.
ROOT_PEM = """-----BEGIN CERTIFICATE-----
MIICiTCCAg+gAwIBAgIQH0evqmIAcFBUTAGem2OZKjAKBggqhkjOPQQDAzCBhTEL
MAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UE
BxMHU2FsZm9yZDEaMBgGA1UEChMRQ09NT0RPIENBIExpbWl0ZWQxKzApBgNVBAMT
IkNPTU9ETyBFQ0MgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMDgwMzA2MDAw
MDAwWhcNMzgwMTE4MjM1OTU5WjCBhTELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdy
ZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBxMHU2FsZm9yZDEaMBgGA1UEChMRQ09N
T0RPIENBIExpbWl0ZWQxKzApBgNVBAMTIkNPTU9ETyBFQ0MgQ2VydGlmaWNhdGlv
biBBdXRob3JpdHkwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAQDR3svdcmCFYX7deSR
FtSrYpn1PlILBs5BAH+X4QokPB0BBO490o0JlwzgdeT6+3eKKvUDYEs2ixYjFq0J
cfRK9ChQtP6IHG4/bC8vCVlbpVsLM5niwz2J+Wos77LTBumjQjBAMB0GA1UdDgQW
BBR1cacZSBm8nZ3qQUfflMRId5nTeTAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/
BAUwAwEB/zAKBggqhkjOPQQDAwNoADBlAjEA7wNbeqy3eApyt4jf/7VGFAkK+qDm
fQjGGoe9GKhzvSbKYAydzpmfz1wPMOG+FDHqAjAU9JM8SaczepBGR7NjfRObTrdv
GDeAU/7dIOA1mjbRxwG55tzd8/8dLDoWV9mSOdY=
-----END CERTIFICATE-----
"""
EXCLUDED_PEM = """-----BEGIN CERTIFICATE-----
MIICTjCCAdOgAwIBAgIKPPYHqWhwDtqLhDAKBggqhkjOPQQDAzBrMQswCQYDVQQG
EwJJTjETMBEGA1UECxMKZW1TaWduIFBLSTElMCMGA1UEChMcZU11ZGhyYSBUZWNo
bm9sb2dpZXMgTGltaXRlZDEgMB4GA1UEAxMXZW1TaWduIEVDQyBSb290IENBIC0g
RzMwHhcNMTgwMjE4MTgzMDAwWhcNNDMwMjE4MTgzMDAwWjBrMQswCQYDVQQGEwJJ
TjETMBEGA1UECxMKZW1TaWduIFBLSTElMCMGA1UEChMcZU11ZGhyYSBUZWNobm9s
b2dpZXMgTGltaXRlZDEgMB4GA1UEAxMXZW1TaWduIEVDQyBSb290IENBIC0gRzMw
djAQBgcqhkjOPQIBBgUrgQQAIgNiAAQjpQy4LRL1KPOxst3iAhKAnjlfSU2fySU0
WXTsuwYc58Byr+iuL+FBVIcUqEqy6HyC5ltqtdyzdc6LBtCGI79G1Y4PPwT01xyS
fvalY8L1X44uT6EYGQIrMgqCZH0Wk9GjQjBAMB0GA1UdDgQWBBR8XQKEE9TMipuB
zhccLikenEhjQjAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAKBggq
hkjOPQQDAwNpADBmAjEAvvNhzwIQHWSVB7gYboiFBS+DCBeQyh+KTOgNG3qxrdWB
CUfvO6wIBHxcmbHtRwfSAjEAnbpV/KlK6O3t5nYBQnvI+GDZjVGLVTv7jHvrZQnD
+JbNR6iC8hZVdyR+EhCVBCyj
-----END CERTIFICATE-----
"""
C1_PEM = """-----BEGIN CERTIFICATE-----
MIIDczCCAlugAwIBAgILAK7PALrEzzL4Q7IwDQYJKoZIhvcNAQELBQAwVjELMAkG
A1UEBhMCVVMxEzARBgNVBAsTCmVtU2lnbiBQS0kxFDASBgNVBAoTC2VNdWRocmEg
SW5jMRwwGgYDVQQDExNlbVNpZ24gUm9vdCBDQSAtIEMxMB4XDTE4MDIxODE4MzAw
MFoXDTQzMDIxODE4MzAwMFowVjELMAkGA1UEBhMCVVMxEzARBgNVBAsTCmVtU2ln
biBQS0kxFDASBgNVBAoTC2VNdWRocmEgSW5jMRwwGgYDVQQDExNlbVNpZ24gUm9v
dCBDQSAtIEMxMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz+upufGZ
BczYKCFK83M0UYRWEPWgTywS4/oTmifQz/l5GnRfHXk5/Fv4cI7gklL35CX5VIPZ
HdPIWoU/Xse2B+4+wM6ar6xWQio5JXDWv7V7Nq2s9nPczdcdioOl+yuQFTdrHCZH
3DspVpNqs8FqOp099cGXOFgFixwR4+S0uF2FHYP+eF8LRWgYSKVGczQ7/g/IdrvH
GPMF0Ybzhe3nudkyrVWIzqa2kbBPrH4VI5b2P/AgNBbeCsbEBEV5f6f9vtKppa+c
xSMq9zwhbL2vj07FOrLzNBL834AaSaTUqZX3noleoomslMuoaJuvimUnzYnu3Yy1
aylwQ6BpC+S5DwIDAQABo0IwQDAdBgNVHQ4EFgQU/qHgcB4qAzlSWkK+XJGFehiq
TbUwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEL
BQADggEBAMJKVvoVIXsoounlHfv4LcQ5lkFMOycsxGwYFYDGrK9HWS8mC+M2sO87
/kOXSTKZEhVb3xEp/6tT+LvBeA+snFOvV71ojD1pM/CjoCNjO2RnIkSt1XHLVip4
kqNPEjE2NuLe/gDEo2APJ62gsIq1NnpSob0n9CAnYuhNlCQT5AoE6TyrLshDCUrG
YQTlSTR+08TI9Q/Aqum6VF7zYytPT1DU/rl7mYw9wC68AivTxEDkigcxHpvOJpkT
+xHqmiIMERnHXhuBUDDIlhJu58tBf5E7oke3VIAb3ADMmpDqw8NQBmIMMMAVSKeo
WXzhriKi4gp6D/piq1JM4fHfyr6DDUI=
-----END CERTIFICATE-----
"""
C3_PEM = """-----BEGIN CERTIFICATE-----
MIICKzCCAbGgAwIBAgIKe3G2gla4EnycqDAKBggqhkjOPQQDAzBaMQswCQYDVQQG
EwJVUzETMBEGA1UECxMKZW1TaWduIFBLSTEUMBIGA1UEChMLZU11ZGhyYSBJbmMx
IDAeBgNVBAMTF2VtU2lnbiBFQ0MgUm9vdCBDQSAtIEMzMB4XDTE4MDIxODE4MzAw
MFoXDTQzMDIxODE4MzAwMFowWjELMAkGA1UEBhMCVVMxEzARBgNVBAsTCmVtU2ln
biBQS0kxFDASBgNVBAoTC2VNdWRocmEgSW5jMSAwHgYDVQQDExdlbVNpZ24gRUND
IFJvb3QgQ0EgLSBDMzB2MBAGByqGSM49AgEGBSuBBAAiA2IABP2lYa57JhAd6bci
MK4G9IGzsUJxlTm801Ljr6/58pc1kjZGDoeVjbk5Wum739D+yAdBPLtVb4Ojavti
sIGJAnB9SMVK4+kiVCJNk7tCDK93nCOmfddhEc5lx/h//vXyqaNCMEAwHQYDVR0O
BBYEFPtaSNCAIEDyqOkAB2kZd6fmw/TPMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMB
Af8EBTADAQH/MAoGCCqGSM49BAMDA2gAMGUCMQC02C8Cif22TGK6Q04ThHK1rt0c
3ta13FaPWEBaLd4gTCKDypOofu4SQMfWh0/434UCMBwUZOR8loMRnLDRWmFLpg9J
0wD8ofzkpf9/rdcw0Md3f76BB1UwUCAU9Vc4CqgxUQ==
-----END CERTIFICATE-----
"""
EXCLUDED_PEMS = ((checks.EXCLUDED_ROOT, EXCLUDED_PEM),
                 (checks.C1_ROOT, C1_PEM), (checks.C3_ROOT, C3_PEM))
ROOT_FINGERPRINT = hashlib.sha256(ssl.PEM_cert_to_DER_cert(ROOT_PEM)).hexdigest()


class PemInventoryTests(unittest.TestCase):
    def test_comments_and_whitespace_do_not_change_der_fingerprints(self):
        body = ('\n# Subject: public fixture\n' + ROOT_PEM + '\n').encode()
        self.assertEqual(checks.pem_fingerprints(body), [ROOT_FINGERPRINT])
        self.assertEqual(checks.EXCLUDED_ROOTS, {fingerprint for fingerprint, _ in EXCLUDED_PEMS})
        for fingerprint, pem in EXCLUDED_PEMS:
            with self.subTest(excluded=fingerprint):
                self.assertEqual(checks.pem_fingerprints(pem.encode()), [fingerprint])

    def test_partial_ambiguous_noncertificate_and_duplicate_pem_fail(self):
        der = ssl.PEM_cert_to_DER_cert(ROOT_PEM)
        def pem(body):
            return (b'-----BEGIN CERTIFICATE-----\n' + base64.b64encode(body)
                    + b'\n-----END CERTIFICATE-----\n')
        invalid = (b'', b'\xff', ROOT_PEM.encode().replace(b'-----END CERTIFICATE-----', b''),
                   (ROOT_PEM + ROOT_PEM).encode(), ('unreviewed\n' + ROOT_PEM).encode(),
                   ROOT_PEM.encode().replace(b'MIICiT', b'MI!CiT'),
                   ROOT_PEM.encode().replace(b'-----END CERTIFICATE-----', b'-----END PRIVATE KEY-----'),
                   pem(der + b'trailing'), pem(der[:-1]), pem(b'not an X.509 certificate'),
                   b' ' * (checks.MAX_BUNDLE_BYTES + 1))
        for body in invalid:
            with self.subTest(body=body[:50]), self.assertRaises(ValueError):
                checks.pem_fingerprints(body)

    def test_all_excluded_roots_fail_even_with_consistent_hashes_and_counts(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'bundle.pem'
            for fingerprint, pem in EXCLUDED_PEMS:
                path.write_text(ROOT_PEM + pem)
                identity = checks.bundle_identity(path)
                with self.subTest(excluded=fingerprint), self.assertRaisesRegex(ValueError, 'Excluded root'):
                    checks.validate_bundle(identity, path, identity['sha256'], 2,
                                           identity['fingerprints_sha256'], (ROOT_FINGERPRINT,))
            path.write_text(ROOT_PEM)
            identity = checks.bundle_identity(path)
            with self.assertRaisesRegex(ValueError, 'unaffected certificate roots missing'):
                checks.validate_bundle(identity, path, identity['sha256'], 1,
                                       identity['fingerprints_sha256'], ('a' * 64,))

    def test_regular_bounded_unchanging_files_are_required(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'bundle.pem'
            path.write_text(ROOT_PEM)
            self.assertEqual(checks.regular_file_bytes(path), ROOT_PEM.encode())
            alias = path.with_name('alias.pem')
            alias.symlink_to(path.name)
            for invalid in (alias, path.parent):
                with self.subTest(path=invalid), self.assertRaisesRegex(ValueError, 'regular file'):
                    checks.regular_file_bytes(invalid)
            with self.assertRaisesRegex(ValueError, 'invalid size'):
                checks.regular_file_bytes(path, 1)
            other = path.with_name('other.pem')
            other.write_text(ROOT_PEM)
            with patch.object(os, 'fstat', return_value=other.stat()), \
                 self.assertRaisesRegex(ValueError, 'changed while reading'):
                checks.regular_file_bytes(path)


class TrustQualificationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.certifi_path = self.root / 'certifi' / 'cacert.pem'
        self.system_path = self.root / 'ssl' / 'certs' / 'ca-certificates.crt'
        self.manifest_path = self.root / 'CA_CERTIFICATES_SECURITY.json'
        for path in (self.certifi_path, self.system_path):
            path.parent.mkdir(parents=True)
            path.write_text(ROOT_PEM)
        digest = hashlib.sha256(ROOT_PEM.encode()).hexdigest()
        inventory = checks.fingerprint_digest([ROOT_FINGERPRINT])
        self.start(patch.multiple(checks, CERTIFI_PATH=self.certifi_path,
            CERTIFI_SHA256=digest, CERTIFI_CERTIFICATES=1, CERTIFI_FINGERPRINTS_SHA256=inventory,
            CERTIFI_RETAINED_ROOTS=frozenset((ROOT_FINGERPRINT,)), G1_ROOT=ROOT_FINGERPRINT,
            MANIFEST_PATH=self.manifest_path))
        self.start(patch.multiple(packages, SYSTEM_BUNDLE_PATH=str(self.system_path),
            BUNDLE_SHA256=digest, BUNDLE_CERTIFICATES=1, BUNDLE_FINGERPRINTS_SHA256=inventory))
        self.manifest_path.write_bytes(checks.manifest_bytes(packages.build_security_manifest('amd64', root=None)))
        self.certifi = ModuleType('certifi')
        self.certifi.__version__ = checks.CERTIFI_VERSION
        self.certifi.where = lambda: str(self.certifi_path)
        self.adapters = ModuleType('requests.adapters')
        self.adapters.DEFAULT_CA_BUNDLE_PATH = str(self.certifi_path)
        outer = self
        class HTTPAdapter:
            def cert_verify(self, connection, url, verify, cert):
                connection.cert_reqs = 'CERT_REQUIRED'
                connection.ca_certs = outer.adapters.DEFAULT_CA_BUNDLE_PATH
        self.adapters.HTTPAdapter = HTTPAdapter
        requests = ModuleType('requests')
        requests.adapters = self.adapters
        self.start(patch.dict(sys.modules, {'certifi': self.certifi, 'requests': requests,
                                          'requests.adapters': self.adapters}))
        self.start(patch.dict(os.environ, {}, clear=True))
        paths = ssl.get_default_verify_paths()._replace(cafile=str(self.system_path),
            capath=str(self.system_path.parent), openssl_cafile=str(self.system_path),
            openssl_capath=str(self.system_path.parent))
        self.start(patch.object(ssl, 'get_default_verify_paths', return_value=paths))
        real_context = ssl.create_default_context
        def create_context(*args, **kwargs):
            if not args and not kwargs:
                return real_context(cafile=str(self.system_path))
            return real_context(*args, **kwargs)
        self.start(patch.object(ssl, 'create_default_context', side_effect=create_context))

    def start(self, patcher):
        result = patcher.start()
        self.addCleanup(patcher.stop)
        return result

    def qualify(self, handshake=runtime.memory_tls_handshake):
        return checks.qualify_trust('amd64', runtime.TLS_CERTIFICATE,
                                    runtime.TLS_PRIVATE_KEY, handshake)

    def test_real_tls_exchanges_and_both_certificate_rejections_pass(self):
        report = self.qualify()
        self.assertEqual(report['tls_probes'], checks.TLS_PROBES)
        self.assertEqual(report['tests'], 8)
        self.assertTrue(report['success'])
        self.assertEqual(checks.validate_trust_report(report, 'amd64'), report)
        self.assertEqual(report['system']['fingerprints'], [ROOT_FINGERPRINT])
        self.assertEqual(report['capath']['entries'], 0)

    def test_each_ca_environment_override_is_rejected_even_when_empty(self):
        for variable in checks.OVERRIDE_VARIABLES:
            with self.subTest(variable=variable), patch.dict(os.environ, {variable: ''}), \
                 self.assertRaisesRegex(ValueError, 'CA environment overrides'):
                self.qualify()

    def test_exact_inherited_default_ca_file_is_recorded_and_revalidated(self):
        expected = {'SSL_CERT_FILE': str(self.system_path)}
        with patch.dict(os.environ, expected):
            report = self.qualify()
        self.assertEqual(report['ca_environment'], expected)
        self.assertEqual(checks.validate_trust_report(report, 'amd64'), report)
        for variable, value in (
            ('SSL_CERT_FILE', str(self.system_path.with_name('old.pem'))),
            ('SSL_CERT_DIR', str(self.system_path.parent)),
            ('REQUESTS_CA_BUNDLE', str(self.certifi_path)),
            ('CURL_CA_BUNDLE', str(self.certifi_path)),
        ):
            bad = {**expected, variable: value}
            with self.subTest(environment=bad):
                with patch.dict(os.environ, bad), self.assertRaisesRegex(ValueError, 'CA environment overrides'):
                    self.qualify()
                with self.assertRaisesRegex(ValueError, 'CA environment overrides'):
                    checks.validate_trust_report({**report, 'ca_environment': bad}, 'amd64')

    def test_wrong_certifi_version_requests_path_and_adapter_verification_fail(self):
        self.certifi.__version__ = '2026.7.22'
        with self.assertRaisesRegex(ValueError, 'certifi version'):
            self.qualify()
        self.certifi.__version__ = checks.CERTIFI_VERSION
        wrong = self.certifi_path.with_name('copy.pem')
        wrong.write_text(ROOT_PEM)
        self.adapters.DEFAULT_CA_BUNDLE_PATH = str(wrong)
        with self.assertRaisesRegex(ValueError, 'reviewed certifi path'):
            self.qualify()
        self.adapters.DEFAULT_CA_BUNDLE_PATH = str(self.certifi_path)
        with patch.object(self.adapters.HTTPAdapter, 'cert_verify',
                          side_effect=lambda connection, *args: setattr(connection, 'cert_reqs', 'CERT_NONE')):
            with self.assertRaisesRegex(ValueError, 'default adapter'):
                self.qualify()
        self.certifi.where = lambda: str(wrong)
        with self.assertRaisesRegex(ValueError, 'reviewed certifi path'):
            self.qualify()

    def test_same_roots_with_modified_bytes_and_changed_root_bundle_fail(self):
        for path in (self.certifi_path, self.system_path):
            for body in (ROOT_PEM + '\n# modified bundle\n',
                         *(ROOT_PEM + pem for _, pem in EXCLUDED_PEMS)):
                with self.subTest(path=path, sha256=hashlib.sha256(body.encode()).hexdigest()):
                    path.write_text(body)
                    with self.assertRaisesRegex(ValueError, 'root inventory'):
                        self.qualify()
            path.write_text(ROOT_PEM)

    def test_install_record_requires_original_regular_file_bytes(self):
        original = self.manifest_path.read_bytes()
        self.manifest_path.write_bytes(original + b' ')
        with self.assertRaisesRegex(ValueError, 'exact signed package'):
            self.qualify()
        self.manifest_path.unlink()
        target = self.manifest_path.with_name('copy.json')
        target.write_bytes(original)
        self.manifest_path.symlink_to(target.name)
        with self.assertRaisesRegex(ValueError, 'regular file'):
            self.qualify()

    def test_active_default_context_must_match_exact_system_inventory(self):
        with patch.object(checks, 'context_fingerprints', return_value=[ROOT_FINGERPRINT, checks.EXCLUDED_ROOT]):
            with self.assertRaisesRegex(ValueError, 'Active requests TLS root inventory'):
                self.qualify()
        paths = ssl.get_default_verify_paths()._replace(cafile=str(self.certifi_path))
        with patch.object(ssl, 'get_default_verify_paths', return_value=paths):
            with self.assertRaisesRegex(ValueError, 'Default SMTP CA file'):
                self.qualify()

    def test_all_excluded_roots_in_effective_requests_and_smtp_stores_fail(self):
        for backend in ('requests', 'smtp'):
            for fingerprint, pem in EXCLUDED_PEMS:
                def create_context(*args, **kwargs):
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    context.load_verify_locations(cadata=ROOT_PEM)
                    if ('requests' if kwargs else 'smtp') == backend:
                        context.load_verify_locations(cadata=pem)
                    return context
                with self.subTest(backend=backend, excluded=fingerprint), \
                     patch.object(ssl, 'create_default_context', side_effect=create_context), \
                     self.assertRaisesRegex(ValueError, 'TLS context contains an excluded root'):
                    self.qualify()

    def test_all_excluded_lazy_capath_roots_fail_even_if_the_bundle_includes_them(self):
        hashed = self.system_path.with_name('01234567.0')
        for fingerprint, pem in EXCLUDED_PEMS:
            self.system_path.write_text(ROOT_PEM + pem)
            hashed.write_text(pem)
            bundle = checks.bundle_identity(self.system_path)
            with self.subTest(excluded=fingerprint), self.assertRaisesRegex(ValueError, 'unreviewed root'):
                checks.capath_inventory(self.system_path.parent, bundle)

    def test_lazy_capath_roots_are_inspected_and_broken_or_unreadable_entries_fail(self):
        hashed = self.system_path.with_name('01234567.0')
        hashed.write_text(ROOT_PEM)
        report = self.qualify()
        self.assertEqual(report['capath']['entries'], 1)
        self.assertEqual(report['capath']['fingerprints'], [ROOT_FINGERPRINT])
        for fingerprint, pem in EXCLUDED_PEMS:
            hashed.write_text(pem)
            with self.subTest(excluded=fingerprint), self.assertRaisesRegex(ValueError, 'unreviewed root'):
                self.qualify()
        hashed.unlink()
        hashed.symlink_to('missing.pem')
        with self.assertRaises(FileNotFoundError):
            self.qualify()
        hashed.unlink()
        hashed.write_text(ROOT_PEM)
        read = checks.regular_file_bytes
        def checked_read(path, *args):
            if Path(path) == hashed:
                raise PermissionError('unreadable hashed root')
            return read(path, *args)
        with patch.object(checks, 'regular_file_bytes', side_effect=checked_read), \
             self.assertRaises(PermissionError):
            self.qualify()

    def test_bypassed_handshake_unexpected_tls_error_and_disabled_verification_fail(self):
        with self.assertRaises(ValueError):
            self.qualify(lambda *args: None)
        with self.assertRaises(ssl.SSLError):
            self.qualify(lambda *args: (_ for _ in ()).throw(ssl.SSLError('unrelated TLS failure')))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with patch.object(ssl, 'create_default_context', return_value=context), \
             self.assertRaisesRegex(ValueError, 'certificate and hostname verification'):
            self.qualify()

    def test_retained_proof_rejects_missing_failed_or_modified_fields(self):
        report = self.qualify()
        invalid = [None, {}, {**report, 'extra': True}]
        for field, value in (('schema', True), ('arch', 'arm64'), ('success', False),
                             ('tests', 7), ('failures', 1), ('errors', ['failed']),
                             ('certifi_version', '2026.7.22'), ('tls_probes', {}),
                             ('ca_environment', None),
                             ('default_root_inventories', {}),
                             ('source_manifest_sha256', 'a' * 64),
                             ('install_manifest_sha256', 'a' * 64)):
            invalid.append({**report, field: value})
        for bundle in ('certifi', 'system'):
            for field, value in (('sha256', 'a' * 64), ('path', '/wrong/bundle.pem'),
                                 ('certificates', True), ('fingerprints', []),
                                 ('fingerprints_sha256', 'a' * 64)):
                changed = copy.deepcopy(report)
                changed[bundle][field] = value
                invalid.append(changed)
        for probe in checks.TLS_PROBES:
            changed = copy.deepcopy(report)
            changed['tls_probes'][probe] = 1
            invalid.append(changed)
        for field, value in (('entries', True), ('path', '/other/directory'),
                             ('certificates', 1), ('fingerprints', [checks.EXCLUDED_ROOT]),
                             ('fingerprints_sha256', 'a' * 64)):
            changed = copy.deepcopy(report)
            changed['capath'][field] = value
            invalid.append(changed)
        for changed in invalid:
            with self.subTest(report=changed), self.assertRaises(ValueError):
                checks.validate_trust_report(changed, 'amd64')

    def test_retained_proof_rejects_each_excluded_capath_root_with_consistent_metadata(self):
        report = self.qualify()
        for fingerprint, _ in EXCLUDED_PEMS:
            changed = copy.deepcopy(report)
            changed['capath'].update(entries=1, certificates=1, fingerprints=[fingerprint],
                fingerprints_sha256=checks.fingerprint_digest([fingerprint]))
            with self.subTest(excluded=fingerprint), self.assertRaisesRegex(ValueError, 'hashed certificate inventory'):
                checks.validate_trust_report(changed, 'amd64')

    def test_module_import_and_retained_replay_need_no_tls_or_application_imports(self):
        report = self.qualify()
        real_import = __import__
        def portable_import(name, *args, **kwargs):
            if name.split('.')[0] in ('ssl', 'certifi', 'requests'):
                raise AssertionError('runtime-only dependency imported: ' + name)
            return real_import(name, *args, **kwargs)
        with patch('builtins.__import__', side_effect=portable_import):
            spec = importlib.util.spec_from_file_location('portable_ca_checks', checks.__file__)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            self.assertEqual(checks.validate_trust_report(report, 'amd64'), report)


class ReviewedTrustReportTests(unittest.TestCase):
    def test_both_architectures_bind_the_full_reviewed_public_root_inventories(self):
        from tests.certificate_trust_fixture import trust_report

        for arch in ('amd64', 'arm64'):
            with self.subTest(arch=arch):
                report = trust_report(arch)
                self.assertEqual(checks.validate_trust_report(report, arch), report)
                self.assertFalse(checks.EXCLUDED_ROOTS.intersection(report['certifi']['fingerprints']))
                self.assertFalse(checks.EXCLUDED_ROOTS.intersection(report['system']['fingerprints']))
                self.assertEqual(checks.CERTIFI_RETAINED_ROOTS, {checks.G1_ROOT})
                self.assertTrue(checks.CERTIFI_RETAINED_ROOTS <= set(report['certifi']['fingerprints']))
                self.assertIn(checks.G1_ROOT, report['system']['fingerprints'])


if __name__ == '__main__':
    unittest.main()
