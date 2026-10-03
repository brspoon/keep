"""Offline source proof must require original crypto signatures and pin binding."""
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


spec = importlib.util.spec_from_file_location('verify_source_proof',
    Path(__file__).resolve().parents[1] / 'scripts/verify_source_proof.py')
verification = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verification)


class SourceProofTests(unittest.TestCase):
    def setUp(self):
        if not shutil.which('openssl'):
            self.skipTest('OpenSSL is required for cryptographic proof verification')
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.private = self.root / 'test-key.pem'
        subprocess.run(['openssl', 'ecparam', '-name', 'prime256v1', '-genkey', '-noout',
                        '-out', str(self.private)], capture_output=True, check=True)
        self.key = subprocess.check_output(['openssl', 'ec', '-in', str(self.private), '-pubout'],
                                          stderr=subprocess.DEVNULL)
        (self.root / 'dhi-verification-key.pem').write_bytes(self.key)
        self.key_sha = hashlib.sha256(self.key).hexdigest()
        self.native = 'sha256:' + '1' * 64
        self.source = 'sha256:' + '2' * 64
        self.layout = self.root / 'dhi-source-proof-oci'
        (self.layout / 'blobs' / 'sha256').mkdir(parents=True)
        (self.layout / 'oci-layout').write_text('{"imageLayoutVersion":"1.0.0"}')
        self.base = {'schemaVersion': 2, 'manifests': [
            {'digest': self.native, 'platform': {'architecture': 'amd64', 'os': 'linux'}}]}
        base_bytes = json.dumps(self.base).encode()
        (self.root / 'pinned-base-index.json').write_bytes(base_bytes)
        self.base_digest = verification.digest(base_bytes)
        self.statement = {'_type': 'https://in-toto.io/Statement/v0.1',
                          'predicateType': verification.PREDICATE,
                          'subject': [{'digest': {'sha256': self.native.split(':')[1]}}],
                          'predicate': {'source': {'name': 'dhi/python', 'digest': self.source}}}
        self.build()

    def blob(self, body, media_type):
        key = verification.digest(body)
        (self.layout / 'blobs' / 'sha256' / key.split(':')[1]).write_bytes(body)
        return {'digest': key, 'size': len(body), 'mediaType': media_type}

    def build(self, *, signed_digest=None, tamper_payload=False, include_signature=True,
              repository='dhi.io/python', source_name='dhi/python'):
        statement_bytes = json.dumps(self.statement).encode()
        (self.root / 'dhi-source-statement-amd64.json').write_bytes(statement_bytes)
        statement_layer = self.blob(statement_bytes, 'application/vnd.in-toto+json')
        config = self.blob(b'{}', 'application/vnd.oci.empty.v1+json')
        manifest = {'schemaVersion': 2, 'artifactType': 'application/vnd.in-toto+json',
                    'subject': {'digest': self.native}, 'config': config, 'layers': [statement_layer]}
        attestation = self.blob(json.dumps(manifest).encode(), 'application/vnd.oci.image.manifest.v1+json')
        payload = {'critical': {'image': {'docker-manifest-digest': signed_digest or attestation['digest']},
                               'type': 'cosign container image signature',
                               'identity': {'docker-reference': 'registry.scout.docker.com/' + source_name}},
                   'optional': {'predicateType': verification.PREDICATE}}
        payload_bytes = json.dumps(payload).encode()
        signature = subprocess.check_output(['openssl', 'dgst', '-sha256', '-sign', str(self.private)],
                                            input=payload_bytes)
        if tamper_payload:
            payload['optional']['predicateType'] = 'changed unsigned value'
            payload_bytes = json.dumps(payload).encode()
        signed_layer = self.blob(payload_bytes, verification.PAYLOAD_TYPE)
        signed_layer['annotations'] = {'dev.cosignproject.cosign/signature': base64.b64encode(signature).decode()}
        signature_manifest = {'schemaVersion': 2, 'artifactType': verification.SIGNATURE_TYPE,
                              'subject': attestation, 'config': config, 'layers': [signed_layer]}
        signature_descriptor = self.blob(json.dumps(signature_manifest).encode(),
                                        'application/vnd.oci.image.manifest.v1+json')
        descriptors = [attestation] + ([signature_descriptor] if include_signature else [])
        (self.layout / 'index.json').write_text(json.dumps({'schemaVersion': 2, 'manifests': descriptors}))
        reference = {'attestation': repository + '@' + attestation['digest'],
                     'source': repository + '@' + self.source,
                     'native_subject': self.native.split(':')[1], 'key_sha256': self.key_sha}
        (self.root / 'dhi-source-proof-reference.json').write_text(json.dumps(reference))
        self.attestation = attestation
        self.statement_layer = statement_layer

    def verify(self):
        return verification.verify_source_proof(self.root, 'amd64',
            expected_base_digest=self.base_digest, expected_key_sha256=self.key_sha)

    def test_original_signature_and_entire_binding_chain_verify(self):
        report = self.verify()
        self.assertTrue(report['signature_verified'])
        self.assertEqual(report['source_image_digest'], self.source)
        self.assertEqual(report['native_image_digest'], self.native)
        self.assertEqual(report['attestation_digest'], self.attestation['digest'])
        self.assertEqual(len(report['signatures']), 1)
        self.assertEqual(len(report['verified_blobs']), 5)

    def test_decoded_verification_claims_cannot_replace_original_signature(self):
        self.build(include_signature=False)
        (self.root / 'dhi-source-verification-claims-amd64.json').write_text('{"verified":true}')
        with self.assertRaisesRegex(ValueError, 'No valid original Docker signature'):
            self.verify()

    def test_rehashed_payload_still_requires_valid_cryptographic_signature(self):
        self.build(tamper_payload=True)
        with self.assertRaisesRegex(ValueError, 'No valid original Docker signature'):
            self.verify()

    def test_valid_signature_for_another_attestation_is_rejected(self):
        self.build(signed_digest='sha256:' + '9' * 64)
        with self.assertRaisesRegex(ValueError, 'does not cover the source attestation'):
            self.verify()

    def test_changed_statement_blob_is_rejected_before_signature_use(self):
        path = self.layout / 'blobs' / 'sha256' / self.statement_layer['digest'].split(':')[1]
        path.write_bytes(b'tampered')
        with self.assertRaisesRegex(ValueError, 'blob digest mismatch'):
            self.verify()

    def test_standalone_statement_must_match_signed_bytes(self):
        (self.root / 'dhi-source-statement-amd64.json').write_text('{}')
        with self.assertRaisesRegex(ValueError, 'differs from signed attestation'):
            self.verify()

    def test_pinned_base_index_cannot_be_replaced(self):
        (self.root / 'pinned-base-index.json').write_text('{}')
        with self.assertRaisesRegex(ValueError, 'base-index digest mismatch'):
            self.verify()

    def test_trusted_public_key_checksum_cannot_be_changed(self):
        (self.root / 'dhi-verification-key.pem').write_bytes(self.key + b'\n')
        with self.assertRaisesRegex(ValueError, 'key checksum mismatch'):
            self.verify()

    def test_signed_statement_must_cover_pinned_native_and_source_reference(self):
        for mutation in ('native', 'source'):
            with self.subTest(mutation=mutation):
                if mutation == 'native':
                    self.statement['subject'][0]['digest']['sha256'] = '9' * 64
                else:
                    self.statement['subject'][0]['digest']['sha256'] = self.native.split(':')[1]
                    self.statement['predicate']['source']['digest'] = 'sha256:' + '9' * 64
                self.build()
                with self.assertRaises(ValueError):
                    self.verify()

    def test_descriptor_size_mismatch_is_rejected(self):
        index_path = self.layout / 'index.json'
        index = json.loads(index_path.read_text())
        index['manifests'][0]['size'] += 1
        index_path.write_text(json.dumps(index))
        with self.assertRaisesRegex(ValueError, 'descriptor size mismatch'):
            self.verify()

    def test_proof_blob_symlink_is_rejected(self):
        path = self.layout / 'blobs' / 'sha256' / self.statement_layer['digest'].split(':')[1]
        outside = self.root / 'outside'
        path.replace(outside)
        path.symlink_to(outside)
        with self.assertRaisesRegex(ValueError, 'regular file'):
            self.verify()

    def test_explicit_package_identity_preserves_default_python_rejection(self):
        self.statement['predicate']['source']['name'] = 'dhi/pkg-sample'
        self.build(repository='dhi.io/pkg-sample', source_name='dhi/pkg-sample')
        with self.assertRaisesRegex(ValueError, 'image reference'):
            self.verify()
        report = verification.verify_source_proof(self.root, 'amd64',
            expected_base_digest=self.base_digest, expected_key_sha256=self.key_sha,
            expected_repository='dhi.io/pkg-sample', expected_source_name='dhi/pkg-sample',
            expected_native_digest=self.native)
        self.assertTrue(report['signature_verified'])

    def test_native_manifest_mode_requires_exact_explicit_native_digest(self):
        native_bytes = json.dumps({'schemaVersion': 2, 'layers': []}).encode()
        self.native = verification.digest(native_bytes)
        self.base_digest = self.native
        (self.root / 'pinned-base-index.json').write_bytes(native_bytes)
        self.statement['subject'][0]['digest']['sha256'] = self.native.split(':')[1]
        self.build()
        with self.assertRaisesRegex(ValueError, 'native manifest digest is required'):
            verification.verify_source_proof(self.root, 'amd64',
                expected_base_digest=self.base_digest, expected_key_sha256=self.key_sha,
                index_is_native_manifest=True)
        report = verification.verify_source_proof(self.root, 'amd64',
            expected_base_digest=self.base_digest, expected_key_sha256=self.key_sha,
            expected_native_digest=self.native, index_is_native_manifest=True)
        self.assertTrue(report['signature_verified'])

    def build_provenance(self, *, include_signature=True, tamper_payload=False,
                         predicate='https://slsa.dev/provenance/v0.2'):
        self.statement['predicateType'] = predicate
        self.statement['predicate'] = {'materials': [
            {'uri': 'https://upstream.example/source.tar.gz', 'digest': {'sha256': '4' * 64}}]}
        self.build(repository='dhi.io/pkg-sample', source_name='dhi/pkg-sample',
                   include_signature=include_signature, tamper_payload=tamper_payload)
        (self.root / 'proof-oci').symlink_to(self.layout, target_is_directory=True)
        # The proof directory itself must be regular, just as in the collector.
        (self.root / 'proof-oci').unlink()
        shutil.copytree(self.layout, self.root / 'proof-oci')
        (self.root / 'statement.json').write_bytes((self.root / 'dhi-source-statement-amd64.json').read_bytes())
        (self.root / 'attestation-reference.json').write_text(json.dumps({
            'attestation': 'dhi.io/pkg-sample@' + self.attestation['digest'],
            'native_subject': self.native, 'predicate_type': predicate, 'key_sha256': self.key_sha}))

    def verify_provenance(self, **kwargs):
        return verification.verify_attestation_proof(self.root, 'amd64',
            expected_base_digest=self.base_digest, expected_repository='dhi.io/pkg-sample',
            expected_source_name='dhi/pkg-sample', expected_native_digest=self.native,
            expected_predicate_type='https://slsa.dev/provenance/v0.2',
            expected_key_sha256=self.key_sha, **kwargs)

    def test_signed_build_provenance_verifies_native_and_material_statement_without_source_oci_claim(self):
        self.build_provenance()
        report = self.verify_provenance()
        self.assertTrue(report['signature_verified'])
        self.assertEqual(report['native_image_digest'], self.native)
        self.assertEqual(report['predicate_type'], 'https://slsa.dev/provenance/v0.2')
        self.assertNotIn('source_image_digest', report)

    def test_build_provenance_requires_original_signature_and_untampered_payload(self):
        self.build_provenance(tamper_payload=True)
        with self.assertRaisesRegex(ValueError, 'No valid original Docker signature'):
            self.verify_provenance()

    def test_build_provenance_cannot_cover_another_native_or_predicate(self):
        self.build_provenance(predicate='https://scout.docker.com/provenance/v0.1')
        with self.assertRaisesRegex(ValueError, 'native/predicate/key'):
            self.verify_provenance()

    def test_standalone_build_materials_cannot_replace_original_signed_statement(self):
        self.build_provenance()
        (self.root / 'statement.json').write_text('{}')
        with self.assertRaisesRegex(ValueError, 'original signed statement bytes'):
            self.verify_provenance()

    def test_build_provenance_entire_retained_oci_must_pass_hash_validation(self):
        self.build_provenance()
        path = self.root / 'proof-oci/blobs/sha256' / self.statement_layer['digest'].split(':')[1]
        path.write_bytes(b'changed source checksum')
        with self.assertRaisesRegex(ValueError, 'blob digest mismatch'):
            self.verify_provenance()


if __name__ == '__main__':
    unittest.main()
