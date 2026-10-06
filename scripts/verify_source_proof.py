#!/usr/bin/env python3
"""Verify retained Docker source-image proof completely offline.

Trust anchors are the reviewed Docker public-key checksum and pinned runtime
image-index digest. OpenSSL verifies the original Cosign signing payload; its
signed attestation digest then binds the native image and corresponding source.
This verifies Docker's signature, not Rekor transparency-log inclusion.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile


BASE_DIGEST = 'sha256:b945ad65f9dcea58d20d119a7a7d650517cb9d27ad26031ac5a6d3ceeaa972f7'
KEY_SHA256 = '1d02bbccf149283ae6288d96264dcad3fb23ee1911d90324a48eab28e4cb8a5f'
PREDICATE = 'https://docker.com/dhi/source/v0.1'
SIGNATURE_TYPE = 'application/vnd.dev.cosign.artifact.sig.v1+json'
PAYLOAD_TYPE = 'application/vnd.dev.cosign.simplesigning.v1+json'
INDEX_TYPES = {'application/vnd.oci.image.index.v1+json',
               'application/vnd.docker.distribution.manifest.list.v2+json'}
MANIFEST_TYPES = {'application/vnd.oci.image.manifest.v1+json',
                  'application/vnd.docker.distribution.manifest.v2+json'}


def digest(body):
    return 'sha256:' + hashlib.sha256(body).hexdigest()


def source_reference(value, repository='dhi.io/python'):
    if (not isinstance(value, str)
            or not re.fullmatch(re.escape(repository) + r'@sha256:[a-f0-9]{64}', value)):
        raise ValueError('Unexpected source-proof image reference')
    return value.split('@', 1)[1]


def read_regular(path, limit=16 * 1024 * 1024):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError('Proof input must be a regular file')
    if path.stat().st_size > limit:
        raise ValueError('Proof input exceeds size limit')
    return path.read_bytes()


class ProofLayout:
    """Check all content-addressed descendants before using any proof data."""
    def __init__(self, root):
        self.root = Path(root)
        self.blobs = {}
        self.manifests = {}
        self.visited = set()

    def blob(self, descriptor):
        key = descriptor.get('digest')
        size = descriptor.get('size')
        if not isinstance(key, str) or not re.fullmatch(r'sha256:[a-f0-9]{64}', key):
            raise ValueError('Malformed proof OCI digest')
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise ValueError('Malformed proof OCI size')
        if key not in self.blobs:
            path = self.root / 'blobs' / 'sha256' / key.split(':', 1)[1]
            if any(p.is_symlink() for p in (self.root, self.root / 'blobs', path.parent)):
                raise ValueError('Proof OCI path must not contain symlinks')
            body = read_regular(path)
            if digest(body) != key:
                raise ValueError('Proof OCI blob digest mismatch')
            self.blobs[key] = body
        body = self.blobs[key]
        if len(body) != size:
            raise ValueError('Proof OCI descriptor size mismatch')
        return body

    def walk(self, descriptor):
        body = self.blob(descriptor)
        key = descriptor['digest']
        if key in self.visited:
            return
        media_type = descriptor.get('mediaType')
        if media_type not in INDEX_TYPES | MANIFEST_TYPES:
            raise ValueError('Unsupported proof OCI manifest type')
        manifest = json.loads(body)
        if manifest.get('schemaVersion') != 2:
            raise ValueError('Malformed proof OCI manifest')
        self.visited.add(key)
        self.manifests[key] = manifest
        if media_type in INDEX_TYPES:
            for child in manifest.get('manifests', []):
                self.walk(child)
        else:
            if manifest.get('config') is not None:
                self.blob(manifest['config'])
            for layer in manifest.get('layers', []):
                self.blob(layer)

    def verify(self):
        marker = json.loads(read_regular(self.root / 'oci-layout'))
        if marker.get('imageLayoutVersion') != '1.0.0':
            raise ValueError('Unsupported proof OCI layout')
        index = json.loads(read_regular(self.root / 'index.json'))
        if index.get('schemaVersion') != 2 or not index.get('manifests'):
            raise ValueError('Malformed proof OCI index')
        for descriptor in index['manifests']:
            self.walk(descriptor)
        return self


def check_signature(key, payload, signature):
    """Verify only fixed OpenSSL arguments and the already checked input bytes."""
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        public_key = root / 'public.pem'
        signature_file = root / 'signature.der'
        public_key.write_bytes(key)
        signature_file.write_bytes(signature)
        result = subprocess.run(['openssl', 'dgst', '-sha256', '-verify', str(public_key),
                                 '-signature', str(signature_file)], input=payload,
                                capture_output=True, check=False)
    return result.returncode == 0


def verify_attestation_proof(materials_dir, architecture, *, expected_base_digest,
                             expected_repository, expected_source_name,
                             expected_native_digest, expected_predicate_type,
                             index_is_native_manifest=False, expected_key_sha256=KEY_SHA256):
    """Verify original package build provenance without inventing a source OCI.

    This proof is bound to the native package-output digest. The caller must
    separately prove the output contains the exact installed APK bytes, then
    acquire the build inputs identified in the verified statement.
    """
    if architecture not in {'amd64', 'arm64'}:
        raise ValueError('Unsupported attestation-proof architecture')
    root = Path(materials_dir)
    if root.is_symlink():
        raise ValueError('Attestation-proof directory must not be a symlink')
    key = read_regular(root / 'dhi-verification-key.pem', 16384)
    if hashlib.sha256(key).hexdigest() != expected_key_sha256:
        raise ValueError('DHI verification key checksum mismatch')
    raw_index = read_regular(root / 'pinned-base-index.json')
    if digest(raw_index) != expected_base_digest:
        raise ValueError('Pinned package-index digest mismatch')
    index = json.loads(raw_index)
    if index_is_native_manifest:
        if (index.get('schemaVersion') != 2 or 'layers' not in index
                or expected_base_digest != expected_native_digest):
            raise ValueError('Reviewed native package manifest digest is required')
    else:
        natives = [row for row in index.get('manifests', [])
                   if row.get('platform', {}).get('os') == 'linux'
                   and row.get('platform', {}).get('architecture') == architecture]
        if (index.get('schemaVersion') != 2 or len(natives) != 1
                or natives[0].get('digest') != expected_native_digest):
            raise ValueError('Provenance native subject differs from reviewed package index')
    if not re.fullmatch(r'sha256:[a-f0-9]{64}', expected_native_digest):
        raise ValueError('Malformed reviewed package-output native digest')
    references = json.loads(read_regular(root / 'attestation-reference.json'))
    attestation_digest = source_reference(references['attestation'], expected_repository)
    if (references.get('native_subject') != expected_native_digest
            or references.get('predicate_type') != expected_predicate_type
            or references.get('key_sha256') != expected_key_sha256):
        raise ValueError('Provenance reference differs from reviewed native/predicate/key')
    proof = ProofLayout(root / 'proof-oci').verify()
    attestation = proof.manifests.get(attestation_digest)
    if (not attestation or attestation.get('artifactType') != 'application/vnd.in-toto+json'
            or attestation.get('subject', {}).get('digest') != expected_native_digest):
        raise ValueError('Retained provenance is not bound to reviewed native package output')
    layers = attestation.get('layers', [])
    if len(layers) != 1 or layers[0].get('mediaType') != 'application/vnd.in-toto+json':
        raise ValueError('Build provenance must contain one original statement')
    raw_statement = proof.blob(layers[0])
    if raw_statement != read_regular(root / 'statement.json'):
        raise ValueError('Retained provenance differs from original signed statement bytes')
    statement = json.loads(raw_statement)
    subjects = statement.get('subject', [])
    if (statement.get('_type') != 'https://in-toto.io/Statement/v0.1'
            or statement.get('predicateType') != expected_predicate_type or not subjects
            or any(row.get('digest', {}).get('sha256') != expected_native_digest.split(':', 1)[1]
                   for row in subjects)):
        raise ValueError('Build provenance does not cover the exact reviewed native output')
    allowed_identities = {'registry.scout.docker.com/' + expected_source_name,
                          'index.docker.io/' + expected_source_name}
    signatures = []
    for manifest_digest, manifest in sorted(proof.manifests.items()):
        if (manifest.get('artifactType') != SIGNATURE_TYPE
                or manifest.get('subject', {}).get('digest') != attestation_digest):
            continue
        for layer in manifest.get('layers', []):
            encoded = layer.get('annotations', {}).get('dev.cosignproject.cosign/signature')
            if layer.get('mediaType') != PAYLOAD_TYPE or not isinstance(encoded, str):
                continue
            payload = proof.blob(layer)
            try:
                signature = base64.b64decode(encoded, validate=True)
            except ValueError:
                continue
            if not signature or len(signature) > 2048 or not check_signature(key, payload, signature):
                continue
            critical = json.loads(payload).get('critical', {})
            if (critical.get('image', {}).get('docker-manifest-digest') != attestation_digest
                    or critical.get('type') != 'cosign container image signature'
                    or critical.get('identity', {}).get('docker-reference') not in allowed_identities):
                raise ValueError('Verified Docker signature does not cover reviewed package provenance')
            signatures.append({'manifest_digest': manifest_digest, 'payload_digest': layer['digest']})
    if not signatures:
        raise ValueError('No valid original Docker signature for package build provenance')
    return {'format': 'keep-package-build-provenance-proof-v1', 'signature_verified': True,
            'architecture': architecture, 'base_index_digest': expected_base_digest,
            'native_image_digest': expected_native_digest, 'key_sha256': expected_key_sha256,
            'attestation_digest': attestation_digest, 'statement_digest': digest(raw_statement),
            'predicate_type': expected_predicate_type, 'signatures': signatures,
            'verified_blobs': [{'digest': name, 'bytes': len(body)}
                               for name, body in sorted(proof.blobs.items())],
            'limitations': 'Docker-key signature verified offline; no Rekor inclusion or source-image attestation is claimed.'}


def verify_source_proof(materials_dir, architecture, *,
                        expected_base_digest=BASE_DIGEST, expected_key_sha256=KEY_SHA256,
                        expected_repository='dhi.io/python', expected_source_name='dhi/python',
                        expected_native_digest=None, index_is_native_manifest=False):
    """Verify the pinned key/index, original signature and retained statement.

    The keyword trust-anchor overrides support explicitly reviewed package
    images and synthetic tests. A package output containing the reviewed APK
    bytes can supply its resolved index/native digest; the original Docker key
    remains pinned. The CLI always uses the Python image's reviewed anchors.
    """
    if architecture not in {'amd64', 'arm64'}:
        raise ValueError('Unsupported source-proof architecture')
    root = Path(materials_dir)
    if root.is_symlink():
        raise ValueError('Source-proof directory must not be a symlink')
    key = read_regular(root / 'dhi-verification-key.pem', 16384)
    if hashlib.sha256(key).hexdigest() != expected_key_sha256:
        raise ValueError('DHI verification key checksum mismatch')
    base_bytes = read_regular(root / 'pinned-base-index.json')
    if digest(base_bytes) != expected_base_digest:
        raise ValueError('Pinned base-index digest mismatch')
    index = json.loads(base_bytes)
    if index_is_native_manifest:
        if (index.get('schemaVersion') != 2 or 'layers' not in index
                or not expected_native_digest or expected_base_digest != expected_native_digest):
            raise ValueError('Reviewed native manifest digest is required')
        native = expected_native_digest
    else:
        natives = [descriptor for descriptor in index.get('manifests', [])
                   if descriptor.get('platform', {}).get('architecture') == architecture
                   and descriptor.get('platform', {}).get('os') == 'linux']
        if index.get('schemaVersion') != 2 or len(natives) != 1:
            raise ValueError('Pinned base index has no unique native image')
        native = natives[0]['digest']
        if expected_native_digest is not None and expected_native_digest != native:
            raise ValueError('Package native image differs from reviewed native digest')
    if not re.fullmatch(r'sha256:[a-f0-9]{64}', native):
        raise ValueError('Malformed pinned native-image digest')
    references = json.loads(read_regular(root / 'dhi-source-proof-reference.json'))
    attestation_digest = source_reference(references['attestation'], expected_repository)
    expected_source = source_reference(references['source'], expected_repository)
    if (references.get('native_subject') != native.split(':', 1)[1]
            or references.get('key_sha256') != expected_key_sha256):
        raise ValueError('Proof reference does not match reviewed native image/key')
    proof = ProofLayout(root / 'dhi-source-proof-oci').verify()
    attestation = proof.manifests.get(attestation_digest)
    if (not attestation or attestation.get('artifactType') != 'application/vnd.in-toto+json'
            or attestation.get('subject', {}).get('digest') != native):
        raise ValueError('Retained attestation is not bound to the pinned native image')
    layers = attestation.get('layers', [])
    if len(layers) != 1 or layers[0].get('mediaType') != 'application/vnd.in-toto+json':
        raise ValueError('Source attestation must contain one original statement')
    raw_statement = proof.blob(layers[0])
    retained_statement = read_regular(root / f'dhi-source-statement-{architecture}.json')
    if raw_statement != retained_statement:
        raise ValueError('Retained statement differs from signed attestation bytes')
    statement = json.loads(raw_statement)
    subjects = statement.get('subject', [])
    if (statement.get('_type') != 'https://in-toto.io/Statement/v0.1'
            or statement.get('predicateType') != PREDICATE or not subjects
            or any(s.get('digest', {}).get('sha256') != native.split(':', 1)[1] for s in subjects)):
        raise ValueError('Source statement does not cover the pinned native image')
    source = statement.get('predicate', {}).get('source', {})
    if source.get('name') != expected_source_name or source.get('digest') != expected_source:
        raise ValueError('Source statement disagrees with retained source-image reference')
    verified_signatures = []
    for manifest_digest, manifest in sorted(proof.manifests.items()):
        if (manifest.get('artifactType') != SIGNATURE_TYPE
                or manifest.get('subject', {}).get('digest') != attestation_digest):
            continue
        for layer in manifest.get('layers', []):
            signature_text = layer.get('annotations', {}).get('dev.cosignproject.cosign/signature')
            if layer.get('mediaType') != PAYLOAD_TYPE or not isinstance(signature_text, str):
                continue
            payload = proof.blob(layer)
            try:
                signature = base64.b64decode(signature_text, validate=True)
            except ValueError:
                continue
            if not signature or len(signature) > 2048 or not check_signature(key, payload, signature):
                continue
            claims = json.loads(payload)
            critical = claims.get('critical', {})
            if (critical.get('image', {}).get('docker-manifest-digest') != attestation_digest
                    or critical.get('type') != 'cosign container image signature'
                    or critical.get('identity', {}).get('docker-reference')
                       != 'registry.scout.docker.com/' + expected_source_name):
                raise ValueError('Verified signature does not cover the source attestation')
            verified_signatures.append({'manifest_digest': manifest_digest,
                                        'payload_digest': layer['digest']})
    if not verified_signatures:
        raise ValueError('No valid original Docker signature for the source attestation')
    return {'format': 'keep-source-proof-verification-v1', 'signature_verified': True,
            'architecture': architecture, 'base_index_digest': expected_base_digest,
            'native_image_digest': native, 'key_sha256': expected_key_sha256,
            'attestation_digest': attestation_digest, 'source_image_digest': expected_source,
            'statement_digest': digest(raw_statement), 'signatures': verified_signatures,
            'verified_blobs': [{'digest': name, 'bytes': len(body)}
                               for name, body in sorted(proof.blobs.items())],
            'limitations': 'Original Docker-key signature verified offline; Rekor transparency inclusion is not checked.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--materials', required=True)
    parser.add_argument('--architecture', choices=('amd64', 'arm64'), required=True)
    args = parser.parse_args()
    print(json.dumps(verify_source_proof(args.materials, args.architecture), indent=2))


if __name__ == '__main__':
    main()
