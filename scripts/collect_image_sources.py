"""Obtain Docker-signed corresponding-source references for the pinned base.

Credentials stay in an ephemeral Docker config; no image or tag is published.
The raw statement and signature are retained with their subject digest.
"""
import argparse
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tempfile

from inspect_candidate import BASE, DIRECT, HASHES, download
from image_distribution import redacted

PREDICATE = 'https://docker.com/dhi/source/v0.1'
KEY_SHA = '1d02bbccf149283ae6288d96264dcad3fb23ee1911d90324a48eab28e4cb8a5f'


def checked_statement(raw, native):
    statement = json.loads(raw)
    if statement.get('predicateType') != PREDICATE:
        raise ValueError('Unexpected corresponding-source predicate')
    if not any(s.get('digest', {}).get('sha256') == native
               for s in statement.get('subject', [])):
        raise ValueError('Source statement does not cover the pinned native image')
    if not statement.get('predicate'):
        raise ValueError('Source statement has no corresponding-source materials')
    return statement


def source_reference(statement):
    source = statement['predicate'].get('source', {})
    if source.get('name') != 'dhi/python' or not re.fullmatch(r'sha256:[a-f0-9]{64}', source.get('digest', '')):
        raise ValueError('Unexpected or unpinned corresponding-source image')
    return 'dhi.io/python@' + source['digest']


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', default='source-materials')
    parser.add_argument('--download', action='store_true')
    args = parser.parse_args()
    arch = HASHES[platform.machine()][0]
    native, _, reg_hash, cosign_hash = DIRECT[arch]
    username = os.environ.pop('DOCKERHUB_USERNAME')
    token = os.environ.pop('DOCKERHUB_TOKEN')
    destination = Path(args.output)
    destination.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        env = {**os.environ, 'DOCKER_CONFIG': str(root / 'config')}
        for registry in ('dhi.io', 'registry.scout.docker.com'):
            subprocess.run(['docker', 'login', registry, '--username', username,
                            '--password-stdin'], input=token, text=True, env=env, check=True)
        regctl = download(root, 'regctl', f'https://github.com/regclient/regclient/releases/download/v0.11.6/regctl-linux-{arch}', reg_hash)
        cosign = download(root, 'cosign', f'https://github.com/sigstore/cosign/releases/download/v3.1.3/cosign-linux-{arch}', cosign_hash)
        key = download(root, 'dhi.pub', 'https://registry.scout.docker.com/keyring/dhi/latest.pub', KEY_SHA)
        shutil.copy2(key, destination / 'dhi-verification-key.pem')
        image = 'dhi.io/python@sha256:' + native
        raw_index = subprocess.check_output([str(regctl), 'manifest', 'get', BASE,
                                             '--format', 'raw-body'], env=env)
        if not any(m['digest'] == 'sha256:' + native
                   and m.get('platform', {}).get('architecture') == arch
                   for m in json.loads(raw_index)['manifests']):
            raise ValueError('Native source subject is outside the pinned image index')
        (destination / 'pinned-base-index.json').write_bytes(raw_index)
        provenance_reference = 'dhi.io/python@sha256:' + DIRECT[arch][1]
        provenance_claims_raw = subprocess.check_output([str(cosign), 'verify',
            provenance_reference, '--key', str(key), '--experimental-oci11',
            '--insecure-ignore-tlog=true'], env=env)
        provenance_claims = json.loads(provenance_claims_raw)
        if not provenance_claims or not all(c['critical']['image']['docker-manifest-digest']
                == 'sha256:' + DIRECT[arch][1] for c in provenance_claims):
            raise ValueError('Signature does not cover the pinned base provenance')
        provenance_raw = subprocess.check_output([str(regctl), 'artifact', 'get', provenance_reference], env=env)
        provenance = json.loads(provenance_raw)
        if provenance.get('predicateType') != 'https://slsa.dev/provenance/v1' or not any(
                s.get('digest', {}).get('sha256') == native for s in provenance.get('subject', [])):
            raise ValueError('Package provenance does not cover the pinned native image')
        (destination / 'base-provenance.json').write_bytes(provenance_raw)
        # Preserve the original signature and signed native APK-material list,
        # so the later public OpenSSL source reconstruction is replayable
        # offline rather than trusting a standalone decoded provenance file.
        base_proof = destination / 'base-build-provenance'
        base_proof.mkdir(parents=True, exist_ok=True)
        shutil.copy2(key, base_proof / 'dhi-verification-key.pem')
        (base_proof / 'pinned-base-index.json').write_bytes(raw_index)
        (base_proof / 'statement.json').write_bytes(provenance_raw)
        (base_proof / 'verification-claims.json').write_bytes(provenance_claims_raw)
        (base_proof / 'attestation-reference.json').write_text(json.dumps({
            'attestation': provenance_reference, 'native_subject': 'sha256:' + native,
            'predicate_type': 'https://slsa.dev/provenance/v1', 'key_sha256': KEY_SHA}, indent=2) + '\n')
        subprocess.run([str(regctl), 'image', 'copy', provenance_reference,
                        'ocidir://' + str((base_proof / 'proof-oci').resolve())
                        + ':provenance', '--referrers'], env=env, check=True)
        from verify_source_proof import verify_attestation_proof
        base_verified = verify_attestation_proof(base_proof, arch,
            expected_base_digest=BASE.split('@', 1)[1], expected_repository='dhi.io/python',
            expected_source_name='dhi/python', expected_native_digest='sha256:' + native,
            expected_predicate_type='https://slsa.dev/provenance/v1')
        (base_proof / 'proof-verification.json').write_text(json.dumps(base_verified, indent=2) + '\n')
        referrers = json.loads(subprocess.check_output(
            [str(regctl), 'artifact', 'list', image, '--format', 'body'], env=env))
        print(json.dumps(redacted({'base': BASE, 'native': native,
                                  'referrers': referrers}), indent=2), flush=True)
        matches = [m for m in referrers.get('manifests', [])
                   if PREDICATE in m.get('annotations', {}).values()]
        if not matches:
            raise ValueError('Pinned native image has no corresponding-source attestation')
        for descriptor in matches:
            reference = 'dhi.io/python@' + descriptor['digest']
            signatures = subprocess.check_output([str(cosign), 'verify', reference,
                '--key', str(key), '--experimental-oci11', '--insecure-ignore-tlog=true'], env=env)
            claims = json.loads(signatures)
            if not claims or not all(c['critical']['image']['docker-manifest-digest']
                                     == descriptor['digest'] for c in claims):
                raise ValueError('Signature does not cover the source attestation')
            raw = subprocess.check_output([str(regctl), 'artifact', 'get', reference], env=env)
            statement = checked_statement(raw, native)
            (destination / f'dhi-source-statement-{arch}.json').write_bytes(raw)
            (destination / f'dhi-source-verification-claims-{arch}.json').write_bytes(signatures)
            print(json.dumps(redacted(statement), indent=2), flush=True)
            if args.download:
                inventory_script = Path(__file__).with_name('image_distribution.py').resolve()
                original_inventory = subprocess.check_output(['docker', 'run', '--rm',
                    '--platform', 'linux/' + arch, '--network', 'none', '--read-only',
                    '-v', str(inventory_script) + ':/source-inventory.py:ro', BASE,
                    'python', '-B', '/source-inventory.py', '--runtime'], env=env)
                (destination / 'base-runtime-inventory.json').write_bytes(original_inventory)
                from alpine_distribution_sources import collect_sources as collect_alpine
                collect_alpine(provenance, destination, base_inventory=json.loads(original_inventory))
                subprocess.run([str(regctl), 'image', 'copy', reference,
                                'ocidir://' + str((destination / 'dhi-source-proof-oci').resolve())
                                + ':attestation', '--referrers'], env=env, check=True)
                (destination / 'dhi-source-proof-reference.json').write_text(json.dumps({
                    'attestation': reference, 'source': source_reference(statement),
                    'native_subject': native, 'key_sha256': KEY_SHA}, indent=2) + '\n')
                source = source_reference(statement)
                layout = destination / 'dhi-source-oci'
                subprocess.run([str(regctl), 'image', 'copy', source,
                                'ocidir://' + str(layout.resolve()) + ':sources'], env=env, check=True)
                from oci_source_materials import inspect_layout
                report = inspect_layout(layout, statement['predicate']['source']['digest'],
                                        destination / 'os-notices')
                (destination / f'dhi-source-inventory-{arch}.json').write_text(json.dumps(report, indent=2) + '\n')
                print(json.dumps(redacted(report), indent=2), flush=True)


if __name__ == '__main__':
    main()
