"""Read-only Scout scan and verified vendor provenance capture for the runtime."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import tarfile
import tempfile
import urllib.request

BASE = 'dhi.io/python@sha256:7b9528fefc51c9d3753ccd25dcf1dea9dd327e7c2f8bef89cd2cf3b34f847408'
HASHES = {
    'x86_64': ('amd64', 'f4e2814bd61040365153d5b964b144cb2dc6ee536a68b5bac4cadf00fc0ec34b'),
    'aarch64': ('arm64', '8b21594c72d4d9403a82a49e9dbdfc04c27c6a21933906f1eefbb0beabe22d58'),
}


DIRECT = {
    'amd64': ('b1f35cef0a3f43c7f377e75de003da89f0a8518ddc3805a5f94db9bd460246f1', '391d5d138a4b0755bc4e451a2cc9c76f2aadf01625da07a0f9170cbd6d9c88e5', '8e0e62a497fcdb8048d18aa927a139613176ba0531f412bc541044e28f9856bd', '4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71'),
    'arm64': ('f38997c3b22744780d20cf7749649535d63fc9a167def975af9d4c1eb4aab605', 'cf5fa207964ed6140f88db8e6720fc43a154a6172644d16c66a8faf3da1371c7', 'a9b71a3ee79b2d1dbbd7d51fd5e8fa214722c192864235d3d8764463c751a1ff', 'c5d324e091826b0d7a78eb16fef316450b4eb9aaec045611c08ba06f5e73220a'),
}


def download(root, name, url, checksum):
    with urllib.request.urlopen(url, timeout=60) as response:
        body = response.read()
    if hashlib.sha256(body).hexdigest() != checksum:
        raise RuntimeError(f'{name} checksum mismatch')
    path = root / name
    path.write_bytes(body)
    path.chmod(0o700)
    return path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--scan-only", action="store_true")
    parser.add_argument("--image", default="keep-ci")
    parser.add_argument("--prefix", default="candidate")
    args = parser.parse_args()
    arch, checksum = HASHES[platform.machine()]
    username = os.environ.pop('DOCKERHUB_USERNAME')
    token = os.environ.pop('DOCKERHUB_TOKEN')
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        archive = root / 'scout.tar.gz'
        url = f'https://github.com/docker/scout-cli/releases/download/v1.24.0/docker-scout_1.24.0_linux_{arch}.tar.gz'
        with urllib.request.urlopen(url, timeout=60) as response:
            archive.write_bytes(response.read())
        if hashlib.sha256(archive.read_bytes()).hexdigest() != checksum:
            raise RuntimeError('Scout download checksum mismatch')
        with tarfile.open(archive) as package:
            member = next(m for m in package.getmembers() if Path(m.name).name == 'docker-scout' and m.isfile())
            binary = root / 'docker-scout'
            binary.write_bytes(package.extractfile(member).read())
            binary.chmod(0o700)
        env = {**os.environ, 'DOCKER_CONFIG': str(root / 'config')}
        for registry in ('dhi.io', 'docker.io', 'registry.scout.docker.com'):
            subprocess.run(['docker', 'login', registry, '--username', username, '--password-stdin'], input=token, text=True, env=env, check=True)
        if not args.scan_only:
            # Verify the original OCI attestation directly: Scout 1.24.0 crashes
            # in VEXExportProcessor even after successful signature verification.
            # Docker documents key verification without Rekor for private attestations:
            # https://docs.docker.com/dhi/how-to/verify/
            native, attestation, reg_hash, cosign_hash = DIRECT[arch]
            regctl = download(root, 'regctl', f'https://github.com/regclient/regclient/releases/download/v0.11.6/regctl-linux-{arch}', reg_hash)
            cosign = download(root, 'cosign', f'https://github.com/sigstore/cosign/releases/download/v3.1.3/cosign-linux-{arch}', cosign_hash)
            key = download(root, 'dhi.pub', 'https://registry.scout.docker.com/keyring/dhi/latest.pub', '1d02bbccf149283ae6288d96264dcad3fb23ee1911d90324a48eab28e4cb8a5f')
            index = json.loads(subprocess.check_output([str(regctl), 'manifest', 'get', BASE, '--format', 'raw-body'], env=env))
            if not any(m['digest'] == 'sha256:' + native and m.get('platform', {}).get('architecture') == arch for m in index['manifests']):
                raise RuntimeError('Native image does not belong to the pinned image index')
            reference = 'dhi.io/python@sha256:' + attestation
            signatures = subprocess.check_output([str(cosign), 'verify', reference, '--key', str(key), '--experimental-oci11', '--insecure-ignore-tlog=true'], env=env)
            claims = json.loads(signatures)
            if not claims or not all(c['critical']['image']['docker-manifest-digest'] == 'sha256:' + attestation for c in claims):
                raise RuntimeError('Signature does not cover the pinned attestation')
            Path(f'candidate-signature-{arch}.json').write_bytes(signatures)
            raw = subprocess.check_output([str(regctl), 'artifact', 'get', reference], env=env)
            statement = json.loads(raw)
            if statement.get('predicateType') != 'https://slsa.dev/provenance/v1' or not any(s.get('digest', {}).get('sha256') == native for s in statement.get('subject', [])):
                raise RuntimeError('Verified attestation has the wrong predicate or image subject')
            if not statement.get('predicate', {}).get('buildDefinition') or not statement.get('predicate', {}).get('runDetails'):
                raise RuntimeError('Verified provenance is incomplete')
            Path(f'candidate-provenance-{arch}.json').write_bytes(raw)
            print('Docker signature, attestation digest, native subject and pinned image index verified.', flush=True)
        subprocess.run([str(binary), 'cves', 'local://' + args.image, '--format', 'sarif', '--output', f'{args.prefix}-scout-{arch}.json'], env=env, check=True)
        # Preserve a complete final-image package/license inventory alongside
        # vulnerability evidence; CVE matches alone are not an SBOM.
        subprocess.run([str(binary), 'sbom', 'local://' + args.image, '--format', 'spdx',
                        '--output', f'{args.prefix}-sbom-{arch}.json'], env=env, check=True)


if __name__ == '__main__':
    main()
