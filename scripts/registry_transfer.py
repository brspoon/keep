#!/usr/bin/env python3
"""Transfer gated CI images by immutable digest within the release registry."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request

from publish_image import hub, validate_release
from publish_release import repository_visibility, require_current_source, require_manual_dispatch, require_new_tags


def transfer_tag(arch):
    run, attempt = os.environ['GITHUB_RUN_ID'], os.environ['GITHUB_RUN_ATTEMPT']
    if arch not in ('amd64', 'arm64') or not re.fullmatch(r'[0-9]+', run) or not re.fullmatch(r'[0-9]+', attempt):
        raise ValueError('Invalid transfer identity')
    return f'transfer-{run}-{attempt}-{arch}'


def checked_digest(value):
    if not isinstance(value, str) or not re.fullmatch(r'sha256:[0-9a-f]{64}', value):
        raise ValueError('Missing or invalid tested image digest')
    return value


def delete_transfer_tag(path, token):
    request = urllib.request.Request('https://hub.docker.com/v2/' + path,
        headers={'Authorization': 'Bearer ' + token}, method='DELETE')
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            if response.status != 204:
                raise ValueError('Transfer tag cleanup failed')
    except urllib.error.HTTPError as error:
        if error.code != 403:
            raise
        # CI deliberately has only read/write credentials. A maintainer can
        # remove the temporary tag with a separate deletion-capable credential.
        print('::warning::Temporary tag retained; maintainer registry cleanup required: ' + path)
        return False
    return True


def report(arch):
    if arch not in ('amd64', 'arm64'):
        raise ValueError('Invalid architecture')
    # Full JSON remains in Actions logs, independent of artifact quota.
    for path in sorted(Path('.').glob(f'candidate-*{arch}.json')):
        print(f'::group::Security evidence: {path.name}', flush=True)
        print(json.dumps(json.loads(path.read_text()), indent=2), flush=True)
        print('::endgroup::', flush=True)


def execute(mode, arch=None):
    require_manual_dispatch(True)
    image = os.environ['DOCKERHUB_IMAGE']
    revision = os.environ['GITHUB_SHA']
    validate_release(image, Path('VERSION').read_text().strip(), revision)
    require_current_source(revision, True)
    username, secret = os.environ['DOCKERHUB_USERNAME'], os.environ['DOCKERHUB_TOKEN']
    token = hub('auth/token', payload={'identifier': username, 'secret': secret})['access_token']
    repository_visibility(hub('repositories/' + image + '/', token), 'is_private', 'Docker Hub')
    with tempfile.TemporaryDirectory(prefix='keep-transfer-') as directory:
        env = {**os.environ, 'DOCKER_CONFIG': directory}
        def docker(*args, capture=False, **kwargs):
            return subprocess.run(['docker', *args], env=env, check=True, text=True,
                                  stdout=subprocess.PIPE if capture else None, **kwargs).stdout
        if mode == 'stage':
            reference = image + ':' + transfer_tag(arch)
            require_new_tags({'images': {arch: reference}, 'manifests': []}, image, token)
            docker('login', '--username', username, '--password-stdin', input=secret)
            docker('tag', 'keep-ci', reference)
            docker('push', reference)
            digest = checked_digest(json.loads(docker('manifest', 'inspect', '--verbose', reference, capture=True))['Descriptor']['digest'])
            Path(f'transfer-{arch}.json').write_text(json.dumps({
                'architecture': arch, 'digest': digest, 'revision': revision,
                'run_id': os.environ['GITHUB_RUN_ID'], 'run_attempt': os.environ['GITHUB_RUN_ATTEMPT']}, sort_keys=True) + '\n')
            with open(os.environ['GITHUB_OUTPUT'], 'a') as output:
                output.write(f'{arch}={digest}\n')
            print(json.dumps({'transfer': reference, 'digest': digest, 'revision': revision}))
        elif mode in ('fetch', 'cleanup'):
            digests = json.loads(os.environ['TESTED_DIGESTS'])
            if set(digests) != {'amd64', 'arm64'}:
                raise ValueError('Both tested architecture digests are required')
            for value in digests.values():
                checked_digest(value)
            if mode == 'fetch':
                docker('login', '--username', username, '--password-stdin', input=secret)
                Path('artifacts').mkdir(exist_ok=True)
                for platform, digest in digests.items():
                    reference = image + '@' + digest
                    docker('pull', '--platform', 'linux/' + platform, reference)
                    docker('tag', reference, 'keep-ci-' + platform)
                    docker('save', '--output', f'artifacts/keep-{platform}.tar', 'keep-ci-' + platform)
            else:
                # Delete only the run-specific tags, never shared image manifests.
                for platform, digest in digests.items():
                    path = 'repositories/' + image + '/tags/' + transfer_tag(platform) + '/'
                    if hub(path, token).get('digest') != digest:
                        raise ValueError('Transfer tag changed; refusing cleanup')
                    if delete_transfer_tag(path, token):
                        print('Removed temporary tag ' + transfer_tag(platform))
        else:
            raise ValueError('Invalid transfer operation')


def aggregate():
    """Expose both digests from one job after checking this run's transfer tags."""
    require_manual_dispatch(True)
    image, revision = os.environ['DOCKERHUB_IMAGE'], os.environ['GITHUB_SHA']
    validate_release(image, Path('VERSION').read_text().strip(), revision)
    require_current_source(revision, True)
    token = hub('auth/token', payload={'identifier': os.environ['DOCKERHUB_USERNAME'],
                                      'secret': os.environ['DOCKERHUB_TOKEN']})['access_token']
    repository_visibility(hub('repositories/' + image + '/', token), 'is_private', 'Docker Hub')
    digests = {}
    for arch in ('amd64', 'arm64'):
        tag = transfer_tag(arch)
        path = Path(f'transfer-{arch}.json')
        if not path.is_file() or path.is_symlink():
            raise ValueError('Both original native transfer records are required')
        record = json.loads(path.read_text())
        digest = checked_digest(record.get('digest'))
        if record != {'architecture': arch, 'digest': digest, 'revision': revision,
                       'run_id': os.environ['GITHUB_RUN_ID'], 'run_attempt': os.environ['GITHUB_RUN_ATTEMPT']}:
            raise ValueError('Native transfer record differs from this tested run')
        if hub('repositories/' + image + '/tags/' + tag + '/', token).get('digest') != digest:
            raise ValueError('Native transfer tag differs from the tested digest')
        digests[arch] = digest
    with open(os.environ['GITHUB_OUTPUT'], 'a') as output:
        for arch, digest in digests.items():
            output.write(f'{arch}={digest}\n')


if __name__ == '__main__':
    if sys.argv[1] == 'aggregate':
        aggregate()
    elif sys.argv[1] == 'report':
        report(sys.argv[2])
    else:
        execute(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None)
