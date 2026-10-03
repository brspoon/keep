#!/usr/bin/env python3
"""Manual publication of two locally tested images. Never changes visibility.

Default is a read-only plan. --execute is a separate operator release decision.
Not called by CI. Requires clean reviewed main and existing registry repository.
"""
import argparse
import json
import os
import subprocess
import urllib.error
from pathlib import Path
from publish_image import hub, validate_release


def release_plan(image, version, revision):
    validate_release(image, version, revision)
    return {
        'images': {arch: f'{image}:sha-{revision}-{arch}' for arch in ('amd64', 'arm64')},
        'manifests': [f'{image}:{version}', f'{image}:sha-{revision}', f'{image}:stable'],
    }


def run(*args, **kwargs):
    return subprocess.run(list(args), check=True, **kwargs)


def execute(image, version, revision, visibility):
    plan = release_plan(image, version, revision)
    if visibility not in ('private', 'public'):
        raise ValueError('Explicit repository visibility is required')
    branch = subprocess.check_output(['git', 'branch', '--show-current'], text=True).strip()
    head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    if branch != 'main' or head != revision or subprocess.check_output(['git', 'status', '--porcelain']).strip():
        raise ValueError('Release requires a clean, reviewed main at the requested revision')
    root = Path.cwd().resolve()
    if (root / 'VERSION').read_text().strip() != version:
        raise ValueError('Source version does not match the release')
    # Verify and re-test each exact image without network or production data.
    image_ids = {}
    for arch in plan['images']:
        local = 'keep-ci-' + arch
        metadata = json.loads(subprocess.check_output(['docker', 'image', 'inspect', local], text=True))[0]
        labels = metadata.get('Config', {}).get('Labels', {}) or {}
        if (metadata.get('Architecture') != arch or metadata.get('Os') != 'linux' or
                labels.get('org.opencontainers.image.revision') != revision or
                labels.get('org.opencontainers.image.version') != version):
            raise ValueError('Image architecture or release metadata mismatch')
        image_ids[arch] = metadata['Id']
        run('docker', 'run', '--rm', '--network', 'none', '--platform', 'linux/' + arch,
            '--mount', f'type=bind,source={root},target=/workspace,readonly', '-w', '/workspace',
            metadata['Id'], 'python', '-B', '-m', 'unittest', 'discover', '-s', 'tests')
    username, secret = os.environ['DOCKERHUB_USERNAME'], os.environ['DOCKERHUB_TOKEN']
    token = hub('auth/token', payload={'identifier': username, 'secret': secret})['access_token']
    repository = hub('repositories/' + image + '/', token)
    if repository.get('is_private') is not (visibility == 'private'):
        raise ValueError('Repository visibility differs from explicit release choice; no visibility changes are allowed')
    # Fail before pushing if any immutable target is already present.
    for reference in list(plan['images'].values()) + plan['manifests'][:-1]:
        tag = reference.rsplit(':', 1)[1]
        try:
            hub('repositories/' + image + '/tags/' + tag + '/', token)
        except urllib.error.HTTPError as error:
            if error.code != 404:
                raise
        else:
            raise ValueError('An immutable release tag already exists; do not overwrite it')
    remote_main = subprocess.check_output(['git', 'ls-remote', 'origin', 'refs/heads/main'], text=True).split()
    if not remote_main or remote_main[0] != revision:
        raise ValueError('Release commit is no longer current remote main')
    run('docker', 'login', '--username', username, '--password-stdin', input=secret, text=True)
    try:
        for arch, reference in plan['images'].items():
            run('docker', 'tag', image_ids[arch], reference)
            run('docker', 'push', reference)
        refs = list(plan['images'].values())
        for target in plan['manifests']:
            run('docker', 'manifest', 'create', target, *refs)
            run('docker', 'manifest', 'push', '--purge', target)
            manifest = json.loads(subprocess.check_output(['docker', 'manifest', 'inspect', target], text=True))
            platforms = {(entry['platform']['os'], entry['platform']['architecture']) for entry in manifest.get('manifests', [])}
            if len(manifest.get('manifests', [])) != 2 or platforms != {('linux', 'amd64'), ('linux', 'arm64')}:
                raise ValueError('Published manifest failed architecture verification; stop promotion')
    finally:
        run('docker', 'logout')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True)
    parser.add_argument('--version', required=True)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--visibility', choices=('private', 'public'), default='private')
    parser.add_argument('--execute', action='store_true')
    args = parser.parse_args()
    if args.execute:
        execute(args.image, args.version, args.revision, args.visibility)
    else:
        print(json.dumps(release_plan(args.image, args.version, args.revision), indent=2))
