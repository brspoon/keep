#!/usr/bin/env python3
"""Publish tested release artifacts, with a read-only default plan."""
import argparse
import json
import os
import re
import subprocess
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from publish_image import hub
from publish_portable import release_plan

BRANCH = 'refs/heads/main'
ARCHES = {'amd64', 'arm64'}


def development_plan(image, revision):
    if not re.fullmatch(r'[a-z0-9][a-z0-9_-]*/[a-z0-9][a-z0-9_.-]*', image):
        raise ValueError('Invalid Docker Hub namespace/repository')
    if not re.fullmatch(r'[0-9a-f]{40}', revision):
        raise ValueError('Use a full Git commit SHA')
    prefix = image + ':dev-portable-' + revision
    return {'images': {arch: prefix + '-' + arch for arch in ('amd64', 'arm64')},
            'manifests': [prefix, image + ':dev-portable']}


def github_repository():
    repository = os.environ['GITHUB_REPOSITORY']
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository):
        raise ValueError('Invalid GitHub repository')
    return repository


def github(path):
    request = urllib.request.Request('https://api.github.com/repos/' + github_repository() + path,
        headers={'Authorization': 'Bearer ' + os.environ['GITHUB_TOKEN'],
                 'Accept': 'application/vnd.github+json'})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        raise ValueError(f'GitHub source check failed ({error.code}) for {path or "repository"}') from error
    except (urllib.error.URLError, TimeoutError) as error:
        raise ValueError(f'GitHub source check could not reach {path or "repository"}') from error


def repository_visibility(metadata, field, service):
    """Require explicit visibility metadata without changing repository access."""
    if not isinstance(metadata, dict) or type(metadata.get(field)) is not bool:
        raise ValueError(service + ' did not return valid repository visibility metadata')
    return metadata[field]


def require_current_source(revision, release=False):
    if not re.fullmatch(r'[0-9a-f]{40}', revision):
        raise ValueError('Release source revision must be a full Git commit SHA')
    try:
        repository = github('')
        repository_visibility(repository, 'private', 'GitHub')
        reference = github('/git/ref/heads/main')
        current = reference['object']['sha']
    except (KeyError, TypeError) as error:
        raise ValueError('GitHub did not return the expected main source metadata') from error
    if not isinstance(current, str) or not re.fullmatch(r'[0-9a-f]{40}', current):
        raise ValueError('GitHub did not return a valid current main revision')
    if current != revision:
        raise ValueError('Release source is stale: tested revision is not current main')


def require_manual_dispatch(release=False):
    if not release:
        raise ValueError('Only confirmed stable releases are supported')
    if os.environ.get('GITHUB_EVENT_NAME') != 'workflow_dispatch':
        raise ValueError('Release publication requires a manual workflow_dispatch run')
    if os.environ.get('GITHUB_REF') != 'refs/heads/main':
        raise ValueError('Release publication requires refs/heads/main')
    if os.environ.get('KEEP_RELEASE_PUBLISH') != 'true':
        raise ValueError('Set publish_release=true in the manual workflow inputs')
    if os.environ.get('KEEP_RELEASE_CONFIRMATION') != 'release-stable':
        raise ValueError('Enter release-stable in the manual workflow confirmation input')


def require_new_tags(plan, image, token):
    for reference in list(plan['images'].values()) + plan['manifests'][:-1]:
        try:
            hub('repositories/' + image + '/tags/' + reference.rsplit(':', 1)[1] + '/', token)
        except urllib.error.HTTPError as error:
            if error.code != 404:
                raise
        else:
            raise ValueError('An immutable release tag already exists; refusing to overwrite')


def verify_manifest(manifest, expected):
    entries = manifest.get('manifests', [])
    if len(entries) != 2:
        raise ValueError('Expected exactly two platform manifests')
    actual = {(entry['platform']['os'], entry['platform']['architecture']): entry['digest'] for entry in entries}
    if actual != {('linux', arch): digest for arch, digest in expected.items()}:
        raise ValueError('Published platforms or digests differ from the tested images')


def tested_identity():
    """Require both native manifests and config IDs from verified release evidence."""
    values = []
    for name in ('TESTED_DIGESTS', 'TESTED_CONFIG_DIGESTS'):
        try:
            identity = json.loads(os.environ[name])
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError('Both verified architecture identities are required: ' + name) from error
        if (not isinstance(identity, dict) or set(identity) != ARCHES or
                any(not isinstance(value, str) or
                    not re.fullmatch(r'sha256:[0-9a-f]{64}', value) for value in identity.values())):
            raise ValueError('Both verified architecture identities are required: ' + name)
        values.append(identity)
    return values


def execute(image, revision, artifacts, release=False):
    version = Path('VERSION').read_text().strip()
    plan = release_plan(image, version, revision) if release else development_plan(image, revision)
    require_manual_dispatch(release)
    if revision != os.environ.get('GITHUB_SHA'):
        raise ValueError('Revision differs from this workflow run')
    expected_digests, expected_configs = tested_identity()
    require_current_source(revision, release)
    version = Path('VERSION').read_text().strip()
    if not re.fullmatch(r'\d+\.\d+\.\d+', version):
        raise ValueError('Invalid source version')
    username, secret = os.environ['DOCKERHUB_USERNAME'], os.environ['DOCKERHUB_TOKEN']
    token = hub('auth/token', payload={'identifier': username, 'secret': secret})['access_token']
    repository_visibility(hub('repositories/' + image + '/', token), 'is_private', 'Docker Hub')
    require_new_tags(plan, image, token)
    # Isolate credentials from any existing docker login and remove them on exit.
    with tempfile.TemporaryDirectory(prefix='keep-dev-docker-') as config:
        environment = {**os.environ, 'DOCKER_CONFIG': config}
        def docker(*args, capture=False, **kwargs):
            result = subprocess.run(['docker', *args], env=environment, check=True,
                                    text=True, stdout=subprocess.PIPE if capture else None, **kwargs)
            return result.stdout if capture else None
        ids = {}
        for arch in plan['images']:
            archive = artifacts / ('keep-' + arch + '.tar')
            if not archive.is_file() or archive.is_symlink():
                raise ValueError('A tested image artifact is missing')
            docker('load', '--input', str(archive))
            metadata = json.loads(docker('image', 'inspect', 'keep-ci-' + arch, capture=True))[0]
            labels = metadata.get('Config', {}).get('Labels', {}) or {}
            if (metadata.get('Architecture') != arch or metadata.get('Os') != 'linux' or
                    labels.get('org.opencontainers.image.revision') != revision or
                    labels.get('org.opencontainers.image.version') != version or
                    labels.get('org.opencontainers.image.source') != 'https://github.com/' + github_repository() or
                    metadata.get('Config', {}).get('User') != '10001:10001' or
                    metadata.get('Id') != expected_configs[arch]):
                raise ValueError('Test artifact identity or runtime configuration does not match')
            ids[arch] = metadata['Id']
        require_current_source(revision, release)
        # Read and verify the original assets once; retain their reports for the
        # deadline check immediately before each registry publication.
        import release_materials
        security_reviews = {}
        identities = release_materials.verify_identities(
            version, release_materials.draft(version), expected_digests,
            security_reviews=security_reviews,
        )
        if any(identities[arch]['config_digest'] != expected_configs[arch] for arch in ARCHES):
            raise ValueError('Original release evidence config differs from the tested image')
        docker('login', '--username', username, '--password-stdin', input=secret)
        digests = {}
        for arch, reference in plan['images'].items():
            docker('tag', ids[arch], reference)
            release_materials.revalidate_security(security_reviews)
            docker('push', reference)
            descriptor = json.loads(docker('manifest', 'inspect', '--verbose', reference, capture=True))['Descriptor']
            digest = descriptor['digest']
            if not re.fullmatch(r'sha256:[0-9a-f]{64}', digest):
                raise ValueError('Invalid registry digest')
            if digest != expected_digests[arch]:
                raise ValueError('Published native digest differs from the tested image: ' + arch)
            digests[arch] = digest
        refs = [image + '@' + digest for digest in digests.values()]
        for reference in plan['manifests']:
            # Do not promote an older test run after the branch has advanced.
            require_current_source(revision, release)
            docker('manifest', 'create', reference, *refs)
            release_materials.revalidate_security(security_reviews)
            docker('manifest', 'push', '--purge', reference)
            verify_manifest(json.loads(docker('manifest', 'inspect', reference, capture=True)), digests)
        print(json.dumps({'published': plan['manifests'], 'platform_digests': digests}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--artifacts', type=Path, default=Path('artifacts'))
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--release', action='store_true', help='Publish stable from tested main artifacts')
    args = parser.parse_args()
    if args.execute:
        execute(args.image, args.revision, args.artifacts, args.release)
    else:
        plan = release_plan(args.image, Path('VERSION').read_text().strip(), args.revision) if args.release else development_plan(args.image, args.revision)
        print(json.dumps(plan, indent=2))
