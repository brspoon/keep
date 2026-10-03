#!/usr/bin/env python3
"""Publish an already-tested image, refusing public repos or reused versions."""
import json
import os
import re
import subprocess
import urllib.error
import urllib.request


def hub(path, token=None, payload=None):
    headers = {'Content-Type': 'application/json'}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    request = urllib.request.Request('https://hub.docker.com/v2/' + path,
                                     data=json.dumps(payload).encode() if payload else None,
                                     headers=headers)
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def validate_release(image, version, revision):
    if not re.fullmatch(r'[a-z0-9][a-z0-9_-]*/[a-z0-9][a-z0-9_.-]*', image):
        raise ValueError('Set DOCKERHUB_IMAGE to the private namespace/repository')
    if not re.fullmatch(r'\d+\.\d+\.\d+', version):
        raise ValueError('Invalid release version')
    if not re.fullmatch(r'[0-9a-f]{40}', revision):
        raise ValueError('Invalid source revision')


def main():
    username = os.environ['DOCKERHUB_USERNAME']
    secret = os.environ['DOCKERHUB_TOKEN']
    image = os.environ['DOCKERHUB_IMAGE']
    version = os.environ['KEEP_RELEASE_VERSION']
    revision = os.environ['GITHUB_SHA']
    validate_release(image, version, revision)
    if not username or not secret:
        raise ValueError('Docker Hub publishing credentials are not configured')
    token = hub('auth/token', payload={'identifier': username, 'secret': secret})['access_token']
    repository = hub('repositories/' + image + '/', token)
    if repository.get('is_private') is not True:
        raise ValueError('Publishing refused: Docker Hub repository must already exist and be private')
    try:
        hub('repositories/' + image + '/tags/' + version + '/', token)
    except urllib.error.HTTPError as error:
        if error.code != 404:
            raise
    else:
        raise ValueError('Version already published. Bump VERSION; release tags are never overwritten.')
    # A delayed/manual run must not promote an older commit over current main.
    request = urllib.request.Request(
        'https://api.github.com/repos/' + os.environ['GITHUB_REPOSITORY'] + '/git/ref/heads/main',
        headers={'Authorization': 'Bearer ' + os.environ['GITHUB_TOKEN'],
                 'Accept': 'application/vnd.github+json'})
    with urllib.request.urlopen(request, timeout=30) as response:
        if json.load(response)['object']['sha'] != revision:
            raise ValueError('Publishing refused: this commit is no longer current main')
    subprocess.run(['docker', 'login', '--username', username, '--password-stdin'],
                   input=secret, text=True, check=True)
    try:
        # stable is promoted last, after the immutable release references exist.
        for tag in (version, 'sha-' + revision, 'stable'):
            reference = image + ':' + tag
            subprocess.run(['docker', 'tag', 'keep-ci', reference], check=True)
            subprocess.run(['docker', 'push', reference], check=True)
        print('Published private Keep release ' + version)
    finally:
        subprocess.run(['docker', 'logout'], check=False)


if __name__ == '__main__':
    main()
