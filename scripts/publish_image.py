"""Shared Docker Hub API and release identity helpers."""
import json
import re
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
        raise ValueError('Set DOCKERHUB_IMAGE to a valid namespace/repository')
    if not re.fullmatch(r'\d+\.\d+\.\d+', version):
        raise ValueError('Invalid release version')
    if not re.fullmatch(r'[0-9a-f]{40}', revision):
        raise ValueError('Invalid source revision')
