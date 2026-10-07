#!/usr/bin/env python3
"""Read-only release tag planning. Publish through the gated image.yml workflow.

The former standalone --execute path is disabled because it cannot establish
original native security evidence or completed Docker Hub analysis.
"""
import argparse
import json
from publish_image import validate_release


def release_plan(image, version, revision):
    validate_release(image, version, revision)
    return {
        'images': {arch: f'{image}:sha-{revision}-{arch}' for arch in ('amd64', 'arm64')},
        'manifests': [f'{image}:{version}', f'{image}:sha-{revision}', f'{image}:stable'],
    }


def execute(image, version, revision, visibility):
    raise ValueError('Standalone publication is disabled; use the gated image.yml candidate and promotion workflow')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True)
    parser.add_argument('--version', required=True)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--visibility', choices=('private', 'public'), default='public')
    parser.add_argument('--execute', action='store_true')
    args = parser.parse_args()
    if args.execute:
        execute(args.image, args.version, args.revision, args.visibility)
    else:
        print(json.dumps(release_plan(args.image, args.version, args.revision), indent=2))
