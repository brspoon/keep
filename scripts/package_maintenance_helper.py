#!/usr/bin/env python3
"""Build the bounded optional host-helper asset from reviewed release source."""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from helper_bundle import inspect_bundle, source_bundle
from private_store import PrivatePaths


def package(source, version, revision):
    body = source_bundle(PrivatePaths(), Path(source).absolute(), version=version, revision=revision)
    digest = hashlib.sha256(body).hexdigest()
    _, manifest = inspect_bundle(body, version=version, revision=revision, expected_sha256=digest)
    return body, manifest


def write_asset(source, directory, version, revision):
    directory = Path(directory)
    body, manifest = package(source, version, revision)
    name = 'keep-' + version + '-maintenance-helper.tar.gz'
    digest = hashlib.sha256(body).hexdigest()
    for filename, data in ((name, body), (name + '.sha256', (digest + '  ' + name + '\n').encode('ascii'))):
        target = directory / filename
        if target.exists() or target.is_symlink():
            if not target.is_file() or target.is_symlink() or target.read_bytes() != data:
                raise ValueError('Existing helper release asset differs')
        else:
            with target.open('xb') as stream:
                stream.write(data)
    return directory / name, manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--version', required=True)
    parser.add_argument('--revision', required=True)
    arguments = parser.parse_args()
    path, _ = write_asset(arguments.source, arguments.output, arguments.version, arguments.revision)
    print(path.name)


if __name__ == '__main__':
    main()
