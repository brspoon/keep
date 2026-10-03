#!/usr/bin/env python3
"""Read-only notice inventory and all-layer privacy checks for a tested image.

Never extract image archives or print matching credential values. Layer checks
include overwritten/deleted files; this is a bounded-format heuristic review,
not proof that arbitrary secrets cannot exist.
"""
import argparse
import hashlib
import importlib.metadata
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import tarfile


CREDENTIAL_PATTERNS = {
    'private-key': re.compile(rb'-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----'),
    'github-token': re.compile(rb'(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})'),
    'aws-access-key': re.compile(rb'(?:AKIA|ASIA)[A-Z0-9]{16}'),
    'credential-url': re.compile(rb'https?://[^\s/\x00:@]{1,128}:[^\s/\x00@]{1,128}@'),
}
PRIVATE_MARKERS_ENV = 'KEEP_PRIVATE_IMAGE_MARKERS'
MAX_PRIVATE_MARKERS = 32
MAX_PRIVATE_MARKER_BYTES = 512
FORBIDDEN_NAMES = {'.env', '.git', '.netrc', '.npmrc', '.pypirc', 'id_rsa', 'id_ed25519'}
# urllib3 2.8.0's URL parser contains an invalid documentation example, not
# credentials. Review the entire exact source file, never exempt its directory.
BENIGN_EXAMPLES = {
    ('credential-url', '6a2814d91987dd9728278d413a154ee5277b15cb262d9945425377f2a693311f'):
        'urllib3 2.8.0 util/url.py line 236: synthetic URL in the Url.url docstring',
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def is_notice_path(path):
    """Include complete license directories, including SPDX/hash filenames."""
    path = PurePosixPath(path)
    return (any(part.lower() in {'licenses', 'licences'} for part in path.parts[:-1])
            or bool(re.search(r'(?:license|licence|copying|copyright|notice)', path.name, re.I)))


def load_private_image_markers(*, required=False, environ=None):
    """Read bounded literal markers without ever echoing their values."""
    environ = os.environ if environ is None else environ
    raw = environ.get(PRIVATE_MARKERS_ENV)
    if raw is None and not required:
        return []
    try:
        raw_size = len(raw.encode('utf-8')) if raw is not None else 0
    except UnicodeError:
        raw_size = 32769
    if raw is None or raw_size > 32768:
        raise ValueError(f'{PRIVATE_MARKERS_ENV} is missing or invalid')
    try:
        markers = json.loads(raw)
    except (ValueError, TypeError):
        raise ValueError(f'{PRIVATE_MARKERS_ENV} is missing or invalid') from None
    try:
        valid = (isinstance(markers, list) and 1 <= len(markers) <= MAX_PRIVATE_MARKERS
                 and all(isinstance(marker, str) and marker
                         and len(marker.encode('utf-8')) <= MAX_PRIVATE_MARKER_BYTES
                         for marker in markers))
    except UnicodeError:
        valid = False
    if not valid:
        raise ValueError(f'{PRIVATE_MARKERS_ENV} is missing or invalid')
    return markers


def image_patterns(markers):
    """Keep credential rules fixed and match each configured marker literally."""
    patterns = dict(CREDENTIAL_PATTERNS)
    if markers:
        patterns['private-host'] = re.compile(b'|'.join(
            re.escape(marker.encode('utf-8')) for marker in markers))
    return patterns


def redacted(value, patterns=None):
    """Retain public attribution but never log recognized secret-shaped fields."""
    if patterns is None:
        patterns = image_patterns(load_private_image_markers())
    if isinstance(value, str):
        body = value.encode('utf-8')
        rules = sorted(name for name, pattern in patterns.items() if pattern.search(body))
        if rules:
            return f"[redacted {','.join(rules)}; sha256={digest(body)}]"
    elif isinstance(value, dict):
        return {key: redacted(item, patterns) for key, item in value.items()}
    elif isinstance(value, list):
        return [redacted(item, patterns) for item in value]
    return value


def scan_stream(stream, hasher=None, patterns=None):
    """Scan every byte with overlap for patterns split across read boundaries."""
    if patterns is None:
        patterns = image_patterns(load_private_image_markers())
    found = set()
    tail = b''
    while chunk := stream.read(1024 * 1024):
        if hasher is not None:
            hasher.update(chunk)
        value = tail + chunk
        found.update(name for name, pattern in patterns.items() if pattern.search(value))
        tail = value[-512:]
    return sorted(found)


def inspect_archive(path, patterns=None):
    if patterns is None:
        patterns = image_patterns(load_private_image_markers(required=True))
    layers = []
    findings = []
    benign_examples = []
    notice_entries = []
    with tarfile.open(path) as archive:
        manifest = json.load(archive.extractfile('manifest.json'))
        if len(manifest) != 1:
            raise ValueError('Review exactly one tested image')
        entry = manifest[0]
        config_bytes = archive.extractfile(entry['Config']).read()
        config = json.loads(config_bytes)
        for rule in scan_stream(io.BytesIO(config_bytes), patterns=patterns):
            findings.append({'scope': 'image-config', 'rule': rule})
        expected = config['rootfs']['diff_ids']
        if len(expected) != len(entry['Layers']):
            raise ValueError('Image config/layer count mismatch')
        for number, name in enumerate(entry['Layers']):
            # docker save supplies uncompressed layer tar files. Bind reviewed
            # content to the config diff IDs; reject other export formats.
            hasher = hashlib.sha256()
            with archive.extractfile(name) as stream:
                while chunk := stream.read(1024 * 1024):
                    hasher.update(chunk)
            layer_id = 'sha256:' + hasher.hexdigest()
            if layer_id != expected[number]:
                raise ValueError('Reviewed layer does not match image config')
            regular_files = 0
            size = 0
            with archive.extractfile(name) as stream, tarfile.open(fileobj=stream, mode='r|') as layer:
                for member in layer:
                    parts = PurePosixPath(member.name).parts
                    if '..' in parts or member.name.startswith('/'):
                        raise ValueError('Unexpected image archive path')
                    basename = parts[-1] if parts else ''
                    rules = []
                    rules += [rule for rule, pattern in patterns.items()
                              if pattern.search(member.name.encode('utf-8'))]
                    if any(part in FORBIDDEN_NAMES for part in parts):
                        rules.append('private-runtime-file')
                    if (member.isfile() and basename.endswith(('.sqlite', '.sqlite3'))
                            and not basename.endswith('.so')):
                        rules.append('runtime-database')
                    if member.isfile():
                        regular_files += 1
                        size += member.size
                        file_hasher = hashlib.sha256()
                        rules += scan_stream(layer.extractfile(member), file_hasher, patterns)
                        if is_notice_path(member.name):
                            notice_entries.append({'layer': number, 'path': member.name,
                                                   'sha256': file_hasher.hexdigest()})
                    for rule in sorted(set(rules)):
                        item = {'scope': 'layer', 'layer': number, 'path': member.name, 'rule': rule}
                        if member.isfile():
                            item['file_sha256'] = file_hasher.hexdigest()
                        reason = BENIGN_EXAMPLES.get((rule, item.get('file_sha256')))
                        if reason:
                            benign_examples.append({**item, 'reason': reason})
                        else:
                            findings.append(item)
            layers.append({'diff_id': layer_id, 'files': regular_files, 'bytes': size})
    return redacted({'config_sha256': digest(config_bytes), 'architecture': config['architecture'],
            'layers': layers, 'findings': findings, 'benign_examples': benign_examples,
            'notice_entries': notice_entries,
            'success': not findings,
            'limitations': 'Known credential formats and configured private markers only; no entropy-based guarantee.'},
            patterns)


def notice(path):
    body = path.read_bytes()
    return {'path': str(path), 'bytes': len(body), 'sha256': digest(body),
            'text': body.decode('utf-8', errors='replace')}


def runtime_inventory():
    """Read actual installed metadata, without importing the application."""
    distributions = []
    for distribution in importlib.metadata.distributions():
        files = []
        native_files = []
        for relative in distribution.files or []:
            if relative.name.endswith('.so'):
                path = Path(distribution.locate_file(relative))
                if path.is_file():
                    native_files.append({'path': str(relative), 'sha256': digest(path.read_bytes())})
            if is_notice_path(str(relative)):
                path = Path(distribution.locate_file(relative))
                if path.is_file():
                    files.append(notice(path))
        distributions.append({'name': distribution.metadata['Name'], 'version': distribution.version,
            'license_expression': distribution.metadata.get('License-Expression'),
            'license_classifiers': [value for value in distribution.metadata.get_all('Classifier', [])
                                   if value.startswith('License ::')], 'notices': files,
            'native_files': native_files})
    os_packages = []
    for record in Path('/lib/apk/db/installed').read_text().split('\n\n'):
        fields = dict(line.split(':', 1) for line in record.splitlines()
                      if len(line) > 1 and line[1] == ':' and line[0] in 'PVLoUc')
        if fields.get('P'):
            os_packages.append({'name': fields.get('P'), 'version': fields.get('V'),
                'license': fields.get('L'), 'origin': fields.get('o'),
                'url': fields.get('U'), 'build_commit': fields.get('c')})
    locations = ('/usr/share/licenses', '/usr/share/doc', '/app')
    notices = []
    for location in locations:
        root = Path(location)
        if root.is_dir():
            for path in sorted(root.rglob('*')):
                if path.is_file() and is_notice_path(path.as_posix()):
                    notices.append(notice(path))
    return {'python': sorted(distributions, key=lambda row: row['name'].lower()),
            'os_packages': sorted(os_packages, key=lambda row: row['name']), 'notices': notices}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime', action='store_true')
    parser.add_argument('--archive')
    args = parser.parse_args()
    if args.runtime == bool(args.archive):
        parser.error('Select exactly one of --runtime or --archive')
    try:
        patterns = image_patterns(load_private_image_markers(required=bool(args.archive)))
    except ValueError as exc:
        parser.error(str(exc))
    try:
        result = runtime_inventory() if args.runtime else inspect_archive(args.archive, patterns)
    except (OSError, ValueError, KeyError, tarfile.TarError):
        parser.error('Image review failed; inspect the input and configuration')
    print(json.dumps(redacted(result, patterns), indent=2))
    if not result.get('success', True):
        raise SystemExit(1)


if __name__ == '__main__':
    main()
