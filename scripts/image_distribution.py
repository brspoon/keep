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
# The CLI's help text and recover callback are separate from libsqlite3 and
# Python's sqlite3 module. Match combinations in ELF payloads, not source/docs.
# Upstream 3.54.1: src/shell.c.in recoverSqlCb(), do_meta_command() and help text;
# ext/recover/sqlite3recover.c recoverSqlCallback(). These are known signatures,
# not a proof against an arbitrary rebuilt/encoded/packed C command shell.
SQLITE_CLI_MARKERS = (b'.recover', b'.shell', b'.system', b'SQLite version ',
                      b'sqlite3_recover_init_sql', b'recoverSqlCb',
                      b'Usage: .system COMMAND', b'Enter ".help" for usage hints.')
SQLITE_METADATA_LIMIT = 16 * 1024 * 1024
SQLITE_CLI_PACKAGES = {'sqlite', 'sqlite3', 'sqlite-tools', 'sqlite3-tools',
                       'sqlite-shell', 'sqlite3-shell'}
SQLITE_CLI_LIMITATIONS = (
    'Checks installed APK identities/payload names, known CLI names/aliases and '
    'known SQLite C-shell/recover marker combinations in every regular ELF payload. '
    'Includes overwritten/deleted lower-layer entries. Does not prove arbitrary '
    'renamed, rebuilt, packed, compressed or encoded command-shell code absent; '
    'Python sqlite3 modules and the core libsqlite3 library are distinct components.')


def sqlite_cli_name(path):
    name = PurePosixPath(path).name.lower()
    return bool(re.fullmatch(r'sqlite(?:3)?(?:[-_.](?:shell|cli|[0-9][0-9.]*))?(?:\.exe)?', name))


def sqlite_package_record(fields, payloads):
    name = fields.get('P', fields.get('pkgname', ''))
    origin = fields.get('o', fields.get('origin', ''))
    provides = fields.get('p', fields.get('provides', '')).split()
    if (origin not in {'sqlite', 'sqlite3'} and not name.startswith('sqlite')
            and not any(row.startswith('cmd:sqlite') for row in provides)):
        return None
    return {'name': name, 'version': fields.get('V', fields.get('pkgver', '')),
            'origin': origin, 'provides': provides, 'payloads': payloads}


def sqlite_apk_metadata(body, *, pkginfo=False):
    """Retain exact SQLite component and payload identities from APK metadata."""
    if len(body) > SQLITE_METADATA_LIMIT:
        raise ValueError('APK metadata exceeds bounded SQLite component review')
    text = body.decode('utf-8')
    if '\x00' in text:
        raise ValueError('Invalid APK metadata for SQLite component review')
    result = []
    for block in [text] if pkginfo else text.split('\n\n'):
        fields, payloads, directory = {}, [], ''
        for line in block.splitlines():
            if pkginfo:
                if ' = ' in line:
                    key, value = line.split(' = ', 1)
                    if key in {'pkgname', 'pkgver', 'origin'} and key in fields:
                        raise ValueError('Ambiguous APK package identity')
                    fields[key] = fields.get(key, '') + ' ' + value if key in fields else value
            elif len(line) > 1 and line[1] == ':':
                key, value = line[0], line[2:]
                if key == 'F':
                    directory = value
                elif key == 'R':
                    path = str(PurePosixPath(directory) / value)
                    if '..' in PurePosixPath(path).parts or path.startswith('/'):
                        raise ValueError('Unsafe installed APK payload path')
                    payloads.append(path)
                else:
                    if key in {'P', 'V', 'o', 'p'} and key in fields:
                        raise ValueError('Ambiguous installed APK package identity')
                    fields[key] = value
        if fields.get('P', fields.get('pkgname')):
            record = sqlite_package_record(fields, payloads)
            if record is not None:
                result.append(record)
    return result


def sqlite_package_findings(packages):
    findings = []
    for package in packages:
        if (package['name'] in SQLITE_CLI_PACKAGES or sqlite_cli_name(package['name'])
                or any(value.startswith('cmd:') and sqlite_cli_name(value[4:].split('=', 1)[0])
                       for value in package['provides'])):
            findings.append({'rule': 'sqlite-cli-package', 'package': package['name']})
        for path in package['payloads']:
            if sqlite_cli_name(path):
                findings.append({'rule': 'sqlite-cli-package-payload',
                                 'package': package['name'], 'payload': path})
    return findings


class SQLitePayloadReview:
    """Observe the same bounded stream used for privacy hashing; never extract."""
    def __init__(self, stream, *, metadata=False):
        self.stream, self.metadata = stream, metadata
        self.prefix, self.tail, self.body = b'', b'', bytearray()
        self.markers = set()

    def read(self, size):
        chunk = self.stream.read(size)
        if len(self.prefix) < 4:
            self.prefix = (self.prefix + chunk)[:4]
        if self.metadata:
            if len(self.body) + len(chunk) > SQLITE_METADATA_LIMIT:
                raise ValueError('APK metadata exceeds bounded SQLite component review')
            self.body.extend(chunk)
        if self.prefix == b'\x7fELF':
            value = self.tail + chunk
            self.markers.update(marker for marker in SQLITE_CLI_MARKERS if marker in value)
            self.tail = value[-512:]
        return chunk

    def cli_markers(self):
        markers = self.markers
        recover = bool(markers & {b'.recover', b'sqlite3_recover_init_sql', b'recoverSqlCb'})
        shell = bool(markers & {b'.shell', b'.system', b'Usage: .system COMMAND'})
        banner = bool(markers & {b'SQLite version ', b'Enter ".help" for usage hints.'})
        return sorted(marker.decode() for marker in markers) if recover and (shell or banner) else []


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
    sqlite_findings, sqlite_metadata = [], []
    elf_files = 0
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
                    if (member.isfile() or member.issym() or member.islnk()) and sqlite_cli_name(member.name):
                        sqlite_findings.append({'layer': number, 'path': member.name,
                                                'rule': 'sqlite-cli-name'})
                    if (member.issym() or member.islnk()) and sqlite_cli_name(member.linkname):
                        sqlite_findings.append({'layer': number, 'path': member.name,
                                                'rule': 'sqlite-cli-alias', 'target': member.linkname})
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
                        metadata = (PurePosixPath(member.name).as_posix() == 'lib/apk/db/installed'
                                    or basename == '.PKGINFO')
                        payload = SQLitePayloadReview(layer.extractfile(member), metadata=metadata)
                        rules += scan_stream(payload, file_hasher, patterns)
                        if payload.prefix == b'\x7fELF':
                            elf_files += 1
                        markers = payload.cli_markers()
                        if markers:
                            sqlite_findings.append({'layer': number, 'path': member.name,
                                'rule': 'sqlite-cli-elf-markers', 'markers': markers,
                                'file_sha256': file_hasher.hexdigest()})
                        if metadata:
                            packages = sqlite_apk_metadata(bytes(payload.body), pkginfo=basename == '.PKGINFO')
                            sqlite_metadata.append({'layer': number, 'path': member.name,
                                'sha256': file_hasher.hexdigest(), 'packages': packages})
                            sqlite_findings.extend({'layer': number, 'path': member.name, **finding}
                                                   for finding in sqlite_package_findings(packages))
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
    sqlite_cli = {'schema': 1, 'scope': 'all-image-layers', 'success': not sqlite_findings,
        'layers_scanned': len(layers), 'files_scanned': sum(row['files'] for row in layers),
        'elf_files_scanned': elf_files, 'apk_metadata': sqlite_metadata,
        'findings': sqlite_findings, 'limitations': SQLITE_CLI_LIMITATIONS}
    return redacted({'config_sha256': digest(config_bytes), 'architecture': config['architecture'],
            'layers': layers, 'findings': findings, 'benign_examples': benign_examples,
            'notice_entries': notice_entries, 'sqlite_cli': sqlite_cli,
            'success': not findings and sqlite_cli['success'],
            'limitations': 'Known credential formats and configured private markers only; no entropy-based guarantee.'},
            patterns)


def validate_sqlite_cli_review(inventory, layers, arch, *, root=Path('.'), image_config_sha256=None):
    """Replay component evidence without changing raw scanner findings or counts."""
    from collect_package_sources import verify_sqlite_replacement
    def require(condition, message):
        if not condition:
            raise ValueError(message)
    require(arch in {'amd64', 'arm64'} and isinstance(inventory, dict)
            and isinstance(layers, dict), 'Missing native SQLite component evidence')
    require(isinstance(image_config_sha256, str)
            and re.fullmatch(r'[a-f0-9]{64}', image_config_sha256)
            and layers.get('config_sha256') == image_config_sha256,
            'SQLite layer evidence does not cover the exact scanned image configuration')
    verify_sqlite_replacement(inventory, arch, root=root)
    runtime = inventory.get('sqlite_cli')
    whole = layers.get('sqlite_cli')
    require(isinstance(runtime, dict) and runtime.get('schema') == 1
            and type(runtime['schema']) is int
            and runtime.get('scope') == 'runtime-filesystem'
            and runtime.get('success') is True and runtime.get('findings') == [],
            'Missing or failed runtime SQLite component review')
    require(layers.get('architecture') == arch and layers.get('success') is True
            and layers.get('findings') == [] and isinstance(whole, dict)
            and whole.get('schema') == 1 and type(whole['schema']) is int
            and whole.get('scope') == 'all-image-layers'
            and whole.get('success') is True and whole.get('findings') == []
            and whole.get('limitations') == SQLITE_CLI_LIMITATIONS,
            'Missing or failed all-layer SQLite component review')
    records = layers.get('layers')
    require(isinstance(records, list) and records
            and all(isinstance(row, dict)
                    and type(row.get('files')) is int and row['files'] >= 0
                    and type(row.get('bytes')) is int and row['bytes'] >= 0
                    and isinstance(row.get('diff_id'), str)
                    and re.fullmatch(r'sha256:[a-f0-9]{64}', row['diff_id']) for row in records)
            and type(whole.get('layers_scanned')) is int
            and whole['layers_scanned'] == len(records)
            and type(whole.get('files_scanned')) is int
            and whole['files_scanned'] == sum(row['files'] for row in records)
            and whole['files_scanned'] > 0
            and type(whole.get('elf_files_scanned')) is int
            and 0 < whole['elf_files_scanned'] <= whole['files_scanned'],
            'Incomplete SQLite component layer coverage')
    expected = {'name': 'sqlite-libs', 'version': '3.53.4-r0', 'origin': 'sqlite',
                'provides': ['so:libsqlite3.so.0=3.53.4'],
                'payloads': ['usr/lib/libsqlite3.so.0', 'usr/lib/libsqlite3.so.3.53.4']}
    metadata = runtime.get('apk_metadata')
    require(isinstance(metadata, dict) and metadata.get('path') == '/lib/apk/db/installed'
            and isinstance(metadata.get('sha256'), str)
            and re.fullmatch(r'[a-f0-9]{64}', metadata['sha256'])
            and isinstance(metadata.get('packages'), list) and len(metadata['packages']) == 1,
            'Missing exact SQLite installed-package component inventory')
    package = metadata['packages'][0]
    require(isinstance(package, dict) and set(package) == set(expected)
            and all(package[key] == value for key, value in expected.items() if key != 'payloads')
            and isinstance(package['payloads'], list)
            and len(package['payloads']) == len(expected['payloads'])
            and set(package['payloads']) == set(expected['payloads']),
            'SQLite package contains unreviewed component payloads')
    installed = [row for row in inventory.get('os_packages', []) if row.get('origin') == 'sqlite']
    lock = json.loads((Path(root) / 'docs/os-package-sources.json').read_bytes())
    origins = [row for row in lock.get('origins', []) if row.get('origin') == 'sqlite']
    require(len(origins) == 1 and origins[0].get('version') == '3.53.4-r0'
            and len(origins[0].get('packages', [])) == 1,
            'SQLite vendor-input source identity differs')
    vendor = origins[0]['packages'][0]
    require(len(installed) == 1
            and all(installed[0].get(key) == vendor.get(key)
                    for key in ('name', 'version', 'build_commit', 'license'))
            and vendor.get('name') == 'sqlite-libs',
            'SQLite installed vendor-input metadata differs from reviewed sources')
    directories = runtime.get('checked_bin_directories')
    allowed = {'/bin', '/sbin', '/usr/bin', '/usr/sbin', '/usr/local/bin', '/usr/local/sbin', '/venv/bin'}
    require(isinstance(directories, list) and all(isinstance(path, str) for path in directories)
            and len(set(directories)) == len(directories) and set(directories) <= allowed
            and {'/usr/bin', '/venv/bin'} <= set(directories),
            'Incomplete SQLite runtime command-path coverage')
    apk_records = whole.get('apk_metadata')
    require(isinstance(apk_records, list) and apk_records,
            'Missing all-layer installed-package metadata')
    final = []
    seen = set()
    for row in apk_records:
        require(isinstance(row, dict) and type(row.get('layer')) is int
                and 0 <= row['layer'] < len(records) and isinstance(row.get('path'), str)
                and isinstance(row.get('sha256'), str) and re.fullmatch(r'[a-f0-9]{64}', row['sha256'])
                and isinstance(row.get('packages'), list),
                'Invalid SQLite layer package metadata')
        require(all(isinstance(package_row, dict)
                    and set(package_row) == set(expected)
                    and all(isinstance(package_row[key], str) and package_row[key]
                            for key in ('name', 'version', 'origin'))
                    and all(isinstance(package_row[key], list)
                            and all(isinstance(value, str) for value in package_row[key])
                            for key in ('provides', 'payloads'))
                    for package_row in row['packages']),
                'Malformed SQLite layer component identity')
        identity = (row['layer'], PurePosixPath(row['path']).as_posix())
        require(identity not in seen, 'Ambiguous SQLite layer package metadata')
        seen.add(identity)
        require(not sqlite_package_findings(row['packages']),
                'SQLite C command-line component occurs in an image layer')
        if identity[1] == 'lib/apk/db/installed':
            final.append(row)
    require(final, 'Missing installed-package metadata in image layers')
    latest = max(final, key=lambda row: row['layer'])
    require(latest['sha256'] == metadata['sha256'] and latest['packages'] == metadata['packages'],
            'SQLite runtime and final-layer component identities differ')
    return {'architecture': arch, 'runtime_apk_metadata_sha256': metadata['sha256'],
            'layers_scanned': len(records), 'sqlite_package': package,
            'justification': 'vulnerable_code_not_present'}


def notice(path):
    body = path.read_bytes()
    return {'path': str(path), 'bytes': len(body), 'sha256': digest(body),
            'text': body.decode('utf-8', errors='replace')}


def expat_replacement_inventory(app=Path('/app'), library=Path('/usr/lib/libexpat.so.1.13.1')):
    """Capture actual bytes; acquisition separately replays the reviewed build."""
    paths = [app / 'EXPAT_BUILD.json', app / 'EXPAT_PATCHED_SECURITY.json']
    if not any(path.exists() or path.is_symlink() for path in paths):
        return None  # The untouched base has no Keep replacement.
    records = []
    for path in paths:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 128 * 1024:
            raise ValueError('Missing bounded regular Expat replacement proof')
        body = path.read_bytes()
        if len(body) > 128 * 1024:
            raise ValueError('Expat replacement proof exceeds size limit')
        value = json.loads(body)
        if not isinstance(value, dict) or body != (json.dumps(value, indent=2, sort_keys=True) + '\n').encode():
            raise ValueError('Expat replacement proof must use canonical JSON bytes')
        records.append((value, digest(body)))
    if library.is_symlink() or not library.is_file() or library.stat().st_size > 16 * 1024 * 1024:
        raise ValueError('Expat replacement must be a bounded canonical regular library')
    body = library.read_bytes()
    if len(body) > 16 * 1024 * 1024:
        raise ValueError('Expat replacement library exceeds size limit')
    return {'build_lock': records[0][0], 'build_lock_sha256': records[0][1],
            'manifest': records[1][0], 'manifest_sha256': records[1][1],
            'library': {'path': str(library), 'sha256': digest(body)}}


def socket_replacement_inventory(app=Path('/app')):
    paths = [app / 'PYTHON_SOCKET_BUILD.json', app / 'SOCKET_SECURITY.json',
             app / 'PYTHON_SOCKET_PYCONFIG.h']
    if not any(path.exists() or path.is_symlink() for path in paths):
        return None
    bodies = []
    for path in paths:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 128 * 1024:
            raise ValueError('Missing bounded regular socket replacement proof')
        bodies.append(path.read_bytes())
    lock, manifest = (json.loads(body) for body in bodies[:2])
    for value, body in zip((lock, manifest), bodies):
        if body != (json.dumps(value, indent=2, sort_keys=True) + '\n').encode():
            raise ValueError('Noncanonical socket replacement JSON')
    path = Path(manifest['library']['path'])
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 4 * 1024 * 1024:
        raise ValueError('Missing bounded regular socket extension')
    return {'build_lock': lock, 'build_lock_sha256': digest(bodies[0]),
            'manifest': manifest, 'manifest_sha256': digest(bodies[1]),
            'pyconfig': bodies[2].decode(), 'pyconfig_sha256': digest(bodies[2]),
            'library': {'path': str(path), 'sha256': digest(path.read_bytes())}}


def sqlite_replacement_inventory(app=Path('/app'), library=Path('/usr/lib/libsqlite3.so.3.54.1')):
    """Inventory actual overlay bytes, separately from signed vendor inputs."""
    paths = [app / 'SQLITE_BUILD.json', app / 'SQLITE_PATCHED_SECURITY.json']
    if not any(path.exists() or path.is_symlink() for path in paths):
        return None
    records = []
    for path in paths:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 128 * 1024:
            raise ValueError('Missing bounded regular SQLite replacement proof')
        body = path.read_bytes()
        if len(body) > 128 * 1024:
            raise ValueError('SQLite replacement proof exceeds size limit')
        value = json.loads(body)
        if not isinstance(value, dict) or body != (json.dumps(value, indent=2, sort_keys=True) + '\n').encode():
            raise ValueError('SQLite replacement proof must use canonical JSON bytes')
        records.append((value, digest(body)))
    if (library.is_symlink() or not library.is_file() or library.resolve(strict=True) != library
            or library.stat().st_size > 16 * 1024 * 1024):
        raise ValueError('SQLite replacement must be a bounded canonical regular library')
    body = library.read_bytes()
    if len(body) > 16 * 1024 * 1024:
        raise ValueError('SQLite replacement library exceeds size limit')
    return {'build_lock': records[0][0], 'build_lock_sha256': records[0][1],
            'manifest': records[1][0], 'manifest_sha256': records[1][1],
            'library': {'path': str(library), 'sha256': digest(body)}}


def sqlite_cli_runtime_inventory(root=Path('/'), installed=None):
    """Check actual installed component/payload metadata and standard CLI aliases.

    The separate archive check scans every layer and regular ELF, including
    deleted files. This runtime check alone is not whole-image absence proof.
    """
    path = root / 'lib/apk/db/installed'
    if installed is None:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > SQLITE_METADATA_LIMIT:
            raise ValueError('Missing bounded regular installed APK metadata')
        installed = path.read_bytes()
    packages = sqlite_apk_metadata(installed)
    findings = sqlite_package_findings(packages)
    checked_paths = []
    for directory in ('bin', 'sbin', 'usr/bin', 'usr/sbin', 'usr/local/bin', 'usr/local/sbin', 'venv/bin'):
        parent = root / directory
        if not parent.is_dir():
            continue
        for candidate in sorted(parent.iterdir()):
            name = candidate.relative_to(root).as_posix()
            if candidate.is_symlink():
                target = os.readlink(candidate)
                if sqlite_cli_name(name) or sqlite_cli_name(target):
                    findings.append({'path': '/' + name, 'target': target, 'rule': 'sqlite-cli-alias'})
            elif candidate.is_file() and sqlite_cli_name(name):
                findings.append({'path': '/' + name, 'rule': 'sqlite-cli-name'})
        checked_paths.append('/' + directory)
    return {'schema': 1, 'scope': 'runtime-filesystem', 'success': not findings,
        'apk_metadata': {'path': '/lib/apk/db/installed', 'sha256': digest(installed),
                         'packages': packages},
        'checked_bin_directories': checked_paths, 'findings': findings,
        'limitations': 'Installed APK component/payload metadata and standard bin-directory names/aliases only; '
                       'require the separately bound all-image-layers evidence for ELF marker coverage.'}


def runtime_inventory(*, http_framing=False):
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
    installed = Path('/lib/apk/db/installed').read_bytes()
    for record in installed.decode('utf-8').split('\n\n'):
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
    result = {'python': sorted(distributions, key=lambda row: row['name'].lower()),
              'os_packages': sorted(os_packages, key=lambda row: row['name']), 'notices': notices}
    if http_framing:
        from http_framing_checks import verify_sources
        lock = json.loads(Path(__file__).with_name('http_framing_sources.json').read_text())
        result['http_framing'] = verify_sources(lock)
    replacement = expat_replacement_inventory()
    if replacement is not None:
        result['expat_replacement'] = replacement
    socket_replacement = socket_replacement_inventory()
    if socket_replacement is not None:
        result['socket_replacement'] = socket_replacement
    sqlite_replacement = sqlite_replacement_inventory()
    if sqlite_replacement is not None:
        result['sqlite_replacement'] = sqlite_replacement
    result['sqlite_cli'] = sqlite_cli_runtime_inventory(installed=installed)
    if not result['sqlite_cli']['success']:
        result['success'] = False
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime', action='store_true')
    parser.add_argument('--http-framing', action='store_true',
                        help='Require the reviewed Keep HTTP parser source identities')
    parser.add_argument('--archive')
    args = parser.parse_args()
    if args.runtime == bool(args.archive):
        parser.error('Select exactly one of --runtime or --archive')
    if args.http_framing and not args.runtime:
        parser.error('--http-framing requires --runtime')
    try:
        patterns = image_patterns(load_private_image_markers(required=bool(args.archive)))
    except ValueError as exc:
        parser.error(str(exc))
    try:
        result = runtime_inventory(http_framing=args.http_framing) if args.runtime else inspect_archive(args.archive, patterns)
    except (OSError, ValueError, KeyError, tarfile.TarError):
        parser.error('Image review failed; inspect the input and configuration')
    print(json.dumps(redacted(result, patterns), indent=2))
    if not result.get('success', True):
        raise SystemExit(1)


if __name__ == '__main__':
    main()
