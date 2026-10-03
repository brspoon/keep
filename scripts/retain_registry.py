#!/usr/bin/env python3
"""Keep registry retention, run on the production host; dry-run by default.

No container/image pruning or database changes. All remote writes are restricted
in code to brspoon/keep. A separate Docker PAT is read from a private file.
"""
import argparse
import base64
from contextlib import closing
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import subprocess
import tarfile
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

IMAGE = 'brspoon/keep'
VERSION = re.compile(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z')
COMMIT_TAG = re.compile(r'sha-[0-9a-f]{40}(?:-amd64|-arm64)?\Z')
TRANSFER_TAG = re.compile(r'transfer-([0-9]+)-([0-9]+)-(amd64|arm64)\Z')
POLICY = 'current-five-plus-two-prior-versions-v1'
MANIFEST_LEDGER = 'keep.registry-manifest-backlog.v1'
DIGEST = re.compile(r'sha256:[0-9a-f]{64}\Z')
ROOT = Path(__file__).resolve().parents[1]
CONFIG_FIELDS = {'backup_directory', 'backup_pattern', 'containers', 'archive_prefix'}
MAX_CONFIG_BYTES = 16 * 1024


class Hold(Exception):
    """A missing or changing safety condition; perform no further deletion."""


def operator_config(root):
    """Read bounded private deployment settings without exposing their values."""
    state = Path(root) / '.registry-state'
    try:
        info = state.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o700):
            raise Hold('Retention state directory must be private and owner-owned')
        descriptor = os.open(state / 'retention-config.json',
                             os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o600
                    or not 0 < info.st_size <= MAX_CONFIG_BYTES):
                raise Hold('Retention configuration must be a bounded private owner file')
            body = stream.read(MAX_CONFIG_BYTES + 1)
            if len(body) > MAX_CONFIG_BYTES:
                raise Hold('Retention configuration exceeds its size limit')
    except OSError:
        raise Hold('Retention configuration is missing or unsafe') from None

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate configuration field')
            result[key] = value
        return result

    try:
        value = json.loads(body, object_pairs_hook=pairs)
    except (ValueError, UnicodeError, RecursionError):
        raise Hold('Retention configuration is invalid') from None
    if (not isinstance(value, dict) or set(value) not in
            (CONFIG_FIELDS, CONFIG_FIELDS | {'minimum_release'})):
        raise Hold('Retention configuration fields are incomplete or unexpected')
    directory = value['backup_directory']
    if (not isinstance(directory, str) or not 0 < len(directory) <= 4096
            or re.search(r'[\x00-\x1f\x7f]', directory)):
        raise Hold('Retention backup directory is invalid')
    backup = Path(directory)
    if not backup.is_absolute() or '..' in backup.parts or backup.is_symlink() or not backup.is_dir():
        raise Hold('Retention backup directory must be an available absolute directory')
    pattern = value['backup_pattern']
    if (not isinstance(pattern, str) or not re.fullmatch(r'[A-Za-z0-9*?_.-]{1,128}', pattern)
            or '..' in pattern or not pattern.endswith('.tar.gz')):
        raise Hold('Retention backup pattern must be a bounded archive basename glob')
    containers = value['containers']
    if (not isinstance(containers, list) or len(containers) != 2
            or any(not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', name)
                   for name in containers) or containers[0] == containers[1]):
        raise Hold('Retention configuration must identify two distinct Keep containers')
    prefix = value['archive_prefix']
    if (not isinstance(prefix, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', prefix)):
        raise Hold('Retention archive prefix must be one bounded path component')
    floor = value.get('minimum_release')
    if 'minimum_release' in value and (not isinstance(floor, str) or len(floor) > 64
                                       or not VERSION.fullmatch(floor)):
        raise Hold('Retention minimum release must be a bounded semantic version')
    return value


def release_floor(production):
    """Validate an optional baseline without admitting a future release."""
    floor = production.get('minimum_release')
    if floor is None:
        return None
    current = production.get('version')
    if (not isinstance(floor, str) or len(floor) > 64 or not VERSION.fullmatch(floor)
            or not isinstance(current, str) or not VERSION.fullmatch(current)):
        raise Hold('Retention minimum release or production version is invalid')
    parsed = tuple(map(int, floor.split('.')))
    if parsed > tuple(map(int, current.split('.'))):
        raise Hold('Retention minimum release is newer than production')
    return parsed


def digest(value):
    if not isinstance(value, str) or not DIGEST.fullmatch(value):
        raise Hold('Incomplete registry digest metadata')
    return value


def closure(tag):
    result = {digest(tag.get('digest'))}
    if not isinstance(tag.get('images'), list) or not tag['images']:
        raise Hold('Incomplete platform metadata')
    result.update(digest(image.get('digest')) for image in tag['images'])
    return result


def inventory(rows):
    result = {}
    for row in rows:
        name = row.get('name')
        if not isinstance(name, str) or name in result:
            raise Hold('Invalid or duplicate registry tag')
        closure(row)
        result[name] = row
    return result


def protection(tags, production, reviewed_artifacts=None):
    reviewed_artifacts = reviewed_artifacts or {}
    version = production.get('version', '')
    if not VERSION.fullmatch(version) or version not in tags or 'stable' not in tags:
        raise Hold('Production version or stable tag is missing')
    stable = tags['stable']
    if stable['digest'] != tags[version]['digest'] or stable['digest'] not in production['registry_digests']:
        raise Hold('Stable is not the verified production release; wait for deployment')
    releases = sorted((name for name in tags if VERSION.fullmatch(name)),
                      key=lambda name: tuple(map(int, name.split('.'))), reverse=True)
    if releases[0] != version:
        raise Hold('A newer release is staged; wait for publication and deployment to finish')
    floor = release_floor(production)
    eligible_releases = [name for name in releases
                         if floor is None or tuple(map(int, name.split('.'))) >= floor]
    revision = production.get('revision', '')
    if not re.fullmatch(r'[0-9a-f]{40}', revision):
        raise Hold('Production source revision is missing')
    commit = 'sha-' + revision
    current = {version, 'stable', commit, commit + '-amd64', commit + '-arm64'}
    if not current <= set(tags) or tags[commit]['digest'] != stable['digest']:
        raise Hold('Current immutable release aliases are missing or inconsistent')
    # Tag removal is independent of manifest removal. Prior version indexes
    # retain their native children even when redundant commit/architecture tags go.
    retained = current | set(eligible_releases[1:3])
    known_release_digests = set().union(*(closure(tags[name]) for name in releases))
    for name, tag in tags.items():
        if name in retained or VERSION.fullmatch(name):
            continue
        if COMMIT_TAG.fullmatch(name) and tag['digest'] in known_release_digests:
            continue
        if (COMMIT_TAG.fullmatch(name) or TRANSFER_TAG.fullmatch(name)) and name in reviewed_artifacts:
            if digest(reviewed_artifacts[name]) != tag['digest']:
                raise Hold('Reviewed build artifact changed')
            continue
        # Orphans, active/unreviewed transfers and custom references are preserved.
        retained.add(name)
    protected = set()
    for name in retained:
        protected.update(closure(tags[name]))
    # Refuse malformed retained multi-platform releases before deleting anything.
    for name in retained:
        if name == 'stable' or VERSION.fullmatch(name):
            platforms = {(image.get('os'), image.get('architecture')) for image in tags[name]['images']}
            if len(tags[name]['images']) != 2 or platforms != {('linux', 'amd64'), ('linux', 'arm64')}:
                raise Hold('Retained release must include amd64 and arm64')
    children = {image['architecture']: image['digest'] for image in stable['images']}
    for name in (commit, version):
        images = tags[name]['images']
        platforms = {(image.get('os'), image.get('architecture')): image.get('digest') for image in images}
        if len(images) != 2 or platforms != {('linux', arch): value for arch, value in children.items()}:
            raise Hold('Current release index platform metadata differs between aliases')
    for arch in ('amd64', 'arm64'):
        native = tags[commit + '-' + arch]
        if (native['digest'] != children[arch] or len(native['images']) != 1 or
                native['images'][0].get('os') != 'linux' or
                native['images'][0].get('architecture') != arch or
                native['images'][0].get('digest') != children[arch]):
            raise Hold('Current native tag does not match its index child')
    return releases, retained, protected


def plan(rows, production, reviewed_artifacts=None):
    tags = inventory(rows)
    reviewed_artifacts = reviewed_artifacts or {}
    releases, retained, protected = protection(tags, production, reviewed_artifacts)
    # Remove redundant build aliases before their version index. Otherwise a
    # fresh inventory would correctly classify those aliases as unknown orphans
    # after the version tag disappeared, interrupting a reviewed cleanup.
    ordered = sorted((name for name in tags if name not in retained),
                     key=lambda name: (bool(VERSION.fullmatch(name)), name))
    remove = {name: tags[name]['digest'] for name in ordered}
    discarded = set().union(*(closure(tags[name]) for name in remove)) if remove else set()
    roots = {tags[name]['digest'] for name in remove if VERSION.fullmatch(name)}
    removable = discarded - protected
    return {'image': IMAGE, 'policy': POLICY, 'production': production['version'],
            'minimum_release': production.get('minimum_release'),
            'retained_releases': [name for name in releases if name in retained],
            'retained_tags': sorted(retained),
            'protected_extra_tags': sorted(retained - {'stable', 'sha-' + production['revision'],
                'sha-' + production['revision'] + '-amd64', 'sha-' + production['revision'] + '-arm64'} - set(releases[:3])),
            'reviewed_artifacts': {name: value for name, value in reviewed_artifacts.items() if name in remove},
            'stable': tags['stable']['digest'], 'tags': remove,
            'manifests': sorted(removable & roots) + sorted(removable - roots)}


def reviewed_targets(proposed):
    tags = proposed.get('tags')
    confirmed = proposed.get('confirmed_absent', [])
    if not isinstance(tags, dict) or not isinstance(confirmed, list):
        raise Hold('Invalid pending cleanup proposal')
    names = set(tags) | set(confirmed)
    if any(not isinstance(name, str) or not (VERSION.fullmatch(name) or COMMIT_TAG.fullmatch(name) or TRANSFER_TAG.fullmatch(name))
           for name in names):
        raise Hold('Invalid pending cleanup proposal')
    return names


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


class Registry:
    def __init__(self, secret):
        self.opener = urllib.request.build_opener(NoRedirect())
        self.hub_token = self.request('https://hub.docker.com/v2/auth/token',
            data={'identifier': 'brspoon', 'secret': secret})['access_token']
        basic = base64.b64encode(('brspoon:' + secret).encode()).decode()
        url = 'https://auth.docker.io/token?' + urllib.parse.urlencode({
            'service': 'registry.docker.io', 'scope': 'repository:' + IMAGE + ':pull,push,delete'})
        self.registry_token = self.request(url, authorization='Basic ' + basic)['token']

    def request(self, url, *, data=None, method=None, authorization=None):
        headers = {'Content-Type': 'application/json', 'User-Agent': 'Keep-retention'}
        if authorization:
            headers['Authorization'] = authorization
        req = urllib.request.Request(url, method=method,
            data=json.dumps(data).encode() if data is not None else None, headers=headers)
        try:
            with self.opener.open(req, timeout=30) as response:
                body = response.read()
                return json.loads(body) if body else None
        except urllib.error.HTTPError as error:
            if method == 'DELETE' and error.code == 404:
                return None  # Idempotent replay of an interrupted cleanup.
            raise Hold('Registry request failed (HTTP %d); no further deletions' % error.code) from None
        except (urllib.error.URLError, TimeoutError, ValueError):
            raise Hold('Registry request failed; no further deletions') from None

    def tags(self, expected_absent=()):
        base = 'https://hub.docker.com/v2/namespaces/brspoon/repositories/keep/'
        repository = self.request(base, authorization='Bearer ' + self.hub_token)
        if not isinstance(repository, dict) or type(repository.get('is_private')) is not bool:
            raise Hold('Keep repository visibility metadata is missing or invalid')
        url = base + 'tags?page_size=100'
        rows, seen = [], set()
        expected = None
        while url:
            parsed = urllib.parse.urlsplit(url)
            if (parsed.scheme != 'https' or parsed.netloc != 'hub.docker.com' or
                    parsed.path.rstrip('/') != urllib.parse.urlsplit(base + 'tags').path or url in seen):
                raise Hold('Unexpected registry pagination URL')
            seen.add(url)
            page = self.request(url, authorization='Bearer ' + self.hub_token)
            if expected is None:
                expected = page['count']
            if page['count'] != expected or len(seen) > 100:
                raise Hold('Registry inventory changed or exceeded the page limit')
            rows.extend(page['results'])
            url = page['next']
        # Hub's cached count can lag a publication (observed 5 versus 9 rows).
        # It can also remain high briefly after a successful deletion. Accept
        # that overcount only when it is no larger than the reviewed deletion
        # targets that are now absent. This also handles partial count-cache
        # convergence; every larger, unexplained shortfall still fails closed.
        if not isinstance(expected, int) or expected < 0:
            raise Hold('Incomplete registry tag inventory')
        tags = inventory(rows)
        shortfall = expected - len(rows)
        reviewed_absent = set(expected_absent) - set(tags)
        if shortfall > len(reviewed_absent):
            raise Hold('Incomplete registry tag inventory')
        return rows

    def delete_tag(self, name):
        if not (VERSION.fullmatch(name) or COMMIT_TAG.fullmatch(name) or TRANSFER_TAG.fullmatch(name)):
            raise Hold('Refusing to delete a non-release tag')
        # Same tag-removal API used by docker/hub-tool (pkg/hub/tags.go).
        self.request('https://hub.docker.com/v2/repositories/brspoon/keep/tags/' + name + '/',
                     method='DELETE', authorization='Bearer ' + self.hub_token)

    def delete_manifest(self, value):
        self.request('https://registry-1.docker.io/v2/brspoon/keep/manifests/' + digest(value),
                     method='DELETE', authorization='Bearer ' + self.registry_token)

    def manifest(self, value):
        """Read one immutable manifest; an exact 404 is the only absence proof."""
        value = digest(value)
        types = ('application/vnd.oci.image.index.v1+json',
                 'application/vnd.docker.distribution.manifest.list.v2+json',
                 'application/vnd.oci.image.manifest.v1+json',
                 'application/vnd.docker.distribution.manifest.v2+json')
        request = urllib.request.Request(
            'https://registry-1.docker.io/v2/brspoon/keep/manifests/' + value,
            headers={'Authorization': 'Bearer ' + self.registry_token,
                     'Accept': ', '.join(types), 'User-Agent': 'Keep-retention'})
        try:
            with self.opener.open(request, timeout=30) as response:
                body = response.read(2 * 1024 * 1024 + 1)
                if (len(body) > 2 * 1024 * 1024 or
                        'sha256:' + hashlib.sha256(body).hexdigest() != value):
                    raise Hold('Registry manifest bytes differ from the reviewed digest')
                data = json.loads(body)
        except urllib.error.HTTPError as error:
            if error.code == 404:
                return None
            raise Hold('Manifest read failed (HTTP %d)' % error.code) from None
        except (urllib.error.URLError, TimeoutError, ValueError):
            raise Hold('Manifest read failed; absence is not established') from None
        if (not isinstance(data, dict) or data.get('schemaVersion') != 2 or
                data.get('mediaType') not in types or data.get('subject')):
            raise Hold('Unsupported manifest or subject reference; preserve it for review')
        children = data.get('manifests', [])
        if (not isinstance(children, list) or len(children) > 100 or
                any(not isinstance(child, dict) for child in children)):
            raise Hold('Invalid manifest reference graph')
        return {'children': sorted({digest(child.get('digest')) for child in children})}


def manifest_backlog(path):
    """Read exact prior targets or an explicit operator-reviewed inventory."""
    if not path.exists() and not path.is_symlink():
        return {}
    if (path.is_symlink() or not path.is_file() or path.stat().st_uid != os.getuid()
            or path.stat().st_mode & 0o077 or path.stat().st_size > 2 * 1024 * 1024):
        raise Hold('Manifest backlog must be a private owner-only file')
    data = json.loads(path.read_text())
    if (not isinstance(data, dict) or data.get('schema') != MANIFEST_LEDGER or data.get('image') != IMAGE or
            not isinstance(data.get('manifests'), dict) or len(data['manifests']) > 10000):
        raise Hold('Unexpected manifest backlog format or repository')
    records = data['manifests']
    for value, record in records.items():
        digest(value)
        if (not isinstance(record, dict) or set(record) != {'children'} or
                not isinstance(record['children'], list) or len(record['children']) > 100
                or len(record['children']) != len(set(record['children']))):
            raise Hold('Invalid remembered manifest references')
        for child in record['children']:
            digest(child)
            if child not in records:
                raise Hold('Incomplete remembered manifest references')
    manifest_order(records)
    return records


def manifest_order(records):
    """Parents precede children, including a child shared by several parents."""
    remaining = set(records)
    order = []
    while remaining:
        children = {child for parent in remaining for child in records[parent]['children']
                    if child in remaining}
        roots = sorted(remaining - children)
        if not roots:
            raise Hold('Cyclic remembered manifest graph')
        order.extend(roots)
        remaining.difference_update(roots)
    return order


def current_manifest_references(registry, tags):
    """Protect nested index references, including arbitrary custom tagged roots."""
    queue = sorted({row['digest'] for row in tags.values()})
    protected = set()
    while queue:
        value = queue.pop()
        if value in protected:
            continue
        if len(protected) >= 10000:
            raise Hold('Current registry reference graph exceeds the reviewed bound')
        record = registry.manifest(value)
        if record is None:
            raise Hold('A currently tagged manifest is unavailable; preserve pending targets')
        protected.add(value)
        queue.extend(record['children'])
    return protected


def remember_manifest_targets(registry, proposed, state):
    """Persist the graph before tags disappear, never broaden to unknown objects."""
    path = state / 'retention-manifests.json'
    records = manifest_backlog(path)
    targets = set(proposed['manifests']) | set(records)
    # A previous result/pending proposal can predate the durable graph feature.
    for name in ('retention-result.json', 'retention-pending.json'):
        previous_path = state / name
        if previous_path.exists():
            previous = json.loads(previous_path.read_text())
            if previous.get('image') != IMAGE or not isinstance(previous.get('manifests'), list):
                raise Hold('Unexpected previous cleanup manifest targets')
            absent = {digest(value) for value in previous.get('confirmed_absent_manifests', [])}
            targets.update(digest(value) for value in previous['manifests'] if value not in absent)
    queue = sorted(targets)
    refreshed = {}
    while queue:
        value = queue.pop()
        if value in refreshed:
            continue
        if len(refreshed) >= 10000:
            raise Hold('Manifest backlog exceeds the reviewed bound')
        current = registry.manifest(value)
        if current is None:
            current = records.get(value, {'children': []})
        elif value in records and current != records[value]:
            raise Hold('Remembered immutable manifest references changed')
        refreshed[value] = current
        queue.extend(child for child in current['children'] if child not in refreshed)
    proposed['manifest_records'] = refreshed
    proposed['manifests'] = manifest_order(refreshed)
    atomic_json(path, {'schema': MANIFEST_LEDGER, 'image': IMAGE, 'manifests': refreshed})
    return proposed


def docker(*args):
    return subprocess.check_output(['docker', *args], text=True, timeout=30)


def recovery(root, receipt, configuration=None):
    """Check retained local recovery and current full-backup coverage."""
    configuration = operator_config(root) if configuration is None else configuration
    record = Path(receipt.get('recovery', ''))
    if (record.parent != root / '.deploy-backups' or record.is_symlink() or not record.is_dir()
            or not re.fullmatch(r'registry-\d{8}T\d{6}Z', record.name)):
        raise Hold('Recorded local recovery directory is unavailable')
    for name in ('database.sqlite3', 'configuration.tgz', 'images.json', 'deployed.json'):
        path = record / name
        if path.is_symlink() or not path.is_file() or not path.stat().st_size:
            raise Hold('Local recovery artifacts are incomplete')
    if json.loads((record / 'deployed.json').read_text()) != receipt:
        raise Hold('Local recovery receipt differs from production')
    try:
        with closing(sqlite3.connect((record / 'database.sqlite3').absolute().as_uri() + '?mode=ro', uri=True)) as db:
            if db.execute('PRAGMA integrity_check').fetchall() != [('ok',)]:
                raise Hold('Retained recovery database integrity failed')
    except sqlite3.Error:
        raise Hold('Retained recovery database integrity could not be verified') from None
    try:
        with tarfile.open(record / 'configuration.tgz', 'r:gz') as saved:
            members = {member.name.removeprefix('./'): member for member in saved.getmembers()}
            for name in ('.env', 'compose.yml', 'compose.override.yml', 'compose.registry.yml'):
                member = members.get(name)
                if member is None or not member.isfile() or not 0 < member.size <= 1024 * 1024:
                    raise Hold('Local recovery configuration coverage is incomplete')
                if len(saved.extractfile(member).read()) != member.size:
                    raise Hold('Local recovery configuration archive is truncated')
    except tarfile.TarError:
        raise Hold('Local recovery configuration archive could not be verified') from None
    previous = json.loads((record / 'images.json').read_text()).get('previous')
    if not isinstance(previous, list) or len(previous) != 2:
        raise Hold('Paired rollback image identities are missing')
    previous = [digest(image) for image in previous]
    available = json.loads(docker('image', 'inspect', *previous))
    if len(available) != 2 or [image.get('Id') for image in available] != previous:
        raise Hold('Recorded paired local rollback images are unavailable')
    archives = sorted(Path(configuration['backup_directory']).glob(configuration['backup_pattern']))
    if not archives:
        raise Hold('Full NAS backup is missing')
    archive = archives[-1]
    age = datetime.now(timezone.utc).timestamp() - archive.stat().st_mtime
    if archive.is_symlink() or not archive.is_file() or not 0 <= age <= 48 * 3600:
        raise Hold('Full NAS backup is stale or invalid')
    try:
        with tarfile.open(archive, 'r:gz') as saved:
            members = {member.name.removeprefix('./'): member for member in saved.getmembers()}
            for name in ('.env', 'compose.yml', 'compose.override.yml', 'compose.registry.yml'):
                member = members.get(configuration['archive_prefix'] + '/' + name)
                if member is None or not member.isfile() or member.size > 1024 * 1024:
                    raise Hold('Full NAS backup lacks deployment configuration coverage')
                if saved.extractfile(member).read() != (root / name).read_bytes():
                    raise Hold('Full NAS backup differs from the current deployment configuration')
    except tarfile.TarError:
        raise Hold('Full NAS backup archive could not be verified') from None


def production(root=ROOT, configuration=None):
    configuration = operator_config(root) if configuration is None else configuration
    state = root / '.registry-state'
    if any((state / name).exists() for name in ('dev-trial-active', 'update-request', 'failed-image', 'last-error.json')):
        raise Hold('Deployment is pending, held, or failed')
    receipt = json.loads((state / 'deployed.json').read_text())
    release_floor({'version': receipt.get('version'),
                   'minimum_release': configuration.get('minimum_release')})
    containers = json.loads(docker('inspect', *configuration['containers']))
    if len(containers) != 2:
        raise Hold('Both Keep containers are required')
    identities = []
    for container in containers:
        if (container['State']['Status'] != 'running' or
                container['State'].get('Health', {}).get('Status') != 'healthy'):
            raise Hold('Both Keep containers must be healthy')
        labels = container['Config'].get('Labels', {})
        identities.append((container['Image'], labels.get('org.opencontainers.image.version'),
                           labels.get('org.opencontainers.image.revision')))
    expected = (receipt.get('image'), receipt.get('version'), receipt.get('revision'))
    if any(identity != expected for identity in identities):
        raise Hold('Live containers do not match the successful deployment receipt')
    if not VERSION.fullmatch(expected[1] or '') or not re.fullmatch('[0-9a-f]{40}', expected[2] or ''):
        raise Hold('Invalid production release identity')
    image = json.loads(docker('image', 'inspect', expected[0]))[0]
    refs = [ref.split('@', 1)[1] for ref in image.get('RepoDigests', []) if ref.startswith(IMAGE + '@')]
    # Read-only integrity verification; no media queries or database mutation.
    code = "import sqlite3; c=sqlite3.connect('file:/app/data/keep.sqlite3?mode=ro',uri=True); assert c.execute('PRAGMA integrity_check').fetchone()[0]=='ok'"
    docker('exec', configuration['containers'][0], 'python', '-c', code)
    recovery(root, receipt, configuration)
    return {'version': expected[1], 'image': expected[0], 'revision': expected[2],
            'registry_digests': refs, 'minimum_release': configuration.get('minimum_release')}


def reviewed_artifacts(root, rows):
    """Use a private operator review of exact terminal workflow attempts only."""
    path = root / '.registry-state/retention-artifacts.json'
    if not path.exists():
        return {}
    if (path.is_symlink() or not path.is_file() or path.stat().st_uid != os.getuid()
            or path.stat().st_mode & 0o077 or path.stat().st_size > 512 * 1024):
        raise Hold('Artifact review must be a private owner-only file')
    data = json.loads(path.read_text())
    if data.get('schema') != 'keep.registry-artifact-review.v1' or data.get('repository') != 'brspoon/keep':
        raise Hold('Artifact review has an unexpected repository or format')
    reviewed = datetime.fromisoformat(data.get('reviewed_at', '').replace('Z', '+00:00'))
    if reviewed.tzinfo is None or reviewed > datetime.now(timezone.utc):
        raise Hold('Artifact review timestamp is invalid')
    entries = data.get('artifacts')
    if not isinstance(entries, dict):
        raise Hold('Artifact review entries are missing')
    result = {}
    tags = inventory(rows)
    for name, entry in entries.items():
        if not isinstance(name, str) or not (COMMIT_TAG.fullmatch(name) or TRANSFER_TAG.fullmatch(name)):
            raise Hold('Artifact review contains an unsupported tag')
        if (not isinstance(entry, dict) or entry.get('status') != 'completed' or
                entry.get('conclusion') not in ('success', 'failure', 'cancelled', 'timed_out', 'neutral', 'skipped', 'action_required', 'stale') or
                not re.fullmatch(r'[1-9][0-9]{0,19}', str(entry.get('run_id', ''))) or
                type(entry.get('run_attempt')) is not int or entry['run_attempt'] < 1 or
                not re.fullmatch(r'[0-9a-f]{40}', entry.get('head_sha', ''))):
            raise Hold('Artifact review lacks a terminal workflow attempt identity')
        transfer = TRANSFER_TAG.fullmatch(name)
        if transfer and (transfer[1] != str(entry['run_id']) or int(transfer[2]) != entry['run_attempt']):
            raise Hold('Transfer review does not identify its exact workflow attempt')
        if COMMIT_TAG.fullmatch(name) and name[4:44] != entry['head_sha']:
            raise Hold('Orphan commit review does not match its source revision')
        value = digest(entry.get('digest'))
        if name in tags:
            if tags[name]['digest'] != value:
                raise Hold('Reviewed build artifact changed')
            result[name] = value
    return result


def atomic_json(path, value):
    temporary = path.with_suffix('.tmp')
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'w') as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(json.dumps(value, indent=2) + '\n')
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def apply(registry, proposed, get_production):
    """Revalidate live health and all remaining references before each write."""
    deleted = []
    expected_absent = reviewed_targets(proposed)
    records = proposed.get('manifest_records', {})
    absent = set()
    for kind, targets in (('tag', proposed['tags']), ('manifest', proposed['manifests'])):
        for target in targets:
            live = get_production()
            tags = inventory(registry.tags(expected_absent=expected_absent))
            _, retained, protected = protection(tags, live, proposed.get('reviewed_artifacts'))
            if (live['version'] != proposed['production']
                    or live.get('minimum_release') != proposed.get('minimum_release')
                    or tags['stable']['digest'] != proposed['stable']):
                raise Hold('Production or stable changed during cleanup')
            # Any new/custom reference outside the reviewed removal set wins.
            for name, tag in tags.items():
                if name not in proposed['tags']:
                    protected.update(closure(tag))
            if kind == 'tag':
                if target not in tags:
                    continue
                value = tags[target]['digest']
                if value != proposed['tags'][target] or target in retained:
                    raise Hold('Deletion target changed or became protected')
                registry.delete_tag(target)
            else:
                if target in protected or any(target in closure(tag) for tag in tags.values()):
                    continue  # Shared manifests are retained, even for old releases.
                # A remembered parent can acquire a new/custom tag, or be kept
                # outside this proposal. Protect its children even if untagged.
                blocked = False
                for parent, record in records.items():
                    if target in record['children'] and parent not in absent:
                        if registry.manifest(parent) is not None:
                            blocked = True
                            break
                if blocked:
                    continue
                current = registry.manifest(target)
                if current is None:
                    absent.add(target)
                    continue
                if target in current_manifest_references(registry, tags):
                    continue
                if target in records and current != records[target]:
                    raise Hold('Reviewed immutable manifest references changed')
                try:
                    registry.delete_manifest(target)
                except Hold:
                    # DELETE can return an error after taking effect. An exact
                    # absence readback resolves that outcome without retrying.
                    if registry.manifest(target) is not None:
                        raise
                if registry.manifest(target) is not None:
                    raise Hold('Manifest deletion is not yet confirmed; preserve pending targets')
                absent.add(target)
            deleted.append({'kind': kind, 'target': target})
    proposed['confirmed_absent_manifests'] = sorted(absent)
    return deleted


def run(root, execute, replace_stale=False, refresh_artifacts=False):
    configuration = operator_config(root)
    state = root / '.registry-state'

    def get_production():
        current = operator_config(root)
        if current != configuration:
            raise Hold('Retention configuration changed during cleanup')
        return production(root, current)

    # Same lock used by the host updater: deployment and cleanup cannot overlap.
    with (root / '.git/keep-deploy.lock').open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Hold('Deployment lock is busy') from None
        live = get_production()
        token = state / 'retention-token'
        if (token.is_symlink() or not token.is_file() or token.stat().st_uid != os.getuid()
                or token.stat().st_mode & 0o077):
            raise Hold('Retention token must be a private owner-only file')
        registry = Registry(token.read_text().strip())
        artifact_refresh = None
        def read_artifact_review(rows):
            nonlocal artifact_refresh
            if refresh_artifacts:
                # Load only for the explicit host option. The helper uses an
                # existing configured GitHub reader; it has no deletion role.
                from refresh_registry_artifacts import RefreshError, refresh_review
                try:
                    artifact_refresh = refresh_review(root, registry, rows)
                except RefreshError:
                    raise Hold('Artifact review refresh found unsafe state; preserve cleanup targets') from None
            return reviewed_artifacts(root, rows)
        pending = state / 'retention-pending.json'
        if execute and pending.exists():
            previous = json.loads(pending.read_text())
            # Reconstruct the proposal from still-present tags, never widen it.
            if previous.get('image') != IMAGE:
                raise Hold('Unexpected pending cleanup repository')
            # Docker Hub's aggregate count can remain high after an earlier
            # partial cleanup. Only the reviewed targets in this exact pending
            # proposal may explain that shortfall while resuming it.
            allowed_absent = reviewed_targets(previous)
            rows = registry.tags(expected_absent=allowed_absent)
            reviewed = read_artifact_review(rows)
            current_names = set(inventory(rows))
            if (previous.get('production') != live['version'] or previous.get('policy') != POLICY
                    or previous.get('minimum_release') != live.get('minimum_release')):
                if not replace_stale:
                    raise Hold('Review pending cleanup after a production or retention policy change')
                proposed = plan(rows, live, reviewed)
                missing = sorted(allowed_absent - current_names)
                if missing:
                    proposed['confirmed_absent'] = missing
                stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
                archived = state / ('retention-pending.stale-' + stamp + '.json')
                if archived.exists():
                    raise Hold('Stale pending archive already exists')
                # Preserve the old proposal before atomically replacing the
                # live pending file below. A crash cannot silently discard it.
                atomic_json(archived, previous)
            else:
                if replace_stale:
                    raise Hold('Pending cleanup already matches production')
                plan(rows, live, reviewed)  # Revalidate current protection before any write.
                proposed = previous
                if any(name in current_names and reviewed.get(name) != value
                       for name, value in proposed.get('reviewed_artifacts', {}).items()):
                    raise Hold('Pending artifact cleanup requires its exact terminal-run review')
        else:
            if replace_stale:
                raise Hold('No stale pending cleanup proposal to replace')
            allowed_absent = set()
            result = state / 'retention-result.json'
            if result.exists():
                previous_result = json.loads(result.read_text())
                if previous_result.get('image') == IMAGE:
                    allowed_absent = reviewed_targets(previous_result)
            rows = registry.tags(expected_absent=allowed_absent)
            proposed = plan(rows, live, read_artifact_review(rows))
            missing = sorted(allowed_absent - set(inventory(rows)))
            if missing:
                proposed['confirmed_absent'] = missing
        if artifact_refresh is not None:
            proposed['artifact_review_refresh'] = artifact_refresh
        proposed = remember_manifest_targets(registry, proposed, state)
        atomic_json(state / 'retention-plan.json', proposed)
        if not execute:
            return {'mode': 'dry-run', **proposed}
        atomic_json(pending, proposed)
        deleted = apply(registry, proposed, get_production)
        remaining = inventory(registry.tags(expected_absent=reviewed_targets(proposed)))
        protection(remaining, get_production(), proposed.get('reviewed_artifacts'))
        if any(name in remaining for name in proposed['tags']):
            raise Hold('Registry deletion not yet visible; pending plan retained')
        result = {'mode': 'execute', **proposed, 'deleted': deleted}
        atomic_json(state / 'retention-result.json', result)
        # Keep unfinished exact targets. Successful absence proofs are retained
        # in the result receipt and need not accumulate in the active backlog.
        absent = set(proposed.get('confirmed_absent_manifests', []))
        records = {value: {'children': [child for child in record['children'] if child not in absent]}
                   for value, record in proposed['manifest_records'].items() if value not in absent}
        atomic_json(state / 'retention-manifests.json',
                    {'schema': MANIFEST_LEDGER, 'image': IMAGE, 'manifests': records})
        pending.unlink()
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--replace-stale-pending', action='store_true')
    parser.add_argument('--refresh-artifacts', action='store_true',
                        help='refresh exact terminal artifact reviews with the existing configured GitHub reader')
    parser.add_argument('--root', type=Path, default=ROOT)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        if args.replace_stale_pending and not args.execute:
            raise Hold('--replace-stale-pending requires --execute')
        result = run(args.root, args.execute, args.replace_stale_pending, args.refresh_artifacts)
    except (Hold, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        # Never print arbitrary exception content that could carry credentials.
        message = str(error) if isinstance(error, Hold) else 'Safety check failed; inspect host configuration'
        print(json.dumps({'status': 'held', 'reason': message}))
        raise SystemExit(1)
    print(json.dumps(result))


if __name__ == '__main__':
    main()
