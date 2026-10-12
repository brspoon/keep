"""Bounded, exact-source optional helper staging; never enrolls or starts Keep.

Only finalized immutable official releases are download authorities. Existing
installations, helper enrollments and service configuration are not overwritten.
All network and filesystem actions are explicit calls, absent on import.
"""
from __future__ import annotations

import gzip
import hashlib
import io
import os
from pathlib import Path
import re
import tarfile
import time
from urllib.parse import urlsplit
import urllib.request

from maintenance_protocol import HASH, REVISION, VERSION, canonical, exact_fields, parse_json
from private_store import StorageError, operation_lock

FORMAT = 'keep.maintenance-helper-bundle.v1'
MINIMUM_PYTHON = '3.12'
MAX_FILE = 512 * 1024
MAX_BUNDLE = 4 * 1024 * 1024
FILES = ('docker_adapter.py', 'helper_bundle.py', 'host_cli.py', 'host_engine.py',
         'host_mailbox.py', 'maintenance_protocol.py', 'private_store.py',
         'recovery_set.py', 'release_resolver.py', 'volume_worker.py', 'windows_native.py')
PREFIX = 'keep-maintenance-helper/'


class BundleError(RuntimeError):
    pass


def identity(version, revision):
    if (not isinstance(version, str) or not VERSION.fullmatch(version)
            or not isinstance(revision, str) or not REVISION.fullmatch(revision)):
        raise BundleError('Helper source identity is invalid')


def create_root(paths, root):
    root = Path(root)
    if root.exists() or root.is_symlink():
        return paths.check(root, directory=True)
    if hasattr(paths, 'create_root'):
        return paths.create_root(root)
    paths.check(root.parent, directory=True, private=False)
    root.mkdir(mode=0o700)
    paths.check(root, directory=True)
    paths.flush_directory(root.parent)
    return root


def source_bundle(paths, source, *, version, revision):
    """Build a deterministic small bundle from reviewed exact-source input files."""
    identity(version, revision)
    source = paths.check(source, directory=True, private=False)
    contents = {name: paths.read(source / name, limit=MAX_FILE, private=False) for name in FILES}
    manifest = {'format': FORMAT, 'version': version, 'revision': revision,
                'minimum_python': MINIMUM_PYTHON,
                'files': {name: {'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)}
                          for name, data in contents.items()}}
    output = io.BytesIO()
    with gzip.GzipFile(fileobj=output, mode='wb', filename='', mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode='w') as archive:
            for name, data in sorted({'MANIFEST.json': canonical(manifest), **contents}.items()):
                entry = tarfile.TarInfo(PREFIX + name)
                entry.size, entry.mode, entry.mtime = len(data), 0o600, 0
                archive.addfile(entry, io.BytesIO(data))
    body = output.getvalue()
    if len(body) > MAX_BUNDLE:
        raise BundleError('Helper source bundle exceeded its bound')
    return body


def inspect_bundle(body, *, version, revision, expected_sha256):
    identity(version, revision)
    if (not isinstance(body, bytes) or not 1 <= len(body) <= MAX_BUNDLE
            or not isinstance(expected_sha256, str) or not HASH.fullmatch(expected_sha256)
            or hashlib.sha256(body).hexdigest() != expected_sha256):
        raise BundleError('Helper source bundle checksum does not match')
    contents, total = {}, 0
    try:
        # Read through the gzip trailer as well as tar's end marker. Tarfile can
        # otherwise accept a truncated gzip stream whose file entries survived.
        with gzip.GzipFile(fileobj=io.BytesIO(body), mode='rb') as compressed:
            expanded = compressed.read(MAX_BUNDLE + 1024 * 1024 + 1)
        if len(expanded) > MAX_BUNDLE + 1024 * 1024:
            raise BundleError('Expanded helper source exceeded its bound')
        with tarfile.open(fileobj=io.BytesIO(expanded), mode='r:') as archive:
            for entry in archive:
                if (len(contents) >= len(FILES) + 1 or not entry.isfile()
                        or entry.name not in {PREFIX + name for name in (*FILES, 'MANIFEST.json')}
                        or entry.name in contents or not 0 < entry.size <= MAX_FILE):
                    raise BundleError('Helper source bundle contains an unexpected member')
                total += entry.size
                if total > MAX_BUNDLE:
                    raise BundleError('Expanded helper source exceeded its bound')
                with archive.extractfile(entry) as stream:
                    data = stream.read(MAX_FILE + 1)
                if len(data) != entry.size:
                    raise BundleError('Helper source bundle member is incomplete')
                contents[entry.name] = data
    except (tarfile.TarError, OSError, EOFError) as error:
        raise BundleError('Helper source bundle is invalid') from error
    if set(contents) != {PREFIX + name for name in (*FILES, 'MANIFEST.json')}:
        raise BundleError('Helper source bundle is incomplete')
    manifest = parse_json(contents.pop(PREFIX + 'MANIFEST.json'), MAX_FILE)
    exact_fields(manifest, ('format', 'version', 'revision', 'minimum_python', 'files'))
    if (manifest['format'] != FORMAT or manifest['version'] != version
            or manifest['revision'] != revision or manifest['minimum_python'] != MINIMUM_PYTHON
            or not isinstance(manifest['files'], dict) or set(manifest['files']) != set(FILES)):
        raise BundleError('Helper source manifest does not match the release')
    result = {}
    for name in FILES:
        declared, data = manifest['files'][name], contents[PREFIX + name]
        exact_fields(declared, ('bytes', 'sha256'))
        if (type(declared['bytes']) is not int or declared['bytes'] != len(data)
                or declared['sha256'] != hashlib.sha256(data).hexdigest()):
            raise BundleError('Helper source file checksum does not match')
        result[name] = data
    return result, manifest


def stage_bundle(paths, state, body, *, version, revision, expected_sha256):
    """Idempotent exact-byte staging; collisions retain the prior source and state."""
    contents, manifest = inspect_bundle(body, version=version, revision=revision, expected_sha256=expected_sha256)
    state = create_root(paths, state)
    with operation_lock(paths, state / 'bundle.lock'):
        releases = state / 'releases'
        if not releases.exists():
            paths.mkdir(releases)
        else:
            paths.check(releases, directory=True)
        root = releases / revision
        if not root.exists():
            paths.mkdir(root)
        else:
            paths.check(root, directory=True)
        proof = canonical({'format': FORMAT, 'version': version, 'revision': revision,
                           'archive_sha256': expected_sha256, 'manifest': manifest})
        for name, data in {**contents, 'bundle-proof.json': proof}.items():
            target = root / name
            if target.exists() or target.is_symlink():
                if paths.read(target, limit=MAX_FILE) != data:
                    raise BundleError('Existing helper source differs and was retained')
            else:
                paths.publish(target, data)
        paths.flush_directory(root)
        return root


class OfficialBundleClient:
    HOSTS = frozenset(('api.github.com', 'github.com', 'release-assets.githubusercontent.com'))

    @classmethod
    def allowed(cls, url):
        parsed = urlsplit(url)
        if (parsed.scheme != 'https' or parsed.hostname not in cls.HOSTS or parsed.port not in (None, 443)
                or parsed.username is not None or parsed.password is not None or parsed.fragment):
            raise BundleError('Helper release transport destination is not allowed')

    def get(self, url, *, limit=MAX_BUNDLE):
        self.allowed(url)
        allowed = self.allowed
        class Redirects(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, request, fp, code, message, headers, new_url):
                allowed(new_url)
                return super().redirect_request(request, fp, code, message, headers, new_url)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), Redirects())
        request = urllib.request.Request(url, headers={'User-Agent': 'Keep-helper-installer', 'Accept-Encoding': 'identity'})
        deadline, data = time.monotonic() + 120, bytearray()
        try:
            with opener.open(request, timeout=15) as response:
                if response.status != 200 or response.headers.get('Content-Encoding', 'identity') != 'identity':
                    raise BundleError('Helper release download is unavailable')
                length = response.headers.get('Content-Length')
                if length is not None and (not length.isdecimal() or int(length) > limit):
                    raise BundleError('Helper release download exceeded its bound')
                while block := response.read(65536):
                    data.extend(block)
                    if len(data) > limit or time.monotonic() > deadline:
                        raise BundleError('Helper release download exceeded its bound')
            return bytes(data)
        except (OSError, urllib.error.URLError) as error:
            raise BundleError('Helper release transport failed') from error


def published_bundle(version, *, client=None):
    """Fetch the small helper asset, tied to immutable release/material source IDs.

    This requires a future published helper asset. Existing releases without it
    fail closed; a raw moving branch is never used as helper executable source.
    """
    if not isinstance(version, str) or not VERSION.fullmatch(version):
        raise BundleError('Helper release version is invalid')
    client = client or OfficialBundleClient()
    base = 'https://github.com/brspoon/keep/releases/'
    release = parse_json(client.get('https://api.github.com/repos/brspoon/keep/releases/tags/' + version, limit=512 * 1024), 512 * 1024)
    if (not isinstance(release, dict) or release.get('draft') is not False or release.get('prerelease') is not False
            or release.get('immutable') is not True or release.get('tag_name') != version
            or release.get('html_url') != base + 'tag/' + version or not release.get('published_at')):
        raise BundleError('Helper requires a finalized immutable stable release')
    assets = release.get('assets')
    if not isinstance(assets, list) or len(assets) > 64:
        raise BundleError('Helper release asset inventory is invalid')
    def asset(name, limit):
        matches = [row for row in assets if isinstance(row, dict) and row.get('name') == name]
        if len(matches) != 1:
            raise BundleError('Helper release asset is unavailable')
        row = matches[0]
        if (type(row.get('size')) is not int or not 1 <= row['size'] <= limit
                or not isinstance(row.get('digest'), str) or not re.fullmatch(r'sha256:[a-f0-9]{64}', row['digest'])):
            raise BundleError('Helper release asset digest is unavailable')
        body = client.get(base + 'download/' + version + '/' + name, limit=limit)
        if len(body) != row['size'] or 'sha256:' + hashlib.sha256(body).hexdigest() != row['digest']:
            raise BundleError('Helper release asset bytes differ from their published identity')
        return body, row['digest'][7:]
    materials_name = 'keep-' + version + '-release-materials.json'
    materials, _ = asset(materials_name, 512 * 1024)
    materials = parse_json(materials, 512 * 1024)
    revision = materials.get('revision') if isinstance(materials, dict) and materials.get('version') == version else None
    identity(version, revision)
    name = 'keep-' + version + '-maintenance-helper.tar.gz'
    body, digest = asset(name, MAX_BUNDLE)
    checksum, _ = asset(name + '.sha256', 4096)
    if checksum != (digest + '  ' + name + '\n').encode('ascii'):
        raise BundleError('Helper release checksum sidecar differs')
    inspect_bundle(body, version=version, revision=revision, expected_sha256=digest)
    return body, version, revision, digest
