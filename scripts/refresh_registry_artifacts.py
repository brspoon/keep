#!/usr/bin/env python3
"""Refresh exact terminal-workflow reviews on the configured Keep host.

Called under the retainer's existing deployment lock. This helper makes only
bounded GitHub GET requests; it never deletes tags or changes credentials.
Credential selection requires a private, explicit operator configuration.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import urllib.error
import urllib.parse
import urllib.request

from review_registry_artifacts import (
    COMMIT_TAG, MAX_REVIEW_BYTES, REPOSITORY, TRANSFER_TAG, ReviewError,
    parse_inventory, review, write_review,
)

CONFIG_SCHEMA = 'keep.registry-github-review.v1'
MAX_REQUESTS = 128
MAX_RESPONSE = 16 * 1024 * 1024
MAX_TOTAL = 32 * 1024 * 1024
ENDPOINT = re.compile(
    r'repos/brspoon/keep(?:/actions/runs/[1-9][0-9]{0,19}/attempts/[1-9][0-9]{0,9}'
    r'|/actions/workflows/image\.yml/runs\?head_sha=[0-9a-f]{40}&per_page=100&page=(?:[1-9]|1[0-9]|20))?\Z'
)


class RefreshError(Exception):
    """Unsafe local review state; preserve artifacts and stop retention."""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError('duplicate field')
        result[key] = value
    return result


def _private_bytes(path, limit):
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > limit):
                raise RefreshError('GitHub review state must be a private bounded owner file.')
            body = stream.read(limit + 1)
            if len(body) > limit:
                raise RefreshError('GitHub review state exceeds its size limit.')
            return body
    except OSError:
        raise RefreshError('GitHub review state is missing or unsafe.') from None


def _state(root):
    state = Path(root) / '.registry-state'
    try:
        info = state.lstat()
    except OSError:
        raise RefreshError('GitHub review directory is unavailable.') from None
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise RefreshError('GitHub review directory must be private and owner-owned.')
    return state


def _configuration(root):
    state = _state(root)
    try:
        value = json.loads(_private_bytes(state / 'github-review.json', 4096), object_pairs_hook=_pairs)
    except (ValueError, UnicodeError, RecursionError):
        raise RefreshError('GitHub review configuration is invalid.') from None
    if (not isinstance(value, dict) or set(value) != {'schema', 'source'}
            or value['schema'] != CONFIG_SCHEMA or value['source'] not in ('git-remote', 'token-file')):
        raise RefreshError('GitHub review configuration is invalid.')
    return state, value['source']


def _credential(root, state, source):
    if source == 'token-file':
        body = _private_bytes(state / 'github-read-token', 4096)
        try:
            token = body.decode('ascii').strip()
        except UnicodeError:
            raise RefreshError('GitHub read credential is invalid.') from None
    else:
        try:
            result = subprocess.run(['git', '-C', str(root), 'config', '--get', 'remote.origin.url'],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10, check=False)
            if result.returncode or len(result.stdout) > 8192:
                raise ValueError('remote unavailable')
            parsed = urllib.parse.urlsplit(result.stdout.decode('utf-8').strip())
            if (parsed.scheme != 'https' or parsed.hostname != 'github.com' or parsed.port is not None
                    or parsed.path not in ('/brspoon/keep', '/brspoon/keep.git')
                    or parsed.query or parsed.fragment):
                raise ValueError('remote differs')
            token = urllib.parse.unquote(parsed.password or parsed.username or '')
        except (OSError, ValueError, UnicodeError, subprocess.TimeoutExpired):
            raise RefreshError('The explicitly selected Keep Git credential is unavailable.') from None
    if not re.fullmatch(r'[A-Za-z0-9_-]{20,4096}', token):
        raise RefreshError('GitHub read credential is invalid.')
    return token


class GitHubReader:
    def __init__(self, root):
        state, source = _configuration(root)
        self._token = _credential(root, state, source)
        self._opener = urllib.request.build_opener(NoRedirect())
        self._repository_checked = False
        self._requests = 0
        self._bytes = 0
        self._cache = {}

    def _get(self, endpoint):
        if not isinstance(endpoint, str) or not ENDPOINT.fullmatch(endpoint):
            raise ReviewError('GitHub review endpoint is outside the fixed Keep read scope.')
        if endpoint in self._cache:
            return self._cache[endpoint]
        if self._requests >= MAX_REQUESTS or self._bytes >= MAX_TOTAL:
            raise ReviewError('GitHub review reached its request limit.')
        self._requests += 1
        request = urllib.request.Request('https://api.github.com/' + endpoint, method='GET',
            headers={'Authorization': 'Bearer ' + self._token, 'Accept': 'application/vnd.github+json'})
        try:
            with self._opener.open(request, timeout=30) as response:
                body = response.read(min(MAX_RESPONSE, MAX_TOTAL - self._bytes) + 1)
            self._bytes += len(body)
            if len(body) > MAX_RESPONSE or self._bytes > MAX_TOTAL:
                raise ValueError('response limit')
            value = json.loads(body, object_pairs_hook=_pairs)
        except (OSError, ValueError, RecursionError, urllib.error.URLError):
            raise ReviewError('GitHub workflow read failed or returned invalid bounded evidence.') from None
        self._cache[endpoint] = value
        return value

    def __call__(self, executable, endpoint):
        # Validate before any authenticated request, including the repository check.
        if not isinstance(endpoint, str) or not ENDPOINT.fullmatch(endpoint):
            raise ReviewError('GitHub review endpoint is outside the fixed Keep read scope.')
        if not self._repository_checked:
            repository = self._get('repos/' + REPOSITORY)
            if (not isinstance(repository, dict) or repository.get('full_name') != REPOSITORY
                    or type(repository.get('private')) is not bool):
                raise ReviewError('GitHub review requires valid Keep repository identity and visibility metadata.')
            self._repository_checked = True
        return self._get(endpoint)


def refresh_review(root, registry, rows):
    """Use fresh caller inventory; missing access never grants artifact removal."""
    state = _state(root)
    config = state / 'github-review.json'
    if not config.exists() and not config.is_symlink():
        return {'status': 'not-configured', 'approved_count': 0}
    _configuration(root)
    existing = state / 'retention-artifacts.json'
    if existing.exists() or existing.is_symlink():
        _private_bytes(existing, MAX_REVIEW_BYTES)
    try:
        parsed, referenced = parse_inventory(rows)
    except ReviewError:
        raise RefreshError('Fresh registry inventory could not be reviewed.') from None
    candidates = [name for name, row in parsed.items() if TRANSFER_TAG.fullmatch(name)
                  or (COMMIT_TAG.fullmatch(name) and row['digest'] not in referenced
                      and not row['image_digests'] & referenced)]
    if not candidates:
        return {'status': 'not-needed', 'approved_count': 0}
    reader = GitHubReader(root)
    approved, omitted = review(rows, executable=None, api=reader)
    temporary = state / ('.artifact-review-' + secrets.token_hex(16) + '.json')
    try:
        write_review(temporary, approved)
        os.replace(temporary, existing)
        descriptor = os.open(state, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except (ReviewError, OSError):
        raise RefreshError('The private artifact review could not be refreshed safely.') from None
    finally:
        temporary.unlink(missing_ok=True)
    return {'status': 'refreshed', 'approved_count': len(approved),
            'omitted_count': len(omitted), 'github_requests': reader._requests}
