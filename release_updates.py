"""Recorded, bounded checks of Keep's public stable releases.

Reading observations performs no network I/O and never initializes a database.
The worker checks only the fixed public repository, without credentials.
"""
from contextlib import closing
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import json
import math
from pathlib import Path
import re
import sqlite3
import time

import requests


REPOSITORY = 'brspoon/keep'
REPOSITORY_URL = 'https://github.com/' + REPOSITORY
LATEST_URL = 'https://api.github.com/repos/' + REPOSITORY + '/releases/latest'
RECENT_URL = 'https://api.github.com/repos/' + REPOSITORY + '/releases?per_page=10'
CHECK_INTERVAL = 21600
MANUAL_INTERVAL = 60
RETRY_INTERVAL = 900
REQUEST_BUDGET = 15
MAX_BODY = 2 * 1024 * 1024
HISTORY_LIMIT = 5
VERSION = re.compile(r'v?((?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8}))\Z')
DATE = re.compile(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}'
                  r'(?:\.[0-9]{1,6})?(?:Z|[+-][0-9]{2}:[0-9]{2})\Z')
ERROR_MESSAGES = {
    'github_unavailable': 'GitHub release information is unavailable. Try again later.',
    'rate_limited': 'GitHub release checks are temporarily rate limited.',
    'invalid_response': 'GitHub did not provide usable release information. Try again later.',
    'no_stable_release': 'A published stable release could not be found.',
    'invalid_cache': 'Recorded release information is unavailable. Check again.',
    'check_interrupted': 'The previous release check did not finish. Check again.',
}


class ReleaseCheckError(Exception):
    def __init__(self, code, retry_at=None):
        self.code = code if code in ERROR_MESSAGES else 'invalid_response'
        self.retry_at = retry_at
        super().__init__(ERROR_MESSAGES[self.code])


def version(value):
    match = VERSION.fullmatch(value) if isinstance(value, str) else None
    return match[1] if match else None


def _number(value):
    return value if type(value) in (int, float) and math.isfinite(value) and 0 <= value <= 32503680000 else None


def timestamp(value):
    value = _number(value)
    if value is None:
        return None
    try:
        return datetime.fromtimestamp(value, timezone.utc).isoformat().replace('+00:00', 'Z')
    except (ValueError, OverflowError, OSError):
        return None


def _date(value):
    if not isinstance(value, str) or not DATE.fullmatch(value):
        return None
    try:
        return datetime.fromisoformat(value.replace('Z', '+00:00')).astimezone(timezone.utc).isoformat().replace('+00:00', 'Z')
    except (ValueError, OverflowError):
        return None


def _release(payload):
    if not isinstance(payload, dict) or payload.get('draft') is not False or payload.get('prerelease') is not False:
        raise ReleaseCheckError('invalid_response')
    tag = payload.get('tag_name')
    release_version = version(tag)
    published = _date(payload.get('published_at'))
    name = payload.get('name')
    if not release_version or not published or name is not None and not isinstance(name, str):
        raise ReleaseCheckError('invalid_response')
    name = ' '.join((name or '').split())[:200] or 'Version ' + release_version
    return {'version': release_version, 'tag': tag, 'name': name, 'published_at': published,
            'url': REPOSITORY_URL + '/releases/tag/' + tag}


def _cached_release(payload):
    if not isinstance(payload, dict):
        raise ReleaseCheckError('invalid_cache')
    try:
        result = _release({'tag_name': payload.get('tag'), 'name': payload.get('name'),
                           'published_at': payload.get('published_at'), 'draft': False, 'prerelease': False})
    except ReleaseCheckError:
        raise ReleaseCheckError('invalid_cache') from None
    if payload.get('version') != result['version']:
        raise ReleaseCheckError('invalid_cache')
    return result


def _unique_fields(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError('Duplicate field')
        result[name] = value
    return result


def _cache(row):
    try:
        latest = json.loads(row['latest_json'], object_pairs_hook=_unique_fields)
        recent = json.loads(row['recent_json'], object_pairs_hook=_unique_fields)
        if not isinstance(recent, list) or len(recent) > HISTORY_LIMIT:
            raise ValueError('Invalid history')
        return (_cached_release(latest) if latest is not None else None,
                [_cached_release(item) for item in recent])
    except (ValueError, TypeError, RecursionError, ReleaseCheckError):
        raise ReleaseCheckError('invalid_cache') from None


def _etag(value):
    return value if isinstance(value, str) and 1 <= len(value) <= 256 and all(32 <= ord(c) < 127 for c in value) else None


def _retry_at(headers, now):
    candidates = [now + 3600]
    delay = headers.get('Retry-After')
    if isinstance(delay, str):
        if re.fullmatch(r'[0-9]{1,10}', delay):
            candidates = [now + int(delay)]
        else:
            try:
                date = parsedate_to_datetime(delay)
                if date.tzinfo is not None:
                    candidates = [date.timestamp()]
            except (ValueError, TypeError, OverflowError):
                pass
    reset = headers.get('X-RateLimit-Reset')
    if isinstance(reset, str) and re.fullmatch(r'[0-9]{1,12}', reset):
        candidates.append(int(reset))
    return min(now + 86400, max(now + MANUAL_INTERVAL, *candidates))


def _fetch(session, url, etag, cached, deadline, now):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ReleaseCheckError('github_unavailable')
    headers = {'Accept': 'application/vnd.github+json', 'User-Agent': 'Keep-release-check',
               'X-GitHub-Api-Version': '2022-11-28', 'Accept-Encoding': 'identity'}
    if _etag(etag) and cached is not None:
        headers['If-None-Match'] = etag
    with session.get(url, headers=headers, timeout=(min(3, remaining), min(5, remaining)),
                     allow_redirects=False, stream=True) as response:
        if time.monotonic() > deadline:
            raise ReleaseCheckError('github_unavailable')
        if response.status_code == 304:
            if cached is None or 'If-None-Match' not in headers:
                raise ReleaseCheckError('invalid_response')
            return cached, etag
        if response.status_code == 429 or (response.status_code == 403 and
                (response.headers.get('X-RateLimit-Remaining') == '0' or response.headers.get('Retry-After'))):
            raise ReleaseCheckError('rate_limited', _retry_at(response.headers, now))
        if response.status_code == 404 and url == LATEST_URL:
            raise ReleaseCheckError('no_stable_release')
        if response.status_code != 200:
            raise ReleaseCheckError('github_unavailable')
        if response.headers.get('Content-Encoding', 'identity').lower() != 'identity':
            raise ReleaseCheckError('invalid_response')
        length = response.headers.get('Content-Length', '')
        if length and (not isinstance(length, str) or not re.fullmatch(r'[0-9]{1,10}', length)
                       or int(length) > MAX_BODY):
            raise ReleaseCheckError('invalid_response')
        body = bytearray()
        # A slow response must not wait for a large buffered chunk before its
        # deadline is checked. The fixed API request asks for uncompressed bytes.
        for chunk in response.iter_content(1):
            body.extend(chunk)
            if len(body) > MAX_BODY:
                raise ReleaseCheckError('invalid_response')
            if time.monotonic() > deadline:
                raise ReleaseCheckError('github_unavailable')
        try:
            payload = json.loads(body, object_pairs_hook=_unique_fields)
        except (ValueError, TypeError, RecursionError):
            raise ReleaseCheckError('invalid_response') from None
        return payload, _etag(response.headers.get('ETag'))


class Store:
    def __init__(self, path, *, initialize=True):
        self.path = Path(path)
        self._initialized = False
        if initialize:
            self._initialize()

    def _initialize(self):
        with closing(sqlite3.connect(self.path, timeout=0.25)) as db, db:
            db.execute('''CREATE TABLE IF NOT EXISTS release_checks (
                id INTEGER PRIMARY KEY CHECK(id=1), latest_json TEXT NOT NULL DEFAULT 'null',
                recent_json TEXT NOT NULL DEFAULT '[]', latest_etag TEXT, recent_etag TEXT,
                last_attempt REAL, last_success REAL, next_attempt REAL NOT NULL DEFAULT 0,
                rate_limit_until REAL NOT NULL DEFAULT 0, failures INTEGER NOT NULL DEFAULT 0,
                outcome TEXT NOT NULL DEFAULT 'never', error_code TEXT
            )''')
            db.execute('INSERT OR IGNORE INTO release_checks(id) VALUES (1)')
        self._initialized = True

    def _read(self):
        try:
            self.path.stat()
        except FileNotFoundError:
            return None
        with closing(sqlite3.connect(self.path.absolute().as_uri() + '?mode=ro', uri=True, timeout=0.25)) as db:
            db.row_factory = sqlite3.Row
            if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='release_checks'").fetchone():
                return None
            row = db.execute('SELECT * FROM release_checks WHERE id=1').fetchone()
            return dict(row) if row else None

    @staticmethod
    def _due(row, now, force):
        if row is None:
            return True
        if (_number(row.get('rate_limit_until')) or 0) > now:
            return False
        if force:
            attempted = _number(row.get('last_attempt'))
            return attempted is None or now >= attempted + MANUAL_INTERVAL
        return now >= (_number(row.get('next_attempt')) or 0)

    def due(self, now=None, force=False):
        now = time.time() if now is None else now
        return self._due(self._read(), now, force)

    def snapshot(self, installed_version, now=None):
        now = time.time() if now is None else now
        row = self._read()
        latest, recent, error = None, [], None
        if row:
            try:
                latest, recent = _cache(row)
            except ReleaseCheckError as failure:
                error = failure.code
        status = row.get('outcome') if row and row.get('outcome') in ('never', 'success', 'failed', 'rate_limited') else 'never'
        attempted = _number(row.get('last_attempt')) if row else None
        succeeded = _number(row.get('last_success')) if row else None
        next_attempt = _number(row.get('next_attempt')) if row else None
        if error:
            status = 'failed'
        elif row and row.get('error_code') in ERROR_MESSAGES:
            error = row['error_code']
        interrupted = bool(row and (row.get('outcome') == 'checking' or
                           status == 'success' and attempted is not None and succeeded is not None and attempted > succeeded))
        if interrupted and (attempted is None or now - attempted > REQUEST_BUDGET + 30):
            status, error = 'failed', 'check_interrupted'
        fresh = bool(latest and status == 'success' and not error and not interrupted and succeeded is not None
                     and 0 <= now - succeeded <= CHECK_INTERVAL)
        installed = version(installed_version)
        comparison, update_available = 'unknown', None
        if fresh and installed:
            current = tuple(map(int, installed.split('.')))
            released = tuple(map(int, latest['version'].split('.')))
            comparison = 'update_available' if released > current else 'up_to_date' if released == current else 'ahead'
            update_available = comparison == 'update_available'
        retry_at = max((attempted + MANUAL_INTERVAL if attempted is not None else 0),
                       (_number(row.get('rate_limit_until')) or 0) if row else 0)
        return {'status': status, 'installed_version': installed or 'unknown',
                'last_attempt_at': timestamp(attempted), 'last_success_at': timestamp(succeeded),
                'next_attempt_at': timestamp(next_attempt) if next_attempt else None,
                'latest_version': latest['version'] if latest else None,
                'latest_tag': latest['tag'] if latest else None,
                'latest_published_at': latest['published_at'] if latest else None,
                'releases': recent, 'comparison': comparison, 'update_available': update_available,
                'stale': not fresh, 'error_code': error,
                'message': ERROR_MESSAGES[error] if error else 'Release information checked.' if status == 'success'
                           else 'Release information has not been checked yet.',
                'can_check': self._due(row, now, True), 'retry_after_seconds': max(0, math.ceil(retry_at - now))}

    def check(self, now=None, force=False, interval=CHECK_INTERVAL):
        if type(interval) is not int or not MANUAL_INTERVAL <= interval <= 86400:
            raise ValueError('Invalid release check interval')
        explicit_now = now is not None
        now = time.time() if now is None else now
        if not self._initialized:
            self._initialize()
        with closing(sqlite3.connect(self.path, timeout=0.25)) as db, db:
            db.row_factory = sqlite3.Row
            db.execute('BEGIN IMMEDIATE')
            row = dict(db.execute('SELECT * FROM release_checks WHERE id=1').fetchone())
            if not self._due(row, now, force):
                return {'status': 'waiting', 'error_code': None, 'latest_version': None}
            # Reserve the attempt before I/O, including recovery after interruption.
            db.execute("UPDATE release_checks SET last_attempt=?,next_attempt=?,outcome='checking',error_code=NULL WHERE id=1",
                       (now, now + RETRY_INTERVAL))
        try:
            latest_cached, recent_cached = _cache(row)
        except ReleaseCheckError:
            latest_cached, recent_cached = None, None
        latest_source = ({'tag_name': latest_cached['tag'], 'name': latest_cached['name'],
                          'published_at': latest_cached['published_at'], 'draft': False, 'prerelease': False}
                         if latest_cached else None)
        recent_source = ([{'tag_name': item['tag'], 'name': item['name'], 'published_at': item['published_at'],
                           'draft': False, 'prerelease': False} for item in recent_cached]
                         if row['last_success'] is not None and recent_cached is not None else None)
        failure = None
        try:
            deadline = time.monotonic() + REQUEST_BUDGET
            with requests.Session() as session:
                session.trust_env = False
                latest_payload, latest_etag = _fetch(session, LATEST_URL, row['latest_etag'], latest_source, deadline, now)
                latest = _release(latest_payload)
                recent_payload, recent_etag = _fetch(session, RECENT_URL, row['recent_etag'], recent_source, deadline, now)
                if not isinstance(recent_payload, list) or len(recent_payload) > 10:
                    raise ReleaseCheckError('invalid_response')
                recent, seen = [], set()
                for payload in recent_payload:
                    if not isinstance(payload, dict):
                        raise ReleaseCheckError('invalid_response')
                    if payload.get('draft') is True or payload.get('prerelease') is True or not version(payload.get('tag_name')):
                        continue
                    item = _release(payload)
                    if item['version'] not in seen:
                        seen.add(item['version'])
                        recent.append(item)
                if latest['version'] not in seen:
                    recent.insert(0, latest)
                recent = recent[:HISTORY_LIMIT]
        except ReleaseCheckError as error:
            failure = error
        except requests.RequestException:
            failure = ReleaseCheckError('github_unavailable')
        completed = now if explicit_now else time.time()
        with closing(sqlite3.connect(self.path, timeout=0.25)) as db, db:
            if failure:
                failures = max(0, min(int(row['failures']), 6)) + 1
                next_attempt = completed + min(interval, RETRY_INTERVAL * 2 ** min(failures - 1, 5))
                cooldown = failure.retry_at or 0
                outcome = 'rate_limited' if failure.code == 'rate_limited' else 'failed'
                db.execute('''UPDATE release_checks SET outcome=?,error_code=?,failures=?,next_attempt=?,
                              rate_limit_until=? WHERE id=1''',
                           (outcome, failure.code, failures, max(next_attempt, cooldown), cooldown))
                return {'status': outcome, 'error_code': failure.code,
                        'latest_version': latest_cached['version'] if latest_cached else None}
            db.execute('''UPDATE release_checks SET latest_json=?,recent_json=?,latest_etag=?,recent_etag=?,
                          last_success=?,next_attempt=?,rate_limit_until=0,failures=0,outcome='success',error_code=NULL
                          WHERE id=1''', (json.dumps(latest), json.dumps(recent), latest_etag, recent_etag,
                                         completed, completed + interval))
        return {'status': 'success', 'error_code': None, 'latest_version': latest['version']}


def job_result(result):
    status = result.get('status') if isinstance(result, dict) else None
    if status == 'success':
        return 'success', 'Release information checked'
    if status == 'waiting':
        return 'waiting', 'Waiting for the next release check'
    if status == 'rate_limited':
        return 'failed', 'Release check rate limited'
    return 'failed', 'Release check unavailable'
