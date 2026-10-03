"""Seerr attribution and narrowly scoped availability job scheduling.

Never use this cache as deletion authorization. Request history is read-only.

Only allowlisted metadata is persisted. Full upstream responses may contain
credentials and private account details and must never be logged or stored.
"""
from contextlib import closing
import hashlib
import json
import sqlite3
import time
import fcntl

import requests

MAX_AGE = 86400
REFRESH_INTERVAL = 15 * 60


class RefreshBusy(ValueError):
    pass


class ResponseError(ValueError):
    """Safe owner-facing transport diagnostic; never include upstream bodies."""
    def __init__(self, status):
        super().__init__(f'Seerr returned HTTP {int(status)}. Check API access and try refreshing again.')


def identifier(value, *, zero=False):
    if type(value) is not int or value < (0 if zero else 1):
        raise ValueError('Invalid Seerr identifier')
    return value


def namespace(getter):
    return hashlib.sha256(json.dumps([getter('SEERR_URL'), getter('SEERR_API_KEY')]).encode()).hexdigest()


class Client:
    def __init__(self, getter, *, timeout=60):
        self.url = getter('SEERR_URL').rstrip('/')
        self.key = getter('SEERR_API_KEY')
        if not self.url or not self.key:
            raise ValueError('Configure Seerr first')
        self.deadline = time.monotonic() + timeout

    def get(self, path, *, _list=False, **params):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise ValueError('Seerr refresh timed out')
        with requests.get(self.url + '/api/v1/' + path,
                          headers={'X-Api-Key': self.key}, params=params,
                          timeout=min(10, remaining), allow_redirects=False,
                          stream=True) as response:
            if response.status_code != 200:
                raise ResponseError(response.status_code)
            content = bytearray()
            for chunk in response.iter_content(65536):
                content.extend(chunk)
                if len(content) > 4 * 1024 * 1024 or time.monotonic() > self.deadline:
                    raise ValueError('Seerr response exceeds refresh limits')
            try:
                result = json.loads(content)
            except (ValueError, UnicodeError):
                raise ValueError('Invalid Seerr response') from None
            if not isinstance(result, list if _list else dict):
                raise ValueError('Invalid Seerr response')
            return result

    def sync_availability(self):
        jobs = self.get('settings/jobs', _list=True)
        matches = [job for job in jobs if isinstance(job, dict) and job.get('id') == 'availability-sync']
        if len(matches) != 1 or type(matches[0].get('running')) is not bool:
            raise ValueError('Invalid availability job status')
        if matches[0]['running']:
            return False
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise ValueError('Availability job timed out')
        # This is the only write allowed by Keep's Seerr integration. Never
        # edit requests, availability records, schedules, or media directly.
        with requests.post(self.url + '/api/v1/settings/jobs/availability-sync/run',
                           headers={'X-Api-Key': self.key}, timeout=min(10, remaining),
                           allow_redirects=False, stream=True) as response:
            if response.status_code != 200:
                raise ResponseError(response.status_code)
        return True

    def test(self):
        account = self.get('auth/me')
        identifier(account.get('id'))
        permissions = account.get('permissions')
        if type(permissions) is not int or not (
                permissions & 2 or (permissions & 8 and permissions & (16 | 16384))):
            raise ValueError('Seerr requires access to all requests and user identities')

    def pages(self, path):
        rows, seen, total = [], set(), None
        for page in range(100):
            # Seerr's endpoints have different sort enums; neither accepts "id".
            # Use supported defaults and retain duplicate/count consistency guards.
            data = self.get(path, take=100, skip=len(rows))
            info, batch = data.get('pageInfo'), data.get('results')
            if not isinstance(info, dict) or not isinstance(batch, list):
                raise ValueError('Incomplete Seerr response')
            count = identifier(info.get('results'), zero=True)
            if total is not None and total != count:
                raise ValueError('Seerr changed during refresh; retry')
            total = count
            for row in batch:
                if not isinstance(row, dict):
                    raise ValueError('Invalid Seerr row')
                key = identifier(row.get('id'))
                if key in seen:
                    raise ValueError('Unstable Seerr pagination; retry')
                seen.add(key)
                rows.append(row)
            if len(rows) == total:
                return rows
            if not batch or len(rows) > total:
                raise ValueError('Incomplete Seerr pagination')
        raise ValueError('Seerr refresh exceeds pagination limit')

    def snapshot(self):
        self.test()
        users = []
        for user in self.pages('user'):
            plex_id = user.get('plexId')
            if plex_id is not None:
                identifier(plex_id)
            # Owner-only identification label; public attribution uses Keep names.
            label = user.get('username') or user.get('plexUsername') or f"Seerr user #{user['id']}"
            if not isinstance(label, str) or '@' in label:
                label = f"Seerr user #{user['id']}"
            users.append({'id': user['id'], 'plex_id': str(plex_id) if plex_id else '',
                          'label': str(label)[:100]})
        records = []
        for row in self.pages('request'):
            media = row.get('media')
            requester = row.get('requestedBy')
            if not isinstance(media, dict) or not isinstance(requester, dict):
                raise ValueError('Incomplete Seerr request')
            kind = row.get('type')
            if kind not in ('movie', 'tv') or type(row.get('status')) is not int or row['status'] not in (1, 2, 3, 4, 5):
                raise ValueError('Unknown Seerr request type or status')
            tmdb = identifier(media.get('tmdbId'))
            tvdb = media.get('tvdbId')
            if tvdb is not None:
                identifier(tvdb)
            seasons = row.get('seasons', [])
            if not isinstance(seasons, list):
                raise ValueError('Invalid Seerr seasons')
            normalized = []
            for season in seasons:
                if not isinstance(season, dict) or type(season.get('status')) is not int or season['status'] not in (1, 2, 3, 4, 5):
                    raise ValueError('Invalid Seerr season')
                normalized.append({'number': identifier(season.get('seasonNumber'), zero=True),
                                   'status': season['status']})
            records.append({'id': row['id'], 'kind': kind, 'tmdb': tmdb, 'tvdb': tvdb,
                            'user': identifier(requester.get('id')), 'status': row['status'],
                            'seasons': normalized, 'is4k': row.get('is4k') is True})
        return {'users': users, 'requests': records}


class Store:
    def __init__(self, path):
        self.path = path
        with closing(sqlite3.connect(path)) as db, db:
            db.execute('CREATE TABLE IF NOT EXISTS seerr_cache (scope TEXT PRIMARY KEY, payload TEXT NOT NULL, updated REAL NOT NULL, failed INTEGER NOT NULL DEFAULT 0)')
            db.execute('CREATE TABLE IF NOT EXISTS seerr_links (scope TEXT NOT NULL, keep_id TEXT NOT NULL, seerr_id INTEGER NOT NULL, PRIMARY KEY(scope, keep_id), UNIQUE(scope, seerr_id))')
            db.execute('CREATE TABLE IF NOT EXISTS seerr_refresh (scope TEXT PRIMARY KEY, next_attempt REAL NOT NULL, failures INTEGER NOT NULL DEFAULT 0)')
            db.execute('CREATE TABLE IF NOT EXISTS seerr_availability_queue (scope TEXT PRIMARY KEY, generation INTEGER NOT NULL, due REAL NOT NULL, failures INTEGER NOT NULL DEFAULT 0)')

    def queue_availability(self, getter):
        if not getter('SEERR_URL') or not getter('SEERR_API_KEY'):
            return False
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute('INSERT INTO seerr_availability_queue VALUES (?,1,?,0) '
                       'ON CONFLICT(scope) DO UPDATE SET generation=generation+1',
                       (namespace(getter), time.time() + 30))
        return True

    def process_availability(self, getter):
        # A separate cross-process lock prevents duplicate worker dispatches.
        with open(str(self.path) + '.seerr-availability.lock', 'a') as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return None
            scope = namespace(getter)
            with closing(sqlite3.connect(self.path)) as db, db:
                # Never replay work against a replacement Seerr connection.
                db.execute('DELETE FROM seerr_availability_queue WHERE scope<>?', (scope,))
                row = db.execute('SELECT generation,due,failures FROM seerr_availability_queue WHERE scope=?', (scope,)).fetchone()
            if not row or time.time() < row[1]:
                return None
            generation, _, failures = row
            try:
                started = Client(getter, timeout=20).sync_availability()
            except (ValueError, requests.RequestException):
                with closing(sqlite3.connect(self.path)) as db, db:
                    db.execute('UPDATE seerr_availability_queue SET due=?,failures=? WHERE scope=?',
                               (time.time() + min(60 * 2 ** min(failures, 6), 3600), failures + 1, scope))
                raise
            with closing(sqlite3.connect(self.path)) as db, db:
                if started:
                    # A deletion arriving during HTTP I/O needs a later pass.
                    db.execute('DELETE FROM seerr_availability_queue WHERE scope=? AND generation=?', (scope, generation))
                db.execute('UPDATE seerr_availability_queue SET due=?,failures=0 WHERE scope=?', (time.time() + 30, scope))
            return started

    def refresh(self, getter, *, automatic=False):
        # Cross-process lock covers manual requests and the dedicated worker.
        # File locks are released on process death, unlike persistent busy flags.
        with open(str(self.path) + '.seerr-refresh.lock', 'a') as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                if automatic:
                    return None
                raise RefreshBusy('A Seerr refresh is already running. Check again shortly.') from None
            return self._refresh(getter, automatic=automatic)

    def _refresh(self, getter, *, automatic=False):
        if not getter('SEERR_URL') or not getter('SEERR_API_KEY'):
            if automatic:
                return None
            raise ValueError('Configure Seerr first')
        scope = namespace(getter)
        started = time.time()
        with closing(sqlite3.connect(self.path)) as db:
            schedule = db.execute('SELECT next_attempt,failures FROM seerr_refresh WHERE scope=?', (scope,)).fetchone()
            previous = db.execute('SELECT updated FROM seerr_cache WHERE scope=?', (scope,)).fetchone()
        if automatic and ((schedule and started < schedule[0]) or
                          (not schedule and previous and started < previous[0] + REFRESH_INTERVAL)):
            return None
        try:
            payload = Client(getter).snapshot()
        except (ValueError, requests.RequestException):
            failures = (schedule[1] if schedule else 0) + 1
            retry = time.time() + min(60 * 2 ** min(failures - 1, 6), 3600)
            with closing(sqlite3.connect(self.path)) as db, db:
                db.execute('UPDATE seerr_cache SET failed=1 WHERE scope=? AND updated<=?', (scope, started))
                db.execute('INSERT OR REPLACE INTO seerr_refresh VALUES (?,?,?)', (scope, retry, failures))
            raise
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute('INSERT INTO seerr_cache VALUES (?, ?, ?, 0) ON CONFLICT(scope) DO UPDATE SET payload=excluded.payload,updated=excluded.updated,failed=0 WHERE seerr_cache.updated<=excluded.updated',
                       (scope, json.dumps(payload), started))
            db.execute('INSERT OR REPLACE INTO seerr_refresh VALUES (?,?,0)', (scope, time.time() + REFRESH_INTERVAL))
        return payload

    def read(self, getter):
        with closing(sqlite3.connect(self.path)) as db:
            row = db.execute('SELECT payload,updated,failed FROM seerr_cache WHERE scope=?', (namespace(getter),)).fetchone()
        if not row:
            return {'users': [], 'requests': [], 'updated': None, 'state': 'unavailable'}
        return {**json.loads(row[0]), 'updated': row[1],
                'refresh_failed': bool(row[2]),
                'state': 'stale' if time.time() - row[1] > MAX_AGE else ('unavailable' if row[2] else 'current')}

    def save_links(self, getter, links, profiles, expected_scope):
        scope = namespace(getter)
        if expected_scope != scope:
            raise ValueError('Seerr settings changed. Reload before saving links.')
        local = {str(p['plex_id']) for p in profiles if p['auth_type'] == 'local'}
        if set(links) != local:
            raise ValueError('Accounts changed. Reload before saving links.')
        snapshot = self.read(getter)
        if snapshot['state'] != 'current':
            raise ValueError('Refresh Seerr before linking')
        known = {u['id'] for u in snapshot['users']}
        plex_ids = {str(p['plex_id']) for p in profiles if p['auth_type'] == 'plex'}
        reserved = {u['id'] for u in snapshot['users'] if u['plex_id'] and u['plex_id'] in plex_ids}
        selected = [identifier(v) for v in links.values() if v is not None]
        if len(selected) != len(set(selected)) or set(selected) - known or set(selected) & reserved:
            raise ValueError('Each Seerr account must match only one Keep account')
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute('DELETE FROM seerr_links WHERE scope=?', (scope,))
            db.executemany('INSERT INTO seerr_links VALUES (?,?,?)',
                           [(scope, k, v) for k, v in links.items() if v is not None])

    def identities(self, getter, snapshot, profiles):
        """Resolve stable IDs, not names/emails. Conflicts deliberately stay unlinked."""
        with closing(sqlite3.connect(self.path)) as db:
            manual = dict(db.execute('SELECT keep_id,seerr_id FROM seerr_links WHERE scope=?', (namespace(getter),)))
        candidates = {}
        for user in snapshot['users']:
            matches = [p for p in profiles if
                       (p['auth_type'] == 'plex' and user['plex_id'] and str(p['plex_id']) == user['plex_id']) or
                       (p['auth_type'] == 'local' and manual.get(str(p['plex_id'])) == user['id'])]
            if len(matches) == 1:
                candidates[user['id']] = matches[0]
        counts = {}
        for profile in candidates.values():
            counts[str(profile['plex_id'])] = counts.get(str(profile['plex_id']), 0) + 1
        return {key: value for key, value in candidates.items() if counts[str(value['plex_id'])] == 1}

    def link(self, getter, keep_id, seerr_id, profiles):
        snapshot = self.read(getter)
        target = next((p for p in profiles if str(p['plex_id']) == keep_id and p['auth_type'] == 'local'), None)
        if not target:
            raise ValueError('Only local accounts can be manually linked')
        if seerr_id is not None:
            if snapshot['state'] != 'current' or not any(u['id'] == seerr_id for u in snapshot['users']):
                raise ValueError('Refresh Seerr before linking')
            identities = self.identities(getter, snapshot, profiles)
            if seerr_id in identities and str(identities[seerr_id]['plex_id']) != keep_id:
                raise ValueError('Seerr account is already linked')
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute('DELETE FROM seerr_links WHERE scope=? AND keep_id=?', (namespace(getter), keep_id))
            if seerr_id is not None:
                try:
                    db.execute('INSERT INTO seerr_links VALUES (?, ?, ?)', (namespace(getter), keep_id, seerr_id))
                except sqlite3.IntegrityError:
                    raise ValueError('Seerr account is already linked') from None


def attribution(snapshot, identities, kind, external_id, *, season=None):
    """Historical approved/completed requests, NOT proof of download ownership."""
    field = 'tmdb' if kind == 'movie' else 'tvdb'
    records = [r for r in snapshot['requests'] if external_id and r['kind'] == kind and
               r[field] == external_id and r['status'] in (2, 5)]
    if season is not None:
        records = [r for r in records if any(s['number'] == season and s['status'] in (2, 5) for s in r['seasons'])]
    ids = sorted({r['user'] for r in records})
    state = 'shared' if len(ids) > 1 else ('known' if ids else 'unknown')
    names = [(identities[i].get('display_name') or 'Keep user') if i in identities else 'Unlinked requester' for i in ids]
    return {'state': state, 'freshness': snapshot['state'], 'names': names,
            'request_ids': [r['id'] for r in records],
            'label': 'Requested by ' + ', '.join(names) if names else 'Requester unknown'}


def movie_deletion_access(snapshot, identities, tmdb_id, keep_id):
    """Policy only. The caller MUST supply a fresh live snapshot before deletion.

    Browsing can use this decision as a hint, never as an authorization token.
    Do not infer identity from display names, or whole-series rights from seasons.
    All requesters (including other statuses/quality variants) count as shared;
    at least one approved/completed request must belong to this linked account.
    """
    if snapshot.get('state') != 'current':
        return False, 'Request history cannot be verified right now. Try again after it refreshes.'
    if type(tmdb_id) is not int or tmdb_id < 1:
        return False, 'This movie cannot be matched safely. Ask someone with Delete any title permission.'
    linked = {key for key, profile in identities.items() if str(profile['plex_id']) == str(keep_id)}
    if len(linked) != 1:
        return False, 'Your request account is not linked. Ask the owner to check your account link.'
    rows = [r for r in snapshot['requests'] if r['kind'] == 'movie' and r['tmdb'] == tmdb_id]
    requesters = {r['user'] for r in rows}
    if len(requesters) > 1:
        return False, 'Shared requests need Delete any title permission.'
    if not rows or not any(r['status'] in (2, 5) for r in rows):
        return False, 'No eligible request was found. Delete any title permission is required.'
    if requesters != linked:
        return False, 'You can only delete movies requested by your linked account.'
    return True, 'You can delete this movie. Your request and access will be verified again before deletion.'


def season_deletion_access(snapshot, identities, tvdb_id, season, keep_id):
    """Require exclusive, explicit season history; never infer series ownership."""
    if snapshot.get('state') != 'current':
        return False, 'Request history cannot be verified right now.'
    if type(tvdb_id) is not int or tvdb_id < 1 or type(season) is not int or season < 0:
        return False, 'This season cannot be matched safely.'
    linked = {key for key, profile in identities.items() if str(profile['plex_id']) == str(keep_id)}
    if len(linked) != 1:
        return False, 'Your request account is not linked unambiguously.'
    series = [r for r in snapshot['requests'] if r['kind'] == 'tv' and r['tvdb'] == tvdb_id]
    # A legacy request without explicit season scope could overlap any season.
    if any(not r['seasons'] for r in series):
        return False, 'Season request history is incomplete.'
    rows = [(r, s) for r in series for s in r['seasons'] if s['number'] == season]
    if not rows or {r['user'] for r, s in rows} != linked:
        return False, 'This season is not requested exclusively by you.'
    if not any(r['status'] in (2, 5) and s['status'] in (2, 5) for r, s in rows):
        return False, 'No approved request was found for this season.'
    return True, ''
