"""Scoped integration credentials and the supported collection/Keep API.

Browser sessions authorize credential management only. Bearer requests never
create a browser session or call the separately authorized media deletion API.
"""
from contextlib import closing
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import math
import re
import secrets
import sqlite3
import time
import uuid

from flask import Blueprint, g, jsonify, redirect, render_template, request, session
import requests
from werkzeug.exceptions import HTTPException

SCOPES = {'collections:read', 'media:read', 'keeps:read', 'keeps:write'}
TOKEN = re.compile(r'keep_[A-Za-z0-9_-]{43}\Z')
MEDIA_ID = re.compile(r'[1-9][0-9]{0,19}\Z')
IDEMPOTENCY = re.compile(r'[A-Za-z0-9_-]{16,128}\Z')
PAGE_SIZE = 100
MAX_PAGES = 100
MAX_BODY = 8192


class ApiProblem(Exception):
    def __init__(self, status, code, message, retry_after=None):
        self.status, self.code, self.message = status, code, message
        self.retry_after = retry_after


def error_response(status, code, message, retry_after=None):
    response = jsonify(error={'code': code, 'message': message})
    response.status_code = status
    response.headers['Cache-Control'] = 'no-store'
    if status == 401:
        response.headers['WWW-Authenticate'] = 'Bearer realm="Keep API"'
    if retry_after is not None:
        response.headers['Retry-After'] = str(retry_after)
    return response


def timestamp(value):
    return datetime.fromtimestamp(value, timezone.utc).isoformat().replace('+00:00', 'Z') if value is not None else None


def stored_timestamp(value):
    return value.replace(' ', 'T') + 'Z' if value else None


def valid_media_id(value):
    if not isinstance(value, str) or not MEDIA_ID.fullmatch(value):
        raise ApiProblem(400, 'invalid_request', 'media_id must be a positive Plex media ID string.')
    return value


def key_expired(expires_at):
    # Zero explicitly means no scheduled expiry. Keep the existing NOT NULL
    # schema so backups and finite keys remain compatible with older releases.
    return expires_at != 0 and expires_at <= time.time()


def key_activity_description(action, name, scopes=None, expires_at=None):
    verb = {'create': 'Created', 'revoke': 'Revoked', 'rotate': 'Replaced',
            'remove': 'Removed'}[action]
    description = f'{verb} API key “{name}”'
    if action in ('create', 'rotate'):
        expiry = ('never expires' if expires_at == 0 else
                  'expires ' + datetime.fromtimestamp(expires_at, timezone.utc).strftime('%d %b %Y, %H:%M UTC'))
        description += f'; scopes: {", ".join(sorted(scopes))}; {expiry}'
    return description


class ApiV1:
    def __init__(self, keep):
        self.keep = keep
        self.app = keep.app
        with closing(keep.attribution_db()) as db, db:
            db.execute('''CREATE TABLE IF NOT EXISTS api_keys (
                id TEXT PRIMARY KEY, user_id TEXT NOT NULL, name TEXT NOT NULL,
                prefix TEXT NOT NULL, secret_hash TEXT NOT NULL UNIQUE,
                scopes TEXT NOT NULL, account_version INTEGER NOT NULL,
                created_at REAL NOT NULL, expires_at REAL NOT NULL,
                revoked_at REAL, last_used_at REAL)''')
            db.execute('CREATE INDEX IF NOT EXISTS api_keys_user ON api_keys(user_id)')
            db.execute('''CREATE TABLE IF NOT EXISTS api_idempotency (
                key_id TEXT NOT NULL, request_key_hash TEXT NOT NULL,
                request_hash TEXT NOT NULL, status TEXT NOT NULL,
                response_status INTEGER, response_json TEXT, created_at REAL NOT NULL,
                PRIMARY KEY(key_id, request_key_hash))''')
            db.execute('''CREATE TABLE IF NOT EXISTS api_rate_limits (
                subject TEXT NOT NULL, window INTEGER NOT NULL, attempts INTEGER NOT NULL,
                PRIMARY KEY(subject, window))''')
        self.blueprint = Blueprint('supported_api', __name__, url_prefix='/api/v1')
        self.blueprint.before_request(self.authenticate)
        self.blueprint.after_request(self.finish_response)
        self.blueprint.register_error_handler(ApiProblem, self.problem_response)
        self.blueprint.register_error_handler(Exception, self.unexpected)
        for path, methods, function in (
                ('/collections', ['GET'], self.collections), ('/media', ['GET'], self.media),
                ('/keeps', ['GET'], self.keeps), ('/keeps', ['POST'], self.mutate),
                ('/keeps/<keep_id>', ['GET'], self.get_keep),
                ('/keeps/<keep_id>', ['PATCH', 'DELETE'], self.mutate)):
            self.blueprint.add_url_rule(path, endpoint=function.__name__ + '_'.join(methods),
                                        view_func=function, methods=methods)
        self.app.register_blueprint(self.blueprint)
        for status in (400, 404, 405, 413, 415, 429, 503):
            self.app.register_error_handler(status, self.http_error)
        self.app.add_url_rule('/settings/api-keys', 'account_api_keys', self.key_management, methods=['GET', 'POST'])
        self.app.add_url_rule('/account/api-keys', 'legacy_account_api_keys',
                             self.legacy_key_management,
                             methods=['GET', 'POST'])
        self.app.add_url_rule('/settings/api-reference', 'api_reference',
                             self.reference)
        self.app.add_url_rule('/api-reference', 'legacy_api_reference',
                             self.legacy_reference)
        self.app.extensions['keep_api'] = self

    @staticmethod
    def problem_response(error):
        return error_response(error.status, error.code, error.message, error.retry_after)

    def unexpected(self, error):
        if isinstance(error, HTTPException):
            return self.http_error(error)
        # Exception messages can contain upstream URLs or credential values.
        self.app.logger.error('Supported API failure: %s', type(error).__name__)
        if isinstance(error, sqlite3.Error):
            return error_response(503, 'service_unavailable', 'Keep is busy. Check the current state before retrying.', 5)
        return error_response(500, 'internal_error', 'Keep could not complete the request. Check the current state before retrying.')

    @staticmethod
    def http_error(error):
        if request.path != '/api/v1' and not request.path.startswith('/api/v1/'):
            return error.get_response()
        codes = {400: 'invalid_request', 404: 'not_found', 405: 'method_not_allowed',
                 413: 'payload_too_large', 415: 'unsupported_media_type',
                 429: 'rate_limited', 503: 'service_unavailable'}
        response = error_response(error.code, codes.get(error.code, 'internal_error'), error.name + '.')
        if error.code == 405:
            response.headers['Allow'] = ', '.join(error.valid_methods or [])
        return response

    def identity(self, db, secret_hash):
        key = db.execute('SELECT * FROM api_keys WHERE secret_hash=?', (secret_hash,)).fetchone()
        profile = db.execute('SELECT * FROM user_profiles WHERE plex_id=?', (key['user_id'],)).fetchone() if key else None
        if (not self.keep.owner_id() or not key or key['revoked_at'] is not None or
                key_expired(key['expires_at']) or not profile or profile['status'] != 'active' or
                profile['session_version'] != key['account_version'] or
                not self.keep.plex_account_access_active(profile)):
            raise ApiProblem(401, 'invalid_token', 'An active API key and account are required.')
        return key, profile

    def require_scope(self, key, scope):
        if scope not in json.loads(key['scopes']):
            raise ApiProblem(403, 'insufficient_scope', 'This API key does not allow the requested operation.')

    def rate_limit(self, subject, limit):
        now = int(time.time())
        window = now - now % 60
        with closing(self.keep.attribution_db()) as db, db:
            db.execute('BEGIN IMMEDIATE')
            db.execute('''INSERT INTO api_rate_limits VALUES (?, ?, 1)
                ON CONFLICT(subject,window) DO UPDATE SET attempts=attempts+1''', (subject, window))
            attempts = db.execute('SELECT attempts FROM api_rate_limits WHERE subject=? AND window=?', (subject, window)).fetchone()[0]
            db.execute('DELETE FROM api_rate_limits WHERE window<?', (window - 3600,))
        if attempts > limit:
            raise ApiProblem(429, 'rate_limited', 'Too many API requests. Try again later.', 60 - now % 60)

    def authenticate(self):
        # Bind API selection and freshness checks to the same request-entry
        # configuration consumed by the existing upstream connection getter.
        snapshot = self.keep._settings_snapshot.get()
        g.api_settings = dict(snapshot if snapshot is not None else
                              self.keep.connection_settings.snapshot())
        if (request.content_length or 0) > self.app.config['MAX_CONTENT_LENGTH']:
            raise ApiProblem(413, 'payload_too_large', 'The API request exceeds the body limit.')
        if request.method in ('GET', 'HEAD') and (request.content_length or 0):
            raise ApiProblem(400, 'invalid_request', 'Read requests do not accept a body.')
        peer = hmac.new(self.app.secret_key.encode(), (request.remote_addr or 'unknown').encode(), hashlib.sha256).hexdigest()
        self.rate_limit('peer:' + peer, 120)
        authorization = request.headers.get('Authorization', '')
        if not authorization.startswith('Bearer ') or not TOKEN.fullmatch(authorization[7:]):
            raise ApiProblem(401, 'invalid_token', 'An active API key and account are required.')
        g.api_secret_hash = hashlib.sha256(authorization[7:].encode()).hexdigest()
        with closing(self.keep.attribution_db()) as db, db:
            key, profile = self.identity(db, g.api_secret_hash)
            g.api_key_id, g.api_user_id = key['id'], key['user_id']
            db.execute('UPDATE api_keys SET last_used_at=? WHERE id=?', (time.time(), key['id']))
        self.rate_limit('key:' + key['id'] + (':write' if request.method in ('POST', 'PATCH', 'DELETE') else ':read'),
                        10 if request.method in ('POST', 'PATCH', 'DELETE') else 60)

    def finish_response(self, response):
        response.headers['Cache-Control'] = 'no-store'
        response.headers['Referrer-Policy'] = 'no-referrer'
        # A long upstream read may outlive revocation. Do not return its results.
        if response.status_code < 400 and hasattr(g, 'api_secret_hash'):
            try:
                with closing(self.keep.attribution_db()) as db:
                    self.identity(db, g.api_secret_hash)
                # Writes checked this under their SQLite reservation before
                # applying the operation. Preserve a committed success if an
                # owner changes settings afterward; discard stale read results.
                if request.method in ('GET', 'HEAD') and g.api_settings != self.keep.connection_settings.snapshot():
                    raise ApiProblem(409, 'conflict', 'Service or collection settings changed. Reload before retrying.')
            except ApiProblem as error:
                return self.problem_response(error)
        self.app.logger.info('API result key=%s method=%s route=%s status=%s',
                             getattr(g, 'api_key_id', 'unauthenticated'), request.method,
                             request.url_rule.rule if request.url_rule else 'unmatched', response.status_code)
        return response

    def current(self, db, scope):
        key, profile = self.identity(db, g.api_secret_hash)
        self.require_scope(key, scope)
        return key, profile

    def selected_collections(self):
        # Use the same snapshot as upstream requests; completion checks reject
        # results after an intervening configuration change.
        raw = self.keep.connection_value('KEEP_COLLECTIONS')
        return {int(key): label for key, label in json.loads(raw).items()} if raw else self.keep.COLLECTIONS

    def parameters(self, allowed):
        if set(request.args) - set(allowed) or any(len(request.args.getlist(key)) != 1 for key in request.args):
            raise ApiProblem(400, 'invalid_request', 'Unsupported or repeated query parameter.')
        values = {}
        for name, default, minimum, maximum in (('limit', 25, 1, 100), ('offset', 0, 0, 10000)):
            text = request.args.get(name, str(default))
            if not re.fullmatch(r'[0-9]{1,5}', text) or not minimum <= int(text) <= maximum:
                raise ApiProblem(400, 'invalid_request', 'Invalid pagination parameter.')
            values[name] = int(text)
        collection = request.args.get('collection_id')
        selected = self.selected_collections()
        if collection is not None:
            if not re.fullmatch(r'[1-9][0-9]{0,8}', collection):
                raise ApiProblem(400, 'invalid_request', 'Invalid collection_id.')
            if int(collection) not in selected:
                raise ApiProblem(404, 'not_found', 'Collection not available.')
            selected = {int(collection): selected[int(collection)]}
        return values, selected

    @staticmethod
    def page(rows, values):
        if len(rows) > 10000:
            raise ApiProblem(422, 'result_limit_exceeded',
                             'Too many records. Filter by collection or narrow the media search before retrying.')
        offset, limit = values['offset'], values['limit']
        return jsonify(data=rows[offset:offset + limit], pagination={
            'limit': limit, 'offset': offset, 'total': len(rows),
            'next_offset': offset + limit if offset + limit < len(rows) else None})

    def collections(self):
        with closing(self.keep.attribution_db()) as db:
            self.current(db, 'collections:read')
        values, selected = self.parameters(('limit', 'offset', 'collection_id'))
        return self.page([{'collection_id': cid, 'name': name} for cid, name in sorted(selected.items())], values)

    def feed(self, collection_id, kind, deadline):
        base = self.keep.connection_value('MAINTAINERR_URL')
        if not base:
            raise ApiProblem(502, 'upstream_unavailable', 'Maintainerr is not available.')
        rows, seen = [], set()
        total_bytes = 0
        try:
            for page in range(1, MAX_PAGES + 1):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ValueError('budget')
                url = f'{base}/api/collections/{kind}/{collection_id}/content/{page}'
                with requests.get(url, params={'size': PAGE_SIZE}, timeout=min(5, remaining),
                                  allow_redirects=False, stream=True) as response:
                    if response.status_code != 200:
                        raise ValueError('status')
                    body = bytearray()
                    for chunk in response.iter_content(16384):
                        body.extend(chunk)
                        total_bytes += len(chunk)
                        if (len(body) > 4 * 1024 * 1024 or total_bytes > 32 * 1024 * 1024 or
                                time.monotonic() > deadline):
                            raise ValueError('budget')
                    payload = json.loads(body)
                items = payload.get('items') if isinstance(payload, dict) else None
                if not isinstance(items, list) or len(items) > PAGE_SIZE:
                    raise ValueError('shape')
                for item in items:
                    if (not isinstance(item, dict) or not isinstance(item.get('mediaData'), dict) or
                            not MEDIA_ID.fullmatch(str(item.get('mediaServerId', ''))) or
                            str(item['mediaServerId']) in seen):
                        raise ValueError('identity')
                    seen.add(str(item['mediaServerId']))
                    rows.append(item)
                if len(items) < PAGE_SIZE:
                    return rows
            raise ValueError('pagination')
        except (requests.RequestException, ValueError, TypeError):
            raise ApiProblem(502, 'upstream_unavailable', 'Maintainerr could not provide a complete collection. Try again later.') from None

    def media(self):
        with closing(self.keep.attribution_db()) as db:
            self.current(db, 'media:read')
        values, selected = self.parameters(('limit', 'offset', 'collection_id', 'search', 'state'))
        state, search = request.args.get('state', 'leaving'), request.args.get('search', '')
        if state not in ('leaving', 'kept', 'all') or len(search) > 100:
            raise ApiProblem(400, 'invalid_request', 'Invalid media filter.')
        rows, deadline = [], time.monotonic() + 20
        for cid in sorted(selected):
            kept = self.feed(cid, 'exclusions', deadline)
            kept_ids = {str(item['mediaServerId']) for item in kept}
            leaving = self.feed(cid, 'media', deadline) if state != 'kept' else []
            for label, source in (('leaving', leaving), ('kept', kept)):
                if state not in (label, 'all'):
                    continue
                for item in source:
                    if label == 'leaving' and str(item['mediaServerId']) in kept_ids:
                        continue
                    data = item['mediaData']
                    title = str(data.get('title') or 'Untitled')[:500]
                    if search.casefold() not in title.casefold():
                        continue
                    rows.append({'media_id': str(item['mediaServerId']), 'collection_id': cid,
                                 'title': title, 'year': data.get('year') if type(data.get('year')) is int else None,
                                 'type': str(data.get('type') or 'unknown')[:30], 'state': label})
        if selected != {cid: name for cid, name in self.selected_collections().items() if cid in selected}:
            raise ApiProblem(409, 'conflict', 'Collection settings changed. Reload before retrying.')
        return self.page(rows, values)

    @staticmethod
    def manager(profile, owner):
        return profile['plex_id'] == owner or bool(profile['can_remove_any'])

    def keep_row(self, row, user_id):
        return {'id': row['collection_id'] + ':' + row['media_id'],
                'collection_id': int(row['collection_id']), 'media_id': row['media_id'],
                'duration': 'temporary' if row['expires_at'] else 'indefinite',
                'expires_at': stored_timestamp(row['expires_at']),
                'extension_available_at': stored_timestamp(row['extension_available_at']),
                'owned_by_current_user': row['user_id'] == user_id}

    def saved_keeps(self, db, selected, profile):
        rows = db.execute('''SELECT s.*, a.user_id FROM keep_schedules s LEFT JOIN keep_attribution a
            ON a.collection_id=s.collection_id AND a.media_id=s.media_id
            ORDER BY s.collection_id, s.media_id''').fetchall()
        return [row for row in rows if int(row['collection_id']) in selected and
                (self.manager(profile, self.keep.owner_id()) or row['user_id'] == profile['plex_id'])]

    def keeps(self):
        values, selected = self.parameters(('limit', 'offset', 'collection_id'))
        with closing(self.keep.attribution_db()) as db:
            _, profile = self.current(db, 'keeps:read')
            rows = [self.keep_row(row, profile['plex_id']) for row in self.saved_keeps(db, selected, profile)]
        return self.page(rows, values)

    def parse_keep_id(self, keep_id):
        match = re.fullmatch(r'([1-9][0-9]{0,8}):([1-9][0-9]{0,19})', keep_id)
        if not match or int(match[1]) not in self.selected_collections():
            raise ApiProblem(404, 'not_found', 'Keep not available.')
        return int(match[1]), match[2]

    def get_keep(self, keep_id):
        if request.args:
            raise ApiProblem(400, 'invalid_request', 'Unsupported query parameter.')
        cid, media_id = self.parse_keep_id(keep_id)
        with closing(self.keep.attribution_db()) as db:
            _, profile = self.current(db, 'keeps:read')
            row = next((row for row in self.saved_keeps(db, {cid}, profile) if row['media_id'] == media_id), None)
            if not row:
                raise ApiProblem(404, 'not_found', 'Keep not available.')
            return jsonify(data=self.keep_row(row, profile['plex_id']))

    def create_key(self, db, profile, name, scopes, expires_at):
        valid_expiry = (type(expires_at) in (int, float) and math.isfinite(expires_at) and
                        (expires_at == 0 or time.time() < expires_at <= time.time() + 366 * 86400))
        if (not isinstance(name, str) or not 1 <= len(name.strip()) <= 80 or
                any(ord(char) < 32 for char in name) or not scopes or set(scopes) - SCOPES or
                not valid_expiry):
            raise ValueError('Choose a name, explicit scopes and a valid expiry.')
        count = db.execute('''SELECT count(*) FROM api_keys WHERE user_id=?
            AND account_version=? AND revoked_at IS NULL AND (expires_at=0 OR expires_at>?)''',
                           (profile['plex_id'], profile['session_version'], time.time())).fetchone()[0]
        if count >= 20:
            raise ValueError('Revoke an existing key before creating more than 20 active keys.')
        token = 'keep_' + secrets.token_urlsafe(32)
        key_id = uuid.uuid4().hex
        db.execute('INSERT INTO api_keys VALUES (?,?,?,?,?,?,?,?,?,NULL,NULL)',
                   (key_id, profile['plex_id'], name.strip(), token[:13], hashlib.sha256(token.encode()).hexdigest(),
                    json.dumps(sorted(set(scopes))), profile['session_version'], time.time(), expires_at))
        return token, key_id

    def key_management(self):
        denied = self.keep.require_owner()
        if denied:
            return denied
        token, notice, error = None, None, False
        user_id = str(session['plex_user']['id'])
        if request.method == 'POST':
            csrf = self.keep.require_form_csrf()
            if csrf:
                return csrf
            limited = self.keep.persistent_rate_limit('api-key-management', 20, 3600)
            if limited:
                return limited
            try:
                with closing(self.keep.attribution_db()) as db, db:
                    db.execute('BEGIN IMMEDIATE')
                    profile = db.execute('SELECT * FROM user_profiles WHERE plex_id=?', (user_id,)).fetchone()
                    if (not profile or profile['status'] != 'active' or
                            not self.keep.plex_account_access_active(profile) or
                            session['plex_user'].get('session_version') != profile['session_version']):
                        return 'Sign in again before managing API keys.', 403
                    action = request.form.get('action')
                    if action == 'create':
                        days = request.form.get('expiry_days', '90')
                        if days == 'never':
                            expires_at = 0
                        elif days in ('30', '90', '365'):
                            expires_at = time.time() + int(days) * 86400
                        else:
                            raise ValueError('Choose an expiry of 30, 90 or 365 days, or Never expires.')
                        token, key_id = self.create_key(db, profile, request.form.get('name', ''),
                                                      request.form.getlist('scope'), expires_at)
                        key = db.execute('SELECT * FROM api_keys WHERE id=?', (key_id,)).fetchone()
                        notice = 'Copy this key now. Keep will not show it again.'
                    elif action in ('revoke', 'rotate', 'remove'):
                        old = db.execute('SELECT * FROM api_keys WHERE id=? AND user_id=?',
                                         (request.form.get('key_id', ''), user_id)).fetchone()
                        if not old:
                            raise ValueError('Key not available.')
                        if action == 'rotate' and (old['revoked_at'] is not None or key_expired(old['expires_at'])):
                            raise ValueError('Create a new key to replace an expired or revoked key.')
                        key = old
                        if action == 'remove':
                            if old['revoked_at'] is None:
                                raise ValueError('Revoke this key before removing it.')
                            db.execute('DELETE FROM api_idempotency WHERE key_id=?', (old['id'],))
                            db.execute('DELETE FROM api_rate_limits WHERE subject IN (?,?)',
                                       ('key:' + old['id'] + ':read', 'key:' + old['id'] + ':write'))
                            db.execute('DELETE FROM api_keys WHERE id=? AND user_id=? AND revoked_at IS NOT NULL',
                                       (old['id'], user_id))
                            notice = 'Revoked API key removed. Its activity history is retained.'
                        elif action == 'rotate':
                            db.execute('UPDATE api_keys SET revoked_at=? WHERE id=?', (time.time(), old['id']))
                            token, key_id = self.create_key(db, profile, old['name'], json.loads(old['scopes']), old['expires_at'])
                            notice = 'The previous key is revoked. Copy its replacement now; its expiry is unchanged.'
                        else:
                            db.execute('UPDATE api_keys SET revoked_at=COALESCE(revoked_at,?) WHERE id=?', (time.time(), old['id']))
                            key_id, notice = old['id'], 'API key revoked.'
                    else:
                        raise ValueError('Choose a supported key action.')
                    db.execute('''INSERT INTO activity_log(actor_id,actor_name,action,description)
                        VALUES (?,?,?,?)''', (*self.keep.activity_actor(), 'api-key-' + action,
                                              key_activity_description(action, key['name'],
                                                                       json.loads(key['scopes']), key['expires_at'])))
            except ValueError as problem:
                notice, error = str(problem), True
        with closing(self.keep.attribution_db()) as db:
            keys = []
            profile = self.keep.current_profile()
            for row in db.execute('''SELECT id,name,prefix,scopes,created_at,expires_at,revoked_at,last_used_at,
                account_version FROM api_keys WHERE user_id=? ORDER BY created_at DESC LIMIT 100''', (user_id,)):
                key = dict(row)
                key['scopes'] = json.loads(key['scopes'])
                key['active'] = key['revoked_at'] is None and not key_expired(key['expires_at']) and key['account_version'] == profile['session_version']
                key['state'] = ('Revoked' if key['revoked_at'] is not None else
                                'Expired' if key_expired(key['expires_at']) else
                                'Sign-in changed' if not key['active'] else 'Active')
                if key['expires_at'] == 0:
                    key['expires_at'] = None
                for field in ('created_at', 'expires_at', 'revoked_at', 'last_used_at'):
                    key[field + '_display'] = (datetime.fromtimestamp(key[field], timezone.utc).strftime('%d %b %Y, %H:%M UTC')
                                              if key[field] is not None else 'Never' if field == 'expires_at' else None)
                    key[field] = timestamp(key[field])
                keys.append(key)
        response = self.app.make_response(render_template('api_keys.html', keys=keys, scopes=sorted(SCOPES),
                                                          new_key=token, notice=notice, error=error))
        response.headers['Cache-Control'] = 'no-store'
        response.headers['Referrer-Policy'] = 'no-referrer'
        return response

    def legacy_key_management(self):
        denied = self.keep.require_owner()
        if denied:
            return denied
        return redirect('/settings/api-keys') if request.method == 'GET' else self.key_management()

    def reference(self):
        denied = self.keep.require_owner()
        if denied:
            return denied
        return render_template('api_reference.html')

    def legacy_reference(self):
        denied = self.keep.require_owner()
        return denied if denied else redirect('/settings/api-reference')

    def mutate(self, keep_id=None):
        if request.args:
            raise ApiProblem(400, 'invalid_request', 'Unsupported query parameter.')
        with closing(self.keep.attribution_db()) as db:
            self.current(db, 'keeps:write')
        payload = self.mutation_payload()
        request_key = request.headers.get('Idempotency-Key', '')
        if not IDEMPOTENCY.fullmatch(request_key):
            raise ApiProblem(400, 'invalid_request', 'Provide an Idempotency-Key of 16–128 letters, digits, underscores or hyphens.')
        request_key_hash = hashlib.sha256(request_key.encode()).hexdigest()
        request_hash = hashlib.sha256(json.dumps([request.method, request.path, payload],
                                                 sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        if request.method == 'POST':
            cid, media_id = payload['collection_id'], payload['media_id']
        else:
            cid, media_id = self.parse_keep_id(keep_id)
        if cid not in self.selected_collections():
            raise ApiProblem(404, 'not_found', 'Collection not available.')
        try:
            with self.keep.keep_mutation_lock():
                replay = self.claim_request(request_key_hash, request_hash)
                if replay is not None:
                    return replay
                attempted = False
                try:
                    settings = g.api_settings
                    deadline = time.monotonic() + 20
                    exclusions = self.feed(cid, 'exclusions', deadline)
                    exclusion = next((item for item in exclusions if str(item['mediaServerId']) == media_id), None)
                    if request.method == 'POST':
                        if exclusion:
                            raise ApiProblem(409, 'conflict', 'This media already has protection. Use its existing Keep.')
                        leaving = self.feed(cid, 'media', deadline)
                        if not any(str(item['mediaServerId']) == media_id for item in leaving):
                            raise ApiProblem(404, 'not_found', 'Media is not available to Keep in this collection.')
                    elif exclusion is None or ('ruleGroupId' in exclusion and exclusion['ruleGroupId'] is None):
                        raise ApiProblem(404, 'not_found', 'Keep not available.')

                    # Account/key/settings updates use SQLite too. Hold its write
                    # reservation through the bounded remote write and metadata
                    # commit, so a completed revocation cannot race the operation.
                    with closing(self.keep.attribution_db()) as db, db:
                        db.execute('BEGIN IMMEDIATE')
                        key, profile = self.current(db, 'keeps:write')
                        if settings != self.keep.connection_settings.snapshot() or cid not in self.selected_collections():
                            raise ApiProblem(409, 'conflict', 'Service or collection settings changed. Reload before retrying.')
                        row = db.execute('''SELECT s.*, a.user_id FROM keep_schedules s
                            LEFT JOIN keep_attribution a ON a.collection_id=s.collection_id AND a.media_id=s.media_id
                            WHERE s.collection_id=? AND s.media_id=?''', (str(cid), media_id)).fetchone()
                        if request.method != 'POST' and (not row or not
                                (self.manager(profile, self.keep.owner_id()) or row['user_id'] == profile['plex_id'])):
                            raise ApiProblem(404, 'not_found', 'Keep not available.')
                        if request.method == 'POST' and row:
                            raise ApiProblem(409, 'conflict', 'Saved Keep state requires review before protecting this media again.')
                        duration = payload.get('duration', 'temporary')
                        if (request.method != 'DELETE' and duration == 'indefinite' and not
                                (profile['plex_id'] == self.keep.owner_id() or profile['can_keep_indefinitely'])):
                            raise ApiProblem(403, 'permission_denied', 'Indefinite Keeps require current account permission.')
                        expires, available = self.schedule(row, duration) if request.method != 'DELETE' else (None, None)
                        if request.method in ('POST', 'DELETE'):
                            attempted = True
                            try:
                                self.exclusion_write(cid, media_id, 0 if request.method == 'POST' else 1)
                            except ApiProblem:
                                self.mark_uncertain(db, request_key_hash)
                                db.commit()
                                raise
                        if request.method == 'DELETE':
                            db.execute('DELETE FROM keep_attribution WHERE collection_id=? AND media_id=?', (str(cid), media_id))
                            db.execute('DELETE FROM keep_schedules WHERE collection_id=? AND media_id=?', (str(cid), media_id))
                            result, status = None, 204
                        else:
                            if request.method == 'POST':
                                db.execute('''INSERT INTO keep_attribution(collection_id,media_id,user_id,username)
                                    VALUES (?,?,?,?)''', (str(cid), media_id, profile['plex_id'],
                                                         profile['display_name'] or profile['plex_username'] or 'Keep user'))
                                db.execute('DELETE FROM notification_queue WHERE collection_id=? AND media_id=?', (cid, media_id))
                            db.execute('''INSERT INTO keep_schedules(collection_id,media_id,expires_at,extension_available_at)
                                VALUES (?,?,?,?) ON CONFLICT(collection_id,media_id) DO UPDATE SET
                                expires_at=excluded.expires_at,extension_available_at=excluded.extension_available_at''',
                                       (str(cid), media_id, expires, available))
                            saved = db.execute('''SELECT s.*, a.user_id FROM keep_schedules s LEFT JOIN keep_attribution a
                                ON a.collection_id=s.collection_id AND a.media_id=s.media_id
                                WHERE s.collection_id=? AND s.media_id=?''', (str(cid), media_id)).fetchone()
                            result, status = {'data': self.keep_row(saved, profile['plex_id'])}, 201 if request.method == 'POST' else 200
                            if request.method == 'POST':
                                try:
                                    self.membership_remove(cid, media_id)
                                except ApiProblem:
                                    # Protection succeeded: preserve its owner and
                                    # schedule even if Leaving removal is uncertain.
                                    self.mark_uncertain(db, request_key_hash)
                                    db.commit()
                                    raise
                        db.execute('''INSERT INTO activity_log(actor_id,actor_name,action,description)
                            VALUES (?,?,?,?)''', (profile['plex_id'],
                                self.keep.activity_actor(self.keep.local_session_user(profile) if profile['auth_type'] == 'local'
                                                         else {'username': profile['plex_username']})[1],
                                'api-keep-' + request.method.lower(),
                                {'POST': 'Created', 'PATCH': 'Changed', 'DELETE': 'Removed'}[request.method]
                                + f' Keep protection using API key “{key["name"]}”; collection {cid}; media {media_id}'))
                        db.execute('''UPDATE api_idempotency SET status='succeeded',response_status=?,response_json=?
                            WHERE key_id=? AND request_key_hash=?''',
                                   (status, json.dumps(result), g.api_key_id, request_key_hash))
                    response = self.app.make_response(('', 204)) if result is None else self.app.make_response((jsonify(result), status))
                    if status == 201:
                        response.headers['Location'] = f'/api/v1/keeps/{cid}:{media_id}'
                    return response
                except Exception:
                    with closing(self.keep.attribution_db()) as db, db:
                        if attempted:
                            self.mark_uncertain(db, request_key_hash)
                        else:
                            db.execute('DELETE FROM api_idempotency WHERE key_id=? AND request_key_hash=?',
                                       (g.api_key_id, request_key_hash))
                    raise
        except self.keep.KeepMutationBusy:
            raise ApiProblem(409, 'busy', 'Another Keep or deletion operation is running. Retry later with the same Idempotency-Key.', 2) from None

    def mutation_payload(self):
        if (request.content_length or 0) > MAX_BODY:
            raise ApiProblem(413, 'payload_too_large', 'Keep write bodies are limited to 8 KiB.')
        body = request.get_data(cache=False)
        if len(body) > MAX_BODY:
            raise ApiProblem(413, 'payload_too_large', 'Keep write bodies are limited to 8 KiB.')
        if request.method == 'DELETE':
            if body:
                raise ApiProblem(400, 'invalid_request', 'DELETE does not accept a request body.')
            return {}
        if request.mimetype != 'application/json':
            raise ApiProblem(415, 'unsupported_media_type', 'Use Content-Type: application/json.')
        def unique_fields(pairs):
            value = {}
            for key, item in pairs:
                if key in value:
                    raise ValueError('duplicate')
                value[key] = item
            return value
        try:
            payload = json.loads(body, object_pairs_hook=unique_fields)
        except (ValueError, UnicodeDecodeError):
            raise ApiProblem(400, 'invalid_request', 'Provide a valid JSON object without repeated fields.') from None
        allowed = {'collection_id', 'media_id', 'duration'} if request.method == 'POST' else {'duration'}
        if not isinstance(payload, dict) or set(payload) - allowed:
            raise ApiProblem(400, 'invalid_request', 'Unsupported request fields.')
        if request.method == 'POST':
            if type(payload.get('collection_id')) is not int or not 1 <= payload['collection_id'] <= 999999999:
                raise ApiProblem(400, 'invalid_request', 'collection_id must be a positive integer.')
            valid_media_id(payload.get('media_id'))
            payload.setdefault('duration', 'temporary')
        if payload.get('duration') not in ('temporary', 'indefinite'):
            raise ApiProblem(400, 'invalid_request', 'duration must be temporary or indefinite.')
        return payload

    def claim_request(self, request_key_hash, request_hash):
        with closing(self.keep.attribution_db()) as db, db:
            db.execute('BEGIN IMMEDIATE')
            _, profile = self.current(db, 'keeps:write')
            # Uncertain/interrupted operations do not expire into automatic retries.
            db.execute("DELETE FROM api_idempotency WHERE status='succeeded' AND created_at<?", (time.time() - 86400,))
            row = db.execute('SELECT * FROM api_idempotency WHERE key_id=? AND request_key_hash=?',
                             (g.api_key_id, request_key_hash)).fetchone()
            if row:
                if row['request_hash'] != request_hash:
                    raise ApiProblem(409, 'conflict', 'This Idempotency-Key was used for a different request.')
                if row['status'] != 'succeeded':
                    raise ApiProblem(409, 'operation_uncertain', 'A previous attempt may have changed protection. Inspect the current state before making a new request.')
                payload = json.loads(row['response_json'])
                if payload is not None:
                    data = payload['data']
                    saved = db.execute('SELECT user_id FROM keep_attribution WHERE collection_id=? AND media_id=?',
                                       (str(data['collection_id']), data['media_id'])).fetchone()
                    if not self.manager(profile, self.keep.owner_id()) and (
                            not data['owned_by_current_user'] or (saved and saved['user_id'] != profile['plex_id'])):
                        raise ApiProblem(404, 'not_found', 'Keep not available.')
                response = self.app.make_response(('', 204)) if payload is None else self.app.make_response((jsonify(payload), row['response_status']))
                response.headers['Idempotency-Replayed'] = 'true'
                if row['response_status'] == 201:
                    response.headers['Location'] = '/api/v1/keeps/' + payload['data']['id']
                return response
            if db.execute('SELECT count(*) FROM api_idempotency WHERE key_id=?', (g.api_key_id,)).fetchone()[0] >= 1000:
                raise ApiProblem(429, 'rate_limited', 'This key has too many retained write attempts. Review uncertain operations or rotate it.', 3600)
            db.execute('INSERT INTO api_idempotency VALUES (?,?,?,\'processing\',NULL,NULL,?)',
                       (g.api_key_id, request_key_hash, request_hash, time.time()))
        return None

    def mark_uncertain(self, db, request_key_hash):
        db.execute("UPDATE api_idempotency SET status='uncertain' WHERE key_id=? AND request_key_hash=?",
                   (g.api_key_id, request_key_hash))

    def schedule(self, row, duration):
        if duration == 'indefinite':
            return None, None
        now = datetime.now(timezone.utc)
        if request.method == 'PATCH' and row and row['expires_at']:
            if row['extension_available_at'] and now < datetime.strptime(row['extension_available_at'], '%Y-%m-%d %H:%M:%S').replace(tzinfo=timezone.utc):
                raise ApiProblem(409, 'conflict', 'A temporary Keep extension is not available yet.')
            current = datetime.strptime(row['expires_at'], '%Y-%m-%d %H:%M:%S').replace(tzinfo=timezone.utc)
            return self.keep.temporary_keep_expiry(max(now, current)), self.keep.db_timestamp(current)
        return self.keep.temporary_keep_expiry(now), None

    def exclusion_write(self, cid, media_id, action):
        try:
            deadline = time.monotonic() + 5
            with requests.post(self.keep.connection_value('MAINTAINERR_URL') + '/api/rules/exclusion',
                               json={'mediaId': media_id, 'collectionId': cid, 'action': action},
                               timeout=5, allow_redirects=False, stream=True) as response:
                if not 200 <= response.status_code < 300:
                    raise ValueError('status')
                body = bytearray()
                for chunk in response.iter_content(4096):
                    body.extend(chunk)
                    if len(body) > 65536 or time.monotonic() > deadline:
                        raise ValueError('budget')
                payload = json.loads(body)
            if (not isinstance(payload, dict) or type(payload.get('code')) is not int
                    or payload['code'] != 1):
                raise ValueError('unconfirmed')
        except (requests.RequestException, ValueError, TypeError):
            raise ApiProblem(502, 'mutation_uncertain', 'Maintainerr could not confirm the write. Inspect current protection before trying another request.') from None

    def membership_remove(self, cid, media_id):
        try:
            with requests.delete(self.keep.connection_value('MAINTAINERR_URL') + '/api/collections/media',
                                 params={'mediaId': media_id, 'collectionId': cid}, timeout=5,
                                 allow_redirects=False, stream=True) as response:
                if not 200 <= response.status_code < 300:
                    raise ValueError('status')
        except (requests.RequestException, ValueError):
            raise ApiProblem(502, 'mutation_uncertain', 'Protection was saved, but collection removal is uncertain. Inspect the title before retrying.') from None
