"""Persist owner defaults; project access only from fresh, scoped Plex evidence."""
from contextlib import contextmanager
import copy
import hashlib
import json
import math
import re
import time
import uuid

PROOF_TTL = 1800
_ID = re.compile(r'[1-9][0-9]{0,19}\Z')
_SCOPE = re.compile(r'[0-9a-f]{64}\Z')
_MODES = {'unset', 'auto', 'manual'}


def _rows(db, sql, values=()):
    cursor = db.execute(sql, values)
    names = [column[0] for column in cursor.description]
    rows = cursor.fetchmany(100001)
    if len(rows) > 100000:
        raise ValueError('Plex defaults inventory exceeds its limit')
    return [dict(zip(names, row)) for row in rows]


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


def _hash(value):
    return hashlib.sha256(_json(value).encode()).hexdigest()


def _now(value=None):
    value = time.time() if value is None else value
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise ValueError('Invalid Plex verification time')
    return float(value)


@contextmanager
def _write(db):
    # Keep the caller's transaction open, including when this is its first write.
    if not db.in_transaction:
        db.execute('BEGIN IMMEDIATE')
    name = 'plex_defaults_' + uuid.uuid4().hex
    db.execute('SAVEPOINT ' + name)
    try:
        yield
    except BaseException:
        db.execute('ROLLBACK TO ' + name)
        db.execute('RELEASE ' + name)
        raise
    else:
        db.execute('RELEASE ' + name)


def init_schema(db):
    db.execute('''CREATE TABLE IF NOT EXISTS plex_user_default_settings (
        id INTEGER PRIMARY KEY CHECK(id=1), email_enabled INTEGER NOT NULL CHECK(email_enabled IN (0,1)),
        library_enabled INTEGER NOT NULL CHECK(library_enabled IN (0,1)), owner_id TEXT NOT NULL DEFAULT '')''')
    db.execute('INSERT OR IGNORE INTO plex_user_default_settings VALUES (1,1,1,\'\')')
    db.execute('''CREATE TABLE IF NOT EXISTS plex_user_default_modes (
        user_id TEXT PRIMARY KEY,
        email_mode TEXT NOT NULL DEFAULT 'unset' CHECK(email_mode IN ('unset','auto','manual')),
        library_mode TEXT NOT NULL DEFAULT 'unset' CHECK(library_mode IN ('unset','auto','manual')),
        new_user_seen INTEGER NOT NULL DEFAULT 0 CHECK(new_user_seen IN (0,1)),
        email_auto_origin INTEGER NOT NULL DEFAULT 0 CHECK(email_auto_origin IN (0,1)))''')
    if 'new_user_seen' not in {row[1] for row in db.execute('PRAGMA table_info(plex_user_default_modes)')}:
        db.execute('ALTER TABLE plex_user_default_modes ADD COLUMN new_user_seen INTEGER NOT NULL DEFAULT 0')
    if 'email_auto_origin' not in {row[1] for row in db.execute('PRAGMA table_info(plex_user_default_modes)')}:
        db.execute('ALTER TABLE plex_user_default_modes ADD COLUMN email_auto_origin INTEGER NOT NULL DEFAULT 0 CHECK(email_auto_origin IN (0,1))')
    db.execute("UPDATE plex_user_default_modes SET email_auto_origin=1 WHERE email_mode='auto' AND email_auto_origin=0")
    db.execute('''CREATE TABLE IF NOT EXISTS plex_user_default_proof (
        id INTEGER PRIMARY KEY CHECK(id=1), scope TEXT NOT NULL, valid INTEGER NOT NULL CHECK(valid IN (0,1)),
        payload TEXT NOT NULL)''')
    db.execute('''CREATE TABLE IF NOT EXISTS plex_user_default_mappings (
        library_key TEXT PRIMARY KEY, scope TEXT NOT NULL, root_fingerprint TEXT NOT NULL,
        section_fingerprint TEXT NOT NULL, section_keys TEXT NOT NULL)''')
    db.execute('''CREATE TABLE IF NOT EXISTS plex_user_default_email_overrides (
        email TEXT PRIMARY KEY COLLATE NOCASE)''')


def settings(db):
    rows = _rows(db, 'SELECT email_enabled,library_enabled FROM plex_user_default_settings WHERE id=1')
    row = rows[0] if rows else {'email_enabled': 1, 'library_enabled': 1}
    return {key: bool(row[key]) for key in ('email_enabled', 'library_enabled')}


def save_settings(db, email_enabled, library_enabled):
    if type(email_enabled) is not bool or type(library_enabled) is not bool:
        raise ValueError('Choose whether each Plex default is enabled')
    with _write(db):
        db.execute('UPDATE plex_user_default_settings SET email_enabled=?,library_enabled=? WHERE id=1',
                   (int(email_enabled), int(library_enabled)))


def user_modes(db, user_id):
    rows = _rows(db, 'SELECT email_mode,library_mode FROM plex_user_default_modes WHERE user_id=?', (str(user_id),))
    row = rows[0] if rows else {'email_mode': 'unset', 'library_mode': 'unset'}
    return {'email': row['email_mode'], 'library': row['library_mode']}


def email_was_automatic(db, user_id):
    row = db.execute('SELECT email_auto_origin FROM plex_user_default_modes WHERE user_id=?', (str(user_id),)).fetchone()
    return bool(row and row[0])


def _set_modes(db, user_id, *, email=None, library=None):
    current = user_modes(db, user_id)
    values = {'email': current['email'] if email is None else email,
              'library': current['library'] if library is None else library}
    if any(value not in _MODES for value in values.values()):
        raise ValueError('Invalid Plex default mode')
    db.execute('''INSERT INTO plex_user_default_modes(user_id,email_mode,library_mode,email_auto_origin) VALUES (?,?,?,?)
        ON CONFLICT(user_id) DO UPDATE SET email_mode=excluded.email_mode,library_mode=excluded.library_mode,
        email_auto_origin=MAX(plex_user_default_modes.email_auto_origin,excluded.email_auto_origin)''',
        (str(user_id), values['email'], values['library'], int(values['email'] == 'auto')))


def _profiles(db):
    return {str(row['plex_id']): row for row in _rows(db, 'SELECT * FROM user_profiles ORDER BY plex_id')}


def _profile(db, user_id):
    rows = _rows(db, 'SELECT * FROM user_profiles WHERE plex_id=?', (str(user_id),))
    return rows[0] if rows else None


def _owner(db):
    table = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='installation'").fetchone()
    if table:
        row = db.execute('SELECT owner FROM installation WHERE id=1').fetchone()
        if row and row[0]:
            return str(row[0])
    rows = _rows(db, 'SELECT owner_id FROM plex_user_default_settings WHERE id=1')
    return rows[0]['owner_id'] if rows else ''


def _email(value):
    if not isinstance(value, str):
        return ''
    value = value.strip().casefold()
    if (not value or len(value) > 254 or value.count('@') != 1
            or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in value)):
        return ''
    local, domain = value.split('@')
    return value if local and '.' in domain[1:-1] else ''


def _blocked_email(db, address):
    return bool(address and db.execute('SELECT 1 FROM plex_user_default_email_overrides WHERE email=?', (address,)).fetchone())


def _email_manageable(db, address, user_id):
    if not address or _blocked_email(db, address):
        return False
    try:
        from plex_defaults_email import can_manage_address
    except ImportError:
        return not (db.execute('SELECT 1 FROM email_recipients WHERE email=? COLLATE NOCASE', (address,)).fetchone()
                    or db.execute('SELECT 1 FROM recipient_subscriptions WHERE email=? COLLATE NOCASE', (address,)).fetchone())
    return bool(can_manage_address(db, address, str(user_id)))


def _manual_libraries(db, user_id):
    return bool(db.execute('SELECT 1 FROM user_library_permissions WHERE user_id=? LIMIT 1', (str(user_id),)).fetchone())


def enroll_new_users(db, user_ids, owner_id):
    """The caller supplies only IDs inserted by its verified discovery/login transaction."""
    owner_id = str(owner_id)
    if not _ID.fullmatch(owner_id):
        raise ValueError('Plex defaults owner differs from the installation')
    enrolled = []
    with _write(db):
        if _owner(db) and _owner(db) != owner_id:
            raise ValueError('Plex defaults owner differs from the installation')
        db.execute('UPDATE plex_user_default_settings SET owner_id=? WHERE id=1', (owner_id,))
        options, profiles = settings(db), _profiles(db)
        for user_id in sorted({str(value) for value in user_ids}):
            profile = profiles.get(user_id)
            if (not _ID.fullmatch(user_id) or user_id == owner_id or not profile or profile.get('auth_type') != 'plex'
                    or profile.get('status') != 'active' or profile.get('plex_access') != 'active'):
                continue
            seen = db.execute('SELECT new_user_seen FROM plex_user_default_modes WHERE user_id=?', (user_id,)).fetchone()
            if seen and seen[0]:
                continue
            modes = user_modes(db, user_id)
            email_mode, library_mode = modes['email'], modes['library']
            address = _email(profile.get('email'))
            if options['email_enabled'] and email_mode == 'unset' and (not address or _email_manageable(db, address, user_id)):
                email_mode = 'auto'
            if (options['library_enabled'] and library_mode == 'unset'
                    and not profile.get('can_delete_media') and not profile.get('can_delete_any')
                    and not _manual_libraries(db, user_id)):
                library_mode = 'auto'
            _set_modes(db, user_id, email=email_mode, library=library_mode)
            db.execute('UPDATE plex_user_default_modes SET new_user_seen=1 WHERE user_id=?', (user_id,))
            if (email_mode, library_mode) != (modes['email'], modes['library']):
                enrolled.append(user_id)
    return enrolled


def _valid_proof(proof, now):
    if not isinstance(proof, dict):
        raise ValueError('Plex library proof is unavailable')
    if proof.get('checked_at') is None:
        raise ValueError('Plex library verification time is unavailable')
    checked = _now(proof['checked_at'])
    if not 0 <= now - checked <= PROOF_TTL:
        raise ValueError('Plex library proof is not fresh')
    machine, sections, users = proof.get('machine'), proof.get('sections'), proof.get('users')
    if (not isinstance(machine, str) or not 0 < len(machine) <= 256
            or not isinstance(sections, dict) or len(sections) > 10000
            or not isinstance(users, dict) or len(users) > 100000):
        raise ValueError('Invalid Plex library proof')
    result = {'machine': machine, 'sections': {}, 'users': {}, 'checked_at': checked}
    for key, row in sections.items():
        if (not isinstance(key, str) or not _ID.fullmatch(key) or not isinstance(row, dict)
                or row.get('key') != key or row.get('kind') not in ('movie', 'show')
                or not isinstance(row.get('name'), str) or len(row['name']) > 512
                or not isinstance(row.get('locations'), list) or not row['locations']
                or any(not isinstance(p, str) or not 0 < len(p) <= 4096 or any(ord(c) < 32 for c in p)
                       for p in row['locations'])):
            raise ValueError('Invalid Plex section proof')
        result['sections'][key] = {field: copy.deepcopy(row[field]) for field in ('key', 'name', 'kind', 'locations')}
    for user_id, row in users.items():
        if (not isinstance(user_id, str) or not _ID.fullmatch(user_id) or not isinstance(row, dict)
                or type(row.get('restricted')) is not bool or not isinstance(row.get('sections'), list)
                or any(not isinstance(key, str) or key not in result['sections'] for key in row['sections'])
                or len(row['sections']) != len(set(row['sections']))):
            raise ValueError('Invalid Plex user share proof')
        result['users'][user_id] = {'sections': sorted(row['sections']), 'restricted': row['restricted']}
    return result


def reconcile(db, *, proof, scope, owner_id, new_user_ids=(), now=None):
    now = _now(now)
    try:
        if not isinstance(scope, str) or not _SCOPE.fullmatch(scope):
            raise ValueError('Invalid Plex configuration scope')
        verified = _valid_proof(proof, now)
    except (TypeError, ValueError):
        with _write(db):
            db.execute('UPDATE plex_user_default_proof SET valid=0 WHERE id=1')
        return {'verified': False, 'enrolled': [], 'users': 0, 'sections': 0}
    with _write(db):
        db.execute('''INSERT INTO plex_user_default_proof(id,scope,valid,payload) VALUES (1,?,1,?)
            ON CONFLICT(id) DO UPDATE SET scope=excluded.scope,valid=1,payload=excluded.payload''', (scope, _json(verified)))
        enrolled = enroll_new_users(db, new_user_ids, owner_id)
    return {'verified': True, 'enrolled': enrolled, 'users': len(verified['users']), 'sections': len(verified['sections'])}


def _proof(db, scope, now=None):
    if not isinstance(scope, str) or not _SCOPE.fullmatch(scope):
        return None
    rows = _rows(db, 'SELECT scope,valid,payload FROM plex_user_default_proof WHERE id=1')
    if not rows or not rows[0]['valid'] or rows[0]['scope'] != scope:
        return None
    try:
        return _valid_proof(json.loads(rows[0]['payload']), _now(now))
    except (TypeError, ValueError, json.JSONDecodeError):
        return None


def catalog(db, scope, now=None):
    proof = _proof(db, scope, now)
    return copy.deepcopy(proof['sections']) if proof else {}


def _libraries(db, libraries=None):
    current = _rows(db, 'SELECT * FROM media_libraries')
    installed = {row['library_key']: row for row in current}
    libraries = current if libraries is None else [dict(row) for row in libraries]
    result = {}
    for row in libraries:
        key, service, path = row.get('library_key'), row.get('service'), row.get('path')
        if (not isinstance(key, str) or service not in ('radarr', 'sonarr')
                or not re.fullmatch(service + r':[1-9][0-9]{0,19}', key)
                or not isinstance(path, str) or not path):
            continue
        if key in result:
            raise ValueError('Duplicate media-library identity')
        present = installed.get(key)
        if not present or any(present.get(field) != row[field] for field in ('service', 'path')):
            continue
        result[key] = row
    return result


def _root_fingerprint(row):
    return _hash({field: row[field] for field in ('library_key', 'service', 'path')})


def _section_fingerprint(proof, keys):
    return _hash({'machine': proof['machine'], 'sections': [
        {field: proof['sections'][key][field] for field in ('key', 'kind', 'locations')} for key in keys]})


def _mapped(db, libraries, scope, proof):
    if not proof:
        return {}
    from plex_library_access import automatic_mappings
    try:
        automatic = automatic_mappings(proof['sections'], list(libraries.values()))
    except (ValueError, TypeError):
        automatic = {}
    saved = {row['library_key']: row for row in _rows(db, 'SELECT * FROM plex_user_default_mappings')}
    result = {}
    for key, root in libraries.items():
        row = saved.get(key)
        if row is None:
            keys = automatic.get(key, [])
        else:
            try:
                keys = json.loads(row['section_keys'])
                if (row['scope'] != scope or row['root_fingerprint'] != _root_fingerprint(root)
                        or not isinstance(keys, list) or any(k not in proof['sections'] for k in keys)
                        or row['section_fingerprint'] != _section_fingerprint(proof, keys)):
                    continue
            except (ValueError, TypeError, KeyError):
                continue
        kind = 'movie' if root['service'] == 'radarr' else 'show'
        if keys and all(k in proof['sections'] and proof['sections'][k]['kind'] == kind for k in keys):
            result[key] = list(keys)
    return result


def mappings(db, libraries, scope):
    return _mapped(db, _libraries(db, libraries), scope, _proof(db, scope))


def save_mappings(db, mappings, libraries, scope):
    if not isinstance(mappings, dict):
        raise ValueError('Invalid Plex library mappings')
    with _write(db):
        proof, roots = _proof(db, scope), _libraries(db, libraries)
        if not proof:
            raise ValueError('Refresh verified Plex libraries before saving mappings')
        if any(key not in roots for key in mappings):
            raise ValueError('Mapping contains an unknown media library')
        prepared = []
        for key, values in mappings.items():
            if (not isinstance(values, (list, tuple)) or any(not isinstance(value, str) for value in values)
                    or len(values) != len(set(values))):
                raise ValueError('Select known Plex sections once each')
            keys = sorted(values)
            kind = 'movie' if roots[key]['service'] == 'radarr' else 'show'
            if any(value not in proof['sections'] or proof['sections'][value]['kind'] != kind for value in keys):
                raise ValueError('Choose Plex sections matching the media-library type')
            prepared.append((key, scope, _root_fingerprint(roots[key]), _section_fingerprint(proof, keys), _json(keys)))
        for key in roots:
            db.execute('DELETE FROM plex_user_default_mappings WHERE library_key=?', (key,))
        db.executemany('INSERT INTO plex_user_default_mappings VALUES (?,?,?,?,?)', prepared)


def _shared_profile(profile, proof, owner):
    if (not profile or str(profile['plex_id']) == owner or profile.get('auth_type') != 'plex'
            or profile.get('status') != 'active' or profile.get('plex_access') != 'active' or not proof):
        return None
    share = proof['users'].get(str(profile['plex_id']))
    return share if share and not share['restricted'] and share['sections'] else None


def _library_keys(db, profile, scope, proof, libraries):
    share = _shared_profile(profile, proof, _owner(db))
    if not share or profile.get('can_delete_media') or profile.get('can_delete_any') or _manual_libraries(db, profile['plex_id']):
        return set()
    shared = set(share['sections'])
    return {key for key, sections in _mapped(db, libraries, scope, proof).items() if set(sections) <= shared}


def auto_library_keys(db, user_id, scope, now=None, libraries=None):
    if user_modes(db, user_id)['library'] != 'auto':
        return set()
    return _library_keys(db, _profile(db, user_id), scope, _proof(db, scope, now), _libraries(db, libraries))


def manual_library_override(db, user_id):
    with _write(db):
        _set_modes(db, str(user_id), library='manual')


def email_override(db, email, *, user_id=None):
    address = _email(email)
    if email and not address:
        raise ValueError('Invalid email override address')
    with _write(db):
        if address:
            db.execute('INSERT OR IGNORE INTO plex_user_default_email_overrides VALUES (?)', (address,))
        ids = {str(user_id)} if user_id is not None else set()
        ids.update(uid for uid, row in _profiles(db).items() if address and _email(row.get('email')) == address)
        for uid in ids:
            _set_modes(db, uid, email='manual')


def shared_email_accounts(db, scope, now=None):
    """Current verified account scope, also used to clamp formerly automatic mail."""
    proof, profiles, owner = _proof(db, scope, now), _profiles(db), _owner(db)
    counts = {}
    for profile in profiles.values():
        address = _email(profile.get('email'))
        if address:
            counts[address] = counts.get(address, 0) + 1
    accounts = []
    for uid, profile in profiles.items():
        share, address = _shared_profile(profile, proof, owner), _email(profile.get('email'))
        if share and address and counts[address] == 1:
            accounts.append({'user_id': uid, 'email': address, 'sections': list(share['sections'])})
    return accounts


def auto_email_accounts(db, scope, now=None):
    return [row for row in shared_email_accounts(db, scope, now)
            if user_modes(db, row['user_id'])['email'] == 'auto'
            and _email_manageable(db, row['email'], row['user_id'])]


def _email_collections(db, user_id, scope, collection_ids, libraries):
    try:
        from plex_defaults_email import eligible_collections
    except ImportError:
        return []
    eligible = eligible_collections(db, str(user_id), scope, collection_ids, libraries=list(libraries.values()))
    return sorted(set(eligible) & set(collection_ids))


def preview(db, scope, libraries, collection_ids):
    proof, profiles, options, owner = _proof(db, scope), _profiles(db), settings(db), _owner(db)
    roots = _libraries(db, libraries)
    values = list(collection_ids)
    if any(isinstance(value, bool) or not re.fullmatch(r'[1-9][0-9]{0,18}', str(value)) for value in values):
        raise ValueError('Invalid configured collection identity')
    collections = sorted({int(value) for value in values})
    accounts = {}
    for profile in profiles.values():
        address = _email(profile.get('email'))
        if address:
            accounts[address] = accounts.get(address, 0) + 1
    users = []
    for uid, profile in profiles.items():
        if profile.get('auth_type') != 'plex' or uid == owner:
            continue
        modes, reasons = user_modes(db, uid), []
        share = _shared_profile(profile, proof, owner)
        address = _email(profile.get('email'))
        keys = sorted(_library_keys(db, profile, scope, proof, roots))
        if not share:
            if not proof:
                reasons.append('Plex library sharing has not been verified recently.')
            elif profile.get('status') != 'active':
                reasons.append('This Keep account is not active.')
            elif profile.get('plex_access') != 'active':
                reasons.append('Access to this Plex server is not active.')
            elif proof['users'].get(uid, {}).get('restricted'):
                reasons.append('This Plex account has content restrictions.')
            else:
                reasons.append('No supported Plex libraries are shared with this user.')
        email_collections = (_email_collections(db, uid, scope, collections, roots)
                             if share and address and accounts[address] == 1 else [])
        manageable_email = bool(address and accounts[address] == 1 and _email_manageable(db, address, uid))
        email_ok = bool(share and options['email_enabled'] and modes['email'] == 'unset' and address
                        and accounts[address] == 1 and email_collections and manageable_email)
        library_ok = bool(share and options['library_enabled'] and modes['library'] == 'unset' and keys)
        if modes['email'] != 'unset':
            reasons.append('Email is already automatic.' if modes['email'] == 'auto' else 'Email was set manually.')
        elif not email_ok:
            if not address:
                reasons.append('This account has no valid email address.' if profile.get('email') else 'This account has no email address.')
            elif accounts[address] > 1:
                reasons.append('This email address is shared by multiple Keep accounts.')
            elif not manageable_email:
                saved = [row for row in _rows(db, 'SELECT email,enabled FROM email_recipients')
                         if _email(row['email']) == address]
                reasons.append('Email is already off; that choice is preserved.' if len(saved) == 1 and saved[0]['enabled'] == 0
                               else 'Existing email preferences are preserved.')
            elif not options['email_enabled']:
                reasons.append('Email defaults are off for new enrollments.')
            elif share:
                reasons.append('No mapped email topics are shared with this user.')
        if modes['library'] != 'unset':
            reasons.append('Library access is already automatic.' if modes['library'] == 'auto' else 'Library access was set manually.')
        elif not library_ok:
            if profile.get('can_delete_media') or profile.get('can_delete_any') or _manual_libraries(db, uid):
                reasons.append('Existing manual Library permissions are preserved.')
            elif not options['library_enabled']:
                reasons.append('Library defaults are off for new enrollments.')
            elif share:
                reasons.append('No Library folders are mapped to this user’s shared Plex libraries.')
        users.append({'id': uid, 'name': profile.get('display_name') or profile.get('full_name') or profile.get('plex_username') or 'Keep user',
                      'email': address, 'library_keys': keys, 'email_eligible': email_ok, 'library_eligible': library_ok,
                      'email_collection_ids': email_collections,
                      'eligible_features': [name for name, allowed in (('email', email_ok), ('library', library_ok)) if allowed],
                      'reasons': reasons, 'modes': modes})
    stable_proof = {key: value for key, value in proof.items() if key != 'checked_at'} if proof else None
    stable_profiles = {uid: {key: value for key, value in profile.items()
                            if key not in ('plex_checked_at', 'last_seen_at', 'welcome_version')}
                       for uid, profile in profiles.items()}
    try:
        from plex_defaults_email import preview_fingerprint
    except ImportError:
        email_routing = None
    else:
        email_routing = preview_fingerprint(db, scope=scope, collection_ids=collections)
    state = {'scope': scope, 'fresh_proof': stable_proof, 'profiles': stable_profiles, 'settings': options, 'owner': owner,
             'libraries': roots, 'collections': collections, 'users': users, 'email_routing': email_routing,
             'modes': _rows(db, 'SELECT * FROM plex_user_default_modes ORDER BY user_id'),
             'mappings': _rows(db, 'SELECT * FROM plex_user_default_mappings ORDER BY library_key'),
             'overrides': _rows(db, 'SELECT * FROM plex_user_default_email_overrides ORDER BY email'),
             'grants': _rows(db, 'SELECT * FROM user_library_permissions ORDER BY user_id,library_key'),
             'recipients': _rows(db, 'SELECT * FROM email_recipients ORDER BY email'),
             'subscriptions': _rows(db, 'SELECT * FROM recipient_subscriptions ORDER BY email,collection_id')}
    return {'generation': _hash(state), 'users': users}


def apply_existing(db, ids, expected_generation, scope, libraries, collection_ids):
    selected = sorted({str(value) for value in ids})
    if not selected or any(not _ID.fullmatch(uid) for uid in selected):
        raise ValueError('Select existing Plex users to apply defaults')
    with _write(db):
        current = preview(db, scope, libraries, collection_ids)
        if current['generation'] != expected_generation:
            raise ValueError('Plex defaults changed. Review a fresh preview before applying.')
        by_id = {row['id']: row for row in current['users']}
        if any(uid not in by_id or not by_id[uid]['eligible_features'] for uid in selected) or not _proof(db, scope):
            raise ValueError('Selected users no longer have eligible Plex defaults')
        email_ids, library_ids = [], []
        for uid in selected:
            row = by_id[uid]
            if row['email_eligible']:
                _set_modes(db, uid, email='auto')
                email_ids.append(uid)
            if row['library_eligible']:
                _set_modes(db, uid, library='auto')
                library_ids.append(uid)
    return {'applied': len(selected), 'email_user_ids': email_ids, 'library_user_ids': library_ids}
