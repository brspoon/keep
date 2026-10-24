"""Route Plex-enrolled email without changing independent manual recipients.

An address which was enrolled automatically keeps its account provenance after
manual preference edits. Its messages always need fresh Plex section proof.
"""
from contextlib import contextmanager
import hashlib
import json
import re
import time
import uuid


_SCOPE = re.compile(r'[0-9a-f]{64}\Z')
_ID = re.compile(r'[1-9][0-9]{0,19}\Z')
_LIMIT = 10000
FILTER_ITEM_LIMIT = 500
FILTER_BUDGET_SECONDS = 60


def _core():
    import plex_user_defaults
    return plex_user_defaults


def _rows(db, sql, values=()):
    cursor = db.execute(sql, values)
    names = [column[0] for column in cursor.description]
    rows = cursor.fetchmany(_LIMIT + 1)
    if len(rows) > _LIMIT:
        raise ValueError('Email defaults inventory exceeds its limit')
    return [dict(zip(names, row)) for row in rows]


def _has(db, name):
    return bool(db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone())


def _address(value):
    if not isinstance(value, str):
        return ''
    value = value.strip().casefold()
    if (not value or len(value) > 254 or value.count('@') != 1
            or any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in value)):
        return ''
    local, domain = value.split('@')
    return value if local and '.' in domain[1:-1] else ''


def _scope(value):
    return isinstance(value, str) and bool(_SCOPE.fullmatch(value))


def _collections(values):
    try:
        result = set(values)
    except TypeError:
        raise ValueError('Choose configured email topics') from None
    if len(result) > _LIMIT or any(type(value) is not int or not 0 < value < 2 ** 63 for value in result):
        raise ValueError('Choose configured email topics')
    return result


def _hash(value):
    body = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()
    if len(body) > 16 * 1024 * 1024:
        raise ValueError('Email defaults evidence exceeds its limit')
    return hashlib.sha256(body).hexdigest()


@contextmanager
def _write(db):
    if not db.in_transaction:
        db.execute('BEGIN IMMEDIATE')
    name = 'plex_email_' + uuid.uuid4().hex
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
    db.execute('''CREATE TABLE IF NOT EXISTS plex_defaults_email_links (
        email TEXT PRIMARY KEY COLLATE NOCASE, user_id TEXT NOT NULL, scope TEXT NOT NULL,
        state TEXT NOT NULL CHECK(state IN ('auto','manual','retired')),
        topics_json TEXT NOT NULL)''')
    db.execute('''CREATE TABLE IF NOT EXISTS plex_defaults_email_mappings (
        scope TEXT NOT NULL, collection_id INTEGER NOT NULL, sections_json TEXT NOT NULL,
        source TEXT NOT NULL CHECK(source IN ('auto','manual')),
        PRIMARY KEY(scope,collection_id))''')


def _links(db):
    return _rows(db, 'SELECT * FROM plex_defaults_email_links ORDER BY email') if _has(db, 'plex_defaults_email_links') else []


def _link(db, address):
    return next((row for row in _links(db) if _address(row['email']) == address), None)


def _saved(db, address):
    recipients = [row for row in _rows(db, 'SELECT email,enabled FROM email_recipients')
                  if _address(row['email']) == address] if _has(db, 'email_recipients') else []
    subscriptions = [row for row in _rows(db, 'SELECT email,collection_id,enabled FROM recipient_subscriptions')
                     if _address(row['email']) == address] if _has(db, 'recipient_subscriptions') else []
    return recipients, subscriptions


def _topics(row):
    try:
        values = json.loads(row['topics_json'])
        if not isinstance(values, list) or len(values) != len(set(values)):
            return None
        return _collections(values)
    except (ValueError, TypeError, KeyError):
        return None


def _owned(db, row):
    recipients, subscriptions = _saved(db, _address(row['email']))
    topics = _topics(row)
    return (topics is not None and len(recipients) == 1 and recipients[0]['enabled'] == 1
            and len(subscriptions) == len(topics)
            and all(item['enabled'] == 1 for item in subscriptions)
            and {item['collection_id'] for item in subscriptions} == topics)


def is_auto_email(db, email, user_id):
    address = _address(email)
    row = _link(db, address) if address else None
    return bool(row and row['state'] == 'auto' and row['user_id'] == str(user_id) and _owned(db, row))


def can_manage_address(db, email, user_id):
    address = _address(email)
    if not address:
        return False
    link = _link(db, address)
    recipients, subscriptions = _saved(db, address)
    if link:
        if link['user_id'] != str(user_id) or link['state'] == 'manual':
            return False
        return _owned(db, link) if recipients or subscriptions else link['state'] == 'retired'
    return not recipients and not subscriptions


def _accounts(db, scope, *, automatic=False, now=None):
    if not _scope(scope):
        return []
    function = _core().auto_email_accounts if automatic else _core().shared_email_accounts
    values = function(db, scope, now=now)
    if not isinstance(values, list) or len(values) > _LIMIT:
        raise ValueError('Plex email scope is unavailable')
    prepared, addresses, identities = [], {}, {}
    for row in values:
        if not isinstance(row, dict):
            raise ValueError('Plex email scope is unavailable')
        uid, address, sections = row.get('user_id'), _address(row.get('email')), row.get('sections')
        if (not isinstance(uid, str) or not _ID.fullmatch(uid) or not address
                or not isinstance(sections, list) or not sections
                or any(not isinstance(key, str) or not _ID.fullmatch(key) for key in sections)
                or len(sections) != len(set(sections))):
            continue
        addresses[address] = addresses.get(address, 0) + 1
        identities[uid] = identities.get(uid, 0) + 1
        prepared.append({'user_id': uid, 'email': address, 'sections': set(sections)})
    return [row for row in prepared if addresses[row['email']] == identities[row['user_id']] == 1]


def _catalog(db, scope, now=None):
    return _core().catalog(db, scope, now=now) if _scope(scope) else {}


def collection_mappings(db, scope, collection_ids, *, now=None):
    selected, catalog = _collections(collection_ids), _catalog(db, scope, now)
    if not catalog or not _has(db, 'plex_defaults_email_mappings'):
        return {}
    result = {}
    for row in _rows(db, 'SELECT collection_id,sections_json FROM plex_defaults_email_mappings WHERE scope=?', (scope,)):
        try:
            keys = json.loads(row['sections_json'])
            valid = (row['collection_id'] in selected and isinstance(keys, list)
                     and len(keys) == len(set(keys))
                     and all(isinstance(key, str) and key in catalog for key in keys))
        except (ValueError, TypeError):
            valid = False
        if valid and keys:
            result[row['collection_id']] = sorted(keys, key=int)
    return result


def save_collection_mappings(db, mapping, scope, collection_ids, *, now=None):
    selected, catalog = _collections(collection_ids), _catalog(db, scope, now)
    if not _scope(scope) or not catalog or not isinstance(mapping, dict):
        raise ValueError('Fresh Plex library scope is required')
    prepared = {}
    for raw_cid, keys in mapping.items():
        cid = int(raw_cid) if isinstance(raw_cid, str) and _ID.fullmatch(raw_cid) else raw_cid
        if (type(cid) is not int or cid not in selected or cid in prepared
                or not isinstance(keys, (list, tuple, set)) or len(keys) > _LIMIT
                or any(not isinstance(key, str) or key not in catalog for key in keys)
                or len(keys) != len(set(keys))):
            raise ValueError('Choose configured topics and verified Plex libraries')
        prepared[cid] = sorted(keys, key=int)
    with _write(db):
        for cid in selected:
            db.execute('''INSERT INTO plex_defaults_email_mappings VALUES (?,?,?,'manual')
                ON CONFLICT(scope,collection_id) DO UPDATE SET sections_json=excluded.sections_json,source='manual' ''',
                (scope, cid, json.dumps(prepared.get(cid, []))))
    return collection_mappings(db, scope, selected, now=now)


def seed_collection_mappings(db, rows, *, scope, collection_ids, now=None):
    """Use only exact Maintainerr libraryId/type proof; owner overrides win."""
    selected, catalog = _collections(collection_ids), _catalog(db, scope, now)
    if not _scope(scope):
        return {}
    prepared, seen = {}, set()
    if isinstance(rows, list) and len(rows) <= _LIMIT and catalog:
        for row in rows:
            if not isinstance(row, dict):
                continue
            cid, key, kind = row.get('id'), row.get('libraryId'), row.get('type')
            if type(cid) is not int or cid not in selected:
                continue
            if cid in seen:
                prepared.pop(cid, None)
                continue
            seen.add(cid)
            expected_kind = 'movie' if kind == 'movie' else 'show' if kind in ('show', 'season', 'episode') else None
            if (isinstance(key, str) and key in catalog and expected_kind
                    and catalog[key].get('kind') == expected_kind):
                prepared[cid] = [key]
    with _write(db):
        db.execute("DELETE FROM plex_defaults_email_mappings WHERE scope=? AND source='auto'", (scope,))
        for cid, keys in prepared.items():
            db.execute('INSERT OR IGNORE INTO plex_defaults_email_mappings VALUES (?,?,?,\'auto\')',
                       (scope, cid, json.dumps(keys)))
    return collection_mappings(db, scope, selected, now=now)


def eligible_collection_ids(db, user_id, *, scope, collection_ids, now=None):
    account = next((row for row in _accounts(db, scope, now=now) if row['user_id'] == str(user_id)), None)
    if account is None:
        return set()
    return {cid for cid, sections in collection_mappings(db, scope, collection_ids, now=now).items()
            if account['sections'].intersection(sections)}


def eligible_collections(db, user_id, scope, collection_ids, libraries=None, *, now=None):
    # Arr root dictionaries do not prove an email item's Plex section.
    return sorted(eligible_collection_ids(db, user_id, scope=scope, collection_ids=collection_ids, now=now))


def manual_override(db, address, *, user_id=None):
    """Freeze defaults while retaining the original account's Plex scope clamp."""
    supplied = address
    address = _address(supplied)
    if not address:
        if supplied in ('', None) and user_id is not None:
            with _write(db):
                _core().email_override(db, '', user_id=str(user_id))
                if _has(db, 'plex_defaults_email_links'):
                    db.execute("UPDATE plex_defaults_email_links SET state='manual' WHERE user_id=?", (str(user_id),))
            return
        raise ValueError('Invalid email recipient')
    row = _link(db, address)
    uid = str(user_id) if user_id is not None else row['user_id'] if row else None
    links = _links(db)
    profiles = _rows(db, 'SELECT plex_id,email FROM user_profiles')
    if uid is None:
        matches = [str(profile['plex_id']) for profile in profiles if _address(profile['email']) == address]
        originated = [identity for identity in matches
                      if any(link['user_id'] == identity for link in links)
                      or _core().email_was_automatic(db, identity)]
        if originated:
            if len(matches) != 1 or len(originated) != 1:
                raise ValueError('Email recipient is shared by another account')
            uid = originated[0]
    if row and uid != row['user_id']:
        raise ValueError('Email recipient is linked to another Plex account')
    prior = [link for link in links if link['user_id'] == uid] if uid else []
    automatic_origin = bool(uid and (prior or _core().email_was_automatic(db, uid)))
    if automatic_origin and row is None:
        # A preferences save must not turn a formerly automatic account's new
        # address into an independent, unscoped destination. Shared addresses
        # cannot be assigned to either account, even if one is disabled.
        for profile in profiles:
            if _address(profile['email']) == address and str(profile['plex_id']) != uid:
                raise ValueError('Email recipient is shared by another account')
    with _write(db):
        _core().email_override(db, address, user_id=uid)
        if row:
            db.execute("UPDATE plex_defaults_email_links SET state='manual' WHERE email=?", (row['email'],))
        elif automatic_origin:
            # A prior scope is still checked against fresh proof at delivery.
            # Before the first route, hold delivery until reconcile supplies it.
            scope = next((link['scope'] for link in prior if _scope(link['scope'])), '')
            db.execute("INSERT INTO plex_defaults_email_links VALUES (?,?,?,'manual','[]')",
                       (address, uid, scope))


def _retire(db, row):
    if row['state'] == 'auto' and _owned(db, row):
        recipients, _ = _saved(db, _address(row['email']))
        db.execute('DELETE FROM recipient_subscriptions WHERE email=?', (recipients[0]['email'],))
        db.execute('DELETE FROM email_recipients WHERE email=?', (recipients[0]['email'],))
    db.execute("UPDATE plex_defaults_email_links SET state='retired' WHERE email=?", (row['email'],))


def reconcile(db, *, scope, collection_ids, now=None):
    selected = _collections(collection_ids)
    shared = {row['user_id']: row for row in _accounts(db, scope, now=now)}
    automatic = {row['user_id']: row for row in _accounts(db, scope, automatic=True, now=now)}
    report = {'created': 0, 'updated': 0, 'retired': 0, 'manual_preserved': 0}
    with _write(db):
        for row in _links(db):
            account = shared.get(row['user_id'])
            mode = _core().user_modes(db, row['user_id'])['email']
            if row['state'] == 'manual' or mode == 'manual' or (row['state'] == 'auto' and not _owned(db, row)):
                if row['state'] != 'manual':
                    manual_override(db, row['email'], user_id=row['user_id'])
                if account and account['email'] == _address(row['email']):
                    db.execute('UPDATE plex_defaults_email_links SET scope=? WHERE email=?', (scope, row['email']))
                report['manual_preserved'] += 1
                continue
            wanted = automatic.get(row['user_id'])
            if not wanted or wanted['email'] != _address(row['email']) or row['scope'] != scope:
                if row['state'] != 'retired':
                    _retire(db, row)
                    report['retired'] += 1
        for uid, account in automatic.items():
            address = account['email']
            topics = eligible_collection_ids(db, uid, scope=scope, collection_ids=selected, now=now)
            row = _link(db, address)
            if not topics:
                if row and row['state'] == 'auto':
                    _retire(db, row)
                    report['retired'] += 1
                continue
            if not can_manage_address(db, address, uid):
                continue
            created = row is None or row['state'] == 'retired'
            if row and row['state'] == 'auto':
                recipients, _ = _saved(db, address)
                db.execute('DELETE FROM recipient_subscriptions WHERE email=?', (recipients[0]['email'],))
            else:
                db.execute('INSERT INTO email_recipients(email,enabled) VALUES (?,1)', (address,))
            db.executemany('INSERT INTO recipient_subscriptions(email,collection_id,enabled) VALUES (?,?,1)',
                           ((address, cid) for cid in sorted(topics)))
            db.execute('''INSERT INTO plex_defaults_email_links VALUES (?,?,?,'auto',?)
                ON CONFLICT(email) DO UPDATE SET user_id=excluded.user_id,scope=excluded.scope,state='auto',topics_json=excluded.topics_json''',
                (address, uid, scope, json.dumps(sorted(topics))))
            report['created' if created else 'updated'] += 1
    return report


def _scoped_account(db, link, address, scope, now):
    if link['state'] not in ('auto', 'manual') or link['scope'] != scope:
        return None
    recipients, _ = _saved(db, address)
    if len(recipients) != 1 or recipients[0]['enabled'] != 1:
        return None
    return next((row for row in _accounts(db, scope, now=now)
                 if row['user_id'] == link['user_id'] and row['email'] == address), None)


def delivery_preferences(db, *, scope, collection_ids, now=None):
    selected = _collections(collection_ids)
    result = {}
    for row in _rows(db, 'SELECT email,enabled FROM email_recipients'):
        if row['enabled'] != 1:
            continue
        address = _address(row['email'])
        link = _link(db, address)
        _, subscriptions = _saved(db, address)
        topics = {item['collection_id'] for item in subscriptions if item['enabled'] == 1 and item['collection_id'] in selected}
        if link:
            account = _scoped_account(db, link, address, scope, now)
            if account is None:
                continue
            topics &= eligible_collection_ids(db, account['user_id'], scope=scope, collection_ids=selected, now=now)
            if not topics:
                continue
        result[row['email']] = topics
    return result


def filter_items(db, address, items, *, scope, section_for_item, now=None):
    address = _address(address)
    link = _link(db, address) if address else None
    if link is None:
        return list(items)
    account = _scoped_account(db, link, address, scope, now)
    if account is None:
        return []
    _, subscriptions = _saved(db, address)
    topics = {row['collection_id'] for row in subscriptions if row['enabled'] == 1}
    mappings = collection_mappings(db, scope, topics, now=now)
    result = []
    deadline = time.monotonic() + FILTER_BUDGET_SECONDS
    for index, item in enumerate(items):
        if index >= FILTER_ITEM_LIMIT or time.monotonic() >= deadline:
            break
        if not isinstance(item, dict) or type(item.get('collection_id')) is not int:
            continue
        sections = set(mappings.get(item['collection_id'], ())) & account['sections']
        if not sections:
            continue
        try:
            section = section_for_item(item)
        except Exception:
            section = None
        if time.monotonic() >= deadline:
            break
        if isinstance(section, str) and section in sections:
            result.append(item)
    return result


def destination_generation(db, address, *, scope, collection_ids, now=None):
    address = _address(address)
    link = _link(db, address) if address else None
    if link is None:
        return ''
    account = _scoped_account(db, link, address, scope, now)
    _, subscriptions = _saved(db, address)
    return 'plex-auto:' + _hash({'scope': scope, 'provenance': link,
        'account': {**account, 'sections': sorted(account['sections'])} if account else None,
        'topics': sorted((row['collection_id'], row['enabled']) for row in subscriptions),
        'mappings': collection_mappings(db, scope, collection_ids, now=now)})


def preview_fingerprint(db, *, scope, collection_ids, now=None):
    return _hash({'scope': scope, 'collections': sorted(_collections(collection_ids)),
        'mappings': _rows(db, 'SELECT * FROM plex_defaults_email_mappings ORDER BY scope,collection_id')
                    if _has(db, 'plex_defaults_email_mappings') else [],
        'links': _links(db),
        'recipients': _rows(db, 'SELECT email,enabled FROM email_recipients ORDER BY email')
                      if _has(db, 'email_recipients') else [],
        'subscriptions': _rows(db, 'SELECT email,collection_id,enabled FROM recipient_subscriptions ORDER BY email,collection_id')
                         if _has(db, 'recipient_subscriptions') else []})
