"""Private notification configuration and fresh per-profile delivery metadata."""
from contextlib import closing
from dataclasses import dataclass, field
import hashlib
import json
import math
import os
from pathlib import Path
import sqlite3
import time
import uuid

from connection_settings import ConnectionSettings, PUSHOVER_FIELDS, validate
import notifications
import pushover


@dataclass(frozen=True)
class Actor:
    user_id: str
    active: bool
    owner: bool = False
    session_version: int = 0


@dataclass(frozen=True)
class Credentials:
    app_token: str = field(repr=False)
    user_key: str = field(repr=False)
    device: str = field(repr=False)


@dataclass(frozen=True)
class TestReservation:
    state: str
    id: str | None = None
    retry_after_seconds: int = 0


class Settings:
    def __init__(self, path, *, initialize=True, connections=None, owner_id=lambda: '', profile_access=lambda profile: False):
        self.path = Path(path)
        self.connections = connections
        self.owner_id = owner_id
        self.profile_access = profile_access
        if initialize:
            self.initialize()

    def _connect(self, *, read_only=False):
        db = sqlite3.connect(self.path.absolute().as_uri() + '?mode=ro', uri=True, timeout=0.25) if read_only else sqlite3.connect(self.path, timeout=0.25)
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA foreign_keys=ON')
        return db

    def initialize(self):
        notifications.Store(self.path)
        with closing(self._connect()) as db, db:
            db.execute('''CREATE TABLE IF NOT EXISTS notification_provider_generations (
                provider TEXT PRIMARY KEY, fingerprint TEXT NOT NULL,
                generation TEXT NOT NULL, synchronized_at REAL NOT NULL
            )''')
            db.execute('''CREATE TABLE IF NOT EXISTS pushover_preferences (
                user_id TEXT PRIMARY KEY REFERENCES user_profiles(plex_id) ON DELETE CASCADE,
                enabled INTEGER NOT NULL DEFAULT 0 CHECK(enabled IN (0,1)),
                user_key TEXT NOT NULL DEFAULT '',device TEXT NOT NULL DEFAULT '',
                collections_json TEXT NOT NULL DEFAULT '[]',events_json TEXT NOT NULL DEFAULT '[]',
                generation TEXT NOT NULL,provider_generation TEXT NOT NULL,
                after_queue_id INTEGER NOT NULL DEFAULT 0,updated_at REAL NOT NULL
            )''')
            db.execute('''CREATE TABLE IF NOT EXISTS notification_email_events (
                email TEXT PRIMARY KEY COLLATE NOCASE,events_json TEXT NOT NULL,
                owner_alerts_activated_at REAL
            )''')
            db.execute('''CREATE TABLE IF NOT EXISTS notification_test_attempts (
                id TEXT PRIMARY KEY,user_id TEXT NOT NULL,kind TEXT NOT NULL,
                credential_scope TEXT NOT NULL,destination_generation TEXT NOT NULL,
                reserved_at REAL NOT NULL,
                finished_at REAL,state TEXT NOT NULL,error_code TEXT,request_id TEXT
            )''')
            test_columns = {row[1] for row in db.execute('PRAGMA table_info(notification_test_attempts)')}
            if 'destination_generation' not in test_columns:
                db.execute("ALTER TABLE notification_test_attempts ADD COLUMN destination_generation TEXT NOT NULL DEFAULT ''")
            db.execute('''CREATE INDEX IF NOT EXISTS notification_test_user
                ON notification_test_attempts(user_id,kind,reserved_at)''')

    @staticmethod
    def _has_table(db, name):
        return bool(db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone())

    def _effective(self, name, fallback=''):
        if name not in PUSHOVER_FIELDS:
            raise ValueError('Unknown notification setting')
        if name in os.environ:
            return validate(name, os.environ[name])
        try:
            self.path.stat()
        except FileNotFoundError:
            return fallback
        with closing(self._connect(read_only=True)) as db:
            row = db.execute('SELECT value FROM connection_settings WHERE name=?', (name,)).fetchone() if self._has_table(db, 'connection_settings') else None
        return validate(name, row[0]) if row else fallback

    def _effective_provider(self):
        enabled = self._effective('PUSHOVER_ENABLED', 'false') == 'true'
        token = self._effective('PUSHOVER_APP_TOKEN')
        fingerprint = hashlib.sha256(json.dumps((enabled, token), separators=(',', ':')).encode()).hexdigest()
        return enabled, token, fingerprint

    @staticmethod
    def _credential_scope(token):
        return hashlib.sha256(json.dumps(('pushover', token), separators=(',', ':')).encode()).hexdigest()

    def installation_view(self):
        configuration_error = ''
        try:
            enabled, token, _ = self._effective_provider()
        except ValueError:
            enabled, token = False, ''
            configuration_error = 'Pushover configuration needs attention. Check the provider settings.'
        return {'enabled': enabled, 'configured': bool(token), 'ready': enabled and bool(token), 'app_token': '',
                'configuration_error': configuration_error,
                'fields': {name: {'managed': name in os.environ, 'secret': name == 'PUSHOVER_APP_TOKEN',
                                 'value': '' if name == 'PUSHOVER_APP_TOKEN' else 'true' if enabled else 'false',
                                 'configured': bool(token) if name == 'PUSHOVER_APP_TOKEN' else True}
                           for name in PUSHOVER_FIELDS}}

    def _profile(self, db, user_id):
        if not self._has_table(db, 'user_profiles'):
            return None
        cursor = db.cursor()
        cursor.row_factory = sqlite3.Row
        row = cursor.execute('SELECT * FROM user_profiles WHERE plex_id=?', (user_id,)).fetchone()
        profile = dict(row) if row else None
        if not profile or profile.get('status') != 'active' or not self.profile_access(profile):
            return None
        return profile

    def _actor(self, db, actor, *, owner=False):
        if (not isinstance(actor, Actor) or not isinstance(actor.user_id, str) or not actor.user_id
                or type(actor.active) is not bool or type(actor.owner) is not bool or not actor.active
                or type(actor.session_version) is not int or actor.session_version < 0):
            raise PermissionError('Your account is unavailable. Sign in again.')
        profile = self._profile(db, actor.user_id)
        if (not profile or type(profile.get('session_version', 0)) is not int
                or profile.get('session_version', 0) != actor.session_version):
            raise PermissionError('Your account is unavailable. Sign in again.')
        actual_owner = (actor.user_id == str(self.owner_id()) and profile.get('auth_type') == 'plex'
                        and profile.get('plex_access') == 'active')
        if owner and (not actor.owner or not actual_owner):
            raise PermissionError('Only the Keep owner can change notification providers.')
        return profile, actual_owner

    def validate_actor(self, actor, db, *, owner=False):
        """Revalidate account/session authority inside the caller's write transaction."""
        return self._actor(db, actor, owner=owner)

    def save_installation(self, actor, *, enabled=None, token_mode='keep', token='', now=None):
        if enabled is not None and type(enabled) is not bool or token_mode not in ('keep', 'replace', 'clear'):
            raise ValueError('Invalid notification provider settings')
        if not isinstance(token, str):
            raise ValueError('Enter a valid Pushover application token')
        with closing(self._connect(read_only=True)) as db:
            self._actor(db, actor, owner=True)
        values, clear = {}, []
        if enabled is not None:
            values['PUSHOVER_ENABLED'] = 'true' if enabled else 'false'
        if token_mode == 'replace' and token:
            values['PUSHOVER_APP_TOKEN'] = validate('PUSHOVER_APP_TOKEN', token)
        elif token_mode == 'clear':
            clear.append('PUSHOVER_APP_TOKEN')
        connections = self.connections or ConnectionSettings(self.path)
        def guard(db):
            self.validate_actor(actor, db, owner=True)
            for name, fallback in (('PUSHOVER_ENABLED', 'false'), ('PUSHOVER_APP_TOKEN', '')):
                if name in os.environ:
                    value = os.environ[name]
                elif name in values:
                    value = values[name]
                elif name in clear:
                    value = ''
                else:
                    row = db.execute('SELECT value FROM connection_settings WHERE name=?', (name,)).fetchone()
                    value = row[0] if row else fallback
                validate(name, value)
        connections.save(values, clear=clear, guard=guard)
        self.synchronize(now=now)
        return self.installation_view()

    @staticmethod
    def _watermarks(db):
        rows = dict(db.execute("SELECT name,seq FROM sqlite_sequence WHERE name IN ('notification_queue','notification_operational_events')"))
        return int(rows.get('notification_queue', 0)), int(rows.get('notification_operational_events', 0))

    @staticmethod
    def _epoch(db, user_id, generation, queue_id, event_id, now):
        db.execute('''INSERT OR IGNORE INTO notification_destination_epochs
            (provider,destination_id,generation,after_queue_id,after_event_id,activated_at)
            VALUES ('pushover',?,?,?,?,?)''', (user_id, generation, queue_id, event_id, now))

    def synchronize(self, *, now=None):
        """Explicit worker/save mutation; never called by GET or destination reads."""
        now = time.time() if now is None else now
        with closing(self._connect()) as db, db:
            db.execute('BEGIN IMMEDIATE')
            _, token, fingerprint = self._effective_provider()
            previous = db.execute("SELECT fingerprint,generation FROM notification_provider_generations WHERE provider='pushover'").fetchone()
            generation = self._credential_scope(token)
            if previous and previous['fingerprint'] == fingerprint and previous['generation'] == generation:
                return previous['generation']
            # Activation changes replace destination generations, while the same
            # application token retains its quota scope across off/on toggles.
            if previous and previous['fingerprint'] == fingerprint and previous['generation'] != generation:
                legacy_cooldown = db.execute("SELECT until_at FROM notification_cooldowns WHERE provider='pushover' AND generation=?", (previous['generation'],)).fetchone()
                if legacy_cooldown:
                    db.execute("INSERT INTO notification_cooldowns VALUES ('pushover',?,?) ON CONFLICT(provider,generation) DO UPDATE SET until_at=MAX(until_at,excluded.until_at)", (generation, legacy_cooldown[0]))
            db.execute("INSERT INTO notification_provider_generations VALUES ('pushover',?,?,?) ON CONFLICT(provider) DO UPDATE SET fingerprint=excluded.fingerprint,generation=excluded.generation,synchronized_at=excluded.synchronized_at", (fingerprint, generation, now))
            queue_id, event_id = self._watermarks(db)
            for row in db.execute('SELECT user_id FROM pushover_preferences').fetchall():
                destination_generation = uuid.uuid4().hex
                db.execute('UPDATE pushover_preferences SET generation=?,provider_generation=?,after_queue_id=?,updated_at=? WHERE user_id=?',
                           (destination_generation, generation, queue_id, now, row['user_id']))
                self._epoch(db, row['user_id'], destination_generation, queue_id, event_id, now)
        return generation

    @staticmethod
    def _preferences(row, available_collections):
        if not row:
            return {'enabled': False, 'configured': False, 'user_key': '', 'device': '',
                    'collections': set(available_collections), 'events': set(notifications.MEDIA_EVENTS)}
        try:
            raw_collections = json.loads(row['collections_json'])
            collections = {cid for cid in raw_collections if type(cid) is int and cid > 0} & set(available_collections)
            events = set(json.loads(row['events_json'])) & notifications.EVENTS
        except (ValueError, TypeError, RecursionError):
            collections, events = set(), set()
        return {'enabled': bool(row['enabled']), 'configured': bool(row['user_key']),
                'user_key': '', 'device': row['device'], 'collections': collections, 'events': events}

    def preferences_view(self, actor, *, available_collections):
        with closing(self._connect(read_only=True)) as db:
            _, owner = self._actor(db, actor)
            row = db.execute('SELECT * FROM pushover_preferences WHERE user_id=?', (actor.user_id,)).fetchone() if self._has_table(db, 'pushover_preferences') else None
        view = self._preferences(row, available_collections)
        view['events'] &= notifications.EVENTS if owner else notifications.MEDIA_EVENTS
        installation = self.installation_view()
        return {**view, 'owner_events_available': owner, 'provider_available': installation['ready'],
                'configuration_error': installation['configuration_error'] if owner else ''}

    def save_preferences(self, actor, *, enabled, collections, events, available_collections,
                         key_mode='keep', user_key='', device=None, now=None):
        if type(enabled) is not bool or key_mode not in ('keep', 'replace', 'clear'):
            raise ValueError('Invalid Pushover preferences')
        selected, event_set = frozenset(collections), frozenset(events)
        if (len(selected) > 200 or any(type(cid) is not int or not 1 <= cid <= 999999999 for cid in selected)
                or not selected <= set(available_collections) or not event_set <= notifications.EVENTS):
            raise ValueError('Invalid notification collection or event preference')
        if not isinstance(user_key, str) or key_mode == 'replace' and user_key and not pushover.KEY.fullmatch(user_key):
            raise ValueError('Enter a valid Pushover user key')
        if device is not None and (not isinstance(device, str) or not pushover.DEVICE.fullmatch(device)):
            raise ValueError('Enter a valid Pushover device name')
        now = time.time() if now is None else now
        with closing(self._connect(read_only=True)) as db:
            self._actor(db, actor, owner=True)
            previous = db.execute('SELECT * FROM pushover_preferences WHERE user_id=?', (actor.user_id,)).fetchone()
        key = previous['user_key'] if previous else ''
        if key_mode == 'clear':
            key = ''
        elif key_mode == 'replace' and user_key:
            key = user_key
        chosen_device = device if device is not None else previous['device'] if previous else ''
        if enabled and (not key or not event_set or event_set & notifications.MEDIA_EVENTS and not selected):
            raise ValueError('Choose a user key, events and relevant collections or turn off Pushover.')
        provider_generation = self.synchronize(now=now)
        with closing(self._connect()) as db, db:
            db.execute('BEGIN IMMEDIATE')
            self._actor(db, actor, owner=True)
            # Credential keep/clear and unchanged device controls use the latest
            # committed row, so concurrent forms cannot restore an old user key.
            provider = db.execute("SELECT fingerprint,generation FROM notification_provider_generations WHERE provider='pushover'").fetchone()
            _, _, fingerprint = self._effective_provider()
            if not provider or provider['fingerprint'] != fingerprint:
                raise ValueError('Notification provider settings changed. Try again.')
            provider_generation = provider['generation']
            previous = db.execute('SELECT * FROM pushover_preferences WHERE user_id=?', (actor.user_id,)).fetchone()
            key = previous['user_key'] if previous else ''
            if key_mode == 'clear':
                key = ''
            elif key_mode == 'replace' and user_key:
                key = user_key
            chosen_device = device if device is not None else previous['device'] if previous else ''
            if enabled and (not key or not event_set or event_set & notifications.MEDIA_EVENTS and not selected):
                raise ValueError('Choose a user key, events and relevant collections or turn off Pushover.')
            changed = (not previous or key != previous['user_key'] or chosen_device != previous['device']
                       or enabled and not previous['enabled'] or previous['provider_generation'] != provider_generation)
            generation = uuid.uuid4().hex if changed else previous['generation']
            queue_id, event_id = self._watermarks(db)
            after_queue_id = queue_id if changed else previous['after_queue_id']
            if changed:
                self._epoch(db, actor.user_id, generation, queue_id, event_id, now)
            db.execute('''INSERT INTO pushover_preferences VALUES (?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(user_id) DO UPDATE SET enabled=excluded.enabled,user_key=excluded.user_key,
                  device=excluded.device,collections_json=excluded.collections_json,events_json=excluded.events_json,
                  generation=excluded.generation,provider_generation=excluded.provider_generation,
                  after_queue_id=excluded.after_queue_id,updated_at=excluded.updated_at''',
                (actor.user_id, int(enabled), key, chosen_device, json.dumps(sorted(selected)), json.dumps(sorted(event_set)),
                 generation, provider_generation, after_queue_id, now))
        return self.preferences_view(actor, available_collections=available_collections)

    def _destination(self, row, profile, available_collections):
        view = self._preferences(row, available_collections)
        if not view['enabled'] or not view['configured']:
            return None
        owner = (row['user_id'] == str(self.owner_id()) and profile.get('auth_type') == 'plex'
                 and profile.get('plex_access') == 'active')
        if not owner:
            return None
        events = frozenset(view['events']) & notifications.EVENTS
        return notifications.Destination('pushover', row['user_id'], row['generation'],
            frozenset(view['collections']), events, row['after_queue_id'], row['provider_generation'], owner)

    def destinations(self, *, available_collections):
        _, _, fingerprint = self._effective_provider()
        with closing(self._connect(read_only=True)) as db:
            if not self._has_table(db, 'notification_provider_generations') or not self._has_table(db, 'pushover_preferences'):
                return []
            provider = db.execute("SELECT fingerprint,generation FROM notification_provider_generations WHERE provider='pushover'").fetchone()
            if not provider or provider['fingerprint'] != fingerprint:
                return []
            result = []
            for row in db.execute('SELECT * FROM pushover_preferences WHERE enabled=1'):
                profile = self._profile(db, row['user_id'])
                if profile and row['provider_generation'] == provider['generation']:
                    target = self._destination(row, profile, available_collections)
                    if target:
                        result.append(target)
            return result

    def sending_credentials(self, destination, *, available_collections):
        enabled, token, fingerprint = self._effective_provider()
        if not enabled or not token or not isinstance(destination, notifications.Destination) or destination.provider != 'pushover':
            return None
        with closing(self._connect(read_only=True)) as db:
            provider = db.execute("SELECT fingerprint,generation FROM notification_provider_generations WHERE provider='pushover'").fetchone()
            row = db.execute('SELECT * FROM pushover_preferences WHERE user_id=?', (destination.id,)).fetchone()
            profile = self._profile(db, destination.id)
            if (not provider or provider['fingerprint'] != fingerprint or not row or not profile
                    or row['provider_generation'] != provider['generation']
                    or self._destination(row, profile, available_collections) != destination):
                return None
        return Credentials(token, row['user_key'], row['device'])

    def validation_credentials(self, actor, *, reservation_id=None):
        """Private saved own-key access for explicit tests, even while disabled."""
        token = self._effective('PUSHOVER_APP_TOKEN')
        with closing(self._connect(read_only=True)) as db:
            self._actor(db, actor, owner=True)
            row = db.execute('SELECT user_key,device,generation FROM pushover_preferences WHERE user_id=?', (actor.user_id,)).fetchone()
            if reservation_id is not None:
                reservation = db.execute("SELECT credential_scope,destination_generation FROM notification_test_attempts WHERE id=? AND user_id=? AND state='reserved'", (reservation_id, actor.user_id)).fetchone()
                if (not reservation or reservation['credential_scope'] != self._credential_scope(token)
                        or not row or reservation['destination_generation'] != row['generation']):
                    return None
        if not token or not row or not pushover.KEY.fullmatch(row['user_key']) or not pushover.DEVICE.fullmatch(row['device']):
            return None
        return Credentials(token, row['user_key'], row['device'])

    def _email_test_address(self, db, profile):
        email = profile.get('email') or ''
        if not email or not self._has_table(db, 'email_recipients'):
            return None
        canonical = self._email_id(email)
        return next((row[0] for row in db.execute('SELECT email FROM email_recipients')
                     if self._email_id(row[0]) == canonical), None)

    def email_test_recipient(self, actor, *, reservation_id=None):
        """Saved own active account address; never accepts a supplied recipient."""
        with closing(self._connect(read_only=True)) as db:
            profile, _ = self._actor(db, actor)
            email = self._email_test_address(db, profile)
            if reservation_id is not None:
                reservation = db.execute("SELECT destination_generation FROM notification_test_attempts WHERE id=? AND user_id=? AND kind='email' AND state='reserved'", (reservation_id, actor.user_id)).fetchone()
                if not reservation or not email or reservation[0] != self.email_generation(self._email_id(email)):
                    return None
        return email

    def reserve_test(self, actor, kind, *, now=None):
        """Persist intent before an explicit test; never sends or auto-replays."""
        if kind not in ('validation', 'notification', 'email'):
            raise ValueError('Invalid notification test')
        now = time.time() if now is None else now
        token = self._effective('PUSHOVER_APP_TOKEN') if kind != 'email' else ''
        credential_scope = self._credential_scope(token) if kind != 'email' else 'email'
        result = None
        with closing(self._connect()) as db, db:
            db.execute('BEGIN IMMEDIATE')
            profile, _ = self._actor(db, actor, owner=kind != 'email')
            if kind == 'email':
                email = self._email_test_address(db, profile)
                if not email:
                    return TestReservation('unconfigured')
                destination_generation = self.email_generation(self._email_id(email))
            else:
                row = db.execute('SELECT user_key,device,generation FROM pushover_preferences WHERE user_id=?', (actor.user_id,)).fetchone()
                if not token or not row or not pushover.KEY.fullmatch(row['user_key']) or not pushover.DEVICE.fullmatch(row['device']):
                    return TestReservation('unconfigured')
                destination_generation = row['generation']
            previous = db.execute('SELECT * FROM notification_test_attempts WHERE user_id=? AND kind=? ORDER BY reserved_at DESC LIMIT 1', (actor.user_id, kind)).fetchone()
            if previous and previous['state'] == 'reserved' and now - previous['reserved_at'] > pushover.REQUEST_BUDGET + 30:
                state = 'review' if kind in ('notification', 'email') else 'cancelled'
                db.execute('UPDATE notification_test_attempts SET state=?,error_code=?,finished_at=? WHERE id=?', (state, 'worker_interrupted', now, previous['id']))
                result = TestReservation('review', previous['id']) if kind in ('notification', 'email') else None
            elif previous and previous['state'] == 'review' and kind in ('notification', 'email'):
                result = TestReservation('review', previous['id'])
            if result is None and previous and now < previous['reserved_at'] + 60:
                result = TestReservation('cooldown', retry_after_seconds=math.ceil(previous['reserved_at'] + 60 - now))
            if result is None and kind == 'notification':
                cooldown = db.execute("SELECT until_at FROM notification_cooldowns WHERE provider='pushover' AND generation=?", (credential_scope,)).fetchone()
                if cooldown and cooldown[0] > now:
                    result = TestReservation('quota', retry_after_seconds=math.ceil(cooldown[0] - now))
            if result is None:
                active = db.execute("SELECT reserved_at FROM notification_test_attempts WHERE state='reserved' AND reserved_at>=? ORDER BY reserved_at DESC LIMIT 1", (now - pushover.REQUEST_BUDGET - 30,)).fetchone()
                if active:
                    # One explicit test plus the serial worker stay within the
                    # provider's two concurrent connection limit across processes.
                    result = TestReservation('busy', retry_after_seconds=max(1, math.ceil(active[0] + pushover.REQUEST_BUDGET + 30 - now)))
            if result is None:
                test_id = uuid.uuid4().hex
                db.execute("INSERT INTO notification_test_attempts(id,user_id,kind,credential_scope,destination_generation,reserved_at,state) VALUES (?,?,?,?,?,?,'reserved')", (test_id, actor.user_id, kind, credential_scope, destination_generation, now))
                result = TestReservation('reserved', test_id)
        return result

    def test_availability(self, actor, kind, *, now=None):
        """Read the reservation gates without reserving or recovering a test."""
        if kind not in ('validation', 'notification', 'email'):
            raise ValueError('Invalid notification test')
        now = time.time() if now is None else now
        token = self._effective('PUSHOVER_APP_TOKEN') if kind != 'email' else ''
        credential_scope = self._credential_scope(token) if kind != 'email' else 'email'

        def view(state, retry=0):
            return {'can_test': state == 'ready', 'state': state, 'retry_after_seconds': retry}

        with closing(self._connect(read_only=True)) as db:
            profile, _ = self._actor(db, actor, owner=kind != 'email')
            if kind == 'email':
                if not self._email_test_address(db, profile):
                    return view('unconfigured')
            else:
                row = db.execute('SELECT user_key,device FROM pushover_preferences WHERE user_id=?', (actor.user_id,)).fetchone() if self._has_table(db, 'pushover_preferences') else None
                if not token or not row or not pushover.KEY.fullmatch(row['user_key']) or not pushover.DEVICE.fullmatch(row['device']):
                    return view('unconfigured')
            if not self._has_table(db, 'notification_test_attempts'):
                return view('ready')
            previous = db.execute('SELECT reserved_at,state FROM notification_test_attempts WHERE user_id=? AND kind=? ORDER BY reserved_at DESC LIMIT 1', (actor.user_id, kind)).fetchone()
            if previous:
                stale = previous['state'] == 'reserved' and now - previous['reserved_at'] > pushover.REQUEST_BUDGET + 30
                if kind in ('notification', 'email') and (previous['state'] == 'review' or stale):
                    return view('review')
                if now < previous['reserved_at'] + 60:
                    return view('cooldown', math.ceil(previous['reserved_at'] + 60 - now))
            if kind == 'notification' and self._has_table(db, 'notification_cooldowns'):
                cooldown = db.execute("SELECT until_at FROM notification_cooldowns WHERE provider='pushover' AND generation=?", (credential_scope,)).fetchone()
                if cooldown and cooldown[0] > now:
                    return view('quota', math.ceil(cooldown[0] - now))
            active = db.execute("SELECT reserved_at FROM notification_test_attempts WHERE state='reserved' AND reserved_at>=? ORDER BY reserved_at DESC LIMIT 1", (now - pushover.REQUEST_BUDGET - 30,)).fetchone()
            if active:
                return view('busy', max(1, math.ceil(active[0] + pushover.REQUEST_BUDGET + 30 - now)))
        return view('ready')

    def complete_test(self, test_id, result, *, now=None):
        """Internal completion of the reservation just created by the route."""
        now = time.time() if now is None else now
        state = getattr(result, 'state', None)
        state = state if state in ('accepted', 'retry', 'rejected', 'review', 'cancelled') else 'review'
        code = getattr(result, 'code', None)
        code = code if code in notifications.SAFE_CODES else None
        if state == 'review' and code is None:
            code = 'response_uncertain'
        request_id = getattr(result, 'request_id', None)
        request_id = request_id if isinstance(request_id, str) and notifications.REQUEST_ID.fullmatch(request_id) else None
        retry_at = getattr(result, 'retry_at', None)
        retry_at = min(now + 32 * 86400, max(now + 60, retry_at)) if type(retry_at) in (int, float) and math.isfinite(retry_at) else now + 3600
        with closing(self._connect()) as db, db:
            db.execute('BEGIN IMMEDIATE')
            previous = db.execute("SELECT credential_scope FROM notification_test_attempts WHERE id=? AND (state='reserved' OR state='review' AND error_code='worker_interrupted')", (test_id,)).fetchone()
            if not previous:
                return False
            db.execute('UPDATE notification_test_attempts SET state=?,error_code=?,request_id=?,finished_at=? WHERE id=?', (state, code, request_id, now, test_id))
            if code == 'quota' and state == 'retry':
                db.execute("INSERT INTO notification_cooldowns VALUES ('pushover',?,?) ON CONFLICT(provider,generation) DO UPDATE SET until_at=MAX(until_at,excluded.until_at)", (previous['credential_scope'], retry_at))
        return True

    def discard_test(self, actor, test_id, *, now=None):
        now = time.time() if now is None else now
        with closing(self._connect()) as db, db:
            db.execute('BEGIN IMMEDIATE')
            self._actor(db, actor)
            return bool(db.execute("""UPDATE notification_test_attempts
                SET state='cancelled',error_code=NULL,finished_at=COALESCE(finished_at,?)
                WHERE id=? AND user_id=? AND (state='review' OR
                    state='reserved' AND kind IN ('notification','email') AND reserved_at<?)""",
                (now, test_id, actor.user_id, now - pushover.REQUEST_BUDGET - 30)).rowcount)

    def test_views(self, actor):
        try:
            token_scope = self._credential_scope(self._effective('PUSHOVER_APP_TOKEN'))
        except ValueError:
            token_scope = None
        with closing(self._connect(read_only=True)) as db:
            profile, _ = self._actor(db, actor)
            if not self._has_table(db, 'notification_test_attempts'):
                return []
            preference = db.execute('SELECT generation FROM pushover_preferences WHERE user_id=?', (actor.user_id,)).fetchone()
            email = self._email_test_address(db, profile)
            email_generation = self.email_generation(self._email_id(email)) if email else None
            rows = db.execute('''SELECT id,kind,reserved_at,finished_at,state,error_code,request_id,credential_scope,destination_generation
                FROM notification_test_attempts WHERE user_id=? ORDER BY reserved_at DESC LIMIT 10''', (actor.user_id,)).fetchall()
        return [{**{key: row[key] for key in ('id','kind','reserved_at','finished_at','state','error_code','request_id')},
                 'current': (row['destination_generation'] == email_generation if row['kind'] == 'email' else
                             bool(preference and row['credential_scope'] == token_scope and row['destination_generation'] == preference[0])),
                 'state': row['state'] if row['state'] in ('reserved', 'accepted', 'retry', 'rejected', 'review', 'cancelled') else 'review',
                 'error_code': row['error_code'] if row['error_code'] in notifications.SAFE_CODES else None,
                 'request_id': row['request_id'] if isinstance(row['request_id'], str) and notifications.REQUEST_ID.fullmatch(row['request_id']) else None}
                for row in rows]

    @staticmethod
    def _email_id(value):
        if not isinstance(value, str) or not 1 <= len(value) <= 256 or any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError('Invalid notification recipient')
        return value.strip().casefold()

    @staticmethod
    def email_generation(email):
        return hashlib.sha256(('email-destination:' + email).encode()).hexdigest()

    def _active_owner_email(self, db):
        profile = self._profile(db, str(self.owner_id()))
        if not profile or profile.get('auth_type') != 'plex' or profile.get('plex_access') != 'active':
            return None
        email = profile.get('email') or ''
        return self._email_id(email) if email else None

    def email_event_preferences(self, email_address, *, db=None):
        """Readonly worker metadata; original recipient addresses stay untouched."""
        email = self._email_id(email_address)
        if db is None:
            with closing(self._connect(read_only=True)) as connection:
                return self.email_event_preferences(email_address, db=connection)
        row = db.execute('SELECT events_json FROM notification_email_events WHERE email=?', (email,)).fetchone() if self._has_table(db, 'notification_email_events') else None
        owner = email == self._active_owner_email(db)
        try:
            events = frozenset(json.loads(row[0])) & notifications.EVENTS if row else notifications.MEDIA_EVENTS
        except (TypeError, ValueError, RecursionError):
            events = frozenset()
        return {'events': events if owner else notifications.MEDIA_EVENTS,
                'owner_verified': owner, 'generation': self.email_generation(email)}

    def save_email_events(self, actor, email_address, events, *, db=None, now=None):
        email = self._email_id(email_address)
        selected = frozenset(events)
        if not selected <= notifications.EVENTS:
            raise ValueError('Invalid notification event preference')
        now = time.time() if now is None else now
        if db is None:
            with closing(self._connect()) as connection, connection:
                connection.execute('BEGIN IMMEDIATE')
                return self.save_email_events(actor, email_address, selected, db=connection, now=now)
        if not db.in_transaction:
            raise ValueError('Notification preferences require a write transaction')
        profile, owner = self._actor(db, actor)
        personal_email = self._email_id(profile.get('email') or '') if profile.get('email') else None
        if not (owner and actor.owner) and email != personal_email:
            raise PermissionError('You can change only your own notification preferences.')
        recipient = next((row for row in db.execute('SELECT email FROM email_recipients') if self._email_id(row[0]) == email), None)
        if not recipient:
            raise ValueError('Notification recipient is unavailable')
        if not owner:
            selected = notifications.MEDIA_EVENTS
        if selected & notifications.OPERATIONAL_EVENTS and (not owner or email != self._active_owner_email(db)):
            raise PermissionError('Operational email alerts require the active owner account address.')
        if email != self._active_owner_email(db):
            selected = notifications.MEDIA_EVENTS
        previous = db.execute('SELECT owner_alerts_activated_at FROM notification_email_events WHERE email=?', (email,)).fetchone()
        activated_at = previous[0] if previous else None
        if selected & notifications.OPERATIONAL_EVENTS and activated_at is None:
            activated_at = now
            _, event_id = self._watermarks(db)
            # One stable email generation preserves existing media backlog.
            # Only the first owner-alert opt-in establishes the event boundary.
            db.execute('''INSERT INTO notification_destination_epochs VALUES ('email',?,?,0,?,?)
                ON CONFLICT(provider,destination_id,generation) DO UPDATE SET
                after_event_id=excluded.after_event_id,activated_at=excluded.activated_at''',
                (email, self.email_generation(email), event_id, now))
        db.execute('''INSERT INTO notification_email_events VALUES (?,?,?) ON CONFLICT(email)
            DO UPDATE SET events_json=excluded.events_json,owner_alerts_activated_at=excluded.owner_alerts_activated_at''',
            (email, json.dumps(sorted(selected)), activated_at))
        return self.email_event_preferences(email_address, db=db)
