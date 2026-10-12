"""Durable provider-independent digest delivery over Keep's existing queue.

The caller holds the existing digest worker lock. Web handlers only read status
or queue work; they never invoke delivery or recover an active worker's sends.
"""
from contextlib import closing
from dataclasses import dataclass
import json
import math
from pathlib import Path
import re
import sqlite3
import time
import uuid


ADDED = 'MEDIA_ADDED_TO_COLLECTION'
REMINDER = 'MEDIA_ABOUT_TO_BE_HANDLED'
MEDIA_EVENTS = frozenset((ADDED, REMINDER))
OPERATIONAL_EVENTS = frozenset(('CONNECTION_FAILED', 'CONNECTION_RESTORED',
                                'JOB_FAILED', 'JOB_RESTORED', 'UPDATE_AVAILABLE'))
EVENTS = MEDIA_EVENTS | OPERATIONAL_EVENTS
CONNECTIONS = frozenset(('plex', 'maintainerr', 'radarr', 'sonarr', 'seerr', 'tautulli', 'email', 'pushover'))
STABLE_VERSION = re.compile(r'(?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8})\Z')
PROVIDERS = frozenset(('email', 'pushover'))
STATES = frozenset(('pending', 'sending', 'accepted', 'retry', 'review', 'rejected', 'cancelled'))
SAFE_CODES = frozenset(('configuration', 'connect_failed', 'rejected', 'quota', 'response_uncertain',
                        'email_uncertain', 'worker_interrupted', 'preparation_failed', 'preferences_changed'))
REQUEST_ID = re.compile(r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\Z')


@dataclass(frozen=True)
class Destination:
    provider: str
    id: str
    generation: str
    collections: frozenset
    events: frozenset = MEDIA_EVENTS
    after_queue_id: int = 0
    provider_generation: str = ''
    owner_verified: bool = False


@dataclass(frozen=True)
class Outcome:
    state: str
    code: str | None = None
    request_id: str | None = None
    retry_at: float | None = None


@dataclass(frozen=True)
class Callbacks:
    enabled_providers: object
    destinations: object
    resolve: object
    render: object
    send: object
    render_event: object = None


def _targets(values, enabled):
    result = {}
    for target in values:
        if (not isinstance(target, Destination) or target.provider not in PROVIDERS
                or not isinstance(target.id, str) or not 1 <= len(target.id) <= 256
                or not isinstance(target.generation, str) or not 1 <= len(target.generation) <= 128
                or not isinstance(target.provider_generation, str) or len(target.provider_generation) > 128
                or type(target.after_queue_id) is not int or target.after_queue_id < 0
                or not isinstance(target.collections, frozenset)
                or any(type(cid) is not int or cid <= 0 for cid in target.collections)
                or not isinstance(target.events, frozenset) or not target.events <= EVENTS
                or type(target.owner_verified) is not bool):
            raise ValueError('Invalid notification destination')
        key = (target.provider, target.id)
        if key in result:
            raise ValueError('Duplicate notification destination')
        if target.provider in enabled:
            result[key] = target
    return result


def _eligible(events, target):
    return [event for event in events if event['id'] > target.after_queue_id
            and event['collection_id'] in target.collections and event['kind'] in target.events]


def _recipient_items(items, events):
    keys = {(event['collection_id'], event['media_id']) for event in events}
    urgent = {(event['collection_id'], event['media_id']) for event in events if event['kind'] == REMINDER}
    result = []
    for item in items:
        # The existing resolver needs one additive media_id field to make this
        # exact after cancellations and per-event preferences. Titles are not IDs.
        key = (item['collection_id'], str(item['media_id']))
        if key in keys:
            result.append({**item, 'urgent': key in urgent})
    return result


class Store:
    def __init__(self, path, *, initialize=True):
        self.path = Path(path)
        if initialize:
            self.initialize()

    def _connect(self, *, read_only=False):
        connection = sqlite3.connect(self.path.absolute().as_uri() + '?mode=ro', uri=True, timeout=0.25) if read_only else sqlite3.connect(self.path, timeout=0.25)
        connection.row_factory = sqlite3.Row
        return connection

    def initialize(self):
        with closing(self._connect()) as db, db:
            db.execute('''CREATE TABLE IF NOT EXISTS notification_runs (
                batch_id TEXT PRIMARY KEY, legacy INTEGER NOT NULL DEFAULT 0,
                finished_at REAL
            )''')
            db.execute('''CREATE TABLE IF NOT EXISTS notification_dispatches (
                batch_id TEXT NOT NULL, provider TEXT NOT NULL,
                destination_id TEXT NOT NULL, generation TEXT NOT NULL,
                provider_generation TEXT NOT NULL DEFAULT '',
                state TEXT NOT NULL, created_at REAL NOT NULL,
                last_attempt REAL, next_attempt REAL NOT NULL DEFAULT 0,
                attempts INTEGER NOT NULL DEFAULT 0, accepted_at REAL,
                error_code TEXT, request_id TEXT,
                PRIMARY KEY(batch_id, provider, destination_id)
            )''')
            db.execute('''CREATE TABLE IF NOT EXISTS notification_destination_epochs (
                provider TEXT NOT NULL, destination_id TEXT NOT NULL,
                generation TEXT NOT NULL, after_queue_id INTEGER NOT NULL,
                after_event_id INTEGER NOT NULL DEFAULT 0,
                activated_at REAL NOT NULL,
                PRIMARY KEY(provider, destination_id, generation)
            )''')
            db.execute('''CREATE TABLE IF NOT EXISTS notification_cooldowns (
                provider TEXT NOT NULL, generation TEXT NOT NULL,
                until_at REAL NOT NULL, PRIMARY KEY(provider, generation)
            )''')
            db.execute('''CREATE TABLE IF NOT EXISTS notification_operational_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT, event_key TEXT UNIQUE NOT NULL,
                kind TEXT NOT NULL, payload_json TEXT NOT NULL,
                created_at REAL NOT NULL, batch_id TEXT UNIQUE
            )''')
            db.execute('''CREATE TABLE IF NOT EXISTS notification_transitions (
                kind TEXT NOT NULL, entity TEXT NOT NULL, scope TEXT NOT NULL,
                state TEXT NOT NULL, episode INTEGER NOT NULL,
                PRIMARY KEY(kind,entity,scope)
            )''')
            db.execute('''CREATE INDEX IF NOT EXISTS notification_dispatch_ready
                          ON notification_dispatches(state,next_attempt)''')

    def activate_destination(self, provider, destination_id, generation, *, now=None):
        """Call only on activation/rekey; newly activated push has no backlog."""
        now = time.time() if now is None else now
        _targets([Destination(provider, destination_id, generation, frozenset())], PROVIDERS)
        with closing(self._connect()) as db, db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('''SELECT after_queue_id FROM notification_destination_epochs
                WHERE provider=? AND destination_id=? AND generation=?''', (provider, destination_id, generation)).fetchone()
            if row:
                return row[0]
            sequence = db.execute("SELECT seq FROM sqlite_sequence WHERE name='notification_queue'").fetchone()
            watermark = int(sequence[0]) if sequence and provider == 'pushover' else 0
            event_sequence = db.execute("SELECT seq FROM sqlite_sequence WHERE name='notification_operational_events'").fetchone()
            event_watermark = int(event_sequence[0]) if event_sequence else 0
            db.execute('INSERT INTO notification_destination_epochs VALUES (?,?,?,?,?,?)',
                       (provider, destination_id, generation, watermark, event_watermark, now))
            return watermark

    @staticmethod
    def _queue_event(db, event_key, kind, payload, now):
        return bool(db.execute('''INSERT OR IGNORE INTO notification_operational_events
            (event_key,kind,payload_json,created_at) VALUES (?,?,?,?)''',
            (event_key, kind, json.dumps(payload, sort_keys=True), now)).rowcount)

    def observe_connection(self, service, state, *, scope='', now=None):
        if service not in CONNECTIONS:
            raise ValueError('Unknown notification connection')
        return self._observe_transition('connection', service, state, scope, now)

    def observe_job(self, job_id, state, *, allowed_job_ids, scope='', now=None):
        # The app passes its fixed background_jobs.JOB_IDS catalog, not request data.
        if job_id not in allowed_job_ids or not isinstance(job_id, str) or not re.fullmatch(r'[a-z0-9-]{1,80}', job_id):
            raise ValueError('Unknown notification job')
        return self._observe_transition('job', job_id, state, scope, now)

    def _observe_transition(self, kind, entity, state, scope, now):
        if state not in ('healthy', 'failed') or not isinstance(scope, str) or len(scope) > 128:
            raise ValueError('Invalid notification transition')
        now = time.time() if now is None else now
        with closing(self._connect()) as db, db:
            db.execute('BEGIN IMMEDIATE')
            previous = db.execute('SELECT state,episode FROM notification_transitions WHERE kind=? AND entity=? AND scope=?', (kind, entity, scope)).fetchone()
            if previous and previous['state'] == state:
                return False
            episode = (previous['episode'] if previous else 0) + int(state == 'failed')
            db.execute('''INSERT INTO notification_transitions VALUES (?,?,?,?,?)
                ON CONFLICT(kind,entity,scope) DO UPDATE SET state=excluded.state,episode=excluded.episode''',
                (kind, entity, scope, state, episode))
            if state == 'healthy' and not previous:
                return False
            event_kind = kind.upper() + ('_FAILED' if state == 'failed' else '_RESTORED')
            # Scope is a trusted configuration fingerprint, never a token/URL.
            key = json.dumps((kind, entity, scope, episode, state), separators=(',', ':'))
            return self._queue_event(db, key, event_kind, {'entity': entity, 'episode': episode}, now)

    def observe_update(self, version, *, now=None):
        if not isinstance(version, str) or not STABLE_VERSION.fullmatch(version):
            raise ValueError('Invalid notification release version')
        now = time.time() if now is None else now
        with closing(self._connect()) as db, db:
            return self._queue_event(db, 'update:' + version, 'UPDATE_AVAILABLE', {'version': version}, now)

    @staticmethod
    def _owner_eligible(db, event, target):
        if not target.owner_verified or event['kind'] not in target.events:
            return False
        epoch = db.execute('''SELECT after_event_id FROM notification_destination_epochs
            WHERE provider=? AND destination_id=? AND generation=?''',
            (target.provider, target.id, target.generation)).fetchone()
        return bool(epoch and event['id'] > epoch[0])

    def _claim_events(self, targets, now, limit):
        with closing(self._connect()) as db, db:
            db.execute('BEGIN IMMEDIATE')
            events = db.execute('SELECT * FROM notification_operational_events WHERE batch_id IS NULL ORDER BY id LIMIT ?', (limit,)).fetchall()
            claimed = []
            for event in events:
                batch_id = uuid.uuid4().hex
                db.execute("INSERT INTO notification_batches(id,status,created_at) VALUES (?,'building',?)", (batch_id, now))
                db.execute('INSERT INTO notification_runs(batch_id) VALUES (?)', (batch_id,))
                db.execute('UPDATE notification_operational_events SET batch_id=? WHERE id=?', (batch_id, event['id']))
                for target in targets.values():
                    if self._owner_eligible(db, event, target):
                        self._seed(db, batch_id, target, 'pending', now)
                claimed.append(batch_id)
        return claimed

    @staticmethod
    def _seed(db, batch_id, target, state, now, *, accepted_at=None):
        db.execute('''INSERT OR IGNORE INTO notification_dispatches
            (batch_id,provider,destination_id,generation,provider_generation,state,created_at,accepted_at)
            VALUES (?,?,?,?,?,?,?,?)''',
            (batch_id, target.provider, target.id, target.generation,
             target.provider_generation, state, now, accepted_at))

    def migrate_legacy(self, destinations, *, now=None):
        """Idempotent, no-send import; preserve uncertain email batch boundaries."""
        now = time.time() if now is None else now
        targets = _targets(destinations, PROVIDERS)
        with closing(self._connect()) as db, db:
            db.execute('BEGIN IMMEDIATE')
            batches = db.execute('''SELECT b.* FROM notification_batches b LEFT JOIN notification_runs r
                ON r.batch_id=b.id WHERE r.batch_id IS NULL ORDER BY b.created_at''').fetchall()
            for batch in batches:
                batch_id = batch['id']
                sent = batch['status'] == 'sent'
                db.execute('INSERT INTO notification_runs VALUES (?,?,?)', (batch_id, 1, now if sent else None))
                receipts = db.execute('SELECT email,sent_at FROM notification_deliveries WHERE batch_id=?', (batch_id,)).fetchall()
                delivered = {row['email'].casefold() for row in receipts}
                for receipt in receipts:
                    email = receipt['email'].casefold()
                    target = targets.get(('email', email)) or Destination('email', email, 'legacy', frozenset())
                    self._seed(db, batch_id, target, 'accepted', now, accepted_at=receipt['sent_at'])
                if sent:
                    # Sent batches can have no remaining work, even after an old
                    # crash left a queue row behind. Reminder claims survive.
                    db.execute('DELETE FROM notification_queue WHERE batch_id=?', (batch_id,))
                elif batch['status'] == 'building':
                    events = [dict(row) for row in db.execute('SELECT * FROM notification_queue WHERE batch_id=?', (batch_id,))]
                    for target in targets.values():
                        if target.provider == 'email' and target.id.casefold() not in delivered and _eligible(events, target):
                            self._seed(db, batch_id, target, 'pending', now)
                else:
                    # Old code did not persist which recipient was in flight.
                    # Hold the unknown remainder as one explicit email review;
                    # never infer safe retries from today's recipient list.
                    sentinel = Destination('email', 'legacy-held', 'legacy', frozenset())
                    self._seed(db, batch_id, sentinel, 'review', now)
                    db.execute("UPDATE notification_dispatches SET error_code='worker_interrupted' WHERE batch_id=? AND destination_id='legacy-held'", (batch_id,))
                    if batch['status'] != 'review':
                        db.execute("UPDATE notification_batches SET status='review',detail='Email delivery needs review' WHERE id=?", (batch_id,))
        for batch in batches:
            # An existing held legacy batch is already a durable review record.
            # Import its dispatch proof without rewriting its original detail.
            if batch['status'] != 'review':
                self._settle(batch['id'], now)
        return len(batches)

    def recover_interrupted(self):
        """Invoke once after the worker lock is acquired, never from an HTTP read."""
        with closing(self._connect()) as db, db:
            db.execute('BEGIN IMMEDIATE')
            db.execute("UPDATE notification_batches SET status='review',detail='Notification delivery needs review' WHERE id IN (SELECT batch_id FROM notification_dispatches WHERE state='sending')")
            changed = db.execute("UPDATE notification_dispatches SET state='review',error_code='worker_interrupted',next_attempt=0 WHERE state='sending'").rowcount
        return changed

    def _claim_batch(self, targets, now, quiet_seconds):
        with closing(self._connect()) as db, db:
            db.execute('BEGIN IMMEDIATE')
            newest = db.execute('SELECT MAX(received_at) FROM notification_queue WHERE batch_id IS NULL').fetchone()[0]
            if newest is None or now - newest < quiet_seconds:
                return None
            batch_id = uuid.uuid4().hex
            db.execute("INSERT INTO notification_batches(id,status,created_at) VALUES (?,'building',?)", (batch_id, now))
            db.execute('INSERT INTO notification_runs(batch_id) VALUES (?)', (batch_id,))
            db.execute('UPDATE notification_queue SET batch_id=? WHERE batch_id IS NULL', (batch_id,))
            events = [dict(row) for row in db.execute('SELECT * FROM notification_queue WHERE batch_id=?', (batch_id,))]
            for target in targets.values():
                if _eligible(events, target):
                    self._seed(db, batch_id, target, 'pending', now)
        return batch_id

    def _cancel_paused_email(self, targets, now):
        """Honor recipient removal while the installation-wide Email switch is off."""
        batches, cancelled = set(), 0
        with closing(self._connect()) as db, db:
            db.execute('BEGIN IMMEDIATE')
            rows = db.execute("""SELECT d.* FROM notification_dispatches d
                JOIN notification_runs r ON r.batch_id=d.batch_id
                WHERE d.provider='email' AND d.state IN ('pending','retry')
                AND r.finished_at IS NULL AND NOT EXISTS
                (SELECT 1 FROM notification_operational_events e WHERE e.batch_id=d.batch_id)""").fetchall()
            for row in rows:
                target = targets.get(('email', row['destination_id']))
                events = [dict(event) for event in db.execute('SELECT * FROM notification_queue WHERE batch_id=?', (row['batch_id'],))]
                if (target is not None and target.generation == row['generation']
                        and target.provider_generation == row['provider_generation'] and _eligible(events, target)):
                    continue
                cancelled += db.execute("""UPDATE notification_dispatches SET state='cancelled',error_code='preferences_changed'
                    WHERE batch_id=? AND provider='email' AND destination_id=? AND state IN ('pending','retry')""",
                    (row['batch_id'], row['destination_id'])).rowcount
                batches.add(row['batch_id'])
        for batch_id in batches:
            self._settle(batch_id, now)
        return cancelled

    def _events(self, batch_id):
        with closing(self._connect()) as db:
            return [dict(row) for row in db.execute('SELECT * FROM notification_queue WHERE batch_id=? ORDER BY id', (batch_id,))]

    def _cancel(self, row):
        with closing(self._connect()) as db, db:
            db.execute("UPDATE notification_dispatches SET state='cancelled',error_code='preferences_changed' WHERE batch_id=? AND provider=? AND destination_id=? AND state IN ('pending','retry')", (row['batch_id'], row['provider'], row['destination_id']))

    def _defer_preparation(self, row, now):
        with closing(self._connect()) as db, db:
            db.execute("UPDATE notification_dispatches SET error_code='preparation_failed',next_attempt=? WHERE batch_id=? AND provider=? AND destination_id=? AND state IN ('pending','retry')", (now + 60, row['batch_id'], row['provider'], row['destination_id']))

    def _reserve(self, row, target, expected_ids, now, *, operational_id=None):
        with closing(self._connect()) as db, db:
            db.execute('BEGIN IMMEDIATE')
            if operational_id is None:
                current = _eligible([dict(event) for event in db.execute('SELECT * FROM notification_queue WHERE batch_id=?', (row['batch_id'],))], target)
                if {event['id'] for event in current} != expected_ids:
                    return False
            else:
                event = db.execute('SELECT * FROM notification_operational_events WHERE id=? AND batch_id=?', (operational_id, row['batch_id'])).fetchone()
                if not event or not self._owner_eligible(db, event, target):
                    return False
            cooldown = db.execute('SELECT until_at FROM notification_cooldowns WHERE provider=? AND generation=?', (target.provider, target.provider_generation)).fetchone()
            if cooldown and cooldown[0] > now:
                db.execute("UPDATE notification_dispatches SET state='retry',error_code='quota',next_attempt=? WHERE batch_id=? AND provider=? AND destination_id=? AND state IN ('pending','retry')", (cooldown[0], row['batch_id'], row['provider'], row['destination_id']))
                return False
            return bool(db.execute("UPDATE notification_dispatches SET state='sending',last_attempt=?,attempts=attempts+1,error_code=NULL WHERE batch_id=? AND provider=? AND destination_id=? AND state IN ('pending','retry') AND next_attempt<=?", (now, row['batch_id'], row['provider'], row['destination_id'], now)).rowcount)

    def _finish(self, row, result, now):
        state = getattr(result, 'state', None)
        if state not in ('accepted', 'retry', 'review', 'rejected', 'cancelled'):
            state, result = 'review', Outcome('review', 'response_uncertain')
        code = getattr(result, 'code', None)
        code = code if code in SAFE_CODES else None
        if state == 'retry' and code not in ('connect_failed', 'quota'):
            state, code = 'review', 'response_uncertain'
        if state == 'retry' and code == 'connect_failed' and row['attempts'] >= 4:
            state = 'rejected'
        request_id = getattr(result, 'request_id', None)
        request_id = request_id if isinstance(request_id, str) and REQUEST_ID.fullmatch(request_id) else None
        retry_at = getattr(result, 'retry_at', None)
        retry_at = retry_at if type(retry_at) in (int, float) and math.isfinite(retry_at) else now + 60
        minimum_retry = now + min(3600, 60 * 2 ** min(row['attempts'], 5)) if code == 'connect_failed' else now + 60
        retry_at = min(now + 32 * 86400, max(minimum_retry, retry_at)) if state == 'retry' else 0
        with closing(self._connect()) as db, db:
            db.execute('''UPDATE notification_dispatches SET state=?,error_code=?,request_id=?,
                          accepted_at=?,next_attempt=? WHERE batch_id=? AND provider=? AND destination_id=? AND state='sending' ''',
                       (state, code, request_id, now if state == 'accepted' else None, retry_at,
                        row['batch_id'], row['provider'], row['destination_id']))
            if (state == 'accepted' and row['provider'] == 'email'
                    and not db.execute('SELECT 1 FROM notification_operational_events WHERE batch_id=?', (row['batch_id'],)).fetchone()):
                # Legacy readers retain per-recipient proof while a media batch
                # is unfinished. The durable dispatch remains after settlement.
                db.execute('INSERT OR IGNORE INTO notification_deliveries(batch_id,email,sent_at) VALUES (?,?,?)',
                           (row['batch_id'], row['destination_id'], now))
            if state == 'retry' and code == 'quota':
                db.execute('''INSERT INTO notification_cooldowns VALUES (?,?,?) ON CONFLICT(provider,generation)
                              DO UPDATE SET until_at=MAX(until_at,excluded.until_at)''',
                           (row['provider'], row['provider_generation'], retry_at))
        return state

    def _settle(self, batch_id, now):
        with closing(self._connect()) as db, db:
            states = {row[0] for row in db.execute('SELECT state FROM notification_dispatches WHERE batch_id=?', (batch_id,))}
            if states <= {'accepted', 'cancelled'}:
                db.execute("UPDATE notification_batches SET status='sent',detail='Notification delivery completed' WHERE id=?", (batch_id,))
                db.execute('UPDATE notification_runs SET finished_at=? WHERE batch_id=?', (now, batch_id))
                db.execute('DELETE FROM notification_queue WHERE batch_id=?', (batch_id,))
                db.execute('DELETE FROM notification_deliveries WHERE batch_id=?', (batch_id,))
            else:
                status = 'review' if states & {'review', 'rejected'} else 'building'
                db.execute('UPDATE notification_batches SET status=?,detail=? WHERE id=?',
                           (status, 'Notification delivery needs review' if status == 'review' else None, batch_id))

    @staticmethod
    def _event_value(row):
        payload = json.loads(row['payload_json'])
        if not isinstance(payload, dict) or row['kind'] not in OPERATIONAL_EVENTS:
            raise ValueError('Invalid recorded operational event')
        if row['kind'] == 'UPDATE_AVAILABLE':
            version = payload.get('version')
            if not isinstance(version, str) or not STABLE_VERSION.fullmatch(version):
                raise ValueError('Invalid recorded operational release')
            fields = {'version': version}
        else:
            entity, episode = payload.get('entity'), payload.get('episode')
            if (not isinstance(entity, str) or not re.fullmatch(r'[a-z0-9-]{1,80}', entity)
                    or type(episode) is not int or not 1 <= episode <= 1000000000
                    or row['kind'].startswith('CONNECTION_') and entity not in CONNECTIONS):
                raise ValueError('Invalid recorded operational transition')
            fields = {'entity': entity, 'episode': episode}
        return {'id': row['id'], 'kind': row['kind'], 'created_at': row['created_at'], **fields}

    def _process_events(self, callbacks, targets, enabled, now, limit):
        claimed = self._claim_events(targets, now, limit)
        report = {state: 0 for state in ('accepted', 'retry', 'review', 'rejected', 'cancelled')}
        with closing(self._connect()) as db:
            rows = [dict(row) for row in db.execute('''SELECT d.*,e.id AS event_id,e.kind,e.payload_json,e.created_at AS event_created
                FROM notification_dispatches d JOIN notification_operational_events e ON e.batch_id=d.batch_id
                WHERE d.state IN ('pending','retry') AND d.next_attempt<=? AND d.provider IN (?,?)
                ORDER BY e.id,d.provider,d.destination_id LIMIT ?''',
                (now, 'email' if 'email' in enabled else '', 'pushover' if 'pushover' in enabled else '', limit))]
        for row in rows:
            try:
                live_enabled = frozenset(callbacks.enabled_providers()) & PROVIDERS
                if row['provider'] not in live_enabled:
                    continue
                target = _targets(callbacks.destinations(), live_enabled).get((row['provider'], row['destination_id']))
                if (not target or not target.owner_verified or target.generation != row['generation']
                        or target.provider_generation != row['provider_generation'] or row['kind'] not in target.events):
                    self._cancel(row)
                    report['cancelled'] += 1
                    continue
                event = self._event_value({'id': row['event_id'], 'kind': row['kind'],
                    'payload_json': row['payload_json'], 'created_at': row['event_created']})
                message = callbacks.render_event(target, event)
                refreshed = _targets(callbacks.destinations(), frozenset(callbacks.enabled_providers()) & PROVIDERS).get((target.provider, target.id))
                if refreshed != target:
                    self._defer_preparation(row, now)
                    continue
            except Exception:
                self._defer_preparation(row, now)
                continue
            if not self._reserve(row, target, set(), now, operational_id=row['event_id']):
                continue
            try:
                outcome = callbacks.send(target, message)
            except Exception:
                outcome = Outcome('review', 'email_uncertain' if target.provider == 'email' else 'response_uncertain')
            report[self._finish(row, outcome, now)] += 1
        for batch_id in set(claimed) | {row['batch_id'] for row in rows}:
            self._settle(batch_id, now)
        return report

    def process(self, callbacks, *, now=None, quiet_seconds=600, batch_limit=16,
                include_media=True):
        """Prepare and deliver independently; no global email review barrier."""
        now = time.time() if now is None else now
        if (type(quiet_seconds) is not int or quiet_seconds < 0 or type(batch_limit) is not int
                or not 1 <= batch_limit <= 100 or type(include_media) is not bool):
            raise ValueError('Invalid notification processing limits')
        enabled = frozenset(callbacks.enabled_providers()) & PROVIDERS
        destinations = tuple(callbacks.destinations())
        targets = _targets(destinations, enabled)
        claim_targets = _targets(destinations, enabled | {'email'})
        # Saved recipient preferences remain distinct from an installation-wide
        # provider switch. A paused legacy email may resume when SMTP is enabled.
        if include_media:
            self.migrate_legacy(destinations, now=now)
        report = {state: 0 for state in ('accepted', 'retry', 'review', 'rejected', 'cancelled')}
        if include_media and 'email' not in enabled:
            report['cancelled'] += self._cancel_paused_email(claim_targets, now)
        if not enabled:
            return {'state': 'disabled', **report}
        claimed, batches = None, []
        if include_media:
            claimed = self._claim_batch(claim_targets, now, quiet_seconds)
        with closing(self._connect()) as db:
            # Review-only batches are not selected for resolution. Their records
            # remain available for an explicit owner decision.
            batches = [row[0] for row in db.execute('''SELECT r.batch_id FROM notification_runs r
                JOIN notification_batches b ON b.id=r.batch_id WHERE r.finished_at IS NULL
                AND NOT EXISTS (SELECT 1 FROM notification_operational_events e WHERE e.batch_id=r.batch_id)
                AND EXISTS (SELECT 1 FROM notification_dispatches d WHERE d.batch_id=r.batch_id
                  AND d.state IN ('pending','retry') AND d.next_attempt<=? AND d.provider IN (?,?))
                ORDER BY b.created_at LIMIT ?''',
                (now, 'email' if 'email' in enabled else '', 'pushover' if 'pushover' in enabled else '', batch_limit))] if include_media else []
        for batch_id in batches:
            events = self._events(batch_id)
            with closing(self._connect()) as db:
                rows = [dict(row) for row in db.execute("SELECT * FROM notification_dispatches WHERE batch_id=? AND state IN ('pending','retry') AND next_attempt<=? AND provider IN (?,?) ORDER BY provider,destination_id",
                    (batch_id, now, 'email' if 'email' in enabled else '', 'pushover' if 'pushover' in enabled else ''))]
            try:
                items = callbacks.resolve(events)
            except Exception:
                for row in rows:
                    self._defer_preparation(row, now)
                continue
            for row in rows:
                key = (row['provider'], row['destination_id'])
                try:
                    live_enabled = frozenset(callbacks.enabled_providers()) & PROVIDERS
                    if row['provider'] not in live_enabled:
                        continue
                    live = _targets(callbacks.destinations(), live_enabled)
                    target = live.get(key)
                    if target is None or target.generation != row['generation'] or target.provider_generation != row['provider_generation']:
                        self._cancel(row)
                        report['cancelled'] += 1
                        continue
                    eligible = _eligible(self._events(batch_id), target)
                    recipient_items = _recipient_items(items, eligible)
                    if not recipient_items:
                        self._cancel(row)
                        report['cancelled'] += 1
                        continue
                    message = callbacks.render(target, recipient_items)
                    refreshed = _targets(callbacks.destinations(), frozenset(callbacks.enabled_providers()) & PROVIDERS).get(key)
                    if refreshed != target:
                        self._defer_preparation(row, now)
                        continue
                except Exception:
                    self._defer_preparation(row, now)
                    continue
                if not self._reserve(row, target, {event['id'] for event in eligible}, now):
                    continue
                try:
                    result = callbacks.send(target, message)
                except Exception:
                    result = Outcome('review', 'email_uncertain' if target.provider == 'email' else 'response_uncertain')
                report[self._finish(row, result, now)] += 1
            self._settle(batch_id, now)
        if claimed:
            self._settle(claimed, now)
        operational = self._process_events(callbacks, targets, enabled, now, batch_limit)
        for outcome in report:
            report[outcome] += operational[outcome]
        with closing(self._connect()) as db:
            held = db.execute("""SELECT 1 FROM notification_dispatches d
                WHERE d.state IN ('review','rejected') AND (? OR EXISTS
                (SELECT 1 FROM notification_operational_events e WHERE e.batch_id=d.batch_id))
                LIMIT 1""", (include_media,)).fetchone()
            unfinished_claim = claimed and db.execute('SELECT 1 FROM notification_runs WHERE batch_id=? AND finished_at IS NULL', (claimed,)).fetchone()
        state = 'review' if held else 'sent' if report['accepted'] else 'empty' if claimed and not batches and not unfinished_claim else 'waiting'
        return {'state': state, **report}

    def resolve_review(self, batch_id, provider, destination_id, *, action, now=None, guard=None):
        """Owner-authorized caller must explain duplicate risk before retry."""
        if action not in ('discard', 'retry'):
            raise ValueError('Invalid review action')
        now = time.time() if now is None else now
        with closing(self._connect()) as db, db:
            db.execute('BEGIN IMMEDIATE')
            if guard is not None:
                guard(db)
            changed = db.execute("UPDATE notification_dispatches SET state=?,error_code=NULL,next_attempt=? WHERE batch_id=? AND provider=? AND destination_id=? AND state IN ('review','rejected') AND destination_id!='legacy-held'",
                                 ('pending' if action == 'retry' else 'cancelled', now,
                                  batch_id, provider, destination_id)).rowcount
            if destination_id == 'legacy-held' and action == 'discard':
                changed = db.execute("UPDATE notification_dispatches SET state='cancelled',error_code=NULL WHERE batch_id=? AND provider='email' AND destination_id='legacy-held' AND state='review'", (batch_id,)).rowcount
        self._settle(batch_id, now)
        return bool(changed)

    def snapshot(self, *, batch_id=None, limit=100):
        """Read-only safe status; credentials/messages/raw provider errors excluded."""
        if type(limit) is not int or not 1 <= limit <= 500:
            raise ValueError('Invalid notification history limit')
        try:
            self.path.stat()
        except FileNotFoundError:
            return []
        with closing(self._connect(read_only=True)) as db:
            if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='notification_dispatches'").fetchone():
                return []
            rows = db.execute('''SELECT d.batch_id,d.provider,d.destination_id,d.state,d.last_attempt,d.accepted_at,
                d.next_attempt,d.attempts,d.error_code,d.request_id,e.kind AS event_kind
                FROM notification_dispatches d LEFT JOIN notification_operational_events e ON e.batch_id=d.batch_id
                WHERE (? IS NULL OR d.batch_id=?) ORDER BY d.created_at DESC,d.provider,d.destination_id LIMIT ?''', (batch_id, batch_id, limit)).fetchall()
        return [{**dict(row), 'state': row['state'] if row['state'] in STATES else 'review',
                 'event_kind': row['event_kind'] if row['event_kind'] in OPERATIONAL_EVENTS else 'MEDIA_DIGEST',
                 'error_code': row['error_code'] if row['error_code'] in SAFE_CODES else None,
                 'request_id': row['request_id'] if isinstance(row['request_id'], str) and REQUEST_ID.fullmatch(row['request_id']) else None}
                for row in rows]
