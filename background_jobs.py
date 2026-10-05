"""Bounded observations and controls consumed by Keep's existing worker.

Observation failures must never prevent automatic work. Owner controls are
durable requests, never callbacks executed in an HTTP request.
"""
from contextlib import closing
from datetime import datetime, timezone
import math
import os
import re
import sqlite3
import threading
import time
import uuid

from connection_settings import AUTO_INTERVALS
import seerr


JOBS = (
    ('onboarding-cleanup', 'Setup cleanup', 'Remove expired setup codes and Plex sign-in attempts.'),
    ('plex-access-sync', 'Plex account access', 'Refresh server access for Plex accounts.'),
    ('keep-expiry', 'Temporary Keeps', 'Release expired Keep protection.'),
    ('reminder-scan', 'Leaving reminders', 'Find titles eligible for a seven-day reminder.'),
    ('reminder-reconcile', 'Reminder reconciliation', 'Resolve and deduplicate queued reminders.'),
    ('queue-cleanup', 'Email queue cleanup', 'Remove queued titles that are no longer eligible.'),
    ('email-digest', 'Email delivery', 'Send queued digests after the quiet period.'),
    ('seerr-availability', 'Seerr availability', 'Request an availability sync after library deletion.'),
    ('seerr-history', 'Seerr request history', 'Refresh request attribution and account links.'),
    ('connection-monitor', 'Connection checks', 'Check which service probes are due.'),
)
RESULT_STATUSES = frozenset(('success', 'failed', 'waiting', 'review', 'disabled'))
RESULT_MESSAGES = frozenset((
    'Completed', 'No changes', 'Waiting for queued work', 'Delivery needs review',
    'Connection unavailable', 'Some Keeps will be retried', 'Email is disabled',
    'Waiting for the next scheduled check', 'Result unavailable',
))
COUNT_RESULT = re.compile(
    r'(?:Checked|Removed|Released|Queued|Updated|Processed) [0-9]{1,12} '
    r'(?:items|records|accounts|Keeps|reminders|titles)(?:; [0-9]{1,12} (?:failed|missing))?\Z'
)
PROBES = (
    ('plex', 'Plex'), ('maintainerr', 'Maintainerr'), ('radarr', 'Radarr'),
    ('sonarr', 'Sonarr'), ('tautulli', 'Tautulli'), ('email', 'Email'),
)
JOB_IDS = frozenset(row[0] for row in JOBS) | frozenset('probe-' + row[0] for row in PROBES)
EDITABLE_JOBS = frozenset(('plex-access-sync', 'reminder-scan', 'seerr-history')) | frozenset(
    'probe-' + row[0] for row in PROBES)
INTERVAL_SECONDS = (300, 600, 900, 1200, 1800, 3600, 7200, 21600, 43200, 86400)


def timestamp(value):
    if value is None or not isinstance(value, (int, float)) or not math.isfinite(value):
        return None
    try:
        return datetime.fromtimestamp(value, timezone.utc).isoformat()
    except (OverflowError, ValueError, OSError):
        return None


def interval_label(seconds):
    if seconds >= 3600 and seconds % 3600 == 0:
        hours = seconds // 3600
        return f'Every {hours} hour' + ('s' if hours != 1 else '')
    if seconds >= 60 and seconds % 60 == 0:
        minutes = seconds // 60
        return f'Every {minutes} minute' + ('s' if minutes != 1 else '')
    return f'Every {seconds} seconds'


INTERVAL_OPTIONS = tuple({'seconds': seconds, 'label': interval_label(seconds)}
                         for seconds in INTERVAL_SECONDS)


class RetryUnstarted(RuntimeError):
    """Native job state was not recorded; retry the exact manual request."""


class Store:
    def __init__(self, path, logger=None):
        self.path = path
        self.logger = logger
        self._initialized = False
        # Only worker-local recovery state lives here. Each map has at most one
        # entry per catalog job; the durable request remains in SQLite throughout.
        self._control_lock = threading.RLock()
        self._retry_operations = {}
        self._last_request_tokens = {}
        self._active_runs = {}
        self._startup_recovery = False
        self._observe(self._initialize)

    def _initialize(self):
        with closing(sqlite3.connect(self.path, timeout=0.25)) as db, db:
            db.execute('BEGIN IMMEDIATE')
            db.execute('''CREATE TABLE IF NOT EXISTS background_jobs (
                job_id TEXT PRIMARY KEY, run_token TEXT NOT NULL,
                started REAL NOT NULL, finished REAL, last_success REAL,
                duration REAL, status TEXT NOT NULL, result TEXT NOT NULL,
                next_run REAL, scope TEXT
            )''')
            columns = {row[1] for row in db.execute('PRAGMA table_info(background_jobs)')}
            if 'scope' not in columns:
                db.execute('ALTER TABLE background_jobs ADD COLUMN scope TEXT')
            db.execute('''CREATE TABLE IF NOT EXISTS background_job_requests (
                job_id TEXT PRIMARY KEY, request_token TEXT NOT NULL,
                claimed_token TEXT, attempted INTEGER NOT NULL DEFAULT 0, scope TEXT
            )''')
            request_columns = {row[1] for row in db.execute('PRAGMA table_info(background_job_requests)')}
            if 'scope' not in request_columns:
                db.execute('ALTER TABLE background_job_requests ADD COLUMN scope TEXT')
            db.execute('''CREATE TABLE IF NOT EXISTS background_job_settings (
                job_id TEXT PRIMARY KEY, interval_seconds INTEGER NOT NULL
            )''')
        self._initialized = True
        return True

    def request_run(self, job_id, *, scope=None):
        if job_id not in JOB_IDS:
            raise ValueError('Unknown background job')
        if scope is not None and (not isinstance(scope, str) or not re.fullmatch('[0-9a-f]{64}', scope)):
            raise ValueError('Invalid background job scope')
        if not self._initialized:
            self._initialize()
        with closing(sqlite3.connect(self.path, timeout=0.25)) as db, db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT request_token,claimed_token,scope FROM background_job_requests WHERE job_id=?',
                             (job_id,)).fetchone()
            if row and row[0] != row[1] and row[2] == scope:
                return False
            token = uuid.uuid4().hex
            db.execute('''INSERT INTO background_job_requests (job_id,request_token,scope) VALUES (?,?,?)
                ON CONFLICT(job_id) DO UPDATE SET request_token=excluded.request_token,
                attempted=0,scope=excluded.scope''', (job_id, token, scope))
        return True

    def pending(self, *, scopes=None):
        self._retry_controls()
        def read():
            with closing(sqlite3.connect(self.path, timeout=0.25)) as db:
                return {job_id: token for job_id, token, scope in db.execute(
                    'SELECT job_id,request_token,scope FROM background_job_requests') if job_id in JOB_IDS
                    and (scope is None or scopes is None or scope == scopes.get(job_id))}
        return self._observe(read) or {}

    def requested(self, job_id, *, first_attempt=False, scope=None):
        def read():
            with closing(sqlite3.connect(self.path, timeout=0.25)) as db, db:
                row = db.execute('SELECT attempted,scope,request_token FROM background_job_requests WHERE job_id=?',
                                 (job_id,)).fetchone()
                if row and scope is not None and row[1] is not None and row[1] != scope:
                    return False
                settlement = self._retry_operations.get(job_id, {}).get('settlement')
                if row and settlement and settlement[1] == row[2]:
                    if settlement[0] == 'acknowledge':
                        return False
                    if first_attempt:
                        return settlement[2]
                requested = bool(row and (not first_attempt or not row[0]))
                if requested:
                    self._last_request_tokens[job_id] = (row[2], row[1])
                return requested
        with self._control_lock:
            self._retry_controls()
            return bool(self._observe(read))

    def claim(self, job_id, *, scope=None):
        """Keep the request durable during I/O and identify its exact completion."""
        self._retry_controls()
        captured = [None]
        captured_scope = [None]
        failed = [False]
        def eligible(row):
            if not row or scope is not None and row[2] is not None and row[2] != scope:
                return False
            if row[1] is None:
                return True
            settlement = self._retry_operations.get(job_id, {}).get('settlement')
            return bool(settlement and settlement[1] == row[1] and not self._active_runs.get(job_id))
        def update():
            with closing(sqlite3.connect(self.path, timeout=0.25)) as db, db:
                before = db.execute('SELECT request_token,claimed_token,scope FROM background_job_requests WHERE job_id=?',
                                 (job_id,)).fetchone()
                if not eligible(before):
                    return None
                try:
                    db.execute('BEGIN IMMEDIATE')
                    row = db.execute('SELECT request_token,claimed_token,scope FROM background_job_requests WHERE job_id=?',
                                     (job_id,)).fetchone()
                    if not eligible(row):
                        return None
                    captured[0] = row[0]
                    captured_scope[0] = row[2]
                except sqlite3.Error:
                    # Automatic work still runs when the control write is busy.
                    # Its completion may settle only this pre-I/O request token.
                    captured[0] = before[0]
                    captured_scope[0] = before[2]
                    raise
                db.execute('UPDATE background_job_requests SET claimed_token=?,attempted=1 WHERE job_id=?',
                           (row[0], job_id))
                return row[0]
        def attempt():
            try:
                return update()
            except Exception:
                failed[0] = True
                raise
        with self._control_lock:
            token = self._observe(attempt) or captured[0]
            if token is None and failed[0] and not self._active_runs.get(job_id):
                known = self._last_request_tokens.get(job_id)
                if known and (known[1] is None or scope is None or known[1] == scope):
                    token, captured_scope[0] = known
            if token:
                self._last_request_tokens[job_id] = (token, captured_scope[0])
            return token

    def acknowledge(self, job_id, token):
        if token:
            self._defer(job_id, 'settlement', ('acknowledge', token, False))

    def _release(self, job_id, token, *, unstarted=False):
        if token:
            self._defer(job_id, 'settlement', ('release', token, unstarted))

    def retry_unstarted(self, job_id):
        """A busy service lock did no work; keep the manual request runnable."""
        with self._control_lock:
            known = self._last_request_tokens.get(job_id)
            token = known[0] if known else None
        self._release(job_id, token, unstarted=True)

    def _defer(self, job_id, operation, value):
        if job_id not in JOB_IDS:
            raise ValueError('Unknown background job')
        with self._control_lock:
            self._retry_operations.setdefault(job_id, {})[operation] = value
            self._retry_controls()

    def _retry_controls(self):
        """Retry exact-token writes before deciding whether manual work is due."""
        with self._control_lock:
            if not self._startup_recovery and not self._retry_operations:
                return
            if not self._initialized and not self._observe(self._initialize):
                return
            if self._startup_recovery:
                def reset():
                    with closing(sqlite3.connect(self.path, timeout=0.25)) as db, db:
                        db.execute('BEGIN IMMEDIATE')
                        # Other worker threads may already be performing I/O.
                        active = tuple(self._active_runs)
                        excluded = (' AND job_id NOT IN (' + ','.join('?' for _ in active) + ')') if active else ''
                        db.execute("""UPDATE background_jobs SET status='interrupted',
                            result='Interrupted before completion',finished=NULL,duration=NULL,
                            next_run=NULL WHERE status='running'""" + excluded, active)
                        db.execute('''UPDATE background_job_requests SET claimed_token=NULL,attempted=0
                            WHERE claimed_token IS NOT NULL''' + excluded, active)
                    return True
                if not self._observe(reset):
                    return
                self._startup_recovery = bool(self._active_runs)
            for job_id, operations in list(self._retry_operations.items()):
                def write():
                    with closing(sqlite3.connect(self.path, timeout=0.25)) as db, db:
                        db.execute('BEGIN IMMEDIATE')
                        if 'start' in operations:
                            self._write_start(db, *operations['start'])
                        if 'finish' in operations:
                            self._write_finish(db, *operations['finish'])
                        if 'settlement' in operations:
                            action, token, unstarted = operations['settlement']
                            if action == 'acknowledge':
                                # A failed claim can leave this exact request
                                # unclaimed; a later request has a different token.
                                db.execute('DELETE FROM background_job_requests WHERE job_id=? AND request_token=?',
                                           (job_id, token))
                                db.execute('UPDATE background_job_requests SET claimed_token=NULL WHERE job_id=? AND claimed_token=?',
                                           (job_id, token))
                            else:
                                db.execute('''UPDATE background_job_requests SET claimed_token=NULL,
                                    attempted=CASE WHEN request_token=? THEN ? ELSE attempted END
                                    WHERE job_id=? AND (claimed_token=? OR request_token=?)''',
                                           (token, 0 if unstarted else 1, job_id, token, token))
                    return True
                if not self._observe(write):
                    return
                self._retry_operations.pop(job_id, None)

    def interval(self, job_id, default):
        def read():
            with closing(sqlite3.connect(self.path, timeout=0.25)) as db:
                row = db.execute('SELECT interval_seconds FROM background_job_settings WHERE job_id=?',
                                 (job_id,)).fetchone()
                return row[0] if row and row[0] in INTERVAL_SECONDS else default
        value = self._observe(read)
        return default if value is None else value

    def set_interval(self, job_id, seconds):
        if job_id not in EDITABLE_JOBS:
            raise ValueError('This job has a fixed schedule')
        if type(seconds) is not int or seconds not in INTERVAL_SECONDS:
            raise ValueError('Choose a supported job frequency')
        if not self._initialized:
            self._initialize()
        with closing(sqlite3.connect(self.path, timeout=0.25)) as db, db:
            db.execute('BEGIN IMMEDIATE')
            db.execute('INSERT OR REPLACE INTO background_job_settings VALUES (?,?)', (job_id, seconds))
            # Change successful cadence immediately while preserving failure backoff.
            db.execute("UPDATE background_jobs SET next_run=finished+? WHERE job_id=? AND status='success' AND finished IS NOT NULL",
                       (seconds, job_id))
            tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if job_id.startswith('probe-') and 'automatic_connection_checks' in tables:
                db.execute('UPDATE automatic_connection_checks SET next_attempt=checked+? WHERE service=? AND failures=0',
                           (seconds, job_id.removeprefix('probe-')))
            if job_id == 'seerr-history' and {'seerr_refresh', 'seerr_cache'} <= tables:
                db.execute('''UPDATE seerr_refresh SET next_attempt=(
                    SELECT updated+? FROM seerr_cache WHERE seerr_cache.scope=seerr_refresh.scope)
                    WHERE failures=0 AND scope IN (SELECT scope FROM seerr_cache)''', (seconds,))

    def due(self, job_id, fallback=True):
        if self.requested(job_id):
            return True
        with self._control_lock:
            finishing = self._retry_operations.get(job_id, {}).get('finish')
        if finishing and finishing[4] == 'success' and finishing[6] is not None:
            return time.time() >= finishing[2] + self.interval(job_id, finishing[6])
        records = self._observe(self.records) or {}
        record = records.get(job_id)
        if record and record['status'] == 'success' and record['next_run'] is not None:
            return time.time() >= record['next_run']
        return fallback

    def _observe(self, operation):
        try:
            return operation()
        except Exception:
            self._initialized = False
            self._warning('Background job observation could not be recorded')
            return None

    def _warning(self, message):
        if self.logger:
            try:
                self.logger.warning(message)
            except Exception:
                pass

    def _start(self, job_id, token, started, scope=None):
        self._defer(job_id, 'start', (job_id, token, started, scope))

    @staticmethod
    def _write_start(db, job_id, token, started, scope=None):
        db.execute('''INSERT INTO background_jobs
                (job_id,run_token,started,status,result,scope)
                VALUES (?,?,?,'running','Running',?)
                ON CONFLICT(job_id) DO UPDATE SET run_token=excluded.run_token,
                last_success=CASE WHEN background_jobs.scope IS excluded.scope
                    THEN background_jobs.last_success ELSE NULL END,
                finished=CASE WHEN background_jobs.scope IS excluded.scope
                    THEN background_jobs.finished ELSE NULL END,
                duration=CASE WHEN background_jobs.scope IS excluded.scope
                    THEN background_jobs.duration ELSE NULL END,
                started=excluded.started,status=excluded.status,result=excluded.result,
                next_run=NULL,scope=excluded.scope''', (job_id, token, started, scope))

    def _finish(self, job_id, token, finished, duration, status, result, interval):
        self._defer(job_id, 'finish', (job_id, token, finished, duration, status, result, interval))

    @staticmethod
    def _write_finish(db, job_id, token, finished, duration, status, result, interval):
        if status == 'failed':
            interval = 30
        if status != 'failed' and job_id in EDITABLE_JOBS:
            saved = db.execute('SELECT interval_seconds FROM background_job_settings WHERE job_id=?',
                               (job_id,)).fetchone()
            if saved and saved[0] in INTERVAL_SECONDS:
                interval = saved[0]
        next_run = finished + interval if interval is not None and status != 'disabled' else None
        db.execute('''UPDATE background_jobs SET finished=?,duration=?,status=?,result=?,
            last_success=CASE WHEN ?='success' THEN ? ELSE last_success END,next_run=?
            WHERE job_id=? AND run_token=?''',
            (finished, duration, status, result, status, finished, next_run, job_id, token))

    def run(self, job_id, callback, interval=30, result_fn=None, scope=None):
        if job_id not in JOB_IDS:
            raise ValueError('Unknown background job')
        if interval is not None and (type(interval) is not int or not 1 <= interval <= 7 * 86400):
            raise ValueError('Invalid background job interval')
        if scope is not None and (job_id not in ('seerr-availability', 'seerr-history') and not job_id.startswith('probe-') or
                                  not isinstance(scope, str) or not re.fullmatch('[0-9a-f]{64}', scope)):
            raise ValueError('Invalid background job scope')
        if not self._initialized:
            self._observe(self._initialize)
        token = uuid.uuid4().hex
        request_token = self.claim(job_id, scope=scope)
        with self._control_lock:
            self._active_runs[job_id] = self._active_runs.get(job_id, 0) + 1
        try:
            self._observe(lambda: self._start(job_id, token, time.time(), scope))
            clock_started = time.monotonic()
            try:
                result = callback()
            except BaseException as error:
                self._observe(lambda: self._finish(
                    job_id, token, time.time(), max(0, time.monotonic() - clock_started),
                    'failed', 'Failed; will retry', 30))
                self._release(job_id, request_token,
                              unstarted=isinstance(error, (seerr.RefreshBusy, RetryUnstarted)))
                raise
            status, summary = 'success', 'Completed'
            if result_fn is not None:
                try:
                    proposed_status, proposed_summary = result_fn(result)
                    if (proposed_status not in RESULT_STATUSES or
                            not isinstance(proposed_summary, str) or
                            (proposed_summary not in RESULT_MESSAGES and not COUNT_RESULT.fullmatch(proposed_summary))):
                        raise ValueError('Invalid background job result')
                    status, summary = proposed_status, proposed_summary
                except Exception:
                    status, summary = 'waiting', 'Result unavailable'
                    self._warning('Background job result could not be recorded')
            self._observe(lambda: self._finish(
                job_id, token, time.time(), max(0, time.monotonic() - clock_started),
                status, summary, interval))
            if status == 'failed':
                self._release(job_id, request_token)
            else:
                self.acknowledge(job_id, request_token)
            return result
        finally:
            with self._control_lock:
                self._active_runs[job_id] -= 1
                if not self._active_runs[job_id]:
                    del self._active_runs[job_id]

    def records(self):
        self._retry_controls()
        with closing(sqlite3.connect(self.path, timeout=0.25)) as db:
            db.row_factory = sqlite3.Row
            return {row['job_id']: dict(row) for row in db.execute('SELECT * FROM background_jobs')
                    if row['job_id'] in JOB_IDS}

    def interrupt_running(self):
        """Called once by the worker after it acquires its exclusive process lock."""
        with self._control_lock:
            self._startup_recovery = True
            self._retry_controls()

    def snapshot(self, getter, connection_settings, *, heartbeat_path, now=None,
                 plex_interval=900, reminder_interval=900):
        now = time.time() if now is None else now
        try:
            heartbeat = os.stat(heartbeat_path).st_mtime
        except OSError:
            heartbeat = None
        available = heartbeat is not None and -30 <= now - heartbeat <= 300
        worker = {'available': available, 'kind': 'success' if available else 'failed',
                  'label': 'Running' if available else 'Unavailable',
                  'checked_at': timestamp(heartbeat)}
        records = self.records()
        scope = seerr.namespace(getter)
        email = str(getter('EMAIL_ENABLED')).lower() == 'true'
        configured = {service: connection_settings.configured(service, getter)
                      for service in (*dict(PROBES), 'seerr')}
        maintainerr = bool(getter('MAINTAINERR_URL'))
        intervals = {job_id: 30 for job_id in JOB_IDS}
        intervals.update({'plex-access-sync': plex_interval, 'reminder-scan': reminder_interval,
                          'seerr-history': seerr.REFRESH_INTERVAL})
        intervals = {job_id: self.interval(job_id, seconds) for job_id, seconds in intervals.items()}
        job_rows = []
        for job_id, title, description in JOBS:
            record = records.get(job_id)
            if job_id.startswith('seerr-') and record and record.get('scope') != scope:
                record = None
            row = self._row(job_id, title, description, record, available)
            row['schedule'] = interval_label(intervals[job_id])
            if job_id == 'seerr-availability':
                row['schedule'] = 'After library deletion'
            if job_id == 'plex-access-sync' and not configured['plex']:
                self._inactive(row, 'Setup needed', 'Configure Plex first')
            elif job_id in ('keep-expiry', 'reminder-reconcile', 'queue-cleanup') and not maintainerr:
                self._inactive(row, 'Setup needed', 'Configure Maintainerr first')
            elif job_id in ('reminder-scan', 'email-digest') and not email:
                self._inactive(row, 'Disabled', 'Email is disabled')
            elif job_id == 'reminder-scan' and not maintainerr:
                self._inactive(row, 'Setup needed', 'Configure Maintainerr first')
            elif job_id.startswith('seerr-') and not configured['seerr']:
                self._inactive(row, 'Setup needed', 'Configure Seerr first')
            elif job_id == 'connection-monitor' and not any(configured[service] for service, _ in PROBES):
                self._inactive(row, 'Setup needed', 'Configure a connection first')
            job_rows.append(row)

        with closing(sqlite3.connect(self.path, timeout=0.25)) as db:
            db.row_factory = sqlite3.Row
            checks = {row['service']: dict(row) for row in db.execute('SELECT * FROM automatic_connection_checks')}
            # Manual refreshes use the same durable Seerr schedule. Ignore records
            # for previous settings rather than attributing them to the new service.
            tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            history = (db.execute('SELECT next_attempt,failures FROM seerr_refresh WHERE scope=?', (scope,)).fetchone()
                       if 'seerr_refresh' in tables else None)
            availability = (db.execute('SELECT due,failures FROM seerr_availability_queue WHERE scope=?', (scope,)).fetchone()
                            if 'seerr_availability_queue' in tables else None)
            cache = (db.execute('SELECT updated,failed FROM seerr_cache WHERE scope=?', (scope,)).fetchone()
                     if 'seerr_cache' in tables else None)
        for row in job_rows:
            if configured['seerr'] and row['id'] == 'seerr-history':
                if history:
                    row['next_run'] = timestamp(history['next_attempt'])
                    if available and history['failures'] and row['status'] != 'running':
                        row.update(status='failed', label='Retrying', result='Connection unavailable')
                elif cache:
                    row['next_run'] = timestamp(cache['updated'] + intervals['seerr-history'])
                if cache:
                    row['last_success'] = timestamp(cache['updated'])
                    record = records.get('seerr-history')
                    matching = record and record.get('scope') == scope
                    observed = (record['finished'] or record['started']) if matching else None
                    if (not cache['failed'] and (not history or not history['failures']) and
                            (observed is None or cache['updated'] > observed)):
                        # A manual refresh has no worker duration, but its scoped
                        # snapshot is newer than the previous worker observation.
                        row.update(last_run=timestamp(cache['updated']), duration=None, result='Completed',
                                   last_attempt_status='success')
                        if available:
                            row.update(status='success', label='Completed')
            if configured['seerr'] and row['id'] == 'seerr-availability':
                row['next_run'] = timestamp(availability['due']) if availability else None
                if available and availability and availability['failures'] and row['status'] != 'running':
                    row.update(status='failed', label='Retrying', result='Connection unavailable')
            if (available and row['id'] != 'seerr-availability' and
                    row['status'] in ('success', 'failed', 'waiting') and row['next_run']):
                due = datetime.fromisoformat(row['next_run']).timestamp()
                if now > due + max(90, intervals[row['id']] / 2):
                    row.update(status='stale', label='Overdue')
        for service, label in PROBES:
            job_id = 'probe-' + service
            fingerprint = connection_settings.connection_fingerprint(service, getter)
            record = records.get(job_id)
            if record and record.get('scope') != fingerprint:
                record = None
            row = self._row(job_id, label + ' connection',
                            'Check the saved connection without changing the service.', record, available)
            intervals[job_id] = self.interval(job_id, AUTO_INTERVALS[service])
            row['schedule'] = interval_label(intervals[job_id])
            if service == 'email' and not email:
                self._inactive(row, 'Disabled', 'Email is disabled')
            elif not configured[service]:
                self._inactive(row, 'Setup needed', 'Complete the connection settings first')
            else:
                check = checks.get(service)
                if (check and check['fingerprint'] == fingerprint and
                        (not record or record['status'] != 'running' and check['checked'] >= record['started'])):
                    row.update(last_run=timestamp(check['checked']), last_success=timestamp(check['last_success']),
                               next_run=timestamp(check['next_attempt']),
                               last_attempt_status='failed' if check['failures'] else 'success')
                    if check['failures']:
                        row.update(status='failed', label='Retrying', result='Connection unavailable')
                    elif now > check['next_attempt'] + max(90, intervals[job_id] / 2):
                        row.update(status='stale', label='Overdue', result='The next check is overdue')
                    else:
                        row.update(status='success', label='Healthy', result='The latest check passed')
                    if not available:
                        row.update(status='stale', label='Unavailable')
            job_rows.append(row)
        scopes = {'seerr-history': scope, 'seerr-availability': scope}
        scopes.update({'probe-' + service: connection_settings.connection_fingerprint(service, getter)
                       for service, _ in PROBES})
        pending = self.pending(scopes=scopes)
        for row in job_rows:
            disabled = row['status'] == 'disabled'
            queued = row['id'] in pending
            running = row['status'] == 'running'
            row.update(interval=intervals[row['id']] if row['id'] != 'seerr-availability' else None,
                       editable=row['id'] in EDITABLE_JOBS and not disabled,
                       queued=queued, can_run=available and not disabled and not queued and not running,
                       interval_options=list(INTERVAL_OPTIONS) if row['id'] in EDITABLE_JOBS else [])
            row['action_reason'] = (row['result'] if disabled else 'Already queued' if queued else
                                    'Already running' if running else
                                    'Jobs are temporarily unavailable' if not available else None)
            if queued and not disabled and not running:
                row.update(status='queued', label='Queued')
        return {'worker': worker, 'jobs': job_rows}

    @staticmethod
    def _inactive(row, label, result):
        row.update(status='disabled', label=label, result=result, next_run=None)

    @staticmethod
    def _row(job_id, title, description, record, available):
        row = {'id': job_id, 'title': title, 'description': description,
               'status': 'waiting', 'label': 'Not run yet', 'result': 'No recorded run',
               'last_run': None, 'last_success': None, 'next_run': None, 'duration': None,
               'last_attempt_status': None}
        if record:
            status = record['status']
            labels = {'running': 'Running', 'success': 'Completed', 'failed': 'Retrying',
                      'waiting': 'Waiting', 'review': 'Needs review', 'disabled': 'Disabled',
                      'interrupted': 'Interrupted'}
            row.update(status=status, label=labels.get(status, 'Unknown'), result=record['result'],
                       last_run=timestamp(record['finished']), last_success=timestamp(record['last_success']),
                       next_run=timestamp(record['next_run']))
            if record['finished'] is not None and status in RESULT_STATUSES:
                row['last_attempt_status'] = status
            if status != 'running' and record['duration'] is not None:
                row['duration'] = f"{record['duration']:.1f} seconds"
            if not available and status != 'disabled':
                row.update(status='stale', label='Interrupted' if status == 'running' else 'Unavailable')
                if status == 'running':
                    row.update(result='The job stopped before recording a result', duration=None)
        elif not available:
            row.update(status='stale', label='Unavailable')
        return row
