"""Bounded job observations for the owner workspace.

These records describe work performed by the existing worker. They do not
schedule or repeat it. Observation failures must never prevent the real work.
"""
from contextlib import closing
from datetime import datetime, timezone
import math
import os
import re
import sqlite3
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
JOB_IDS = frozenset(row[0] for row in JOBS)
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


class Store:
    def __init__(self, path, logger=None):
        self.path = path
        self.logger = logger
        self._initialized = False
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
        self._initialized = True

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
        with closing(sqlite3.connect(self.path, timeout=0.25)) as db, db:
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
        next_run = finished + interval if interval is not None and status != 'disabled' else None
        with closing(sqlite3.connect(self.path, timeout=0.25)) as db, db:
            db.execute('''UPDATE background_jobs SET finished=?,duration=?,status=?,result=?,
                last_success=CASE WHEN ?='success' THEN ? ELSE last_success END,next_run=?
                WHERE job_id=? AND run_token=?''',
                (finished, duration, status, result, status, finished, next_run, job_id, token))

    def run(self, job_id, callback, interval=30, result_fn=None, scope=None):
        if job_id not in JOB_IDS:
            raise ValueError('Unknown background job')
        if interval is not None and (type(interval) is not int or not 1 <= interval <= 7 * 86400):
            raise ValueError('Invalid background job interval')
        if scope is not None and (job_id not in ('seerr-availability', 'seerr-history') or
                                  not isinstance(scope, str) or not re.fullmatch('[0-9a-f]{64}', scope)):
            raise ValueError('Invalid background job scope')
        if not self._initialized:
            self._observe(self._initialize)
        token = uuid.uuid4().hex
        self._observe(lambda: self._start(job_id, token, time.time(), scope))
        clock_started = time.monotonic()
        try:
            result = callback()
        except BaseException:
            self._observe(lambda: self._finish(
                job_id, token, time.time(), max(0, time.monotonic() - clock_started),
                'failed', 'Failed; will retry', 30))
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
        return result

    def records(self):
        with closing(sqlite3.connect(self.path, timeout=0.25)) as db:
            db.row_factory = sqlite3.Row
            return {row['job_id']: dict(row) for row in db.execute('SELECT * FROM background_jobs')
                    if row['job_id'] in JOB_IDS}

    def interrupt_running(self):
        """Called once by the worker after it acquires its exclusive process lock."""
        def update():
            with closing(sqlite3.connect(self.path, timeout=0.25)) as db, db:
                db.execute("""UPDATE background_jobs SET status='interrupted',
                    result='Interrupted before completion',finished=NULL,duration=NULL,
                    next_run=NULL WHERE status='running'""")
        self._observe(update)

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
                    row['next_run'] = timestamp(cache['updated'] + seerr.REFRESH_INTERVAL)
                if cache:
                    row['last_success'] = timestamp(cache['updated'])
                    record = records.get('seerr-history')
                    matching = record and record.get('scope') == scope
                    observed = (record['finished'] or record['started']) if matching else None
                    if (not cache['failed'] and (not history or not history['failures']) and
                            (observed is None or cache['updated'] > observed)):
                        # A manual refresh has no worker duration, but its scoped
                        # snapshot is newer than the previous worker observation.
                        row.update(last_run=timestamp(cache['updated']), duration=None, result='Completed')
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
            row = self._row('probe-' + service, label + ' connection',
                            'Check the saved connection without changing the service.', None, available)
            row['schedule'] = interval_label(AUTO_INTERVALS[service])
            if service == 'email' and not email:
                self._inactive(row, 'Disabled', 'Email is disabled')
            elif not configured[service]:
                self._inactive(row, 'Setup needed', 'Complete the connection settings first')
            else:
                check = checks.get(service)
                if check and check['fingerprint'] == connection_settings.connection_fingerprint(service, getter):
                    row.update(last_run=timestamp(check['checked']), last_success=timestamp(check['last_success']),
                               next_run=timestamp(check['next_attempt']))
                    if check['failures']:
                        row.update(status='failed', label='Retrying', result='Connection unavailable')
                    elif now > check['next_attempt'] + max(90, AUTO_INTERVALS[service] / 2):
                        row.update(status='stale', label='Overdue', result='The next check is overdue')
                    else:
                        row.update(status='success', label='Healthy', result='The latest check passed')
                    if not available:
                        row.update(status='stale', label='Worker unavailable')
            job_rows.append(row)
        return {'worker': worker, 'jobs': job_rows}

    @staticmethod
    def _inactive(row, label, result):
        row.update(status='disabled', label=label, result=result, next_run=None)

    @staticmethod
    def _row(job_id, title, description, record, available):
        row = {'id': job_id, 'title': title, 'description': description,
               'status': 'waiting', 'label': 'Not run yet', 'result': 'No recorded run',
               'last_run': None, 'last_success': None, 'next_run': None, 'duration': None}
        if record:
            status = record['status']
            labels = {'running': 'Running', 'success': 'Completed', 'failed': 'Retrying',
                      'waiting': 'Waiting', 'review': 'Needs review', 'disabled': 'Disabled',
                      'interrupted': 'Interrupted'}
            row.update(status=status, label=labels.get(status, 'Unknown'), result=record['result'],
                       last_run=timestamp(record['finished']), last_success=timestamp(record['last_success']),
                       next_run=timestamp(record['next_run']))
            if status != 'running' and record['duration'] is not None:
                row['duration'] = f"{record['duration']:.1f} seconds"
            if not available and status != 'disabled':
                row.update(status='stale', label='Interrupted' if status == 'running' else 'Worker unavailable')
                if status == 'running':
                    row.update(result='The worker stopped before recording a result', duration=None)
        elif not available:
            row.update(status='stale', label='Worker unavailable')
        return row
