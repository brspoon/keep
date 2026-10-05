"""Shared connection settings with deliberate owner overrides for Plex."""
import os
import sqlite3
from contextlib import closing
import json
import re
import hashlib
import time
import ipaddress
from urllib.parse import urlsplit

CONNECTION_FIELDS = (
    'MAINTAINERR_URL', 'PLEX_SERVER_URL', 'PLEX_MACHINE_IDENTIFIER', 'PLEX_ADMIN_TOKEN',
    'RADARR_URL', 'RADARR_API_KEY', 'SONARR_URL', 'SONARR_API_KEY',
    'SEERR_URL', 'SEERR_API_KEY', 'TAUTULLI_URL', 'TAUTULLI_API_KEY',
)
EMAIL_FIELDS = ('EMAIL_ENABLED', 'SMTP_HOST', 'SMTP_PORT', 'SMTP_SECURITY', 'SMTP_USER', 'SMTP_PASSWORD', 'SMTP_FROM', 'SMTP_SENDER_NAME')
FIELDS = CONNECTION_FIELDS + EMAIL_FIELDS + ('KEEP_URL', 'KEEP_COLLECTIONS')
SECRETS = ('PLEX_ADMIN_TOKEN', 'RADARR_API_KEY', 'SONARR_API_KEY', 'SEERR_API_KEY', 'TAUTULLI_API_KEY', 'SMTP_PASSWORD')
PLEX_FIELDS = ('PLEX_SERVER_URL', 'PLEX_MACHINE_IDENTIFIER', 'PLEX_ADMIN_TOKEN')
SERVICE_FIELDS = {
    'plex': PLEX_FIELDS,
    'maintainerr': ('MAINTAINERR_URL',),
    'radarr': ('RADARR_URL', 'RADARR_API_KEY'),
    'sonarr': ('SONARR_URL', 'SONARR_API_KEY'),
    'seerr': ('SEERR_URL', 'SEERR_API_KEY'),
    'tautulli': ('TAUTULLI_URL', 'TAUTULLI_API_KEY'),
    'email': EMAIL_FIELDS,
}
AUTO_INTERVALS = {'plex': 3600, 'maintainerr': 900, 'radarr': 3600,
                  'sonarr': 3600, 'seerr': 900, 'tautulli': 3600, 'email': 86400}
SERVICE_URL_PORTS = {
    'PLEX_SERVER_URL': 32400, 'MAINTAINERR_URL': 6246, 'RADARR_URL': 7878,
    'SONARR_URL': 8989, 'SEERR_URL': 5055, 'TAUTULLI_URL': 8181,
}


def split_service_url(name, value):
    """Display saved addresses without replacing their effective HTTP(S) port."""
    if name not in SERVICE_URL_PORTS:
        raise ValueError('Unknown service address')
    if not value:
        return {'scheme': 'http', 'host': '', 'port': str(SERVICE_URL_PORTS[name]), 'path': ''}
    parsed = urlsplit(validate(name, value))
    return {'scheme': parsed.scheme, 'host': parsed.hostname,
            'port': str(parsed.port or (443 if parsed.scheme == 'https' else 80)),
            'path': parsed.path}


def service_url_from_form(name, form, saved_value=''):
    """Compose split controls; keep legacy forms and unchanged addresses intact."""
    if name not in SERVICE_URL_PORTS:
        raise ValueError('Unknown service address')
    if name + '_host' not in form:
        # Older clients send the complete URL. A blank legacy input kept its value.
        return form[name] if name in form and form[name].strip() else None
    values = {part: form.get(name + '_' + part, '') for part in ('scheme', 'host', 'port', 'path')}
    if any(not isinstance(value, str) or len(value) > 4096 or
           any(ord(char) < 32 or ord(char) == 127 for char in value)
           for value in values.values()):
        raise ValueError('Invalid service address')
    values = {part: value.strip() for part, value in values.items()}
    if not values['host']:
        return ''
    if values['scheme'] not in ('http', 'https'):
        raise ValueError('Choose HTTP or HTTPS')
    if not re.fullmatch(r'[0-9]{1,5}', values['port']) or not 1 <= int(values['port']) <= 65535:
        raise ValueError('Use a port between 1 and 65535')
    host = values['host']
    if host.startswith('[') and host.endswith(']'):
        host = host[1:-1]
    if ':' in host:
        try:
            ipaddress.IPv6Address(host)
        except ValueError:
            raise ValueError('Enter a hostname or IP address without a port') from None
        authority = '[' + host + ']'
    else:
        try:
            authority = host.encode('idna').decode('ascii')
        except UnicodeError:
            raise ValueError('Enter a valid hostname or IP address') from None
        if not re.fullmatch(r'[A-Za-z0-9_.-]+', authority):
            raise ValueError('Enter a hostname or IP address without a protocol or path')
    path = values['path']
    if path and not path.startswith('/'):
        path = '/' + path
    values.update(host=host, path=path.rstrip('/'), port=str(int(values['port'])))
    if saved_value and values == split_service_url(name, saved_value):
        return validate(name, saved_value)
    return validate(name, values['scheme'] + '://' + authority + ':' + values['port'] + path)


def connection_open_services(form, action=None):
    """Disclosure state contains only bounded service IDs, never settings."""
    if 'open_services' in form:
        value = form.get('open_services', '')
        if not isinstance(value, str) or len(value) > 128:
            return set()
        return set(value.split(',')) & SERVICE_FIELDS.keys()
    action = action or form.get('action', '')
    service = {'smtp': 'email', 'discover-collections': 'maintainerr',
               'collections': 'maintainerr', 'refresh-seerr': 'seerr',
               'link-seerr': 'seerr', 'save-seerr-links': 'seerr'}.get(action, action)
    if service.startswith('save-'):
        service = service.removeprefix('save-')
    return {service} if service in SERVICE_FIELDS else set()


def validate(name, value):
    if name not in FIELDS or not isinstance(value, str):
        raise ValueError('Unknown setting')
    if len(value) > 4096 or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError('Invalid setting value')
    if name not in SECRETS:
        value = value.strip()
    if name == 'KEEP_COLLECTIONS':
        try:
            parsed = json.loads(value)
        except (ValueError, TypeError):
            raise ValueError('Collections must be a JSON object') from None
        if not isinstance(parsed, dict) or len(parsed) > 200:
            raise ValueError('Invalid collections')
        for key, label in parsed.items():
            if (not re.fullmatch(r'[1-9][0-9]{0,8}', key) or
                    not isinstance(label, str) or not label.strip() or len(label) > 200 or
                    any(ord(c) < 32 for c in label)):
                raise ValueError('Invalid collection ID or label')
        return json.dumps(parsed, sort_keys=True)
    if name == 'EMAIL_ENABLED' and value not in ('true', 'false'):
        raise ValueError('Email enabled must be true or false')
    if name == 'SMTP_PORT' and (not value.isdigit() or not 1 <= int(value) <= 65535):
        raise ValueError('Invalid SMTP port')
    if name == 'SMTP_SECURITY' and value not in ('ssl', 'starttls'):
        raise ValueError('Choose ssl or starttls')
    if name == 'SMTP_FROM' and value and not re.fullmatch(r'[^@\s<>]+@[^@\s<>]+\.[^@\s<>]+', value):
        raise ValueError('Invalid sender address')
    if name == 'SMTP_HOST' and value and not re.fullmatch(r'[A-Za-z0-9.:-]+', value):
        raise ValueError('Invalid SMTP hostname')
    if name.endswith('_URL'):
        if name in SERVICE_URL_PORTS and not value:
            return ''
        try:
            url = urlsplit(value)
            port = url.port
        except ValueError:
            raise ValueError('Invalid service URL') from None
        if (url.scheme not in ('http', 'https') or not url.hostname or
                url.username is not None or url.password is not None or
                url.query or url.fragment or '\\' in value or ' ' in value or
                port is not None and not 1 <= port <= 65535):
            raise ValueError('Use an HTTP or HTTPS URL without credentials, query or fragment')
        value = value.rstrip('/')
    elif name == 'PLEX_MACHINE_IDENTIFIER' and not value:
        raise ValueError('Plex machine identifier is required')
    return value


class ConnectionSettings:
    def __init__(self, path):
        self.path = path
        with closing(sqlite3.connect(path)) as db, db:
            db.execute("BEGIN IMMEDIATE")
            legacy = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='user_profiles'").fetchone()
            ready = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='portable_configuration'").fetchone()
            if legacy and not ready:
                raise RuntimeError('Run scripts/migrate_configuration.py against the backed-up legacy configuration before starting this release')
            db.execute('CREATE TABLE IF NOT EXISTS portable_configuration (version INTEGER NOT NULL)')
            if not ready:
                db.execute('INSERT INTO portable_configuration VALUES (1)')
            db.execute('CREATE TABLE IF NOT EXISTS connection_settings (name TEXT PRIMARY KEY, value TEXT NOT NULL)')
            # Legacy saved values may have been ignored by deployment overrides.
            # They become authoritative only after an explicit owner Save/Connect.
            db.execute("""CREATE TABLE IF NOT EXISTS plex_connection_overrides (
                name TEXT PRIMARY KEY CHECK(name IN
                ('PLEX_SERVER_URL', 'PLEX_MACHINE_IDENTIFIER', 'PLEX_ADMIN_TOKEN')))
            """)
            db.execute('CREATE TABLE IF NOT EXISTS connection_checks (service TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, passed INTEGER NOT NULL, checked REAL NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS automatic_connection_checks (service TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, checked REAL NOT NULL, last_success REAL, failures INTEGER NOT NULL, next_attempt REAL NOT NULL)')

    def connection_fingerprint(self, service, getter):
        values = [getter(name) for name in SERVICE_FIELDS[service]]
        return hashlib.sha256(json.dumps(values).encode()).hexdigest()

    def record_check(self, service, fingerprint, passed):
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute('INSERT OR REPLACE INTO connection_checks VALUES (?, ?, ?, ?)',
                       (service, fingerprint, int(passed), time.time()))

    @staticmethod
    def configured(service, getter):
        if service == 'email':
            return str(getter('EMAIL_ENABLED')).lower() == 'true' and all(
                getter(name) for name in ('SMTP_HOST', 'SMTP_PORT', 'SMTP_SECURITY'))
        return all(getter(name) for name in SERVICE_FIELDS[service])

    def automatic_due(self, service, getter, now=None):
        if not self.configured(service, getter):
            return False
        now = time.time() if now is None else now
        fingerprint = self.connection_fingerprint(service, getter)
        with closing(sqlite3.connect(self.path)) as db:
            row = db.execute('SELECT fingerprint,checked,next_attempt FROM automatic_connection_checks WHERE service=?',
                             (service,)).fetchone()
            if not row or row[0] != fingerprint or now >= row[2]:
                return True
            try:
                observed = db.execute('''SELECT scope,started,next_run FROM background_jobs
                    WHERE job_id=? AND status='failed' ''', ('probe-' + service,)).fetchone()
            except sqlite3.OperationalError:
                # Older installs may not have job observations yet.
                return False
        # A failed native write leaves an older canonical schedule. Retry only
        # that probe; genuine recorded failures keep their native backoff.
        return bool(observed and observed[0] == fingerprint and row[1] < observed[1] and
                    observed[2] is not None and now >= observed[2])

    def automatic_interval(self, service, db=None):
        """Use a saved Jobs cadence; older databases retain the service default."""
        import background_jobs
        try:
            if db is None:
                with closing(sqlite3.connect(self.path, timeout=0.25)) as connection:
                    return self.automatic_interval(service, connection)
            row = db.execute('SELECT interval_seconds FROM background_job_settings WHERE job_id=?',
                             ('probe-' + service,)).fetchone()
            if row and row[0] in background_jobs.INTERVAL_SECONDS:
                return row[0]
        except sqlite3.Error:
            pass
        return AUTO_INTERVALS[service]

    def record_automatic_check(self, service, fingerprint, passed, now=None):
        now = time.time() if now is None else now
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute('BEGIN IMMEDIATE')
            previous = db.execute('SELECT fingerprint,last_success,failures FROM automatic_connection_checks WHERE service=?',
                                  (service,)).fetchone()
            matching = previous and previous[0] == fingerprint
            last_success = now if passed else (previous[1] if matching else None)
            failures = 0 if passed else (previous[2] if matching else 0) + 1
            interval = self.automatic_interval(service, db)
            next_attempt = now + (interval if passed else min(300, interval))
            db.execute('INSERT OR REPLACE INTO automatic_connection_checks VALUES (?,?,?,?,?,?)',
                       (service, fingerprint, now, last_success, failures, next_attempt))
        return (previous[2] if matching else 0), failures

    def automatic_states(self, getter, now=None):
        from datetime import datetime, timezone
        now = time.time() if now is None else now
        with closing(sqlite3.connect(self.path)) as db:
            checks = {row[0]: row[1:] for row in db.execute('SELECT * FROM automatic_connection_checks')}
        states = {}
        for service in SERVICE_FIELDS:
            if service == 'email' and str(getter('EMAIL_ENABLED')).lower() != 'true':
                state = {'kind': 'unknown', 'label': 'Disabled', 'detail': 'Email delivery is turned off.'}
            elif not self.configured(service, getter):
                state = {'kind': 'unknown', 'label': 'Setup needed', 'detail': 'Complete the connection settings first.'}
            elif service not in checks or checks[service][0] != self.connection_fingerprint(service, getter):
                state = {'kind': 'unknown', 'label': 'Pending', 'detail': 'The background worker has not checked these settings yet.'}
            else:
                _, checked, last_success, failures, next_attempt = checks[service]
                tested = datetime.fromtimestamp(checked, timezone.utc)
                overdue = now > next_attempt + max(90, self.automatic_interval(service) / 2)
                if failures >= 2:
                    kind, label, detail = 'error', 'Needs attention', 'Repeated automatic checks failed; the service may be unavailable.'
                elif overdue:
                    kind, label, detail = 'error', 'Overdue', 'The background check is overdue. Check the worker and service.'
                elif failures:
                    kind, label, detail = 'warning', 'Retrying', 'One automatic check failed; Keep will retry.'
                else:
                    kind, label, detail = 'success', 'Healthy', 'The latest automatic check passed.'
                state = {'kind': kind, 'label': label, 'detail': detail,
                         'checked_at': tested.strftime('%Y-%m-%d %H:%M UTC'),
                         'checked_at_iso': tested.isoformat(),
                         'last_success': datetime.fromtimestamp(last_success, timezone.utc).strftime('%Y-%m-%d %H:%M UTC') if last_success else None}
            states[service] = state
        return states

    def check_states(self, getter):
        from datetime import datetime, timezone
        with closing(sqlite3.connect(self.path)) as db:
            checks = {row[0]: row[1:] for row in db.execute('SELECT * FROM connection_checks')}
        states = {}
        for service in SERVICE_FIELDS:
            state = {'kind': 'unknown', 'label': 'Not checked', 'detail': 'Use Test to check the saved connection.'}
            required = SERVICE_FIELDS[service] if service != 'email' else ('SMTP_HOST',)
            if service == 'email' and str(getter('EMAIL_ENABLED')).lower() != 'true':
                state = {'kind': 'unknown', 'label': 'Email disabled', 'detail': 'Email delivery is turned off.'}
            elif not all(getter(name) for name in required):
                state = {'kind': 'unknown', 'label': 'Setup needed', 'detail': 'Complete the connection settings first.'}
            elif service in checks:
                fingerprint, passed, checked = checks[service]
                if fingerprint == self.connection_fingerprint(service, getter):
                    tested = datetime.fromtimestamp(checked, timezone.utc)
                    stamp = tested.strftime('%Y-%m-%d %H:%M UTC')
                    state = {'kind': 'success' if passed else 'error',
                             'label': 'Last test passed' if passed else 'Last test failed',
                             'tested_at': stamp,
                             'tested_at_iso': tested.isoformat(),
                             'detail': 'This is the last manual test result, not continuous monitoring.'}
                else:
                    state['label'] = 'Settings changed · test again'
            states[service] = state
        return states

    def get(self, name, fallback=''):
        if name in os.environ and name not in PLEX_FIELDS:
            return validate(name, os.environ[name])
        with closing(sqlite3.connect(self.path)) as db, db:
            row = db.execute('''SELECT value, EXISTS(
                SELECT 1 FROM plex_connection_overrides WHERE name=connection_settings.name)
                FROM connection_settings WHERE name=?''', (name,)).fetchone()
        override = name in PLEX_FIELDS and row and row[1]
        if not override and name in os.environ:
            return validate(name, os.environ[name])
        return validate(name, row[0]) if row else fallback

    def snapshot(self):
        with closing(sqlite3.connect(self.path)) as db, db:
            rows = db.execute('''SELECT setting.name, setting.value, marker.name IS NOT NULL
                FROM connection_settings setting LEFT JOIN plex_connection_overrides marker
                ON marker.name=setting.name''').fetchall()
        values = {name: value for name, value, override in rows}
        overrides = {name for name, value, override in rows if override and name in PLEX_FIELDS}
        for name in FIELDS:
            if name in os.environ and name not in overrides:
                values[name] = os.environ[name]
        return {name: validate(name, value) for name, value in values.items() if name in FIELDS}

    def save(self, values, *, clear=(), plex_override=False):
        clear = set(clear)
        editable = set(PLEX_FIELDS) if plex_override else set()
        if any(name not in SECRETS or name in os.environ and name not in editable
               for name in clear) or clear.intersection(values):
            raise ValueError('Invalid credential clearing request')
        clean = {}
        for name, value in values.items():
            if name in os.environ and name not in editable:
                raise ValueError('Environment-managed settings cannot be changed here')
            if name in SECRETS and not value:
                continue
            clean[name] = validate(name, value)
        # An explicitly cleared Plex credential must not fall back to an env token.
        clean.update({name: '' for name in clear if name in PLEX_FIELDS})
        with closing(sqlite3.connect(self.path)) as db, db:
            db.executemany('DELETE FROM connection_settings WHERE name=?',
                           ((name,) for name in clear if name not in PLEX_FIELDS))
            db.executemany('INSERT INTO connection_settings VALUES (?, ?) ON CONFLICT(name) DO UPDATE SET value=excluded.value', clean.items())
            db.executemany('INSERT OR IGNORE INTO plex_connection_overrides VALUES (?)',
                           ((name,) for name in clean if name in editable))
