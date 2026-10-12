"""Worker integration for durable notifications without importing the Flask app.

Helpers read saved preferences and effective settings afresh. Delivery and
recovery are explicit worker operations; constructing this adapter sends
nothing and does not create or change any database tables.
"""
from collections.abc import Mapping
from contextlib import closing
from dataclasses import dataclass, field
from html import escape
import math
from pathlib import Path
import sqlite3
import time
from urllib.parse import urlsplit

import background_jobs
import notifications
import pushover


CONNECTION_LABELS = {
    'plex': 'Plex', 'maintainerr': 'Maintainerr', 'radarr': 'Radarr',
    'sonarr': 'Sonarr', 'seerr': 'Seerr', 'tautulli': 'Tautulli',
    'email': 'Email', 'pushover': 'Pushover',
}
JOB_LABELS = {row[0]: row[1] for row in background_jobs.JOBS}
SELF_JOBS = frozenset(('email-digest', 'notification-delivery', 'notification-digest'))


@dataclass(frozen=True)
class Helpers:
    store: object
    settings: object
    collections: object
    # Include enabled recipients with an empty collection set for owner alerts.
    # Original saved address spelling is retained for the SMTP recipient.
    email_preferences: object
    email_enabled: object
    value: object
    reconcile: object
    resolve: object
    build_email: object
    # The app supplies its fresh SMTP-settings wrapper, not a stale pass snapshot.
    send_email: object
    send_push: object = None
    build_event_email: object = None


@dataclass(frozen=True)
class Message:
    subject: str = field(repr=False)
    text: str = field(repr=False)
    html: str = field(default='', repr=False)
    url: str = field(default='', repr=False)


def _email_id(address):
    if (not isinstance(address, str) or not 1 <= len(address) <= 256
            or any(ord(char) < 32 or ord(char) == 127 for char in address)):
        raise ValueError('Invalid notification recipient')
    return address.strip().casefold()


def _link(value):
    if not value:
        return ''
    if (not isinstance(value, str) or len(value) > 4096
            or any(ord(char) < 32 or ord(char) == 127 for char in value)):
        raise ValueError('Keep URL is unavailable')
    try:
        parsed = urlsplit(value)
        valid = parsed.scheme in ('http', 'https') and parsed.hostname and not parsed.username and not parsed.password
    except ValueError:
        valid = False
    if not valid:
        raise ValueError('Keep URL is unavailable')
    return value


def _observed_time(value, now):
    return (type(value) in (int, float) and math.isfinite(value)
            and 0 <= value <= now + 30)


def recorded_connections(path):
    """Read existing canonical probe observations without schema or HTTP work."""
    path = Path(path)
    try:
        path.stat()
    except FileNotFoundError:
        return {}
    with closing(sqlite3.connect(path.absolute().as_uri() + '?mode=ro', uri=True, timeout=0.25)) as db:
        db.row_factory = sqlite3.Row
        if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='automatic_connection_checks'").fetchone():
            return {}
        return {row['service']: dict(row) for row in db.execute('SELECT * FROM automatic_connection_checks')
                if row['service'] in notifications.CONNECTIONS}


class Runtime:
    def __init__(self, helpers):
        self.helpers = helpers

    def enabled_providers(self):
        providers = {'email'} if self.helpers.email_enabled() else set()
        try:
            ready = self.helpers.settings().installation_view()['ready']
        except ValueError:
            # A malformed environment-managed push setting must not stop email.
            ready = False
        if ready:
            providers.add('pushover')
        return providers

    def _emails(self, collections):
        preferences = self.helpers.email_preferences()
        if not isinstance(preferences, Mapping):
            raise ValueError('Notification recipient preferences are unavailable')
        grouped = {}
        for address, selected in sorted(preferences.items(), key=lambda item: (item[0].casefold(), item[0])):
            identity = _email_id(address)
            if not identity:
                raise ValueError('Invalid notification recipient')
            chosen = {cid for cid in selected if type(cid) is int and cid > 0 and cid in collections}
            if identity in grouped:
                grouped[identity][1].update(chosen)
            else:
                grouped[identity] = (address, chosen)
        return grouped

    def _email_target(self, identity, selected):
        metadata = self.helpers.settings().email_event_preferences(identity)
        return notifications.Destination('email', identity, metadata['generation'],
            frozenset(selected), metadata['events'], owner_verified=metadata['owner_verified'])

    def destinations(self):
        collections = frozenset(self.helpers.collections())
        email = [self._email_target(identity, selected)
                 for identity, (_, selected) in self._emails(collections).items()]
        try:
            push = self.helpers.settings().destinations(available_collections=collections)
        except ValueError:
            push = []
        return email + list(push)

    def _url(self):
        return _link(self.helpers.value('KEEP_URL'))

    def render(self, target, items):
        url = self._url()
        if target.provider == 'email':
            if not url:
                raise ValueError('Digest needs Keep URL')
            subject, html, text = self.helpers.build_email(items, url)
            return Message(subject, text, html, url)
        return Message('Keep', pushover.digest_message(items), url=url if len(url) <= 512 else '')

    def render_event(self, target, event):
        kind = event['kind']
        if kind == 'UPDATE_AVAILABLE':
            version = event.get('version')
            if not isinstance(version, str) or not notifications.STABLE_VERSION.fullmatch(version):
                raise ValueError('Invalid recorded release')
            subject, text = 'Keep update available', f'Keep {version} is available. Open About to review the release.'
        elif kind in ('CONNECTION_FAILED', 'CONNECTION_RESTORED'):
            label = CONNECTION_LABELS[event['entity']]
            restored = kind == 'CONNECTION_RESTORED'
            subject = f'Keep: {label} connection ' + ('restored' if restored else 'unavailable')
            text = f'{label} connection ' + ('is working again.' if restored else 'needs attention. Open Notifications or Connections to review its status.')
        elif kind in ('JOB_FAILED', 'JOB_RESTORED'):
            label = JOB_LABELS[event['entity']]
            restored = kind == 'JOB_RESTORED'
            subject = f'Keep: {label} ' + ('recovered' if restored else 'needs attention')
            text = f'{label} ' + ('completed successfully again.' if restored else 'needs attention. Open Jobs to review its status.')
        else:
            raise ValueError('Invalid recorded notification event')
        url = self._url()
        if target.provider == 'email' and self.helpers.build_event_email is not None:
            subject, html, text = self.helpers.build_event_email(subject, text, url)
            return Message(subject, text, html, url)
        html = '<p>' + escape(text) + '</p>'
        if url:
            html += '<p><a href="' + escape(url, quote=True) + '">Open Keep</a></p>'
        return Message(subject, text, html, url if target.provider == 'email' or len(url) <= 512 else '')

    def send(self, target, message):
        if target.provider not in self.enabled_providers():
            return notifications.Outcome('cancelled', 'preferences_changed')
        collections = frozenset(self.helpers.collections())
        if target.provider == 'email':
            saved = self._emails(collections).get(target.id)
            if not saved or self._email_target(target.id, saved[1]) != target:
                return notifications.Outcome('cancelled', 'preferences_changed')
            self.helpers.send_email([saved[0]], message.subject, message.html, message.text)
            return notifications.Outcome('accepted')
        credentials = self.helpers.settings().sending_credentials(target, available_collections=collections)
        if credentials is None:
            return notifications.Outcome('cancelled', 'preferences_changed')
        sender = self.helpers.send_push or pushover.send
        result = sender(credentials.app_token, credentials.user_key, message.text,
            title=message.subject, device=credentials.device, url=message.url)
        return notifications.Outcome(result.state, result.code, result.request_id, result.retry_at)

    def callbacks(self):
        return notifications.Callbacks(self.enabled_providers, self.destinations,
            self.helpers.resolve, self.render, self.send, self.render_event)

    def recover_after_lock(self, *, now=None):
        """Once after the existing worker lock, never during a web request."""
        now = time.time() if now is None else now
        try:
            self.helpers.settings().synchronize(now=now)
        except ValueError:
            pass
        store = self.helpers.store()
        migrated = store.migrate_legacy(self.destinations(), now=now)
        interrupted = store.recover_interrupted()
        return {'migrated': migrated, 'interrupted': interrupted}

    def process_digest(self, *, now=None, quiet_seconds=600):
        """Keep the app's string results and propagate reconciliation failures."""
        now = time.time() if now is None else now
        store, callbacks = self.helpers.store(), self.callbacks()
        if self.enabled_providers():
            try:
                self.helpers.reconcile()
            except Exception:
                # Operational delivery is independent of private upstream media
                # availability. Never claim or settle unreconciled media here.
                try:
                    store.process(callbacks, now=now, quiet_seconds=quiet_seconds, include_media=False)
                except Exception:
                    # Preserve the original reconciliation error for native job
                    # reporting. Durable operational work remains for next pass.
                    pass
                raise
        return store.process(callbacks, now=now, quiet_seconds=quiet_seconds)['state']

    def process_operational(self, *, now=None):
        return self.helpers.store().process(self.callbacks(), now=now, include_media=False)['state']

    def observe_recorded(self, *, connections, jobs, releases, current_connection_scopes,
                         current_job_scopes, now=None, excluded_job_ids=SELF_JOBS):
        """Record fixed, sanitized transitions from worker observations only.

        Scope maps contain only currently configured services/jobs. Connection
        scopes are effective credential fingerprints; Seerr job scopes are its
        active namespace. General job scopes use None, matching native records.
        No connection probe, release lookup or private service request is made.
        """
        now = time.time() if now is None else now
        store, count = self.helpers.store(), 0
        for service, scope in current_connection_scopes.items():
            row = connections.get(service)
            if (service not in notifications.CONNECTIONS or not isinstance(scope, str)
                    or not 1 <= len(scope) <= 128 or not isinstance(row, Mapping)
                    or row.get('fingerprint') != scope or not _observed_time(row.get('checked'), now)
                    or type(row.get('failures')) is not int or row['failures'] < 0):
                continue
            # Connections displays one failure as Retrying. Leave any prior
            # failed episode in place until a definite successful check, and
            # alert only after the same repeated-failure threshold as the UI.
            if row['failures'] == 1:
                continue
            count += bool(store.observe_connection(service, 'failed' if row['failures'] else 'healthy', scope=scope, now=now))
        for job_id, scope in current_job_scopes.items():
            row = jobs.get(job_id)
            if (job_id not in background_jobs.JOB_IDS or job_id in excluded_job_ids
                    or job_id.startswith('probe-') or job_id == 'connection-monitor'
                    or not isinstance(row, Mapping) or (row.get('scope') or None) != (scope or None)
                    or scope is not None and (not isinstance(scope, str) or len(scope) > 128)
                    or not _observed_time(row.get('finished'), now)
                    or row.get('status') not in ('success', 'failed', 'review')):
                continue
            count += bool(store.observe_job(job_id, 'healthy' if row['status'] == 'success' else 'failed',
                scope=scope or '', allowed_job_ids=background_jobs.JOB_IDS, now=now))
        if (isinstance(releases, Mapping) and releases.get('status') == 'success'
                and releases.get('stale') is False and releases.get('comparison') == 'update_available'
                and releases.get('update_available') is True
                and isinstance(releases.get('latest_version'), str)
                and notifications.STABLE_VERSION.fullmatch(releases['latest_version'])):
            count += bool(store.observe_update(releases['latest_version'], now=now))
        return count
