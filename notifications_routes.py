"""Owner notification controls and saved-own-credential test actions.

The adapter keeps Flask application helpers out of this module. Its callbacks
are require_owner, require_csrf, current_account_session, actor, settings_store,
core_store, db, collections, csrf_token, log_activity, send_email_test and
send_push_test. It also supplies connections and quiet_seconds. Sender callbacks
accept only a freshly read saved address or Credentials object, and send the
application's fixed test notification. Neither accepts request form data.
"""
from contextlib import closing
from datetime import datetime, timezone
import math
import os
import re
import sqlite3
import time

from flask import redirect, render_template, request, session

import notifications
import pushover


EVENT_LABELS = {
    notifications.ADDED: 'Leaving summaries',
    notifications.REMINDER: 'Seven-day reminders',
    'CONNECTION_FAILED': 'Connection failures',
    'CONNECTION_RESTORED': 'Connection recovery',
    'JOB_FAILED': 'Job failures',
    'JOB_RESTORED': 'Job recovery',
    'UPDATE_AVAILABLE': 'Keep updates',
}
NOTICES = {
    'recipient': 'Recipient settings saved.',
    'subscriptions': 'Email collection preferences saved.',
}
STATE_LABELS = {
    'pending': ('Pending', 'neutral'), 'reserved': ('Sending', 'neutral'),
    'sending': ('Sending', 'neutral'), 'accepted': ('Sent', 'success'),
    'retry': ('Waiting to retry', 'neutral'), 'rejected': ('Delivery failed', 'error'),
    'review': ('Delivery needs review', 'warning'), 'cancelled': ('Discarded', 'neutral'),
}
STORAGE_ERROR = 'Keep could not read notification settings. Try again shortly.'
ACCESS_ERROR = 'Your account is unavailable. Sign in again.'
TEST_ID = re.compile(r'[0-9a-f]{32}\Z')


class Routes:
    def __init__(self, app, adapter):
        self.app, self.adapter = app, adapter

    def now(self):
        return getattr(self.adapter, 'now', time.time)()

    def _response(self, value, status=200):
        response = self.app.make_response((value, status))
        response.headers['Cache-Control'] = 'no-store'
        return response

    def _guard(self, *, owner=False, csrf=False):
        try:
            if not self.adapter.current_account_session():
                return self._response(ACCESS_ERROR, 403)
        except (sqlite3.Error, OSError):
            return self._response(STORAGE_ERROR, 503)
        if owner:
            denied = self.adapter.require_owner()
            if denied:
                response = self.app.make_response(denied)
                response.headers['Cache-Control'] = 'no-store'
                return response
            try:
                view = self._settings().preferences_view(self.adapter.actor(), available_collections=())
                if not view['owner_events_available']:
                    return self._response('Only the Keep owner can manage notifications.', 403)
            except PermissionError:
                return self._response(ACCESS_ERROR, 403)
            except (sqlite3.Error, OSError, ValueError):
                return self._response(STORAGE_ERROR, 503)
        if csrf:
            denied = self.adapter.require_csrf()
            if denied:
                response = self.app.make_response(denied)
                response.headers['Cache-Control'] = 'no-store'
                return response
        return None

    def _settings(self, *, initialize=False):
        return self.adapter.settings_store(initialize=initialize)

    def _core(self, *, read_only=True):
        return self.adapter.core_store(read_only=read_only)

    def _redirect(self, message):
        session['notifications_notice'] = message
        response = redirect('/settings/notifications', code=303)
        response.headers['Cache-Control'] = 'no-store'
        return response

    def _when(self, value):
        if type(value) not in (int, float) or not math.isfinite(value):
            return 'Not attempted'
        try:
            moment = datetime.fromtimestamp(value, timezone.utc)
        except (ValueError, OSError, OverflowError):
            return 'Unknown'
        return moment.strftime('%Y-%m-%d %H:%M UTC')

    def _test_available(self, settings, actor, kind, configured):
        if not configured:
            return False, 'Save the required notification settings first.'
        view = settings.test_availability(actor, kind, now=self.now())
        return view['can_test'], {
            'unconfigured': 'Save the required notification settings first.',
            'review': 'A previous test delivery needs review.',
            'cooldown': 'Wait briefly before testing again.',
            'quota': 'Pushover is temporarily unavailable. Try again later.',
            'busy': 'A notification test is already running.',
        }.get(view['state'], '')

    def _email_installation(self, settings, actor):
        connections = self.adapter.connections
        enabled = connections.get('EMAIL_ENABLED', 'false') == 'true'
        configured = bool(connections.get('SMTP_HOST') and connections.get('SMTP_FROM'))
        address = settings.email_test_recipient(actor)
        available, reason = self._test_available(settings, actor, 'email', enabled and configured and bool(address))
        if not enabled:
            reason = 'Enable email notifications before testing.'
        elif not configured:
            reason = 'Set up SMTP in Connections.'
        elif not address:
            reason = 'Add your account email to the email recipients.'
        return {'enabled': enabled, 'configured': configured,
                'managed': 'EMAIL_ENABLED' in os.environ,
                'can_test': available, 'test_reason': reason}

    def preferences_context(self, email_address=''):
        """Email choices for full-page and fragment Preferences rendering."""
        settings, actor = self._settings(), self.adapter.actor()
        with closing(self.adapter.db()) as db:
            _, owner = settings.validate_actor(actor, db)
        allowed = notifications.EVENTS if owner else notifications.MEDIA_EVENTS
        email_events = (settings.email_event_preferences(email_address)['events'] if email_address else notifications.MEDIA_EVENTS) & allowed
        return {'email_events': set(email_events), 'event_labels': EVENT_LABELS}

    def pushover_context(self):
        """Saved owner delivery settings, shown only in Admin Notifications."""
        settings, actor = self._settings(), self.adapter.actor()
        collections = self.adapter.collections()
        view = settings.preferences_view(actor, available_collections=collections)
        tests = settings.test_views(actor)
        installation = settings.installation_view()
        if installation['configuration_error']:
            view['can_test'], view['test_reason'] = False, 'Pushover is unavailable. Check the provider settings.'
        else:
            view['can_test'], view['test_reason'] = self._test_available(
                settings, actor, 'notification', view['configured'] and installation['configured'])
        reviews = [self._test_row(row, actor.user_id) for row in tests
                   if row['kind'] == 'notification' and (row['state'] == 'review' or
                       row['state'] == 'reserved' and self.now() - row['reserved_at'] > pushover.REQUEST_BUDGET + 30)]
        for row in reviews:
            row.pop('_time', None)
        return {'push_preferences': view, 'event_labels': EVENT_LABELS, 'test_reviews': reviews}

    def _recipients(self):
        with closing(self.adapter.db()) as db:
            recipients = [dict(row) for row in db.execute('SELECT email,enabled FROM email_recipients ORDER BY email COLLATE NOCASE')]
            profiles = [dict(row) for row in db.execute('SELECT plex_id,email,full_name,display_name,plex_username FROM user_profiles')]
            subscriptions = {}
            for row in db.execute('SELECT email,collection_id FROM recipient_subscriptions WHERE enabled=1'):
                subscriptions.setdefault(row['email'].strip().casefold(), set()).add(row['collection_id'])
            pending = db.execute('SELECT COUNT(*) FROM notification_queue').fetchone()[0]
            newest = db.execute('SELECT MAX(received_at) FROM notification_queue WHERE batch_id IS NULL').fetchone()[0]
            held = db.execute("SELECT COUNT(*) FROM notification_batches WHERE status='review'").fetchone()[0]
        for recipient in recipients:
            address = recipient['email'].strip().casefold()
            names, aliases = {}, []
            for profile in profiles:
                if (profile['email'] or '').strip().casefold() != address:
                    continue
                values = [(profile[name] or '').strip() for name in ('full_name', 'display_name', 'plex_username') if (profile[name] or '').strip()]
                if values:
                    names.setdefault(values[0].casefold(), values[0])
                    aliases.extend(values)
            recipient.update(names=list(names.values()), search_text=' '.join([recipient['email'], *aliases]),
                             subscriptions=subscriptions.get(address, set()))
        remaining = max(0, math.ceil(newest + self.adapter.quiet_seconds - self.now())) if newest is not None else None
        due_text = ('No email pending' if remaining is None else 'Sending soon' if remaining == 0
                    else f'About {(remaining + 59) // 60} min remaining')
        return {'recipients': recipients, 'pending': pending, 'held': held, 'due_text': due_text,
                'active_recipients': sum(bool(row['enabled']) for row in recipients)}, profiles

    def _delivery_rows(self, profiles, tests, actor):
        names = {row['plex_id']: row['display_name'] or row['full_name'] or row['plex_username'] or 'Keep user'
                 for row in profiles}
        rows = []
        for row in self._core().snapshot(limit=100):
            label, tone = STATE_LABELS.get(row['state'], STATE_LABELS['review'])
            destination = ('Legacy email delivery' if row['destination_id'] == 'legacy-held' else
                           names.get(row['destination_id'], 'Former user') if row['provider'] == 'pushover' else row['destination_id'])
            rows.append({'batch_id': row['batch_id'], 'provider': row['provider'],
                         'destination_id': row['destination_id'], 'destination': destination,
                         'label': label, 'tone': tone, 'when': self._when(row['accepted_at'] or row['last_attempt']),
                         'event_label': EVENT_LABELS.get(row['event_kind'], 'Leaving summary'),
                         'review_needed': row['state'] in ('review', 'rejected'),
                         'can_retry': row['destination_id'] != 'legacy-held',
                         'request_id': row['request_id'], '_time': row['accepted_at'] or row['last_attempt'] or 0})
        rows.extend(self._test_row(row, actor.user_id) for row in tests if row['kind'] in ('email', 'notification'))
        rows.sort(key=lambda row: row['_time'], reverse=True)
        for row in rows:
            row.pop('_time', None)
        return rows[:100]

    def _test_row(self, row, user_id):
        state = row['state']
        if state == 'reserved' and self.now() - row['reserved_at'] > pushover.REQUEST_BUDGET + 30:
            state = 'review'
        label, tone = STATE_LABELS.get(state, STATE_LABELS['review'])
        return {'batch_id': 'test:' + row['id'], 'provider': 'email' if row['kind'] == 'email' else 'pushover',
                'destination_id': user_id, 'destination': 'Your account', 'label': label, 'tone': tone,
                'when': self._when(row['finished_at'] or row['reserved_at']), 'event_label': 'Test notification',
                'review_needed': state == 'review', 'can_retry': False, 'request_id': row['request_id'],
                '_time': row['finished_at'] or row['reserved_at']}

    def render_page(self, *, error=None, status=200, expanded_recipient='', new_recipient_email=''):
        denied = self._guard(owner=True)
        if denied:
            return denied
        try:
            settings, actor = self._settings(), self.adapter.actor()
            context, profiles = self._recipients()
            tests = settings.test_views(actor)
            push = self.pushover_context()
            context.update(push, pushover_installation=settings.installation_view(), owner_push=push['push_preferences'],
                           email_installation=self._email_installation(settings, actor),
                           delivery_rows=self._delivery_rows(profiles, tests, actor))
        except PermissionError:
            return self._response(ACCESS_ERROR, 403)
        except (sqlite3.Error, OSError, ValueError):
            return self._response(STORAGE_ERROR, 503)
        notice = session.pop('notifications_notice', None) or NOTICES.get(session.pop('settings_notice', None))
        context.update(section='notifications', admin_active_path='/settings/notifications',
                       collections=self.adapter.collections(), csrf_token=self.adapter.csrf_token(),
                       notice=notice if not error else None,
                       settings_error=error or session.pop('settings_error', None),
                       settings_error_email=session.pop('settings_error_email', ''),
                       expanded_recipient=expanded_recipient, new_recipient_email=new_recipient_email)
        return self._response(render_template('notifications.html', **context), status)

    def legacy_email_redirect(self):
        denied = self._guard(owner=True)
        if denied:
            return denied
        response = redirect('/settings/notifications', code=302)
        response.headers['Cache-Control'] = 'no-store'
        return response

    def save_email(self):
        denied = self._guard(owner=True, csrf=True)
        if denied:
            return denied
        try:
            if 'EMAIL_ENABLED' in os.environ:
                return self.render_page(error='Email notifications are managed by the environment.', status=400)
            settings, actor = self._settings(), self.adapter.actor()
            self.adapter.connections.save({'EMAIL_ENABLED': 'true' if request.form.get('enabled') == '1' else 'false'},
                guard=lambda db: settings.validate_actor(actor, db, owner=True))
        except PermissionError:
            return self._response(ACCESS_ERROR, 403)
        except (sqlite3.Error, OSError, ValueError):
            return self._response('Keep could not save Email settings. Try again shortly.', 503)
        self.adapter.log_activity('notification-email-updated', 'Updated Email notifications')
        return self._redirect('Email settings saved.')

    def save_installation(self):
        denied = self._guard(owner=True, csrf=True)
        if denied:
            return denied
        try:
            settings = self._settings(initialize=True)
            managed = settings.installation_view()['fields']['PUSHOVER_ENABLED']['managed']
            if managed and 'enabled' in request.form:
                return self.render_page(error='Pushover notifications are managed by the environment.', status=400)
            settings.save_installation(self.adapter.actor(), enabled=None if managed else request.form.get('enabled') == '1',
                                       token_mode=request.form.get('token_mode', 'keep'), token=request.form.get('app_token', ''), now=self.now())
        except PermissionError:
            return self._response(ACCESS_ERROR, 403)
        except ValueError:
            return self.render_page(error='Check the Pushover settings and try again.', status=400)
        except (sqlite3.Error, OSError):
            return self._response('Keep could not save Pushover settings. Try again shortly.', 503)
        self.adapter.log_activity('notification-pushover-updated', 'Updated Pushover notifications')
        return self._redirect('Pushover settings saved.')

    def _run_test(self, provider):
        settings, actor = self._settings(initialize=True), self.adapter.actor()
        if provider == 'email':
            installation = self._email_installation(settings, actor)
            if not installation['enabled'] or not installation['configured']:
                return 'Enable and configure Email before testing.', False
        reservation = settings.reserve_test(actor, 'email' if provider == 'email' else 'notification', now=self.now())
        if reservation.state != 'reserved':
            return {
                'unconfigured': 'Save the required notification settings first.',
                'review': 'A previous test delivery needs review.',
                'cooldown': 'Wait briefly before testing again.',
                'quota': 'Pushover is temporarily unavailable. Try again later.',
                'busy': 'A notification test is already running.',
            }.get(reservation.state, 'The test is unavailable. Try again later.'), False
        if not self.adapter.current_account_session():
            result = notifications.Outcome('cancelled', 'preferences_changed')
        else:
            try:
                actor = self.adapter.actor()
                if provider == 'email':
                    address = settings.email_test_recipient(actor, reservation_id=reservation.id)
                    installation = self._email_installation(settings, actor)
                    result = (self.adapter.send_email_test(address) if address and installation['enabled'] and installation['configured']
                              else notifications.Outcome('cancelled', 'preferences_changed'))
                else:
                    credentials = settings.validation_credentials(actor, reservation_id=reservation.id)
                    result = (self.adapter.send_push_test(credentials) if credentials
                              else notifications.Outcome('cancelled', 'preferences_changed'))
            except PermissionError:
                result = notifications.Outcome('cancelled', 'preferences_changed')
            except Exception:
                # An exception after submission cannot prove the message was not accepted.
                result = notifications.Outcome('review', 'email_uncertain' if provider == 'email' else 'response_uncertain')
        if not settings.complete_test(reservation.id, result, now=self.now()):
            return 'Test delivery needs review.', False
        state = getattr(result, 'state', None)
        message = {'accepted': 'Test notification sent.', 'review': 'Test delivery needs review.',
                   'rejected': 'Test notification was rejected. Check the saved settings.',
                   'retry': 'The test could not be sent. Try again later.',
                   'cancelled': 'Settings changed before the test. Try again.'}.get(state, 'Test delivery needs review.')
        return message, state == 'accepted'

    def test(self, provider):
        denied = self._guard(owner=True, csrf=True)
        if denied:
            return denied
        if provider not in notifications.PROVIDERS:
            return self._response('Unknown notification provider.', 404)
        try:
            message, accepted = self._run_test(provider)
        except PermissionError:
            return self._response(ACCESS_ERROR, 403)
        except (sqlite3.Error, OSError, ValueError):
            return self._response('Keep could not record the test. Check recent deliveries before trying again.', 503)
        return self._redirect(message) if accepted else self.render_page(error=message, status=400)

    def handle_personal(self, action, form=None):
        """Root calls before its legacy Email/appearance branch.

        Returns handled/saved/error/test_feedback/response. Return response
        immediately when present; successful saves use the normal saved redirect.
        Test feedback renders Preferences with saved=False and no saved notice.
        """
        result = dict(handled=action in ('pushover', 'test-pushover', 'discard-pushover-test'),
                      saved=False, error=None, test_feedback=None, response=None)
        if not result['handled']:
            return result
        denied = self._guard(owner=True, csrf=True)
        if denied:
            result['response'] = denied
            return result
        form = request.form if form is None else form
        try:
            if action == 'pushover':
                settings, actor = self._settings(initialize=True), self.adapter.actor()
                enabled = form.get('receive_pushover') == '1'
                previous = settings.preferences_view(actor, available_collections=self.adapter.collections())
                collections = ({int(value) for value in form.getlist('pushover_collection_id')}
                               if enabled or 'pushover_collection_id' in form else previous['collections'])
                events = set(form.getlist('pushover_event')) if enabled or 'pushover_event' in form else previous['events']
                settings.save_preferences(actor, enabled=enabled, collections=collections, events=events,
                    available_collections=self.adapter.collections(), key_mode=form.get('key_mode', 'keep'),
                    user_key=form.get('user_key', ''), device=form.get('device'), now=self.now())
                self.adapter.log_activity('personal-pushover-updated', 'Updated Pushover preferences')
                result['saved'] = True
            elif action == 'discard-pushover-test':
                test_id = form.get('test_id', '')
                if not TEST_ID.fullmatch(test_id) or not self._settings(initialize=True).discard_test(self.adapter.actor(), test_id, now=self.now()):
                    result['error'] = 'That test delivery is unavailable for review.'
                else:
                    result['test_feedback'] = 'Test delivery discarded.'
            else:
                result['test_feedback'], _ = self._run_test('pushover')
        except PermissionError:
            result['error'] = ACCESS_ERROR
        except ValueError:
            result['error'] = 'Check your Pushover key, events and collections, then try again.'
        except (sqlite3.Error, OSError):
            result['error'] = ('Keep could not record the test. Check its status before trying again.'
                               if action == 'test-pushover' else 'Keep could not save notification settings. Try again shortly.')
        return result

    def save_owner_preferences(self):
        result = self.handle_personal('pushover')
        if result['response'] is not None:
            return result['response']
        if result['saved']:
            return self._redirect('Pushover delivery settings saved.')
        return self.render_page(error=result['error'], status=400)

    def review(self):
        denied = self._guard(owner=True, csrf=True)
        if denied:
            return denied
        batch = request.form.get('batch_id', '')
        provider = request.form.get('provider', '')
        destination = request.form.get('destination_id', '')
        action = request.form.get('action', '')
        if (provider not in notifications.PROVIDERS or action not in ('discard', 'retry')
                or not 1 <= len(batch) <= 128 or not 1 <= len(destination) <= 256
                or any(ord(char) < 32 or ord(char) == 127 for char in batch + destination)):
            return self.render_page(error='Choose a valid delivery review action.', status=400)
        if action == 'retry' and request.form.get('confirm_duplicate') != '1':
            return self.render_page(error='Confirm the possible duplicate before resending.', status=400)
        try:
            if batch.startswith('test:'):
                test_id, actor, settings = batch[5:], self.adapter.actor(), self._settings(initialize=True)
                view = next((row for row in settings.test_views(actor) if row['id'] == test_id), None)
                if (not TEST_ID.fullmatch(test_id) or destination != actor.user_id or not view or action != 'discard'
                        or view['kind'] != ('email' if provider == 'email' else 'notification')):
                    return self.render_page(error='That test delivery is unavailable for review.', status=404)
                changed = settings.discard_test(actor, test_id, now=self.now())
            else:
                core = self._core()
                view = next((row for row in core.snapshot(batch_id=batch, limit=500)
                             if row['provider'] == provider and row['destination_id'] == destination), None)
                if not view or view['state'] not in ('review', 'rejected') or action == 'retry' and destination == 'legacy-held':
                    return self.render_page(error='That delivery is unavailable for review.', status=404)
                settings, actor = self._settings(), self.adapter.actor()
                changed = self._core(read_only=False).resolve_review(batch, provider, destination, action=action, now=self.now(),
                    guard=lambda db: settings.validate_actor(actor, db, owner=True))
            if not changed:
                return self.render_page(error='That delivery changed. Refresh and try again.', status=409)
        except PermissionError:
            return self._response(ACCESS_ERROR, 403)
        except (sqlite3.Error, OSError, ValueError):
            return self._response('Keep could not save the review. Try again shortly.', 503)
        self.adapter.log_activity('notification-reviewed', 'Discarded notification delivery' if action == 'discard' else 'Queued notification resend')
        return self._redirect('Delivery discarded.' if action == 'discard' else 'Delivery queued to resend.')


def register_routes(app, adapter):
    routes = Routes(app, adapter)
    app.add_url_rule('/settings/notifications', 'settings_notifications', routes.render_page, methods=['GET'])
    app.add_url_rule('/settings/notifications/email', 'save_notification_email', routes.save_email, methods=['POST'])
    app.add_url_rule('/settings/notifications/pushover', 'save_notification_pushover', routes.save_installation, methods=['POST'])
    app.add_url_rule('/settings/notifications/pushover/preferences', 'save_owner_pushover_preferences', routes.save_owner_preferences, methods=['POST'])
    app.add_url_rule('/settings/notifications/test/<provider>', 'test_notification_provider', routes.test, methods=['POST'])
    app.add_url_rule('/settings/notifications/review', 'review_notification_delivery', routes.review, methods=['POST'])
    if not any(rule.rule == '/settings/email' for rule in app.url_map.iter_rules()):
        app.add_url_rule('/settings/email', 'settings_email', routes.legacy_email_redirect, methods=['GET'])
    return routes
