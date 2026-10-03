import os
import socket
import tempfile
import unittest
from contextlib import closing
from unittest.mock import patch
from connection_settings import ConnectionSettings, validate
import test_keep
from test_keep import keep


class StoreTests(unittest.TestCase):
    def test_connection_checks_keep_the_last_result_until_settings_change(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {}, clear=True):
            store = ConnectionSettings(directory + '/settings.sqlite3')
            store.save({'RADARR_URL': 'http://radarr', 'RADARR_API_KEY': 'secret'})
            self.assertEqual(store.check_states(store.get)['radarr']['label'], 'Not checked')
            fingerprint = store.connection_fingerprint('radarr', store.get)
            store.record_check('radarr', fingerprint, True)
            passed = store.check_states(store.get)['radarr']
            self.assertEqual(passed['kind'], 'success')
            self.assertEqual(passed['label'], 'Last test passed')
            self.assertIn('UTC', passed['tested_at'])
            self.assertRegex(passed['tested_at_iso'], r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?\+00:00$')
            self.assertEqual(store.check_states(store.get)['sonarr']['label'], 'Setup needed')
            with patch('connection_settings.time.time', return_value=9999999999):
                self.assertEqual(store.check_states(store.get)['radarr'], passed)
            store.record_check('radarr', fingerprint, False)
            failed = store.check_states(store.get)['radarr']
            self.assertEqual(failed['kind'], 'error')
            self.assertEqual(failed['label'], 'Last test failed')
            with patch('connection_settings.time.time', return_value=9999999999):
                self.assertEqual(store.check_states(store.get)['radarr'], failed)
            store.save({'RADARR_API_KEY': 'changed'})
            self.assertEqual(store.check_states(store.get)['radarr']['label'], 'Settings changed · test again')
            self.assertEqual(store.check_states(store.get)['email']['label'], 'Email disabled')

    def test_shared_persistence_environment_precedence_and_atomic_validation(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {}, clear=True):
            first = ConnectionSettings(directory + '/settings.sqlite3')
            second = ConnectionSettings(first.path)
            first.save({'MAINTAINERR_URL': 'http://maintainerr:6246/'})
            self.assertEqual(second.get('MAINTAINERR_URL'), 'http://maintainerr:6246')
            with self.assertRaises(ValueError):
                first.save({'MAINTAINERR_URL': 'http://changed', 'PLEX_SERVER_URL': 'file:///etc/passwd'})
            self.assertEqual(second.get('MAINTAINERR_URL'), 'http://maintainerr:6246')
            with patch.dict(os.environ, MAINTAINERR_URL='https://override'):
                self.assertEqual(second.get('MAINTAINERR_URL'), 'https://override')
                with self.assertRaises(ValueError):
                    first.save({'MAINTAINERR_URL': 'http://changed'})

    def test_blank_secret_preserves_and_bad_urls_rejected(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {}, clear=True):
            store = ConnectionSettings(directory + '/settings.sqlite3')
            store.save({'PLEX_ADMIN_TOKEN': 'private-token'})
            store.save({'PLEX_ADMIN_TOKEN': ''})
            self.assertEqual(store.get('PLEX_ADMIN_TOKEN'), 'private-token')
        for value in ('http://user:secret@host', 'http://host?token=secret', 'http://host/#secret', 'file:///tmp/a', 'http://host:bad', 'http://host\n'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate('PLEX_SERVER_URL', value)


class ConnectionRouteTests(unittest.TestCase):
    setUp = test_keep.KeepTests.setUp

    def test_token_never_rendered_and_page_not_cached(self):
        with patch.dict(os.environ, PLEX_ADMIN_TOKEN='never-display-this'):
            response = self.client.get('/settings/connections')
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(b'never-display-this', response.data)
        self.assertEqual(response.headers['Cache-Control'], 'no-store')

    def test_csrf_and_owner_required_before_probe(self):
        with patch.object(keep.requests, 'get') as get:
            self.assertEqual(self.client.post('/settings/connections', data={'action': 'plex'}).status_code, 403)
            with patch.object(keep, 'is_owner', return_value=False):
                self.assertEqual(self.client.get('/settings/connections').status_code, 403)
                self.assertEqual(self.client.post('/settings/connections', data={'action': 'plex', 'csrf_token': 'test-csrf'}).status_code, 403)
            get.assert_not_called()

    def test_probe_disables_redirects_and_hides_error_details(self):
        with patch.object(keep.requests, 'get', side_effect=keep.requests.ConnectionError('private-token')) as get:
            response = self.client.post('/settings/connections', data={'action': 'plex', 'csrf_token': 'test-csrf'})
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(b'private-token', response.data)
        self.assertFalse(get.call_args.kwargs['allow_redirects'])

    def test_connection_diagnostics_are_actionable_and_never_echo_exception_text(self):
        cases = [
            (keep.requests.ConnectionError('Name resolution failed for user:secret@private.invalid'),
             'could not resolve'),
            (keep.requests.ConnectionError('connection refused at http://user:secret@private.invalid'),
             'refused the connection'),
            (keep.requests.Timeout('timed out for http://user:secret@private.invalid'),
             'timed out'),
            (keep.requests.HTTPError(response=type('Response', (), {'status_code': 401})()),
             'rejected authentication'),
            (keep.requests.HTTPError(response=type('Response', (), {'status_code': 404})()),
             'api path was not found'),
            (keep.requests.HTTPError(response=type('Response', (), {'status_code': 503})()),
             'server error (http 503)'),
            (ValueError('unexpected API response: bearer private-token'),
             'unexpected response'),
        ]
        for failure, expected in cases:
            with self.subTest(expected=expected):
                message = keep.connection_failure_message('radarr', failure)
                self.assertIn(expected, message.lower())
                self.assertNotIn('private.invalid', message)
                self.assertNotIn('user:secret', message)
                self.assertNotIn('private-token', message)

    def test_dns_exception_chain_and_collection_probe_error_are_safe(self):
        message = keep.connection_failure_message(
            'maintainerr', keep.requests.ConnectionError('failed', socket.gaierror(-2, 'unknown')))
        self.assertIn('could not resolve', message.lower())
        with patch.object(keep, 'discover_collections',
                          side_effect=keep.requests.ConnectionError(
                              'connection refused to http://user:private@service.invalid')):
            response = self.client.post('/settings/connections', data={
                'action': 'discover-collections', 'csrf_token': 'test-csrf'})
        self.assertIn(b'refused the connection', response.data)
        self.assertIn(b'Your saved selection is unchanged', response.data)
        self.assertNotIn(b'user:private', response.data)
        self.assertNotIn(b'service.invalid', response.data)

class PortableTests(unittest.TestCase):
    setUp = test_keep.KeepTests.setUp

    def test_disabled_email_returns_private_invitation_without_smtp(self):
        with patch.dict(os.environ, EMAIL_ENABLED='false'), patch.object(keep, 'send_email') as send:
            response = self.client.post('/settings/users/local', data={
                'csrf_token': 'test-csrf', 'email': 'portable@example.com',
                'full_name': 'Portable User', 'display_name': 'Portable'})
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'/auth/local/setup/', response.data)
        self.assertEqual(response.headers['Referrer-Policy'], 'no-referrer')
        self.assertEqual(response.headers['Cache-Control'], 'no-store')
        send.assert_not_called()

    def test_disabled_email_pauses_worker_and_self_service_reset(self):
        with patch.dict(os.environ, EMAIL_ENABLED='false'), patch.object(keep, 'send_email') as send:
            self.assertEqual(keep.process_digest(), 'disabled')
            response = self.client.get('/auth/local/forgot')
        self.assertIn(b'Email is disabled', response.data)
        send.assert_not_called()

    def test_collection_selection_rejects_unknown_ids_and_preserves_data(self):
        environment = dict(os.environ)
        environment.pop('KEEP_COLLECTIONS', None)
        with patch.dict(os.environ, environment, clear=True), tempfile.TemporaryDirectory() as directory:
            store = ConnectionSettings(directory + '/config.sqlite3')
            with patch.object(keep, 'connection_settings', store), patch.object(keep, 'discover_collections', return_value={12: 'Family Movies'}):
                response = self.client.post('/settings/connections', data={'csrf_token': 'test-csrf', 'action': 'collections', 'collection_id': '999'})
                self.assertEqual(response.status_code, 400)
                response = self.client.post('/settings/connections', data={'csrf_token': 'test-csrf', 'action': 'collections', 'collection_id': '12'})
                self.assertEqual(response.status_code, 200)
                self.assertEqual(store.get('KEEP_COLLECTIONS'), '{"12": "Family Movies"}')

    def test_configuration_snapshot_stays_consistent_during_request(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {}, clear=True):
            store = ConnectionSettings(directory + '/config.sqlite3')
            store.save({'MAINTAINERR_URL': 'http://old'})
            with patch.object(keep, 'connection_settings', store):
                token = keep._settings_snapshot.set(store.snapshot())
                try:
                    store.save({'MAINTAINERR_URL': 'http://new'})
                    self.assertEqual(keep.connection_value('MAINTAINERR_URL'), 'http://old')
                finally:
                    keep._settings_snapshot.reset(token)
                self.assertEqual(keep.connection_value('MAINTAINERR_URL'), 'http://new')


class MigrationTests(unittest.TestCase):
    def test_migration_preserves_rows_and_never_executes_source(self):
        import importlib.util
        import sqlite3
        from pathlib import Path
        spec = importlib.util.spec_from_file_location('migration', 'scripts/migrate_configuration.py')
        migration = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(migration)
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {}, clear=True):
            dbpath = Path(directory) / 'keep.sqlite3'
            source = Path(directory) / 'legacy.py'
            source.write_text('raise RuntimeError("must not execute")\nMAINTAINERR_URL="http://legacy"\nCOLLECTIONS={9:"Legacy"}\n')
            with sqlite3.connect(dbpath) as db:
                db.execute('CREATE TABLE user_profiles (id TEXT)')
                db.execute("INSERT INTO user_profiles VALUES ('retained')")
            with self.assertRaises(RuntimeError):
                ConnectionSettings(str(dbpath))
            migration.migrate(source, dbpath)
            store = ConnectionSettings(str(dbpath))
            self.assertEqual(store.get('MAINTAINERR_URL'), 'http://legacy')
            self.assertEqual(store.get('KEEP_COLLECTIONS'), '{"9": "Legacy"}')
            store.save({'MAINTAINERR_URL': 'http://updated'})
            migration.migrate(source, dbpath)
            self.assertEqual(store.get('MAINTAINERR_URL'), 'http://updated')
            with sqlite3.connect(dbpath) as db:
                self.assertEqual(db.execute('SELECT id FROM user_profiles').fetchone()[0], 'retained')

class FreshInstallTests(unittest.TestCase):
    def test_first_run_is_locked_without_owner_and_has_no_legacy_defaults(self):
        import subprocess
        import sys
        with tempfile.TemporaryDirectory() as directory:
            environment = {**os.environ, 'FLASK_SECRET_KEY': 'test-only-secret-not-for-production-0000',
                           'KEEP_DB_PATH': directory + '/new.sqlite3'}
            for key in tuple(environment):
                if key.startswith(('PLEX_', 'SMTP_', 'MAINTAINERR_')) or key in ('EMAIL_ENABLED', 'KEEP_COLLECTIONS'):
                    environment.pop(key)
            result = subprocess.run([sys.executable, '-B', '-c', 'import app; assert not app.owner_id(); assert app.app.test_client().get("/").location == "/setup"'], env=environment, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            environment['PLEX_OWNER_ID'] = '1234'
            result = subprocess.run([sys.executable, '-B', '-c', 'import app; assert app.get_collections() == {}; assert not app.email_enabled(); assert app.connection_value("SMTP_FROM") == ""'], env=environment, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)


class DiscoveryTests(unittest.TestCase):
    def test_discovery_rejects_wrong_schema_and_identifies_collections(self):
        import service_discovery as discovery
        with patch.object(discovery, 'read_service', return_value=b'[{"id":12,"title":"Family"}]'):
            self.assertEqual(discovery.discover_collections('http://service'), {12: 'Family'})
        for content in (b'{}', b'[{"id":true,"title":"bad"}]', b'[{"id":1,"title":"a"},{"id":1,"title":"b"}]'):
            with patch.object(discovery, 'read_service', return_value=content), self.assertRaises(ValueError):
                discovery.discover_collections('http://service')

    def test_plex_checks_machine_identity_before_account_endpoint(self):
        import service_discovery as discovery
        with patch.object(discovery, 'read_service', return_value=b'<MediaContainer machineIdentifier="other"/>') as read:
            with self.assertRaises(ValueError):
                discovery.test_plex('http://plex', 'secret', 'expected')
            self.assertEqual(read.call_count, 1)

class DeselectedCollectionTests(unittest.TestCase):
    def test_queued_events_for_unselected_collections_are_not_sent(self):
        with patch.object(keep, 'get_collections', return_value={}), patch.object(keep, 'digest_collection_items') as fetch:
            self.assertEqual(keep.resolve_digest([{'collection_id': 99, 'media_id': '1'}]), [])
            fetch.assert_not_called()

class EmailTransportTests(unittest.TestCase):
    def test_ssl_verifies_certificates_and_hostname(self):
        import ssl
        with patch.dict(os.environ, EMAIL_ENABLED='true', SMTP_SECURITY='ssl'), patch.object(keep.smtplib, 'SMTP_SSL') as smtp:
            smtp.return_value.__enter__.return_value.send_message.return_value = {}
            keep.send_email('test@example.com', 'Test', '<p>Test</p>', 'Test')
        context = smtp.call_args.kwargs['context']
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)

class ConcurrentStartupTests(unittest.TestCase):
    def test_web_and_worker_can_initialize_the_same_new_database(self):
        import subprocess
        import sys
        with tempfile.TemporaryDirectory() as directory:
            environment = {**os.environ, 'FLASK_SECRET_KEY': 'test-only-secret-not-for-production-0000',
                           'KEEP_DB_PATH': directory + '/new.sqlite3', 'PLEX_OWNER_ID': '7'}
            processes = [subprocess.Popen([sys.executable, '-B', '-c', 'import app; assert app.owner_id() == "7"'], env=environment,
                                          stdout=subprocess.PIPE, stderr=subprocess.PIPE) for _ in range(2)]
            for process in processes:
                _, error = process.communicate(timeout=15)
                self.assertEqual(process.returncode, 0, error.decode())


class RedesignedConnectionTests(unittest.TestCase):
    def setUp(self):
        test_keep.KeepTests.setUp(self)
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        environment = {key: value for key, value in os.environ.items()
                       if key not in keep.CONNECTION_FIELDS + keep.EMAIL_FIELDS + ('KEEP_COLLECTIONS',)}
        env_patch = patch.dict(os.environ, environment, clear=True)
        env_patch.start()
        self.addCleanup(env_patch.stop)
        self.store = ConnectionSettings(directory.name + '/settings.sqlite3')
        self.store.save({'PLEX_ADMIN_TOKEN': 'synthetic-secret', 'SMTP_PASSWORD': 'synthetic-mail',
                         'PLEX_SERVER_URL': 'http://example.test:32400',
                         'PLEX_MACHINE_IDENTIFIER': 'synthetic-server', 'SMTP_USER': 'synthetic-user'})
        store_patch = patch.object(keep, 'connection_settings', self.store)
        store_patch.start()
        self.addCleanup(store_patch.stop)

    def post(self, **data):
        return self.client.post('/settings/connections', data={'csrf_token': 'test-csrf', **data})

    def test_separate_saves_and_explicit_credential_lifecycle(self):
        self.post(action='save-email', SMTP_USER='updated', PLEX_ADMIN_TOKEN='ignored',
                  PLEX_ADMIN_TOKEN_mode='replace')
        self.assertEqual(self.store.get('PLEX_ADMIN_TOKEN'), 'synthetic-secret')
        self.assertEqual(self.store.get('SMTP_USER'), 'updated')
        self.post(action='save-plex', PLEX_ADMIN_TOKEN='ignored', PLEX_ADMIN_TOKEN_mode='keep')
        self.assertEqual(self.store.get('PLEX_ADMIN_TOKEN'), 'synthetic-secret')
        self.post(action='save-plex', PLEX_ADMIN_TOKEN='', PLEX_ADMIN_TOKEN_mode='replace', PLEX_SERVER_URL='')
        self.assertEqual(self.store.get('PLEX_ADMIN_TOKEN'), 'synthetic-secret')
        self.assertEqual(self.store.get('PLEX_SERVER_URL'), 'http://example.test:32400')
        self.post(action='save-plex', PLEX_ADMIN_TOKEN='replacement', PLEX_ADMIN_TOKEN_mode='replace')
        self.assertEqual(self.store.get('PLEX_ADMIN_TOKEN'), 'replacement')
        self.post(action='save-plex', PLEX_ADMIN_TOKEN_mode='clear')
        self.assertEqual(self.store.get('PLEX_ADMIN_TOKEN'), '')
        self.assertEqual(self.store.get('SMTP_PASSWORD'), 'synthetic-mail')

    def test_clear_and_invalid_edit_are_atomic(self):
        response = self.post(action='save-plex', PLEX_ADMIN_TOKEN_mode='clear', PLEX_SERVER_URL='file:///invalid')
        self.assertIn(b'role="alert"', response.data)
        self.assertEqual(self.store.get('PLEX_ADMIN_TOKEN'), 'synthetic-secret')
        with self.assertRaises(ValueError):
            self.store.save({}, clear=['SMTP_USER'])

    def test_reveal_requires_owner_csrf_and_supported_secret(self):
        endpoint = '/settings/connections/reveal'
        data = {'csrf_token': 'test-csrf', 'name': 'PLEX_ADMIN_TOKEN'}
        response = self.client.post(endpoint, data=data)
        self.assertEqual(response.json, {'value': 'synthetic-secret'})
        self.assertEqual(response.headers['Cache-Control'], 'no-store')
        self.assertEqual(self.client.get(endpoint).status_code, 405)
        self.assertEqual(self.client.post(endpoint, data={'name': 'PLEX_ADMIN_TOKEN'}).status_code, 403)
        with patch.object(keep, 'is_owner', return_value=False):
            response = self.client.post(endpoint, data=data)
            self.assertEqual(response.status_code, 403)
            self.assertNotIn(b'synthetic-secret', response.data)
        with patch.dict(os.environ, PLEX_ADMIN_TOKEN='synthetic-override'):
            response = self.client.post(endpoint, data=data)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json, {'value': 'synthetic-override'})
            self.assertEqual(response.headers['Cache-Control'], 'no-store')
        self.assertEqual(self.client.post(endpoint, data={**data, 'name': 'SMTP_USER'}).status_code, 403)
        with self.client.session_transaction() as session:
            session.clear()
        response = self.client.post(endpoint, data=data)
        self.assertEqual(response.status_code, 302)
        self.assertNotIn(b'synthetic-secret', response.data)

    def test_managed_fields_are_read_only_status_and_do_not_mutate_saved_values(self):
        with patch.dict(os.environ, RADARR_API_KEY='synthetic-override', RADARR_URL='http://override.test'):
            response = self.client.get('/settings/connections')
            self.assertNotIn(b'name="RADARR_API_KEY"', response.data)
            self.assertNotIn(b'name="RADARR_URL"', response.data)
            self.assertNotIn(b'synthetic-override', response.data)
            self.assertIn(b'value="override.test"', response.data)
            self.assertNotIn(b'name="RADARR_URL_host"', response.data)
            self.assertNotIn(b'name="RADARR_URL_port"', response.data)
            self.assertIn(b'id="RADARR_URL_scheme"', response.data)
            self.post(action='save-radarr', RADARR_API_KEY_mode='clear', RADARR_URL='http://bad.test')
        self.assertEqual(self.store.get('RADARR_API_KEY'), '')
        self.assertEqual(self.store.get('RADARR_URL'), '')

    def test_saved_secrets_not_in_html_or_activity(self):
        with patch.object(keep, 'log_activity') as log:
            response = self.post(action='save-email', SMTP_PASSWORD_mode='replace', SMTP_PASSWORD='new-synthetic-secret')
        for value in (b'synthetic-secret', b'synthetic-mail', b'new-synthetic-secret'):
            self.assertNotIn(value, response.data)
        self.assertNotIn('new-synthetic-secret', str(log.call_args))
        self.assertIn(b'keep-ui.css', response.data)

    def test_collection_discovery_is_independent_and_preserves_selection(self):
        self.store.save({'KEEP_COLLECTIONS': '{"12": "Family"}'})
        page = self.client.get('/settings/connections').data
        self.assertIn(b'Choose collections', page)
        self.assertNotIn(b'Review setup', page)
        self.assertNotIn(b'Remove credential', page)
        self.assertNotIn(b'Settings marked', page)
        self.assertIn(b'/plex/connect', page.split(b'id="plex"')[1].split(b'</section>')[0])
        with patch.object(keep, 'discover_collections', return_value={12: 'Family', 13: 'Other'}):
            page = self.post(action='discover-collections').data
        self.assertIn(b'value="12" checked', page)
        self.assertIn(b'value="13"', page)
        self.assertEqual(self.store.get('KEEP_COLLECTIONS'), '{"12": "Family"}')
        with patch.object(keep, 'discover_collections', return_value={}):
            page = self.post(action='discover-collections').data
        self.assertIn(b'No collections found', page)
        self.assertNotIn(b'Could not load collections', page)
        for failure, expected in ((ValueError('bad schema'), b'Maintainerr returned an unexpected response'),
                                  (keep.requests.ConnectionError('private'), b'could not complete the connection')):
            with patch.object(keep, 'discover_collections', side_effect=failure):
                page = self.post(action='discover-collections').data
            self.assertIn(expected, page)
            self.assertNotIn(b'No collections found', page)
            self.assertNotIn(b'Save collection selection', page)
            self.assertEqual(self.store.get('KEEP_COLLECTIONS'), '{"12": "Family"}')
        with patch.dict(os.environ, KEEP_COLLECTIONS='{"99":"Managed"}'):
            page = self.client.get('/settings/connections').data
            self.assertNotIn(b'value="discover-collections"', page)
            self.assertEqual(self.post(action='collections', collection_id='12').status_code, 400)

    def test_probe_uses_saved_values_not_unsaved_form(self):
        with patch.object(keep, 'test_plex') as probe:
            self.post(action='plex', PLEX_SERVER_URL='http://unsaved.test', PLEX_ADMIN_TOKEN='unsaved')
        probe.assert_called_once_with('http://example.test:32400', 'synthetic-secret', 'synthetic-server')

    def test_connection_controls_keep_unsaved_protection_without_repeated_notes(self):
        with patch.object(keep, 'discover_collections', return_value={1: 'Movies'}):
            page = self.post(action='discover-collections').data.decode()
        self.assertEqual(page.count('data-protect-unsaved data-saved-test'), 7)
        self.assertNotIn('class="connection-test-note"', page)
        self.assertNotIn('Tests use saved settings, not edits above', page)
        self.assertNotIn('Automatic checks run in the background. Use Test', page)
        self.assertNotIn('class="page-footnote"', page)
        self.assertIn('<form method="post" data-protect-unsaved', page)
        self.assertIn('class="connection-metrics"', page)
        self.assertIn('<h3>Account links</h3>', page)
        self.assertNotIn('upcoming title-details popup', page)
        self.assertNotIn('Use Test to verify connectivity now.', page)
        self.assertIn('/static/service-icons/tautulli.svg?v=', page)

    def test_split_address_save_preserves_base_paths_and_unchanged_web_ports(self):
        self.store.save({'RADARR_URL': 'https://RADARR.example.test/radarr'})
        response = self.post(action='save-radarr', RADARR_URL_scheme='https',
                             RADARR_URL_host='radarr.example.test', RADARR_URL_port='443',
                             RADARR_URL_path='/radarr', RADARR_API_KEY='changed-key')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.store.get('RADARR_URL'), 'https://RADARR.example.test/radarr')
        self.assertEqual(self.store.get('RADARR_API_KEY'), 'changed-key')
        self.post(action='save-radarr', RADARR_URL_scheme='http', RADARR_URL_host='radarr',
                  RADARR_URL_port='7878', RADARR_URL_path='/custom')
        self.assertEqual(self.store.get('RADARR_URL'), 'http://radarr:7878/custom')
        self.post(action='save-radarr', RADARR_URL_scheme='http', RADARR_URL_host='',
                  RADARR_URL_port='7878', RADARR_URL_path='')
        self.assertEqual(self.store.get('RADARR_URL'), '')

    def test_invalid_split_address_does_not_apply_credential_edits(self):
        response = self.post(action='save-plex', PLEX_SERVER_URL_scheme='http',
                             PLEX_SERVER_URL_host='user:secret@host', PLEX_SERVER_URL_port='32400',
                             PLEX_SERVER_URL_path='', PLEX_ADMIN_TOKEN='replacement')
        self.assertIn(b'role="alert"', response.data)
        self.assertEqual(self.store.get('PLEX_ADMIN_TOKEN'), 'synthetic-secret')
        self.assertEqual(self.store.get('PLEX_SERVER_URL'), 'http://example.test:32400')

    def test_saving_or_testing_only_reopens_the_submitted_or_previously_open_cards(self):
        import re

        def opened(page):
            return set(re.findall(r'<details[^>]*id="([^"]+)"[^>]*\sopen\s*>', page.decode()))

        self.assertEqual(opened(self.post(action='save-email').data), {'email'})
        with patch.object(keep, 'test_plex'):
            self.assertEqual(opened(self.post(action='plex').data), {'plex'})
            self.assertEqual(opened(self.post(action='plex', open_services='plex,radarr').data), {'plex', 'radarr'})
            self.assertEqual(opened(self.post(action='plex', open_services='').data), set())

    def test_port_controls_use_numeric_text_inputs_without_native_spinners(self):
        import re
        page = self.client.get('/settings/connections').get_data(as_text=True)
        for name in ('SMTP_PORT', 'PLEX_SERVER_URL_port', 'MAINTAINERR_URL_port',
                     'RADARR_URL_port', 'SONARR_URL_port', 'SEERR_URL_port', 'TAUTULLI_URL_port'):
            control = re.search(r'<input[^>]+id="' + name + r'"[^>]*>', page).group(0)
            self.assertIn('type="text"', control)
            self.assertIn('inputmode="numeric"', control)
        self.assertIn('id="RADARR_URL_port" name="RADARR_URL_port" value="7878"', page)

    def test_radarr_and_sonarr_are_separate_masked_connections_with_discovery(self):
        page = self.client.get('/settings/connections').data
        for service in (b'Radarr', b'Sonarr'):
            self.assertIn(service, page)
        self.post(action='save-radarr', RADARR_URL='http://radarr.test:7878',
                  RADARR_API_KEY='radarr-private-key')
        self.assertEqual(self.store.get('RADARR_URL'), 'http://radarr.test:7878')
        self.assertEqual(self.store.get('RADARR_API_KEY'), 'radarr-private-key')
        self.assertNotIn(b'radarr-private-key', self.client.get('/settings/connections').data)
        libraries = [{'key': 'radarr:4', 'service': 'radarr', 'external_id': '4',
                      'name': 'Movies', 'path': '/mnt/synology/Movies'}]
        with patch.object(keep.media_services, 'test_connection', return_value={'version': '6.0.0'}), \
             patch.object(keep.media_services, 'discover_libraries', return_value=libraries):
            response = self.post(action='radarr')
        self.assertIn(b'Radarr 6.0.0 connection succeeded', response.data)
        self.assertIn(b'class="notice"', response.data)
        self.assertIn(b'Automatic: Pending', response.data)
        self.assertNotIn(b'Manual Test:', response.data)
        self.assertNotIn(b'Tested ', response.data)
        with closing(keep.attribution_db()) as db:
            saved = db.execute("SELECT * FROM media_libraries WHERE library_key='radarr:4'").fetchone()
        self.assertEqual(saved['name'], 'Movies')
        self.assertEqual(saved['path'], '/mnt/synology/Movies')

    def test_direct_secret_edit_checkbox_and_empty_username(self):
        self.post(action='save-email', SMTP_PASSWORD='direct-edit', EMAIL_ENABLED='true')
        self.assertEqual(self.store.get('SMTP_PASSWORD'), 'direct-edit')
        self.assertEqual(self.store.get('EMAIL_ENABLED'), 'true')
        self.post(action='save-email', SMTP_PASSWORD='', SMTP_USER='')
        self.assertEqual(self.store.get('SMTP_PASSWORD'), 'direct-edit')
        self.assertEqual(self.store.get('SMTP_USER'), '')
        self.assertEqual(self.store.get('EMAIL_ENABLED'), 'false')

    def test_smtp_probe_tls_auth_and_no_mail(self):
        self.store.save({'SMTP_HOST': 'smtp.example.test', 'SMTP_PORT': '587', 'SMTP_SECURITY': 'starttls'})
        with patch.object(keep.smtplib, 'SMTP') as transport:
            response = self.post(action='smtp')
        smtp = transport.return_value.__enter__.return_value
        smtp.starttls.assert_called_once()
        self.assertTrue(smtp.starttls.call_args.kwargs['context'].check_hostname)
        smtp.login.assert_called_once_with('synthetic-user', 'synthetic-mail')
        smtp.send_message.assert_not_called()
        smtp.sendmail.assert_not_called()
        self.assertIn(b'No email was sent', response.data)
        with patch.object(keep.smtplib, 'SMTP', side_effect=keep.smtplib.SMTPAuthenticationError(535, b'synthetic-mail')):
            response = self.post(action='smtp')
        self.assertIn(b'role="alert"', response.data)
        self.assertNotIn(b'synthetic-mail', response.data)
        self.assertIn(b'rejected authentication', response.data)
        self.assertNotIn(b'HTTP 535', response.data)

    def test_smtp_response_codes_are_distinct_from_http_diagnostics(self):
        for code in (450, 550):
            with self.subTest(code=code):
                message = keep.connection_failure_message(
                    'email', keep.smtplib.SMTPResponseException(code, b'private-mail-detail'))
                self.assertIn(f'SMTP {code}', message)
                self.assertNotIn('HTTP', message)
                self.assertNotIn('private-mail-detail', message)


class MaskedIdentifierTests(unittest.TestCase):
    setUp = test_keep.KeepTests.setUp

    def test_identifier_is_omitted_and_owner_can_deliberately_reveal_it(self):
        identifier = 'private-looking-machine-identifier'
        with patch.dict(os.environ, PLEX_MACHINE_IDENTIFIER=identifier):
            page = self.client.get('/settings/connections')
            self.assertNotIn(identifier.encode(), page.data)
            self.assertIn(b'data-credential="PLEX_MACHINE_IDENTIFIER"', page.data)
            revealed = self.client.post('/settings/connections/reveal', data={'csrf_token': 'test-csrf', 'name': 'PLEX_MACHINE_IDENTIFIER'})
            self.assertEqual(revealed.json, {'value': identifier})
            self.assertEqual(revealed.headers['Cache-Control'], 'no-store')
            self.assertEqual(self.client.post('/settings/connections/reveal', data={'name': 'PLEX_MACHINE_IDENTIFIER'}).status_code, 403)
        with self.client.session_transaction() as session:
            session.clear()
        response = self.client.post('/settings/connections/reveal', data={'csrf_token': 'test-csrf', 'name': 'PLEX_MACHINE_IDENTIFIER'})
        self.assertNotEqual(response.status_code, 200)
