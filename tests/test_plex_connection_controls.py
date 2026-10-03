"""Owner Plex connection journeys using synthetic identities and mocked services."""
import json
import os
import re
import sqlite3
import tempfile
import unittest
from contextlib import closing
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlsplit

from connection_settings import ConnectionSettings, FIELDS, PLEX_FIELDS
import test_keep
from test_keep import keep


ENV_PLEX = {'PLEX_SERVER_URL': 'http://deployment.example.test:32400',
            'PLEX_MACHINE_IDENTIFIER': 'deployment-machine',
            'PLEX_ADMIN_TOKEN': 'deployment-private-token'}
OLD_PLEX = {'PLEX_SERVER_URL': 'http://old.example.test:32400',
            'PLEX_MACHINE_IDENTIFIER': 'old-machine',
            'PLEX_ADMIN_TOKEN': 'old-private-token'}


class PlexOverrideStoreTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = directory.name + '/settings.sqlite3'
        env_patch = patch.dict(os.environ, {}, clear=True)
        env_patch.start()
        self.addCleanup(env_patch.stop)

    def markers(self):
        with closing(sqlite3.connect(self.path)) as db:
            return {row[0] for row in db.execute('SELECT name FROM plex_connection_overrides')}

    def test_legacy_rows_stay_ignored_until_a_deliberate_per_field_override(self):
        # Model an actual pre-upgrade database, rather than seeding via the new API.
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute('CREATE TABLE connection_settings(name TEXT PRIMARY KEY, value TEXT NOT NULL)')
            db.executemany('INSERT INTO connection_settings VALUES (?,?)', OLD_PLEX.items())
        with patch.dict(os.environ, ENV_PLEX):
            store = ConnectionSettings(self.path)
            self.assertEqual(self.markers(), set())
            self.assertEqual({name: store.get(name) for name in PLEX_FIELDS}, ENV_PLEX)
            self.assertEqual({name: store.snapshot()[name] for name in PLEX_FIELDS}, ENV_PLEX)
            store.save({'PLEX_SERVER_URL': 'https://manual.example.test/plex',
                        'PLEX_ADMIN_TOKEN': ''}, plex_override=True)
            self.assertEqual(self.markers(), {'PLEX_SERVER_URL'})
            expected = {**ENV_PLEX, 'PLEX_SERVER_URL': 'https://manual.example.test/plex'}
            with patch.dict(os.environ, PLEX_SERVER_URL='http://later-deployment.example.test'):
                restarted = ConnectionSettings(self.path)
                self.assertEqual({name: restarted.get(name) for name in PLEX_FIELDS}, expected)
                self.assertEqual({name: restarted.snapshot()[name] for name in PLEX_FIELDS}, expected)

    def test_validation_and_other_environment_settings_keep_their_existing_rules(self):
        store = ConnectionSettings(self.path)
        store.save(OLD_PLEX)
        with patch.dict(os.environ, {**ENV_PLEX, 'RADARR_URL': 'http://radarr.example.test'}):
            for values in ({'PLEX_ADMIN_TOKEN': 'changed'},
                           {'RADARR_URL': 'http://changed.example.test'}):
                with self.assertRaises(ValueError):
                    store.save(values)
            with self.assertRaises(ValueError):
                store.save({'PLEX_ADMIN_TOKEN': 'changed',
                            'PLEX_SERVER_URL': 'file:///invalid'}, plex_override=True)
            with self.assertRaises(ValueError):
                store.save({'PLEX_ADMIN_TOKEN': 'changed',
                            'RADARR_URL': 'http://changed.example.test'}, plex_override=True)
            self.assertEqual(self.markers(), set())
            self.assertEqual(store.get('PLEX_ADMIN_TOKEN'), ENV_PLEX['PLEX_ADMIN_TOKEN'])
            with closing(sqlite3.connect(self.path)) as db:
                self.assertEqual(dict(db.execute('SELECT name,value FROM connection_settings')), OLD_PLEX)

    def test_explicit_credential_clear_survives_environment_and_worker_reload(self):
        store = ConnectionSettings(self.path)
        store.save(OLD_PLEX)
        with patch.dict(os.environ, ENV_PLEX):
            store.save({}, clear=['PLEX_ADMIN_TOKEN'], plex_override=True)
            self.assertEqual(self.markers(), {'PLEX_ADMIN_TOKEN'})
            for reader in (store, ConnectionSettings(self.path)):
                self.assertEqual(reader.get('PLEX_ADMIN_TOKEN'), '')
                self.assertEqual(reader.snapshot()['PLEX_ADMIN_TOKEN'], '')
                self.assertFalse(reader.configured('plex', reader.get))
            with patch.dict(os.environ, PLEX_ADMIN_TOKEN='later-private-token'):
                self.assertEqual(ConnectionSettings(self.path).get('PLEX_ADMIN_TOKEN'), '')


class PlexConnectionJourneyTests(unittest.TestCase):
    def setUp(self):
        test_keep.KeepTests.setUp(self)
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        environment = {key: value for key, value in os.environ.items() if key not in FIELDS}
        env_patch = patch.dict(os.environ, environment, clear=True)
        env_patch.start()
        self.addCleanup(env_patch.stop)
        self.store = ConnectionSettings(directory.name + '/settings.sqlite3')
        self.store.save({**OLD_PLEX, 'KEEP_URL': 'https://keep.example.test'})
        store_patch = patch.object(keep, 'connection_settings', self.store)
        store_patch.start()
        self.addCleanup(store_patch.stop)
        # Any unexpected service call fails instead of reaching a live endpoint.
        for method in ('get', 'post'):
            network_patch = patch.object(keep.requests, method, side_effect=AssertionError('Unexpected network call'))
            network_patch.start()
            self.addCleanup(network_patch.stop)

    def post(self, action, **data):
        return self.client.post('/settings/connections', data={
            'csrf_token': 'test-csrf', 'action': action, **data})

    def assert_editable_controls(self):
        page = self.client.get('/settings/connections').get_data(as_text=True)
        for name in ('PLEX_SERVER_URL_scheme', 'PLEX_SERVER_URL_host',
                     'PLEX_SERVER_URL_port', 'PLEX_SERVER_URL_path',
                     'PLEX_MACHINE_IDENTIFIER', 'PLEX_ADMIN_TOKEN'):
            control = re.search(r'<(?:input|select)[^>]+id="' + name + r'"[^>]*>', page).group(0)
            self.assertIn('name="' + name + '"', control)
            self.assertNotIn('readonly', control)
            self.assertNotIn('disabled', control)
        self.assertIn('action="/settings/connections/plex/connect"', page)
        self.assertIn('Connect / Reconnect Plex', page)
        self.assertIn('value="save-plex"', page)
        for value in ('old-private-token', 'deployment-private-token', 'resource-private-token',
                      'manual-private-token', 'old-machine', 'deployment-machine', 'selected-machine'):
            self.assertNotIn(value, page)

    def connection_journey(self):
        self.assert_editable_controls()
        pin_response = Mock()
        pin_response.json.return_value = {'id': 123, 'code': 'synthetic-pin'}
        with patch.object(keep.requests, 'post', return_value=pin_response) as pins:
            response = self.client.post('/settings/connections/plex/connect', data={'csrf_token': 'test-csrf'})
        self.assertEqual(response.status_code, 302)
        pins.assert_called_once()
        self.assertEqual(pins.call_args.args[0], keep.PLEX_API_BASE + '/pins')
        self.assertEqual(pins.call_args.kwargs['data'], {'strong': 'true'})
        self.assertFalse(pins.call_args.kwargs['allow_redirects'])
        forward_url = parse_qs(urlsplit(response.location).fragment.lstrip('?'))['forwardUrl'][0]
        self.assertEqual(urlsplit(forward_url).netloc, 'keep.example.test')
        state = parse_qs(urlsplit(forward_url).query)['state'][0]
        resource = {'owned': True, 'provides': 'server', 'product': 'Plex Media Server',
                    'clientIdentifier': 'selected-machine', 'accessToken': 'resource-private-token',
                    'name': '<Synthetic Plex>', 'connections': [{'uri': 'https://selected.example.test:32400'}]}
        pin_response.json.return_value = {'authToken': 'broad-private-token'}
        with patch.object(keep.requests, 'get', return_value=pin_response) as pin_read, \
             patch.object(keep, 'get_plex_user', return_value={'id': '7'}), \
             patch('service_discovery.read_service', return_value=json.dumps([resource]).encode()):
            callback = self.client.get('/auth/plex/callback?state=' + state)
        self.assertEqual(callback.location, '/settings/connections/plex/select')
        pin_read.assert_called_once()
        self.assertEqual(pin_read.call_args.args[0], keep.PLEX_API_BASE + '/pins/123')
        selection = self.client.get(callback.location)
        self.assertIn(b'&lt;Synthetic Plex&gt;', selection.data)
        self.assertNotIn(b'resource-private-token', selection.data)
        with patch.object(keep, 'test_plex') as verify:
            selected = self.client.post(callback.location, data={'csrf_token': 'test-csrf', 'server': '0'})
        self.assertEqual(selected.location, '/settings/connections')
        verify.assert_called_once_with('https://selected.example.test:32400', 'resource-private-token', 'selected-machine')
        automatic = {'PLEX_SERVER_URL': 'https://selected.example.test:32400',
                     'PLEX_MACHINE_IDENTIFIER': 'selected-machine', 'PLEX_ADMIN_TOKEN': 'resource-private-token'}
        self.assertEqual({name: self.store.get(name) for name in PLEX_FIELDS}, automatic)
        with self.client.session_transaction() as session:
            self.assertEqual(str(session['plex_user']['id']), '7')
            self.assertNotIn('private-token', str(dict(session)))
        self.assertEqual(keep.owner_id(), '7')
        self.assert_editable_controls()
        manual = self.post('save-plex', PLEX_SERVER_URL_scheme='http',
                           PLEX_SERVER_URL_host='manual.example.test', PLEX_SERVER_URL_port='32401',
                           PLEX_SERVER_URL_path='/plex', PLEX_MACHINE_IDENTIFIER='manual-machine',
                           PLEX_ADMIN_TOKEN='manual-private-token')
        self.assertEqual(manual.status_code, 200)
        self.assertIn(b'Settings saved.', manual.data)
        self.assertNotIn(b'class="settings-error"', manual.data)
        self.assertEqual(self.store.get('PLEX_SERVER_URL'), 'http://manual.example.test:32401/plex')
        self.assertEqual(self.store.get('PLEX_MACHINE_IDENTIFIER'), 'manual-machine')
        self.assertEqual(self.store.get('PLEX_ADMIN_TOKEN'), 'manual-private-token')
        with patch.object(keep, 'test_plex') as verify:
            self.assertEqual(self.post('plex').status_code, 200)
        verify.assert_called_once_with('http://manual.example.test:32401/plex', 'manual-private-token', 'manual-machine')
        self.assert_editable_controls()

    def test_connect_fills_verified_values_and_manual_fields_remain_editable(self):
        self.connection_journey()

    def test_environment_fallback_can_be_reconnected_and_then_manually_changed(self):
        with patch.dict(os.environ, ENV_PLEX):
            self.connection_journey()
            restarted = ConnectionSettings(self.store.path)
            self.assertEqual(restarted.snapshot()['PLEX_ADMIN_TOKEN'], 'manual-private-token')
            self.assertEqual(self.post('remove-PLEX_ADMIN_TOKEN').status_code, 200)
            revealed = self.client.post('/settings/connections/reveal', data={
                'csrf_token': 'test-csrf', 'name': 'PLEX_ADMIN_TOKEN'})
            self.assertEqual(revealed.json, {'value': ''})
            self.assertEqual(ConnectionSettings(self.store.path).get('PLEX_ADMIN_TOKEN'), '')

    def test_manual_save_can_replace_environment_fields_before_using_connect(self):
        with patch.dict(os.environ, ENV_PLEX):
            self.assert_editable_controls()
            response = self.post('save-plex', PLEX_SERVER_URL_scheme='https',
                                 PLEX_SERVER_URL_host='manual.example.test', PLEX_SERVER_URL_port='443',
                                 PLEX_SERVER_URL_path='', PLEX_MACHINE_IDENTIFIER='manual-machine',
                                 PLEX_ADMIN_TOKEN='')
            self.assertIn(b'Settings saved.', response.data)
            expected = {'PLEX_SERVER_URL': 'https://manual.example.test:443',
                        'PLEX_MACHINE_IDENTIFIER': 'manual-machine',
                        'PLEX_ADMIN_TOKEN': ENV_PLEX['PLEX_ADMIN_TOKEN']}
            self.assertEqual({name: self.store.get(name) for name in PLEX_FIELDS}, expected)
            self.assertEqual({name: self.store.snapshot()[name] for name in PLEX_FIELDS}, expected)
            self.assertIn(b'Settings saved.', self.post(
                'save-plex', PLEX_ADMIN_TOKEN='manual-private-token').data)
            revealed = self.client.post('/settings/connections/reveal', data={
                'csrf_token': 'test-csrf', 'name': 'PLEX_ADMIN_TOKEN'})
            self.assertEqual(revealed.json, {'value': 'manual-private-token'})
            self.assertEqual(revealed.headers['Cache-Control'], 'no-store')
            self.assert_editable_controls()

    def test_manual_and_automatic_changes_require_owner_and_csrf(self):
        endpoints = ('/settings/connections', '/settings/connections/plex/connect',
                     '/settings/connections/plex/select')
        with patch.dict(os.environ, ENV_PLEX), patch.object(self.store, 'save') as save:
            for endpoint in endpoints:
                self.assertEqual(self.client.post(endpoint, data={
                    'action': 'save-plex', 'PLEX_ADMIN_TOKEN': 'forged'}).status_code, 403)
            with patch.object(keep, 'is_owner', return_value=False):
                for endpoint in endpoints:
                    self.assertEqual(self.client.post(endpoint, data={
                        'csrf_token': 'test-csrf', 'action': 'save-plex',
                        'PLEX_ADMIN_TOKEN': 'forged'}).status_code, 403)
            save.assert_not_called()
