"""Verified-server discovery preserves authorization, owner choices and sign-in history."""
from contextlib import closing
import copy
import os
import unittest
from unittest.mock import Mock, patch
import xml.etree.ElementTree as ET

import test_keep

keep = test_keep.keep


def xml_users(*users):
    root = ET.Element('MediaContainer')
    for attributes, servers in users:
        user = ET.SubElement(root, 'User', attributes)
        for server in servers:
            ET.SubElement(user, 'Server', server)
    return ET.tostring(root)


def share(**changes):
    return {'machineIdentifier': 'test', 'pending': '0', 'allLibraries': '1',
            'numLibraries': '0', **changes}


def friend(user_id='8', username='Plex Friend', email='friend@example.test', servers=None):
    return ({'id': user_id, 'username': username, 'email': email},
            [share()] if servers is None else servers)


class PlexUserDiscoveryTests(unittest.TestCase):
    def setUp(self):
        test_keep.KeepTests.setUp(self)
        self.snapshot_token = keep._settings_snapshot.set(None)
        self.addCleanup(keep._settings_snapshot.reset, self.snapshot_token)
        with closing(keep.attribution_db()) as db, db:
            saved = [tuple(row) for row in db.execute('SELECT name,value FROM connection_settings')]
            overrides = [tuple(row) for row in db.execute('SELECT name FROM plex_connection_overrides')]
            db.execute('DELETE FROM connection_settings')
            db.execute('DELETE FROM plex_connection_overrides')
        def restore():
            with closing(keep.attribution_db()) as db, db:
                db.execute('DELETE FROM connection_settings')
                db.execute('DELETE FROM plex_connection_overrides')
                db.executemany('INSERT INTO connection_settings VALUES (?,?)', saved)
                db.executemany('INSERT INTO plex_connection_overrides VALUES (?)', overrides)
        self.addCleanup(restore)
        environment = patch.dict(os.environ, {'PLEX_SERVER_URL': 'http://plex',
            'PLEX_MACHINE_IDENTIFIER': 'test', 'PLEX_ADMIN_TOKEN': 'discovery-secret'})
        environment.start()
        self.addCleanup(environment.stop)
        self.identity = b'<MediaContainer machineIdentifier="test"/>'
        self.accounts = b'<MediaContainer><Account id="7"/></MediaContainer>'

    def profile(self, user_id='8'):
        with closing(keep.attribution_db()) as db:
            row = db.execute('SELECT * FROM user_profiles WHERE plex_id=?', (user_id,)).fetchone()
        return dict(row) if row else None

    def profiles(self):
        with closing(keep.attribution_db()) as db:
            return [tuple(row) for row in db.execute('SELECT * FROM user_profiles ORDER BY plex_id')]

    def sync(self, users):
        with patch('service_discovery.read_service', side_effect=[self.identity, self.accounts, users]):
            return keep.sync_plex_user_access()

    def test_all_library_user_is_discovered_before_first_sign_in_without_extra_permissions(self):
        self.assertEqual(self.sync(xml_users(friend())), 1)
        user = self.profile()
        self.assertEqual((user['plex_id'], user['plex_username'], user['email']),
                         ('8', 'Plex Friend', 'friend@example.test'))
        self.assertEqual((user['auth_type'], user['status'], user['plex_access'], user['plex_sync_visible']),
                         ('plex', 'active', 'active', 1))
        self.assertIsNone(user['last_seen_at'])
        self.assertTrue(user['plex_checked_at'])
        self.assertEqual(user['session_version'], 0)
        for field in ('can_remove_any', 'can_keep_indefinitely', 'can_delete_media', 'can_delete_any'):
            self.assertEqual(user[field], 0)
        self.assertEqual((user['display_name'], user['full_name'], user['password_hash']), ('', '', ''))
        with closing(keep.attribution_db()) as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM user_library_permissions WHERE user_id=?', ('8',)).fetchone()[0], 0)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM api_keys WHERE user_id=?', ('8',)).fetchone()[0], 0)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM email_recipients WHERE email=?', (user['email'],)).fetchone()[0], 0)
        self.assertEqual(self.sync(xml_users(friend())), 0)
        with closing(keep.attribution_db()) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM activity_log WHERE action='plex-user-discovered'").fetchone()[0], 1)

    def test_discovery_requires_an_accepted_share_on_the_configured_server(self):
        self.accounts = b'<MediaContainer><Account id="7"/><Account id="99" name="History only"/></MediaContainer>'
        users = xml_users(
            friend('8', servers=[share(machineIdentifier='other-server')]),
            friend('9', servers=[]),
            friend('10', servers=[share(pending='1')]),
            friend('11', servers=[share(allLibraries='0', numLibraries='0')]))
        self.assertEqual(self.sync(users), 0)
        self.assertEqual([self.profile(user_id) for user_id in ('8', '9', '10', '11', '99')], [None] * 5)

    def test_explicit_shared_library_count_also_qualifies(self):
        self.assertEqual(self.sync(xml_users(friend(servers=[share(allLibraries='0', numLibraries='2')]))), 1)
        self.assertIsNotNone(self.profile())

    def test_metadata_refresh_preserves_manual_names_status_permissions_and_sign_in(self):
        with closing(keep.attribution_db()) as db, db:
            db.execute("""INSERT INTO user_profiles
                (plex_id,plex_username,email,display_name,full_name,auth_type,status,plex_access,
                 plex_checked_at,plex_sync_visible,last_seen_at,session_version,
                 can_remove_any,can_keep_indefinitely,can_delete_media,can_delete_any,theme_mode,welcome_version)
                VALUES ('8','Old Plex','old@example.test','Owner alias','Owner full name','plex','disabled','active',
                 CURRENT_TIMESTAMP,1,'2026-09-01 12:00:00',4,1,1,1,1,'dark','old-welcome')""")
            db.execute("INSERT INTO user_library_permissions VALUES ('8','radarr:1')")
        before = self.profile()
        self.assertEqual(self.sync(xml_users(friend(username=' Renamed   Plex '))), 1)
        after = self.profile()
        self.assertEqual(after['plex_username'], 'Renamed Plex')
        self.assertEqual(after['email'], 'friend@example.test')
        for field in ('display_name', 'full_name', 'status', 'last_seen_at', 'session_version',
                      'can_remove_any', 'can_keep_indefinitely', 'can_delete_media', 'can_delete_any',
                      'theme_mode', 'welcome_version'):
            self.assertEqual(after[field], before[field], field)
        with closing(keep.attribution_db()) as db:
            self.assertEqual([tuple(row) for row in db.execute('SELECT * FROM user_library_permissions')],
                             [('8', 'radarr:1')])

    def test_missing_optional_email_does_not_erase_an_existing_address(self):
        self.sync(xml_users(friend()))
        self.assertEqual(self.sync(xml_users(friend(username='Renamed', email=''))), 1)
        self.assertEqual(self.profile()['email'], 'friend@example.test')
        self.assertIsNone(self.profile()['last_seen_at'])

    def test_missing_name_never_imports_or_erases_an_existing_name(self):
        self.assertEqual(self.sync(xml_users(friend(username=''))), 0)
        self.assertIsNone(self.profile())
        self.sync(xml_users(friend()))
        self.assertEqual(self.sync(xml_users(friend(username='', email=''))), 0)
        self.assertEqual(self.profile()['plex_username'], 'Plex Friend')

    def test_title_or_email_never_becomes_a_public_plex_username(self):
        users = xml_users(({'id': '8', 'title': 'Private Full Name'}, [share()]),
                          friend('9', username='private@example.test'))
        self.assertEqual(self.sync(users), 0)
        self.assertIsNone(self.profile('8'))
        self.assertIsNone(self.profile('9'))

    def test_malformed_or_duplicate_identity_metadata_rejects_the_entire_snapshot(self):
        malformed = (
            xml_users(friend(), friend()),
            xml_users(friend(user_id='0')),
            xml_users(friend(user_id='not-an-id')),
            xml_users(friend(username='x' * 201)),
            xml_users(friend(username='line\nname')),
            xml_users(friend(email='invalid-email')),
            xml_users(friend(servers=[share(), share()])),
            xml_users(friend(servers=[share(pending='unknown')])),
            xml_users(friend(servers=[share(allLibraries='unknown')])),
            xml_users(friend(servers=[share(allLibraries='0', numLibraries='NaN')])),
            b'<NotMediaContainer/>',
            b'<MediaContainer><User',
        )
        for users in malformed:
            with self.subTest(users=users):
                before = self.profiles()
                self.assertIsNone(self.sync(users))
                self.assertEqual(self.profiles(), before)

    def test_duplicate_server_accounts_rejects_refresh_without_revoking_known_users(self):
        self.sync(xml_users(friend()))
        before = self.profiles()
        self.accounts = b'<MediaContainer><Account id="7"/><Account id="7"/></MediaContainer>'
        self.assertIsNone(self.sync(xml_users()))
        self.assertEqual(self.profiles(), before)

    def test_server_system_account_zero_does_not_block_discovery_or_authorize_a_user(self):
        self.accounts = b'<MediaContainer><Account id="0" name=""/><Account id="7"/></MediaContainer>'
        with patch('service_discovery.read_service', side_effect=[self.identity, self.accounts, xml_users(friend())]):
            snapshot = keep.get_plex_user_access_snapshot()
        self.assertIsNotNone(snapshot)
        self.assertNotIn('0', snapshot['authorized'])
        self.assertNotIn('0', snapshot['profiles'])
        with patch.object(keep, 'get_plex_user_access_snapshot', return_value=snapshot):
            self.assertEqual(keep.sync_plex_user_access(), 1)
        self.assertIsNone(self.profile('0'))
        self.assertIsNotNone(self.profile('8'))

    def test_duplicate_zero_or_negative_server_accounts_leave_profiles_unchanged(self):
        for accounts in (b'<Account id="0"/><Account id="0"/>', b'<Account id="-1"/>'):
            with self.subTest(accounts=accounts):
                self.accounts = b'<MediaContainer>' + accounts + b'</MediaContainer>'
                before = self.profiles()
                self.assertIsNone(self.sync(xml_users(friend())))
                self.assertEqual(self.profiles(), before)

    def test_wrong_server_identity_cannot_import_or_revoke_users(self):
        self.sync(xml_users(friend()))
        before = self.profiles()
        self.identity = b'<MediaContainer machineIdentifier="different"/>'
        with patch('service_discovery.read_service', side_effect=[self.identity]) as read:
            self.assertIsNone(keep.sync_plex_user_access())
        self.assertEqual(read.call_count, 1)
        self.assertEqual(self.profiles(), before)

    def test_provider_failure_preserves_profiles_and_logs_no_exception_credentials(self):
        self.sync(xml_users(friend()))
        before = self.profiles()
        with patch('service_discovery.read_service', side_effect=keep.requests.ConnectionError('discovery-secret')), \
             patch.object(keep.app.logger, 'error') as error:
            self.assertIsNone(keep.sync_plex_user_access())
        self.assertEqual(self.profiles(), before)
        self.assertNotIn('discovery-secret', repr(error.call_args_list))

    def test_changed_connection_during_fetch_discards_all_results(self):
        before = self.profiles()
        def read(url, headers):
            if url.endswith('/identity'):
                return self.identity
            if url.endswith('/accounts'):
                return self.accounts
            keep.connection_settings.save({'PLEX_MACHINE_IDENTIFIER': 'replacement'}, plex_override=True)
            return xml_users(friend())
        with patch('service_discovery.read_service', side_effect=read):
            self.assertIsNone(keep.sync_plex_user_access())
        self.assertEqual(self.profiles(), before)

    def test_stale_worker_connection_context_never_requests_the_old_server(self):
        token = keep._settings_snapshot.set(keep.connection_settings.snapshot())
        try:
            keep.connection_settings.save({'PLEX_MACHINE_IDENTIFIER': 'replacement'}, plex_override=True)
            with patch('service_discovery.read_service') as read:
                self.assertIsNone(keep.sync_plex_user_access())
            read.assert_not_called()
        finally:
            keep._settings_snapshot.reset(token)

    def test_changed_connection_or_stale_snapshot_before_write_does_not_mutate_profiles(self):
        with patch('service_discovery.read_service', side_effect=[self.identity, self.accounts, xml_users(friend())]):
            original = keep.get_plex_user_access_snapshot()
        for age in (61, -1, float('nan')):
            with self.subTest(age=age):
                snapshot = copy.deepcopy(original)
                snapshot['started'] = keep.time.monotonic() - age
                before = self.profiles()
                with patch.object(keep, 'get_plex_user_access_snapshot', return_value=snapshot):
                    self.assertIsNone(keep.sync_plex_user_access())
                self.assertEqual(self.profiles(), before)
        keep.connection_settings.save({'PLEX_MACHINE_IDENTIFIER': 'replacement'}, plex_override=True)
        with patch.object(keep, 'get_plex_user_access_snapshot', return_value=original):
            self.assertIsNone(keep.sync_plex_user_access())
        self.assertIsNone(self.profile())

    def test_complete_feed_revokes_discovered_account_without_changing_owner_disable(self):
        self.sync(xml_users(friend()))
        with closing(keep.attribution_db()) as db, db:
            db.execute("UPDATE user_profiles SET status='disabled' WHERE plex_id='8'")
        self.assertEqual(self.sync(xml_users()), 1)
        self.assertEqual((self.profile()['plex_access'], self.profile()['status'], self.profile()['session_version']),
                         ('revoked', 'disabled', 1))
        self.assertEqual(self.sync(xml_users(friend())), 1)
        self.assertEqual((self.profile()['plex_access'], self.profile()['status'], self.profile()['session_version']),
                         ('active', 'disabled', 2))

    def test_local_account_conflict_rejects_all_imports_before_any_write(self):
        with closing(keep.attribution_db()) as db, db:
            db.execute("INSERT INTO user_profiles(plex_id,plex_username,auth_type) VALUES ('9','Local','local')")
        before = self.profiles()
        self.assertIsNone(self.sync(xml_users(friend('8'), friend('9'))))
        self.assertEqual(self.profiles(), before)

    def test_legacy_id_only_wrapper_returns_ids_without_creating_profiles(self):
        with patch('service_discovery.read_service', side_effect=[self.identity, self.accounts, xml_users(friend())]):
            self.assertEqual(keep.get_authorized_plex_user_ids(), {'7', '8'})
        self.assertIsNone(self.profile())

    def test_provider_requests_are_bounded_without_redirects_or_token_queries(self):
        class Response:
            status_code = 200
            def __init__(self, body): self.body = body
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def iter_content(self, size): return iter((self.body,))
        responses = [Response(self.identity), Response(self.accounts), Response(xml_users(friend()))]
        with patch.object(keep.requests, 'get', side_effect=responses) as get:
            self.assertEqual(keep.sync_plex_user_access(), 1)
        self.assertEqual(get.call_count, 3)
        for call in get.call_args_list:
            self.assertFalse(call.kwargs['allow_redirects'])
            self.assertTrue(call.kwargs['stream'])
            self.assertEqual(call.kwargs['timeout'], (3, 8))
            self.assertEqual(call.kwargs['headers']['X-Plex-Token'], 'discovery-secret')
            self.assertNotIn('discovery-secret', call.args[0])
        self.assertEqual(get.call_args_list[-1].args[0], 'https://plex.tv/api/users/')

    def test_total_provider_deadline_failure_preserves_profiles(self):
        before = self.profiles()
        with patch('service_discovery.read_service', side_effect=[self.identity, self.accounts, xml_users(friend())]), \
             patch.object(keep.time, 'monotonic', side_effect=[0, 0, 1, 2, 3, 44, 46]):
            self.assertIsNone(keep.sync_plex_user_access())
        self.assertEqual(self.profiles(), before)

    def test_internal_snapshot_ids_and_profile_membership_fail_closed(self):
        with patch('service_discovery.read_service', side_effect=[self.identity, self.accounts, xml_users(friend())]):
            original = keep.get_plex_user_access_snapshot()
        malformed = []
        for invalid in ('0', 'local:8', 'not-an-id'):
            value = copy.deepcopy(original)
            value['authorized'].add(invalid)
            malformed.append(value)
        value = copy.deepcopy(original)
        value['authorized'].remove('8')
        malformed.append(value)
        value = copy.deepcopy(original)
        value['profiles']['8']['username'] = 'private@example.test'
        malformed.append(value)
        value = copy.deepcopy(original)
        value['profiles']['7'] = value['profiles']['8']
        malformed.append(value)
        before = self.profiles()
        for snapshot in malformed:
            with self.subTest(snapshot=snapshot), patch.object(keep, 'get_plex_user_access_snapshot', return_value=snapshot):
                self.assertIsNone(keep.sync_plex_user_access())
                self.assertEqual(self.profiles(), before)

    def test_first_successful_plex_login_reuses_imported_profile_and_owner_choices(self):
        self.sync(xml_users(friend()))
        self.assertIsNone(self.profile()['last_seen_at'])
        with closing(keep.attribution_db()) as db, db:
            db.execute("""UPDATE user_profiles SET display_name='Custom alias', full_name='Owner-set name',
                can_remove_any=1,can_keep_indefinitely=1,can_delete_media=1,can_delete_any=1
                WHERE plex_id='8'""")
            db.execute("INSERT INTO user_library_permissions VALUES ('8','radarr:1')")
        before = self.profile()
        with self.client.session_transaction() as session:
            session['plex_binding'] = 'discovered-user-login'
        state = keep.onboarding.put_flow('discovered-user-login', 'login', {'pin': 123, 'code': 'test-code'})
        pin = Mock()
        pin.json.return_value = {'authToken': 'synthetic-login-token'}
        with patch.object(keep.requests, 'get', return_value=pin), \
             patch.object(keep, 'get_plex_user', return_value={
                 'id': '8', 'username': 'Signed-in Plex', 'email': 'friend@example.test', 'thumb': ''}), \
             patch.object(keep, 'plex_user_has_server_access', return_value=True):
            response = self.client.get('/auth/plex/callback?state=' + state)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers['Location'], '/')
        after = self.profile()
        self.assertTrue(after['last_seen_at'])
        self.assertEqual(after['plex_username'], 'Signed-in Plex')
        for field in ('plex_id', 'auth_type', 'status', 'display_name', 'full_name', 'session_version',
                      'can_remove_any', 'can_keep_indefinitely', 'can_delete_media', 'can_delete_any'):
            self.assertEqual(after[field], before[field], field)
        with closing(keep.attribution_db()) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM user_profiles WHERE plex_id='8'").fetchone()[0], 1)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM user_profiles').fetchone()[0], 2)
            self.assertEqual([tuple(row) for row in db.execute('SELECT * FROM user_library_permissions')],
                             [('8', 'radarr:1')])
        with self.client.session_transaction() as session:
            self.assertEqual(str(session['plex_user']['id']), '8')
