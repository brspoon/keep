"""New-user defaults preserve existing choices and verified Plex access."""
from contextlib import closing
import copy
from html.parser import HTMLParser
import time
from unittest import TestCase
from unittest.mock import Mock, patch

import test_keep

keep = test_keep.keep


class Fields(HTMLParser):
    def __init__(self, body):
        super().__init__()
        self.inputs = []
        self.in_defaults_form = False
        self.feed(body)

    def handle_starttag(self, tag, attributes):
        attributes = dict(attributes)
        if tag == 'form':
            self.in_defaults_form = attributes.get('data-save-key') == 'plex-user-defaults'
        if tag == 'input' and self.in_defaults_form:
            self.inputs.append(attributes)

    def handle_endtag(self, tag):
        if tag == 'form':
            self.in_defaults_form = False


class PlexDefaultsRouteTests(TestCase):
    def setUp(self):
        test_keep.KeepTests.setUp(self)
        token = keep._settings_snapshot.set(None)
        self.addCleanup(keep._settings_snapshot.reset, token)
        environment = patch.dict(keep.os.environ, PLEX_ADMIN_TOKEN='synthetic-plex-admin')
        environment.start()
        self.addCleanup(environment.stop)
        self.scope = keep.plex_defaults_scope()
        self.proof = {'machine': 'test', 'checked_at': time.time(), 'sections': {
            '1': {'key': '1', 'name': 'Movies', 'kind': 'movie', 'locations': ['/media/movies']},
            '2': {'key': '2', 'name': 'Private Movies', 'kind': 'movie', 'locations': ['/media/private']},
            '3': {'key': '3', 'name': 'Shows', 'kind': 'show', 'locations': ['/media/shows']},
        }, 'users': {uid: {'sections': ['1'], 'restricted': False} for uid in ('8', '9')}}
        with closing(keep.attribution_db()) as db, db:
            # Start with unset modes and no prior automatic delivery ownership.
            for table in ('plex_user_default_modes', 'plex_user_default_proof', 'plex_user_default_mappings',
                          'plex_user_default_email_overrides', 'plex_defaults_email_links',
                          'plex_defaults_email_mappings', 'recipient_subscriptions', 'email_recipients'):
                db.execute('DELETE FROM ' + table)
            db.execute("UPDATE plex_user_default_settings SET email_enabled=1,library_enabled=1,owner_id='7' WHERE id=1")
            for uid in ('8', '9'):
                db.execute('''INSERT INTO user_profiles(plex_id,plex_username,email,plex_checked_at)
                    VALUES (?,?,?,CURRENT_TIMESTAMP)''', (uid, 'Plex ' + uid, 'user' + uid + '@example.test'))
            db.executemany('''INSERT INTO media_libraries(library_key,service,external_id,name,path)
                VALUES (?,?,?,?,?)''', [('radarr:1', 'radarr', '1', 'Movies', '/media/movies'),
                                      ('radarr:2', 'radarr', '2', 'Private Movies', '/media/private')])
            db.execute('''INSERT INTO keep_schedules(collection_id,media_id,expires_at,extension_available_at)
                VALUES ('1','42','2099-01-31 12:00:00','2099-01-01 12:00:00')''')
            keep.plex_user_defaults.reconcile(db, proof=self.proof, scope=self.scope, owner_id='7')
            keep.plex_user_defaults.save_mappings(db, {'radarr:1': ['1'], 'radarr:2': ['2']},
                [dict(row) for row in db.execute('SELECT * FROM media_libraries')], self.scope)
            keep.plex_defaults_email.save_collection_mappings(db, {1: ['1'], 3: ['3']},
                scope=self.scope, collection_ids=keep.recipient_collection_ids())

    def form(self, path, **fields):
        return self.client.post(path, data={'csrf_token': 'test-csrf', **fields})

    def profile(self, uid='8'):
        with closing(keep.attribution_db()) as db:
            return dict(db.execute('SELECT * FROM user_profiles WHERE plex_id=?', (uid,)).fetchone())

    def rows(self, *tables):
        with closing(keep.attribution_db()) as db:
            return {table: sorted(tuple(row) for row in db.execute('SELECT * FROM ' + table)) for table in tables}

    def protected(self):
        return self.rows('general_settings', 'keep_schedules', 'user_profiles', 'user_library_permissions',
            'email_recipients', 'recipient_subscriptions', 'plex_user_default_settings', 'plex_user_default_modes',
            'plex_user_default_proof', 'plex_user_default_mappings', 'plex_user_default_email_overrides',
            'plex_defaults_email_links', 'plex_defaults_email_mappings')

    def enroll(self, uid='8'):
        with closing(keep.attribution_db()) as db, db:
            keep.plex_user_defaults.enroll_new_users(db, [uid], '7')
            keep.plex_defaults_email.reconcile(db, scope=self.scope, collection_ids=keep.recipient_collection_ids())

    def modes(self, uid='8'):
        with closing(keep.attribution_db()) as db:
            return keep.plex_user_defaults.user_modes(db, uid)

    def editor_generation(self, uid='8'):
        with closing(keep.attribution_db()) as db:
            return keep.plex_user_library_editor_state(db, self.profile(uid), keep.media_libraries())['generation']

    def access_snapshot(self, new_id='10'):
        return {'authorized': {'7', '8', '9', new_id},
            'profiles': {new_id: {'username': 'New Plex', 'email': 'new@example.test'}},
            'scope': keep._plex_sync_scope(keep._plex_sync_connection(fresh=True)),
            'started': time.monotonic()}

    def test_general_renders_only_two_new_user_default_toggles_without_writes_or_network(self):
        before = self.protected()
        with patch.object(keep.requests, 'get') as network, patch.object(keep, 'sync_plex_user_access') as sync:
            general = self.client.get('/settings/general')
        self.assertEqual(general.status_code, 200)
        self.assertIn('no-store', general.headers['Cache-Control'])
        body = general.get_data(as_text=True)
        fields = Fields(body).inputs
        boxes = [row for row in fields if row.get('type') == 'checkbox']
        self.assertEqual({row['name'] for row in boxes}, {'email_enabled', 'library_enabled'})
        self.assertEqual(len(boxes), 2)
        self.assertTrue(all(row['value'] == '1' and 'checked' in row and 'disabled' not in row for row in boxes))
        self.assertEqual({row['name']: row['value'] for row in fields if row.get('type') == 'hidden'},
                         {'csrf_token': 'test-csrf', 'action': 'plex-defaults'})
        self.assertNotIn('/settings/users/plex-defaults', body)
        self.assertNotIn('mapping_generation', body)
        self.assertNotIn('plex-mappings', body)
        self.assertEqual(self.protected(), before)
        network.assert_not_called()
        sync.assert_not_called()

    def test_defaults_saves_preserve_manual_permissions_auto_modes_and_email_optouts(self):
        test_keep.set_keep_duration_days(45)
        self.enroll('8')
        self.enroll('9')
        response = self.form('/settings/recipients', action='disable', email='user8@example.test')
        self.assertEqual(response.status_code, 302)
        response = self.form('/settings/users/9', full_name='Manual Person', display_name='Manual',
            plex_library_state=self.editor_generation('9'), can_delete_media='1', library_key=['radarr:2'])
        self.assertEqual(response.status_code, 302)
        with closing(keep.attribution_db()) as db, db:
            db.execute("INSERT INTO user_profiles(plex_id,plex_username,email,plex_checked_at) VALUES ('11','Existing Plex','existing@example.test',CURRENT_TIMESTAMP)")
        before = self.protected()
        before.pop('plex_user_default_settings')
        for email, library in ((False, False), (True, False), (False, True), (True, True)):
            with self.subTest(email=email, library=library):
                fields = {name: '1' for name, enabled in (('email_enabled', email), ('library_enabled', library)) if enabled}
                response = self.form('/settings/general', action='plex-defaults', **fields)
                self.assertEqual(response.status_code, 302)
                self.assertEqual(response.headers['Location'], '/settings/general')
                with closing(keep.attribution_db()) as db:
                    self.assertEqual(keep.plex_user_defaults.settings(db), {'email_enabled': email, 'library_enabled': library})
                page = self.client.get('/settings/general')
                boxes = {row['name']: 'checked' in row for row in Fields(page.get_data(as_text=True)).inputs
                         if row.get('type') == 'checkbox'}
                self.assertEqual(boxes, {'email_enabled': email, 'library_enabled': library})
                self.assertEqual(self.rows(*before), before)
                self.assertEqual(self.modes('8'), {'email': 'manual', 'library': 'auto'})
                self.assertEqual(self.modes('9'), {'email': 'auto', 'library': 'manual'})
                self.assertEqual(self.modes('11'), {'email': 'unset', 'library': 'unset'})
                self.assertEqual(keep.granted_library_keys({'id': 8}), {'radarr:1'})
                self.assertEqual(keep.granted_library_keys({'id': 9}), {'radarr:2'})

    def test_missing_csrf_and_non_owner_cannot_save_defaults(self):
        before = self.protected()
        for csrf in (None, '', 'incorrect'):
            fields = {'action': 'plex-defaults', 'email_enabled': '1'}
            if csrf is not None:
                fields['csrf_token'] = csrf
            with self.subTest(csrf=csrf):
                self.assertEqual(self.client.post('/settings/general', data=fields).status_code, 403)
        with self.client.session_transaction() as session:
            session['plex_user'] = {'id': 8, 'username': 'Plex 8'}
        self.assertEqual(self.form('/settings/general', action='plex-defaults', email_enabled='1').status_code, 403)
        self.assertEqual(self.client.get('/settings/general').status_code, 403)
        self.assertEqual(self.protected(), before)

    def test_invalid_or_duplicate_default_values_cannot_partially_save(self):
        before = self.protected()
        for fields in ({'email_enabled': 'true'}, {'library_enabled': '0'},
                       {'email_enabled': ['1', '1']}, {'library_enabled': ['1', '0']}):
            with self.subTest(fields=fields):
                self.assertEqual(self.form('/settings/general', action='plex-defaults', **fields).status_code, 400)
                self.assertEqual(self.protected(), before)

    def test_removed_existing_user_review_is_not_a_get_or_post_entry_point(self):
        before = self.protected()
        self.assertNotIn('settings_plex_defaults_review', keep.app.view_functions)
        # The existing POST-only user editor still matches this unknown ID.
        for method, status in (('GET', 405), ('POST', 404)):
            with self.subTest(method=method):
                response = self.client.open('/settings/users/plex-defaults', method=method,
                    data={'csrf_token': 'test-csrf', 'preview_generation': 'old-confirmation', 'user_id': ['8']})
                self.assertEqual(response.status_code, status)
        self.assertEqual(self.protected(), before)

    def test_removed_mapping_action_is_rejected_without_changing_settings_or_access(self):
        before = self.protected()
        response = self.form('/settings/general', action='plex-mappings', mapping_generation='old-confirmation',
                             **{'library:radarr:1': ['2'], 'collection:1': ['2']})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.protected(), before)

    def test_first_verified_callback_enrolls_only_new_user_and_defers_until_scoped_sync(self):
        with self.client.session_transaction() as session:
            session['plex_binding'] = 'new-default-user'
        state = keep.onboarding.put_flow('new-default-user', 'login', {'pin': 123, 'code': 'test-code'})
        pin, jobs = Mock(), Mock()
        pin.json.return_value = {'authToken': 'synthetic-login-token'}
        with patch.object(keep.requests, 'get', return_value=pin), \
             patch.object(keep, 'get_plex_user', return_value={'id': '10', 'username': 'New Plex',
                 'email': 'new@example.test', 'thumb': ''}), \
             patch.object(keep, 'plex_user_has_server_access', return_value=True), \
             patch.object(keep, 'job_store', return_value=jobs):
            response = self.client.get('/auth/plex/callback?state=' + state)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.modes('10'), {'email': 'auto', 'library': 'auto'})
        self.assertEqual(self.modes('8'), {'email': 'unset', 'library': 'unset'})
        self.assertTrue(self.profile('10')['last_seen_at'])
        self.assertEqual(self.profile('10')['can_delete_media'], 0)
        self.assertEqual(keep.granted_library_keys({'id': 10}), set())
        jobs.request_run.assert_called_once_with('plex-access-sync')

    def test_library_proof_failure_defers_new_discovery_defaults_then_success_scopes_them(self):
        snapshot = self.access_snapshot()
        with patch.object(keep, 'get_plex_user_access_snapshot', return_value=snapshot), \
             patch.object(keep, 'get_plex_library_access_snapshot', return_value=(None, self.scope, [])):
            self.assertEqual(keep.sync_plex_user_access(), 1)
        self.assertEqual(self.modes('10'), {'email': 'auto', 'library': 'auto'})
        self.assertEqual(keep.granted_library_keys({'id': 10}), set())
        with closing(keep.attribution_db()) as db:
            self.assertFalse(db.execute("SELECT 1 FROM email_recipients WHERE email='new@example.test'").fetchone())
        proof = copy.deepcopy(self.proof)
        proof['users']['10'] = {'sections': ['1'], 'restricted': False}
        with patch.object(keep, 'get_plex_user_access_snapshot', return_value=snapshot), \
             patch.object(keep, 'get_plex_library_access_snapshot', return_value=(proof, self.scope, [])):
            keep.sync_plex_user_access()
        self.assertEqual(keep.granted_library_keys({'id': 10}), {'radarr:1'})
        profile = self.profile('10')
        self.assertTrue(all(profile[field] == 0 for field in ('can_delete_media', 'can_delete_any', 'can_remove_any', 'can_keep_indefinitely')))
        with closing(keep.attribution_db()) as db:
            topics = [row[0] for row in db.execute("SELECT collection_id FROM recipient_subscriptions WHERE email='new@example.test' AND enabled=1")]
        self.assertEqual(topics, [1])

    def test_login_queue_contention_preserves_verified_login_and_defers_defaults(self):
        jobs = Mock()
        jobs.request_run.side_effect = keep.sqlite3.OperationalError('database is locked')
        with patch.object(keep, 'job_store', return_value=jobs):
            keep.remember_plex_user({'id': '10', 'username': 'New Plex',
                'email': 'new@example.test'}, access_verified=True)
        self.assertEqual(self.modes('10'), {'email': 'auto', 'library': 'auto'})
        self.assertTrue(self.profile('10')['last_seen_at'])
        self.assertEqual(keep.granted_library_keys({'id': 10}), set())

    def test_rejected_identity_collision_invalidates_previous_automatic_access(self):
        self.enroll('8')
        self.assertEqual(keep.granted_library_keys({'id': 8}), {'radarr:1'})
        with closing(keep.attribution_db()) as db, db:
            db.execute("UPDATE user_profiles SET auth_type='local' WHERE plex_id='9'")
        before = self.rows('user_profiles', 'user_library_permissions')
        snapshot = self.access_snapshot(new_id='9')
        revoked = copy.deepcopy(self.proof)
        revoked['users']['8']['sections'] = []
        with patch.object(keep, 'get_plex_user_access_snapshot', return_value=snapshot), \
             patch.object(keep, 'get_plex_library_access_snapshot', return_value=(revoked, self.scope, [])):
            self.assertIsNone(keep.sync_plex_user_access())
        self.assertEqual(keep.granted_library_keys({'id': 8}), set())
        self.assertEqual(self.rows(*before), before)

    def test_shared_new_address_cannot_partially_create_an_owner_recipient(self):
        self.enroll('8')
        with closing(keep.attribution_db()) as db, db:
            db.execute("UPDATE user_profiles SET email='shared@example.test' WHERE plex_id IN ('8','9')")
        before = self.protected()
        response = self.form('/settings/recipients', action='add', email='shared@example.test')
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.protected(), before)

    def test_shared_new_address_cannot_partially_change_existing_topics(self):
        self.enroll('8')
        with closing(keep.attribution_db()) as db, db:
            db.execute("UPDATE user_profiles SET email='shared@example.test' WHERE plex_id IN ('8','9')")
            db.execute("INSERT INTO email_recipients(email,enabled) VALUES ('shared@example.test',0)")
            db.execute("INSERT INTO recipient_subscriptions VALUES ('shared@example.test',3,1)")
        before = self.protected()
        response = self.form('/settings/recipients/preferences', email='shared@example.test', collection_id=['1'])
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.protected(), before)

    def test_follow_plex_name_save_preserves_raw_manual_flags_and_grants(self):
        self.enroll()
        with closing(keep.attribution_db()) as db, db:
            db.execute("UPDATE user_profiles SET can_delete_media=1,can_delete_any=1,can_remove_any=1,can_keep_indefinitely=1 WHERE plex_id='8'")
            db.execute("INSERT INTO user_library_permissions VALUES ('8','radarr:2')")
        before = self.profile()
        grants = self.rows('user_library_permissions')
        response = self.form('/settings/users/8', full_name=' Updated Person ', display_name='New display',
            follow_plex_libraries='1', plex_library_state=self.editor_generation(), can_remove_any='1', can_keep_indefinitely='1')
        self.assertEqual(response.status_code, 302)
        after = self.profile()
        self.assertEqual(after['full_name'], 'Updated Person')
        self.assertEqual(after['display_name'], 'New display')
        for field in before.keys() - {'full_name', 'display_name'}:
            self.assertEqual(after[field], before[field], field)
        self.assertEqual(self.rows('user_library_permissions'), grants)
        self.assertEqual(self.modes()['library'], 'auto')

    def test_forged_disabled_controls_cannot_widen_follow_plex_access(self):
        self.enroll()
        response = self.form('/settings/users/8', full_name='Person', display_name='Alias',
            follow_plex_libraries='1', plex_library_state=self.editor_generation(),
            can_delete_media='1', can_delete_any='1', library_key=['radarr:2'])
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.profile()['can_delete_media'], 0)
        self.assertEqual(self.profile()['can_delete_any'], 0)
        self.assertEqual(self.rows('user_library_permissions'), {'user_library_permissions': []})
        self.assertEqual(keep.granted_library_keys({'id': 8}), {'radarr:1'})

    def test_unchecking_follow_plex_is_manual_denial_and_sync_never_readds_it(self):
        self.enroll()
        response = self.form('/settings/users/8', full_name='Person', display_name='Alias',
                             plex_library_state=self.editor_generation())
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.modes()['library'], 'manual')
        self.assertEqual(keep.granted_library_keys({'id': 8}), set())
        snapshot = self.access_snapshot('8')
        snapshot['profiles']['8'] = {'username': 'Plex 8', 'email': 'user8@example.test'}
        with patch.object(keep, 'get_plex_user_access_snapshot', return_value=snapshot), \
             patch.object(keep, 'get_plex_library_access_snapshot', return_value=(self.proof, self.scope, [])):
            keep.sync_plex_user_access()
        self.assertEqual(self.modes()['library'], 'manual')
        self.assertEqual(keep.granted_library_keys({'id': 8}), set())

    def test_stale_or_missing_auto_editor_generation_fails_before_any_writes(self):
        self.enroll()
        old = self.editor_generation()
        proof = copy.deepcopy(self.proof)
        proof['users']['8']['sections'] = []
        with closing(keep.attribution_db()) as db, db:
            keep.plex_user_defaults.reconcile(db, proof=proof, scope=self.scope, owner_id='7')
        before = self.protected()
        for generation in (old, ''):
            self.assertEqual(self.form('/settings/users/8', full_name='Unwanted', display_name='Changed',
                follow_plex_libraries='1', plex_library_state=generation).status_code, 409)
            self.assertEqual(self.protected(), before)

    def test_legacy_manual_editor_submission_still_sets_exact_explicit_grants(self):
        response = self.form('/settings/users/8', full_name='Manual Person', display_name='Manual',
                             can_delete_media='1', library_key=['radarr:2'])
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.modes()['library'], 'manual')
        self.assertEqual(self.profile()['can_delete_media'], 1)
        self.assertEqual(keep.granted_library_keys({'id': 8}), {'radarr:2'})
