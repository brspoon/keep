"""Isolated policy tests: no Flask imports, provider requests, or email delivery."""
import copy
import sqlite3
import sys
import tempfile
import threading
import types
import unittest
from unittest.mock import patch

import plex_user_defaults as defaults

SCOPE = 'a' * 64
OTHER_SCOPE = 'b' * 64


class PlexUserDefaultsTests(unittest.TestCase):
    def setUp(self):
        self.now = 1800000000.0
        self.clock = patch.object(defaults.time, 'time', side_effect=lambda: self.now)
        self.clock.start()
        self.addCleanup(self.clock.stop)
        self.db = sqlite3.connect(':memory:')
        self.addCleanup(self.db.close)
        self.db.executescript('''
            CREATE TABLE installation(id INTEGER PRIMARY KEY,owner TEXT);
            INSERT INTO installation VALUES(1,'7');
            CREATE TABLE user_profiles(plex_id TEXT PRIMARY KEY,plex_username TEXT DEFAULT '',
              email TEXT DEFAULT '',display_name TEXT DEFAULT '',full_name TEXT DEFAULT '',
              auth_type TEXT DEFAULT 'plex',status TEXT DEFAULT 'active',plex_access TEXT DEFAULT 'active',
              can_delete_media INTEGER DEFAULT 0,can_delete_any INTEGER DEFAULT 0,
              can_remove_any INTEGER DEFAULT 0,can_keep_indefinitely INTEGER DEFAULT 0,
              last_seen_at TEXT,plex_checked_at TEXT,session_version INTEGER DEFAULT 0,
              password_hash TEXT DEFAULT '',welcome_version TEXT DEFAULT '');
            CREATE TABLE media_libraries(library_key TEXT PRIMARY KEY,service TEXT,path TEXT,name TEXT);
            CREATE TABLE user_library_permissions(user_id TEXT,library_key TEXT,PRIMARY KEY(user_id,library_key));
            CREATE TABLE email_recipients(email TEXT PRIMARY KEY COLLATE NOCASE,enabled INTEGER);
            CREATE TABLE recipient_subscriptions(email TEXT COLLATE NOCASE,collection_id INTEGER,
              enabled INTEGER,PRIMARY KEY(email,collection_id));
        ''')
        for uid, email in (('7', 'owner@example.test'), ('8', 'existing@example.test'),
                           ('9', 'new@example.test'), ('10', 'other@example.test'), ('11', '')):
            self.db.execute('INSERT INTO user_profiles(plex_id,plex_username,email) VALUES(?,?,?)',
                            (uid, 'Plex ' + uid, email))
        self.db.execute("INSERT INTO user_profiles(plex_id,email,auth_type) VALUES('local:x','local@example.test','local')")
        self.libraries = [
            {'library_key': 'radarr:1', 'service': 'radarr', 'path': '/media/movies', 'name': 'Movies'},
            {'library_key': 'sonarr:2', 'service': 'sonarr', 'path': '/media/shows', 'name': 'Shows'},
            {'library_key': 'radarr:3', 'service': 'radarr', 'path': '/media/private', 'name': 'Private'},
        ]
        self.db.executemany('INSERT INTO media_libraries VALUES(:library_key,:service,:path,:name)', self.libraries)
        self.proof = {'machine': 'server-one', 'checked_at': self.now,
                      'sections': {
                          '1': {'key': '1', 'name': 'Movies', 'kind': 'movie', 'locations': ['/media/movies']},
                          '2': {'key': '2', 'name': 'Shows', 'kind': 'show', 'locations': ['/media/shows']},
                          '3': {'key': '3', 'name': 'Private', 'kind': 'movie', 'locations': ['/media/private']},
                      }, 'users': {uid: {'sections': ['1', '2'], 'restricted': False} for uid in ('8', '9', '11')}}
        self.proof['users']['10'] = {'sections': ['3'], 'restricted': False}
        defaults.init_schema(self.db)

        def can_manage(db, address, user_id):
            return not (db.execute('SELECT 1 FROM email_recipients WHERE email=?', (address,)).fetchone()
                        or db.execute('SELECT 1 FROM recipient_subscriptions WHERE email=?', (address,)).fetchone())

        def collections(db, uid, scope, collection_ids, libraries=None, **kwargs):
            proof = defaults._proof(db, scope)
            sections = proof['users'].get(uid, {}).get('sections', []) if proof else []
            return sorted({100 + int(key) for key in sections} & set(collection_ids))

        self.email_module = types.SimpleNamespace(can_manage_address=can_manage, eligible_collections=collections)
        self.modules = patch.dict(sys.modules, {'plex_defaults_email': self.email_module})
        self.modules.start()
        self.addCleanup(self.modules.stop)
        self.sync()
        self.db.commit()

    def sync(self, proof=None, *, new=(), scope=SCOPE):
        return defaults.reconcile(self.db, proof=self.proof if proof is None else proof,
                                  scope=scope, owner_id='7', new_user_ids=new, now=self.now)

    def protected(self):
        return {name: self.db.execute('SELECT * FROM ' + name + ' ORDER BY 1,2').fetchall()
                for name in ('user_profiles', 'user_library_permissions', 'email_recipients', 'recipient_subscriptions')}

    def preview(self):
        return defaults.preview(self.db, SCOPE, self.libraries, [101, 102, 103])

    def row(self, uid):
        return next(row for row in self.preview()['users'] if row['id'] == uid)

    def test_schema_defaults_are_enabled_idempotent_and_do_not_change_existing_choices(self):
        before = self.protected()
        defaults.init_schema(self.db)
        self.assertEqual(defaults.settings(self.db), {'email_enabled': True, 'library_enabled': True})
        self.assertEqual(defaults.user_modes(self.db, '8'), {'email': 'unset', 'library': 'unset'})
        self.assertEqual(self.protected(), before)
        with self.assertRaises(ValueError):
            defaults.save_settings(self.db, 'false', True)

    def test_only_supplied_new_plex_users_enroll_and_manual_tables_stay_exact(self):
        before = self.protected()
        self.assertEqual(defaults.enroll_new_users(self.db, ['9', '7', 'local:x', 'missing'], '7'), ['9'])
        self.assertEqual(defaults.user_modes(self.db, '9'), {'email': 'auto', 'library': 'auto'})
        self.assertEqual(defaults.user_modes(self.db, '8'), {'email': 'unset', 'library': 'unset'})
        self.assertEqual(defaults.auto_library_keys(self.db, '9', SCOPE), {'radarr:1', 'sonarr:2'})
        self.assertEqual(defaults.auto_email_accounts(self.db, SCOPE),
                         [{'user_id': '9', 'email': 'new@example.test', 'sections': ['1', '2']}])
        self.assertEqual(self.protected(), before)
        self.assertEqual(defaults.enroll_new_users(self.db, ['9'], '7'), [])

    def test_discovery_does_not_automatically_adopt_existing_users(self):
        self.sync()
        self.assertEqual(defaults.auto_library_keys(self.db, '8', SCOPE), set())
        self.assertEqual(defaults.auto_email_accounts(self.db, SCOPE), [])
        self.sync(new=['9'])
        self.assertEqual(defaults.user_modes(self.db, '9')['library'], 'auto')

    def test_enrollment_survives_missing_proof_but_access_waits_for_verification(self):
        defaults.enroll_new_users(self.db, ['9'], '7')
        result = defaults.reconcile(self.db, proof=None, scope=SCOPE, owner_id='7', now=self.now)
        self.assertFalse(result['verified'])
        self.assertEqual(defaults.user_modes(self.db, '9')['email'], 'auto')
        self.assertEqual(defaults.auto_library_keys(self.db, '9', SCOPE), set())
        self.assertEqual(defaults.catalog(self.db, SCOPE), {})
        self.sync()
        self.assertEqual(defaults.auto_library_keys(self.db, '9', SCOPE), {'radarr:1', 'sonarr:2'})

    def test_future_default_toggles_do_not_withdraw_existing_auto_accounts_or_retro_enroll(self):
        defaults.enroll_new_users(self.db, ['9'], '7')
        defaults.save_settings(self.db, False, False)
        self.assertEqual(defaults.auto_library_keys(self.db, '9', SCOPE), {'radarr:1', 'sonarr:2'})
        self.assertEqual(len(defaults.auto_email_accounts(self.db, SCOPE)), 1)
        self.assertEqual(defaults.enroll_new_users(self.db, ['10'], '7'), [])
        self.assertEqual(defaults.user_modes(self.db, '10'), {'email': 'unset', 'library': 'unset'})
        self.assertFalse(self.row('8')['email_eligible'])
        self.assertFalse(self.row('8')['library_eligible'])
        defaults.save_settings(self.db, True, True)
        self.assertEqual(defaults.enroll_new_users(self.db, ['10'], '7'), [])
        self.assertEqual(defaults.user_modes(self.db, '10'), {'email': 'unset', 'library': 'unset'})

    def test_invalid_stale_future_and_malformed_proofs_fail_closed(self):
        defaults.enroll_new_users(self.db, ['9'], '7')
        variants = [None, {}, {**self.proof, 'checked_at': self.now - 1801},
                    {**self.proof, 'checked_at': self.now + 1}, {**self.proof, 'checked_at': True}]
        missing = copy.deepcopy(self.proof)
        del missing['checked_at']
        variants.append(missing)
        unknown = copy.deepcopy(self.proof)
        unknown['users']['9']['sections'] = ['999']
        variants.append(unknown)
        for proof in variants:
            with self.subTest(proof=proof):
                result = defaults.reconcile(self.db, proof=proof, scope=SCOPE, owner_id='7', now=self.now)
                self.assertFalse(result['verified'])
                self.assertEqual(defaults.auto_library_keys(self.db, '9', SCOPE), set())
                self.assertEqual(defaults.auto_email_accounts(self.db, SCOPE), [])
                self.assertEqual(defaults.user_modes(self.db, '9')['library'], 'auto')

    def test_freshness_boundary_and_configuration_scope_are_required(self):
        defaults.enroll_new_users(self.db, ['9'], '7')
        self.assertTrue(defaults.auto_library_keys(self.db, '9', SCOPE, now=self.now + 1800))
        self.assertEqual(defaults.auto_library_keys(self.db, '9', SCOPE, now=self.now + 1800.01), set())
        self.assertEqual(defaults.auto_library_keys(self.db, '9', OTHER_SCOPE), set())
        self.assertEqual(defaults.shared_email_accounts(self.db, OTHER_SCOPE), [])

    def test_revocation_restrictions_and_partial_sharing_change_only_effective_access(self):
        defaults.enroll_new_users(self.db, ['9'], '7')
        for change in ('missing', 'restricted', 'partial'):
            with self.subTest(change=change):
                proof = copy.deepcopy(self.proof)
                if change == 'missing':
                    del proof['users']['9']
                elif change == 'restricted':
                    proof['users']['9']['restricted'] = True
                else:
                    proof['users']['9']['sections'] = ['1']
                self.sync(proof)
                expected = {'radarr:1'} if change == 'partial' else set()
                self.assertEqual(defaults.auto_library_keys(self.db, '9', SCOPE), expected)
                self.assertEqual(defaults.user_modes(self.db, '9')['library'], 'auto')

    def test_disabled_revoked_local_and_owner_profiles_never_gain_automatic_access(self):
        defaults.enroll_new_users(self.db, ['9'], '7')
        for field, value in (('status', 'disabled'), ('plex_access', 'revoked'), ('auth_type', 'local')):
            with self.subTest(field=field):
                self.db.execute('UPDATE user_profiles SET ' + field + '=? WHERE plex_id=\'9\'', (value,))
                self.assertEqual(defaults.auto_library_keys(self.db, '9', SCOPE), set())
                self.assertFalse(any(a['user_id'] == '9' for a in defaults.shared_email_accounts(self.db, SCOPE)))
                self.db.execute("UPDATE user_profiles SET status='active',plex_access='active',auth_type='plex' WHERE plex_id='9'")
        self.assertEqual(defaults.enroll_new_users(self.db, ['7', 'local:x'], '7'), [])

    def test_owner_library_override_is_separate_and_persistent(self):
        defaults.enroll_new_users(self.db, ['9'], '7')
        before = self.protected()
        defaults.manual_library_override(self.db, '9')
        self.sync(new=['9'])
        self.assertEqual(defaults.user_modes(self.db, '9'), {'email': 'auto', 'library': 'manual'})
        self.assertEqual(defaults.auto_library_keys(self.db, '9', SCOPE), set())
        self.assertEqual(len(defaults.auto_email_accounts(self.db, SCOPE)), 1)
        self.assertEqual(self.protected(), before)

    def test_email_override_follows_linked_account_after_address_changes(self):
        defaults.enroll_new_users(self.db, ['9'], '7')
        defaults.email_override(self.db, ' NEW@EXAMPLE.TEST ', user_id='9')
        self.db.execute("UPDATE user_profiles SET email='changed@example.test' WHERE plex_id='9'")
        self.sync(new=['9'])
        self.assertEqual(defaults.user_modes(self.db, '9')['email'], 'manual')
        self.assertEqual(defaults.auto_email_accounts(self.db, SCOPE), [])
        shared = next(row for row in defaults.shared_email_accounts(self.db, SCOPE) if row['user_id'] == '9')
        self.assertEqual(shared['email'], 'changed@example.test')
        self.assertTrue(defaults.auto_library_keys(self.db, '9', SCOPE))

    def test_automatic_email_origin_survives_manual_override_before_first_address_or_proof(self):
        defaults.enroll_new_users(self.db, ['11'], '7')
        defaults.reconcile(self.db, proof=None, scope=SCOPE, owner_id='7', now=self.now)
        self.assertTrue(defaults.email_was_automatic(self.db, '11'))
        defaults.email_override(self.db, '', user_id='11')
        self.db.execute("UPDATE user_profiles SET email='later@example.test' WHERE plex_id='11'")
        defaults.email_override(self.db, 'later@example.test', user_id='11')
        self.assertEqual(defaults.user_modes(self.db, '11')['email'], 'manual')
        self.assertTrue(defaults.email_was_automatic(self.db, '11'))
        self.assertFalse(defaults.email_was_automatic(self.db, '8'))
        self.assertFalse(defaults.email_was_automatic(self.db, 'unknown'))

    def test_explicit_apply_records_per_feature_automatic_email_origin(self):
        preview = self.preview()
        defaults.apply_existing(self.db, ['8'], preview['generation'], SCOPE, self.libraries, [101, 102, 103])
        self.assertTrue(defaults.email_was_automatic(self.db, '8'))
        defaults.manual_library_override(self.db, '8')
        defaults.email_override(self.db, 'existing@example.test', user_id='8')
        self.assertTrue(defaults.email_was_automatic(self.db, '8'))
        defaults.save_settings(self.db, False, True)
        defaults.enroll_new_users(self.db, ['9'], '7')
        self.assertFalse(defaults.email_was_automatic(self.db, '9'))

    def test_unreleased_mode_migration_marks_only_current_auto_email_as_origin(self):
        self.db.execute("INSERT INTO plex_user_default_modes(user_id,email_mode,library_mode) VALUES('8','auto','unset')")
        self.db.execute("INSERT INTO plex_user_default_modes(user_id,email_mode,library_mode) VALUES('9','manual','auto')")
        defaults.init_schema(self.db)
        self.assertTrue(defaults.email_was_automatic(self.db, '8'))
        self.assertFalse(defaults.email_was_automatic(self.db, '9'))

    def test_address_override_covers_linked_accounts_and_future_reuse(self):
        self.db.execute("UPDATE user_profiles SET email='new@example.test' WHERE plex_id='8'")
        defaults.email_override(self.db, 'new@example.test')
        self.assertEqual(defaults.user_modes(self.db, '8')['email'], 'manual')
        self.assertEqual(defaults.user_modes(self.db, '9')['email'], 'manual')
        self.db.execute("UPDATE user_profiles SET email='new@example.test' WHERE plex_id='10'")
        defaults.enroll_new_users(self.db, ['10'], '7')
        self.assertEqual(defaults.user_modes(self.db, '10')['email'], 'unset')

    def test_missing_invalid_and_duplicate_email_accounts_are_excluded(self):
        defaults.enroll_new_users(self.db, ['9', '11'], '7')
        self.assertEqual([row['user_id'] for row in defaults.auto_email_accounts(self.db, SCOPE)], ['9'])
        self.db.execute("UPDATE user_profiles SET email='NEW@example.test' WHERE plex_id='8'")
        self.assertEqual(defaults.auto_email_accounts(self.db, SCOPE), [])
        self.db.execute("UPDATE user_profiles SET email='' WHERE plex_id='8'")
        self.db.execute("UPDATE user_profiles SET email='invalid' WHERE plex_id='9'")
        self.assertEqual(defaults.shared_email_accounts(self.db, SCOPE),
                         [{'user_id': '10', 'email': 'other@example.test', 'sections': ['3']}])

    def test_manual_recipient_and_orphan_subscription_rows_block_email_takeover(self):
        self.db.execute("INSERT INTO email_recipients VALUES('new@example.test',0)")
        self.db.execute("INSERT INTO recipient_subscriptions VALUES('existing@example.test',101,0)")
        before = self.protected()
        defaults.enroll_new_users(self.db, ['9'], '7')
        self.assertEqual(defaults.user_modes(self.db, '9')['email'], 'unset')
        self.assertFalse(self.row('8')['email_eligible'])
        self.assertFalse(self.row('9')['email_eligible'])
        self.assertEqual(self.protected(), before)

    def test_explicit_multi_section_mapping_requires_all_shared_sections(self):
        defaults.enroll_new_users(self.db, ['9'], '7')
        defaults.save_mappings(self.db, {'radarr:1': ['1', '3']}, self.libraries, SCOPE)
        self.assertNotIn('radarr:1', defaults.auto_library_keys(self.db, '9', SCOPE))
        proof = copy.deepcopy(self.proof)
        proof['users']['9']['sections'] = ['1', '2', '3']
        self.sync(proof)
        self.assertIn('radarr:1', defaults.auto_library_keys(self.db, '9', SCOPE))

    def test_mapping_validation_is_atomic_and_rejects_unknown_wrong_kind_or_duplicates(self):
        defaults.save_mappings(self.db, {'radarr:1': ['1']}, self.libraries, SCOPE)
        before = self.db.execute('SELECT * FROM plex_user_default_mappings').fetchall()
        for mapping in ({'radarr:1': ['2']}, {'radarr:1': ['999']}, {'radarr:1': ['1', '1']},
                        {'radarr:1': '1'}, {'radarr:999': ['1']}):
            with self.subTest(mapping=mapping), self.assertRaises(ValueError):
                defaults.save_mappings(self.db, mapping, self.libraries, SCOPE)
            self.assertEqual(self.db.execute('SELECT * FROM plex_user_default_mappings').fetchall(), before)

    def test_mapping_root_path_scope_machine_and_section_identity_are_pinned(self):
        defaults.enroll_new_users(self.db, ['9'], '7')
        defaults.save_mappings(self.db, {'radarr:1': ['1']}, self.libraries, SCOPE)
        changed_roots = copy.deepcopy(self.libraries)
        changed_roots[0]['path'] = '/media/private'
        self.assertNotIn('radarr:1', defaults.auto_library_keys(self.db, '9', SCOPE, libraries=changed_roots))
        for field, value in (('machine', 'replacement-server'), ('locations', ['/replaced'])):
            proof = copy.deepcopy(self.proof)
            if field == 'machine':
                proof['machine'] = value
            else:
                proof['sections']['1']['locations'] = value
            self.sync(proof)
            self.assertNotIn('radarr:1', defaults.auto_library_keys(self.db, '9', SCOPE))
        self.sync(self.proof, scope=OTHER_SCOPE)
        self.assertNotIn('radarr:1', defaults.auto_library_keys(self.db, '9', OTHER_SCOPE))

    def test_stale_caller_library_catalog_cannot_authorize_changed_database_root(self):
        defaults.enroll_new_users(self.db, ['9'], '7')
        defaults.save_mappings(self.db, {'radarr:1': ['1']}, self.libraries, SCOPE)
        self.db.execute("UPDATE media_libraries SET path='/replacement' WHERE library_key='radarr:1'")
        self.assertNotIn('radarr:1', defaults.auto_library_keys(self.db, '9', SCOPE, libraries=self.libraries))
        with self.assertRaises(ValueError):
            defaults.save_mappings(self.db, {'radarr:1': ['1']}, self.libraries, SCOPE)

    def test_explicit_empty_mapping_blocks_automatic_and_omission_restores_it(self):
        defaults.enroll_new_users(self.db, ['9'], '7')
        defaults.save_mappings(self.db, {'radarr:1': []}, self.libraries, SCOPE)
        self.assertNotIn('radarr:1', defaults.auto_library_keys(self.db, '9', SCOPE))
        defaults.save_mappings(self.db, {}, self.libraries, SCOPE)
        self.assertIn('radarr:1', defaults.auto_library_keys(self.db, '9', SCOPE))

    def test_automatic_mapping_ambiguity_never_broadens_access(self):
        defaults.enroll_new_users(self.db, ['9'], '7')
        proof = copy.deepcopy(self.proof)
        proof['sections']['4'] = {'key': '4', 'name': 'Duplicate', 'kind': 'movie', 'locations': ['/media/movies']}
        proof['users']['9']['sections'].append('4')
        self.sync(proof)
        self.assertNotIn('radarr:1', defaults.auto_library_keys(self.db, '9', SCOPE))

    def test_preview_explains_independent_feature_eligibility_without_writes(self):
        self.db.execute("UPDATE user_profiles SET can_delete_media=1 WHERE plex_id='8'")
        self.db.execute("INSERT INTO user_library_permissions VALUES('8','radarr:1')")
        self.db.execute("INSERT INTO email_recipients VALUES('new@example.test',0)")
        before = self.protected()
        rows = {row['id']: row for row in self.preview()['users']}
        self.assertNotIn('7', rows)
        self.assertNotIn('local:x', rows)
        self.assertEqual(rows['8']['eligible_features'], ['email'])
        self.assertEqual(rows['9']['eligible_features'], ['library'])
        self.assertIn('Existing manual Library permissions are preserved.', rows['8']['reasons'])
        self.assertIn('Email is already off; that choice is preserved.', rows['9']['reasons'])
        self.assertTrue(all('disabled, unavailable' not in reason for row in rows.values() for reason in row['reasons']))
        self.assertEqual(self.protected(), before)

    def test_preview_email_requires_eligible_topics_not_just_configured_collection_ids(self):
        self.email_module.eligible_collections = lambda *args, **kwargs: []
        self.assertFalse(self.row('8')['email_eligible'])
        self.assertEqual(self.row('8')['email_collection_ids'], [])

    def test_email_routing_edits_invalidate_preview_and_collection_ids_are_validated(self):
        self.email_module.preview_fingerprint = lambda *args, **kwargs: 'first'
        preview = self.preview()
        self.email_module.preview_fingerprint = lambda *args, **kwargs: 'changed topic mapping'
        with self.assertRaises(ValueError):
            defaults.apply_existing(self.db, ['8'], preview['generation'], SCOPE, self.libraries, [101, 102, 103])
        for collection_ids in ([True], [0], [-1], ['not-an-id']):
            with self.subTest(collection_ids=collection_ids), self.assertRaises(ValueError):
                defaults.preview(self.db, SCOPE, self.libraries, collection_ids)

    def test_apply_enrolls_only_explicit_selected_untouched_features(self):
        self.db.execute("UPDATE user_profiles SET can_delete_media=1 WHERE plex_id='8'")
        self.db.execute("INSERT INTO user_library_permissions VALUES('8','radarr:1')")
        before = self.protected()
        preview = self.preview()
        result = defaults.apply_existing(self.db, ['8'], preview['generation'], SCOPE, self.libraries, [101, 102, 103])
        self.assertEqual(result, {'applied': 1, 'email_user_ids': ['8'], 'library_user_ids': []})
        self.assertEqual(defaults.user_modes(self.db, '8'), {'email': 'auto', 'library': 'unset'})
        self.assertEqual(defaults.user_modes(self.db, '9'), {'email': 'unset', 'library': 'unset'})
        self.assertEqual(self.protected(), before)

    def test_preview_generation_ignores_verified_timestamp_and_runtime_churn(self):
        first = self.preview()['generation']
        self.now += 30
        self.proof['checked_at'] = self.now
        self.sync()
        self.db.execute("UPDATE user_profiles SET plex_checked_at='new check',last_seen_at='new login',welcome_version='new welcome'")
        self.assertEqual(self.preview()['generation'], first)
        self.db.execute("UPDATE user_profiles SET session_version=1 WHERE plex_id='8'")
        self.assertNotEqual(self.preview()['generation'], first)

    def test_expired_preview_cannot_apply_even_with_matching_historical_generation(self):
        preview = self.preview()
        self.now += 1801
        with self.assertRaises(ValueError):
            defaults.apply_existing(self.db, ['8'], preview['generation'], SCOPE, self.libraries, [101, 102, 103])
        self.assertEqual(defaults.user_modes(self.db, '8')['library'], 'unset')

    def test_profile_recipient_mapping_settings_and_collection_drift_reject_stale_apply(self):
        changes = (
            lambda: self.db.execute("UPDATE user_profiles SET status='disabled' WHERE plex_id='8'"),
            lambda: self.db.execute("INSERT INTO email_recipients VALUES('existing@example.test',0)"),
            lambda: defaults.save_mappings(self.db, {'radarr:1': []}, self.libraries, SCOPE),
            lambda: defaults.save_settings(self.db, False, True),
        )
        for change in changes:
            with self.subTest(change=change):
                self.db.execute('SAVEPOINT fixture_drift')
                preview = self.preview()
                change()
                with self.assertRaises(ValueError):
                    defaults.apply_existing(self.db, ['8'], preview['generation'], SCOPE, self.libraries, [101, 102, 103])
                self.assertEqual(defaults.user_modes(self.db, '8')['library'], 'unset')
                self.db.execute('ROLLBACK TO fixture_drift')
                self.db.execute('RELEASE fixture_drift')
        preview = self.preview()
        with self.assertRaises(ValueError):
            defaults.apply_existing(self.db, ['8'], preview['generation'], SCOPE, self.libraries, [101])

    def test_unknown_or_ineligible_selection_cannot_partially_enroll_valid_user(self):
        preview = self.preview()
        for ids in (['8', '999'], ['8', '7'], ['8', 'local:x'], []):
            with self.subTest(ids=ids), self.assertRaises(ValueError):
                defaults.apply_existing(self.db, ids, preview['generation'], SCOPE, self.libraries, [101, 102, 103])
            self.assertEqual(defaults.user_modes(self.db, '8'), {'email': 'unset', 'library': 'unset'})

    def test_concurrent_apply_rechecks_generation_under_sqlite_write_lock(self):
        preview = self.preview()
        with tempfile.TemporaryDirectory(prefix='keep-default-policy-') as directory:
            path = directory + '/policy.sqlite3'
            with sqlite3.connect(path) as copy_db:
                self.db.backup(copy_db)
            barrier, results = threading.Barrier(2), []

            def apply():
                with sqlite3.connect(path, timeout=5) as db:
                    barrier.wait(timeout=5)
                    try:
                        defaults.apply_existing(db, ['8'], preview['generation'], SCOPE, self.libraries, [101, 102, 103])
                    except ValueError:
                        results.append('stale')
                    else:
                        results.append('applied')

            threads = [threading.Thread(target=apply) for _ in range(2)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=10)
                self.assertFalse(thread.is_alive())
            self.assertCountEqual(results, ['applied', 'stale'])
            with sqlite3.connect(path) as db:
                self.assertEqual(defaults.user_modes(db, '8'), {'email': 'auto', 'library': 'auto'})
                self.assertEqual(db.execute('SELECT COUNT(*) FROM user_library_permissions').fetchone()[0], 0)

    def test_connection_row_factory_does_not_change_policy_results(self):
        self.db.row_factory = sqlite3.Row
        self.sync(new=['9'])
        self.assertEqual(defaults.auto_library_keys(self.db, '9', SCOPE), {'radarr:1', 'sonarr:2'})


if __name__ == '__main__':
    unittest.main()
