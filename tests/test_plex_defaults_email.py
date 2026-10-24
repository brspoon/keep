import copy
import sqlite3
import unittest
from unittest.mock import Mock, patch

import plex_defaults_email as email
import plex_user_defaults as defaults


SCOPE = 'a' * 64
OTHER_SCOPE = 'b' * 64


class PlexDefaultsEmailTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(':memory:')
        self.addCleanup(self.db.close)
        self.db.executescript('''
            CREATE TABLE user_profiles(plex_id TEXT PRIMARY KEY,plex_username TEXT,email TEXT,
                auth_type TEXT,status TEXT,plex_access TEXT,can_delete_media INTEGER,can_delete_any INTEGER);
            INSERT INTO user_profiles VALUES('1','owner','owner@example.test','plex','active','active',0,0);
            INSERT INTO user_profiles VALUES('2','one','one@example.test','plex','active','active',0,0);
            INSERT INTO user_profiles VALUES('3','two','two@example.test','plex','active','active',0,0);
            CREATE TABLE installation(id INTEGER,owner TEXT);
            INSERT INTO installation VALUES(1,'1');
            CREATE TABLE user_library_permissions(user_id TEXT,library_key TEXT);
            CREATE TABLE email_recipients(email TEXT PRIMARY KEY COLLATE NOCASE,enabled INTEGER);
            CREATE TABLE recipient_subscriptions(email TEXT COLLATE NOCASE,collection_id INTEGER,enabled INTEGER,
                PRIMARY KEY(email,collection_id));
            INSERT INTO email_recipients VALUES('Manual@Example.test',1);
            INSERT INTO recipient_subscriptions VALUES('Manual@Example.test',30,0);
        ''')
        defaults.init_schema(self.db)
        email.init_schema(self.db)
        self.ids = {10, 20, 30}
        self.proof = {'machine': 'pms-one', 'checked_at': 100,
            'sections': {key: {'key': key, 'name': name, 'kind': kind, 'locations': ['/media/' + key]}
                         for key, name, kind in (('1', 'Movies', 'movie'), ('2', 'Shows', 'show'), ('3', 'Private', 'movie'))},
            'users': {'2': {'sections': ['1'], 'restricted': False},
                      '3': {'sections': ['2'], 'restricted': False}}}
        self.sync(new=('2', '3'))
        self.seed()
        email.reconcile(self.db, scope=SCOPE, collection_ids=self.ids, now=100)
        self.db.commit()

    def sync(self, *, proof=None, new=(), scope=SCOPE, now=100):
        return defaults.reconcile(self.db, proof=self.proof if proof is None else proof,
            scope=scope, owner_id='1', new_user_ids=new, now=now)

    def seed(self, rows=None, scope=SCOPE):
        rows = rows if rows is not None else [{'id': 10, 'libraryId': '1', 'type': 'movie'},
            {'id': 20, 'libraryId': '2', 'type': 'show'}, {'id': 30, 'libraryId': '3', 'type': 'movie'}]
        return email.seed_collection_mappings(self.db, rows, scope=scope, collection_ids=self.ids, now=100)

    def query(self, sql, args=()):
        return self.db.execute(sql, args).fetchall()

    def items(self):
        return [{'collection_id': 10, 'media_id': '11', 'section': '1'},
                {'collection_id': 10, 'media_id': '12', 'section': '3'},
                {'collection_id': 20, 'media_id': '21', 'section': '2'},
                {'collection_id': 30, 'media_id': '31', 'section': '3'}]

    def filtered(self, address='one@example.test', *, scope=SCOPE, now=100, callback=None):
        return email.filter_items(self.db, address, self.items(), scope=scope,
            section_for_item=callback or (lambda item: item['section']), now=now)

    def test_enrollment_adds_only_scoped_topics_and_preserves_manual_rows(self):
        self.assertEqual(self.query("SELECT collection_id FROM recipient_subscriptions WHERE email='one@example.test'"), [(10,)])
        self.assertEqual(self.query("SELECT collection_id FROM recipient_subscriptions WHERE email='two@example.test'"), [(20,)])
        self.assertEqual(self.query("SELECT * FROM recipient_subscriptions WHERE email='Manual@Example.test'"), [('Manual@Example.test', 30, 0)])
        self.assertEqual(email.delivery_preferences(self.db, scope=SCOPE, collection_ids=self.ids, now=100),
                         {'Manual@Example.test': set(), 'one@example.test': {10}, 'two@example.test': {20}})
        self.assertEqual([row['media_id'] for row in self.filtered()], ['11'])

    def test_independent_manual_recipient_is_never_scoped_or_rewritten(self):
        lookup = Mock(side_effect=AssertionError('Manual routing does not query Plex'))
        self.assertEqual(self.filtered('Manual@Example.test', callback=lookup), self.items())
        lookup.assert_not_called()
        self.assertEqual(email.destination_generation(self.db, 'Manual@Example.test', scope=SCOPE,
                         collection_ids=self.ids, now=100), '')
        self.assertFalse(email.can_manage_address(self.db, 'manual@example.test', '2'))
        self.assertFalse(email.is_auto_email(self.db, 'manual@example.test', '2'))

    def test_existing_disabled_or_orphan_manual_address_cannot_be_adopted(self):
        self.db.execute("INSERT INTO email_recipients VALUES('disabled@example.test',0)")
        self.db.execute("INSERT INTO recipient_subscriptions VALUES('orphan@example.test',10,1)")
        self.assertFalse(email.can_manage_address(self.db, 'DISABLED@example.test', '2'))
        self.assertFalse(email.can_manage_address(self.db, 'orphan@example.test', '2'))
        self.assertTrue(email.is_auto_email(self.db, 'one@example.test', '2'))
        self.assertFalse(email.can_manage_address(self.db, 'one@example.test', '3'))

    def test_mixed_collection_uses_actual_item_section_and_never_topic_membership_alone(self):
        email.save_collection_mappings(self.db, {10: ['1', '3']}, SCOPE, self.ids, now=100)
        lookup = Mock(side_effect=lambda item: item['section'])
        self.assertEqual([row['media_id'] for row in self.filtered(callback=lookup)], ['11'])
        self.assertEqual(lookup.call_count, 2)
        self.assertEqual(self.filtered(callback=lambda item: None), [])
        self.assertEqual(self.filtered(callback=Mock(side_effect=RuntimeError('Plex unavailable'))), [])

    def test_manual_personal_topics_keep_account_clamp_and_optout_across_email_change(self):
        email.manual_override(self.db, 'one@example.test', user_id='2')
        self.db.execute("INSERT INTO recipient_subscriptions VALUES('one@example.test',30,1)")
        email.reconcile(self.db, scope=SCOPE, collection_ids=self.ids, now=100)
        self.assertEqual(defaults.user_modes(self.db, '2')['email'], 'manual')
        self.assertEqual(self.query("SELECT collection_id FROM recipient_subscriptions WHERE email='one@example.test' ORDER BY 1"), [(10,), (30,)])
        self.assertEqual([row['media_id'] for row in self.filtered()], ['11'])
        self.db.execute("UPDATE email_recipients SET enabled=0 WHERE email='one@example.test'")
        self.assertEqual(self.filtered(), [])
        self.db.execute("UPDATE user_profiles SET email='new@example.test' WHERE plex_id='2'")
        email.reconcile(self.db, scope=SCOPE, collection_ids=self.ids, now=100)
        self.assertEqual(self.query("SELECT email FROM email_recipients WHERE email='new@example.test'"), [])
        self.assertEqual(self.query("SELECT enabled FROM email_recipients WHERE email='one@example.test'"), [(0,)])
        self.assertEqual(self.filtered(), [])

    def test_email_change_removes_only_owned_old_auto_rows(self):
        self.db.execute("UPDATE user_profiles SET email='new@example.test' WHERE plex_id='2'")
        email.reconcile(self.db, scope=SCOPE, collection_ids=self.ids, now=100)
        self.assertEqual(self.query("SELECT email FROM email_recipients WHERE email='one@example.test'"), [])
        self.assertEqual(self.query("SELECT collection_id FROM recipient_subscriptions WHERE email='new@example.test'"), [(10,)])
        self.assertEqual(self.filtered(), [])
        self.assertEqual([row['media_id'] for row in self.filtered('new@example.test')], ['11'])
        self.assertEqual(self.query("SELECT * FROM email_recipients WHERE email='Manual@Example.test'"), [('Manual@Example.test', 1)])

    def test_manual_address_change_retains_scope_for_formerly_automatic_account(self):
        email.manual_override(self.db, 'one@example.test', user_id='2')
        self.db.execute("UPDATE user_profiles SET email='new@example.test' WHERE plex_id='2'")
        email.manual_override(self.db, 'new@example.test', user_id='2')
        self.db.execute("INSERT INTO email_recipients VALUES('new@example.test',1)")
        self.db.executemany("INSERT INTO recipient_subscriptions VALUES('new@example.test',?,1)", [(10,), (30,)])
        self.assertEqual(self.query("SELECT user_id,state FROM plex_defaults_email_links WHERE email='new@example.test'"), [('2', 'manual')])
        self.assertEqual([row['media_id'] for row in self.filtered('new@example.test')], ['11'])
        self.assertEqual(email.delivery_preferences(self.db, scope=SCOPE, collection_ids=self.ids, now=100)['new@example.test'], {10})
        self.assertTrue(email.destination_generation(self.db, 'new@example.test', scope=SCOPE,
                        collection_ids=self.ids, now=100).startswith('plex-auto:'))

    def test_owner_address_action_infers_former_automatic_account_and_retains_scope(self):
        email.manual_override(self.db, 'one@example.test', user_id='2')
        self.db.execute("UPDATE user_profiles SET email='new@example.test' WHERE plex_id='2'")
        email.manual_override(self.db, 'new@example.test')
        self.db.execute("INSERT INTO email_recipients VALUES('new@example.test',1)")
        self.db.executemany("INSERT INTO recipient_subscriptions VALUES('new@example.test',?,1)", [(10,), (30,)])
        self.assertEqual(self.query("SELECT user_id,state FROM plex_defaults_email_links WHERE email='new@example.test'"), [('2', 'manual')])
        self.assertEqual([row['media_id'] for row in self.filtered('new@example.test')], ['11'])
        self.assertEqual(email.delivery_preferences(self.db, scope=SCOPE, collection_ids=self.ids, now=100)['new@example.test'], {10})

    def test_automatic_origin_before_first_route_is_scoped_after_personal_save(self):
        self.db.execute("INSERT INTO user_profiles VALUES('4','new','','plex','active','active',0,0)")
        proof = copy.deepcopy(self.proof)
        proof['users']['4'] = {'sections': ['1'], 'restricted': False}
        self.sync(proof=proof, new=('4',))
        self.assertTrue(defaults.email_was_automatic(self.db, '4'))
        self.assertEqual(self.query("SELECT email FROM plex_defaults_email_links WHERE user_id='4'"), [])
        email.manual_override(self.db, '', user_id='4')
        self.db.execute("UPDATE user_profiles SET email='future@example.test' WHERE plex_id='4'")
        email.manual_override(self.db, 'future@example.test', user_id='4')
        self.db.execute("INSERT INTO email_recipients VALUES('future@example.test',1)")
        self.db.executemany("INSERT INTO recipient_subscriptions VALUES('future@example.test',?,1)", [(10,), (30,)])
        self.assertEqual(self.query("SELECT user_id,state,scope FROM plex_defaults_email_links WHERE email='future@example.test'"), [('4', 'manual', '')])
        self.assertEqual(self.filtered('future@example.test'), [])
        self.assertNotIn('future@example.test', email.delivery_preferences(self.db, scope=SCOPE, collection_ids=self.ids, now=100))
        email.reconcile(self.db, scope=SCOPE, collection_ids=self.ids, now=100)
        self.assertEqual([row['media_id'] for row in self.filtered('future@example.test')], ['11'])
        self.assertEqual(self.query("SELECT collection_id FROM recipient_subscriptions WHERE email='future@example.test' ORDER BY 1"), [(10,), (30,)])

    def test_owner_save_infers_automatic_origin_even_before_first_route(self):
        self.db.execute("INSERT INTO user_profiles VALUES('4','new','','plex','active','active',0,0)")
        proof = copy.deepcopy(self.proof)
        proof['users']['4'] = {'sections': ['1'], 'restricted': False}
        self.sync(proof=proof, new=('4',))
        email.manual_override(self.db, '', user_id='4')
        self.db.execute("UPDATE user_profiles SET email='future@example.test' WHERE plex_id='4'")
        email.manual_override(self.db, 'future@example.test')
        self.assertEqual(self.query("SELECT user_id,state,scope FROM plex_defaults_email_links WHERE email='future@example.test'"), [('4', 'manual', '')])

    def test_new_manual_address_rejects_other_account_provenance_or_shared_profile(self):
        original = self.query('SELECT * FROM plex_defaults_email_links ORDER BY email')
        with self.assertRaises(ValueError):
            email.manual_override(self.db, 'two@example.test', user_id='2')
        self.assertEqual(self.query('SELECT * FROM plex_defaults_email_links ORDER BY email'), original)
        self.assertEqual(defaults.user_modes(self.db, '2')['email'], 'auto')
        self.db.execute("UPDATE user_profiles SET email='shared@example.test' WHERE plex_id IN ('2','3')")
        with self.assertRaises(ValueError):
            email.manual_override(self.db, 'shared@example.test', user_id='2')
        with self.assertRaises(ValueError):
            email.manual_override(self.db, 'shared@example.test')
        self.assertEqual(self.query("SELECT email FROM plex_defaults_email_links WHERE email='shared@example.test'"), [])
        self.assertEqual(defaults.user_modes(self.db, '2')['email'], 'auto')

    def test_never_automatic_personal_save_does_not_scope_independent_manual_mail(self):
        self.db.execute("INSERT INTO user_profiles VALUES('4','manual','manual@example.test','plex','active','active',0,0)")
        email.manual_override(self.db, 'manual@example.test', user_id='4')
        email.manual_override(self.db, 'manual@example.test')
        self.assertFalse(defaults.email_was_automatic(self.db, '4'))
        self.assertEqual(self.query("SELECT email FROM plex_defaults_email_links WHERE email='manual@example.test'"), [])
        self.assertEqual(self.filtered('manual@example.test'), self.items())

    def test_missing_address_account_optout_survives_a_future_verified_email(self):
        self.db.execute("UPDATE user_profiles SET email='' WHERE plex_id='2'")
        email.manual_override(self.db, '', user_id='2')
        self.assertEqual(defaults.user_modes(self.db, '2')['email'], 'manual')
        self.db.execute("UPDATE user_profiles SET email='future@example.test' WHERE plex_id='2'")
        email.reconcile(self.db, scope=SCOPE, collection_ids=self.ids, now=100)
        self.assertEqual(self.query("SELECT email FROM email_recipients WHERE email='future@example.test'"), [])
        self.assertEqual(self.filtered(), [])
        with self.assertRaises(ValueError):
            email.manual_override(self.db, 'invalid-address', user_id='2')

    def test_shared_email_never_unions_account_sections(self):
        self.db.execute("UPDATE user_profiles SET email='one@example.test' WHERE plex_id='3'")
        email.reconcile(self.db, scope=SCOPE, collection_ids=self.ids, now=100)
        self.assertEqual(self.filtered(), [])
        self.assertNotIn('one@example.test', email.delivery_preferences(self.db, scope=SCOPE, collection_ids=self.ids, now=100))
        self.assertEqual(self.query("SELECT email FROM email_recipients WHERE email='one@example.test'"), [])

    def test_stale_missing_restricted_or_revoked_proof_stops_scoped_manual_mail(self):
        email.manual_override(self.db, 'one@example.test', user_id='2')
        self.assertEqual(self.filtered(now=1901), [])
        self.assertEqual(self.filtered(scope=OTHER_SCOPE), [])
        proof = copy.deepcopy(self.proof)
        proof['users']['2']['restricted'] = True
        self.sync(proof=proof)
        self.assertEqual(self.filtered(), [])
        self.sync()
        self.db.execute("UPDATE user_profiles SET plex_access='revoked' WHERE plex_id='2'")
        self.assertEqual(self.filtered(), [])

    def test_scope_replacement_cannot_reuse_old_mapping_or_union_old_sections(self):
        old = email.destination_generation(self.db, 'one@example.test', scope=SCOPE, collection_ids=self.ids, now=100)
        self.sync(scope=OTHER_SCOPE)
        self.assertEqual(self.filtered(scope=OTHER_SCOPE), [])
        self.seed(scope=OTHER_SCOPE)
        email.reconcile(self.db, scope=OTHER_SCOPE, collection_ids=self.ids, now=100)
        self.assertEqual([row['media_id'] for row in self.filtered(scope=OTHER_SCOPE)], ['11'])
        self.assertNotEqual(old, email.destination_generation(self.db, 'one@example.test', scope=OTHER_SCOPE,
                            collection_ids=self.ids, now=100))

    def test_new_user_default_off_does_not_disable_existing_enrollment(self):
        defaults.save_settings(self.db, False, False)
        email.reconcile(self.db, scope=SCOPE, collection_ids=self.ids, now=100)
        self.assertEqual([row['media_id'] for row in self.filtered()], ['11'])

    def test_seed_uses_exact_keys_types_and_preserves_owner_mapping_override(self):
        email.save_collection_mappings(self.db, {10: ['1', '3']}, SCOPE, self.ids, now=100)
        rows = [{'id': 10, 'libraryId': '3', 'type': 'movie'},
                {'id': 20, 'libraryId': '1', 'type': 'show'},
                {'id': 30, 'libraryId': '999', 'type': 'movie'}]
        self.assertEqual(self.seed(rows), {10: ['1', '3']})
        self.assertEqual(self.seed([{'id': 20, 'name': 'Shows', 'type': 'show'}]), {10: ['1', '3']})
        self.assertEqual(self.seed([]), {10: ['1', '3']})

    def test_invalid_or_ambiguous_source_clears_auto_only_and_ignores_names(self):
        self.assertEqual(self.seed([{'id': 10, 'libraryId': '1', 'type': 'movie'},
                                    {'id': 10, 'libraryId': '3', 'type': 'movie'}]), {})
        self.seed()
        self.assertEqual(email.seed_collection_mappings(self.db, None, scope=SCOPE, collection_ids=self.ids, now=100), {})
        self.assertEqual(self.filtered(), [])
        with self.assertRaises(ValueError):
            email.save_collection_mappings(self.db, {999: ['1']}, SCOPE, self.ids, now=100)
        with self.assertRaises(ValueError):
            email.save_collection_mappings(self.db, {10: ['999']}, SCOPE, self.ids, now=100)
        with self.assertRaises(ValueError):
            email.save_collection_mappings(self.db, {10: ['1']}, OTHER_SCOPE, self.ids, now=100)

    def test_preview_eligibility_ignores_unset_mode_but_requires_verified_mapping(self):
        self.db.execute("UPDATE plex_user_default_modes SET email_mode='unset' WHERE user_id='2'")
        self.assertEqual(email.eligible_collection_ids(self.db, '2', scope=SCOPE, collection_ids=self.ids, now=100), {10})
        self.assertEqual(email.eligible_collections(self.db, '2', SCOPE, self.ids, libraries=[], now=100), [10])
        self.assertEqual(email.eligible_collection_ids(self.db, '2', scope=OTHER_SCOPE, collection_ids=self.ids, now=100), set())

    def test_generation_and_preview_fingerprint_change_on_topic_or_manual_preference_edits(self):
        before = email.destination_generation(self.db, 'one@example.test', scope=SCOPE, collection_ids=self.ids, now=100)
        preview = email.preview_fingerprint(self.db, scope=SCOPE, collection_ids=self.ids, now=100)
        email.save_collection_mappings(self.db, {10: ['1', '3']}, SCOPE, self.ids, now=100)
        self.assertNotEqual(before, email.destination_generation(self.db, 'one@example.test', scope=SCOPE, collection_ids=self.ids, now=100))
        self.assertNotEqual(preview, email.preview_fingerprint(self.db, scope=SCOPE, collection_ids=self.ids, now=100))
        mapped = email.preview_fingerprint(self.db, scope=SCOPE, collection_ids=self.ids, now=100)
        self.db.execute("UPDATE recipient_subscriptions SET enabled=0 WHERE email='one@example.test'")
        self.assertNotEqual(mapped, email.preview_fingerprint(self.db, scope=SCOPE, collection_ids=self.ids, now=100))

    def test_scoped_filter_has_item_and_time_budgets_without_changing_manual_mail(self):
        lookup = Mock(return_value='1')
        items = [{'collection_id': 10, 'media_id': str(index)} for index in range(5)]
        with patch.object(email, 'FILTER_ITEM_LIMIT', 2):
            self.assertEqual(len(email.filter_items(self.db, 'one@example.test', items, scope=SCOPE,
                section_for_item=lookup, now=100)), 2)
            self.assertEqual(email.filter_items(self.db, 'manual@example.test', items, scope=SCOPE,
                section_for_item=lookup, now=100), items)
        self.assertEqual(lookup.call_count, 2)
        with patch.object(email.time, 'monotonic', side_effect=(0, 61)):
            self.assertEqual(email.filter_items(self.db, 'one@example.test', items, scope=SCOPE,
                section_for_item=lookup, now=100), [])
        self.assertEqual(lookup.call_count, 2)
        with patch.object(email.time, 'monotonic', side_effect=(0, 0, 61)):
            self.assertEqual(email.filter_items(self.db, 'one@example.test', items, scope=SCOPE,
                section_for_item=lookup, now=100), [])
        self.assertEqual(lookup.call_count, 3)


if __name__ == '__main__':
    unittest.main()
