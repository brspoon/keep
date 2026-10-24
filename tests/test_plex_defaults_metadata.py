"""Automatic email resolves exact current Plex items inside one bounded pass."""
from contextlib import closing
from types import SimpleNamespace
import time
from unittest import TestCase
from unittest.mock import patch
import xml.etree.ElementTree as ET

import test_keep

keep = test_keep.keep


def metadata(media_id='42', title='Test Movie', year='2026', section='1', kind='movie'):
    root = ET.Element('MediaContainer')
    attrs = {'ratingKey': media_id, 'title': title, 'type': kind, 'librarySectionID': section}
    if year is not None:
        attrs['year'] = year
    ET.SubElement(root, 'Video' if kind in ('movie', 'episode') else 'Directory', attrs)
    return ET.tostring(root)


class PlexDefaultsMetadataTests(TestCase):
    def setUp(self):
        test_keep.KeepTests.setUp(self)
        token = keep._settings_snapshot.set(None)
        self.addCleanup(keep._settings_snapshot.reset, token)
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
        environment = patch.dict(keep.os.environ, {'PLEX_SERVER_URL': 'http://plex',
            'PLEX_MACHINE_IDENTIFIER': 'test', 'PLEX_ADMIN_TOKEN': 'synthetic-metadata-secret'})
        environment.start()
        self.addCleanup(environment.stop)
        self.identity = b'<MediaContainer machineIdentifier="test"/>'
        self.item = {'media_id': '42', 'title': 'Test Movie', 'year': 2026, 'collection_id': 1}

    def automatic_recipient(self):
        def clear_recipient():
            with closing(keep.attribution_db()) as db, db:
                db.execute("DELETE FROM recipient_subscriptions WHERE email='metadata@example.test'")
                db.execute("DELETE FROM email_recipients WHERE email='metadata@example.test'")
        clear_recipient()
        self.addCleanup(clear_recipient)
        scope = keep.plex_defaults_scope()
        proof = {'machine': 'test', 'checked_at': time.time(), 'sections': {
            '1': {'key': '1', 'name': 'Movies', 'kind': 'movie', 'locations': ['/media/movies']},
            '2': {'key': '2', 'name': 'Private', 'kind': 'movie', 'locations': ['/media/private']},
        }, 'users': {'8': {'sections': ['1'], 'restricted': False}}}
        with closing(keep.attribution_db()) as db, db:
            db.execute('''INSERT INTO user_profiles(plex_id,plex_username,email,plex_checked_at)
                VALUES ('8','Metadata User','metadata@example.test',CURRENT_TIMESTAMP)''')
            keep.plex_user_defaults.reconcile(db, proof=proof, scope=scope, owner_id='7', new_user_ids=['8'])
            keep.plex_defaults_email.save_collection_mappings(db, {1: ['1', '2']},
                scope=scope, collection_ids=keep.recipient_collection_ids())
            keep.plex_defaults_email.reconcile(db, scope=scope, collection_ids=keep.recipient_collection_ids())
            self.assertTrue(db.execute("SELECT 1 FROM plex_defaults_email_links WHERE email='metadata@example.test' AND state='auto'").fetchone())
        return SimpleNamespace(id='metadata@example.test')

    def test_exact_item_on_verified_server_uses_shared_deadline_and_header_token(self):
        deadline = time.monotonic() + 10
        with patch('service_discovery.read_service', side_effect=[self.identity, metadata()]) as read:
            self.assertEqual(keep.plex_email_section_for_item(self.item, deadline=deadline), '1')
        self.assertEqual([call.args[0] for call in read.call_args_list],
                         ['http://plex/identity', 'http://plex/library/metadata/42'])
        self.assertTrue(all(call.kwargs == {'deadline': deadline} for call in read.call_args_list))
        self.assertTrue(all(call.args[1]['X-Plex-Token'] == 'synthetic-metadata-secret' for call in read.call_args_list))
        self.assertTrue(all('synthetic-metadata-secret' not in call.args[0] for call in read.call_args_list))
        for kind in ('show', 'season', 'episode'):
            with self.subTest(kind=kind), patch('service_discovery.read_service', side_effect=[self.identity, metadata(kind=kind)]):
                self.assertEqual(keep.plex_email_section_for_item(self.item), '1')
        with patch('service_discovery.read_service', side_effect=[self.identity, metadata(year=None)]):
            self.assertEqual(keep.plex_email_section_for_item({k: v for k, v in self.item.items() if k != 'year'}), '1')
        expired = time.monotonic() - 1
        with patch('service_discovery.read_service', side_effect=[self.identity, metadata()]):
            self.assertIsNone(keep.plex_email_section_for_item(self.item, deadline=expired))

    def test_metadata_identity_title_year_type_and_section_mismatches_deny(self):
        variants = [metadata(media_id='43'), metadata(title='Different Movie'), metadata(year='2025'),
                    metadata(year=None), metadata(section='0'), metadata(section='01'),
                    metadata(section='not-a-section'), metadata(kind='artist'),
                    b'<MediaContainer/>', b'<html/>',
                    b'<MediaContainer><Video/><Video/></MediaContainer>']
        for response in variants:
            with self.subTest(response=response), patch('service_discovery.read_service', side_effect=[self.identity, response]):
                self.assertIsNone(keep.plex_email_section_for_item(self.item))

    def test_wrong_pms_identity_denies_before_fetching_private_metadata(self):
        with patch('service_discovery.read_service', return_value=b'<MediaContainer machineIdentifier="other"/>') as read:
            self.assertIsNone(keep.plex_email_section_for_item(self.item))
        self.assertEqual(read.call_count, 1)
        self.assertEqual(read.call_args.args[0], 'http://plex/identity')

    def test_invalid_item_ids_never_call_the_provider(self):
        for media_id in (None, 42, '', '0', '042', '../42', '42?token=private', 'local:42'):
            with self.subTest(media_id=media_id), patch('service_discovery.read_service') as read:
                self.assertIsNone(keep.plex_email_section_for_item({**self.item, 'media_id': media_id}))
            read.assert_not_called()

    def test_fresh_connection_change_during_metadata_fetch_rejects_result(self):
        def read(url, headers, **kwargs):
            if url.endswith('/identity'):
                return self.identity
            keep.connection_settings.save({'PLEX_SERVER_URL': 'http://replacement'}, plex_override=True)
            return metadata()
        with patch('service_discovery.read_service', side_effect=read):
            self.assertIsNone(keep.plex_email_section_for_item(self.item))

    def test_identity_cache_is_per_pass_and_rechecks_changed_connection(self):
        cache = {}
        def read(url, headers, **kwargs):
            if url.endswith('/identity'):
                return self.identity
            return metadata(media_id=url.rsplit('/', 1)[-1])
        with patch('service_discovery.read_service', side_effect=read) as provider:
            self.assertEqual(keep.plex_email_section_for_item(self.item, identity_cache=cache), '1')
            self.assertEqual(keep.plex_email_section_for_item({**self.item, 'media_id': '43'}, identity_cache=cache), '1')
            self.assertEqual(provider.call_count, 3)
            keep.connection_settings.save({'PLEX_SERVER_URL': 'http://replacement'}, plex_override=True)
            self.assertEqual(keep.plex_email_section_for_item({**self.item, 'media_id': '44'}, identity_cache=cache), '1')
            self.assertEqual(provider.call_count, 5)
            self.assertEqual(provider.call_args_list[-2].args[0], 'http://replacement/identity')
            # A separate pass verifies identity even for an unchanged connection.
            self.assertEqual(keep.plex_email_section_for_item(self.item, identity_cache={}), '1')
            self.assertEqual(provider.call_count, 7)

    def test_filter_pass_shares_45_second_budget_and_removes_other_library_items(self):
        target = self.automatic_recipient()
        items = [self.item, {**self.item, 'media_id': '43'}]
        def read(url, headers, **kwargs):
            if url.endswith('/identity'):
                return self.identity
            media_id = url.rsplit('/', 1)[-1]
            return metadata(media_id=media_id, section='1' if media_id == '42' else '2')
        started = time.monotonic()
        with patch('service_discovery.read_service', side_effect=read) as provider:
            self.assertEqual(keep.filter_plex_email_items(target, items), [self.item])
        self.assertEqual(provider.call_count, 3)
        deadlines = {call.kwargs['deadline'] for call in provider.call_args_list}
        self.assertEqual(len(deadlines), 1)
        self.assertAlmostEqual(deadlines.pop() - started, 45, delta=0.5)
        self.assertEqual(items[1]['media_id'], '43')

    def test_post_lookup_non_plex_configuration_scope_change_discards_filtered_items(self):
        target = self.automatic_recipient()
        def read(url, headers, **kwargs):
            if url.endswith('/identity'):
                return self.identity
            keep.connection_settings.save({'RADARR_URL': 'http://changed-radarr'})
            return metadata()
        with patch('service_discovery.read_service', side_effect=read):
            self.assertEqual(keep.filter_plex_email_items(target, [self.item]), [])
