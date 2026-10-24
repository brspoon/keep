"""Explicit server-scoped Plex shares and complete media-root mappings."""
import copy
import unittest
from unittest.mock import Mock, patch
import xml.etree.ElementTree as ET

import plex_library_access as access


def xml(value):
    return ET.fromstring(value)


def catalog():
    return xml('''<MediaContainer size="3">
      <Directory key="1" type="movie" title="Movies"><Location path="/media/movies"/></Directory>
      <Directory key="2" type="show" title="TV"><Location path="/media/tv"/></Directory>
      <Directory key="3" type="artist" title="Music"><Location path="/media/music"/></Directory>
    </MediaContainer>''')


def users(*rows):
    root = ET.Element('MediaContainer')
    for user_id, attributes, servers in rows or [('8', {}, [{}])]:
        user = ET.SubElement(root, 'User', {'id': user_id, **attributes})
        for changes in servers:
            ET.SubElement(user, 'Server', {'machineIdentifier': 'machine', 'id': '40',
                'pending': '0', 'allLibraries': '1', 'numLibraries': '2', **changes})
    return root


def detail(**changes):
    root = ET.Element('MediaContainer')
    share = ET.SubElement(root, 'SharedServer', {'id': '40', 'userID': '8',
        'machineIdentifier': 'machine', **changes})
    ET.SubElement(share, 'Section', {'id': '1001', 'key': '1', 'type': 'movie', 'shared': '1'})
    ET.SubElement(share, 'Section', {'id': '1002', 'key': '2', 'type': 'show', 'shared': '0'})
    ET.SubElement(share, 'Section', {'id': '1003', 'key': '3', 'type': 'artist', 'shared': '1'})
    return root


class PlexLibraryAccessTests(unittest.TestCase):
    def setUp(self):
        self.connection = {'PLEX_MACHINE_IDENTIFIER': 'machine', 'PLEX_SERVER_URL': 'http://plex:32400',
                           'PLEX_ADMIN_TOKEN': 'never-return-this-token'}
        self.responses = {
            'http://plex:32400/identity': xml('<MediaContainer machineIdentifier="machine"/>'),
            'http://plex:32400/library/sections': catalog(),
            'https://plex.tv/api/users/': users(),
            'https://plex.tv/api/servers/machine/shared_servers/40': detail(),
        }
        self.read = Mock(side_effect=lambda url: copy.deepcopy(self.responses[url]))

    def collect(self, requested=('8',)):
        return access.collect(self.connection, self.read, requested)

    def test_explicit_pms_key_not_cloud_id_or_counts_controls_scope(self):
        with patch.object(access.time, 'time', return_value=123.5):
            proof = self.collect()
        self.assertEqual(proof['checked_at'], 123.5)
        self.assertEqual(proof['machine'], 'machine')
        self.assertEqual(proof['users'], {'8': {'sections': ['1'], 'restricted': False}})
        self.assertEqual(proof['sections']['1'], {'key': '1', 'name': 'Movies', 'kind': 'movie',
                                                'locations': ['/media/movies']})
        self.assertEqual(set(proof['sections']), {'1', '2'})
        self.assertNotIn('never-return-this-token', repr(proof))
        self.assertEqual([call.args[0] for call in self.read.call_args_list], list(self.responses))

    def test_all_libraries_flag_never_substitutes_for_explicit_sections(self):
        for section in self.responses[list(self.responses)[-1]][0]:
            section.set('shared', '0')
        self.assertEqual(self.collect()['users']['8']['sections'], [])

    def test_empty_revoked_share_or_absent_user_has_no_scope(self):
        self.responses[list(self.responses)[-1]] = xml('<MediaContainer size="0"/>')
        self.assertEqual(self.collect()['users']['8']['sections'], [])
        self.responses['https://plex.tv/api/users/'] = xml('<MediaContainer/>')
        self.assertEqual(self.collect()['users']['8']['sections'], [])

    def test_pending_and_other_server_shares_are_not_read_or_granted(self):
        for changes in ({'pending': '1'}, {'machineIdentifier': 'other-machine'}):
            with self.subTest(changes=changes):
                self.read.reset_mock()
                self.responses['https://plex.tv/api/users/'] = users(('8', {}, [changes]))
                self.assertEqual(self.collect()['users']['8']['sections'], [])
                self.assertEqual(self.read.call_count, 3)

    def test_only_requested_users_details_are_fetched(self):
        self.responses['https://plex.tv/api/users/'] = users(('8', {}, [{}]), ('9', {}, [{'id': '41'}]))
        self.assertEqual(set(self.collect()['users']), {'8'})
        self.assertEqual(self.read.call_count, 4)

    def test_filtered_or_restricted_users_never_receive_unfiltered_scope(self):
        for name, value in (('restricted', '1'), ('filterMovies', 'contentRating=G'),
                            ('filterTelevision', 'label=Kids'), ('filterMusic', 'label=Music'),
                            ('filterPhotos', 'label=Family'), ('restrictionProfile', 'child')):
            with self.subTest(name=name):
                self.responses['https://plex.tv/api/users/'] = users(('8', {name: value}, [{}]))
                self.assertEqual(self.collect()['users']['8'], {'sections': [], 'restricted': True})
        self.responses['https://plex.tv/api/users/'] = users()
        self.responses[list(self.responses)[-1]] = detail(filterTelevision='contentRating=TV-G')
        self.assertEqual(self.collect()['users']['8'], {'sections': [], 'restricted': True})

    def test_empty_filters_and_unrestricted_flag_allow_explicit_share(self):
        self.responses['https://plex.tv/api/users/'] = users(('8', {'restricted': '0', 'filterMovies': ''}, [{}]))
        self.assertEqual(self.collect()['users']['8']['sections'], ['1'])

    def test_machine_user_and_share_identity_must_match(self):
        for changes in ({'machineIdentifier': 'other'}, {'id': '41'}, {'userID': '9'},
                        {'userId': '9'}, {'accountID': '9'}):
            with self.subTest(changes=changes):
                self.responses[list(self.responses)[-1]] = detail(**changes)
                with self.assertRaises(ValueError):
                    self.collect()
        self.responses['http://plex:32400/identity'].set('machineIdentifier', 'other')
        with self.assertRaises(ValueError):
            self.collect()

    def test_optional_detail_identity_fields_may_be_absent_when_url_is_bound(self):
        response = detail()
        response[0].attrib.clear()
        self.responses[list(self.responses)[-1]] = response
        self.assertEqual(self.collect()['users']['8']['sections'], ['1'])

    def test_repeated_container_and_user_server_identities_cannot_disagree(self):
        for endpoint, name, value in (
                ('http://plex:32400/library/sections', 'machineIdentifier', 'other'),
                ('https://plex.tv/api/servers/machine/shared_servers/40', 'userID', '9')):
            with self.subTest(endpoint=endpoint, name=name):
                response = self.responses[endpoint]
                response.set(name, value)
                with self.assertRaises(ValueError):
                    self.collect()
                del response.attrib[name]
        self.responses['https://plex.tv/api/users/'] = users(('8', {}, [{'userID': '9'}]))
        with self.assertRaises(ValueError):
            self.collect()

    def test_cloud_container_identifier_is_not_the_shared_pms_identity(self):
        self.responses['https://plex.tv/api/users/'].set('machineIdentifier', 'plex-cloud-service')
        self.responses[list(self.responses)[-1]].set('machineIdentifier', 'plex-cloud-service')
        self.assertEqual(self.collect()['users']['8'], {'sections': ['1'], 'restricted': False})
        self.responses[list(self.responses)[-1]][0].set('machineIdentifier', 'different-pms')
        with self.assertRaises(ValueError):
            self.collect()

    def test_detail_pending_share_grants_nothing(self):
        self.responses[list(self.responses)[-1]] = detail(pending='1')
        self.assertEqual(self.collect()['users']['8']['sections'], [])

    def test_duplicate_user_server_share_and_section_identities_fail_whole_snapshot(self):
        variants = [users(('8', {}, [{}]), ('8', {}, [])), users(('8', {}, [{}, {}])),
                    users(('8', {}, [{}]), ('9', {}, [{}]))]
        for response in variants:
            with self.subTest(response=ET.tostring(response)):
                self.responses['https://plex.tv/api/users/'] = response
                with self.assertRaises(ValueError):
                    self.collect()
        self.responses['https://plex.tv/api/users/'] = users()
        response = detail()
        response[0].append(copy.deepcopy(response[0][0]))
        self.responses[list(self.responses)[-1]] = response
        with self.assertRaises(ValueError):
            self.collect()

    def test_unknown_section_cloud_key_confusion_and_malformed_bits_fail(self):
        for field, value in (('key', '1001'), ('key', '01'), ('shared', 'true'),
                             ('shared', ''), ('type', 'show')):
            with self.subTest(field=field, value=value):
                response = detail()
                response[0][0].set(field, value)
                self.responses[list(self.responses)[-1]] = response
                with self.assertRaises(ValueError):
                    self.collect()

    def test_missing_catalog_location_or_duplicate_catalog_key_fail(self):
        for response in (xml('<MediaContainer><Directory key="1" type="movie" title="Movies"/></MediaContainer>'),
                         xml('<MediaContainer><Directory key="1" type="artist"/><Directory key="1" type="artist"/></MediaContainer>')):
            self.responses['http://plex:32400/library/sections'] = response
            with self.assertRaises(ValueError):
                self.collect()

    def test_partial_pagination_wrong_xml_and_fetch_failures_are_sanitized(self):
        for response in (xml('<MediaContainer size="1"/>'), xml('<MediaContainer offset="1"/>'),
                         xml('<MediaContainer totalSize="2"/>'), xml('<html/>')):
            self.responses['https://plex.tv/api/users/'] = response
            with self.assertRaises(ValueError):
                self.collect()
        self.read.side_effect = RuntimeError('token=never-return-this-token')
        with self.assertRaises(ValueError) as error:
            self.collect()
        self.assertNotIn('never-return-this-token', str(error.exception))
        self.assertIsNone(error.exception.__cause__)

    def test_user_and_section_bounds_and_canonical_ids_are_enforced(self):
        for ids in (['8'] * 2, ['08'], ['local:8'], [8], ['1'] * 501):
            with self.subTest(ids=ids[:2]):
                with self.assertRaises(ValueError):
                    self.collect(ids)
        response = ET.Element('MediaContainer')
        for number in range(501):
            ET.SubElement(response, 'User', {'id': str(number + 1)})
        self.responses['https://plex.tv/api/users/'] = response
        with self.assertRaises(ValueError):
            self.collect()
        self.responses['https://plex.tv/api/users/'] = users()
        response = ET.Element('MediaContainer')
        for number in range(5001):
            ET.SubElement(response, 'Directory', {'key': str(number + 1), 'type': 'artist'})
        self.responses['http://plex:32400/library/sections'] = response
        with self.assertRaises(ValueError):
            self.collect()

    def test_catalog_location_and_unknown_shared_server_shapes_fail(self):
        response = catalog()
        response[0].append(copy.deepcopy(response[0][0]))
        self.responses['http://plex:32400/library/sections'] = response
        with self.assertRaises(ValueError):
            self.collect()
        self.responses['http://plex:32400/library/sections'] = catalog()
        self.responses[list(self.responses)[-1]] = xml('<MediaContainer><Server/></MediaContainer>')
        with self.assertRaises(ValueError):
            self.collect()

    def test_configured_url_cannot_add_credentials_query_or_fragment(self):
        for base in ('https://token@example.test', 'http://plex/?token=secret', 'http://plex/#secret',
                     'file:///private', 'http://plex:0', ' http://plex', 'http://plex\n'):
            with self.subTest(base=base):
                self.connection['PLEX_SERVER_URL'] = base
                with self.assertRaises(ValueError):
                    self.collect()


class AutomaticMappingTests(unittest.TestCase):
    def setUp(self):
        self.sections = {'1': {'key': '1', 'name': 'Movies', 'kind': 'movie',
                               'locations': ['/media/movies']},
                         '2': {'key': '2', 'name': 'TV', 'kind': 'show', 'locations': ['/media/tv']}}

    def library(self, path, key='radarr:3'):
        return {'library_key': key, 'service': key.split(':')[0], 'path': path}

    def test_exact_and_ancestor_location_covers_whole_correct_kind_root(self):
        rows = [self.library('/media/movies/'), self.library('/media/movies/kids', 'radarr:4'),
                self.library('/media/tv', 'sonarr:2')]
        self.assertEqual(access.automatic_mappings(self.sections, rows),
                         {'radarr:3': ['1'], 'radarr:4': ['1'], 'sonarr:2': ['2']})

    def test_partial_prefix_suffix_kind_and_different_mounts_do_not_map(self):
        for path, key in (('/media', 'radarr:3'), ('/media/movies2', 'radarr:3'),
                          ('/movies', 'radarr:3'), ('/different/media/movies', 'radarr:3'),
                          ('/media/movies', 'sonarr:2'), ('/MEDIA/movies', 'radarr:3')):
            with self.subTest(path=path, key=key):
                self.assertEqual(access.automatic_mappings(self.sections, [self.library(path, key)]), {})

    def test_multiple_locations_of_one_section_cover_multiple_separate_roots(self):
        self.sections['1']['locations'].append('/media/kids')
        self.assertEqual(access.automatic_mappings(self.sections,
            [self.library('/media/kids'), self.library('/media/movies', 'radarr:4')]),
            {'radarr:3': ['1'], 'radarr:4': ['1']})

    def test_duplicate_and_nested_overlapping_sections_are_ambiguous(self):
        for path in ('/media/movies', '/media/movies/kids', '/media'):
            with self.subTest(path=path):
                self.sections['3'] = {'key': '3', 'kind': 'movie', 'locations': [path]}
                self.assertEqual(access.automatic_mappings(self.sections, [self.library('/media/movies')]), {})

    def test_windows_drive_and_unc_paths_normalize_without_suffix_matching(self):
        self.sections['1']['locations'] = ['D:\\Media\\Movies', '\\\\NAS\\Media\\Movies']
        rows = [self.library('d:/media/movies/Children'),
                self.library('//nas/media/movies', 'radarr:4'), self.library('E:/media/movies', 'radarr:5')]
        self.assertEqual(access.automatic_mappings(self.sections, rows), {'radarr:3': ['1'], 'radarr:4': ['1']})
        self.sections['1']['locations'] = ['D:/Straße']
        self.assertEqual(access.automatic_mappings(self.sections, [self.library('D:/STRASSE')]), {})

    def test_relative_traversal_and_invalid_paths_never_become_grants(self):
        for path in ('media/movies', '/media/../media/movies', 'C:Movies',
                     'D:\\Media\\..\\Movies', '/media/movies\n', '\\\\?\\C:\\Movies'):
            with self.subTest(path=path), self.assertRaises(ValueError):
                access.automatic_mappings(self.sections, [self.library(path)])

    def test_duplicate_library_ids_and_invalid_section_shape_fail_closed(self):
        with self.assertRaises(ValueError):
            access.automatic_mappings(self.sections, [self.library('/media/movies'), self.library('/media/other')])
        self.sections['1']['key'] = '9'
        with self.assertRaises(ValueError):
            access.automatic_mappings(self.sections, [self.library('/media/movies')])


if __name__ == '__main__':
    unittest.main()
