import unittest

from connection_settings import (SERVICE_URL_PORTS, connection_open_services,
                                 service_url_from_form, split_service_url, validate)


class ConnectionAddressTests(unittest.TestCase):
    def form(self, name, address):
        return {name + '_' + part: value for part, value in address.items()}

    def test_saved_urls_round_trip_without_changing_ports_paths_or_authority(self):
        urls = ('http://radarr', 'https://RADARR.example.test/radarr',
                'http://radarr:80/base', 'http://radarr:7878/base/path',
                'https://[2001:db8::1]/base', 'http://[::1]:7878', 'https://médias.example/radarr')
        for url in urls:
            with self.subTest(url=url):
                parts = split_service_url('RADARR_URL', url)
                self.assertEqual(service_url_from_form('RADARR_URL', self.form('RADARR_URL', parts), url), url)
        self.assertEqual(split_service_url('RADARR_URL', 'http://radarr')['port'], '80')
        self.assertEqual(split_service_url('RADARR_URL', 'https://radarr')['port'], '443')

    def test_new_connections_offer_native_ports_without_configuring_an_empty_host(self):
        for name, port in SERVICE_URL_PORTS.items():
            with self.subTest(name=name):
                parts = split_service_url(name, '')
                self.assertEqual(parts['port'], str(port))
                self.assertEqual(service_url_from_form(name, self.form(name, parts)), '')
                self.assertEqual(validate(name, ''), '')
        with self.assertRaises(ValueError):
            validate('KEEP_URL', '')

    def test_compose_separate_protocol_port_and_path_including_ipv6(self):
        parts = {'scheme': 'https', 'host': '[2001:db8::1]', 'port': '8443', 'path': 'radarr'}
        self.assertEqual(service_url_from_form('RADARR_URL', self.form('RADARR_URL', parts)),
                         'https://[2001:db8::1]:8443/radarr')
        parts.update(scheme='http', host='radarr_service', port='7878', path='')
        self.assertEqual(service_url_from_form('RADARR_URL', self.form('RADARR_URL', parts)),
                         'http://radarr_service:7878')

    def test_invalid_components_cannot_smuggle_credentials_query_or_ports(self):
        defaults = {'scheme': 'http', 'host': 'radarr', 'port': '7878', 'path': ''}
        cases = [('scheme', 'file'), ('host', 'user:secret@host'), ('host', 'host:7878'),
                 ('host', 'host?token=secret'), ('host', 'host/#fragment'), ('host', 'http://host'),
                 ('host', 'host\\path'), ('host', 'host\n'), ('port', '0'), ('port', '65536'),
                 ('port', '-1'), ('port', 'abc'), ('path', '/path?token=secret'),
                 ('path', '/path#fragment'), ('path', '/bad path')]
        for key, value in cases:
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                service_url_from_form('RADARR_URL', self.form('RADARR_URL', {**defaults, key: value}))
        with self.assertRaises(ValueError):
            validate('RADARR_URL', 'http://host:0')

    def test_legacy_url_fields_keep_the_existing_blank_and_absent_behavior(self):
        self.assertIsNone(service_url_from_form('RADARR_URL', {}))
        self.assertIsNone(service_url_from_form('RADARR_URL', {'RADARR_URL': ''}))
        self.assertEqual(service_url_from_form('RADARR_URL', {'RADARR_URL': 'http://legacy:7878'}),
                         'http://legacy:7878')

    def test_disclosure_state_is_bounded_and_falls_back_to_the_submitted_service(self):
        self.assertEqual(connection_open_services({'open_services': 'plex,email,unknown,plex'}), {'plex', 'email'})
        self.assertEqual(connection_open_services({'open_services': ''}, 'save-radarr'), set())
        self.assertEqual(connection_open_services({'open_services': 'plex,' * 100}), set())
        for action, service in [('save-radarr', 'radarr'), ('smtp', 'email'),
                                ('discover-collections', 'maintainerr'), ('save-seerr-links', 'seerr')]:
            self.assertEqual(connection_open_services({}, action), {service})
        self.assertEqual(connection_open_services({}, 'unknown'), set())
