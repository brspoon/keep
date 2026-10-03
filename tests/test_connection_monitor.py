import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import connection_monitor
from connection_settings import ConnectionSettings


class AutomaticConnectionTests(unittest.TestCase):
    def test_runtime_module_is_packaged(self):
        root = Path(__file__).resolve().parents[1]
        self.assertIn('!connection_monitor.py', (root / '.dockerignore').read_text().splitlines())
        self.assertIn('connection_monitor.py', (root / 'Dockerfile').read_text())

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        env = patch.dict(os.environ, {}, clear=True)
        env.start()
        self.addCleanup(env.stop)
        self.store = ConnectionSettings(directory.name + '/settings.sqlite3')
        self.store.save({'RADARR_URL': 'http://radarr', 'RADARR_API_KEY': 'secret'})

    def test_due_times_failures_recovery_and_changed_credentials(self):
        getter = self.store.get
        fingerprint = self.store.connection_fingerprint('radarr', getter)
        self.assertTrue(self.store.automatic_due('radarr', getter, now=100))
        self.store.record_automatic_check('radarr', fingerprint, True, now=100)
        self.assertFalse(self.store.automatic_due('radarr', getter, now=3699))
        self.assertTrue(self.store.automatic_due('radarr', getter, now=3700))
        self.assertEqual(self.store.automatic_states(getter, now=100)['radarr']['label'], 'Healthy')
        self.store.record_automatic_check('radarr', fingerprint, False, now=3700)
        self.assertEqual(self.store.automatic_states(getter, now=3700)['radarr']['label'], 'Retrying')
        self.store.record_automatic_check('radarr', fingerprint, False, now=4000)
        self.assertEqual(self.store.automatic_states(getter, now=4000)['radarr']['label'], 'Needs attention')
        self.assertEqual(self.store.automatic_states(getter, now=9000)['radarr']['label'], 'Needs attention')
        self.store.record_automatic_check('radarr', fingerprint, True, now=4300)
        self.assertEqual(self.store.automatic_states(getter, now=4300)['radarr']['label'], 'Healthy')
        self.assertEqual(self.store.automatic_states(getter, now=11000)['radarr']['label'], 'Overdue')
        self.store.save({'RADARR_API_KEY': 'replacement'})
        self.assertEqual(self.store.automatic_states(getter, now=4300)['radarr']['label'], 'Pending')
        self.assertTrue(self.store.automatic_due('radarr', getter, now=4300))

    def test_unconfigured_and_disabled_services_never_probe(self):
        self.assertFalse(self.store.automatic_due('sonarr', self.store.get))
        self.assertFalse(self.store.automatic_due('email', self.store.get))
        states = self.store.automatic_states(self.store.get)
        self.assertEqual(states['sonarr']['label'], 'Setup needed')
        self.assertEqual(states['email']['label'], 'Disabled')

    def test_run_due_uses_status_only_and_keeps_other_services_running(self):
        logger = Mock()
        with patch.object(connection_monitor.media_services, 'test_connection', side_effect=ValueError('private response')) as status, \
                patch.object(connection_monitor.media_services, 'discover_libraries') as libraries:
            connection_monitor.run_due(self.store, self.store.get, Mock(), logger)
            self.assertEqual(status.call_count, 1)
            libraries.assert_not_called()
            self.assertEqual(self.store.automatic_states(self.store.get)['radarr']['label'], 'Retrying')
            self.assertFalse(logger.warning.called)

    def test_maintainerr_checks_selected_collections_without_mutation(self):
        getter = {'MAINTAINERR_URL': 'http://maintainerr', 'KEEP_COLLECTIONS': '{"1": "Movies"}'}.get
        with patch.object(connection_monitor, 'discover_collections', return_value={1: 'Movies'}):
            connection_monitor.probe('maintainerr', lambda key: getter(key, ''), Mock())
        with patch.object(connection_monitor, 'discover_collections', return_value={2: 'Other'}):
            with self.assertRaises(ValueError):
                connection_monitor.probe('maintainerr', lambda key: getter(key, ''), Mock())


if __name__ == '__main__':
    unittest.main()
