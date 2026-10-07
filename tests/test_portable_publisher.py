import importlib.util
import sys
import unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, str(Path('scripts').resolve()))
import publish_portable as publisher


class PortablePublisherTests(unittest.TestCase):
    def test_plan_includes_both_platforms_and_promotes_stable_last(self):
        result = publisher.release_plan('example/keep', '2.0.0', 'a' * 40)
        self.assertEqual(set(result['images']), {'amd64', 'arm64'})
        self.assertEqual(result['manifests'][-1], 'example/keep:stable')

    def test_legacy_execution_fails_before_any_subprocess_or_registry_access(self):
        with patch('subprocess.run') as run, patch('subprocess.check_output') as output, \
             patch('publish_image.hub') as hub:
            with self.assertRaisesRegex(ValueError, 'Standalone publication is disabled'):
                publisher.execute('example/keep', '2.0.0', 'a' * 40, 'public')
            run.assert_not_called()
            output.assert_not_called()
            hub.assert_not_called()
