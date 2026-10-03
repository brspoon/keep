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

    def test_execute_refuses_feature_branch_before_registry_access(self):
        with patch.object(publisher.subprocess, 'check_output', side_effect=['brspoon/work\n', 'a' * 40]), patch.object(publisher, 'hub') as hub:
            with self.assertRaisesRegex(ValueError, 'clean, reviewed main'):
                publisher.execute('example/keep', '2.0.0', 'a' * 40, 'private')
            hub.assert_not_called()
