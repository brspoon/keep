import errno
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

from scripts.patch_python_runtime import apply_hunks, patch_provenance


class RuntimePatchTests(unittest.TestCase):
    def test_exact_upstream_hunk_is_applied_or_already_present(self):
        patch = {'path': 'example.py', 'commit': 'upstream',
                 'hunks': [{'before': 'value = 1', 'after': 'value = 2'}]}
        self.assertEqual(apply_hunks('value = 1\n', patch), 'value = 2\n')
        self.assertEqual(apply_hunks('value = 2\n', patch), 'value = 2\n')

    def test_unknown_or_ambiguous_context_is_rejected(self):
        patch = {'path': 'example.py', 'commit': 'upstream',
                 'hunks': [{'before': 'value = 1', 'after': 'value = 2'}]}
        for source in ('value = 3\n', 'value = 1\nvalue = 1\n',
                       'value = 2\nvalue = 2\n',
                       'value = 1\nvalue = 1\nvalue = 2\n'):
            with self.assertRaises(RuntimeError):
                apply_hunks(source, patch)

    def test_local_patch_provenance_does_not_claim_an_upstream_commit(self):
        patch = {'source_kind': 'keep-local', 'source_id': 'keep-reviewed-change',
                 'commit': None}
        self.assertEqual(patch_provenance(patch), {
            'source_kind': 'keep-local', 'source_id': 'keep-reviewed-change',
            'upstream_commit': None,
        })
        patch['commit'] = 'pretend-upstream'
        with self.assertRaises(ValueError):
            patch_provenance(patch)

    def test_existing_upstream_provenance_is_preserved(self):
        self.assertEqual(patch_provenance({'commit': 'upstream'}), {
            'source_kind': 'upstream', 'upstream_commit': 'upstream',
        })

    def test_missing_local_identifier_or_unknown_source_is_rejected(self):
        for patch in ({'source_kind': 'keep-local', 'commit': None},
                      {'source_kind': 'unknown', 'commit': 'upstream'},
                      {'commit': None}):
            with self.assertRaises(ValueError):
                patch_provenance(patch)

    def local_reset_helpers(self):
        manifest = Path(__file__).resolve().parents[1] / 'scripts/python_security_patches.json'
        local = next(p for p in json.loads(manifest.read_text())
                     if p.get('source_kind') == 'keep-local')
        self.assertEqual(local['source_id'], 'keep-tempfile-bound-permission-reset-v1')
        self.assertIsNone(local['commit'])
        self.assertEqual(len(local['hunks']), 1)
        os_calls = SimpleNamespace(
            O_RDONLY=0, O_NONBLOCK=2048, O_NOFOLLOW=131072,
            supports_follow_symlinks=set(), open=Mock(return_value=41),
            chmod=Mock(), close=Mock(),
        )
        namespace = {'_os': os_calls, '_errno': errno, '_resetflags': Mock()}
        exec(compile(local['hunks'][0]['after'], 'keep-local-cleanup-guard', 'exec'), namespace)
        return namespace, os_calls

    def test_unbound_reset_cannot_call_permission_operations(self):
        namespace, os_calls = self.local_reset_helpers()
        for call in (
            lambda: namespace['_resetperms_fd'](None, '/synthetic-outside'),
            lambda: namespace['_resetperms_at']('entry', None, '/synthetic-outside'),
        ):
            with self.assertRaises(PermissionError):
                call()
        namespace['_resetflags'].assert_not_called()
        os_calls.open.assert_not_called()
        os_calls.chmod.assert_not_called()

    def test_unavailable_nofollow_or_failed_open_cannot_fall_back(self):
        namespace, os_calls = self.local_reset_helpers()
        namespace['_nofollow_mode'] = None
        with self.assertRaises(PermissionError):
            namespace['_resetperms_at']('entry', 31, '/synthetic-entry')
        os_calls.open.assert_not_called()
        namespace['_nofollow_mode'] = os_calls.O_NOFOLLOW
        denied = PermissionError(errno.EACCES, 'synthetic open denial')
        os_calls.open.side_effect = denied
        with self.assertRaises(PermissionError) as caught:
            namespace['_resetperms_at']('entry', 31, '/synthetic-entry')
        self.assertIs(caught.exception, denied)
        os_calls.chmod.assert_not_called()
        os_calls.close.assert_not_called()

    def test_safe_descriptor_is_closed_even_when_chmod_fails(self):
        namespace, os_calls = self.local_reset_helpers()
        os_calls.chmod.side_effect = OSError('synthetic chmod failure')
        with self.assertRaises(OSError):
            namespace['_resetperms_at']('entry', 31, '/synthetic-entry')
        os_calls.open.assert_called_once_with('entry', namespace['_nofollow_mode'], dir_fd=31)
        os_calls.chmod.assert_called_once_with(41, 0o700)
        os_calls.close.assert_called_once_with(41)
