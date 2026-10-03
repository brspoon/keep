"""Offline guard tests for automatic GitHub artifact-review refresh."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import urllib.error

sys.path.insert(0, str(Path('scripts').resolve()))
import refresh_registry_artifacts as refresh
import retain_registry as retention


TOKEN = 'syntheticGithubReadToken_0123456789'
SHA = 'a' * 40
REVIEWED_SHA = 'b' * 40


def digest(number):
    return 'sha256:' + format(number, '064x')


def run_record(run_id=12345, attempt=2, sha=SHA, *, private=True,
               head_repository='brspoon/keep', repository='brspoon/keep'):
    return {
        'id': run_id, 'run_attempt': attempt, 'head_sha': sha,
        'path': '.github/workflows/image.yml', 'status': 'completed',
        'conclusion': 'success', 'event': 'workflow_dispatch', 'head_branch': 'main',
        'repository': {'full_name': repository},
        'head_repository': {'full_name': head_repository},
    }


def transfer_inventory(name='transfer-12345-2-amd64', number=9):
    return [{'name': name, 'digest': digest(number),
             'images': [{'digest': digest(number)}]}]


class Response:
    def __init__(self, value):
        self.body = json.dumps(value).encode()

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, _limit=-1):
        return self.body


class FakeOpener:
    def __init__(self, replies):
        self.replies = replies
        self.requests = []

    def open(self, request, timeout):
        self.requests.append((request, timeout))
        endpoint = request.full_url.removeprefix('https://api.github.com/')
        reply = self.replies.get(endpoint)
        if isinstance(reply, BaseException):
            raise reply
        if reply is None:
            raise AssertionError('Unexpected GitHub endpoint: ' + endpoint)
        return Response(reply)


class RegistryArtifactRefreshTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='keep-artifact-refresh-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.state = self.root / '.registry-state'
        self.state.mkdir(mode=0o700)
        os.chmod(self.state, 0o700)

    def write_private(self, path, data):
        path.write_bytes(data if isinstance(data, bytes) else data.encode())
        path.chmod(0o600)
        return path

    def configure_token(self, token=TOKEN):
        self.write_private(self.state / 'github-review.json', json.dumps({
            'schema': refresh.CONFIG_SCHEMA, 'source': 'token-file'}))
        self.write_private(self.state / 'github-read-token', token)

    def existing_review(self):
        path = self.state / 'retention-artifacts.json'
        document = {
            'schema': 'keep.registry-artifact-review.v1',
            'repository': 'brspoon/keep', 'reviewed_at': '2026-10-01T12:00:00Z',
            'artifacts': {'sha-' + REVIEWED_SHA: {
                'digest': digest(81), 'run_id': '900', 'run_attempt': 1,
                'head_sha': REVIEWED_SHA, 'status': 'completed', 'conclusion': 'success',
            }},
        }
        self.write_private(path, json.dumps(document))
        return path, path.read_bytes()

    def successful_opener(self, record=None):
        replies = {
            'repos/brspoon/keep': {'full_name': 'brspoon/keep', 'private': True},
            'repos/brspoon/keep/actions/runs/12345/attempts/2': record or run_record(),
        }
        return FakeOpener(replies)

    def test_current_terminal_transfer_is_reviewed_and_written_owner_only(self):
        self.configure_token()
        opener = self.successful_opener()
        with patch.object(refresh.urllib.request, 'build_opener', return_value=opener):
            outcome = refresh.refresh_review(self.root, object(), transfer_inventory())

        self.assertEqual(outcome['status'], 'refreshed')
        self.assertEqual(outcome['approved_count'], 1)
        self.assertEqual(outcome['github_requests'], 2)
        path = self.state / 'retention-artifacts.json'
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        document = json.loads(path.read_text())
        self.assertEqual(document['schema'], 'keep.registry-artifact-review.v1')
        self.assertEqual(set(document['artifacts']), {'transfer-12345-2-amd64'})
        approved = document['artifacts']['transfer-12345-2-amd64']
        self.assertEqual(approved['digest'], digest(9))
        self.assertEqual(approved['run_id'], '12345')
        self.assertEqual(approved['run_attempt'], 2)
        self.assertEqual(opener.requests[0][0].full_url, 'https://api.github.com/repos/brspoon/keep')
        self.assertEqual(opener.requests[1][0].full_url,
                         'https://api.github.com/repos/brspoon/keep/actions/runs/12345/attempts/2')
        for request, timeout in opener.requests:
            self.assertEqual(request.get_method(), 'GET')
            self.assertEqual(timeout, 30)
            self.assertEqual(request.get_header('Authorization'), 'Bearer ' + TOKEN)
        self.assertNotIn(TOKEN, path.read_text())
        self.assertEqual(json.loads((self.state / 'github-review.json').read_text()), {
            'schema': refresh.CONFIG_SCHEMA, 'source': 'token-file',
        })
        self.assertEqual(retention.reviewed_artifacts(self.root, transfer_inventory()),
                         {'transfer-12345-2-amd64': digest(9)})

    def test_missing_configuration_does_not_read_credentials_or_replace_existing_review(self):
        path, before = self.existing_review()
        with patch.object(refresh, '_credential', side_effect=AssertionError('credential read')), \
             patch.object(refresh, 'GitHubReader', side_effect=AssertionError('reader constructed')):
            result = refresh.refresh_review(self.root, object(), transfer_inventory())
        self.assertEqual(result, {'status': 'not-configured', 'approved_count': 0})
        self.assertEqual(path.read_bytes(), before)

    def test_no_candidate_rows_need_no_configuration_or_credential_read(self):
        path, before = self.existing_review()
        with patch.object(refresh, 'GitHubReader', side_effect=AssertionError('reader constructed')):
            result = refresh.refresh_review(self.root, object(), [
                {'name': 'custom-keep', 'digest': digest(7)},
            ])
        self.assertEqual(result, {'status': 'not-configured', 'approved_count': 0})
        self.assertEqual(path.read_bytes(), before)

    def test_unsafe_configuration_is_rejected_and_existing_review_is_preserved(self):
        review_path, before_review = self.existing_review()
        config = self.write_private(self.state / 'github-review.json', json.dumps({
            'schema': refresh.CONFIG_SCHEMA, 'source': 'token-file', 'token_path': '/tmp/attacker'}))
        self.write_private(self.state / 'github-read-token', TOKEN)
        with patch.object(refresh.urllib.request, 'build_opener', side_effect=AssertionError('network opened')):
            with self.assertRaises(refresh.RefreshError):
                refresh.refresh_review(self.root, object(), transfer_inventory())
        self.assertEqual(review_path.read_bytes(), before_review)
        self.assertTrue(config.exists())

    def test_symlink_or_loosely_permitted_token_fails_closed(self):
        review_path, before_review = self.existing_review()
        self.write_private(self.state / 'github-review.json', json.dumps({
            'schema': refresh.CONFIG_SCHEMA, 'source': 'token-file'}))
        real_token = self.root / 'token'
        self.write_private(real_token, TOKEN)
        alias = self.state / 'github-read-token'
        alias.symlink_to(real_token)
        with patch.object(refresh.urllib.request, 'build_opener', side_effect=AssertionError('network opened')):
            with self.assertRaises(refresh.RefreshError):
                refresh.refresh_review(self.root, object(), transfer_inventory())
        alias.unlink()
        token_file = self.write_private(alias, TOKEN)
        token_file.chmod(0o644)
        with patch.object(refresh.urllib.request, 'build_opener', side_effect=AssertionError('network opened')):
            with self.assertRaises(refresh.RefreshError):
                refresh.refresh_review(self.root, object(), transfer_inventory())
        self.assertEqual(review_path.read_bytes(), before_review)

    def test_unsafe_prior_review_stops_before_credentials_or_network(self):
        self.configure_token()
        path = self.state / 'retention-artifacts.json'
        path.write_text('{}')
        path.chmod(0o644)
        with patch.object(refresh, 'GitHubReader', side_effect=AssertionError('reader constructed')):
            with self.assertRaises(refresh.RefreshError):
                refresh.refresh_review(self.root, object(), transfer_inventory())

    def test_github_api_failure_never_grants_candidate_tags(self):
        self.configure_token()
        old_path, before = self.existing_review()
        opener = FakeOpener({
            'repos/brspoon/keep': {'full_name': 'brspoon/keep', 'private': True},
            'repos/brspoon/keep/actions/runs/12345/attempts/2':
                urllib.error.URLError('server echoed ' + TOKEN),
        })
        with patch.object(refresh.urllib.request, 'build_opener', return_value=opener):
            outcome = refresh.refresh_review(self.root, object(), transfer_inventory())
        self.assertEqual(outcome['status'], 'refreshed')
        self.assertEqual(outcome['approved_count'], 0)
        self.assertNotIn(TOKEN, repr(outcome))
        self.assertEqual(retention.reviewed_artifacts(self.root, transfer_inventory()), {})
        written = json.loads(old_path.read_text())
        self.assertEqual(written['artifacts'], {})
        self.assertNotIn(TOKEN, old_path.read_text())
        self.assertEqual(before != old_path.read_bytes(), True)

    def test_invalid_repository_metadata_check_precedes_workflow_reads(self):
        self.configure_token()
        for repository in (
            {'full_name': 'foreign/keep', 'private': True},
            {'full_name': 'brspoon/keep'},
            {'full_name': 'brspoon/keep', 'private': 'false'},
            {'full_name': 'brspoon/keep', 'private': 0},
            {'full_name': 'brspoon/keep', 'private': None},
        ):
            opener = FakeOpener({'repos/brspoon/keep': repository})
            reader = refresh.GitHubReader(self.root)
            with patch.object(reader, '_opener', opener):
                with self.subTest(repository=repository), self.assertRaisesRegex(
                        refresh.ReviewError, 'identity and visibility metadata'):
                    reader(None, 'repos/brspoon/keep/actions/runs/12345/attempts/2')
            self.assertEqual(len(opener.requests), 1)
            self.assertTrue(opener.requests[0][0].full_url.endswith('/repos/brspoon/keep'))

    def test_public_and_private_repository_workflow_reads_remain_fixed_and_cached(self):
        self.configure_token()
        endpoint = 'repos/brspoon/keep/actions/runs/12345/attempts/2'
        for private in (False, True):
            opener = FakeOpener({'repos/brspoon/keep': {'full_name': 'brspoon/keep', 'private': private},
                                 endpoint: run_record()})
            with self.subTest(private=private), patch.object(refresh.urllib.request, 'build_opener', return_value=opener):
                reader = refresh.GitHubReader(self.root)
                self.assertEqual(reader(None, endpoint), run_record())
                self.assertEqual(reader(None, endpoint), run_record())
            self.assertEqual(len(opener.requests), 2)
            self.assertTrue(all(request.get_method() == 'GET' for request, _ in opener.requests))

    def test_foreign_reflected_or_malformed_endpoints_are_rejected_before_network(self):
        self.configure_token()
        reader = refresh.GitHubReader(self.root)
        opener = self.successful_opener()
        with patch.object(reader, '_opener', opener):
            endpoints = [
                'repos/other/repo',
                'repos/brspoon/keep/actions/runs/12345/attempts/2?redirect=https://evil.invalid',
                'https://api.github.com/repos/brspoon/keep/actions/runs/12345/attempts/2',
                'repos/brspoon/keep/actions/workflows/evil.yml/runs?head_sha=' + SHA + '&per_page=100&page=1',
            ]
            for endpoint in endpoints:
                with self.subTest(endpoint=endpoint), self.assertRaises(refresh.ReviewError):
                    reader(None, endpoint)
        self.assertEqual(opener.requests, [])

    def test_reader_refuses_redirects_and_enforces_request_and_response_bounds(self):
        request = refresh.urllib.request.Request('https://api.github.com/repos/brspoon/keep')
        self.assertIsNone(refresh.NoRedirect().redirect_request(
            request, object(), 302, 'Found', {}, 'https://attacker.invalid/'))
        self.configure_token()
        reader = refresh.GitHubReader(self.root)
        opener = self.successful_opener()
        with patch.object(reader, '_opener', opener), patch.object(refresh, 'MAX_REQUESTS', 1):
            reader._get('repos/brspoon/keep')
            with self.assertRaises(refresh.ReviewError):
                reader._get('repos/brspoon/keep/actions/runs/12345/attempts/2')

        oversized = FakeOpener({'repos/brspoon/keep': {'full_name': 'brspoon/keep', 'private': True}})
        reader = refresh.GitHubReader(self.root)
        with patch.object(reader, '_opener', oversized), patch.object(refresh, 'MAX_RESPONSE', 8):
            with self.assertRaises(refresh.ReviewError):
                reader._get('repos/brspoon/keep')

        reader = refresh.GitHubReader(self.root)
        reader._bytes = refresh.MAX_TOTAL
        opener = self.successful_opener()
        with patch.object(reader, '_opener', opener), self.assertRaises(refresh.ReviewError):
            reader._get('repos/brspoon/keep')
        self.assertEqual(opener.requests, [])

    def test_configured_git_remote_is_fixed_to_keep_and_credential_is_not_persisted(self):
        self.write_private(self.state / 'github-review.json', json.dumps({
            'schema': refresh.CONFIG_SCHEMA, 'source': 'git-remote'}))
        completed = subprocess.CompletedProcess(
            ['git'], 0, stdout=('https://' + TOKEN + '@github.com/brspoon/keep.git\n').encode(), stderr=b'')
        with patch.object(refresh.subprocess, 'run', return_value=completed) as run:
            reader = refresh.GitHubReader(self.root)
        run.assert_called_once_with(['git', '-C', str(self.root), 'config', '--get', 'remote.origin.url'],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    timeout=10, check=False)
        opener = self.successful_opener()
        with patch.object(reader, '_opener', opener):
            reader(None, 'repos/brspoon/keep/actions/runs/12345/attempts/2')
        self.assertEqual(opener.requests[0][0].get_header('Authorization'), 'Bearer ' + TOKEN)
        self.assertNotIn(TOKEN, (self.state / 'github-review.json').read_text())

    def test_git_remote_to_other_host_or_repository_is_rejected_before_network(self):
        self.write_private(self.state / 'github-review.json', json.dumps({
            'schema': refresh.CONFIG_SCHEMA, 'source': 'git-remote'}))
        for remote in (
            'https://github.com/attacker/keep.git',
            'https://github.com/brspoon/other.git',
            'https://github.com.evil.invalid/brspoon/keep.git',
            'http://github.com/brspoon/keep.git',
        ):
            completed = subprocess.CompletedProcess(['git'], 0, stdout=(remote + '\n').encode(), stderr=b'')
            with patch.object(refresh.subprocess, 'run', return_value=completed):
                with self.subTest(remote=remote), self.assertRaises(refresh.RefreshError):
                    refresh.GitHubReader(self.root)


if __name__ == '__main__':
    unittest.main()
