"""Read-only evidence and private-output checks for registry artifact review."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path('scripts').resolve()))
import review_registry_artifacts as reviewer
import retain_registry as retention


def digest(number):
    return 'sha256:' + format(number, '064x')


def run_record(run_id, attempt, sha, *, status='completed', conclusion='success',
               event='workflow_dispatch', branch='main', repository='brspoon/keep',
               head_repository='brspoon/keep', path='.github/workflows/image.yml'):
    return {
        'id': run_id, 'run_attempt': attempt, 'head_sha': sha, 'path': path,
        'status': status, 'conclusion': conclusion, 'event': event,
        'head_branch': branch, 'repository': {'full_name': repository},
        'head_repository': {'full_name': head_repository},
    }


def inventory(*tags):
    return {'rows': list(tags)}


def tag(name, number, images=None):
    row = {'name': name, 'digest': digest(number)}
    if images is not None:
        row['images'] = images
    return row


def release(version='2.17.6'):
    return tag(version, 1, [
        {'os': 'linux', 'architecture': 'amd64', 'digest': digest(2)},
        {'os': 'linux', 'architecture': 'arm64', 'digest': digest(3)},
    ])


class ArtifactReviewTests(unittest.TestCase):
    def test_only_orphan_commit_and_terminal_exact_transfer_attempt_are_approved(self):
        sha = 'a' * 40
        transfer = run_record(98765, 4, 'b' * 40, conclusion='failure')
        source_listing = {'total_count': 1, 'workflow_runs': [run_record(12345, 2, sha)]}
        exact_source = run_record(12345, 2, sha)
        calls = []

        def api(executable, endpoint):
            calls.append(endpoint)
            if '/workflows/image.yml/runs?' in endpoint:
                return source_listing
            if endpoint.endswith('/98765/attempts/4'):
                return transfer
            if endpoint.endswith('/12345/attempts/2'):
                return exact_source
            raise AssertionError(endpoint)

        rows = inventory(release(), tag('sha-' + sha, 10),
                         tag('sha-' + sha + '-arm64', 11),
                         tag('transfer-98765-4-amd64', 12),
                         tag('custom-keep', 13))
        approved, omitted = reviewer.review(rows, '/usr/bin/gh', api)
        self.assertEqual(set(approved), {'sha-' + sha, 'sha-' + sha + '-arm64', 'transfer-98765-4-amd64'})
        self.assertEqual(omitted, [])
        self.assertEqual(approved['sha-' + sha]['head_sha'], sha)
        self.assertEqual(approved['sha-' + sha]['run_id'], '12345')
        self.assertEqual(approved['sha-' + sha]['run_attempt'], 2)
        self.assertEqual(approved['transfer-98765-4-amd64']['conclusion'], 'failure')
        self.assertEqual(sum('/workflows/image.yml/runs?' in call for call in calls), 1)
        self.assertIn('repos/brspoon/keep/actions/runs/98765/attempts/4', calls)

    def test_commit_aliases_tied_by_index_or_platform_digest_are_not_approved(self):
        sha = 'c' * 40
        rows = inventory(release(), tag('sha-' + sha, 1),
                         tag('sha-' + sha + '-amd64', 2),
                         tag('sha-' + sha + '-arm64', 3))
        approved, reasons = reviewer.review(rows, api=lambda *_: self.fail('must not query tied tags'))
        self.assertEqual(approved, {})
        self.assertEqual([row['tag'] for row in reasons],
                         ['sha-' + sha, 'sha-' + sha + '-amd64', 'sha-' + sha + '-arm64'])
        self.assertTrue(all(row['reason'] == 'digest_is_referenced_by_version_tag' for row in reasons))

    def test_historical_main_push_is_valid_publisher_but_fork_head_is_not(self):
        sha = '4' * 40
        rows = inventory(release(), tag('sha-' + sha, 14))
        push = run_record(1234, 1, sha, event='push', conclusion='success')
        exact = run_record(1234, 1, sha, event='push', conclusion='success')
        calls = []
        def api(_gh, endpoint):
            calls.append(endpoint)
            if '/workflows/image.yml/runs?' in endpoint:
                return {'total_count': 1, 'workflow_runs': [push]}
            return exact
        approved, reasons = reviewer.review(rows, api=api)
        self.assertEqual(reasons, [])
        self.assertEqual(approved['sha-' + sha]['run_id'], '1234')

        fork = run_record(1235, 1, sha, event='pull_request',
                          head_repository='fork-owner/keep')
        approved, reasons = reviewer.review(rows, api=lambda *_: {
            'total_count': 1, 'workflow_runs': [fork]})
        self.assertNotIn('sha-' + sha, approved)
        self.assertIn('No successful trusted main-branch publisher', reasons[0]['reason'])

    def test_legacy_transfer_from_trusted_non_main_branch_can_be_reviewed(self):
        attempt = run_record(89, 3, '9' * 40, event='push', branch='feature/old-release')
        rows = inventory(release(), tag('transfer-89-3-arm64', 21))
        approved, reasons = reviewer.review(rows, api=lambda *_: attempt)
        self.assertEqual(reasons, [])
        self.assertEqual(approved['transfer-89-3-arm64']['run_attempt'], 3)

    def test_source_is_omitted_if_any_workflow_run_is_nonterminal(self):
        sha = 'd' * 40
        rows = inventory(release(), tag('sha-' + sha, 9))
        listing = {'total_count': 2, 'workflow_runs': [
            run_record(10, 1, sha), run_record(11, 1, sha, status='in_progress', conclusion=None),
        ]}
        approved, reasons = reviewer.review(rows, api=lambda *_: listing)
        self.assertNotIn('sha-' + sha, approved)
        self.assertIn('not in a known terminal state', reasons[0]['reason'])

    def test_foreign_workflow_evidence_and_mismatched_attempt_are_omitted(self):
        foreign = run_record(70, 1, 'e' * 40, repository='someone-else/keep')
        mismatch = run_record(71, 1, 'f' * 40)
        rows = inventory(release(), tag('transfer-70-1-amd64', 9),
                         tag('transfer-71-2-arm64', 10))
        answers = {
            'repos/brspoon/keep/actions/runs/70/attempts/1': foreign,
            'repos/brspoon/keep/actions/runs/71/attempts/2': mismatch,
        }
        approved, reasons = reviewer.review(rows, api=lambda _gh, endpoint: answers[endpoint])
        self.assertEqual(approved, {})
        self.assertEqual(len(reasons), 2)
        self.assertIn('expected repository', reasons[0]['reason'])
        self.assertIn('did not match its exact', reasons[1]['reason'])

    def test_transfer_requires_exact_completed_manual_main_attempt_and_known_conclusion(self):
        sha = '1' * 40
        bad_records = [
            run_record(80, 1, sha, status='queued', conclusion=None),
            run_record(80, 1, sha, conclusion='future-conclusion'),
            run_record(80, 1, sha, head_repository='fork-owner/keep'),
            run_record(81, 1, sha),
            run_record(80, 2, sha),
        ]
        for record in bad_records:
            rows = inventory(release(), tag('transfer-80-1-amd64', 9))
            approved, _ = reviewer.review(rows, api=lambda _gh, _endpoint, value=record: value)
            self.assertEqual(approved, {}, record)

    def test_orphan_source_pagination_is_bounded_and_must_be_complete(self):
        sha = '2' * 40
        rows = inventory(release(), tag('sha-' + sha, 90))
        calls = []

        def api(_gh, endpoint):
            calls.append(endpoint)
            page = int(endpoint.rsplit('page=', 1)[1])
            return {'total_count': reviewer.PAGE_SIZE * (reviewer.MAX_RUN_PAGES + 1),
                    'workflow_runs': [run_record((page - 1) * reviewer.PAGE_SIZE + i + 1, 1, sha)
                                      for i in range(reviewer.PAGE_SIZE)]}

        approved, reasons = reviewer.review(rows, api=api)
        self.assertEqual(approved, {})
        self.assertEqual(len(calls), reviewer.MAX_RUN_PAGES)
        self.assertIn('bounded page limit', reasons[0]['reason'])

        pages = {'page=1': [run_record(44, 1, sha)],
                 'page=2': [run_record(44, 1, sha)]}
        def duplicate_api(_gh, endpoint):
            if '/workflows/image.yml/runs?' in endpoint:
                return {'total_count': 2, 'workflow_runs': pages['page=' + endpoint.rsplit('page=', 1)[1]]}
            raise AssertionError(endpoint)
        approved, reasons = reviewer.review(rows, api=duplicate_api)
        self.assertEqual(approved, {})
        self.assertIn('repeated a run attempt', reasons[0]['reason'])

    def test_version_metadata_and_tag_digests_are_validated(self):
        malformed = [
            inventory(tag('2.17.6', 1)),
            inventory(release(), tag('sha-' + 'g' * 40, 5)),
            inventory(release(), tag('transfer-0-1-amd64', 5)),
            inventory(release(), {'name': 'sha-' + 'a' * 40, 'digest': 'latest'}),
        ]
        for document in malformed:
            with self.subTest(document=document), self.assertRaises(reviewer.ReviewError):
                reviewer.parse_inventory(document)

    def test_private_output_is_atomic_owner_only_and_never_overwrites(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            os.chmod(parent, 0o700)
            output = parent / 'review.json'
            approved = {'sha-' + 'a' * 40: {
                'digest': digest(5), 'run_id': '8', 'run_attempt': 1,
                'head_sha': 'a' * 40, 'status': 'completed', 'conclusion': 'success',
            }}
            reviewer.write_review(output, approved, '2026-10-01T12:00:00Z')
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            content = json.loads(output.read_text())
            self.assertEqual(content, {
                'schema': 'keep.registry-artifact-review.v1',
                'repository': 'brspoon/keep', 'reviewed_at': '2026-10-01T12:00:00Z',
                'artifacts': approved,
            })
            with self.assertRaises(reviewer.ReviewError):
                reviewer.write_review(output, {})
            self.assertEqual(json.loads(output.read_text()), content)

    def test_oversized_review_is_rejected_before_creating_output(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            os.chmod(parent, 0o700)
            output = parent / 'review.json'
            approved = {'sha-' + 'a' * 40: {
                'digest': digest(5), 'run_id': '8', 'run_attempt': 1,
                'head_sha': 'a' * 40, 'status': 'completed', 'conclusion': 'success',
            }}
            with patch.object(reviewer, 'MAX_REVIEW_BYTES', 128):
                with self.assertRaisesRegex(reviewer.ReviewError, '512 KiB retention-reader limit'):
                    reviewer.write_review(output, approved, '2026-10-01T12:00:00Z')
            self.assertFalse(output.exists())
            self.assertEqual(list(parent.iterdir()), [])

    def test_output_contract_is_consumed_by_retention_reader(self):
        sha = '3' * 40
        rows = inventory(release(), tag('sha-' + sha, 45, [
            {'os': 'linux', 'architecture': 'amd64', 'digest': digest(45)}]))['rows']
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / '.registry-state'
            state.mkdir(mode=0o700)
            os.chmod(state, 0o700)
            evidence = {'sha-' + sha: {
                'digest': digest(45), 'run_id': '123', 'run_attempt': 1,
                'head_sha': sha, 'status': 'completed', 'conclusion': 'success',
            }}
            reviewer.write_review(state / 'retention-artifacts.json', evidence)
            self.assertEqual(retention.reviewed_artifacts(root, rows), {'sha-' + sha: digest(45)})

    def test_private_output_rejects_symlink_destination_parent_and_loose_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            parent = root / 'secure'
            parent.mkdir(mode=0o700)
            os.chmod(parent, 0o700)
            target = root / 'target.json'
            target.write_text('{}')
            symlink_output = parent / 'link.json'
            symlink_output.symlink_to(target)
            with self.assertRaises(reviewer.ReviewError):
                reviewer.write_review(symlink_output, {})
            loose = root / 'loose'
            loose.mkdir(mode=0o700)
            os.chmod(loose, 0o755)
            with self.assertRaises(reviewer.ReviewError):
                reviewer.write_review(loose / 'review.json', {})
            parent_link = root / 'parent-link'
            parent_link.symlink_to(parent, target_is_directory=True)
            with self.assertRaises(reviewer.ReviewError):
                reviewer.write_review(parent_link / 'review.json', {})
            self.assertEqual(target.read_text(), '{}')

    def test_inventory_input_rejects_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'inventory.json'
            source.write_text('[]')
            alias = root / 'alias.json'
            alias.symlink_to(source)
            with self.assertRaises(reviewer.ReviewError):
                reviewer.read_inventory(alias)


if __name__ == '__main__':
    unittest.main()
