"""Offline verification of original candidate publication provenance."""
import datetime
import json
import os
import re
from contextlib import chdir
from pathlib import Path
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import hub_analysis_review
import candidate_publication
import release_materials as materials
import registry_transfer
from tests.test_release_publish import SHA, DIGESTS, hub_review


class CandidatePublicationTests(unittest.TestCase):
    def setUp(self):
        self.environment = patch.dict(os.environ, {
            'GITHUB_RUN_ID': '999', 'GITHUB_RUN_ATTEMPT': '1', 'GITHUB_SHA': SHA,
            'GITHUB_REPOSITORY': 'brspoon/keep', 'KEEP_CANDIDATE_ONLY': 'false',
            'KEEP_CANDIDATE_RUN_ID': '123', 'KEEP_CANDIDATE_RUN_ATTEMPT': '2',
        })
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.repository = {'id': 91, 'full_name': 'brspoon/keep', 'private': False}
        self.workflow = {'id': 92, 'path': '.github/workflows/image.yml'}
        self.record = {'id': 123, 'run_attempt': 2, 'workflow_id': 92,
                       'path': self.workflow['path'], 'event': 'workflow_dispatch',
                       'head_branch': 'main', 'head_sha': SHA, 'status': 'completed',
                       'conclusion': 'success', 'repository': self.repository,
                       'head_repository': self.repository}
        self.jobs = [{'id': index, 'name': name, 'run_id': 123, 'run_attempt': 2,
                      'head_sha': SHA, 'status': 'completed', 'conclusion': 'success',
                      'steps': [{'name': step, 'status': 'completed', 'conclusion': 'success'}
                                for step in steps]}
                     for index, (name, steps) in enumerate(candidate_publication.REQUIRED.items(), start=1)]
        self.jobs.append({'id': 99, 'name': 'publish-release', 'conclusion': 'skipped'})
        self.total = len(self.jobs)

    def api(self, path):
        if path == '':
            return self.repository
        if path == '/actions/workflows/image.yml':
            return self.workflow
        if path == '/actions/runs/123/attempts/2':
            return self.record
        if path == '/actions/runs/123/attempts/2/jobs?per_page=100&page=1':
            return {'jobs': self.jobs, 'total_count': self.total}
        self.fail('Unexpected candidate metadata request: ' + path)

    def test_completed_original_candidate_returns_producer_without_changing_current_run(self):
        self.assertEqual(candidate_publication.publication_identity(self.api), ('123', '2'))
        self.assertEqual(os.environ['GITHUB_RUN_ID'], '999')
        self.assertEqual(os.environ['GITHUB_RUN_ATTEMPT'], '1')

    def test_candidate_or_partial_selection_is_rejected_before_metadata(self):
        for changes in ({'KEEP_CANDIDATE_ONLY': 'true'}, {'KEEP_CANDIDATE_RUN_ATTEMPT': ''},
                        {'KEEP_CANDIDATE_RUN_ID': '', 'KEEP_CANDIDATE_RUN_ATTEMPT': ''},
                        {'KEEP_CANDIDATE_RUN_ID': '999'}):
            with self.subTest(changes=changes), patch.dict(os.environ, changes), \
                 self.assertRaises(ValueError):
                candidate_publication.publication_identity(self.api)

    def test_wrong_source_workflow_repository_or_incomplete_attempt_is_rejected(self):
        for field, value in (('head_sha', 'b' * 40), ('event', 'push'), ('head_branch', 'other'),
                             ('status', 'in_progress'), ('conclusion', 'failure'),
                             ('run_attempt', 1), ('workflow_id', 93), ('repository', {}),
                             ('path', '.github/workflows/other.yml')):
            original = dict(self.record)
            self.record[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                candidate_publication.publication_identity(self.api)
            self.record = original

    def test_failed_changed_missing_duplicate_or_partial_native_jobs_are_rejected(self):
        native = next(job for job in self.jobs if 'amd64' in job['name'])
        for mutation in (
            lambda: native.update(conclusion='failure'),
            lambda: native.update(run_attempt=1),
            lambda: native.update(head_sha='b' * 40),
            lambda: native['steps'][1].update(conclusion='skipped'),
            lambda: self.jobs.append(dict(native)),
            lambda: self.jobs.pop(self.jobs.index(native)),
            lambda: setattr(self, 'total', self.total + 1),
            lambda: self.jobs[-1].update(conclusion='success'),
        ):
            original = json.loads(json.dumps(self.jobs))
            count = self.total
            mutation()
            with self.subTest(jobs=self.jobs), self.assertRaises(ValueError):
                candidate_publication.publication_identity(self.api)
            self.jobs, self.total = original, count
            native = next(job for job in self.jobs if 'amd64' in job['name'])

    def test_promotion_consumes_original_asset_bytes_and_transfer_identity_in_a_new_run(self):
        from tests.test_release_materials import ReleaseMaterialsTests
        fixture = ReleaseMaterialsTests()
        fixture.setUp()
        fixture.environ.stop()
        try:
            rows, bodies = fixture.verify_fixture(validation=True, native_digests=DIGESTS)
            original = dict(bodies)
            record = {**self.record, 'id': 123456, 'run_attempt': 3}
            jobs = [{**job, 'run_id': 123456, 'run_attempt': 3} for job in self.jobs]
            def api(path):
                if path == '/actions/runs/123456/attempts/3':
                    return record
                if path == '/actions/runs/123456/attempts/3/jobs?per_page=100&page=1':
                    return {'jobs': jobs, 'total_count': len(jobs)}
                if path == '/releases/88/assets?per_page=100':
                    return rows
                return self.api(path)
            with chdir(fixture.root), patch.dict(os.environ, {
                    'KEEP_CANDIDATE_RUN_ID': '123456', 'KEEP_CANDIDATE_RUN_ATTEMPT': '3',
                    'GITHUB_EVENT_NAME': 'workflow_dispatch', 'KEEP_VALIDATION_RUN_ID': '100'}), \
                 patch.object(materials, 'api', side_effect=api), \
                 patch.object(materials, 'asset_body', side_effect=lambda asset: bodies[asset['name']]), \
                 patch.object(materials, 'verify_durable_validation'), \
                 patch.object(materials.review_image, 'current_day', return_value=datetime.date(2026, 10, 20)):
                identities = materials.verify_identities(fixture.VERSION, {'id': 88}, DIGESTS)
                self.assertEqual(registry_transfer.transfer_tag('amd64'), 'transfer-123456-3-amd64')
                self.assertEqual(registry_transfer.transfer_tag('arm64'), 'transfer-123456-3-arm64')
                self.assertEqual(os.environ['GITHUB_RUN_ID'], '999')
                self.assertEqual(os.environ['GITHUB_RUN_ATTEMPT'], '1')
                self.assertEqual({identity['run_id'] for identity in identities.values()}, {'123456'})
                self.assertEqual(bodies, original)
                with self.assertRaisesRegex(ValueError, 'identity differs'):
                    materials.verify_identities(fixture.VERSION, {'id': 88}, {**DIGESTS, 'arm64': DIGESTS['amd64']})
                self.assertEqual(bodies, original)
        finally:
            fixture.doCleanups()


class WorkflowConditionTests(unittest.TestCase):
    """Evaluate actual job conditions across candidate and promotion dependency states."""
    def setUp(self):
        self.workflow = (Path(__file__).resolve().parents[1] / '.github/workflows/image.yml').read_text()

    def job(self, name):
        body = self.workflow.split('  ' + name + ':\n', 1)[1]
        return re.split(r'^  [A-Za-z0-9_-]+:\n', body, maxsplit=1, flags=re.MULTILINE)[0]

    def condition(self, name, values):
        body = self.job(name)
        expression = re.search(r'^    if: (.+)$', body, re.MULTILINE)[1]
        dependencies = re.search(r'^    needs: \[([^]]+)\]$', body, re.MULTILINE)[1].split(', ')
        referenced = set(re.findall(r'needs\.([A-Za-z0-9_-]+)\.', expression))
        self.assertTrue(referenced <= set(dependencies), (name, referenced, dependencies))
        # GitHub implicitly requires successful dependencies unless a status
        # function overrides that behavior. This matters for intentionally
        # skipped native/prepare jobs in the separate promotion dispatch.
        if 'always()' not in expression and any(values['needs.' + dependency + '.result'] != 'success'
                                               for dependency in dependencies):
            return False
        token_pattern = r"always\(\)|&&|\|\||==|!|\(|\)|'[^']*'|[A-Za-z_][A-Za-z0-9_.-]*"
        tokens = re.findall(token_pattern, expression)
        self.assertEqual(''.join(tokens), re.sub(r'\s+', '', expression))
        position = 0
        def atom():
            nonlocal position
            token = tokens[position]
            position += 1
            if token == '!':
                return not atom()
            if token == '(':
                value = disjunction()
                self.assertEqual(tokens[position], ')')
                position += 1
                return value
            if token == 'always()':
                return True
            return token[1:-1] if token.startswith("'") else values[token]
        def comparison():
            nonlocal position
            value = atom()
            if position < len(tokens) and tokens[position] == '==':
                position += 1
                value = value == atom()
            return value
        def conjunction():
            nonlocal position
            value = comparison()
            while position < len(tokens) and tokens[position] == '&&':
                position += 1
                other = comparison()
                value = bool(value) and bool(other)
            return value
        def disjunction():
            nonlocal position
            value = conjunction()
            while position < len(tokens) and tokens[position] == '||':
                position += 1
                other = conjunction()
                value = bool(value) or bool(other)
            return value
        result = disjunction()
        self.assertEqual(position, len(tokens))
        return bool(result)

    def values(self, candidate=True):
        return {'github.event_name': 'workflow_dispatch', 'github.ref': 'refs/heads/main',
                'inputs.publish_release': True, 'inputs.candidate_only': candidate,
                'inputs.confirmation': 'release-stable', 'needs.release-needed.outputs.publish': 'true',
                'needs.release-needed.result': 'success', 'needs.validated-main.result': 'success',
                'needs.prepare-release.result': 'success' if candidate else 'skipped',
                'needs.release-native.result': 'success' if candidate else 'skipped',
                'needs.tested-images.result': 'success'}

    def test_candidate_stages_and_aggregates_without_release_publication(self):
        values = self.values()
        self.assertTrue(self.condition('prepare-release', values))
        self.assertTrue(self.condition('release-native', values))
        self.assertTrue(self.condition('tested-images', values))
        self.assertFalse(self.condition('publish-release', values))

    def test_promotion_consumes_skipped_staging_dependencies_and_successful_aggregation(self):
        values = self.values(candidate=False)
        self.assertFalse(self.condition('prepare-release', values))
        self.assertFalse(self.condition('release-native', values))
        self.assertTrue(self.condition('tested-images', values))
        self.assertTrue(self.condition('publish-release', values))

    def test_failed_native_or_validation_and_wrong_dispatch_never_reach_publication(self):
        for candidate in (True, False):
            for changes in ({'needs.validated-main.result': 'failure'},
                            {'needs.tested-images.result': 'failure'},
                            {'github.event_name': 'push'}, {'github.event_name': 'pull_request'},
                            {'github.ref': 'refs/heads/other'}, {'inputs.publish_release': False},
                            {'inputs.confirmation': ''}, {'needs.release-needed.outputs.publish': 'false'}):
                values = {**self.values(candidate), **changes}
                with self.subTest(candidate=candidate, changes=changes):
                    self.assertFalse(self.condition('publish-release', values))
        for result in ('failure', 'cancelled', 'skipped'):
            values = {**self.values(), 'needs.release-native.result': result}
            with self.subTest(native=result):
                self.assertFalse(self.condition('tested-images', values))
                self.assertFalse(self.condition('publish-release', values))

