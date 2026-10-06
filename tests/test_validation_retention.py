"""Offline scope, provenance, prompt cleanup and race tests for validation storage."""
import copy
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import sys
import unittest
import urllib.parse
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import validation_retention as retention


class ValidationRetentionTests(unittest.TestCase):
    def setUp(self):
        self.planner = retention.plan
        self.now = dt.datetime(2026, 10, 15, 12, tzinfo=dt.timezone.utc)
        self.main = 'f' * 40
        self.runs, self.releases, self.assets, self.artifacts, self.indexes, self.jobs = {}, [], {}, {}, {}, {}
        self.deletes = []
        self.env = patch.dict(os.environ, {
            'GITHUB_REPOSITORY': 'brspoon/keep', 'GITHUB_TOKEN': 'fake-token',
            'GITHUB_REF': 'refs/heads/main', 'GITHUB_SHA': self.main,
            'GITHUB_EVENT_NAME': 'workflow_dispatch', 'GITHUB_RUN_ID': '900',
            'GITHUB_WORKFLOW_REF': 'brspoon/keep/' + retention.CLEANUP_WORKFLOW + '@refs/heads/main'}, clear=True)
        self.env.start()
        self.addCleanup(self.env.stop)
        self.add_candidate(100, 'a' * 40, 12)
        self.add_candidate(200, 'b' * 40, 8)
        self.add_candidate(50, 'c' * 40, 13, success=False)
        self.add_candidate(150, 'd' * 40, 3, success=False)
        self.releases.append({'id': 999, 'tag_name': '2.21.3', 'draft': False})
        self.provider = patch.object(retention, 'api', side_effect=self.api)
        self.provider.start()
        self.addCleanup(self.provider.stop)
        self.reader = patch.object(retention.builds, 'read_index', side_effect=lambda row: copy.deepcopy(self.indexes[row['id']]))
        self.reader.start()
        self.addCleanup(self.reader.stop)

    def add_candidate(self, number, sha, age, *, success=True):
        when = (self.now - dt.timedelta(days=age)).isoformat().replace('+00:00', 'Z')
        run = {'id': number, 'workflow_id': 40, 'path': retention.WORKFLOW,
               'event': 'push', 'head_branch': 'main', 'head_sha': sha, 'run_attempt': 1,
               'status': 'completed', 'conclusion': 'success' if success else 'failure',
               'created_at': when, 'updated_at': when,
               'repository': {'id': 11, 'full_name': retention.REPOSITORY},
               'head_repository': {'id': 11, 'full_name': retention.REPOSITORY}}
        release = {'id': number + 1000, 'draft': True, 'prerelease': True,
                   'tag_name': f'candidate-{sha}-{number}', 'target_commitish': sha,
                   'published_at': None, 'created_at': when, 'updated_at': when,
                   'author': {'login': 'github-actions[bot]', 'type': 'Bot'}}
        self.runs[number] = run
        self.releases.append(release)
        self.assets[release['id']], self.artifacts[number], self.jobs[number] = [], [], []
        if not success:
            return
        for offset, name in enumerate(('prepare-candidate', 'installer-windows', 'contributor-tests', 'required-checks',
                                       *(retention.builds.job_name(arch) for arch in retention.builds.ARCHES))):
            job = {'id': number * 10 + offset, 'name': name, 'run_id': number, 'run_attempt': 1,
                   'head_sha': sha, 'status': 'completed', 'conclusion': 'success'}
            if name.startswith('image / '):
                job['steps'] = [{'name': step, 'status': 'completed', 'conclusion': 'success'}
                                for step in (*retention.builds.NATIVE_STEPS, retention.builds.RETAIN_STEP,
                                             retention.builds.INDEX_STEP)]
            self.jobs[number].append(job)
        for arch_number, arch in enumerate(retention.builds.ARCHES):
            records = []
            for offset, path in enumerate(sorted(retention.expected_paths('2.21.4', arch))):
                asset_id = number * 1000 + arch_number * 100 + offset
                digest = hashlib.sha256(path.encode()).hexdigest()
                name = f'build-{number}-1-{arch}--' + Path(path).name
                self.assets[release['id']].append({'id': asset_id, 'name': name, 'size': 50,
                                                 'digest': 'sha256:' + digest, 'state': 'uploaded'})
                records.append({'id': asset_id, 'path': path, 'name': name, 'bytes': 50, 'sha256': digest})
            artifact = {'id': number * 100 + arch_number, 'name': f'validated-build-{number}-1-{arch}',
                        'expired': False, 'size_in_bytes': 1000, 'digest': 'sha256:' + '9' * 64,
                        'workflow_run': {'id': number, 'repository_id': 11, 'head_repository_id': 11,
                                         'head_branch': 'main', 'head_sha': sha}}
            self.artifacts[number].append(artifact)
            job = next(row for row in self.jobs[number] if row['name'] == retention.builds.job_name(arch))
            self.indexes[artifact['id']] = {'schema': retention.builds.SCHEMA, 'repository': retention.REPOSITORY,
                'version': '2.21.4', 'revision': sha, 'architecture': arch, 'config_digest': 'sha256:' + '8' * 64,
                'candidate': {'id': release['id'], 'tag_name': release['tag_name']}, 'assets': records,
                'build': {'run_id': number, 'run_attempt': 1, 'job_id': job['id'],
                          'job_name': job['name'], 'workflow_id': 40}}

    def make_legacy(self, number):
        for job in self.jobs[number]:
            if job['name'].startswith('image / '):
                job['steps'] = [step for step in job['steps'] if step['name'] != retention.LOADER_STEP]
                for step in job['steps']:
                    if step['name'] == retention.CURRENT_ACCEPTANCE_STEP:
                        step['name'] = retention.LEGACY_ACCEPTANCE_STEP
        for artifact in self.artifacts[number]:
            index = self.indexes[artifact['id']]
            index['assets'] = [row for row in index['assets'] if 'candidate-dependencies-' not in row['path']]
        self.assets[number + 1000] = [row for row in self.assets[number + 1000]
                                      if 'candidate-dependencies-' not in row['name']]

    def cleanup_run(self):
        return {'id': 900, 'workflow_id': 80, 'path': retention.CLEANUP_WORKFLOW,
                'event': os.environ['GITHUB_EVENT_NAME'], 'status': 'in_progress',
                'head_branch': 'main', 'head_sha': os.environ['GITHUB_SHA'],
                'repository': {'id': 11, 'full_name': retention.REPOSITORY},
                'head_repository': {'id': 11, 'full_name': retention.REPOSITORY}}

    def api(self, path, *, method='GET'):
        route = path.partition('?')[0]
        if method == 'DELETE':
            self.deletes.append(route)
            if route.startswith('/actions/artifacts/'):
                artifact_id = int(route.rsplit('/', 1)[1])
                for rows in self.artifacts.values():
                    rows[:] = [row for row in rows if row['id'] != artifact_id]
            elif route.startswith('/releases/'):
                release_id = int(route.rsplit('/', 1)[1])
                self.releases[:] = [row for row in self.releases if row['id'] != release_id]
            else:
                raise AssertionError('Unscoped deletion: ' + route)
            return None
        if route == '':
            return {'id': 11, 'full_name': retention.REPOSITORY}
        if route == '/actions/workflows/image.yml':
            return {'id': 40, 'path': retention.WORKFLOW}
        if route == '/actions/workflows/validation-retention.yml':
            return {'id': 80, 'path': retention.CLEANUP_WORKFLOW}
        if route == '/actions/workflows/image.yml/runs':
            state = urllib.parse.parse_qs(urllib.parse.urlsplit(path).query).get('status', [None])[0]
            return {'workflow_runs': [run for run in self.runs.values() if run.get('status') == state]}
        if route == '/git/ref/heads/main':
            return {'object': {'sha': self.main}}
        if route == '/releases':
            return self.releases
        if route.startswith('/releases/'):
            release_id = int(route.split('/')[2])
            if route.endswith('/assets'):
                return self.assets[release_id]
            return next(row for row in self.releases if row['id'] == release_id)
        if route.startswith('/actions/artifacts/'):
            artifact_id = int(route.rsplit('/', 1)[1])
            return next(row for rows in self.artifacts.values() for row in rows if row['id'] == artifact_id)
        if route.startswith('/actions/runs/'):
            run_id = int(route.split('/')[3])
            if run_id == 900:
                return self.cleanup_run()
            if route.endswith('/artifacts'):
                return {'artifacts': self.artifacts[run_id]}
            if route.endswith('/jobs'):
                return {'jobs': self.jobs[run_id]}
            return self.runs[run_id]
        raise AssertionError('Unexpected provider route ' + path)

    def inventory(self):
        return retention.plan(self.now)

    def test_superseded_and_abandoned_candidates_are_immediately_eligible_across_docs_head(self):
        plan = self.inventory()
        self.assertEqual(plan['protected_release_ids'], [1200])
        actions = {row['run_id']: row['action'] for row in plan['candidates']}
        self.assertEqual(actions, {50: 'delete', 100: 'delete', 150: 'delete', 200: 'keep'})
        self.assertNotIn('grace_days', plan)
        self.assertFalse(plan['blocked'])
        self.assertEqual(self.deletes, [])

    def test_all_current_main_candidates_are_protected_even_with_newer_success(self):
        self.main = 'a' * 40
        plan = self.inventory()
        self.assertEqual(plan['protected_release_ids'], [1100, 1200])
        self.assertEqual(next(row for row in plan['candidates'] if row['run_id'] == 100)['reason'], 'current main candidate')

    def test_active_validation_and_manual_publication_block_every_deletion(self):
        for state in retention.ACTIVE:
            with self.subTest(state=state):
                self.runs[800] = {'id': 800, 'workflow_id': 40, 'path': retention.WORKFLOW,
                                  'status': state, 'event': 'workflow_dispatch'}
                plan = self.inventory()
                self.assertTrue(plan['blocked'])
                self.assertTrue(all(row['action'] == 'keep' for row in plan['candidates']))
                with self.assertRaisesRegex(ValueError, 'active'):
                    retention.execute(plan)
        self.assertEqual(self.deletes, [])

    def test_expired_indexes_do_not_displace_the_latest_usable_candidate(self):
        self.add_candidate(300, 'e' * 40, 8)
        for artifact in self.artifacts[300]:
            artifact['expired'] = True
        plan = self.inventory()
        self.assertEqual(plan['protected_release_id'], 1200)
        self.assertEqual(next(row for row in plan['candidates'] if row['run_id'] == 300)['action'], 'delete')

    def test_no_usable_indexes_preserves_latest_success_until_replacement(self):
        for rows in self.artifacts.values():
            for artifact in rows:
                artifact['expired'] = True
        plan = self.inventory()
        self.assertEqual(plan['protected_release_id'], 1200)
        newest = next(row for row in plan['candidates'] if row['run_id'] == 200)
        self.assertIn('current validation unavailable', newest['reason'])

    def test_exact_legacy_contract_authenticates_original_indexes_but_is_not_usable(self):
        self.make_legacy(100)
        plan = self.inventory()
        legacy = next(row for row in plan['candidates'] if row['run_id'] == 100)
        self.assertFalse(legacy['usable'])
        self.assertTrue(legacy['successful'])
        self.assertTrue(next(row for row in plan['candidates'] if row['run_id'] == 200)['usable'])
        self.assertEqual(plan['protected_release_ids'], [1200])
        read_ids = {call.args[0]['id'] for call in retention.builds.read_index.call_args_list}
        self.assertTrue({10000, 10001}.issubset(read_ids))
        for artifact in self.artifacts[100]:
            index = self.indexes[artifact['id']]
            self.assertEqual({row['path'] for row in index['assets']},
                             retention.expected_paths('2.21.4', index['architecture'], legacy=True))
            self.assertEqual(len(index['assets']), 18)
        for artifact in self.artifacts[200]:
            self.assertEqual(len(self.indexes[artifact['id']]['assets']), 19)
        self.assertEqual(self.deletes, [])

    def test_only_legacy_candidates_preserve_latest_successful_fallback(self):
        self.make_legacy(100)
        self.make_legacy(200)
        plan = self.inventory()
        self.assertTrue(all(not row['usable'] for row in plan['candidates']))
        self.assertEqual(plan['protected_release_ids'], [1200])
        newest = next(row for row in plan['candidates'] if row['run_id'] == 200)
        self.assertEqual(newest['action'], 'keep')
        self.assertIn('current validation unavailable', newest['reason'])
        self.assertEqual(self.deletes, [])

    def test_all_current_main_legacy_candidates_remain_protected(self):
        self.main = 'a' * 40
        self.make_legacy(100)
        self.add_candidate(300, self.main, 1)
        self.make_legacy(300)
        plan = self.inventory()
        self.assertEqual(plan['protected_release_ids'], [1100, 1200, 1300])
        for row in plan['candidates']:
            if row['revision'] == self.main:
                self.assertEqual(row['action'], 'keep')
                self.assertEqual(row['reason'], 'current main candidate')
        self.assertEqual(self.deletes, [])

    def test_legacy_and_current_native_profiles_cannot_be_mixed(self):
        self.make_legacy(100)
        current = next(row for row in self.jobs[200] if row['name'].endswith('(arm64)'))
        legacy = next(row for row in self.jobs[100] if row['name'].endswith('(arm64)'))
        legacy['steps'] = copy.deepcopy(current['steps'])
        with self.assertRaisesRegex(ValueError, 'disagree on the validation profile'):
            self.inventory()
        self.assertEqual(self.deletes, [])

    def test_arbitrary_missing_gates_are_not_treated_as_legacy(self):
        saved = copy.deepcopy(self.jobs)
        for legacy in (False, True):
            for missing in (retention.LOADER_STEP, retention.CURRENT_ACCEPTANCE_STEP,
                            'Scan candidate without suppressions', retention.builds.RETAIN_STEP,
                            retention.builds.INDEX_STEP):
                self.jobs = copy.deepcopy(saved)
                if legacy:
                    self.make_legacy(100)
                    if missing in (retention.LOADER_STEP, retention.CURRENT_ACCEPTANCE_STEP):
                        missing = retention.LEGACY_ACCEPTANCE_STEP
                native = next(row for row in self.jobs[100] if row['name'].endswith('(amd64)'))
                native['steps'] = [step for step in native['steps'] if step['name'] != missing]
                with self.subTest(legacy=legacy, missing=missing), self.assertRaises(ValueError):
                    self.inventory()
        self.assertEqual(self.deletes, [])

    def test_failed_or_skipped_legacy_gates_still_block_planning(self):
        self.make_legacy(100)
        saved = copy.deepcopy(self.jobs)
        for name in (retention.LEGACY_ACCEPTANCE_STEP, 'Scan candidate without suppressions',
                     retention.builds.RETAIN_STEP, retention.builds.INDEX_STEP):
            for conclusion in ('failure', 'skipped', None):
                self.jobs = copy.deepcopy(saved)
                native = next(row for row in self.jobs[100] if row['name'].endswith('(amd64)'))
                next(step for step in native['steps'] if step['name'] == name)['conclusion'] = conclusion
                with self.subTest(name=name, conclusion=conclusion), self.assertRaisesRegex(ValueError, 'gate did not succeed'):
                    self.inventory()
        self.assertEqual(self.deletes, [])

    def test_malformed_or_duplicate_steps_block_both_native_profiles(self):
        saved = copy.deepcopy(self.jobs)
        for legacy in (False, True):
            for mutation in ('missing', 'mapping', 'non-object', 'missing-name', 'blank-name',
                             'duplicate', 'mixed-acceptance'):
                self.jobs = copy.deepcopy(saved)
                if legacy:
                    self.make_legacy(100)
                native = next(row for row in self.jobs[100] if row['name'].endswith('(amd64)'))
                if mutation == 'missing':
                    del native['steps']
                elif mutation == 'mapping':
                    native['steps'] = {}
                elif mutation == 'non-object':
                    native['steps'].append(None)
                elif mutation == 'missing-name':
                    native['steps'].append({'status': 'completed', 'conclusion': 'success'})
                elif mutation == 'blank-name':
                    native['steps'].append({'name': ' \t', 'status': 'completed', 'conclusion': 'success'})
                elif mutation == 'duplicate':
                    native['steps'].append(copy.deepcopy(native['steps'][0]))
                else:
                    native['steps'].append({'name': retention.CURRENT_ACCEPTANCE_STEP if legacy
                                            else retention.LEGACY_ACCEPTANCE_STEP,
                                            'status': 'completed', 'conclusion': 'success'})
                with self.subTest(legacy=legacy, mutation=mutation), self.assertRaises(ValueError):
                    self.inventory()
        self.assertEqual(self.deletes, [])

    def test_shared_job_ids_across_required_names_block_both_profiles(self):
        saved = copy.deepcopy((self.jobs, self.indexes, self.assets))
        for legacy in (False, True):
            for other_name in ('prepare-candidate', retention.builds.job_name('arm64')):
                self.jobs, self.indexes, self.assets = copy.deepcopy(saved)
                if legacy:
                    self.make_legacy(100)
                native = next(row for row in self.jobs[100] if row['name'].endswith('(amd64)'))
                other = next(row for row in self.jobs[100] if row['name'] == other_name)
                native['id'] = other['id']
                # Keep the index internally consistent so only the ambiguous
                # provider job identities cause this rejection.
                self.indexes[10000]['build']['job_id'] = other['id']
                with self.subTest(legacy=legacy, other_name=other_name), self.assertRaisesRegex(
                        ValueError, 'Duplicate required validation producer job identity'):
                    self.inventory()
        self.assertEqual(self.deletes, [])

    def test_older_required_attempt_cannot_reuse_another_producer_job_id(self):
        saved = copy.deepcopy((self.runs, self.jobs, self.indexes, self.assets))
        for legacy in (False, True):
            self.runs, self.jobs, self.indexes, self.assets = copy.deepcopy(saved)
            if legacy:
                self.make_legacy(100)
            self.runs[100]['run_attempt'] = 2
            prepare = next(row for row in self.jobs[100] if row['name'] == 'prepare-candidate')
            arm64 = next(row for row in self.jobs[100] if row['name'].endswith('(arm64)'))
            older = copy.deepcopy(prepare)
            older['id'] = arm64['id']
            prepare['run_attempt'] = 2
            self.jobs[100].append(older)
            # Selected jobs and both original native indexes still agree; the
            # ambiguous ID belongs only to an older required-job attempt.
            with self.subTest(legacy=legacy), self.assertRaisesRegex(
                    ValueError, 'Duplicate required validation producer job identity'):
                self.inventory()
        self.assertEqual(self.deletes, [])

    def test_legacy_jobs_preserve_strict_producer_and_latest_attempt_selection(self):
        self.make_legacy(100)
        saved_runs, saved_jobs = copy.deepcopy((self.runs, self.jobs))
        for mutation in ('foreign-run', 'foreign-sha', 'future-attempt', 'invalid-id',
                         'duplicate', 'duplicate-latest', 'latest-failed', 'latest-active'):
            self.runs, self.jobs = copy.deepcopy((saved_runs, saved_jobs))
            native = next(row for row in self.jobs[100] if row['name'].endswith('(amd64)'))
            if mutation == 'foreign-run':
                native['run_id'] = 999
            elif mutation == 'foreign-sha':
                native['head_sha'] = 'e' * 40
            elif mutation == 'future-attempt':
                native['run_attempt'] = 2
            elif mutation == 'invalid-id':
                native['id'] = True
            elif mutation in ('duplicate', 'duplicate-latest'):
                duplicate = copy.deepcopy(native)
                if mutation == 'duplicate-latest':
                    duplicate['id'] += 10000
                self.jobs[100].append(duplicate)
            else:
                self.runs[100]['run_attempt'] = 2
                newer = copy.deepcopy(native)
                newer.update(id=1999, run_attempt=2)
                if mutation == 'latest-failed':
                    newer['conclusion'] = 'failure'
                else:
                    newer.update(status='in_progress', conclusion=None)
                self.jobs[100].append(newer)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.inventory()
        self.assertEqual(self.deletes, [])

    def test_index_and_asset_tampering_blocks_both_native_profiles(self):
        saved = copy.deepcopy((self.jobs, self.indexes, self.assets))
        for legacy in (False, True):
            for mutation in ('producer', 'revision', 'hash', 'size', 'missing-record',
                             'duplicate-record', 'unknown-record', 'missing-api-asset', 'wrong-api-hash'):
                self.jobs, self.indexes, self.assets = copy.deepcopy(saved)
                if legacy:
                    self.make_legacy(100)
                index = self.indexes[10000]
                record = index['assets'][0]
                if mutation == 'producer':
                    index['build']['job_id'] += 999
                elif mutation == 'revision':
                    index['revision'] = 'e' * 40
                elif mutation == 'hash':
                    record['sha256'] = '0' * 64
                elif mutation == 'size':
                    record['bytes'] += 1
                elif mutation == 'missing-record':
                    index['assets'].pop()
                elif mutation == 'duplicate-record':
                    index['assets'][-1] = copy.deepcopy(record)
                elif mutation == 'unknown-record':
                    record['path'] = 'unknown.json'
                elif mutation == 'missing-api-asset':
                    self.assets[1100] = [row for row in self.assets[1100] if row['id'] != record['id']]
                else:
                    next(row for row in self.assets[1100] if row['id'] == record['id'])['digest'] = 'sha256:' + '0' * 64
                with self.subTest(legacy=legacy, mutation=mutation), self.assertRaises(ValueError):
                    self.inventory()
        self.assertEqual(self.deletes, [])

    def test_current_profile_cannot_use_the_legacy_evidence_inventory(self):
        for index in self.indexes.values():
            if index['build']['run_id'] == 100:
                index['assets'] = [row for row in index['assets'] if 'candidate-dependencies-' not in row['path']]
        self.assets[1100] = [row for row in self.assets[1100] if 'candidate-dependencies-' not in row['name']]
        with self.assertRaisesRegex(ValueError, 'evidence inventory is incomplete'):
            self.inventory()
        self.assertEqual(self.deletes, [])

    def test_legacy_profile_rejects_current_or_unindexed_producer_assets(self):
        original_indexes, original_assets = copy.deepcopy((self.indexes, self.assets))
        for indexed in (False, True):
            self.indexes, self.assets = copy.deepcopy((original_indexes, original_assets))
            self.make_legacy(100)
            record = next(row for row in original_indexes[10000]['assets']
                          if row['path'] == 'candidate-dependencies-amd64.json')
            asset = next(row for row in original_assets[1100] if row['id'] == record['id'])
            self.assets[1100].append(copy.deepcopy(asset))
            if indexed:
                self.indexes[10000]['assets'].append(copy.deepcopy(record))
            with self.subTest(indexed=indexed), self.assertRaisesRegex(ValueError, 'inventory'):
                self.inventory()
        self.assertEqual(self.deletes, [])

    def test_provider_failures_and_unknown_metadata_block_planning(self):
        bad_changes = [lambda: self.releases[0].update(author={'login': 'someone', 'type': 'User'}),
                       lambda: self.releases[0].update(draft=False),
                       lambda: self.releases[0].update(tag_name='candidate-nope'),
                       lambda: self.releases[0].update(target_commitish='d' * 40),
                       lambda: self.runs[100].update(head_repository={'id': 99, 'full_name': 'fork/keep'}),
                       lambda: self.runs[100].update(event='pull_request'),
                       lambda: self.runs[100].update(status='unknown'),
                       lambda: self.releases.append(copy.deepcopy(self.releases[0])),
                       lambda: self.artifacts[100][0].update(name='validated-build-999-1-amd64'),
                       lambda: self.assets[1100][0].update(name='other-artifact.tar'),
                       lambda: self.assets[1100][0].update(digest='not-a-hash'),
                       lambda: self.jobs[100][-1]['steps'][0].update(conclusion='skipped'),
                       lambda: self.indexes[10000].update(revision='e' * 40),
                       lambda: self.assets[1100][0].update(size=51),
                       lambda: self.runs[100].update(updated_at='2026-10-16T00:00:00Z')]
        saved = copy.deepcopy((self.runs, self.releases, self.artifacts, self.assets, self.jobs, self.indexes))
        for change in bad_changes:
            self.runs, self.releases, self.artifacts, self.assets, self.jobs, self.indexes = copy.deepcopy(saved)
            change()
            with self.subTest(change=change):
                with self.assertRaises(ValueError):
                    self.inventory()
        with patch.object(retention, 'api', side_effect=OSError('provider unavailable')):
            with self.assertRaises(OSError):
                self.inventory()
        self.assertEqual(self.deletes, [])

    def test_success_without_complete_full_native_jobs_is_not_trusted(self):
        self.jobs[100] = [job for job in self.jobs[100] if not job['name'].endswith('(arm64)')]
        with self.assertRaisesRegex(ValueError, 'Missing required'):
            self.inventory()

    def test_latest_producing_attempt_is_required_for_usable_index(self):
        self.runs[200]['run_attempt'] = 2
        native = copy.deepcopy(self.jobs[200][-1])
        native.update(id=2999, run_attempt=2)
        self.jobs[200].append(native)
        plan = self.inventory()
        self.assertEqual(plan['protected_release_id'], 1100)

    def test_executed_cleanup_only_deletes_paired_exact_artifacts_and_drafts(self):
        plan = self.inventory()
        with patch.object(retention, 'plan', side_effect=lambda: self.planner(self.now)):
            deleted = retention.execute(plan)
        self.assertEqual(deleted, [1050, 1100, 1150])
        self.assertEqual(self.deletes, ['/releases/1050', '/actions/artifacts/10000',
                                       '/actions/artifacts/10001', '/releases/1100', '/releases/1150'])
        self.assertIn(999, [row['id'] for row in self.releases])
        self.assertIn(1200, [row['id'] for row in self.releases])
        self.assertNotIn(1150, [row['id'] for row in self.releases])

    def test_execution_refuses_stale_main_foreign_workflow_or_missing_approval_context(self):
        plan = self.inventory()
        changes = [{'GITHUB_SHA': 'a' * 40}, {'GITHUB_EVENT_NAME': 'push'},
                   {'GITHUB_REF': 'refs/heads/feature'}, {'GITHUB_REPOSITORY': 'fork/keep'},
                   {'GITHUB_WORKFLOW_REF': 'brspoon/keep/.github/workflows/image.yml@refs/heads/main'}]
        for change in changes:
            with patch.dict(os.environ, change), self.subTest(change=change):
                with self.assertRaises(ValueError):
                    retention.execute(plan)
        self.assertEqual(self.deletes, [])

    def test_rerun_or_changed_draft_between_plan_and_execution_aborts(self):
        plan = self.inventory()
        self.releases[2]['updated_at'] = '2026-10-14T00:00:00Z'
        with patch.object(retention, 'plan', side_effect=lambda: self.planner(self.now)):
            with self.assertRaisesRegex(ValueError, 'plan changed'):
                retention.execute(plan)
        self.assertEqual(self.deletes, [])

    def test_activation_between_plan_and_execution_aborts(self):
        plan = self.inventory()
        self.runs[800] = {'id': 800, 'workflow_id': 40, 'path': retention.WORKFLOW,
                          'status': 'queued', 'event': 'workflow_dispatch'}
        with patch.object(retention, 'plan', side_effect=lambda: self.planner(self.now)):
            with self.assertRaisesRegex(ValueError, 'plan changed'):
                retention.execute(plan)
        self.assertEqual(self.deletes, [])

    def test_artifact_metadata_race_blocks_before_delete(self):
        plan = self.inventory()
        for row in plan['candidates']:
            if row['run_id'] != 100:
                row['action'] = 'keep'
        original = self.api
        def mutate(path, **kwargs):
            result = original(path, **kwargs)
            if path == '/actions/artifacts/10000':
                return {**result, 'digest': 'sha256:' + '0' * 64}
            return result
        with patch.object(retention, 'api', side_effect=mutate), patch.object(retention, 'plan', return_value=plan):
            with self.assertRaisesRegex(ValueError, 'Index changed'):
                retention.execute(plan)
        self.assertEqual(self.deletes, [])

    def test_draft_mutation_after_index_cleanup_never_deletes_changed_release(self):
        plan = self.inventory()
        for row in plan['candidates']:
            if row['run_id'] != 100:
                row['action'] = 'keep'
        original = self.api
        def mutate(path, **kwargs):
            result = original(path, **kwargs)
            if path == '/releases/1100' and kwargs.get('method', 'GET') == 'GET' and len(self.deletes) == 2:
                return {**result, 'updated_at': '2026-10-14T00:00:00Z'}
            return result
        with patch.object(retention, 'api', side_effect=mutate), patch.object(retention, 'plan', return_value=plan):
            with self.assertRaisesRegex(ValueError, 'Draft or producer changed'):
                retention.execute(plan)
        self.assertNotIn('/releases/1100', self.deletes)
        self.assertEqual(self.deletes, ['/actions/artifacts/10000', '/actions/artifacts/10001'])

    def test_cli_defaults_to_dry_run(self):
        with patch.object(sys, 'argv', ['validation_retention.py']), patch.object(retention, 'plan', return_value=self.inventory()), \
             patch.object(retention, 'execute') as execute, patch('builtins.print') as output:
            retention.main()
        execute.assert_not_called()
        self.assertEqual(json.loads(output.call_args.args[0])['schema'], 'keep.validation-retention-plan.v1')

    def test_new_candidate_appearing_after_preflight_stops_cleanup(self):
        plan = self.inventory()
        original = self.api
        def new_candidate(path, **kwargs):
            result = original(path, **kwargs)
            if path.startswith('/releases?'):
                added = copy.deepcopy(self.releases[0])
                added.update(id=1998, tag_name='candidate-' + 'e' * 40 + '-998', target_commitish='e' * 40)
                return [*result, added]
            return result
        with patch.object(retention, 'plan', return_value=plan), patch.object(retention, 'api', side_effect=new_candidate):
            with self.assertRaisesRegex(ValueError, 'inventory changed'):
                retention.execute(plan)
        self.assertEqual(self.deletes, [])

    def test_protected_candidate_storage_change_stops_cleanup(self):
        plan = self.inventory()
        original = self.api
        def changed_protected(path, **kwargs):
            result = original(path, **kwargs)
            if path.startswith('/releases/1200/assets?'):
                return [{**result[0], 'size': 51}, *result[1:]]
            return result
        with patch.object(retention, 'plan', return_value=plan), patch.object(retention, 'api', side_effect=changed_protected):
            with self.assertRaisesRegex(ValueError, 'metadata changed'):
                retention.execute(plan)
        self.assertEqual(self.deletes, [])

    def test_active_run_during_paired_artifact_cleanup_stops_before_draft_delete(self):
        plan = self.inventory()
        for row in plan['candidates']:
            if row['run_id'] != 100:
                row['action'] = 'keep'
        original = self.api
        def activate(path, **kwargs):
            result = original(path, **kwargs)
            if path == '/actions/artifacts/10000' and kwargs.get('method') == 'DELETE':
                self.runs[800] = {'id': 800, 'workflow_id': 40, 'path': retention.WORKFLOW,
                                  'status': 'in_progress', 'event': 'workflow_dispatch'}
            return result
        with patch.object(retention, 'plan', return_value=plan), patch.object(retention, 'api', side_effect=activate):
            with self.assertRaisesRegex(ValueError, 'started during cleanup'):
                retention.execute(plan)
        self.assertEqual(self.deletes, ['/actions/artifacts/10000'])

    def test_execute_does_not_replan_or_redownload_indexes_for_each_candidate(self):
        plan = self.inventory()
        original_planner = self.planner
        with patch.object(retention, 'plan', side_effect=lambda: original_planner(self.now)) as planner:
            retention.execute(plan)
        planner.assert_called_once()

    def test_just_abandoned_candidate_is_eligible_without_any_waiting_period(self):
        when = (self.now - dt.timedelta(seconds=1)).isoformat().replace('+00:00', 'Z')
        self.runs[150].update(created_at=when, updated_at=when)
        next(row for row in self.releases if row['id'] == 1150).update(created_at=when, updated_at=when)
        candidate = next(row for row in self.inventory()['candidates'] if row['run_id'] == 150)
        self.assertEqual(candidate['action'], 'delete')
        self.assertEqual(candidate['reason'], 'superseded or abandoned candidate')

    def test_completed_primary_main_push_can_trigger_cleanup(self):
        with patch.dict(os.environ, {'GITHUB_EVENT_NAME': 'workflow_run', 'RETENTION_TRIGGER_RUN_ID': '200'}):
            retention.execute_guard()
            self.runs[200]['conclusion'] = 'failure'
            retention.execute_guard()
        self.assertEqual(self.deletes, [])

    def test_workflow_run_trigger_rejects_missing_foreign_nonpush_or_nonterminal_parent(self):
        original = copy.deepcopy(self.runs[200])
        changes = [{'event': 'workflow_dispatch'}, {'event': 'pull_request'},
                   {'head_branch': 'other'}, {'status': 'in_progress'},
                   {'head_sha': 'not-a-sha'}, {'workflow_id': 41},
                   {'path': '.github/workflows/other.yml'},
                   {'head_repository': {'id': 99, 'full_name': 'fork/keep'}},
                   {'conclusion': 'unknown'}]
        with patch.dict(os.environ, {'GITHUB_EVENT_NAME': 'workflow_run', 'RETENTION_TRIGGER_RUN_ID': '200'}):
            for change in changes:
                self.runs[200] = {**original, **change}
                with self.subTest(change=change), self.assertRaises(ValueError):
                    retention.execute_guard()
            self.runs[200] = original
            with patch.dict(os.environ, {'RETENTION_TRIGGER_RUN_ID': ''}), self.assertRaises(ValueError):
                retention.execute_guard()
        self.assertEqual(self.deletes, [])

    def test_protected_storage_change_after_each_artifact_delete_blocks_remaining_writes(self):
        saved = copy.deepcopy((self.runs, self.releases, self.assets, self.artifacts))
        for trigger_id, expected in ((10000, ['/actions/artifacts/10000']),
                                     (10001, ['/actions/artifacts/10000', '/actions/artifacts/10001'])):
            self.runs, self.releases, self.assets, self.artifacts = copy.deepcopy(saved)
            self.deletes = []
            plan = self.inventory()
            for row in plan['candidates']:
                if row['run_id'] != 100:
                    row['action'] = 'keep'
            original = self.api
            def mutate(path, **kwargs):
                result = original(path, **kwargs)
                if path == '/actions/artifacts/' + str(trigger_id) and kwargs.get('method') == 'DELETE':
                    self.assets[1200][0]['size'] += 1
                return result
            with self.subTest(trigger_id=trigger_id), patch.object(retention, 'plan', return_value=plan), \
                 patch.object(retention, 'api', side_effect=mutate):
                with self.assertRaisesRegex(ValueError, 'metadata changed'):
                    retention.execute(plan)
            self.assertEqual(self.deletes, expected)
            self.assertNotIn('/releases/1100', self.deletes)

    def test_target_artifact_change_during_protection_guard_is_detected_before_delete(self):
        plan = self.inventory()
        for row in plan['candidates']:
            if row['run_id'] != 100:
                row['action'] = 'keep'
        original = self.api
        inventories = 0
        def mutate(path, **kwargs):
            nonlocal inventories
            result = original(path, **kwargs)
            if path.startswith('/releases?'):
                inventories += 1
                if inventories == 2:
                    self.artifacts[100][0]['digest'] = 'sha256:' + '0' * 64
            return result
        with patch.object(retention, 'plan', return_value=plan), patch.object(retention, 'api', side_effect=mutate):
            with self.assertRaisesRegex(ValueError, 'Index changed'):
                retention.execute(plan)
        self.assertEqual(self.deletes, [])

    def test_target_draft_change_during_final_protection_guard_is_detected_before_delete(self):
        plan = self.inventory()
        for row in plan['candidates']:
            if row['run_id'] != 100:
                row['action'] = 'keep'
        original = self.api
        def mutate(path, **kwargs):
            result = original(path, **kwargs)
            if path.startswith('/releases?') and len(self.deletes) == 2:
                next(row for row in self.releases if row['id'] == 1100)['updated_at'] = '2026-10-14T00:00:00Z'
            return result
        with patch.object(retention, 'plan', return_value=plan), patch.object(retention, 'api', side_effect=mutate):
            with self.assertRaisesRegex(ValueError, 'Draft or producer changed'):
                retention.execute(plan)
        self.assertEqual(self.deletes, ['/actions/artifacts/10000', '/actions/artifacts/10001'])
        self.assertNotIn('/releases/1100', self.deletes)

    def test_partial_cleanup_retry_replans_only_remaining_artifacts_and_drafts(self):
        self.api('/actions/artifacts/10000', method='DELETE')
        self.deletes = []
        plan = self.inventory()
        self.assertFalse(next(row for row in plan['candidates'] if row['run_id'] == 100)['usable'])
        with patch.object(retention, 'plan', side_effect=lambda: self.planner(self.now)):
            deleted = retention.execute(plan)
        self.assertIn(1100, deleted)
        self.assertIn('/actions/artifacts/10001', self.deletes)
        self.assertNotIn('/actions/artifacts/10000', self.deletes)
        self.assertNotIn('/releases/1200', self.deletes)

    def test_active_status_queries_do_not_walk_completed_history(self):
        with patch.object(retention, 'pages', return_value=[]) as pages:
            self.assertEqual(retention.active_runs(40), [])
        expected = {'/actions/workflows/image.yml/runs?status=' + state for state in retention.ACTIVE}
        self.assertEqual({call.args[0] for call in pages.call_args_list}, expected)
        with patch.object(retention, 'pages', return_value=[{'id': 55, 'workflow_id': 40,
                                                          'path': retention.WORKFLOW, 'status': 'completed',
                                                          'conclusion': 'success'}]):
            with self.assertRaisesRegex(ValueError, 'Ambiguous active'):
                retention.active_runs(40)

    def test_cleanup_workflow_limits_automatic_trigger_and_serializes_with_publication(self):
        workflow = (Path(__file__).resolve().parents[1] / retention.CLEANUP_WORKFLOW).read_text()
        self.assertIn("workflows: ['Validate Keep and publish retained images']", workflow)
        self.assertIn('branches: [main]', workflow)
        self.assertIn('types: [completed]', workflow)
        self.assertIn("github.event.workflow_run.event == 'push'", workflow)
        self.assertIn("github.repository == 'brspoon/keep'", workflow)
        self.assertIn("github.ref == 'refs/heads/main'", workflow)
        self.assertIn('group: keep-image-refs/heads/main', workflow)
        self.assertIn('queue: max', workflow)
        self.assertIn('cancel-in-progress: false', workflow)
        self.assertRegex(workflow, r'execute:\s+description:[^\n]+\s+type: boolean\s+default: false')
        self.assertIn("RETENTION_EXECUTE: ${{ github.event_name == 'workflow_run' || github.event_name == 'schedule' || inputs.execute }}", workflow)
        self.assertIn('RETENTION_TRIGGER_RUN_ID: ${{ github.event.workflow_run.id }}', workflow)
        self.assertIn('python3 -B scripts/validation_retention.py --execute', workflow)
        self.assertIn('persist-credentials: false', workflow)

    def test_pagination_continues_and_rejects_unbounded_or_malformed_pages(self):
        with patch.object(retention, 'api', side_effect=[[{'id': n} for n in range(100)], [{'id': 101}]]) as api:
            self.assertEqual(len(retention.pages('/releases')), 101)
            self.assertIn('page=2', api.call_args.args[0])
        with patch.object(retention, 'api', return_value={'unexpected': []}):
            with self.assertRaises(ValueError):
                retention.pages('/releases')
        with patch.object(retention, 'api', return_value=[{}] * 100):
            with self.assertRaisesRegex(ValueError, 'bound'):
                retention.pages('/releases')


if __name__ == '__main__':
    unittest.main()
