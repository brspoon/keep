import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import Mock, patch

import requests
import release_updates as updates


def release(tag='2.10.0', **values):
    return {'tag_name': tag, 'name': 'Release ' + tag, 'published_at': '2026-10-11T12:00:00Z',
            'draft': False, 'prerelease': False, 'html_url': 'https://outside.example/untrusted',
            'body': 'Unrendered remote markdown', 'author': {'email': 'private@example.test'}, **values}


class Response:
    def __init__(self, payload=None, status=200, headers=None, chunks=None):
        self.status_code = status
        self.headers = headers or {}
        self.chunks = chunks if chunks is not None else [json.dumps(payload).encode()]

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def iter_content(self, size):
        return iter(self.chunks)


class ReleaseUpdateTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / 'release observations.sqlite3'
        self.store = updates.Store(self.path)
        self.session = Mock()
        self.session.__enter__ = Mock(return_value=self.session)
        self.session.__exit__ = Mock(return_value=False)
        self.factory = patch.object(updates.requests, 'Session', return_value=self.session).start()
        self.addCleanup(patch.stopall)
        self.succeed()

    def succeed(self, latest=None, recent=None, etags=True):
        latest = release() if latest is None else latest
        recent = [latest, release('2.9.0')] if recent is None else recent
        self.session.get.side_effect = [Response(latest, headers={'ETag': '"latest"'} if etags else {}),
                                        Response(recent, headers={'ETag': '"recent"'} if etags else {})]

    def row(self):
        with sqlite3.connect(self.path) as db:
            db.row_factory = sqlite3.Row
            return dict(db.execute('SELECT * FROM release_checks WHERE id=1').fetchone())

    def test_read_only_snapshot_does_not_create_tables_or_use_http(self):
        empty = Path(self.directory.name) / 'empty?read-only.sqlite3'
        sqlite3.connect(empty).close()
        before = empty.read_bytes()
        observer = updates.Store(empty, initialize=False)
        snapshot = observer.snapshot('2.9.0', now=100)
        self.assertEqual(snapshot['status'], 'never')
        self.assertEqual(snapshot['comparison'], 'unknown')
        self.assertIsNone(snapshot['latest_version'])
        self.assertIsNone(snapshot['update_available'])
        self.assertTrue(snapshot['can_check'])
        self.assertEqual(empty.read_bytes(), before)
        with sqlite3.connect(empty) as db:
            self.assertEqual(db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall(), [])
        self.factory.assert_not_called()

    def test_missing_database_is_unknown_and_unavailable_database_raises(self):
        path = Path(self.directory.name) / 'missing.sqlite3'
        observer = updates.Store(path, initialize=False)
        self.assertEqual(observer.snapshot('2.9.0', now=100)['status'], 'never')
        self.assertFalse(path.exists())
        with patch.object(updates.sqlite3, 'connect', side_effect=sqlite3.OperationalError('private/path')):
            with self.assertRaises(sqlite3.OperationalError):
                self.store.snapshot('2.9.0', now=100)

    def test_fresh_release_checks_numeric_versions_and_fixed_public_requests(self):
        result = self.store.check(now=100)
        self.assertEqual(updates.job_result(result), ('success', 'Release information checked'))
        for installed, expected in (('2.9.0', 'update_available'), ('2.10.0', 'up_to_date'), ('2.11.0', 'ahead')):
            self.assertEqual(self.store.snapshot(installed, now=100)['comparison'], expected)
        snapshot = self.store.snapshot('2.9.0', now=100)
        self.assertEqual(snapshot['latest_version'], '2.10.0')
        self.assertEqual(snapshot['releases'][0]['url'], 'https://github.com/brspoon/keep/releases/tag/2.10.0')
        self.assertNotIn('outside.example', str(snapshot))
        self.assertNotIn('private@example.test', str(snapshot))
        self.assertNotIn('Unrendered', str(snapshot))
        self.assertFalse(self.session.trust_env)
        self.assertEqual([call.args[0] for call in self.session.get.call_args_list],
                         [updates.LATEST_URL, updates.RECENT_URL])
        for call in self.session.get.call_args_list:
            self.assertFalse(call.kwargs['allow_redirects'])
            self.assertTrue(call.kwargs['stream'])
            self.assertNotIn('Authorization', call.kwargs['headers'])
            self.assertNotIn('If-None-Match', call.kwargs['headers'])
            self.assertLessEqual(max(call.kwargs['timeout']), 5)

    def test_history_omits_drafts_prereleases_and_nonsemantic_tags_and_is_bounded(self):
        recent = [release('nightly'), release('2.20.0', prerelease=True), release('2.19.0', draft=True),
                  release('v2.10.0'), release('2.10.0'), *[release(f'2.{i}.0') for i in range(9, 4, -1)]]
        self.succeed(latest=release('v2.10.0'), recent=recent)
        self.assertEqual(self.store.check(now=100)['status'], 'success')
        snapshot = self.store.snapshot('2.9.0', now=100)
        self.assertEqual([item['version'] for item in snapshot['releases']], ['2.10.0', '2.9.0', '2.8.0', '2.7.0', '2.6.0'])
        self.assertEqual(snapshot['latest_tag'], 'v2.10.0')
        self.assertEqual(len(snapshot['releases']), updates.HISTORY_LIMIT)

    def test_success_schedule_manual_throttle_and_restart_are_durable(self):
        self.assertTrue(self.store.due(now=100))
        self.store.check(now=100)
        restarted = updates.Store(self.path, initialize=False)
        self.assertFalse(restarted.due(now=100))
        self.assertFalse(restarted.due(now=159, force=True))
        self.assertTrue(restarted.due(now=160, force=True))
        self.assertFalse(restarted.due(now=21699))
        self.assertTrue(restarted.due(now=21700))
        self.assertEqual(restarted.snapshot('2.9.0', now=120)['retry_after_seconds'], 40)
        self.session.get.reset_mock()
        self.assertEqual(self.store.check(now=120, force=True)['status'], 'waiting')
        self.session.get.assert_not_called()

    def test_failed_checks_preserve_cache_and_never_report_up_to_date(self):
        self.store.check(now=100)
        before = self.row()
        self.session.get.side_effect = requests.ConnectionError('https://private.example/?token=DO-NOT-RECORD')
        outcome = self.store.check(now=160, force=True)
        self.assertEqual(updates.job_result(outcome), ('failed', 'Release check unavailable'))
        snapshot = self.store.snapshot('2.10.0', now=160)
        self.assertEqual(snapshot['status'], 'failed')
        self.assertEqual(snapshot['comparison'], 'unknown')
        self.assertIsNone(snapshot['update_available'])
        self.assertTrue(snapshot['stale'])
        self.assertEqual(snapshot['latest_version'], '2.10.0')
        self.assertEqual(self.row()['latest_json'], before['latest_json'])
        self.assertEqual(self.row()['recent_json'], before['recent_json'])
        self.assertEqual(self.row()['last_success'], 100)
        self.assertNotIn('private.example', str(snapshot))
        self.assertNotIn('DO-NOT-RECORD', str(snapshot))
        self.assertFalse(updates.Store(self.path, initialize=False).due(now=1059))
        self.assertTrue(self.store.due(now=1060))

    def test_partial_history_failure_preserves_the_entire_prior_observation(self):
        self.store.check(now=100)
        before = self.row()
        self.session.get.side_effect = [Response(release('2.11.0')), Response({'unexpected': []})]
        self.assertEqual(self.store.check(now=160, force=True)['status'], 'failed')
        self.assertEqual(self.row()['latest_json'], before['latest_json'])
        self.assertEqual(self.store.snapshot('2.10.0', now=160)['latest_version'], '2.10.0')

    def test_conditional_checks_refresh_success_only_with_matching_valid_cache(self):
        self.store.check(now=100)
        self.session.get.reset_mock()
        self.session.get.side_effect = [Response(status=304), Response(status=304)]
        self.assertEqual(self.store.check(now=160, force=True)['status'], 'success')
        self.assertEqual(self.session.get.call_args_list[0].kwargs['headers']['If-None-Match'], '"latest"')
        self.assertEqual(self.session.get.call_args_list[1].kwargs['headers']['If-None-Match'], '"recent"')
        self.assertEqual(self.store.snapshot('2.10.0', now=160)['comparison'], 'up_to_date')
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE release_checks SET latest_json='null' WHERE id=1")
        self.session.get.side_effect = [Response(status=304)]
        self.assertEqual(self.store.check(now=220, force=True)['error_code'], 'invalid_response')
        self.assertNotIn('If-None-Match', self.session.get.call_args.kwargs['headers'])

    def test_rate_limit_cooldown_cannot_be_bypassed_manually_or_after_restart(self):
        self.session.get.side_effect = [Response(status=403, headers={'X-RateLimit-Remaining': '0', 'X-RateLimit-Reset': '4000'})]
        result = self.store.check(now=100)
        self.assertEqual(updates.job_result(result), ('failed', 'Release check rate limited'))
        self.assertEqual(result['error_code'], 'rate_limited')
        restarted = updates.Store(self.path, initialize=False)
        self.assertFalse(restarted.due(now=3999, force=True))
        self.assertFalse(restarted.snapshot('2.9.0', now=3999)['can_check'])
        self.assertTrue(restarted.due(now=4000, force=True))
        self.session.get.reset_mock()
        self.assertEqual(restarted.check(now=2000, force=True)['status'], 'waiting')
        self.session.get.assert_not_called()

    def test_retry_after_headers_are_bounded_and_failed_checks_back_off(self):
        self.session.get.side_effect = [Response(status=429, headers={'Retry-After': '9999999999'})]
        self.store.check(now=100)
        self.assertEqual(self.row()['rate_limit_until'], 86500)
        self.assertLessEqual(self.store.snapshot('2.9.0', now=100)['retry_after_seconds'], 86400)
        self.session.get.side_effect = requests.ConnectionError('offline')
        self.store.check(now=86500)
        first = self.row()['next_attempt']
        self.store.check(now=first)
        self.assertGreater(self.row()['next_attempt'] - first, first - 86500)
        self.assertLessEqual(self.row()['next_attempt'] - first, updates.CHECK_INTERVAL)

    def test_redirect_missing_release_and_malformed_latest_fail_without_partial_cache(self):
        cases = [Response(status=302, headers={'Location': 'https://outside.example'}), Response(status=404),
                 Response(release('2.10.0-rc1')), Response(release(draft=True)), Response(release(prerelease=True)),
                 Response(release(published_at=None)), Response(release(published_at='2026-10-11T12:00:00')),
                 Response(release(name={'secret': 'DO-NOT-RECORD'})), Response([]), Response(release(draft=0)),
                 Response(chunks=[b'{"draft":false,"draft":true}']), Response(chunks=[b'not JSON']),
                 Response(chunks=[b'[' * 2000 + b']' * 2000])]
        for index, response in enumerate(cases):
            with self.subTest(index=index):
                store = updates.Store(Path(self.directory.name) / f'invalid-{index}.sqlite3')
                self.session.get.side_effect = [response]
                self.assertEqual(store.check(now=100)['status'], 'failed')
                snapshot = store.snapshot('2.9.0', now=100)
                self.assertIsNone(snapshot['latest_version'])
                self.assertEqual(snapshot['comparison'], 'unknown')
                self.assertNotIn('DO-NOT-RECORD', str(snapshot))

    def test_response_limits_and_deadline_stop_unsafe_reads(self):
        for response in (Response(headers={'Content-Length': str(updates.MAX_BODY + 1)}),
                         Response(headers={'Content-Length': '9' * 5000}),
                         Response(headers={'Content-Length': '\u00b2'}),
                         Response(chunks=[b'x' * (updates.MAX_BODY + 1)]),
                         Response(release(), headers={'Content-Encoding': 'gzip'})):
            with self.subTest(response=response):
                self.session.get.side_effect = [response]
                self.assertEqual(self.store.check(now=100, force=True)['error_code'], 'invalid_response')
                with sqlite3.connect(self.path) as db:
                    db.execute('UPDATE release_checks SET last_attempt=NULL,next_attempt=0')
        self.session.get.side_effect = [Response(release())]
        with patch.object(updates.time, 'monotonic', side_effect=[0, 0, 0, updates.REQUEST_BUDGET + 1]):
            self.assertEqual(self.store.check(now=100, force=True)['error_code'], 'github_unavailable')

    def test_expired_future_and_interrupted_observations_never_claim_up_to_date(self):
        self.store.check(now=100)
        for now in (99, 21701):
            with self.subTest(now=now):
                snapshot = self.store.snapshot('2.10.0', now=now)
                self.assertEqual(snapshot['comparison'], 'unknown')
                self.assertTrue(snapshot['stale'])
        with sqlite3.connect(self.path) as db:
            db.execute('UPDATE release_checks SET last_attempt=160 WHERE id=1')
        snapshot = self.store.snapshot('2.10.0', now=220)
        self.assertEqual(snapshot['error_code'], 'check_interrupted')
        self.assertEqual(snapshot['comparison'], 'unknown')

    def test_interrupted_reservations_are_detected_after_any_prior_outcome(self):
        for prior in ('never', 'failed', 'rate_limited', 'success'):
            with self.subTest(prior=prior):
                with sqlite3.connect(self.path) as db:
                    db.execute('''UPDATE release_checks SET outcome=?,last_attempt=NULL,last_success=NULL,
                                  next_attempt=0,rate_limit_until=0''', (prior,))
                self.session.get.side_effect = KeyboardInterrupt
                with self.assertRaises(KeyboardInterrupt):
                    self.store.check(now=100)
                snapshot = self.store.snapshot('2.10.0', now=200)
                self.assertEqual(snapshot['status'], 'failed')
                self.assertEqual(snapshot['error_code'], 'check_interrupted')
                self.assertEqual(snapshot['comparison'], 'unknown')
        self.session.get.side_effect = requests.ConnectionError('offline')
        self.store.check(now=1000)
        self.assertEqual(self.store.snapshot('2.10.0', now=1100)['error_code'], 'github_unavailable')
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE release_checks SET outcome='checking',last_attempt=NULL")
        snapshot = self.store.snapshot('2.10.0', now=1100)
        self.assertEqual(snapshot['status'], 'failed')
        self.assertEqual(snapshot['error_code'], 'check_interrupted')

    def test_cached_metadata_is_sanitized_and_corruption_can_be_refreshed(self):
        self.store.check(now=100)
        with sqlite3.connect(self.path) as db:
            latest = json.loads(self.row()['latest_json'])
            latest.update(url='https://private.example/token', private='DO-NOT-RECORD')
            db.execute('UPDATE release_checks SET latest_json=?', (json.dumps(latest),))
        snapshot = self.store.snapshot('2.9.0', now=100)
        self.assertNotIn('private.example', str(snapshot))
        self.assertNotIn('DO-NOT-RECORD', str(snapshot))
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE release_checks SET recent_json='not JSON'")
        self.assertEqual(self.store.snapshot('2.9.0', now=100)['error_code'], 'invalid_cache')
        self.succeed()
        self.assertEqual(self.store.check(now=160, force=True)['status'], 'success')
        self.assertNotIn('If-None-Match', self.session.get.call_args_list[-1].kwargs['headers'])

    def test_job_result_never_treats_unknown_or_unsuccessful_results_as_success(self):
        for result in (None, {}, {'status': 'failed'}, {'status': 'private error'}):
            self.assertEqual(updates.job_result(result), ('failed', 'Release check unavailable'))
        self.assertEqual(updates.job_result({'status': 'waiting'}), ('waiting', 'Waiting for the next release check'))


if __name__ == '__main__':
    unittest.main()
