import json
import unittest
from unittest.mock import Mock, patch

import requests
import pushover


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


class PushoverTests(unittest.TestCase):
    def setUp(self):
        # Deliberately synthetic format fixtures, never live credentials.
        self.token, self.user = 'A' * 30, 'B' * 30
        self.session = Mock()
        self.session.__enter__ = Mock(return_value=self.session)
        self.session.__exit__ = Mock(return_value=False)
        self.factory = patch.object(pushover.requests, 'Session', return_value=self.session).start()
        self.addCleanup(patch.stopall)
        self.session.post.return_value = Response({'status': 1, 'request': '12345678-1234-1234-1234-123456789012'})

    def send(self, **kwargs):
        return pushover.send(self.token, self.user, 'One title leaving soon.', now=100, **kwargs)

    def test_acceptance_is_safe_fixed_https_normal_priority_without_credentials_in_result(self):
        result = self.send(device='iphone', url='https://keep.example/leaving')
        self.assertEqual(result.state, 'accepted')
        self.assertEqual(result.request_id, '12345678-1234-1234-1234-123456789012')
        self.assertNotIn(self.token, str(result))
        self.assertNotIn(self.user, str(result))
        call = self.session.post.call_args
        self.assertEqual(call.args, (pushover.MESSAGE_URL,))
        self.assertEqual(call.kwargs['data']['priority'], 0)
        self.assertEqual(call.kwargs['data']['device'], 'iphone')
        self.assertFalse(call.kwargs['allow_redirects'])
        self.assertTrue(call.kwargs['stream'])
        self.assertFalse(self.session.trust_env)
        self.assertNotIn('Authorization', call.kwargs['headers'])
        self.assertEqual(self.session.post.call_count, 1)

    def test_configuration_bounds_fail_before_network(self):
        for kwargs in ({'token': 'bad'}, {'device': 'x' * 26}, {'message': 'x' * 1025},
                       {'title': 'x' * 251}, {'url': 'javascript:alert(1)'},
                       {'url': 'https://user:password@keep.example/'}, {'url': 'https://keep.example/\nsecret'}):
            with self.subTest(kwargs=kwargs):
                values = {'token': self.token, 'user': self.user, 'message': 'Hello', **kwargs}
                self.assertEqual(pushover.send(**values).code, 'configuration')
        self.factory.assert_not_called()

    def test_definite_rejection_and_quota_never_automatically_repeat_post(self):
        for response in (Response({'status': 0, 'errors': [self.user]}, status=400),
                         Response({'status': 0, 'errors': [self.token]})):
            self.session.post.return_value = response
            result = self.send()
            self.assertEqual(result, pushover.Result('rejected', 'rejected'))
            self.assertNotIn(self.user, str(result))
            self.assertNotIn(self.token, str(result))
        self.session.post.return_value = Response(status=429, headers={'X-Limit-App-Reset': '4000'})
        self.assertEqual(self.send(), pushover.Result('retry', 'quota', retry_at=4000))
        self.assertEqual(self.session.post.call_count, 3)

    def test_only_connect_timeout_is_safe_to_retry_and_all_ambiguous_failures_need_review(self):
        for error in (requests.ReadTimeout('secret token=' + self.token),
                      requests.ConnectionError('connection lost after submission'),
                      requests.Timeout('unknown phase')):
            self.session.post.side_effect = error
            self.assertEqual(self.send(), pushover.Result('review', 'response_uncertain'))
        self.session.post.side_effect = requests.ConnectTimeout('connection not established')
        self.assertEqual(self.send(), pushover.Result('retry', 'connect_failed', retry_at=160))
        self.assertEqual(self.session.post.call_count, 4)

    def test_unusable_responses_are_uncertain_and_never_follow_redirects(self):
        responses = (Response(status=302, headers={'Location': 'https://outside.example'}),
                     Response(status=500), Response(chunks=[b'not json']), Response({'status': True}),
                     Response(chunks=[b'{"status":1,"status":0}']),
                     Response(chunks=[b'[' * 2000 + b']' * 2000]),
                     Response(headers={'Content-Length': str(pushover.MAX_RESPONSE + 1)}),
                     Response(chunks=[b'x' * (pushover.MAX_RESPONSE + 1)]),
                     Response(headers={'Content-Encoding': 'gzip'}))
        for response in responses:
            with self.subTest(status=response.status_code):
                self.session.post.return_value = response
                self.assertEqual(self.send(), pushover.Result('review', 'response_uncertain'))
        self.assertEqual(self.session.post.call_count, len(responses))

    def test_deadline_and_quota_reset_are_bounded(self):
        with patch.object(pushover.time, 'monotonic', side_effect=[0, pushover.REQUEST_BUDGET + 1]):
            self.assertEqual(self.send().state, 'review')
        self.session.post.return_value = Response(status=429, headers={'X-Limit-App-Reset': '999999999999'})
        self.assertEqual(self.send().retry_at, 100 + 32 * 86400)

    def test_validation_uses_fixed_endpoint_and_returns_no_device_or_license_details(self):
        self.session.post.return_value = Response({'status': 1, 'devices': ['private-device'], 'licenses': ['iOS']})
        result = pushover.validate(self.token, self.user, device='iphone', now=100)
        self.assertEqual(result.state, 'accepted')
        self.assertEqual(self.session.post.call_args.args, (pushover.VALIDATE_URL,))
        self.assertNotIn('private-device', str(result))

    def test_request_identifier_rejects_a_secret_or_arbitrary_remote_text(self):
        self.session.post.return_value = Response({'status': 1, 'request': self.token})
        result = self.send()
        self.assertEqual(result.state, 'accepted')
        self.assertIsNone(result.request_id)
        self.assertNotIn(self.token, str(result))

    def test_digest_is_compact_plain_text_and_bounded_without_losing_the_total(self):
        items = [{'title': 'Long ' * 80, 'year': 2026, 'urgent': index < 2} for index in range(100)]
        message = pushover.digest_message(items)
        self.assertLessEqual(len(message), 1024)
        self.assertIn('100 titles', message)
        self.assertIn('2 within seven days', message)
        self.assertIn('more. Open Keep', message)
        self.assertNotIn('html', message)


if __name__ == '__main__':
    unittest.main()
