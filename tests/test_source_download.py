import errno
import io
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import unittest
from unittest.mock import patch
import urllib.error

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import source_download


class SourceDownloadTests(unittest.TestCase):
    def fetch(self):
        return source_download.download('https://example.org/source.tar.gz', maximum=8, timeout=60)

    def test_connection_reset_then_success_keeps_same_source_and_bound(self):
        failure = urllib.error.URLError(ConnectionResetError(errno.ECONNRESET, 'reset'))
        with patch.object(source_download.urllib.request, 'urlopen', side_effect=[failure, io.BytesIO(b'source')]) as opener, patch.object(source_download.time, 'sleep') as sleep:
            self.assertEqual(self.fetch(), b'source')
            self.assertEqual(opener.call_count, 2)
            self.assertTrue(all(call.args == ('https://example.org/source.tar.gz',) for call in opener.call_args_list))
            sleep.assert_called_once_with(1)

    def test_transient_failure_is_bounded_to_three_attempts(self):
        failure = urllib.error.URLError(OSError(errno.ENETUNREACH, 'unreachable'))
        with patch.object(source_download.urllib.request, 'urlopen', side_effect=failure) as opener, patch.object(source_download.time, 'sleep') as sleep, patch.object(source_download.shutil, 'which', return_value=None):
            with self.assertRaises(urllib.error.URLError):
                self.fetch()
            self.assertEqual(opener.call_count, 3)
            self.assertEqual([call.args for call in sleep.call_args_list], [(1,), (2,)])

    def test_http_permanent_and_certificate_errors_fail_immediately(self):
        errors = [urllib.error.HTTPError('https://example.org', 404, 'missing', {}, None),
                  urllib.error.HTTPError('https://example.org', 403, 'forbidden', {}, None),
                  urllib.error.URLError(ssl.SSLCertVerificationError('bad certificate')),
                  urllib.error.URLError(socket.gaierror(socket.EAI_NONAME, 'unknown host'))]
        for error in errors:
            with self.subTest(error=error), patch.object(source_download.urllib.request, 'urlopen', side_effect=error) as opener, patch.object(source_download.time, 'sleep') as sleep:
                with self.assertRaises(type(error)):
                    self.fetch()
                self.assertEqual(opener.call_count, 1)
                sleep.assert_not_called()

    def test_http_service_unavailable_then_success(self):
        error = urllib.error.HTTPError('https://example.org', 503, 'unavailable', {}, None)
        with patch.object(source_download.urllib.request, 'urlopen', side_effect=[error, io.BytesIO(b'bytes')]), patch.object(source_download.time, 'sleep'):
            self.assertEqual(self.fetch(), b'bytes')

    def test_size_limit_is_enforced_without_retry(self):
        with patch.object(source_download.urllib.request, 'urlopen', return_value=io.BytesIO(b'too large')) as opener, patch.object(source_download.time, 'sleep') as sleep:
            with self.assertRaisesRegex(ValueError, 'size limit'):
                self.fetch()
            self.assertEqual(opener.call_count, 1)
            sleep.assert_not_called()

    def test_http_source_is_rejected_before_network(self):
        with patch.object(source_download.urllib.request, 'urlopen') as opener:
            with self.assertRaisesRegex(ValueError, 'HTTPS'):
                source_download.download('http://example.org/source', maximum=8, timeout=60)
            opener.assert_not_called()

    def test_exhausted_transport_uses_one_recovery_with_identical_source_and_limits(self):
        failure = urllib.error.URLError(OSError(errno.ENETUNREACH, 'unreachable'))
        with patch.object(source_download.urllib.request, 'urlopen', side_effect=failure) as opener, patch.object(source_download.time, 'sleep'), patch.object(source_download.shutil, 'which', return_value='/usr/bin/curl'), patch.object(source_download, 'download_ipv4', return_value=b'source') as recovery:
            self.assertEqual(self.fetch(), b'source')
            self.assertEqual(opener.call_count, 3)
            recovery.assert_called_once_with('/usr/bin/curl', 'https://example.org/source.tar.gz', maximum=8, timeout=60)

    def test_http_and_certificate_errors_never_use_transport_recovery(self):
        errors = [urllib.error.HTTPError('https://example.org', 503, 'unavailable', {}, None),
                  urllib.error.HTTPError('https://example.org', 403, 'forbidden', {}, None),
                  urllib.error.URLError(ssl.SSLCertVerificationError('bad certificate'))]
        for error in errors:
            with self.subTest(error=error), patch.object(source_download.urllib.request, 'urlopen', side_effect=error), patch.object(source_download.time, 'sleep'), patch.object(source_download, 'download_ipv4') as recovery:
                with self.assertRaises(type(error)):
                    self.fetch()
                recovery.assert_not_called()

    def test_failed_recovery_does_not_restart_retry_loop(self):
        failure = urllib.error.URLError(OSError(errno.ENETUNREACH, 'unreachable'))
        with patch.object(source_download.urllib.request, 'urlopen', side_effect=failure) as opener, patch.object(source_download.time, 'sleep'), patch.object(source_download.shutil, 'which', return_value='/usr/bin/curl'), patch.object(source_download, 'download_ipv4', side_effect=failure) as recovery:
            with self.assertRaises(urllib.error.URLError):
                self.fetch()
            self.assertEqual(opener.call_count, 3)
            self.assertEqual(recovery.call_count, 1)

    def recover(self):
        return source_download.download_ipv4('/usr/bin/curl', 'https://example.org/source.tar.gz', maximum=8, timeout=60)

    def curl_result(self, body=b'source', returncode=0):
        def run(args, **kwargs):
            if '--version' in args:
                return subprocess.CompletedProcess(args, 0, 'curl 8.4.0 test', '')
            Path(args[args.index('--output') + 1]).write_bytes(body)
            return subprocess.CompletedProcess(args, returncode, b'', b'')
        return run

    def test_recovery_disables_configuration_and_bounds_https_ipv4_transfer(self):
        with patch.object(source_download.subprocess, 'run', side_effect=self.curl_result()) as runner:
            self.assertEqual(self.recover(), b'source')
        self.assertEqual(runner.call_count, 2)
        args = runner.call_args.args[0]
        self.assertEqual(args[:2], ['/usr/bin/curl', '--disable'])
        self.assertIn('--ipv4', args)
        self.assertIn('--fail', args)
        self.assertNotIn('--insecure', args)
        for option, value in {'--proto': '=https', '--proto-redir': '=https', '--max-redirs': '10', '--max-filesize': '8', '--connect-timeout': '60', '--max-time': '60', '--url': 'https://example.org/source.tar.gz'}.items():
            self.assertEqual(args[args.index(option) + 1], value)
        self.assertEqual(runner.call_args.kwargs['timeout'], 70)
        self.assertFalse(Path(args[args.index('--output') + 1]).exists())

    def test_recovery_requires_curl_with_streaming_size_enforcement(self):
        for version in ['curl 8.3.0 test', 'unexpected version']:
            with self.subTest(version=version), patch.object(source_download.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, version, '')) as runner:
                with self.assertRaisesRegex(ValueError, '8.4'):
                    self.recover()
                self.assertEqual(runner.call_count, 1)

    def test_recovery_rechecks_size_and_refuses_curl_transfer_failures(self):
        cases = [(b'oversized', 0, ValueError), (b'', 63, ValueError), (b'', 22, urllib.error.URLError), (b'partial', 28, urllib.error.URLError), (b'', 60, urllib.error.URLError)]
        for body, code, error in cases:
            with self.subTest(code=code, body=body), patch.object(source_download.subprocess, 'run', side_effect=self.curl_result(body, code)) as runner:
                with self.assertRaises(error):
                    self.recover()
                self.assertEqual(runner.call_count, 2)

    def test_recovery_process_timeout_blocks_source_acquisition(self):
        version = subprocess.CompletedProcess([], 0, 'curl 8.4.0 test', '')
        with patch.object(source_download.subprocess, 'run', side_effect=[version, subprocess.TimeoutExpired('curl', 70)]):
            with self.assertRaises(subprocess.TimeoutExpired):
                self.recover()


if __name__ == '__main__':
    unittest.main()
