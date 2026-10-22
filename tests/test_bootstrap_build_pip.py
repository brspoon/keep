"""Build pip executes only from the verified wheel and installs offline."""
import hashlib
import io
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
import urllib.request
import venv
import zipfile

from scripts import bootstrap_build_pip as bootstrap


class Response(io.BytesIO):
    def __init__(self, body, length=None):
        super().__init__(body)
        self.headers = {} if length is None else {'Content-Length': str(length)}
        self.read_limits = []

    def read(self, maximum=-1):
        self.read_limits.append(maximum)
        return super().read(maximum)


def fixture_wheel():
    """A minimal offline installer exercising zipimport in a real target venv."""
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w') as wheel:
        wheel.writestr('pip/__init__.py', "__version__ = '26.2.2'\n")
        wheel.writestr('pip/__main__.py', '''import json
from pathlib import Path
import sys
import sysconfig
import zipfile

target = Path(sysconfig.get_path('purelib'))
package = target / 'pip'
package.mkdir(exist_ok=True)
with zipfile.ZipFile(sys.argv[-1]) as wheel:
    (package / '__init__.py').write_bytes(wheel.read('pip/__init__.py'))
metadata = target / 'pip-26.2.2.dist-info'
metadata.mkdir(exist_ok=True)
(metadata / 'METADATA').write_text('Name: pip\\nVersion: 26.2.2\\n')
(package / 'bootstrap.json').write_text(json.dumps({
    'python': sys.executable, 'isolated': sys.flags.isolated,
    'args': sys.argv[1:], 'source': __file__,
}))
''')
    return output.getvalue()


class BuildPipBootstrapTests(unittest.TestCase):
    def fetch(self, body, length=None):
        response = Response(body, length)
        opener = Mock()
        opener.open.return_value = response
        return response, opener

    def test_reviewed_wheel_is_exactly_pinned(self):
        self.assertEqual(bootstrap.PIP_VERSION, '26.2.2')
        self.assertEqual(bootstrap.WHEEL_URL,
            'https://files.pythonhosted.org/packages/3f/06/'
            '3e4420302363fbb71be3c7f35ce042f54bfca330e3e66b3a2e3c4cca579f/'
            'pip-26.2.2-py3-none-any.whl')
        self.assertEqual(bootstrap.WHEEL_SHA256,
            'fd7f4dfa8190e014013b9f08f3e973f4e4c26ffd179a204895533a7254813a70')

    def test_tampered_wheel_never_executes(self):
        _, opener = self.fetch(b'tampered wheel')
        with patch.object(bootstrap.urllib.request, 'build_opener', return_value=opener), \
                patch.object(bootstrap.subprocess, 'run') as run, \
                patch.object(bootstrap.tempfile, 'TemporaryDirectory') as temporary:
            with self.assertRaisesRegex(ValueError, 'checksum mismatch'):
                bootstrap.bootstrap('target-python')
        run.assert_not_called()
        temporary.assert_not_called()

    def test_download_uses_verified_tls_timeout_and_bounded_read(self):
        body = b'verified test wheel'
        response, opener = self.fetch(body, len(body))
        with patch.object(bootstrap.urllib.request, 'build_opener', return_value=opener) as build, \
                patch.object(bootstrap, 'WHEEL_SHA256', hashlib.sha256(body).hexdigest()):
            self.assertEqual(bootstrap.download_wheel(), body)
        opener.open.assert_called_once_with(bootstrap.WHEEL_URL, timeout=bootstrap.DOWNLOAD_TIMEOUT)
        self.assertEqual(response.read_limits, [bootstrap.MAXIMUM_WHEEL_BYTES + 1])
        handler = build.call_args.args[0]
        self.assertIsInstance(handler, urllib.request.HTTPSHandler)
        self.assertEqual(handler._context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(handler._context.check_hostname)

    def test_download_rejects_oversized_and_truncated_bodies_before_execution(self):
        for body, length, message in (
                (b'12345', None, 'size limit'),
                (b'123', 5, 'size limit'),
                (b'12', 3, 'Truncated'),
                (b'12', 'invalid', 'Invalid')):
            with self.subTest(body=body, length=length):
                _, opener = self.fetch(body, length)
                with patch.object(bootstrap.urllib.request, 'build_opener', return_value=opener), \
                        patch.object(bootstrap, 'MAXIMUM_WHEEL_BYTES', 4), \
                        patch.object(bootstrap.subprocess, 'run') as run:
                    with self.assertRaisesRegex(ValueError, message):
                        bootstrap.bootstrap()
                run.assert_not_called()

    def test_http_redirect_is_rejected(self):
        request = urllib.request.Request(bootstrap.WHEEL_URL)
        with self.assertRaisesRegex(ValueError, 'require HTTPS'):
            bootstrap.HTTPSRedirectHandler().redirect_request(
                request, None, 302, 'Found', {}, 'http://example.test/pip.whl')

    def test_timeout_and_certificate_failures_do_not_execute_or_retry(self):
        for error in (TimeoutError('timed out'), ssl.SSLCertVerificationError('untrusted')):
            with self.subTest(error=error):
                opener = Mock()
                opener.open.side_effect = error
                with patch.object(bootstrap.urllib.request, 'build_opener', return_value=opener), \
                        patch.object(bootstrap.subprocess, 'run') as run:
                    with self.assertRaises(type(error)):
                        bootstrap.bootstrap()
                self.assertEqual(opener.open.call_count, 1)
                run.assert_not_called()

    def test_install_is_isolated_offline_and_checks_target_version(self):
        body = b'verified test wheel'
        _, opener = self.fetch(body)
        wheel_paths = []

        def run(command, **kwargs):
            self.assertEqual(command[:3], ['chosen-python', '-I', '-c'])
            self.assertTrue(kwargs['check'])
            self.assertGreater(kwargs['timeout'], 0)
            if command[3] == bootstrap.INSTALL_CODE:
                wheel = Path(command[4])
                wheel_paths.append(wheel)
                self.assertEqual(wheel.read_bytes(), body)
                self.assertEqual(command[5:], [
                    '--isolated', '--disable-pip-version-check', 'install',
                    '--no-index', '--no-deps', '--no-compile', '--force-reinstall', str(wheel)])
            else:
                self.assertEqual(command[3], bootstrap.VERIFY_CODE)
            return subprocess.CompletedProcess(command, 0)

        with patch.object(bootstrap.urllib.request, 'build_opener', return_value=opener), \
                patch.object(bootstrap, 'WHEEL_SHA256', hashlib.sha256(body).hexdigest()), \
                patch.object(bootstrap.subprocess, 'run', side_effect=run) as execute:
            bootstrap.bootstrap('chosen-python')
        self.assertEqual(execute.call_count, 2)
        self.assertEqual(len(wheel_paths), 1)
        self.assertFalse(wheel_paths[0].parent.exists())

    def test_failed_install_cleans_verified_wheel(self):
        body = b'verified test wheel'
        _, opener = self.fetch(body)
        wheel_paths = []

        def fail(command, **kwargs):
            wheel_paths.append(Path(command[4]))
            raise subprocess.CalledProcessError(1, command)

        with patch.object(bootstrap.urllib.request, 'build_opener', return_value=opener), \
                patch.object(bootstrap, 'WHEEL_SHA256', hashlib.sha256(body).hexdigest()), \
                patch.object(bootstrap.subprocess, 'run', side_effect=fail) as execute:
            with self.assertRaises(subprocess.CalledProcessError):
                bootstrap.bootstrap()
        self.assertEqual(execute.call_count, 1)
        self.assertFalse(wheel_paths[0].parent.exists())

    def test_verified_wheel_runs_in_empty_and_existing_pip_interpreters(self):
        body = fixture_wheel()
        with tempfile.TemporaryDirectory(prefix='keep-bootstrap-test-') as temporary:
            for existing in (False, True):
                with self.subTest(existing_pip=existing):
                    root = Path(temporary) / str(existing)
                    venv.EnvBuilder(with_pip=False).create(root)
                    python = root / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python')
                    site = Path(subprocess.check_output([
                        str(python), '-I', '-c',
                        "import sysconfig; print(sysconfig.get_path('purelib'))",
                    ], text=True).strip())
                    subprocess.run([str(python), '-I', '-c',
                        "import importlib.util; assert importlib.util.find_spec('pip') is None"],
                        check=True)
                    if existing:
                        (site / 'pip').mkdir()
                        (site / 'pip/__init__.py').write_text(
                            "raise RuntimeError('Unverified existing pip executed')\n")
                    _, opener = self.fetch(body, len(body))
                    with patch.object(bootstrap.urllib.request, 'build_opener', return_value=opener), \
                            patch.object(bootstrap, 'WHEEL_SHA256', hashlib.sha256(body).hexdigest()):
                        bootstrap.bootstrap(python)
                    installed = json.loads((site / 'pip/bootstrap.json').read_text())
                    self.assertEqual(Path(installed['python']).resolve(), python.resolve())
                    self.assertEqual(installed['isolated'], 1)
                    self.assertIn('--no-index', installed['args'])
                    self.assertIn('--no-deps', installed['args'])
                    wheel = Path(installed['args'][-1])
                    self.assertTrue(installed['source'].startswith(str(wheel)))
                    self.assertFalse(wheel.parent.exists())

    def test_installed_version_mismatch_fails(self):
        with tempfile.TemporaryDirectory(prefix='keep-bootstrap-version-') as temporary:
            root = Path(temporary)
            venv.EnvBuilder(with_pip=False).create(root)
            python = root / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python')
            site = Path(subprocess.check_output([
                str(python), '-I', '-c', "import sysconfig; print(sysconfig.get_path('purelib'))",
            ], text=True).strip())
            (site / 'pip').mkdir()
            (site / 'pip/__init__.py').write_text("__version__ = '26.2.1'\n")
            result = subprocess.run([str(python), '-I', '-c', bootstrap.VERIFY_CODE],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b'does not match verified bootstrap version', result.stderr)

    def test_cli_selects_interpreter(self):
        with patch.object(bootstrap, 'bootstrap') as install:
            bootstrap.main(['--python', 'selected-python'])
        install.assert_called_once_with('selected-python')


if __name__ == '__main__':
    unittest.main()
