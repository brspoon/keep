"""Install the reviewed build pip without running an older network client.

The interpreter needs a working system CA store before this helper runs.
Only the pinned, checksum-verified wheel supplies the installation code.
"""
import argparse
import hashlib
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request


PIP_VERSION = '26.2.2'
WHEEL_NAME = 'pip-' + PIP_VERSION + '-py3-none-any.whl'
WHEEL_URL = ('https://files.pythonhosted.org/packages/3f/06/'
             '3e4420302363fbb71be3c7f35ce042f54bfca330e3e66b3a2e3c4cca579f/'
             + WHEEL_NAME)
WHEEL_SHA256 = 'fd7f4dfa8190e014013b9f08f3e973f4e4c26ffd179a204895533a7254813a70'
MAXIMUM_WHEEL_BYTES = 4 * 1024 * 1024
DOWNLOAD_TIMEOUT = 60
INSTALL_TIMEOUT = 120
INSTALL_CODE = (
    "import runpy,sys; wheel=sys.argv.pop(1); sys.path.insert(0,wheel); "
    "runpy.run_module('pip',run_name='__main__')"
)
VERIFY_CODE = (
    "import importlib.metadata,pip\n"
    "expected=" + repr(PIP_VERSION) + "\n"
    "if pip.__version__ != expected or importlib.metadata.version('pip') != expected:\n"
    "    raise SystemExit('Installed pip does not match verified bootstrap version ' + expected)\n"
)


class HTTPSRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, newurl):
        if urllib.parse.urlsplit(newurl).scheme != 'https':
            raise ValueError('pip wheel redirects require HTTPS')
        return super().redirect_request(request, response, code, message, headers, newurl)


def download_wheel():
    """Fetch a size-limited wheel with normal TLS verification, then check it."""
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        HTTPSRedirectHandler(),
    )
    with opener.open(WHEEL_URL, timeout=DOWNLOAD_TIMEOUT) as response:
        length = response.headers.get('Content-Length')
        if length is not None:
            try:
                length = int(length)
            except ValueError as error:
                raise ValueError('Invalid pip wheel download length') from error
            if length < 0 or length > MAXIMUM_WHEEL_BYTES:
                raise ValueError('pip wheel download exceeds size limit')
        body = response.read(MAXIMUM_WHEEL_BYTES + 1)
    if len(body) > MAXIMUM_WHEEL_BYTES:
        raise ValueError('pip wheel download exceeds size limit')
    if length is not None and len(body) != length:
        raise ValueError('Truncated pip wheel download')
    if hashlib.sha256(body).hexdigest() != WHEEL_SHA256:
        raise ValueError('pip wheel checksum mismatch')
    return body


def bootstrap(python=None):
    """Install the fixed pip in the chosen interpreter, including an empty venv."""
    python = str(python or sys.executable)
    body = download_wheel()
    with tempfile.TemporaryDirectory(prefix='keep-build-pip-') as temporary:
        wheel = Path(temporary) / WHEEL_NAME
        with wheel.open('xb') as stream:
            stream.write(body)
        subprocess.run([
            python, '-I', '-c', INSTALL_CODE, str(wheel),
            '--isolated', '--disable-pip-version-check', 'install',
            '--no-index', '--no-deps', '--no-compile', '--force-reinstall', str(wheel),
        ], check=True, timeout=INSTALL_TIMEOUT)
        subprocess.run([python, '-I', '-c', VERIFY_CODE], check=True, timeout=30)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--python', default=sys.executable,
                        help='interpreter receiving the verified build pip')
    args = parser.parse_args(argv)
    bootstrap(args.python)


if __name__ == '__main__':
    main()
