"""Bounded retries for transient public-source transport failures.

Identity and checksum validation remain the caller's responsibility. Permanent
HTTP, certificate and hash failures never trigger another source selection.
"""
import errno
from pathlib import Path
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request


def transient(error):
    if isinstance(error, urllib.error.HTTPError):
        return error.code in {408, 429, 500, 502, 503, 504}
    reason = error.reason if isinstance(error, urllib.error.URLError) else error
    if isinstance(reason, ssl.SSLError):
        return False
    if isinstance(reason, (TimeoutError, socket.timeout)):
        return True
    if isinstance(reason, socket.gaierror):
        return reason.errno == socket.EAI_AGAIN
    return isinstance(reason, OSError) and reason.errno in {
        errno.ECONNRESET, errno.ECONNABORTED, errno.ETIMEDOUT,
        errno.ENETUNREACH, errno.EHOSTUNREACH,
    }


def download_ipv4(curl, url, *, maximum, timeout):
    """Try the same HTTPS source once using a bounded IPv4-only transport."""
    version = subprocess.run([curl, '--disable', '--version'], check=True,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             text=True, timeout=10)
    match = re.match(r'curl (\d+)\.(\d+)\.(\d+)\b', version.stdout)
    if not match or tuple(map(int, match.groups())) < (8, 4, 0):
        raise ValueError('IPv4 source recovery requires curl 8.4 or newer for transfer size limits')
    with tempfile.TemporaryDirectory(prefix='keep-source-ipv4-') as directory:
        path = Path(directory) / 'source'
        result = subprocess.run([
            curl, '--disable', '--fail', '--silent', '--show-error', '--location',
            '--ipv4', '--proto', '=https', '--proto-redir', '=https',
            '--max-redirs', '10', '--connect-timeout', str(timeout),
            '--max-time', str(timeout), '--max-filesize', str(maximum),
            '--output', str(path), '--url', url,
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout + 10)
        if result.returncode == 63:
            raise ValueError('Source download exceeds size limit')
        if result.returncode:
            raise urllib.error.URLError('IPv4 source recovery failed (curl exit '
                                        + str(result.returncode) + ')')
        with path.open('rb') as source:
            body = source.read(maximum + 1)
        if len(body) > maximum:
            raise ValueError('Source download exceeds size limit')
        return body


def download(url, *, maximum, timeout):
    if urllib.parse.urlsplit(url).scheme != 'https':
        raise ValueError('Source downloads require HTTPS')
    for attempt in range(3):
        try:
            with urllib.request.urlopen(url, timeout=timeout) as response:
                body = response.read(maximum + 1)
            if len(body) > maximum:
                raise ValueError('Source download exceeds size limit')
            return body
        except (urllib.error.URLError, OSError) as error:
            if not transient(error):
                raise
            if attempt == 2:
                # HTTP responses already reached the server; another transport
                # must not rescue authentication or server-policy failures.
                curl = None if isinstance(error, urllib.error.HTTPError) else shutil.which('curl')
                if not curl:
                    raise
                print('Source transport recovery: one IPv4 attempt for '
                      + urllib.parse.urlsplit(url).hostname, file=sys.stderr, flush=True)
                return download_ipv4(curl, url, maximum=maximum, timeout=timeout)
            time.sleep(attempt + 1)
