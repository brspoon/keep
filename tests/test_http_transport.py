"""Real Requests/urllib3 decoding with in-memory upstream HTTP responses."""
import gzip
import http.client
import io
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch
import zlib

import requests
import urllib3
from service_discovery import read_service


class SocketFixture:
    def __init__(self, wire):
        self.wire = wire

    def makefile(self, *args, **kwargs):
        return io.BytesIO(self.wire)


def response(body, encoding=None, chunk_line=None):
    headers = b'Transfer-Encoding: chunked\r\n'
    if encoding:
        headers += b'Content-Encoding: ' + encoding.encode() + b'\r\n'
    line = chunk_line if chunk_line is not None else f'{len(body):x}'.encode()
    wire = b'HTTP/1.1 200 OK\r\n' + headers + b'\r\n' + line + b'\r\n' + body + b'\r\n0\r\n\r\n'
    upstream = http.client.HTTPResponse(SocketFixture(wire), method='GET')
    upstream.begin()
    result = requests.Response()
    result.status_code = 200
    result.raw = urllib3.HTTPResponse(body=upstream, headers=dict(upstream.headers),
                                     original_response=upstream, preload_content=False)
    return result


def read_trailing_deflate(raw=False):
    # Run this function in a child: old urllib3 can spin without socket I/O,
    # so a network read timeout cannot bound it.
    original = b'A' * 40000
    compressor = zlib.compressobj(wbits=-15 if raw else 15)
    body = compressor.compress(original) + compressor.flush() + b'tail'
    with patch('service_discovery.requests.get', return_value=response(body, 'deflate')):
        assert read_service('https://upstream.example') == original


class HTTPTransportTests(unittest.TestCase):
    def test_valid_chunked_and_compressed_responses(self):
        original = b'{"items":[]}' * 4000
        for encoding, body in ((None, original), ('deflate', zlib.compress(original)),
                               ('gzip', gzip.compress(original))):
            with self.subTest(encoding=encoding):
                with patch('service_discovery.requests.get', return_value=response(body, encoding)) as get:
                    self.assertEqual(read_service('https://upstream.example'), original)
                self.assertFalse(get.call_args.kwargs['allow_redirects'])
                self.assertEqual(get.call_args.kwargs['timeout'], (3, 8))

    def test_trailing_deflate_finishes_for_wrapped_and_raw_streams(self):
        for raw in (False, True):
            with self.subTest(raw=raw):
                result = subprocess.run(
                    [sys.executable, '-B', '-c',
                     f'import test_http_transport as t; t.read_trailing_deflate({raw!r})'],
                    cwd=Path(__file__).resolve().parent, capture_output=True, text=True,
                    timeout=5, env={**os.environ,
                                    'PYTHONPATH': str(Path(__file__).resolve().parents[1])})
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_oversized_chunk_line_rejected(self):
        for line in (b'1' * 70000, b'1;' + b'a' * 70000):
            with self.subTest(extension=line.startswith(b'1;')):
                with patch('service_discovery.requests.get', return_value=response(b'A', chunk_line=line)):
                    with self.assertRaises(requests.exceptions.ChunkedEncodingError) as error:
                        read_service('https://upstream.example')
                self.assertIn('chunk size line exceeded', str(error.exception))


if __name__ == '__main__':
    unittest.main()
