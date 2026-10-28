"""Offline response-framing controls for the loaded stdlib and Requests paths."""
import hashlib
import http.client
import io
from pathlib import Path

import requests
import urllib3
from urllib3.exceptions import InvalidHeader


class MemorySocket:
    def __init__(self, wire):
        self.file = io.BytesIO(wire)

    def makefile(self, *args, **kwargs):
        return self.file


def response(headers, body=b'', method='GET', status=200, client=http.client):
    sock = MemorySocket(b'HTTP/1.1 ' + str(status).encode() + b' Test\r\n'
                        + headers + b'\r\n\r\n' + body)
    result = client.HTTPResponse(sock, method=method)
    result.begin()
    return result, sock


def requests_response(raw):
    wrapped = requests.Response()
    wrapped.status_code = 200
    wrapped.raw = urllib3.response.HTTPResponse(
        raw, headers=dict(raw.headers), original_response=raw,
        preload_content=False, decode_content=False)
    return wrapped


def check_framing(case, client=http.client):
    """Use real parsers and Requests iteration, with synthetic in-memory I/O."""
    bad_lengths = ('+5', '5_0', '-5', '5 0', '\xb2', '5\x85', '5\xa0', '5\v', '5\f', '1' * 5000)
    for value in bad_lengths:
        with case.subTest(length=value):
            raw, _ = response(b'Content-Length: ' + value.encode('latin1'), client=client)
            case.assertIsNone(raw.length)
            raw.close()
            wrapped = urllib3.response.HTTPResponse(
                io.BytesIO(), headers={'content-length': value}, preload_content=False)
            case.assertIsNone(wrapped.length_remaining)
            wrapped.close()
    for value in ('0', '5', ' 5 ', '\t5\t', '5 \t '):
        length = int(value)
        with case.subTest(valid_length=value):
            raw, _ = response(b'Content-Length: ' + value.encode(), b'HELLO'[:length], client=client)
            case.assertEqual(raw.length, length)
            case.assertEqual(raw.read(), b'HELLO'[:length])
            case.assertTrue(raw.isclosed())
            raw, _ = response(b'Content-Length: ' + value.encode(), b'HELLO'[:length])
            case.assertEqual(requests_response(raw).content, b'HELLO'[:length])
    for method, status in (('HEAD', 200), ('GET', 204), ('GET', 304)):
        raw, _ = response(b'Content-Length: 5', method=method, status=status, client=client)
        case.assertEqual(raw.length, 0)
        case.assertEqual(raw.read(), b'')
    for value in ('5, 5', ' 5 ,\t5\t'):
        raw = urllib3.response.HTTPResponse(io.BytesIO(b'HELLO'),
            headers={'content-length': value}, preload_content=False)
        case.assertEqual(raw.length_remaining, 5)
        case.assertEqual(raw.read(), b'HELLO')
    with case.assertRaises(InvalidHeader):
        urllib3.response.HTTPResponse(io.BytesIO(),
            headers={'content-length': '5, 6'}, preload_content=False)
    invalid = (b'-5', b'+5', b'0x5', b'1_f', b' 5', b'\t5', b'\xb2', b'5\v', b'5\f')
    for size in invalid:
        for streaming in (False, True):
            with case.subTest(chunk=size, streaming=streaming):
                wire = size + b'\r\nHELLO\r\n0\r\n\r\n'
                raw, sock = response(b'Transfer-Encoding: chunked', wire, client=client)
                with case.assertRaises(client.IncompleteRead):
                    raw.read()
                case.assertTrue(raw.isclosed())
                case.assertTrue(sock.file.closed)
                raw, sock = response(b'Transfer-Encoding: chunked', wire)
                wrapped = requests_response(raw)
                with case.assertRaises(requests.exceptions.ChunkedEncodingError):
                    if streaming:
                        list(wrapped.iter_content(chunk_size=2))
                    else:
                        _ = wrapped.content
                case.assertTrue(raw.isclosed())
                case.assertTrue(sock.file.closed)
                case.assertTrue(wrapped.raw.closed)
    for size, data in ((b'5', b'HELLO'), (b'5;name=value', b'HELLO'),
                       (b'5 \t;name=value', b'HELLO'), (b'a', b'0123456789'),
                       (b'A', b'0123456789'), (b'10000', b'x' * 65536)):
        wire = size + b'\r\n' + data + b'\r\n0\r\nX-Trailer: yes\r\n\r\n'
        raw, _ = response(b'Transfer-Encoding: chunked', wire, client=client)
        case.assertEqual(raw.read(), data)
        raw, _ = response(b'Transfer-Encoding: chunked', wire)
        case.assertEqual(b''.join(requests_response(raw).iter_content(13)), data)
    for wire in (b'5\r\nabc', b'1' * (client._MAXLINE + 1) + b'\r\n'):
        raw, _ = response(b'Transfer-Encoding: chunked', wire, client=client)
        with case.assertRaises((client.IncompleteRead, client.LineTooLong)):
            raw.read()
        raw.close()
        raw, sock = response(b'Transfer-Encoding: chunked', wire)
        with case.assertRaises(requests.exceptions.ChunkedEncodingError):
            _ = requests_response(raw).content
        case.assertTrue(sock.file.closed)


def verify_sources(lock):
    paths = {'http.client': Path(http.client.__file__),
             'urllib3.response': Path(urllib3.response.__file__)}
    if urllib3.__version__ != '2.8.0':
        raise ValueError('Unreviewed urllib3 runtime version')
    records = {}
    for name, path in paths.items():
        if path.is_symlink() or not path.is_file():
            raise ValueError('HTTP parser source must be a regular file')
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != lock[name]['after_sha256']:
            raise ValueError('Loaded HTTP parser differs from reviewed source: ' + name)
        records[name] = {'path': str(path), 'sha256': digest}
    return records
