"""One bounded, non-retrying Pushover API call with safe delivery outcomes."""
from dataclasses import dataclass
import json
import re
import time
from urllib.parse import urlsplit

import requests


MESSAGE_URL = 'https://api.pushover.net/1/messages.json'
VALIDATE_URL = 'https://api.pushover.net/1/users/validate.json'
MAX_RESPONSE = 65536
REQUEST_BUDGET = 15
KEY = re.compile(r'[A-Za-z0-9]{30}\Z')
DEVICE = re.compile(r'[A-Za-z0-9_-]{0,25}\Z')
REQUEST_ID = re.compile(r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\Z')
CODES = frozenset(('configuration', 'connect_failed', 'rejected', 'quota', 'response_uncertain'))


@dataclass(frozen=True)
class Result:
    state: str
    code: str | None = None
    request_id: str | None = None
    retry_at: float | None = None


def _configured(token, user, device):
    return (isinstance(token, str) and KEY.fullmatch(token)
            and isinstance(user, str) and KEY.fullmatch(user)
            and isinstance(device, str) and DEVICE.fullmatch(device))


def _url(value):
    if not value:
        return ''
    if not isinstance(value, str) or len(value) > 512 or any(ord(c) < 32 for c in value):
        return None
    try:
        parsed = urlsplit(value)
        return value if parsed.scheme in ('http', 'https') and parsed.hostname and not parsed.username and not parsed.password else None
    except ValueError:
        return None


def _unique_fields(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate field')
        result[key] = value
    return result


def _call(endpoint, data, *, now=None):
    now = time.time() if now is None else now
    deadline = time.monotonic() + REQUEST_BUDGET
    try:
        with requests.Session() as session:
            # Do not read proxy credentials or netrc; TLS verification stays on.
            session.trust_env = False
            with session.post(endpoint, data=data, timeout=(3, 5), stream=True,
                              allow_redirects=False, headers={'Accept': 'application/json',
                              'Accept-Encoding': 'identity'}) as response:
                status = response.status_code
                if status == 429:
                    reset = response.headers.get('X-Limit-App-Reset', '')
                    retry_at = int(reset) if isinstance(reset, str) and re.fullmatch(r'[0-9]{1,12}', reset) else now + 3600
                    return Result('retry', 'quota', retry_at=min(now + 32 * 86400, max(now + 60, retry_at)))
                if 400 <= status < 500:
                    return Result('rejected', 'rejected')
                # A POST can have succeeded when its response is unusable. Do not
                # automatically repeat redirects, 5xx, malformed JSON or timeouts.
                if status != 200 or time.monotonic() > deadline:
                    return Result('review', 'response_uncertain')
                if response.headers.get('Content-Encoding', 'identity').lower() != 'identity':
                    return Result('review', 'response_uncertain')
                length = response.headers.get('Content-Length', '')
                if length and (not isinstance(length, str) or not re.fullmatch(r'[0-9]{1,10}', length)
                               or int(length) > MAX_RESPONSE):
                    return Result('review', 'response_uncertain')
                body = bytearray()
                for chunk in response.iter_content(1):
                    body.extend(chunk)
                    if len(body) > MAX_RESPONSE or time.monotonic() > deadline:
                        return Result('review', 'response_uncertain')
                try:
                    payload = json.loads(body, object_pairs_hook=_unique_fields)
                except (ValueError, TypeError, RecursionError):
                    return Result('review', 'response_uncertain')
                if not isinstance(payload, dict) or type(payload.get('status')) is not int:
                    return Result('review', 'response_uncertain')
                if payload['status'] != 1:
                    return Result('rejected', 'rejected')
                request_id = payload.get('request')
                if not isinstance(request_id, str) or not REQUEST_ID.fullmatch(request_id):
                    request_id = None
                # Acceptance by Pushover is not evidence of display on a device.
                return Result('accepted', request_id=request_id)
    except requests.ConnectTimeout:
        # The connection was not established; the message was not submitted.
        return Result('retry', 'connect_failed', retry_at=now + 60)
    except requests.RequestException:
        return Result('review', 'response_uncertain')


def send(token, user, message, *, title='Keep', device='', url='', now=None):
    link = _url(url)
    if (not _configured(token, user, device) or not isinstance(message, str) or not 1 <= len(message) <= 1024
            or not isinstance(title, str) or len(title) > 250 or link is None):
        return Result('rejected', 'configuration')
    data = {'token': token, 'user': user, 'message': message, 'title': title, 'priority': 0}
    if device:
        data['device'] = device
    if link:
        data.update(url=link, url_title='Open Keep')
    return _call(MESSAGE_URL, data, now=now)


def validate(token, user, *, device='', now=None):
    if not _configured(token, user, device):
        return Result('rejected', 'configuration')
    return _call(VALIDATE_URL, {'token': token, 'user': user, **({'device': device} if device else {})}, now=now)


def digest_message(items):
    """Compact, plain-text summary; the Leaving page contains full details."""
    urgent = sum(bool(item.get('urgent')) for item in items)
    summary = f'{len(items)} title' + ('s' if len(items) != 1 else '') + ' leaving soon.'
    if urgent:
        summary += f' {urgent} within seven days.'
    lines = [summary]
    shown = 0
    for item in items[:8]:
        title = ' '.join(str(item.get('title') or 'Untitled').split())[:160]
        year = item.get('year')
        if type(year) is int and 1800 <= year <= 9999:
            title += f' ({year})'
        line = '\n' + title
        if len(''.join(lines)) + len(line) > 980:
            break
        lines.append(line)
        shown += 1
    if shown < len(items):
        lines.append(f'\nAnd {len(items) - shown} more. Open Keep for details.')
    return ''.join(lines)[:1024]
