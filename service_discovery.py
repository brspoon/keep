"""Bounded, read-only service probes. Callers must enforce owner access and CSRF."""
import json
import time
import xml.etree.ElementTree as ET
import requests


def read_service(url, headers=None):
    deadline = time.monotonic() + 15
    with requests.get(url, headers=headers or {}, timeout=(3, 8),
                      allow_redirects=False, stream=True) as response:
        if response.status_code != 200:
            raise ValueError('Service did not return success')
        data = bytearray()
        for chunk in response.iter_content(16384):
            if time.monotonic() > deadline:
                raise ValueError('Service response exceeded time limit')
            data.extend(chunk)
            if len(data) > 1024 * 1024:
                raise ValueError('Service response exceeded limit')
        return bytes(data)


def discover_collections(base_url):
    rows = json.loads(read_service(base_url + '/api/collections'))
    if not isinstance(rows, list) or len(rows) > 200:
        raise ValueError('Unexpected collection response')
    result = {}
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError('Unexpected collection row')
        cid, title = row.get('id'), row.get('title')
        if type(cid) is not int or not 1 <= cid <= 999999999 or not isinstance(title, str) or not title.strip() or len(title) > 200:
            raise ValueError('Unexpected collection identity')
        if cid in result:
            raise ValueError('Duplicate collection identity')
        result[cid] = title
    return result


def test_plex(base_url, token, machine_id):
    root = ET.fromstring(read_service(base_url + '/identity', {'X-Plex-Token': token}))
    if root.tag != 'MediaContainer' or not machine_id or root.get('machineIdentifier') != machine_id:
        raise ValueError('Plex machine identifier does not match')
    # Identity can be public; accounts verifies that the token has server access.
    accounts = ET.fromstring(read_service(base_url + '/accounts', {'X-Plex-Token': token, 'Accept': 'application/xml'}))
    if accounts.tag != 'MediaContainer':
        raise ValueError('Unexpected Plex accounts response')
