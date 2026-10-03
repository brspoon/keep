"""Narrow Radarr and Sonarr API client used by Library Management."""
from urllib.parse import urljoin
import hashlib
import json
import time
from contextvars import ContextVar
from contextlib import contextmanager

import requests


SERVICES = {
    "radarr": {
        "url": "RADARR_URL",
        "key": "RADARR_API_KEY",
        "items": "/api/v3/movie",
        "singular": "/api/v3/movie/{item_id}",
        "delete_exclusion": "addImportExclusion",
        "kind": "Movie",
    },
    "sonarr": {
        "url": "SONARR_URL",
        "key": "SONARR_API_KEY",
        "items": "/api/v3/series",
        "singular": "/api/v3/series/{item_id}",
        "delete_exclusion": "addImportListExclusion",
        "kind": "Series",
    },
}
MAX_ARTWORK_BYTES = 8 * 1024 * 1024
ARTWORK_TYPES = {"image/jpeg", "image/png", "image/webp"}
_deadline = ContextVar('media_request_deadline', default=None)


@contextmanager
def request_budget(seconds=60):
    token = _deadline.set(time.monotonic() + seconds)
    try:
        yield
    finally:
        _deadline.reset(token)


def _config(service):
    try:
        return SERVICES[service]
    except KeyError:
        raise ValueError("Unsupported media service") from None


def _request(service, settings, method, path, **kwargs):
    config = _config(service)
    base_url = settings(config["url"])
    api_key = settings(config["key"])
    if not base_url or not api_key:
        raise ValueError(f"{service.title()} is not configured")
    headers = {"X-Api-Key": api_key, "Accept": "application/json", **kwargs.pop("headers", {})}
    remaining = _deadline.get() - time.monotonic() if _deadline.get() is not None else 20
    if remaining <= 0:
        raise ValueError('Media operation timed out')
    response = requests.request(
        method, urljoin(base_url.rstrip("/") + "/", path.lstrip("/")),
        headers=headers, timeout=min(20, remaining), allow_redirects=False, **kwargs,
    )
    response.raise_for_status()
    if not 200 <= response.status_code < 300:
        raise requests.HTTPError("Unexpected redirect or response", response=response)
    return response


def test_connection(service, settings):
    status = _request(service, settings, "GET", "/api/v3/system/status").json()
    if not isinstance(status, dict) or not status.get("version"):
        raise ValueError("Unexpected service response")
    return status


def discover_libraries(service, settings):
    rows = _request(service, settings, "GET", "/api/v3/rootfolder").json()
    if not isinstance(rows, list):
        raise ValueError("Unexpected root-folder response")
    libraries = []
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("id"), int) or not row.get("path"):
            continue
        path = str(row["path"]).rstrip("/\\")
        label = path.replace("\\", "/").rsplit("/", 1)[-1] or f"{service.title()} {row['id']}"
        libraries.append({
            "key": f"{service}:{row['id']}", "service": service,
            "external_id": str(row["id"]), "name": label, "path": path,
        })
    return libraries


def list_media(service, settings):
    rows = _request(service, settings, "GET", _config(service)["items"]).json()
    if not isinstance(rows, list):
        raise ValueError("Unexpected media response")
    return rows


def get_media(service, item_id, settings):
    if not isinstance(item_id, int) or item_id < 1:
        raise ValueError("Invalid media ID")
    row = _request(
        service, settings, "GET", _config(service)["singular"].format(item_id=item_id)
    ).json()
    if not isinstance(row, dict) or row.get("id") != item_id:
        raise ValueError("Unexpected media response")
    return row


def delete_media(service, item_id, settings):
    config = _config(service)
    return _request(
        service, settings, "DELETE", config["singular"].format(item_id=item_id),
        params={"deleteFiles": "true", config["delete_exclusion"]: "false"},
    )


def downloaded_seasons(item):
    """Cheap browsing hints from Sonarr's series inventory, never delete authority."""
    rows = item.get('seasons')
    if not isinstance(rows, list):
        return []
    numbers = []
    seen = set()
    for row in rows:
        if not isinstance(row, dict):
            return []
        number = row.get('seasonNumber')
        if type(number) is not int or number < 0 or number in seen:
            return []
        seen.add(number)
        stats = row.get('statistics') or {}
        count = stats.get('episodeFileCount') if isinstance(stats, dict) else None
        if type(count) is int and count > 0:
            numbers.append(number)
    return sorted(numbers)


def season_inventory(series_id, settings):
    """Join fresh files to every episode; reject ambiguous or partial inventories."""
    files = _request('sonarr', settings, 'GET', '/api/v3/episodefile', params={'seriesId': series_id}).json()
    episodes = _request('sonarr', settings, 'GET', '/api/v3/episode', params={'seriesId': series_id}).json()
    if not isinstance(files, list) or not isinstance(episodes, list) or len(files) > 20000 or len(episodes) > 20000:
        raise ValueError('Incomplete season inventory')
    by_file, by_season, seen_episodes, season_episodes = {}, {}, set(), {}
    for row in files:
        if not isinstance(row, dict) or type(row.get('id')) is not int or row['id'] < 1 \
                or type(row.get('seriesId')) is not int or row['seriesId'] != series_id or type(row.get('seasonNumber')) is not int \
                or row['seasonNumber'] < 0 or row['id'] in by_file \
                or type(row.get('size')) is not int or row['size'] < 0 \
                or not isinstance(row.get('path'), str) or not row['path']:
            raise ValueError('Invalid episode file inventory')
        by_file[row['id']] = {'file': row, 'episodes': []}
    for row in episodes:
        if not isinstance(row, dict) or type(row.get('id')) is not int or row['id'] < 1 \
                or row['id'] in seen_episodes or type(row.get('seriesId')) is not int or row['seriesId'] != series_id \
                or type(row.get('seasonNumber')) is not int or row['seasonNumber'] < 0 \
                or type(row.get('hasFile')) is not bool or type(row.get('episodeFileId')) is not int \
                or type(row.get('monitored')) is not bool:
            raise ValueError('Invalid episode inventory')
        seen_episodes.add(row['id'])
        season_episodes.setdefault(row['seasonNumber'], []).append(row)
        fid = row['episodeFileId']
        if not row['hasFile']:
            if fid != 0:
                raise ValueError('Episode inventory changed')
            continue
        if fid not in by_file or by_file[fid]['file']['seasonNumber'] != row['seasonNumber']:
            raise ValueError('File spans seasons or inventory changed')
        by_file[fid]['episodes'].append(row)
    for fid, data in by_file.items():
        if not data['episodes']:
            raise ValueError('Episode file has no verified episode mapping')
        number = data['file']['seasonNumber']
        by_season.setdefault(number, []).append(data)
    result = {}
    for number, rows in by_season.items():
        all_episodes = season_episodes[number]
        # Monitoring is intentionally changed during deletion; all identity/file
        # fields stay bound to the preview, including missing episodes in scope.
        canonical = {'files': [r['file'] for r in sorted(rows, key=lambda r: r['file']['id'])],
                     'episodes': [{k:v for k,v in e.items() if k != 'monitored'}
                                  for e in sorted(all_episodes, key=lambda e:e['id'])]}
        result[number] = {'number': number, 'fileIds': sorted(r['file']['id'] for r in rows),
                          'episodeIds': sorted(e['id'] for e in all_episodes),
                          'monitoredEpisodeIds': sorted(e['id'] for e in all_episodes if e['monitored']),
                          'episodes': sum(len(r['episodes']) for r in rows),
                          'bytes': sum(r['file']['size'] for r in rows),
                          'fingerprint': hashlib.sha256(json.dumps(canonical, sort_keys=True).encode()).hexdigest()}
    return result


def unmonitor_seasons(series_id, seasons, settings):
    # Partial season updates, not a whole-series PUT that could overwrite settings.
    return _request('sonarr', settings, 'POST', '/api/v3/seasonpass', json={
        'series': [{'id': series_id, 'seasons': [{'seasonNumber': n, 'monitored': False} for n in seasons]}]})


def season_monitoring(item):
    rows = item.get('seasons')
    if not isinstance(rows, list):
        raise ValueError('Incomplete season monitoring state')
    result = {}
    for row in rows:
        if not isinstance(row, dict) or type(row.get('seasonNumber')) is not int or row['seasonNumber'] < 0 \
                or row['seasonNumber'] in result or type(row.get('monitored')) is not bool:
            raise ValueError('Invalid season monitoring state')
        result[row['seasonNumber']] = row['monitored']
    return result


def unmonitor_episodes(episode_ids, settings):
    return _request('sonarr', settings, 'PUT', '/api/v3/episode/monitor',
                    json={'episodeIds': episode_ids, 'monitored': False})


def delete_episode_files(file_ids, settings):
    if not file_ids or any(type(n) is not int or n < 1 for n in file_ids) or len(set(file_ids)) != len(file_ids):
        raise ValueError('Invalid episode file IDs')
    return _request('sonarr', settings, 'DELETE', '/api/v3/episodefile/bulk', json={'episodeFileIds': file_ids})


def _artwork_path(item, item_id):
    for image in (item or {}).get("images") or []:
        if not isinstance(image, dict) or image.get("coverType") != "poster":
            continue
        path = image.get("url")
        if not isinstance(path, str) or not path.startswith("/"):
            continue
        clean_path, separator, query = path.partition("?")
        prefix = f"/mediacover/{item_id}/"
        if not clean_path.lower().startswith(prefix):
            continue
        filename = clean_path[len(prefix):]
        if not filename or "/" in filename or "\\" in filename or filename in {".", ".."}:
            continue
        return f"/api/v3/mediacover/{item_id}/{filename}{separator}{query}"
    return f"/api/v3/mediacover/{item_id}/poster.jpg"


def artwork(service, item_id, settings, item=None, thumbnail=False):
    if not isinstance(item_id, int) or item_id < 1:
        raise ValueError("Invalid media ID")
    path = _artwork_path(item, item_id)
    thumbnail_path = path.replace('/poster.jpg', '/poster-500.jpg') if thumbnail else path
    try:
        response = _request(service, settings, "GET", thumbnail_path,
                            headers={"Accept": "image/jpeg,image/png,image/webp"}, stream=True)
    except requests.HTTPError as error:
        if error.response is not None:
            error.response.close()
        if thumbnail_path == path or error.response is None or error.response.status_code != 404:
            raise
        response = _request(service, settings, "GET", path,
                            headers={"Accept": "image/jpeg,image/png,image/webp"}, stream=True)
    try:
        content_type = response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type not in ARTWORK_TYPES:
            raise ValueError("Unexpected artwork response")
        declared_length = response.headers.get("Content-Length")
        if declared_length and int(declared_length) > MAX_ARTWORK_BYTES:
            raise ValueError("Artwork response is too large")
        chunks, total = [], 0
        for chunk in response.iter_content(64 * 1024):
            if not chunk:
                continue
            total += len(chunk)
            if total > MAX_ARTWORK_BYTES:
                raise ValueError("Artwork response is too large")
            chunks.append(chunk)
        return b"".join(chunks), content_type
    finally:
        response.close()
