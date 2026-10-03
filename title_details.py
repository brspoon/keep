"""Allowlisted display metadata; never an authorization source."""
import copy
import json
import threading
import time
from collections import OrderedDict

_cache = OrderedDict()
_lock = threading.Lock()


def cached_metadata(key, loader):
    """Cache public display fields only; callers recheck membership every time."""
    with _lock:
        entry = _cache.get(key)
        if entry and entry[0] > time.monotonic():
            _cache.move_to_end(key)
            return copy.deepcopy(entry[1])
    value = normalize(loader())
    if len(json.dumps(value).encode()) > 65536:
        return value
    with _lock:
        _cache[key] = (time.monotonic() + 60, copy.deepcopy(value))
        _cache.move_to_end(key)
        while len(_cache) > 128:
            _cache.popitem(last=False)
    return value


def runtime_label(data, kind):
    # Explicit units: Arr runtime is minutes; Plex duration is milliseconds.
    value = data.get('runtime')
    if type(value) not in (int, float) or not 0 < value <= 1440:
        value = data.get('duration')
        value = value / 60000 if type(value) in (int, float) and 0 < value <= 86400000 else 0
    if not value:
        return ''
    minutes = max(1, round(value))
    label = f'{minutes // 60}h {minutes % 60}m' if minutes >= 60 else f'{minutes}m'
    return label + (' per episode' if kind == 'tv' else '')


def season_rows(details, snapshot, identities, attribution):
    """Omit explicitly empty, unrequested seasons; never infer request absence offline."""
    records = [r for r in snapshot['requests'] if details['external_id'] and
               r['kind'] == 'tv' and r['tvdb'] == details['external_id']]
    requested = {s['number'] for r in records for s in r['seasons']}
    numbers = sorted(set(details['seasons']) | requested)
    rows = []
    for number in numbers:
        count = details['season_files'].get(number)
        if count == 0 and number not in requested and snapshot['state'] == 'current' and not any(not r['seasons'] for r in records):
            continue
        history = attribution(snapshot, identities, 'tv', details['external_id'], season=number)
        if not history['names']:
            if snapshot['state'] != 'current':
                history['label'] = 'Request history unavailable' if snapshot['state'] != 'stale' else 'Request history out of date'
            elif number in requested:
                history['label'] = 'No approved request recorded'
            elif details['external_id'] and not any(not r['seasons'] for r in records):
                history['label'] = 'No request recorded'
            else:
                history['label'] = 'Season request details unavailable'
        rows.append({'number': number, 'history': history,
                     'availability': ('In library' if count > 0 else 'Not in library') if count is not None else ''})
    return rows


def positive_id(value):
    try:
        return int(value) if not isinstance(value, bool) and int(value) > 0 else None
    except (ValueError, TypeError):
        return None


def normalize(data):
    raw_genres = data.get('genres') or data.get('Genre') or []
    genres = []
    for genre in raw_genres if isinstance(raw_genres, list) else []:
        # Maintainerr uses name objects, Plex uses tag objects, and Arr uses strings.
        candidates = (genre.get('name'), genre.get('tag')) if isinstance(genre, dict) else (genre,)
        label = next((value.strip() for value in candidates
                      if isinstance(value, str) and value.strip()), '')
        if label:
            genres.append(label)
    kind = ('tv' if data.get('type') in ('show', 'series', 'tv') else
            'movie' if data.get('type') == 'movie' else 'unknown')
    providers = data.get('providerIds') or {}
    def external(name):
        value = data.get(name + 'Id')
        if not value and isinstance(providers, dict):
            values = providers.get(name) or []
            value = values[0] if isinstance(values, list) and values else None
        return positive_id(value)
    raw_seasons = data.get('seasons') if isinstance(data.get('seasons'), list) else []
    seasons = sorted({s['seasonNumber'] for s in raw_seasons
                      if isinstance(s, dict) and type(s.get('seasonNumber')) is int and s['seasonNumber'] >= 0})
    season_files = {}
    for season in raw_seasons:
        if not isinstance(season, dict) or season.get('seasonNumber') not in seasons:
            continue
        stats = season.get('statistics')
        count = stats.get('episodeFileCount') if isinstance(stats, dict) else None
        if type(count) is int and count >= 0:
            season_files[season['seasonNumber']] = count
    return {'title': str(data.get('title') or 'Untitled'), 'year': data.get('year') or '',
            'overview': str(data.get('overview') or data.get('summary') or 'No description available.'),
            'genres': genres, 'kind': kind, 'external_id': external('tvdb' if kind == 'tv' else 'tmdb'),
            'seasons': seasons, 'season_files': season_files, 'runtime': runtime_label(data, kind)}
