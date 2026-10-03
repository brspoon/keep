"""Read-only, bounded interpretation of the configured Leaving rules.

Only simple OR-of-AND date and zero-view rules are forecastable. Unknown rule
shapes and missing inputs never become a reassuring countdown.
"""
import json
import math
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode, quote

import requests


class ForecastUnavailable(ValueError):
    pass


def _get_json(url, headers=None):
    with requests.get(url, headers=headers or {}, timeout=(3, 7),
                      allow_redirects=False, stream=True) as response:
        response.raise_for_status()
        if response.status_code != 200:
            raise ForecastUnavailable('Service did not return success')
        body = bytearray()
        for chunk in response.iter_content(16384):
            body.extend(chunk)
            if len(body) > 1024 * 1024:
                raise ForecastUnavailable('Service response is too large')
    return json.loads(body)


def tautulli_api(settings, command, **params):
    base, key = settings('TAUTULLI_URL'), settings('TAUTULLI_API_KEY')
    if not base or not key:
        raise ForecastUnavailable('Tautulli is not connected')
    payload = _get_json(base + '/api/v2?' + urlencode({'cmd': command, **params}),
                        {'X-Api-Key': key})
    envelope = payload.get('response') if isinstance(payload, dict) else None
    if not isinstance(envelope, dict) or envelope.get('result') != 'success':
        raise ForecastUnavailable('Tautulli could not return playback data')
    return envelope.get('data')


def tautulli_thresholds(settings):
    data = tautulli_api(settings, 'get_settings', key='Monitoring')
    if not isinstance(data, dict):
        raise ForecastUnavailable('Tautulli settings are unavailable')
    monitoring = data.get('Monitoring', data)
    try:
        values = {kind: int(monitoring[key]) for kind, key in
                  (('movie', 'movie_watched_percent'), ('tv', 'tv_watched_percent'))}
    except (KeyError, ValueError, TypeError):
        raise ForecastUnavailable('Tautulli watched thresholds are unavailable') from None
    if any(not 1 <= number <= 100 for number in values.values()):
        raise ForecastUnavailable('Invalid Tautulli watched threshold')
    return values


def watched_history(settings, plex_id, kind, threshold):
    """Return complete qualifying history, or fail rather than call it unwatched."""
    if not str(plex_id).isdigit():
        raise ForecastUnavailable('Missing Plex media ID')
    scope = 'grandparent_rating_key' if kind == 'tv' else 'rating_key'
    rows = []
    for start in range(0, 5000, 100):
        data = tautulli_api(settings, 'get_history', **{scope: plex_id},
                            start=start, length=100, grouping=1)
        if not isinstance(data, dict) or not isinstance(data.get('data'), list):
            raise ForecastUnavailable('Incomplete Tautulli history')
        page = data['data']
        if len(page) > 100:
            raise ForecastUnavailable('Invalid Tautulli history page')
        for row in page:
            if not isinstance(row, dict) or str(row.get(scope)) != str(plex_id):
                raise ForecastUnavailable('Unexpected Tautulli history item')
            try:
                percent = float(row['percent_complete'])
            except (KeyError, TypeError, ValueError):
                raise ForecastUnavailable('Playback percentage unavailable') from None
            if percent >= threshold:
                rows.append(row)
        total = data.get('recordsFiltered')
        if type(total) is int and start + len(page) >= total:
            return rows
        if len(page) < 100:
            return rows
    raise ForecastUnavailable('Tautulli history exceeds lookup limit')


def read_rules(settings, collection_ids):
    base = settings('MAINTAINERR_URL')
    if not base:
        raise ForecastUnavailable('Maintainerr is not connected')
    payload = _get_json(base + '/api/rules')
    if not isinstance(payload, list) or len(payload) > 200:
        raise ForecastUnavailable('Invalid Maintainerr rule list')
    wanted = {int(cid) for cid in collection_ids}
    groups = {}
    for group in payload:
        if not isinstance(group, dict) or group.get('collectionId') not in wanted:
            continue
        cid = group['collectionId']
        if cid in groups or not group.get('isActive') or not group.get('useRules'):
            raise ForecastUnavailable('Selected collection has ambiguous or inactive rules')
        groups[cid] = parse_group(group)
    if set(groups) != wanted:
        raise ForecastUnavailable('A selected collection has no active rule')
    return groups


def find_plex_media(settings, groups, kind, external_id, title):
    """Find an Arr title in one selected Plex library by provider ID."""
    if not external_id or not title or '/' in title or len(title) > 200:
        return None
    field = 'tmdb' if kind == 'movie' else 'tvdb'
    matches = []
    for cid, group in groups.items():
        if group['kind'] != kind or not group['library_id'].isdigit():
            continue
        path = f"/api/media-server/library/{group['library_id']}/content/search/{quote(title, safe='')}"
        rows = _get_json(settings('MAINTAINERR_URL') + path)
        if not isinstance(rows, list) or len(rows) > 500:
            raise ForecastUnavailable('Plex search is incomplete')
        for row in rows:
            if not isinstance(row, dict):
                continue
            providers = row.get('providerIds') or {}
            ids = (providers.get(field) or []) if isinstance(providers, dict) else []
            if str(external_id) in [str(value) for value in ids] and str(row.get('id') or '').isdigit():
                matches.append((cid, row['id']))
    return matches[0] if len(matches) == 1 else None


def parse_group(group):
    """Support the currently configured OR-of-AND rule shape, not arbitrary DSL."""
    if group.get('dataType') not in ('movie', 'show'):
        raise ForecastUnavailable('Unsupported Maintainerr media type')
    constants = {(1, 0): 'arr_added', (2, 0): 'arr_added',
                 (4, 3): 'views', (4, 6): 'views',
                 (4, 4): 'last_viewed', (0, 16): 'last_episode_added'}
    sections = {}
    rows = group.get('rules')
    if not isinstance(rows, list) or not rows or len(rows) > 30:
        raise ForecastUnavailable('Unsupported Maintainerr rule group')
    if any(not isinstance(item, dict) or type(item.get('section')) is not int or
           type(item.get('id')) is not int for item in rows):
        raise ForecastUnavailable('Invalid Maintainerr rule')
    for row in sorted(rows, key=lambda item: (item.get('section', -1), item.get('id', -1))):
        if not isinstance(row, dict) or row.get('isActive') is not True or type(row.get('section')) is not int:
            raise ForecastUnavailable('Inactive or invalid rule in group')
        raw = row.get('ruleJson')
        try:
            rule = json.loads(raw) if isinstance(raw, str) else raw
            source = tuple(rule['firstVal'])
            field = constants[source]
            action = int(rule['action'])
            value = int(rule['customVal']['value'])
            operator = rule.get('operator')
        except (ValueError, TypeError, KeyError, AttributeError):
            raise ForecastUnavailable('Unsupported Maintainerr condition') from None
        if source == (1, 0) and group['dataType'] != 'movie' or source == (2, 0) and group['dataType'] != 'show' or source == (4, 3) and group['dataType'] != 'movie' or source == (4, 6) and group['dataType'] != 'show':
            raise ForecastUnavailable('Rule source does not match media type')
        if ((field == 'views' and (action, value) != (2, 0)) or
                (field != 'views' and (action != 5 or value < 0 or value > 100 * 365 * 86400))):
            raise ForecastUnavailable('Unsupported Maintainerr comparison')
        section = sections.setdefault(row['section'], [])
        if section and str(operator) != '0':
            raise ForecastUnavailable('Unsupported rule operator')
        if not section and len(sections) > 1 and str(operator) != '1':
            raise ForecastUnavailable('Unsupported section operator')
        section.append((field, value))
    if sorted(sections) != list(range(len(sections))) or len(sections) > 4:
        raise ForecastUnavailable('Unsupported Maintainerr rule sections')
    return {'name': str(group.get('name') or ''), 'library_id': str(group.get('libraryId') or ''),
            'kind': 'movie' if group.get('dataType') == 'movie' else 'tv',
            'sections': list(sections.values()),
            'delete_after_days': (group.get('collection') or {}).get('deleteAfterDays'),
            'watch_override': (group.get('collection') or {}).get('tautulliWatchedPercentOverride')}


def parse_date(value):
    if isinstance(value, datetime):
        return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, timezone.utc)
    if isinstance(value, str) and value:
        try:
            result = datetime.fromisoformat(value.replace('Z', '+00:00'))
            return result.replace(tzinfo=timezone.utc) if result.tzinfo is None else result.astimezone(timezone.utc)
        except ValueError:
            return None
    return None


def estimate(group, values, now=None):
    """Earliest date at which any complete AND section can match."""
    now = now or datetime.now(timezone.utc)
    candidates = []
    unknown = False
    for section in group['sections']:
        gates = []
        for field, value in section:
            if field == 'views':
                if values.get('views') is None:
                    raise ForecastUnavailable('Watch history is unavailable')
                if values['views'] != 0:
                    gates = None
                    break
            else:
                if field == 'last_viewed' and field in values and values[field] is None and values.get('views') == 0:
                    gates = None  # Verified empty qualifying history cannot satisfy this path.
                    break
                date = parse_date(values.get(field))
                if date is None:
                    unknown = True
                    gates = None
                    break
                gates.append(date + timedelta(seconds=value))
        if gates is not None and gates:
            candidates.append(max(gates))
    if unknown:
        raise ForecastUnavailable('A rule input is unavailable')
    if not candidates:
        return None
    eligible_at = min(candidates)
    return {'eligible_at': eligible_at, 'days': max(0, math.ceil((eligible_at - now).total_seconds() / 86400))}


def criteria(group):
    title = 'movie' if group['kind'] == 'movie' else 'show'
    names = {'arr_added': (f'The {title} was added to the library', 'it was added to the library'),
             'views': ('The movie has never been watched', 'it has never been watched') if title == 'movie'
                      else ('No episode of the show has been watched', 'none of its episodes have been watched'),
             'last_viewed': (f'The {title} was last watched', 'it was last watched'),
             'last_episode_added': ('The newest episode was added', 'its newest episode was added')}
    paths = []
    for section in group['sections']:
        parts = []
        for field, seconds in section:
            name = names[field][bool(parts)]
            if field == 'views':
                parts.append(name)
            else:
                parts.append(f'{name} {plain_duration(seconds)} ago or earlier')
        if len(parts) > 2:
            sentence = ', '.join(parts[:-1]) + ', and ' + parts[-1]
        else:
            sentence = ' and '.join(parts)
        paths.append(sentence + '.')
    return paths


def countdown_label(days):
    """Approximate long forecasts without hiding nearby day-level changes."""
    if days <= 0:
        return 'now'
    if days < 60:
        return f'in {days} ' + ('day' if days == 1 else 'days')
    months = max(1, round(days / 30.44))
    years, remainder = divmod(months, 12)
    if years and remainder:
        return f'in about {years} ' + ('year' if years == 1 else 'years') + \
               f' and {remainder} ' + ('month' if remainder == 1 else 'months')
    if years:
        return f'in about {years} ' + ('year' if years == 1 else 'years')
    return f'in about {months} ' + ('month' if months == 1 else 'months')


def plain_duration(seconds):
    """Readable approximations for guidance; eligibility uses exact seconds."""
    days = seconds / 86400
    if seconds and seconds % (365 * 86400) == 0:
        years = seconds // (365 * 86400)
        return f'{years} year' + ('s' if years != 1 else '')
    whole_years = int(days // 365)
    half_years = (whole_years + 0.5) * 365
    if whole_years >= 1 and abs(days - half_years) <= 7:
        return f'about {whole_years} and a half years' if whole_years > 1 else 'about a year and a half'
    if days >= 365:
        return f'about {days / 365:.1f} years'
    if days >= 60:
        months = max(1, round(days / 30.44))
        return f'about {months} months'
    return f'{math.ceil(days)} days'
