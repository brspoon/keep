"""Read explicit Plex library shares and conservatively map media roots.

The supplied read(url) performs authenticated GETs with a shared deadline, byte
limit and redirect policy. This module never receives or returns access tokens.
"""
import re
import time
from urllib.parse import urlsplit
import xml.etree.ElementTree as ET


MAX_USERS = 500
MAX_SECTIONS = 5000
MAX_LOCATIONS = 64
_NUMBER = re.compile(r'[1-9][0-9]{0,19}\Z')
_MACHINE = re.compile(r'[A-Za-z0-9_-]{1,128}\Z')
_KINDS = {'movie': 'movie', 'show': 'show', 'tvshow': 'show'}


def _require(value):
    if not value:
        raise ValueError('Plex library access could not be verified')


def _number(value):
    _require(isinstance(value, str) and _NUMBER.fullmatch(value))
    return value


def _text(value, limit=200):
    _require(isinstance(value, str) and 0 < len(value) <= limit
             and not any(ord(char) < 32 or ord(char) == 127 for char in value))
    return value


def _flag(element, name, default=None):
    value = element.get(name)
    if value is None:
        return default
    _require(value in ('0', '1'))
    return value == '1'


def _restricted(element):
    restricted = _flag(element, 'restricted', False)
    return restricted or any(value.strip() for name, value in element.attrib.items()
                             if name.lower().startswith(('filter', 'restriction')))


def _read(read, url, limit):
    try:
        root = read(url)
    except Exception:
        raise ValueError('Plex library access response unavailable') from None
    _require(isinstance(root, ET.Element) and root.tag == 'MediaContainer' and len(root) <= limit)
    for name in ('size', 'totalSize', 'offset'):
        if root.get(name) is not None:
            _require(re.fullmatch(r'[0-9]{1,6}', root.get(name)))
    if root.get('offset') is not None:
        _require(int(root.get('offset')) == 0)
    if root.get('size') is not None:
        _require(int(root.get('size')) == len(root))
    if root.get('totalSize') is not None:
        _require(int(root.get('totalSize')) == len(root))
    return root


def _path(value):
    """Return a lexical absolute path identity without consulting this host."""
    _text(value, 4096)
    _require(value == value.strip())
    windows = bool(re.match(r'^[A-Za-z]:[/\\]', value) or value.startswith(('\\\\', '//')))
    if windows:
        value = value.replace('\\', '/')
        if value.startswith('//'):
            parts = value[2:].split('/')
            _require(len(parts) >= 2 and parts[0] and parts[1]
                     and parts[0] not in ('.', '..') and parts[1] not in ('.', '..')
                     and not any(char in part for part in parts[:2] for char in '*?:'))
            anchor, tail = ('unc', parts[0].lower(), parts[1].lower()), parts[2:]
        else:
            anchor, tail = ('drive', value[:2].lower()), value[3:].split('/')
        _require(all(':' not in part and not any(char in part for char in '*?') for part in tail))
        _require(all(part != '..' for part in tail))
        return ('windows', anchor, tuple(part.lower() for part in tail if part not in ('', '.')))
    _require(value.startswith('/') and '\\' not in value)
    parts = value[1:].split('/')
    _require('..' not in parts)
    return ('posix', ('/',), tuple(part for part in parts if part not in ('', '.')))


def _contains(parent, child):
    return parent[:2] == child[:2] and child[2][:len(parent[2])] == parent[2]


def _catalog(root):
    sections, known, location_count = {}, {}, 0
    for directory in root:
        _require(directory.tag == 'Directory')
        key, kind = _number(directory.get('key')), directory.get('type')
        _require(key not in known and isinstance(kind, str) and 0 < len(kind) <= 32)
        known[key] = _KINDS.get(kind)
        if kind not in _KINDS:
            continue
        name = _text(directory.get('title'))
        _require(0 < len(directory) <= MAX_LOCATIONS)
        locations, identities = [], set()
        for location in directory:
            location_count += 1
            _require(location_count <= MAX_SECTIONS)
            _require(location.tag == 'Location')
            path = _text(location.get('path'), 4096)
            identity = _path(path)
            _require(identity not in identities)
            identities.add(identity)
            locations.append(path)
        sections[key] = {'key': key, 'name': name, 'kind': _KINDS[kind], 'locations': locations}
    return sections, known


def _shared_sections(root, machine, share_id, user_id, known):
    # plex.tv's container identifies its cloud service, not the shared PMS.
    # The requested share, user and optional SharedServer machine bind scope.
    for name in ('userID', 'userId'):
        if root.get(name) is not None:
            _require(_number(root.get(name)) == user_id)
    if not len(root):
        return [], False
    _require(len(root) == 1 and root[0].tag == 'SharedServer')
    share = root[0]
    if share.get('id') is not None:
        _require(_number(share.get('id')) == share_id)
    for name in ('userID', 'userId', 'accountID'):
        if share.get(name) is not None:
            _require(_number(share.get(name)) == user_id)
    if share.get('machineIdentifier') is not None:
        _require(share.get('machineIdentifier') == machine)
    _require(len(share) <= MAX_SECTIONS)
    pending, restricted = _flag(share, 'pending', False), bool(_restricted(share) or _restricted(root))
    result, seen, cloud_ids = [], set(), set()
    for section in share:
        _require(section.tag == 'Section')
        key = _number(section.get('key'))
        _require(key in known and key not in seen)
        seen.add(key)
        if section.get('id') is not None:
            cloud_id = _number(section.get('id'))
            _require(cloud_id not in cloud_ids)
            cloud_ids.add(cloud_id)
        if section.get('type') is not None and known[key] is not None:
            _require(_KINDS.get(section.get('type')) == known[key])
        shared = _flag(section, 'shared')
        _require(shared is not None)
        restricted = bool(restricted or _restricted(section))
        if shared and known[key] is not None:
            result.append(key)
    return ([], restricted) if pending or restricted else (sorted(result, key=int), False)


def collect(connection, read, user_ids):
    """Collect server-bound, explicit section shares; failures return no proof."""
    _require(isinstance(connection, dict) and callable(read))
    machine, base = connection.get('PLEX_MACHINE_IDENTIFIER'), connection.get('PLEX_SERVER_URL')
    _require(isinstance(machine, str) and _MACHINE.fullmatch(machine))
    _text(base, 2048)
    _require(base == base.strip())
    try:
        url = urlsplit(base)
        _require(url.scheme in ('http', 'https') and url.hostname and url.port != 0
                 and url.username is None and url.password is None and not url.query and not url.fragment)
    except ValueError:
        raise ValueError('Invalid configured Plex address') from None
    _require(isinstance(user_ids, (set, frozenset, list, tuple)) and len(user_ids) <= MAX_USERS)
    targets = {_number(user_id) for user_id in user_ids}
    _require(len(targets) == len(user_ids))
    base = base.rstrip('/')
    identity = _read(read, base + '/identity', 0)
    _require(identity.get('machineIdentifier') == machine)
    catalog = _read(read, base + '/library/sections', MAX_SECTIONS)
    if catalog.get('machineIdentifier') is not None:
        _require(catalog.get('machineIdentifier') == machine)
    sections, known = _catalog(catalog)
    friends = _read(read, 'https://plex.tv/api/users/', MAX_USERS)
    users = {user_id: {'sections': [], 'restricted': False} for user_id in targets}
    seen_users, seen_shares, server_count = set(), set(), 0
    for user in friends:
        _require(user.tag == 'User')
        user_id = _number(user.get('id'))
        _require(user_id not in seen_users and len(user) <= MAX_USERS)
        seen_users.add(user_id)
        restricted, selected, seen_machines = bool(_restricted(user)), None, set()
        for server in user:
            server_count += 1
            _require(server_count <= MAX_SECTIONS and server.tag == 'Server' and len(server) == 0)
            server_machine = server.get('machineIdentifier')
            _require(isinstance(server_machine, str) and _MACHINE.fullmatch(server_machine)
                     and server_machine not in seen_machines)
            seen_machines.add(server_machine)
            if server_machine != machine:
                continue
            for name in ('userID', 'userId'):
                if server.get(name) is not None:
                    _require(_number(server.get(name)) == user_id)
            pending = _flag(server, 'pending')
            _require(pending is not None)
            _flag(server, 'allLibraries')  # Counts and all-libraries flags never authorize sections.
            if server.get('numLibraries') is not None:
                _require(re.fullmatch(r'[0-9]{1,6}', server.get('numLibraries'))
                         and int(server.get('numLibraries')) <= MAX_SECTIONS)
            restricted = bool(restricted or _restricted(server))
            if not pending:
                share_id = _number(server.get('id'))
                _require(share_id not in seen_shares)
                seen_shares.add(share_id)
                selected = share_id
        if user_id not in targets:
            continue
        users[user_id]['restricted'] = restricted
        if selected is None or restricted:
            continue
        shared = _read(read, f'https://plex.tv/api/servers/{machine}/shared_servers/{selected}', 1)
        keys, detail_restricted = _shared_sections(shared, machine, selected, user_id, known)
        users[user_id] = {'sections': keys, 'restricted': detail_restricted}
    return {'machine': machine, 'sections': sections, 'users': users, 'checked_at': time.time()}


def automatic_mappings(sections, libraries):
    """Map only a unique section covering a whole Arr root, never a partial root."""
    _require(isinstance(sections, dict) and len(sections) <= MAX_SECTIONS
             and isinstance(libraries, (list, tuple)) and len(libraries) <= MAX_SECTIONS)
    locations = []
    for key, section in sections.items():
        _number(key)
        _require(isinstance(section, dict) and section.get('key') == key
                 and section.get('kind') in ('movie', 'show')
                 and isinstance(section.get('locations'), list) and 0 < len(section['locations']) <= MAX_LOCATIONS)
        for path in section['locations']:
            locations.append((key, section['kind'], _path(path)))
            _require(len(locations) <= MAX_SECTIONS)
    result, seen = {}, set()
    for library in libraries:
        _require(isinstance(library, dict))
        key, service = library.get('library_key'), library.get('service')
        _require(service in ('radarr', 'sonarr') and isinstance(key, str)
                 and re.fullmatch(service + r':[1-9][0-9]{0,19}', key) and key not in seen)
        seen.add(key)
        root = _path(library.get('path'))
        kind = 'movie' if service == 'radarr' else 'show'
        overlapping = {section_key for section_key, section_kind, path in locations
                       if section_kind == kind and (_contains(path, root) or _contains(root, path))}
        covering = {section_key for section_key, section_kind, path in locations
                    if section_kind == kind and _contains(path, root)}
        if len(covering) == 1 and overlapping == covering:
            result[key] = sorted(covering, key=int)
    return result
