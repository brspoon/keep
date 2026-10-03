#!/usr/bin/env python3
"""Collect exact Python source archives and their complete attribution files.

Archives are checksum verified and inspected without extracting source files.
The retained PyPI release record and archive PKG-INFO both bind each source to
the requirement pin. Native code supplied separately by wheel builders (for
example CFFI's statically linked libffi) needs its own matching source record.
"""
import argparse
from email.parser import BytesParser
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile
import urllib.parse
import urllib.request
import zipfile


MAX_DOWNLOAD = 64 * 1024 * 1024
MAX_UNPACKED = 256 * 1024 * 1024
MAX_FILES = 40000
MAX_NOTICE = 8 * 1024 * 1024
NOTICE_NAME = re.compile(r'(?:license|licence|copying|copyright|notice)', re.I)
PIN = re.compile(r'([A-Za-z0-9][A-Za-z0-9._-]*)==([0-9][A-Za-z0-9.!+_-]*)')


def canonical_name(name):
    return re.sub(r'[-_.]+', '-', name).lower()


def sha256(body):
    return hashlib.sha256(body).hexdigest()


def exact_requirements(path):
    """Reject unpinned, conditional, editable, duplicate or ambiguous inputs."""
    pins = []
    names = set()
    for number, line in enumerate(Path(path).read_text().splitlines(), 1):
        line = line.split('#', 1)[0].strip()
        if not line:
            continue
        match = PIN.fullmatch(line)
        if not match:
            raise ValueError(f'Requirement line {number} must be one exact name==version pin')
        name, version = match.groups()
        name = canonical_name(name)
        if name in names:
            raise ValueError(f'Duplicate pinned requirement: {name}')
        names.add(name)
        pins.append((name, version))
    if not pins:
        raise ValueError('No pinned requirements')
    return sorted(pins)


def public_url(url, hosts):
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme != 'https' or parsed.hostname not in hosts
            or parsed.username or parsed.password or parsed.port not in (None, 443)):
        raise ValueError('Unexpected source download URL')
    return url


def fetch_public(url):
    public_url(url, {'pypi.org', 'files.pythonhosted.org'})
    request = urllib.request.Request(url, headers={'User-Agent': 'Keep-source-bundle/1'})
    with urllib.request.urlopen(request, timeout=60) as response:
        public_url(response.geturl(), {'pypi.org', 'files.pythonhosted.org'})
        body = response.read(MAX_DOWNLOAD + 1)
    if len(body) > MAX_DOWNLOAD:
        raise ValueError('Source download exceeds size limit')
    return body


def safe_name(name):
    """Validate every retained archive path even though no source is extracted."""
    parts = PurePosixPath(name).parts
    if (not parts or '..' in parts or name.startswith('/')
            or '\\' in name or ':' in name or '\x00' in name):
        raise ValueError('Unsafe source archive path')
    return PurePosixPath(*parts).as_posix()


def inspect_source(body, filename, name, version):
    """Return attribution bytes only after validating the complete archive."""
    if len(body) > MAX_DOWNLOAD:
        raise ValueError('Source archive exceeds size limit')
    notices = {}
    identities = []
    seen = set()
    total = 0
    count = 0

    def record(path, size, reader):
        nonlocal total, count
        path = safe_name(path)
        if path in seen:
            raise ValueError('Duplicate source archive path')
        seen.add(path)
        count += 1
        total += size
        if count > MAX_FILES or total > MAX_UNPACKED or size < 0:
            raise ValueError('Source archive exceeds inspection limits')
        selected = bool(NOTICE_NAME.search(PurePosixPath(path).name))
        identity = len(PurePosixPath(path).parts) == 2 and path.endswith('/PKG-INFO')
        if selected or identity:
            if size > MAX_NOTICE:
                raise ValueError('Source notice or metadata exceeds size limit')
            content = reader()
            if len(content) != size:
                raise ValueError('Truncated source archive member')
            if selected:
                notices[path] = content
            if identity:
                identities.append(BytesParser().parsebytes(content))

    if filename.endswith('.zip'):
        with zipfile.ZipFile(io.BytesIO(body)) as archive:
            for member in archive.infolist():
                safe_name(member.filename)
                mode = member.external_attr >> 16
                if stat.S_ISLNK(mode):
                    raise ValueError('Source archive links are unsupported')
                if not member.is_dir():
                    record(member.filename, member.file_size,
                           lambda member=member: archive.read(member))
    elif filename.endswith(('.tar.gz', '.tgz', '.tar.bz2', '.tar.xz')):
        with tarfile.open(fileobj=io.BytesIO(body), mode='r:*') as archive:
            for member in archive:
                safe_name(member.name)
                if member.issym() or member.islnk():
                    raise ValueError('Source archive links are unsupported')
                if member.isfile():
                    record(member.name, member.size,
                           lambda member=member: archive.extractfile(member).read())
                elif not member.isdir():
                    raise ValueError('Source archive special files are unsupported')
    else:
        raise ValueError('Unsupported Python source archive format')
    if len(identities) != 1:
        raise ValueError('Source archive requires exactly one top-level PKG-INFO')
    identity = identities[0]
    if (canonical_name(identity.get('Name', '')) != name
            or identity.get('Version') != version):
        raise ValueError('Source archive identity does not match pinned requirement')
    if not notices:
        raise ValueError('Source archive contains no license or attribution files')
    return notices


def collect_sources(requirements_path, output_root, fetch=fetch_public):
    """Retain verified sdists and notices under output_root/python/name-version.

    A fetch callback returning bytes supports offline replay from retained
    release records and archives. No latest-version or wheel-only fallback is
    permitted. Paths in the returned manifest are relative to output_root.
    """
    output_root = Path(output_root)
    packages = []
    for name, version in exact_requirements(requirements_path):
        metadata_url = f'https://pypi.org/pypi/{name}/{version}/json'
        release_bytes = fetch(metadata_url)
        if len(release_bytes) > MAX_DOWNLOAD:
            raise ValueError('PyPI release metadata exceeds size limit')
        release = json.loads(release_bytes)
        info = release.get('info', {})
        if (canonical_name(info.get('name', '')) != name
                or info.get('version') != version):
            raise ValueError('PyPI release identity does not match pinned requirement')
        sources = [row for row in release.get('urls', []) if row.get('packagetype') == 'sdist']
        if len(sources) != 1:
            raise ValueError(f'{name}=={version} requires exactly one source distribution')
        source = sources[0]
        url = public_url(source['url'], {'files.pythonhosted.org'})
        filename = source['filename']
        if safe_name(filename) != filename or len(PurePosixPath(filename).parts) != 1:
            raise ValueError('Unsafe Python source archive filename')
        expected = source.get('digests', {}).get('sha256', '')
        if not re.fullmatch(r'[a-f0-9]{64}', expected):
            raise ValueError('PyPI source archive requires SHA256 digest')
        body = fetch(url)
        if sha256(body) != expected:
            raise ValueError(f'Source checksum mismatch: {name}=={version}')
        notices = inspect_source(body, filename, name, version)
        relative = Path('python') / f'{name}-{version}'
        destination = output_root / relative
        destination.mkdir(parents=True, exist_ok=True)
        (destination / filename).write_bytes(body)
        (destination / 'pypi-release.json').write_bytes(release_bytes)
        retained = []
        for member, content in sorted(notices.items()):
            target = relative / 'notices' / member
            (output_root / target).parent.mkdir(parents=True, exist_ok=True)
            (output_root / target).write_bytes(content)
            retained.append({'archive_member': member, 'path': target.as_posix(),
                             'bytes': len(content), 'sha256': sha256(content)})
        packages.append({'name': name, 'version': version,
                         'archive': (relative / filename).as_posix(),
                         'archive_url': url, 'sha256': expected, 'bytes': len(body),
                         'release_metadata': (relative / 'pypi-release.json').as_posix(),
                         'release_metadata_url': metadata_url,
                         'release_metadata_sha256': sha256(release_bytes),
                         'notices': retained})
    result = {'format': 'keep-python-sources-v1', 'packages': packages,
              'scope': 'Exact pinned sdists and nested notices; separate wheel-builder native sources are recorded by the enclosing bundle.'}
    output_root.mkdir(parents=True, exist_ok=True)
    (output_root / 'python-sources.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--requirements', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    result = collect_sources(args.requirements, args.output)
    print(json.dumps({'packages': len(result['packages']),
                      'source_bytes': sum(row['bytes'] for row in result['packages']),
                      'notice_files': sum(len(row['notices']) for row in result['packages'])}))


if __name__ == '__main__':
    main()
