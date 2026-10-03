#!/usr/bin/env python3
"""Retain preferred sources identified by verified native build attestations.

The caller verifies the original SLSA and Scout signatures and their native
subject before calling this module. Downloads are checked against the signed
material hashes; Alpine contexts are checked against reviewed immutable commits
and archive hashes. No downloaded recipe or archive member is executed.
"""
import base64
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import tarfile
import urllib.parse

ROOT = Path(__file__).resolve().parents[1]
SHA256 = re.compile(r'[a-f0-9]{64}')
MAX_DOWNLOAD = 512 * 1024 * 1024
SOURCE_MIRRORS = {
    'https://invisible-mirror.net/archives/ncurses/current/ncurses-6.6-20260516.tgz': {
        'origin': 'ncurses', 'version': '6.6_p20260516-r0',
        'sha256': '933438009f594f54656c53c7bc347a7e0ff21881700fc3db811086f7a3fd3b60',
        'url': 'https://distfiles.alpinelinux.org/distfiles/v3.24/ncurses-6.6-20260516.tgz',
    },
    'https://zlib.net/fossils/zlib-1.3.2.tar.gz': {
        'origin': 'zlib', 'version': '1.3.2-r0',
        'sha256': 'bb329a0a2cd0274d05519d61c667c062e06990d72e125ee2dfa8de64f0119d16',
        'url': 'https://distfiles.alpinelinux.org/distfiles/v3.24/zlib-1.3.2.tar.gz',
    },
}


def download(url):
    from source_download import download as fetch_bytes
    return fetch_bytes(url, maximum=MAX_DOWNLOAD, timeout=120)


def checked(body, algorithm, expected, label):
    if hashlib.new(algorithm, body).hexdigest() != expected:
        raise ValueError(label + ' ' + algorithm + ' mismatch')
    return body


def safe_path(value):
    path = PurePosixPath(value)
    if (not value or path.is_absolute() or '..' in path.parts or '\\' in value
            or '\x00' in value or re.match(r'^[A-Za-z]:', value)):
        raise ValueError('Unsafe source path')
    return str(path)


def archive_files(body, prefix):
    """Read bounded regular context files; retain link metadata as data only."""
    files, links, total = {}, [], 0
    with tarfile.open(fileobj=io.BytesIO(body), mode='r:*') as archive:
        seen = set()
        for number, member in enumerate(archive, 1):
            name = safe_path(member.name)
            if number > 250000 or name in seen:
                raise ValueError('Duplicate source archive entry or member limit')
            seen.add(name)
            if not name.startswith(prefix):
                continue
            relative = name[len(prefix):]
            if not relative:
                continue
            relative = safe_path(relative)
            if member.isfile():
                total += member.size
                if member.size > 8 * 1024 * 1024 or total > 64 * 1024 * 1024:
                    raise ValueError('Source context size limit')
                files[relative] = archive.extractfile(member).read()
            elif member.issym() or member.islnk():
                links.append({'path': relative, 'target': member.linkname,
                              'type': 'symlink' if member.issym() else 'hardlink'})
            elif not member.isdir():
                raise ValueError('Unsupported source context archive entry')
    return files, links


def scalar_vars(recipe):
    section = re.search(r'^vars:\n((?:[ \t]+[^\n]*\n)+)', recipe, re.M)
    if not section:
        raise ValueError('Provider recipe lacks version variables')
    values = {}
    for line in section[1].splitlines():
        match = re.fullmatch(r'\s+([A-Za-z0-9_-]+):\s*(.*?)\s*', line)
        if not match or match[1] in values:
            raise ValueError('Malformed or duplicate provider variable')
        value = match[2]
        if value.startswith('"'):
            value = json.loads(value)
        elif value.startswith("'") and value.endswith("'"):
            value = value[1:-1]
        values[match[1]] = value
    return values


def recipe_inputs(recipe):
    """The reviewed generated format has literal URL/path pairs, not shell."""
    result = {}
    lines = recipe.splitlines()
    for number, line in enumerate(lines):
        match = re.fullmatch(r'\s*- url: (\S+)\s*', line)
        if not match:
            continue
        url = match[1]
        paths = []
        for following in lines[number + 1:number + 12]:
            if re.match(r'\s*- url:', following):
                break
            path = re.fullmatch(r'\s+path: (\S+)\s*', following)
            if path:
                paths.append(path[1])
                break
        if len(paths) != 1 or url in result:
            raise ValueError('Ambiguous provider source URL/path')
        result[url] = paths[0]
    return result


def materials(statement):
    predicate = statement.get('predicate') or {}
    if statement.get('predicateType') == 'https://slsa.dev/provenance/v0.2':
        rows = predicate.get('materials')
    elif statement.get('predicateType') == 'https://slsa.dev/provenance/v1':
        rows = (predicate.get('buildDefinition') or {}).get('resolvedDependencies')
    else:
        raise ValueError('Unsupported signed build provenance version')
    if not isinstance(rows, list):
        raise ValueError('Missing signed build materials')
    result = {}
    for row in rows:
        uri = row.get('uri', '')
        if not isinstance(uri, str) or uri in result:
            raise ValueError('Duplicate or malformed signed material URI')
        result[uri] = row.get('digest', {})
    return result


def collect_sources(origin, architecture, slsa_statement, scout_statement,
                    output_root, fetch=download):
    name, version = origin['origin'], origin['version']
    if architecture not in {'amd64', 'arm64'} or not re.fullmatch(r'[a-z0-9][a-z0-9_.-]*', name):
        raise ValueError('Unsupported origin or architecture')
    if scout_statement.get('predicateType') != 'https://scout.docker.com/provenance/v0.1':
        raise ValueError('Missing verified Scout build recipe')
    encoded = scout_statement.get('predicate', {}).get('source_map', {}).get('dockerfile')
    if not isinstance(encoded, str) or len(encoded) > 4 * 1024 * 1024:
        raise ValueError('Missing or oversized signed provider recipe')
    signed_recipe = base64.b64decode(encoded, validate=True)
    text = signed_recipe.decode('utf-8')
    variables = scalar_vars(text)
    release_version, release_number = version.rsplit('-r', 1)
    if variables.get('VERSION') != release_version or variables.get('REL') != release_number:
        raise ValueError('Signed recipe version differs from reviewed installed package')
    inputs, signed_materials = recipe_inputs(text), materials(slsa_statement)
    recipe = origin['recipe']
    public_recipe = checked(fetch(recipe['url']), 'sha256', recipe['sha256'], 'Pinned public provider recipe')
    public_vars = scalar_vars(public_recipe.decode('utf-8'))
    for key in ('VERSION', 'COMMIT_SHA', 'REL', 'PIP_VERSION', 'PIP_CHECKSUM', 'WHEEL_VERSION', 'WHEEL_CHECKSUM'):
        if public_vars.get(key) != variables.get(key):
            raise ValueError('Signed and pinned public recipe identities differ: ' + key)
    root = Path(output_root)
    if root.is_symlink() or root.exists() and any(root.iterdir()):
        raise ValueError('Source output must be an empty directory without links')
    root.mkdir(parents=True, exist_ok=True)
    records, seen, links, excluded = [], set(), [], []

    def retain(path, body, url, role, source_path=None):
        path = safe_path(path)
        if path in seen:
            raise ValueError('Duplicate retained source filename')
        seen.add(path)
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(body)
        records.append({'path': path, 'url': url, 'role': role, 'bytes': len(body),
                        'sha256': hashlib.sha256(body).hexdigest(),
                        'source_path': source_path or path})

    retain('build/provider-signed.yaml', signed_recipe, None, 'signed-provider-build-recipe')
    retain('build/provider-public.yaml', public_recipe, recipe['url'], 'pinned-provider-build-recipe')
    sources = {}
    for uri, target in inputs.items():
        clean_uri = uri.removeprefix('git+')
        if clean_uri.startswith('https://github.com/alpinelinux/aports.git#'):
            continue
        digest = signed_materials.get(clean_uri, {}).get('sha256')
        if not isinstance(digest, str) or not SHA256.fullmatch(digest):
            raise ValueError('Recipe input lacks a signed source digest: ' + clean_uri)
        if clean_uri.endswith(('.apk', '.whl')):
            excluded.append({'url': clean_uri, 'sha256': digest,
                             'reason': 'Binary build input; corresponding preferred source is packaged separately.'})
            continue
        filename = safe_path(PurePosixPath(target).name)
        mirror = SOURCE_MIRRORS.get(clean_uri)
        if mirror and any((mirror['origin'] != name, mirror['version'] != version,
                           mirror['sha256'] != digest)):
            raise ValueError('Historical source mirror differs from the signed reviewed release')
        download_uri = mirror['url'] if mirror else clean_uri
        body = checked(fetch(download_uri), 'sha256', digest, 'Signed preferred source')
        if filename in sources:
            raise ValueError('Ambiguous upstream source filename')
        sources[filename] = body
        retain('sources/' + filename, body, download_uri, 'signed-upstream-source')
        if mirror:
            records[-1]['declared_url'] = clean_uri
            records[-1]['retrieval_method'] = 'reviewed-historical-mirror-identical-to-signed-material-hash'

    commit = recipe.get('upstream_commit')
    if commit:
        if variables.get('COMMIT_SHA') != commit:
            raise ValueError('Signed Alpine recipe commit differs from reviewed recipe')
        git_uri = 'https://github.com/alpinelinux/aports.git#' + commit
        if git_uri not in signed_materials or 'git+' + git_uri not in inputs:
            raise ValueError('Alpine recipe commit is absent from signed build materials')
        lock = json.loads((ROOT / 'docs/aports-source-lock.json').read_bytes())
        matches = [row for row in lock['aports'] if row['origin'] == name and row['commit'] == commit]
        if len(matches) != 1:
            raise ValueError('Alpine source context is not reviewed and pinned')
        entry = matches[0]
        archive = checked(fetch(entry['url']), 'sha256', entry['sha256'], 'Alpine build source archive')
        context, links = archive_files(archive, 'aports-' + commit + '/main/' + name + '/')
        apkbuild = context.get('APKBUILD')
        if apkbuild is None:
            raise ValueError('Matching Alpine APKBUILD is missing')
        checked(apkbuild, 'sha256', entry['apkbuild_sha256'], 'Alpine APKBUILD')
        blocks = re.findall(r'^sha512sums="\n([^\"]+)"$', apkbuild.decode('utf-8'), re.M)
        if len(blocks) != 1:
            raise ValueError('Missing complete Alpine source checksum list')
        checksum_names = set()
        for line in blocks[0].strip().splitlines():
            match = re.fullmatch(r'([a-f0-9]{128})  ([^\s]+)', line)
            if not match or match[2] in checksum_names:
                raise ValueError('Malformed or duplicate Alpine source checksum')
            checksum_names.add(match[2])
            body = context.get(match[2], sources.get(match[2]))
            if body is None:
                raise ValueError('Alpine source input is missing: ' + match[2])
            checked(body, 'sha512', match[1], 'Complete Alpine source input ' + match[2])
        retain('context/aports-' + commit + '.tar.gz', archive, entry['url'], 'complete-alpine-build-recipes')
        for filename, body in sorted(context.items()):
            retain('context/aports/main/' + name + '/' + filename, body, entry['url'],
                   'alpine-package-build-context')
    elif name == 'python-3.14':
        # CPython uses Docker's own complete recipe and patch tree, not APKBUILD.
        url = 'https://github.com/docker-hardened-images/catalog/archive/' + recipe['revision'] + '.tar.gz'
        lock = json.loads((ROOT / 'docs/aports-source-lock.json').read_bytes())
        matches = [row for row in lock.get('provider_contexts', [])
                   if row['origin'] == name and row['revision'] == recipe['revision'] and row['url'] == url]
        if len(matches) != 1:
            raise ValueError('Python provider patch context is not reviewed and pinned')
        archive = checked(fetch(url), 'sha256', matches[0]['sha256'], 'Python provider patch context')
        context, links = archive_files(archive, 'catalog-' + recipe['revision'] + '/package/apk/main/python/patch/')
        if not context:
            raise ValueError('Python provider patch context is missing')
        retain('context/catalog-' + recipe['revision'] + '.tar.gz', archive, url,
               'complete-provider-build-recipes')
        for filename, body in sorted(context.items()):
            retain('context/python/patch/' + filename, body, url, 'pinned-provider-python-patch')
        # The matching public recipe hash pins its chosen script and patch policy.
        # Patch contents additionally retain immutable catalog revision and hashes.
    else:
        raise ValueError('No reviewed package source context')
    if not sources and not commit:
        raise ValueError('No preferred source archive found')
    subject_digests = {s.get('digest', {}).get('sha256') for s in slsa_statement.get('subject', [])}
    if len(subject_digests) != 1 or not SHA256.fullmatch(next(iter(subject_digests)) or ''):
        raise ValueError('Build provenance must bind one native image digest')
    scout_digests = {s.get('digest', {}).get('sha256') for s in scout_statement.get('subject', [])}
    if scout_digests != subject_digests:
        raise ValueError('Scout and SLSA native subjects differ')
    manifest = {'schema': 1, 'origin': name, 'version': version, 'architecture': architecture,
        'provider_oci_binding': True, 'binding_method': 'signed-build-provenance',
        'source_image_digest': None, 'native_image_digest': 'sha256:' + next(iter(subject_digests)),
        'signed_statement_sha256': {key: hashlib.sha256(json.dumps(statement, sort_keys=True).encode()).hexdigest()
            for key, statement in (('slsa', slsa_statement), ('scout', scout_statement))},
        'recipe_revision': recipe['revision'], 'aports_commit': commit,
        'files': records, 'links_not_followed': links, 'excluded_binary_build_inputs': excluded,
        'coverage': 'Preferred upstream sources, every checksum-listed Alpine input and complete pinned package build context; original signed proof is retained separately.'}
    (root / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    return manifest
