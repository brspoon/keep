#!/usr/bin/env python3
"""Build a source-only distribution from checked native image acquisition.

Acquisition OCI images stay outside the archive. Source files, complete recipes,
original signature proof, notices and every omitted APK identity are retained.
The timezone exception is explicitly version/checksum bound, not OCI signed.
"""
import argparse
import gzip
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile
import tempfile
from urllib.parse import urlsplit
import urllib.request

from python_distribution_sources import canonical_name, collect_sources, exact_requirements, fetch_public, public_url
from build_patched_zlib import URL as ZLIB_URL, ARCHIVE_SHA256 as ZLIB_SHA
from collect_package_sources import expected_packages, match_package_output, resolve_native
from oci_source_materials import retain_materials, safe_name
from verify_source_proof import BASE_DIGEST, PREDICATE, ProofLayout, digest, verify_source_proof, verify_attestation_proof


ROOT = Path(__file__).resolve().parents[1]
MAX_DOWNLOAD = 64 * 1024 * 1024


def fetch_source(url):
    """Fetch locked PyPI/native/patch sources, checking HTTPS redirect hosts."""
    hosts = {'pypi.org', 'files.pythonhosted.org', 'github.com', 'codeload.github.com',
             'raw.githubusercontent.com'}
    public_url(url, hosts)
    request = urllib.request.Request(url, headers={'User-Agent': 'Keep-source-bundle/1'})
    with urllib.request.urlopen(request, timeout=60) as response:
        public_url(response.geturl(), hosts)
        body = response.read(MAX_DOWNLOAD + 1)
    if len(body) > MAX_DOWNLOAD:
        raise ValueError('Matching source download exceeds size limit')
    return body


def file_sha(path):
    hasher = hashlib.sha256()
    with Path(path).open('rb') as stream:
        while chunk := stream.read(1024 * 1024):
            hasher.update(chunk)
    return hasher.hexdigest()


def regular(root, relative):
    """Resolve a declared relative file without following any filesystem link."""
    name = safe_name(relative)
    path = Path(root)
    if path.is_symlink():
        raise ValueError('Source input root must not be a symlink')
    for part in PurePosixPath(name).parts:
        path = path / part
        if path.is_symlink():
            raise ValueError('Source input must not contain filesystem symlinks')
    if not path.is_file():
        raise ValueError('Declared source input is missing: ' + name)
    return path


def read_json(root, name):
    path = regular(root, name)
    if path.stat().st_size > 32 * 1024 * 1024:
        raise ValueError('Source metadata exceeds size limit')
    return json.loads(path.read_bytes())


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def copy_file(root, relative, target, expected=None, size=None):
    source = regular(root, relative)
    if expected is not None and file_sha(source) != expected:
        raise ValueError('Source file checksum mismatch: ' + relative)
    if size is not None and source.stat().st_size != size:
        raise ValueError('Source file size mismatch: ' + relative)
    target = Path(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)
    target.chmod(0o755 if source.stat().st_mode & 0o111 else 0o644)


def checked_download(url, expected, target, fetch=fetch_source):
    body = fetch(url)
    if hashlib.sha256(body).hexdigest() != expected:
        raise ValueError('Matching source checksum mismatch: ' + Path(target).name)
    Path(target).parent.mkdir(parents=True, exist_ok=True)
    Path(target).write_bytes(body)


def source_fetch(lock, fetch=fetch_public):
    pins = {(row['name'], row['version']): row for row in lock['python']}

    def locked_fetch(url):
        body = fetch(url)
        if url.startswith('https://pypi.org/pypi/'):
            release = json.loads(body)
            key = (canonical_name(release['info']['name']), release['info']['version'])
            row = pins.get(key)
            sources = [p for p in release['urls'] if p.get('packagetype') == 'sdist']
            if not row or len(sources) != 1 or any((
                    sources[0]['url'] != row['url'], sources[0]['filename'] != row['filename'],
                    sources[0]['digests']['sha256'] != row['sha256'])):
                raise ValueError('PyPI source identity differs from reviewed source lock')
        return body
    return locked_fetch


def check_native_wheels(inventory, lock, arch):
    native_arch = {'amd64': 'x86_64', 'arm64': 'aarch64'}[arch]
    distributions = {canonical_name(p['name']): p for p in inventory['python']}
    wheels = [w for w in lock['native_wheels']['native_wheels'] if w['architecture'] == native_arch]
    if {w['package'] for w in wheels} != {'cffi', 'argon2-cffi-bindings'} or len(wheels) != 2:
        raise ValueError('Both embedded native dependencies require reviewed source identities')
    for wheel in wheels:
        package = distributions.get(wheel['package'], {})
        if package.get('version') != wheel['version'] or not any(
                f['path'] == wheel['binary_path'] and f['sha256'] == wheel['binary_sha256']
                for f in package.get('native_files', [])):
            raise ValueError('Runtime native wheel differs from reviewed source: ' + wheel['package'])


def check_runtime(inventory, lock, os_lock, arch):
    """Cover exactly the packages in the candidate, including build identities."""
    if not isinstance(inventory, dict) or not inventory.get('python') or not inventory.get('os_packages'):
        raise ValueError('A complete candidate runtime inventory is required')
    actual_python = [(canonical_name(row['name']), row['version']) for row in inventory['python']]
    expected_python = [(row['name'], row['version']) for row in lock['python']]
    if (len({name for name, _ in actual_python}) != len(actual_python)
            or len({name for name, _ in expected_python}) != len(expected_python)
            or set(actual_python) != set(expected_python)):
        raise ValueError('Runtime Python packages differ from reviewed source lock')
    expected = {}
    for origin in os_lock['origins']:
        expected_packages(origin, arch)
        for row in origin['packages']:
            if row['name'] in expected:
                raise ValueError('Duplicate OS package in reviewed source map')
            expected[row['name']] = (row['version'], origin['origin'], row['build_commit'], row['license'])
    actual = {}
    for row in inventory['os_packages']:
        if row['name'] in actual:
            raise ValueError('Duplicate installed OS package')
        actual[row['name']] = (row['version'], row['origin'], row['build_commit'], row['license'])
    if actual != expected:
        raise ValueError('Runtime OS packages differ from reviewed source map')
    check_native_wheels(inventory, lock, arch)
    return {'python_packages': len(expected_python), 'os_packages': len(expected),
            'os_origins': len(os_lock['origins']), 'native_wheels': 2}


def check_runtime_notices(root, inventory, os_lock, arch):
    """Require complete committed OS notices inside the actual candidate."""
    directory = Path(root) / 'docs/licenses/os'
    manifest = read_json(directory, 'manifest.json')
    if manifest.get('schema') != 1 or manifest.get('ready_for_runtime_distribution') is not True:
        raise ValueError('Committed OS notices are incomplete for runtime distribution')
    expected = {row['origin']: row['version'] for row in os_lock['origins']}
    expected['expat-original-base'] = '2.8.4-r0'
    python = [row for row in os_lock['origins'] if row['origin'] == 'python-3.14']
    if python:
        expected['python-3.14-ensurepip'] = python[0]['version']
    installed = {row['path']: row for row in inventory.get('notices', [])}
    covered = set()
    seen = set()
    for notice in manifest.get('notices', []):
        name = safe_name(notice['notice_file'])
        if name in seen or '/' in name:
            raise ValueError('Duplicate or unsafe committed OS notice filename')
        seen.add(name)
        path = regular(directory, name)
        if file_sha(path) != notice['sha256'] or path.stat().st_size != notice['bytes']:
            raise ValueError('Committed OS notice differs from its manifest')
        runtime = installed.get('/app/licenses/os/' + name)
        if not runtime or runtime.get('sha256') != notice['sha256'] or runtime.get('bytes') != notice['bytes']:
            raise ValueError('Candidate runtime lacks the committed OS notice bytes: ' + name)
        for provenance in notice.get('provenance', []):
            origin = provenance.get('origin')
            if (origin in expected and provenance.get('version') == expected[origin]
                    and provenance.get('architecture') == arch):
                covered.add(origin)
    if covered != set(expected):
        raise ValueError('Committed runtime notices do not cover every reviewed OS origin and original Expat')
    return {'origins': len(covered), 'notices': len(seen), 'runtime_bytes_verified': True,
            'manifest_sha256': file_sha(directory / 'manifest.json')}


def copy_proof(source, destination, arch, proof):
    """Retain only proof blobs actually verified; no extraneous OCI files."""
    destination = Path(destination)
    for name in ('pinned-base-index.json', 'dhi-verification-key.pem',
                 'dhi-source-proof-reference.json', f'dhi-source-statement-{arch}.json'):
        copy_file(source, name, destination / name)
    layout = ProofLayout(Path(source) / 'dhi-source-proof-oci').verify()
    target = destination / 'dhi-source-proof-oci'
    for name in ('oci-layout', 'index.json'):
        copy_file(layout.root, name, target / name)
    for value, body in layout.blobs.items():
        path = target / 'blobs/sha256' / value.split(':')[1]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body)
    write_json(destination / 'source-proof-verification.json', proof)


def copy_attestation_proof(source, destination, proof):
    """Retain the original signed statement and only its verified OCI blobs."""
    destination = Path(destination)
    for name in ('pinned-base-index.json', 'dhi-verification-key.pem',
                 'attestation-reference.json', 'statement.json'):
        copy_file(source, name, destination / name)
    layout = ProofLayout(Path(source) / 'proof-oci').verify()
    target = destination / 'proof-oci'
    for name in ('oci-layout', 'index.json'):
        copy_file(layout.root, name, target / name)
    for value, body in layout.blobs.items():
        path = target / 'blobs/sha256' / value.split(':')[1]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body)
    write_json(destination / 'proof-verification.json', proof)


def verify_base_provenance(source, os_lock, arch):
    """Bind fallback/layer source identity to the actual signed native base."""
    proof_root = Path(source) / 'base-build-provenance'
    proof = verify_attestation_proof(proof_root, arch,
        expected_base_digest=BASE_DIGEST, expected_repository='dhi.io/python',
        expected_source_name='dhi/python', expected_native_digest=os_lock['base_native_digests'][arch],
        expected_predicate_type='https://slsa.dev/provenance/v1')
    original = regular(source, 'base-provenance.json').read_bytes()
    if regular(proof_root, 'statement.json').read_bytes() != original:
        raise ValueError('Original base provenance differs from its signed native statement')
    return json.loads(original), proof


def provenance_apks(material_root, manifest):
    """Identify binary inputs by URI and checksum in verified source provenance."""
    identities = {}

    def visit(value, provenance_file):
        if isinstance(value, list):
            for row in value:
                visit(row, provenance_file)
        elif isinstance(value, dict):
            uri = value.get('uri', '')
            sha = value.get('digest', {}).get('sha256', '') if isinstance(value.get('digest'), dict) else ''
            if (isinstance(uri, str) and urlsplit(uri).scheme in {'https', 'http'}
                    and urlsplit(uri).path.endswith('.apk') and re.fullmatch(r'[a-f0-9]{64}', sha)):
                identities.setdefault(sha, []).append({'uri': uri, 'digest': {'sha256': sha},
                                                       'provenance_file': provenance_file})
            for child in value.values():
                visit(child, provenance_file)

    for record in manifest['files']:
        if record['type'] != 'file' or not record['source_path'].startswith('opt/docker/provenance/'):
            continue
        path = regular(material_root, record['path'])
        if path.stat().st_size > 32 * 1024 * 1024:
            raise ValueError('Provider provenance input exceeds size limit')
        try:
            document = json.loads(path.read_bytes())
        except (ValueError, UnicodeDecodeError):
            continue  # Preserve non-JSON provenance rather than executing/parsing it.
        visit(document, record['path'])
    return identities


def omit_apk_materials(material_root, manifest):
    """Omit only binary material hashes explicitly declared by provenance."""
    identities = provenance_apks(material_root, manifest)
    excluded = []
    for record in manifest['files']:
        if (record['type'] == 'file' and record['source_path'].startswith('opt/docker/materials/')
                and record['sha256'] in identities):
            path = regular(material_root, record['path'])
            if file_sha(path) != record['sha256'] or path.stat().st_size != record['bytes']:
                raise ValueError('Binary material changed after OCI verification')
            path.unlink()
            record['original_retention_path'] = record.pop('path')
            record['type'] = 'excluded-binary'
            record['reason'] = 'Binary APK build input; preferred sources are retained separately.'
            record['provenance'] = identities[record['sha256']][0]
            record['provenance_occurrences'] = identities[record['sha256']]
            excluded.append(record['sha256'])
    manifest['excluded_binary_digests'] = sorted(set(excluded))
    manifest['retained_bytes'] = sum(row.get('bytes', 0) for row in manifest['files'] if row['type'] == 'file')
    write_json(Path(material_root) / 'material-manifest.json', manifest)
    return sorted(set(excluded))


def retain_signed_materials(source, destination, arch, *, proof, material_inspector=None):
    if material_inspector is None:
        from package_source_notices import inspect_package_materials
        material_inspector = inspect_package_materials
    material_root = Path(destination) / 'materials'
    manifest = retain_materials(Path(source) / 'dhi-source-oci', proof['source_image_digest'], material_root)
    excluded = omit_apk_materials(material_root, manifest)
    return material_root, excluded, material_inspector


def report_origins(report, os_lock, arch):
    origins = [row['origin'] for row in os_lock['origins']]
    results = report.get('origins', [])
    names = [row.get('origin') for row in results]
    if (report.get('format') != 'keep-os-package-source-acquisition-v1'
            or report.get('architecture') != arch or report.get('success') is not True
            or report.get('pending_origins') or len(set(names)) != len(names)
            or len(set(origins)) != len(origins) or set(names) != set(origins)
            or any(row.get('success') is not True for row in results)):
        raise ValueError('Every reviewed OS origin requires successful completed source acquisition')
    return {row['origin']: row for row in results}


def cached_manifest_fetch(source, manifest, roles):
    """Recheck public fallback inputs through their original pinned collector."""
    available = {}
    for row in manifest['files']:
        path = regular(source, row['path'])
        if file_sha(path) != row['sha256'] or path.stat().st_size != row['bytes']:
            raise ValueError('Retained source checksum mismatch: ' + row['path'])
        if row['role'] in roles:
            if row['url'] in available:
                raise ValueError('Ambiguous retained download URL')
            available[row['url']] = path

    def fetch(url):
        if url not in available:
            raise ValueError('Matching retained source input is missing: ' + url)
        return available[url].read_bytes()
    return fetch


def retain_timezone(source, destination, origin, result, arch):
    from tzdata_distribution_sources import collect_sources as collect_timezone
    if (origin['origin'] != 'tzdata' or result.get('provider_oci_binding') is not False
            or result.get('source_results') != [] or result.get('reviewed_apks') != expected_packages(origin, arch)
            or any(key in result for key in ('native_image_digest', 'image_index_digest'))
            or not any(row.get('failure_kind') == 'apk-binary-mismatch' for row in result.get('candidate_failures', []))):
        raise ValueError('Invalid unsigned timezone fallback')
    fallback = result['public_source_fallback']
    if fallback.get('provider_oci_binding') is not False:
        raise ValueError('Timezone fallback must not claim signed OCI binding')
    relative = safe_name(fallback['directory'])
    root = Path(source) / relative
    manifest = read_json(root, fallback['manifest'])
    if (manifest.get('architecture') != arch or manifest.get('provider_oci_binding') is not False
            or manifest.get('files') != fallback.get('files')
            or manifest.get('binding_method') != fallback.get('binding_method')):
        raise ValueError('Timezone fallback manifest differs from acquisition')
    fetch = cached_manifest_fetch(root, manifest, {'complete-alpine-build-recipes', 'upstream-source',
                                                  'pinned-provider-build-recipe', 'upstream-lgpl-license'})
    verified = collect_timezone(origin, arch, destination, fetch=fetch)
    if verified != manifest:
        raise ValueError('Timezone fallback provenance differs from checked source inputs')
    return {'origin': 'tzdata', 'version': origin['version'], 'provider_oci_binding': False,
            'apk_binary_match_verified': False, 'reviewed_apks': expected_packages(origin, arch),
            'binding_method': verified['binding_method'], 'files': len(verified['files'])}


def retain_output_groups(package_root, target, origin, result, arch):
    """Replay every APK match, including a narrowly reviewed noarch source."""
    from collect_package_sources import reviewed_output_groups
    expected = reviewed_output_groups(origin, arch)
    groups = result.get('output_groups')
    if groups is None:
        if len(expected) != 1 or expected[0].get('allow_noarch'):
            raise ValueError('Cross-platform noarch outputs require explicit acquisition groups')
        groups = [{**{key: result[key] for key in ('native_image_digest', 'image_index_digest',
                                                   'index_is_native_manifest', 'apk_matches')},
                   'architecture': arch, 'directory': 'package-output-oci', 'allow_noarch': False}]
    if len(groups) != len(expected):
        raise ValueError('Package output groups differ from reviewed architecture partition')
    checked, covered = [], set()
    all_expected = {row['name']: row for row in expected_packages(origin, arch)}
    for declared, plan in zip(groups, expected):
        group_arch = plan['architecture']
        names = [row['name'] for row in plan['packages']]
        allow_noarch = plan.get('allow_noarch', False)
        directory = 'package-output-oci' if group_arch == arch else f'package-output-{group_arch}-oci'
        if (declared.get('architecture') != group_arch or declared.get('directory') != directory
                or declared.get('allow_noarch') is not allow_noarch
                or set(names) & covered or any(name not in all_expected for name in names)):
            raise ValueError('Package output group is outside reviewed architecture partition')
        covered.update(names)
        matching_proofs = [row for row in result['source_results']
                           if row.get('proof_architecture', arch) == group_arch
                           and set(row.get('for_packages', all_expected)) == set(names)]
        if not matching_proofs:
            raise ValueError('Every package output group requires its own signed source proof')
        if result.get('output_groups') is None:
            raw_index = regular(package_root, 'package-image-index.json').read_bytes()
        else:
            proof_directory = safe_name(matching_proofs[0]['directory'])
            if matching_proofs[0].get('binding_method') == 'signed-build-provenance':
                proof_directory += '/slsa-proof'
            raw_index = regular(package_root, proof_directory + '/pinned-base-index.json').read_bytes()
        native, index_digest, direct = resolve_native(raw_index, group_arch)
        if (native != declared['native_image_digest'] or index_digest != declared['image_index_digest']
                or direct != declared['index_is_native_manifest']):
            raise ValueError('Package image index differs from matched acquisition')
        matched = match_package_output(package_root / safe_name(declared['directory']), native, group_arch,
                                       [all_expected[name] for name in names], allow_noarch=allow_noarch)
        if matched['apk_matches'] != declared.get('apk_matches'):
            raise ValueError('Package APK matches differ from original checked output')
        if result.get('output_groups') is None and matched != read_json(package_root, 'package-output-match.json'):
            raise ValueError('Package APK matches differ from original checked output')
        output = target / 'output-groups' / group_arch
        output.mkdir(parents=True, exist_ok=True)
        (output / 'package-image-index.json').write_bytes(raw_index)
        write_json(output / 'package-output-match.json', matched)
        checked.append({'architecture': group_arch, 'native_image_digest': native,
                        'image_index_digest': index_digest, 'index_is_native_manifest': direct,
                        'allow_noarch': allow_noarch, 'packages': names, 'matched': matched})
    if covered != set(all_expected):
        raise ValueError('Package output groups do not cover every reviewed APK exactly once')
    return checked


def retain_build_provenance(package_root, target, origin, row, group, arch):
    """Replay original signatures and complete preferred inputs, without an OCI-source claim."""
    from package_provenance_sources import collect_sources as collect_preferred
    from package_source_notices import inspect_build_provenance_sources
    root = Path(package_root) / safe_name(row['directory'])
    if (row.get('binding_method') != 'signed-build-provenance'
            or row.get('source_image_attestation') is not False
            or row.get('source_image_digest') is not None
            or row.get('native_image_digest') != group['native_image_digest']
            or row.get('signature_verified') is not True or row.get('provider_oci_binding') is not True
            or row.get('upstream_manifest') != 'upstream-sources/manifest.json'):
        raise ValueError('Invalid native build-provenance source identity')
    attestations = row.get('attestations', [])
    slsa = [value for value in attestations if value.get('predicate_type') in
            {'https://slsa.dev/provenance/v0.2', 'https://slsa.dev/provenance/v1'}]
    scout = [value for value in attestations if value.get('predicate_type') == 'https://scout.docker.com/provenance/v0.1']
    if len(attestations) != 2 or len(slsa) != 1 or len(scout) != 1:
        raise ValueError('Native preferred sources require both original signed SLSA and Scout statements')
    statements, proofs = {}, []
    for kind, declared, name in (('slsa', slsa[0], 'slsa-proof'), ('scout', scout[0], 'scout-proof')):
        if declared.get('directory') != name:
            raise ValueError('Unexpected build-provenance proof directory')
        proof_root = root / name
        checked = verify_attestation_proof(proof_root, group['architecture'],
            expected_base_digest=group['image_index_digest'], expected_repository=origin['image'],
            expected_source_name=origin['predicate_image_name'], expected_native_digest=group['native_image_digest'],
            expected_predicate_type=declared['predicate_type'], index_is_native_manifest=group['index_is_native_manifest'])
        if checked['attestation_digest'] != declared.get('attestation_digest'):
            raise ValueError('Build-provenance digest differs from acquired source identity')
        copy_attestation_proof(proof_root, Path(target) / name, checked)
        statements[kind] = read_json(proof_root, 'statement.json')
        proofs.append({'predicate_type': declared['predicate_type'], 'attestation_digest': checked['attestation_digest'],
                       'signature_verified': True, 'directory': name})
    upstream = root / 'upstream-sources'
    manifest = read_json(upstream, 'manifest.json')
    fetch = cached_manifest_fetch(upstream, manifest, {'signed-upstream-source', 'pinned-provider-build-recipe',
        'complete-alpine-build-recipes', 'complete-provider-build-recipes'})
    verified = collect_preferred(origin, group['architecture'], statements['slsa'], statements['scout'],
                                 Path(target) / 'upstream-sources', fetch=fetch)
    if verified != manifest:
        raise ValueError('Preferred source manifest differs from original signed build inputs')
    notices = inspect_build_provenance_sources(Path(target) / 'upstream-sources', Path(target) / 'notices',
        origin=origin['origin'], version=origin['version'], architecture=group['architecture'],
        native_image_digest=group['native_image_digest'], source_manifest_sha256=file_sha(upstream / 'manifest.json'))
    if notices.get('success') is not True:
        raise ValueError('Native build preferred-source/notice coverage is incomplete: ' + origin['origin'])
    return notices, {'binding_method': 'signed-build-provenance', 'source_image_attestation': False,
        'native_image_digest': group['native_image_digest'], 'attestations': proofs,
        'signature_verified': True, 'preferred_source_verified': True,
        'source_manifest_sha256': file_sha(upstream / 'manifest.json')}


def retain_openssl(source, destination, origin, result, arch, *, base_source, os_lock, runtime_inventory):
    from openssl_distribution_sources import collect_sources as collect_openssl
    if (origin['origin'] != 'openssl' or result.get('provider_oci_binding') is not False
            or result.get('source_results') != [] or result.get('reviewed_apks') != expected_packages(origin, arch)
            or any(key in result for key in ('native_image_digest', 'image_index_digest'))
            or not result.get('candidate_failures')
            or any(row.get('failure_kind') != 'registry-reference-not-found'
                   and not (row.get('registry_reference_not_found') is True and row.get('failure_kind') == 'registry-tag-list-error')
                   for row in result['candidate_failures'])):
        raise ValueError('Invalid reviewed OpenSSL public reconstruction')
    provenance, base_proof = verify_base_provenance(base_source, os_lock, arch)
    fallback = result['public_source_fallback']
    if fallback.get('provider_oci_binding') is not False:
        raise ValueError('OpenSSL public sources must not claim a package source-image binding')
    root = Path(source) / safe_name(fallback['directory'])
    manifest = read_json(root, fallback['manifest'])
    if manifest.get('files') != fallback.get('files') or manifest.get('binding_method') != fallback.get('binding_method'):
        raise ValueError('OpenSSL public manifest differs from acquired source identity')
    fetch = cached_manifest_fetch(root, manifest, {'complete-alpine-build-recipes', 'upstream-source',
                                                  'pinned-provider-build-recipe'})
    checked = collect_openssl(origin, arch, provenance, runtime_inventory, destination, fetch=fetch)
    if checked != manifest:
        raise ValueError('OpenSSL public sources differ from pinned native base/build identities')
    return {'origin': 'openssl', 'version': origin['version'], 'provider_oci_binding': False,
        'apk_binary_match_verified': False, 'reviewed_apks': expected_packages(origin, arch),
        'binding_method': checked['binding_method'], 'native_base_signature_verified': True,
        'native_base_attestation_digest': base_proof['attestation_digest'], 'files': len(checked['files'])}


def retain_packages(source, destination, os_lock, arch, *, material_inspector=None,
                    base_source=None, runtime_inventory=None):
    source, destination = Path(source), Path(destination)
    report = read_json(source, 'package-sources.json')
    results = report_origins(report, os_lock, arch)
    coverage = []
    for origin in os_lock['origins']:
        name = origin['origin']
        result = results[name]
        if result.get('architecture') != arch or result.get('version') != origin['version']:
            raise ValueError('Acquired origin identity differs from reviewed map')
        package_root = source / name
        if read_json(package_root, 'acquisition.json') != result:
            raise ValueError('Origin acquisition differs from completed report')
        target = destination / name
        copy_file(package_root, 'acquisition.json', target / 'acquisition.json')
        if result.get('provider_oci_binding') is False:
            if name == 'openssl' and base_source is not None and runtime_inventory is not None:
                coverage.append(retain_openssl(package_root, target / 'public-sources', origin, result, arch,
                    base_source=base_source, os_lock=os_lock, runtime_inventory=runtime_inventory))
            else:
                coverage.append(retain_timezone(package_root, target / 'public-sources', origin, result, arch))
            continue
        if result.get('provider_oci_binding') is not True or not result.get('source_results'):
            raise ValueError('Package origin has no signed corresponding sources')
        groups = retain_output_groups(package_root, target, origin, result, arch)
        copy_file(package_root, 'recipe.yaml', target / 'recipe.yaml', origin['recipe']['sha256'])
        proofs = []
        directories = set()
        for row in result['source_results']:
            relative = safe_name(row['directory'])
            if relative in directories:
                raise ValueError('Duplicate package source proof directory')
            directories.add(relative)
            proof_root = package_root / relative
            proof_arch = row.get('proof_architecture', arch)
            names = row.get('for_packages', [package['name'] for package in expected_packages(origin, arch)])
            selected = [group for group in groups if group['architecture'] == proof_arch
                        and set(group['packages']) == set(names)]
            if len(selected) != 1 or len(names) != len(set(names)):
                raise ValueError('Source proof does not cover one reviewed package output group')
            group = selected[0]
            proof_target = target / relative
            if row.get('binding_method') == 'signed-build-provenance':
                notices, retained_proof = retain_build_provenance(package_root, proof_target, origin, row, group, arch)
                notices['architecture'] = arch
                notices['proof_architecture'] = proof_arch
                notices['for_packages'] = names
                for notice in notices['notices']:
                    notice['provenance'].update({'architecture': arch, 'proof_architecture': proof_arch, 'for_packages': names})
                write_json(proof_target / 'notices/package-material-inventory.json', notices)
                proofs.append({**retained_proof, 'directory': relative, 'proof_architecture': proof_arch,
                    'for_packages': names, 'notice_inventory': str((proof_target / 'notices/package-material-inventory.json').relative_to(destination))})
                continue
            proof = verify_source_proof(proof_root, proof_arch, expected_base_digest=group['image_index_digest'],
                expected_native_digest=group['native_image_digest'], index_is_native_manifest=group['index_is_native_manifest'],
                expected_repository=origin['image'], expected_source_name=origin['predicate_image_name'])
            if (row.get('signature_verified') is not True or row.get('provider_oci_binding') is not True
                    or row['source_image_digest'] != proof['source_image_digest']
                    or row['attestation_digest'] != proof['attestation_digest']):
                raise ValueError('Acquired package source differs from offline signed proof')
            copy_proof(proof_root, proof_target, proof_arch, proof)
            materials, excluded, inspect = retain_signed_materials(proof_root, proof_target, proof_arch,
                proof=proof, material_inspector=material_inspector)
            notices = inspect(materials, proof_target / 'notices', origin=name,
                version=origin['version'], architecture=arch, expected_digest=proof['source_image_digest'],
                excluded_binary_digests=excluded)
            if notices.get('success') is not True:
                raise ValueError('Package preferred-source/notice coverage is incomplete: ' + name)
            # Attribution belongs to the target runtime. Its proof platform can
            # differ only for a reviewed noarch APK and remains explicit.
            notices['proof_architecture'] = proof_arch
            notices['for_packages'] = names
            for notice in notices['notices']:
                notice['provenance'].update({'proof_architecture': proof_arch, 'for_packages': names})
            write_json(proof_target / 'notices/package-material-inventory.json', notices)
            proofs.append({'source_image_digest': proof['source_image_digest'],
                           'attestation_digest': proof['attestation_digest'], 'directory': relative,
                           'proof_architecture': proof_arch, 'for_packages': names,
                           'signature_verified': True, 'preferred_source_verified': True,
                           'notice_inventory': str((proof_target / 'notices/package-material-inventory.json').relative_to(destination))})
        coverage.append({'origin': name, 'version': origin['version'], 'provider_oci_binding': True,
                         'apk_binary_match_verified': True,
                         'apk_matches': [row for group in groups for row in group['matched']['apk_matches']],
                         'output_groups': [{key: group[key] for key in ('architecture', 'allow_noarch', 'packages',
                                                                      'native_image_digest', 'image_index_digest')}
                                           for group in groups], 'sources': proofs})
    write_json(destination / 'package-sources.json', report)
    return coverage


def retain_original_base(source, destination, os_lock, arch, *, root=ROOT, fetch=fetch_source):
    """Keep pinned image proof and revalidate the overwritten Alpine package."""
    from alpine_distribution_sources import collect_sources as collect_original_expat
    proof = verify_source_proof(source, arch, expected_native_digest=os_lock['base_native_digests'][arch])
    if os_lock['base_index'].split('@')[1] != BASE_DIGEST:
        raise ValueError('OS map differs from pinned original image')
    copy_proof(source, destination / 'proof', arch, proof)
    provenance, base_proof = verify_base_provenance(source, os_lock, arch)
    subjects = provenance.get('subject', [])
    native = os_lock['base_native_digests'][arch].split(':')[1]
    if (provenance.get('predicateType') != 'https://slsa.dev/provenance/v1' or not subjects
            or any(row.get('digest', {}).get('sha256') != native for row in subjects)):
        raise ValueError('Original base provenance has the wrong pinned subject')
    copy_file(source, 'base-provenance.json', destination / 'base-provenance.json')
    copy_attestation_proof(Path(source) / 'base-build-provenance', destination / 'build-provenance', base_proof)
    copy_file(source, 'base-runtime-inventory.json', destination / 'base-runtime-inventory.json')
    manifest = read_json(source, 'manifest.json')
    expat_fetch = cached_manifest_fetch(source, manifest, {'complete-alpine-build-recipes', 'upstream-source'})
    checked = collect_original_expat(provenance, destination / 'original-expat', fetch=expat_fetch,
                                    base_inventory=read_json(source, 'base-runtime-inventory.json'))
    if checked != manifest:
        raise ValueError('Original Alpine expat source manifest differs from checked inputs')
    # The base source image describes image assembly. Its APK blobs add no
    # preferred sources beyond the package images above; keep just its recipes
    # and provenance, retaining omitted material identities in the manifest.
    materials = destination / 'assembly-materials'
    retained = retain_materials(Path(source) / 'dhi-source-oci', proof['source_image_digest'], materials)
    from base_python_distribution_sources import collect_sources as collect_base_python
    base_python_lock = read_json(root, 'docs/base-python-sources.json')
    apk_records = [row for row in retained['files'] if row['type'] == 'file'
                   and row['source_path'].startswith('opt/docker/materials/')
                   and row['sha256'] == base_python_lock['package']['apk_sha256'][arch]]
    if not apk_records:
        raise ValueError('Signed original base source materials lack the exact Python APK for ensurepip audit')
    base_python = collect_base_python(regular(materials, apk_records[0]['path']), arch,
        destination / 'ensurepip', lock=base_python_lock, fetch=fetch)
    omit_apk_materials(materials, retained)
    return {'native_image_digest': proof['native_image_digest'], 'source_image_digest': proof['source_image_digest'],
            'signature_verified': True, 'original_expat_version': '2.8.4-r0',
            'original_ensurepip': {'source_packages': len(base_python['source_packages']),
                'matched_python_modules': sum(len(row['matched_python_modules']) for row in base_python['wheels']),
                'native_resources': len(base_python['native_resources']),
                'native_build_sources': len(base_python['native_build_sources'])},
            'provenance_verification': 'Original native-base build provenance and source-reference signatures reverified offline.'}


def consolidate_notices(stage, os_lock, arch, runtime_inventory=None, *, selected_comment_paths=()):
    """Create the reusable notices-only union, including checked public inputs."""
    from package_source_notices import import_public_notices, merge_notice_bundles
    stage = Path(stage)
    public = stage / 'public-notices'
    provenance = read_json(stage / 'original-base', 'base-provenance.json')
    import_public_notices(stage / 'original-base/original-expat', public / 'original-expat',
                          origin='expat-original-base', architecture=arch, base_provenance=provenance)
    timezone = stage / 'os-packages/tzdata/public-sources'
    if timezone.exists():
        origins = [row for row in os_lock['origins'] if row['origin'] == 'tzdata']
        import_public_notices(timezone, public / 'tzdata', origin='tzdata', architecture=arch,
                              package_spec=origins[0])
    openssl = stage / 'os-packages/openssl/public-sources'
    if openssl.exists():
        origins = [row for row in os_lock['origins'] if row['origin'] == 'openssl']
        import_public_notices(openssl, public / 'openssl', origin='openssl', architecture=arch,
            package_spec=origins[0], base_provenance=provenance, runtime_inventory=runtime_inventory)
    bundles = sorted({path.parent for path in stage.rglob('package-material-inventory.json')})
    return merge_notice_bundles(bundles, stage / 'os-notices', selected_comment_paths=selected_comment_paths)


def reviewed_notice_comments(root, arch):
    """Select only reviewed headers attributed to this runtime architecture."""
    manifest = read_json(Path(root) / 'docs/licenses/os', 'manifest.json')
    declared = set(manifest.get('selected_source_comments', []))
    selected = set()
    for notice in manifest.get('notices', []):
        for provenance in notice.get('provenance', []):
            if provenance.get('architecture') != arch or provenance.get('discovery') != 'complete-leading-legal-comment':
                continue
            path = provenance.get('source_path')
            if not isinstance(path, str) or path not in declared:
                raise ValueError('Runtime source copyright header lacks explicit committed review')
            selected.add(path)
    return sorted(selected)


def check_generated_notices(root, generated, arch):
    """Every actual source notice must already ship as reviewed runtime bytes."""
    if generated.get('ready_for_runtime_distribution') is not True:
        raise ValueError('Actual preferred sources still need explicitly reviewed runtime attribution')
    committed = read_json(Path(root) / 'docs/licenses/os', 'manifest.json')
    by_hash = {row['sha256']: row for row in committed['notices']}
    for notice in generated['notices']:
        match = by_hash.get(notice['sha256'])
        if match is None or match.get('bytes') != notice['bytes']:
            raise ValueError('Actual preferred-source notice is missing from committed runtime notices')
        for provenance in notice['provenance']:
            identity = (provenance['origin'], provenance['version'], arch, provenance['source_path'])
            if not any((row.get('origin'), row.get('version'), row.get('architecture'), row.get('source_path')) == identity
                       for row in match['provenance']):
                raise ValueError('Actual source notice attribution differs from committed runtime provenance')


def file_records(directory):
    records = []
    for path in sorted(Path(directory).rglob('*')):
        if path == Path(directory) / 'MANIFEST.json':
            continue
        if path.is_symlink():
            raise ValueError('Source bundle must not contain filesystem symlinks')
        if path.is_file():
            records.append({'path': path.relative_to(directory).as_posix(),
                            'bytes': path.stat().st_size, 'sha256': file_sha(path)})
    return records


def archive_tree(directory, archive, name):
    """Produce a deterministic regular-file archive; links remain metadata."""
    directory, archive = Path(directory), Path(archive)
    with archive.open('wb') as raw, gzip.GzipFile(filename='', fileobj=raw, mode='wb', mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode='w|') as package:
            for path in sorted(directory.rglob('*')):
                if path.is_symlink():
                    raise ValueError('Source bundle must not contain filesystem symlinks')
                entry = tarfile.TarInfo(name + '/' + path.relative_to(directory).as_posix())
                entry.mtime = entry.uid = entry.gid = 0
                entry.uname = entry.gname = ''
                if path.is_dir():
                    entry.type, entry.mode = tarfile.DIRTYPE, 0o755
                    package.addfile(entry)
                elif path.is_file():
                    entry.size = path.stat().st_size
                    entry.mode = 0o755 if path.stat().st_mode & 0o111 else 0o644
                    with path.open('rb') as stream:
                        package.addfile(entry, stream)
                else:
                    raise ValueError('Unsupported source bundle entry')


def keep_source(root, destination):
    """Archive the exact committed Keep source whose recipes we distribute."""
    if subprocess.run(['git', 'diff', '--quiet', 'HEAD', '--'], cwd=root, check=False).returncode:
        raise ValueError('Commit Keep changes before packaging their matching source')
    revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
    destination.mkdir(parents=True, exist_ok=True)
    with (destination / 'keep-source.tar').open('wb') as stream:
        subprocess.run(['git', 'archive', '--format=tar', 'HEAD'], cwd=root, stdout=stream, check=True)
    for filename in ('Dockerfile', '.dockerignore', 'requirements.txt', 'LICENSE', 'VERSION',
                     'scripts/build_patched_zlib.py', 'scripts/patch_python_runtime.py',
                     'scripts/python_security_patches.json', 'docs/PYTHON_LICENSE.txt',
                     'docs/distribution-sources.json', 'docs/os-package-sources.json',
                     'docs/aports-source-lock.json', 'docs/base-python-sources.json'):
        copy_file(root, filename, destination / 'build' / filename)
    return revision


def build_bundle(sources, architecture, runtime_inventory, output, *, root=ROOT, fetch=fetch_source,
                 material_inspector=None):
    if architecture not in {'amd64', 'arm64'}:
        raise ValueError('Unsupported bundle architecture')
    if runtime_inventory is None:
        raise ValueError('A candidate runtime inventory is required')
    source, root, output = Path(sources), Path(root), Path(output)
    lock = read_json(root, 'docs/distribution-sources.json')
    os_lock = read_json(root, 'docs/os-package-sources.json')
    if (os_lock.get('schema_version') != 1 or architecture not in os_lock.get('architectures', [])
            or os_lock.get('source_predicate_type') != PREDICATE):
        raise ValueError('Unsupported reviewed OS source map')
    if set(exact_requirements(root / 'requirements.txt')) != {(row['name'], row['version']) for row in lock['python']}:
        raise ValueError('Requirements differ from reviewed source lock')
    inventory_path = Path(runtime_inventory)
    inventory = read_json(inventory_path.parent, inventory_path.name)
    counts = check_runtime(inventory, lock, os_lock, architecture)
    runtime_notices = check_runtime_notices(root, inventory, os_lock, architecture)
    version = regular(root, 'VERSION').read_text().strip()
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.+_-]*', version):
        raise ValueError('Unsafe Keep version for distribution archive')
    package_root = source / 'packages'
    if not package_root.exists():
        package_root = source / 'os-packages'
    # Separate staging prevents unrelated bootstrap files and failed acquisition
    # layouts from silently entering the final archive.
    with tempfile.TemporaryDirectory(prefix='keep-distribution-') as directory:
        stage = Path(directory)
        os_coverage = retain_packages(package_root, stage / 'os-packages', os_lock, architecture,
                                     material_inspector=material_inspector, base_source=source, runtime_inventory=inventory)
        base_coverage = retain_original_base(source, stage / 'original-base', os_lock, architecture, root=root, fetch=fetch)
        notice_union = consolidate_notices(stage, os_lock, architecture, inventory,
            selected_comment_paths=reviewed_notice_comments(root, architecture))
        check_generated_notices(root, notice_union, architecture)
        copy_file(inventory_path.parent, inventory_path.name, stage / 'runtime-inventory.json')
        python = collect_sources(root / 'requirements.txt', stage, fetch=source_fetch(lock, fetch))
        for material in lock['native_wheels']['materials']:
            checked_download(material['url'], material['sha256'], stage / 'native-wheels' / safe_name(material['path']), fetch)
        write_json(stage / 'native-wheels/manifest.json', lock['native_wheels'])
        for notice in lock['native_wheels']['supplemental_notices']:
            copy_file(root, notice['path'], stage / 'supplemental-notices' / Path(notice['path']).name,
                      notice['sha256'], notice['bytes'])
        copy_file(root, 'docs/licenses/README.md', stage / 'supplemental-notices/README.md')
        for path in sorted((root / 'docs/licenses/os').iterdir()):
            if path.is_symlink() or not path.is_file():
                raise ValueError('Committed OS notice directory must contain regular files only')
            copy_file(path.parent, path.name, stage / 'committed-runtime-os-notices' / path.name)
        checked_download(ZLIB_URL, ZLIB_SHA, stage / 'keep-patches/zlib-1.3.2.tar.gz', fetch)
        revision = keep_source(root, stage / 'keep')
        provider_bound = [row['origin'] for row in os_coverage if row['provider_oci_binding']]
        public_fallbacks = [row['origin'] for row in os_coverage if not row['provider_oci_binding']]
        coverage = {'runtime': counts, 'runtime_notices': runtime_notices,
                    'source_notice_union': {'notices': len(notice_union['notices']),
                                           'origins_needing_explicit_attribution': notice_union['origins_needing_explicit_attribution']},
                    'original_base': base_coverage, 'os_origins': os_coverage,
                    'provider_bound_origins': provider_bound, 'public_source_fallbacks': public_fallbacks,
                    'python_source_packages': len(python['packages']), 'native_source_materials': len(lock['native_wheels']['materials']),
                    'limitations': 'Reviewed public fallbacks are explicitly listed and have no historical package-source OCI binding. Signed build provenance is distinguished from source-image attestations. APK byte matches were checked against acquisition images before binary layouts were omitted. Links and original modes remain in material manifests for reconstruction. Signatures do not prove Rekor inclusion or legal clearance.'}
        write_json(stage / 'SOURCE-COVERAGE.json', coverage)
        manifest = {'format': 'keep-container-source-bundle-v1', 'version': version,
                    'revision': revision, 'architecture': architecture,
                    'base_source_digest': base_coverage['source_image_digest'],
                    'coverage': coverage, 'files': file_records(stage)}
        write_json(stage / 'MANIFEST.json', manifest)
        output.mkdir(parents=True, exist_ok=True)
        name = f'keep-{version}-source-materials-{architecture}'
        archive = output / (name + '.tar.gz')
        archive_tree(stage, archive, name)
        sha = file_sha(archive)
        (output / (archive.name + '.sha256')).write_text(sha + '  ' + archive.name + '\n')
    return {'archive': archive.name, 'bytes': archive.stat().st_size, 'sha256': sha,
            'revision': revision, 'architecture': architecture, 'coverage': counts,
            'provider_bound_origins': len(provider_bound), 'public_source_fallbacks': public_fallbacks}


def prepare_notices(sources, architecture, runtime_inventory, output, *, root=ROOT,
                    fetch=fetch_source, material_inspector=None):
    """Generate reviewable runtime notices before their candidate-image rebuild.

    Signature, APK, preferred-source and package-inventory checks still apply.
    Committed notice bytes and clean Git are gates for the later final archive,
    so this preparation does not claim a distributable image or final bundle.
    """
    if architecture not in {'amd64', 'arm64'} or runtime_inventory is None:
        raise ValueError('Notice preparation requires architecture and candidate runtime inventory')
    source, root, output = Path(sources), Path(root), Path(output)
    if output.is_symlink() or output.exists() and any(output.iterdir()):
        raise ValueError('Notice preparation output must be an empty directory without symlinks')
    lock = read_json(root, 'docs/distribution-sources.json')
    os_lock = read_json(root, 'docs/os-package-sources.json')
    inventory_path = Path(runtime_inventory)
    inventory = read_json(inventory_path.parent, inventory_path.name)
    counts = check_runtime(inventory, lock, os_lock, architecture)
    package_root = source / 'packages'
    if not package_root.exists():
        package_root = source / 'os-packages'
    output.mkdir(parents=True, exist_ok=True)
    coverage = retain_packages(package_root, output / 'os-packages', os_lock, architecture,
        material_inspector=material_inspector, base_source=source, runtime_inventory=inventory)
    base = retain_original_base(source, output / 'original-base', os_lock, architecture, root=root, fetch=fetch)
    notices = consolidate_notices(output, os_lock, architecture, inventory)
    report = {'format': 'keep-runtime-notice-preparation-v1', 'architecture': architecture,
        'runtime': counts, 'os_origins': coverage, 'original_base': base,
        'notices': len(notices['notices']), 'notice_directory': 'os-notices',
        'ready_for_runtime_distribution': notices['ready_for_runtime_distribution'],
        'origins_needing_explicit_attribution': notices['origins_needing_explicit_attribution'],
        'limitations': 'Source and notice preparation only; final archive additionally requires committed notices verified in a rebuilt candidate and clean committed Keep source.'}
    write_json(output / 'NOTICE-PREPARATION.json', report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sources', required=True)
    parser.add_argument('--architecture', choices=('amd64', 'arm64'), required=True)
    parser.add_argument('--runtime-inventory', required=True)
    parser.add_argument('--output', default='distribution')
    parser.add_argument('--prepare-notices', action='store_true',
                        help='Prepare reviewable notices before committing them and rebuilding the candidate')
    args = parser.parse_args()
    operation = prepare_notices if args.prepare_notices else build_bundle
    print(json.dumps(operation(args.sources, args.architecture, args.runtime_inventory, args.output)))


if __name__ == '__main__':
    main()
