#!/usr/bin/env python3
"""Acquire signed OS package sources only after matching the reviewed APK bytes.

Tags are discovery pointers, never matching-source evidence. Every installed
APK checksum must occur as a regular file in the resolved native package image.
Full acquisition OCI layouts and original signatures are retained; the release
bundle may separately retain source contexts without unrelated tool binaries.
"""
import argparse
import gzip
import hashlib
import io
import json
import lzma
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request

from image_distribution import redacted
from inspect_candidate import BASE, DIRECT, HASHES, download
from oci_source_materials import SourceInventory, open_layer, safe_name
from tzdata_distribution_sources import collect_sources as collect_timezone_sources
from verify_source_proof import KEY_SHA256, PREDICATE, digest, read_regular, verify_attestation_proof, verify_source_proof
from source_concurrency import ordered_map, source_workers


ROOT = Path(__file__).resolve().parents[1]
ACQUISITION_ERRORS = (ValueError, KeyError, OSError, EOFError, tarfile.TarError,
                      lzma.LZMAError, subprocess.CalledProcessError)


class PackageBinaryMismatch(ValueError):
    """A resolved package image lacks one or more reviewed APK byte sequences."""


SLSA_PREDICATES = ('https://slsa.dev/provenance/v0.2', 'https://slsa.dev/provenance/v1')
SCOUT_PROVENANCE = 'https://scout.docker.com/provenance/v0.1'


def expected_packages(origin, architecture):
    packages = []
    names = set()
    for package in origin.get('packages', []):
        name = package.get('name')
        expected = package.get('binaries', {}).get(architecture, {}).get('sha256', '')
        if (not isinstance(name, str) or not re.fullmatch(r'[a-z0-9][a-z0-9+_.-]*', name)
                or name in names or package.get('version') != origin['version']
                or not re.fullmatch(r'[a-f0-9]{64}', expected)):
            raise ValueError('Missing or ambiguous reviewed APK identity')
        names.add(name)
        packages.append({'name': name, 'version': package['version'], 'sha256': expected})
    if not packages:
        raise ValueError('Origin has no reviewed installed APKs')
    return packages


def resolve_native(raw, architecture):
    manifest = json.loads(raw)
    if manifest.get('schemaVersion') != 2:
        raise ValueError('Unsupported package image manifest')
    if 'manifests' in manifest:
        matches = [entry for entry in manifest['manifests']
                   if entry.get('platform', {}).get('architecture') == architecture
                   and entry.get('platform', {}).get('os') == 'linux']
        if len(matches) != 1:
            raise ValueError('Package index has no unique native platform')
        native = matches[0]['digest']
        direct = False
    elif 'layers' in manifest and 'config' in manifest:
        native = digest(raw)
        direct = True
    else:
        raise ValueError('Package reference is not a native image or platform index')
    if not re.fullmatch(r'sha256:[a-f0-9]{64}', native):
        raise ValueError('Malformed native package image digest')
    return native, digest(raw), direct


def reviewed_output_groups(origin, architecture):
    """Partition target APKs by their reviewed output platform, never by name alone."""
    packages = expected_packages(origin, architecture)
    mapping = origin.get('architecture_independent_outputs', {})
    if mapping and (origin.get('origin') != 'ncurses'
                    or origin.get('version') != '6.6_p20260516-r0'
                    or mapping != {'ncurses-terminfo-base': 'arm64'}):
        raise ValueError('Unreviewed architecture-independent package output exception')
    if any(name not in {package['name'] for package in packages} for name in mapping):
        raise ValueError('Architecture-independent output is not an installed package')
    groups = {}
    for package in packages:
        actual = mapping.get(package['name'], architecture)
        groups.setdefault(actual, []).append(package)
    return [{'architecture': actual,
             'directory': 'package-output-oci' if actual == architecture else 'package-output-' + actual + '-oci',
             'packages': groups[actual],
             'allow_noarch': actual != architecture}
            for actual in sorted(groups, key=lambda actual: (actual != architecture, actual))]


def noarch_identity(stream, package):
    """Read APK metadata across concatenated gzip/tar members without extracting."""
    stream.seek(0)
    with gzip.GzipFile(fileobj=stream, mode='rb') as compressed:
        decoded = compressed.read(128 * 1024 * 1024 + 1)
    if len(decoded) > 128 * 1024 * 1024:
        raise ValueError('Architecture-independent APK exceeds decoded-size limit')
    metadata = []
    with tarfile.open(fileobj=io.BytesIO(decoded), mode='r:', ignore_zeros=True) as archive:
        for count, member in enumerate(archive, 1):
            name = safe_name(member.name)
            if count > 100000:
                raise ValueError('Architecture-independent APK exceeds member limit')
            if name == '.PKGINFO':
                if not member.isfile() or member.size > 65536:
                    raise ValueError('Require regular bounded architecture-independent APK metadata')
                metadata.append(archive.extractfile(member).read())
    if len(metadata) != 1:
        raise ValueError('Require one original architecture-independent APK .PKGINFO')
    fields = {}
    for line in metadata[0].decode('utf-8').splitlines():
        if ' = ' not in line:
            continue
        key, value = line.split(' = ', 1)
        if key in {'pkgname', 'pkgver', 'arch'}:
            if key in fields:
                raise ValueError('Duplicate architecture-independent APK identity')
            fields[key] = value
    if fields != {'pkgname': package['name'], 'pkgver': package['version'], 'arch': 'noarch'}:
        raise ValueError('Cross-platform APK must have exact name/version and arch=noarch')
    return {**fields, 'metadata_sha256': hashlib.sha256(metadata[0]).hexdigest()}


def match_package_output(layout, native, architecture, packages, *, allow_noarch=False):
    """Hash all regular layer members; retain matching APK locations as proof."""
    layout = Path(layout)
    if layout.is_symlink() or (layout / 'index.json').is_symlink():
        raise ValueError('Package-output OCI must not contain index symlinks')
    marker = json.loads((layout / 'oci-layout').read_text())
    if marker.get('imageLayoutVersion') != '1.0.0':
        raise ValueError('Unsupported package-output OCI layout')
    index = json.loads((layout / 'index.json').read_text())
    if index.get('schemaVersion') != 2 or not index.get('manifests'):
        raise ValueError('Missing package-output OCI index')
    inventory = SourceInventory(layout, layout.parent / 'unused-notices',
                                max_declared_bytes=4 * 1024 ** 3)
    for descriptor in index['manifests']:
        inventory.walk(descriptor)
    manifest = inventory.manifests.get(native)
    if not manifest or 'layers' not in manifest or not manifest.get('config'):
        raise ValueError('Resolved native package output is not retained')
    config = json.loads(inventory.blob(manifest['config']).read_bytes())
    if config.get('architecture') != architecture or config.get('os') != 'linux':
        raise ValueError('Package output configuration has the wrong native platform')
    matches = {package['sha256']: [] for package in packages}
    for layer in manifest['layers']:
        if 'tar' not in layer.get('mediaType', ''):
            raise ValueError('Unsupported package-output layer format')
        with open_layer(inventory.blob(layer), layer.get('mediaType', '')) as stream, tarfile.open(fileobj=stream, mode='r|*') as archive:
            for member in archive:
                name = safe_name(member.name)
                if not inventory.budget(name, member.size):
                    raise ValueError('Package-output APK inventory limit reached')
                if not member.isfile():
                    continue
                hasher = hashlib.sha256()
                # Cross-platform acceptance requires inspecting the exact APK
                # bytes after hashing. Spooling avoids holding an output layer
                # or a large package in memory and never executes its contents.
                with tempfile.SpooledTemporaryFile(max_size=8 * 1024 * 1024) as retained:
                    with archive.extractfile(member) as content:
                        while chunk := content.read(1024 * 1024):
                            hasher.update(chunk)
                            if allow_noarch:
                                retained.write(chunk)
                    value = hasher.hexdigest()
                    if value in matches:
                        item = {'layer_digest': layer['digest'], 'path': name, 'bytes': member.size}
                        if allow_noarch:
                            package = next(row for row in packages if row['sha256'] == value)
                            item['package_identity'] = noarch_identity(retained, package)
                        matches[value].append(item)
    missing = [package['name'] for package in packages if not matches[package['sha256']]]
    if missing:
        raise PackageBinaryMismatch('Native package output does not contain reviewed APK bytes: ' + ', '.join(missing))
    return {'native_image_digest': native, 'architecture': architecture,
            'all_apks_matched': True, 'allow_noarch': allow_noarch,
            'apk_matches': [{**package, 'matches': matches[package['sha256']]} for package in packages],
            'verified_blobs': [{'digest': key, 'bytes': value}
                               for key, value in sorted(inventory.verified.items())]}


def package_statement(raw, native, source_name):
    statement = json.loads(raw)
    subjects = statement.get('subject', [])
    source = statement.get('predicate', {}).get('source', {})
    if (statement.get('predicateType') != PREDICATE or not subjects
            or any(row.get('digest', {}).get('sha256') != native.split(':', 1)[1] for row in subjects)):
        raise ValueError('Package source statement has the wrong native subject')
    if source.get('name') != source_name or not re.fullmatch(r'sha256:[a-f0-9]{64}', source.get('digest', '')):
        raise ValueError('Package source statement has the wrong source repository/digest')
    return statement


def verify_retained_source(layout, expected):
    layout = Path(layout)
    if layout.is_symlink() or (layout / 'index.json').is_symlink():
        raise ValueError('Retained package-source OCI must not contain index symlinks')
    if json.loads((layout / 'oci-layout').read_text()).get('imageLayoutVersion') != '1.0.0':
        raise ValueError('Unsupported retained package-source OCI layout')
    index = json.loads((layout / 'index.json').read_text())
    if index.get('schemaVersion') != 2 or not index.get('manifests'):
        raise ValueError('Retained package-source OCI index is missing')
    inventory = SourceInventory(layout, layout.parent / 'unused-source-notices')
    for descriptor in index['manifests']:
        inventory.walk(descriptor)
    if expected not in inventory.visited:
        raise ValueError('Retained source image differs from signed package-source digest')
    return {'source_image_digest': expected, 'binding_verified': True,
            'verified_blobs': [{'digest': key, 'bytes': value}
                               for key, value in sorted(inventory.verified.items())]}


def retain_recipe(origin, root):
    recipe = origin['recipe']
    expected = recipe['sha256']
    if (not re.fullmatch(r'[a-f0-9]{64}', expected)
            or not re.fullmatch(r'https://raw\.githubusercontent\.com/docker-hardened-images/catalog/'
                                r'[a-f0-9]{40}/package/[A-Za-z0-9/_.-]+\.yaml', recipe['url'])):
        raise ValueError('Unreviewed public package recipe reference')
    with urllib.request.urlopen(recipe['url'], timeout=60) as response:
        body = response.read(4 * 1024 * 1024 + 1)
    if len(body) > 4 * 1024 * 1024 or hashlib.sha256(body).hexdigest() != expected:
        raise ValueError('Pinned package recipe checksum mismatch')
    (root / 'recipe.yaml').write_bytes(body)
    return {'path': 'recipe.yaml', 'sha256': expected, 'url': recipe['url']}


class Registry:
    def __init__(self, regctl, cosign, key, env):
        # Acquisition commands only read the completed temporary login config.
        # Each command runs in its own process and each origin has its own OCI
        # output directories; no registry/client state is written by workers.
        self.regctl, self.cosign, self.key, self.env = str(regctl), str(cosign), Path(key), dict(env)

    def manifest(self, reference):
        return subprocess.check_output([self.regctl, 'manifest', 'get', reference,
                                        '--format', 'raw-body'], env=self.env, stderr=subprocess.PIPE)

    def tags(self, repository):
        raw = subprocess.check_output([self.regctl, 'tag', 'ls', repository], env=self.env,
                                      stderr=subprocess.PIPE)
        return [line.strip() for line in raw.decode('utf-8').splitlines() if line.strip()]

    def referrers(self, reference, *, external=None):
        command = [self.regctl, 'artifact', 'list', reference, '--format', 'body']
        if external:
            command += ['--external', external]
        return json.loads(subprocess.check_output(command, env=self.env, stderr=subprocess.PIPE))

    def verify(self, reference):
        return subprocess.check_output([self.cosign, 'verify', reference, '--key', str(self.key),
            '--experimental-oci11', '--insecure-ignore-tlog=true'], env=self.env)

    def statement(self, reference):
        return subprocess.check_output([self.regctl, 'artifact', 'get', reference], env=self.env)

    def copy(self, reference, destination, *, referrers=False):
        command = [self.regctl, 'image', 'copy', reference,
                   'ocidir://' + str(Path(destination).resolve()) + ':retained']
        if referrers:
            command.append('--referrers')
        subprocess.run(command, env=self.env, check=True)


def acquire_signed_sources(origin, group, raw_index, root, registry):
    repository, source_name = origin['image'], origin['predicate_image_name']
    architecture, native = group['architecture'], group['native_image_digest']
    native_reference = repository + '@' + native
    referrers = registry.referrers(native_reference)
    (root / ('package-native-referrers-' + architecture + '.json')).write_text(json.dumps(referrers, indent=2) + '\n')
    descriptors = [row for row in referrers.get('manifests', [])
                   if PREDICATE in row.get('annotations', {}).values()]
    if not descriptors:
        return acquire_build_provenance_sources(origin, group, raw_index, root, registry, referrers)
    source_results, source_failures = [], []
    for descriptor in descriptors:
        try:
            value = descriptor.get('digest', '')
            if not re.fullmatch(r'sha256:[a-f0-9]{64}', value):
                raise ValueError('Malformed package source-attestation digest')
            attestation_reference = repository + '@' + value
            claims_bytes = registry.verify(attestation_reference)
            claims = json.loads(claims_bytes)
            if not claims or not all(row.get('critical', {}).get('image', {}).get('docker-manifest-digest')
                                     == value for row in claims):
                raise ValueError('Cosign claims do not cover package source attestation')
            raw_statement = registry.statement(attestation_reference)
            statement = package_statement(raw_statement, native, source_name)
            source_reference = repository + '@' + statement['predicate']['source']['digest']
            source_directory = root / 'sources' / value.split(':', 1)[1]
            source_directory.mkdir(parents=True, exist_ok=True)
            shutil.copy2(registry.key, source_directory / 'dhi-verification-key.pem')
            (source_directory / 'pinned-base-index.json').write_bytes(raw_index)
            (source_directory / f'dhi-source-statement-{architecture}.json').write_bytes(raw_statement)
            (source_directory / f'dhi-source-verification-claims-{architecture}.json').write_bytes(claims_bytes)
            (source_directory / 'dhi-source-proof-reference.json').write_text(json.dumps({
                'attestation': attestation_reference, 'source': source_reference,
                'native_subject': native.split(':', 1)[1], 'key_sha256': KEY_SHA256}, indent=2) + '\n')
            registry.copy(attestation_reference, source_directory / 'dhi-source-proof-oci', referrers=True)
            proof = verify_source_proof(source_directory, architecture,
                expected_base_digest=group['image_index_digest'], expected_repository=repository,
                expected_source_name=source_name, expected_native_digest=native,
                index_is_native_manifest=group['index_is_native_manifest'])
            (source_directory / 'source-proof-verification.json').write_text(json.dumps(proof, indent=2) + '\n')
            registry.copy(source_reference, source_directory / 'dhi-source-oci')
            source_content = verify_retained_source(source_directory / 'dhi-source-oci', proof['source_image_digest'])
            (source_directory / 'source-layout-verification.json').write_text(json.dumps(source_content, indent=2) + '\n')
            source_results.append({'directory': str(source_directory.relative_to(root)),
                'source_image_digest': proof['source_image_digest'], 'attestation_digest': value,
                'signature_verified': True, 'provider_oci_binding': True,
                'proof_architecture': architecture, 'native_image_digest': native,
                'for_packages': [package['name'] for package in group['apk_matches']]})
        except ACQUISITION_ERRORS as error:
            source_failures.append({'attestation_digest': descriptor.get('digest'),
                                    'error': type(error).__name__ + ': ' + str(error)})
    if not source_results:
        raise ValueError('No usable signed sources for matching package APKs: ' + json.dumps(source_failures))
    return source_results, source_failures


def acquire_build_attestation(origin, group, raw_index, directory, registry, descriptors, predicates):
    """Retain and replay an original signed build attestation before reading it."""
    failures = []
    for predicate in predicates:
        for descriptor in descriptors:
            if predicate not in descriptor.get('annotations', {}).values():
                continue
            value = descriptor.get('digest', '')
            try:
                if not re.fullmatch(r'sha256:[a-f0-9]{64}', value):
                    raise ValueError('Malformed package build-provenance digest')
                reference = origin['image'] + '@' + value
                claims_bytes = registry.verify(reference)
                claims = json.loads(claims_bytes)
                if not claims or not all(row.get('critical', {}).get('image', {}).get('docker-manifest-digest')
                                         == value for row in claims):
                    raise ValueError('Cosign claims do not cover package build provenance')
                raw_statement = registry.statement(reference)
                directory.mkdir(parents=True, exist_ok=True)
                shutil.copy2(registry.key, directory / 'dhi-verification-key.pem')
                (directory / 'pinned-base-index.json').write_bytes(raw_index)
                (directory / 'statement.json').write_bytes(raw_statement)
                (directory / 'verification-claims.json').write_bytes(claims_bytes)
                (directory / 'attestation-reference.json').write_text(json.dumps({
                    'attestation': reference, 'native_subject': group['native_image_digest'],
                    'predicate_type': predicate, 'key_sha256': KEY_SHA256}, indent=2) + '\n')
                registry.copy(reference, directory / 'proof-oci', referrers=True)
                proof = verify_attestation_proof(directory, group['architecture'],
                    expected_base_digest=group['image_index_digest'], expected_repository=origin['image'],
                    expected_source_name=origin['predicate_image_name'],
                    expected_native_digest=group['native_image_digest'], expected_predicate_type=predicate,
                    index_is_native_manifest=group['index_is_native_manifest'])
                (directory / 'proof-verification.json').write_text(json.dumps(proof, indent=2) + '\n')
                return json.loads(raw_statement), {'directory': directory.name,
                    'predicate_type': predicate, 'attestation_digest': value}, failures
            except ACQUISITION_ERRORS as error:
                failures.append({'attestation_digest': value, 'predicate_type': predicate,
                                 'error': type(error).__name__ + ': ' + str(error)})
    raise ValueError('No usable original signed package build provenance for ' + ', '.join(predicates)
                     + ': ' + json.dumps(failures))


def acquire_build_provenance_sources(origin, group, raw_index, root, registry, referrers):
    """Acquire sources named by signed build inputs; no source-image claim."""
    descriptors = referrers.get('manifests', [])
    directory = root / 'build-provenance' / group['native_image_digest'].split(':', 1)[1]
    directory.mkdir(parents=True, exist_ok=True)
    (directory / 'pinned-base-index.json').write_bytes(raw_index)
    slsa, slsa_proof, slsa_failures = acquire_build_attestation(origin, group, raw_index,
        directory / 'slsa-proof', registry, descriptors, SLSA_PREDICATES)
    scout, scout_proof, scout_failures = acquire_build_attestation(origin, group, raw_index,
        directory / 'scout-proof', registry, descriptors, (SCOUT_PROVENANCE,))
    from package_provenance_sources import collect_sources as collect_provenance_sources
    manifest = collect_provenance_sources(origin, group['architecture'], slsa, scout,
                                          directory / 'upstream-sources')
    result = {'directory': str(directory.relative_to(root)),
              'binding_method': 'signed-build-provenance', 'signature_verified': True,
              'provider_oci_binding': True, 'source_image_attestation': False,
              'proof_architecture': group['architecture'], 'native_image_digest': group['native_image_digest'],
              'for_packages': [package['name'] for package in group['apk_matches']],
              'upstream_manifest': 'upstream-sources/manifest.json',
              'attestations': [slsa_proof, scout_proof], 'source_materials': manifest.get('source_materials', [])}
    (directory / 'acquisition.json').write_text(json.dumps(redacted(result), indent=2) + '\n')
    return [result], slsa_failures + scout_failures


def registry_not_found(error):
    if not isinstance(error, subprocess.CalledProcessError):
        return False
    value = error.stderr or b''
    if isinstance(value, bytes):
        value = value.decode('utf-8', errors='replace')
    return any(text in value.lower() for text in ('404', 'not found', 'manifest_unknown', 'name_unknown'))


def discover_openssl_candidates(origin, registry, root):
    """Discover existing aliases only; every APK still requires exact matching."""
    tags = registry.tags(origin['image'])
    accepted = sorted(tag for tag in tags if isinstance(tag, str)
                      and re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}', tag)
                      and tag.startswith('3.5.8') and 'alpine3.24' in tag)
    result = {'repository': origin['image'], 'tags': tags, 'accepted_candidate_tags': accepted}
    (root / 'registry-tag-listing.json').write_text(json.dumps(redacted(result), indent=2) + '\n')
    return [origin['image'] + ':' + tag for tag in accepted]


def discover_origin(origin, architecture, destination, registry):
    """Retain registry metadata without downloading output or source layers.

    Discovery documents possible routes; it does not claim that a statement,
    signature, source layout, or package output has been verified.
    """
    repository = origin['image']
    if (not re.fullmatch(r'dhi\.io/pkg-[a-z0-9][a-z0-9_.-]*', repository)
            or origin['predicate_image_name'] != 'dhi/' + repository.split('/', 1)[1]):
        raise ValueError('Unreviewed package discovery repository')
    root = Path(destination)
    root.mkdir(parents=True, exist_ok=True)
    external = 'registry.scout.docker.com/' + origin['predicate_image_name']
    attempts, subjects, artifacts = [], [], []
    candidates = list(dict.fromkeys([origin['reference'], *origin.get('candidate_references', [])]))
    declared_count = len(candidates)
    discovered = False
    for reference in candidates:
        try:
            if not re.fullmatch(re.escape(repository) + r'(?:[:][A-Za-z0-9_.-]+|@sha256:[a-f0-9]{64})', reference):
                raise ValueError('Candidate package discovery reference is outside reviewed repository')
            raw = registry.manifest(reference)
            native, index_digest, direct = resolve_native(raw, architecture)
            if '@' in reference and reference.split('@', 1)[1] != index_digest:
                raise ValueError('Discovery manifest differs from immutable reference')
            (root / 'package-image-index.json').write_bytes(raw)
            manifest = json.loads(raw)
            embedded = [(repository, row, 'embedded-index') for row in manifest.get('manifests', [])
                        if row.get('digest') != native
                        and (row.get('platform', {}).get('os') == 'unknown'
                             or row.get('annotations', {}).get('vnd.docker.reference.type') == 'attestation-manifest')]
            routes = [('native', native)]
            if not direct:
                routes.append(('index', index_digest))
            pending = embedded
            for scope, subject in routes:
                for location, source_repo in (('internal', repository), ('external', external)):
                    name = scope + '-' + location
                    try:
                        listing = registry.referrers(repository + '@' + subject,
                                                     **({'external': external} if location == 'external' else {}))
                        (root / ('referrers-' + name + '.json')).write_text(json.dumps(listing, indent=2) + '\n')
                        descriptors = listing.get('manifests', [])
                        if not isinstance(descriptors, list) or len(descriptors) > 64:
                            raise ValueError('Unsupported or excessive package-discovery referrers')
                        pending += [(source_repo, descriptor, name) for descriptor in descriptors]
                        subjects.append({'scope': scope, 'subject_digest': subject,
                            'repository': source_repo, 'descriptors': len(descriptors), 'report': 'referrers-' + name + '.json'})
                    except ACQUISITION_ERRORS as error:
                        failure = {'scope': scope, 'subject_digest': subject, 'repository': source_repo,
                                   'error': type(error).__name__ + ': ' + str(error)}
                        (root / ('referrers-' + name + '-error.json')).write_text(json.dumps(failure, indent=2) + '\n')
                        subjects.append(failure)
            seen = set()
            for source_repo, descriptor, route in pending:
                value = descriptor.get('digest', '')
                if not re.fullmatch(r'sha256:[a-f0-9]{64}', value):
                    artifacts.append({'route': route, 'error': 'Malformed discovery descriptor digest'})
                    continue
                identity = (source_repo, value)
                if identity in seen:
                    continue
                seen.add(identity)
                item = {'route': route, 'reference': source_repo + '@' + value,
                        'descriptor': descriptor, 'signature_verified': False}
                folder = root / 'artifacts' / source_repo.split('/', 1)[0] / value.split(':', 1)[1]
                folder.mkdir(parents=True, exist_ok=True)
                try:
                    artifact_raw = registry.manifest(item['reference'])
                    if digest(artifact_raw) != value:
                        raise ValueError('Discovery artifact manifest digest mismatch')
                    (folder / 'manifest.json').write_bytes(artifact_raw)
                    artifact_manifest = json.loads(artifact_raw)
                    item['manifest'] = str((folder / 'manifest.json').relative_to(root))
                    item['manifest_annotations'] = artifact_manifest.get('annotations', {})
                    if len(artifact_manifest.get('layers', [])) == 1:
                        statement = registry.statement(item['reference'])
                        layer = artifact_manifest['layers'][0]
                        if len(statement) != layer['size'] or digest(statement) != layer['digest']:
                            raise ValueError('Discovery statement differs from retained manifest layer')
                        (folder / 'statement.json').write_bytes(statement)
                        parsed = json.loads(statement)
                        item['statement'] = str((folder / 'statement.json').relative_to(root))
                        item['predicate_type'] = parsed.get('predicateType')
                        item['subjects'] = parsed.get('subject', [])
                        item['predicate'] = parsed.get('predicate', {})
                except ACQUISITION_ERRORS as error:
                    item['error'] = type(error).__name__ + ': ' + str(error)
                artifacts.append(item)
            result = {'origin': origin['origin'], 'version': origin['version'], 'architecture': architecture,
                      'discovery_reference': reference, 'native_image_digest': native,
                      'image_index_digest': index_digest, 'subjects': subjects, 'artifacts': artifacts,
                      'candidate_failures': attempts, 'acquisition_complete': False}
            break
        except ACQUISITION_ERRORS as error:
            attempts.append({'reference': reference, 'error': type(error).__name__ + ': ' + str(error),
                             'registry_reference_not_found': registry_not_found(error)})
            if (origin['origin'] == 'openssl' and origin['version'] == '3.5.8-r1' and not discovered
                    and len(attempts) == declared_count
                    and all(row['registry_reference_not_found'] for row in attempts)):
                discovered = True
                try:
                    candidates += [candidate for candidate in discover_openssl_candidates(origin, registry, root)
                                   if candidate not in candidates]
                except ACQUISITION_ERRORS as error:
                    attempts.append({'reference': external + ':authenticated-tag-list',
                                     'error': type(error).__name__ + ': ' + str(error)})
    else:
        result = {'origin': origin['origin'], 'version': origin['version'], 'architecture': architecture,
                  'subjects': subjects, 'artifacts': artifacts, 'candidate_failures': attempts,
                  'acquisition_complete': False}
    (root / 'discovery.json').write_text(json.dumps(redacted(result), indent=2) + '\n')
    return result


def acquire_origin(origin, architecture, destination, registry, *, base_provenance=None, runtime_inventory=None):
    origin_name = origin.get('origin', '')
    repository = origin.get('image', '')
    source_name = origin.get('predicate_image_name', '')
    if (not re.fullmatch(r'[a-z0-9][a-z0-9_.-]*', origin_name)
            or not re.fullmatch(r'dhi\.io/pkg-[a-z0-9][a-z0-9_.-]*', repository)
            or source_name != 'dhi/' + repository.split('/', 1)[1]):
        raise ValueError('Unreviewed package origin/repository identity')
    packages = expected_packages(origin, architecture)
    output_plans = reviewed_output_groups(origin, architecture)
    root = Path(destination)
    root.mkdir(parents=True, exist_ok=True)
    candidates = list(dict.fromkeys([origin['reference'], *origin.get('candidate_references', [])]))
    attempts = []
    binary_mismatch_seen = False
    matching_output_seen = False
    declared_candidates = len(candidates)
    tags_discovered = False
    for reference in candidates:
        try:
            if not re.fullmatch(re.escape(repository) + r'(?:[:][A-Za-z0-9_.-]+|@sha256:[a-f0-9]{64})', reference):
                raise ValueError('Candidate package reference is outside reviewed repository')
            raw_index = registry.manifest(reference)
            _, index_digest, _ = resolve_native(raw_index, architecture)
            if '@' in reference and reference.split('@', 1)[1] != index_digest:
                raise ValueError('Registry response differs from immutable package reference')
            output_groups = []
            for plan in output_plans:
                native, group_index, direct_manifest = resolve_native(raw_index, plan['architecture'])
                output = root / plan['directory']
                registry.copy(repository + '@' + native, output)
                matched = match_package_output(output, native, plan['architecture'], plan['packages'],
                                               allow_noarch=plan['allow_noarch'])
                matching_output_seen = True
                group = {'architecture': plan['architecture'], 'directory': plan['directory'],
                         'native_image_digest': native, 'image_index_digest': group_index,
                         'index_is_native_manifest': direct_manifest, 'allow_noarch': plan['allow_noarch'],
                         'apk_matches': matched['apk_matches']}
                output_groups.append(group)
                (root / ('package-output-match-' + plan['architecture'] + '.json')).write_text(json.dumps(matched, indent=2) + '\n')
            apk_matches = [package for group in output_groups for package in group['apk_matches']]
            (root / 'package-output-match.json').write_text(json.dumps({'architecture': architecture,
                'all_apks_matched': True, 'apk_matches': apk_matches, 'output_groups': output_groups}, indent=2) + '\n')
            (root / 'package-image-index.json').write_bytes(raw_index)
            source_results, source_failures = [], []
            for group in output_groups:
                sources, failures = acquire_signed_sources(origin, group, raw_index, root, registry)
                source_results += sources
                source_failures += failures
            recipe = retain_recipe(origin, root)
            primary = output_groups[0]
            result = {'origin': origin_name, 'version': origin['version'], 'architecture': architecture,
                'success': True, 'provider_oci_binding': True,
                'discovery_reference': reference, 'image_index_digest': index_digest,
                'index_is_native_manifest': primary['index_is_native_manifest'],
                'native_image_digest': primary['native_image_digest'],
                'output_groups': output_groups, 'apk_matches': apk_matches, 'source_results': source_results,
                'source_failures': source_failures, 'candidate_failures': attempts, 'recipe': recipe}
            (root / 'acquisition.json').write_text(json.dumps(redacted(result), indent=2) + '\n')
            return result
        except ACQUISITION_ERRORS as error:
            binary_mismatch = isinstance(error, PackageBinaryMismatch)
            binary_mismatch_seen = binary_mismatch_seen or binary_mismatch
            attempts.append({'reference': reference, 'error': type(error).__name__ + ': ' + str(error),
                             'failure_kind': 'apk-binary-mismatch' if binary_mismatch
                                else 'registry-reference-not-found' if registry_not_found(error) else 'acquisition-error'})
            if (origin_name == 'openssl' and origin['version'] == '3.5.8-r1' and not tags_discovered
                    and len(attempts) == declared_candidates
                    and all(attempt['failure_kind'] == 'registry-reference-not-found' for attempt in attempts)):
                tags_discovered = True
                try:
                    discovered = discover_openssl_candidates(origin, registry, root)
                    candidates += [candidate for candidate in discovered if candidate not in candidates]
                except ACQUISITION_ERRORS as discovery_error:
                    attempts.append({'reference': repository + ':authenticated-tag-list',
                        'failure_kind': 'registry-tag-list-error',
                        'registry_reference_not_found': registry_not_found(discovery_error),
                        'error': type(discovery_error).__name__ + ': ' + str(discovery_error)})
    # The reviewed timezone tag is reused for 2026b/c/d. This narrowly scoped
    # source-only path does not invent a historical provider image or rescue a
    # signature failure after finding matching APK bytes.
    if (origin_name == 'tzdata' and origin['version'] == '2026c-r0'
            and origin.get('mutable_tag_reused_across_upstream_versions') is True
            and binary_mismatch_seen and not matching_output_seen):
        try:
            fallback_directory = root / 'tzdata-public-sources'
            fallback = collect_timezone_sources(origin, architecture, fallback_directory)
            result = {'origin': origin_name, 'version': origin['version'], 'architecture': architecture,
                'success': True, 'provider_oci_binding': False, 'source_results': [],
                'public_source_fallback': {'directory': 'tzdata-public-sources', 'manifest': 'manifest.json',
                    'provider_oci_binding': False, 'binding_method': fallback['binding_method'],
                    'files': fallback['files']},
                'reviewed_apks': packages, 'candidate_failures': attempts}
            (root / 'acquisition.json').write_text(json.dumps(redacted(result), indent=2) + '\n')
            return result
        except ACQUISITION_ERRORS as error:
            attempts.append({'reference': 'reviewed-public-IANA-2026c-source-inputs',
                             'failure_kind': 'public-source-fallback-error',
                             'error': type(error).__name__ + ': ' + str(error)})
    if (origin_name == 'openssl' and origin['version'] == '3.5.8-r1' and attempts
            and all(row['failure_kind'] == 'registry-reference-not-found'
                    or (row['failure_kind'] == 'registry-tag-list-error'
                        and row.get('registry_reference_not_found') is True) for row in attempts)):
        try:
            if base_provenance is None or runtime_inventory is None:
                raise ValueError('Pinned base provenance and actual runtime inventory are required for OpenSSL sources')
            from openssl_distribution_sources import collect_sources as collect_openssl_sources
            fallback = collect_openssl_sources(origin, architecture, base_provenance, runtime_inventory,
                                                root / 'openssl-public-sources')
            result = {'origin': origin_name, 'version': origin['version'], 'architecture': architecture,
                'success': True, 'provider_oci_binding': False, 'source_results': [],
                'public_source_fallback': {'directory': 'openssl-public-sources', 'manifest': 'manifest.json',
                    'provider_oci_binding': False, 'binding_method': fallback['binding_method'],
                    'files': fallback['files']}, 'reviewed_apks': packages, 'candidate_failures': attempts}
            (root / 'acquisition.json').write_text(json.dumps(redacted(result), indent=2) + '\n')
            return result
        except ACQUISITION_ERRORS as error:
            attempts.append({'reference': 'reviewed-public-OpenSSL-3.5.8-source-inputs',
                             'failure_kind': 'public-source-fallback-error',
                             'error': type(error).__name__ + ': ' + str(error)})
    result = {'origin': origin_name, 'version': origin['version'], 'architecture': architecture,
              'success': False, 'candidate_failures': attempts}
    (root / 'acquisition.json').write_text(json.dumps(redacted(result), indent=2) + '\n')
    return result


def collect_packages(lock, architecture, destination, registry, *, base_provenance=None, runtime_inventory=None,
                     workers=None):
    if (lock.get('schema_version') != 1 or architecture not in lock.get('architectures', [])
            or lock.get('source_predicate_type') != PREDICATE):
        raise ValueError('Unsupported reviewed OS package source map')
    workers = source_workers(workers)
    origins = lock['origins']
    names = [row.get('origin', '') for row in origins]
    if (not names or any(not isinstance(name, str) or not re.fullmatch(r'[a-z0-9][a-z0-9_.-]*', name)
                         for name in names)
            or len(set(names)) != len(names)):
        raise ValueError('OS package origins require unique safe output directory names')
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    results = []
    report = {'format': 'keep-os-package-source-acquisition-v1', 'architecture': architecture,
              'success': False, 'origins': results,
              'pending_origins': names.copy()}
    (destination / 'package-sources.json').write_text(json.dumps(redacted(report), indent=2) + '\n')

    def acquire(origin):
        try:
            return acquire_origin(origin, architecture, destination / origin['origin'], registry,
                                  base_provenance=base_provenance, runtime_inventory=runtime_inventory)
        except Exception as error:
            return {'origin': origin['origin'], 'success': False,
                    'error': type(error).__name__ + ': ' + str(error)}

    # Only the caller writes aggregate reports/logs. Workers return independent
    # origin results, so completion order cannot change retained evidence.
    for result in ordered_map(acquire, origins, workers):
        results.append(result)
        report['pending_origins'] = names[len(results):]
        (destination / 'package-sources.json').write_text(json.dumps(redacted(report), indent=2) + '\n')
        print(json.dumps(redacted({'origin': result['origin'], 'success': result['success']})), flush=True)
    report['success'] = bool(results) and all(row['success'] for row in results)
    (destination / 'package-sources.json').write_text(json.dumps(redacted(report), indent=2) + '\n')
    return report


def verified_base_inputs(provenance_path, inventory_path, proof_directory, architecture):
    """Load public-reconstruction inputs only after replaying original base proof."""
    provenance_path, inventory_path = Path(provenance_path), Path(inventory_path)
    if not provenance_path.exists() and not inventory_path.exists():
        return None, None
    original = read_regular(Path(proof_directory) / 'statement.json')
    native = 'sha256:' + DIRECT[architecture][0]
    verify_attestation_proof(proof_directory, architecture,
        expected_base_digest=BASE.split('@', 1)[1], expected_repository='dhi.io/python',
        expected_source_name='dhi/python', expected_native_digest=native,
        expected_predicate_type='https://slsa.dev/provenance/v1')
    if read_regular(provenance_path) != original:
        raise ValueError('Base package materials differ from original signed provenance bytes')
    return json.loads(original), json.loads(read_regular(inventory_path))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--map', default=str(ROOT / 'docs/os-package-sources.json'))
    parser.add_argument('--output', default='source-materials/os-packages')
    parser.add_argument('--architecture', choices=('amd64', 'arm64'))
    parser.add_argument('--base-provenance', help='Verified base SLSA JSON (defaults beside output directory)')
    parser.add_argument('--runtime-inventory', help='Actual runtime inventory JSON (defaults to base inventory beside output)')
    parser.add_argument('--workers', type=int, choices=range(1, 5),
                        help='Concurrent source origins (default KEEP_SOURCE_DOWNLOAD_WORKERS or 4)')
    parser.add_argument('--discover-origin', action='append', default=[],
                        help='Only retain attestation discovery metadata for this reviewed origin; repeatable')
    args = parser.parse_args()
    host_architecture = HASHES[platform.machine()][0]
    architecture = args.architecture or host_architecture
    _, _, reg_hash, cosign_hash = DIRECT[host_architecture]
    username = os.environ.pop('DOCKERHUB_USERNAME')
    token = os.environ.pop('DOCKERHUB_TOKEN')
    lock = json.loads(Path(args.map).read_text())
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        env = {**os.environ, 'DOCKER_CONFIG': str(root / 'config')}
        for registry in ('dhi.io', 'registry.scout.docker.com'):
            subprocess.run(['docker', 'login', registry, '--username', username, '--password-stdin'],
                           input=token, text=True, env=env, check=True)
        regctl = download(root, 'regctl', f'https://github.com/regclient/regclient/releases/download/v0.11.6/regctl-linux-{host_architecture}', reg_hash)
        cosign = download(root, 'cosign', f'https://github.com/sigstore/cosign/releases/download/v3.1.3/cosign-linux-{host_architecture}', cosign_hash)
        key = download(root, 'dhi.pub', 'https://registry.scout.docker.com/keyring/dhi/latest.pub', KEY_SHA256)
        client = Registry(regctl, cosign, key, env)
        if args.discover_origin:
            origins = [origin for origin in lock['origins'] if origin['origin'] in args.discover_origin]
            if {origin['origin'] for origin in origins} != set(args.discover_origin):
                raise ValueError('Unknown reviewed package discovery origin')
            report = {'format': 'keep-package-attestation-discovery-v1', 'architecture': architecture,
                      'acquisition_complete': False,
                      'origins': [discover_origin(origin, architecture, Path(args.output) / origin['origin'], client)
                                  for origin in origins]}
            (Path(args.output) / 'package-discovery.json').write_text(json.dumps(redacted(report), indent=2) + '\n')
        else:
            provenance_path = Path(args.base_provenance) if args.base_provenance else Path(args.output).parent / 'base-provenance.json'
            inventory_path = Path(args.runtime_inventory) if args.runtime_inventory else Path(args.output).parent / 'base-runtime-inventory.json'
            provenance, inventory = verified_base_inputs(provenance_path, inventory_path,
                Path(args.output).parent / 'base-build-provenance', architecture)
            report = collect_packages(lock, architecture, args.output, client,
                base_provenance=provenance, runtime_inventory=inventory, workers=args.workers)
    (Path(args.output).parent / 'os-package-source-review.json').write_text(json.dumps(redacted(report), indent=2) + '\n')
    print(json.dumps(redacted(report), indent=2), flush=True)
    if not args.discover_origin and not report['success']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
