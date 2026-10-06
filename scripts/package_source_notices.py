#!/usr/bin/env python3
"""Inventory retained package sources and make a notices-only distribution.

The caller must first verify the package APK binding, signed source statement,
and OCI layout, then use retain_materials to create the input manifest. This
module rechecks every retained byte sequence and requires readable source and
build inputs. A source image digest or an APK wrapper alone is not coverage.
It never extracts archive paths or follows source links, and executes no source.
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import tempfile

from oci_source_materials import PrefixReader, SourceInventory, safe_name


SOURCE_SUFFIXES = {'.c', '.h', '.cc', '.cpp', '.cxx', '.hpp', '.s', '.py',
                   '.rs', '.go', '.sh', '.awk', '.pl', '.f', '.f90', '.java',
                   '.m4', '.ac', '.am', '.pm', '.tcl', '.exp'}
NOTICE_CODE_SUFFIXES = SOURCE_SUFFIXES | {'.js', '.ts', '.rb', '.php', '.ps1', '.psm1'}
NOTICE_BASENAME = re.compile(r'^(?:license|licence|copying[0-9]*|copyright|notice)(?:[._-]|$)', re.I)
BUILD_NAMES = {'APKBUILD', 'Makefile', 'makefile', 'CMakeLists.txt', 'meson.build',
               'configure', 'configure.ac', 'config', 'build.sh'}
LEGAL_MARKER = re.compile(br'copyright|SPDX-License-Identifier|permission is hereby granted|'
                          br'licensed under|licen[cs]e|public domain', re.I)
SHA256 = re.compile(r'[a-f0-9]{64}')
ROOT = Path(__file__).resolve().parents[1]
GPL2_PATH = 'docs/licenses/GPL-2.0-only.txt'
GPL2_SHA256 = '231f7edcc7352d7734a96eef0b8030f77982678c516876fcb81e25b32d68564c'
GPL2_BYTES = 18002
GPL2_SOURCE_URL = ('https://gcc.gnu.org/git/?p=gcc.git;a=blob_plain;f=COPYING;'
                   'hb=0063a8238d6f2b3cb933cffb33a0b69abfa90674')
MPL2_PATH = 'docs/licenses/MPL-2.0.txt'
MPL2_SHA256 = 'fab3dd6bdab226f1c08630b1dd917e11fcb4ec5e1e020e2c16f83a0a13863e85'
MPL2_BYTES = 16726
MPL2_SOURCE_URL = 'https://www.mozilla.org/media/MPL/2.0/index.815ca599c9df.txt'
CA_CERTDATA_NOTICE = ('sources/ca-certificates-20260909.tar.bz2!'
                     'ca-certificates-20260909/certdata.txt#leading-comment')
CA_CERTDATA_NOTICE_SHA256 = '6f3d0ca739e01730cb2314a8302be79cb23a5956d7770dc3de37bc4b4db79df1'
CA_SOURCE_SHA256 = 'dc460c535f3833432be4e561d214a5fe816b05ede5a2ade64787e501671cd082'


def checked_path(root, relative):
    name = safe_name(relative)
    path = Path(root)
    if path.is_symlink():
        raise ValueError('Material root must not be a symlink')
    for part in PurePosixPath(name).parts:
        path = path / part
        if path.is_symlink():
            raise ValueError('Retained material paths must not contain symlinks')
    if not path.is_file():
        raise ValueError('Missing retained material file')
    return path


def check_file(path, record):
    expected = record.get('sha256', '')
    expected_size = record.get('bytes')
    if (not isinstance(expected, str) or not SHA256.fullmatch(expected)
            or not isinstance(expected_size, int) or isinstance(expected_size, bool)
            or expected_size < 0):
        raise ValueError('Malformed retained material identity')
    hasher = hashlib.sha256()
    count = 0
    with path.open('rb') as stream:
        while chunk := stream.read(1024 * 1024):
            count += len(chunk)
            hasher.update(chunk)
    if count != expected_size or hasher.hexdigest() != expected:
        raise ValueError('Retained material checksum or size mismatch')


def readable(prefix):
    if not prefix or b'\x00' in prefix or prefix.startswith(b'\x7fELF'):
        return False
    try:
        prefix.decode('utf-8')
    except UnicodeDecodeError:
        return False
    return True


def leading_notice(prefix, *, complete_file=False):
    """Preserve a complete leading comment containing a legal notice, verbatim."""
    start = re.match(br'\s*', prefix).end()
    if prefix[start:start + 2] == b'/*':
        end = -1
        while prefix[start:start + 2] == b'/*':
            end = prefix.find(b'*/', start + 2)
            if end < 0:
                return None
            start = end + 2
            start += re.match(br'\s*', prefix[start:]).end()
        block = prefix[:end + 2]
    else:
        lines = prefix.splitlines(keepends=True)
        block_lines = []
        ended = False
        comment_style = next((mark for mark in (b'//', b'.\\"', b';', b'#')
                              if prefix[start:].startswith(mark)), None)
        for line in lines:
            stripped = line.lstrip()
            if not stripped.strip() or comment_style and stripped.startswith(comment_style):
                block_lines.append(line)
            else:
                ended = True
                break
        # A capped prefix may stop midway through a line-comment license.
        # Only EOF or an observed non-comment line proves its boundary.
        block = b''.join(block_lines) if ended or complete_file else b''
    return block if block and LEGAL_MARKER.search(block) else None


class MaterialInventory(SourceInventory):
    def __init__(self, output_dir, **limits):
        super().__init__(Path('/unused-source-layout'), output_dir, **limits)
        self.readable_sources = []
        self.build_inputs = []
        self.apk_archives = set()
        self.binary_files = []
        self.baselayout_recipes = []
        self.fixture_archives = {}
        self.archive_fixtures = []

    def scan_archive(self, stream, origin, depth=0, zip_format=False):
        # Retained upstream paths often equal their provenance source path.
        # Keep one archive locator so explicit reviewed notice selections do
        # not acquire a redundant 'sources/x.tar!sources/x.tar!' prefix.
        parts = origin.split('!')
        if depth == 1 and len(parts) == 2 and parts[0] == parts[1]:
            origin = parts[0]
        return super().scan_archive(stream, origin, depth, zip_format=zip_format)

    def regular_file(self, stream, name, size, origin, depth):
        prefix = stream.read(min(size, 65536))
        stream = PrefixReader(prefix, stream)
        location = origin + '!' + name
        fixture_binding = self.fixture_archives.get(origin.split('!', 1)[0])
        fixture = fixture_binding['fixtures'].get(name) if fixture_binding and depth == 1 else None
        if fixture:
            # This finite checked fixture set deliberately includes malformed
            # compressed data and archives with unsafe internal member names.
            # Retain/hash its complete bytes in the original outer source;
            # never extract it or mistake a parser test input for dependency
            # source. Ordinary archives still traverse with the same bounds.
            if size != fixture['bytes'] or size > self.max_archive_bytes:
                raise ValueError('Reviewed upstream archive fixture size mismatch')
            hasher, count = hashlib.sha256(), 0
            while chunk := stream.read(min(size - count + 1, 1024 * 1024)):
                count += len(chunk)
                hasher.update(chunk)
                if count > size:
                    raise ValueError('Reviewed upstream archive fixture size mismatch')
            if count != size or hasher.hexdigest() != fixture['sha256']:
                raise ValueError('Reviewed upstream archive fixture checksum mismatch')
            self.files.append({'path': location, 'bytes': size, 'kind': 'preserved-test-fixture'})
            self.archive_fixtures.append({**fixture, 'path': location,
                'upstream_archive_sha256': fixture_binding['upstream_archive_sha256'],
                'origin': fixture_binding['origin'], 'version': fixture_binding['version'],
                'bytes_preserved_in_original_source_archive': True,
                'recursively_interpreted': False})
            return
        path = PurePosixPath(name)
        basename, suffix = path.name, path.suffix.lower()
        if basename == '.PKGINFO':
            self.apk_archives.add(origin)
        if prefix.startswith(b'\x7fELF'):
            self.binary_files.append({'path': location, 'bytes': size, 'format': 'ELF'})
        if readable(prefix) and '.git' not in path.parts:
            if (basename == 'APKBUILD' and 'main/alpine-baselayout/APKBUILD' in str(path)
                    and len(prefix) == size):
                text = prefix.decode('utf-8')
                values = {'pkgname': 'alpine-baselayout', 'pkgver': '3.7.2',
                          'pkgrel': '1', 'license': 'GPL-2.0-only'}
                if all(re.findall(r'^' + key + r'=[\"\']?([^\n\"\']+)[\"\']?$', text, re.M) == [value]
                       for key, value in values.items()):
                    self.baselayout_recipes.append({'path': location,
                        'sha256': hashlib.sha256(prefix).hexdigest(), 'declarations': values})
            if suffix in SOURCE_SUFFIXES or basename in {'certdata.txt', 'zlib.h', 'tzdata.zi'}:
                self.readable_sources.append({'path': location, 'bytes': size})
            if (basename in BUILD_NAMES or basename.startswith('Dockerfile')
                    or suffix in {'.patch', '.diff', '.yaml', '.yml'}):
                self.build_inputs.append({'path': location, 'bytes': size})
            notice = leading_notice(prefix, complete_file=len(prefix) == size)
            if notice:
                value = hashlib.sha256(notice).hexdigest()
                destination = self.output_dir / 'notices' / (value + '.txt')
                if self.output_dir.is_symlink() or destination.parent.is_symlink() or destination.is_symlink():
                    raise ValueError('Unsafe notice output path')
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(notice)
                self.notices.append({'path': location + '#leading-comment',
                    'bytes': len(notice), 'sha256': value,
                    'notice_file': 'notices/' + destination.name, 'encoding': 'utf-8',
                    'discovery': 'complete-leading-legal-comment'})
        # SourceInventory broadly finds files under licenses/. Avoid copying
        # executable license-helper code as if it were a notice text.
        if (suffix in NOTICE_CODE_SUFFIXES
                and (NOTICE_BASENAME.match(basename) or any(
                    part.lower() in {'licenses', 'licences'} for part in path.parts[:-1]))):
            self.files.append({'path': location, 'bytes': size, 'kind': 'source-file'})
            return
        super().regular_file(stream, name, size, origin, depth)


def excluded_evidence(record):
    proof = record.get('provenance', record.get('provenance_evidence', {}))
    expected = record.get('sha256', '')
    proof_digest = proof.get('digest', {}).get('sha256', proof.get('sha256')) if isinstance(proof, dict) else None
    if (not isinstance(expected, str) or not SHA256.fullmatch(expected)
            or not isinstance(record.get('bytes'), int) or isinstance(record['bytes'], bool)
            or record['bytes'] < 0 or not isinstance(proof, dict)
            or not isinstance(proof.get('uri'), str) or not proof['uri'].split('?', 1)[0].endswith('.apk')
            or proof_digest != expected):
        raise ValueError('Excluded binary must have matching APK provenance evidence')
    return proof


def inspect_package_materials(material_root, output_dir, *, origin, version,
                              architecture, expected_digest=None,
                              excluded_binary_digests=(), **limits):
    """Return readable-material and full-notice evidence for one package origin.

The output contains notice texts and package-material-inventory.json only.
Excluded binary identities must have explicit matching provider APK provenance.
Incomplete archive traversal or APK-only material makes success false.
"""
    root = Path(material_root)
    manifest_path = checked_path(root, 'material-manifest.json')
    manifest = json.loads(manifest_path.read_bytes())
    source_digest = manifest.get('source_image_digest', '')
    if (manifest.get('schema') != 1 or manifest.get('binding_verified') is not True
            or not re.fullmatch(r'sha256:[a-f0-9]{64}', source_digest)
            or expected_digest is not None and source_digest != expected_digest):
        raise ValueError('Retained source material does not match verified source image')
    return _inspect_records(root, output_dir, origin=origin, version=version,
        architecture=architecture, manifest=manifest,
        binding={'source_image_digest': source_digest},
        excluded_binary_digests=excluded_binary_digests, **limits)


def inspect_build_provenance_sources(source_dir, output_dir, *, origin, version,
                                    architecture, native_image_digest,
                                    source_manifest_sha256, **limits):
    """Inventory preferred sources after the caller verifies and replays proofs.

The caller must verify original native SLSA and Scout signatures and replay
package_provenance_sources.collect_sources against these retained downloads.
This function binds that replay's manifest and native subject, then rechecks
every file. It makes no package source-image claim.
"""
    root = Path(source_dir)
    manifest_path = checked_path(root, 'manifest.json')
    body = manifest_path.read_bytes()
    if (not isinstance(source_manifest_sha256, str)
            or not SHA256.fullmatch(source_manifest_sha256)
            or hashlib.sha256(body).hexdigest() != source_manifest_sha256):
        raise ValueError('Verified build source manifest checksum mismatch')
    manifest = json.loads(body)
    expected = {'schema': 1, 'origin': origin, 'version': version,
        'architecture': architecture, 'provider_oci_binding': True,
        'binding_method': 'signed-build-provenance', 'source_image_digest': None,
        'native_image_digest': native_image_digest}
    if (not isinstance(native_image_digest, str)
            or not re.fullmatch(r'sha256:[a-f0-9]{64}', native_image_digest)
            or any(manifest.get(key) != value for key, value in expected.items())):
        raise ValueError('Preferred source manifest differs from verified native build binding')
    statements = manifest.get('signed_statement_sha256', {})
    if (not isinstance(statements, dict) or set(statements) != {'slsa', 'scout'}
            or any(not isinstance(value, str) or not SHA256.fullmatch(value)
                   for value in statements.values())):
        raise ValueError('Missing original signed build statement identities')
    records = manifest.get('files')
    if not isinstance(records, list) or not records:
        raise ValueError('Missing preferred source records')
    return _inspect_records(root, output_dir, origin=origin, version=version,
        architecture=architecture,
        manifest={**manifest, 'files': [{**row, 'type': 'file'} for row in records]},
        binding={**expected, 'source_manifest_sha256': source_manifest_sha256,
                 'signed_statement_sha256': statements}, **limits)


def inspect_provenance_materials(source_dir, output_dir, *, origin, version,
                                architecture, native_image_digest=None,
                                source_manifest_sha256=None, **limits):
    """Convenient alias; callers still verify signatures and replay first."""
    manifest_path = checked_path(source_dir, 'manifest.json')
    body = manifest_path.read_bytes()
    manifest = json.loads(body)
    return inspect_build_provenance_sources(source_dir, output_dir,
        origin=origin, version=version, architecture=architecture,
        native_image_digest=native_image_digest or manifest.get('native_image_digest'),
        source_manifest_sha256=source_manifest_sha256 or hashlib.sha256(body).hexdigest(),
        **limits)


def _inspect_records(root, output_dir, *, origin, version, architecture,
                     manifest, binding, excluded_binary_digests=(), **limits):
    root, output = Path(root), Path(output_dir)
    if output.is_symlink() or output.exists() and any(output.iterdir()):
        raise ValueError('Notice output must be an empty directory without symlinks')
    if architecture not in {'amd64', 'arm64'} or not re.fullmatch(r'[a-z0-9][a-z0-9_.-]*', origin):
        raise ValueError('Invalid package source origin or architecture')
    output.mkdir(parents=True, exist_ok=True)
    inventory = MaterialInventory(output, **limits)
    fixture_lock = json.loads(checked_path(ROOT, 'docs/source-archive-fixtures.json').read_bytes())
    if fixture_lock.get('schema') != 1 or not isinstance(fixture_lock.get('archives'), list):
        raise ValueError('Malformed reviewed source fixture lock')
    records = manifest.get('files')
    if not isinstance(records, list):
        raise ValueError('Missing source material file manifest')
    seen, retained, excluded = set(), [], []
    requested_exclusions = set(excluded_binary_digests)
    for record in records:
        kind = record.get('type')
        if kind == 'excluded-binary':
            excluded.append({**record, 'provenance': excluded_evidence(record)})
            requested_exclusions.discard(record['sha256'])
            continue
        source_path = safe_name(record.get('source_path', ''))
        if kind in {'directory', 'symlink', 'hardlink', 'whiteout'}:
            continue
        if kind != 'file':
            raise ValueError('Unsupported retained material manifest entry')
        relative = safe_name(record.get('path', ''))
        if relative in seen:
            raise ValueError('Duplicate retained material file path')
        seen.add(relative)
        path = checked_path(root, relative)
        check_file(path, record)
        matches = [row for row in fixture_lock['archives']
                   if row.get('origin') == origin and row.get('version') == version
                   and row.get('upstream_archive_sha256') == record['sha256']]
        if len(matches) > 1:
            raise ValueError('Ambiguous reviewed source archive fixture binding')
        if matches:
            rows = matches[0]['fixtures']
            if (not isinstance(rows, list) or any(
                    not isinstance(row.get('sha256'), str) or not SHA256.fullmatch(row['sha256'])
                    or not isinstance(row.get('bytes'), int) or isinstance(row['bytes'], bool)
                    or row['bytes'] < 0 or row.get('classification') !=
                    'upstream-archive-or-compression-test-fixture' for row in rows)):
                raise ValueError('Malformed reviewed source archive fixture identity')
            fixtures = {safe_name(row['path']): row for row in rows}
            if len(fixtures) != len(rows):
                raise ValueError('Duplicate reviewed archive fixture path')
            inventory.fixture_archives[relative] = {**matches[0], 'fixtures': fixtures}
        if record['sha256'] in requested_exclusions:
            excluded.append({**record, 'type': 'excluded-binary', 'provenance': excluded_evidence(record)})
            requested_exclusions.discard(record['sha256'])
            continue
        retained.append({'path': relative, 'source_path': source_path,
                         'sha256': record['sha256'], 'bytes': record['bytes']})
        if not inventory.budget(relative, record['bytes']):
            break
        with path.open('rb') as stream:
            inventory.regular_file(stream, source_path, record['bytes'], relative, 0)
    if requested_exclusions:
        raise ValueError('Requested binary exclusions were not present with matching provenance')
    def outside_apks(row):
        return not any(row['path'].startswith(value + '!') for value in inventory.apk_archives)
    def relevant_source(row):
        # A full aports tree also contains code for thousands of other
        # packages. That code must not stand in for this origin's source.
        parts = [part for segment in row['path'].split('!')
                 for part in PurePosixPath(segment).parts]
        aports = [number for number, part in enumerate(parts)
                  if part == 'aports' or part.startswith('aports-')]
        if aports and not any(len(parts[start + 1:]) > 2
                and parts[start + 1] in {'main', 'community', 'testing'}
                and parts[start + 2] == origin for start in aports):
            return False
        catalog = [number for number, part in enumerate(parts)
                   if part == 'catalog' or part.startswith('catalog-')]
        catalog_origin = 'python' if origin == 'python-3.14' else origin
        if catalog and not any(parts[start + 1:start + 5] ==
                ['package', 'apk', 'main', catalog_origin] for start in catalog):
            return False
        return True
    sources = [row for row in inventory.readable_sources if outside_apks(row) and relevant_source(row)]
    recipes = [row for row in inventory.build_inputs if outside_apks(row) and relevant_source(row)]
    notices = [row for row in inventory.notices if outside_apks(row) and relevant_source(row)]
    baselayout_recipes = [row for row in inventory.baselayout_recipes
                         if outside_apks(row) and relevant_source(row)]
    baselayout_source = any('/main/alpine-baselayout/' in row['path'] for row in sources)
    if (origin == 'alpine-baselayout' and version == '3.7.2-r1' and baselayout_source
            and baselayout_recipes):
        # Baselayout's preferred sources are the packaging tree's own scripts
        # and configuration files. Its exact APKBUILD declares GPL2 but the
        # source directory does not carry a standalone copy of the terms.
        # Supplement only that reviewed version, after source evidence exists.
        license_path = checked_path(ROOT, GPL2_PATH)
        check_file(license_path, {'sha256': GPL2_SHA256, 'bytes': GPL2_BYTES})
        target = output / 'notices' / (GPL2_SHA256 + '.txt')
        if target.parent.is_symlink() or target.is_symlink():
            raise ValueError('Unsafe supplemental GPL2 notice destination')
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(license_path.read_bytes())
        notices.append({'path': 'supplemental/GNU-GPL-2.0-only',
            'notice_file': 'notices/' + target.name, 'bytes': GPL2_BYTES,
            'sha256': GPL2_SHA256, 'encoding': 'utf-8',
            'discovery': 'reviewed-baselayout-full-license-supplement',
            'license_source_url': GPL2_SOURCE_URL,
            'recipe_license_evidence': baselayout_recipes})
    certdata_notices = [row for row in notices if row['path'] == CA_CERTDATA_NOTICE
                        and row['sha256'] == CA_CERTDATA_NOTICE_SHA256]
    if (origin == 'ca-certificates' and version == '20260909-r0'
            and any(row['sha256'] == CA_SOURCE_SHA256 for row in retained)
            and certdata_notices and any(row['path'].endswith(
                '!ca-certificates-20260909/certdata.txt') for row in sources)):
        # The matching certificate source carries MPL2's exhibit notice, not
        # the full terms. Reuse Mozilla's complete checked primary text only
        # after that exact release's readable source and notice are present.
        license_path = checked_path(ROOT, MPL2_PATH)
        check_file(license_path, {'sha256': MPL2_SHA256, 'bytes': MPL2_BYTES})
        target = output / 'notices' / (MPL2_SHA256 + '.txt')
        if target.parent.is_symlink() or target.is_symlink():
            raise ValueError('Unsafe supplemental MPL2 notice destination')
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(license_path.read_bytes())
        notices.append({'path': 'supplemental/Mozilla-MPL-2.0',
            'notice_file': 'notices/' + target.name, 'bytes': MPL2_BYTES,
            'sha256': MPL2_SHA256, 'encoding': 'utf-8',
            'discovery': 'reviewed-ca-certificates-full-license-supplement',
            'license_source_url': MPL2_SOURCE_URL,
            'recipe_license_evidence': [{key: row[key] for key in ('path', 'sha256')}
                                       for row in certdata_notices]})
    # Remove texts found inside unexcluded APKs from the notices-only result.
    kept_notice_files = {row['notice_file'] for row in notices}
    for path in (output / 'notices').glob('*.txt'):
        if str(path.relative_to(output)) not in kept_notice_files:
            path.unlink()
    warnings = [row for row in inventory.warnings if relevant_source(row)
                or row['reason'].startswith('Archive inventory limit reached')]
    if inventory.apk_archives:
        warnings.append({'path': origin, 'reason': 'Unexcluded binary APK inputs require provenance-based curation',
                         'archives': sorted(inventory.apk_archives)})
    if not sources:
        warnings.append({'path': origin, 'reason': 'No readable preferred source files found; APK wrappers or Git metadata alone are insufficient'})
    if not recipes:
        warnings.append({'path': origin, 'reason': 'No readable build recipes or patch inputs found'})
    if not notices:
        warnings.append({'path': origin, 'reason': 'No readable full notice texts or complete source notice headers found'})
    provenance = {'origin': origin, 'version': version, 'architecture': architecture,
                  **binding}
    report = {**provenance, 'schema': 1,
        'success': bool(sources and recipes and notices and not warnings),
        'binding_verified': True, 'preferred_source_present': bool(sources),
        'build_inputs_present': bool(recipes), 'notice_inventory_complete': not warnings,
        'notices': [{**row, 'provenance': provenance} for row in notices],
        'standalone_notice_count': sum(row.get('discovery') != 'complete-leading-legal-comment' for row in notices),
        'reviewable_comment_count': sum(row.get('discovery') == 'complete-leading-legal-comment' for row in notices),
        'requires_runtime_comment_selection': bool(notices) and all(row.get('discovery') == 'complete-leading-legal-comment' for row in notices),
        'readable_source_files': sources, 'build_inputs': recipes,
        'archives': [row for row in inventory.files if row['kind'] == 'source-archive'],
        'retained_files': retained, 'excluded_binaries': excluded,
        'embedded_binary_files': inventory.binary_files,
        'preserved_archive_fixtures': inventory.archive_fixtures,
        'warnings': warnings, 'links_not_followed': inventory.links_skipped,
        'limitations': 'Caller verifies original package APK and OCI signature binding before retention. This module checks retained file hashes and inventories readable source/build inputs; filename and leading-comment discovery is evidence for review, not legal certification.'}
    (output / 'package-material-inventory.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def merge_notice_bundles(bundles, output_dir, *, selected_comment_paths=()):
    """Make a maintainable runtime notice bundle from standalone full notices.

Complete source headers remain inventoried in the source bundle. Include one
in the runtime notice bundle only when its exact path is explicitly reviewed,
for example a component which has no standalone attribution file.
"""
    output = Path(output_dir)
    if output.is_symlink() or output.exists() and any(output.iterdir()):
        raise ValueError('Merged notice output must be empty without symlinks')
    output.mkdir(parents=True, exist_ok=True)
    notices = {}
    selections = set(selected_comment_paths)
    matched_selections = set()
    packages = []
    for directory in bundles:
        directory = Path(directory)
        report = json.loads(checked_path(directory, 'package-material-inventory.json').read_bytes())
        if report.get('success') is not True:
            raise ValueError('Cannot publish incomplete package source notices')
        package = {key: report[key] for key in ('origin', 'version', 'architecture', 'source_image_digest')}
        for key in ('provider_oci_binding', 'binding_method', 'source_manifest_sha256',
                    'native_image_digest', 'signed_statement_sha256'):
            if key in report:
                package[key] = report[key]
        package['runtime_notice_count'] = 0
        packages.append(package)
        for notice in report['notices']:
            if notice.get('discovery') == 'complete-leading-legal-comment':
                if notice['path'] not in selections:
                    continue
                matched_selections.add(notice['path'])
            package['runtime_notice_count'] += 1
            source = checked_path(directory, notice['notice_file'])
            check_file(source, notice)
            value = notice['sha256']
            destination = output / (value + '.txt')
            if destination.is_symlink():
                raise ValueError('Merged notice destination is a symlink')
            if value not in notices:
                destination.write_bytes(source.read_bytes())
                notices[value] = {'notice_file': destination.name, 'sha256': value,
                                  'bytes': notice['bytes'], 'provenance': []}
            attribution = {**notice['provenance'], 'source_path': notice['path'],
                           'discovery': notice.get('discovery', 'notice-file')}
            for key in ('license_source_url', 'recipe_license_evidence'):
                if key in notice:
                    attribution[key] = notice[key]
            if attribution not in notices[value]['provenance']:
                notices[value]['provenance'].append(attribution)
    if selections != matched_selections:
        raise ValueError('Explicit runtime copyright selection was not found')
    result = {'schema': 1, 'packages': packages, 'notices': list(notices.values()),
              'ready_for_runtime_distribution': bool(packages) and all(row['runtime_notice_count'] for row in packages),
              'origins_needing_explicit_attribution': [row for row in packages if not row['runtime_notice_count']],
              'selected_source_comments': sorted(matched_selections)}
    (output / 'manifest.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


def import_public_notices(source, output_dir, *, origin, architecture,
                          package_spec=None, base_provenance=None,
                          runtime_inventory=None):
    """Recheck pinned timezone/original-Expat inputs and import full notices.

The pinned public collectors are replayed offline against retained downloads.
No provider source-image binding is invented. Original-Expat provenance must
already be checked against the pinned base by the caller, as in the builder.
Only explicitly reviewed attribution headers are copied from source code.
"""
    source, output = Path(source), Path(output_dir)
    if output.is_symlink() or output.exists() and any(output.iterdir()):
        raise ValueError('Public notice output must be empty without symlinks')
    if architecture not in {'amd64', 'arm64'}:
        raise ValueError('Unsupported public notice architecture')
    manifest_path = checked_path(source, 'manifest.json')
    manifest = json.loads(manifest_path.read_bytes())
    records = manifest.get('files', [])
    paths, downloads = set(), {}
    download_roles = {'complete-alpine-build-recipes', 'upstream-source',
                      'pinned-provider-build-recipe', 'upstream-lgpl-license',
                      'alpine-signing-key', 'signed-alpine-binary-evidence',
                      'upstream-detached-signature'}
    for record in records:
        relative = safe_name(record.get('path', ''))
        if relative in paths:
            raise ValueError('Duplicate checked public source filename')
        paths.add(relative)
        path = checked_path(source, relative)
        check_file(path, record)
        if record.get('role') in download_roles:
            url = record.get('url')
            if not isinstance(url, str) or url in downloads:
                raise ValueError('Ambiguous public source download identity')
            downloads[url] = path

    def fetch(url):
        if url not in downloads:
            raise ValueError('Required pinned public source input is missing')
        return downloads[url].read_bytes()

    with tempfile.TemporaryDirectory(prefix='keep-public-notice-check-') as directory:
        if origin == 'tzdata':
            from tzdata_distribution_sources import collect_sources
            if package_spec is None:
                raise ValueError('Timezone notices require the reviewed package source map')
            verified = collect_sources(package_spec, architecture, directory, fetch=fetch)
            if (manifest.get('provider_oci_binding') is not False
                    or manifest.get('architecture') != architecture):
                raise ValueError('Timezone notice inputs have invalid architecture or OCI claim')
            selected_header_roles = {'upstream-bsd-attribution-source', 'upstream-lgpl-attribution-source'}
            binding_method = verified['binding_method']
        elif origin == 'expat-original-base':
            from alpine_distribution_sources import collect_sources
            if base_provenance is None:
                raise ValueError('Original Expat notices require checked native base provenance')
            identity_records = [row for row in records if row.get('role') == 'package-build-identity']
            if len(identity_records) != 1 or identity_records[0]['path'] != 'original-base-expat-inventory.json':
                raise ValueError('Original Expat notices require retained verified base inventory')
            inventory = json.loads(checked_path(source, identity_records[0]['path']).read_bytes())
            expected_arch = {'amd64': 'x86_64', 'arm64': 'aarch64'}[architecture]
            if any(row.get('arch') != expected_arch for row in manifest.get('package_inputs', [])):
                raise ValueError('Original Expat notice inputs have the wrong architecture')
            verified = collect_sources(base_provenance, directory, fetch=fetch, base_inventory=inventory)
            selected_header_roles = set()
            binding_method = 'Pinned original Alpine package build commit, complete recipes and checked source archive; caller verifies native base provenance.'
        elif origin == 'expat':
            from alpine_expat_sources import collect_sources
            if package_spec is None:
                raise ValueError('Alpine Expat notices require the reviewed package source map')
            if runtime_inventory is None:
                runtime_inventory = json.loads(checked_path(source, 'runtime-expat-identity.json').read_bytes())
            verified = collect_sources(package_spec, architecture, runtime_inventory, directory, fetch=fetch)
            selected_header_roles = set()
            binding_method = verified['binding_method']
        elif origin == 'openssl':
            from openssl_distribution_sources import collect_sources
            if package_spec is None or base_provenance is None:
                raise ValueError('OpenSSL notices require reviewed packages and checked native base provenance')
            if runtime_inventory is None:
                runtime_inventory = json.loads(checked_path(source, 'runtime-openssl-identity.json').read_bytes())
            verified = collect_sources(package_spec, architecture, base_provenance,
                                       runtime_inventory, directory, fetch=fetch)
            selected_header_roles = set()
            binding_method = verified['binding_method']
        else:
            raise ValueError('Only reviewed timezone, OpenSSL and Expat notice imports are supported')
        # Coverage wording is descriptive and may improve without changing an
        # input. Every file, checksum, role and source identity must still match.
        ignored = {'coverage'}
        if ({key: value for key, value in verified.items() if key not in ignored}
                != {key: value for key, value in manifest.items() if key not in ignored}):
            raise ValueError('Public notice source manifest differs from pinned verified inputs')
        output.mkdir(parents=True, exist_ok=True)
        provenance = {'origin': origin, 'version': verified['version'], 'architecture': architecture,
            'source_image_digest': None, 'provider_oci_binding': False,
            'binding_method': binding_method,
            'source_manifest_sha256': hashlib.sha256(manifest_path.read_bytes()).hexdigest()}
        if origin == 'openssl':
            provenance['native_image_digest'] = verified['native_image_digest']
            report = _inspect_records(source, output, origin=origin, version=verified['version'],
                architecture=architecture,
                manifest={**verified, 'files': [{**row, 'type': 'file'} for row in verified['files']]},
                binding=provenance)
            # AUTHORS carries the upstream project's explicit full attribution.
            # Preserve it alongside every full license discovered in the actual
            # matching release, without exporting thousands of source comments.
            for record in verified['files']:
                if record['role'] != 'upstream-attribution':
                    continue
                body = checked_path(source, record['path']).read_bytes()
                if not readable(body):
                    raise ValueError('OpenSSL attribution text must be readable')
                target = output / 'notices' / (record['sha256'] + '.txt')
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(body)
                report['notices'].append({'path': record['source_path'],
                    'notice_file': 'notices/' + target.name, 'sha256': record['sha256'],
                    'bytes': record['bytes'], 'encoding': 'utf-8',
                    'discovery': 'checked-public-upstream-attribution',
                    'provenance': {**provenance, 'source_url': record['url']}})
                report['standalone_notice_count'] += 1
            report['reviewed_public_source_files'] = verified['files']
            report['limitations'] = verified['coverage']
            (output / 'package-material-inventory.json').write_text(json.dumps(report, indent=2) + '\n')
            return report
        notices = []
        for record in verified['files']:
            if record['role'] in {'upstream-notice', 'upstream-lgpl-license'}:
                body = checked_path(source, record['path']).read_bytes()
                discovery = 'checked-public-standalone-notice'
            elif record['role'] in selected_header_roles:
                body = checked_path(source, record['path']).read_bytes()
                body = leading_notice(body, complete_file=True)
                if body is None:
                    raise ValueError('Reviewed public source copyright header is missing or incomplete')
                discovery = 'reviewed-public-source-copyright'
            else:
                continue
            if not readable(body):
                raise ValueError('Checked public notice must be readable complete text')
            value = hashlib.sha256(body).hexdigest()
            target = output / 'notices' / (value + '.txt')
            if target.parent.is_symlink() or target.is_symlink():
                raise ValueError('Unsafe public notice destination')
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(body)
            notices.append({'path': record['path'], 'notice_file': 'notices/' + target.name,
                'bytes': len(body), 'sha256': value, 'encoding': 'utf-8',
                'discovery': discovery, 'provenance': {**provenance, 'source_role': record['role'],
                    'source_url': record['url'], 'source_file_sha256': record['sha256']}})
        if not notices:
            raise ValueError('No full checked public notices found')
        report = {**provenance, 'schema': 1, 'success': True,
            'preferred_source_present': True, 'build_inputs_present': True,
            'notice_inventory_complete': True, 'notices': notices, 'warnings': [],
            'standalone_notice_count': len(notices), 'reviewable_comment_count': 0,
            'requires_runtime_comment_selection': False,
            'reviewed_public_source_files': verified['files'],
            'limitations': verified['coverage']}
        (output / 'package-material-inventory.json').write_text(json.dumps(report, indent=2) + '\n')
        return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--materials')
    mode.add_argument('--merge-bundles', nargs='+', metavar='NOTICE_DIRECTORY')
    mode.add_argument('--public-sources')
    mode.add_argument('--build-sources', help='Sources whose native signatures and acquisition replay the caller already verified')
    parser.add_argument('--output', required=True)
    parser.add_argument('--origin')
    parser.add_argument('--version')
    parser.add_argument('--architecture', choices=('amd64', 'arm64'))
    parser.add_argument('--source-digest')
    parser.add_argument('--native-image-digest')
    parser.add_argument('--source-manifest-sha256')
    parser.add_argument('--map', default=str(Path(__file__).resolve().parents[1] / 'docs/os-package-sources.json'))
    parser.add_argument('--base-provenance')
    parser.add_argument('--selected-comment', action='append', default=[],
                        help='Exact reviewed copyright comment path to export with standalone notices')
    args = parser.parse_args()
    if args.build_sources:
        if not all((args.origin, args.version, args.architecture,
                    args.native_image_digest, args.source_manifest_sha256)):
            parser.error('--build-sources requires origin, version, architecture, native-image-digest and source-manifest-sha256 from verified replay')
        result = inspect_build_provenance_sources(args.build_sources, args.output,
            origin=args.origin, version=args.version, architecture=args.architecture,
            native_image_digest=args.native_image_digest,
            source_manifest_sha256=args.source_manifest_sha256)
        print(json.dumps({key: result[key] for key in ('origin', 'success', 'warnings')}, indent=2))
        if not result['success']:
            raise SystemExit(1)
        return
    if args.merge_bundles:
        result = merge_notice_bundles(args.merge_bundles, args.output,
                                     selected_comment_paths=args.selected_comment)
        print(json.dumps({'packages': len(result['packages']), 'notice_texts': len(result['notices']),
                          'ready_for_runtime_distribution': result['ready_for_runtime_distribution']}, indent=2))
        if not result['ready_for_runtime_distribution']:
            raise SystemExit(1)
        return
    if args.public_sources:
        if not args.origin or not args.architecture:
            parser.error('--public-sources requires --origin and --architecture')
        spec = None
        if args.origin in {'tzdata', 'openssl'}:
            lock = json.loads(Path(args.map).read_bytes())
            matches = [row for row in lock['origins'] if row['origin'] == args.origin]
            if len(matches) != 1:
                parser.error('Reviewed source map must have exactly one requested public-source origin')
            spec = matches[0]
        base_provenance = None
        if args.base_provenance:
            path = Path(args.base_provenance)
            base_provenance = json.loads(checked_path(path.parent, path.name).read_bytes())
        result = import_public_notices(args.public_sources, args.output,
            origin=args.origin, architecture=args.architecture,
            package_spec=spec, base_provenance=base_provenance)
        print(json.dumps({'origin': result['origin'], 'notice_texts': len(result['notices']),
                          'provider_oci_binding': False}, indent=2))
        return
    if not all((args.origin, args.version, args.architecture, args.source_digest)):
        parser.error('--materials requires --origin, --version, --architecture and --source-digest')
    result = inspect_package_materials(args.materials, args.output, origin=args.origin,
        version=args.version, architecture=args.architecture, expected_digest=args.source_digest)
    print(json.dumps({key: result[key] for key in ('origin', 'success', 'warnings')}, indent=2))
    if not result['success']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
