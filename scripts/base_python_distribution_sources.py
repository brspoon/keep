#!/usr/bin/env python3
"""Retain matching sources for ensurepip wheels in the original Python layer.

The input APK must match the reviewed architecture-specific bytes. Wheel
metadata, every shipped Python module and six embedded distlib launchers are
then matched to pinned complete source archives; no package code is executed.
Later deletion of ensurepip does not remove the original immutable layer.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import tarfile
import zipfile

from oci_source_materials import open_layer, safe_name
from python_distribution_sources import collect_sources as collect_python, canonical_name, fetch_public


ROOT = Path(__file__).resolve().parents[1]
NOTICE_NAME = re.compile(r'^(?:license|licence|copying|copyright|notice|authors)(?:[._-]|$)', re.I)


def sha256(body):
    return hashlib.sha256(body).hexdigest()


def source_members(path):
    result = {}
    total = 0
    with tarfile.open(path, mode='r:*') as archive:
        for count, member in enumerate(archive, 1):
            name = safe_name(member.name)
            if count > 100000 or member.size > 32 * 1024 * 1024:
                raise ValueError('Base Python source archive exceeds member limits')
            if member.isfile():
                total += member.size
                if total > 128 * 1024 * 1024 or name in result:
                    raise ValueError('Base Python source archive exceeds limits or repeats a file')
                result[name] = archive.extractfile(member).read()
            elif not member.isdir():
                raise ValueError('Base Python source archive must not contain links or special files')
    return result


def apk_wheels(apk, architecture, lock):
    """Verify exact APK and retain only declared wheels as in-memory bytes."""
    apk = Path(apk)
    if apk.is_symlink() or not apk.is_file():
        raise ValueError('Original Python APK must be a regular file')
    hasher = hashlib.sha256()
    with apk.open('rb') as stream:
        while chunk := stream.read(1024 * 1024):
            hasher.update(chunk)
    expected = lock['package']['apk_sha256'].get(architecture)
    if architecture not in {'amd64', 'arm64'} or hasher.hexdigest() != expected:
        raise ValueError('Original Python APK differs from reviewed architecture-specific bytes')
    required = {row['apk_path']: row for row in lock['wheels']}
    found, metadata = {}, []
    with open_layer(apk, 'application/vnd.oci.image.layer.v1.tar+gzip', max_bytes=512 * 1024 * 1024) as stream:
        with tarfile.open(fileobj=stream, mode='r|', ignore_zeros=True) as archive:
            for count, member in enumerate(archive, 1):
                name = safe_name(member.name)
                if count > 100000:
                    raise ValueError('Original Python APK exceeds archive member limit')
                if name == '.PKGINFO' or name in required:
                    if not member.isfile() or member.size > 8 * 1024 * 1024:
                        raise ValueError('Original Python APK metadata/wheel must be a bounded regular file')
                    body = archive.extractfile(member).read()
                    if name == '.PKGINFO':
                        metadata.append(body)
                    else:
                        if name in found:
                            raise ValueError('Original Python APK repeats an ensurepip wheel')
                        row = required[name]
                        if len(body) != row['bytes'] or sha256(body) != row['sha256']:
                            raise ValueError('Original Python APK wheel differs from reviewed bytes')
                        found[name] = body
    if len(metadata) != 1 or set(found) != set(required):
        raise ValueError('Original Python APK requires one metadata record and both ensurepip wheels')
    fields = {}
    for line in metadata[0].decode('utf-8').splitlines():
        if ' = ' in line:
            key, value = line.split(' = ', 1)
            if key in {'pkgname', 'pkgver', 'origin', 'commit', 'arch'}:
                if key in fields:
                    raise ValueError('Original Python APK repeats an identity field')
                fields[key] = value
    package = lock['package']
    expected_identity = {'pkgname': package['name'], 'pkgver': package['version'],
        'origin': package['origin'], 'commit': package['build_commit'],
        'arch': {'amd64': 'x86_64', 'arm64': 'aarch64'}[architecture]}
    if fields != expected_identity:
        raise ValueError('Original Python APK build metadata differs from reviewed identity')
    return found, fields


def wheel_identity(body, row):
    files = {}
    total = 0
    with zipfile.ZipFile(io.BytesIO(body)) as archive:
        for count, entry in enumerate(archive.infolist(), 1):
            name = safe_name(entry.filename)
            if count > 10000 or name in files or entry.file_size > 32 * 1024 * 1024:
                raise ValueError('Base Python wheel has duplicate or oversized entries')
            if entry.is_dir():
                continue
            if (entry.external_attr >> 16) & 0o170000 == 0o120000:
                raise ValueError('Base Python wheel must not contain symlinks')
            total += entry.file_size
            if total > 64 * 1024 * 1024:
                raise ValueError('Base Python wheel exceeds decoded byte limit')
            files[name] = archive.read(entry)
    metadata = [body for name, body in files.items() if name.endswith('.dist-info/METADATA')]
    if len(metadata) != 1:
        raise ValueError('Base Python wheel requires one metadata record')
    text = metadata[0].decode('utf-8')
    names = re.findall(r'^Name: (.+)$', text, re.M)
    versions = re.findall(r'^Version: (.+)$', text, re.M)
    if names != [row['name']] or versions != [row['version']]:
        raise ValueError('Base Python wheel name/version differs from reviewed source')
    return files


def retain_notices(root, notices, architecture, lock, distribution):
    """Export only notices bound to actual wheels or their native source."""
    directory = root / 'runtime-notices' / distribution['name']
    directory.mkdir(parents=True, exist_ok=True)
    rows = []
    provenance = {'origin': 'python-3.14-ensurepip', 'version': lock['package']['version'],
        'architecture': architecture, 'source_image_digest': None,
        'distribution': distribution['name'], 'distribution_version': distribution['version'],
        'original_apk_sha256': lock['package']['apk_sha256'][architecture],
        'binding_method': 'Exact original APK wheel/source/archive byte comparison'}
    for notice in notices:
        body = notice.pop('body')
        relative = 'notices/' + sha256(body) + '.txt'
        target = directory / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(body)
        rows.append({**notice, 'notice_file': relative, 'sha256': sha256(body),
                     'bytes': len(body), 'encoding': 'utf-8',
                     'discovery': 'checked-original-ensurepip-standalone-notice',
                     'provenance': provenance})
    report = {**provenance, 'schema': 1, 'success': True, 'notices': rows,
        'preferred_source_present': True, 'build_inputs_present': True,
        'notice_inventory_complete': True, 'standalone_notice_count': len(rows),
        'reviewable_comment_count': 0, 'requires_runtime_comment_selection': False,
        'warnings': [], 'limitations': 'Original APK and complete source archive bytes are checked; original base signature is checked by the enclosing bundle.'}
    (directory / 'package-material-inventory.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    return {'distribution': distribution['name'], 'notices': len(rows),
            'inventory': (directory / 'package-material-inventory.json').relative_to(root).as_posix()}


def collect_sources(apk, architecture, output_root, *, lock=None, fetch=fetch_public):
    lock = lock or json.loads((ROOT / 'docs/base-python-sources.json').read_text())
    if lock.get('format') != 'keep-original-base-python-source-lock-v1':
        raise ValueError('Unsupported original-base Python source lock')
    wheels, package_identity = apk_wheels(apk, architecture, lock)
    root = Path(output_root)
    if root.is_symlink() or root.exists() and any(root.iterdir()):
        raise ValueError('Base Python source output must be empty without symlinks')
    root.mkdir(parents=True, exist_ok=True)
    requirements = root / 'base-layer-requirements.txt'
    requirements.write_text(''.join(f"{row['name']}=={row['version']}\n" for row in lock['sources']))
    pins = {(row['name'], row['version']): row for row in lock['sources']}

    def locked_fetch(url):
        body = fetch(url)
        if url.startswith('https://pypi.org/pypi/'):
            metadata = json.loads(body)
            key = (canonical_name(metadata['info']['name']), metadata['info']['version'])
            pin = pins.get(key)
            sdists = [row for row in metadata['urls'] if row.get('packagetype') == 'sdist']
            if (pin is None or len(sdists) != 1 or sdists[0]['url'] != pin['url']
                    or sdists[0]['filename'] != pin['filename'] or sdists[0]['digests']['sha256'] != pin['sha256']):
                raise ValueError('Base Python source identity differs from reviewed lock')
        return body

    sources = collect_python(requirements, root, fetch=locked_fetch)
    archives = {row['name']: source_members(root / row['archive']) for row in sources['packages']}
    wheel_reports, notice_reports = [], []
    native = []
    for row in lock['wheels']:
        body = wheels[row['apk_path']]
        files = wheel_identity(body, row)
        name, version = row['name'], row['version']
        source = archives[name]
        modules, notices = [], []
        for path, module in files.items():
            if path.startswith(name + '/') and path.endswith('.py'):
                candidates = [f'{name}-{version}/src/{path}', f'{name}-{version}/{path}']
                matches = [candidate for candidate in candidates if source.get(candidate) == module]
                if len(matches) != 1:
                    raise ValueError('Installed base wheel Python module differs from source archive: ' + path)
                modules.append({'wheel_path': path, 'source_member': matches[0], 'sha256': sha256(module), 'bytes': len(module)})
            elif NOTICE_NAME.match(Path(path).name):
                relative = path.split('.dist-info/licenses/', 1)[-1]
                candidates = [f'{name}-{version}/{relative}', f'{name}-{version}/src/{relative}']
                matches = [candidate for candidate in candidates if source.get(candidate) == module]
                if len(matches) != 1:
                    raise ValueError('Original base wheel notice differs from complete source archive: ' + path)
                notices.append({'path': path, 'source_member': matches[0], 'body': module})
        if not modules:
            raise ValueError('Original base wheel has no matched preferred Python sources')
        if not notices:
            raise ValueError('Original base wheel has no source-bound full attribution files')
        if name == 'pip':
            vendor = files.get('pip/_vendor/vendor.txt', b'').decode('utf-8')
            if re.findall(r'^distlib==(.+)$', vendor, re.M) != [lock['distlib_vendor_version']]:
                raise ValueError('Original pip distlib vendor version differs from reviewed source')
            actual_native = {path for path in files if path.endswith(('.exe', '.dll', '.so'))}
            reviewed_native = {resource['path'] for resource in lock['native_resources'] if resource['wheel'] == name}
            if actual_native != reviewed_native:
                raise ValueError('Original pip embedded native resource inventory differs from reviewed lock')
            for resource in lock['native_resources']:
                if resource['wheel'] != name:
                    continue
                payload = files[resource['path']]
                source_payload = archives['distlib'].get(resource['matching_distlib_member'])
                if payload != source_payload or sha256(payload) != resource['sha256'] or len(payload) != resource['bytes']:
                    raise ValueError('Original pip native launcher differs from complete distlib source distribution')
                native.append(resource)
        elif any(path.endswith(('.exe', '.dll', '.so')) for path in files):
            raise ValueError('Unreviewed native resource in base wheel')
        wheel_reports.append({**row, 'matched_python_modules': modules})
        notice_reports.append(retain_notices(root, notices, architecture, lock, row))
    distlib = archives['distlib']
    build_sources = []
    for relative in lock['required_distlib_build_sources']:
        name = 'distlib-' + lock['distlib_vendor_version'] + '/' + safe_name(relative)
        if name not in distlib:
            raise ValueError('Complete distlib native launcher build source is missing')
        build_sources.append({'source_member': name, 'sha256': sha256(distlib[name]), 'bytes': len(distlib[name])})
    native_license = 'distlib-' + lock['distlib_vendor_version'] + '/LICENSE.txt'
    if native_license not in distlib:
        raise ValueError('Complete distlib launcher attribution is missing')
    notice_reports.append(retain_notices(root, [{'path': native_license, 'source_member': native_license,
        'body': distlib[native_license]}], architecture, lock,
        {'name': 'distlib', 'version': lock['distlib_vendor_version']}))
    report = {'format': 'keep-original-base-python-sources-v1', 'architecture': architecture,
        'scope': 'Supplemental immutable original Python APK layer; separate from installed application Python packages.',
        'package_identity': package_identity, 'apk_sha256': lock['package']['apk_sha256'][architecture],
        'wheels': wheel_reports, 'source_packages': sources['packages'], 'native_resources': native,
        'native_build_sources': build_sources, 'runtime_notice_inventories': notice_reports,
        'binding_method': 'Exact reviewed original APK and wheel bytes; every wheel Python module matches the pinned source archive, and embedded launcher bytes match the complete distlib source distribution.',
        'limitations': 'The caller must separately verify the original native base provenance/signature. This helper does not claim a Docker source-image attestation.'}
    (root / 'base-python-sources.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apk', type=Path, required=True)
    parser.add_argument('--architecture', choices=('amd64', 'arm64'), required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = collect_sources(args.apk, args.architecture, args.output)
    print(json.dumps({'architecture': args.architecture, 'source_packages': len(report['source_packages']),
                      'matched_python_modules': sum(len(row['matched_python_modules']) for row in report['wheels']),
                      'native_resources': len(report['native_resources'])}))


if __name__ == '__main__':
    main()
