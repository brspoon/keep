#!/usr/bin/env python3
"""Retain corresponding sources in version draft releases, outside Actions quota.

Main validation retains its original bundles privately through validated_build.
Version-release writes here require confirmed manual publication of current main.
"""
import argparse
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request

from build_distribution_bundle import archive_tree, file_sha
from publish_image import hub
from publish_release import github_repository, repository_visibility, require_current_source, require_manual_dispatch
from registry_transfer import checked_digest

ARCHES = ('amd64', 'arm64')
HASH = re.compile(r'[0-9a-f]{64}\Z')


def evidence_names(arch):
    reports = [f'candidate-{arch}.json'] + [f'candidate-{kind}-{arch}.json' for kind in
               ('layers', 'notices', 'provenance', 'regression', 'review', 'sbom', 'scout', 'signature')]
    sources = [f'source-{kind}-{arch}.log' for kind in
               ('acquisition-base', 'acquisition-packages', 'distribution')]
    return reports + sources


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


def api(path, *, method='GET', data=None):
    request = urllib.request.Request('https://api.github.com/repos/' + github_repository() + path,
        method=method, data=json.dumps(data).encode() if data is not None else None,
        headers={'Authorization': 'Bearer ' + os.environ['GITHUB_TOKEN'],
                 'Accept': 'application/vnd.github+json', 'Content-Type': 'application/json'})
    with urllib.request.build_opener(NoRedirect()).open(request, timeout=60) as response:
        return json.load(response)


def guard():
    require_manual_dispatch(True)
    if github_repository() != 'brspoon/keep':
        raise ValueError('Release material writes are restricted to Keep')
    require_current_source(os.environ['GITHUB_SHA'], True)
    version = Path('VERSION').read_text().strip()
    if not re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', version):
        raise ValueError('Invalid release version')
    return version


def bundle(arch, *, verify_files=False):
    version = Path('VERSION').read_text().strip()
    path = Path('distribution') / f'keep-{version}-source-materials-{arch}.tar.gz'
    prefix = path.name.removesuffix('.tar.gz') + '/'
    expected = file_sha(path)
    checksum = path.with_name(path.name + '.sha256')
    if checksum.read_text() != expected + '  ' + path.name + '\n':
        raise ValueError('Source bundle checksum differs')
    with tarfile.open(path, 'r:gz') as archive:
        manifests = [member for member in archive.getmembers() if member.name == prefix + 'MANIFEST.json']
        if len(manifests) != 1:
            raise ValueError('Require one source manifest')
        manifest_member = manifests[0]
        if not manifest_member.isfile() or manifest_member.size > 16 * 1024 * 1024:
            raise ValueError('Invalid source manifest')
        manifest = json.load(archive.extractfile(manifest_member))
        if (manifest.get('format') != 'keep-container-source-bundle-v1' or
                manifest.get('revision') != os.environ['GITHUB_SHA'] or
                manifest.get('version') != version or manifest.get('architecture') != arch):
            raise ValueError('Source bundle identity differs from tested source')
        if verify_files:
            declared = {row['path']: row for row in manifest['files']}
            if len(declared) != len(manifest['files']):
                raise ValueError('Duplicate source inventory member')
            seen = set()
            for member in archive.getmembers():
                if not member.name.startswith(prefix) or '..' in PurePosixPath(member.name).parts:
                    raise ValueError('Unsafe source archive member')
                if member.isdir():
                    continue
                name = member.name[len(prefix):]
                if name == 'MANIFEST.json':
                    continue
                if not member.isfile() or name in seen or name not in declared:
                    raise ValueError('Unexpected source archive member')
                seen.add(name)
                row = declared[name]
                sha = hashlib.sha256()
                with archive.extractfile(member) as stream:
                    while chunk := stream.read(1024 * 1024):
                        sha.update(chunk)
                if member.size != row['bytes'] or sha.hexdigest() != row['sha256']:
                    raise ValueError('Source archive member checksum differs')
            if seen != set(declared):
                raise ValueError('Incomplete corresponding-source archive')
    return path, {'archive': path.name, 'sha256': expected, 'bytes': path.stat().st_size,
                  'manifest': manifest}


def report(arch):
    _, proof = bundle(arch)
    target = Path('distribution') / f'source-bundle-{arch}.json'
    target.write_text(json.dumps(proof, sort_keys=True) + '\n')
    print('::group::Verified corresponding-source inventory ' + arch)
    print(json.dumps(proof, sort_keys=True), flush=True)
    print('::endgroup::', flush=True)


def tested_digests():
    values = json.loads(os.environ['TESTED_DIGESTS'])
    if set(values) != set(ARCHES):
        raise ValueError('Both native tested digests are required')
    return {arch: checked_digest(value) for arch, value in values.items()}


def portable_evidence(path, arch, identity):
    proof = json.loads(path.read_text())
    candidate, cleanup = proof.get('candidate', {}), proof.get('cleanup', {})
    project = proof.get('project', '')
    if (proof.get('schema') != 'keep.portable-container-trial.v1' or proof.get('outcome') != 'passed' or
            not re.fullmatch(r'keep-recovery-[a-f0-9]{12}', project) or
            any(candidate.get(key) != identity[key] for key in ('version', 'revision', 'architecture')) or
            candidate.get('os') != 'linux' or candidate.get('image_id') != identity['config_digest']):
        raise ValueError('Portable recovery proof differs from the tested native image')
    required_volumes = {project + '-' + name for name in ('fresh-data', 'fixture-data', 'restore-data', 'rollback-data')}
    if (cleanup.get('containers_removed') is not True or
            set(cleanup.get('volumes_removed', [])) != required_volumes or
            any(cleanup.get(key) for key in ('preserved_volumes', 'preserved_networks',
                                           'container_cleanup_error', 'network_inventory_error')) or
            proof.get('failure') or proof.get('report_error')):
        raise ValueError('Portable recovery resources were not verified clean')


def installer_evidence(path, arch, identity):
    proof = json.loads(path.read_text())
    candidate, cleanup = proof.get('candidate', {}), proof.get('cleanup', {})
    runner_sha = file_sha(Path(__file__).with_name('installer_container_trial.py'))
    if (proof.get('schema') != 'keep.installer-container-trial.v1' or proof.get('outcome') != 'passed'
            or proof.get('runner_sha256') != runner_sha or proof.get('error_type')
            or any(candidate.get(key) != identity[key] for key in ('version', 'revision', 'architecture'))
            or candidate.get('image_id') != identity['config_digest']):
        raise ValueError('Installer trial proof differs from the tested native image')
    if (cleanup.get('preexisting_resources') != {'containers': [], 'volumes': [], 'networks': []}
            or cleanup.get('resources_absent') is not True or cleanup.get('removed_volume') is not True
            or cleanup.get('error_type') or cleanup.get('trial_not_started')):
        raise ValueError('Installer trial resources were not verified clean')
    required = {
        'fresh-install': {'both_services_healthy': True, 'http_setup': True, 'cookie_http_only': True,
                          'cookie_same_site': 'Lax', 'cookie_secure': False},
        'installer-rerun': {'environment_unchanged': True, 'resources_unchanged': True, 'bootstrap_rotated': True},
        'owner-preservation': {'owner_preserved': True, 'bootstrap_disabled': True, 'database_integrity': 'ok'},
    }
    phases = proof.get('phases', [])
    if (not isinstance(phases, list) or len(phases) != len(required)
            or any(not isinstance(phase, dict) for phase in phases)
            or [phase.get('name') for phase in phases] != list(required)):
        raise ValueError('Installer trial lifecycle proof is incomplete')
    for phase in phases:
        if phase.get('status') != 'passed':
            raise ValueError('Installer trial lifecycle proof is incomplete')
        for key, expected in required[phase['name']].items():
            actual = phase.get(key)
            if (actual is not expected if isinstance(expected, bool) else actual != expected):
                raise ValueError('Installer trial lifecycle proof is incomplete')


def fetch(arch):
    version = guard()
    digests = tested_digests()
    image = os.environ['DOCKERHUB_IMAGE']
    if image != 'brspoon/keep':
        raise ValueError('Release material retrieval is restricted to Keep')
    username, secret = os.environ['DOCKERHUB_USERNAME'], os.environ['DOCKERHUB_TOKEN']
    token = hub('auth/token', payload={'identifier': username, 'secret': secret})['access_token']
    repository_visibility(hub('repositories/' + image + '/', token), 'is_private', 'Docker Hub')
    reference = image + '@' + digests[arch]
    with tempfile.TemporaryDirectory(prefix='keep-materials-pull-') as directory:
        env = {**os.environ, 'DOCKER_CONFIG': directory}
        subprocess.run(['docker', 'login', '--username', username, '--password-stdin'],
                       input=secret, text=True, env=env, check=True)
        subprocess.run(['docker', 'pull', '--platform', 'linux/' + arch, reference], env=env, check=True)
        subprocess.run(['docker', 'tag', reference, 'keep-ci'], env=env, check=True)
        inspected = json.loads(subprocess.check_output(['docker', 'image', 'inspect', reference], env=env))[0]
    labels = inspected['Config']['Labels']
    if (inspected['Architecture'] != arch or inspected['Os'] != 'linux' or
            labels.get('org.opencontainers.image.revision') != os.environ['GITHUB_SHA'] or
            labels.get('org.opencontainers.image.version') != version or
            labels.get('org.opencontainers.image.source') != 'https://github.com/' + github_repository()):
        raise ValueError('Retrieved native image identity differs')
    checked_digest(inspected['Id'])
    original = json.loads(Path(f'candidate-notices-{arch}.json').read_text())
    actual = json.loads(subprocess.check_output(['docker', 'run', '--rm', '--network', 'none',
        '--read-only', '-v', str(Path('scripts').resolve()) + ':/checks:ro', 'keep-ci',
        'python', '-B', '/checks/image_distribution.py', '--runtime']))
    if actual != original:
        raise ValueError('Retrieved runtime notice inventory differs from the tested image')
    Path(f'release-image-{arch}.json').write_text(json.dumps({
        'version': version, 'revision': os.environ['GITHUB_SHA'], 'architecture': arch,
        'native_digest': digests[arch], 'config_digest': inspected['Id']}, sort_keys=True) + '\n')


def draft(version, *, create=False):
    # The tag endpoint returns published releases only. List authenticated
    # releases so an unpublished draft can be reused without creating a duplicate.
    matches = []
    page = 1
    while True:
        rows = api(f'/releases?per_page=100&page={page}')
        matches.extend(row for row in rows if row.get('tag_name') == version)
        if len(rows) < 100:
            break
        page += 1
    if len(matches) > 1:
        raise ValueError('Multiple release drafts match this version')
    if matches:
        release = matches[0]
    elif create:
        # Only the single prepare job creates a draft; native jobs upload later.
        release = api('/releases', method='POST', data={
            'tag_name': version, 'target_commitish': os.environ['GITHUB_SHA'],
            'name': 'Keep ' + version + ' candidate', 'draft': True,
            'body': 'Release candidate. Corresponding sources and native security evidence are retained here. Release acceptance and finalization are pending.'})
    else:
        raise ValueError('A prepared release draft is required')
    if (release.get('draft') is not True or release.get('tag_name') != version or
            release.get('target_commitish') != os.environ['GITHUB_SHA'] or
            not isinstance(release.get('id'), int)):
        raise ValueError('Release draft differs from the confirmed source')
    return release


def upload(release, path):
    path = Path(path)
    expected, size = file_sha(path), path.stat().st_size
    assets = api(f"/releases/{release['id']}/assets?per_page=100")
    old = [row for row in assets if row['name'] == path.name]
    if old:
        if len(old) != 1 or old[0].get('digest') != 'sha256:' + expected or old[0]['size'] != size:
            raise ValueError('An existing release asset differs; refusing overwrite')
        return old[0]
    # Stream directly to GitHub's fixed upload host. Never forward credentials
    # through redirects or load a 500-MB source bundle into memory.
    url_path = '/repos/' + github_repository() + f"/releases/{release['id']}/assets?" + urllib.parse.urlencode({'name': path.name})
    connection = http.client.HTTPSConnection('uploads.github.com', timeout=300)
    try:
        connection.putrequest('POST', url_path)
        for name, value in {'Authorization': 'Bearer ' + os.environ['GITHUB_TOKEN'],
                            'Content-Type': 'application/octet-stream', 'Content-Length': str(size),
                            'Accept': 'application/vnd.github+json', 'User-Agent': 'Keep-release-materials'}.items():
            connection.putheader(name, value)
        connection.endheaders()
        with path.open('rb') as stream:
            while chunk := stream.read(1024 * 1024):
                connection.send(chunk)
        response = connection.getresponse()
        body = response.read(1024 * 1024)
        if response.status != 201:
            raise ValueError('Release asset upload failed with HTTP ' + str(response.status))
        result = json.loads(body)
    finally:
        connection.close()
    if result.get('digest') != 'sha256:' + expected or result.get('size') != size:
        raise ValueError('Uploaded asset digest or length differs')
    return result


def registry_config(native):
    """Bind the immutable uploaded manifest to the original local image config."""
    native = checked_digest(native)
    opener = urllib.request.build_opener(NoRedirect())
    basic = base64.b64encode((os.environ['DOCKERHUB_USERNAME'] + ':' +
                              os.environ['DOCKERHUB_TOKEN']).encode()).decode('ascii')
    query = urllib.parse.urlencode({'service': 'registry.docker.io',
                                    'scope': 'repository:brspoon/keep:pull'})
    request = urllib.request.Request('https://auth.docker.io/token?' + query,
                                     headers={'Authorization': 'Basic ' + basic})
    with opener.open(request, timeout=30) as response:
        body = response.read(64 * 1024 + 1)
    if len(body) > 64 * 1024:
        raise ValueError('Registry read token response exceeds its limit')
    token = json.loads(body)['token']
    if not isinstance(token, str) or not re.fullmatch(r'[A-Za-z0-9_.-]{20,8192}', token):
        raise ValueError('Registry returned an invalid read token')
    request = urllib.request.Request('https://registry-1.docker.io/v2/brspoon/keep/manifests/' + native,
        headers={'Authorization': 'Bearer ' + token,
                 'Accept': 'application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json'})
    with opener.open(request, timeout=30) as response:
        body = response.read(2 * 1024 * 1024 + 1)
    if len(body) > 2 * 1024 * 1024 or 'sha256:' + hashlib.sha256(body).hexdigest() != native:
        raise ValueError('Immutable native manifest bytes differ from the tested transfer digest')
    manifest = json.loads(body)
    if (manifest.get('schemaVersion') != 2 or manifest.get('manifests') is not None
            or manifest.get('subject') is not None or not isinstance(manifest.get('config'), dict)):
        raise ValueError('Require one native image manifest without references')
    return checked_digest(manifest['config'].get('digest'))


def archive_native(arch):
    """Archive the original tested job files directly, without Actions storage."""
    version = guard()
    run, attempt = os.environ['GITHUB_RUN_ID'], os.environ['GITHUB_RUN_ATTEMPT']
    if not re.fullmatch(r'[1-9][0-9]{0,19}', run) or not re.fullmatch(r'[1-9][0-9]{0,9}', attempt):
        raise ValueError('Invalid native workflow attempt')
    path = Path(f'transfer-{arch}.json')
    if not path.is_file() or path.is_symlink() or path.stat().st_size > 8192:
        raise ValueError('Require the original native transfer record')
    record = json.loads(path.read_text())
    native = checked_digest(record.get('digest'))
    if record != {'architecture': arch, 'digest': native, 'revision': os.environ['GITHUB_SHA'],
                  'run_id': run, 'run_attempt': attempt}:
        raise ValueError('Native transfer record differs from this exact workflow attempt')
    image = os.environ['DOCKERHUB_IMAGE']
    if image != 'brspoon/keep':
        raise ValueError('Native evidence is restricted to Keep')
    token = hub('auth/token', payload={'identifier': os.environ['DOCKERHUB_USERNAME'],
                                     'secret': os.environ['DOCKERHUB_TOKEN']})['access_token']
    repository_visibility(hub('repositories/' + image + '/', token), 'is_private', 'Docker Hub')
    tag = f'transfer-{run}-{attempt}-{arch}'
    if hub('repositories/' + image + '/tags/' + tag + '/', token).get('digest') != native:
        raise ValueError('Native transfer tag changed before source archival')
    inspected = json.loads(subprocess.check_output(['docker', 'image', 'inspect', 'keep-ci']))[0]
    labels = inspected.get('Config', {}).get('Labels') or {}
    if (inspected.get('Architecture') != arch or inspected.get('Os') != 'linux'
            or inspected.get('Config', {}).get('User') != '10001:10001'
            or labels.get('org.opencontainers.image.version') != version
            or labels.get('org.opencontainers.image.revision') != os.environ['GITHUB_SHA']
            or labels.get('org.opencontainers.image.source') != 'https://github.com/' + github_repository()):
        raise ValueError('Original tested native image identity differs')
    identity = {'version': version, 'revision': os.environ['GITHUB_SHA'], 'architecture': arch,
                'native_digest': native, 'config_digest': checked_digest(inspected.get('Id'))}
    if registry_config(native) != identity['config_digest']:
        raise ValueError('Transferred native manifest differs from the original tested image config')
    Path(f'release-image-{arch}.json').write_text(json.dumps(identity, sort_keys=True) + '\n')
    archive(arch, native_digest=native)


def archive(arch, native_digest=None):
    version = guard()
    native = checked_digest(native_digest) if native_digest is not None else tested_digests()[arch]
    source, proof = bundle(arch, verify_files=True)
    original = json.loads((Path('distribution') / f'source-bundle-{arch}.json').read_text())
    if original['manifest'] != proof['manifest']:
        raise ValueError('Retained source files differ from the original native CI bundle')
    identity = json.loads(Path(f'release-image-{arch}.json').read_text())
    if identity != {'version': version, 'revision': os.environ['GITHUB_SHA'], 'architecture': arch,
                    'native_digest': native, 'config_digest': identity.get('config_digest')}:
        raise ValueError('Native release identity differs')
    checked_digest(identity['config_digest'])
    validation_path = Path(f'validation-provenance-{arch}.json')
    validation = None
    if os.environ.get('KEEP_VALIDATION_RUN_ID') or os.environ.get('GITHUB_EVENT_NAME') == 'workflow_dispatch':
        if not validation_path.is_file() or validation_path.is_symlink() or validation_path.stat().st_size > 128 * 1024:
            raise ValueError('Approved publication requires original main validation provenance')
        import validated_build
        validation = json.loads(validation_path.read_text())
        index = validated_build.verify_provenance(validation, arch, identity['config_digest'])
        validated_build.verify_files(index, arch)
    reports = [Path(name) for name in evidence_names(arch)]
    if any(not p.is_file() or p.is_symlink() for p in reports):
        raise ValueError('Require all twelve original native security reports')
    # Existing review rechecks the unsuppressed report and fixed/blocked ledger.
    # Reassess current exception expiry without replacing the review report
    # produced by the original successful main build.
    original_review = Path(f'candidate-review-{arch}.json')
    review_bytes = original_review.read_bytes()
    try:
        subprocess.run(['python3', 'scripts/review_image.py', arch], check=True)
    finally:
        original_review.write_bytes(review_bytes)
    portable = Path(f'portable-recovery-{arch}.json')
    if not portable.is_file() or portable.is_symlink():
        raise ValueError('Native portable recovery evidence is required')
    portable_evidence(portable, arch, identity)
    installer = Path(f'installer-trial-{arch}.json')
    if not installer.is_file() or installer.is_symlink():
        raise ValueError('Native one-command installer evidence is required')
    installer_evidence(installer, arch, identity)
    outputs = [source, source.with_name(source.name + '.sha256')]
    with tempfile.TemporaryDirectory(prefix='keep-native-evidence-') as directory:
        stage = Path(directory)
        records = []
        retained = [*reports, portable, installer, Path('distribution') / f'source-bundle-{arch}.json']
        if validation is not None:
            retained.append(validation_path)
            identity['main_validation'] = validation_summary(validation)
        for path in retained:
            body = path.read_bytes()
            records.append({'path': path.name, 'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest()})
            (stage / path.name).write_bytes(body)
        identity.update(source={'name': source.name, 'sha256': proof['sha256'], 'bytes': proof['bytes']},
                        evidence=records, run_id=os.environ['GITHUB_RUN_ID'],
                        run_attempt=int(os.environ['GITHUB_RUN_ATTEMPT']))
        (stage / 'IDENTITY.json').write_text(json.dumps(identity, sort_keys=True) + '\n')
        security = Path('distribution') / f'keep-{version}-security-evidence-{arch}.tar.gz'
        archive_tree(stage, security, security.name.removesuffix('.tar.gz'))
    checksum = security.with_name(security.name + '.sha256')
    checksum.write_text(file_sha(security) + '  ' + security.name + '\n')
    release = draft(version)
    for path in [*outputs, security, checksum]:
        guard()
        upload(release, path)


def asset_body(asset):
    url = 'https://api.github.com/repos/' + github_repository() + f"/releases/assets/{asset['id']}"
    request = urllib.request.Request(url, headers={'Authorization': 'Bearer ' + os.environ['GITHUB_TOKEN'],
                                                  'Accept': 'application/octet-stream'})
    opener = urllib.request.build_opener(NoRedirect())
    try:
        response = opener.open(request, timeout=60)
    except urllib.error.HTTPError as error:
        location = error.headers.get('Location', '')
        parsed = urllib.parse.urlsplit(location)
        if (error.code != 302 or parsed.scheme != 'https' or
                parsed.netloc != 'release-assets.githubusercontent.com' or parsed.fragment):
            raise
        response = opener.open(urllib.request.Request(location), timeout=60)
    with response:
        body = response.read(32 * 1024 * 1024 + 1)
    if (len(body) != asset['size'] or len(body) > 32 * 1024 * 1024 or
            'sha256:' + hashlib.sha256(body).hexdigest() != asset.get('digest')):
        raise ValueError('Release evidence asset checksum or length differs')
    return body


def validation_summary(proof):
    """Separate the producer's identity from this manual publication run."""
    build = proof['index']['build']
    artifact = proof['artifact']
    return {'run_id': build['run_id'], 'run_attempt': build['run_attempt'],
            'job_id': build['job_id'], 'workflow_id': build['workflow_id'],
            'artifact_id': artifact['id'], 'artifact_digest': artifact['digest']}


def verify_durable_validation(identity, proof, arch):
    import validated_build
    index = validated_build.verify_provenance(proof, arch, identity['config_digest'])
    if identity.get('main_validation') != validation_summary(proof):
        raise ValueError('Durable main validation producer identity differs')
    originals = {PurePosixPath(row['path']).name: row for row in index['assets']}
    source = originals[f"keep-{identity['version']}-source-materials-{arch}.tar.gz"]
    if identity['source'] != {'name': PurePosixPath(source['path']).name,
                             'sha256': source['sha256'], 'bytes': source['bytes']}:
        raise ValueError('Durable sources differ from the original main validation')
    for record in identity['evidence']:
        if record['path'] == f'validation-provenance-{arch}.json':
            continue
        original = originals.get(record['path'], {})
        if record['sha256'] != original.get('sha256') or record['bytes'] != original.get('bytes'):
            raise ValueError('Durable native evidence differs from the original main validation')


def verify_identities(version, release, digests=None):
    rows = api(f"/releases/{release['id']}/assets?per_page=100")
    assets = {row['name']: row for row in rows}
    if len(assets) != len(rows):
        raise ValueError('Duplicate release asset identity')
    identities = {}
    with tempfile.TemporaryDirectory(prefix='keep-release-readback-') as directory:
        for arch in ARCHES:
            security_name = f'keep-{version}-security-evidence-{arch}.tar.gz'
            security = assets[security_name]
            path = Path(directory) / security_name
            path.write_bytes(asset_body(security))
            with tarfile.open(path, 'r:gz') as package:
                prefix = security_name.removesuffix('.tar.gz') + '/'
                identity = json.load(package.extractfile(prefix + 'IDENTITY.json'))
                if (identity.get('version') != version or identity.get('revision') != os.environ['GITHUB_SHA'] or
                        identity.get('architecture') != arch or
                        (digests is not None and identity.get('native_digest') != digests[arch]) or
                        identity.get('run_id') != os.environ['GITHUB_RUN_ID'] or
                        identity.get('run_attempt') != int(os.environ['GITHUB_RUN_ATTEMPT'])):
                    raise ValueError('Durable release evidence identity differs')
                checked_digest(identity['native_digest'])
                checked_digest(identity['config_digest'])
                required = set(evidence_names(arch)) | {f'portable-recovery-{arch}.json', f'installer-trial-{arch}.json',
                                                      f'source-bundle-{arch}.json'}
                require_validation = bool(os.environ.get('KEEP_VALIDATION_RUN_ID')) or os.environ.get('GITHUB_EVENT_NAME') == 'workflow_dispatch'
                if require_validation or identity.get('main_validation') is not None:
                    required.add(f'validation-provenance-{arch}.json')
                records = identity['evidence']
                if len(records) != len(required) or {row['path'] for row in records} != required:
                    raise ValueError('Durable evidence inventory is incomplete')
                members = [member for member in package.getmembers() if not member.isdir()]
                if (len(members) != len(required) + 1 or
                        {member.name for member in members} != {prefix + name for name in required | {'IDENTITY.json'}} or
                        any(not member.isfile() for member in members)):
                    raise ValueError('Unexpected durable evidence archive member')
                for record in identity['evidence']:
                    data = package.extractfile(prefix + record['path']).read()
                    if len(data) != record['bytes'] or hashlib.sha256(data).hexdigest() != record['sha256']:
                        raise ValueError('Durable native evidence member differs')
                if f'validation-provenance-{arch}.json' in required:
                    proof = json.load(package.extractfile(prefix + f'validation-provenance-{arch}.json'))
                    verify_durable_validation(identity, proof, arch)
            source_name = f'keep-{version}-source-materials-{arch}.tar.gz'
            source = assets[source_name]
            if (identity['source'] != {'name': source_name, 'sha256': source.get('digest', '').removeprefix('sha256:'),
                                      'bytes': source['size']} or not HASH.fullmatch(identity['source']['sha256'])):
                raise ValueError('Durable source asset differs from native evidence')
            for name, original in [(source_name, source), (security_name, security)]:
                expected = original['digest'].removeprefix('sha256:') + '  ' + name + '\n'
                if asset_body(assets[name + '.sha256']).decode() != expected:
                    raise ValueError('Durable asset checksum sidecar differs')
            identities[arch] = identity
    return identities


def aggregate():
    """Expose both digests only after reading the original native release assets."""
    version = guard()
    identities = verify_identities(version, draft(version))
    image = os.environ['DOCKERHUB_IMAGE']
    if image != 'brspoon/keep':
        raise ValueError('Native aggregation is restricted to Keep')
    token = hub('auth/token', payload={'identifier': os.environ['DOCKERHUB_USERNAME'],
                                     'secret': os.environ['DOCKERHUB_TOKEN']})['access_token']
    repository_visibility(hub('repositories/' + image + '/', token), 'is_private', 'Docker Hub')
    for arch, identity in identities.items():
        tag = f"transfer-{os.environ['GITHUB_RUN_ID']}-{os.environ['GITHUB_RUN_ATTEMPT']}-{arch}"
        if hub('repositories/' + image + '/tags/' + tag + '/', token).get('digest') != identity['native_digest']:
            raise ValueError('Original native transfer tag differs from durable evidence')
    guard()
    with open(os.environ['GITHUB_OUTPUT'], 'a') as output:
        for arch, identity in identities.items():
            output.write(f"{arch}={identity['native_digest']}\n")
            output.write(f"{arch}_config={identity['config_digest']}\n")
    print('Both original native digests verified against source and security assets.')


def verify():
    version = guard()
    digests = tested_digests()
    release = draft(version)
    identities = verify_identities(version, release, digests)
    with tempfile.TemporaryDirectory(prefix='keep-release-identity-') as directory:
        identity_path = Path(directory) / f'keep-{version}-release-materials.json'
        identity_path.write_text(json.dumps({'version': version, 'revision': os.environ['GITHUB_SHA'],
                                            'run_id': os.environ['GITHUB_RUN_ID'], 'images': identities},
                                           indent=2, sort_keys=True) + '\n')
        guard()
        upload(release, identity_path)
    print('Corresponding sources and original native evidence verified before stable promotion.')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=('report', 'fetch', 'archive', 'archive-native', 'aggregate', 'verify', 'prepare'))
    parser.add_argument('architecture', nargs='?', choices=ARCHES)
    args = parser.parse_args()
    if args.mode == 'verify':
        verify()
    elif args.mode == 'prepare':
        draft(guard(), create=True)
    elif args.mode == 'aggregate':
        aggregate()
    elif args.architecture:
        {'report': report, 'fetch': fetch, 'archive': archive,
         'archive-native': archive_native}[args.mode](args.architecture)
    else:
        parser.error('A native architecture is required')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # Never print request headers, redirect URLs or provider credentials.
        detail = ': ' + str(error) if isinstance(error, ValueError) else ''
        raise SystemExit('Release materials failed: ' + type(error).__name__ + detail) from None
