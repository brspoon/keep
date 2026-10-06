#!/usr/bin/env python3
"""Retain tested main images privately; restore them only for approved publication.

The immutable, run-bound Actions artifact contains only a small index. Its asset
IDs, sizes and hashes bind the larger image, sources and original reports stored
in an unpublished candidate draft. No registry credentials or rebuild fallback
are used here.
"""
import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

from build_distribution_bundle import file_sha
import release_materials as materials
from publish_release import require_manual_dispatch
from registry_transfer import checked_digest

REPOSITORY = 'brspoon/keep'
WORKFLOW = '.github/workflows/image.yml'
ARCHES = ('amd64', 'arm64')
SCHEMA = 'keep.validated-native-build.v1'
PROVENANCE_SCHEMA = 'keep.main-validation-provenance.v1'
INDEX_LIMIT = 128 * 1024
ZIP_LIMIT = 512 * 1024
JSON_LIMIT = 4 * 1024 * 1024
ASSET_LIMIT = 2 * 1024 * 1024 * 1024
SHA = re.compile(r'[0-9a-f]{40}\Z')
HASH = re.compile(r'[0-9a-f]{64}\Z')
NATIVE_STEPS = (
    'Build the image to test with temporary registry credentials',
    'Test installation launcher on the native host',
    'Test Python application and release tools', 'Test JavaScript',
    'Verify packaged version', 'Verify non-root runtime',
    'Verify private runtime data directory',
    'Verify installation tools are absent and runtime libraries work',
    'Validate portable Compose',
    'Smoke-test packaged web and worker with durable data',
    'Exercise portable installation, restore and failed-upgrade recovery',
    'Exercise one-command installation and owner-preserving reruns',
    'Capture verified vendor evidence and Scout assessment',
    'Inventory installed notices and inspect every image layer',
    'Scan candidate without suppressions',
    'Verify all nine runtime security fixes in the tested image',
    'Verify default Expat and OpenSSL library loading',
    'Accept only reviewed fixed findings and block all others',
    'Obtain verified base source materials and license notices',
    'Obtain matching sources for every installed OS package',
    'Package sources and notices for the exact tested runtime',
    'Print source bundle manifest and compact summary',
)
RETAIN_STEP = 'Retain exact tested image, sources and original evidence'
INDEX_STEP = 'Retain immutable validation index'


def positive(value, label):
    if isinstance(value, bool) or not re.fullmatch(r'[1-9][0-9]{0,19}', str(value)):
        raise ValueError('Invalid ' + label)
    return int(value)


def context():
    if os.environ.get('GITHUB_REPOSITORY') != REPOSITORY:
        raise ValueError('Validated builds are restricted to the primary Keep repository')
    revision = os.environ.get('GITHUB_SHA', '')
    version = Path('VERSION').read_text().strip()
    if not SHA.fullmatch(revision) or not re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', version):
        raise ValueError('Invalid tested source identity')
    return version, revision


def api(path, *, method='GET', data=None):
    if path and (not path.startswith('/') or path.startswith('//')):
        raise ValueError('Invalid GitHub API path')
    request = urllib.request.Request('https://api.github.com/repos/' + REPOSITORY + path,
        method=method, data=json.dumps(data).encode() if data is not None else None,
        headers={'Authorization': 'Bearer ' + os.environ['GITHUB_TOKEN'],
                 'Accept': 'application/vnd.github+json', 'Content-Type': 'application/json',
                 'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'Keep-validated-build'})
    with urllib.request.build_opener(materials.NoRedirect()).open(request, timeout=60) as response:
        body = response.read(JSON_LIMIT + 1)
    if len(body) > JSON_LIMIT:
        raise ValueError('GitHub metadata exceeds its size limit')
    return json.loads(body)


def pages(path, key=None):
    rows = []
    for page in range(1, 1001):
        result = api(path + ('&' if '?' in path else '?') + f'per_page=100&page={page}')
        batch = result.get(key) if key else result
        if not isinstance(batch, list) or any(not isinstance(row, dict) for row in batch):
            raise ValueError('Invalid paginated GitHub metadata')
        rows.extend(batch)
        if len(batch) < 100:
            return rows
    raise ValueError('GitHub pagination exceeds its limit')


def run_record(run_id, *, completed):
    _, revision = context()
    run_id = positive(run_id, 'validation run ID')
    repository = api('')
    repository_id = positive(repository.get('id'), 'repository ID')
    if repository.get('full_name') != REPOSITORY or type(repository.get('private')) is not bool:
        raise ValueError('Invalid primary repository identity')
    workflow = api('/actions/workflows/image.yml')
    workflow_id = positive(workflow.get('id'), 'workflow ID')
    if workflow.get('path') != WORKFLOW:
        raise ValueError('Validation workflow identity differs')
    run = api(f'/actions/runs/{run_id}')
    if (run.get('id') != run_id or run.get('workflow_id') != workflow_id or
            run.get('path') != WORKFLOW or run.get('event') != 'push' or
            run.get('head_branch') != 'main' or run.get('head_sha') != revision or
            run.get('repository', {}).get('id') != repository_id or
            run.get('repository', {}).get('full_name') != REPOSITORY or
            run.get('head_repository', {}).get('id') != repository_id or
            run.get('head_repository', {}).get('full_name') != REPOSITORY):
        raise ValueError('Validation must originate from this exact primary-repository main push')
    positive(run.get('run_attempt'), 'validation run attempt')
    if completed and (run.get('status') != 'completed' or run.get('conclusion') != 'success'):
        raise ValueError('Selected main validation run must have completed successfully')
    return run, repository_id


def current_main():
    _, revision = context()
    if api('/git/ref/heads/main').get('object', {}).get('sha') != revision:
        raise ValueError('Selected tested revision is not current main')


def push_guard():
    context()
    if os.environ.get('GITHUB_EVENT_NAME') != 'push' or os.environ.get('GITHUB_REF') != 'refs/heads/main':
        raise ValueError('Private candidate retention requires a trusted main push')
    run, _ = run_record(os.environ.get('GITHUB_RUN_ID'), completed=False)
    if run['run_attempt'] != positive(os.environ.get('GITHUB_RUN_ATTEMPT'), 'current run attempt'):
        raise ValueError('Candidate retention attempt differs from its main workflow')
    return run


def job_name(arch):
    return f'image / image ({arch})'


def job_success(job, *, native=False):
    if job.get('status') != 'completed' or job.get('conclusion') != 'success':
        raise ValueError('A required validation job did not succeed')
    if native:
        steps = job.get('steps')
        if not isinstance(steps, list):
            raise ValueError('Native validation steps are unavailable')
        by_name = {step.get('name'): step for step in steps}
        for name in (*NATIVE_STEPS, RETAIN_STEP, INDEX_STEP):
            step = by_name.get(name, {})
            if step.get('status') != 'completed' or step.get('conclusion') != 'success':
                raise ValueError('Native validation gate did not succeed: ' + name)


def latest_job(jobs, run, name):
    matches = [job for job in jobs if job.get('name') == name]
    if not matches:
        raise ValueError('Missing required main validation job: ' + name)
    for job in matches:
        attempt = positive(job.get('run_attempt'), 'job attempt')
        if (job.get('run_id') != run['id'] or job.get('head_sha') != run['head_sha'] or
                attempt > run['run_attempt']):
            raise ValueError('Required job belongs to a different main validation run')
    attempt = max(job['run_attempt'] for job in matches)
    newest = [job for job in matches if job['run_attempt'] == attempt]
    if len(newest) != 1:
        raise ValueError('Duplicate required main validation job: ' + name)
    job_success(newest[0], native=name.startswith('image / '))
    return newest[0]


def origin(run_id):
    require_manual_dispatch(True)
    current_main()
    run, repository_id = run_record(run_id, completed=True)
    # Failed-job-only reruns can leave the other architecture's successful job
    # on an earlier attempt. Consider all attempts and select the newest job
    # independently for each required name, never a superseded success.
    jobs = pages(f"/actions/runs/{run['id']}/jobs?filter=all", 'jobs')
    for name in ('prepare-candidate', 'installer-windows', 'contributor-tests', 'required-checks',
                 *(job_name(arch) for arch in ARCHES)):
        latest_job(jobs, run, name)
    return run, repository_id


def candidate_tag(run_id):
    return f"candidate-{os.environ['GITHUB_SHA']}-{positive(run_id, 'validation run ID')}"


def candidate(run_id, *, create=False):
    tag = candidate_tag(run_id)
    matches = [row for row in pages('/releases') if row.get('tag_name') == tag]
    if len(matches) > 1:
        raise ValueError('Multiple private candidate drafts match this validation')
    if matches:
        release = matches[0]
    elif create:
        release = api('/releases', method='POST', data={
            'tag_name': tag, 'target_commitish': os.environ['GITHUB_SHA'],
            'name': 'Unpublished main validation ' + os.environ['GITHUB_SHA'][:12],
            'draft': True, 'prerelease': True,
            'body': 'Private storage for exact tested native images and original evidence. '
                    'This candidate is not approved for publication.'})
    else:
        raise ValueError('The original private candidate draft is unavailable')
    if (release.get('draft') is not True or release.get('tag_name') != tag or
            release.get('target_commitish') != os.environ['GITHUB_SHA']):
        raise ValueError('Candidate must remain an unpublished draft for the exact tested SHA')
    positive(release.get('id'), 'candidate release ID')
    return release


def prepare():
    run = push_guard()
    candidate(run['id'], create=True)
    print('Prepared unpublished storage for this main validation run.')


def inspect_image(arch, config=None):
    version, revision = context()
    rows = json.loads(subprocess.check_output(['docker', 'image', 'inspect', 'keep-ci']))
    if not isinstance(rows, list) or len(rows) != 1:
        raise ValueError('Require one tested native image')
    image = rows[0]
    labels = image.get('Config', {}).get('Labels') or {}
    digest = checked_digest(image.get('Id'))
    if (image.get('Architecture') != arch or image.get('Os') != 'linux' or
            image.get('Config', {}).get('User') != '10001:10001' or
            labels.get('org.opencontainers.image.version') != version or
            labels.get('org.opencontainers.image.revision') != revision or
            labels.get('org.opencontainers.image.source') != 'https://github.com/' + REPOSITORY or
            (config is not None and digest != config)):
        raise ValueError('Retained image config, architecture, runtime user or source identity differs')
    return digest


def input_paths(arch):
    version, _ = context()
    source = f'distribution/keep-{version}-source-materials-{arch}.tar.gz'
    return [f'keep-tested-{arch}.tar', source, source + '.sha256',
            *materials.evidence_names(arch), f'portable-recovery-{arch}.json',
            f'installer-trial-{arch}.json', f'distribution/source-bundle-{arch}.json']


def regular(path, limit=ASSET_LIMIT):
    path = Path(path)
    if not path.is_file() or path.is_symlink() or path.stat().st_size <= 0 or path.stat().st_size > limit:
        raise ValueError('Require a regular retained file within its size limit: ' + path.name)
    return path


def asset_limit(path):
    # Images and matching source packages can be large. Reports, logs and
    # checksum sidecars must remain small independently of provider metadata.
    return ASSET_LIMIT if path.endswith(('.tar', '.tar.gz')) else 32 * 1024 * 1024


def upload(release, path, name):
    path = regular(path)
    digest, size = 'sha256:' + file_sha(path), path.stat().st_size
    matches = [row for row in pages(f"/releases/{release['id']}/assets") if row.get('name') == name]
    if matches:
        if len(matches) != 1 or matches[0].get('digest') != digest or matches[0].get('size') != size:
            raise ValueError('An existing candidate asset differs; refusing overwrite')
        return matches[0]
    url_path = '/repos/' + REPOSITORY + f"/releases/{release['id']}/assets?" + urllib.parse.urlencode({'name': name})
    connection = http.client.HTTPSConnection('uploads.github.com', timeout=300)
    try:
        connection.putrequest('POST', url_path)
        for key, value in {'Authorization': 'Bearer ' + os.environ['GITHUB_TOKEN'],
                           'Content-Type': 'application/octet-stream', 'Content-Length': str(size),
                           'Accept': 'application/vnd.github+json', 'User-Agent': 'Keep-validated-build'}.items():
            connection.putheader(key, value)
        connection.endheaders()
        with path.open('rb') as stream:
            while chunk := stream.read(1024 * 1024):
                connection.send(chunk)
        response = connection.getresponse()
        body = response.read(JSON_LIMIT + 1)
        if response.status != 201 or len(body) > JSON_LIMIT:
            raise ValueError('Candidate asset upload failed')
        result = json.loads(body)
    finally:
        connection.close()
    if result.get('name') != name or result.get('size') != size or result.get('digest') != digest:
        raise ValueError('Uploaded candidate asset identity differs')
    positive(result.get('id'), 'candidate asset ID')
    return result


def native_job(run, arch, attempt, *, job_id=None, completed=True):
    path = f"/actions/runs/{run['id']}/attempts/{positive(attempt, 'producer attempt')}/jobs"
    # GitHub's step metadata can lag the runner by a few seconds at the start
    # of retention. Retry only nonterminal metadata, never a failed/skipped gate.
    for poll in range(1 if completed else 6):
        matches = [row for row in pages(path, 'jobs') if row.get('name') == job_name(arch)]
        if len(matches) != 1:
            raise ValueError('Require one original native producer job')
        job = matches[0]
        if (job.get('run_id') != run['id'] or job.get('run_attempt') != int(attempt) or
                job.get('head_sha') != os.environ['GITHUB_SHA'] or
                (job_id is not None and job.get('id') != job_id)):
            raise ValueError('Original native producer identity differs')
        positive(job.get('id'), 'native job ID')
        if completed:
            job_success(job, native=True)
            return job
        if job.get('status') != 'in_progress':
            raise ValueError('Candidate retention must run in its original native job')
        steps = {step.get('name'): step for step in job.get('steps', [])}
        gates = [steps.get(name, {}) for name in NATIVE_STEPS]
        if any(gate.get('conclusion') not in (None, 'success') for gate in gates):
            raise ValueError('A native gate failed or was skipped before retention')
        if all(gate.get('status') == 'completed' and gate.get('conclusion') == 'success' for gate in gates):
            return job
        if poll < 5:
            time.sleep(2)
    raise ValueError('All native gates must succeed before retention; metadata did not settle')


def artifact_name(run_id, attempt, arch):
    return f'validated-build-{run_id}-{attempt}-{arch}'


def retain(arch):
    run = push_guard()
    version, revision = context()
    attempt = run['run_attempt']
    job = native_job(run, arch, attempt, completed=False)
    config = inspect_image(arch)
    identity = {'version': version, 'revision': revision, 'architecture': arch, 'config_digest': config}
    source, source_proof = materials.bundle(arch, verify_files=True)
    summary = Path(f'distribution/source-bundle-{arch}.json')
    if json.loads(summary.read_text()) != source_proof:
        raise ValueError('Original source summary differs from the verified bundle')
    materials.portable_evidence(regular(f'portable-recovery-{arch}.json', JSON_LIMIT), arch, identity)
    materials.installer_evidence(regular(f'installer-trial-{arch}.json', JSON_LIMIT), arch, identity)
    release = candidate(run['id'])
    prefix = f"build-{run['id']}-{attempt}-{arch}--"
    with tempfile.TemporaryDirectory(prefix='keep-retain-image-') as directory:
        image_path = Path(directory) / f'keep-tested-{arch}.tar'
        subprocess.run(['docker', 'image', 'save', '--output', str(image_path), 'keep-ci'], check=True)
        # Saving must not silently switch the mutable local name between checks.
        inspect_image(arch, config)
        records = []
        for name in input_paths(arch):
            path = image_path if name == image_path.name else regular(name, asset_limit(name))
            asset = upload(release, path, prefix + path.name)
            records.append({'path': name, 'id': positive(asset.get('id'), 'candidate asset ID'),
                            'name': asset['name'], 'bytes': path.stat().st_size, 'sha256': file_sha(path)})
    index = {'schema': SCHEMA, 'repository': REPOSITORY, **identity,
             'build': {'run_id': run['id'], 'run_attempt': attempt, 'job_id': job['id'],
                       'job_name': job_name(arch), 'workflow_id': run['workflow_id']},
             'candidate': {'id': release['id'], 'tag_name': release['tag_name']}, 'assets': records}
    path = Path(f'validated-build/{arch}/index.json')
    path.parent.mkdir(parents=True, exist_ok=True)
    body = (json.dumps(index, sort_keys=True, indent=2) + '\n').encode()
    if len(body) > INDEX_LIMIT:
        raise ValueError('Validation index exceeds its size limit')
    path.write_bytes(body)
    print('Retained exact tested image, matching sources and original native evidence: ' + arch)


def artifact_metadata(row, run, repository_id, arch):
    attempt = positive(row.get('name', '').removeprefix(f"validated-build-{run['id']}-").removesuffix('-' + arch),
                       'artifact producer attempt')
    workflow_run = row.get('workflow_run', {})
    if (row.get('name') != artifact_name(run['id'], attempt, arch) or
            attempt > run['run_attempt'] or row.get('expired') is not False or
            not isinstance(row.get('digest'), str) or not re.fullmatch(r'sha256:[0-9a-f]{64}', row['digest']) or
            type(row.get('size_in_bytes')) is not int or not 0 < row['size_in_bytes'] <= ZIP_LIMIT or
            workflow_run.get('id') != run['id'] or workflow_run.get('repository_id') != repository_id or
            workflow_run.get('head_repository_id') != repository_id or
            workflow_run.get('head_branch') != 'main' or workflow_run.get('head_sha') != run['head_sha']):
        raise ValueError('Immutable validation index artifact identity differs or has expired')
    positive(row.get('id'), 'artifact ID')
    return attempt


def select_artifact(rows, run, repository_id, arch):
    matches = [row for row in rows if re.fullmatch(rf"validated-build-{run['id']}-[1-9][0-9]*-{arch}", row.get('name', ''))]
    if not matches:
        raise ValueError('No immutable validation index is available; run explicit main validation')
    attempts = [(positive(row['name'].split('-')[-2], 'artifact producer attempt'), row) for row in matches]
    if len({attempt for attempt, _ in attempts}) != len(attempts):
        raise ValueError('Duplicate immutable validation indexes')
    attempt, selected = max(attempts, key=lambda pair: pair[0])
    artifact_metadata(selected, run, repository_id, arch)
    return attempt, selected


def binary_response(path, *, artifact=False):
    # The Actions ZIP endpoint negotiates its redirect using the GitHub API
    # media type. Release assets instead require the binary media type.
    request = urllib.request.Request('https://api.github.com/repos/' + REPOSITORY + path,
        headers={'Authorization': 'Bearer ' + os.environ['GITHUB_TOKEN'],
                 'Accept': 'application/vnd.github+json' if artifact else 'application/octet-stream',
                 'X-GitHub-Api-Version': '2022-11-28',
                 'User-Agent': 'Keep-validated-build'})
    opener = urllib.request.build_opener(materials.NoRedirect())
    try:
        return opener.open(request, timeout=300)
    except urllib.error.HTTPError as error:
        if error.code != 302:
            raise ValueError(f'GitHub binary download request failed (HTTP {error.code})') from None
        location = error.headers.get('Location', '')
        parsed = urllib.parse.urlsplit(location)
        allowed = ('release-assets.githubusercontent.com',)
        # Actions artifacts are served by GitHub's signed Azure Blob URLs. No
        # authentication headers may cross either redirect trust boundary.
        actions_host = artifact and bool(re.fullmatch(r'[a-z0-9-]+\.blob\.core\.windows\.net', parsed.hostname or ''))
        if (parsed.scheme != 'https' or parsed.username or parsed.password or
                parsed.port is not None or parsed.fragment or
                (parsed.hostname not in allowed and not actions_host)):
            raise ValueError('Rejected GitHub binary download redirect') from None
        return opener.open(urllib.request.Request(location, headers={'User-Agent': 'Keep-validated-build'}), timeout=300)


def download(path, target, size, digest, *, limit=ASSET_LIMIT, artifact=False):
    if type(size) is not int or not 0 < size <= limit:
        raise ValueError('Retained download exceeds its size limit')
    checked_digest(digest)
    count, sha = 0, hashlib.sha256()
    try:
        with binary_response(path, artifact=artifact) as response, Path(target).open('xb') as output:
            while chunk := response.read(min(1024 * 1024, size - count + 1)):
                count += len(chunk)
                if count > size:
                    raise ValueError('Retained download exceeds its declared size')
                sha.update(chunk)
                output.write(chunk)
        if count != size or 'sha256:' + sha.hexdigest() != digest:
            raise ValueError('Retained download checksum or length differs')
    except Exception:
        Path(target).unlink(missing_ok=True)
        raise


def read_index(artifact):
    with tempfile.TemporaryDirectory(prefix='keep-validation-index-') as directory:
        path = Path(directory) / 'index.zip'
        download(f"/actions/artifacts/{artifact['id']}/zip", path, artifact['size_in_bytes'],
                 artifact['digest'], limit=ZIP_LIMIT, artifact=True)
        with zipfile.ZipFile(path) as package:
            entries = package.infolist()
            if (len(entries) != 1 or entries[0].filename != 'index.json' or entries[0].is_dir() or
                    entries[0].file_size > INDEX_LIMIT or entries[0].file_size <= 0 or
                    stat.S_ISLNK(entries[0].external_attr >> 16) or entries[0].flag_bits & 1):
                raise ValueError('Unsafe or unexpected validation index archive member')
            with package.open(entries[0]) as stream:
                body = stream.read(INDEX_LIMIT + 1)
            if len(body) > INDEX_LIMIT:
                raise ValueError('Validation index exceeds its size limit')
    return json.loads(body)


def validate_index(index, run, repository_id, artifact, arch):
    version, revision = context()
    attempt = artifact_metadata(artifact, run, repository_id, arch)
    if (not isinstance(index, dict) or index.get('schema') != SCHEMA or index.get('repository') != REPOSITORY or
            index.get('version') != version or index.get('revision') != revision or index.get('architecture') != arch):
        raise ValueError('Original validation index source identity differs')
    checked_digest(index.get('config_digest'))
    build = index.get('build', {})
    if (build.get('run_id') != run['id'] or build.get('run_attempt') != attempt or
            build.get('workflow_id') != run['workflow_id'] or build.get('job_name') != job_name(arch)):
        raise ValueError('Original validation index producer differs')
    native_job(run, arch, attempt, job_id=positive(build.get('job_id'), 'native job ID'))
    newest = latest_job(pages(f"/actions/runs/{run['id']}/jobs?filter=all", 'jobs'), run, job_name(arch))
    if newest.get('id') != build['job_id'] or newest.get('run_attempt') != attempt:
        raise ValueError('Immutable index does not belong to the latest native validation job')
    release = candidate(run['id'])
    if index.get('candidate') != {'id': release['id'], 'tag_name': release['tag_name']}:
        raise ValueError('Original candidate draft identity differs')
    records = index.get('assets')
    expected = set(input_paths(arch))
    if (not isinstance(records, list) or len(records) != len(expected) or
            any(not isinstance(row, dict) for row in records) or {row.get('path') for row in records} != expected):
        raise ValueError('Original image, source or evidence inventory is incomplete')
    prefix = f"build-{run['id']}-{attempt}-{arch}--"
    seen_ids = set()
    for row in records:
        asset_id = positive(row.get('id'), 'candidate asset ID')
        if (asset_id in seen_ids or row.get('name') != prefix + PurePosixPath(row['path']).name or
                type(row.get('bytes')) is not int or not 0 < row['bytes'] <= asset_limit(row['path']) or
                not isinstance(row.get('sha256'), str) or not HASH.fullmatch(row['sha256'])):
            raise ValueError('Invalid retained candidate asset identity')
        seen_ids.add(asset_id)
    # Assets may be mutable provider records; require current ID metadata to
    # agree with the immutable index before any large download.
    assets = pages(f"/releases/{release['id']}/assets")
    for row in records:
        matches = [asset for asset in assets if asset.get('id') == row['id']]
        if (len(matches) != 1 or matches[0].get('name') != row['name'] or
                matches[0].get('size') != row['bytes'] or matches[0].get('digest') != 'sha256:' + row['sha256']):
            raise ValueError('Private candidate asset no longer matches its immutable index')
    return index


def check():
    run, repository_id = origin(os.environ.get('KEEP_VALIDATION_RUN_ID'))
    rows = pages(f"/actions/runs/{run['id']}/artifacts", 'artifacts')
    for arch in ARCHES:
        _, artifact = select_artifact(rows, run, repository_id, arch)
        validate_index(read_index(artifact), run, repository_id, artifact, arch)
    print('Selected current-main validation completed all required gates and retains both native indexes.')


def provenance(arch, index, artifact):
    return {'schema': PROVENANCE_SCHEMA, 'architecture': arch, 'index': index,
            'artifact': {key: artifact[key] for key in ('id', 'name', 'size_in_bytes', 'digest', 'workflow_run', 'expired')}}


def verify_provenance(proof, arch, config):
    if (not isinstance(proof, dict) or proof.get('schema') != PROVENANCE_SCHEMA or proof.get('architecture') != arch):
        raise ValueError('Require original main validation provenance')
    index = proof.get('index', {})
    selected = positive(os.environ.get('KEEP_VALIDATION_RUN_ID'), 'selected validation run ID')
    if index.get('build', {}).get('run_id') != selected or index.get('config_digest') != config:
        raise ValueError('Main validation provenance differs from selected run or tested image config')
    run, repository_id = origin(selected)
    artifact = api(f"/actions/artifacts/{positive(proof.get('artifact', {}).get('id'), 'artifact ID')}")
    if {key: artifact.get(key) for key in proof['artifact']} != proof['artifact']:
        raise ValueError('Original immutable index artifact metadata changed')
    restored = read_index(artifact)
    if restored != index:
        raise ValueError('Durable main provenance differs from the immutable validation index')
    validate_index(restored, run, repository_id, artifact, arch)
    return index


def verify_files(index, arch):
    for row in index['assets']:
        if row['path'] == f'keep-tested-{arch}.tar':
            continue
        path = regular(row['path'])
        if path.stat().st_size != row['bytes'] or file_sha(path) != row['sha256']:
            raise ValueError('Original retained source or native evidence bytes changed')


def restore(arch):
    run, repository_id = origin(os.environ.get('KEEP_VALIDATION_RUN_ID'))
    rows = pages(f"/actions/runs/{run['id']}/artifacts", 'artifacts')
    _, artifact = select_artifact(rows, run, repository_id, arch)
    index = validate_index(read_index(artifact), run, repository_id, artifact, arch)
    with tempfile.TemporaryDirectory(prefix='keep-restore-validation-') as directory:
        stage = Path(directory)
        for row in index['assets']:
            target = stage / row['path']
            target.parent.mkdir(parents=True, exist_ok=True)
            download(f"/releases/assets/{row['id']}", target, row['bytes'], 'sha256:' + row['sha256'],
                     limit=asset_limit(row['path']))
        # Only whitelist paths from our own manifest schema are materialized.
        # No release-provided archive is ever extracted into the checkout.
        for row in index['assets']:
            if row['path'] == f'keep-tested-{arch}.tar':
                continue
            target = Path(row['path'])
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.is_symlink() or any(parent.is_symlink() for parent in target.parents):
                raise ValueError('Unsafe retained output path')
            shutil.copyfile(stage / row['path'], target)
        materials.bundle(arch, verify_files=True)
        materials.portable_evidence(Path(f'portable-recovery-{arch}.json'), arch, index)
        materials.installer_evidence(Path(f'installer-trial-{arch}.json'), arch, index)
        subprocess.run(['docker', 'image', 'load', '--input', str(stage / f'keep-tested-{arch}.tar')], check=True)
        inspect_image(arch, index['config_digest'])
        verify_files(index, arch)
    proof = provenance(arch, index, artifact)
    Path(f'validation-provenance-{arch}.json').write_text(json.dumps(proof, sort_keys=True, indent=2) + '\n')
    current_main()
    print('Restored original tested main image and untouched sources/evidence: ' + arch)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=('prepare', 'retain', 'check', 'restore'))
    parser.add_argument('architecture', nargs='?', choices=ARCHES)
    args = parser.parse_args()
    if args.mode in ('prepare', 'check'):
        if args.architecture:
            parser.error('This mode does not take an architecture')
        {'prepare': prepare, 'check': check}[args.mode]()
    elif args.architecture:
        {'retain': retain, 'restore': restore}[args.mode](args.architecture)
    else:
        parser.error('A native architecture is required')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        detail = ': ' + str(error) if isinstance(error, ValueError) else ''
        raise SystemExit('Validated build failed: ' + type(error).__name__ + detail) from None
