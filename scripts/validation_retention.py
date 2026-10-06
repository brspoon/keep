#!/usr/bin/env python3
"""Plan or remove only superseded, authenticated main-validation storage.

Normal releases, Git tags and registry objects are outside this tool's scope.
The latest usable native build survives documentation-only main changes. Cleanup
defaults to a dry run and blocks while validation or publication is active.
"""
import argparse
import datetime as dt
import json
import os
from pathlib import PurePosixPath
import re
import urllib.request

import validated_build as builds

REPOSITORY = builds.REPOSITORY
WORKFLOW = builds.WORKFLOW
CLEANUP_WORKFLOW = '.github/workflows/validation-retention.yml'
LIMIT = 4 * 1024 * 1024
CANDIDATE = re.compile(r'candidate-([0-9a-f]{40})-([1-9][0-9]{0,19})\Z')
VERSION = re.compile(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z')
ACTIVE = {'queued', 'in_progress', 'requested', 'pending', 'waiting'}
CONCLUSIONS = {'success', 'failure', 'neutral', 'cancelled', 'skipped', 'timed_out',
               'action_required', 'stale', 'startup_failure'}
LOADER_STEP = 'Verify default Expat and OpenSSL library loading'
CURRENT_ACCEPTANCE_STEP = 'Accept only reviewed fixed findings and block all others'
LEGACY_ACCEPTANCE_STEP = 'Accept only the nine verified-fixed findings and block all others'


def api(path, *, method='GET'):
    if path and (not path.startswith('/') or path.startswith('//')):
        raise ValueError('Invalid scoped GitHub API path')
    request = urllib.request.Request('https://api.github.com/repos/' + REPOSITORY + path,
        method=method, headers={'Authorization': 'Bearer ' + os.environ['GITHUB_TOKEN'],
                               'Accept': 'application/vnd.github+json',
                               'X-GitHub-Api-Version': '2022-11-28',
                               'User-Agent': 'Keep-validation-retention'})
    with urllib.request.build_opener(builds.materials.NoRedirect()).open(request, timeout=60) as response:
        if method == 'DELETE':
            if response.status != 204:
                raise ValueError('Scoped cleanup did not return HTTP 204')
            return None
        body = response.read(LIMIT + 1)
    if len(body) > LIMIT:
        raise ValueError('Cleanup metadata exceeds its size limit')
    return json.loads(body)


def pages(path, key=None):
    rows = []
    for page in range(1, 1001):
        result = api(path + ('&' if '?' in path else '?') + f'per_page=100&page={page}')
        batch = result.get(key) if key and isinstance(result, dict) else result
        if not isinstance(batch, list) or any(not isinstance(row, dict) for row in batch):
            raise ValueError('Invalid cleanup pagination')
        rows.extend(batch)
        if len(batch) < 100:
            return rows
    raise ValueError('Cleanup pagination exceeds its bound')


def timestamp(value):
    if not isinstance(value, str) or not value.endswith('Z'):
        raise ValueError('Require a UTC provider timestamp')
    try:
        return dt.datetime.fromisoformat(value[:-1] + '+00:00')
    except ValueError:
        raise ValueError('Invalid provider timestamp') from None


def identity():
    if os.environ.get('GITHUB_REPOSITORY', REPOSITORY) != REPOSITORY:
        raise ValueError('Cleanup is restricted to the primary repository')
    repository = api('')
    workflow = api('/actions/workflows/image.yml')
    if repository.get('full_name') != REPOSITORY or workflow.get('path') != WORKFLOW:
        raise ValueError('Cleanup repository or producer workflow differs')
    return builds.positive(repository.get('id'), 'repository ID'), builds.positive(workflow.get('id'), 'workflow ID')


def status(run):
    value = run.get('status')
    if value not in ACTIVE | {'completed'}:
        raise ValueError('Unknown workflow status; cleanup cannot prove inactivity')
    if value == 'completed' and run.get('conclusion') not in CONCLUSIONS:
        raise ValueError('Unknown completed workflow conclusion')
    return value


def active_runs(workflow_id):
    active = []
    # Ask only for nonterminal states: cleanup must not walk the repository's
    # entire completed Actions history before every scoped deletion.
    for state in sorted(ACTIVE):
        for run in pages('/actions/workflows/image.yml/runs?status=' + state, 'workflow_runs'):
            if run.get('workflow_id') != workflow_id or run.get('path') != WORKFLOW or status(run) != state:
                raise ValueError('Ambiguous active validation/publication run identity')
            active.append(builds.positive(run.get('id'), 'active workflow run ID'))
    if len(set(active)) != len(active):
        raise ValueError('Duplicate active workflow run identity')
    return sorted(active)


def run_identity(run, revision, run_id, repository_id, workflow_id):
    if (run.get('id') != run_id or run.get('workflow_id') != workflow_id or
            run.get('path') != WORKFLOW or run.get('event') != 'push' or
            run.get('head_branch') != 'main' or run.get('head_sha') != revision or
            any(run.get(key, {}).get('id') != repository_id or
                run.get(key, {}).get('full_name') != REPOSITORY
                for key in ('repository', 'head_repository'))):
        raise ValueError('Candidate lacks a trusted primary-repository main producer')
    builds.positive(run.get('run_attempt'), 'producer attempt')
    status(run)


def release_identity(release):
    match = CANDIDATE.fullmatch(release.get('tag_name', ''))
    author = release.get('author', {})
    if (not match or release.get('draft') is not True or release.get('published_at') is not None or
            release.get('prerelease') is not True or release.get('target_commitish') != match[1] or
            author.get('login') != 'github-actions[bot]' or author.get('type') != 'Bot'):
        raise ValueError('Candidate draft namespace, source or creator is untrusted')
    builds.positive(release.get('id'), 'candidate release ID')
    return match[1], builds.positive(match[2], 'candidate producer run ID')


def expected_paths(version, arch, *, legacy=False):
    source = f'distribution/keep-{version}-source-materials-{arch}.tar.gz'
    paths = {f'keep-tested-{arch}.tar', source, source + '.sha256',
             *builds.materials.evidence_names(arch), f'portable-recovery-{arch}.json',
             f'installer-trial-{arch}.json', f'distribution/source-bundle-{arch}.json'}
    if legacy:
        paths.remove(f'candidate-dependencies-{arch}.json')
    return paths


def asset_snapshot(assets, run_id, attempt):
    result, ids, names = [], set(), set()
    for asset in assets:
        asset_id = builds.positive(asset.get('id'), 'candidate asset ID')
        match = re.fullmatch(rf'build-{run_id}-([1-9][0-9]{{0,19}})-(amd64|arm64)--([A-Za-z0-9_.-]+)',
                             asset.get('name', ''))
        if not match or int(match[1]) > attempt:
            raise ValueError('Candidate contains an unknown asset namespace')
        arch, basename = match[2], match[3]
        fixed = {PurePosixPath(path).name for path in expected_paths('0.0.0', arch)
                 if 'keep-0.0.0-source-materials-' not in path}
        source = re.fullmatch(rf'keep-((?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*))-source-materials-{arch}\.tar\.gz(?:\.sha256)?', basename)
        if (basename not in fixed and source is None) or asset.get('state') != 'uploaded':
            raise ValueError('Candidate contains an unknown or incomplete asset')
        if asset_id in ids or asset['name'] in names:
            raise ValueError('Duplicate candidate asset identity')
        ids.add(asset_id)
        names.add(asset['name'])
        size = asset.get('size')
        if type(size) is not int or not 0 < size <= builds.asset_limit(basename):
            raise ValueError('Invalid candidate asset size')
        builds.checked_digest(asset.get('digest'))
        result.append({key: asset.get(key) for key in ('id', 'name', 'size', 'digest', 'state')})
    return sorted(result, key=lambda row: row['id'])


def artifacts_for(run, repository_id):
    result = []
    for artifact in pages(f"/actions/runs/{run['id']}/artifacts", 'artifacts'):
        name = artifact.get('name', '')
        if not name.startswith('validated-build-'):
            continue
        match = re.fullmatch(rf"validated-build-{run['id']}-([1-9][0-9]{{0,19}})-(amd64|arm64)", name)
        origin = artifact.get('workflow_run', {})
        if (not match or int(match[1]) > run['run_attempt'] or type(artifact.get('expired')) is not bool or
                origin != {'id': run['id'], 'repository_id': repository_id,
                           'head_repository_id': repository_id, 'head_branch': 'main',
                           'head_sha': run['head_sha']}):
            raise ValueError('Unknown or mismatched validation index artifact')
        builds.positive(artifact.get('id'), 'index artifact ID')
        builds.checked_digest(artifact.get('digest'))
        size = artifact.get('size_in_bytes')
        if type(size) is not int or not 0 < size <= builds.ZIP_LIMIT:
            raise ValueError('Invalid validation index size')
        result.append(artifact)
    if len({row['id'] for row in result}) != len(result) or len({row['name'] for row in result}) != len(result):
        raise ValueError('Duplicate validation index artifacts')
    return sorted(result, key=lambda row: row['id'])


def latest_producer_job(jobs, run, name):
    """Select a producer before interpreting its native validation contract."""
    matches = [job for job in jobs if job.get('name') == name]
    if not matches:
        raise ValueError('Missing required main validation job: ' + name)
    attempts, ids = [], set()
    for job in matches:
        attempt = builds.positive(job.get('run_attempt'), 'job attempt')
        job_id = builds.positive(job.get('id'), 'job ID')
        if (type(job.get('run_attempt')) is not int or type(job.get('id')) is not int or
                job.get('run_id') != run['id'] or job.get('head_sha') != run['head_sha'] or
                attempt > run['run_attempt'] or job_id in ids):
            raise ValueError('Required job has an ambiguous or different producer identity')
        ids.add(job_id)
        attempts.append((attempt, job))
    latest = max(attempt for attempt, _ in attempts)
    newest = [job for attempt, job in attempts if attempt == latest]
    if len(newest) != 1:
        raise ValueError('Duplicate required main validation job: ' + name)
    builds.job_success(newest[0])
    return newest[0]


def native_profile(job):
    """Recognize the exact pre-dependency contract without approving it."""
    steps = job.get('steps')
    if (not isinstance(steps, list) or any(not isinstance(step, dict) or
            not isinstance(step.get('name'), str) or not step['name'].strip() for step in steps)):
        raise ValueError('Native validation step metadata is unavailable or malformed')
    by_name = {step['name']: step for step in steps}
    if len(by_name) != len(steps):
        raise ValueError('Duplicate native validation step metadata')
    if LOADER_STEP not in by_name and CURRENT_ACCEPTANCE_STEP not in by_name and LEGACY_ACCEPTANCE_STEP in by_name:
        profile = 'legacy'
        required = tuple(name for name in builds.NATIVE_STEPS
                         if name not in (LOADER_STEP, CURRENT_ACCEPTANCE_STEP)) + (LEGACY_ACCEPTANCE_STEP,)
    elif LOADER_STEP in by_name and CURRENT_ACCEPTANCE_STEP in by_name and LEGACY_ACCEPTANCE_STEP not in by_name:
        profile = 'current'
        required = builds.NATIVE_STEPS
    else:
        raise ValueError('Unknown or incomplete native validation profile')
    for name in (*required, builds.RETAIN_STEP, builds.INDEX_STEP):
        step = by_name.get(name, {})
        if step.get('status') != 'completed' or step.get('conclusion') != 'success':
            raise ValueError('Native validation gate did not succeed: ' + name)
    return profile


def usable(run, release, artifacts, assets):
    if run.get('status') != 'completed' or run.get('conclusion') != 'success':
        return False
    jobs = pages(f"/actions/runs/{run['id']}/jobs?filter=all", 'jobs')
    selected = {name: latest_producer_job(jobs, run, name)
                for name in ('prepare-candidate', 'installer-windows', 'contributor-tests', 'required-checks',
                             *(builds.job_name(arch) for arch in builds.ARCHES))}
    relevant = [job for job in jobs if job.get('name') in selected]
    if len({job['id'] for job in relevant}) != len(relevant):
        raise ValueError('Duplicate required validation producer job identity')
    profiles = {native_profile(selected[builds.job_name(arch)]) for arch in builds.ARCHES}
    if len(profiles) != 1:
        raise ValueError('Native architectures disagree on the validation profile')
    legacy = profiles == {'legacy'}
    available = True
    versions = set()
    for arch in builds.ARCHES:
        matches = [row for row in artifacts if row['name'].endswith('-' + arch)]
        job = selected[builds.job_name(arch)]
        matching = [row for row in matches if row['name'] == builds.artifact_name(run['id'], job['run_attempt'], arch)]
        if not matching or matching[0]['expired']:
            available = False
            continue
        artifact = matching[0]
        index = builds.read_index(artifact)
        if not isinstance(index, dict):
            raise ValueError('Usable validation index is malformed')
        version = index.get('version', '')
        if (not isinstance(version, str) or not VERSION.fullmatch(version) or index.get('schema') != builds.SCHEMA or
                index.get('repository') != REPOSITORY or index.get('revision') != run['head_sha'] or
                index.get('architecture') != arch or
                index.get('build') != {'run_id': run['id'], 'run_attempt': job['run_attempt'],
                                       'job_id': job['id'], 'job_name': builds.job_name(arch),
                                       'workflow_id': run['workflow_id']} or
                index.get('candidate') != {'id': release['id'], 'tag_name': release['tag_name']}):
            raise ValueError('Usable validation index source or producer binding differs')
        builds.checked_digest(index.get('config_digest'))
        records = index.get('assets')
        expected = expected_paths(version, arch, legacy=legacy)
        if (not isinstance(records, list) or len(records) != len(expected) or
                any(not isinstance(row, dict) or not isinstance(row.get('path'), str) for row in records) or
                {row.get('path') for row in records} != expected):
            raise ValueError('Usable candidate evidence inventory is incomplete')
        ids = set()
        for record in records:
            asset_id = builds.positive(record.get('id'), 'index asset ID')
            basename = PurePosixPath(record['path']).name
            if (asset_id in ids or record.get('name') != f"build-{run['id']}-{job['run_attempt']}-{arch}--{basename}" or
                    type(record.get('bytes')) is not int or
                    not 0 < record['bytes'] <= builds.asset_limit(record['path']) or
                    not isinstance(record.get('sha256'), str) or not builds.HASH.fullmatch(record['sha256'])):
                raise ValueError('Invalid indexed candidate asset')
            ids.add(asset_id)
            matching_assets = [row for row in assets if row['id'] == asset_id]
            if (len(matching_assets) != 1 or matching_assets[0]['name'] != record['name'] or
                    matching_assets[0]['size'] != record['bytes'] or
                    matching_assets[0]['digest'] != 'sha256:' + record['sha256']):
                raise ValueError('Candidate storage no longer agrees with its immutable index')
        prefix = f"build-{run['id']}-{job['run_attempt']}-{arch}--"
        if {row['id'] for row in assets if row['name'].startswith(prefix)} != ids:
            raise ValueError('Candidate producer asset inventory differs from its immutable index')
        versions.add(version)
    if available and len(versions) != 1:
        raise ValueError('Native indexes disagree on the version')
    # Authenticated legacy storage can be retained or superseded, but cannot
    # satisfy the current dependency qualification or promotion contract.
    return available and not legacy


def snapshot(release, run, artifacts, assets):
    return {'release': {key: release.get(key) for key in ('id', 'tag_name', 'draft', 'prerelease',
             'target_commitish', 'author', 'published_at', 'created_at', 'updated_at')},
            'run': {key: run.get(key) for key in ('id', 'workflow_id', 'path', 'event', 'head_branch',
             'head_sha', 'run_attempt', 'status', 'conclusion', 'created_at', 'updated_at',
             'repository', 'head_repository')},
            'artifacts': [{key: row.get(key) for key in ('id', 'name', 'expired', 'size_in_bytes', 'digest', 'workflow_run')}
                          for row in artifacts], 'assets': assets}


def plan(now=None):
    now = now or dt.datetime.now(dt.timezone.utc)
    if now.tzinfo is None:
        raise ValueError('Cleanup planning requires an aware time')
    repository_id, workflow_id = identity()
    main_revision = api('/git/ref/heads/main').get('object', {}).get('sha', '')
    if not builds.SHA.fullmatch(main_revision):
        raise ValueError('Current main revision is unavailable')
    active = active_runs(workflow_id)
    candidates, release_ids, run_ids = [], set(), set()
    for release in pages('/releases'):
        tag = release.get('tag_name', '')
        if not isinstance(tag, str):
            raise ValueError('Invalid release tag metadata')
        if not tag.startswith('candidate-'):
            continue
        revision, run_id = release_identity(release)
        if release['id'] in release_ids or run_id in run_ids:
            raise ValueError('Ambiguous candidate draft or producer identity')
        release_ids.add(release['id'])
        run_ids.add(run_id)
        run = api(f'/actions/runs/{run_id}')
        run_identity(run, revision, run_id, repository_id, workflow_id)
        assets = asset_snapshot(pages(f"/releases/{release['id']}/assets"), run_id, run['run_attempt'])
        artifacts = artifacts_for(run, repository_id)
        dates = [timestamp(row.get(key)) for row in (release, run) for key in ('created_at', 'updated_at')]
        if any(value > now for value in dates):
            raise ValueError('Candidate lifecycle timestamp is in the future')
        candidates.append({'release_id': release['id'], 'tag_name': tag, 'run_id': run_id,
                           'revision': revision,
                           'created_at': run['created_at'], 'last_activity': max(dates).isoformat(),
                           'usable': usable(run, release, artifacts, assets),
                           'successful': run.get('conclusion') == 'success' and run.get('status') == 'completed',
                           'snapshot': snapshot(release, run, artifacts, assets)})
    eligible = [row for row in candidates if row['usable']]
    # If index storage was removed/expired, preserve the newest successful draft
    # until replacement validation exists rather than deleting the final copy.
    fallback = [row for row in candidates if row['successful']]
    protected = max(eligible or fallback, key=lambda row: (timestamp(row['created_at']), row['run_id']), default=None)
    protected_ids = {row['release_id'] for row in candidates if row['revision'] == main_revision}
    if protected is not None:
        protected_ids.add(protected['release_id'])
    for row in candidates:
        if active:
            reason = 'active validation or publication'
        elif row['revision'] == main_revision:
            reason = 'current main candidate'
        elif protected is not None and row['release_id'] == protected['release_id']:
            reason = 'latest usable native build' if eligible else 'latest successful build; current validation unavailable'
        elif row['snapshot']['run']['status'] != 'completed':
            reason = 'producer is active'
        else:
            reason = 'superseded or abandoned candidate'
        row.update(action='delete' if reason.startswith('superseded') else 'keep', reason=reason)
    return {'schema': 'keep.validation-retention-plan.v1', 'repository': REPOSITORY,
            'workflow_id': workflow_id, 'active_runs': active,
            'blocked': bool(active), 'protected_release_id': protected['release_id'] if protected else None,
            'protected_release_ids': sorted(protected_ids), 'main_revision': main_revision,
            'candidates': sorted(candidates, key=lambda row: row['run_id'])}


def execute_guard():
    if (os.environ.get('GITHUB_REPOSITORY') != REPOSITORY or
            os.environ.get('GITHUB_REF') != 'refs/heads/main' or
            os.environ.get('GITHUB_EVENT_NAME') not in ('schedule', 'workflow_dispatch', 'workflow_run') or
            os.environ.get('GITHUB_WORKFLOW_REF') != REPOSITORY + '/' + CLEANUP_WORKFLOW + '@refs/heads/main'):
        raise ValueError('Cleanup writes require the trusted main retention workflow')
    repository_id, producer_workflow_id = identity()
    workflow = api('/actions/workflows/validation-retention.yml')
    workflow_id = builds.positive(workflow.get('id'), 'cleanup workflow ID')
    run_id = builds.positive(os.environ.get('GITHUB_RUN_ID'), 'cleanup run ID')
    run = api('/actions/runs/' + str(run_id))
    revision = os.environ.get('GITHUB_SHA', '')
    if (workflow.get('path') != CLEANUP_WORKFLOW or run.get('id') != run_id or run.get('workflow_id') != workflow_id or
            run.get('path') != CLEANUP_WORKFLOW or run.get('head_branch') != 'main' or
            run.get('head_sha') != revision or not builds.SHA.fullmatch(revision) or
            run.get('event') != os.environ['GITHUB_EVENT_NAME'] or run.get('status') != 'in_progress' or
            any(run.get(key, {}).get('id') != repository_id or run.get(key, {}).get('full_name') != REPOSITORY
                for key in ('repository', 'head_repository')) or
            api('/git/ref/heads/main').get('object', {}).get('sha') != revision):
        raise ValueError('Cleanup workflow is untrusted or no longer current main')
    if os.environ['GITHUB_EVENT_NAME'] == 'workflow_run':
        trigger_id = builds.positive(os.environ.get('RETENTION_TRIGGER_RUN_ID'), 'cleanup trigger run ID')
        trigger = api('/actions/runs/' + str(trigger_id))
        trigger_revision = trigger.get('head_sha', '')
        if not builds.SHA.fullmatch(trigger_revision) or trigger.get('status') != 'completed':
            raise ValueError('Cleanup trigger must be a completed primary main validation')
        run_identity(trigger, trigger_revision, trigger_id, repository_id, producer_workflow_id)


def recheck_candidate(candidate, repository_id, workflow_id):
    release = api(f"/releases/{candidate['release_id']}")
    revision, run_id = release_identity(release)
    run = api(f'/actions/runs/{run_id}')
    run_identity(run, revision, run_id, repository_id, workflow_id)
    assets = asset_snapshot(pages(f"/releases/{candidate['release_id']}/assets"), run_id, run['run_attempt'])
    artifacts = artifacts_for(run, repository_id)
    if snapshot(release, run, artifacts, assets) != candidate['snapshot']:
        raise ValueError('Candidate metadata changed before scoped cleanup')


def protection_guard(current, rows, deleted, repository_id, workflow_id):
    """Reconfirm surviving storage and workflow inactivity before EACH write."""
    execute_guard()
    if active_runs(workflow_id):
        raise ValueError('Validation/publication started during cleanup')
    actual_ids = set()
    for release in pages('/releases'):
        if release.get('tag_name', '').startswith('candidate-'):
            release_identity(release)
            if release['id'] in actual_ids:
                raise ValueError('Ambiguous candidate inventory during cleanup')
            actual_ids.add(release['id'])
    if actual_ids != set(rows) - set(deleted):
        raise ValueError('Candidate inventory changed during cleanup')
    for release_id in current['protected_release_ids']:
        recheck_candidate(rows[release_id], repository_id, workflow_id)


def execute(original):
    execute_guard()
    if original['blocked']:
        raise ValueError('Cleanup is blocked by active validation or publication')
    # Reassess protection once before mutations, including immutable index ZIPs.
    # Later boundaries re-read current provider metadata without downloading the
    # same immutable indexes or walking every producer's jobs for each deletion.
    current = plan()
    if (current['blocked'] or current['protected_release_ids'] != original['protected_release_ids'] or
            current['main_revision'] != original['main_revision']):
        raise ValueError('Cleanup plan changed; refusing stale deletion')
    rows = {row['release_id']: row for row in current['candidates']}
    for candidate in original['candidates']:
        if candidate['action'] == 'delete' and (
                candidate['release_id'] not in rows or rows[candidate['release_id']]['action'] != 'delete' or
                rows[candidate['release_id']]['snapshot'] != candidate['snapshot']):
            raise ValueError('Cleanup plan changed; refusing stale deletion')
    repository_id, workflow_id = identity()
    deleted = []
    for candidate in original['candidates']:
        if candidate['action'] != 'delete':
            continue
        protection_guard(current, rows, deleted, repository_id, workflow_id)
        recheck_candidate(candidate, repository_id, workflow_id)
        for artifact in candidate['snapshot']['artifacts']:
            protection_guard(current, rows, deleted, repository_id, workflow_id)
            actual = api(f"/actions/artifacts/{artifact['id']}")
            if {key: actual.get(key) for key in artifact} != artifact:
                raise ValueError('Index changed before scoped deletion')
            api(f"/actions/artifacts/{artifact['id']}", method='DELETE')
        protection_guard(current, rows, deleted, repository_id, workflow_id)
        release = api(f"/releases/{candidate['release_id']}")
        release_identity(release)
        assets = asset_snapshot(pages(f"/releases/{candidate['release_id']}/assets"), candidate['run_id'],
                                candidate['snapshot']['run']['run_attempt'])
        run = api(f"/actions/runs/{candidate['run_id']}")
        expected = snapshot(release, run, [], assets)
        saved = {**candidate['snapshot'], 'artifacts': []}
        if expected != saved:
            raise ValueError('Draft or producer changed before scoped deletion')
        api(f"/releases/{candidate['release_id']}", method='DELETE')
        deleted.append(candidate['release_id'])
    return deleted


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true', help='Remove only reviewed, superseded candidate storage')
    args = parser.parse_args()
    inventory = plan()
    print(json.dumps(inventory, sort_keys=True, indent=2), flush=True)
    if args.execute:
        print(json.dumps({'deleted_candidate_ids': execute(inventory)}, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        detail = ': ' + str(error) if isinstance(error, ValueError) else ''
        raise SystemExit('Validation retention failed: ' + type(error).__name__ + detail) from None
