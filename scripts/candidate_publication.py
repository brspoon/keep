"""Verify the original completed candidate publication before a later promotion."""
import os
import re

REPOSITORY = 'brspoon/keep'
WORKFLOW = '.github/workflows/image.yml'
REQUIRED = {
    'validated-main': ('Require a successful main validation run for this exact revision',),
    'prepare-release': ('Prepare the version draft release',),
    'tested-images': ('Verify original native evidence and source assets before aggregating tested digests',),
    **{f'Promote retained image ({arch})': (
        'Restore the exact image and original evidence from successful main validation',
        'Transfer retained image through the registry without rebuilding',
        'Archive original corresponding sources and evidence in the approved version draft',
    ) for arch in ('amd64', 'arm64')},
}


def positive(value, label):
    if not isinstance(value, str) or not re.fullmatch(r'[1-9][0-9]{0,19}', value):
        raise ValueError('Invalid ' + label)
    return value


def selected_identity():
    run = os.environ.get('KEEP_CANDIDATE_RUN_ID', '')
    attempt = os.environ.get('KEEP_CANDIDATE_RUN_ATTEMPT', '')
    if run or attempt:
        if os.environ.get('KEEP_CANDIDATE_ONLY') != 'false':
            raise ValueError('An original candidate can be selected only for promotion')
        return (positive(run, 'candidate publication run ID'),
                positive(attempt, 'candidate publication run attempt'))
    if os.environ.get('KEEP_CANDIDATE_ONLY') == 'false':
        raise ValueError('Promotion requires the original candidate publication run and attempt')
    return (positive(os.environ.get('GITHUB_RUN_ID', ''), 'publication run ID'),
            positive(os.environ.get('GITHUB_RUN_ATTEMPT', ''), 'publication run attempt'))


def publication_identity(api):
    run, attempt = selected_identity()
    selected = bool(os.environ.get('KEEP_CANDIDATE_RUN_ID'))
    if not selected:
        return run, attempt
    if os.environ.get('KEEP_CANDIDATE_ONLY') != 'false':
        raise ValueError('An original candidate can be selected only for promotion')
    if run == os.environ.get('GITHUB_RUN_ID'):
        raise ValueError('Promotion must select a completed earlier candidate publication')
    if os.environ.get('GITHUB_REPOSITORY') != REPOSITORY:
        raise ValueError('Candidate publication is restricted to the primary Keep repository')
    repository = api('')
    workflow = api('/actions/workflows/image.yml')
    record = api(f'/actions/runs/{run}/attempts/{attempt}')
    if any(not isinstance(value, dict) for value in (repository, workflow, record)):
        raise ValueError('Original candidate repository or workflow metadata is unavailable')
    repository_id = repository.get('id')
    workflow_id = workflow.get('id')
    if (type(repository_id) is not int or repository_id <= 0 or
            repository.get('full_name') != REPOSITORY or type(repository.get('private')) is not bool or
            type(workflow_id) is not int or workflow_id <= 0 or workflow.get('path') != WORKFLOW or
            any(type(record.get(field)) is not int for field in ('id', 'run_attempt', 'workflow_id')) or
            record.get('id') != int(run) or record.get('run_attempt') != int(attempt) or
            record.get('workflow_id') != workflow_id or record.get('path') != WORKFLOW or
            record.get('event') != 'workflow_dispatch' or record.get('head_branch') != 'main' or
            record.get('head_sha') != os.environ.get('GITHUB_SHA') or
            record.get('status') != 'completed' or record.get('conclusion') != 'success' or
            any(not isinstance(record.get(field), dict) or
                record[field].get('id') != repository_id or
                record.get(field, {}).get('full_name') != REPOSITORY
                for field in ('repository', 'head_repository'))):
        raise ValueError('Original candidate publication must be a successful exact-main primary workflow attempt')
    jobs = []
    total = None
    for page in range(1, 1001):
        response = api(f'/actions/runs/{run}/attempts/{attempt}/jobs?per_page=100&page={page}')
        if not isinstance(response, dict):
            raise ValueError('Original candidate job inventory is unavailable')
        batch = response.get('jobs')
        count = response.get('total_count')
        if (not isinstance(batch, list) or any(not isinstance(job, dict) for job in batch) or
                type(count) is not int or count < 0 or (total is not None and total != count)):
            raise ValueError('Original candidate job inventory is unavailable or inconsistent')
        total = count
        jobs.extend(batch)
        if len(batch) < 100:
            break
    else:
        raise ValueError('Original candidate job inventory exceeds its limit')
    if (len(jobs) != total or any(type(job.get('id')) is not int or job['id'] <= 0 for job in jobs) or
            len({job['id'] for job in jobs}) != len(jobs)):
        raise ValueError('Original candidate job inventory is incomplete or duplicated')
    for name, required_steps in REQUIRED.items():
        matches = [job for job in jobs if job.get('name') == name]
        if len(matches) != 1:
            raise ValueError('Missing or ambiguous original candidate job: ' + name)
        job = matches[0]
        if (type(job.get('run_id')) is not int or type(job.get('run_attempt')) is not int or
                job.get('run_id') != int(run) or job.get('run_attempt') != int(attempt) or
                job.get('head_sha') != os.environ.get('GITHUB_SHA') or
                job.get('status') != 'completed' or job.get('conclusion') != 'success'):
            raise ValueError('Original candidate job did not succeed in the selected attempt: ' + name)
        steps = job.get('steps')
        if not isinstance(steps, list) or any(not isinstance(step, dict) for step in steps):
            raise ValueError('Original candidate steps are unavailable')
        for step_name in required_steps:
            matches = [step for step in steps if step.get('name') == step_name]
            if (len(matches) != 1 or matches[0].get('status') != 'completed' or
                    matches[0].get('conclusion') != 'success'):
                raise ValueError('Original candidate gate did not succeed: ' + step_name)
    publishers = [job for job in jobs if job.get('name') == 'publish-release']
    if len(publishers) != 1 or publishers[0].get('conclusion') != 'skipped':
        raise ValueError('Original run must have stopped before release publication')
    return run, attempt
