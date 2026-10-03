#!/usr/bin/env python3
"""Create private, read-only GitHub evidence for orphan Keep registry tags."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import subprocess
import sys

REPOSITORY = 'brspoon/keep'
WORKFLOW = '.github/workflows/image.yml'
VERSION = re.compile(r'(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z')
COMMIT_TAG = re.compile(r'sha-([0-9a-f]{40})(?:-(amd64|arm64))?\Z')
TRANSFER_TAG = re.compile(r'transfer-([1-9][0-9]{0,19})-([1-9][0-9]{0,9})-(amd64|arm64)\Z')
TAG_NAME = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}\Z')
DIGEST = re.compile(r'sha256:[0-9a-f]{64}\Z')
SHA = re.compile(r'[0-9a-f]{40}\Z')
TERMINAL_CONCLUSIONS = {
    'success', 'failure', 'cancelled', 'timed_out', 'neutral', 'skipped',
    'action_required', 'stale',
}
PAGE_SIZE = 100
MAX_RUN_PAGES = 20
MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_REVIEW_BYTES = 512 * 1024
GH_TIMEOUT = 30


class ReviewError(Exception):
    """Invalid or incomplete input/evidence; no artifact is approved."""


def parse_inventory(value):
    if isinstance(value, dict):
        value = value.get('rows')
    if not isinstance(value, list):
        raise ReviewError('Inventory must be a list or an object with a rows list.')
    rows = {}
    version_closure = set()
    for row in value:
        if not isinstance(row, dict):
            raise ReviewError('Inventory contains a malformed tag row.')
        name = row.get('name')
        digest = row.get('digest')
        if (not isinstance(name, str) or not TAG_NAME.fullmatch(name) or name in rows or
                (name.startswith('sha-') and not COMMIT_TAG.fullmatch(name)) or
                (name.startswith('transfer-') and not TRANSFER_TAG.fullmatch(name))):
            raise ReviewError('Inventory contains an invalid or duplicate tag name.')
        if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
            raise ReviewError(f'Inventory tag {name} has an invalid digest.')
        images = row.get('images', [])
        if not isinstance(images, list):
            raise ReviewError(f'Inventory tag {name} has invalid platform metadata.')
        image_digests = set()
        platforms = set()
        for image in images:
            if not isinstance(image, dict) or not isinstance(image.get('digest'), str) or not DIGEST.fullmatch(image['digest']):
                raise ReviewError(f'Inventory tag {name} has invalid platform metadata.')
            image_digests.add(image['digest'])
            platform = (image.get('os'), image.get('architecture'))
            if platform != (None, None):
                if platform not in (('linux', 'amd64'), ('linux', 'arm64')) or platform in platforms:
                    raise ReviewError(f'Inventory tag {name} has invalid platform metadata.')
                platforms.add(platform)
        if VERSION.fullmatch(name):
            if (len(images) != 2 or platforms != {('linux', 'amd64'), ('linux', 'arm64')} or
                    len(image_digests) != 2):
                raise ReviewError(f'Version tag {name} has incomplete multi-platform metadata.')
            version_closure.add(digest)
            version_closure.update(image_digests)
        rows[name] = {'digest': digest, 'image_digests': image_digests}
    return rows, version_closure


def _gh_json(executable, endpoint):
    """Run one bounded, explicitly read-only gh API request."""
    try:
        result = subprocess.run([executable, 'api', '--method', 'GET', endpoint],
                                capture_output=True, text=True, timeout=GH_TIMEOUT,
                                check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise ReviewError('GitHub API request failed or timed out.') from None
    if result.returncode != 0 or len(result.stdout.encode('utf-8')) > MAX_JSON_BYTES:
        raise ReviewError('GitHub API request failed or returned an oversized response.')
    try:
        return json.loads(result.stdout)
    except (json.JSONDecodeError, TypeError):
        raise ReviewError('GitHub API returned invalid JSON.') from None


def _valid_run_record(run, expected_sha=None):
    if not isinstance(run, dict):
        raise ReviewError('GitHub returned a malformed workflow run.')
    run_id, attempt = run.get('id'), run.get('run_attempt')
    head_sha = run.get('head_sha')
    repo = run.get('repository')
    head_repo = run.get('head_repository')
    if (type(run_id) is not int or run_id < 1 or type(attempt) is not int or attempt < 1 or
            not isinstance(head_sha, str) or not SHA.fullmatch(head_sha) or
            not isinstance(repo, dict) or repo.get('full_name') != REPOSITORY or
            not isinstance(head_repo, dict) or not isinstance(head_repo.get('full_name'), str) or
            run.get('path') != WORKFLOW):
        raise ReviewError('GitHub workflow evidence did not match the expected repository and workflow.')
    if expected_sha is not None and head_sha != expected_sha:
        raise ReviewError('GitHub workflow listing did not match its requested source revision.')
    status, conclusion = run.get('status'), run.get('conclusion')
    if status != 'completed':
        raise ReviewError('A workflow run for this source is not in a known terminal state.')
    if conclusion not in TERMINAL_CONCLUSIONS:
        raise ReviewError('A workflow run has an unknown terminal conclusion.')
    return run


def review(inventory, executable='gh', api=_gh_json):
    """Return exact terminal evidence and safe omission reasons without writing files."""
    rows, version_digests = parse_inventory(inventory)
    approved = {}
    reasons = []
    source_cache = {}
    for name, row in rows.items():
        transfer = TRANSFER_TAG.fullmatch(name)
        commit = COMMIT_TAG.fullmatch(name)
        if transfer:
            run_id, attempt, arch = transfer.groups()
            try:
                record = api(executable,
                    f'repos/{REPOSITORY}/actions/runs/{run_id}/attempts/{attempt}')
                checked = _valid_run_record(record)
                if (str(checked['id']) != run_id or checked['run_attempt'] != int(attempt) or
                        checked['head_repository']['full_name'] != REPOSITORY):
                    raise ReviewError('Transfer tag did not match its exact trusted same-repository attempt.')
                approved[name] = {
                    'digest': row['digest'], 'run_id': str(checked['id']),
                    'run_attempt': checked['run_attempt'], 'head_sha': checked['head_sha'],
                    'status': checked['status'], 'conclusion': checked['conclusion'],
                }
            except ReviewError as error:
                reasons.append({'tag': name, 'reason': str(error)})
            continue
        if not commit:
            continue
        source_sha, arch = commit.groups()
        if row['digest'] in version_digests or row['image_digests'] & version_digests:
            reasons.append({'tag': name, 'reason': 'digest_is_referenced_by_version_tag'})
            continue
        try:
            if source_sha not in source_cache:
                source_cache[source_sha] = _latest_publisher_run_for_review(
                    executable, source_sha, api)
            checked = source_cache[source_sha]
            approved[name] = {
                'digest': row['digest'], 'run_id': str(checked['id']),
                'run_attempt': checked['run_attempt'], 'head_sha': checked['head_sha'],
                'status': checked['status'], 'conclusion': checked['conclusion'],
            }
        except ReviewError as error:
            reasons.append({'tag': name, 'reason': str(error)})
    return approved, reasons


def _latest_publisher_run_for_review(executable, source_sha, api):
    """Pagination and exact-attempt check using an injectable API reader."""
    runs = []
    run_keys = set()
    total_count = None
    for page in range(1, MAX_RUN_PAGES + 1):
        endpoint = (f'repos/{REPOSITORY}/actions/workflows/image.yml/runs'
                    f'?head_sha={source_sha}&per_page={PAGE_SIZE}&page={page}')
        payload = api(executable, endpoint)
        if (not isinstance(payload, dict) or type(payload.get('total_count')) is not int or
                payload['total_count'] < 0 or not isinstance(payload.get('workflow_runs'), list) or
                len(payload['workflow_runs']) > PAGE_SIZE):
            raise ReviewError('GitHub workflow listing is incomplete or malformed.')
        if total_count is None:
            total_count = payload['total_count']
        elif total_count != payload['total_count']:
            raise ReviewError('GitHub workflow listing changed during pagination.')
        batch = payload['workflow_runs']
        for run in batch:
            checked = _valid_run_record(run, source_sha)
            key = (checked['id'], checked['run_attempt'])
            if key in run_keys:
                raise ReviewError('GitHub workflow pagination repeated a run attempt.')
            run_keys.add(key)
            runs.append(checked)
        if len(runs) == total_count:
            break
        if len(runs) > total_count or not batch:
            raise ReviewError('GitHub workflow pagination did not return the complete listing.')
        if page == MAX_RUN_PAGES:
            raise ReviewError('GitHub workflow listing exceeded the bounded page limit.')
    else:
        raise ReviewError('GitHub workflow listing exceeded the bounded page limit.')
    if not runs:
        raise ReviewError('No workflow evidence exists for this source revision.')
    publishers = [run for run in runs if
                  run['head_repository']['full_name'] == REPOSITORY and
                  run.get('head_branch') == 'main' and
                  run.get('event') in ('push', 'workflow_dispatch') and
                  run.get('conclusion') == 'success']
    if not publishers:
        raise ReviewError('No successful trusted main-branch publisher run exists for this source revision.')
    selected = max(publishers, key=lambda row: (row['id'], row['run_attempt']))
    exact = api(executable,
        f'repos/{REPOSITORY}/actions/runs/{selected["id"]}/attempts/{selected["run_attempt"]}')
    exact = _valid_run_record(exact, source_sha)
    for field in ('id', 'run_attempt', 'head_sha', 'status', 'conclusion', 'event', 'head_branch'):
        if exact.get(field) != selected.get(field):
            raise ReviewError('Exact workflow attempt differs from the workflow listing.')
    if exact['head_repository']['full_name'] != selected['head_repository']['full_name']:
        raise ReviewError('Exact workflow attempt head repository differs from its listing.')
    return exact


def read_inventory(path):
    source = Path(path)
    try:
        fd = os.open(source, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    except OSError:
        raise ReviewError('Inventory must be a readable regular JSON file.') from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_JSON_BYTES:
            raise ReviewError('Inventory must be a regular, bounded JSON file.')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(MAX_JSON_BYTES + 1)
        if len(raw) > MAX_JSON_BYTES:
            raise ReviewError('Inventory must be a regular, bounded JSON file.')
        try:
            return json.loads(raw.decode('utf-8'))
        except (UnicodeError, json.JSONDecodeError):
            raise ReviewError('Inventory file is unreadable or invalid JSON.') from None
    finally:
        os.close(fd)


def _open_private_parent(path):
    parent = path.parent
    flags = os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0) | getattr(os, 'O_NOFOLLOW', 0)
    try:
        fd = os.open(parent, flags)
        info = os.fstat(fd)
    except OSError:
        raise ReviewError('Output parent must already exist as a real directory.') from None
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or
            stat.S_IMODE(info.st_mode) != 0o700):
        os.close(fd)
        raise ReviewError('Output parent must be a real owner-owned mode-0700 directory.')
    return fd


def write_review(path, approved, reviewed_at=None):
    output = Path(path)
    if output.name in ('', '.', '..') or output.name in ('.', '..'):
        raise ReviewError('Invalid output file path.')
    document = {
        'schema': 'keep.registry-artifact-review.v1',
        'repository': REPOSITORY,
        'reviewed_at': reviewed_at or datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
        'artifacts': approved,
    }
    encoded = (json.dumps(document, indent=2, sort_keys=True) + '\n').encode('utf-8')
    if len(encoded) > MAX_REVIEW_BYTES:
        raise ReviewError(
            'Review document exceeds the 512 KiB retention-reader limit; '
            'review fewer registry artifacts per inventory.')
    parent_fd = _open_private_parent(output)
    temp_name = f'.registry-review-{os.getpid()}-{secrets.token_hex(12)}.tmp'
    temp_fd = None
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0)
        temp_fd = os.open(temp_name, flags, 0o600, dir_fd=parent_fd)
        os.fchmod(temp_fd, 0o600)
        with os.fdopen(temp_fd, 'wb') as stream:
            temp_fd = None
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        # Same-directory hard link publishes atomically and refuses replacement.
        os.link(temp_name, output.name, src_dir_fd=parent_fd,
                dst_dir_fd=parent_fd, follow_symlinks=False)
        os.unlink(temp_name, dir_fd=parent_fd)
        os.fsync(parent_fd)
        return output
    except FileExistsError:
        raise ReviewError('Output already exists; choose a new filename.') from None
    except OSError:
        raise ReviewError('Could not safely write the private review file.') from None
    finally:
        if temp_fd is not None:
            os.close(temp_fd)
        try:
            os.unlink(temp_name, dir_fd=parent_fd)
        except FileNotFoundError:
            pass
        os.close(parent_fd)


def resolve_gh(value):
    found = shutil.which(value)
    if not found or not os.access(found, os.X_OK):
        raise ReviewError('The gh executable is not available.')
    return found


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inventory', type=Path, required=True,
                        help='JSON Hub inventory as a list or {"rows": [...]}')
    parser.add_argument('--output', type=Path, required=True,
                        help='New JSON file in an existing owner-owned mode-0700 directory')
    parser.add_argument('--gh', default='gh', help='Existing authenticated gh executable')
    args = parser.parse_args(argv)
    try:
        executable = resolve_gh(args.gh)
        source = read_inventory(args.inventory)
        approved, reasons = review(source, executable)
        write_review(args.output, approved)
    except ReviewError as error:
        print('Registry artifact review stopped: ' + str(error), file=sys.stderr)
        return 2
    for item in reasons:
        print(f'Omitted {item["tag"]}: {item["reason"]}', file=sys.stderr)
    print(f'Wrote private review for {len(approved)} artifact tag(s): {args.output}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
