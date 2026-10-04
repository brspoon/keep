#!/usr/bin/env python3
"""Choose native CI only after proving a harmless published-version docs change.

Fast contribution and Windows checks always run. This does not authorize image
reuse: unpublished versions and any uncertain classification get fresh native
verification, and publication retains its exact-commit requirements.
"""
from dataclasses import dataclass
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import urllib.error
import urllib.request


REPOSITORY = 'brspoon/keep'
API = 'https://api.github.com/repos/' + REPOSITORY
SHA = re.compile(r'[0-9a-f]{40}\Z')
VERSION = re.compile(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z')
# Explicit prose-only files, never a blanket docs/** or *.md exclusion.
DOCUMENTS = frozenset({
    'README.md', 'CHANGELOG.md', 'docs/README.md', 'docs/API.md',
    'docs/DOCKERHUB_OVERVIEW.md', 'docs/FEATURES.md', 'docs/INSTALLATION.md',
    'docs/MIGRATION.md', 'docs/PORTABLE_BACKUP.md', 'docs/PREVIEW.md',
})
SCREENSHOT_SUFFIXES = frozenset({'.png', '.jpg', '.jpeg', '.webp'})
DIFF_LIMIT = 8 * 1024 * 1024
METADATA_LIMIT = 1024 * 1024


@dataclass(frozen=True)
class Change:
    status: str
    old_path: str | None
    new_path: str | None
    old_mode: str
    new_mode: str


@dataclass(frozen=True)
class Plan:
    native_required: bool
    documentation_only: bool
    reason: str
    version: str = ''
    files: int = 0


def harmless_path(path):
    if (not isinstance(path, str) or not path or '\\' in path or
            path.startswith('/') or any(ord(character) < 32 for character in path)):
        return False
    parts = path.split('/')
    if any(part in {'', '.', '..'} for part in parts):
        return False
    name = PurePosixPath(path)
    return path in DOCUMENTS or (
        name.parts[:2] == ('docs', 'screenshots') and
        len(name.parts) >= 3 and name.suffix in SCREENSHOT_SUFFIXES)


def parse_changes(raw):
    """Read Git's NUL-delimited raw diff, retaining both names and file modes."""
    if not isinstance(raw, bytes) or len(raw) > DIFF_LIMIT or (raw and not raw.endswith(b'\0')):
        raise ValueError('Invalid Git change listing')
    tokens = raw.split(b'\0')[:-1]
    changes = []
    position = 0
    while position < len(tokens):
        header = tokens[position].decode('ascii')
        position += 1
        match = re.fullmatch(r':([0-7]{6}) ([0-7]{6}) ([0-9a-f]{40}) ([0-9a-f]{40}) (A|D|M|T|R(?:100|[0-9]{1,2})|C(?:100|[0-9]{1,2}))', header)
        if not match:
            raise ValueError('Unsupported Git change status')
        old_mode, new_mode, _old_sha, _new_sha, status = match.groups()
        name_count = 2 if status.startswith(('R', 'C')) else 1
        names = tokens[position:position + name_count]
        if len(names) != name_count or any(not name for name in names):
            raise ValueError('Missing Git change name')
        position += name_count
        paths = [name.decode('utf-8') for name in names]
        old_path = None if status == 'A' else paths[0]
        new_path = None if status == 'D' else paths[-1]
        changes.append(Change(status, old_path, new_path, old_mode, new_mode))
    return changes


def harmless_change(change):
    if change.status == 'T' or change.status.startswith('C'):
        return False
    # Symlinks, submodules and executable-mode changes are never documentation.
    modes = {'A': ('000000', '100644'), 'D': ('100644', '000000')}.get(
        change.status, ('100644', '100644'))
    if (change.old_mode, change.new_mode) != modes:
        return False
    return all(harmless_path(path) for path in (change.old_path, change.new_path) if path is not None)


def git(root, *arguments):
    return subprocess.run(['git', *arguments], cwd=root, check=True, timeout=30,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout


def changed_files(root, event, base, head):
    if (event not in {'push', 'pull_request'} or not SHA.fullmatch(base or '') or
            not SHA.fullmatch(head or '') or base == '0' * 40 or head == '0' * 40):
        raise ValueError('Trusted diff endpoints are unavailable')
    for revision in (base, head):
        if git(root, 'rev-parse', '--verify', revision + '^{commit}').decode().strip() != revision:
            raise ValueError('Diff endpoint is not an exact commit')
    if event == 'pull_request':
        base = git(root, 'merge-base', base, head).decode().strip()
        if not SHA.fullmatch(base):
            raise ValueError('Pull request merge base is unavailable')
    elif git(root, 'rev-parse', 'HEAD').decode().strip() != head:
        raise ValueError('Main diff differs from the checked-out commit')
    return parse_changes(git(root, 'diff', '--raw', '-z', '--no-abbrev', '--find-renames', base, head, '--'))


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file, code, message, headers, newurl):
        return None


def published_version(version):
    """Read only public, completed GitHub release metadata; never send a token."""
    if not VERSION.fullmatch(version):
        raise ValueError('Invalid published version')
    url = API + '/releases/tags/' + version
    request = urllib.request.Request(url, headers={
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'Keep-CI-change-classification'})
    try:
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=10) as response:
            if response.geturl() != url:
                raise ValueError('Release metadata returned from an unexpected address')
            body = response.read(METADATA_LIMIT + 1)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return False
        raise
    if len(body) > METADATA_LIMIT:
        raise ValueError('Release metadata exceeds its size limit')
    release = json.loads(body)
    if not isinstance(release, dict):
        raise ValueError('Release metadata is unavailable')
    release_id = release.get('id')
    if (isinstance(release_id, bool) or not isinstance(release_id, int) or release_id < 1 or
            release.get('tag_name') != version or release.get('draft') is not False or
            release.get('prerelease') is not False or
            not isinstance(release.get('published_at'), str) or
            not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z', release['published_at']) or
            release.get('url') != API + '/releases/' + str(release_id) or
            release.get('html_url') != 'https://github.com/' + REPOSITORY + '/releases/tag/' + version):
        return False
    return True


def classify(root, event, base, head, repository, *, release_lookup=published_version):
    if repository != REPOSITORY:
        return Plan(True, False, 'Primary repository identity is unavailable; full native verification is required.')
    try:
        changes = changed_files(root, event, base, head)
    except (ValueError, UnicodeError, OSError, subprocess.SubprocessError):
        return Plan(True, False, 'The complete change list could not be verified; full native verification is required.')
    if not changes or not all(harmless_change(change) for change in changes):
        return Plan(True, False, 'Changes include build, source, test, policy or unknown inputs; full native verification is required.', files=len(changes))
    try:
        version = git(root, 'show', head + ':VERSION').decode().strip()
        if not VERSION.fullmatch(version):
            raise ValueError('Invalid committed version')
        published = release_lookup(version)
        if type(published) is not bool:
            raise ValueError('Published version proof is unavailable')
    except (ValueError, UnicodeError, OSError, subprocess.SubprocessError):
        return Plan(True, True, 'The current version could not be verified as publicly released; full native verification is required.', files=len(changes))
    if not published:
        return Plan(True, True, 'This version is not publicly released; fresh exact-commit native verification is required.', version, len(changes))
    return Plan(False, True, 'Only allowlisted prose or screenshots changed for an already published version; fast checks remain required.', version, len(changes))


def report(plan, event, *, output=None, summary=None):
    if output:
        with Path(output).open('a') as stream:
            stream.write('native_required=' + str(plan.native_required).lower() + '\n')
            stream.write('documentation_only=' + str(plan.documentation_only).lower() + '\n')
            stream.write('reason=' + plan.reason + '\n')
    native = 'required after merging' if event == 'pull_request' else 'required'
    if not plan.native_required:
        native = 'skipped for published-version documentation'
    message = ('Native validation: ' + native + '. ' + plan.reason +
               '\nPython, JavaScript and Windows installer checks remain required.\n' +
               'No older commit\'s image or source evidence is reused.\n')
    print(message, end='')
    if summary:
        with Path(summary).open('a') as stream:
            stream.write('### CI validation plan\n\n' + message + '\n')


def main():
    event = os.environ.get('GITHUB_EVENT_NAME', '')
    plan = classify(Path.cwd(), event, os.environ.get('CI_BASE_SHA', ''),
        os.environ.get('CI_HEAD_SHA', ''), os.environ.get('GITHUB_REPOSITORY', ''))
    report(plan, event, output=os.environ.get('GITHUB_OUTPUT'), summary=os.environ.get('GITHUB_STEP_SUMMARY'))


if __name__ == '__main__':
    main()
