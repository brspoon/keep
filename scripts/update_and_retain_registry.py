#!/usr/bin/env python3
"""Run the existing host updater, then retain registry images after deployment.

The host supplies update_registry.py; it is not part of the portable repository.
Cleanup failure never turns a successful deployment into a failed deployment.
"""
import argparse
from datetime import datetime, timedelta, timezone
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

from retain_registry import Hold as RetentionHold, operator_config

ROOT = Path(__file__).resolve().parents[1]
MAX_RECEIPT_AGE = timedelta(hours=24)
RECEIPT_FIELDS = {'image', 'version', 'revision', 'completed_at', 'recovery'}
MARKER_SCHEMA = 'keep.registry-post-deploy.v1'
HOLD_FILES = ('dev-trial-active', 'update-request', 'failed-image', 'last-error.json')


class Hold(Exception):
    """The completed deployment cannot safely trigger retention."""


def _now():
    return datetime.now(timezone.utc)


def _pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise Hold('Deployment state contains duplicate JSON fields')
        value[key] = item
    return value


def _read_json(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 16 * 1024:
        raise Hold('Deployment state is missing or unsafe')
    try:
        return json.loads(path.read_text(), object_pairs_hook=_pairs)
    except (OSError, ValueError, UnicodeError, RecursionError):
        raise Hold('Deployment state could not be validated') from None


def receipt_time(receipt):
    value = receipt.get('completed_at')
    if not isinstance(value, str) or not re.fullmatch(
            r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])', value):
        raise Hold('Deployment completion timestamp is invalid')
    try:
        completed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if completed.tzinfo is None:
            raise ValueError('missing timezone')
        return completed.astimezone(timezone.utc)
    except (ValueError, OverflowError):
        raise Hold('Deployment completion timestamp is invalid') from None


def _validate_receipt(receipt, root, *, fresh=False, require_recovery=True):
    if not isinstance(receipt, dict) or set(receipt) != RECEIPT_FIELDS:
        raise Hold('Deployment receipt fields are incomplete or unexpected')
    patterns = {'image': r'sha256:[0-9a-f]{64}',
                'version': r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)',
                'revision': r'[0-9a-f]{40}'}
    if any(not isinstance(receipt[key], str) or not re.fullmatch(pattern, receipt[key])
           for key, pattern in patterns.items()):
        raise Hold('Deployment receipt identity is invalid')
    completed, now = receipt_time(receipt), _now()
    if completed > now or (fresh and now - completed > MAX_RECEIPT_AGE):
        raise Hold('Deployment completion is future-dated or stale')
    if not isinstance(receipt['recovery'], str):
        raise Hold('Deployment recovery path is invalid')
    recovery = Path(receipt['recovery'])
    parent = root / '.deploy-backups'
    if (not recovery.is_absolute() or recovery.parent != parent or
            not re.fullmatch(r'registry-\d{8}T\d{6}Z', recovery.name)):
        raise Hold('Deployment recovery path is invalid')
    try:
        datetime.strptime(recovery.name, 'registry-%Y%m%dT%H%M%SZ')
    except ValueError:
        raise Hold('Deployment recovery path timestamp is invalid') from None
    if require_recovery and (parent.is_symlink() or recovery.is_symlink() or not recovery.is_dir()):
        raise Hold('Deployment recovery directory is unavailable or invalid')
    return receipt


def read_receipt(root, *, fresh=False):
    return _validate_receipt(_read_json(root / '.registry-state/deployed.json'), root, fresh=fresh)


def marker_path(root):
    return root / '.registry-state/retention-after-deploy.json'


def _read_marker(root):
    path = marker_path(root)
    if not path.exists() and not path.is_symlink():
        return None
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077):
        raise Hold('Post-deployment retention marker must be private and owner-only')
    value = _read_json(path)
    if (not isinstance(value, dict) or set(value) != {'schema', 'receipt'} or
            value['schema'] != MARKER_SCHEMA):
        raise Hold('Post-deployment retention marker is invalid')
    # Older recovery directories may have been retired after a newer deployment.
    return _validate_receipt(value['receipt'], root, require_recovery=False)


def cleanup_ready(root):
    try:
        operator_config(root)
    except RetentionHold:
        raise Hold('Retention operator configuration is unavailable or unsafe') from None
    state = root / '.registry-state'
    if state.is_symlink() or not state.is_dir():
        raise Hold('Deployment state directory is unsafe')
    if any((state / name).exists() or (state / name).is_symlink() for name in HOLD_FILES):
        raise Hold('Deployment is pending, held, or failed')
    lock_path = root / '.git/keep-deploy.lock'
    if lock_path.is_symlink() or not lock_path.is_file():
        raise Hold('Deployment lock cannot be verified')
    with lock_path.open('rb') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Hold('Deployment lock is busy') from None
        # Retention takes this same lock and rechecks production/recovery itself.
        # Release the probe before starting that subprocess.
        fcntl.flock(lock, fcntl.LOCK_UN)


def _write_marker(root, receipt):
    path = marker_path(root)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', prefix='.retention-after-deploy-',
                                         dir=path.parent, delete=False) as output:
            temporary = Path(output.name)
            os.chmod(temporary, 0o600)
            json.dump({'schema': MARKER_SCHEMA, 'receipt': receipt}, output, sort_keys=True)
            output.write('\n')
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _status(status, reason):
    print(json.dumps({'status': status, 'reason': reason}), flush=True)


def run(root=ROOT, after_deploy=False, queued=False):
    root = Path(root)
    if after_deploy and queued:
        raise ValueError('--after-deploy and --queued are separate operations')
    before = None
    if not after_deploy:
        try:
            before = read_receipt(root)
        except (Hold, OSError):
            pass  # An invalid old receipt must not block the authorized updater.
        command = [sys.executable, str(root / 'scripts/update_registry.py')]
        if queued:
            command.append('--queued')
        try:
            updated = subprocess.run(command, cwd=root, check=False)
        except OSError:
            _status('update-failed', 'The host updater could not be started')
            return 1
        if updated.returncode != 0:
            _status('update-failed', 'The host updater failed; registry retention was not run')
            return updated.returncode
    try:
        cleanup_ready(root)
        after = read_receipt(root, fresh=True)
        if not after_deploy:
            if before is None:
                raise Hold('The previous deployment receipt could not be validated')
            if (after == before or receipt_time(after) <= receipt_time(before) or
                    all(after[key] == before[key] for key in ('image', 'version', 'revision'))):
                _status('unchanged', 'No new completed deployment; registry retention was not run')
                return 0
        if _read_marker(root) == after:
            _status('already-retained', 'This completed deployment already triggered successful retention')
            return 0
        # Waiting for the updater also allows it to clear last-error and release
        # its lock before retention independently acquires that lock.
        retained = subprocess.run([sys.executable, str(root / 'scripts/retain_registry.py'),
                                   '--execute', '--refresh-artifacts', '--root', str(root)], cwd=root, check=False)
        if retained.returncode != 0:
            raise Hold('Registry cleanup did not complete; hourly retention remains available to retry')
        cleanup_ready(root)
        if read_receipt(root, fresh=True) != after:
            raise Hold('Deployment changed during cleanup; its trigger marker was not saved')
        _write_marker(root, after)
    except (Hold, OSError, ValueError, TypeError):
        _status('held', 'Registry cleanup is held; deployment state was preserved and the hourly job can retry')
        return 0
    _status('retained', 'Registry retention completed after the successful deployment')
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--queued', action='store_true', help='forward the existing updater queue flag')
    mode.add_argument('--after-deploy', action='store_true', help='retain after a fresh guarded manual deployment')
    parser.add_argument('--root', type=Path, default=ROOT, help='deployment checkout directory')
    args = parser.parse_args(argv)
    os.umask(0o077)
    return run(args.root, after_deploy=args.after_deploy, queued=args.queued)


if __name__ == '__main__':
    raise SystemExit(main())
