"""Apply exact security hunks with upstream or Keep-local provenance.

No fuzzy matching or version/packaging metadata changes are permitted.
"""
import hashlib
import json
from pathlib import Path
import sysconfig


def patch_provenance(patch):
    kind = patch.get('source_kind', 'upstream')
    if kind == 'upstream':
        if not isinstance(patch['commit'], str) or not patch['commit']:
            raise ValueError('Upstream security patch requires a commit')
        return {'source_kind': kind, 'upstream_commit': patch['commit']}
    if kind == 'keep-local':
        if patch.get('commit') is not None or not patch.get('source_id'):
            raise ValueError('Keep-local security patch requires its own source identifier')
        return {'source_kind': kind, 'source_id': patch['source_id'],
                'upstream_commit': None}
    raise ValueError(f'Unknown security patch source: {kind}')


def apply_hunks(original, patch):
    updated = original
    for hunk in patch['hunks']:
        before_count = updated.count(hunk['before'])
        if before_count == 1:
            updated = updated.replace(hunk['before'], hunk['after'], 1)
        elif before_count != 0 or updated.count(hunk['after']) != 1:
            source = patch.get('source_id') or patch['commit']
            raise RuntimeError(f"Security patch context mismatch: {patch['path']} {source}")
    return updated


def clear_bytecode(target):
    """Remove all importable cached forms of this exact patched source module."""
    paths = [target.with_suffix('.pyc')]
    cache = target.parent / '__pycache__'
    if cache.is_symlink():
        raise RuntimeError('Security patch bytecode directory is a symlink')
    if cache.exists():
        paths.extend(cache.glob(target.stem + '.*.pyc'))
    for path in paths:
        if path.exists() or path.is_symlink():
            path.unlink()


def apply_patches(root, patches):
    root = Path(root).resolve()
    pending, records = {}, []
    for patch in patches:
        provenance = patch_provenance(patch)
        target = root / patch['path']
        if target.is_symlink() or not target.is_file() or not target.resolve().is_relative_to(root):
            raise RuntimeError('Security patch target is outside the standard library')
        original = pending.get(target, target.read_text())
        updated = apply_hunks(original, patch)
        compile(updated, str(target), 'exec')
        pending[target] = updated
        records.append({'path': patch['path'], **provenance,
                        'before_sha256': hashlib.sha256(original.encode()).hexdigest(),
                        'after_sha256': hashlib.sha256(updated.encode()).hexdigest()})
    # Reject all unreviewed contexts before changing any source file.
    for target, updated in pending.items():
        cache = target.parent / '__pycache__'
        if cache.is_symlink():
            raise RuntimeError('Security patch bytecode directory is a symlink')
    for target, updated in pending.items():
        target.write_text(updated)
        clear_bytecode(target)
    return records


def main():
    root = Path(sysconfig.get_path('stdlib'))
    patches = json.loads(Path(__file__).with_name('python_security_patches.json').read_text())
    for record in apply_patches(root, patches):
        print(json.dumps(record))


if __name__ == '__main__':
    main()
