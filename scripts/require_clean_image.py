"""Fail unless both complete scan reports contain zero findings; no exceptions."""
import json
from pathlib import Path
import sys


def require_clean(grype, scout):
    matches = grype['matches']
    runs = scout['runs']
    if not isinstance(matches, list) or not isinstance(runs, list) or not runs:
        raise ValueError('Incomplete scan report')
    if any(not isinstance(run.get('results'), list) for run in runs):
        raise ValueError('Incomplete Scout results')
    results = [r for run in runs for r in run['results']]
    if matches or results:
        raise ValueError(f'Zero-finding gate: Grype reports {len(matches)} matches; Scout reports {len(results)} findings')


if __name__ == '__main__':
    prefix, arch = sys.argv[1:]
    require_clean(json.loads(Path(f'{prefix}-{arch}.json').read_text()), json.loads(Path(f'{prefix}-scout-{arch}.json').read_text()))
    print('Both complete scans report zero findings. No exceptions applied.')
