"""Bound source acquisition while keeping reports in reviewed input order."""
from concurrent.futures import ThreadPoolExecutor
import os


DEFAULT_WORKERS = 4
MAX_WORKERS = 4


def source_workers(workers=None):
    """Use an explicit count or the shared CI setting; never accept an unbounded pool."""
    value = os.environ.get('KEEP_SOURCE_DOWNLOAD_WORKERS', str(DEFAULT_WORKERS)) if workers is None else workers
    if isinstance(value, bool) or str(value) not in {str(number) for number in range(1, MAX_WORKERS + 1)}:
        raise ValueError('Source download workers must be an integer from 1 to 4')
    return int(value)


def ordered_map(function, items, workers):
    """Yield every task in input order; a single worker preserves serial callbacks."""
    workers = source_workers(workers)
    if workers == 1:
        for item in items:
            yield function(item)
        return
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix='keep-sources') as pool:
        yield from pool.map(function, items)
