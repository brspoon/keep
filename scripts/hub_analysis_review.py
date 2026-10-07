"""Validate a maintainer's recorded Docker Hub hosted-analysis review.

This is a manual review receipt, not a Docker Hub API scan result. The supported
Hub API does not expose a documented hosted-analysis completion/count contract.
"""
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile

ARCHES = ('amd64', 'arm64')
SEVERITIES = {'critical', 'high', 'medium', 'low', 'unspecified'}
MAX_AGE_SECONDS = 3600
MAX_BYTES = 32 * 1024


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate Docker Hub review field')
        result[key] = value
    return result


def validate_review(body, image, revision, digests, *, now=None):
    """Require explicit complete, zero-count results for both exact native images."""
    if not isinstance(body, bytes) or not body or len(body) > MAX_BYTES:
        raise ValueError('A bounded Docker Hub hosted-analysis review receipt is required')
    try:
        review = json.loads(body.decode('utf-8'), object_pairs_hook=unique_object)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError('Docker Hub review must be valid UTF-8 JSON') from error
    fields = {'format', 'review_source', 'image', 'revision', 'reviewed_at', 'reviewed_by', 'architectures'}
    if (not isinstance(review, dict) or set(review) != fields or
            review.get('format') != 'keep-hub-analysis-review-v1' or
            review.get('review_source') != 'docker-hub-ui' or
            review.get('image') != image or review.get('revision') != revision or
            not isinstance(review.get('reviewed_by'), str) or
            not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]{0,38}', review['reviewed_by'])):
        raise ValueError('Docker Hub review identity or maintainer verification differs')
    timestamp = review.get('reviewed_at')
    if not isinstance(timestamp, str) or not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z', timestamp):
        raise ValueError('Docker Hub review requires an exact UTC review time')
    try:
        reviewed_at = datetime.datetime.strptime(timestamp, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=datetime.timezone.utc)
    except ValueError as error:
        raise ValueError('Docker Hub review time is invalid') from error
    current = now if now is not None else utc_now()
    if current.tzinfo is None or current.utcoffset() != datetime.timedelta(0):
        raise ValueError('Docker Hub review validation requires UTC time')
    age = (current - reviewed_at).total_seconds()
    if age < 0 or age > MAX_AGE_SECONDS:
        raise ValueError('Docker Hub review is future-dated or older than one hour')
    results = review.get('architectures')
    if (not isinstance(digests, dict) or set(digests) != set(ARCHES) or
            not isinstance(results, dict) or set(results) != set(ARCHES)):
        raise ValueError('Docker Hub review requires both native architecture identities')
    for arch in ARCHES:
        result = results[arch]
        if (not isinstance(digests[arch], str) or
                not re.fullmatch(r'sha256:[0-9a-f]{64}', digests[arch]) or
                not isinstance(result, dict) or set(result) != {'platform', 'digest', 'status', 'unfiltered', 'counts'} or
                result.get('platform') != 'linux/' + arch or result.get('digest') != digests[arch] or
                result.get('status') != 'complete' or result.get('unfiltered') is not True):
            raise ValueError('Docker Hub hosted analysis is incomplete or differs for ' + arch)
        counts = result.get('counts')
        if (not isinstance(counts, dict) or set(counts) != SEVERITIES or
                any(type(value) is not int or value != 0 for value in counts.values())):
            raise ValueError('Docker Hub review must explicitly report zero vulnerabilities at every severity for ' + arch)
    return review


def review_body(image, revision, digests):
    value = os.environ.get('KEEP_HUB_ANALYSIS_REVIEW')
    if not isinstance(value, str):
        raise ValueError('A Docker Hub hosted-analysis review receipt is required before release publication')
    body = value.encode('utf-8')
    review = validate_review(body, image, revision, digests)
    if review['reviewed_by'] != os.environ.get('GITHUB_ACTOR'):
        raise ValueError('Docker Hub review maintainer must match the dispatching GitHub actor')
    return body


def retain_review(materials, release, version, body):
    """Retain exact supplied bytes separately from original native evidence."""
    run, attempt = os.environ.get('GITHUB_RUN_ID', ''), os.environ.get('GITHUB_RUN_ATTEMPT', '')
    if not re.fullmatch(r'[1-9][0-9]*', run) or not re.fullmatch(r'[1-9][0-9]*', attempt):
        raise ValueError('Docker Hub review retention requires this publication run identity')
    with tempfile.TemporaryDirectory(prefix='keep-hub-review-') as directory:
        path = Path(directory) / f'keep-{version}-hub-analysis-review-{run}-{attempt}.json'
        path.write_bytes(body)
        sidecar = path.with_name(path.name + '.sha256')
        sidecar.write_text(hashlib.sha256(body).hexdigest() + '  ' + path.name + '\n')
        materials.guard()
        asset = materials.upload(release, path)
        materials.guard()
        checksum = materials.upload(release, sidecar)
        if materials.asset_body(asset) != body or materials.asset_body(checksum) != sidecar.read_bytes():
            raise ValueError('Retained Docker Hub review bytes or checksum differ')
