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


def reviewed_findings(results, security_reviews, today):
    """Bind truthful hosted findings to the original, fully verified native proof."""
    import review_image
    from scout_exception_policy import canonical_scout_finding, finding_decision

    if not isinstance(security_reviews, dict) or set(security_reviews) != set(ARCHES):
        raise ValueError('Docker Hub nonzero findings require both original native security reviews')
    for arch in ARCHES:
        context = security_reviews[arch]
        required = {'report', 'scout', 'evidence', 'provenance', 'dependencies'}
        if (not isinstance(context, dict) or not required <= set(context)
                or set(context) - required - {'root'}):
            raise ValueError('Docker Hub findings require original native security evidence for ' + arch)
        # Always use the current UTC day, including immediately before a push.
        # Neither the receipt timestamp nor an earlier caller review extends approval.
        checked = review_image.review_reports(arch, **{**context, 'today': today})
        if checked['blocked'] or checked['scout_blocked']:
            raise ValueError('Docker Hub findings require successful native security review for ' + arch)
        policy = review_image.reviewed_policy(context.get('root', Path('.')))
        original = [canonical_scout_finding(run, finding)
                    for run in context['scout']['runs'] for finding in run['results']]
        for finding in results[arch]['findings']:
            reason = finding_decision(finding, policy, today)
            if reason:
                raise ValueError('Docker Hub finding blocks ' + arch + ': ' + finding['id'] + ': ' + reason)
            if original and finding not in original:
                raise ValueError('Docker Hub finding differs from original native Scout evidence for ' + arch)


def validate_review(body, image, revision, digests, *, now=None, security_reviews=None):
    """Require complete exact-image counts; v2 permits only reviewed false positives."""
    if not isinstance(body, bytes) or not body or len(body) > MAX_BYTES:
        raise ValueError('A bounded Docker Hub hosted-analysis review receipt is required')
    try:
        review = json.loads(body.decode('utf-8'), object_pairs_hook=unique_object)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError('Docker Hub review must be valid UTF-8 JSON') from error
    fields = {'format', 'review_source', 'image', 'revision', 'reviewed_at', 'reviewed_by', 'architectures'}
    if (not isinstance(review, dict) or set(review) != fields or
            not isinstance(review.get('format'), str) or
            review['format'] not in {'keep-hub-analysis-review-v1', 'keep-hub-analysis-review-v2'} or
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
    v2 = review['format'] == 'keep-hub-analysis-review-v2'
    nonzero = False
    for arch in ARCHES:
        result = results[arch]
        result_fields = {'platform', 'digest', 'status', 'unfiltered', 'counts'}
        if v2:
            result_fields.add('findings')
        if (not isinstance(digests[arch], str) or
                not re.fullmatch(r'sha256:[0-9a-f]{64}', digests[arch]) or
                not isinstance(result, dict) or set(result) != result_fields or
                result.get('platform') != 'linux/' + arch or result.get('digest') != digests[arch] or
                result.get('status') != 'complete' or result.get('unfiltered') is not True):
            raise ValueError('Docker Hub hosted analysis is incomplete or differs for ' + arch)
        counts = result.get('counts')
        if (not isinstance(counts, dict) or set(counts) != SEVERITIES or
                any(type(value) is not int or value < 0 or (not v2 and value != 0)
                    for value in counts.values())):
            requirement = 'nonnegative integer counts' if v2 else 'zero vulnerabilities at every severity'
            raise ValueError('Docker Hub review must explicitly report ' + requirement + ' for ' + arch)
        if v2:
            from scout_exception_policy import FINDING_FIELDS
            findings = result['findings']
            if not isinstance(findings, list):
                raise ValueError('Docker Hub v2 review requires explicit findings for ' + arch)
            derived = {severity: 0 for severity in SEVERITIES}
            identities = set()
            for finding in findings:
                if (not isinstance(finding, dict) or set(finding) != FINDING_FIELDS
                        or any(not isinstance(value, str) or not value for value in finding.values())
                        or finding['severity'] not in {severity.upper() for severity in SEVERITIES}):
                    raise ValueError('Docker Hub finding identity or severity is incomplete for ' + arch)
                identity = tuple(finding[key] for key in sorted(FINDING_FIELDS))
                if identity in identities:
                    raise ValueError('Duplicate Docker Hub finding for ' + arch)
                identities.add(identity)
                derived[finding['severity'].lower()] += 1
            if counts != derived:
                raise ValueError('Docker Hub counts differ from the explicit findings for ' + arch)
            nonzero = nonzero or bool(findings)
    if nonzero:
        reviewed_findings(results, security_reviews, current.date())
    return review


def review_body(image, revision, digests, *, security_reviews=None):
    value = os.environ.get('KEEP_HUB_ANALYSIS_REVIEW')
    if not isinstance(value, str):
        raise ValueError('A Docker Hub hosted-analysis review receipt is required before release publication')
    body = value.encode('utf-8')
    review = validate_review(body, image, revision, digests, security_reviews=security_reviews)
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
