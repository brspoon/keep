"""Accept only approved, verified-fixed findings within their review deadlines."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
from inspect_candidate import BASE, DIRECT


def current_day():
    return datetime.datetime.now(datetime.timezone.utc).date()


def exception_deadlines(policy):
    if (not isinstance(policy, dict)
            or not isinstance(policy.get('base'), str)
            or not re.fullmatch(r'sha256:[0-9a-f]{64}', policy['base'])
            or not isinstance(policy.get('approval'), str) or not policy['approval'].strip()):
        raise ValueError('Missing or invalid reviewed base/approval')
    sources = policy.get('reviewed_sources')
    if (not isinstance(sources, dict) or not sources
            or 'scripts/python_security_patches.json' not in sources
            or any(not isinstance(name, str) or not name
                   or not isinstance(digest, str) or not re.fullmatch(r'[0-9a-f]{64}', digest)
                   for name, digest in sources.items())):
        raise ValueError('Missing or invalid reviewed source hashes')
    rules = policy.get('exceptions')
    if not isinstance(rules, dict):
        raise ValueError('Missing exception policy')
    deadlines = {}
    for finding, rule in rules.items():
        if not isinstance(rule, dict) or rule.get('status') != 'fixed':
            raise ValueError(f'{finding}: only verified-fixed exceptions are permitted')
        for field in ('severity', 'type', 'package', 'version', 'evidence'):
            if not isinstance(rule.get(field), str) or not rule[field].strip():
                raise ValueError(f'{finding}: missing exception {field}')
        review = rule.get('review')
        if not isinstance(review, dict):
            raise ValueError(f'{finding}: missing exception review metadata')
        for field in ('deadline', 'approval', 'remove_when'):
            if not isinstance(review.get(field), str) or not review[field].strip():
                raise ValueError(f'{finding}: missing review {field}')
        try:
            deadline = datetime.date.fromisoformat(review['deadline'])
        except ValueError as error:
            raise ValueError(f'{finding}: invalid review deadline') from error
        if deadline.isoformat() != review['deadline']:
            raise ValueError(f'{finding}: review deadline must use YYYY-MM-DD')
        deadlines[finding] = deadline
    return deadlines


def deadline_warnings(policy, today=None, warning_days=14):
    """Report upcoming and overdue reviews without accepting any findings."""
    if warning_days < 0:
        raise ValueError('Warning days must be nonnegative')
    today = today or current_day()
    warnings = []
    for finding, deadline in sorted(exception_deadlines(policy).items()):
        remaining = (deadline - today).days
        if remaining <= warning_days:
            rule = policy['exceptions'][finding]
            warnings.append({'id': finding, 'package': rule['package'],
                             'version': rule['version'], 'deadline': deadline.isoformat(),
                             'days_remaining': remaining})
    return warnings


def assess(report, scout, evidence, policy, arch, today=None):
    today = today or current_day()
    deadlines = exception_deadlines(policy)
    if policy['base'] != BASE.split('@')[1] or arch not in DIRECT:
        raise ValueError('Unreviewed base or architecture')
    if evidence != {'success': True, 'tests': 9, 'failures': 0, 'errors': 0,
                    'skipped': 0, 'arch': arch,
                    'patch_manifest_sha256': policy['reviewed_sources']['scripts/python_security_patches.json']}:
        raise ValueError('Missing or unsuccessful security regression evidence')
    if (not isinstance(report, dict) or not isinstance(report.get('matches'), list)
            or report.get('ignoredMatches', []) != []
            or not isinstance(scout, dict) or not isinstance(scout.get('runs'), list) or not scout['runs']):
        raise ValueError('Incomplete scan report')
    for run in scout['runs']:
        if (not isinstance(run, dict) or not isinstance(run.get('results'), list)
                or not isinstance(run.get('invocations', []), list)
                or any(not isinstance(invocation, dict) or invocation.get('executionSuccessful') is False
                       for invocation in run.get('invocations', []))):
            raise ValueError('Incomplete Scout report')
    accepted, blocked = [], []
    for match in report['matches']:
        if not isinstance(match, dict):
            raise ValueError('Incomplete Grype finding')
        vulnerability, package = match.get('vulnerability'), match.get('artifact')
        if (not isinstance(vulnerability, dict) or not isinstance(package, dict)
                or any(not isinstance(vulnerability.get(key), str) or not vulnerability[key]
                       for key in ('id', 'severity'))
                or any(not isinstance(package.get(key), str) or not package[key]
                       for key in ('type', 'name', 'version'))):
            raise ValueError('Incomplete Grype finding')
        finding = vulnerability['id']
        rule = policy['exceptions'].get(finding)
        valid = bool(rule and package['type'] == rule['type']
                     and package['name'] == rule['package']
                     and package['version'] == rule['version']
                     and vulnerability['severity'] == rule['severity'])
        entry = {'id': finding, 'package': package['name'], 'version': package['version']}
        if not valid:
            entry['reason'] = 'exception_mismatch' if rule else 'unmatched_finding'
            blocked.append(entry)
        else:
            entry['deadline'] = deadlines[finding].isoformat()
            if today > deadlines[finding]:
                entry['reason'] = 'exception_expired'
                blocked.append(entry)
            else:
                accepted.append(entry)
    return {'accepted_fixed': accepted, 'blocked': blocked,
            'scout_blocked': [r for run in scout['runs'] for r in run['results']],
            'raw_matches': len(report['matches']), 'review_date': today.isoformat()}


def reviewed_policy(root=Path('.')):
    policy = json.loads((root / 'docs/image-exceptions.json').read_text())
    exception_deadlines(policy)
    for name, digest in policy['reviewed_sources'].items():
        if hashlib.sha256((root / name).read_bytes()).hexdigest() != digest:
            raise ValueError(f'{name} changed; verified-fixed review must be refreshed')
    return policy


def review_reports(arch, report, scout, evidence, provenance, root=Path('.'), today=None):
    """Reassess original report objects without modifying retained evidence."""
    policy = reviewed_policy(root)
    if arch not in DIRECT:
        raise ValueError('Unreviewed architecture')
    if (not isinstance(provenance, dict)
            or provenance.get('predicateType') != 'https://slsa.dev/provenance/v1'
            or not isinstance(provenance.get('subject'), list)
            or not any(isinstance(subject, dict) and isinstance(subject.get('digest'), dict)
                       and subject['digest'].get('sha256') == DIRECT[arch][0]
                       for subject in provenance['subject'])):
        raise ValueError('Base provenance does not cover the reviewed native image')
    return assess(report, scout, evidence, policy, arch, today)


def review_candidate(arch, root=Path('.'), today=None):
    return review_reports(
        arch,
        json.loads((root / f'candidate-{arch}.json').read_text()),
        json.loads((root / f'candidate-scout-{arch}.json').read_text()),
        json.loads((root / f'candidate-regression-{arch}.json').read_text()),
        json.loads((root / f'candidate-provenance-{arch}.json').read_text()),
        root, today,
    )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('arch', nargs='?', choices=tuple(DIRECT))
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--check-only', action='store_true', help='Revalidate without writing any evidence files')
    mode.add_argument('--check-deadlines', action='store_true', help='Warn about reviews due soon; expiry alone never fails this check')
    parser.add_argument('--warning-days', type=int, default=14)
    args = parser.parse_args(argv)
    if (args.check_deadlines and args.arch) or (not args.check_deadlines and not args.arch):
        parser.error('Specify an architecture for image review, or --check-deadlines alone')
    try:
        if args.check_deadlines:
            policy = json.loads(Path('docs/image-exceptions.json').read_text())
            warnings = deadline_warnings(policy, warning_days=args.warning_days)
            messages = []
            for warning in warnings:
                message = (f"{warning['id']} ({warning['package']} {warning['version']}): "
                           f"review deadline {warning['deadline']} ({warning['days_remaining']} days remaining). "
                           'A finding needing this exception after the deadline blocks release. '
                           'Unused exceptions do not block a clean scan.')
                messages.append(message)
                escaped = message.replace('%', '%25').replace('\r', '%0D').replace('\n', '%0A')
                print('::warning::' + escaped)
            summary = '\n'.join('- ' + message for message in messages) or 'No image exception reviews are due within the warning window.'
            if os.environ.get('GITHUB_STEP_SUMMARY'):
                with Path(os.environ['GITHUB_STEP_SUMMARY']).open('a') as output:
                    output.write('### Image exception review deadlines\n\n' + summary + '\n')
            print(f'{len(warnings)} image exception reviews due within {args.warning_days} days or overdue. Deadlines unchanged.')
            return 0
        result = review_candidate(args.arch)
        if not args.check_only:
            Path(f'candidate-review-{args.arch}.json').write_text(json.dumps(result, indent=2) + '\n')
        print(f"Accepted {len(result['accepted_fixed'])} verified-fixed matches; blocked {len(result['blocked'])} Grype and {len(result['scout_blocked'])} Scout findings. Raw reports retained.")
        for entry in result['blocked']:
            print(f"{entry['id']} ({entry['package']} {entry['version']}): {entry['reason']}" +
                  (f"; review deadline {entry['deadline']}" if 'deadline' in entry else ''))
        return int(bool(result['blocked'] or result['scout_blocked']))
    except (ValueError, KeyError, OSError) as error:
        print(str(error))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
