"""Enforce reviewed image security checks and the finding acceptance policy."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
from inspect_candidate import BASE, DIRECT
from scout_exception_policy import canonical_scout_finding, finding_decision, scout_deadlines


GRYPE_SQLITE_SHELL_FINDING = 'CVE-2026-119586'
GRYPE_COMPONENT_SOURCE_BINDINGS = {
    'scripts/review_image.py', 'scripts/image_distribution.py',
    'scripts/collect_package_sources.py', 'scripts/build_patched_sqlite.py',
    'scripts/sqlite_security_checks.py', 'scripts/sqlite_security_patches.json',
    'docs/sqlite-build.json', 'docs/os-package-sources.json',
}
GRYPE_SQLITE_SHELL_CPE = 'cpe:2.3:a:sqlite:sqlite:3.54.1:*:*:*:*:*:*:*'
GRYPE_SQLITE_SHELL_CPE_WILDCARD = 'cpe:2.3:a:sqlite:sqlite:*:*:*:*:*:*:*:*'
GRYPE_SQLITE_SHELL_PURL = {
    'amd64': 'pkg:apk/alpine/sqlite-libs@3.54.1-r0?arch=x86_64&distro=alpine-3.24&upstream=sqlite',
    'arm64': 'pkg:apk/alpine/sqlite-libs@3.54.1-r0?arch=aarch64&distro=alpine-3.24&upstream=sqlite',
}


def current_day():
    return datetime.datetime.now(datetime.timezone.utc).date()


def image_config_sha256(report, arch):
    """Read the original Grype image-config identity; never infer it from layers."""
    source = report.get('source') if isinstance(report, dict) else None
    target = source.get('target') if isinstance(source, dict) else None
    if (not isinstance(target, dict) or source.get('type') != 'image'
            or target.get('os') != 'linux' or target.get('architecture') != arch):
        return None
    identity = target.get('imageID')
    if not isinstance(identity, str) or not re.fullmatch(r'sha256:[0-9a-f]{64}', identity):
        return None
    return identity.removeprefix('sha256:')


def verify_image_binding(report, layers, arch, expected_image_config):
    """Bind both original reports to an independently supplied image config."""
    if (arch not in DIRECT or not isinstance(expected_image_config, str)
            or not re.fullmatch(r'sha256:[0-9a-f]{64}', expected_image_config)):
        raise ValueError('An exact expected image-config identity is required')
    expected = expected_image_config.removeprefix('sha256:')
    if (image_config_sha256(report, arch) != expected or not isinstance(layers, dict)
            or layers.get('architecture') != arch or layers.get('config_sha256') != expected):
        raise ValueError('Original Grype and layer reports differ from the expected image config')
    return expected


def exception_deadlines(policy):
    if (not isinstance(policy, dict)
            or not isinstance(policy.get('base'), str)
            or not re.fullmatch(r'sha256:[0-9a-f]{64}', policy['base'])
            or not isinstance(policy.get('approval'), str) or not policy['approval'].strip()):
        raise ValueError('Missing or invalid reviewed base/approval')
    if type(policy.get('require_zero_findings', False)) is not bool:
        raise ValueError('require_zero_findings must be a boolean')
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
    scout_deadlines(policy)
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
    component_deadlines = grype_component_deadlines(policy)
    if set(deadlines) & set(component_deadlines):
        raise ValueError('A Grype finding has conflicting review classifications')
    return deadlines


def grype_component_deadlines(policy):
    """Validate the one reviewed Grype package-to-absent-shell mismatch; default deny."""
    rules = policy.get('grype_component_reviews', {})
    if not isinstance(rules, dict):
        raise ValueError('Invalid Grype component-review policy')
    fields = {'status', 'justification', 'component', 'severity', 'type', 'package',
              'version', 'namespace', 'matcher', 'cpe', 'cpe_version_constraint',
              'purl_by_arch', 'evidence', 'source_bindings', 'review'}
    deadlines = {}
    for finding, rule in rules.items():
        if (finding != GRYPE_SQLITE_SHELL_FINDING or not isinstance(rule, dict)
                or set(rule) != fields or rule['status'] != 'not_affected'
                or rule['justification'] != 'vulnerable_code_not_present'
                or rule['component'] != 'sqlite-command-line-shell'):
            raise ValueError('Only the exact SQLite CLI absent-code Grype review is supported')
        expected = {'severity': 'High', 'type': 'apk', 'package': 'sqlite-libs',
                    'version': '3.54.1-r0', 'namespace': 'nvd:cpe',
                    'matcher': 'apk-matcher', 'cpe': GRYPE_SQLITE_SHELL_CPE,
                    'cpe_version_constraint': '<= 3.54.1 (unknown)'}
        if any(rule.get(key) != value for key, value in expected.items()):
            raise ValueError('Grype SQLite component review differs from the exact observed match')
        if (rule.get('purl_by_arch') != GRYPE_SQLITE_SHELL_PURL
                or any(not isinstance(rule.get(key), str) or not rule[key].strip()
                       for key in ('evidence',))):
            raise ValueError('Grype SQLite component-review finding identity is incomplete')
        bindings = rule.get('source_bindings')
        if (not isinstance(bindings, dict) or set(bindings) != GRYPE_COMPONENT_SOURCE_BINDINGS
                or any(not isinstance(digest, str) or not re.fullmatch(r'[0-9a-f]{64}', digest)
                       or policy.get('reviewed_sources', {}).get(name) != digest
                       for name, digest in bindings.items())):
            raise ValueError('Grype SQLite component source bindings differ from reviewed sources')
        review = rule.get('review')
        if (not isinstance(review, dict)
                or set(review) != {'reviewed_on', 'deadline', 'approval', 'remove_when'}
                or any(not isinstance(value, str) or not value.strip() for value in review.values())):
            raise ValueError('Grype SQLite component review requires explicit approval and dates')
        try:
            start = datetime.date.fromisoformat(review['reviewed_on'])
            deadline = datetime.date.fromisoformat(review['deadline'])
        except ValueError as error:
            raise ValueError('Invalid Grype SQLite component-review date') from error
        if (start.isoformat() != review['reviewed_on'] or deadline.isoformat() != review['deadline']
                or deadline < start):
            raise ValueError('Invalid Grype SQLite component-review date range')
        deadlines[finding] = deadline
    return deadlines


def grype_sqlite_shell_identity(match, arch, rule):
    """Check every stable scanner identity field for the exact CLI-only CPE match."""
    vulnerability = match.get('vulnerability')
    artifact = match.get('artifact')
    if not isinstance(vulnerability, dict) or not isinstance(artifact, dict):
        return False
    if any(vulnerability.get(key) != value for key, value in {
            'id': GRYPE_SQLITE_SHELL_FINDING, 'severity': rule['severity'],
            'namespace': rule['namespace'],
            'dataSource': 'https://nvd.nist.gov/vuln/detail/CVE-2026-119586'}.items()):
        return False
    if any(artifact.get(key) != value for key, value in {
            'type': rule['type'], 'name': rule['package'], 'version': rule['version'],
            'purl': rule['purl_by_arch'][arch], 'metadataType': 'ApkMetadata'}.items()):
        return False
    metadata = artifact.get('metadata')
    architecture = {'amd64': 'x86_64', 'arm64': 'aarch64'}[arch]
    if not isinstance(metadata, dict) or metadata.get('Arch') != architecture:
        return False
    locations = artifact.get('locations')
    if (not isinstance(locations, list) or len(locations) != 1
            or not isinstance(locations[0], dict)
            or locations[0].get('path') != '/lib/apk/db/installed'
            or locations[0].get('accessPath') != '/lib/apk/db/installed'
            or locations[0].get('annotations') != {'evidence': 'primary'}):
        return False
    details = match.get('matchDetails')
    if not isinstance(details, list) or len(details) != 1 or not isinstance(details[0], dict):
        return False
    detail = details[0]
    searched = detail.get('searchedBy')
    found = detail.get('found')
    return (match.get('relatedVulnerabilities') == []
            and detail.get('type') == 'cpe-match' and detail.get('matcher') == rule['matcher']
            and isinstance(searched, dict) and searched.get('namespace') == rule['namespace']
            and searched.get('cpes') == [rule['cpe']]
            and searched.get('package') == {'name': 'sqlite', 'version': '3.54.1-r0'}
            and isinstance(found, dict)
            and found.get('vulnerabilityID') == GRYPE_SQLITE_SHELL_FINDING
            and found.get('versionConstraint') == rule['cpe_version_constraint']
            and found.get('cpes') == [GRYPE_SQLITE_SHELL_CPE_WILDCARD])


def grype_component_decision(match, policy, today, *, inventory, layers, arch, root,
                             image_config_sha256, deadlines):
    """Return a blocking reason unless exact scanner identity and proof both pass."""
    vulnerability = match.get('vulnerability') if isinstance(match, dict) else None
    finding = vulnerability.get('id') if isinstance(vulnerability, dict) else None
    rule = policy.get('grype_component_reviews', {}).get(finding)
    if rule is None:
        return None
    if not grype_sqlite_shell_identity(match, arch, rule):
        return 'component_review_mismatch'
    if policy.get('require_zero_findings', False):
        return 'finding_not_permitted'
    if today < datetime.date.fromisoformat(rule['review']['reviewed_on']):
        return 'component_review_not_started'
    if today > deadlines[finding]:
        return 'exception_expired'
    if (not isinstance(image_config_sha256, str)
            or not re.fullmatch(r'[0-9a-f]{64}', image_config_sha256)
            or inventory is None or layers is None or arch not in DIRECT):
        return 'missing_component_proof'
    try:
        from image_distribution import validate_sqlite_cli_review
        proof = validate_sqlite_cli_review(inventory, layers, arch, root=root,
                                           image_config_sha256=image_config_sha256)
        if (not isinstance(proof, dict) or proof.get('architecture') != arch
                or proof.get('justification') != rule['justification']):
            return 'invalid_component_proof'
    except (ValueError, TypeError, KeyError, OSError, ImportError):
        return 'invalid_component_proof'
    return None


def deadline_warnings(policy, today=None, warning_days=14):
    """Report upcoming and overdue reviews without accepting any findings."""
    if warning_days < 0:
        raise ValueError('Warning days must be nonnegative')
    today = today or current_day()
    warnings = []
    exception_deadlines(policy)
    reviews = [(finding, rule, datetime.date.fromisoformat(rule['review']['deadline']))
               for section in ('exceptions', 'grype_component_reviews',
                               'scout_exceptions', 'scout_component_reviews')
               for finding, rule in policy.get(section, {}).items()]
    for finding, rule, deadline in sorted(reviews, key=lambda item: item[0]):
        remaining = (deadline - today).days
        if remaining <= warning_days:
            warnings.append({'id': finding, 'package': rule['package'],
                             'version': rule['version'], 'deadline': deadline.isoformat(),
                             'days_remaining': remaining})
    return warnings


def assess(report, scout, evidence, policy, arch, today=None, *, inventory=None,
           layers=None, root=Path('.'), expected_image_config=None):
    today = today or current_day()
    deadlines = exception_deadlines(policy)
    if policy['base'] != BASE.split('@')[1] or arch not in DIRECT:
        raise ValueError('Unreviewed base or architecture')
    image_config = (verify_image_binding(report, layers, arch, expected_image_config)
                    if expected_image_config is not None else None)
    if evidence != {'success': True, 'tests': 10, 'failures': 0, 'errors': 0,
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
    accepted, grype_not_affected, blocked = [], [], []
    seen_grype_components = set()
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
        component_rule = policy.get('grype_component_reviews', {}).get(finding)
        if component_rule is not None and rule is not None:
            raise ValueError('A Grype finding has conflicting review classifications')
        if component_rule is not None:
            if finding in seen_grype_components:
                reason = 'duplicate_component_finding'
            else:
                seen_grype_components.add(finding)
                reason = grype_component_decision(
                    match, policy, today, inventory=inventory, layers=layers, arch=arch, root=root,
                    image_config_sha256=image_config, deadlines=grype_component_deadlines(policy))
            entry = {'id': finding, 'package': package['name'], 'version': package['version']}
            if reason:
                entry['reason'] = reason
                blocked.append(entry)
            else:
                entry.update({'status': component_rule['status'],
                              'justification': component_rule['justification'],
                              'component': component_rule['component'],
                              'deadline': component_rule['review']['deadline']})
                grype_not_affected.append(entry)
            continue
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
            if policy.get('require_zero_findings', False):
                entry['reason'] = 'finding_not_permitted'
                blocked.append(entry)
            elif today > deadlines[finding]:
                entry['reason'] = 'exception_expired'
                blocked.append(entry)
            else:
                accepted.append(entry)
    scout_accepted, scout_not_affected, scout_blocked, seen = [], [], [], set()
    for run in scout['runs']:
        for result in run['results']:
            finding = canonical_scout_finding(run, result)
            identity = tuple(sorted(finding.items())) if finding else None
            reason = finding_decision(finding, policy, today, inventory=inventory,
                                      layers=layers, arch=arch, root=root,
                                      image_config_sha256=image_config)
            if reason or identity in seen:
                scout_blocked.append(result)
            else:
                seen.add(identity)
                component = policy.get('scout_component_reviews', {}).get(finding['id'])
                if component is None:
                    scout_accepted.append({**finding,
                        'deadline': policy['scout_exceptions'][finding['id']]['review']['deadline']})
                else:
                    scout_not_affected.append({**finding, 'status': component['status'],
                        'justification': component['justification'], 'component': component['component'],
                        'deadline': component['review']['deadline']})
    return {'accepted_fixed': accepted, 'grype_not_affected': grype_not_affected,
            'blocked': blocked,
            'scout_accepted_false_positive': scout_accepted,
            'scout_not_affected': scout_not_affected,
            'scout_blocked': scout_blocked,
            'raw_matches': len(report['matches']), 'review_date': today.isoformat()}


def reviewed_policy(root=Path('.')):
    policy = json.loads((root / 'docs/image-exceptions.json').read_text())
    exception_deadlines(policy)
    for name, digest in policy['reviewed_sources'].items():
        if hashlib.sha256((root / name).read_bytes()).hexdigest() != digest:
            raise ValueError(f'{name} changed; verified-fixed review must be refreshed')
    return policy


def review_reports(arch, report, scout, evidence, provenance, root=Path('.'), today=None,
                   *, dependencies=None, inventory=None, layers=None, expected_image_config=None):
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
    from runtime_dependency_checks import validate_report
    validate_report(dependencies, arch, root=root)
    return assess(report, scout, evidence, policy, arch, today,
                  inventory=inventory, layers=layers, root=root,
                  expected_image_config=expected_image_config)


def review_candidate(arch, root=Path('.'), today=None, *, expected_image_config=None):
    return review_reports(
        arch,
        json.loads((root / f'candidate-{arch}.json').read_text()),
        json.loads((root / f'candidate-scout-{arch}.json').read_text()),
        json.loads((root / f'candidate-regression-{arch}.json').read_text()),
        json.loads((root / f'candidate-provenance-{arch}.json').read_text()),
        root, today,
        dependencies=json.loads((root / f'candidate-dependencies-{arch}.json').read_bytes()),
        inventory=json.loads((root / f'candidate-notices-{arch}.json').read_bytes()),
        layers=json.loads((root / f'candidate-layers-{arch}.json').read_bytes()),
        expected_image_config=expected_image_config,
    )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('arch', nargs='?', choices=tuple(DIRECT))
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--check-only', action='store_true', help='Revalidate without writing any evidence files')
    mode.add_argument('--check-deadlines', action='store_true', help='Warn about reviews due soon; expiry alone never fails this check')
    parser.add_argument('--warning-days', type=int, default=14)
    parser.add_argument('--expected-image-config',
                        help='independently obtained sha256 image-config identity')
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
        result = review_candidate(args.arch, expected_image_config=args.expected_image_config)
        if not args.check_only:
            Path(f'candidate-review-{args.arch}.json').write_text(json.dumps(result, indent=2) + '\n')
        print(f"Accepted {len(result['accepted_fixed'])} verified-fixed Grype matches, {len(result['grype_not_affected'])} absent-code Grype findings, {len(result['scout_accepted_false_positive'])} reviewed Scout false positives and {len(result['scout_not_affected'])} absent-code Scout findings; blocked {len(result['blocked'])} Grype and {len(result['scout_blocked'])} Scout findings. Raw reports retained.")
        for entry in result['blocked']:
            print(f"{entry['id']} ({entry['package']} {entry['version']}): {entry['reason']}" +
                  (f"; review deadline {entry['deadline']}" if 'deadline' in entry else ''))
        return int(bool(result['blocked'] or result['scout_blocked']))
    except (ValueError, KeyError, OSError) as error:
        print(str(error))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
