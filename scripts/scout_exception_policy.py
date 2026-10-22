"""Exact, time-limited adjudication of reviewed Scout false positives.

This never filters scanner output or changes hosted vulnerability counts.
"""
import datetime
import re


FINDING_FIELDS = {'id', 'severity', 'purl', 'affected_version', 'fixed_version'}
SOURCE_BINDINGS = {'scripts/alpine_musl_sources.py', 'scripts/runtime_dependency_checks.py'}


def scout_deadlines(policy):
    rules = policy.get('scout_exceptions', {})
    if not isinstance(rules, dict):
        raise ValueError('Invalid Scout exception policy')
    deadlines = {}
    for finding, rule in rules.items():
        if not isinstance(rule, dict) or rule.get('status') != 'fixed_false_positive':
            raise ValueError(f'{finding}: only verified-fixed Scout false positives are permitted')
        for field in ('severity', 'type', 'package', 'version', 'distribution',
                      'distribution_version', 'purl', 'affected_version', 'fixed_version', 'evidence'):
            if not isinstance(rule.get(field), str) or not rule[field].strip():
                raise ValueError(f'{finding}: missing Scout exception {field}')
        purl = (f"pkg:{rule['type']}/{rule['distribution']}/{rule['package']}@{rule['version']}"
                f"?os_name={rule['distribution']}&os_version={rule['distribution_version']}")
        if rule['purl'] != purl or rule['severity'] not in {'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNSPECIFIED'}:
            raise ValueError(f'{finding}: invalid Scout package or severity binding')
        bindings = rule.get('source_bindings')
        if (not isinstance(bindings, dict) or set(bindings) != SOURCE_BINDINGS
                or any(not isinstance(digest, str) or not re.fullmatch(r'[0-9a-f]{64}', digest)
                       or policy.get('reviewed_sources', {}).get(name) != digest
                       for name, digest in bindings.items())):
            raise ValueError(f'{finding}: Scout source bindings differ from reviewed sources')
        review = rule.get('review')
        if not isinstance(review, dict) or any(not isinstance(review.get(field), str)
                                              or not review[field].strip()
                                              for field in ('deadline', 'approval', 'remove_when')):
            raise ValueError(f'{finding}: missing Scout review metadata')
        try:
            deadline = datetime.date.fromisoformat(review['deadline'])
        except ValueError as error:
            raise ValueError(f'{finding}: invalid Scout review deadline') from error
        if deadline.isoformat() != review['deadline']:
            raise ValueError(f'{finding}: Scout deadline must use YYYY-MM-DD')
        deadlines[finding] = deadline
    return deadlines


def finding_decision(finding, policy, today):
    """Return a blocking reason, or None for an exact unexpired approval."""
    deadlines = scout_deadlines(policy)
    if (not isinstance(finding, dict) or set(finding) != FINDING_FIELDS
            or any(not isinstance(value, str) or not value for value in finding.values())):
        return 'incomplete_scout_finding'
    rule = policy.get('scout_exceptions', {}).get(finding['id'])
    if not rule:
        return 'unmatched_finding'
    expected = {key: rule[key] for key in FINDING_FIELDS - {'id'}}
    expected['id'] = finding['id']
    if finding != expected:
        return 'exception_mismatch'
    if policy.get('require_zero_findings', False):
        return 'finding_not_permitted'
    if today > deadlines[finding['id']]:
        return 'exception_expired'
    return None


def canonical_scout_finding(run, result):
    """Read structured SARIF identity; never infer identity from message text."""
    if (not isinstance(result, dict) or result.get('kind') != 'fail'
            or result.get('level') != 'none' or result.get('suppressions', []) != []
            or result.get('baselineState') == 'absent'):
        return None
    tool = run.get('tool')
    if not isinstance(tool, dict) or not isinstance(tool.get('driver'), dict):
        return None
    rules = tool['driver'].get('rules', [])
    index = result.get('ruleIndex')
    if type(index) is not int or not isinstance(rules, list) or not 0 <= index < len(rules):
        return None
    rule = rules[index]
    if not isinstance(rule, dict) or rule.get('id') != result.get('ruleId'):
        return None
    properties = rule.get('properties', {})
    if not isinstance(properties, dict):
        return None
    purls = properties.get('purls')
    if not isinstance(purls, list) or len(purls) != 1:
        return None
    finding = {'id': result['ruleId'], 'severity': properties.get('cvssV3_severity'),
               'purl': purls[0], 'affected_version': properties.get('affected_version'),
               'fixed_version': properties.get('fixed_version')}
    if any(not isinstance(value, str) or not value for value in finding.values()):
        return None
    return finding
