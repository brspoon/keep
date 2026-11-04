"""Exact, time-limited Scout fixed-code and absent-code adjudication.

This never filters scanner output or changes hosted vulnerability counts.
"""
import datetime
from pathlib import Path
import re


FINDING_FIELDS = {'id', 'severity', 'purl', 'affected_version', 'fixed_version'}
SOURCE_BINDINGS = {'scripts/alpine_musl_sources.py', 'scripts/runtime_dependency_checks.py'}
COMPONENT_SOURCE_BINDINGS = {
    'scripts/image_distribution.py', 'scripts/runtime_dependency_checks.py',
    'scripts/build_patched_sqlite.py', 'scripts/sqlite_security_checks.py',
    'docs/sqlite-build.json', 'scripts/sqlite_security_patches.json',
}
SQLITE_SHELL_FINDING = 'CVE-2026-119586'


def component_deadlines(policy):
    """Validate optional, explicitly approved absent-code reviews; default deny."""
    rules = policy.get('scout_component_reviews', {})
    if not isinstance(rules, dict):
        raise ValueError('Invalid Scout component-review policy')
    fields = {'status', 'justification', 'component', 'severity', 'type', 'package',
              'version', 'distribution', 'distribution_version', 'purl',
              'affected_version', 'fixed_version', 'evidence', 'source_bindings', 'review'}
    deadlines = {}
    for finding, rule in rules.items():
        if (finding != SQLITE_SHELL_FINDING or not isinstance(rule, dict) or set(rule) != fields
                or rule['status'] != 'not_affected'
                or rule['justification'] != 'vulnerable_code_not_present'
                or rule['component'] != 'sqlite-command-line-shell'):
            raise ValueError('Only an exact SQLite shell absent-code review is supported')
        expected = {'type': 'apk', 'package': 'sqlite', 'version': '3.53.4-r0',
                    'distribution': 'alpine', 'distribution_version': '3.24', 'severity': 'HIGH'}
        if any(rule.get(key) != value for key, value in expected.items()):
            raise ValueError('SQLite component review differs from the verified vendor identity')
        purl = 'pkg:apk/alpine/sqlite@3.53.4-r0?os_name=alpine&os_version=3.24'
        if (rule['purl'] != purl or any(not isinstance(rule[key], str) or not rule[key].strip()
                for key in ('affected_version', 'fixed_version', 'evidence'))):
            raise ValueError('SQLite component-review finding identity is incomplete')
        bindings = rule['source_bindings']
        if (not isinstance(bindings, dict) or set(bindings) != COMPONENT_SOURCE_BINDINGS
                or any(not isinstance(digest, str) or not re.fullmatch(r'[0-9a-f]{64}', digest)
                       or policy.get('reviewed_sources', {}).get(name) != digest
                       for name, digest in bindings.items())):
            raise ValueError('SQLite component source bindings differ from reviewed sources')
        review = rule['review']
        if (not isinstance(review, dict)
                or set(review) != {'reviewed_on', 'deadline', 'approval', 'remove_when'}
                or any(not isinstance(value, str) or not value.strip() for value in review.values())):
            raise ValueError('SQLite component review requires explicit approval and dates')
        try:
            start = datetime.date.fromisoformat(review['reviewed_on'])
            deadline = datetime.date.fromisoformat(review['deadline'])
        except ValueError as error:
            raise ValueError('Invalid SQLite component-review date') from error
        if (start.isoformat() != review['reviewed_on'] or deadline.isoformat() != review['deadline']
                or deadline < start):
            raise ValueError('Invalid SQLite component-review date range')
        deadlines[finding] = deadline
    return deadlines


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
    components = component_deadlines(policy)
    if set(deadlines) & set(components):
        raise ValueError('A Scout finding has conflicting review classifications')
    return {**deadlines, **components}


def finding_decision(finding, policy, today, *, inventory=None, layers=None,
                     arch=None, root=Path('.'), image_config_sha256=None):
    """Return a blocking reason, or None for an exact unexpired approval."""
    deadlines = scout_deadlines(policy)
    if (not isinstance(finding, dict) or set(finding) != FINDING_FIELDS
            or any(not isinstance(value, str) or not value for value in finding.values())):
        return 'incomplete_scout_finding'
    rule = policy.get('scout_exceptions', {}).get(finding['id'])
    component = policy.get('scout_component_reviews', {}).get(finding['id'])
    if component is not None:
        rule = component
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
    if component is not None:
        if today < datetime.date.fromisoformat(rule['review']['reviewed_on']):
            return 'component_review_not_started'
        if (inventory is None or layers is None or arch not in ('amd64', 'arm64')
                or not isinstance(image_config_sha256, str)
                or not re.fullmatch(r'[0-9a-f]{64}', image_config_sha256)):
            return 'missing_component_proof'
        try:
            from image_distribution import validate_sqlite_cli_review
            proof = validate_sqlite_cli_review(inventory, layers, arch, root=root,
                                               image_config_sha256=image_config_sha256)
            if (not isinstance(proof, dict) or proof.get('architecture') != arch
                    or proof.get('justification') != 'vulnerable_code_not_present'):
                return 'invalid_component_proof'
        except (ValueError, TypeError, KeyError, OSError, ImportError):
            return 'invalid_component_proof'
    return None


def canonical_scout_finding(run, result):
    """Read structured SARIF identity; never infer identity from message text."""
    if (not isinstance(run, dict) or not isinstance(result, dict) or result.get('kind') != 'fail'
            or result.get('suppressions', []) != []
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
    rule_id = result.get('ruleId')
    if (not isinstance(rule_id, str) or not rule_id
            or not isinstance(rule, dict) or rule.get('id') != rule_id):
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
    # These are the observed Scout pairs needed by the two supported scopes.
    # Unknown severity/level combinations remain blocking, including low/medium.
    levels = {'UNSPECIFIED': 'none', 'HIGH': 'error'}
    if finding['severity'] not in levels or result.get('level') != levels[finding['severity']]:
        return None
    return finding
