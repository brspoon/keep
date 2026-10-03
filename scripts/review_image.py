"""Accept only owner-approved, verified-fixed runtime findings; fail all others."""
import datetime
import hashlib
import json
from pathlib import Path
import sys
from inspect_candidate import BASE, DIRECT


def assess(report, scout, evidence, policy, arch, today=None):
    today = today or datetime.date.today()
    if today > datetime.date.fromisoformat(policy['expires']):
        raise ValueError('Verified-fixed review expired')
    if policy['base'] != BASE.split('@')[1] or arch not in DIRECT:
        raise ValueError('Unreviewed base or architecture')
    if evidence != {'success': True, 'tests': 9, 'failures': 0, 'errors': 0,
                    'skipped': 0, 'arch': arch,
                    'patch_manifest_sha256': policy['reviewed_sources']['scripts/python_security_patches.json']}:
        raise ValueError('Missing or unsuccessful security regression evidence')
    if not isinstance(report['matches'], list) or not scout['runs']:
        raise ValueError('Incomplete scan report')
    if any(not isinstance(r.get('results'), list) for r in scout['runs']):
        raise ValueError('Incomplete Scout report')
    accepted, blocked = [], []
    for match in report['matches']:
        vulnerability, package = match['vulnerability'], match['artifact']
        rule = policy['exceptions'].get(vulnerability['id'])
        valid = bool(rule and package['type'] == rule['type']
                     and package['name'] == rule['package']
                     and package['version'] == rule['version']
                     and vulnerability['severity'] == rule['severity'])
        entry = {'id': vulnerability['id'], 'package': package['name'], 'version': package['version']}
        (accepted if valid else blocked).append(entry)
    return {'accepted_fixed': accepted, 'blocked': blocked,
            'scout_blocked': [r for run in scout['runs'] for r in run['results']],
            'raw_matches': len(report['matches']), 'expires': policy['expires']}


if __name__ == '__main__':
    arch = sys.argv[1]
    policy = json.loads(Path('docs/image-exceptions.json').read_text())
    for name, digest in policy['reviewed_sources'].items():
        if hashlib.sha256(Path(name).read_bytes()).hexdigest() != digest:
            raise ValueError(f'{name} changed; verified-fixed review must be refreshed')
    provenance = json.loads(Path(f'candidate-provenance-{arch}.json').read_text())
    if provenance.get('predicateType') != 'https://slsa.dev/provenance/v1' or not any(s.get('digest', {}).get('sha256') == DIRECT[arch][0] for s in provenance.get('subject', [])):
        raise ValueError('Base provenance does not cover the reviewed native image')
    result = assess(json.loads(Path(f'candidate-{arch}.json').read_text()),
                    json.loads(Path(f'candidate-scout-{arch}.json').read_text()),
                    json.loads(Path(f'candidate-regression-{arch}.json').read_text()), policy, arch)
    Path(f'candidate-review-{arch}.json').write_text(json.dumps(result, indent=2) + '\n')
    print(f"Accepted {len(result['accepted_fixed'])} verified-fixed matches; blocked {len(result['blocked'])} Grype and {len(result['scout_blocked'])} Scout findings. Raw reports retained.")
    raise SystemExit(bool(result['blocked'] or result['scout_blocked']))
