"""Explicit historical approvals for deadline and immutable-evidence tests.

These synthetic policies keep their original review dates when the active policy
changes. Current base/source bindings are used so integrity checks still exercise
the actual checked-in inputs; this fixture never authorizes an image.
"""
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HISTORICAL_FINDINGS = ('CVE-2026-87910', 'CVE-2025-15367', 'CVE-2026-12345')
RENEWED_FINDINGS = ('CVE-2025-15367', 'CVE-2026-12345')


def historical_review_policy():
    inputs = json.loads((ROOT / 'docs/image-exceptions.json').read_text())
    return {
        'base': inputs['base'],
        'reviewed_sources': inputs['reviewed_sources'],
        'approval': 'Synthetic historical verified-fixed review through October 20 UTC.',
        'require_zero_findings': False,
        'exceptions': {
            finding: {
                'severity': 'Medium', 'type': 'apk', 'package': 'python-3.14',
                'version': '3.14.8-r0', 'status': 'fixed',
                'evidence': 'Synthetic complete native verified-fixed evidence.',
                'review': {
                    'approval': 'Synthetic October 7 verified-fixed approval.',
                    'reviewed_on': '2026-10-07', 'deadline': '2026-10-20',
                    'remove_when': 'Verified fixes, both native probes and clean unsuppressed scans.',
                },
            } for finding in HISTORICAL_FINDINGS
        },
    }


def renewed_review_policy():
    policy = historical_review_policy()
    policy['approval'] = 'Synthetic fresh verified-fixed review through November 1 UTC.'
    policy['exceptions'].pop('CVE-2026-87910')
    for rule in policy['exceptions'].values():
        rule['review'].update(
            approval='Synthetic October 18 verified-fixed renewal.',
            reviewed_on='2026-10-18', deadline='2026-11-01',
        )
    return policy
