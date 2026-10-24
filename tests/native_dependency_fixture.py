"""Native dependency report fixtures bound to reviewed replacement output pins."""
import hashlib
import json
from pathlib import Path

from scripts.alpine_expat_sources import build_security_manifest
from scripts.build_patched_expat import expected_manifest, json_bytes
from scripts.dhi_python_packages import build_security_manifest as python_security_manifest
from scripts.alpine_musl_sources import build_security_manifest as musl_security_manifest
from scripts.expat_security_checks import expected_report as expat_probe_report
from scripts.runtime_dependency_checks import MUSL_PROBES
from tests.certificate_trust_fixture import trust_report


ROOT = Path(__file__).resolve().parents[1]


def dependency_report(arch, *, root=ROOT):
    manifest = build_security_manifest(arch, root=None)
    replacement = expected_manifest(arch, root=root)
    python = python_security_manifest(arch, root=None)
    musl = musl_security_manifest(arch, root=None)
    return {
        'schema': 5, 'arch': arch, 'success': True, 'tests': 4,
        'failures': 0, 'errors': [],
        'versions': {'expat': '2.9.0', 'openssl': '3.5.9', 'python': '3.14.8', 'musl': '1.2.6-r3'},
        'loaded_libraries': {
            name: {'path': path, 'sha256': digest, 'device': '0:1', 'inode': inode}
            for name, path, digest, inode in (
                ('expat', '/usr/lib/libexpat.so.1.13.0', replacement['library']['sha256'], 101),
                ('ssl', '/usr/lib/libssl.so.3', 'e' * 64, 102),
                ('crypto', '/usr/lib/libcrypto.so.3', 'f' * 64, 103),
                ('python', python['library']['path'], python['library']['sha256'], 104),
                ('python_ssl', python['ssl_extension']['path'], python['ssl_extension']['sha256'], 105),
                ('musl', musl['library']['path'], musl['library']['sha256'], 108),
            )
        },
        'expat_source_manifest_sha256': manifest['source_manifest_sha256'],
        'expat_install_manifest_sha256': hashlib.sha256(
            (json.dumps(manifest, sort_keys=True, indent=2) + '\n').encode()).hexdigest(),
        'expat_build_manifest': replacement,
        'expat_build_manifest_sha256': hashlib.sha256(json_bytes(replacement)).hexdigest(),
        'expat_security_probes': expat_probe_report(),
        'python_source_manifest_sha256': python['source_manifest_sha256'],
        'python_install_manifest_sha256': hashlib.sha256(
            (json.dumps(python, sort_keys=True, indent=2) + '\n').encode()).hexdigest(),
        'python_files': {
            name: {'path': python[name]['path'], 'sha256': python[name]['sha256'],
                   'device': '0:1', 'inode': inode}
            for name, inode in (('executable', 106), ('abi_library', 107))
        },
        'python_aliases': python['aliases'],
        'python_tls_probes': {'wrap_bio_requires_hostname': True,
                              'sni_context_switch_handshake': True,
                              'tls_memory_bio_handshake': True},
        'musl_source_manifest_sha256': musl['source_manifest_sha256'],
        'musl_install_manifest_sha256': hashlib.sha256(
            (json.dumps(musl, sort_keys=True, indent=2) + '\n').encode()).hexdigest(),
        'musl_aliases': musl['aliases'], 'musl_probes': dict(MUSL_PROBES),
        'certificate_trust': trust_report(arch),
    }


def certificate_failure_reports(arch, *, root=ROOT):
    """Keep other native evidence valid while changing one trust obligation."""
    excluded_root = '86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b'
    for failure in ('missing_proof', 'certifi_hash', 'system_hash', 'failed_tls', 'ca_environment', 'excluded_capath_root'):
        report = dependency_report(arch, root=root)
        if failure == 'missing_proof':
            report['certificate_trust'] = None
            message = 'Invalid certificate trust report schema'
        elif failure.endswith('_hash'):
            report['certificate_trust'][failure.removesuffix('_hash')]['sha256'] = '0' * 64
            message = 'Certificate bundle differs'
        elif failure == 'failed_tls':
            report['certificate_trust']['tls_probes']['smtp_hostname_rejection'] = False
            message = 'Missing or failed certificate TLS probes'
        elif failure == 'ca_environment':
            report['certificate_trust']['ca_environment']['SSL_CERT_FILE'] = '/tmp/unreviewed.pem'
            message = 'CA environment overrides'
        else:
            report['certificate_trust']['capath'].update(
                entries=1, certificates=1, fingerprints=[excluded_root],
                fingerprints_sha256=hashlib.sha256((excluded_root + '\n').encode()).hexdigest())
            message = 'Unreviewed or invalid OpenSSL hashed certificate inventory'
        yield failure, report, message


def musl_failure_reports(arch, *, root=ROOT):
    """Keep other evidence valid while breaking one fixed-libc obligation."""
    for failure in ('source_proof', 'install_proof', 'loader_hash', 'libc_alias',
                    'package_version', 'regex_probe', 'missing_libc'):
        report = dependency_report(arch, root=root)
        if failure in ('source_proof', 'install_proof'):
            name = 'source' if failure == 'source_proof' else 'install'
            report['musl_' + name + '_manifest_sha256'] = None
            message = 'musl source or install manifest differs'
        elif failure == 'loader_hash':
            report['loaded_libraries']['musl']['sha256'] = '0' * 64
            message = 'musl loaded-library hash differs'
        elif failure == 'libc_alias':
            report['musl_aliases'] = {}
            message = 'musl aliases differ'
        elif failure == 'package_version':
            report['versions']['musl'] = '1.2.6-r2'
            message = 'Dependency report versions differ'
        elif failure == 'regex_probe':
            report['musl_probes']['regex_length_limit'] = False
            message = 'Missing or failed musl qualification probes'
        else:
            del report['loaded_libraries']['musl']
            message = 'Incomplete dependency loaded-library evidence'
        yield failure, report, message
