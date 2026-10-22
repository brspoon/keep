"""Original native dependency report fixtures for archive revalidation tests."""
import hashlib
import json

from scripts.alpine_expat_sources import build_security_manifest
from scripts.dhi_python_packages import build_security_manifest as python_security_manifest
from scripts.runtime_dependency_checks import EXPAT_LIBRARY_SHA256
from tests.certificate_trust_fixture import trust_report


def dependency_report(arch):
    manifest = build_security_manifest(arch, root=None)
    python = python_security_manifest(arch, root=None)
    return {
        'schema': 3, 'arch': arch, 'success': True, 'tests': 3,
        'failures': 0, 'errors': [],
        'versions': {'expat': '2.9.0', 'openssl': '3.5.9', 'python': '3.14.8'},
        'loaded_libraries': {
            name: {'path': path, 'sha256': digest, 'device': '0:1', 'inode': inode}
            for name, path, digest, inode in (
                ('expat', '/usr/lib/libexpat.so.1.13.0', EXPAT_LIBRARY_SHA256[arch], 101),
                ('ssl', '/usr/lib/libssl.so.3', 'e' * 64, 102),
                ('crypto', '/usr/lib/libcrypto.so.3', 'f' * 64, 103),
                ('python', python['library']['path'], python['library']['sha256'], 104),
                ('python_ssl', python['ssl_extension']['path'], python['ssl_extension']['sha256'], 105),
            )
        },
        'expat_source_manifest_sha256': manifest['source_manifest_sha256'],
        'expat_install_manifest_sha256': hashlib.sha256(
            (json.dumps(manifest, sort_keys=True, indent=2) + '\n').encode()).hexdigest(),
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
        'certificate_trust': trust_report(arch),
    }


def certificate_failure_reports(arch):
    """Keep other native evidence valid while changing one trust obligation."""
    excluded_root = '86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b'
    for failure in ('missing_proof', 'certifi_hash', 'system_hash', 'failed_tls', 'excluded_capath_root'):
        report = dependency_report(arch)
        if failure == 'missing_proof':
            report['certificate_trust'] = None
            message = 'Invalid certificate trust report schema'
        elif failure.endswith('_hash'):
            report['certificate_trust'][failure.removesuffix('_hash')]['sha256'] = '0' * 64
            message = 'Certificate bundle differs'
        elif failure == 'failed_tls':
            report['certificate_trust']['tls_probes']['smtp_hostname_rejection'] = False
            message = 'Missing or failed certificate TLS probes'
        else:
            report['certificate_trust']['capath'].update(
                entries=1, certificates=1, fingerprints=[excluded_root],
                fingerprints_sha256=hashlib.sha256((excluded_root + '\n').encode()).hexdigest())
            message = 'Unreviewed or invalid OpenSSL hashed certificate inventory'
        yield failure, report, message
