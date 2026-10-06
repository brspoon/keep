"""Original native dependency report fixtures for archive revalidation tests."""
import hashlib
import json

from alpine_expat_sources import build_security_manifest
from runtime_dependency_checks import EXPAT_LIBRARY_SHA256


def dependency_report(arch):
    manifest = build_security_manifest(arch, root=None)
    return {
        'schema': 1, 'arch': arch, 'success': True, 'tests': 2,
        'failures': 0, 'errors': [],
        'versions': {'expat': '2.9.0', 'openssl': '3.5.9'},
        'loaded_libraries': {
            name: {'path': path, 'sha256': digest, 'device': '0:1', 'inode': inode}
            for name, path, digest, inode in (
                ('expat', '/usr/lib/libexpat.so.1.13.0', EXPAT_LIBRARY_SHA256[arch], 101),
                ('ssl', '/usr/lib/libssl.so.3', 'e' * 64, 102),
                ('crypto', '/usr/lib/libcrypto.so.3', 'f' * 64, 103),
            )
        },
        'expat_source_manifest_sha256': manifest['source_manifest_sha256'],
        'expat_install_manifest_sha256': hashlib.sha256(
            (json.dumps(manifest, sort_keys=True, indent=2) + '\n').encode()).hexdigest(),
    }
