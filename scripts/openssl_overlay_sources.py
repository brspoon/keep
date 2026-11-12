"""Retain independent OpenSSL replacement and build-only Perl source evidence."""
import hashlib
import json
from pathlib import Path
import tarfile

import build_patched_openssl as build
import openssl_build_tools as perl


def retain(stage, inventory, arch, *, root, fetch):
    from build_distribution_bundle import copy_file, file_records, write_json
    from collect_package_sources import verify_openssl_replacement, retain_expat_compiler_provenance
    from package_source_notices import _inspect_records, readable
    replacement = verify_openssl_replacement(inventory, arch, root=root)
    spec = build.reviewed_spec(root)
    output = Path(stage) / 'openssl-overlay'
    if output.exists() or output.is_symlink():
        raise ValueError('OpenSSL source output must be new')
    output.mkdir()
    source = output / 'preferred-source'
    build.replay_sources(source.resolve(), root=root, fetch=fetch)
    for name in ('scripts/build_patched_openssl.py', 'scripts/openssl_build_tools.py',
                 'scripts/openssl_overlay_sources.py', 'scripts/openssl_security_patches.json',
                 'docs/openssl-build.json', 'docs/openssl-build-tools.json'):
        copy_file(root, name, output / Path(name).name)
    write_json(output / 'OPENSSL_SECURITY.json', replacement['manifest'])
    compiler_source = Path(stage) / 'os-packages/expat/public-sources/compiler-provenance'
    compiler = retain_expat_compiler_provenance(compiler_source,
        output / 'compiler-provenance', arch, root=root)
    # The original archive and exact patched tree remain independently visible.
    # The archive supplies complete upstream license and attribution material.
    archive = source / (build.SOURCE_DIRECTORY + '.tar.gz')
    records = [{'path': archive.name, 'source_path': archive.name, 'type': 'file',
                'sha256': build.SOURCE_SHA256, 'bytes': archive.stat().st_size}]
    binding = {'origin': 'openssl-overlay', 'version': '3.5.9', 'architecture': arch,
                 'provider_oci_binding': False, 'source_image_digest': None,
                 'binding_method': 'Reviewed upstream source, exact backports and native replacement build',
                 'replacement_manifest_sha256': replacement['manifest_sha256']}
    report = _inspect_records(source, output / 'source-notices', origin='openssl-overlay',
        version='3.5.9', architecture=arch, manifest={'files': records}, binding=binding)
    if not report['success']:
        raise ValueError('OpenSSL replacement notices are incomplete')
    # Explicit full AUTHORS attribution, matching the original OpenSSL collector.
    authors = source / 'source' / build.SOURCE_DIRECTORY / 'AUTHORS.md'
    body = authors.read_bytes()
    if not readable(body):
        raise ValueError('OpenSSL attribution must be readable')
    checksum = hashlib.sha256(body).hexdigest()
    (output / 'AUTHORS.md').write_bytes(body)
    notice = output / 'source-notices/notices' / (checksum + '.txt')
    notice.parent.mkdir(parents=True, exist_ok=True); notice.write_bytes(body)
    report['notices'].append({'path': build.SOURCE_DIRECTORY + '/AUTHORS.md',
        'notice_file': 'notices/' + notice.name, 'sha256': checksum, 'bytes': len(body),
        'encoding': 'utf-8', 'discovery': 'checked-public-upstream-attribution',
        'provenance': {**binding, 'source_url': build.SOURCE_URL}})
    report['standalone_notice_count'] += 1
    write_json(output / 'source-notices/package-material-inventory.json', report)
    perl_output = output / 'build-only-perl'
    perl_spec = perl.prepare(perl_output, arch, root=root, fetch=fetch)
    perl_proof = perl.verify_sources(perl_output, perl_spec)
    # Keep the original signed control and signature proof, without a tool binary.
    parts = perl.python_packages.gzip_parts((perl_output / 'perl.apk').read_bytes())
    signing = perl_output / 'signature-proof'
    signing.mkdir()
    (signing / 'signature.tar.gz').write_bytes(parts[0][0])
    (signing / 'control.tar.gz').write_bytes(parts[1][0])
    write_json(signing / 'package-identity.json', perl_spec['binaries'][arch])
    (perl_output / 'perl.apk').unlink()
    perl_records = []
    for row in perl_spec['sources']:
        path = perl_output / row['path']
        perl_records.append({'path': row['path'], 'source_path': row['path'], 'type': 'file',
                             'bytes': path.stat().st_size, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()})
    report = _inspect_records(perl_output, perl_output / 'source-notices', origin='perl-build-only',
        version=perl_spec['version'], architecture=arch, manifest={'files': perl_records},
        binding={'origin': 'perl-build-only', 'version': perl_spec['version'], 'architecture': arch,
                 'provider_oci_binding': False, 'source_image_digest': None,
                 'binding_method': 'Pinned signed Alpine APK, complete recipe and matching source hashes',
                 'build_lock_sha256': perl.LOCK_SHA256})
    if not report['success']:
        raise ValueError('Build-only Perl source notices are incomplete')
    full_notices = perl_output / 'full-notices'
    full_notices.mkdir()
    attribution = []
    with tarfile.open(perl_output / 'perl-5.42.3.tar.xz', mode='r:xz') as archive:
        for name in ('Artistic', 'Copying', 'AUTHORS'):
            matches = [m for m in archive if m.name == 'perl-5.42.3/' + name]
            if len(matches) != 1 or not matches[0].isfile() or not 0 < matches[0].size < 1024 * 1024:
                raise ValueError('Missing complete Perl license or attribution')
            body = archive.extractfile(matches[0]).read()
            if not readable(body):
                raise ValueError('Perl full notice is not readable')
            (full_notices / name).write_bytes(body)
            attribution.append({'path': name, 'source_path': matches[0].name, 'bytes': len(body),
                                'sha256': hashlib.sha256(body).hexdigest()})
    write_json(full_notices / 'manifest.json', {'source_lock_sha256': perl.LOCK_SHA256, 'files': attribution})
    # This source-only tool is absent from Keep's runtime. Preserve its complete
    # notice report without adding it to the runtime OS-notice union.
    (perl_output / 'source-notices/package-material-inventory.json').rename(
        perl_output / 'source-notices/build-only-source-inventory.json')
    coverage = {'origin': 'openssl-overlay', 'version': '3.5.9', 'architecture': arch,
                'provider_oci_binding': False, 'vendor_apk_signature_applies_to_replacement': False,
                'build_lock_sha256': replacement['build_lock_sha256'],
                'replacement_manifest_sha256': replacement['manifest_sha256'],
                'files': replacement['files'], 'compiler_provenance': compiler,
                'toolchain': spec['toolchain'], 'perl_source_proof': perl_proof,
                'retained_files': file_records(output)}
    write_json(output / 'SOURCE-REPLAY.json', coverage)
    return {k: v for k, v in coverage.items() if k != 'retained_files'}
