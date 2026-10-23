"""Source orchestration fixture; native build/source parsing has separate tests."""
from contextlib import ExitStack, contextmanager
import hashlib
import json
from pathlib import Path
from unittest.mock import patch

import alpine_expat_sources as vendor
import build_patched_expat as build
import collect_package_sources as collection


COPYING = b'Copyright Fixture Authors. Permission is hereby granted to use this source.\n'
HEADER = (b'/*\n * Copyright Fixture Patch Contributors.\n'
          b' * Permission is hereby granted to use this source.\n */')
FORTIFY_LICENSE = b'Copyright Fortify Fixture Authors. Permission is hereby granted to use these headers.\n'
FORTIFY_HEADER = (b'/*\n * Copyright Fortify Fixture Contributors.\n'
                  b' * Permission is hereby granted to use these headers.\n */')


def qualified_inventory(architecture='amd64'):
    spec = {**build.immutable_spec(),
            'expected_library_sha256': {'amd64': 'a' * 64, 'arm64': 'b' * 64},
            'compiler_sha256': {'amd64': 'c' * 64, 'arm64': 'd' * 64},
            'build_script_sha256': hashlib.sha256(Path(build.__file__).read_bytes()).hexdigest()}
    manifest = build._manifest(spec, architecture, spec['expected_library_sha256'][architecture],
                               spec['compiler_sha256'][architecture], qualified=True)
    replacement = {'build_lock': spec,
                   'build_lock_sha256': hashlib.sha256(build.json_bytes(spec)).hexdigest(),
                   'manifest': manifest,
                   'manifest_sha256': hashlib.sha256(build.json_bytes(manifest)).hexdigest(),
                   'library': {'path': '/usr/lib/libexpat.so.1.13.0',
                               'sha256': spec['expected_library_sha256'][architecture]}}
    inventory = {'os_packages': [{
        'name': name, 'version': vendor.VERSION, 'origin': 'expat', 'license': 'MIT',
        'build_commit': vendor.BUILD_COMMIT, 'url': 'https://libexpat.github.io/'}
        for name in ('expat', 'libexpat')], 'expat_replacement': replacement}
    return spec, inventory


@contextmanager
def checked_source_fixture(architecture='amd64', *, collection_module=collection):
    spec, inventory = qualified_inventory(architecture)
    inputs = {vendor.SOURCE_URL: b'checked original source archive',
              vendor.APKBUILD_URL: b'checked original APKBUILD',
              vendor.APORTS_URL: b'checked original aports context',
              vendor.SOURCE_URL + '.asc': b'checked detached signature',
              'https://example.test/vendor.apk': b'checked signed vendor APK',
              'https://example.test/key': b'checked vendor signing key'}
    fortify_downloads = [
        ('packages/amd64/fortify-headers.apk', 'https://example.test/amd64/fortify.apk', 'signed-alpine-binary-evidence'),
        ('packages/arm64/fortify-headers.apk', 'https://example.test/arm64/fortify.apk', 'signed-alpine-binary-evidence'),
        ('keys/key.pub', 'https://example.test/key', 'alpine-signing-key'),
        ('fortify-headers.tar.gz', 'https://example.test/fortify.tar.gz', 'upstream-source'),
        ('aports.tar.gz', 'https://example.test/fortify-aports.tar.gz', 'complete-alpine-build-recipes'),
        ('APKBUILD', 'https://example.test/fortify-APKBUILD', 'matching-apk-build-script'),
        ('clang.patch', 'https://example.test/fortify-clang.patch', 'matching-apk-build-patch')]
    for name, url, _ in fortify_downloads:
        inputs.setdefault(url, ('checked Fortify input: ' + name).encode())
    cpp_downloads = [
        (arch + '/' + name + '-15.2.0-r7.apk', 'https://example.test/cpp/' + arch + '/' + name + '.apk',
         'signed-dhi-binary-evidence')
        for arch in ('amd64', 'arm64') for name in ('g++', 'libstdc++-dev')]
    cpp_downloads.append(('keys/dhi.pub', 'https://example.test/cpp/dhi.pub', 'dhi-signing-key'))
    for name, url, _ in cpp_downloads:
        inputs[url] = ('checked C++ input: ' + name).encode()
    download_records = [
        {'path': name, 'url': url, 'sha256': hashlib.sha256(inputs[url]).hexdigest(), 'role': role}
        for name, url, role in (
            [('expat-2.9.0.tar.xz', vendor.SOURCE_URL, 'upstream-source'),
             ('APKBUILD', vendor.APKBUILD_URL, 'matching-apk-build-script')]
            + [('fortify/' + name, url, role) for name, url, role in fortify_downloads]
            + [('cpp/' + name, url, role) for name, url, role in cpp_downloads])]
    gcc = next(row for row in json.loads((build.ROOT / 'docs/os-package-sources.json').read_bytes())['origins']
               if row['origin'] == 'gcc')
    reviewed_cpp = {'cpp/' + arch + '/' + package['name'] + '.apk': {
        'path': 'cpp/' + arch + '/' + package['name'] + '.apk', **package['binaries'][arch]}
        for arch in ('amd64', 'arm64') for package in gcc['build_only_packages']}
    cpp_binding = collection_module.expat_cpp_source_binding(reviewed_cpp)

    def collect(origin, arch, actual, output, fetch):
        assert arch == architecture
        assert actual['os_packages'] == inventory['os_packages']
        output = Path(output)
        output.mkdir(parents=True)
        rows = [
            ('expat-2.9.0.tar.xz', vendor.SOURCE_URL, 'upstream-source'),
            ('context/main/expat/APKBUILD', vendor.APKBUILD_URL, 'matching-apk-build-script'),
            ('aports.tar.gz', vendor.APORTS_URL, 'complete-alpine-build-recipes'),
            ('source.asc', vendor.SOURCE_URL + '.asc', 'upstream-detached-signature'),
            ('vendor.apk', 'https://example.test/vendor.apk', 'signed-alpine-binary-evidence'),
            ('key.pub', 'https://example.test/key', 'alpine-signing-key')]
        files = []
        for name, url, role in rows:
            body = fetch(url)
            path = output / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(body)
            files.append({'path': name, 'bytes': len(body),
                          'sha256': hashlib.sha256(body).hexdigest(),
                          'url': url, 'role': role, 'source_path': name})
        for name, body, role in (
                ('COPYING', COPYING, 'upstream-notice'),
                ('EXPAT_SECURITY.json', build.json_bytes(vendor.security_manifest(origin, arch)),
                 'runtime-installation-manifest')):
            (output / name).write_bytes(body)
            files.append({'path': name, 'bytes': len(body),
                          'sha256': hashlib.sha256(body).hexdigest(),
                          'url': 'verified-vendor:' + name, 'role': role, 'source_path': name})
        manifest = {'files': files, 'package_inputs': [{'signature_verified': True}],
                    'source_manifest_sha256': hashlib.sha256(vendor.source_lock_bytes(origin)).hexdigest(),
                    'binding_method': 'signed-alpine-packages'}
        (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
        return manifest

    def replay(output, *, root, fetch):
        assert fetch(build.SOURCE_URL) == inputs[vendor.SOURCE_URL]
        assert fetch(build.RECIPE_URL) == inputs[vendor.APKBUILD_URL]
        output = Path(output)
        output.mkdir(parents=True)
        files = {build.SOURCE_DIRECTORY + '/' + name: HEADER + b'\nint source;\n'
                 for name in build.PATCHED_FILES}
        files.update({build.SOURCE_DIRECTORY + '/COPYING': COPYING,
                      'expat-2.9.0.tar.xz': inputs[vendor.SOURCE_URL],
                      'APKBUILD': inputs[vendor.APKBUILD_URL],
                      'expat-build.json': build.json_bytes(spec),
                      'expat_security_patches.json': b'checked patch manifest',
                      'build_patched_expat.py': Path(build.__file__).read_bytes(),
                      'SOURCE_REPLAY.json': build.json_bytes(build.source_replay_record())})
        fortify_records = []
        for name, url, role in fortify_downloads:
            body = fetch(url)
            assert body == inputs[url]
            files['fortify/' + name] = body
            fortify_records.append({'path': name, 'bytes': len(body),
                                    'sha256': hashlib.sha256(body).hexdigest(),
                                    'url': url, 'role': role, 'source_path': name})
        fortify_sources = [('LICENSE', FORTIFY_LICENSE, 'upstream-notice')]
        fortify_sources += [('include/header-' + str(number) + '.h',
                             FORTIFY_HEADER + b'\nint checked_header;\n',
                             'upstream-permissive-attribution-source') for number in range(10)]
        for name, body, role in fortify_sources:
            files['fortify/' + name] = body
            fortify_records.append({'path': name, 'bytes': len(body),
                                    'sha256': hashlib.sha256(body).hexdigest(),
                                    'url': 'https://example.test/fortify.tar.gz', 'role': role,
                                    'source_path': 'fortify-headers-3.0.1/' + name})
        files['fortify/manifest.json'] = build.json_bytes({'files': fortify_records})
        cpp_records = []
        for name, url, role in cpp_downloads:
            body = fetch(url)
            files['cpp/' + name] = body
            cpp_records.append({'path': name, 'url': url, 'bytes': len(body),
                                'sha256': hashlib.sha256(body).hexdigest(), 'role': role})
            if name.endswith('.apk'):
                metadata = b'checked original C++ package metadata'
                files['cpp/' + name + '.PKGINFO'] = metadata
                cpp_records.append({'path': name + '.PKGINFO', 'url': url, 'bytes': len(metadata),
                                    'sha256': hashlib.sha256(metadata).hexdigest(),
                                    'role': 'vendor-build-only-apk-metadata'})
        files['cpp/CPP_BUILD_INPUTS.json'] = build.json_bytes({'files': cpp_records})
        for name, body in files.items():
            path = output / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(body)
        return build.source_replay_record()

    def compiler_proof(source, destination, arch, *, root):
        # Original proof crypto is tested by the compiler provenance tests.
        # This fixture exercises only full source orchestration and replay.
        assert arch == architecture
        statement = build.json_bytes({'fixture': 'original signed compiler SLSA'})
        if source is not None:
            assert (Path(source) / 'statement.json').read_bytes() == statement
        destination = Path(destination)
        destination.mkdir(parents=True)
        (destination / 'statement.json').write_bytes(statement)
        return {'schema': 'keep-expat-compiler-provenance-v1', 'architecture': arch,
                'build_image': build.BUILD_IMAGE, 'signature_verified': True}

    with ExitStack() as stack:
        stack.enter_context(patch.object(build, 'reviewed_spec', return_value=spec))
        stack.enter_context(patch.object(vendor, 'collect_sources', side_effect=collect))
        stack.enter_context(patch.object(build, 'replay_sources', side_effect=replay))
        stack.enter_context(patch.object(build, 'source_download_records', return_value=download_records, create=True))
        stack.enter_context(patch.object(collection_module, 'retain_expat_compiler_provenance',
                                        side_effect=compiler_proof))
        stack.enter_context(patch.object(collection_module, 'expat_cpp_source_binding', return_value=cpp_binding))
        yield vendor.reviewed_spec(), inventory, inputs
