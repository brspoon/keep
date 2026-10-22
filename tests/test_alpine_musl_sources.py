"""Signed musl runtime and build inputs stay bound to exact source and bytes."""
from contextlib import ExitStack
import copy
import gzip
import hashlib
import io
import json
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from scripts import alpine_musl_sources as sources


def archive(entries, links=None, directories=(), modes=None, owners=None):
    stream = io.BytesIO()
    modes, owners = modes or {}, owners or {}
    with tarfile.open(fileobj=stream, mode='w') as output:
        for name in directories:
            member = tarfile.TarInfo(name)
            member.type, member.mode = tarfile.DIRTYPE, modes.get(name, 0o755)
            member.uid, member.gid = owners.get(name, (0, 0))
            output.addfile(member)
        for name, body in entries:
            member = tarfile.TarInfo(name)
            member.size, member.mode = len(body), modes.get(name, 0o644)
            member.uid, member.gid = owners.get(name, (0, 0))
            output.addfile(member, io.BytesIO(body))
        for name, target in (links or {}).items():
            member = tarfile.TarInfo(name)
            member.type, member.linkname = tarfile.SYMTYPE, target
            member.mode = modes.get(name, 0o777)
            member.uid, member.gid = owners.get(name, (0, 0))
            output.addfile(member)
    return stream.getvalue()


@unittest.skipUnless(shutil.which('openssl'), 'Alpine APK verification requires OpenSSL')
class AlpineMuslSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key_directory = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.key_directory.cleanup)
        cls.private = Path(cls.key_directory.name) / 'test-signing.pem'
        subprocess.run(['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt',
                        'rsa_keygen_bits:2048', '-out', str(cls.private)],
                       check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        cls.key = subprocess.check_output(['openssl', 'pkey', '-in', str(cls.private), '-pubout'])

    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(sources, 'installed_stat', self.root_stat))
        keys = copy.deepcopy(sources.KEYS)
        for key in keys.values():
            key['sha256'] = hashlib.sha256(self.key).hexdigest()
        self.stack.enter_context(patch.object(sources, 'KEYS', keys))
        self.bodies, binaries, metadata_hashes, loaders, dev_hashes = {}, {}, {}, {}, {}
        self.payloads = {}
        for arch in sources.ARCHES:
            self.bodies['https://alpinelinux.org/keys/' + keys[arch]['name']] = self.key
            loaders[arch] = hashlib.sha256(self.loader_bytes(arch)).hexdigest()
            binaries[arch], metadata_hashes[arch] = {}, {}
            self.payloads[arch] = {name: self.payload(name, arch) for name in ('musl', 'musl-dev')}
            records = sources.payload_inventory(sources.tar_entries(self.payloads[arch]['musl-dev']))
            dev_hashes[arch] = hashlib.sha256(json.dumps(records, sort_keys=True,
                                                       separators=(',', ':')).encode()).hexdigest()
        self.stack.enter_context(patch.object(sources, 'LOADER_SHA256', loaders))
        self.stack.enter_context(patch.object(sources, 'DEV_INVENTORY_SHA256', dev_hashes))
        for arch in sources.ARCHES:
            for name in ('musl', 'musl-dev'):
                body, metadata = self.apk(name, arch)
                self.bodies[self.url(name, arch)] = body
                binaries[arch][name] = hashlib.sha256(body).hexdigest()
                metadata_hashes[arch][name] = hashlib.sha256(metadata).hexdigest()
        self.stack.enter_context(patch.object(sources, 'BINARY_SHA256', binaries))
        self.stack.enter_context(patch.object(sources, 'PKGINFO_SHA256', metadata_hashes))
        self.source_fixture()
        self.package_spec = sources.reviewed_spec()

    def source_fixture(self):
        self.copyright_body = (b'Copyright (C) ordinary musl contributors.\n'
                               b'Permission is hereby granted to use this software.\n'
                               b'Full copyright, license terms and disclaimer.\n')
        attribution_pins = {}
        self.attribution_bodies = {}
        for number, path in enumerate(sources.ATTRIBUTION_SOURCES):
            body = (f'/* Copyright (C) ordinary contributor {number}.\n'
                    ' * Permission is hereby granted to use this software.\n'
                    ' * Full permission terms and disclaimer.\n'
                    ' */\n\nint ordinary_source;\n').encode()
            self.attribution_bodies[path] = body
            attribution_pins[path] = hashlib.sha256(body).hexdigest()
        self.stack.enter_context(patch.object(sources, 'ATTRIBUTION_SOURCES', attribution_pins))
        source = archive([('musl-1.2.6/COPYRIGHT', self.copyright_body),
                          *[(self.source_path(path), body)
                            for path, body in self.attribution_bodies.items()]])
        self.stack.enter_context(patch.object(sources, 'SOURCE_SHA256', hashlib.sha256(source).hexdigest()))
        self.stack.enter_context(patch.object(sources, 'SOURCE_SHA512', hashlib.sha512(source).hexdigest()))
        self.stack.enter_context(patch.object(sources, 'COPYRIGHT_SHA256',
                                             hashlib.sha256(self.copyright_body).hexdigest()))
        signature = b'ordinary retained upstream detached signature; verification is not claimed'
        self.stack.enter_context(patch.object(sources, 'SIGNATURE_SHA256', hashlib.sha256(signature).hexdigest()))
        self.bodies[sources.SOURCE_URL + '.asc'] = signature
        self.patch_body = ('>From ' + sources.UPSTREAM_COMMIT + ' Mon Sep 17 00:00:00 2001\n'
                           'Reviewed regular expression integer overflow correction\n').encode()
        self.stack.enter_context(patch.object(sources, 'PATCH_SHA256', hashlib.sha256(self.patch_body).hexdigest()))
        self.stack.enter_context(patch.object(sources, 'PATCH_SHA512', hashlib.sha512(self.patch_body).hexdigest()))
        context_pins = copy.deepcopy(sources.CONTEXT_FILES)
        self.context_bodies = {}
        for name in context_pins:
            body = self.patch_body if name == 'CVE-2026-107891.patch' else (
                'ordinary complete pinned build context ' + name + '\n').encode()
            self.context_bodies[name] = body
            context_pins[name] = {**context_pins[name], 'sha256': hashlib.sha256(body).hexdigest(),
                                  'sha512': hashlib.sha512(body).hexdigest()}
        self.stack.enter_context(patch.object(sources, 'CONTEXT_FILES', context_pins))
        self.recipe = self.make_recipe()
        self.recipes = self.make_recipes()
        self.stack.enter_context(patch.object(sources, 'APKBUILD_SHA256', hashlib.sha256(self.recipe).hexdigest()))
        self.stack.enter_context(patch.object(sources, 'APORTS_SHA256', hashlib.sha256(self.recipes).hexdigest()))
        self.bodies.update({sources.APORTS_URL: self.recipes, sources.SOURCE_URL: source})

    @staticmethod
    def source_path(path):
        return path if path.startswith('musl-1.2.6/') else 'musl-1.2.6/' + path

    def make_recipe(self):
        names = list(sources.CONTEXT_FILES)
        sums = [sources.SOURCE_SHA512 + '  musl-1.2.6.tar.gz']
        sums.extend(sources.CONTEXT_FILES[name]['sha512'] + '  ' + name for name in names)
        return ('pkgname=musl\npkgver=1.2.6\npkgrel=3\nlicense="MIT"\n'
                'source="https://musl.libc.org/releases/musl-$pkgver.tar.gz\n\t'
                + '\n\t'.join(names) + '\n\t"\n'
                '# secfixes:\n#   1.2.6-r3:\n#     - CVE-2026-107891\n'
                'sha512sums="\n' + '\n'.join(sums) + '\n"\n'
                'build() { ./configure --prefix=/usr; make; }\ncheck() { make check; }\n').encode()

    def make_recipes(self, recipe=None, replacements=None):
        prefix = f'aports-{sources.BUILD_COMMIT}/main/musl/'
        context = {**self.context_bodies, **(replacements or {})}
        return archive([(prefix + 'APKBUILD', self.recipe if recipe is None else recipe),
                        *[(prefix + name, body) for name, body in context.items()],
                        (f'aports-{sources.BUILD_COMMIT}/README.md', b'complete pinned aports context')])

    @staticmethod
    def inventory():
        return {'os_packages': [{'name': 'musl', 'version': sources.VERSION, 'origin': 'musl',
                                 'license': 'MIT', 'build_commit': sources.BUILD_COMMIT,
                                 'url': 'https://musl.libc.org/'}]}

    def collect(self, root, arch='amd64', inventory=None, package_spec=None):
        return sources.collect_sources(self.package_spec if package_spec is None else package_spec,
                                       arch, self.inventory() if inventory is None else inventory,
                                       root, fetch=self.bodies.__getitem__)

    @staticmethod
    def url(name, arch):
        return (f'https://dl-cdn.alpinelinux.org/alpine/v3.24/main/'
                f'{sources.ARCHES[arch]}/{name}-{sources.VERSION}.apk')

    @staticmethod
    def loader_bytes(arch):
        return ('ordinary test musl loader ' + arch).encode()

    @staticmethod
    def loader_path(arch):
        return 'lib/ld-musl-' + sources.ARCHES[arch] + '.so.1'

    def payload(self, name, arch):
        native = sources.ARCHES[arch]
        if name == 'musl':
            loader = self.loader_path(arch)
            return archive([(loader, self.loader_bytes(arch))],
                           {'lib/libc.musl-' + native + '.so.1': 'ld-musl-' + native + '.so.1'},
                           directories=('lib',), modes={loader: 0o755})
        return archive([('usr/include/stdio.h', b'/* complete ordinary stdio header */\n'),
                        ('usr/include/features.h', b'/* complete ordinary features header */\n'),
                        ('usr/lib/crt1.o', b'ordinary crt object'),
                        ('usr/lib/libc.a', b'ordinary static libc archive')],
                       {'usr/lib/libc.so': '../../lib/ld-musl-' + native + '.so.1'},
                       directories=('usr', 'usr/include', 'usr/lib'))

    def apk(self, name, arch, *, changes=None, signer=None, extra_metadata=b'',
            fields=None, payload=None, control_extra=()):
        data = gzip.compress(self.payloads[arch][name] if payload is None else payload, mtime=0)
        values = {'pkgname': name, 'pkgver': sources.VERSION, 'origin': 'musl',
                  'arch': sources.ARCHES[arch], 'commit': sources.BUILD_COMMIT,
                  'license': 'MIT', 'url': 'https://musl.libc.org/',
                  'datahash': hashlib.sha256(data).hexdigest()}
        values.update(changes or {})
        metadata = ''.join(key + ' = ' + value + '\n' for key, value in values.items()).encode()
        for key, records in (sources.expected_fields(name, arch) if fields is None else fields).items():
            metadata += ''.join(key + ' = ' + value + '\n' for value in records).encode()
        metadata += extra_metadata
        control = gzip.compress(archive([('.PKGINFO', metadata), *control_extra]), mtime=0)
        signature = subprocess.run(['openssl', 'dgst', '-sha1', '-sign', str(self.private)],
                                   input=control, check=True, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE).stdout
        signed = gzip.compress(archive([('.SIGN.RSA.' + (signer or sources.KEYS[arch]['name']),
                                         signature)]), mtime=0)
        return signed + control + data, metadata

    def replace_apk(self, name='musl', arch='amd64', **kwargs):
        body, metadata = self.apk(name, arch, **kwargs)
        self.bodies[self.url(name, arch)] = body
        sources.BINARY_SHA256[arch][name] = hashlib.sha256(body).hexdigest()
        sources.PKGINFO_SHA256[arch][name] = hashlib.sha256(metadata).hexdigest()
        self.package_spec = sources.reviewed_spec()
        return body

    def runtime(self, root, arch='amd64', build=False):
        root = Path(root)
        names = ('musl', 'musl-dev') if build else ('musl',)
        rows = []
        for name in names:
            for path, item in sources.tar_entries(self.payloads[arch][name]).items():
                target, member = root / path, item['member']
                target.parent.mkdir(parents=True, exist_ok=True)
                if member.isdir():
                    target.mkdir(exist_ok=True)
                elif member.issym():
                    target.symlink_to(member.linkname)
                    if stat.S_IMODE(target.lstat().st_mode) != member.mode:
                        target.lchmod(member.mode)
                else:
                    target.write_bytes(item['body'])
                if not member.issym():
                    target.chmod(member.mode)
            values = {'P': name, 'V': sources.VERSION, 'A': sources.ARCHES[arch],
                      'o': 'musl', 'c': sources.BUILD_COMMIT,
                      'L': 'MIT', 'U': 'https://musl.libc.org/'}
            for key, field in [('D', 'depend'), ('p', 'provides'), ('i', 'install_if')]:
                records = sources.expected_fields(name, arch).get(field, [])
                if records:
                    values[key] = ' '.join(records)
            rows.append(''.join(key + ':' + value + '\n' for key, value in values.items()))
        database = root / 'lib/apk/db/installed'
        database.parent.mkdir(parents=True)
        database.write_text('\n'.join(rows) + '\n')
        return database

    def prepared(self, root, arch='amd64'):
        return sources.prepare_packages(self.package_spec, arch, root, fetch=self.bodies.__getitem__)

    @staticmethod
    def root_stat(path):
        info = Path(path).lstat()
        fields = {name: getattr(info, name) for name in dir(info) if name.startswith('st_')}
        return SimpleNamespace(**{**fields, 'st_uid': 0, 'st_gid': 0})

    def test_complete_signed_cohort_prepares_for_both_architectures(self):
        for arch in sources.ARCHES:
            with self.subTest(architecture=arch), tempfile.TemporaryDirectory() as root:
                fetch = Mock(side_effect=self.bodies.__getitem__)
                manifest = sources.prepare_packages(self.package_spec, arch, root, fetch=fetch)
                self.assertEqual(fetch.call_count, 3)
                self.assertEqual(manifest, sources.build_security_manifest(arch, root=None))
                self.assertEqual(json.loads((Path(root) / 'MUSL_SECURITY.json').read_text()), manifest)
                self.assertEqual({path.name for path in Path(root).glob('*.apk')},
                                 {name + '-' + sources.VERSION + '.apk' for name in ('musl', 'musl-dev')})
                self.assertEqual((Path(root) / 'source-lock.json').read_bytes(),
                                 sources.source_lock_bytes(self.package_spec))

    def test_each_package_verifies_native_metadata_and_signature(self):
        for arch in sources.ARCHES:
            for name in ('musl', 'musl-dev'):
                with self.subTest(architecture=arch, name=name):
                    metadata, identity = sources.verify_apk(self.bodies[self.url(name, arch)],
                                                            name, arch, self.key)
                    self.assertEqual(hashlib.sha256(metadata).hexdigest(),
                                     sources.PKGINFO_SHA256[arch][name])
                    self.assertEqual(identity['pkgname'], name)
                    self.assertEqual(identity['pkgver'], sources.VERSION)
                    self.assertIs(identity['signature_verified'], True)

    def test_outer_and_signing_key_hashes_are_mandatory(self):
        for name in ('musl', 'musl-dev'):
            body = self.bodies[self.url(name, 'amd64')]
            for candidate, key in ((body + b'changed', self.key), (body, self.key + b'changed')):
                with self.subTest(name=name, changed=candidate != body), self.assertRaisesRegex(ValueError, 'checksum'):
                    sources.verify_apk(candidate, name, 'amd64', key)

    def test_bad_signature_is_rejected_after_outer_hash_is_repinned(self):
        for name in ('musl', 'musl-dev'):
            parts = sources.gzip_parts(self.bodies[self.url(name, 'amd64')])
            signed = gzip.compress(archive([('.SIGN.RSA.' + sources.KEYS['amd64']['name'],
                                            b'invalid RSA signature')]), mtime=0)
            body = signed + parts[1][0] + parts[2][0]
            sources.BINARY_SHA256['amd64'][name] = hashlib.sha256(body).hexdigest()
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'signature'):
                sources.verify_apk(body, name, 'amd64', self.key)

    def test_unsigned_control_and_signed_datahash_cannot_be_substituted(self):
        original = sources.gzip_parts(self.bodies[self.url('musl', 'amd64')])
        changed = sources.gzip_parts(self.apk('musl', 'amd64', changes={'arch': 'aarch64'})[0])
        for parts in ((original[0][0], changed[1][0], original[2][0]),
                      (original[0][0], original[1][0], gzip.compress(b'changed payload', mtime=0))):
            body = b''.join(parts)
            sources.BINARY_SHA256['amd64']['musl'] = hashlib.sha256(body).hexdigest()
            with self.subTest(parts=parts), self.assertRaises(ValueError):
                sources.verify_apk(body, 'musl', 'amd64', self.key)

    def test_signed_wrong_package_metadata_is_rejected(self):
        for name in ('musl', 'musl-dev'):
            for field, value in {'pkgname': 'other', 'pkgver': '1.2.6-r2', 'origin': 'other',
                                 'arch': 'aarch64', 'commit': '0' * 40, 'license': 'other',
                                 'url': 'https://example.invalid/'}.items():
                body = self.replace_apk(name, changes={field: value})
                with self.subTest(name=name, field=field), self.assertRaises(ValueError):
                    sources.verify_apk(body, name, 'amd64', self.key)

    def test_duplicate_and_unreviewed_dependency_provision_fields_are_rejected(self):
        for name in ('musl', 'musl-dev'):
            for extra in (b'pkgver = ' + sources.VERSION.encode() + b'\n',
                          b'depend = unreviewed-package\n', b'provides = unreviewed-soname\n',
                          b'install_if = unreviewed-trigger\n'):
                body = self.replace_apk(name, extra_metadata=extra)
                with self.subTest(name=name, extra=extra), self.assertRaises(ValueError):
                    sources.verify_apk(body, name, 'amd64', self.key)

    def test_metadata_pin_is_checked_independently(self):
        for name in ('musl', 'musl-dev'):
            body = self.bodies[self.url(name, 'amd64')]
            sources.PKGINFO_SHA256['amd64'][name] = '0' * 64
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'metadata.*checksum|checksum.*metadata'):
                sources.verify_apk(body, name, 'amd64', self.key)

    def test_wrong_signing_key_name_and_lifecycle_script_are_rejected(self):
        for name in ('musl', 'musl-dev'):
            for kwargs in ({'signer': 'unreviewed.rsa.pub'},
                           {'control_extra': [('.post-install', b'unreviewed code')]}):
                body = self.replace_apk(name, **kwargs)
                with self.subTest(name=name, kwargs=kwargs), self.assertRaises(ValueError):
                    sources.verify_apk(body, name, 'amd64', self.key)

    def test_loader_hash_alias_permissions_and_extra_payload_are_rejected(self):
        loader = self.loader_path('amd64')
        alias = 'lib/libc.musl-x86_64.so.1'
        candidates = [archive([(loader, b'unreviewed loader')], {alias: 'ld-musl-x86_64.so.1'},
                              directories=('lib',), modes={loader: 0o755}),
                      archive([(loader, self.loader_bytes('amd64'))], {alias: '../../unreviewed'},
                              directories=('lib',), modes={loader: 0o755}),
                      archive([(loader, self.loader_bytes('amd64'))], {alias: 'ld-musl-x86_64.so.1'},
                              directories=('lib',), modes={loader: 0o644}),
                      archive([(loader, self.loader_bytes('amd64'))], {alias: 'ld-musl-x86_64.so.1'},
                              directories=('lib',), modes={loader: 0o755}, owners={loader: (123, 0)}),
                      archive([(loader, self.loader_bytes('amd64')), ('lib/extra.so', b'extra')],
                              {alias: 'ld-musl-x86_64.so.1'}, directories=('lib',), modes={loader: 0o755})]
        for payload in candidates:
            body = self.replace_apk(payload=payload)
            with self.subTest(payload=hashlib.sha256(payload).hexdigest()), self.assertRaises(ValueError):
                sources.verify_apk(body, 'musl', 'amd64', self.key)

    def test_dev_inventory_binds_header_object_modes_and_aliases(self):
        original = self.payloads['amd64']['musl-dev']
        rows = sources.tar_entries(original)
        for selected in ('usr/include/stdio.h', 'usr/lib/crt1.o', 'usr/lib/libc.so'):
            changed = copy.deepcopy(rows)
            if changed[selected]['body'] is not None:
                changed[selected]['body'] += b'changed'
            else:
                changed[selected]['member'].linkname = '../../lib/other.so'
            entries = [(path, item['body']) for path, item in changed.items() if item['body'] is not None]
            links = {path: item['member'].linkname for path, item in changed.items() if item['member'].issym()}
            directories = [path for path, item in changed.items() if item['member'].isdir()]
            payload = archive(entries, links, directories)
            body = self.replace_apk('musl-dev', payload=payload)
            with self.subTest(path=selected), self.assertRaises(ValueError):
                sources.verify_apk(body, 'musl-dev', 'amd64', self.key)
        changed_mode = archive([(path, item['body']) for path, item in rows.items() if item['body'] is not None],
                               {path: item['member'].linkname for path, item in rows.items() if item['member'].issym()},
                               [path for path, item in rows.items() if item['member'].isdir()],
                               modes={'usr/include/stdio.h': 0o600})
        body = self.replace_apk('musl-dev', payload=changed_mode)
        with self.assertRaises(ValueError):
            sources.verify_apk(body, 'musl-dev', 'amd64', self.key)

    def test_unsafe_duplicate_and_malformed_archives_are_rejected(self):
        for payload in (archive([('../escape', b'unsafe')]), archive([('/absolute', b'unsafe')]),
                        archive([('duplicate', b'one'), ('duplicate', b'two')])):
            body = self.replace_apk(payload=payload)
            with self.subTest(payload=payload[:64]), self.assertRaises(ValueError):
                sources.verify_apk(body, 'musl', 'amd64', self.key)
        original = self.bodies[self.url('musl-dev', 'amd64')]
        for body in (original + gzip.compress(b'fourth member', mtime=0), original[:40]):
            sources.BINARY_SHA256['amd64']['musl-dev'] = hashlib.sha256(body).hexdigest()
            with self.assertRaises(ValueError):
                sources.verify_apk(body, 'musl-dev', 'amd64', self.key)

    def test_offline_reviewed_manifest_and_changed_map_are_exact(self):
        with tempfile.TemporaryDirectory() as root:
            docs = Path(root) / 'docs'
            docs.mkdir()
            mapping = {'origins': [self.package_spec]}
            (docs / 'os-package-sources.json').write_text(json.dumps(mapping))
            self.assertEqual(sources.build_security_manifest('amd64', root),
                             sources.build_security_manifest('amd64', root=None))
            mapping['origins'][0]['version'] = '1.2.6-r2'
            (docs / 'os-package-sources.json').write_text(json.dumps(mapping))
            with self.assertRaisesRegex(ValueError, 'source map'):
                sources.build_security_manifest('amd64', root)
        changed = copy.deepcopy(self.package_spec)
        changed['version'] = '1.2.6-r2'
        with self.assertRaisesRegex(ValueError, 'source map'):
            sources.source_lock_bytes(changed)

    def test_runtime_native_package_and_loader_bytes_pass_for_both_architectures(self):
        for arch in sources.ARCHES:
            with self.subTest(architecture=arch), tempfile.TemporaryDirectory() as root:
                self.runtime(root, arch)
                manifest = sources.build_security_manifest(arch, root=None)
                self.assertEqual(sources.verify_installed(arch, manifest, runtime_root=root), manifest)

    def test_missing_mismatched_duplicate_runtime_package_and_extra_dev_are_rejected(self):
        for change in ('missing', 'version', 'commit', 'license', 'dependency', 'duplicate', 'dev'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as root:
                database = self.runtime(root, build=change == 'dev')
                body = database.read_text()
                if change == 'missing':
                    body = body.replace('P:musl\n', 'P:other\n')
                elif change == 'version':
                    body = body.replace('V:' + sources.VERSION, 'V:1.2.6-r2')
                elif change == 'commit':
                    body = body.replace('c:' + sources.BUILD_COMMIT, 'c:' + '0' * 40)
                elif change == 'license':
                    body = body.replace('L:MIT', 'L:other')
                elif change == 'dependency':
                    body = body.replace('P:musl\n', 'P:musl\nD:unreviewed\n')
                elif change == 'duplicate':
                    body += '\n' + body
                database.write_text(body)
                with self.assertRaises(ValueError):
                    sources.verify_installed('amd64', sources.build_security_manifest('amd64', root=None),
                                             runtime_root=root)

    def test_changed_runtime_loader_alias_type_mode_and_manifest_are_rejected(self):
        for change in ('bytes', 'alias', 'normalized-alias', 'canonical-symlink', 'mode', 'manifest', 'integer-signature'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as root:
                self.runtime(root)
                manifest = sources.build_security_manifest('amd64', root=None)
                loader = Path(root) / self.loader_path('amd64')
                if change == 'bytes':
                    loader.write_bytes(b'changed loader')
                elif change == 'alias':
                    alias = Path(root) / 'lib/libc.musl-x86_64.so.1'
                    alias.unlink()
                    alias.symlink_to('other.so')
                elif change == 'normalized-alias':
                    alias = Path(root) / 'lib/libc.musl-x86_64.so.1'
                    alias.unlink()
                    alias.symlink_to('./ld-musl-x86_64.so.1')
                    if stat.S_IMODE(alias.lstat().st_mode) != 0o777:
                        alias.lchmod(0o777)
                elif change == 'canonical-symlink':
                    target = loader.with_name('other')
                    loader.rename(target)
                    loader.symlink_to('other')
                elif change == 'mode':
                    loader.chmod(0o644)
                elif change == 'integer-signature':
                    manifest['packages'][0]['signature_verified'] = 1
                else:
                    manifest['package_version'] = '1.2.6-r2'
                with self.assertRaises(ValueError):
                    sources.verify_installed('amd64', manifest, runtime_root=root)

    def test_nonempty_and_symlink_output_and_unsupported_architecture_are_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            (Path(root) / 'existing').write_text('preserved')
            with self.assertRaisesRegex(ValueError, 'empty'):
                self.prepared(root)
            link = Path(root) / 'link'
            link.symlink_to(root, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, 'symlink'):
                self.prepared(link)
        with tempfile.TemporaryDirectory() as root, self.assertRaisesRegex(ValueError, 'architecture'):
            self.prepared(root, 'ppc64le')

    def test_offline_build_inputs_select_only_exact_native_dev_apk(self):
        for arch in sources.ARCHES:
            with self.subTest(architecture=arch), tempfile.TemporaryDirectory() as prepared:
                self.prepared(prepared, arch)
                inputs = sources.build_installation_inputs(Path(prepared).resolve(), arch)
                self.assertEqual(inputs, [Path(prepared).resolve() / ('musl-dev-' + sources.VERSION + '.apk')])
                self.assertEqual(inputs[0].read_bytes(), self.bodies[self.url('musl-dev', arch)])

    def test_prepared_dev_apk_key_lock_and_manifest_tampering_are_rejected(self):
        for target in ('apk', 'key', 'lock', 'manifest', 'symlink'):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as prepared:
                self.prepared(prepared)
                root = Path(prepared)
                if target in ('apk', 'symlink'):
                    path = root / ('musl-dev-' + sources.VERSION + '.apk')
                elif target == 'key':
                    path = root / 'keys' / sources.KEYS['amd64']['name']
                elif target == 'lock':
                    path = root / 'source-lock.json'
                else:
                    path = root / 'MUSL_SECURITY.json'
                if target == 'symlink':
                    other = path.with_name('unreviewed.apk')
                    path.rename(other)
                    path.symlink_to(other.name)
                else:
                    path.write_bytes(path.read_bytes() + b'changed')
                with self.assertRaises((ValueError, json.JSONDecodeError)):
                    sources.build_installation_inputs(Path(prepared).resolve(), 'amd64')

    def test_exact_build_cohort_and_full_dev_payload_pass_both_architectures(self):
        for arch in sources.ARCHES:
            with self.subTest(architecture=arch), tempfile.TemporaryDirectory() as prepared, \
                    tempfile.TemporaryDirectory() as root:
                manifest = self.prepared(prepared, arch)
                self.runtime(root, arch, build=True)
                self.assertEqual(sources.verify_build_installed(arch, manifest, Path(prepared).resolve(),
                                                                runtime_root=root), manifest)

    def test_build_verification_requires_dev_package_and_exact_identity(self):
        for change in ('missing', 'duplicate', 'version', 'commit', 'dependency'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as prepared, \
                    tempfile.TemporaryDirectory() as root:
                manifest = self.prepared(prepared)
                database = self.runtime(root, build=True)
                body = database.read_text()
                if change == 'missing':
                    body = body.replace('P:musl-dev\n', 'P:other\n')
                elif change == 'duplicate':
                    body += '\n' + body.split('\n\n')[1] + '\n'
                elif change == 'version':
                    body = body.replace('P:musl-dev\nV:' + sources.VERSION,
                                        'P:musl-dev\nV:1.2.6-r2')
                elif change == 'commit':
                    body = body.replace('P:musl-dev\n', 'P:musl-dev\nc:' + '0' * 40 + '\n')
                else:
                    body = body.replace('D:musl=' + sources.VERSION, 'D:musl=1.2.6-r2')
                database.write_text(body)
                with self.assertRaises(ValueError):
                    sources.verify_build_installed('amd64', manifest, Path(prepared).resolve(), runtime_root=root)

    def test_build_verification_rechecks_prepared_signed_dev_input(self):
        with tempfile.TemporaryDirectory() as prepared, tempfile.TemporaryDirectory() as root:
            manifest = self.prepared(prepared)
            self.runtime(root, build=True)
            path = Path(prepared) / ('musl-dev-' + sources.VERSION + '.apk')
            path.write_bytes(path.read_bytes() + b'changed after installation input verification')
            with self.assertRaisesRegex(ValueError, 'checksum'):
                sources.verify_build_installed('amd64', manifest, Path(prepared).resolve(), runtime_root=root)

    def test_build_verification_checks_headers_objects_aliases_modes_and_parents(self):
        for change in ('header', 'object', 'alias', 'mode', 'parent-symlink', 'missing'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as prepared, \
                    tempfile.TemporaryDirectory() as root:
                manifest = self.prepared(prepared)
                self.runtime(root, build=True)
                header = Path(root) / 'usr/include/stdio.h'
                if change == 'header':
                    header.write_bytes(b'unreviewed header')
                elif change == 'object':
                    (Path(root) / 'usr/lib/crt1.o').write_bytes(b'unreviewed crt object')
                elif change == 'alias':
                    alias = Path(root) / 'usr/lib/libc.so'
                    alias.unlink()
                    alias.symlink_to('../../lib/other.so')
                elif change == 'mode':
                    header.chmod(0o600)
                elif change == 'missing':
                    header.unlink()
                else:
                    parent = Path(root) / 'usr/include'
                    parent.rename(parent.with_name('other-include'))
                    parent.symlink_to('other-include')
                with self.assertRaises((ValueError, FileNotFoundError)):
                    sources.verify_build_installed('amd64', manifest, Path(prepared).resolve(), runtime_root=root)

    def test_installed_loader_and_dev_ownership_are_checked(self):
        for build, selected in ((False, self.loader_path('amd64')),
                                (True, 'usr/include/stdio.h')):
            with self.subTest(build=build), tempfile.TemporaryDirectory() as prepared, \
                    tempfile.TemporaryDirectory() as root:
                manifest = self.prepared(prepared)
                self.runtime(root, build=build)
                def changed_stat(path):
                    info = self.root_stat(path)
                    if Path(path) == Path(root).resolve() / selected:
                        info.st_uid = 123
                    return info
                with patch.object(sources, 'installed_stat', changed_stat), self.assertRaises(ValueError):
                    if build:
                        sources.verify_build_installed('amd64', manifest, Path(prepared).resolve(), runtime_root=root)
                    else:
                        sources.verify_installed('amd64', manifest, runtime_root=root)

    def test_both_architectures_retain_full_recipes_sources_and_complete_notices(self):
        for arch in sources.ARCHES:
            with self.subTest(architecture=arch), tempfile.TemporaryDirectory() as root:
                result = self.collect(root, arch)
                self.assertIs(result['provider_oci_binding'], False)
                self.assertIsNone(result['source_image_digest'])
                self.assertIs(result['upstream_signature_verified'], False)
                self.assertEqual(result['binding_method'], 'signed-alpine-packages')
                self.assertEqual([row['pkgname'] for row in result['package_inputs']],
                                 ['musl', 'musl-dev'])
                self.assertTrue(all(row['signature_verified'] for row in result['package_inputs']))
                for record in result['files']:
                    body = (Path(root) / record['path']).read_bytes()
                    self.assertEqual(hashlib.sha256(body).hexdigest(), record['sha256'])
                self.assertEqual((Path(root) / f'aports-{sources.BUILD_COMMIT}.tar.gz').read_bytes(),
                                 self.recipes)
                self.assertEqual((Path(root) / 'musl-1.2.6-COPYRIGHT').read_bytes(), self.copyright_body)
                attribution = [row for row in result['files']
                               if row['role'] == 'upstream-permissive-attribution-source']
                self.assertEqual(len(attribution), 11)
                for record in attribution:
                    self.assertEqual((Path(root) / record['path']).read_bytes(),
                                     self.attribution_bodies[record['source_path']])
                installation = json.loads((Path(root) / 'MUSL_SECURITY.json').read_text())
                self.assertEqual(installation, sources.build_security_manifest(arch, root=None))
                self.assertEqual(result['source_manifest_sha256'], installation['source_manifest_sha256'])
                self.assertEqual(result['installation_manifest_sha256'],
                                 hashlib.sha256((Path(root) / 'MUSL_SECURITY.json').read_bytes()).hexdigest())

    def test_wrong_missing_duplicate_or_dev_runtime_package_is_rejected_before_download(self):
        original = self.inventory()
        cases = [{'os_packages': []}, {'os_packages': original['os_packages'] * 2},
                 {'os_packages': [*original['os_packages'],
                                  {**original['os_packages'][0], 'name': 'musl-dev'}]}]
        for field, value in {'version': '1.2.6-r2', 'origin': 'other', 'license': 'other',
                             'build_commit': '0' * 40, 'url': 'https://example.invalid/'}.items():
            changed = copy.deepcopy(original)
            changed['os_packages'][0][field] = value
            cases.append(changed)
        for inventory in cases:
            fetch = Mock(side_effect=AssertionError('invalid runtime must fail before downloads'))
            with self.subTest(inventory=inventory), tempfile.TemporaryDirectory() as root:
                with self.assertRaisesRegex(ValueError, 'runtime'):
                    sources.collect_sources(self.package_spec, 'amd64', inventory, root, fetch=fetch)
                fetch.assert_not_called()

    def test_recipe_identity_source_patch_checksums_and_security_marker_are_exact(self):
        for original, replacement in ((b'pkgrel=3', b'pkgrel=2'),
                                      (b'license="MIT"', b'license="unknown"'),
                                      (sources.SOURCE_SHA512.encode(), b'0' * 128),
                                      (sources.PATCH_SHA512.encode(), b'0' * 128),
                                      (b'CVE-2026-107891', b'CVE-2026-other')):
            changed = self.recipe.replace(original, replacement)
            with self.subTest(original=original), self.assertRaises(ValueError):
                sources.recipe_identity(changed)

    def test_changed_aports_source_and_each_context_file_are_rejected(self):
        for url in (sources.APORTS_URL, sources.SOURCE_URL, sources.SOURCE_URL + '.asc'):
            body = self.bodies[url]
            self.bodies[url] += b'changed'
            with self.subTest(url=url), tempfile.TemporaryDirectory() as root, self.assertRaisesRegex(ValueError, 'checksum'):
                self.collect(root)
            self.bodies[url] = body
        for name in self.context_bodies:
            changed = self.make_recipes(replacements={name: self.context_bodies[name] + b'changed'})
            with self.subTest(context=name), patch.object(sources, 'APORTS_SHA256', hashlib.sha256(changed).hexdigest()):
                self.bodies[sources.APORTS_URL] = changed
                self.package_spec = sources.reviewed_spec()
                with tempfile.TemporaryDirectory() as root, self.assertRaisesRegex(ValueError, 'checksum'):
                    self.collect(root)

    def test_recipe_checksum_is_checked_independently_of_context_archive(self):
        changed = self.make_recipes(recipe=self.recipe + b'# changed recipe\n')
        self.bodies[sources.APORTS_URL] = changed
        with patch.object(sources, 'APORTS_SHA256', hashlib.sha256(changed).hexdigest()):
            self.package_spec = sources.reviewed_spec()
            with tempfile.TemporaryDirectory() as root, self.assertRaisesRegex(ValueError, 'checksum'):
                self.collect(root)

    def test_patch_upstream_commit_is_checked_after_all_hashes_are_repinned(self):
        changed_patch = self.patch_body.replace(sources.UPSTREAM_COMMIT.encode(), b'0' * 40)
        context = copy.deepcopy(sources.CONTEXT_FILES)
        context['CVE-2026-107891.patch'] = {
            **context['CVE-2026-107891.patch'], 'sha256': hashlib.sha256(changed_patch).hexdigest(),
            'sha512': hashlib.sha512(changed_patch).hexdigest()}
        with patch.object(sources, 'PATCH_SHA256', hashlib.sha256(changed_patch).hexdigest()), \
                patch.object(sources, 'PATCH_SHA512', hashlib.sha512(changed_patch).hexdigest()), \
                patch.object(sources, 'CONTEXT_FILES', context):
            recipe = self.make_recipe()
            recipes = self.make_recipes(recipe=recipe, replacements={'CVE-2026-107891.patch': changed_patch})
            self.bodies[sources.APORTS_URL] = recipes
            with patch.object(sources, 'APKBUILD_SHA256', hashlib.sha256(recipe).hexdigest()), \
                    patch.object(sources, 'APORTS_SHA256', hashlib.sha256(recipes).hexdigest()):
                self.package_spec = sources.reviewed_spec()
                with tempfile.TemporaryDirectory() as root, self.assertRaisesRegex(ValueError, 'upstream.*identity|upstream.*commit'):
                    self.collect(root)

    def rebind_source(self, body):
        self.bodies[sources.SOURCE_URL] = body
        self.stack.enter_context(patch.object(sources, 'SOURCE_SHA256', hashlib.sha256(body).hexdigest()))
        self.stack.enter_context(patch.object(sources, 'SOURCE_SHA512', hashlib.sha512(body).hexdigest()))
        self.recipe = self.make_recipe()
        self.recipes = self.make_recipes()
        self.bodies[sources.APORTS_URL] = self.recipes
        self.stack.enter_context(patch.object(sources, 'APKBUILD_SHA256', hashlib.sha256(self.recipe).hexdigest()))
        self.stack.enter_context(patch.object(sources, 'APORTS_SHA256', hashlib.sha256(self.recipes).hexdigest()))
        self.package_spec = sources.reviewed_spec()

    def test_copyright_hash_is_independent_of_outer_source_checksum(self):
        with patch.object(sources, 'COPYRIGHT_SHA256', '0' * 64):
            self.package_spec = sources.reviewed_spec()
            with tempfile.TemporaryDirectory() as root, self.assertRaisesRegex(ValueError, 'checksum'):
                self.collect(root)

    def test_attribution_hash_is_independent_of_outer_source_checksum(self):
        selected = next(iter(self.attribution_bodies))
        changed = archive([('musl-1.2.6/COPYRIGHT', self.copyright_body),
                           *[(self.source_path(path), body + b'changed' if path == selected else body)
                             for path, body in self.attribution_bodies.items()]])
        self.rebind_source(changed)
        with tempfile.TemporaryDirectory() as root, self.assertRaisesRegex(ValueError, 'checksum'):
            self.collect(root)

    def test_missing_attribution_source_is_rejected(self):
        selected = next(iter(self.attribution_bodies))
        changed = archive([('musl-1.2.6/COPYRIGHT', self.copyright_body),
                           *[(self.source_path(path), body) for path, body in self.attribution_bodies.items()
                             if path != selected]])
        self.rebind_source(changed)
        with tempfile.TemporaryDirectory() as root, self.assertRaises(ValueError):
            self.collect(root)

    def test_offline_notice_import_retains_all_twelve_complete_legal_texts(self):
        scripts = str(Path(__file__).resolve().parents[1] / 'scripts')
        with patch.object(sys, 'path', [scripts, *sys.path]), \
                patch.dict(sys.modules, {'alpine_musl_sources': sources}):
            from package_source_notices import import_public_notices, leading_notice
            for arch in sources.ARCHES:
                with self.subTest(architecture=arch), tempfile.TemporaryDirectory() as root:
                    retained, output = Path(root) / 'retained', Path(root) / 'notices'
                    self.collect(retained, arch)
                    result = import_public_notices(retained, output, origin='musl', architecture=arch,
                                                   package_spec=self.package_spec)
                    self.assertTrue(result['success'])
                    self.assertIs(result['provider_oci_binding'], False)
                    self.assertIsNone(result['source_image_digest'])
                    self.assertEqual(len(result['notices']), 12)
                    actual = {(output / row['notice_file']).read_bytes() for row in result['notices']}
                    expected = {self.copyright_body,
                                *(leading_notice(body, complete_file=True)
                                  for body in self.attribution_bodies.values())}
                    self.assertEqual(actual, expected)

    def test_offline_notice_import_rejects_tampered_or_missing_attribution(self):
        scripts = str(Path(__file__).resolve().parents[1] / 'scripts')
        with patch.object(sys, 'path', [scripts, *sys.path]), \
                patch.dict(sys.modules, {'alpine_musl_sources': sources}):
            from package_source_notices import import_public_notices
            for missing in (False, True):
                with self.subTest(missing=missing), tempfile.TemporaryDirectory() as root:
                    retained, output = Path(root) / 'retained', Path(root) / 'notices'
                    manifest = self.collect(retained)
                    row = next(row for row in manifest['files']
                               if row['role'] == 'upstream-permissive-attribution-source')
                    path = retained / row['path']
                    if missing:
                        path.unlink()
                    else:
                        path.write_bytes(b'unreviewed license attribution')
                    with self.assertRaises((ValueError, FileNotFoundError)):
                        import_public_notices(retained, output, origin='musl', architecture='amd64',
                                              package_spec=self.package_spec)


if __name__ == '__main__':
    unittest.main()
