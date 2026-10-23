#!/usr/bin/env python3
"""Retain and install exact signed build-only GNU make and Bash inputs offline."""
import argparse
import io
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import subprocess
import tarfile

if __package__:
    from . import alpine_expat_sources as alpine
    from . import dhi_cpp_packages as cpp
else:
    import alpine_expat_sources as alpine
    import dhi_cpp_packages as cpp

PREPARED_ROOT = Path('/opt/expat-build-tools')
PACKAGES = json.loads(r'''
{
  "make": {
    "version": "4.4.1-r4",
    "build_commit": "9368161bd37f74fb11747ba79197f8480aaca7dc",
    "license": "GPL-3.0-or-later",
    "url": "https://www.gnu.org/software/make",
    "context_path": "aports-9368161bd37f74fb11747ba79197f8480aaca7dc.tar.gz",
    "recipe_url_prefix": "https://raw.githubusercontent.com/alpinelinux/aports/9368161bd37f74fb11747ba79197f8480aaca7dc/main/make",
    "recipe_files": {
      "APKBUILD": {
        "bytes": 1087,
        "sha256": "f0d914d8fd78e99fab1f82b8f002e19ccaa88bf8d4f65986c744490cdf943c1c",
        "target": null,
        "type": "file"
      },
      "getopt-gcc15.patch": {
        "bytes": 1128,
        "sha256": "54a9713fa5ecf7626342d271d389f2483a293322f2fafad8ad206a7db4d83f5d",
        "target": null,
        "type": "file"
      }
    },
    "source_inputs": [
      {
        "path": "aports-9368161bd37f74fb11747ba79197f8480aaca7dc.tar.gz",
        "url": "https://github.com/alpinelinux/aports/archive/9368161bd37f74fb11747ba79197f8480aaca7dc.tar.gz",
        "sha256": "0582cb9a24be86c34028e55fc5b61f1d5873e70e2bfbf486dc0e5b0da450210d",
        "role": "complete-alpine-build-recipes"
      },
      {
        "path": "APKBUILD",
        "url": "https://raw.githubusercontent.com/alpinelinux/aports/9368161bd37f74fb11747ba79197f8480aaca7dc/main/make/APKBUILD",
        "sha256": "f0d914d8fd78e99fab1f82b8f002e19ccaa88bf8d4f65986c744490cdf943c1c",
        "role": "matching-apk-build-script"
      },
      {
        "path": "make-4.4.1.tar.gz",
        "sha256": "dd16fb1d67bfab79a72f5e8390735c49e3e8e70b4945a15ab1f81ddb78658fb3",
        "sha512": "145260cbd6a8226cef3dfef0c8baba31847beaebc7e6b65d39d02715fd4f4cab9b139b6c3772e550088d4f9ae80c6d3ed20b9a7664c693644dfb96b4cb60e67c",
        "url": "https://ftp.gnu.org/gnu/make/make-4.4.1.tar.gz",
        "role": "upstream-source"
      }
    ],
    "notices": [
      {
        "archive": "make-4.4.1.tar.gz",
        "source_path": "make-4.4.1/AUTHORS",
        "path": "notices/AUTHORS",
        "sha256": "602720d79792fc690cc90e36507385299e86279a9947b0d188e90477917c6db7",
        "url": "https://ftp.gnu.org/gnu/make/make-4.4.1.tar.gz"
      },
      {
        "archive": "make-4.4.1.tar.gz",
        "source_path": "make-4.4.1/COPYING",
        "path": "notices/COPYING",
        "sha256": "e79e9c8a0c85d735ff98185918ec94ed7d175efc377012787aebcf3b80f0d90b",
        "url": "https://ftp.gnu.org/gnu/make/make-4.4.1.tar.gz"
      }
    ],
    "binaries": {
      "amd64": {
        "url": "https://dl-cdn.alpinelinux.org/alpine/v3.24/main/x86_64/make-4.4.1-r4.apk",
        "sha256": "a916626a876f64c6b6fb32a6bf0fa93351d09fae0aa7684135642390da647e60",
        "controls": {
          ".PKGINFO": "ee01140d5cc1f2c8a77884d6085540a300e73b69e74573ffb2f8bc50224bd55b"
        },
        "data_sha256": "1c2e7c907027416eaad7e1812822d3acce9addce7a57cfb45f7a308091c4c0d7",
        "payload_sha256": "b095ec2d15c572c7e939555cfbb0718fc10ef208a277b4dc711b7ac0eb8dbaa2",
        "depend": [
          "so:libc.musl-x86_64.so.1"
        ],
        "provides": [
          "cmd:gmake=4.4.1-r4",
          "cmd:make=4.4.1-r4"
        ],
        "replaces": [],
        "install_if": [],
        "triggers": []
      },
      "arm64": {
        "url": "https://dl-cdn.alpinelinux.org/alpine/v3.24/main/aarch64/make-4.4.1-r4.apk",
        "sha256": "0a2c6c3fa0d90b652bbaeac362d1bfe54b75aae57631a6b448826f8b51c85170",
        "controls": {
          ".PKGINFO": "eb8477a4843dc8525345d48106d6dd36b6aa1cfbac08b0638877e05207257783"
        },
        "data_sha256": "089957b2eb357c06fb29c275fdafc70721a2755f7883b6f60c5cac2e3842d314",
        "payload_sha256": "19d7952ba52c7c1630f0580205058729f46ef80ec45a29c5f3e0e88c58327662",
        "depend": [
          "so:libc.musl-aarch64.so.1"
        ],
        "provides": [
          "cmd:gmake=4.4.1-r4",
          "cmd:make=4.4.1-r4"
        ],
        "replaces": [],
        "install_if": [],
        "triggers": []
      }
    }
  },
  "bash": {
    "version": "5.3.9-r1",
    "build_commit": "1522c3193610902d8493f9790a2755c11f21f26d",
    "license": "GPL-3.0-or-later",
    "url": "https://www.gnu.org/software/bash/bash.html",
    "context_path": "aports-1522c3193610902d8493f9790a2755c11f21f26d.tar.gz",
    "recipe_url_prefix": "https://raw.githubusercontent.com/alpinelinux/aports/1522c3193610902d8493f9790a2755c11f21f26d/main/bash",
    "recipe_files": {
      "APKBUILD": {
        "bytes": 4518,
        "sha256": "4dbeb2dcbde454870383a81c79d04a63aed951bc9ec7c3ecdc7e9f251d7a55bb",
        "target": null,
        "type": "file"
      },
      "bash-noinfo.patch": {
        "bytes": 393,
        "sha256": "d821496623974e1930dab5f9c11e82f7d4d92c5d6005a2b28a9da62bc6a0699d",
        "target": null,
        "type": "file"
      },
      "bash.post-install": {
        "bytes": 39,
        "sha256": "8d3f6002c8da057110c04bb8e823d2a90e555df1cec438833cd1768ef293bbf8",
        "target": null,
        "type": "file"
      },
      "bash.post-upgrade": {
        "bytes": null,
        "sha256": null,
        "target": "bash.post-install",
        "type": "symlink"
      },
      "bash.pre-deinstall": {
        "bytes": 42,
        "sha256": "c704907faf0ff83d5e6625bb8b1adbc7334eee9f0e78f76dd482aa7104507fa6",
        "target": null,
        "type": "file"
      },
      "bashrc": {
        "bytes": 265,
        "sha256": "ff75bd25a858d543a9a42089dccabcd2e27778e786b4bcb35ae2a376201fef03",
        "target": null,
        "type": "file"
      },
      "profile-bashrc.sh": {
        "bytes": 402,
        "sha256": "92995ce139ad668bf9e70b9246cee6cdd080942d9a13fdcfbbe1cdaaacdfd9a8",
        "target": null,
        "type": "file"
      }
    },
    "source_inputs": [
      {
        "path": "aports-1522c3193610902d8493f9790a2755c11f21f26d.tar.gz",
        "url": "https://github.com/alpinelinux/aports/archive/1522c3193610902d8493f9790a2755c11f21f26d.tar.gz",
        "sha256": "2650f18e000b4ca9b997b6867c8ff98d89712873143cc5255983d0eb6ad426a3",
        "role": "complete-alpine-build-recipes"
      },
      {
        "path": "APKBUILD",
        "url": "https://raw.githubusercontent.com/alpinelinux/aports/1522c3193610902d8493f9790a2755c11f21f26d/main/bash/APKBUILD",
        "sha256": "4dbeb2dcbde454870383a81c79d04a63aed951bc9ec7c3ecdc7e9f251d7a55bb",
        "role": "matching-apk-build-script"
      },
      {
        "path": "bash-5.3-1.tar.gz",
        "sha256": "0d5cd86965f869a26cf64f4b71be7b96f90a3ba8b3d74e27e8e9d9d5550f31ba",
        "sha512": "426702c8b0fb9e0c9956259973ce5b657890fd47f4f807a64febf20077bb48d0b91474ed6e843d2ef277186b46c5fffa79b808da9b48d4ec027d5e2de1b28ed8",
        "url": "https://ftp.gnu.org/gnu/bash/bash-5.3.tar.gz",
        "role": "upstream-source"
      },
      {
        "path": "bash53-001",
        "sha256": "1f608434364af86b9b45c8b0ea3fb3b165fb830d27697e6cdfc7ac17dee3287f",
        "sha512": "66d0987f1a8951974c3a707a1980ef391a1f2a2938f0fa46adb77fcdcef6a3ca49e67182b9640ece3e59bb289e5b4a17eb870aa2a525a03e829a7be158d020a6",
        "url": "https://ftp.gnu.org/gnu/bash/bash-5.3-patches/bash53-001",
        "role": "matching-source-patch"
      },
      {
        "path": "bash53-002",
        "sha256": "e385548a00130765ec7938a56fbdca52447ab41fabc95a25f19ade527e282001",
        "sha512": "05caea1c1f5a3d27f2aa351c24f324f9d544ded89db4183ae2872e0283dde62dd6166ca4e780304398935b4aa3fb4db77ecf57acd0f0e295d279ffe40b772158",
        "url": "https://ftp.gnu.org/gnu/bash/bash-5.3-patches/bash53-002",
        "role": "matching-source-patch"
      },
      {
        "path": "bash53-003",
        "sha256": "f245d9c7dc3f5a20d84b53d249334747940936f09dc97e1dcb89fc3ab37d60ed",
        "sha512": "3d4004653cb3f2cba984e67b8e7ae54c19351e176b62bb415f88fdd482ae04be063dacf6303c8343ab6c8bf4f2388026c1742ac603a5cd5c330db22a4b76f4cb",
        "url": "https://ftp.gnu.org/gnu/bash/bash-5.3-patches/bash53-003",
        "role": "matching-source-patch"
      },
      {
        "path": "bash53-004",
        "sha256": "9591d245045529f32f0812f94180b9d9ce9023f5a765c039b852e5dfc99747d0",
        "sha512": "d3c7c83ae0742f2a4e1bc96e8fdb3f05c8c0a7e631d3473922ac245f83194925ae443e761269fa6a519298b1123ee4008bcbcdaf9180dff0a0df7fbe5e029bbb",
        "url": "https://ftp.gnu.org/gnu/bash/bash-5.3-patches/bash53-004",
        "role": "matching-source-patch"
      },
      {
        "path": "bash53-005",
        "sha256": "cca1ef52dbbf433bc98e33269b64b2c814028efe2538be1e2c9a377da90bc99d",
        "sha512": "e81b43b084c1e9d59acd174d0792a93053780bdef61e7f4072d90b425d99a3fb7d35ef4c0ab79c4fb24bb6b38a8d9e99aad2fceac6efddf723a2cd123b32f0ea",
        "url": "https://ftp.gnu.org/gnu/bash/bash-5.3-patches/bash53-005",
        "role": "matching-source-patch"
      },
      {
        "path": "bash53-006",
        "sha256": "29119addefed8eff91ae37fd51822c31780ee30d4a28376e96002706c995ff10",
        "sha512": "f7e303405571635e20c26507c46f9ae0a61ea1328fa0492f2eba2095d398f799e62c1dbf0c07b440c290244f2c54186691ef4aaa2d65f2de101f9888386e2391",
        "url": "https://ftp.gnu.org/gnu/bash/bash-5.3-patches/bash53-006",
        "role": "matching-source-patch"
      },
      {
        "path": "bash53-007",
        "sha256": "c0976bbfffa1453c7cfdd62058f206a318568ff2d690f5d4fa048793fa3eb299",
        "sha512": "5f9419b34c759b92a29f25d97e5da3f02603b3138afc11523c7bd304139db0cd02ff82a093cf78a338a7f9d88cb50a880fa6a105be83f8ca85ea8ff7d5c5d80b",
        "url": "https://ftp.gnu.org/gnu/bash/bash-5.3-patches/bash53-007",
        "role": "matching-source-patch"
      },
      {
        "path": "bash53-008",
        "sha256": "097cd723cbfb8907674ac32214063a3fd85282657ec5b4e544d2c0f719653fb4",
        "sha512": "094b7dc2abe6fc41c62494c6b69640fbd8c6bd93e7cde0618504bb8589fc51fec2fb1686b2729c37e430d336d93ec174233d78f23c82026aca49a240a00477c1",
        "url": "https://ftp.gnu.org/gnu/bash/bash-5.3-patches/bash53-008",
        "role": "matching-source-patch"
      },
      {
        "path": "bash53-009",
        "sha256": "eee30fe78a4b0cb2fe20e010e00308899cfc613e0774ebb3c8557a1552f24f8c",
        "sha512": "07f37cee118e510ae58ea408f9d97b942017e1378532d4e3cd5a4d7405994ddadaba5d3ddb4bbda6b375760967faa51add7f46914ba919a27c14e7036f64f3be",
        "url": "https://ftp.gnu.org/gnu/bash/bash-5.3-patches/bash53-009",
        "role": "matching-source-patch"
      }
    ],
    "notices": [
      {
        "archive": "bash-5.3-1.tar.gz",
        "source_path": "bash-5.3/AUTHORS",
        "path": "notices/AUTHORS",
        "sha256": "8ea258e958e649cd29f8094c23e6f58efb83fa0745adb5943d811735a627983a",
        "url": "https://ftp.gnu.org/gnu/bash/bash-5.3.tar.gz"
      },
      {
        "archive": "bash-5.3-1.tar.gz",
        "source_path": "bash-5.3/COPYING",
        "path": "notices/COPYING",
        "sha256": "8ceb4b9ee5adedde47b31e975c1d90c73ad27b6b165a1dcd80c7c545eb65b903",
        "url": "https://ftp.gnu.org/gnu/bash/bash-5.3.tar.gz"
      },
      {
        "archive": "bash-5.3-1.tar.gz",
        "source_path": "bash-5.3/lib/readline/COPYING",
        "path": "notices/lib/readline/COPYING",
        "sha256": "8ceb4b9ee5adedde47b31e975c1d90c73ad27b6b165a1dcd80c7c545eb65b903",
        "url": "https://ftp.gnu.org/gnu/bash/bash-5.3.tar.gz"
      },
      {
        "archive": "bash-5.3-1.tar.gz",
        "source_path": "bash-5.3/examples/shellmath/LICENSE",
        "path": "notices/examples/shellmath/LICENSE",
        "sha256": "5908bd3b6f430bffa4f8a20290eebdd933b62e2213908b83da1230355f3e9c1a",
        "url": "https://ftp.gnu.org/gnu/bash/bash-5.3.tar.gz"
      },
      {
        "archive": "bash-5.3-1.tar.gz",
        "source_path": "bash-5.3/tests/COPYRIGHT",
        "path": "notices/tests/COPYRIGHT",
        "sha256": "e649815d1b6becdc545dda87c91f1b65497ddf6461240b904b2d8511a63476fb",
        "url": "https://ftp.gnu.org/gnu/bash/bash-5.3.tar.gz"
      }
    ],
    "binaries": {
      "amd64": {
        "url": "https://dl-cdn.alpinelinux.org/alpine/v3.24/main/x86_64/bash-5.3.9-r1.apk",
        "sha256": "4ad962f26fb3c68365171233fe61e3c51bbee1cab35e8dc661198233daeab0dd",
        "controls": {
          ".PKGINFO": "88bf03ab7cc3bcd76217845253883da926618a4f668c0cf3bcab359aa247a6f6",
          ".post-install": "8d3f6002c8da057110c04bb8e823d2a90e555df1cec438833cd1768ef293bbf8",
          ".post-upgrade": "8d3f6002c8da057110c04bb8e823d2a90e555df1cec438833cd1768ef293bbf8",
          ".pre-deinstall": "c704907faf0ff83d5e6625bb8b1adbc7334eee9f0e78f76dd482aa7104507fa6"
        },
        "data_sha256": "c42cf7677b39f188f9faeb0ae954f275c1c07a8268afbeec5841b03181012295",
        "payload_sha256": "3f0c4634f5fadf4bf1824e59fde09bad80c2aa8979d4dc58194d8623cf998187",
        "depend": [
          "/bin/sh",
          "so:libc.musl-x86_64.so.1",
          "so:libreadline.so.8"
        ],
        "provides": [
          "cmd:bash=5.3.9-r1"
        ],
        "replaces": [],
        "install_if": [],
        "triggers": []
      },
      "arm64": {
        "url": "https://dl-cdn.alpinelinux.org/alpine/v3.24/main/aarch64/bash-5.3.9-r1.apk",
        "sha256": "95f4f976bdf2f4ca18ff41c32916eb6d7b12a0dae12504d55d04427460d6542f",
        "controls": {
          ".PKGINFO": "9ca10155f6d1ef7da238f101b6af51a0e76b6e145161fb455a68a22410b092fe",
          ".post-install": "8d3f6002c8da057110c04bb8e823d2a90e555df1cec438833cd1768ef293bbf8",
          ".post-upgrade": "8d3f6002c8da057110c04bb8e823d2a90e555df1cec438833cd1768ef293bbf8",
          ".pre-deinstall": "c704907faf0ff83d5e6625bb8b1adbc7334eee9f0e78f76dd482aa7104507fa6"
        },
        "data_sha256": "bfbd96492477bb776613589e4de2bfde5f820473b8e306f78939862edc6cb19a",
        "payload_sha256": "a811af66c1705eec314312e1d1d2c6196e1da62078146e12e1687228a8f408a6",
        "depend": [
          "/bin/sh",
          "so:libc.musl-aarch64.so.1",
          "so:libreadline.so.8"
        ],
        "provides": [
          "cmd:bash=5.3.9-r1"
        ],
        "replaces": [],
        "install_if": [],
        "triggers": []
      }
    }
  }
}
''')
LIMIT = 64 * 1024 * 1024
download = cpp.download
json_bytes = cpp.json_bytes
digest = cpp.digest
checked = cpp.checked
require = cpp.require


def reviewed_spec():
    return {'schema': 'keep-expat-build-tools-v1', 'installation': 'build-only-offline-apk',
            'packages': PACKAGES, 'signing_keys': {arch: {**key,
                'url': 'https://alpinelinux.org/keys/' + key['name']} for arch, key in alpine.KEYS.items()}}


def source_lock_bytes():
    return json_bytes(reviewed_spec())


def source_download_records():
    records = []
    for name, spec in PACKAGES.items():
        records.extend({**row, 'path': name + '/' + row['path']} for row in spec['source_inputs'])
        for arch, package in spec['binaries'].items():
            records.append({'path': name + '/' + arch + '/' + name + '-' + spec['version'] + '.apk',
                            'url': package['url'], 'sha256': package['sha256'], 'role': 'signed-alpine-build-only-apk'})
    records.extend({'path': 'keys/' + row['name'], 'url': 'https://alpinelinux.org/keys/' + row['name'],
                    'sha256': row['sha256'], 'role': 'alpine-signing-key'} for row in alpine.KEYS.values())
    return records


def archive_entries(body):
    """Parse payload links without following them or extracting downloaded paths."""
    entries, total = {}, 0
    with tarfile.open(fileobj=io.BytesIO(body), mode='r:', ignore_zeros=True) as archive:
        for count, member in enumerate(archive, 1):
            name = cpp.safe_name(member.name)
            total += member.size
            require(count <= 10000 and 0 <= member.size <= LIMIT and total <= LIMIT
                    and name not in entries, 'Ambiguous or oversized Expat build-tool archive')
            require(member.isfile() or member.isdir() or member.issym() or member.islnk(),
                    'Unsupported Expat build-tool archive member')
            require(member.uid == 0 and member.gid == 0 and not member.mode & 0o7000,
                    'Unsafe Expat build-tool archive ownership or mode')
            data = archive.extractfile(member).read() if member.isfile() else None
            require(data is None or len(data) == member.size, 'Truncated Expat build-tool member')
            entries[name] = {'member': member, 'body': data}
    for name, entry in entries.items():
        member = entry['member']
        for ancestor in PurePosixPath(name).parents:
            if ancestor.as_posix() in entries:
                require(entries[ancestor.as_posix()]['member'].isdir(), 'Build-tool payload parent is a link')
        if member.islnk():
            link = cpp.safe_name(member.linkname)
            require(link in entries and entries[link]['member'].isfile()
                    and member.mode == entries[link]['member'].mode, 'Build-tool hardlink leaves regular payload')
        if member.issym():
            require(not member.linkname.startswith('/') and '\\' not in member.linkname
                    and '\x00' not in member.linkname, 'Unsafe build-tool symbolic link')
            resolved = posixpath.normpath(posixpath.join(posixpath.dirname(name), member.linkname))
            require(resolved in entries and entries[resolved]['member'].isfile(),
                    'Build-tool symbolic link must target its regular payload')
    return entries


def verify_apk(body, name, architecture, key):
    require(name in PACKAGES and architecture in alpine.ARCHES, 'Unsupported Expat build-tool package')
    spec, signing = PACKAGES[name], alpine.KEYS[architecture]
    expected = spec['binaries'][architecture]
    checked(body, expected['sha256'], 'Expat build-tool APK')
    checked(key, signing['sha256'], 'Expat build-tool signing key')
    parts = alpine.gzip_parts(body)
    signs = archive_entries(parts[0][1])
    signature = '.SIGN.RSA.' + signing['name']
    require(set(signs) == {signature} and signs[signature]['body'] is not None,
            'Expat build-tool APK signing key name differs')
    alpine.verify_rsa(signs[signature]['body'], parts[1][0], key)
    controls = archive_entries(parts[1][1])
    require(set(controls) == set(expected['controls']), 'Expat build-tool APK control scripts differ')
    for path, checksum in expected['controls'].items():
        require(controls[path]['body'] is not None, 'Expat build-tool control must be regular')
        checked(controls[path]['body'], checksum, 'Expat build-tool control ' + path)
    metadata = controls['.PKGINFO']['body']
    fields = cpp.metadata_fields(metadata)
    identity = {'pkgname': name, 'pkgver': spec['version'], 'origin': name,
                'arch': alpine.ARCHES[architecture], 'commit': spec['build_commit'],
                'license': spec['license'], 'url': spec['url'], 'datahash': expected['data_sha256']}
    require(all(fields.get(k) == [v] for k, v in identity.items()), 'Expat build-tool signed identity differs')
    for field in ('depend', 'provides', 'replaces', 'install_if', 'triggers'):
        require(sorted(fields.get(field, [])) == sorted(expected.get(field, [])),
                'Expat build-tool dependencies or provisions differ')
    checked(parts[2][0], expected['data_sha256'], 'Expat build-tool compressed payload')
    payload = archive_entries(parts[2][1])
    checked(json_bytes(cpp.payload_manifest(payload)), expected['payload_sha256'],
            'Expat build-tool complete payload inventory')
    return controls, payload


def verify_source_inputs(name, inputs, root, records):
    spec = PACKAGES[name]
    context = inputs[name + '/' + spec['context_path']]
    prefix = 'aports-' + spec['build_commit'] + '/main/' + name + '/'
    found = {}
    with tarfile.open(fileobj=io.BytesIO(context), mode='r:gz') as archive:
        for member in archive:
            if not member.name.startswith(prefix) or member.isdir():
                continue
            relative = member.name[len(prefix):]
            cpp.safe_name(relative)
            require(relative not in found and (member.isfile() or member.issym()),
                    'Unexpected build-tool recipe context member')
            require(member.size <= 1024 * 1024, 'Oversized build-tool recipe input')
            found[relative] = {'type': 'file' if member.isfile() else 'symlink',
                               'target': member.linkname if member.issym() else None,
                               'body': archive.extractfile(member).read() if member.isfile() else None}
    require(set(found) == set(spec['recipe_files']), 'Incomplete build-tool recipe context')
    for path, expected in spec['recipe_files'].items():
        entry = found[path]
        require(entry['type'] == expected['type'] and entry['target'] == expected['target'],
                'Expat build-tool recipe link identity differs')
        if entry['type'] == 'file':
            require(len(entry['body']) == expected['bytes'], 'Expat build-tool recipe size differs')
            checked(entry['body'], expected['sha256'], 'Expat build-tool complete recipe ' + path)
            alpine.retain(root, records, name + '/recipe/' + path, entry['body'],
                          spec['recipe_url_prefix'] + '/' + path, 'matching-apk-build-script', prefix + path)
        else:
            link = cpp.safe_name(entry['target'])
            require(link in found and found[link]['type'] == 'file', 'Unsafe build-tool recipe link')
            alpine.retain(root, records, name + '/recipe/' + path + '.link.json',
                          json_bytes({'path': path, 'target': link, 'type': 'symlink'}),
                          spec['source_inputs'][0]['url'], 'matching-build-recipe-link', prefix + path)
    require(found['APKBUILD']['body'] == inputs[name + '/APKBUILD'],
            'Build-tool downloaded recipe differs from complete context')
    for notice in spec['notices']:
        body = alpine.read_member(inputs[name + '/' + notice['archive']], notice['source_path'])
        checked(body, notice['sha256'], 'Expat build-tool full license')
        alpine.retain(root, records, name + '/' + notice['path'], body, notice['url'],
                      'upstream-attribution' if notice['source_path'].endswith('/AUTHORS')
                      else 'upstream-notice', notice['source_path'])


def prepare(output, *, architecture=None, fetch=download):
    require(set(PACKAGES) == {'make', 'bash'}, 'Missing reviewed Expat build-tool inputs')
    architectures = list(alpine.ARCHES) if architecture is None else [architecture]
    require(all(arch in alpine.ARCHES for arch in architectures), 'Unsupported Expat build-tool architecture')
    root, records, inputs = cpp.empty_directory(output), [], {}
    for row in source_download_records():
        if row['role'] == 'signed-alpine-build-only-apk' and not any(
                '/' + arch + '/' in row['path'] for arch in architectures):
            continue
        data = checked(fetch(row['url']), row['sha256'], 'Expat retained build-tool input')
        if 'sha512' in row:
            alpine.checked(data, 'sha512', row['sha512'], 'Expat build-tool recipe source integrity')
        inputs[row['path']] = data
        alpine.retain(root, records, row['path'], data, row['url'], row['role'])
    packages = []
    for name, spec in PACKAGES.items():
        verify_source_inputs(name, inputs, root, records)
        for arch in architectures:
            path = name + '/' + arch + '/' + name + '-' + spec['version'] + '.apk'
            controls, _ = verify_apk(inputs[path], name, arch, inputs['keys/' + alpine.KEYS[arch]['name']])
            for control, entry in controls.items():
                alpine.retain(root, records, path + control, entry['body'], spec['binaries'][arch]['url'],
                              'verified-apk-control-not-executed')
            packages.append({'name': name, 'architecture': arch, 'version': spec['version'],
                             'signature_verified': True, 'apk_sha256': spec['binaries'][arch]['sha256']})
    manifest = {'schema': 'keep-expat-prepared-build-tools-v1', 'architectures': architectures,
                'source_manifest_sha256': digest(source_lock_bytes()), 'packages': packages,
                'provider_oci_binding': False, 'binding_method': 'signed-alpine-build-inputs-with-matching-recipe-sources',
                'files': records}
    (root / 'manifest.json').write_bytes(json_bytes(manifest))
    return manifest


def installation_inputs(output, architecture):
    root = Path(output).absolute()
    manifest = json.loads(cpp.regular_bytes(root / 'manifest.json'))
    require(manifest.get('schema') == 'keep-expat-prepared-build-tools-v1'
            and architecture in manifest.get('architectures', [])
            and manifest.get('source_manifest_sha256') == digest(source_lock_bytes()),
            'Expat build-tool prepared identity differs')
    require({p.name for p in (root / 'keys').iterdir()} == {v['name'] for v in alpine.KEYS.values()},
            'Unreviewed Expat build-tool installation key')
    key = cpp.regular_bytes(root / 'keys' / alpine.KEYS[architecture]['name'])
    paths, payloads = [], {}
    for name, spec in PACKAGES.items():
        path = root / name / architecture / (name + '-' + spec['version'] + '.apk')
        controls, payloads[name] = verify_apk(cpp.regular_bytes(path), name, architecture, key)
        for control, entry in controls.items():
            require(cpp.regular_bytes(Path(str(path) + control)) == entry['body'],
                    'Retained Expat build-tool control differs from signed APK')
        paths.append(path)
    return paths, payloads


def installation_manifest(architecture):
    require(architecture in alpine.ARCHES, 'Unsupported Expat build-tool architecture')
    return {'schema': 'keep-expat-build-tool-security-v1', 'architecture': architecture,
            'source_manifest_sha256': digest(source_lock_bytes()), 'package_scripts_executed': False,
            'packages': {name: {'version': spec['version'], 'build_commit': spec['build_commit'],
                **spec['binaries'][architecture]} for name, spec in PACKAGES.items()}}


def verify_installed(architecture, *, prepared_root=PREPARED_ROOT, runtime_root='/'):
    _, payloads = installation_inputs(prepared_root, architecture)
    records = cpp.verify_cohort(architecture, runtime_root)
    for name, payload in payloads.items():
        spec = PACKAGES[name]
        expected = {'P': name, 'V': spec['version'], 'A': alpine.ARCHES[architecture], 'o': name,
                    'c': spec['build_commit'], 'L': spec['license'], 'U': spec['url']}
        require(name in records and all(records[name].get(k) == v for k, v in expected.items()),
                'Installed Expat build-tool identity differs')
        for field, key in (('depend', 'D'), ('provides', 'p'), ('replaces', 'r')):
            require(sorted(records[name].get(key, '').split())
                    == sorted(spec['binaries'][architecture].get(field, [])),
                    'Installed Expat build-tool dependencies or provisions differ')
        cpp.verify_payload_installed(payload, runtime_root)
    return installation_manifest(architecture)


def install(output, *, architecture=None):
    arch = cpp.native_architecture()
    require(architecture is None or architecture == arch, 'Expat build-tool cross-installation is forbidden')
    paths, _ = installation_inputs(output, arch)
    before = cpp.verify_cohort(arch)
    require(not any(name in before for name in PACKAGES), 'Expat build tools must be newly installed')
    subprocess.run(['/sbin/apk', 'add', '--no-network', '--repositories-file', '/dev/null',
                    '--keys-dir', str(Path(output).absolute() / 'keys'), '--no-cache', '--no-scripts',
                    *(str(path) for path in paths)], check=True, timeout=180)
    manifest = verify_installed(arch, prepared_root=output)
    require({name: row for name, row in cpp.installed_records().items() if name not in PACKAGES} == before,
            'Expat build-tool installation changed an existing package')
    environment = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}
    for path, marker in (('/usr/bin/make', 'GNU Make 4.4.1'), ('/bin/bash', 'GNU bash, version 5.3.9')):
        version = subprocess.check_output([path, '--version'], env=environment, text=True, timeout=20)
        require(version.startswith(marker), 'Installed Expat build-tool version differs')
    (Path(output) / 'BUILD_TOOLS_SECURITY.json').write_bytes(json_bytes(manifest))
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--prepare', action='store_true')
    mode.add_argument('--install', action='store_true')
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--architecture', choices=alpine.ARCHES)
    args = parser.parse_args()
    architecture = cpp.native_architecture()
    require(args.architecture is None or args.architecture == architecture,
            'Expat build-tool cross-preparation is forbidden')
    result = prepare(args.output, architecture=architecture) if args.prepare else install(args.output)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
