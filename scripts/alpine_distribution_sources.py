#!/usr/bin/env python3
"""Retain matching Alpine expat inputs from verified base-image provenance.

The original base layers contain Alpine's 2.8.4 binaries even after Keep's
upgrade to DHI's 2.8.5 packages. This collector covers the original Alpine
binaries only; the DHI upgrade needs its own provider source/build materials.
Recipes are retained as data. No APKBUILD or downloaded source is executed.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import tarfile
import urllib.request


BUILD_COMMIT = "08d1eb8641965d3807628f6a4ff15914be5b79ae"
APORTS_URL = f"https://github.com/alpinelinux/aports/archive/{BUILD_COMMIT}.tar.gz"
APORTS_SHA256 = "407881de4122a383ee3deec54f4fa18bd55f63282d366bfec0ad128f6cf7f2b6"
SOURCE_URL = "https://github.com/libexpat/libexpat/releases/download/R_2_8_4/expat-2.8.4.tar.xz"
SOURCE_SHA512 = ("00a34340b4fdc3baee6dbd83df3e41710ebffb38dc23664406be187a73f1e948"
                 "451568fea07b6f33532b6b6244650808ce157255bcf6216d98267535cc97f3cd")
COPYING_SHA256 = "31b15de82aa19a845156169a17a5488bf597e561b2c318d159ed583139b25e87"
APK_URL = re.compile(
    r"https://dl-cdn\.alpinelinux\.org/alpine/v3\.24/main/"
    r"(?P<arch>x86_64|aarch64)/(?P<name>expat|libexpat)-2\.8\.4-r0\.apk\Z")


def download(url):
    with urllib.request.urlopen(url, timeout=60) as response:
        return response.read()


def checked(body, algorithm, expected, label):
    if hashlib.new(algorithm, body).hexdigest() != expected:
        raise ValueError(f"{label} {algorithm} checksum mismatch")
    return body


def read_member(body, name):
    """Read one regular archive entry, rejecting ambiguous or unsafe paths."""
    with tarfile.open(fileobj=io.BytesIO(body), mode="r:*") as archive:
        matches = []
        for member in archive:
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts:
                raise ValueError("Unsafe source archive path")
            if member.name == name:
                if not member.isfile():
                    raise ValueError("Expected a regular source archive entry")
                matches.append(member)
        if len(matches) != 1:
            raise ValueError(f"Expected exactly one archive entry: {name}")
        return archive.extractfile(matches[0]).read()


def package_identity(body, name, arch):
    text = read_member(body, ".PKGINFO").decode("utf-8")
    fields = {}
    for line in text.splitlines():
        if " = " in line:
            key, value = line.split(" = ", 1)
            # Dependencies may repeat. Identity fields may not.
            if key in fields and key in {"pkgname", "pkgver", "origin", "arch", "commit"}:
                raise ValueError("Duplicate package identity field")
            fields[key] = value
    expected = {"pkgname": name, "pkgver": "2.8.4-r0", "origin": "expat",
                "arch": arch, "commit": BUILD_COMMIT}
    if any(fields.get(key) != value for key, value in expected.items()):
        raise ValueError("Original Alpine expat package identity mismatch")
    return text, expected


def recipe_identity(recipe):
    """Check exact release/source declarations without evaluating shell text."""
    declarations = {"pkgname": "expat", "pkgver": "2.8.4", "pkgrel": "0"}
    for key, expected in declarations.items():
        if re.findall(rf"^{key}=([^\n]+)$", recipe, re.M) != [expected]:
            raise ValueError("Alpine expat recipe identity mismatch")
    source_declaration = ('source="https://github.com/libexpat/libexpat/releases/'
                          'download/$_tagver/expat-$pkgver.tar.xz"')
    if recipe.splitlines().count(source_declaration) != 1:
        raise ValueError("Alpine expat source declaration changed")
    blocks = re.findall(r'^sha512sums="\n([^"\n]+)\n"$', recipe, re.M)
    if len(blocks) != 1:
        raise ValueError("Expected one exact expat source checksum")
    if blocks[0] != SOURCE_SHA512 + "  expat-2.8.4.tar.xz":
        raise ValueError("Alpine expat recipe source checksum mismatch")


def collect_sources(provenance, output_root, fetch=download, base_inventory=None):
    """Bind original APKs, their whole recipe snapshot, source and notice bytes."""
    predicate = provenance.get("predicate", {})
    dependencies = predicate.get("buildDefinition", {}).get("resolvedDependencies", [])
    packages = []
    for dependency in dependencies:
        url = dependency.get("uri", "")
        match = APK_URL.fullmatch(url)
        if match:
            checksum = dependency.get("digest", {}).get("sha256", "")
            if not re.fullmatch(r"[a-f0-9]{64}", checksum):
                raise ValueError("Original expat APK is missing its provenance digest")
            packages.append((url, checksum, match["name"], match["arch"]))
    identities = {(name, arch) for _, _, name, arch in packages}
    if len(packages) != 2 or len(identities) != 2 or len({arch for _, arch in identities}) != 1:
        raise ValueError("Require exactly both original expat APKs for one architecture")
    if {name for name, _ in identities} != {"expat", "libexpat"}:
        raise ValueError("Require expat and libexpat from the base provenance")
    root = Path(output_root)
    root.mkdir(parents=True, exist_ok=True)
    records = []

    def retain(name, body, url, role):
        target = root / name
        target.write_bytes(body)
        item = {"path": name, "sha256": hashlib.sha256(body).hexdigest(),
                "bytes": len(body), "url": url, "role": role}
        records.append(item)
        return item

    binary_inputs = []
    if base_inventory is not None:
        # Capture this inventory from the exact native base whose signatures,
        # index membership and provenance were checked by the calling workflow.
        # Archived binaries may have disappeared from an upstream mirror; their
        # signed digests and installed build metadata still bind the sources.
        rows = [row for row in base_inventory.get("os_packages", [])
                if row.get("name") in {"expat", "libexpat"}]
        if len(rows) != 2 or {row.get("name") for row in rows} != {"expat", "libexpat"}:
            raise ValueError("Require both original expat packages in the base inventory")
        for row in rows:
            if (row.get("version") != "2.8.4-r0" or row.get("origin") != "expat" or
                    row.get("build_commit") != BUILD_COMMIT):
                raise ValueError("Original Alpine expat base inventory identity mismatch")
        metadata = retain("original-base-expat-inventory.json",
                          (json.dumps(base_inventory, indent=2) + "\n").encode(),
                          "verified-native-base:/lib/apk/db/installed", "package-build-identity")
        for url, checksum, name, arch in sorted(packages):
            binary_inputs.append({"pkgname": name, "pkgver": "2.8.4-r0", "origin": "expat",
                                  "arch": arch, "commit": BUILD_COMMIT, "url": url,
                                  "apk_sha256": checksum, "metadata": metadata["path"]})
    else:
        for url, checksum, name, arch in sorted(packages):
            body = checked(fetch(url), "sha256", checksum, name + " APK")
            pkginfo, identity = package_identity(body, name, arch)
            filename = f"{name}-2.8.4-r0-{arch}.apk"
            binary = retain(filename, body, url, "original-base-binary-evidence")
            metadata = retain(filename + ".PKGINFO", pkginfo.encode(), url, "package-build-identity")
            binary_inputs.append({**identity, "apk": binary["path"],
                                  "apk_sha256": checksum, "metadata": metadata["path"]})

    recipes = checked(fetch(APORTS_URL), "sha256", APORTS_SHA256, "Alpine recipe archive")
    recipe_path = f"aports-{BUILD_COMMIT}/main/expat/APKBUILD"
    recipe = read_member(recipes, recipe_path)
    recipe_identity(recipe.decode("utf-8"))
    retain(f"aports-{BUILD_COMMIT}.tar.gz", recipes, APORTS_URL, "complete-alpine-build-recipes")
    retain("expat-2.8.4-APKBUILD", recipe,
           f"https://raw.githubusercontent.com/alpinelinux/aports/{BUILD_COMMIT}/main/expat/APKBUILD",
           "matching-apk-build-script")
    source = checked(fetch(SOURCE_URL), "sha512", SOURCE_SHA512, "expat source")
    retain("expat-2.8.4.tar.xz", source, SOURCE_URL, "upstream-source")
    copying = checked(read_member(source, "expat-2.8.4/COPYING"), "sha256", COPYING_SHA256,
                      "expat notice")
    retain("expat-2.8.4-COPYING", copying, SOURCE_URL, "upstream-notice")
    manifest = {"schema": 1, "origin": "expat", "version": "2.8.4-r0",
                "build_commit": BUILD_COMMIT, "package_inputs": binary_inputs,
                "source_sha512": SOURCE_SHA512, "files": records,
                "coverage": "Original base-layer Alpine binaries; excludes DHI's 2.8.5 upgrade."}
    (root / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provenance", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--base-inventory", type=Path,
                        help="Inventory captured from the verified original native base")
    args = parser.parse_args()
    inventory = json.loads(args.base_inventory.read_text()) if args.base_inventory else None
    manifest = collect_sources(json.loads(args.provenance.read_text()), args.output,
                               base_inventory=inventory)
    print(json.dumps({"origin": manifest["origin"], "version": manifest["version"],
                      "build_commit": manifest["build_commit"], "files": len(manifest["files"])}))


if __name__ == "__main__":
    main()
