"""Corresponding sources stay bound to the original package build identity."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location(
    "alpine_distribution_sources", Path(__file__).resolve().parents[1] / "scripts/alpine_distribution_sources.py")
sources = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sources)


def archive(entries):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as package:
        for name, body in entries:
            member = tarfile.TarInfo(name)
            member.size = len(body)
            package.addfile(member, io.BytesIO(body))
    return stream.getvalue()


def pkginfo(name, arch="x86_64", commit=sources.BUILD_COMMIT):
    return (f"pkgname = {name}\npkgver = 2.8.4-r0\norigin = expat\n"
            f"arch = {arch}\ncommit = {commit}\nlicense = MIT\n").encode()


class AlpineDistributionSourceTests(unittest.TestCase):
    def fixture(self, arch="x86_64"):
        upstream = archive([("expat-2.8.4/COPYING", b"MIT copyright and conditions"),
                            ("expat-2.8.4/expat/lib/xmlparse.c", b"preferred source")])
        checksum = hashlib.sha512(upstream).hexdigest()
        recipe = ("pkgname=expat\npkgver=2.8.4\npkgrel=0\n"
                  'source="https://github.com/libexpat/libexpat/releases/download/$_tagver/expat-$pkgver.tar.xz"\n'
                  f'sha512sums="\n{checksum}  expat-2.8.4.tar.xz\n"\n'
                  "build() { ./configure --enable-static; make; }\n").encode()
        recipes = archive([(f"aports-{sources.BUILD_COMMIT}/main/expat/APKBUILD", recipe),
                           (f"aports-{sources.BUILD_COMMIT}/main/expat/retained.patch", b"build patch")])
        bodies = {sources.SOURCE_URL: upstream, sources.APORTS_URL: recipes}
        dependencies = []
        for name in ("expat", "libexpat"):
            url = f"https://dl-cdn.alpinelinux.org/alpine/v3.24/main/{arch}/{name}-2.8.4-r0.apk"
            bodies[url] = archive([(".PKGINFO", pkginfo(name, arch))])
            dependencies.append({"uri": url, "digest": {"sha256": hashlib.sha256(bodies[url]).hexdigest()}})
        provenance = {"predicate": {"buildDefinition": {"resolvedDependencies": dependencies}}}
        return bodies, provenance, checksum

    def collect(self, bodies, provenance, checksum, root, base_inventory=None):
        with patch.object(sources, "SOURCE_SHA512", checksum), \
                patch.object(sources, "APORTS_SHA256", hashlib.sha256(bodies[sources.APORTS_URL]).hexdigest()), \
                patch.object(sources, "COPYING_SHA256", hashlib.sha256(b"MIT copyright and conditions").hexdigest()):
            return sources.collect_sources(provenance, root, fetch=bodies.__getitem__,
                                           base_inventory=base_inventory)

    def test_both_architectures_retain_whole_recipes_sources_notices_and_package_identity(self):
        for arch in ("x86_64", "aarch64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as directory:
                bodies, provenance, checksum = self.fixture(arch)
                result = self.collect(bodies, provenance, checksum, directory)
                self.assertEqual({row["pkgname"] for row in result["package_inputs"]}, {"expat", "libexpat"})
                self.assertEqual({row["arch"] for row in result["package_inputs"]}, {arch})
                recipe_file = next(row for row in result["files"] if row["role"] == "complete-alpine-build-recipes")
                self.assertEqual((Path(directory) / recipe_file["path"]).read_bytes(), bodies[sources.APORTS_URL])
                for row in result["files"]:
                    body = (Path(directory) / row["path"]).read_bytes()
                    self.assertEqual(hashlib.sha256(body).hexdigest(), row["sha256"])
                self.assertEqual(json.loads((Path(directory) / "manifest.json").read_text()), result)

    def test_changed_apk_bytes_do_not_get_a_completed_manifest(self):
        bodies, provenance, checksum = self.fixture()
        url = provenance["predicate"]["buildDefinition"]["resolvedDependencies"][0]["uri"]
        bodies[url] += b"replacement"
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "APK sha256 checksum"):
                self.collect(bodies, provenance, checksum, directory)
            self.assertFalse((Path(directory) / "manifest.json").exists())

    def test_another_build_commit_cannot_be_substituted_even_with_a_matching_download_hash(self):
        bodies, provenance, checksum = self.fixture()
        dependency = provenance["predicate"]["buildDefinition"]["resolvedDependencies"][0]
        bodies[dependency["uri"]] = archive([(".PKGINFO", pkginfo("expat", commit="f" * 40))])
        dependency["digest"]["sha256"] = hashlib.sha256(bodies[dependency["uri"]]).hexdigest()
        with tempfile.TemporaryDirectory() as directory, self.assertRaisesRegex(ValueError, "package identity mismatch"):
            self.collect(bodies, provenance, checksum, directory)

    def test_wrong_or_missing_source_provenance_is_rejected(self):
        bodies, provenance, checksum = self.fixture()
        dependencies = provenance["predicate"]["buildDefinition"]["resolvedDependencies"]
        for changed in ([dependencies[0]], [dependencies[0], dependencies[0]],
                        [{**row, "uri": row["uri"].replace("2.8.4", "2.8.5")} for row in dependencies]):
            with self.subTest(dependencies=changed), tempfile.TemporaryDirectory() as directory:
                bad = {"predicate": {"buildDefinition": {"resolvedDependencies": changed}}}
                with self.assertRaisesRegex(ValueError, "original expat APKs"):
                    self.collect(bodies, bad, checksum, directory)

    def test_upstream_source_is_checked_against_the_build_recipe(self):
        bodies, provenance, checksum = self.fixture()
        bodies[sources.SOURCE_URL] += b"modified source"
        with tempfile.TemporaryDirectory() as directory, self.assertRaisesRegex(ValueError, "source sha512 checksum"):
            self.collect(bodies, provenance, checksum, directory)

    def test_source_commands_are_not_evaluated_or_accepted_as_another_source(self):
        bodies, _, checksum = self.fixture()
        recipe = sources.read_member(bodies[sources.APORTS_URL],
                                     f"aports-{sources.BUILD_COMMIT}/main/expat/APKBUILD").decode()
        hostile = recipe.replace("expat-$pkgver.tar.xz", "$(touch /tmp/unsafe).tar.xz")
        with patch.object(sources, "SOURCE_SHA512", checksum), self.assertRaisesRegex(ValueError, "source declaration"):
            sources.recipe_identity(hostile)

    def test_duplicate_and_unsafe_archive_entries_are_rejected(self):
        for body, message in [(archive([("entry", b"one"), ("entry", b"two")]), "exactly one"),
                              (archive([("../unsafe", b"escape"), ("entry", b"ok")]), "Unsafe")]:
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                sources.read_member(body, "entry")

    def test_another_recipe_snapshot_is_rejected(self):
        bodies, provenance, checksum = self.fixture()
        with tempfile.TemporaryDirectory() as directory, patch.object(sources, "APORTS_SHA256", "0" * 64):
            with self.assertRaisesRegex(ValueError, "recipe archive sha256 checksum"):
                sources.collect_sources(provenance, directory, fetch=bodies.__getitem__)

    def test_original_base_inventory_avoids_unavailable_binary_mirrors(self):
        bodies, provenance, checksum = self.fixture("aarch64")
        for dependency in provenance["predicate"]["buildDefinition"]["resolvedDependencies"]:
            del bodies[dependency["uri"]]
        inventory = {"os_packages": [{"name": name, "version": "2.8.4-r0", "origin": "expat",
                                      "build_commit": sources.BUILD_COMMIT}
                                     for name in ("expat", "libexpat")]}
        with tempfile.TemporaryDirectory() as directory:
            result = self.collect(bodies, provenance, checksum, directory, inventory)
            self.assertEqual({row["arch"] for row in result["package_inputs"]}, {"aarch64"})
            self.assertTrue(all("apk_sha256" in row for row in result["package_inputs"]))
            metadata = Path(directory) / "original-base-expat-inventory.json"
            self.assertEqual(json.loads(metadata.read_text()), inventory)
            self.assertFalse(any(row["role"] == "original-base-binary-evidence" for row in result["files"]))

    def test_another_version_or_build_in_base_inventory_is_rejected(self):
        bodies, provenance, checksum = self.fixture()
        for field, value in (("version", "2.8.5-r0"), ("origin", "other"), ("build_commit", "f" * 40)):
            inventory = {"os_packages": [{"name": name, "version": "2.8.4-r0", "origin": "expat",
                                          "build_commit": sources.BUILD_COMMIT}
                                         for name in ("expat", "libexpat")]}
            inventory["os_packages"][0][field] = value
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                with self.assertRaisesRegex(ValueError, "base inventory identity mismatch"):
                    self.collect(bodies, provenance, checksum, directory, inventory)


if __name__ == "__main__":
    unittest.main()
