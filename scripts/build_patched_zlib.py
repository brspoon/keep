"""Build the exact upstream zlib fix used by the runtime image."""
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request


COMMIT = "df84af25dc1942490e1d1c899a07619152a46148"
ARCHIVE_SHA256 = "b99a0b86c0ba9360ec7e78c4f1e43b1cbdf1e6936c8fa0f6835c0cd694a495a1"
URL = "https://github.com/madler/zlib/archive/refs/tags/v1.3.2.tar.gz"
VULNERABLE_SOURCE = """            if (ret == -1)
                return state->again ? put - len : 0;
"""
FIXED_SOURCE = """            if (ret == -1) {
                state->strm.avail_in = 0;
                state->strm.next_in = state->in;
                return state->again ? put - len : 0;
            }
"""
SOURCES = (
    "adler32", "crc32", "deflate", "infback", "inffast", "inflate",
    "inftrees", "trees", "zutil", "compress", "uncompr", "gzclose",
    "gzlib", "gzread", "gzwrite",
)


def checked_source(body):
    digest = hashlib.sha256(body).hexdigest()
    if digest != ARCHIVE_SHA256:
        raise RuntimeError("zlib source archive checksum mismatch")
    return digest


def main():
    with urllib.request.urlopen(URL, timeout=60) as response:
        body = response.read()
    archive_digest = checked_source(body)
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        with tarfile.open(fileobj=io.BytesIO(body), mode="r:gz") as archive:
            archive.extractall(root, filter="data")
        source = root / "zlib-1.3.2"
        gzwrite_path = source / "gzwrite.c"
        gzwrite = gzwrite_path.read_text()
        if gzwrite.count(VULNERABLE_SOURCE) != 1 or FIXED_SOURCE in gzwrite:
            raise RuntimeError("zlib 1.3.2 security patch context mismatch")
        gzwrite_path.write_text(gzwrite.replace(VULNERABLE_SOURCE, FIXED_SOURCE, 1))
        if gzwrite_path.read_text().count(FIXED_SOURCE) != 1:
            raise RuntimeError("upstream zlib security fix was not applied exactly")
        subprocess.run(["./configure", "--prefix=/opt/zlib"], cwd=source, check=True)
        objects = []
        for name in SOURCES:
            target = root / f"{name}.o"
            subprocess.run(
                ["gcc", "-O3", "-fPIC", "-DPIC", "-I", str(source),
                 "-c", str(source / f"{name}.c"), "-o", str(target)],
                check=True,
            )
            objects.append(str(target))
        built_library = root / "libz.so.1.3.2"
        subprocess.run(
            ["gcc", "-shared", "-Wl,-soname,libz.so.1",
             f"-Wl,--version-script,{source / 'zlib.map'}", "-O3", "-fPIC",
             "-o", str(built_library), *objects, "-lc"],
            check=True,
        )
        (root / "libz.so.1").symlink_to(built_library.name)
        test_env = {**os.environ, "LD_LIBRARY_PATH": str(root)}
        for name in ("example", "minigzip"):
            subprocess.run(
                ["gcc", "-O3", "-I", str(source),
                 str(source / "test" / f"{name}.c"), str(built_library),
                 "-o", str(root / name)],
                check=True,
            )
        example_target = root / "example-output"
        subprocess.run([str(root / "example"), str(example_target)], env=test_env, check=True)
        compressed = subprocess.run(
            [str(root / "minigzip")], input=b"hello world\n",
            env=test_env, check=True, stdout=subprocess.PIPE,
        ).stdout
        expanded = subprocess.run(
            [str(root / "minigzip"), "-d"], input=compressed,
            env=test_env, check=True, stdout=subprocess.PIPE,
        ).stdout
        if expanded != b"hello world\n":
            raise RuntimeError("patched zlib shared-library round trip failed")
        install_root = Path("/opt/zlib")
        (install_root / "lib").mkdir(parents=True, exist_ok=True)
        library = install_root / "lib/libz.so.1.3.2"
        shutil.copy2(built_library, library)
        library.chmod(0o755)
        if not library.is_file() or library.is_symlink():
            raise RuntimeError("patched zlib shared library was not installed")
        manifest = {
            "archive_sha256": archive_digest,
            "library_sha256": hashlib.sha256(library.read_bytes()).hexdigest(),
            "upstream_commit": COMMIT,
            "version": "1.3.2",
        }
        Path("/opt/zlib/ZLIB_SECURITY.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n"
        )
        shutil.copy2(source / "LICENSE", install_root / "ZLIB_LICENSE.txt")


if __name__ == "__main__":
    main()
