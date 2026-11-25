"""Verify the reviewed CPython cookiejar backport in the built image."""
import hashlib
import http.cookiejar
import json
from pathlib import Path
import sysconfig


EXPECTED_SHA256 = "2b82ea24d49f29f750228e29e8f7f1658305da3c50c4cc77b0a3398255be93de"
UPSTREAM_COMMIT = "ac1d49f4fbb33941475c5aa3cb663ab39d64cb73"


def main():
    expected_path = Path(sysconfig.get_path("stdlib")) / "http/cookiejar.py"
    origin = Path(http.cookiejar.__spec__.origin)
    if origin != expected_path or origin.is_symlink():
        raise ValueError("Python imported cookiejar from an unexpected path")
    digest = hashlib.sha256(origin.read_bytes()).hexdigest()
    if digest != EXPECTED_SHA256:
        raise ValueError("Imported cookiejar does not match the reviewed backport")
    print(json.dumps({"path": str(origin), "sha256": digest, "commit": UPSTREAM_COMMIT}))


if __name__ == "__main__":
    main()
