# Image security

The portable runtime uses the digest-pinned Docker Hardened Python base in
Dockerfile. The build removes installation tools, runs as UID 10001, applies
the reviewed upstream Python fixes and separately identified Keep hardening in
scripts/python_security_patches.json, and
builds checksum-pinned zlib 1.3.2 with the exact upstream commit hunk that fixes
CVE-2026-85091.

Every architecture job verifies signed vendor provenance, runs Docker Scout and
an unsuppressed Grype scan, and executes all nine runtime regression probes.
Scout must report zero findings. Grype permits only the verified-fixed
findings recorded in docs/image-exceptions.json; every other finding blocks release.
Source hashes, base identity, successful probes and the October 7, 2026 review
expiry are enforced by scripts/review_image.py. Full raw JSON reports are printed
in the workflow logs under each architecture's security-evidence groups and saved
with the tested image in an unpublished main-validation draft. A small immutable
Actions index binds the original reports to their producing run and attempt,
independently of log retention. Large evidence and source archives stay out of
Actions artifact storage.
The checksum-verified Scout executable also captures
the final image's complete SPDX SBOM as `candidate-sbom-<architecture>.json`.
The existing evidence reporter retains it alongside scans. License inventory
review remains a separate release gate; an SBOM or a zero-CVE report alone does
not establish redistribution compliance or image-layer privacy.
Native jobs also inventory installed license texts and package build metadata,
and inspect every exported layer (including overwritten/deleted files) against
its config diff ID. Known credential/private-file findings block the job; exact
reviewed synthetic examples remain visible in its evidence. See
[source distribution](SOURCE_DISTRIBUTION.md) for matching-source delivery
requirements. Layer heuristics do not certify arbitrary
secrets absent. Build-generated dependency bytecode is omitted; runtime source
and notices remain, with bytecode writes already disabled by the runtime environment.
The pinned Python base's Expat 2.8.4 package is affected by
CVE-2026-93990. The image upgrades Expat and libexpat to Alpine's signed
2.8.5-r0 packages during the build. BuildKit mounts the temporary package manager
and its library read-only; neither tool is copied into any final image layer.
The Python base's exact signed provenance check remains in place. The
unsuppressed Scout and Grype scans still block any new finding; no Expat
exception was added.
Native jobs acquire corresponding package sources and original signature
evidence, verify the actual runtime package identities, and package versioned
source/notice archives with SHA-256 manifests before transferring an image.
The original Expat layer, runtime security patches and statically embedded wheel
libraries are included. Full OS and supplemental notices are also copied into
the image. See [source distribution](SOURCE_DISTRIBUTION.md) for matching
source downloads, verification, and retention requirements.

Tested main images remain in unpublished candidate storage until approved manual
publication restores them. Publication verifies successful original native jobs,
image configurations, retained evidence hashes and the original reports against
the current review policy and expiry, without rebuilding or rerunning scanners.
Approved images then pass through temporary run-and-attempt-specific registry tags;
the publication job receives immutable digests, validates source/runtime identity,
and promotes stable only after both architecture jobs succeed. After publication,
CI attempts to remove only its temporary tags, not their shared image manifests. If the CI
token lacks delete permission, it emits an explicit cleanup warning; the operator
removes those exact tags using the host's separate retention credential after
verifying their digests. Never broaden the CI token merely for tag cleanup.
A passing gate is not a guarantee of no undiscovered
vulnerabilities.

For a release, review the successful native workflow for its exact source revision
and image digests. The exception policy, patch inputs and regression checks are
tracked in this repository; results for an older image do not validate a newer
candidate.

## Directory cleanup

The runtime applies the exact Python 3.14 backport hunks from
[commit 363aec1](https://github.com/python/cpython/commit/363aec1fd31ecbd92c3c7d0a40af4e90b4613e19)
to `shutil.py` and `tempfile.py` for CVE-2026-12345. The new probe exercises
permission recovery while a fixture directory is replaced with a symbolic link,
then checks that the sibling fixture retains its contents, inode and permissions.
The original eight probes remain required. Use of this pinned backport requires
review against the actual native candidate evidence and the current upstream
advisory; the pinned commit alone does not establish upstream acceptance.

Keep also applies its separately identified `keep-tempfile-bound-permission-reset-v1`
guard. Permission recovery requires an open directory descriptor and a safe
non-following operation. It raises instead of falling back to pathname permission
changes when that operation is unavailable or fails. Unreadable entries or a
permission-denied root can therefore leave cleanup incomplete; ordinary cleanup
continues to work. The probe verifies these boundaries against disposable fixtures.

The narrow scanner rule for this package still requires successful regression
evidence on both native architectures, the exact reviewed source hashes and the
existing review expiry. A local probe alone does not validate a rebuilt release.
