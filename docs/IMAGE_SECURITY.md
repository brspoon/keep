# Image security

The portable runtime uses the digest-pinned Docker Hardened Python base in
Dockerfile. The build removes installation tools, runs as UID 10001, applies
the reviewed upstream Python fixes and separately identified Keep hardening in
scripts/python_security_patches.json, and
builds checksum-pinned zlib 1.3.2 with the exact upstream commit hunk that fixes
CVE-2026-85091. The patched library replaces `/usr/lib/libz.so.1.3.2`, behind
the runtime's existing `libz.so.1` alias.

Every architecture job verifies signed vendor provenance, runs Docker Scout and
an unsuppressed Grype scan, and executes all nine runtime regression probes.
Scout must report zero findings. Grype permits only the verified-fixed
findings recorded in docs/image-exceptions.json; every other finding blocks release.
Source hashes, base identity, complete scans, successful probes and the deadline
of each exception used by a finding are enforced by scripts/review_image.py.
Full raw JSON reports are printed
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
the current review policy and any needed exception deadlines, without rebuilding
or rerunning scanners. Archive revalidation uses `--check-only`. Aggregation and
final publication read and verify the original report bytes again, then reassess
the verified reports immediately before each native image or manifest push.
This applies the current deadlines even when publication queues or crosses a UTC
date boundary. The original evidence bytes, including the review result, remain
unchanged.
Approved images then pass through temporary run-and-attempt-specific registry tags;
the publication job receives immutable digests, validates source/runtime identity,
and promotes stable only after both architecture jobs succeed. After publication,
CI attempts to remove only its temporary tags, not their shared image manifests. If the CI
token lacks delete permission, it emits an explicit cleanup warning. A maintainer
can remove those exact tags with a separate deletion-capable credential after
verifying their digests and references. Never broaden the CI token merely for tag cleanup.
A passing gate is not a guarantee of no undiscovered
vulnerabilities.

For a release, review the successful native workflow for its exact source revision
and image digests. The exception policy, patch inputs and regression checks are
tracked in this repository; results for an older image do not validate a newer
candidate.

## Exception review deadlines

Each exception records its reviewed scope and evidence in
docs/image-exceptions.json, with `review.approval`, `review.deadline` and
`review.remove_when` describing the inherited approval, deadline and removal
condition. Approval remains limited to the exact
finding ID, severity, package type, package name and installed version, with the
reviewed source hashes, pinned base provenance and all required runtime probes.
Unknown findings and mismatched packages, versions or severities block validation.

The UTC deadline is inclusive: a finding may use its matching exception on that date,
but it blocks validation and promotion afterward. Expiration applies only when a
scanner finding needs the exception. A clean scan with no exceptions or unused
expired exceptions can pass if every other security check passes. This does not
extend an approval or waive provenance, source integrity, scan completeness or
runtime checks. Existing published releases and running installations are
unaffected by these validation deadlines.

Run the dependency-free deadline check from the repository root:

```sh
python3 -B scripts/review_image.py --check-deadlines
```

It warns about every exception that expires within 14 days or has expired, even
if no current finding uses it. Use `--warning-days <days>` to adjust the notice
window. Warnings appear in Actions annotations and the step summary; they do not
fail the command. An invalid policy still fails. Contributor checks run this step
before installing dependencies, and **Review image-exception deadlines** runs
daily and on manual dispatch with read-only repository access, no dependency
installation, registry credentials, image build or publication. These notices
allow reviews to begin ahead of a deadline without blocking a clean candidate.

The existing approvals still end on October 7, 2026. Correcting deadline handling
does not make a candidate that needs those exceptions eligible on October 8.
Such a candidate needs proven dependency replacements or a new explicit security
review before release.

## zlib delivery correction

The previously published image copied the patched zlib library to
`/lib/libz.so.1.3.2`, while Python's normal library lookup continued loading the
vendor file in `/usr/lib`. The original probe opened the patched copy by absolute
path, so it passed without detecting that the application loaded different bytes.
The Dockerfile now replaces `/usr/lib/libz.so.1.3.2` behind the existing SONAME
alias instead.

The strengthened zlib probe remains one of the nine required security checks.
It uses normal `libz.so.1` lookup after importing Python's consumers, verifies the
loaded mappings' file identity and SHA-256 against the build manifest, and rejects
divergent loader candidates. It also checks zlib and gzip round trips and
`binascii.crc32`.

The original retained reports remain unchanged. The supplementary October 5
database scan of each original native image archive reported the same eight
findings, with no ignored findings. Those scans and the original passing probes do not
validate the delivery correction. An isolated amd64 trial passed all nine security
probes and offline web/worker startup, restart and durable-data smoke checks.
These results are supplementary. Native arm64 execution is unavailable in the
current local checks. The corrected final recipe still requires complete native
amd64 and arm64 builds, signed provenance, all nine runtime checks with the
strengthened zlib probe, Scout and Grype scans, matching-source and license
evidence, and installation and recovery checks before release.

Release remains blocked pending that evidence and an explicit review of the
corrected source hashes and any needed exceptions. No exception deadline has
been extended; the existing October 7, 2026 deadlines remain in force.
The runtime correction requires a new release version; the previously published
image cannot be replaced under its immutable version tag.

### October 6 native qualification

Main validation [37479080905](https://github.com/brspoon/keep/actions/runs/37479080905)
built the corrected recipe on native amd64 and arm64. Both images passed all nine
runtime probes, including normal zlib loading, and the application, installation
and recovery checks. Vendor provenance, source hashes and scan completeness
passed before the finding assessment blocked both candidates.

The October 6 Grype database reported 13 new OpenSSL findings across
`libcrypto3`, `libssl3` and `openssl` at `3.5.8-r1`, plus the Werkzeug finding
fixed by `3.1.9`. Scout also reported Expat `CVE-2026-102633` and
`CVE-2026-77214`, requiring `2.9.0-r0`, and the same Werkzeug issue. These findings
are outside the existing approvals. Renewing the eight previously accepted
exceptions cannot qualify these images for publication.

Werkzeug is now pinned to `3.1.9` with matching source records. The documented
newer DHI base contains OpenSSL `3.5.9-r0`, but its signed native identity and
matching sources still require verification. Its Expat `2.8.5-r0` also requires
a verified replacement. Public DHI `2.9.0-r0` package URLs returned HTTP 403;
this does not establish their availability through the authenticated build path.

**Review vendor runtime candidate** is a manual, main-only workflow that checks
the exact documented candidate index, Docker signatures, both native image
subjects and source statements, then tries the signed Expat `2.9.0-r0` packages
on native amd64 and arm64. It retains original vendor evidence and inventories
using the existing scoped registry credential in temporary configuration.
Its result is an assessment, not release approval. A replacement must still
pass complete Keep validation and matching-source/license checks. No exception
deadline or finding scope has changed.

## Replacing patched dependencies

Assess a newer base by its immutable digest and both native architecture images.
A higher package version or an upstream release note alone does not prove that
all reviewed fixes are present. Before removing an individual patch or exception,
verify its exact source change in the replacement, run the corresponding runtime
probes on amd64 and arm64, and obtain complete unsuppressed scans. Keep local
hardening unless the replacement proves equivalent behavior at its boundaries.

Update the base identity, signed provenance, source locks, source hashes,
matching-source archives and exception evidence together for the candidate being
tested. Preserve original retained reports; a replacement image requires new
native validation rather than changed evidence for an older image. If a fix,
provenance or architecture cannot be verified, retain its patch and exception and
record that remaining release blocker. No newer base eliminating these exceptions
has yet been verified.

### October 5, 2026 base assessment

The public Docker Hub catalog identifies the following newer Python 3.14 Alpine
3.24 candidate. These are discovery identities; its OCI manifest bytes and signed
provenance have not been verified, and the Dockerfile pins remain unchanged.

| Stage | Catalog index digest | amd64 native digest | arm64 native digest |
| --- | --- | --- | --- |
| Runtime | `sha256:b945ad65f9dcea58d20d119a7a7d650517cb9d27ad26031ac5a6d3ceeaa972f7` | `sha256:fa220ee7ebeadd3e4d68f5fecb73dd29b69622684ce130157e59fd9811cbeb80` | `sha256:233127fc1adc0748f183e2341864e6c3caa2c9855819657c26b4a49c50fd7f06` |
| Development | `sha256:b718c87cdd7bb7dc88d6bbe347f81123b9cf6f2dac6eec6d4828c2cd8262582d` | `sha256:9ec93de838bc6840ec301a01141f9ab7df29eb13eee3aea75b2d42fe32ba85cf` | `sha256:9459339e3924445a7742d3e8d255847694025cb7a1ffae6f308e80e955a081b4` |

The [amd64 runtime catalog](https://hub.docker.com/hardened-images/catalog/dhi/python/images/python%2Falpine-3.24%2F3.14/sha256-fa220ee7ebeadd3e4d68f5fecb73dd29b69622684ce130157e59fd9811cbeb80)
and [arm64 runtime catalog](https://hub.docker.com/hardened-images/catalog/dhi/python/images/python%2Falpine-3.24%2F3.14/sha256-233127fc1adc0748f183e2341864e6c3caa2c9855819657c26b4a49c50fd7f06)
list Python `3.14.7-r2`, zlib `1.3.2-r0`, Expat `2.8.5-r0` and OpenSSL
`3.5.9-r0`. The catalog's zero runtime findings do not prove Keep's required fixes.

Static comparison of the public Python APK contents against every exact hunk in
the patch manifest gave the same result for both architectures:

| Reviewed change | Replacement package contents |
| --- | --- |
| `1e54caa`, `a0d023f`, `16dea1e`, `fb2f0bbc`, `31980e8` | All 17 fixed hunks present |
| `363aec1` in `shutil.py` and `tempfile.py` | All seven backport hunks still needed |
| `keep-tempfile-bound-permission-reset-v1` | Guard still needed after the backport |

The [amd64 Python APK](https://dhi.io/apk/alpine/v3.24/main/x86_64/python-3.14-3.14.7-r2.apk)
has SHA-256 `a6fa39d2a124caa7d96a092009e19ef6c5244cc11fce070f5728c9030c25f5b8`;
the [arm64 Python APK](https://dhi.io/apk/alpine/v3.24/main/aarch64/python-3.14-3.14.7-r2.apk)
has SHA-256 `1cf58f70edd7eb9a939d66c0853a17e85009173c44ea0d19e6340f708cc3f9f4`.
Both identify build commit `1add8ab3ef38366e0da70f01b8607a92326be82d`.
The existing manifest applies to those contents in memory. Package signatures,
binding to the candidate images and native runtime behavior remain unverified.

The public zlib APK bytes for both architectures still match the original package
hashes in `docs/os-package-sources.json`. The [provider recipe](https://raw.githubusercontent.com/docker-hardened-images/catalog/main/package/apk/main/zlib/alpine-3.24/1.yaml)
also retains the reviewed SHA-256
`e847c98224bdd96ea521ff76ba55f7dd2786867ee8d4e3f849a7e8d3d098c274`.
No replacement for Keep's `df84af25` zlib fix was proven.

DHI manifest and anonymous pull-token requests returned HTTP 401. Authenticated
manifest/provenance verification, native Linux amd64/arm64 builds, final-image
Scout/Grype scans and the nine runtime probes could not be run in this assessment.
No patch or exception was removed. A base change still requires coordinated
updates to `Dockerfile`, `inspect_candidate.py`, base/package source locks,
source hashes and original Expat-layer materials, followed by new native evidence.
The new Python package version cannot use the old version's exception approval.
If final scans still need any October 7 exception afterward, a new explicit
security review remains required.

### Upstream and alternative-base blockers

The retained evidence from the [main validation run for `aea169a`](https://github.com/brspoon/keep/actions/runs/37379610092)
contains eight Grype findings on each native architecture: seven for Python and
one for zlib. All nine original runtime probes passed and Scout reported no
findings, but the original zlib probe did not verify the library used by Python.
These reports remain tied to the original image. Being within the October 7
deadlines does not authorize that image or prove the correction. The changed
recipe and probe source bindings require fresh corrected candidate evidence and
review; needed exceptions still block after their deadlines. The
`CVE-2026-4360` policy entry is unused by those reports.

As of October 5, the Python 3.14 directory-cleanup
[backport PR](https://github.com/python/cpython/pull/158430) remains open and
unmerged. Keep's pinned `363aec1` is an earlier revision of that pending backport.
The [Python 3.13 backport](https://github.com/python/cpython/pull/158429) is also
unmerged, and the [Python 3.12 backport was reverted](https://github.com/python/cpython/commit/e1f3590f155c6d66007e958c98c9d69316551993)
after premature merging. The examined Python 3.14.8 upstream source and DHI APKs
still lack the seven reviewed cleanup hunks and Keep's permission-recovery guard.
The newer APKs also have changed zipfile contexts, so the existing complete patch
manifest cannot simply be carried forward unchanged. Moving to an older Python
series does not establish remediation.

The examined DHI Alpine and Debian Python 3.13/3.14 candidates do not establish
an exception-free replacement. Their catalog results are discovery information,
not signed package-to-image binding or final-image validation. In particular,
a catalog with zero findings does not prove the cleanup behavior.

Wolfi's [zlib recipe](https://github.com/wolfi-dev/os/blob/main/zlib.yaml) builds
`1.3.2.1_rc20260917` from a source revision containing the reviewed `df84af25`
fix. That provides a candidate for replacing Keep's separate zlib build with a
vendor-maintained package. Its examined [Python 3.14 recipe](https://github.com/wolfi-dev/os/blob/main/python-3.14.yaml)
uses `3.14.8_git20261001`, whose source still lacks the cleanup correction.
Neither the complete alternative image nor its signed native materials, runtime
behavior and unsuppressed scans have been verified. No base switch, patch removal
or new exception is justified by this assessment.

### Dependency maintenance

Prefer supported vendor packages that contain the required fixes and accurately
identify their installed versions. Keep the small, non-root production image,
immutable base pins, source/provenance checks and native regression tests.
Automated dependency-update proposals should feed this review process; updates
to the private base also need coordinated native provenance, package-source and
matching-source changes. A Dockerfile digest update alone is incomplete.

Remove each local patch and scanner exception only after the replacement proves
the corresponding source fix, runtime behavior and complete final-image scans
on both architectures. Do not filter unfixed vulnerabilities or relabel installed
packages to obtain a clean report. The unresolved prerequisite for a vendor-only
runtime is a package containing the reviewed Python cleanup correction and safe
permission recovery. Until a replacement is verified, the existing approval
limits and deadlines remain in force.

### Optional vendor qualification

A future vendor upgrade can reduce local patches and scanner exceptions. Prefer
an updated DHI image when it contains the required fixes; evaluate alternatives
as complete images with their own libc, package identities, notices and sources.
Do not mix a replacement library from another distro into the existing runtime.

Update immutable base and native identities, signed provenance, source locks and
notices together. Remove a patch or exception only after its replacement passes
source inspection, all required native probes and complete unsuppressed scans on
both architectures. Retain Keep's cleanup guard until equivalent behavior is
proven. Dependency-update proposals must pass the same coordinated review.
No base migration or exception removal has been validated yet.

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
evidence on both native architectures, the exact reviewed source hashes and, when
a finding needs the exception, its existing review deadline. A local probe alone
does not validate a rebuilt release.
