# Image security

The portable runtime uses the digest-pinned Docker Hardened Python base in
Dockerfile. The build removes installation tools, runs as UID 10001, applies
the reviewed upstream Python fixes and separately identified Keep hardening in
scripts/python_security_patches.json, and
installs the exact signed Alpine musl `1.2.6-r3`, zlib `1.3.2-r1`, DHI Python `3.14.8-r0` and
DHI CA bundle `20261020-r0` packages. Package versions change through verified offline APK installation;
the build never relabels an older package or suppresses a finding.

Every architecture job verifies signed vendor provenance, runs checksum-pinned
Docker Scout `1.27.0` and an unsuppressed Grype scan, and executes all nine runtime
regression probes.
Zero Scout and Docker Hub findings remain the default requirement. The only
temporary Scout approval is the verified musl false positive described below,
through October 25, 2026 UTC inclusive. Grype's complete raw findings remain visible;
only the two exact verified-fixed Python `3.14.8-r0` scopes in
docs/image-exceptions.json may pass through November 1, 2026 UTC inclusive.
Every other Grype finding blocks. Historical Python `3.14.7-r2` and zlib
`1.3.2-r0` scopes are retired and cannot authorize this runtime.
Source hashes, base identity, complete scans, successful probes and the deadline
of each exception used by a finding are enforced by scripts/review_image.py.
Full JSON report contents are printed in the workflow logs under each
architecture's security-evidence groups. After all applicable gates pass, the
original report bytes are saved with the tested image in an unpublished
main-validation draft. A small immutable Actions index binds those reports to
their producing run and attempt, independently of log retention. A failed
main security run supplies log-derived findings, without a retained promotion archive;
reformatted log contents do not prove original report byte identity. Large
evidence and source archives stay out of Actions artifact storage.
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
The reviewed newer DHI base supplies OpenSSL `3.5.9-r0`. The image upgrades
its Expat `2.8.5-r0` packages to Alpine's signed `2.9.0-r0` APKs with exact hashes
for both architectures. Installation checks the pinned public keys and package
signatures without networking or repository updates. BuildKit mounts the APKs,
keys and package manager read-only; those inputs do not enter a final image layer.
A separate native dependency report verifies ordinary `pyexpat` and `ssl` imports,
functional XML/TLS checks and the mapped libraries' canonical paths, file
identities and hashes. Expat's loaded bytes must match its signed APK. This
report is retained with the original evidence and rechecked during promotion.
No OpenSSL or Expat exception is added.
Native jobs acquire corresponding package sources and original signature
evidence, verify the actual runtime package identities, and package versioned
source/notice archives with SHA-256 manifests before transferring an image.
The original Expat, Python, zlib, musl and CA certificate layers, runtime security patches and statically embedded wheel
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
and retains them for a separate stable-promotion run. Before publishing release
tags, a maintainer must inspect Docker Hub's completed stored analysis for both
exact native digests and record truthful counts and every approved false positive.
Any unapproved finding blocks; the certifi Critical finding must be absent.
A CLI scan is not proof that Hub's stored analysis has completed. Missing,
pending, unapproved, stale or wrong-digest review records block stable promotion. After publication,
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

## Certificate trust and build-tool candidate (October 21)

The [certifi advisory](https://github.com/certifi/python-certifi/security/advisories/GHSA-6q48-6c7w-9gw2)
requires removing the compromised emSign trust path. This candidate pins certifi
`2026.10.19`, following the [Python Security announcement](https://discuss.python.org/t/information-for-python-users-regarding-emudhra-emsign-ca-certificate-security-incident/109576)
that recommends this release over `2026.10.18` to preserve unaffected roots and
requires pip `26.2.2` or newer. Updating the system CA store alone does not fix
older pip's vendored trust store.

Package inspection verifies the DHI-signed `ca-certificates-bundle 20261020-r0`
APK, its pinned key, metadata and payload hash for amd64 and arm64. The same
noarch APK bytes serve both platforms. The [pinned DHI recipe](https://github.com/docker-hardened-images/catalog/blob/6428625d5032aaa4bc4c05dfde7f49c1268424ce/package/apk/main/ca-certificates/alpine-3.24/20251003.yaml)
records the matching Alpine source. The development image upgrades the matching
`ca-certificates` management package and bundle together, with normal vendor
triggers enabled. Updating the bundle alone lets the older generator restore
stale roots. The runtime receives only the prebuilt bundle, without adding CA
management tools. The base image digests, Python package cohort,
cleanup backport and Keep permission guard remain unchanged.

Keep's default HTTPS Requests connections use certifi's bundle; SMTP SSL and
STARTTLS use `ssl.create_default_context()` and the system CA store. Certifi's
120-root bundle removes emSign ECC Root CA - G3 while retaining G1, C1 and C3.
The vendor system bundle has 118 roots: it also follows Mozilla NSS's separate
[C1/C3 removal](https://github.com/mozilla/nss/commit/15734105a44679969114534ac5ceaf08e9630dd3),
alongside the [G3 removal](https://github.com/mozilla/nss/commit/0a2b0c75fa036930d98331b721c0780693a3e17a),
and retains G1. Those extra vendor policy removals can affect certificates
chaining through C1/C3; they are distinct from certifi's compatibility choice.

The build verifies the installed CA generator, configuration, individual roots,
hashed certificate directory and effective trust after the transaction; a
trigger that hides its own failure cannot pass these checks. It refreshes its
system bundle before bootstrapping pip. It creates the
application environment with `--without-pip`, downloads the fixed pip `26.2.2`
wheel with normal HTTPS verification, checks its pinned SHA-256, and runs that
wheel to install itself offline. Only the fixed pip then downloads application
dependencies. Pip is removed before the environment enters the final runtime;
the bootstrap wheel is a build input. Older ensurepip bytes in immutable base
layers retain their existing source and notice coverage.

The native dependency report now requires retained certificate trust evidence:
exact certifi and system bundle hashes and root inventories, the signed CA
installation/source manifest binding, the active Requests and SMTP trust stores,
the OpenSSL certificate directory, and successful local handshakes with hostname
and untrusted-certificate rejection. Missing or modified proof blocks acceptance.
The pinned DHI base's exact `SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt`
setting is recorded and accepted because it names the verified default bundle.
Other CA file values, directory overrides and Requests/Curl overrides block
qualification and retained-evidence revalidation.
Archive readback and final promotion revalidate this evidence against the current
source map without changing the original report bytes.

The [native review](https://github.com/brspoon/keep/actions/runs/39719304568)
passed application, installation, recovery, all nine security regressions,
dependency/certificate trust checks, signed source acquisition and notice
preparation on amd64 and arm64. Both reports contain the exact 120-root certifi
and 118-root system inventories and successful TLS controls. The reviewed notice
union retains all 124 original text files unchanged and adds the new CA source
attributions. Rebuilt source archives must also pass their full member and
installed-notice checks before release.

Overall image security acceptance remains blocked by the separate musl finding
below. No new exception or deadline extension is introduced: the existing two
exact Python scopes and November 1, 2026 UTC inclusive deadline remain unchanged.

### October 21 musl release hold

The original complete Scout reports identify `CVE-2026-107891` against the pinned
base's musl `1.2.6-r2`. The [maintainer advisory](https://www.openwall.com/lists/musl/2026/10/21/1)
describes integer overflows in libc's regular-expression compiler; this finding
does not come from the CA update. The bounded source assessment does not establish
application-level exploitability, and that uncertainty does not waive the gate.

[Alpine 3.24 security data](https://secdb.alpinelinux.org/v3.24/main.json) records
the fix at `1.2.6-r3`; [edge data](https://secdb.alpinelinux.org/edge/main.json)
records it at `1.2.6-r6`. Scout's reports name Alpine 3.24 but use the edge
threshold. Correcting that threshold alone would still leave the installed r2
package affected. The musl candidate installs Alpine's exact signed `1.2.6-r3`
package in the runtime. Its build stage upgrades libc and the exactly coupled
`musl-dev` package together before creating the application environment; neither
the development package nor package-management tools enter the final runtime.
The inspected DHI delivery still offers r2, so the source records identify Alpine
signature/source binding explicitly and retain original DHI r2 provenance separately.

The [pinned Alpine recipe](https://github.com/alpinelinux/aports/blob/8f79d39391b46d6dbf1800fb68b8212a21d5ee2e/main/musl/APKBUILD)
retains the matching upstream `1.2.6` source and complete build context, including
the regex correction and every other checksum-listed patch. The loader's upstream
version stays `1.2.6`; its package revision, signed payload bytes and source identity
establish which correction is installed. Fresh interpreters must verify the loader
actually mapped by normal consumers, its inode/device/hash, libc alias and successful
bounded libc controls. The retained dependency report requires this evidence along
with all existing Python, TLS and dependency proofs; older reports cannot qualify
the changed candidate. All native application, installer/recovery and source gates
remain required.

The [musl notice-preparation run](https://github.com/brspoon/keep/actions/runs/39726218264)
passed both native builds, application, installation, recovery, all nine security
regressions, default loaded-libc checks and signed matching-source acquisition.
The reviewed two-architecture notice union adds r3 attribution and separates the
original DHI r2 provenance while retaining all 124 complete text files unchanged.
It contains 53 package/architecture groups with no attribution gaps.
Both original Scout `1.24.0` reports still matched the genuine r3 package against
the r6 threshold. Grype contained only the two existing exact Python scopes.

The [Scout 1.27.0 qualification](https://github.com/brspoon/keep/actions/runs/39728273258)
rebuilt both architectures, verified every source-archive member and installed
notice, and passed all functional, security, provenance and source/license checks.
It remained failed solely at Scout acceptance: the original complete reports
matched stable Alpine 3.24 musl `1.2.6-r3` against edge's `1.2.6-r6` threshold.
That failed run cannot qualify publication.

The October 22 review permits only `CVE-2026-107891`, `UNSPECIFIED`, exact PURL
`pkg:apk/alpine/musl@1.2.6-r3?os_name=alpine&os_version=3.24`, affected range
`<1.2.6-r6` and fixed version `1.2.6-r6`, through **October 25 UTC inclusive**.
[Alpine's stable feed](https://secdb.alpinelinux.org/v3.24/main.json) identifies r3
as fixed; edge uses r6. The signed APKs, immutable recipe and correction patch,
actual default-loader bytes, native probes and complete matching sources establish
the installed fix. This is a scoped false-positive approval, not approval to ship
unfixed musl. Old r2, other packages/distributions/versions/severities/thresholds,
and every unmatched finding still block.

Fresh complete qualification on both architectures and exact-main validation
remain required. The original Scout reports remain unchanged and visible. Docker
Hub must be reviewed with completed, unfiltered analysis for both exact digests;
its counts remain truthful, including this finding if still present. The v2
receipt records each exact finding and binds acceptance to original native
source/provenance/runtime evidence. The native and hosted gates reapply the same
inclusive deadline before each publication push. A needed approval blocks on
October 26; an unused expired entry does not block a clean image. The two Python
approvals and their November 1 deadlines are unchanged.

[Scout issue #248](https://github.com/docker/scout-cli/issues/248) tracks the
correction. Remove the approval only after fresh complete native scans and actual
hosted analysis no longer report it, with all existing qualification checks
passing. Issue closure, a client announcement or suppressing the result does not
prove correction. Zero findings remains the default release goal; further false
positives need their own explicit, evidence-backed review and bounded approval.

## Vendor package replacement candidate (October 7)

The `2.23.3` source prepares Alpine's signed zlib `1.3.2-r1` and the complete
four-package DHI Python `3.14.8-r0` cohort for both native architectures. The
[Alpine recipe](https://github.com/alpinelinux/aports/blob/0afa2da0e8c8051c6f8f64a7a388e5a259904245/main/zlib/APKBUILD)
includes the zlib fix already supplied locally in `2.23.2`. Genuine APK
installation replaces both the library and the older APK inventory entry that
Docker Hub now reports. The [pinned DHI Python recipe](https://github.com/docker-hardened-images/catalog/blob/d65ec8748eef33c1ed9033563e0a0a146ef3c739/package/apk/main/python/alpine-3.24/3.14.yaml)
identifies the Python replacement; its signed native source/binary binding
passes the authenticated source acquisition gate on both architectures.

All eight candidate Python APKs and both zlib APKs have passed exact hashes,
official key hashes, RSA signature and signed payload checks. Public zlib build
context, fix, source and license bytes have been verified. These are package
inspection results; the native gates below determine qualification. The October 7
review below approves only three exact verified-fixed Grype scopes, retaining
the October 20 deadline. The existing Python cleanup backport
and Keep permission guard remain; changed ZIP contexts retain strict bounded-output behavior and
normal reads through EOF. Modified stdlib bytecode is removed before capture.
Normal TLS setup, hostname validation and a complete in-memory handshake with
an SNI context change are required alongside signed Python executable and
loaded-library identities.

The original pinned DHI base is unchanged. Its Python `3.14.7-r2`, zlib
`1.3.2-r0`, Expat `2.8.5-r0` and original ensurepip materials remain in immutable
earlier layers, so their exact original source records remain required. New
ensurepip and cache bytes are removed in the installation RUN before a new
layer is captured. Current runtime source records cannot replace that original
coverage. Native source acquisition regenerates both architectures' complete
notice union for explicit review before the final source-archive gate.
The unchanged development base builds the existing `cp314` application wheels;
their compatibility with the upgraded runtime must pass native CFFI, Argon2,
SQLite, application and recovery checks. Its Python development package has an
exact old-runtime dependency, so it is not partially upgraded with runtime APKs.

The October 7 [notice-preparation qualification](https://github.com/brspoon/keep/actions/runs/37654700878)
built both native architectures and passed application, installation, recovery,
all nine runtime probes and all three dependency families. Authenticated
matching-source collection passed for all 18 current OS origins and all three
overwritten base origins. It also verified the earlier ensurepip sources and
prepared the complete native notice inventories. Original-base zlib acquisition
uses its previously verified immutable native manifests, with unchanged APK
hashes and required signatures. The Python 3.14.8 provider context and malformed
upstream archive test fixtures retain exact archive, path, size and hash bindings;
other archives keep their normal traversal checks.

The reused timezone package tag no longer matches the historical binary. The
existing pinned IANA/Alpine source fallback retains the same full notice bytes,
including the three BSD headers and POSIXtz copyright. Its current attributions
explicitly record public source checks rather than claiming the old provider
signature. Earlier release evidence and its original notice manifest remain
unchanged; their signed attributions do not transfer to the fallback. The current
union preserves all 124 full notice texts and records 556 complete native
attributions across 22 current and earlier-layer origins on each architecture.

The [complete native qualification](https://github.com/brspoon/keep/actions/runs/37657188329)
at source revision `6cf7c2ca4b5ae86d46bdf21cee41b27069702e6d` rebuilt both
architectures with `prepare_notices=false`. Application, installation, recovery,
all nine runtime probes, all three dependency families, authenticated source
collection and complete source-archive checks passed. The committed notice
bytes and every required native attribution also passed. Scout reported zero
findings on both architectures. Grype reported `CVE-2026-87910`,
`CVE-2025-15367` and `CVE-2026-12345` against Python `3.14.8-r0`, so security
acceptance failed for both images under the then-required zero-Grype policy.
That failed run cannot provide publication images, and its original evidence
remains unchanged. The new review requires fresh successful native qualification
and complete exact-commit main validation before candidate publication.

Inspection of the signed DHI packages confirms the vendor's POP3 control-character
and tarfile filter fixes. The cleanup correction still comes from Keep's
verified backport, together with the Keep permission guard. Generic upstream
version ranges do not describe all these vendor backports. A controlled
comparison of Grype `0.118.0` and `0.120.1` against the unchanged native Python
package identities and CPEs, using the same current official database, returned
the same three findings. Updating the scanner alone does not resolve acceptance.
That focused comparison is diagnostic evidence, not a complete image scan or
replacement qualification. The full original native reports remain unchanged.

The October 7 review inspected the signed APK/source bindings, exact vendor
POP3 and tarfile fixes, Keep's applied cleanup backport and permission guard,
and both architectures' complete original scans, nine runtime probes, three
dependency families and matching-source/license evidence. It permits only
`CVE-2026-87910`, `CVE-2025-15367` and `CVE-2026-12345` at Medium severity,
APK package `python-3.14`, version `3.14.8-r0`. The cleanup approval applies
to the patched Keep runtime, not the unpatched vendor package. No additional
risk or later deadline is approved.

Publication must replay this policy against unchanged original evidence bytes.
Docker Hub's completed analysis must then show zero findings for both candidate
digests before release tags or stable promotion. Internal Grype approvals do
not change Hub's counts. A clean Hub result is time-bound evidence: newly
published advisories can change those counts.

The current [Python 3.15 release notice](https://www.python.org/downloads/release/python-3150rc3/)
identifies a production-unsuitable preview and schedules the final release for
October 9. That schedule does not establish package availability or qualification.
Keep must retain its required guards and pass both native security gates
before this candidate can be published. A scheduled upstream release does not
replace verification or extend an exception deadline.

### Alternate vendor assessment

The October 7 assessment also inspected the immutable native images in
Red Hat's `registry.access.redhat.com/hi/python:3.14` index
`sha256:9ad2603a9f39caba3ac4101788fcceb2d63569fd1f448821bacba7c922b8b144`.
The vendor's POP3 and tarfile fixes are present, but its cleanup sources still
require the reviewed backport and Keep permission guard. Inspected Red Hat
Python `3.12.15` and `3.13.16` sources also do not supply that cleanup correction.
Vendor advisory status or a newer version alone does not prove its inclusion.

Complete read-only Grype scans of both Red Hat 3.14 base images reported ten
matches across four CVEs: `CVE-2025-12781`, `CVE-2026-55856`,
`CVE-2026-95619` and `CVE-2026-84783`. Full catalog replays retained all 50
packages and 261 CPEs per architecture; Grype `0.118.0` and `0.120.1` each
returned the same ten matches with no ignored findings. Some records conflict
with Red Hat's [GCC](https://access.redhat.com/security/cve/CVE-2026-95619),
[OpenSSL](https://access.redhat.com/security/cve/CVE-2026-84783) and
[MariaDB](https://access.redhat.com/security/cve/CVE-2026-55856) records.
These are reported findings, not four independently validated defects. They still block the
zero-finding gate; source inspection cannot substitute for an official data
correction and complete unsuppressed rescanning.

No Red Hat Keep image was built or qualified. A base change would additionally
require authenticated source/build bindings, matching source and license
records, rebuilt native wheels, loaded-library integrity checks and all existing
functional, installation, recovery and runtime probes on both architectures.
The current candidate, scanner configuration, original evidence and historical
approval deadlines remain unchanged.

## October 18 verified-fixed review

Fresh [complete native qualification](https://github.com/brspoon/keep/actions/runs/39150602670)
at source revision `521c3376c058d0e2392e5b7ac2299666f82e5e3f`, attempt 1,
passed on amd64 and arm64. Scout reported zero findings. Complete unsuppressed
Grype reports contained only `CVE-2025-15367` and `CVE-2026-12345`, both Medium
severity against APK package `python-3.14` version `3.14.8-r0`. Application,
installation, recovery, all nine runtime probes, all three dependency families,
signed provenance, source acquisition, full source archive member integrity and
matching-source/license checks passed on both architectures.

Fresh inspection of the signed native APKs verifies the complete vendor POP3
control-character fix. This is signed-source inspection plus loaded-runtime
verification; the cleanup patch manifest does not supply POP3 patch hunks.
The seven cleanup correction hunks produce byte-identical production sources to
the merged [upstream 3.14 backport](https://github.com/python/cpython/commit/58ed0259cae509a19138795df302fe60b544dc74).
Keep's separately identified permission guard remains required: upstream still
allows pathname permission fallback. Approval is limited to the checked Linux
descriptor capabilities with no `chflags`. Unreadable or unbound entries fail
closed and can remain unremoved; ordinary cleanup must continue to pass.

The unused `CVE-2026-87910` tarfile exception is removed. Both fresh scanners omit
it and its vendor source checks and runtime regression remain required. If that
finding reappears, it blocks as unmatched until separately reviewed.
Only the two findings still reported receive a fresh verified-fixed review,
through **November 1, 2026 UTC inclusive**. Package, version, type, severity,
base, source integrity, scan completeness and runtime checks remain unchanged.
No unfixed finding or additional risk is accepted. Historical reviews and
published release evidence retain their original bytes; promotion rereads the
current policy and deadlines against those original reports.

The [DHI Python `3.14.8-r1` recipe](https://github.com/docker-hardened-images/catalog/commit/63431ba13a121bcaa4aa09975b91715103a3be9c)
patches pip's bundled urllib3. Its Python patch inputs are unchanged and both
signed native packages still need the cleanup correction and Keep guard.
Keep already pins urllib3 `2.8.0` and removes pip from the final runtime.
The revised package is not a qualified replacement for these protections.

Wolfi's [October 14 Python recipe change](https://github.com/wolfi-dev/os/commit/b284ec5596d7290b37ef0bcb6ea6d30cb3db6834)
contains the upstream cleanup correction. Its inspected source still lacks the
POP3 control-character fix and Keep's stricter permission guard, and its recipe
also changes to OpenSSL 4.0 with additional patches. It is an alternate-source
candidate requiring complete image, provenance, source/license and native
qualification; it is not a verified replacement for the current runtime.

No runtime package, patch or source/license input changes in this review.
Existing published images and releases retain their identities. New main
candidates still require complete exact-commit native validation before publication.

## Exception review deadlines

The current policy permits only the two reviewed Python `3.14.8-r0` Grype
scopes renewed on October 18. Earlier package approvals are preserved in Git history and original
release evidence; they are absent from the active exception dictionary.

Each exception records its reviewed scope and evidence in
docs/image-exceptions.json, with `review.approval`, `review.deadline` and
`review.remove_when` describing the current approval, deadline and removal
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

The October 18 review covers only the two remaining Python `3.14.8-r0`
findings through November 1, 2026 UTC, inclusive. Each entry records its fresh
review date and evidence. Earlier Python, zlib and tarfile approvals do not
carry forward or authorize other package versions. A finding that still needs
one of the current exceptions on November 2 blocks validation and promotion;
it requires a proven replacement or another explicit security review.
Correcting deadline handling alone never renews an approval.
The separate Scout false-positive entry uses the same advisory warning mechanism
and expires October 25, 2026 UTC inclusive. It does not change the Python deadline.

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

At that stage, release remained blocked pending complete native evidence and an
explicit review of the corrected source hashes and any needed exceptions. The
October 6 review below records the completed replacement evidence and renewed
exact scopes; successful current-main validation remains required before release.
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

Werkzeug is now pinned to `3.1.9` with matching source records. Final main
validation [37483049399](https://github.com/brspoon/keep/actions/runs/37483049399)
passed the nine runtime probes on both architectures and no longer reported the
Werkzeug finding. Each image still blocked on 39 OpenSSL package findings from
Grype and two Expat findings from Scout. Matching-source acquisition and final
image retention did not run after the security gate failed.

Authenticated vendor assessment
[37483114376](https://github.com/brspoon/keep/actions/runs/37483114376)
verified the documented newer DHI index, both native subjects, and Docker
signatures for the original build and source statements. The retained OCI
signature objects and statement bytes also passed offline verification against
the pinned Docker key and index.

Both native inventories contain Python `3.14.7-r2`, OpenSSL `3.5.9-r0` and
Expat `2.8.5-r0`. The authenticated package installation failed on both
architectures: the configured vendor repositories offer `expat` and `libexpat`
at `2.8.5-r0`, which cannot satisfy the exact `2.9.0-r0` requirement. Alpine subsequently published signed `2.9.0-r0` packages for both architectures
in its edge repository. The replacement recipe pins those four APK hashes and
trust keys, retaining their complete matching source/build/license inputs.
Package verification also checks all XML symbols required by the reviewed
Python extensions; native installation and ordinary library loading remain
mandatory. The newer base's Python, OpenSSL, CA certificate, timezone and xz
source records are updated together. The original DHI Expat layer retains its
own signed package-source coverage.

Python `3.14.8` alone does not replace every reviewed fix: the inspected upstream
release and DHI package still lack the temporary-directory cleanup correction.
The DHI package additionally carries a tar-link correction absent from the
upstream release. Retain cleanup, permission-reset and zlib defenses until
verified replacements supply them. Existing Python `3.14.7-r1` approvals did not
cover findings for `3.14.7-r2`. The completed review below approves only the seven
exact replacement tuples and the existing patched zlib tuple through October 20.

**Review vendor runtime candidate** retains its read-only main vendor assessment.
Its optional `qualification` input also builds and tests both native Keep images
on a maintainer branch, obtains checked sources and prepares small notice records
for review. This mode neither publishes nor retains images for promotion.
Original scanner reports and full notice inputs remain in its small seven-day
artifact, including source headers that need explicit attribution selection.
Security findings still fail the job; independent source preparation can finish
so matching notices can be committed and checked in a rebuilt candidate. Only
successful complete current-main validation can supply promotion images.
Disable `prepare_notices` after committing the checked notice union to verify
the rebuilt images' notices and complete source archives without retaining
images or enabling publication.

The replacement images in native qualification
[37499120809](https://github.com/brspoon/keep/actions/runs/37499120809) passed all
nine security probes and verified normal loading of Expat `2.9.0` and OpenSSL
`3.5.9` on both architectures. Scout reported zero findings; Grype reported the
seven Python findings at `3.14.7-r2` and the patched zlib finding. No OpenSSL or
Expat exception is needed. At that time, the Python findings blocked because the
approvals covered `3.14.7-r1`, not the replacement revision.

Source acquisition in
[37501921315](https://github.com/brspoon/keep/actions/runs/37501921315) completed
for all 18 installed OS origins on both architectures. Notice preparation then
exceeded a metadata size limit on the complete GCC inventory. The preparation
helper now uses a separate bounded inventory reader while preserving exact input
bytes. The subsequent native run
[37504275731](https://github.com/brspoon/keep/actions/runs/37504275731) completed
source acquisition and notice preparation on both architectures, with all nine
security probes passing. Its retained notice inputs reproduce the committed
124-text union after explicit copyright-header selection and the checked POSIXtz
license supplement. Native qualification
[37508957671](https://github.com/brspoon/keep/actions/runs/37508957671) then verified
the rebuilt installed notice manifest, all 124 complete notice texts, all 458
source attributions and every member of both source archives. Both architectures
passed all nine security probes, ordinary dependency loading, installation and
recovery checks. Grype reported the same eight findings and Scout reported none;
both jobs failed only the finding gate under the earlier r1 approvals.

The October 6 verified-fixed review now covers only those seven exact Python
`3.14.7-r2` findings and patched zlib `1.3.2-r0`, through October 20 UTC. Six Python
fixes are present in the verified base sources; Keep still supplies the cleanup
correction, permission guard and corrected zlib library. No unfixed finding,
additional finding ID or broader package/severity match is accepted. The original
qualification reports remain unchanged. New current-main validation must pass
every gate before its retained images and sources can be selected for separately
approved publication.

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
At that assessment stage, the new Python package version could not use the old
version's exception approval. Findings needing an original October 7 exception
afterward required the new explicit review recorded above.

### Upstream and alternative-base blockers

The retained evidence from the [main validation run for `aea169a`](https://github.com/brspoon/keep/actions/runs/37379610092)
contains eight Grype findings on each native architecture: seven for Python and
one for zlib. All nine original runtime probes passed and Scout reported no
findings, but the original zlib probe did not verify the library used by Python.
These reports remain tied to the original image. Being within the October 7
deadlines does not authorize that image or prove the correction. The changed
recipe and probe source bindings require fresh corrected candidate evidence and
review; needed exceptions still block after their deadlines.

The unused `CVE-2026-4360` exception has been removed. The verified Python
`3.14.7-r2` packages contain the hardlink-target filtering fix from `5e0ef3f`.
Both native architectures passed its regression probe, and their original
unsuppressed Grype and Scout reports contain no finding for it. All nine runtime
probes and exact Python source assertions remain required; a future finding for
this retired exception blocks as unmatched.

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
The October 6 qualification records the earlier replacement libraries and eight
historical scopes. The October 7 package replacement retires those scopes; only
three exact Python `3.14.8-r0` findings remain approved, with the same deadline.
They still require their reviewed fixes, complete native evidence and a valid
per-entry deadline.

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
