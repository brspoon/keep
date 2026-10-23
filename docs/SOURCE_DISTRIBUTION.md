# Container sources and notices

Each tested Keep release prepares a source archive and SHA-256 checksum for each
architecture. These materials accompany the container; Keep's MIT license does
not replace the licenses of Python, OS libraries, embedded wheel code or assets.
The native image workflow must finish source packaging before transferring an
image for publication.

Independent OS origins and pinned Python distributions download concurrently,
with four workers by default. `KEEP_SOURCE_DOWNLOAD_WORKERS` or each collector's
`--workers` option accepts 1–4 workers. Reports remain in input order; every
source must pass its original verification before the bundle can succeed.

## Matching the container

`docs/os-package-sources.json` records the exact installed OS package versions,
both architectures' APK hashes, and pinned public Docker build recipes. Registry
tags are discovery pointers. The collector checks the native image configuration
and hashes the APK files in its output before accepting Docker's signed native
build provenance and recipe. Upstream downloads must match the hashes in that
provenance; the complete pinned Alpine context and every checksum-listed source
input are retained. The collector preserves original statements, signatures,
verification keys and OCI content hashes. Offline verification checks the
signatures again; it does not claim Rekor transparency-log inclusion. A provider
source-image attestation, when available, is checked separately.

The historical ncurses snapshot is obtained from Alpine's retained distfiles
because the recorded upstream `current/` URL no longer serves it. Both the
original signed material hash and the Alpine recipe checksum must match the
retained bytes; the manifest records the declared and retrieval URLs.
The exact zlib 1.3.2 package archive also uses Alpine's retained distfile, with
the same signed-source and recipe checksum requirements. Alpine's retained files
also supply the exact signed CA 20260909 and 20261020, GDBM 1.26 and Readline 8.3 source
archives and Readline's three patches. Each mapping requires its reviewed
origin, package revision, declared URL and signed SHA-256. The manifest records
both the declared and retrieval URLs; mirror bytes must also match the recipe
checksums. Public downloads retry
transient failures at most three times with Python's HTTPS client. If a transport
failure persists and curl 8.4 or newer is available, one IPv4-only attempt uses
the same URL, HTTPS-only redirects, verified TLS, and bounded time and size.
HTTP errors never select this alternate transport. Authentication, certificate,
permanent HTTP and checksum failures still block collection; recovery does not
change the source identity or relax any signature or checksum requirement.

The APK metadata's build commit is a provider build identifier. The public
package recipe separately records the upstream Alpine recipe commit. Those
identifiers are not interchangeable. The image-level source collection contains
assembly inputs, so package-level sources are collected separately.

The source map covers 18 origins and 29 installed OS packages. The original
DHI Expat 2.8.5, Python 3.14.7-r2, zlib 1.3.2-r0, musl 1.2.6-r2 and CA bundle 20260909-r0 in earlier image layers retain their exact APK hashes,
native-base material binding and signed package sources separately from the
installed replacement packages. Alpine's zlib 1.3.2-r1 is verified separately
against signed APKs, its complete pinned aports context, upstream source,
security patch and full Zlib notice. DHI Python 3.14.8-r0 has matching signed
native build/source records verified on both architectures; public recipe and
archive inspection alone cannot satisfy that gate. Keep's exact Python patches
are also included. Both architectures' committed notice union is regenerated
from their checked native inventories and verified in the rebuilt source-archive
gate. Passing source and notice checks does not waive the separate security gate.

Alpine's signed musl `1.2.6-r3` runtime replacement and its matching build-only
`musl-dev` package have their own exact native APK, metadata and signing-key pins.
The complete immutable aports context, every recipe input and patch, upstream
source archive, full `COPYRIGHT` and the reviewed TRE/math/crypt/architecture
attribution headers are replayed offline. Original DHI musl `1.2.6-r2` source and
notice provenance remains separately bound to the original base. Signed Alpine
packages do not acquire a Docker package-build or source-image attestation claim.
The development package is used only to build dependencies; the final package
inventory continues to contain the core musl package alone. Complete native
compatibility, source-archive and installed-notice verification remains mandatory.
The [native notice preparation](https://github.com/brspoon/keep/actions/runs/39726218264)
verified both replacement-package source sets and original DHI sources. Their
reviewed union contains 53 package/architecture groups, with all 124 full notice
texts unchanged. New r3 source attributions accompany the separately labeled
original-base r2 records; every other existing source attribution is unchanged.
This preparation does not replace the rebuilt archive and installed-notice gates
or successful complete scanner acceptance.

The Python source lock covers all 17 pinned distributions,
including Certifi's MPL-covered material. Native CFFI wheel bytes are checked
against their embedded libffi 3.4.6 source and wheel build recipe; this is
separate from the OS libffi package. Argon2's embedded source and complete
license choices are retained too. Earlier base layers also carry Python's bundled
pip 26.2.1 and wheel 0.48.0. Their Python modules are checked against matching
source distributions; the six embedded distlib 0.4.2 Windows launchers are
matched to its complete source distribution and C/build inputs. Their full
notices and vendored attribution accompany these materials.

The certificate candidate records the DHI-signed `ca-certificates-bundle 20261020-r0`
overlay separately from the exact original `20260909-r0` CA origin
in `original_base_origins`. Its [pinned provider recipe](https://github.com/docker-hardened-images/catalog/blob/6428625d5032aaa4bc4c05dfde7f49c1268424ce/package/apk/main/ca-certificates/alpine-3.24/20251003.yaml)
identifies Alpine commit `e78f5987166c6ffbe23f6472e2e8f040298fe2da`;
the signed APK's provider build identifier is
`68cdc7eb180fe3a0843d7489185b3ca10ea806d1`. Both native source collectors must
bind the new APK bytes to their signed package provenance. The original CA
source, signatures and base-layer binding remain required alongside the new
overlay's source; replacing an installed package does not replace earlier-layer
source obligations.

The same origin's `build_only_packages` record pins the native `ca-certificates`
management package used only in the development stage. Source acquisition and
archive replay require its exact APK bytes in the signed package output alongside
the bundle. It adds no package to the final runtime inventory. Both build CA
packages must be updated together so the older vendor trigger cannot regenerate
the old bundle.

The matching `ca-certificates-20261020.tar.bz2` source has SHA-256
`1048bc7f50fa42a6621bc2f8816173f89a0c0098f26dff072bc8fe40af714400`.
Its complete leading `certdata.txt` legal notice is byte-identical to the
reviewed 20260909 notice. The MPL supplement accepts each exact release's archive,
readable source and notice before adding the checked full MPL 2.0 terms; another
version or source hash cannot reuse that approval. Complete new and original CA
attributions still require native notice preparation and review.

The Python source lock pins certifi `2026.10.23` and its matching MPL-covered
source distribution. Its 118-root inventory removes emSign G3, C1 and C3,
retains G1, and matches the reviewed vendor system bundle. See the
[current maintenance candidate](IMAGE_SECURITY.md#python-expat-and-certificate-maintenance-october-23)
for the advisory and policy references. Pip `26.2.2` is a checksum-verified build
bootstrap input and is removed before the application environment enters the
runtime. It does not replace the older pip/ensurepip source records required by
immutable base layers. Keep's source archive explicitly includes the CA package
verifier, pip bootstrap and certificate trust checks with the Docker build inputs.
Native certificate checks, signed source acquisition and notice preparation
passed in [the native review](https://github.com/brspoon/keep/actions/runs/39719304568).
Rebuilt archive member and installed-notice verification remain required;
the separate musl finding still blocks complete image security acceptance.

Docker's timezone package tag is reused across IANA releases. If it no longer
matches the recorded 2026d APK, a narrowly scoped fallback obtains IANA 2026d,
the pinned provider and Alpine recipes, all checksum-verified source inputs and
patches, and their notices. The report explicitly records that no historical
provider OCI binding was established. It does not substitute this fallback for
a missing signature or mismatched binary of another package.
The complete GNU LGPL 2.0 notice for the retained POSIXtz build source is read
from its committed `docs/licenses/os` file and checked against the same reviewed
SHA-256 before collection. This avoids a repeated GNU website download. The
notice evidence keeps the original GNU URL and records that the verified notice
was acquired from the repository; missing, changed or oversized notice files
still block collection. Signed package sources retain the same complete terms
only after the exact POSIXtz archive and its LGPL header have been verified.
Their original package signatures and source identities remain in the notice
provenance.

If the reviewed OpenSSL 3.5.9-r0 package repository has no retrievable image or
package attestation, a separate narrow reconstruction checks the actual APK
identities against the signed pinned base provenance and runtime inventory,
then retains the matching pinned public provider/Alpine recipes, every patch,
and checksum-verified OpenSSL source. Its report explicitly records the absence
of a signed package build or source-image binding. This method does not rescue
a signature failure or an unrelated missing package.

The original Expat inputs use Alpine's signed `2.9.0-r0` APKs, independently
pinned for amd64 and arm64. The installer checks each APK and official key hash,
its RSA signature, signed metadata and payload hash, exact library bytes and
SONAME alias. It installs only these files with networking disabled and the
pinned public keys; the temporary APKs, keys and installation tools are mounted
without entering a final image layer. Source collection retains the original
APKs and key, complete immutable aports context, checksum-matching upstream
source and full MIT notice. It records Alpine package verification without a
Docker package-build or source-image attestation claim. The upstream detached
signature is retained without claiming separate OpenPGP verification.

The runtime then replaces the canonical library with the separately identified
Keep build in `docs/expat-build.json`. Its source set contains the complete
Expat 2.9.0 release, both merged security corrections and their prerequisites,
the Keep-local literal-markup accounting correction, the exact patch manifest
and builder, native compiler/output hashes and full replayed sources. The local
correction is identified as `keep-expat-literal-markup-accounting-v1`, with
`source_kind: keep-local` and no upstream commit claim. Its exact hunks and
before/after hashes remain in `expat_security_patches.json`; the source replay
record lists the local identity separately from the merged upstream commits.
Original signed materials and manifests remain unchanged
under `alpine-expat-sources/vendor-inputs/`; the additional source set is under
`keep-build/`. The combined proof records
`signed-vendor-inputs-and-reviewed-keep-build`,
`apk_binary_match_verified: false` and `runtime_build_verified: true`.
It verifies the independently inventoried loaded-library hash against the
reviewed build rather than attributing modified bytes to Alpine's signature.
Offline archive replay rejects missing, altered or extra source outputs.
New source-header attribution is retained alongside the complete MIT notice.
The current local correction still requires fresh native qualification; source
replay alone does not qualify its output or pass source-delivery verification.
The build-only Fortify input retains both signed `fortify-headers 3.0.1-r2`
APKs and keys, the complete matching upstream source and Alpine recipe/patch,
all ten headers and their copyright notices, and the full 0BSD license. Its
verified headers are used through an isolated compiler include directory.
The development image's original signed SLSA statement, index, native-subject
binding and OCI signature proof are also required and replayed offline. These
records authenticate the compiler image; they do not claim that the complete
compiler toolchain was rebuilt from source during this review.
The local OCI layout's root `index.json` is a generated wrapper. Retention
omits its copy-tool transfer timestamps and sorts its descriptors and JSON keys,
then verifies the retained proof again. Original content-addressed manifests,
statements, signatures, references and the pinned compiler image index retain
their exact bytes. The generated wrapper is identified separately from those
original proof objects.
The existing GCC origin also pins matching DHI `g++` and `libstdc++-dev`
`15.2.0-r7` as build-only packages. Expat's unmodified configure step requires
C++11 with tests enabled, even though its Autotools regression targets are C.
These packages are installed offline only in the development stage. Their exact
signed bytes must match the native GCC package output already used to obtain
the complete GCC source, recipes and notices. They do not enter the final
runtime package inventory or disable any upstream tests.
The separate `keep-build/build-tools/` set retains signed Alpine v3.24 Make
`4.4.1-r4` and Bash `5.3.9-r1` packages for both architectures, their keys,
complete immutable aports contexts, checksum-matching GNU source archives,
recipe patches and full license/attribution texts. Their installation is offline
with package scripts disabled; exact payloads, required command paths and the
unchanged compiler/package cohort are verified before running the upstream tests.
These records identify Alpine build inputs without claiming a DHI package-build
attestation or adding Make and Bash to the runtime package inventory.

## Contents and verification

The archive includes preferred source files and source archives, package build
recipes and patches, original signature evidence, full notices, Keep's source
archive and Docker build inputs, runtime package identities, and a per-file
`MANIFEST.json`. Original OCI paths, hashes, file modes and link metadata are
recorded when source contexts are retained. No downloaded build recipe is
executed during collection. Source archives retain upstream content; inspect
their build instructions before extracting or rebuilding them.

CPython and GCC include deliberately malformed archive test fixtures, and XZ
includes compressed codec test streams. A finite reviewed inventory binds each fixture's path, size and SHA-256 to its exact
outer source archive. Notice scanning records those fixtures and preserves their
bytes in the source archive, without interpreting their unsafe test members.
Other archives still undergo normal traversal and bounds checks.

Use the adjacent checksum file before inspecting an archive. For example, for
release 2.26.1:

```sh
sha256sum -c keep-2.26.1-source-materials-amd64.tar.gz.sha256
```

Use `shasum -a 256` on macOS and compare its output to the checksum file.
After unpacking, the manifest identifies each retained file's SHA-256, release
version, architecture and source revision. Both architecture archives are
needed to cover both published images. Full OS notices and their provenance are
also retained in `docs/licenses/os` and copied to `/app/licenses/os` in the
container. The reviewed runtime union contains 135 complete notice texts
(919,491 bytes) and 626 complete native attributions, covering all 23 current and
earlier-layer origins on both architectures. It retains 21 explicitly selected
source copyright headers, three patched Expat headers, ten Fortify headers,
eleven musl subcomponent headers and four timezone headers from the checked
public sources. All 124 earlier notice texts retain their original bytes;
Python and zlib packages have their own source attributions, and timezone attributions describe
the verified fallback rather than reusing earlier provider signature claims.
The native gate checks the rebuilt candidate against those committed hashes.
It also verifies the exact installed notice-manifest bytes and every generated
notice's complete native source attribution against the committed provenance.
Sharing a license text does not transfer its source or signature evidence.
The certificate overlay retains the earlier notice text bytes and separately
attributes the current and original CA sources on both architectures.
Asset and installed Python notices remain in their original paths.

The collection and packaging scripts are under `scripts/`. Authenticated
provider collection uses temporary Docker credentials; final archives contain
the sources and notices themselves and must be readable without that account.
Every trusted main-push native run collects, verifies and packages both source
archives against its tested images. It saves the original images, archives and
reports in an unpublished candidate draft, with a small immutable Actions index
binding their asset IDs, sizes and SHA-256 hashes to the original run and producing
attempt. Indexes expire after 90 days. Superseded candidate drafts and their
temporary indexes are eligible for cleanup once superseded. Current-main
candidates, the latest usable build and published source assets are protected. See the
[retention policy](RELEASE_POLICY.md#temporary-validation-storage).
Pull-request checks remain read-only and receive no publication credentials.

Keep copies needed for an investigation before the repository's log retention
expires; logs do not replace corresponding-source delivery for a published image.

## Durable release assets and retention

Confirmed manual publication restores the complete original source archive
and checksum from the selected successful main validation run, then saves those
same bytes in the matching version draft, alongside original security evidence and portable recovery
proof. The evidence also includes `installer-trial-amd64.json` and
`installer-trial-arm64.json`, recording real Docker startup, HTTP setup cookies,
reruns and synthetic owner/data preservation on the corresponding architecture.
The archive is the one collected and verified by that job against its
tested candidate; no second source collection, image build, scanner or native test
run is used. Only the small index travels through Actions artifacts. Candidate
tests, security review, source/notice verification and native
recovery must still pass before a native image becomes eligible for publication.
The original native dependency report must also retain the certificate trust
proof for the active Requests and SMTP stores. Archive readback and final
promotion reject missing proof, changed bundle/source identities, unreviewed
roots or failed TLS probes without rewriting the retained report bytes.

Aggregation binds both architectures' original run, attempt, source revision,
native manifest and image-configuration identities to their source-member and
report hashes. The original validation run and each architecture's producing job
and attempt are checked separately from the approving publication run. It verifies
the durable server asset sizes and SHA-256 digests
and the exact corresponding transfer tags before publishing the tested image
pair. Stable promotion is last. Public release writes require confirmed manual
publication from current main; trusted main validation can write only its
unpublished candidate storage. Routine logs are validation proof, not a
substitute for these durable original release assets. Missing or expired candidate
indexes block promotion without rebuilding. See the [release policy](RELEASE_POLICY.md#publishing-a-validated-main-commit).

Preserve each architecture's source archive and its adjacent checksum locally
from the matching GitHub release. Include the original
SPDX SBOM, scanner/review results, runtime regression probes, image-layer/notice
inventory and verified provenance/signature evidence. The automatically generated
`keep-<version>-release-materials.json` records the source revision, native manifest
and image-configuration digests, source archive names/hashes and original native
run. It is prepared before stable promotion and does not bind the final
multi-platform index digest. Record that published index and its verified native
children alongside the exact source asset names and hashes. Verify uploaded asset
sizes and SHA-256 digests against the local files; the generated JSON alone does
not establish final index publication or successful source asset delivery.

## Component licenses and redistribution

| Entry | Resolution |
| --- | --- |
| `keep-ci` | Image wrapper. Keep's own source is MIT; component licenses still apply. |
| DHI `python` | Base-image wrapper, not an additional unlicensed Python distribution. The installed CPython records identify PSF-2.0 and Keep bundles the complete Python license. This does not cover all libraries in that base. |
| `jinja2` 3.1.6 | BSD-3-Clause, verified against its retained wheel notice and the [upstream release license](https://github.com/pallets/jinja/blob/3.1.6/LICENSE.txt). |
| `tzdata` 2026d-r0 | Installed package declares Public-Domain. [IANA's versioned license](https://data.iana.org/time-zones/tzdb-2026d/LICENSE) places the data in the public domain and names BSD exceptions for three code files; those exceptions must be considered if code is redistributed. |

The scanner's broad origin license expressions sometimes use `OR` where the
installed APK metadata uses `AND`, notably CA certificates, GCC and xz. Do not
select the least restrictive scanner branch as a redistribution decision.

### Python notices

| Distributions | Declared/reviewed license |
| --- | --- |
| argon2-cffi, argon2-cffi-bindings, blinker, charset-normalizer, gunicorn, urllib3 | MIT |
| cffi | MIT-0 |
| click, Flask, idna, itsdangerous, Jinja2, MarkupSafe, pycparser, Werkzeug | BSD-3-Clause |
| requests | Apache-2.0; retained NOTICE as well as LICENSE |
| certifi | MPL-2.0 |

Retain the installed notices and vendored attribution, including any additional
notices recorded for Requests and Werkzeug. Redistribution must supply the
matching source for covered MPL files (including CA material), not only a link
to a newer release or an SBOM license label.

Werkzeug also ships the Silk debugger icons with a separate
[CC-BY-2.5 or CC-BY-3.0 attribution](https://github.com/pallets/werkzeug/blob/3.1.9/src/werkzeug/debug/shared/ICON_LICENSE.md)
to Mark James in `werkzeug/debug/shared/ICON_LICENSE.md`. Its notice is retained
in the native notice inventory. A package-level BSD label does not cover those
assets. Likewise, retain and verify the source/license choices for
code embedded in compiled wheels; the wheel's wrapper license is not proof
that every bundled native component has the same license.

### OS components and delivery requirements

Use `candidate-notices-<architecture>.json` for the exact versions, package origins,
build-commit identifiers and package URLs in each image. The source map covers:

| Origin/components | Installed license metadata | Required review/delivery |
| --- | --- | --- |
| alpine-baselayout-data | GPL-2.0-only | Full notice and matching source/build inputs. |
| gdbm, readline | GPL-3.0-or-later | Full notices and corresponding source/build inputs. |
| libgcc, libstdc++ | GPL-2.0-or-later AND LGPL-2.1-or-later | Verify actual runtime-file licenses and any applicable [GCC runtime exception](https://github.com/gcc-mirror/gcc/blob/releases/gcc-15.2.0/COPYING.RUNTIME); retain notices and provide covered source. Do not apply an exception based solely on package name. |
| xz-libs | GPL-2.0-or-later AND 0BSD AND Public-Domain AND LGPL-2.1-or-later | Identify installed library/file licenses from the exact source and retain their notices/source requirements. |
| ca-certificates-bundle | MPL-2.0 AND MIT | Retain attribution and provide the matching covered source. |
| libcrypto3, libssl3, openssl | Apache-2.0 | Full license, copyright and any applicable NOTICE from the matching source. |
| bzip2, libbz2 | bzip2-1.0.6 | Full upstream copyright/conditions. |
| expat, libexpat, libffi, musl | MIT | Full upstream copyright/conditions. |
| ncurses, ncurses-terminfo-base, libncursesw, libpanelw | X11 | Full upstream copyright/conditions. |
| libuuid | BSD-3-Clause | Matching copyright/conditions. |
| mpdecimal | BSD-2-Clause | Matching copyright/conditions. |
| python-3.14 and three bytecode subpackages | PSF-2.0 | Retain complete Python license and describe Keep's exact patches. |
| sqlite-libs | blessing | Preserve provenance and attribution where present. |
| tzdata | Public-Domain | Retain the versioned source license and identify any BSD code exceptions. |
| zlib | Zlib | Retain the bundled license and identify the modified upstream source/security hunk. |

For downloaded GPL binaries, provide the matching corresponding source with
equivalent access, including patches and build scripts. A generic upstream URL,
an SBOM license label or Keep's MIT license does not replace those materials.
See the [SFLC compliance guide](https://softwarefreedom.org/resources/2008/compliance-guide.html).

Scanner origin expressions can differ from the licenses of installed files.
Review the actual package sources and retained notices before selecting a license
branch or applying an exception. Embedded libraries and earlier image layers have
their own source and notice requirements. The source collector binds package
binaries, recipes and source hashes as described above; provider build identifiers
and upstream recipe commits are not interchangeable.

## Retention

Keep every distributed release's matching source archives, checksums and original
verification evidence, even after its container tags are removed or its security
support ends. Source-release assets have no automated deletion policy. Preserve
the local copies outside disposable worktrees and retain their accompanying
notices. Routine CI log retention does not limit durable release-asset retention.
Removing a container tag, image index or native manifest does not authorize
removing the corresponding source archives, notices, checksums or original
verification evidence. Keep those materials available for every distributed
release independently of registry cleanup.

## Release delivery

Each finalized GitHub release must retain its architecture-specific source
archives, notices, checksums and original verification evidence. Link the matching
source downloads beside the corresponding image on Docker Hub. Draft assets and
finite Actions artifact retention do not provide public source delivery.

Before announcing a public release, download both architecture source bundles and
their checksums without authentication. Verify the archive hashes, manifest
version and revision, and the image index and native digests against the release.
Check every source and notice link as an unauthenticated recipient. An authenticated
maintainer download or a public repository setting alone does not establish that
all release assets are accessible. See the [release policy](RELEASE_POLICY.md) for
validation, source delivery and reporting requirements.
