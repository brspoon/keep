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
also supply the exact signed CA 20260909, GDBM 1.26 and Readline 8.3 source
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
DHI Expat 2.8.5 in an earlier image layer retains its exact APK hashes,
native-base material binding and signed package sources separately from the
installed Alpine 2.9.0 packages. Keep's exact Python patches and modified zlib 1.3.2 sources are
also included. The Python source lock covers all 17 pinned distributions,
including Certifi's MPL-covered material. Native CFFI wheel bytes are checked
against their embedded libffi 3.4.6 source and wheel build recipe; this is
separate from the OS libffi package. Argon2's embedded source and complete
license choices are retained too. Earlier base layers also carry Python's bundled
pip 26.2.1 and wheel 0.48.0. Their Python modules are checked against matching
source distributions; the six embedded distlib 0.4.2 Windows launchers are
matched to its complete source distribution and C/build inputs. Their full
notices and vendored attribution accompany these materials.

Docker's timezone package tag is reused across IANA releases. If it no longer
matches the recorded 2026d APK, a narrowly scoped fallback obtains IANA 2026d,
the pinned provider and Alpine recipes, all checksum-verified source inputs and
patches, and their notices. The report explicitly records that no historical
provider OCI binding was established. It does not substitute this fallback for
a missing signature or mismatched binary of another package.
The complete GNU LGPL 2.0 notice for the retained POSIXtz build source is read
from its committed `docs/licenses/os` file and checked against the same reviewed
SHA-256 before collection. This avoids a repeated GNU website download. The
source manifest keeps the original GNU URL and records that the verified notice
was acquired from the repository; missing, changed or oversized notice files
still block collection.

If the reviewed OpenSSL 3.5.9-r0 package repository has no retrievable image or
package attestation, a separate narrow reconstruction checks the actual APK
identities against the signed pinned base provenance and runtime inventory,
then retains the matching pinned public provider/Alpine recipes, every patch,
and checksum-verified OpenSSL source. Its report explicitly records the absence
of a signed package build or source-image binding. This method does not rescue
a signature failure or an unrelated missing package.

The Expat replacement uses Alpine's signed `2.9.0-r0` APKs, independently
pinned for amd64 and arm64. The installer checks each APK and official key hash,
its RSA signature, signed metadata and payload hash, exact library bytes and
SONAME alias. It installs only these files with networking disabled and the
pinned public keys; the temporary APKs, keys and installation tools are mounted
without entering a final image layer. Source collection retains the original
APKs and key, complete immutable aports context, checksum-matching upstream
source and full MIT notice. It records Alpine package verification without a
Docker package-build or source-image attestation claim. The upstream detached
signature is retained without claiming separate OpenPGP verification.

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
release 2.23.2:

```sh
sha256sum -c keep-2.23.2-source-materials-amd64.tar.gz.sha256
```

Use `shasum -a 256` on macOS and compare its output to the checksum file.
After unpacking, the manifest identifies each retained file's SHA-256, release
version, architecture and source revision. Both architecture archives are
needed to cover both published images. Full OS notices and their provenance are
also retained in `docs/licenses/os` and copied to `/app/licenses/os` in the
container. The prepared runtime union contains 124 complete notice texts
(814,844 bytes), covering all 20 current and earlier-layer origins on both
architectures, including 20 explicitly reviewed source copyright headers.
The native gate checks the rebuilt candidate against those committed hashes.
It also verifies the exact installed notice-manifest bytes and every generated
notice's complete native source attribution against the committed provenance.
Sharing a license text does not transfer its source or signature evidence.
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
