# Release policy

## Validation and publication

GitHub Actions tests amd64 and arm64 on main pushes and trusted pull requests.
External-fork pull requests receive a separate read-only Python and JavaScript
validation job, without repository secrets. Native build, security, and source
checks require the maintainer's configured registry credentials and are required
for a release.

Both architectures also run the installer against real Docker containers,
checking startup, HTTP setup cookies and owner-preserving reruns. An independent
Windows job validates PowerShell 5.1 syntax and native filesystem permissions,
locking and launcher behavior before release preparation. Full Windows Docker
Desktop, LAN-device and Plex acceptance remain separate checks; see
[development testing](DEVELOPMENT_TESTING.md#installation-platforms).

Image publication runs only from a manual `workflow_dispatch` on `main`, with
`publish_release` set to `true` and confirmation set to `release-stable`.
Main pushes never publish an image, even when `VERSION` changes. Both native
jobs must pass, the tested source commit must still be current main, and the
publisher may use only their exact tested images. Publication supports private
or public repositories without changing either repository's visibility.

Version and commit tags are immutable. The publisher verifies the native child
digests in the multi-platform indexes and promotes mutable `stable` last.
An existing version skips new image publication, so a documentation-only change
does not create a new runtime release. Runtime or image-input changes require a
version bump; documentation and release-tooling changes outside the image inputs
do not.

## Release files

The native workflow prepares matching source archives, checksums, and original
security, installation and recovery evidence for each architecture. During a deliberately
confirmed release, it stages those files in a GitHub draft release. Aggregation
checks the original image identities, asset sizes and hashes, and exact run and
attempt transfer tags before promoting the image. It does not recollect source
materials or replace evidence from the jobs that tested the images.

Ordinary pull-request and main-push validation uses read-only repository
permissions, retains proof in CI logs, and does not upload Actions artifacts.
Only the confirmed release jobs receive the write permissions needed for draft
assets. The aggregation job uses that permission to read draft metadata and
verify assets; it never changes repository visibility.

After verification, finalize the candidate as a normal GitHub release, preserving
all assets. A draft is temporary staging, not a release for users to install.
For a public release, finalized notes, source archives, notices, checksums and
image tags must be accessible without authentication. Source delivery requirements
are described in [source distribution](SOURCE_DISTRIBUTION.md).

Matching source archives and original verification evidence are retained for
every distributed version, independently of container tag cleanup or support
status. CI log expiry is not a source-retention policy. See
[source distribution](SOURCE_DISTRIBUTION.md).

## Deployment and registry cleanup

Publication does not restart an installation. Operators upgrade both Keep
services together after backing up their data and deployment configuration.
Portable Compose does not install automatic upgrade, backup, or registry-cleanup
schedules. See [upgrades](MIGRATION.md) and [backup and restore](PORTABLE_BACKUP.md).

The maintainer's [registry retention policy](REGISTRY_RETENTION.md) keeps up to seven
tags after a verified deployment: `stable`, the current version, its commit tag,
that commit's amd64 and arm64 tags, and up to two preceding versions for rollback.
These typically refer to three image indexes and six native child manifests.
Only the latest stable release receives fixes; the preceding versions are
recovery aids. Unknown custom references and active or unreviewed build artifacts
remain protected.

Registry cleanup uses separate credentials from image publication. Ordinary Keep
installations need neither. The maintainer's cleanup tooling checks release and
build identities before removal; unavailable information protects the affected
objects. See [registry retention](REGISTRY_RETENTION.md).

## Before announcing a release

Maintainers should verify the release before announcing availability:

- Check the exact source commit's required native tests, current image-security
  review and source/license materials. A passing run for another commit is not
  evidence for this release.
- Record browser, integration, installation and recovery observations separately
  from automated tests. Document any untested platform or deferred manual trial.
- Review repository history, release files, workflow logs and image layers for
  credentials, private data and internal operational records before exposing them.
- Verify branch protections, release/tag permissions and publication credential
  scope. Repository and registry visibility changes remain a separate maintainer
  decision; the workflow does not change them.
- Enable GitHub private vulnerability reporting when the repository is public.
  Test the form and maintainer notification with a non-maintainer account before
  accepting external reports. If unavailable, configure and test a confidential
  reporting channel before announcement; never solicit vulnerability details in
  public issues. See [SECURITY.md](../SECURITY.md).
- Verify the documented installer, both architecture images, and every source and
  checksum download without authentication. Finalize staged releases so the linked
  assets are accessible, then check their identities and hashes.

Main's own checks must pass as well as the manually dispatched release workflow.
Publishing an image does not establish that any installation has upgraded.
