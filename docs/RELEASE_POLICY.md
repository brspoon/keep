# Release policy

## Validation and publication

Every pull request receives read-only Python, JavaScript and Windows installer
checks without repository secrets. After merging, the main-push workflow builds
and fully validates amd64 and arm64 once. Native security, installation, recovery,
and matching-source checks remain required before publication. Only trusted main
jobs receive the credentials needed to obtain the pinned base and source materials.

The workflow first classifies the complete Git diff. Only explicitly allowlisted
prose and screenshots for an already published version may skip native image
validation. Python, JavaScript and Windows installer checks still run, and the
Actions summary explains which validation path was selected. Build inputs,
dependencies, installers, tests, source locks, security policies and license
materials receive full native validation. Unknown paths, missing diff information
or unavailable release metadata also require full validation. An unpublished
version needs exact-commit native validation even for documentation changes;
no image or source evidence is borrowed from another commit.

Independent OS and Python source downloads use up to four workers. Each source
still passes its original identity, checksum, signature, architecture and coverage
checks, and reports retain their deterministic order. This does not introduce a
persistent source cache or reuse an earlier successful verification result.

Both architectures also run the installer against real Docker containers,
checking startup, HTTP setup cookies and owner-preserving reruns. An independent
Windows job validates PowerShell 5.1 syntax and native filesystem permissions,
locking and launcher behavior in the same main validation run. Full Windows Docker
Desktop, LAN-device and Plex acceptance remain separate checks; see
[development testing](DEVELOPMENT_TESTING.md#installation-platforms).

Image publication runs only from a manual `workflow_dispatch` on `main`, with
`publish_release` set to `true`, confirmation set to `release-stable`, and
`validation_run_id` identifying the successful main-push run for that exact commit.
Main pushes never publish an image, even when `VERSION` changes. Both native
jobs must pass, the tested source commit must still be current main, and the
publisher may use only their retained tested images. The manual workflow restores
and verifies the original files; it does not build, rescan or repeat the long native
tests. Publication supports private
or public repositories without changing either repository's visibility.

Version and commit tags are immutable. The publisher verifies the native child
digests in the multi-platform indexes and promotes mutable `stable` last.
An existing version skips new image publication, so a documentation-only change
does not create a new runtime release. Runtime or image-input changes require a
version bump; documentation and release-tooling changes outside the image inputs
do not.

## Release files

Main validation saves each tested image, matching source archive, checksum, and
original security, installation and recovery evidence in an unpublished candidate
draft named for the full source commit and validation run. These draft assets are
available to maintainers; validation never uploads an unapproved image to Docker Hub.
Only a small immutable index is uploaded as an Actions artifact, retained for
90 days. It binds the original producer job and attempt to the draft asset IDs,
sizes and SHA-256 hashes. Large image and source archives stay out of Actions
artifact storage.

Approved publication checks the successful primary-repository main workflow and
its required jobs, verifies the index and original assets, and restores the exact
image configuration. It stages the original source archives and evidence in the
version's separate draft release. Aggregation checks both original build identities,
asset hashes and current publication transfer tags. The publisher checks loaded
image configurations and native manifest digests before creating version or commit
indexes and promoting stable. Original scanner reports must still satisfy the
checked-in review policy and its expiry; scanners are not rerun.

After verification, finalize the version draft as a normal GitHub release,
preserving all assets. Candidate storage remains unpublished. A draft is temporary
staging, not a release for users to install.
GitHub release immutability is enabled for future releases. Attach and verify every
source, checksum, notice and evidence asset before publishing the version draft:
publication locks its assets and source tag. Assets cannot be added, replaced or
deleted afterward; corrections require a new release. Release titles and notes
remain editable. Releases published before this setting was enabled are not
retroactively locked. See [GitHub's immutable-release guidance](https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases).
For a public release, finalized notes, source archives, notices, checksums and
image tags must be accessible without authentication. Source delivery requirements
are described in [source distribution](SOURCE_DISTRIBUTION.md).

Matching source archives and original verification evidence are retained for
every distributed version, independently of container tag cleanup or support
status. CI log expiry is not a source-retention policy. See
[source distribution](SOURCE_DISTRIBUTION.md).

## Publishing a validated main commit

1. Wait for the main-push **Validate Keep and publish retained images** run to
   succeed. Copy its numeric run ID from the Actions URL (`/actions/runs/<id>`).
2. Review that commit and its original validation evidence, then obtain publication
   approval. A successful validation run alone does not authorize publication.
3. Select **Run workflow** on `main`, enter that ID as `validation_run_id`, enable
   `publish_release`, and enter `release-stable` as confirmation.
4. Review the promotion result and finalize the version draft with its original
   source and evidence assets. Verify public downloads and image identities before
   announcing the release.

If a native job fails, investigate the failure and use **Re-run failed jobs** after
it is understood and safe to retry. A successful architecture can retain its
original attempt's image; restoration verifies each architecture's producing job,
attempt and retention steps independently, and requires the entire selected run
to finish successfully. Do not rerun successful jobs just to publish.

Missing, expired, altered or wrong-commit records stop publication. There is no
fallback build or substitution from another commit. When the 90-day index has
expired, explicitly request new main validation before publication. Keep candidate
drafts intact while their validation may be used; deleting one prevents promotion.
Already published versions retain their durable source and evidence assets
independently of candidate/index expiry.

## Temporary validation storage

The **Clean superseded validation drafts** workflow runs after main validation
completes, with a daily catch-up run. It protects all candidates for current main
and the latest usable successful native build, even
when a later documentation commit skipped image validation. It leaves storage
alone while validation or publication is active. Superseded or abandoned failed
candidates are eligible immediately, without an extra grace period. If no
usable index remains, it conservatively protects the latest successful candidate
until replacement validation exists.

Cleanup verifies the primary-repository producer, draft namespace, creator,
original indexes and exact provider IDs before removing a candidate's temporary
indexes and draft. It rechecks mutable state before deletion and refuses changed
or ambiguous metadata. It never deletes version releases, their distributed
source/evidence assets, Git tags or registry objects. Cleanup, main validation
and publication share a queue with cancellation disabled.

Maintainers can select **Run workflow** for a read-only inventory. The manual
`execute` input defaults to `false`; enable it only to apply the scoped retention
plan. The local command `python3 scripts/validation_retention.py` also defaults to
an inventory and requires authenticated read access to drafts. Deletion is
restricted to the trusted retention workflow on current main.

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
