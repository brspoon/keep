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
tests. Published Keep releases and images are public.

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
checked-in review policy. Each exception needed by a matching finding must still
be within its inclusive review deadline on the promotion date; unused expired
exceptions do not block a clean scan. Scanners are not rerun. Revalidation uses
`scripts/review_image.py --check-only` when archiving. Aggregation and final
publication read and verify the original retained report bytes again and apply
the current review policy. The verified reports are reassessed immediately before
each native image or manifest push, including stable, so a queued publication or
UTC date change cannot reuse an earlier deadline decision. The original reports
and review evidence remain byte-for-byte unchanged.

Read-only deadline checks warn in contributor runs and in the daily/manual
**Review image-exception deadlines** workflow. These warnings are advisory,
including for unused expired exceptions. They do not approve additional risk or
replace native image validation. See [image security](IMAGE_SECURITY.md) for
deadline behavior and dependency replacement requirements.

Maintainers can use **Review vendor runtime candidate** with `qualification`
enabled to test both native images and prepare checked notice bytes on a
maintainer branch. It has read-only repository access and never retains a
promotion image. Failed security review still fails qualification, while checked
source preparation can produce reviewable notice records. Commit the verified
notice union, rebuild, and complete normal main validation before publication.

After verification, finalize the version draft as a normal GitHub release,
preserving all assets. Candidate storage remains unpublished. A draft is temporary
staging, not a release for users to install.
GitHub release immutability is enabled for future releases. Attach and verify every
source, checksum, notice and evidence asset before publishing the version draft:
publication locks its assets and source tag. Assets cannot be added, replaced or
deleted afterward; corrections require a new release. Release titles and notes
remain editable. Releases published before this setting was enabled are not
retroactively locked. See [GitHub's immutable-release guidance](https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases).
Finalized release notes, source archives, notices, checksums and
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

## Upgrades and registry retention

Publication does not restart an installation. Operators upgrade both Keep
services together after backing up their data and deployment configuration.
Portable Compose does not install automatic upgrade or backup
schedules. See [upgrades](MIGRATION.md) and [backup and restore](PORTABLE_BACKUP.md).

Only the latest stable release receives fixes. Older release images retained for
rollback are recovery aids, as described in [supported versions](../SUPPORT.md).
Container tag retention does not limit retention of matching source archives,
notices, checksums or original verification evidence.

Before removing temporary registry artifacts, verify their exact tags, digests
and references. Preserve image indexes and native manifests referenced by retained
tags, and leave active or unrecognized build artifacts intact. CI removes only its
own temporary publication tags; see [image security](IMAGE_SECURITY.md) for its
credential boundaries.

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
  scope.
- Keep GitHub private vulnerability reporting enabled.
  Test the form and maintainer notification with a non-maintainer account before
  accepting external reports. If unavailable, configure and test a confidential
  reporting channel before announcement; never solicit vulnerability details in
  public issues. See [SECURITY.md](../SECURITY.md).
- Verify the documented installer, both architecture images, and every source and
  checksum download without authentication. Finalize staged releases so the linked
  assets are accessible, then check their identities and hashes.

Main's own checks must pass as well as the manually dispatched release workflow.
Publishing an image does not establish that any installation has upgraded.
