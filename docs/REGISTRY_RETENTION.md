# Keep registry retention

The selected policy keeps seven release tags when three releases are available:

- `stable`, the current version, `sha-<current-source-revision>` and its
  `-amd64`/`-arm64` tags;
- the two preceding semantic version tags, for registry-based rollback.

An optional `minimum_release` baseline excludes older versions from the rollback
set. At the baseline release, retention keeps its five current aliases; the next
two releases grow the set to six and seven tags. Older version tags and recognized
build aliases become cleanup candidates, subject to every safety check below.
Unknown references and active transfers remain protected.

The prior version indexes keep their native manifests. Their redundant commit
and architecture aliases can be removed without deleting those manifests.
Seven tags normally refer to nine manifest objects: three release indexes and
their six native children. Shared child digests can reduce that object count;
additional protected artifacts can increase it. A tag count is not an image
object count, and an untagged native child is not an orphan while an index uses it.
The latest approved stable release receives security fixes; rollback versions
may lack them. Matching-source retention is independent: removing an image tag
does not authorize removing source archives, notices or release evidence.

These scripts are advanced maintainer tools for the `brspoon/keep` registry.
Ordinary Keep users do not need to run them. The installer and portable Compose
configuration do not install registry-retention or deployment jobs. Maintainers
configure the host integration and any retry schedule separately. The
post-deployment wrapper described below adds cleanup after a verified update.

## Safety checks

The script modifies only `brspoon/keep`. It verifies repository identity and an
explicit public or private visibility value without changing visibility. Both
application and digest containers must be healthy and match the successful
deployment receipt. `stable`, version, source and native aliases must agree with
the running release. A newer staged version, pending/failed deployment, or a busy
deployment lock holds cleanup.

Before deletion, the script checks live SQLite integrity, the retained local
recovery receipt, database and configuration archive, recorded image identities,
and a full NAS backup from the past 48 hours covering the current environment and
Compose files. Local rollback Docker images may be removed after a healthy
deployment; their absence does not block registry retention. Retained preceding
release indexes and their native manifests remain protected in the registry.
These checks establish that recovery materials are present and consistent; the
separate isolated restore trial establishes that the tested recovery procedure
works.

Every write rechecks health and registry references. Build aliases are removed
before obsolete version tags, then only manifests with no remaining references
are eligible for removal. A shared manifest remains protected even when a
redundant tag is deleted. Local Docker images, volumes and host/NAS backups are
never pruned by this tool.

## Transfer and orphan artifacts

Current publication uses temporary `transfer-<run>-<attempt>-<architecture>`
tags. CI attempts to remove its own tags with the publication token; a token
without delete permission can leave them behind. CI does not receive broader
deletion authority to avoid that warning.

Unknown/custom tags, orphan commit tags and unreviewed transfer tags remain
protected. The tag count can temporarily exceed seven during a build or while
an artifact needs review. With the explicit credential configuration below,
`retain_registry.py --refresh-artifacts` reviews the exact GitHub workflow
attempt and digest from the fresh registry inventory while holding the existing
deployment lock. Its bounded GitHub reader accepts only the fixed Keep
repository and workflow metadata endpoints, sends GET requests, and rejects
redirects. Active, unknown, mismatched or incompletely inventoried attempts are
excluded. Unavailable access grants no removal permission; later hourly runs can
retry the review. No CI deletion permission is expanded.

An operator can still prepare the same exact review with
`scripts/review_registry_artifacts.py`, using an authenticated GitHub CLI and a
fresh, complete registry inventory. Automatic review does not turn an unknown
custom tag or an unseen untagged object into a deletion target.

The resulting owner-only `retention-artifacts.json` records terminal attempt
identities and exact tag digests. Place the reviewed file in the host's
`.registry-state/` directory with mode `0600`. The cleanup script rejects
nonterminal evidence, wrong repositories, mismatched run/attempt/source IDs,
changed digests and unsafe review-file permissions. This file grants no general
wildcard deletion permission. Automatic refresh atomically replaces this file
with the newly verified terminal attempt/tag identities; new build artifacts
require their own review rather than a wildcard approval.

The persistent manifest backlog preserves exact admitted digests and parent/child
relationships before tags disappear. Interrupted deletion, process restart and
later tag removal must not discard unfinished targets. A retained, custom or
unreviewed parent protects its children, including an untagged parent; parent
absence must be confirmed before its eligible children are removed. Unknown
references win over deletion eligibility.

The private owner-only `.registry-state/retention-manifests.json` uses schema
`keep.registry-manifest-backlog.v1`, fixed image `brspoon/keep`, and a `manifests`
object mapping each exact digest to its `children` digest list. Every child must
have its own record. Only reviewed obsolete targets belong in this seed;
protected objects stay outside it. The retainer refreshes immutable manifest
bytes and persists the resulting graph before deleting any tags.

Docker Hub's supported tags API does not enumerate arbitrary untagged manifests.
The initial backlog therefore needs an explicitly reviewed exact-digest seed,
matched against a complete Image Management inventory and all protected release
objects. It is not permission to delete every untagged object. The ledger tracks
the known graph and subsequent managed releases; an unseen out-of-band untagged
parent remains an inventory blind spot requiring fresh operator review. Preserve
matching source assets and original evidence regardless of image deletion.

## Credentials and operation

The default deployment root is the checkout containing the script. Both
`retain_registry.py` and `update_and_retain_registry.py` accept `--root` when an
operator needs to identify a different deployment checkout.

Before either helper can trigger cleanup, provision the private
`.registry-state/retention-config.json` file with these four required fields:

```json
{
  "backup_directory": "/path/to/keep-backups",
  "backup_pattern": "keep-backup-*.tar.gz",
  "containers": ["keep-keep-app-1", "keep-keep-digest-1"],
  "archive_prefix": "keep"
}
```

Use the actual full-backup directory, archive filename pattern, live container
names and archive layout for that installation. List the application container
first and the digest container second. The backup directory must be an existing
absolute directory; the pattern must match archive basenames ending in
`.tar.gz`, with no directory components. The archive prefix is the single
top-level directory containing the deployment configuration inside the full
backup. Retention still compares those saved files with the current deployment.

The only optional field is `minimum_release`, a semantic version such as
`"2.0.0"`. It must not exceed the verified production version. Omitting it keeps
the two preceding releases without a baseline. A baseline change requires a new
review of any pending cleanup plan using `--replace-stale`.

The state directory must be owned by the executing user with mode `0700`, and
the configuration must be a regular owner-owned file with mode `0600`.
Symlinks, duplicate or unknown fields, invalid values and files exceeding
16 KiB are rejected. Missing or changed configuration holds cleanup; it never
waives recovery checks. Keep deployment-specific values in this private file,
out of version control. Install and verify it before updating an
existing host's helpers.

Use the existing host-side cleanup token, stored as a private owner-only
`.registry-state/retention-token` file. The token needs the Docker Hub deletion
capability; normal CI retains its separate read/write publication credential.
Docker personal-token scope can be broader than one repository, so the script
hardcodes the repository and rejects redirects and foreign pagination URLs.

Automatic GitHub review requires an explicit `.registry-state/github-review.json`
with exactly these fields:

```json
{
  "schema": "keep.registry-github-review.v1",
  "source": "token-file"
}
```

The `.registry-state` directory must be owned by the executing host user with
mode `0700`. The configuration must be a bounded regular owner-owned file with
mode `0600`; symlinks are rejected. For `token-file`, provision the approved
GitHub read credential privately at the fixed `.registry-state/github-read-token`
path with the same owner and mode `0600`. There is no configurable token path.
Use a credential that can read this repository's metadata and Actions
workflow attempts. An existing approved GitHub sign-in credential may be supplied
through the private host handoff; any broader account privileges remain those of
the credential, while this client permits only the fixed GET operations.

Alternatively, explicitly set `"source": "git-remote"` to reuse a credential
already embedded in this checkout's exact Keep HTTPS `origin` URL. Only
`github.com/brspoon/keep` or its `.git` form is accepted, without a port, query
or fragment. This option does not modify the remote or discover credentials
from other repositories. Missing configuration disables automatic review;
invalid or unsafe local configuration holds cleanup. Installation and observed
review/cleanup remain separate operational evidence.

On the configured production host, preview before executing:

```sh
cd keep
python3 scripts/retain_registry.py --refresh-artifacts
# Inspect the exact retained tags, protected extras, deletion tags and digests.
python3 scripts/retain_registry.py --execute --refresh-artifacts
```

Plans and results are saved privately in `.registry-state/retention-plan.json`
and `retention-result.json`. An interrupted execution preserves
`retention-pending.json` and resumes only its reviewed targets. If the production
version or policy changes, preview and review the replacement before using
`--execute --replace-stale-pending`; the old proposal is archived. The hourly
job never replaces stale state automatically.

After installing and verifying the configured reader, include
`--refresh-artifacts` in the existing hourly `--execute` invocation so terminal
transfer attempts can be admitted on later retries. Updating the schedule and
observing a completed execution require separate host receipts; this document
does not establish that the new reader or schedule is installed.

## Post-deployment trigger

After installation on the configured host, the queued update job can invoke:

```sh
cd keep
python3 scripts/update_and_retain_registry.py --queued
```

The wrapper invokes the host's existing `scripts/update_registry.py` and waits
for it to exit. Only exit zero plus a validated changed deployment receipt, a
newer completion timestamp from the past 24 hours, and cleared deployment hold,
pending and failure state can trigger
`retain_registry.py --execute --refresh-artifacts`. The wrapper
checks that the deployment lock is available, releases its probe, and lets
retention acquire that same lock for its own full safety checks. An unchanged,
malformed, stale or future-dated receipt cannot trigger cleanup. The host updater
is not copied into this repository or changed by the wrapper.

Guarded manual releases may keep the deployment hold through final verification.
After the operator removes that hold, explicitly run:

```sh
python3 scripts/update_and_retain_registry.py --after-deploy
```

This mode skips the updater and accepts only a fresh valid completed receipt with
all holds removed. A private `.registry-state/retention-after-deploy.json` marker
records the exact receipt only after successful cleanup and prevents repeated
successful triggers. A cleanup hold or failure preserves deployment success and
does not write that marker; the hourly retention job remains the retry path.
Neither mode removes holds, alters recovery state, broadens deletion authority,
changes repository visibility or performs local Docker pruning. CI publication
does not invoke this host cleanup path.

During an explicit release, coordinate the host's deployment hold and updater
lock before publication, so registry cleanup cannot race staged images. Remove
the hold only after the successful paired deployment and recovery verification.
Do not remove pending state blindly, change visibility, or run broad Docker
pruning as part of this procedure. See [release policy](RELEASE_POLICY.md).
