# Backup and restore

Keep stores private and operationally important state in `/app/data/keep.sqlite3`:
service credentials, local password hashes, ownership and setup state, accounts,
preferences, Keeps, deletion permissions and library grants, Seerr links/history,
reminder claims, connection checks, and pending or held background work. Back up
the database together with the private `.env`, Compose overrides, and exact image
reference. Encrypt off-host copies and restrict access. Git and container images do
not contain this durable data.

The `portable_backup` module, included in Keep 2.18.0,
uses Python's standard-library SQLite backup API. It reads the source database
read-only, so committed WAL contents are included without copying live `-wal` or
`-shm` files. It checks SQLite integrity,
writes a mode-0600 temporary snapshot in the destination directory, and publishes
it atomically. It refuses symlink files, non-private destination directories, and
existing destinations. It does not print database contents or stored credentials.
The destination directory must already exist, be owned by the container user, and
have mode 0700. Keep separate dated files; the command never applies retention or
deletes older backups.

## Create a backup

The examples below use a Linux/macOS shell. Docker Desktop hosts must also verify
the effective Linux ownership and permissions of a backup destination inside the
container; host permissions alone do not establish those values. On Windows,
use a controlled Docker volume/export or an appropriately prepared bind mount
and adapt the host path and shell syntax for PowerShell. Do not assume that a
Windows directory gives the container UID 10001 and mode 0700.

For planned maintenance, stop both Keep services first. The SQLite API can make a
consistent snapshot while writes continue, but stopping the web and digest worker
also prevents new Keep work while you preserve the matching deployment files.

```sh
docker compose stop keep-app keep-digest
docker compose ps --all
```

Confirm both services show as stopped. Set `BACKUP_DIR` to an existing protected
host directory with mode 0700. The directory must appear inside the container as
owned by UID 10001 with mode 0700; on a Linux Docker host, prepare it for that UID
before running the command. On Linux, create this exact directory and set its
ownership without changing any parent or unrelated files:

```sh
BACKUP_DIR=/private/path/keep-backups
sudo mkdir -m 0700 "$BACKUP_DIR"
sudo chown 10001:10001 "$BACKUP_DIR"
```

If it already exists, inspect its ownership and permissions first. Use elevated
host access when copying or verifying these protected files off-host. Docker
Desktop can translate bind-mount ownership differently; verify the effective
UID and mode in a one-off container before relying on the path. A private Docker
volume with a deliberately controlled export is an alternative. Use a new output
filename each time.

```sh
BACKUP_DIR=/private/path/keep-backups
docker compose run --rm --no-deps --entrypoint python \
  -v "$BACKUP_DIR:/recovery" keep-app \
  -m portable_backup backup \
  --database /app/data/keep.sqlite3 \
  --output /recovery/keep-2026-10-01.sqlite3
```

The command must report that it created and integrity-checked the backup. Keep
the exact image reference, private environment file, and Compose overrides with
the recovery point. Verify the backup's existence, owner, mode 0600, and integrity
before restarting:

```sh
sudo stat -c '%U:%G %a %n' "$BACKUP_DIR/keep-2026-10-01.sqlite3"
docker compose start keep-app keep-digest
docker compose ps
```

Confirm both services return to their expected healthy state. Copy the backup to
an encrypted off-host location and verify its integrity there too. Record its
date, image/version, destination, and integrity result. Schedule daily backups and
one before each migration; retain at least 14 daily copies plus any recovery point
needed for an upgrade. Portable Compose does not install a backup scheduler.

## Restore to a stopped installation

Restoring replaces no existing file automatically. Stop both services and confirm
they are stopped using `docker compose ps --all`. Preserve the current database and any `-wal`, `-shm`, or
`-journal` sidecars as a separate recovery point. Then move those exact files out
of the active names within the `keep-data` volume; do not delete them. Choose a
new suffix each time. This one-off command checks every source and destination
before moving any file, and refuses symlinks or collisions:

```sh
RECOVERY_SUFFIX=before-restore-20261001
docker compose run --rm --no-deps --entrypoint python \
  -e RECOVERY_SUFFIX="$RECOVERY_SUFFIX" keep-app -c '
from pathlib import Path
import os, re
suffix = os.environ["RECOVERY_SUFFIX"]
if not re.fullmatch(r"[A-Za-z0-9._-]+", suffix):
    raise SystemExit("invalid recovery suffix")
root = Path("/app/data")
pairs = [(root / ("keep.sqlite3" + ext), root / ("keep.sqlite3." + suffix + ext))
         for ext in ("", "-wal", "-shm", "-journal")]
for source, target in pairs:
    if source.is_symlink() or target.is_symlink() or target.exists():
        raise SystemExit("refusing symlink or existing preservation target")
for source, target in pairs:
    if source.exists():
        source.rename(target)
'
```

If any preservation target already exists, stop and choose a new unique suffix.

Mount the verified snapshot directory read-only and restore to the now-absent
database path. The one-off Compose container mounts the same `keep-data` volume as
the service, but does not start the app or digest worker:

```sh
docker compose run --rm --no-deps --entrypoint python \
  -v "$BACKUP_DIR:/recovery:ro" keep-app \
  -m portable_backup restore \
  --input /recovery/keep-2026-10-01.sqlite3 \
  --database /app/data/keep.sqlite3
```

The helper verifies the input and restored database, creates the database with
mode 0600, and refuses an existing target or symlink. It cannot determine whether
other containers have the volume open; confirm both services are stopped before
the restore and keep them stopped until it succeeds. Restore the matching `.env`,
Compose overrides, and image reference. Start the services, verify health and
owner/local-account login, then compare key account, preference, Keep, permission,
Seerr, reminder, and pending/held queue state with the recovery point. Do not let
restored work dispatch to production integrations during a trial.

## Isolated recovery acceptance

Use a separate Compose project and volume, a separate loopback port, and the
intended recovery image. Disable outbound email and block production integration
access before starting the worker. The worker also checks service history, scans
reminders, and processes queued Seerr synchronization; disabling email alone does
not isolate those operations. Use disposable service fixtures or grant only the
controlled access needed by the trial. Record the date, image, backup timestamp,
restore result, and observed state. Remove only the named trial containers,
volume, and private temporary copies after verification.

A successful backup and integrity check do not prove a usable restore. The native
workflow exercises installation, restore, and API credential/retry-state recovery
against the packaged candidate on both architectures. See the
[recovery validation guide](RECOVERY_TRIAL.md) for the procedure and scope. These
synthetic checks do not establish an unfamiliar operator's recovery or real
household acceptance. A restore loses changes after the chosen backup; queued
SMTP deliveries may need review to avoid duplicates.
