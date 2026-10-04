# Upgrades and legacy migration

## Upgrade an installation

Work from the installation directory (`~/keep` on Linux/macOS, `$HOME\keep` in
Windows PowerShell for the one-command installer).
Read the target release notes and [create a verified backup](PORTABLE_BACKUP.md)
of the database, `.env`, Compose files, and exact current image before upgrading.
Test the new release on an isolated copy when it changes data or recovery behavior.

Edit `KEEP_IMAGE` in `.env` to select the new version. For example, to select
Keep 2.21.4:

```dotenv
KEEP_IMAGE=brspoon/keep:2.21.4
```

Then pull and recreate both services together:

```sh
docker compose pull
docker compose config --quiet
docker compose up -d
docker compose ps
```

Confirm both services are healthy. Sign in and verify connections, Keeps,
preferences, and background work before considering the upgrade complete.
Rerunning the installation command preserves the existing version and settings;
it does not perform this upgrade for you.

## Data and rollback

The pre-portable import below is a one-time migration, not a step for every
upgrade. For a portable installation, record the running image reference/version,
Compose project, volume name and private configuration. Create and verify a
SQLite backup, review the target changelog, and test the upgrade on an isolated
copy. Update web and worker together against the same database and exact image
reference. The Compose files downloaded at installation keep that release's
default image; set `KEEP_IMAGE` to a reviewed version tag or digest when selecting
another release. Never mix
image versions between the services. Verify health, owner login, service
connections, keeps, subscriptions and notification state after activation.

Keep 2.3 adds persistent ownership and setup/authorization tables. Existing
PLEX_OWNER_ID installations retain that identity and bypass first-run setup.
Do not issue a new bootstrap code or change the owner ID during an upgrade.
A conflicting owner override fails closed; investigate rather than replacing
the database. Later releases also add deletion permissions, Seerr history/links/sync queues,
automatic checks, appearance preferences and durable reminder claims. Include
those in rehearsals; older code is not assumed compatible with the latest schema.
For rollback, stop both services, restore the complete pre-upgrade database and
matching private configuration, restore data ownership if needed, then start the
exact prior image reference. Do not run an older image against the modified
post-upgrade database. The default application user is UID/GID 10001; existing
volumes must be readable and writable by that identity.
Before 2.17.3, completed per-title reminder history was not retained. The first
catch-up scan cannot reconstruct historical delivery; review queue behavior and
[the reminder upgrade note](INSTALLATION.md#leaving-reminders-and-email-appearance).

## Upgrade from a pre-portable release

Rehearse this on an isolated copy first, and perform the production cutover only
with operator authorization. Never run migrations without a verified backup.
This older migration requires a source checkout containing
`scripts/migrate_configuration.py`; it is not part of the one-command fresh install.

1. Record the current image ID, Compose project, volume name and effective config.
   Preserve the old source `app.py` and private `.env`. Back up the live SQLite
   database using SQLite's backup API and verify `PRAGMA integrity_check`.
2. Stop both old services for the migration cutover. Keep rollback copies of the
   database, source, Compose files and `.env` outside Git, readable only by the owner.
3. Run the new `scripts/migrate_configuration.py --source /private/old-app.py
   --database /private/keep.sqlite3` with the old deployment environment loaded.
   The script reads literal assignments with Python AST; it never executes old
   code. It imports legacy collection labels and SMTP branding, then overlays
   explicit environment settings. It does not print any values. It inserts absent
   settings only, preserves existing settings, and does not touch accounts, keeps,
   subscriptions, activity or notification tables. Repeat runs are safe.
4. Reuse the existing volume explicitly in a private Compose override:

   ```yaml
   volumes:
     keep-data:
       external: true
       name: YOUR_EXISTING_VOLUME
   ```

   The default portable project is `keep`; older deployments may have a different
   project/volume name. Do not use `docker compose down -v`. The new non-root user
   is UID/GID 10001. While both services are stopped, ensure the existing data
   directory is owned by 10001:10001 and mode 0700, and that the database is
   readable and writable by that identity. An existing volume can retain 0755
   directory mode after Docker copy-up; follow the scoped directory repair in
   [installation](INSTALLATION.md#legacy-data-volume-permissions) before using the portable backup
   helper. Do not recursively change ownership or permissions as part of this
   repair.
5. Preserve FLASK_SECRET_KEY, PLEX_OWNER_ID, KEEP_WEBHOOK_SECRET, KEEP_URL and any
   needed networking. Environment values continue to win. Before removing service overrides, verify
   SQLite contains the current effective values: the migration inserts absent
   settings only and will not overwrite an older saved value. Remove overrides
   from all sources for both services only after that check, then verify that
   the effective configuration is unchanged.
6. Validate Compose without printing secrets, start both services, check health,
   sign in as owner, verify users/preferences/keeps and collection selection,
   perform connection tests and inspect the digest queue before enabling email.
7. Keep the pre-upgrade backup until a restore drill and functional checks pass.

The app refuses a legacy database without the configuration migration marker,
preventing silent loss of legacy collection/branding configuration. Fresh databases
start with no collections and email disabled.

Rollback: stop both new services, restore the complete pre-upgrade database and
private config, restore prior data ownership, then start the exact previous image.
Do not assume older code is compatible with a modified database. New keeps or
account changes made after upgrade are absent from the pre-upgrade backup; record
that recovery point before rollback.
