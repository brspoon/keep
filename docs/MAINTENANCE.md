# In-app updates and restarts

An enrolled installation lets the owner use **Admin → About → Install update**
or **Restart**. Updates select the latest verified stable Keep release. Keep
finishes active work, saves its database and settings, and restarts both services
together. If activation fails, it restores the matching previous image,
database, and settings before opening the app again.

The optional helper runs on the Docker host. The app containers do not receive
the Docker socket. Installing Keep alone does not enroll or start this helper.

## Requirements

The supported host layout is Linux with a local Docker Engine, Compose v2,
Python 3.12 or newer, and the standard Keep Compose project. Both Keep services
must share one local named data volume and use the same published image.
The operator running the helper must own the installation and private state
and have access to that local Docker engine.

Custom Compose layouts need a separately reviewed local adapter. Remote Docker
engines, extra containers writing to the data volume, and unverified image
sources cannot be enrolled. macOS and Windows Docker Desktop maintenance is
not yet supported; their normal installation and manual upgrades remain available.

## Stage the helper

For a new installation, add `--maintenance-helper` to the Python installer:

```sh
python3 scripts/install_keep.py --start --maintenance-helper --directory /srv/keep
```

For an existing installation, first upgrade using the
[manual upgrade guide](MIGRATION.md#upgrade-an-installation). Then run the same
installer with the optional flag. It preserves the existing owner, database,
version, and configuration and stages the helper source from the installed
release's immutable GitHub assets. It does not enroll the installation.

The installer prints the exact helper revision directory under
`.maintenance-host/releases/`. Keep that path for the commands below. A release
without the helper asset cannot stage it.

## Enroll the installation

Finish Plex owner setup in Keep first. Resolve Python and Docker to their actual
absolute executable paths; a symlink launcher is not accepted. Installation
configuration files must belong to the operator and be readable only by that
operator. Set the paths, context, project, and volume to the values from the
actual installation.

For the standard `/srv/keep` installation, an enrollment command has this form:

```sh
/usr/bin/python3.12 /srv/keep/.maintenance-host/releases/<revision>/host_cli.py enroll \
  --state /srv/keep/.maintenance-host --installation /srv/keep \
  --docker-executable /usr/bin/docker --docker-config /home/keep-operator/.docker \
  --context default --project keep --volume keep_keep-data
```

The helper verifies the local context, services, volume, released image, and
active owner before creating an installation key. The key is stored privately;
it is not printed or added to `.env` or service arguments. A changed context,
owner, image, or configuration requires attention instead of automatic adoption.

Check enrollment and one foreground poll:

```sh
/usr/bin/python3.12 /srv/keep/.maintenance-host/releases/<revision>/host_cli.py status --state /srv/keep/.maintenance-host
/usr/bin/python3.12 /srv/keep/.maintenance-host/releases/<revision>/host_cli.py worker --state /srv/keep/.maintenance-host --once
```

## Run the helper

The foreground worker uses the same command without `--once`. It polls every
15 seconds and checks for newer stable releases at most hourly. Use one worker
per installation.

To run it with the enrolled operator's systemd user service, save this as
`~/.config/systemd/user/keep-maintenance.service`, mode `0600`. Replace the
Python executable and revision path with the verified values:

```ini
[Unit]
Description=Keep maintenance helper

[Service]
Type=simple
WorkingDirectory=/srv/keep
ExecStart=/usr/bin/python3.12 /srv/keep/.maintenance-host/releases/<revision>/host_cli.py worker --state /srv/keep/.maintenance-host
Restart=on-failure
RestartSec=15
UMask=0077

[Install]
WantedBy=default.target
```

Then run as that operator:

```sh
systemctl --user daemon-reload
systemctl --user enable --now keep-maintenance.service
systemctl --user status keep-maintenance.service
```

A user service follows the user's service manager. Running continuously without
a login needs an operator decision about systemd lingering or a system service.
The installer does not change either setting.

## Interrupted maintenance

About shows the recorded operation and reconnects after a restart. If the
connection drops after a request, refresh its status before trying again.
The helper retains the same request and recovery journal across restarts.
After a completed update begins admitting new work, recovery preserves those
new writes and never restores the older database.

If an operation needs attention, preserve its journal, keys, database backups,
configuration, and image archives. Stop the helper service before changing its
source or service definition. Do not delete its state to clear an operation.

Manual upgrades remain available when the helper is not configured. Existing
external update tools must use a reviewed adapter for the same maintenance
barrier; an independent restart during an in-app operation is unsafe.
