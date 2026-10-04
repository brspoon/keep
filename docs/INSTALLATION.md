# Installation and configuration

## Requirements

Install the prerequisites first. Keep's one-command setup installs Keep, then
you complete ownership and service configuration in your browser.

| Prerequisite | Official installation instructions |
| --- | --- |
| Docker with Compose v2 | [Docker Desktop for macOS](https://docs.docker.com/desktop/setup/install/mac-install/) or [Windows](https://docs.docker.com/desktop/setup/install/windows-install/); on Linux, [Docker Engine](https://docs.docker.com/engine/install/) and the [Compose plugin](https://docs.docker.com/compose/install/linux/). |
| Python 3.9 or newer | [Linux](https://docs.python.org/3/using/unix.html), [macOS](https://www.python.org/downloads/macos/), or [Windows](https://www.python.org/downloads/windows/). |
| curl on Linux/macOS | [curl downloads](https://curl.se/download.html). macOS already includes curl. |
| PowerShell 5.1 or newer on Windows | Windows PowerShell 5.1 is sufficient, or [install PowerShell 7](https://learn.microsoft.com/en-us/powershell/scripting/install/install-powershell-on-windows). |
| Plex and Maintainerr | [Plex Media Server](https://www.plex.tv/media-server-downloads/) and [Maintainerr installation](https://docs.maintainerr.info/installation/). Both services must already be running. |

Start Docker before running the installer. Windows requires Docker Desktop
running Linux containers; run the installer directly in PowerShell, without a
WSL terminal. Python must be available as `py -3` or `python` on Windows, or
`python3` on Linux/macOS. Python is used by the installer; the application and
worker run inside Docker with their dependencies included.

Your account must be able to run Docker, and the computer needs internet access
to download Keep. Plex and Maintainerr must already be running and reachable
from both Keep containers. They are not included. Docker Desktop provides the
Docker and Compose tools on Windows and macOS; on Linux you can use Docker Engine
with the Compose v2 plugin.

The installer checks prerequisites and stops with repair guidance when a tool
is missing or unusable. It does not install prerequisites or change Docker's
permissions automatically. See [missing prerequisite help](#missing-prerequisites).

Keep starts on your trusted local network. Git, a domain, and a reverse proxy
are not required. The installation uses the prebuilt `brspoon/keep:2.21.4` image
for both the web app and worker, with a shared `keep-data` volume. Docker selects
the amd64 or arm64 image for your server.

## First installation

Once the prerequisites are ready, run one command on the computer where Keep
will live. The address, port, directory, and HTTPS examples later in this guide
are optional alternatives; they are not additional steps for a default install.

**Linux / macOS**

```sh
curl -fsSL https://raw.githubusercontent.com/brspoon/keep/2.21.4/install.sh | sh
```

**Windows — PowerShell**

```powershell
irm https://raw.githubusercontent.com/brspoon/keep/2.21.4/install.ps1 | iex
```

The installer checks prerequisites, downloads the release files into your home
directory's `keep` folder (`~/keep` on Linux/macOS, `$HOME\keep` on Windows),
generates signing and webhook secrets, and saves a private `.env` file. It
detects the server's private IPv4 address and uses port 5000. It validates the
Compose configuration, pulls the image, starts both services, and waits for
both to become healthy. It then prints a setup address such as
`http://192.168.1.100:5000/setup` and a temporary owner setup code.

### Finish setup in your browser

1. Open the printed `/setup` address on a computer or phone on the same network. On **Establish ownership**, enter the setup code printed by the installer and select **Continue with Plex**.
2. Sign in with the Plex account that owns your server. Select the server on **Choose your Plex server**, then select **Verify and save selected server**. Keep verifies and saves the connection, then returns you to **Set up Keep**.
3. Select **Configure services and collections** to open **Admin → Connections**. Enter Maintainerr's address, select **Save Maintainerr**, then **Test Maintainerr**. Choose at least one collection from the successful test and select **Save collection selection**.
4. Select **Return to Setup** to review the setup checklist. It explains any missing configuration, and **Verify services and finish setup** stays disabled until the required settings are saved. Once available, select it to verify Plex's identity and server access, retrieve Maintainerr's collections, and check that every selected collection still exists. If email is enabled, Keep also checks the SMTP connection and configured authentication without sending an email.
5. When **Setup verified** appears, select **Open Keep**.

Radarr, Sonarr, Seerr, Tautulli, and email are optional. The
[Maintainerr webhook](#maintainerr-webhook-for-email-summaries) is only needed
for email summaries. The checklist requires a saved Plex address, server
identity, and credential; a Maintainerr address; and at least one selected
collection. If email is enabled, save the SMTP host and sender address. Having
those settings enables the button; the final verification still tests the live
services and any configured SMTP authentication before recording completion.
Saving or testing connections alone does not complete setup. **Return to Setup**
appears only for the owner while setup is unfinished. After completion, `/setup`
opens Connections instead, and later connection changes or service outages do
not restart setup.

The setup code and Plex authorization each expire after ten minutes. If the
code expires before you claim ownership, rerun the installation command to get
a new code. After ownership is claimed, open `/setup` to resume saved progress;
the installer does not replace the owner or reset your configuration.

Keep the installation's `.env` private: it contains deployment secrets. The data
volume also holds account and service credentials. [Back up both](PORTABLE_BACKUP.md) before
upgrading or moving the installation.

### Missing prerequisites

If a prerequisite check fails, follow the reported command or official
installation link, reopen your terminal if necessary, and rerun the Keep
command. Commands that install system packages may require administrator access.
Keep does not run them automatically.

If `curl` is missing, the Linux/macOS download command cannot fetch Keep's
launcher, so the message comes from your shell before Keep can offer help.
Install curl first using your operating system's package manager:

| System | Get curl |
| --- | --- |
| Debian / Ubuntu | Run `sudo apt-get update`, then `sudo apt-get install curl`. |
| Fedora | Run `sudo dnf install curl`. |
| macOS | Try `/usr/bin/curl --version`; curl is included with macOS. If it works, restore `/usr/bin` to your shell's `PATH`. If you already use Homebrew, its [curl formula](https://formulae.brew.sh/formula/curl) is another option. |
| Other Linux distributions | Use your distribution's package manager or [curl's platform downloads](https://curl.se/download.html). |

If Python is missing or older than 3.9, use the official Python links above or
the installer's suggested package-manager command. Then check
`python3 --version` on Linux/macOS or `py -3 --version` / `python --version` on
Windows. If Docker is missing, install it using the official platform guide;
if it is installed but unavailable, start Docker and confirm your account can
run `docker info` and `docker compose version`. Use Docker's
[Linux post-installation guide](https://docs.docker.com/engine/install/linux-postinstall/)
for permission configuration; Keep does not change Docker group membership.

### Choose an address, port, or directory

If the server has several network interfaces, specify the address your phone
and computer can reach. It must be a private IPv4 address belonging to the
server. You can also choose another available port or installation directory:

**Linux / macOS**

```sh
curl -fsSL https://raw.githubusercontent.com/brspoon/keep/2.21.4/install.sh | sh -s -- --bind-address 192.168.1.100 --port 5001 --directory "$HOME/keep"
```

**Windows — PowerShell**

```powershell
& ([scriptblock]::Create((irm 'https://raw.githubusercontent.com/brspoon/keep/2.21.4/install.ps1'))) --bind-address 192.168.1.100 --port 5001 --directory "$HOME\keep"
```

Replace the example address with your server's address. If automatic detection
cannot find a private address, the installer asks you to supply `--bind-address`.
It does not open firewall rules or forward router ports. LAN HTTP should be used
only on a trusted network; do not expose its port directly to the internet.

The installer preserves an existing `.env`, secrets, owner, and data. Rerunning
it does not upgrade an established installation or silently change its address,
transport mode, or image. Conflicting options fail with an explanation. For an
upgrade, follow the [upgrade guide](MIGRATION.md).

### Inspect the installer before running it

The commands above execute a versioned installation script. To review the Linux/
macOS launcher first, download the same file, read it, then run it:

```sh
curl -fsSL https://raw.githubusercontent.com/brspoon/keep/2.21.4/install.sh -o install.sh
less install.sh
sh install.sh
```

On Windows, fetch the PowerShell launcher into a variable, inspect it, then
execute that exact text:

```powershell
$installer = irm 'https://raw.githubusercontent.com/brspoon/keep/2.21.4/install.ps1'
$installer
& ([scriptblock]::Create($installer))
```

### Troubleshooting first setup

From the installation directory, `docker compose ps` shows the two services.
Use `docker compose logs --tail 100 keep-app keep-digest` to inspect failures;
remove sensitive information before sharing logs. If both services are healthy
but your browser cannot load Keep, check the printed address, host firewall,
and whether the browser is on the same network. The installer does not
configure Plex or Maintainerr networking for you.

On Windows, start Docker Desktop and select Linux containers before installing.
If Windows Defender Firewall asks about access, permit it only on your trusted
private network. Do not add a public-network rule or router port forwarding for
LAN HTTP. Check that `py -3 --version` or `python --version` reports Python 3.9
or newer; a Microsoft Store shortcut alone is not a working Python installation.

If the download returns 404 or the image pull is denied, check the release tag
and your access to GitHub or Docker Hub. A restricted image requires an
authorized Docker Hub account and `docker login`. For testing an unpublished
candidate from an authorized source checkout, use the appropriate Python command:

```sh
python3 scripts/install_keep.py --start --source-directory .
```

On Windows, replace `python3` with `py -3` or `python`.

This runs the same installer with local release files. It still needs access
to the selected container image.

## Optional HTTPS

You can install behind an existing HTTPS reverse proxy instead of using LAN
HTTP. Replace the example hostname with the hostname configured in your proxy.

**Linux / macOS**

```sh
curl -fsSL https://raw.githubusercontent.com/brspoon/keep/2.21.4/install.sh | sh -s -- --url https://keep.example.com
```

**Windows — PowerShell**

```powershell
& ([scriptblock]::Create((irm 'https://raw.githubusercontent.com/brspoon/keep/2.21.4/install.ps1'))) --url https://keep.example.com
```

HTTPS mode binds the app to `127.0.0.1:5000` by default and uses secure session
cookies. Configure a proxy on the host to forward to that address. For a proxy
in another container, attach it to Keep's Docker network and forward to
`keep-app:5000`. Set the hostname and certificate in your proxy before opening
the printed HTTPS address. Keep does not install or configure a proxy.

To move an existing LAN installation to HTTPS, back up the database and
deployment files, prepare the proxy, and edit these values in the installation's `.env`:

```dotenv
KEEP_URL=https://keep.example.com
KEEP_TRANSPORT_MODE=https
KEEP_BIND_ADDRESS=127.0.0.1
```

From the installation directory, run `docker compose up -d` to recreate both
services with the new configuration. Sign in again at the new address. Update Maintainerr's webhook
URL if you use email summaries, and reissue any outstanding account setup or
reset links. `KEEP_URL` controls browser callbacks and generated links, so it
must match the address users will open.

Enable HTTPS, reject arbitrary Host headers, and avoid logging
`/auth/local/setup/` paths, which contain short-lived setup credentials. Keep
does not trust client-supplied forwarding headers. Use proxy-side rate limits
and configure HSTS at the proxy.

## Upgrades and source builds

Before upgrading, restoring, or moving an existing installation, read the
[backup and restore guide](PORTABLE_BACKUP.md) and the
[upgrade and migration guide](MIGRATION.md). Keep's database lives in the shared
`keep-data` volume. Preserve that volume and back it up with the deployment
configuration before changing image versions. Keep both services on the same
version. Use a versioned image reference for a planned upgrade or rollback;
`stable` is mutable. See the [support policy](../SUPPORT.md) for supported
releases.

To build from source, download and extract a source release or use a source
checkout; the minimal installation folder does not include the build overlay.
Create configuration for that source directory, then use `compose.build.yml`.
Source builders may need to authenticate to Docker Hardened Images with
`docker login dhi.io`:

```sh
python3 scripts/install_keep.py --url https://keep.example.com
docker compose -f compose.yml -f compose.build.yml config --quiet
docker compose -f compose.yml -f compose.build.yml up -d --build
```

This advanced example uses an existing HTTPS proxy. Keep the source build
separate from an established installation unless you are deliberately upgrading
that installation with a verified backup.

## Legacy data-volume permissions

This repair applies only to existing volumes created by an older Keep image
whose `/app/data` directory is still mode `0755`. It is not part of a new
installation. A new image cannot change directory metadata in a volume Docker
has already created. If the portable backup helper reports this permission
problem, back up your deployment and database first. Then stop both services,
repair only the data directory, verify it, and complete the backup before
starting or upgrading Keep:

```sh
docker compose stop keep-app keep-digest
docker compose ps --all
docker compose run --rm --no-deps --user 0:0 --entrypoint python keep-app -c '
import os, stat
path = "/app/data"
info = os.lstat(path)
if not stat.S_ISDIR(info.st_mode):
    raise SystemExit("/app/data must be a real directory")
os.chown(path, 10001, 10001, follow_symlinks=False)
os.chmod(path, 0o700, follow_symlinks=False)
info = os.stat(path)
assert info.st_uid == 10001 and stat.S_IMODE(info.st_mode) == 0o700
'
```

This one-off command uses the existing Compose data volume and does not change
the database or its files. Keep both services stopped until the repair and
backup are complete. Do not create a replacement empty volume during an upgrade
or recovery.

## Networks and proxies

Connections provides a protocol chooser, hostname, port and optional base path.
New connections start with their standard service port. You can also paste a
complete HTTP or HTTPS URL into the hostname field. Existing saved addresses
keep their effective protocol, port and path until you edit them. SMTP uses its
own host, port and encryption fields.

Container URLs must be reachable from the containers. `localhost` refers to the
container itself, not the host. Add a private Docker network override or a host
route suitable for your OS when Plex/Maintainerr run elsewhere. Avoid putting
service tokens in URLs. Use HTTPS for services across an untrusted network.

By default rate limits use the direct peer address and ignore client-supplied
forwarding headers. Behind a proxy this groups clients by proxy address. Do not
change proxy trust casually: only trust headers from an isolated proxy path.
Use proxy-side per-client rate limits as well. Configure HSTS at the HTTPS proxy.

## Precedence and storage

For most settings, an explicit environment variable takes precedence over a saved
SQLite setting, followed by the generic default. Omit a variable entirely to
enable UI management; a blank environment value still wins and may fail validation.
Plex's server address, machine identifier and administrator token can always be
edited by the owner. Environment values provide their initial settings until an
explicit Save Plex or verified Connect / Reconnect replaces the supplied fields.
Older saved values do not override the environment automatically.
Supply the identical `.env` to both services. Each web
request and worker iteration reads a consistent settings snapshot, so updates
apply on the next operation without restarting. The signing secret, browser URL,
transport mode, and webhook secret remain deployment-controlled.
Owner identity is persisted in SQLite; a configured PLEX_OWNER_ID must match it.
Keep refuses a conflicting owner instead of reassigning ownership.

Data is stored in `keep-data` at `/app/data/keep.sqlite3`. Both services share the
volume. Saved credentials are masked by default and never included in page HTML or
exception logs. The owner can deliberately reveal a supported service credential, including an environment override;
Keep fetches it through an owner-only, CSRF-protected, non-cacheable request.
Hide removes the revealed value from the page; it is also concealed after 30
seconds, when the page becomes hidden, or when a form is submitted. A typed
replacement is masked but retained so it can be saved. Environment
credentials can be revealed; deployment-managed fields outside Plex remain read-only.
Credentials are stored in plaintext
in the protected volume, so backups and volume access must be treated as access
to credentials. Restrict host and Docker access.

Blank credential and masked machine-identifier submissions retain existing values.
To replace one, type the replacement and save that service. Eye controls reveal
the saved value on demand; simply revealing and saving does not replace it.
There is no Clear checkbox or Remove credential button. Deleting the text and
saving does not erase the stored credential. Optional text fields such as SMTP
username can be emptied. Use Connect/Reconnect Plex to replace a Plex connection
through authorization and verified server selection. Each card saves independently to SQLite; Keep never edits the container
configuration or environment. Plex changes take effect from SQLite on the next
operation in both services, without changing the environment or owner identity.
For other services, to move a deployed setting into UI management,
back up the database and deployment files, copy the current effective value into
SQLite, then remove its override from every configuration source for both web and
worker. Recreate both affected services and verify effective settings and health.
Removing an override alone can reactivate an older SQLite value. The UI does not
perform this deployment migration automatically.

## Email and local accounts

Email is disabled by default. Configure SMTP host, port, security (`ssl` or
`starttls`), optional username/password, sender address and display name, then
check Enable email delivery. TLS certificate verification remains enabled.
Test SMTP checks the saved connection, TLS and optional authentication without
sending an email. It does not verify sender acceptance or inbox delivery.

With email disabled, digests pause without consuming the queue. Self-service
password reset directs users to the owner. Creating a local account or requesting
its setup/reset link as owner displays a private one-use link, valid for 24 hours,
for delivery out of band. The page is not cached and sends no referrer. Reissuing
a link invalidates the prior link. Disabling an account invalidates its links and
sessions. Turning email back on may resume queued notifications; inspect them first.

Changing selected collections does not delete historical keeps or saved recipient
preferences. Unselected collections leave the active views; selecting them again
restores their visibility and management controls. Existing Keeps in unselected
collections continue blocking library deletion. Temporary Keeps still expire on
their saved schedule; indefinite Keeps remain until explicitly removed. If Keep
cannot verify a retained collection, deletion fails safely. Reselect the collection
to manage its Keeps; removing a collection selection does not remove protection.
Subscription choices for newly selected collections
must be reviewed by the owner and recipients.

## Deliberate service overrides

New installations configure services in the owner UI; no service variables are
needed in `.env`. Advanced deployments may explicitly override `PLEX_SERVER_URL`,
`PLEX_MACHINE_IDENTIFIER`, `PLEX_ADMIN_TOKEN`, `MAINTAINERR_URL`, `KEEP_COLLECTIONS`,
`RADARR_URL`, `RADARR_API_KEY`, `SONARR_URL`, `SONARR_API_KEY`,
`SEERR_URL`, `SEERR_API_KEY`, `TAUTULLI_URL`, `TAUTULLI_API_KEY`,
`EMAIL_ENABLED`, `SMTP_HOST`, `SMTP_PORT`, `SMTP_SECURITY`, `SMTP_USER`,
`SMTP_PASSWORD`, `SMTP_FROM`, or `SMTP_SENDER_NAME`. Overridden fields identify
their source and cannot be changed through the UI, except for the three Plex
connection fields described above. TLS uses `ssl` internally
(usually port 465); STARTTLS uses `starttls` (usually port 587).

## Optional integrations and background checks

- Radarr and Sonarr provide Library Management inventory and file deletion through
  their APIs. Test discovers root folders; the owner grants per-library access and
  deletion capabilities. Do not mount media into Keep. Active Keeps block deletion.
- Seerr provides request history, stable account matching and requester-scoped
  deletion checks. Local accounts require explicit owner links. The worker imports
  history after configuration and every 15 minutes after success; history becomes
  stale after 24 hours. Successful deletions queue a Seerr availability-sync job.
  See [Seerr setup and deletion policy](seerr-attribution.md).
- Tautulli supplies qualifying watch history and watched thresholds. A forecast
  requires verifiable Plex/playback data and supported current Maintainerr rules;
  estimated eligibility does not promise immediate collection entry or removal.
- SMTP enables invitations, resets and Leaving summaries. A successful SMTP probe
  proves connection/TLS/authentication, not sender acceptance or inbox delivery.

Keep's `keep-digest` worker also performs read-only background connection checks:
Maintainerr every 15 minutes; Plex, Radarr, Sonarr and Tautulli hourly; enabled SMTP
daily. Failures retry after five minutes. Seerr's own scheduled refresh supplies
its health state. Connections shows pending, healthy, retrying, overdue and repeated
failure states. A manual Test always uses saved settings and gives temporary toast
feedback; it does not save typed changes or prove continuous service health. If a
form has unsaved edits, Keep asks before running the test and explains that the
page response will discard those edits. Save first to test the new values.

Account, recipient, Preferences, connection and collection-selection forms protect
unsaved edits before navigation or another action. Connection diagnostics identify
common DNS, refusal, timeout, TLS, authentication, HTTP and service-response issues
without echoing service URLs, credentials or raw response text.

## Maintainerr webhook for email summaries

Configure this in Maintainerr, separately from Keep's service connection:

1. Open **Settings → Notifications** and create an enabled **Webhook** agent.
2. Set its URL to your Keep address followed by `/api/webhooks/maintainerr`,
   for example `http://192.168.1.100:5000/api/webhooks/maintainerr` on a trusted LAN
   or `https://keep.example.com/api/webhooks/maintainerr` through HTTPS.
   Maintainerr must reach that route; a reverse-proxy login
   or access gateway must permit the machine request with its webhook credential.
3. Set **Auth Header** to `Bearer YOUR_KEEP_WEBHOOK_SECRET`, using the exact secret
   configured in Keep's `.env`. Replace the placeholder privately; do not put the
   secret in the URL or a public screenshot.
4. Use this JSON payload template:

   ```json
   {"notificationType": "{{notification_type}}"}
   ```

   Maintainerr flattens extra event fields into the payload, including
   `collectionName` and `mediaItems`; each media item includes `mediaServerId`.
   Keep needs these fields for new-entry events. Aggregated removal warnings may
   omit a collection name; Keep resolves membership in the worker. This contract
   is documented in [Maintainerr 3.22.0 notifications](https://docs.maintainerr.info/3.22.0/notifications/).
   Verify your installed version's payload rather than substituting title names.
5. Enable **Media Added to Collection** and **Media About to be Handled**; set
   the advance warning to seven days. Attach the agent to every rule group whose
   collection you selected in Keep, and save each rule group. Collection names
   for new-entry events must match Keep's saved labels; refresh/resave the selected
   collections after renaming them in Maintainerr.
6. Configure SMTP and recipients in Keep, then verify a controlled event with a
   disposable title and an explicitly chosen test recipient. Maintainerr's generic
   Test notification is ignored by Keep and does not prove media-event queuing or
   inbox delivery. A Keep response of `queued` proves queue acceptance only.

Keep handles `MEDIA_ADDED_TO_COLLECTION` and `MEDIA_ABOUT_TO_BE_HANDLED`; other
notification types return `ignored`. Invalid authorization returns HTTP 401;
unknown new-entry collections or missing media IDs return HTTP 400. Inspect
sanitized service logs when diagnosing delivery. Reminder catch-up complements
webhooks; it does not replace the new-entry notification agent.

## Leaving reminders and email appearance

Maintainerr webhooks enqueue new Leaving events and seven-day reminders; they
never send mail in the HTTP request. Its timer can combine several collections
without a collection name. Keep resolves those title IDs against the currently
configured, active collections in the worker.

The email worker also scans those collections on startup and every 15 minutes.
Active, unprotected titles with a known future deadline within seven days are
queued even if the original webhook was missed. Kept or removed titles are
excluded. Unknown dates or retention never create guessed reminders. The normal
10-minute quiet window consolidates events; recipients keep their chosen lists.

A durable SQLite reminder claim identifies each collection, title, and Leaving
entry timestamp. It survives queue cleanup and restarts; repeated scans or
webhooks do not resend the same reminder. A new Leaving entry can generate a new
reminder. SMTP failures or interrupted sending still hold a batch for review,
since SMTP cannot guarantee whether a failed attempt reached the recipient.
The startup scan can catch up existing titles: releases before 2.17.3 did not
retain per-title completed reminder history, so historical duplicate detection
cannot be reconstructed for emails already sent before this upgrade.

Digest, account invitation, and password reset emails share Keep’s brand yellow,
dark text on primary buttons, and theme-aware surfaces and status labels. Inline
light styling is the fallback when an email client strips stylesheet rules.
`prefers-color-scheme: dark` adapts supporting clients to their system preference;
client-specific automatic recoloring or missing media-query support can affect
rendering. This is independent of the recipient’s saved app appearance.

## Automatic Plex connection and recovery

Connect / Reconnect Plex is an owner-only, CSRF-protected action. Ordinary Plex
sign-in never changes service settings. Selection always requires confirmation,
including installations with one server; reconnect replaces the saved connection
only after verification. The owner can also edit every Plex connection field
manually, before or after connecting. Saving a replacement takes precedence over
an environment-provided initial value; reconnect does not change owner identity.

Automatic discovery uses only advertised HTTPS connections with certificate
verification. If none are reachable, check Plex secure-connection settings,
DNS and Keep's runtime network access. Advanced manual controls support a private
HTTP endpoint where deliberately needed; Keep never silently downgrades TLS.
Plex resource credentials may carry broad privileges; Keep makes no narrow-scope
claim. It retains only the selected resource credential. The account authorization
token is used in memory for identity/resource lookup and is not saved.

Authorization flows and unselected resource credentials expire after ten minutes;
web requests and worker iterations delete expired rows. Consumption deletes rows
immediately. SQLite secure deletion is enabled for these records, but backups,
filesystem snapshots and storage recovery can retain older data. Protect them as
credentials. Session cookies contain random flow bindings, never Plex credentials.

The bootstrap command refuses established ownership and legacy databases with
profiles but no owner. Recover those by restoring the correct original owner
configuration. Do not delete profiles or the installation record to reset setup.
After bootstrap-based installation, rolling back to a release before 2.3 requires
setting PLEX_OWNER_ID to the persisted installation owner; earlier releases cannot
read bootstrap ownership. Use a matching pre-upgrade backup when restoring, and
never replace the database with an empty volume.
