# Keep

Keep is a self-hosted companion for Plex and Maintainerr. It helps you see which titles are due to leave selected collections, protect favorites, and manage who can do so. Optional integrations add email summaries, watch history, and permission-scoped library management.

## Before you install

You need Docker with Compose v2 and Python 3.9 or newer. On Linux/macOS, you also need curl. On Windows, use PowerShell 5.1 or newer and Docker Desktop running Linux containers. Your account must be able to run Docker. Plex and Maintainerr must already be running and reachable from Keep.

Keep starts on your local network. You do not need Git, a domain, or a reverse proxy to install it. Use HTTPS if you later make Keep accessible outside your trusted network.

## Install

Run the command for your system on the computer where Keep will live.

**Linux / macOS**

```sh
curl -fsSL https://raw.githubusercontent.com/brspoon/keep/2.21.2/install.sh | sh
```

**Windows — PowerShell**

```powershell
irm https://raw.githubusercontent.com/brspoon/keep/2.21.2/install.ps1 | iex
```

The installer downloads the release files into a `keep` folder in your home directory, creates private configuration and secrets, pulls the prebuilt image, and starts the web app and background worker. Once both services are healthy, it prints a local setup address and a temporary owner setup code.

Open that address on your phone or computer on the same network. Enter the code, sign in to Plex, and select the server you own. In **Admin → Connections**, save and test Maintainerr and choose collections. Return to setup and select **Verify services and finish setup**.

Radarr, Sonarr, Seerr, Tautulli, and email are optional. See the [installation guide](docs/INSTALLATION.md) to choose a port or address, use an HTTPS proxy, or troubleshoot setup. Keep the installation's `.env` file and data volume private, and back them up before upgrading.

## Guides

- [Documentation index](docs/README.md) — find installation, backup, migration, API, and contributor guides.
- [Installation and configuration](docs/INSTALLATION.md)
- [Backup and restore](docs/PORTABLE_BACKUP.md)
- [Upgrade and migration](docs/MIGRATION.md)
- [API guide](docs/API.md) and [OpenAPI specification](static/openapi.json)
- [Contributing](CONTRIBUTING.md) and [development and testing](docs/DEVELOPMENT_TESTING.md)
- [Security policy](SECURITY.md) and [supported versions](SUPPORT.md)
- [License](LICENSE) and [third-party notices](THIRD_PARTY.md)

Keep's own source code is licensed under MIT. Dependencies and bundled assets may have separate licenses and notices. Keep is independent of Plex, Maintainerr, Radarr, Sonarr, Seerr, and Tautulli; their names identify compatible services and do not imply endorsement.

Plex and the Plex logo are trademarks of Plex and used under a license.
