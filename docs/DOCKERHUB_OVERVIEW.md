# Keep

**Keep — a self-hosted companion for Plex and Maintainerr**

Browse titles scheduled to leave selected Maintainerr collections, protect favorites with Keeps, and see who protected them. Optional integrations include Radarr, Sonarr, Seerr, Tautulli, and SMTP. Permission-scoped Library Management is a separate feature that can permanently delete authorized media; active Keeps block deletion.

## Intended audience

Keep is for self-hosters who already run Plex and Maintainerr. Installation needs Docker with Compose v2 and Python 3.9 or newer. Linux/macOS also needs curl; Windows uses PowerShell 5.1 or newer and Docker Desktop running Linux containers. Plex and Maintainerr are not included. Maintainerr's API has no built-in authentication and must remain private.

## Installation

Run the command for your system on the Docker host.

**Linux / macOS**

```sh
curl -fsSL https://raw.githubusercontent.com/brspoon/keep/2.21.2/install.sh | sh
```

**Windows — PowerShell**

```powershell
irm https://raw.githubusercontent.com/brspoon/keep/2.21.2/install.ps1 | iex
```

The installer downloads the release files into a `keep` folder in your home directory, generates private configuration, and starts both required containers from the same versioned image. It waits for the web app and worker to become healthy, then prints a local setup address and temporary owner setup code. Open the address on your local network, enter the code, sign in to Plex, and configure Maintainerr and collections.

Git, a domain, and a reverse proxy are not required for local installation. Use HTTPS before exposing Keep outside a trusted network. The [installation guide](https://github.com/brspoon/keep/blob/main/docs/INSTALLATION.md) covers custom ports and addresses, HTTPS, and optional integrations. Back up the shared data volume and deployment configuration before upgrading; do not run only one of the two services.

## API

The Keep owner creates and manages account-bound integration keys under **Admin → API keys**, and browses endpoints under **Admin → API reference**. Both pages are owner-only. The API is served under `/api/v1`. New keys expire after 30, 90 or 365 days, or Never expire; revoked keys can be removed while activity history remains. See the [API guide](https://github.com/brspoon/keep/blob/main/docs/API.md) and [OpenAPI contract](https://github.com/brspoon/keep/blob/main/static/openapi.json). These keys authorize clients calling Keep; existing service connections retain their own settings and credentials.

## Image tags and recovery

Version tags identify a specific release. `stable` points to the latest stable release and can change. Both amd64 and arm64 are included in the multi-platform image; Docker selects the matching architecture.

The registry retains the current stable/version/commit tags, the current commit's architecture tags, and up to two preceding versions for rollback. Only the latest stable release receives fixes. Use a version tag or digest for a planned upgrade or rollback. Matching source archives are retained separately from image cleanup in [GitHub Releases](https://github.com/brspoon/keep/releases).

## License and source

Keep's own code is licensed under [MIT](https://github.com/brspoon/keep/blob/main/LICENSE). Dependencies, base-image software, and bundled assets have separate licenses and notices. See [third-party attribution](https://github.com/brspoon/keep/blob/main/THIRD_PARTY.md), [GitHub Releases](https://github.com/brspoon/keep/releases) for matching source archives and checksums, and the [source-material guide](https://github.com/brspoon/keep/blob/main/docs/SOURCE_DISTRIBUTION.md).

Keep is independent of and not endorsed by Plex, Maintainerr, Radarr, Sonarr, Seerr, or Tautulli. Product names identify compatible services.

## Support

Use [GitHub Issues](https://github.com/brspoon/keep/issues) for bugs and feature requests. See [SUPPORT.md](https://github.com/brspoon/keep/blob/main/SUPPORT.md) for supported versions and help. Report suspected vulnerabilities through [GitHub's private reporting form](https://github.com/brspoon/keep/security/advisories/new); [SECURITY.md](https://github.com/brspoon/keep/blob/main/SECURITY.md) explains what to include and what to do if the form is unavailable. Never post vulnerability details, credentials, database files, private artwork, or unredacted service responses in public issues.

Plex and the Plex logo are trademarks of Plex and used under a license.
