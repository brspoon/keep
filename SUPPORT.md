# Keep support

Keep is intended for self-hosters who already operate Plex and Maintainerr. Installation uses Docker Compose and starts on your trusted local network; HTTPS is optional for local use and required for access across an untrusted network. See [installation and configuration](docs/INSTALLATION.md) before asking for help.

Installers are provided for Linux/macOS shells and Windows PowerShell. Windows uses Docker Desktop with Linux containers. Keep itself runs in the same amd64 or arm64 Linux image on each host. See [development and testing](docs/DEVELOPMENT_TESTING.md#installation-platforms) for the platform validation scope.

## Supported versions

Support is limited to the latest stable Keep release. Up to two preceding version tags are retained as rollback choices; they are not supported maintenance releases and do not receive a security-fix commitment. Upgrade to the latest stable release before reporting an issue.

Use [GitHub Releases](https://github.com/brspoon/keep/releases) to find release notes, matching source archives, and checksums. The image version is shown in Keep and in your installation's `KEEP_IMAGE` setting.

## Where to ask

- Use [GitHub Issues](https://github.com/brspoon/keep/issues) for reproducible bugs and feature requests that do not contain sensitive information.
- Use [installation guidance](docs/INSTALLATION.md), [backup and restore](docs/PORTABLE_BACKUP.md), and the in-app FAQ for common operator questions.
- Report suspected vulnerabilities through [GitHub's private reporting form](https://github.com/brspoon/keep/security/advisories/new). See [SECURITY.md](SECURITY.md) for reporting guidance. Do not post vulnerability details in public issues, discussions, or pull requests.

Never attach `.env` files, database files or backups, invitation/reset URLs, access tokens, API keys, private media artwork, or unredacted logs/service responses. Do not expose Maintainerr directly to the public internet; its API does not provide built-in authentication.

Keep is independent of Plex, Maintainerr, Radarr, Sonarr, Seerr, and Tautulli. Their names identify compatible services; no endorsement or support relationship is implied. Keep is licensed under [MIT](LICENSE); dependencies and bundled assets have separate license and attribution terms in [THIRD_PARTY.md](THIRD_PARTY.md).
