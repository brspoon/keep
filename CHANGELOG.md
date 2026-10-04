# Changelog

## Unreleased

- Build and fully validate both native images once per merged main commit, retaining the exact images, matching sources and original evidence for approved publication.
- Publish retained images without rebuilding or repeating native tests; reject missing, expired, altered or wrong-commit validation records before promotion.
- Keep pull-request checks read-only and preserve per-architecture evidence when retrying failed native jobs.

## 2.21.3 — 2026-10-03

- Disable setup completion until the required settings are saved, with a checklist identifying missing Plex, Maintainerr, collection, or enabled email configuration before live verification.
- Match setup links to Keep's shared theme controls, including hover highlights and visible keyboard focus in light and dark mode.
- Report SMTP authentication failures cleanly when a username is configured without a saved password, while retaining support for unauthenticated relays.
- Add an owner-only Return to Setup button while initial setup is unfinished, preserve saved service configuration, and explain how to use the installer-provided setup code.
- Show platform-specific installation commands or official setup links when prerequisites are missing, without installing tools or changing Docker permissions automatically.
- Add the Keep logo and official prerequisite links to the README, and clarify the browser setup steps and required service verification in the installation and Docker Hub guides.

## 2.21.2 — 2026-10-03

- Apply the Python 3.14 temporary-directory correction and additional permission-recovery guards; verify that cleanup preserves files outside the temporary tree.
- Simplify contribution and confidential security-reporting guidance, remove internal deployment journals, and keep host-specific retention settings in private configuration.
