# Changelog

## 2.23.0 — 2026-10-05

- Count down the next run time on Jobs in real time.
- Add pull to refresh on mobile pages.

## 2.22.1 — 2026-10-05

- Use Node.js 24 LTS for JavaScript tests in contributor and native image validation.
- Correct development and operator guidance for pull-request checks, configurable job frequencies, API media fields, backup verification, and registry recovery.
- Document the required branch naming convention and immutable future GitHub release assets.
- Align the versioned installers, Compose image, and installation examples with 2.22.1.

## 2.22.0 — 2026-10-04

- Add Run now controls, queued and running feedback, and frequency editing for recurring account, reminder, Seerr history, and connection jobs.
- Preserve manual requests and job frequencies across restarts, recover job status after temporary database write failures, and announce completed or failed attempts to screen readers.
- Remove the background worker status bar from Jobs and keep schedule, next run, and recent results beside each job.
- Show matching user names for email recipients and include their names in Email page searches.

## 2.21.6 — 2026-10-04

- Adopt the gold media-case Keep logo across the app, setup and admin pages, empty states, browser and mobile icons, emails, and repository branding.
- Give the logo more presence on app pages, add a shorter banner to the repository overviews, and use a compact email header that follows the message theme.
- Embed the logo in email messages so it displays without fetching a remote image.
- Remove the native beveled edge from the Plex sign-in button while retaining visible keyboard focus.
- Show recipient validation inside Email admin and use a themed page for missing URLs, preserving validation rules and API error responses.

## 2.21.5 — 2026-10-04

- Open title details immediately with the existing card artwork and title, and load optional watch history and Leaving estimates separately from the main details.
- Remove redundant Keep inventory checks from title details while retaining fresh membership and permission checks.
- Hide empty collection sections and their jump links across Leaving, Kept, and Manage Library, including My Keeps, search filters, and removal of the last title; show a single helpful empty state when nothing remains.
- Sort Leaving and Kept titles alphabetically to match Manage Library.
- Keep the selected All Keeps/My Keeps control yellow in both appearances, and match Delete series to the other delete buttons.
- Add the sign-in screenshot to the repository gallery.

## 2.21.4 — 2026-10-03

- Replace backtracking email validation with a bounded linear check shared by local accounts, recipients, and personal preferences, retaining the existing address policy.
- Build mobile activity-filter navigation from a fixed local path and encoded filter values so DOM values cannot become executable or external URLs.
- Clarify that recovery-trial credentials are synthetic API bearers, with SHA-256 lookup hashes matching the production API; account passwords continue to use Argon2.
- Align the installer, launchers, Compose image and installation guides with 2.21.4; check the actual checkout bundle and versioned entrypoints before native image validation.

- Build and fully validate both native images once for each main commit that requires native validation, retaining the exact images, matching sources and original evidence for approved publication.
- Publish retained images without rebuilding or repeating native tests; reject missing, expired, altered or wrong-commit validation records before promotion.
- Keep pull-request checks read-only and preserve per-architecture evidence when retrying failed native jobs.
- Skip native image validation for allowlisted documentation and screenshot changes only when the current version is already published; keep fast checks and exact-commit publication requirements.
- Download independent OS and Python package sources with up to four workers while preserving every checksum, signature, architecture and source-coverage check.
- Clean up superseded validation drafts and their temporary indexes after main validation completes, protecting current-main candidates, the latest usable build and active validation/publication runs.

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
