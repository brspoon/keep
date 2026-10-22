# Changelog

## 2.27.4 — 2026-10-22

- Update the container's C library with the vendor's regular-expression security fix.
- Update trusted certificate authorities for HTTPS connections and email delivery after the emSign security incident.
  Email servers whose certificates rely only on retired emSign roots need an updated certificate chain.

## 2.27.3 — 2026-10-19

- Match titles to Plex by TMDB or TVDB ID so different title spellings no longer prevent Leaving estimates. Keep estimates unavailable when the match is ambiguous or library data is incomplete.

## 2.27.2 — 2026-10-14

- Collapse Events and Collections in Preferences and show selection counts. Keep Save and Cancel visible while scrolling the settings.

## 2.27.1 — 2026-10-14

- Move the Notifications summary to the top and keep Email and Pushover settings collapsed until opened. Show provider setup status and delivery review notices above email recipients.
- Use the shared confirmation banner for success and error messages on Notifications.
- Keep Save buttons available when an unsaved-changes confirmation is canceled.

## 2.27.0 — 2026-10-14

- Remove the host maintenance helper and the in-app Install update and Restart controls. About still checks for releases and links to the manual Docker upgrade guide.
- If you enrolled the helper, finish or recover pending work and stop its host service before upgrading through Docker. Keep preserves earlier recovery records and refuses to start with unfinished or inconsistent state.

## 2.26.2 — 2026-10-13

- Fix saving appearance and email preferences.
- Move Pushover settings to Admin Notifications and make Pushover available only to the owner. Other users can receive Leaving summaries and seven-day reminders by email.
- Keep desktop letter navigation below the header and within short windows.
- Refresh release information after an upgrade and recover maintenance controls automatically when the helper becomes available.

## 2.26.1 — 2026-10-13

- Simplify desktop letter navigation and hide it for short collections. Remove the mobile scroller to give posters more room.
- Use more space for library grids on wide screens and close the gap beneath sticky navigation.
- Make Admin layouts, status colors, and action notifications consistent.
- Fix notification checkbox click areas and Save buttons flashing during page load.
- Remove completed maintenance snapshot containers while preserving recovery files. Update the optional host helper to receive this fix; updating the app image alone does not update the helper.

## 2.26.0 — 2026-10-12

- Add Admin Notifications with email and Pushover settings, test notifications, and delivery history.
- Let users choose notification channels, events, and collections in Preferences. The owner can also receive connection, job, and update alerts.
- Keep uncertain deliveries for review without pausing other recipients or channels.
- Add Install update and Restart controls on About for installations with the optional Linux maintenance helper.

## 2.25.0 — 2026-10-11

- Add letter navigation to Manage Library, Leaving, and Kept, with a desktop side index and a mobile drag handle that follow searches and filters.
- Add an Admin About page with update checks, recent releases, support links, and copyable diagnostics.
- Remove the note at the bottom of Jobs.

## 2.24.0 — 2026-10-11

- Expand the API reference with authentication guidance, response examples, and copyable requests.
- Add collection-specific media details and exact Plex, TMDB, TVDB, and IMDb ID filters, with available Keep and Leaving metadata.
- Add an owner-only API endpoint for recorded worker and job status.
- Use consistent search fields and clear buttons throughout Keep.

## 2.23.3 — 2026-10-07

- Update the container's Python and zlib packages with vendor security fixes.

## 2.23.2 — 2026-10-06

- Ensure the container uses the patched zlib library for normal Python operations.
- Update the container's Werkzeug dependency to 3.1.9.
- Update the container base and replace OpenSSL and Expat with fixed releases.
- Allow clean image scans to pass when expired security exceptions are unused; continue blocking findings that need an expired exception.

## 2.23.1 — 2026-10-05

- Clarify that Leaving updates follow Maintainerr's configured rule schedule.
- Remove installation-specific maintenance tools and contributor branch restrictions from the public repository.

## 2.23.0 — 2026-10-05

- Count down the next run time on Jobs in real time.
- Add pull to refresh on mobile pages.

## 2.22.1 — 2026-10-05

- Clarify configurable job schedules, API media fields, and backup verification on Linux and macOS.
- Make source archives and checksums immutable for future GitHub releases.

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

- Use a bounded email-address check for local accounts, recipients, and preferences.
- Harden mobile Activity filter links against unsafe URLs.
- Clarify recovery credentials and update versioned installation examples.

## 2.21.3 — 2026-10-03

- Disable setup completion until the required settings are saved, with a checklist identifying missing Plex, Maintainerr, collection, or enabled email configuration before live verification.
- Match setup links to Keep's shared theme controls, including hover highlights and visible keyboard focus in light and dark mode.
- Report SMTP authentication failures cleanly when a username is configured without a saved password, while retaining support for unauthenticated relays.
- Add an owner-only Return to Setup button while initial setup is unfinished, preserve saved service configuration, and explain how to use the installer-provided setup code.
- Show platform-specific installation commands or official setup links when prerequisites are missing, without installing tools or changing Docker permissions automatically.
- Add the Keep logo and official prerequisite links to the README, and clarify the browser setup steps and required service verification in the installation and Docker Hub guides.

## 2.21.2 — 2026-10-03

- Apply the Python 3.14 temporary-directory correction and additional permission-recovery guards; verify that cleanup preserves files outside the temporary tree.
- Simplify contribution and confidential security-reporting guidance.
