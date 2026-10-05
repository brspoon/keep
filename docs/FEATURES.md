# Features, accounts, and permissions

Keep helps the people using your Plex server protect titles they still plan to watch and make room by removing media they no longer want. See the [preview gallery](PREVIEW.md) for Leaving, Kept, and Manage Library in light and dark mode.

## Who can use Keep?

- **Plex sign-in:** viewers must have access to the Plex server selected by the Keep owner. Having a Plex account alone does not grant access to Keep. The owner establishes the installation using the Plex account that owns that server.
- **Local Keep accounts:** the owner can create accounts that sign in with an email address and password instead of Plex. A local Keep account does not grant Plex server access or playback rights.
- **Owner-controlled access:** there is no public self-registration for local accounts. The owner can disable accounts and control their Keep and library permissions.

Keep periodically rechecks Plex server access. Non-owner Plex accounts need current verification; if it expires, viewers may need to sign in with Plex again. These checks do not promise immediate detection of a change made in Plex. Local accounts use their separate owner-managed access.

## Leaving and Kept

**Leaving** shows titles in the Maintainerr collections selected by the owner. Countdown badges show the time before possible removal. A title's details can show its current status, request history, and watch information when the relevant integrations and data are available.

Choose **Keep** to protect a title from scheduled removal. A temporary Keep lasts 30 days. On **Kept**, see who protected each title, when protection expires, and use **Manage Keep** to extend it when available. The owner can grant indefinite protection and permission to manage other people's Keeps.

When a temporary Keep expires, or someone removes its protection, the title may qualify for Leaving again under the library's rules. **Removing a Keep does not delete the title or its files.** Leaving and Kept are shared browsing views; deletion access is controlled separately.

## Manage Library

Manage Library uses Radarr and Sonarr to show downloaded media, file sizes, and available cleanup actions. The owner must grant deletion capability and access to specific libraries before a viewer can use it.

- **Requester-restricted access:** viewers can delete movies or downloaded TV seasons requested exclusively by their verified Seerr account. Shared, ambiguous, stale, or unavailable request history does not establish deletion rights. Local accounts need an explicit owner-managed Seerr link.
- **Delete any title:** this separate permission allows deletion of other titles within granted libraries, including whole series, without relying on Seerr request ownership. Restricted season access does not grant whole-series deletion rights.
- **Protection and confirmation:** active Keeps block deletion, including for the owner. Deletion requires confirmation and fresh permission and protection checks. Deleting media permanently removes its files; selected-season deletion leaves the series and other seasons in place.

See [Seerr setup and deletion policy](seerr-attribution.md) for request matching, season eligibility, and deletion limits.

## Connections and what they enable

| Connection | Required? | What it provides |
| --- | --- | --- |
| Plex | Yes | Owner setup, authorized Plex sign-in, and media/server identity. Local Keep accounts remain available after owner setup. |
| Maintainerr | Yes | Leaving and Kept collections, cleanup rules, and Keep protection. |
| Radarr | Optional | Movie inventory and movie deletion in Manage Library. |
| Sonarr | Optional | Show inventory, season cleanup, and authorized whole-series deletion. |
| Seerr | Optional | Request history and verified requester-based deletion access. Linking an account alone does not grant deletion permission. |
| Tautulli | Optional | Qualifying watch history and watched thresholds for Leaving information and supported forecasts. |
| SMTP/email | Optional | Invitations, password resets, and Leaving email summaries. With email disabled, the owner can share private account setup/reset links. |

Plex and Maintainerr must already be running and reachable from Keep. Optional connections enable their associated features; forecasts require supported rules and verifiable media/watch data. See [installation and configuration](INSTALLATION.md) for setup.

## Email and personal preferences

When email delivery is enabled, viewers can choose which selected Leaving lists they follow and turn their summaries on or off. Keep sends new-entry summaries and reminders when titles have seven days or less remaining; missed updates can make a reminder arrive later. Kept titles are excluded. Preferences also provide system, light, and dark appearance choices.

Under **Admin → Email**, recipient cards show the corresponding account's full name, with a display name or Plex username as a fallback. Search matches email addresses, full names, display names, and Plex usernames. Addresses without an associated account remain independent email recipients.

## Owner controls and API access

The owner manages accounts, indefinite-Keep and Keep-management permissions, deletion capabilities, library grants, and Seerr account links. Under Admin, the owner also manages selected Maintainerr collections, service connections, email recipients, jobs, and activity records.

**Admin → Jobs** shows each job's schedule, next run, and latest result. **Run now** queues an available job to run shortly. **Edit** changes the frequency of Plex account access checks, Leaving reminders, Seerr request history refreshes, and service connection checks. Lifecycle tasks such as temporary Keep expiry, reminder reconciliation, and cleanup keep their fixed schedules. Running email delivery still respects recipient preferences and the digest quiet period; it does not resend completed deliveries.

Only the owner can create and manage scoped API keys. The supported API reads selected Leaving and Kept collections and manages Keep protection. Keys remain subject to current account permissions; they do not grant administration or media-file deletion. See the [API guide](API.md) for endpoints, scopes, expiry, and retry rules.
