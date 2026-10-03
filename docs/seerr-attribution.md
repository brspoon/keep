# Seerr integration and deletion permissions

Keep uses Seerr request history to show who requested a title and to limit
requester-based library deletion. A recorded request is historical attribution;
it does not prove that the request caused a download.

## Set up Seerr

1. Under **Admin → Connections**, save the Seerr address, any reverse-proxy base
   path, and API key. `SEERR_URL` and `SEERR_API_KEY` environment overrides take
   precedence over values saved in Keep.
2. Test the connection. Keep checks the authenticated identity and access to all
   requests and users.
3. Refresh request history from the Seerr connection card. The `keep-digest`
   worker also imports history after configuration, on its next 30-second check,
   then every 15 minutes after a successful refresh. History becomes stale after
   24 hours. A web-only installation supports manual refresh.
4. Plex accounts match by stable Plex ID. The owner can separately link local
   Keep accounts to Seerr accounts. Links are saved as a validated atomic batch;
   duplicate or conflicting matches stay unlinked. Changing the Seerr connection
   requires a new refresh and relinking local accounts.

## Request details

Open a title's details from Leaving, Kept, or Manage Library to see request
history. Requesters do not appear on browsing cards. Keep matches movies by
TMDB ID and series by TVDB ID, never by title, name, or email. Approved or
completed requests can identify requesters; pending, declined, failed, missing,
or ambiguous history does not establish ownership. Keep displays linked Keep
names rather than private Seerr account labels.

Season details distinguish availability from request history. A downloaded
season without recorded history says **No request recorded**, not **Requester
unknown**. Missing account links, requests without season scope, pending
requests, and stale or unavailable history remain distinct. Empty seasons with
no request are omitted only when the current snapshot has explicit season
scope and download counts are known.

Details show runtime when the source supplies valid minutes or Plex duration
milliseconds, and current Keep protection. A failed protection lookup displays
unavailable status. Actions remain on the browsing cards.

## Library deletion permissions

All library access is limited to libraries selected by the owner.

- Requester-restricted accounts can delete only a movie requested exclusively by
  their unambiguously linked Seerr account, with at least one approved or
  completed request. Another requester in any status or quality variant makes
  the title shared. Restricted inventory omits ineligible titles, including on
  direct details and artwork requests. Stale or unavailable history hides it.
- **Delete any title** is a separate owner-managed permission. It permits shared
  or unknown movies and whole-series deletion without depending on Seerr, but
  does not bypass active Keeps or library selection. This permission defaults
  off for new accounts; upgrades preserve existing library grants without
  granting this override.
- Before restricted deletion, Keep fetches a fresh, bounded, complete request and
  user snapshot from Seerr with a 20-second budget. Partial visibility, missing
  IDs or history, ambiguous links, and service failures deny deletion. The saved
  browsing snapshot never authorizes a deletion.
- After network verification, Keep rechecks account and session status,
  connection settings, library grants, account links, media identity, and Keep
  protection. An incomplete protection check blocks deletion. Leaving and Kept
  remain shared browsing views.

## Delete selected seasons

A season request never grants whole-series deletion rights. Restricted accounts
can select only eligible downloaded seasons; elevated accounts see all downloaded
seasons and retain a separate whole-series action.

Eligibility requires the exact TVDB series ID and explicit season number,
including Specials (season 0), with approved or completed request and season
status. Another requester in any status or quality makes the season shared.
A series request without explicit season scope denies restricted deletion.

Keep reads a fresh Sonarr episode and file inventory, counts multi-episode files
once, and rejects orphan files, cross-season mappings, duplicate IDs, or
inconsistent inventories. A signed ten-minute preview binds the account/session,
connection, library, series, and file/episode fingerprints. Posted paths, file
IDs, and ownership claims are not trusted; changes require a new preview.

After a separate deletion confirmation, Keep revalidates live request history
unless the account has elevated permission, active Keeps, access, and file
identity. It unmonitors only selected seasons and their episodes, including
missing episodes, verifies that state, and rechecks files and access before
removing the selected file IDs. The series, unselected seasons, Seerr requests,
and unrelated settings remain intact. Sonarr operations share a 60-second budget;
timed-out writes are not retried automatically.

A whole-series Keep blocks every season's deletion, including for the owner.
Keep mutations, expiry, and deletion share a nonblocking cross-process file lock.
Competing browser writes receive a busy response; expiry work retries later and
rechecks renewed or indefinite protection.

Verification rereads the inventory after deletion. A partial or uncertain outcome
requires a reload. Monitoring may already be off after a failure; Keep does not
restore it automatically because doing so could download removed files again.
Queued downloads and later requests can still add files. Independent services
cannot provide an atomic transaction, so an external administrator can change
state between the final check and a write.

## Seerr availability updates

After confirmed movie, series, or season deletion, Keep queues Seerr's **Media
Availability Sync** job. This is Keep's only Seerr write: it triggers the job
without creating, modifying, cancelling, or deleting requests, changing its
schedule, or directly editing availability. Keep does not force a Plex rescan.

The worker coalesces deletions for 30 seconds and waits while the job is running.
Pending work survives restarts; transport and API failures retry with backoff
from one minute to one hour. A deletion arriving during dispatch gets a later
pass. Changing the connection discards its old queue. Failed or unconfirmed
media deletions do not enqueue a sync. Seerr must allow its settings/jobs API;
acceptance of the trigger does not establish completion of Seerr's job. A sync
failure leaves the successful media deletion intact.

## Implementation and testing

History reads use GET requests without redirects or credentials in query strings.
Refreshes allow at most 100 pages per endpoint, 4 MiB per response, and a
60-second deadline. Incomplete or unstable pagination fails the refresh.
SQLite snapshot replacement is atomic; a failed refresh retains the previous
snapshot and marks it unavailable. Manual and automatic refreshes share a
cross-process lock. Failed attempts retry after 1, 2, 4, 8, 16, 32, then 60 minutes;
schedules and failures survive restarts. Credentials and response bodies are not
logged. Persisted attribution contains IDs, statuses, quality flags, seasons,
and owner-only account labels.

Browsing metadata uses a 60-second, 128-entry process-local cache scoped to the
connection and database; collection membership is checked before access. Library
details reuse their fresh inventory. Dialogs, Keep protection, and requester
history are not cached in that metadata cache. Deletion authorization stays live.

Relevant upstream contracts are Seerr's `server/entity/User.ts`,
`server/entity/SeasonRequest.ts`, `server/routes/user/index.ts`,
`server/routes/request.ts`, and `server/lib/permissions.ts`; and Sonarr's
`Sonarr.Api.V3/SeasonPass/SeasonPassController.cs`,
`Sonarr.Api.V3/EpisodeFiles/EpisodeFileController.cs`, and
`Sonarr.Api.V3/Episodes/EpisodeController.cs`.

Use synthetic accounts and disposable media for tests. Check exclusive and
shared requests, unlinked accounts, manual imports, season scopes, and outages.
For deletion checks, verify the intended files and monitoring state while other
seasons remain unchanged. Automated tests do not establish real-provider
behavior for every deployment. See [development testing](DEVELOPMENT_TESTING.md).
