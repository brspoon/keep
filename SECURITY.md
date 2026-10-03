# Security

Keep is intended for a household deployment on a trusted local network or behind
HTTPS. See [installation](docs/INSTALLATION.md) for owner setup and networking.

HTTPS is the default transport mode and uses Secure session cookies. The
installer can explicitly select `KEEP_TRANSPORT_MODE=lan-http` for a private or
loopback IPv4 address. Only that mode permits HTTP browser access and omits the
cookie's Secure flag. HttpOnly, SameSite, CSRF validation, and session-bound Plex
authorization still apply. Keep must not infer a weaker mode from request headers
or the proxy's connection to the container. LAN HTTP provides no transport
encryption; use it only on a trusted network and require HTTPS for internet
access. Plex's authorization service and identity requests continue using HTTPS.

New ownership requires a locally issued random setup code plus verified Plex
authentication. Codes are hashed, expire after ten minutes, and are consumed
atomically. A visitor cannot claim an installation without that operator-issued
code. Existing PLEX_OWNER_ID ownership is persisted; a conflicting override is
rejected. Ownership cannot be reassigned in the admin UI. All settings writes, connection
probes and collection discovery require an authenticated owner and CSRF token.
Service endpoints are operator-controlled and may be on private networks; restrict
container egress to intended services. Plex/Maintainerr HTTP probes reject redirects and bound responses. Automatic Plex
discovery selects owned resources and verifies HTTPS, machine identity and access
before saving. Manual service URLs may use HTTP on trusted private networks.
The owner may manually replace Plex's connection fields, including initial
environment values. Explicit per-field overrides are persisted; existing stored
values do not silently take precedence, and connection edits cannot change ownership.
SMTP tests use certificate-verified TLS or STARTTLS and do not send mail.

Library deletion is a separately granted capability with explicit per-library
authorization. Keep resolves media and root-folder identities from Radarr or
Sonarr; browser-provided filesystem paths are never accepted. A deletion sends
numeric movie/series identifiers to Radarr/Sonarr, with file deletion enabled
and list exclusion disabled. Selected-season deletion instead unmonitors the
selected Sonarr seasons/episodes and deletes their verified episode-file IDs;
the series and other seasons remain. Radarr/Sonarr perform filesystem operations.
The Keep container should not mount media storage. Active keeps block deletion, destructive actions require a fresh
server-side permission check plus CSRF validation, and successes, failures and
policy blocks are recorded in owner-visible activity. Keep creation, duration
changes, removal, expiry and library deletion share a nonblocking cross-process
lock. Expiry rechecks the current schedule under that lock; whole-title deletion
rechecks protection immediately before the destructive request. Competing browser
mutations return a busy response; due expiry rows remain for a later retry.
External service administrators remain outside this coordination.
Without Delete any title,
movie/season deletion requires live, exclusive Seerr requester verification;
whole-series deletion requires the broader capability. Cached display history
never authorizes deletion. Signed season previews, revalidation and serialized
writes limit stale confirmations; uncertain writes are not automatically retried.
See [deletion contracts and limitations](docs/seerr-attribution.md).

Plex authorization uses expiring, session-bound server-side flows. Ordinary sign-in
does not update service configuration. Non-owner Plex access expires 24 hours
after the last positive login or access-feed verification; requests reject stale
proof even during worker/Plex outages. An omitted account can sign in again;
ordinary Keep activity cannot renew proof. Renewal after expiry invalidates older
sessions and API keys. The installation owner and local accounts have separate
authority. Selected resource tokens may have broad
privileges; no narrow administrator scope is claimed. Connection secrets and the
masked machine identifier are revealed only through owner-authorized, CSRF-protected,
no-store responses. They are absent from initial HTML and are not stored in cookies.

Secrets in the data volume and `.env` require host-level protection. No encryption
at rest is claimed. Never publish database backups, populated environment files,
invitation URLs or authenticated service responses. Local setup URLs contain
credentials; disable/redact proxy access logging for those paths. Do not enable
Flask debug mode or HTTP wire logging. Keep does not trust client forwarding headers.

The supported `/api/v1` API accepts account-bound Bearer keys, independently of
browser sessions and the existing authenticated webhook routes. Only the owner
can access API settings and create or manage keys. Keys are named, explicitly
scoped, revocable and replaceable. New keys default to finite expiry;
the owner may explicitly choose Never expires. That choice skips only scheduled
expiry, never account, Plex-access, credential-version, revocation or scope checks.
Only a SHA-256 hash of the random secret is stored. The full key appears once in a CSRF-protected, no-store
owner response. Each request must recheck current account status, Plex access
where applicable, account credential version, key expiry, revocation and scope.
API keys do not replace service credentials or grant administration or media-file
deletion. Keep writes must enforce current ownership and account permissions,
share the browser/worker mutation lock and require an idempotency key. Uncertain
remote writes must remain uncertain rather than silently becoming retryable.
Parsing, upstream response sizes, pagination and request rates are bounded.
Cross-origin browser API access is not enabled. Authentication, authorization,
revocation, retry-safety or credential-disclosure failures on this surface are
reportable; tests and this policy do not establish that a control is effective.

Only the latest approved stable release receives security fixes. Previous release
images retained for rollback are recovery aids and may lack those fixes.

## Report a vulnerability

Use [GitHub's private vulnerability reporting form](https://github.com/brspoon/keep/security/advisories/new)
to report a suspected vulnerability confidentially. Include the affected Keep
version, steps to reproduce the issue, and its security impact. Use synthetic
data and redact credentials and personal information.

Do not disclose suspected vulnerabilities in public issues, discussions, or pull
requests. If the reporting form is unavailable, open an issue asking the
maintainer to enable private reporting, without including vulnerability details.
Wait for a private reporting channel before sharing the report.
