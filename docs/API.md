# Keep API v1

The Keep API gives an account-bound client access to the selected Leaving and Kept collections and to Keep protection actions. The owner can also read recorded worker and job observations. It does not expose Radarr or Sonarr library inventory, file paths, media deletion, or arbitrary upstream service data. Removing a Keep only removes protection; it never deletes a title from Plex.

The OpenAPI 3.1 contract is maintained in the version-controlled [`static/openapi.json`](../static/openapi.json) source. The owner can browse the interactive, read-only reference under **Admin → API reference** to inspect scopes, parameters, request and response fields, examples, and errors. The page can copy request examples and download the OpenAPI contract; it does not execute requests or accept API secrets. The API is versioned at `/api/v1`. Additive fields and optional parameters may be introduced within v1; a breaking contract change requires a new version namespace. Clients should tolerate added response fields.

## First request

Create a key under **Admin → API keys**, selecting only the scopes needed by the integration. For a read-only collection integration, start with `collections:read` and `media:read`. Set `KEEP_API_URL` to your Keep base URL and supply `KEEP_API_TOKEN` from your credential store. The URLs below use those shell variables:

```sh
curl --fail-with-body \
  --header "Authorization: Bearer ${KEEP_API_TOKEN}" \
  --header 'Accept: application/json' \
  "${KEEP_API_URL}/api/v1/collections?limit=25&offset=0"
```

Use the base URL that opens your Keep installation and append `/api/v1`. No public hostname is required when the integration runs on your private network. HTTPS protects the bearer credential in transit.

## Access and keys

The Keep owner creates and manages keys under **Admin → API keys**. These settings and the API reference are available only to the owner. Keys are named, belong to the owner account, and are shown in usable form only once at creation or rotation. Keep stores a cryptographic hash of each secret. A key cannot be created through the API.

Choose an expiry of **30, 90 or 365 days**, or **Never expires**. The default is 90 days. Every key has an explicit set of scopes. An explicitly non-expiring key remains subject to revocation, account state, scope, and current-permission checks on every request. A key may be revoked or atomically rotated. Rotation invalidates the old secret as the replacement is issued and preserves the original expiry, including expiries chosen in older releases. Revoking a Keep account, changing its session version, or changing its live permissions also affects its API keys immediately: each request checks that the account remains active and recomputes authorization. A key's scopes limit what it can request; they never grant account permissions.

Revoked keys can be removed from the key list. Removal deletes the credential and its related retry and rate-limit records while retaining audit history.

The API key is the credential. **Bearer** is the HTTP authentication scheme used to send that same key; it is not a separate token or another sign-in method. Send the complete `keep_...` secret in the `Authorization: Bearer ...` header. Never place credentials in a URL, query string, source control, or logs. Use HTTPS in normal deployments and keep the secret in a protected credential store.

Keys issued to non-owner accounts in older releases retain their existing authorization rules. Non-owner Plex accounts need a positive server-access verification within the last 24 hours. The worker refreshes observed accounts every 15 minutes by default; the owner can change this frequency under **Admin → Jobs**. Accounts omitted from Plex's access feeds must sign in with Plex again before that verification expires. Feed absence revokes previously observed accounts; an upstream outage cannot renew access. Expired verification blocks browser sessions and API keys even if the worker is unavailable. Fresh verification after expiry changes the account's credential version and invalidates its older keys. Local accounts and the installation owner retain their separate authorization rules.

```http
Authorization: Bearer keep_<secret>
Accept: application/json
```

Scopes are:

- `collections:read` — list configured collections.
- `media:read` — read the selected Leaving and Kept collection media.
- `keeps:read` — list or read Keep records the account is allowed to see.
- `keeps:write` — create a Keep, change its duration, or remove its protection, subject to current Keep permissions.
- `status:read` — read recorded worker and job observations; also requires the account to be the current owner.

Existing keys keep their selected scopes. To use `/status`, create a key with `status:read` explicitly selected. An older non-owner key cannot use this endpoint even if it has that scope.

No CORS access is enabled by default. Browser clients should use the Keep web application rather than sending API keys from a browser.

## Resources and identifiers

A `media_id` is a positive Plex media ID represented as a decimal string with at most 20 digits. A `collection_id` is a positive integer no greater than 999,999,999. Media and Keep `id` values combine both values as `collection_id:media_id`, for example `1:42`. A title can occur in several selected collections, so use the composite ID when the collection matters.

Media reads contain only documented fields:

| Field | Meaning |
| --- | --- |
| `id`, `media_id`, `collection_id` | Composite ID, Plex media ID string, and configured collection ID. |
| `title`, `year`, `type` | Maintainerr title metadata. Missing titles become `Untitled`, missing or invalid years become `null`, and missing types become `unknown`. Title and type are limited to 500 and 30 characters. |
| `state` | `leaving` or `kept`; Kept takes precedence when a title appears in both feeds. |
| `provider_ids` | `tmdb`, `tvdb`, and `imdb` arrays containing validated IDs from Maintainerr's `mediaData` only. Arrays are always present and contain at most 10 distinct canonical strings each. An empty array means no supported valid ID was supplied. |
| `entered_leaving_at` | UTC timestamp from a valid timezone-aware Maintainerr `addDate`, only for Leaving media. Missing, invalid, or timezone-naive dates and Kept media return `null`. This is not a deletion deadline. |
| `keep` | An accessible local Keep record, or `null`. Requires both `media:read` and `keeps:read` and follows the same current object permissions as Keep reads. |

A `null` media `keep` does **not** establish that a title is unprotected or protected indefinitely. The key might lack `keeps:read`, the local record might be absent, or the account might not be allowed to see it. Provider IDs are metadata, not a way to read arbitrary upstream records. Raw Maintainerr records, paths, account IDs, and upstream credentials are never included.

A Keep record contains its composite ID, collection and media IDs, duration, expiry and extension availability, and whether the current account owns it. Accounts see their own Keeps. An account with the current Keep-manager or owner permission may also see and manage other Keeps. `PATCH` and `DELETE` apply the same current authorization check. Indefinite duration additionally requires the account's current indefinite-Keep permission.

## List requests

`GET /collections`, `GET /media`, and `GET /keeps` use the same pagination envelope. `limit` defaults to 25 and may be from 1 to 100. `offset` defaults to 0. `offset` may be at most 10,000. The full aggregated result must contain no more than 10,000 records; larger results fail with `422 result_limit_exceeded` and return no partial page. Filter by collection or narrow the media search, then follow `next_offset` until it is `null`. A single upstream collection feed must also finish within 100 pages of 100 records and the read budget, or the request fails without partial results.

```json
{
  "data": [],
  "pagination": {
    "limit": 25,
    "offset": 0,
    "total": 0,
    "next_offset": null
  }
}
```

`GET /collections`, `GET /media`, and `GET /keeps` accept `collection_id`. `GET /media` also accepts `search` (at most 100 characters), `state`, exact `media_id`, `media_type`, and a `provider`/`provider_id` pair. Filters intersect; they do not replace each other. `state` is `leaving` by default and may be `kept` or `all`. Search is case-insensitive title matching. List results use the caller's current permissions and configured collections. Unsupported or repeated query parameters return `400`; an unavailable collection returns `404`. A collection read or list can fail if its source cannot be read completely; the API does not return a silently truncated upstream page as a complete result.

For example, list both Leaving and Kept media in collection 1:

```sh
curl --fail-with-body \
  --header "Authorization: Bearer ${KEEP_API_TOKEN}" \
  --header 'Accept: application/json' \
  "${KEEP_API_URL}/api/v1/media?collection_id=1&state=all&limit=25&offset=0"
```

Follow `pagination.next_offset` until it is `null`, keeping the same filters. Pagination is a fresh read on every request; titles may enter or leave a collection between pages. If a stable complete inventory is needed, reconcile by collection and media ID rather than treating page position as identity. A settings change during a read returns `409 conflict`; repeat the read against the current configuration.

## Exact and provider media lookup

Use `GET /media/{item_id}` to read the title in a specific selected collection. `item_id` is the composite ID, for example `1:42`. This endpoint reads both Leaving and Kept feeds, accepts no query parameters, and returns `{ "data": ... }`. It returns `404 not_found` when the collection or title is unavailable.

```sh
curl --fail-with-body \
  --header "Authorization: Bearer ${KEEP_API_TOKEN}" \
  --header 'Accept: application/json' \
  "${KEEP_API_URL}/api/v1/media/1:42"
```

Use `GET /media?media_id=42&state=all` to find the same Plex ID across selected collections. A provider lookup requires all three of `provider`, `provider_id`, and `media_type`:

```sh
curl --fail-with-body \
  --header "Authorization: Bearer ${KEEP_API_TOKEN}" \
  --header 'Accept: application/json' \
  "${KEEP_API_URL}/api/v1/media?provider=tmdb&provider_id=550&media_type=movie&state=all"
```

`provider` is `tmdb`, `tvdb`, or `imdb`. TMDB and TVDB IDs are positive decimal strings with at most 20 digits, without leading zeros, signs, or whitespace. IMDb IDs use a lowercase `tt` prefix followed by 7–20 digits with a nonzero numeric value; leading zeros within an IMDb ID are normal. Unsupported or malformed IDs return `400`.

`media_type` is `movie` or `show`. TMDB movie and television IDs use separate namespaces, so an ID alone is insufficient. For show lookup, Keep recognizes Maintainerr's `show`, `series`, and `tv` types; episodes and seasons are excluded. `media_type` can also be used without provider filters. Provider lookup operates only on validated IDs already present in selected collection metadata; Keep does not query a provider or proxy its API. Use `state=all` when checking an identity across both Leaving and Kept; omitting it searches Leaving only.

An example exact-detail response is:

```json
{
  "data": {
    "id": "1:42",
    "media_id": "42",
    "collection_id": 1,
    "title": "Example Movie",
    "year": 2024,
    "type": "movie",
    "state": "leaving",
    "provider_ids": {"tmdb": ["550"], "tvdb": [], "imdb": ["tt0137523"]},
    "entered_leaving_at": "2026-10-10T18:00:00Z",
    "keep": null
  }
}
```

## Recorded operational status

`GET /status` requires `status:read` **and** the current owner role. It accepts no query parameters. Use this read for integrations that monitor Keep's recorded worker and job state:

```sh
curl --fail-with-body \
  --header "Authorization: Bearer ${KEEP_API_TOKEN}" \
  --header 'Accept: application/json' \
  "${KEEP_API_URL}/api/v1/status"
```

The response is a `{ "data": ... }` object containing `version`, UTC `observed_at`, `worker`, and `jobs`. `worker.heartbeat_at` is the recorded heartbeat or `null`; `worker.available` uses Keep's existing tolerance of no more than 300 seconds old or 30 seconds ahead. Availability describes heartbeat freshness, not full container health.

Each job contains its fixed catalog `id`, current `status`, nullable UTC `last_run_at`, `last_success_at`, and `next_run_at`, nullable `last_attempt_status`, `queued`, and nullable `interval_seconds`. `last_run_at` is the completion time of the latest finished attempt or connection check. Current statuses are `running`, `success`, `failed`, `waiting`, `review`, `disabled`, `interrupted`, `stale`, or `queued`. `last_attempt_status` describes a recorded finished result (`success`, `failed`, `waiting`, `review`, or `disabled`) separately from freshness and queue state. Null timestamps or intervals mean no usable observation is available. `queued` describes an existing pending manual request; this endpoint does not create one.

These are local recorded observations. Reading status does not contact an upstream service, run a job, edit a schedule, restart Keep, or inspect Docker. An unavailable worker or stale job should not be reported as healthy merely because the HTTP request succeeded. No prose job results, internal paths, connection addresses, scope fingerprints, account details, or credentials are exposed. `/health` remains the basic application liveness endpoint; neither endpoint proves an entire deployment is healthy.

## Keep writes and retries

`POST /keeps`, `PATCH /keeps/{keep_id}`, and `DELETE /keeps/{keep_id}` require an `Idempotency-Key` header containing 16–128 ASCII letters, digits, underscores, or hyphens. Generate a new key for each intended operation and retain it with the method, path, and body until the outcome is known. The same key, method, path, and request body replays the original successful response for 24 hours. Reusing a key with a different request returns `409 conflict`. A replay includes `Idempotency-Replayed: true`; creation also includes the Keep's relative `Location` header.

A request interrupted while an upstream protection change may have occurred returns `409 operation_uncertain` or `502 mutation_uncertain`. Do not automatically retry it with a new key. Inspect the current Keep state first; then use a new key for a new operation. This avoids repeating a remote action whose result is unknown.

Retry records belong to the API key that made the request. After replacing a key, check the current Keep state before repeating an earlier write with its replacement. A successful replay contains the original response, which may differ from the title's current state; read the Keep again when current state matters.

If a network timeout hides the result, repeat the same request with the same key. Do not create a second intended operation merely because the first response was lost. If Keep then reports an uncertain result, inspect current protection before taking another action. A `409 busy` response applies no new operation; wait for `Retry-After` and retry with the same key. Uncertain records are retained until the key is removed; they do not become safe automatic retries after 24 hours.

Create a temporary Keep:

```http
POST /api/v1/keeps
Authorization: Bearer keep_<secret>
Content-Type: application/json
Idempotency-Key: client-keep-create-0001
```

```json
{"collection_id": 1, "media_id": "42"}
```

`duration` accepts `temporary` or `indefinite` and defaults to `temporary`. Temporary Keeps use the duration currently set by the owner under **Admin → General**: 1–365 days, with a default of 30. The only accepted fields are `collection_id`, `media_id`, and `duration`. The API returns `201 Created` with a Keep record in the `{ "data": ... }` envelope.

Change a Keep's duration:

```http
PATCH /api/v1/keeps/1:42
Authorization: Bearer keep_<secret>
Content-Type: application/json
Idempotency-Key: client-keep-update-0001
```

```json
{"duration": "temporary"}
```

The only accepted field is `duration`, which is required. Extending a temporary Keep or changing an indefinite Keep to temporary uses the owner's current duration. Changing a temporary Keep follows Keep's existing extension-availability rules; an unavailable extension returns `409 conflict`. Saving a different duration in Admin does not change existing expiry dates or extension availability. The response contains the updated Keep in the `{ "data": ... }` envelope; read the Keep record to see its availability time.

Remove protection:

```http
DELETE /api/v1/keeps/1:42
Authorization: Bearer keep_<secret>
Idempotency-Key: client-keep-remove-0001
```

A successful request returns `204 No Content`. It removes Keep protection only. It does not remove media from Plex or delete media files.

## Errors and limits

Errors use a stable JSON envelope:

```json
{"error": {"code": "invalid_request", "message": "The request is invalid."}}
```

The API returns the following errors as appropriate. Inspect `error.code` as well as the HTTP status; several conditions share a status.

| HTTP status | Error code | Integration action |
| --- | --- | --- |
| 400 | `invalid_request` | Correct unsupported, repeated, or invalid parameters or body fields. |
| 401 | `invalid_token` | Check the credential's expiry, revocation, and account state. The response includes `WWW-Authenticate`. |
| 403 | `insufficient_scope`, `permission_denied` | Review the key scopes and the account's current permission. |
| 404 | `not_found` | Check the configured collection and resource IDs and current visibility. |
| 405 | `method_not_allowed` | Use a supported method from the `Allow` response header. |
| 409 | `busy` | Wait for `Retry-After`; retry the same write with the same idempotency key. |
| 409 | `conflict` | Check whether settings changed, a Keep extension is unavailable, or a key was reused for a different operation. |
| 409 | `operation_uncertain` | Inspect current protection before making another operation. |
| 413 | `payload_too_large` | Reduce the body size. |
| 415 | `unsupported_media_type` | Send JSON writes with `Content-Type: application/json`. |
| 422 | `result_limit_exceeded` | Narrow the filters; the complete aggregate exceeds 10,000 records and no partial page is returned. |
| 429 | `rate_limited` | Wait for the `Retry-After` delay before another request. |
| 502 | `upstream_unavailable` | Retry a read later; the required source did not provide a complete result. |
| 502 | `mutation_uncertain` | Inspect current protection before making another operation. |
| 503 | `service_unavailable` | Wait for `Retry-After` when present. Check current state before repeating a write. |
| 500 | `internal_error` | Check current state before repeating a write. |

Responses do not disclose secrets or internal upstream details. GET requests accept no body. DELETE accepts no body, and JSON writes reject unknown or repeated fields. API responses use `Cache-Control: no-store`.

JSON write bodies are limited to 8 KiB. The application rejects requests above its global 1 MiB request limit. Limits are 60 reads per key per minute, 10 writes per key per minute, and 120 requests per peer per minute. These use minute windows; `429` responses include the retry delay. A key can retain up to 1,000 write-attempt records; uncertain attempts count toward this limit until the key is removed. Keep mutation operations share the application's cross-process mutation lock; contention returns `409 busy` before a new operation is applied.

Rotation preserves the original key's exact expiry, including Never expires; it does not extend or shorten it. The key management UI is the only key creation, revocation, rotation, and removal surface. Keys are not returned by API endpoints, and the API never accepts a secret in a path or query parameter.

## Backup and recovery

Keep's database backup includes key hashes, scopes, expiry, revocation and account state, together with successful and uncertain retry records. Restoring it does not recover the usable secrets; integrations must retain their own protected copies. Uncertain writes remain uncertain after a restore and must be checked before another attempt.

A backup restores the state at the time it was taken. Restoring an older backup can undo later key revocations, account changes, or password changes. Review the restored accounts and revoke or replace affected keys before exposing the recovered API to clients. The portable recovery fixture exercises credential validity and retry records as well as database fingerprints. Both native architectures run the recovery fixture against the packaged candidate. See the [recovery validation guide](RECOVERY_TRIAL.md) for the procedure, recorded evidence, and the distinction between synthetic recovery and human acceptance.
