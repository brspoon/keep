# Keep API v1

The Keep API gives an account-bound client access to the selected Leaving and Kept collections and to Keep protection actions. It does not expose Radarr or Sonarr library inventory, file paths, media deletion, or arbitrary upstream service data. Removing a Keep only removes protection; it never deletes a title from Plex.

The OpenAPI 3.1 contract is maintained in the version-controlled [`static/openapi.json`](../static/openapi.json) source. The owner can browse the interactive, read-only reference under **Admin → API reference**. The API is versioned at `/api/v1`. Additive fields and optional parameters may be introduced within v1; a breaking contract change requires a new version namespace.

## Access and keys

The Keep owner creates and manages keys under **Admin → API keys**. These settings and the API reference are available only to the owner. Keys are named, belong to the owner account, and are shown in usable form only once at creation or rotation. Keep stores a cryptographic hash of each secret. A key cannot be created through the API.

Choose an expiry of **30, 90 or 365 days**, or **Never expires**. The default is 90 days. Every key has an explicit set of scopes. An explicitly non-expiring key remains subject to revocation, account state, scope, and current-permission checks on every request. A key may be revoked or atomically rotated. Rotation invalidates the old secret as the replacement is issued and preserves the original expiry, including expiries chosen in older releases. Revoking a Keep account, changing its session version, or changing its live permissions also affects its API keys immediately: each request checks that the account remains active and recomputes authorization. A key's scopes limit what it can request; they never grant account permissions.

Revoked keys can be removed from the key list. Removal deletes the credential and its related retry and rate-limit records while retaining audit history.

Send the secret in the `Authorization` header. Never place credentials in a URL, query string, source control, or logs. Use HTTPS in normal deployments and keep the secret in a protected credential store.

Keys issued to non-owner accounts in older releases retain their existing authorization rules. Non-owner Plex accounts need a positive server-access verification within the last 24 hours. The worker normally refreshes observed accounts every 15 minutes; accounts omitted from Plex's access feeds must sign in with Plex again before that verification expires. Feed absence revokes previously observed accounts; an upstream outage cannot renew access. Expired verification blocks browser sessions and API keys even if the worker is unavailable. Fresh verification after expiry changes the account's credential version and invalidates its older keys. Local accounts and the installation owner retain their separate authorization rules.

```http
Authorization: Bearer keep_<secret>
Accept: application/json
```

Scopes are:

- `collections:read` — list configured collections.
- `media:read` — read the selected Leaving and Kept collection media.
- `keeps:read` — list or read Keep records the account is allowed to see.
- `keeps:write` — create a Keep, change its duration, or remove its protection, subject to current Keep permissions.

No CORS access is enabled by default. Browser clients should use the Keep web application rather than sending API keys from a browser.

## Resources and identifiers

A `media_id` is a positive Plex media ID represented as a decimal string with at most 20 digits. A `collection_id` is a positive integer no greater than 999,999,999. A Keep `id` combines both values as `collection_id:media_id`, for example `1:42`.

Media reads contain only the documented allowlisted fields: media ID, collection ID, title, year, normalized type, and state. They do not contain raw Maintainerr records, provider IDs, paths, or other upstream properties.

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

`GET /media` accepts `collection_id`, `search` (at most 100 characters), and `state`. `state` is `leaving` by default and may be `kept` or `all`. Search is case-insensitive title matching. `GET /keeps` accepts `collection_id`. List results use the caller's current permissions and configured collections. A collection read or list can fail if its source cannot be read completely; the API does not return a silently truncated upstream page as a complete result.

## Keep writes and retries

`POST /keeps`, `PATCH /keeps/{keep_id}`, and `DELETE /keeps/{keep_id}` require an `Idempotency-Key` header containing 16–128 ASCII letters, digits, underscores, or hyphens. The same key, method, path, and request body replays the original successful response for 24 hours. Reusing a key with a different request returns `409 conflict`.

A request interrupted while an upstream protection change may have occurred returns `409 operation_uncertain` or `502 mutation_uncertain`. Do not automatically retry it with a new key. Inspect the current Keep state first; then use a new key for a new operation. This avoids repeating a remote action whose result is unknown.

Retry records belong to the API key that made the request. After replacing a key, check the current Keep state before repeating an earlier write with its replacement.

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

`duration` is optional and defaults to `temporary`. The only accepted fields are `collection_id`, `media_id`, and `duration`. The API returns `201 Created` with a Keep record in the `{ "data": ... }` envelope.

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

The only accepted field is `duration`, which is required. Changing a temporary Keep follows Keep's existing extension-availability rules; an unavailable extension returns `409 conflict`. The response contains the updated Keep in the `{ "data": ... }` envelope; read the Keep record to see its availability time.

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

The API returns `400 invalid_request`, `401 invalid_token`, `403 insufficient_scope` or `permission_denied`, `404 not_found`, `405 method_not_allowed`, `409 busy`, `conflict`, or `operation_uncertain`, `413 payload_too_large`, `415 unsupported_media_type`, `429 rate_limited`, `502 upstream_unavailable` or `mutation_uncertain`, `503 service_unavailable`, and `500 internal_error` as appropriate. `429` includes `Retry-After`. A list whose complete aggregate exceeds 10,000 records returns `422 result_limit_exceeded` with no partial results. Responses do not disclose secrets or internal upstream details.

JSON write bodies are limited to 8 KiB. The application rejects requests above its global 1 MiB request limit. Limits are 60 reads per key per minute, 10 writes per key per minute, and 120 requests per peer per minute. `429` responses include the retry delay. Keep mutation operations share the application's cross-process mutation lock; contention returns `409 busy` before a new operation is applied.

Rotation preserves the original key's exact expiry, including Never expires; it does not extend or shorten it. The key management UI is the only key creation, revocation, rotation, and removal surface. Keys are not returned by API endpoints, and the API never accepts a secret in a path or query parameter.

## Backup and recovery

Keep's database backup includes key hashes, scopes, expiry, revocation and account state, together with successful and uncertain retry records. Restoring it does not recover the usable secrets; integrations must retain their own protected copies. Uncertain writes remain uncertain after a restore and must be checked before another attempt.

A backup restores the state at the time it was taken. Restoring an older backup can undo later key revocations, account changes, or password changes. Review the restored accounts and revoke or replace affected keys before exposing the recovered API to clients. The portable recovery fixture exercises credential validity and retry records as well as database fingerprints. Both native architectures run the recovery fixture against the packaged candidate. See the [recovery validation guide](RECOVERY_TRIAL.md) for the procedure, recorded evidence, and the distinction between synthetic recovery and human acceptance.
