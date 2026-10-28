# API Key Management

## Purpose and Scope

Define the API key lifecycle visible to users and operators: key format,
name and status rules, self-service and administrator REST endpoints, CLI
commands, retention, and security guarantees.

This specification owns API key management behavior. The related boundaries
remain authoritative in their dedicated specifications:

- `authentication.md` owns API key credential recognition, validation, and
  the debounced `last_used_at` authentication touch.
- `api-key-service.md` owns service signatures, transaction behavior,
  locking, persistence, and audit-event creation.
- `identity-audit-log.md` owns the `api_key_created` and
  `api_key_revoked` event payloads.
- `data-model.md` owns the `ApiKey` table and indexes.
- `api-spec.md` owns shared API envelopes, pagination, filtering, sorting,
  validation, and global responses.

API key rotation is performed by creating a replacement key, updating the
consumer, and revoking the old key. Sentinel does not expose a rotate
operation because the plaintext secret cannot be recovered or transformed.
There is no single-key detail endpoint: list responses expose every stored
non-secret field needed to identify and manage a key.

## API Key Contract

### Key Format and Visibility

API keys use this format:

```text
stl_ak_<32 random alphanumeric characters>
```

The random suffix is generated with a cryptographically secure random number
generator. The `stl_ak_` prefix lets the authentication boundary distinguish
API keys from JWTs without attempting JWT decoding.

The full key is returned exactly once, in the successful creation response.
Sentinel persists only:

- the lowercase hexadecimal SHA-256 digest of the full key;
- the first 12 characters as a display prefix; and
- the key's non-secret metadata.

No later API, CLI, log, or audit response returns the full key or its hash.
The plaintext cannot be recovered after creation.

### API Key Name Rule

Every creation entry point applies these steps in order:

1. Trim leading and trailing whitespace.
2. Convert the value to lowercase.
3. Require a length of 1-128 characters after normalization.
4. Require every character to match `[a-z0-9._-]`.

The normalized value is persisted and returned. For example,
`"  CI.Production  "` becomes `"ci.production"`. A value that is empty
after trimming, too long, or contains any other character is rejected with
`AUTH_API_KEY_NAME_INVALID`.

Names are unique per owner among non-revoked keys. The uniqueness comparison
uses the normalized stored value. An expired but non-revoked key still
reserves its name; after revocation, the owner may reuse the name.

### Expiration

`expires_at` is optional. `NULL` means the key does not expire. A non-NULL
value must be strictly later than the creation operation's current time;
otherwise creation is rejected with `AUTH_API_KEY_INVALID_EXPIRY`.

The request accepts a full ISO 8601 datetime. A value without an explicit
offset is interpreted as UTC; a value with an offset is converted to UTC. A
date-only value is not accepted and returns the global `422 VALIDATION_ERROR`.

There is no minimum duration and no maximum expiration. A key may expire
seconds after creation or have no expiration.

### Derived Status

Status is derived at read time and is not stored. Exactly one status applies,
using this precedence:

1. `revoked` when `revoked_at IS NOT NULL`.
2. Otherwise, `expired` when `expires_at IS NOT NULL AND expires_at <= now`.
3. Otherwise, `active`.

The same derivation applies to API and CLI responses, `status` filters,
active-key anomaly counts, and all service queries. In particular, a revoked
key whose expiration has passed is `revoked`, never `expired`.

The operation or query takes one UTC `now` snapshot and uses it for every
status calculation in that invocation. A key with `expires_at` equal to that
snapshot is expired.

### Lifecycle and Retention

Every authenticated active user may create, list, and revoke their own keys.
Key creation requires a JWT-backed session; a request authenticated by an API
key cannot create another key. This prevents a compromised key from
self-replicating.

Users with `manage_users` may list and revoke keys for any user. They cannot
create keys on another user's behalf. CLI operators with shell access may list
keys by username and revoke a key by its globally unique UUID.

Revocation sets `revoked_at` and `revoked_by`; it never deletes the row.
Self-service and administrator revocations record the acting user's UUID.
CLI and external-sync revocations use `revoked_by = NULL`. Deactivation
propagates its actor: authenticated API deactivation records the administrator,
while CLI and external-sync deactivation use NULL. Repeating or concurrently
executing a revocation is an idempotent
no-op after the first successful mutation and creates no additional audit
event.

User deactivation revokes every non-revoked key, including expired keys.
Reactivation never restores them; the plaintext secrets are unavailable and
the user must create new keys.

Revoked and expired keys are retained indefinitely. There is no cleanup task.
The retained API key row is lifecycle history, while `IdentityAuditEvent` is
the authoritative historical audit record. Current revocation and expiry state
is determined from the API key row, never reconstructed from audit events; see
`docs/features/platform/audit-trail-infrastructure.md` (Operational State
Authority).

### Active-Key Anomaly Warning

There is no hard limit on keys per user. After successful creation, count the
owner's keys whose derived status is `active`. When the count exceeds 20,
emit a WARNING containing only:

- the structured event name;
- the owner's internal `user_id` UUID;
- the active-key count; and
- the threshold value 20.

The structured record is
`event="api_key_active_count_exceeded"`, `user_id=<owner UUID>`,
`active_key_count=<count>`, and `threshold=20`. It must not contain a
username, email, key name, key prefix, key secret, key hash, or source IP.
The warning is operational and does not replace the creation audit event.

## API

All list endpoints follow the pagination, validation, response-envelope, and
deterministic secondary-ordering contracts in `docs/api-spec.md`. The
`status` filter accepts one value. Invalid values are silently ignored and,
because the filter has only one value, produce an empty result per
`api-spec.md` (Enum Filter Validation). Both list endpoints support:

| Parameter | Type | Default | Description |
|---|---|---|---|
| `status` | string | -- | One of `active`, `revoked`, or `expired` |
| `page` | int | `1` | Page number |
| `per_page` | int | `20` | Items per page; maximum 100 |
| `sort_by` | string | `created_at` | `created_at` or `last_used_at` |
| `sort_order` | string | `desc` | `asc` or `desc` |

When `sort_by=last_used_at`, NULL ordering per `api-spec.md` (Nullable
Sort Field Ordering). Non-NULL values follow `sort_order`. The
primary-key tiebreaker required by `api-spec.md` makes pagination
deterministic.

All non-creation responses omit the plaintext key and hash. `revoked_by` is
either NULL for a CLI or automated revocation or the standard User Reference
Object from `api-spec.md` for the acting user. The common API key object is:

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "prefix": "stl_ak_7f3a9",
  "name": "ci.production",
  "status": "active",
  "created_at": "2026-08-01T10:00:00Z",
  "last_used_at": null,
  "expires_at": null,
  "revoked_at": null,
  "revoked_by": null
}
```

### List My API Keys

```text
GET /api/v1/api-keys
```

**`Access: Authenticated`**

Returns only keys whose `user_id` equals the authenticated user's ID. The
owner is implicit and no owner filter is accepted. The endpoint delegates the
query to `api_key_service.list_user_keys()`; the handler performs no database
query. The handler captures one UTC `now` snapshot, passes it to the service,
and uses that same value to serialize every returned `status`.

**Response (200):** the standard paginated envelope containing common API
key objects.

### Create API Key

```text
POST /api/v1/api-keys
```

**`Access: Authenticated`**

This endpoint additionally requires JWT session authentication. API-key
authentication returns `403 AUTH_SESSION_REQUIRED` with detail
`"This operation requires session authentication."`. The
`require_session_authentication()` dependency (defined in
`docs/features/identity/authentication.md`) enforces this before handler
execution; the handler does not re-parse the token or duplicate the
`stl_ak_` recognition rule.

**Request body:**

```json
{
  "name": "ci.production",
  "expires_at": "2026-12-01T10:00:00Z"
}
```

`expires_at` may be omitted or `null`. The handler delegates to
`api_key_service.create_key()` with the authenticated user's ID. The service
uses that user as both owner and audit actor; there is no separate actor,
system creation, or administrator creation path.

**Response (201):**

```json
{
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "prefix": "stl_ak_7f3a9",
    "name": "ci.production",
    "key": "stl_ak_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "status": "active",
    "created_at": "2026-08-01T10:00:00Z",
    "last_used_at": null,
    "expires_at": "2026-12-01T10:00:00Z",
    "revoked_at": null,
    "revoked_by": null
  }
}
```

The creation response contains the common API key object plus `key`. The
`key` field appears only in this response.

**Error responses:**

| Status | Code | Condition |
|---|---|---|
| 400 | `AUTH_API_KEY_INVALID_EXPIRY` | `expires_at` is not strictly in the future |
| 403 | `AUTH_SESSION_REQUIRED` | Request is authenticated by API key instead of JWT session |
| 409 | `USER_INACTIVE` | Owner became inactive before creation acquired the user lock |
| 409 | `AUTH_API_KEY_NAME_CONFLICT` | A non-revoked key has the same normalized name |
| 422 | `AUTH_API_KEY_NAME_INVALID` | Normalized name violates the API Key Name Rule |

### Revoke My API Key

```text
POST /api/v1/api-keys/{key_id}/revoke
```

**`Access: Authenticated`**

Calls `api_key_service.revoke_key()` with
`owner_user_id=current_user.id` and `acting_user_id=current_user.id`. A
missing key and a key owned by another user both return
`404 AUTH_API_KEY_NOT_FOUND`; the response must not reveal whether another
user's key exists. The handler performs no preliminary key lookup or
ownership query.

The operation is idempotent. An already-revoked key returns 200 with its
unchanged representation and creates no new audit event.

**Response (200):** `data` contains the common API key object with
`status="revoked"`.

**Error responses:**

| Status | Code | Condition |
|---|---|---|
| 404 | `AUTH_API_KEY_NOT_FOUND` | Key does not exist or belongs to another user |

### List All API Keys

```text
GET /api/v1/admin/api-keys
```

**`Capability: manage_users`**

Supports the common list parameters plus:

| Parameter | Type | Default | Description |
|---|---|---|---|
| `owner` | string | -- | Owner UUID or case-sensitive exact username per `api-spec.md`; unknown owner yields an empty result |

The endpoint captures one UTC `now` snapshot, passes it to
`api_key_service.list_all_keys()`, and uses that same value to serialize every
returned `status`. Every item adds `owner`, the standard User Reference Object
from `api-spec.md`, to the common API key object. The endpoint returns the
standard paginated envelope.

### Revoke API Key

```text
POST /api/v1/admin/api-keys/{key_id}/revoke
```

**`Capability: manage_users`**

Calls `api_key_service.revoke_key()` without an owner restriction and with
the authenticated administrator as actor. A missing key returns
`404 AUTH_API_KEY_NOT_FOUND`. The operation is idempotent.

An administrator may revoke the API key used for the current request.
Authentication has already completed, so this request succeeds; subsequent
requests using that key fail authentication.

**Response (200):** `data` contains the common API key object plus `owner`,
the standard User Reference Object, with `status="revoked"`.

**Error responses:**

| Status | Code | Condition |
|---|---|---|
| 404 | `AUTH_API_KEY_NOT_FOUND` | Key does not exist |

## CLI Commands

The CLI provides operator listing and emergency revocation. It intentionally
does not create API keys: creation must be self-service through a JWT session,
preserving the anti-replication and owner-attribution rules above.

### `sentinel api-key list`

```text
sentinel api-key list --username <username>
```

**Parameters:**

| Parameter | Required | Description |
|---|---|---|
| `--username` | Yes | Owner username; trimmed and lowercased before lookup |

Lists all keys for the user, without pagination, using
`api_key_service.list_user_keys_for_cli()`. This is an operator command over
one user's expected-small key set, not an API list endpoint. Rows are ordered
by `id` descending — `id` is a UUIDv7 value, so this is equivalent to
`created_at` descending with a deterministic tiebreak, in a single column.
Inactive users are accepted; the command reports retained keys regardless of
owner lifecycle state.

**Output:** a fixed-width table on stdout with columns `ID`, `PREFIX`,
`NAME`, `STATUS`, `CREATED AT`, `LAST USED AT`, and `EXPIRES AT`, in that
order. UUIDs are included so the operator can pass a selected value to
`api-key revoke`. Each column's width is the maximum length across its
header and every rendered value in the result set (no truncation, no
wrapping); columns are separated by two spaces and each row's trailing
spaces are stripped, matching the rendering already used by `manage-user
list`/`show` (`docs/conventions.md`, Human-Readable Format). Timestamps
use the exact format `YYYY-MM-DD HH:MM:SS UTC` (`strftime("%Y-%m-%d
%H:%M:%S UTC")` after converting to UTC), with no sub-second precision. A
user with no keys produces the header and no data rows — no alternative
"no keys found" message. NULL `LAST USED AT` and `EXPIRES AT` values
display as `—`.

**Errors and exit codes:**

| Code | Condition and output |
|---|---|
| 0 | Success, including an empty key list |
| 1 | Unknown user: `Error: User '<username>' not found.` on stderr |
| 2 | Database or unexpected system failure on stderr |

**Idempotency:** Idempotent (read-only).

### `sentinel api-key revoke`

```text
sentinel api-key revoke --key-id <uuid>
```

**Parameters:**

| Parameter | Required | Description |
|---|---|---|
| `--key-id` | Yes | Globally unique API key UUID |

Calls `api_key_service.revoke_key()` without an owner restriction and with
`acting_user_id=None`. Therefore `revoked_by` and the audit actor are NULL
(system action). The command does not accept or infer a username; `key_id`
uniquely identifies the target.

**Output:** print `API key '<key_id>' is revoked.` to stdout whether this
invocation performed the mutation or found the key already revoked. This
single idempotent confirmation does not require a preliminary read. Both
outcomes exit 0.

**Errors and exit codes:**

| Code | Condition and output |
|---|---|
| 0 | Revoked or already revoked |
| 1 | Missing key: `Error: API key '<key_id>' not found.` on stderr; malformed UUID is a Click user error |
| 2 | Database or unexpected system failure on stderr |

**Idempotency:** Idempotent; repeated and concurrent calls create at most one
mutation and one `api_key_revoked` event.

## Use Cases

### Personal Automation

An existing user creates `my-automation-bot`, stores the returned secret in
the consumer's secret store, and uses it for programmatic requests. Actions
performed with the key are attributed to its owner, a person, so they appear
as that person's actions: the owner's account is not a bot account.

### Dedicated Automation Identity

An administrator creates a dedicated local user such as
`security-scanner` and marks it as a bot account
(`docs/features/identity/user-management.md`, Bot Accounts), so that clients
present its actions as automated. An operator authenticates as that user and
creates an API key through the self-service endpoint. The automation then has
its own roles and attribution. Administrators still cannot create its key on
its behalf.

## Security and Audit Guarantees

- API key plaintext and hashes never appear in logs, audit events, list
  responses, CLI output, or error details.
- Key prefixes and names are display metadata but are omitted from API key
  credential-validation failure warnings; see `authentication.md`.
- API key lifecycle mutations and their `IdentityAuditEvent` records are
  atomic in the caller-owned database transaction.
- `last_used_at` is high-frequency operational authentication metadata, not
  a lifecycle mutation. It creates no `IdentityAuditEvent`.
- Expiration is optional by design. Users and operators are responsible for
  revoking credentials that are no longer needed; user deactivation provides
  an administrative bulk-revocation path.

## Cross-references

- `docs/api-spec.md` — API envelopes, pagination, filtering, sorting,
  validation, and global responses
- `docs/cli-reference.md` — operator-facing CLI index
- `docs/data-model.md` — `ApiKey` schema and indexes
- `docs/features/identity/api-key-service.md` — service operations,
  transaction ownership, locking, and exceptions
- `docs/features/identity/authentication.md` — API key credential validation
- `docs/features/identity/identity-audit-log.md` — API key audit events and
  operational-metadata exclusion
- `docs/features/identity/rbac.md` — capabilities and Endpoint Permission Map
- `docs/features/identity/user-service.md` — deactivation orchestration
- `docs/features/platform/cli-infrastructure.md` — shared CLI execution
  mechanism
- `docs/features/platform/logging.md` — logging and PII rules
- `docs/features/platform/testing-strategy.md` — required implementation
  verification
