# Bugzilla Needinfo Count

## Purpose

People at SUSE ask the security team for information in SUSE Bugzilla by
setting the `needinfo?` flag of a bug with the requestee
`security-team@suse.de`. Sentinel reports how many open bugs carry such a
request, so that a client can show the number beside the Tickets that need
attention and link to the Bugzilla search that lists the bugs.

Sentinel searches with its own Bugzilla account, whose API key no client
holds, so every caller receives the same count, including the restricted bugs
that this account can see. It reads the count from Bugzilla when a client asks
for it, and keeps the result for a short time so that the readers of one
minute share one Bugzilla request.

## Scope

In scope:

- the fixed Bugzilla search, its optional API key, and the validation of its
  response;
- the shared Redis cache of the result and the coordination of concurrent
  readers;
- the operation `GET /api/v1/bugzilla/needinfo-count`.

Out of scope:

- the bugs themselves: Sentinel never stores, returns, or logs a bug ID,
  summary, flag, or person of a matching bug;
- the permissions of the Bugzilla account to which the API key belongs, which
  decide which restricted bugs the count includes (Security and Privacy);
- the links between CVEs and their public bugs, which
  `docs/features/tickets/cve-sync-bugzilla.md` owns;
- presentation in a client.

## Related Specifications

| Specification | Relation |
|---|---|
| `docs/data-sources.md` (SUSE Bugzilla) | Hosts, interfaces, and verified behavior of SUSE Bugzilla |
| `docs/features/platform/networking.md` | Shared HTTP client used for the Bugzilla request |
| `docs/configuration.md` (External APIs) | `BUGZILLA_API_KEY` |
| `docs/conventions.md` (Redis; Secret Field Typing; External JSON Decoding) | Redis key, error handling, secret typing, and JSON decoding rules |
| `docs/features/platform/logging.md` | Secrets discipline |
| `docs/features/identity/rbac.md` | `triage_ticket` and the Endpoint Permission Map |
| `docs/api-spec.md` | Response envelope, Infrastructure Dependency Errors |

## Bugzilla Search

### Search Request

The count is the number of bugs that one `Bug.search` call to the JSON-RPC
interface of SUSE Bugzilla returns:

```text
POST https://bugzilla.suse.com/jsonrpc.cgi
Content-Type: application/json
```

```json
{
  "method": "Bug.search",
  "params": [
    {
      "include_fields": ["id"],
      "bug_status": [
        "UNCONFIRMED", "NEW", "CONFIRMED", "IN_PROGRESS", "REOPENED"
      ],
      "f1": "flagtypes.name",
      "o1": "equals",
      "v1": "needinfo?",
      "f2": "requestees.login_name",
      "o2": "equals",
      "v2": "security-team@suse.de",
      "limit": 0
    }
  ],
  "id": 1
}
```

| Member of `params[0]` | Purpose |
|---|---|
| `include_fields: ["id"]` | Returns only the ID of each bug. Bugzilla 5.0.6 ignores `count_only` and otherwise returns complete bugs, including the email addresses of their reporter, assignee, and CC list (`docs/data-sources.md`, SUSE Bugzilla) |
| `bug_status` (five values) | The open statuses: a resolved or verified bug is not counted |
| `f1`, `o1`, `v1` | A flag of type `needinfo` that is requested (`needinfo?`), not granted or denied |
| `f2`, `o2`, `v2` | The requestee of a flag is `security-team@suse.de` |
| `limit: 0` | No page limit, so that a default search limit of the server cannot truncate the result |

- The URL and the body are fixed: they are constants of the implementation,
  not settings, and no value of a client request reaches them. The only
  variable part is the member `Bugzilla_api_key` (Authentication).
- Sentinel uses the JSON-RPC interface, which Bugzilla 5.0 still provides but
  deprecates, because it accepts the API key in the request body, outside the
  URL (Authentication). The REST bug search with the
  same parameters returns the same bugs (`docs/data-sources.md`, SUSE
  Bugzilla).
- The request uses the shared HTTP client with its defaults
  (`docs/features/platform/networking.md`): `Accept: application/json`, TLS
  verification, and no redirect following. `Bug.search` changes nothing in
  Bugzilla, so the client enables the transport-level retry for this `POST`
  (`retry_non_idempotent=True`, `docs/features/platform/networking.md`,
  Method Safety).
- The complete read, including transport retries, has a deadline of
  **10 seconds**. When the deadline passes, the read is abandoned and has the
  outcome Transport failure (Response Contract), also when the deadline cuts
  short the wait of a retry that a `Retry-After` header asked for.

### Authentication

`BUGZILLA_API_KEY` (`docs/configuration.md`, External APIs) is the API key of
the Bugzilla account with which Sentinel searches:

- Set, the request carries the key as the member `Bugzilla_api_key` of
  `params[0]`, and the read is **authenticated**: Bugzilla searches with the
  permissions of the key's account, so the count includes the restricted bugs
  that this account can see.
- Empty or unset, the request carries no credential, and the read is
  **anonymous**: Bugzilla excludes every restricted bug, such as an embargoed
  one, so the count includes only public bugs. The application starts
  normally.

The key travels in the request body because SUSE Bugzilla reads it from no
header: it ignores `X-BUGZILLA-API-KEY`. Its REST bug search is a `GET`, which
carries the key only as a query parameter and would put it in every logged
request URL (`docs/features/platform/logging.md`,
Integration with Third-Party Loggers) and in the access logs of Bugzilla and
of the servers in front of it.

The key is a secret (`docs/conventions.md`, Secret Field Typing):

- It is a `SecretStr` setting, never logged, never written to a Redis value
  or a response, and never included in an exception message that Sentinel
  raises.
- A non-empty value must consist of printable ASCII characters without
  whitespace (U+0021 to U+007E), the rule of the secrets that Sentinel sends
  in a header. Any other value, for example one with a trailing newline from
  a file-based secret, fails startup with an error that names the variable
  but never its value. The value is rejected, never trimmed.
- It is supplied like the other credentials, as an environment variable from
  the deployment's secret store (`docs/deployment.md`). The API server is the
  only process role that uses it; `sync_bugzilla_bugs` never sends it.

### Response Contract

Bugzilla answers a `Bug.search` call with HTTP 200 whether it succeeds or
fails; the members `result` and `error` of the JSON body tell them apart. The
read classifies the response into exactly one outcome:

| Response | Outcome |
|---|---|
| HTTP 200 whose body is a JSON object in which `error` is `null` and `result` is a JSON object with a member `bugs` that is an array, every element of which is a JSON object with a member `id` that is an integer of at least 1 | **Count**: the number of elements of `bugs` |
| HTTP 200, on an authenticated read, whose body is a JSON object in which `error` is a JSON object with a member `code` equal to the integer `306`, the code of an invalid or revoked API key | **API key rejected** |
| HTTP 200 whose body is a JSON object in which `error` is a JSON object with a member `code` that is an integer, in every other case | **Bugzilla error** |
| Any HTTP status other than 200, including a redirect, which is not followed, a 403 of the bot protection, a 429, and a 5xx after transport retries | **HTTP failure** |
| HTTP 200 with any other body: not decodable, including a body whose content coding the shared client rejects, not JSON, not a JSON object, or with `error` or `result` absent or invalid | **Invalid response** |
| Connection error, timeout, proxy error, or protocol error after transport retries, or the deadline of the read | **Transport failure** |

- The body is decoded as UTF-8 through `decode_json()` (`docs/conventions.md`,
  External JSON Decoding). An empty body, a byte order mark, content after the
  value, the literals `NaN`, `Infinity`, and `-Infinity`, and a duplicated
  `error`, `result`, or `bugs` member make it not JSON. A JSON boolean or a
  number with a fraction or exponent is not an integer.
- Other members, and members of an element of `bugs` other than `id`, are
  ignored. The IDs are validated but not used: they are discarded with the
  decoded body and never stored, returned, or logged. The `message` of an
  error is never read.
- Every outcome other than Count is a **failed read**. A failed read never
  falls back to an anonymous request.
- Bugzilla returns at most 10000 bugs in one response (`docs/data-sources.md`,
  SUSE Bugzilla), so a count cannot exceed 10000 (Known Limitations).

### Search URL

The response of the operation carries the URL of the Bugzilla web search
with the same conditions, so that a client can link to the list of the
counted bugs:

```text
https://bugzilla.suse.com/buglist.cgi?bug_status=UNCONFIRMED&bug_status=NEW&bug_status=CONFIRMED&bug_status=IN_PROGRESS&bug_status=REOPENED&f1=flagtypes.name&o1=equals&v1=needinfo%3F&f2=requestees.login_name&o2=equals&v2=security-team%40suse.de&query_format=advanced
```

The URL is a constant of a release. It carries no credential: Bugzilla lists
to the person who follows it the matching bugs that their own Bugzilla
account can see.

## Cache and Read Coordination

### Redis Keys

The feature owns two application-owned Redis keys (`docs/conventions.md`,
Redis Key Conventions), both accessed through `REDIS_URL`:

| Key | Value | Expiry |
|---|---|---|
| `sentinel:bugzilla_needinfo_count` | The outcome of the latest completed read, as a JSON object (below) | 60 seconds after a Count; 10 seconds after a failed read |
| `sentinel:bugzilla_needinfo_count:lock` | `1` while a read is in progress | 15 seconds |

The value of `sentinel:bugzilla_needinfo_count` is one of:

| Value | Written after |
|---|---|
| `{"outcome": "count", "count": <integer ≥ 0>, "authenticated": <boolean>}` | A Count; `authenticated` states whether the read was authenticated |
| `{"outcome": "unavailable"}` | A failed read |

- A value is written with one atomic `SET` that includes its expiry. A value
  that is not a JSON object matching one of these forms, decoded through
  `decode_json()`, counts as absent. The values contain no bug ID, no
  credential, and no text received from Bugzilla.
- The lock expires 5 seconds after the deadline of the read that holds it, so
  it outlives every read that completes. The read releases it with a plain
  `DEL`. A read that stalls past the expiry can remove the lock of a later
  read; the only consequence is that one more read can start (Read
  Coordination).
- Every Redis operation of the feature has a connect and operation timeout of
  2 seconds; a timeout is a `RedisError`.

### `get_needinfo_count()`

```python
async def get_needinfo_count() -> NeedinfoCount: ...
```

`NeedinfoCount` carries `count` (int), `authenticated` (bool), and `url`
(str, the Search URL). The function lives in
`app/services/bugzilla_needinfo_service.py`. It reads no application data and
opens no database session.

**Behavior**:

1. Read `sentinel:bugzilla_needinfo_count`. A Count value returns it. An
   `unavailable` value raises `BugzillaUnavailableError` without a Bugzilla
   request.
2. Otherwise, set the lock key only if it is absent (`SET ... NX` with its
   expiry).
3. If the lock is acquired:
   1. Read `sentinel:bugzilla_needinfo_count` again: a read that completed
      between steps 1 and 2 has written it. If it holds a value, release the
      lock and continue as in step 1.
   2. Read the count from Bugzilla (Bugzilla Search).
   3. Write the outcome to `sentinel:bugzilla_needinfo_count` (Redis Keys).
   4. Release the lock.
   5. Return the Count, or raise `BugzillaUnavailableError` after a failed
      read.
4. If the lock is held by another read, wait for its outcome: every 250
   milliseconds, read both keys in one command (`MGET`).
   - A Count value returns it, and an `unavailable` value raises
     `BugzillaUnavailableError`.
   - When neither key exists, the other read ended without writing an
     outcome: raise `BugzillaUnavailableError`.
   - When no value has appeared 15 seconds after the wait began, the expiry
     of the lock, raise `BugzillaUnavailableError`. The other read can take
     that long: its re-read, its 10-second Bugzilla read, and its write.

**Redis unavailability**: every Redis operation catches `RedisError`
(`docs/conventions.md`, Redis Error Handling). The cache only spares Bugzilla
repeated requests, so a failure before the wait does not fail the operation:

- A failure in step 1 or step 2 abandons the cache: the function reads the
  count from Bugzilla directly, without lock or cache write, and returns its
  Count or raises `BugzillaUnavailableError`.
- A failure in step 3 leaves the outcome of the read unchanged: a failed
  re-read in step 3.1 continues with step 3.2, and a failed write or release
  is ignored. A lock that is not released expires.
- A failure of a read in step 4 raises `BugzillaUnavailableError`: another
  read is already in progress, and a second one would exceed the response
  time that the wait bounds.
- Each failure logs `bugzilla_needinfo_cache_failed` (Logging). The function
  logs at most one such record per invocation.

**Response time**: an invocation that reads Bugzilla ends within the 10-second
deadline of the read plus its Redis operations; one that waits ends within 15
seconds plus one poll.

**Re-invocation**: the function changes no persistent state. A call within the
expiry of a cached value returns that value or raises without a Bugzilla
request; a later call reads Bugzilla again. While Redis is available, the
calls of all API processes that find no cached value share one Bugzilla read;
while it is unavailable, each call sends its own.

**Audit events**: none. The read changes no application state.

**Exceptions**: the function raises `BugzillaUnavailableError` as stated
above. A failure to create the HTTP client, such as `TLSConfigurationError`
for a corrupt `SUSE_CA_CERT_PATH` or the `ValueError` of an invalid proxy
variable (`docs/features/platform/networking.md`), propagates; the lock is
released and no outcome is written, so the next call retries.

### Service Exceptions

`BugzillaNeedinfoServiceError` inherits from `ServiceError` and is the base
of this module's exceptions. The API handler catches each documented
exception and maps it as follows (`docs/api-spec.md`, Infrastructure
Dependency Errors):

| Exception | HTTP | Code | Raised when |
|---|---|---|---|
| `BugzillaUnavailableError` | 503 | `BUGZILLA_UNAVAILABLE` | No valid count from SUSE Bugzilla is available |

## API Endpoint

### Get Bugzilla Needinfo Count

Returns the number of open SUSE Bugzilla bugs on which a `needinfo?` flag
asks `security-team@suse.de` for information.

```text
GET /api/v1/bugzilla/needinfo-count
```

**`Capability: triage_ticket`**

**Request body**: none.

**Query parameters**: none.

**Response** (200):

```json
{
  "data": {
    "count": 2,
    "authenticated": true,
    "url": "https://bugzilla.suse.com/buglist.cgi?bug_status=UNCONFIRMED&bug_status=NEW&bug_status=CONFIRMED&bug_status=IN_PROGRESS&bug_status=REOPENED&f1=flagtypes.name&o1=equals&v1=needinfo%3F&f2=requestees.login_name&o2=equals&v2=security-team%40suse.de&query_format=advanced"
  }
}
```

| Field | Type | Description |
|---|---|---|
| `count` | integer, required | The number of open bugs that match the search for a `needinfo?` flag with the requestee `security-team@suse.de` (Search Request; Known Limitations, Same flag), among the bugs that the Bugzilla read could see. At least 0 and at most 10000. It can lag Bugzilla by up to 60 seconds (Cache and Read Coordination) |
| `authenticated` | boolean, required | Whether the Bugzilla read that produced `count` was authenticated with Sentinel's API key. `true`: the read was authenticated, so `count` can also include restricted (private) bugs, those that the key's Bugzilla account can see. `false`: the read was anonymous because no API key is configured, so `count` includes only public bugs and can be lower than the number of bugs that ask the security team. `true` does not prove that `count` includes every restricted bug: that depends on the permissions of the key's account, which Sentinel cannot observe |
| `url` | string, required | The URL of the Bugzilla web search with the same conditions (Search URL). The same for every response of a release |

**Behavior**:

- The route calls `get_needinfo_count()` and returns its result. The result is
  the same for every caller: it depends on Sentinel's Bugzilla account, not
  on the caller.
- The operation reads no Ticket, CVE, or other application data, and its
  result is not constrained by the caller's scope.
- The handler holds no row lock while the service waits for Bugzilla
  (`docs/conventions.md`, Transaction Hygiene Rules), but the request keeps
  the database connection of its authentication until it returns (Known
  Limitations). The response time is that of `get_needinfo_count()`: at most
  about 15 seconds.

**Error responses**:

| Status | Code | Condition |
|---|---|---|
| 503 | `BUGZILLA_UNAVAILABLE` | No valid count could be obtained from Bugzilla (`BugzillaUnavailableError`) |

The operation does not return `REDIS_UNAVAILABLE`: it reads Bugzilla directly
when Redis is unavailable (`get_needinfo_count()`).

## Logging

| Event | Level | Fields | Emitted when |
|---|---|---|---|
| `bugzilla_needinfo_read_failed` | WARNING | `reason`, `authenticated`; `http_status` when `reason` is `http_status`; `error_code` when `reason` is `bugzilla_error` | A read has an outcome other than Count and API key rejected |
| `bugzilla_needinfo_api_key_rejected` | ERROR | — | A read has the outcome API key rejected: the configured key is invalid or revoked and needs to be replaced |
| `bugzilla_needinfo_cache_failed` | WARNING | `error_type` | A Redis operation of `get_needinfo_count()` fails |

- `reason` is `http_status`, `bugzilla_error`, `invalid_response`, or
  `transport`, for the outcomes HTTP failure, Bugzilla error, Invalid
  response, and Transport failure. `error_code` is the integer `code` of the
  Bugzilla error.
- `error_type` is the exception class name only.
- No record carries the request body, the API key, the response body, a bug
  ID, an exception message, or text received from Bugzilla. A failed read
  that only waited for another request's read logs nothing; the read that
  failed has logged it.

## Security and Privacy

- **Credential handling.** The API key travels only in the body of a `POST`
  to the fixed host `bugzilla.suse.com` over verified TLS, through a forward
  proxy only inside a `CONNECT` tunnel, and the client follows no redirect, so
  the key reaches no other host. No URL that Sentinel requests or logs
  carries it. The `httpx` logger records the URL, not the body
  (`docs/features/platform/logging.md`, Integration with Third-Party
  Loggers).
- **What a leaked key exposes.** A Bugzilla API key carries every permission
  of its account. The account to which `BUGZILLA_API_KEY` belongs can read the
  restricted bugs of the security team, embargoed ones included, and holds no
  permission to edit bugs or administer Bugzilla. A leaked key therefore
  discloses every bug that the account can read, and allows what Bugzilla
  permits every signed-in user who can see a bug, such as commenting on it or
  filing a bug. An exposed key is revoked in Bugzilla and replaced. Sentinel
  uses it only for this search, which changes nothing in Bugzilla.
- **What the response discloses.** The response carries only a number, a
  boolean, and a constant URL; no bug ID, summary, product, flag setter, or
  person. A caller with `triage_ticket` and scope `non_confidential`, such as
  a restricted analyst, receives a count that includes restricted bugs. By
  comparing it with the list that the Search URL shows to their own Bugzilla
  account, such a caller learns how many restricted bugs wait for the
  security team, and, by watching it, when one is added or answered, but
  nothing about the content of any of them. This disclosure is accepted.
- **No personal data.** The search requests only bug IDs, so no email
  address or name of a Bugzilla user is received; the IDs are discarded after
  validation. `security-team@suse.de` is the address of a team, a constant of
  the query.
- **Fixed request.** No client input reaches the Bugzilla request, so the
  operation cannot be used to search Bugzilla with Sentinel's account. While
  Redis is available, callers cause at most one Bugzilla request per 60
  seconds, and one per 10 seconds while Bugzilla fails.

## Design Decisions

- **Read on request, not by a fetcher.** The count belongs to Bugzilla and is
  useful only while someone looks at it. A read on request with a short cache
  keeps no copy in PostgreSQL and sends no request while nobody asks, at the
  cost of a slower response after the cache expires. A scheduled fetcher
  would write a value that nobody may read, and would report a count up to its
  interval old. Request-driven reads of an external service from the API
  follow the precedent of the SMELT requests of package addition
  (`docs/features/packages/package-service.md`).
- **Shared cache with one read at a time.** Several analysts load the Ticket
  list within the same minute. The cache and the lock make all API processes
  share one Bugzilla request, and the short cache of a failure keeps an
  outage of Bugzilla from making every request wait for its own deadline.
- **Fail open on Redis.** Redis holds only a copy of a value that Bugzilla can
  return again, so the operation does not fail when Redis does before it
  waits (`docs/architecture.md`, PostgreSQL as single source of truth).
- **Anonymous fallback.** Without a key, the operation still reports the
  public bugs, and `authenticated` lets a client say that the count is
  partial. A rejected key fails the operation instead of falling back, so that
  an expired or revoked key is noticed and the count does not silently shrink.
- **JSON-RPC instead of REST.** The REST bug search would carry the key in
  the query string. The JSON-RPC interface keeps it out of every URL, at the
  cost of an interface that Bugzilla deprecates. If an upgrade of SUSE
  Bugzilla removes it, the read fails visibly (HTTP failure or Invalid
  response), and the search is moved to a credential transport that the
  upgraded release accepts outside the URL.
- **Constant query.** The requestee and the statuses are constants: Sentinel
  serves one security team, and its Bugzilla host is fixed as well.

## Known Limitations

- **Visibility of the account.** An authenticated count includes only the
  restricted bugs that the key's Bugzilla account can see; Bugzilla does not
  report what it excluded. The person who follows the Search URL can see more
  or fewer bugs than the count, according to their own Bugzilla account.
- **Same flag.** The search can match its two flag conditions on different
  flags of one bug, for example a `needinfo?` asked of another person and
  another requested flag whose requestee is the security team. The web search
  of the Search URL applies the same conditions, so the count and the list
  agree.
- **Up to 60 seconds old.** A count can lag a change in Bugzilla by up to 60
  seconds, and a recovered Bugzilla is noticed up to 10 seconds late.
- **At most 10000.** A count is at most 10000, the largest response that
  Bugzilla returns.
- **Held database connection.** Like every authenticated request, the request
  holds the database connection of its authentication until it returns, so a
  request that waits for Bugzilla keeps a pooled connection idle for up to
  about 15 seconds. Many concurrent requests while Bugzilla is slow can use up
  the connection pool of an API process for that time.
- **Changed key or deployment.** A change of `BUGZILLA_API_KEY` takes effect
  after a restart and after the cached value expires. While API processes with
  and without a key run side by side, `authenticated` reports the process
  that performed the cached read.

## Testing Requirements

Implementation tests must cover:

- the exact request URL and body, `include_fields`, no `Bugzilla_api_key`
  without a key, the member `Bugzilla_api_key` with a key, the key absent
  from the URL and from every header, and transport retry enabled for the
  `POST`;
- startup validation of `BUGZILLA_API_KEY`: empty or unset accepted; a
  printable ASCII value accepted; a value with whitespace, a trailing
  newline, or a non-ASCII character rejected with an error that does not
  contain the value;
- every row of Response Contract, including an `id` that is a boolean, a
  float, zero, or negative, an element that is not an object, a body that is
  not an object, `result` or `bugs` absent, `error` code `306` on an
  authenticated read (API key rejected) and on an anonymous read (Bugzilla
  error), a duplicated `bugs` member, `NaN`, and the 10-second deadline;
- the cache: a hit sends no Bugzilla request; a Count is cached for 60
  seconds and a failed read for 10; an invalid cached value counts as absent;
  a value written between steps 1 and 2 is returned without a Bugzilla
  request;
- coordination: a second concurrent call waits and returns the first call's
  Count or its failure without a second Bugzilla request, also when the first
  call's read ends near its deadline; a waiter raises when both keys
  disappear, and after 15 seconds without a value;
- Redis failure at each step (`RedisError`, including an OOM `ResponseError`
  and a timeout): before the wait, the operation reads Bugzilla directly and
  returns its result; during the wait, it raises; either way it logs
  `bugzilla_needinfo_cache_failed` once;
- the endpoint: 200 with the response schema, `authenticated` for both
  configurations, `503 BUGZILLA_UNAVAILABLE`, `401` without credentials, and
  `403` for a user without `triage_ticket`;
- that no log record, Redis value, or response contains the API key, a bug
  ID, or the Bugzilla response body;
- contract tests against sanitized fixtures of the real responses, written
  before the parser (`docs/conventions.md`, External Integration Contract
  Verification): an anonymous and an authenticated Count, and the error of an
  invalid key.

## Cross-references

- `docs/api-spec.md` — Response Format; Infrastructure Dependency Errors
- `docs/features/identity/rbac.md` — `triage_ticket`; Business Rule 14;
  Endpoint Permission Map
- `docs/data-sources.md` — SUSE Bugzilla
- `docs/configuration.md` — External APIs (`BUGZILLA_API_KEY`)
- `docs/deployment.md` — Network Access; configuration checklists; Redis
  Durability, Memory, and Persistence
- `docs/features/platform/networking.md` — Shared HTTP Client; Non-Fetcher
  Components
- `docs/features/platform/logging.md` — Secrets and PII Discipline
- `docs/features/packages/package-service.md` — the SMELT requests of package
  addition, the precedent of a request-driven read from the API
- `docs/conventions.md` — Redis; Secret Field Typing; External JSON Decoding;
  External Integration Contract Verification
- `docs/features/tickets/cve-sync-bugzilla.md` — the anonymous fetcher that
  links CVEs to their public bugs
