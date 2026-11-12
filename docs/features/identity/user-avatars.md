# User Avatars

## Purpose

Users appear throughout the API as Ticket assignees, grant holders, package
maintainers, and the actors of recorded actions. Each user has a nullable
picture URL, `avatar_url`, so that a client can show a picture of the person
next to the name. Sentinel stores only the URL, never image data: the picture
stays with the system that owns it (`docs/architecture.md`, Design
Constraints).

The pictures are the profile pictures of SUSE's Slack workspace. The scheduled
fetcher `sync_slack_avatars` looks up every active person by the email address
of their Sentinel account and stores the URL of the picture that the person
uploaded to Slack.

## Scope

This specification owns:

- the `avatar_url` field: its meaning for clients, its writers, and its
  invariants;
- the Slack integration: the bot token, the lookup request, and the response
  contract; and
- the fetcher `sync_slack_avatars`.

Out of scope:

- how a client presents the picture, what it shows without one, and the
  Content Security Policy that lets a browser load it: they belong to the UI
  (`docs/architecture.md`, System Boundary); and
- uploading, storing, or serving image data, and pictures from any source
  other than pictures uploaded to Slack (Design Notes).

## Related Specifications

| Spec | Relationship |
|---|---|
| `docs/data-model.md` (User) | The `avatar_url` column |
| `docs/api-spec.md` (User References in Responses) | The user reference object carries `avatar_url` |
| `docs/features/identity/user-management.md` | The directory entry and the complete user profile carry `avatar_url`; a bot account has none (Bot Accounts) |
| `docs/features/identity/authentication.md` (Get Current User) | The caller's own profile carries `avatar_url` |
| `docs/features/identity/user-service.md` | Operational metadata exclusions; `deactivate_user()` and `update_user()` clear the value |
| `docs/features/identity/identity-audit-log.md` | The value is operational metadata and creates no identity audit event |
| `docs/features/platform/fetcher-infrastructure.md` | The `BaseFetcher` contract of `sync_slack_avatars` |
| `docs/features/platform/networking.md` | The shared HTTP client of the lookups |
| `docs/data-sources.md` (Slack; Fetcher Registry) | The source and the registry entry |
| `docs/configuration.md` (External APIs) | `SLACK_BOT_TOKEN` |
| `docs/deployment.md` (Network Access) | Outbound access to `slack.com` |

## Avatar URL

### Field

`User.avatar_url` holds the URL of the user's picture, or `NULL` when Sentinel
has none (`docs/data-model.md`, User). Every user representation of the API
carries it as `avatar_url`, a string or `null`, always present: the user
reference object (`docs/api-spec.md`, User References in Responses), the
directory entry of List Users and Get User, the complete user profile and its
`manager` object (`docs/features/identity/user-management.md`), and the
caller's own profile (`docs/features/identity/authentication.md`, Get Current
User). Like the other fields of these representations, it comes from the
current User record and is returned exactly as stored. The OpenAPI document
publishes it as a required, nullable string without a `format`.

The contract for clients:

- `avatar_url` is the URL of an image that a client may load as the user's
  picture. The API states nothing else about it: not its host, path, query,
  image format, or size, which change with the source of the pictures. A
  client neither parses it nor derives another URL from it.
- The value is a URI reference, which a client resolves against the URL of
  the response that carries it (RFC 3986, section 5). Every value that Sentinel
  stores today is an absolute `https` URL; a relative value, such as a path
  that Sentinel itself serves, can therefore be introduced without a breaking
  change.
- `null` means that Sentinel has no picture of the user. A URL can also stop
  working before the next run of the fetcher, for example after the person
  replaced the picture in Slack; a client treats a picture that fails to load
  like `null`.
- The value identifies no one and grants nothing: `id` remains the identifier
  of the user.

### Invariants and Writers

`avatar_url` is `NULL` for every inactive user and every bot account: a
picture shows a person, an inactive account must not keep one, and an
automation operates a bot account
(`docs/features/identity/user-management.md`, Bot Accounts). Otherwise the
value derives from the user's `email` at the time of a lookup.

Exactly these operations write the value
(`docs/features/identity/user-service.md`, Operational metadata exclusions):

| Writer | Write |
|---|---|
| `sync_slack_avatars` | Sets or clears the value of an active user who is not a bot account, under the conditional write of its Algorithm |
| `deactivate_user()` | Clears it in the deactivation transaction |
| `update_user()` | Clears it when an effective change sets `bot` to `true` or changes `email` |

`create_user()` creates every user without a picture, and reactivation
restores none: the next run of the fetcher looks the user up again. No other
operation writes the value, including external provisioning, and no request,
CLI option, or service parameter accepts it as input.

The value is operational metadata, like `synced_at`: no write creates an
identity audit event (`docs/features/identity/identity-audit-log.md`, Service
Contract). An audit event is append-only, so it would retain a URL that
deactivation must delete. An effective write updates `updated_at` like every
other write of the User row.

### Removing the Integration

Without a bot token, the next run of `sync_slack_avatars` clears every stored
URL and sends no request (Algorithm, disabled mode). To remove the
integration, for example when the Slack app is withdrawn:

1. remove `SLACK_BOT_TOKEN` from the environment of every process role and
   restart the processes; the fetcher runs in a Celery worker;
2. enable the fetcher if it is disabled, trigger it
   (`docs/features/platform/fetcher-operations.md`, Trigger Fetcher) or wait
   for its next scheduled run, and check that the run succeeded: its
   `items_updated` counts the cleared URLs, and the
   `slack_avatar_sync_disabled` log event reports them; and
3. disable the fetcher afterwards, if desired.

Disabling the fetcher (`FetcherConfig.enabled = false`) only pauses the
refresh: the stored URLs remain, they are no longer updated, and deactivation
still clears them. Disabling it therefore removes no URL.

## Slack Integration

### Slack App and Bot Token

Sentinel uses an internal Slack app installed in SUSE's workspace, with
exactly the bot scopes `users:read` and `users:read.email` and token rotation
disabled. The app has no endpoint, event subscription, or permission to post
messages. Its bot token is the setting `SLACK_BOT_TOKEN`
(`docs/configuration.md`, External APIs):

- It is a secret: a `SecretStr` field that is never logged and never written
  to an error field (`docs/conventions.md`, Secret Field Typing;
  `docs/features/platform/logging.md`, Secrets and PII Discipline).
- It is sent verbatim after `Bearer ` in the `Authorization` header, so a
  non-empty value must consist of printable ASCII characters without
  whitespace; any other value fails startup with an error that names the
  variable (`docs/conventions.md`, Secret Field Typing). It is never sent in a
  request body or a URL, although Slack also accepts it as a request
  parameter.
- Empty or unset, the integration is disabled: the application starts
  normally, and `sync_slack_avatars` clears the stored URLs (Algorithm).
- It is supplied like the other credentials, as an environment variable from
  the deployment's secret store (`docs/deployment.md`). The Celery worker,
  which runs the fetcher, is the only process role that uses it.

Slack requires `users:read` together with `users:read.email`, and
`users:read` also permits listing the workspace's member directory. Slack
therefore does not limit the token to lookups; Sentinel does. The token is
read only by the `sync_slack_avatars` module and used only for
`users.lookupByEmail`: once per selected user and run, for active Sentinel
users who are not bot accounts, and for no other Slack method or purpose.

### Lookup Request

The fetcher sends one request per selected user:

- `POST https://slack.com/api/users.lookupByEmail`, a fixed URL that is not
  configurable;
- the header `Authorization: Bearer <token>`; and
- an `application/x-www-form-urlencoded` body with exactly one parameter,
  `email`, whose value is the user's stored email address. Sentinel stores
  email addresses in lowercase, and Slack matches them case-insensitively.

The lookup uses `POST` so that the email address never appears in a URL: the
`httpx` logger writes the URL of every request at the default log level
(`docs/features/platform/logging.md`, Integration with Third-Party Loggers),
and the text of an `httpx.HTTPStatusError` carries it. The lookup changes
nothing at Slack, so the fetcher enables the transport-level retry of the
shared HTTP client for it, which by default excludes connection errors and
timeouts of a `POST` (`docs/features/platform/networking.md`, Method Safety).
The client follows no redirect (`docs/features/platform/networking.md`,
Redirect Policy).

### Response Contract

Slack answers a valid request with HTTP 200 whether the lookup succeeds or
fails; the `ok` member of the JSON body tells them apart. The fetcher decodes
the body through `decode_json()` (`docs/conventions.md`, External JSON
Decoding) and consumes exactly these members:

| Member | Read when | Use |
|---|---|---|
| `ok` | Always | `true` for a found member, `false` for an error |
| `error` | `ok` is `false` | The Slack error code |
| `user.profile.image_192` | `ok` is `true` | The candidate picture URL |

The fetcher reads no other member. In particular, it never reads, stores, or
logs the member's email address, names, title, telephone number, status, time
zone, identifiers, team, `deleted`, `is_custom_image`, `avatar_hash`, or other
`image_*` sizes. The decoded body is discarded once the lookup is classified.

The lookup of an HTTP 200 response has one of these outcomes:

| Body | Outcome |
|---|---|
| `ok` is `true`, `user` is an object, its `profile` is an object, and its `image_192` is a string | Picture, when `image_192` is an Accepted Picture URL; otherwise No picture |
| `ok` is `false` and `error` is `users_not_found` | No picture |
| `ok` is `false` and `error` is a token error: `not_authed`, `invalid_auth`, `account_inactive`, `token_revoked`, `token_expired`, `missing_scope`, or `not_allowed_token_type` | Token rejected |
| `ok` is `false` and `error` is `ratelimited` | Rate limited |
| `ok` is `false` and `error` is another value or absent | Lookup error |
| Any other body: not decodable, not a JSON object, `ok` absent or not a boolean, or `ok` is `true` without the members above | Invalid response |

Slack returns `users_not_found` for an address that no member has, for a
malformed address, and for a member who is deactivated in Slack. The outcome
No picture therefore also covers a person who has left the workspace. Error
Handling defines what each outcome does, and how responses other than HTTP 200
are handled.

### Accepted Picture URL

All `image_*` URLs of a picture that the person uploaded to Slack are on
`avatars.slack-edge.com`. For a person without an uploaded picture, Slack
returns a Gravatar URL on `secure.gravatar.com` instead, whose default image is
Slack's generic avatar. Sentinel uses only uploaded pictures (Design Notes).

`image_192` is an accepted picture URL when:

- it has at most 2048 characters, each a printable ASCII character (U+0021 to
  U+007E); and
- it is an absolute URL whose scheme is `https` and whose host is exactly
  `avatars.slack-edge.com`, with no user information, port, or fragment. Its
  path and query are not restricted further.

The fetcher stores an accepted URL exactly as Slack returned it. Every other
string, for example a Gravatar URL, a URL on `ca.slack-edge.com` or another
host, or an `http` URL, is the outcome No picture. A string containing an
inadmissible character fails the character rule, so it is never stored,
stripped, or altered (`docs/conventions.md`, External String Admissibility).
The fetcher never builds a picture URL itself, for example from the member and
team identifiers and the avatar hash: that format is undocumented.

`image_192` is a picture 192 pixels square, which covers an avatar up to 96
CSS pixels wide on a display with two device pixels per CSS pixel.

## Fetcher: `sync_slack_avatars`

| Property | Value |
|----------|-------|
| Fetcher name | `sync_slack_avatars` |
| Class name | `SyncSlackAvatars` |
| Description | `"Sync user profile picture URLs from Slack"` |
| Inherits | `BaseFetcher` |
| Module | `backend/app/services/identity/sync_slack_avatars.py` |
| Schedule | Daily at 06:30 UTC (`30 6 * * *`) |
| Source | Slack Web API, `users.lookupByEmail` of SUSE's workspace |
| Scope | Every active user who is not a bot account, once per run; no cursor |
| Auth | Slack bot token (`SLACK_BOT_TOKEN`) as a Bearer token |
| Custom settings | No |
| `default_request_delay` | `1.2` seconds between consecutive lookups of a run |
| `http_client_options` | `{"retry_non_idempotent": True}` (Lookup Request) |
| `queue` | Default queue |
| `catch_up()` | Not implemented (`participates_in_catch_up = False`): the fetcher writes no Ticket-scoped data |

### Algorithm

1. **Mode**: when `SLACK_BOT_TOKEN` is empty or unset, the run is in disabled
   mode: it sends no request, and the outcome of every selected user is No
   picture. Otherwise it is in lookup mode.
2. **Selection**: in one short read-only transaction, read the `id` and
   `email` of every user whose `active` is `true` and whose `bot` is `false`,
   in ascending `id` order, then end the transaction. Each selected user is one
   work unit, and the units are processed one at a time in this order.
3. **Lookup**: in lookup mode, send the Lookup Request with the selected email
   address while no transaction is open, and classify the response (Response
   Contract; Error Handling). The request delay of the run separates
   consecutive lookups (`docs/features/platform/fetcher-infrastructure.md`,
   Request Delay).
4. **Value**: the outcome Picture gives the accepted URL, and No picture gives
   `NULL`. A unit failure keeps the stored value and continues with the next
   user; a run failure ends the run (Error Handling).
5. **Write**: in a transaction of its own, set `avatar_url` to the value only
   if the user's `active` is still `true`, `bot` is still `false`, `email` is
   still the selected address, and the stored value differs from the value
   (a stored `NULL` differs from every URL); then commit. The statement locks
   only that User row, and no network I/O occurs while its transaction is
   open. When it changes no row, the value was already stored, or the user
   changed after the selection; every writer that handles such a change clears
   the value itself (Invariants and Writers).
6. **Disabled-mode report**: when `execute()` of a run in disabled mode
   returns normally, log `slack_avatar_sync_disabled` with `fetcher_name` and
   `cleared`, the number of users whose URL the run cleared: at `WARNING` when
   `cleared` is greater than zero, otherwise at `INFO`. A run that fails
   reports its committed clears in `items_updated` only.

A user who becomes active, stops being a bot account, or is created after the
selection is looked up by the next run. A run never creates or deletes a user
and writes no column other than `avatar_url`.

### Error Handling

The transport-level retries of the shared HTTP client apply to each lookup,
including connection errors and timeouts (Lookup Request;
`docs/features/platform/networking.md`, Transport-Level Retry). After them, a
lookup fails the run in these cases:

| Condition | `FetcherError` message |
|---|---|
| `httpx.NetworkError`, `httpx.ProxyError`, or `httpx.RemoteProtocolError` | `"Failed to connect to Slack"` |
| `httpx.TimeoutException` | `"Slack request timed out"` |
| HTTP 429, or the outcome Rate limited | `"Slack rate limit reached"` |
| Any other status than 200, including another 2xx status and a redirect | `"Slack returned HTTP {status_code}"` |
| The outcome Token rejected | `"Slack rejected the bot token ({error})"`, with the token error code of the response |

The `FetcherError` raised for a transport error or for a status that
`httpx` reports as an `httpx.HTTPStatusError` is chained from that exception.
The text of an `httpx.HTTPStatusError` holds the status with its reason phrase
and the fixed URL, plus the `Location` header of a redirect; no exception
text carries a body or an email address, because neither the URL nor a
header of the request contains one. The
`FetcherError` of another 2xx status, of Token rejected, and of Rate limited
has no cause, so its `error_detail` is `NULL`
(`docs/features/platform/fetcher-infrastructure.md`, Error Message
Sanitization). The units processed before the failure keep their committed
values and outcomes; the unit whose lookup failed and every later unit record
no outcome and keep their stored values. A token that Slack rejects therefore
fails every run and removes no URL, until the token is replaced or removed.

These conditions fail only their unit, which records `record_failed()`, keeps
its stored value, and logs the per-item `WARNING` of
`docs/features/platform/fetcher-infrastructure.md` (`SoftTimeLimitExceeded`
handling convention), with `item` set to the user's UUID:

| Condition | `cause` of the warning |
|---|---|
| The outcome Invalid response, including an `httpx.DecodingError` of the body | `SlackResponseError` |
| The outcome Lookup error | `SlackLookupError` |
| A database error in the write of step 5, which is rolled back | The class name of the database exception |

`SlackResponseError` and `SlackLookupError` are exceptions of the fetcher
module that it raises and catches for these outcomes; their messages carry no
value of the response.

A database error in the selection of step 2 fails the run with the generic
fallback (`docs/features/platform/fetcher-infrastructure.md`, BaseFetcher
fallback). `asyncio.CancelledError`, `SoftTimeLimitExceeded`, and
`MemoryError` are never caught per unit.

No log record and no error field of a run contains an email address, the
token, a picture URL, or a member of a Slack response, except the token error
code of the Token rejected message, which comes from the fixed list of
Response Contract.

### Work Unit and Metrics

| Mapping | Behavior |
|---|---|
| Selected | Each user of the selection of step 2, once |
| Succeeded | `record_succeeded()` for each unit with the outcome Picture or No picture whose write committed, whether it changed the value, found the value already stored, or found the user changed after the selection |
| Failed | `record_failed()` for each unit with the outcome Invalid response or Lookup error, and for each unit whose write failed |
| Created | Never: the fetcher creates no row |
| Updated | `record_updated()` after the commit for each unit whose write changed `avatar_url` |
| Excluded before selection | Inactive users and bot accounts, whose value is `NULL` (Invariants and Writers) |
| No outcome | The unit whose lookup fails the run, and every later unit |

A run in which every unit fails ends in `failure`, and a run with some failed
units in `partial` (`docs/features/platform/fetcher-infrastructure.md`,
Finalization). A run with no selected user is a successful run with no unit.
In disabled mode, a successful run reports every cleared URL as an update.

### Rate and Processing Time

`users.lookupByEmail` belongs to Slack's rate-limit tier 3, at least 50
requests per minute for each app and workspace, and Slack recommends designing
for one request per second. The default delay of 1.2 seconds keeps a run at 50
lookups per minute. The limit belongs to the Slack app, so deployments that
share one bot token share it, and each of them needs a different schedule or
a larger delay. With the `FetcherConfig` bootstrap default `run_timeout` of
3600 seconds, whose soft time limit is 3420 seconds, a run covers about 2,800
users; a larger number of users needs a larger `run_timeout`
(`docs/features/platform/fetcher-operations.md`, Update Fetcher Config).

The refresh is daily because profile pictures change rarely. A new user, a
reactivated user, and a user whose email address changed get their picture at
the next run, or earlier through a manual trigger of the fetcher.

## Concurrency

- At most one run is active at a time
  (`docs/features/platform/fetcher-infrastructure.md`, Concurrency Control).
- The write of step 5 is a conditional update of one User row. Its row lock
  serializes it with `deactivate_user()` and `update_user()`, which lock the
  User `FOR NO KEY UPDATE`, and with the `FOR SHARE` lock of the assignment
  paths (`docs/features/identity/user-service.md`, Assignment concurrent with
  eligibility loss). It holds no other lock, so it cannot form a lock cycle
  with them.
- When a deactivation, a change of `bot` to `true`, or a change of `email`
  commits after the selection and before the write, the write's conditions
  are evaluated against the committed row, after any wait for its lock, and
  match no row: a URL looked up before the change never reaches the changed
  user. When the write commits first, the later operation clears the value.
- Reactivation, creation, and a change of `bot` to `false` set no value; the
  next run looks the user up.

## Security and Privacy

- **Approved use.** SUSE IT and SUSE Data Privacy approved the Slack app on
  these conditions, which this specification implements:
  - the token is used only to look up Sentinel users by email address to show
    their profile picture, never to list the member directory or for any other
    purpose (Slack App and Bot Token);
  - nothing from a Slack response is kept or logged except the picture URL,
    which is kept and not logged (Response Contract; Error Handling). The
    only other value recorded is the token error code in the message of a
    failed run, from a fixed list of Slack error codes that identify no
    one;
  - the stored URL is deleted when a user is removed from Sentinel. Sentinel
    never deletes users (`docs/features/identity/user-service.md`, User
    Deletion), so deactivation deletes it (Invariants and Writers); and
  - repository fixtures contain only sanitized, fictional data, and raw
    responses obtained during manual tests are deleted once the testing is done
    (`docs/conventions.md`, Example Data in Documentation; External
    Integration Contract Verification).
- **The person controls the picture.** A person who removes their uploaded
  picture in Slack has no picture in Sentinel after the next run.
- **Exposure.** Every authenticated user reads the `avatar_url` of every user,
  like the other fields of the directory
  (`docs/features/identity/user-management.md`, Security Considerations); no
  unauthenticated caller receives it (`docs/features/identity/rbac.md`, Access
  Levels). Slack serves the picture itself without authentication, so anyone
  who obtains the URL can load the picture; Sentinel protects only the URL.
- **Image loading.** Sentinel never requests the picture: only a client does,
  directly from Slack's image host, which then sees the client's address. The
  host that a client may load images from, and what it sends to that host, are
  decisions of the UI (`docs/architecture.md`, System Boundary).
- **Token compromise.** The token lets its holder read the member directory of
  SUSE's workspace, email addresses included. It is a secret setting, sent only
  over TLS to a fixed host with no redirect followed, and never logged. If it
  leaks, revoke it in the Slack app, supply a new one, and restart the Celery
  worker.
- **Untrusted response.** A wrong or compromised Slack response can at most
  set an `avatars.slack-edge.com` URL on an active user who is not a bot
  account, or clear one. It cannot change another field or another user.

## Design Notes

- **Only pictures uploaded to Slack.** For a person who uploaded no picture,
  Slack returns a Gravatar URL whose default image is Slack's generic avatar.
  Using Gravatar pictures would require a server-side request to Gravatar for
  each such URL, with its default replaced by `d=404`, to tell a real Gravatar
  picture from the generic avatar, and would add a second outbound host, a
  second external contract to verify, more error cases, and a second image
  host for clients. A person can upload a picture to Slack instead. Another
  source can be added later by changing only the fetcher: the contract of
  `avatar_url` already admits any image URL.
- **A stored URL rather than a lookup per request.** Looking pictures up when
  the API serves a user would put Slack's availability and rate limit on the
  path of every response that contains a user. A stored URL costs one lookup
  per user and day.
- **Clearing without a token.** Removing the token is the way to remove the
  integration, and it must leave no reference to Slack behind. A configuration
  error that loses the token clears the URLs too, but the next run with the
  token restores them, and the `WARNING` of step 6 reports the clearing. A
  token that Slack rejects fails the run instead, so a revoked or mistyped
  token clears nothing.
- **No database constraint.** The three writers and the conditional write
  maintain the invariant that inactive users and bot accounts have no
  picture, and tests prove it. A `CHECK` constraint would require
  `deactivate_user()` to write `active` and `avatar_url` in one statement,
  while the Ticket unassignment of its later step flushes pending changes, and
  a missed clear would then fail the deactivation itself.

## Testing Requirements

Tests follow `docs/features/platform/testing-strategy.md` and cover at least:

1. **Contract**: contract tests on sanitized, fictional fixtures of live
   responses, written before the parser, under `backend/tests/fixtures/slack/`:
   a member with an uploaded picture, a member without one (Gravatar form),
   `users_not_found`, `invalid_auth`, and `not_authed`.
2. **Classification**: every row of the outcome table of Response Contract;
   every rule of Accepted Picture URL, including another host,
   `ca.slack-edge.com`, a Gravatar URL, `http`, user information, a port, a
   fragment, 2048 and 2049 characters, whitespace, U+0000, and a surrogate code
   point; the stored value equals the returned string; and the External JSON
   Decoding cases of `docs/features/platform/testing-strategy.md`, as Invalid
   response.
3. **Request**: exactly one `POST` per selected user to the fixed URL, with
   the Bearer header and a form body that holds only `email`; the token in no
   URL or body; no other Slack method; no request in disabled mode; the
   transport-level retry of a connection error and of a 5xx response of the
   lookup; and the request delay: no wait before the first lookup, the
   `request_delay` of the run's configuration snapshot rather than the class
   default between later lookups, no wait for a zero delay, and no delay
   between the transport retries of one lookup.
4. **Algorithm and metrics**: the selection excludes inactive users and bot
   accounts; a picture stored, changed, and unchanged; No picture clearing a
   stored URL; disabled mode clearing every stored URL with its metrics and
   its log event at `WARNING`, and at `INFO` when nothing is cleared; every unit
   failure keeping the stored value, with its warning fields; every run failure
   with its message and `error_detail`, keeping the earlier commits and giving
   the remaining units no outcome; and the `failure`, `partial`, and `success`
   run statuses.
5. **Concurrency**, with independent sessions: a deactivation, a change of
   `bot` to `true`, and a change of `email` committed between the selection and
   the write leave the value `NULL`; a write committed first is cleared by the
   later operation; and a write waiting for the `FOR SHARE` lock of an
   assignment path completes after it.
6. **Writers**: `deactivate_user()` clears the value in its transaction, and
   its rollback keeps it; `update_user()` clears it for an effective change of
   `bot` to `true` and of `email`, and not for another change or a no-op,
   without an audit event and without listing it in `changed_fields`;
   `create_user()` stores `NULL`; reactivation restores nothing; and the
   identity metadata writers structural test lists exactly the writers of
   Invariants and Writers.
7. **Privacy**: with fixtures that carry distinctive fictional values in every
   unconsumed member, the logs and the run's error fields of every path contain
   no email address, token, picture URL, or unconsumed member; and the Slack
   token boundary structural test.
8. **Representations**: every user representation carries `avatar_url` from
   the current User record, `null` included: the user reference object in each
   response that embeds one, the directory entry, the complete user profile and
   its `manager`, and `GET /api/v1/users/me`. The OpenAPI document declares it
   as a required, nullable string in each of these schemas.
9. **Configuration**: `SLACK_BOT_TOKEN` is a `SecretStr`; a value with
   whitespace or a character outside printable ASCII fails startup with an
   error that names the variable and not the value; and an empty or unset value
   selects disabled mode.

## Cross-references

- `docs/architecture.md` — Design Constraints; System Boundary; Integration
  Patterns
- `docs/api-spec.md` — User References in Responses; Versioning
- `docs/conventions.md` — Secret Field Typing; External Integration Contract
  Verification; External String Admissibility; External JSON Decoding;
  Transaction Hygiene Rules; Example Data in Documentation
- `docs/data-model.md` — User
- `docs/data-sources.md` — Slack; Fetcher Registry
- `docs/configuration.md` — External APIs
- `docs/deployment.md` — Network Access
- `docs/features/identity/user-management.md` — Bot Accounts; Access Level
  Requirements; Security Considerations
- `docs/features/identity/user-service.md` — Operational metadata
  exclusions; `update_user()`; `deactivate_user()`
- `docs/features/identity/identity-audit-log.md` — Service Contract
- `docs/features/identity/authentication.md` — Get Current User
- `docs/features/platform/fetcher-infrastructure.md` — BaseFetcher Base
  Class; Error Message Sanitization; Request Delay; Fetcher Documentation
  Requirements
- `docs/features/platform/fetcher-operations.md` — Trigger Fetcher; Update
  Fetcher Config
- `docs/features/platform/networking.md` — Shared HTTP Client
- `docs/features/platform/logging.md` — Secrets and PII Discipline
- `docs/features/identity/rbac.md` — Access Levels
- `docs/features/platform/testing-strategy.md` — User Avatars
