# Maintained Package Names

## Purpose

Let a client find the exact name of a source package that SMELT maintains
from a part of it, typed without regard to letter case. Add Package to Ticket
(`docs/features/packages/package-model.md`, API Endpoints) resolves the name
it receives in SMELT exactly, and SMELT's package-scoped path is
case-sensitive, so a caller must know the canonical name, such as `openssl-3`
or `MozillaFirefox`, before it adds a package.

Sentinel keeps a local snapshot of the names of the source packages that SMELT
maintains, synchronized daily by a fetcher, and serves a search over it. The
snapshot is an aid to finding a name: it decides nothing. Add Package to
Ticket still resolves every name in SMELT and remains the only authority on
whether a name has tracks and Products.

## Scope

This specification defines:

- the `MaintainedPackage` entity, which holds the names of the latest
  published snapshot;
- the `sync_smelt_packages` fetcher, which reads the complete SMELT
  maintained sweep and publishes the snapshot;
- the publication boundary, which both the fetcher and the example dataset
  loader call;
- the search service operation and its endpoint, `GET
  /api/v1/maintained-packages`.

Out of scope:

- binary package names: the snapshot holds source package names only, the
  kind of name that Add Package to Ticket takes;
- whether a name resolves to a Product of Sentinel's catalog or to a
  supported codestream, which Add Package to Ticket decides when it resolves
  the name;
- the request grammar of Add Package to Ticket, which that operation owns:
  the snapshot holds every name that SMELT maintains, without filtering it by
  that grammar.

## Related Specifications

| Spec | Relationship |
|---|---|
| `docs/features/packages/package-model.md` | SMELT; Add Package to Ticket, whose input this search helps a caller find; SMELT Query for Package Resolution |
| `docs/features/packages/product-catalog.md` | SMELT Integration (Origin, Authentication, and Pagination), which governs every SMELT request; Catalog Publication Boundaries, the pattern that the publication boundary follows |
| `docs/data-sources.md` | SMELT source entry and the maintained sweep contract; Fetcher Registry |
| `docs/features/platform/fetcher-infrastructure.md` | `BaseFetcher` lifecycle, error sanitization, request delay, metrics, and documentation template |
| `docs/features/platform/networking.md` | Shared HTTP client, transport retry, and TLS trust store |
| `docs/features/platform/example-dataset.md` | The fictional names that a dataset backend serves |
| `docs/deployment.md` | Package Name Initialization after the first deployment |

## Domain Concepts

### Maintained Package Name

A source package name for which the SMELT maintained sweep returns at least
one row: SMELT ships the package from at least one codestream to at least one
Product. It is the same maintained set that the package-scoped operation of
Add Package to Ticket reads, with the same `include_reactive_ltss=true`
parameter (`docs/data-sources.md`, SMELT).

A name is kept exactly as SMELT returns it, with its letter case
(`docs/data-sources.md`, SMELT, for the observed names). Two names
that differ only in letter case are two maintained packages; SMELT maintains
at least one pair of this kind. No name is removed as a maintenance incident or for its
shape: the maintained sweep returns no incident package, and maintained names
can end in a dot and digits, such as `go1.25`.

### Snapshot

The set of maintained package names that one complete, validated sweep
observed. The `MaintainedPackage` rows are exactly the names of the latest
published snapshot. A snapshot is never empty. A failed synchronization
publishes nothing and leaves the previous snapshot in place. Before the first
publication the table is empty and the search returns no name.

The snapshot carries no expiry or freshness state of its own. Its age is the
time of the last successful `sync_smelt_packages` run, which the fetcher run
history shows to every authenticated user
(`docs/features/platform/fetcher-operations.md`).

## Data Model

See `docs/data-model.md` (MaintainedPackage) for the column listing.

| Column | Meaning |
|---|---|
| `id` | Internal UUIDv7 primary key, never serialized |
| `name` | The source package name exactly as SMELT returns it; unique, compared exactly, including letter case |
| `created_at` | When the name last entered the snapshot; a name that stays in consecutive snapshots keeps its row, and a name that leaves and returns gets a new one |

Rows are inserted and deleted only by the publication boundary and are never
updated in place, so the table has no `updated_at`. No other table references
it.

## Publication Boundary

### `publish_maintained_packages()`

```python
async def publish_maintained_packages(
    db: AsyncSession,
    names: frozenset[str],
) -> MaintainedPackagePublication:
```

Publishes one complete snapshot. It follows the pattern of the Product
catalog publication (`docs/features/packages/product-catalog.md`, Catalog
Publication Boundaries): it receives input that its caller has already
validated, performs only database work, and owns its transaction. Its callers
are `sync_smelt_packages`, after its external I/O and validation, and the
example dataset loader (`docs/features/platform/example-dataset.md`).

**Q1 (inputs)**: `db` is a session with no open transaction and no pending
work. `names` is the non-empty set of the snapshot's names, each a non-empty
string of at most 255 characters without an inadmissible character
(`docs/conventions.md`, External String Admissibility).

**Q2 (guards)**: an empty `names` is a caller-contract violation and raises
`ValueError` before any database operation.

**Q3 (behavior)**: in one transaction, which it begins and commits once also
when nothing changes:

1. Read the names of the published snapshot.
2. Delete every row whose `name` is not in `names`.
3. Insert one row for every name of `names` that has none.
4. Commit.

Publications are serialized: when two overlap, each publishes its own
snapshot whole, and the table holds the snapshot of the publication that
commits last, never a union or a mix of the two. A reader sees either the
previous snapshot or the new one, never part of a publication. The mechanism
is an implementation choice.

The result reports the number of names created (inserted), removed (deleted),
and unchanged (present before and after).

This boundary is one of the named exceptions of `docs/conventions.md`
(Caller-Owned Service Transactions), like the catalog publication boundaries.
A database error propagates before the commit succeeds; the caller rolls the
session back and no partial publication persists.

**Q4 (audit events)**: none. The snapshot is synchronized reference data, like
the Product catalog.

**Q5 (re-invocation)**: idempotent. A repeated publication of the same
`names` changes no row and reports every name as unchanged.

**Q6 (exceptions)**: `ValueError` from Q2; database exceptions propagate
unchanged. It performs no network I/O, registers no post-commit effect, and
dispatches no task.

## Service

### `search_maintained_packages()`

```python
async def search_maintained_packages(
    db: AsyncSession,
    *,
    search: str | None = None,
    page: int = 1,
    per_page: int = 20,
) -> MaintainedPackagePage:
```

Category B read-only operation. `page` and `per_page` have passed the API
validation of `docs/api-spec.md` (Pagination); `search` has passed the Query
Parameter Length Limit.

**Q3 (behavior)**:

1. Trim the outer whitespace of `search` once. An absent or empty result means
   no filter.
2. With a term, select the names that contain it without regard to letter
   case. `%`, `_`, and backslash are literal characters, not SQL pattern
   syntax.
3. Order the selected names in two groups: first the names that start with
   the term, compared without regard to letter case as in step 2, then the
   other names. Within each group, and for every name without a term, order
   by `name` in ascending Unicode code-point order, independent of database
   collation. `name` is unique, so the order is total and needs no
   tie-breaker (`docs/api-spec.md`, Deterministic Pagination Ordering).
4. Return the requested page of names and the total number of selected names.
   The page and the total describe one published snapshot, also when a
   publication commits during the operation.

Before the first publication, and for a page beyond the last, the operation
returns no name with the correct total. It creates no audit event, acquires no
lock, does not commit or roll back, and propagates database exceptions
unchanged; it raises no module-specific exception.

## API Endpoints

### Search Maintained Packages

```
GET /api/v1/maintained-packages
```

**`Access: Authenticated`**

Returns the names of the source packages that SMELT maintains, from the
latest published snapshot, optionally matching a term. The route delegates to
`search_maintained_packages()` and performs no ORM query. It does not contact
SMELT: its outcome does not depend on SMELT's availability, and it has no
`SMELT_UNAVAILABLE` response.

**Query parameters**:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `search` | string | -- | Case-insensitive substring match on the name. Outer whitespace is trimmed once; an empty result means no filter. `%`, `_`, and backslash are literal characters, not SQL pattern syntax. Max 500 chars |
| `page` | integer | 1 | Page number |
| `per_page` | integer | 20 | Items per page (max 100) |

Pagination follows `docs/api-spec.md` (Pagination). The order is fixed:
names that start with the term first, then the others, each group in Unicode
code-point order (`search_maintained_packages()`, step 3). Client-controlled
sorting (`sort_by`/`sort_order`) is not supported, because the order that
places the names starting with the term first is the one that finding a name
needs, and without a term the code-point order is the only meaningful one.

**Response** (200 OK), for `?search=openssl`:

```json
{
  "data": [
    {"name": "openssl"},
    {"name": "openssl-3"},
    {"name": "compat-openssl098"}
  ],
  "meta": {
    "total": 3,
    "page": 1,
    "per_page": 20
  }
}
```

**`MaintainedPackageItem`**:

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | The source package name exactly as SMELT maintains it, with its letter case |

Before the first snapshot is published, the endpoint returns `200 OK` with an
empty `data` array and `meta.total = 0`, as List Products does before its
catalog is ready (`docs/features/packages/product-catalog.md`, List Products).

The endpoint has no endpoint-specific error responses.

## Background Tasks

### Fetcher: `sync_smelt_packages`

The fetcher supports this feature, so its definition is a section of this
specification (`docs/features/platform/fetcher-infrastructure.md`, Fetcher
Documentation Requirements).

| Property | Value |
|----------|-------|
| Fetcher name | `sync_smelt_packages` |
| Class name | `SyncSmeltPackages` |
| Description | Synchronize the names of the source packages that SMELT maintains |
| Schedule | Daily at 00:00 UTC (`0 0 * * *`) |
| Source | SMELT (`smelt.suse.de/api`), maintained sweep `experimental/v2/maintained/` |
| Scope | The complete maintained sweep on every run; no cursor or incremental mode |
| Auth | None |
| Custom settings | No |

The fetcher declares no `default_request_delay` (its initial `request_delay`
is `0`), participates in no catch-up, and declares no queue. A complete sweep
is about 1,200 pages and took about 32 minutes when read sequentially
(`docs/data-sources.md`, SMELT), within the soft time limit of 3420 seconds
that the default `run_timeout` of 3600 seconds gives. An operator who sees runs reach the soft time
limit raises `run_timeout` through the fetcher configuration
(`docs/features/platform/fetcher-operations.md`).

#### Algorithm

1. Request the pages of the sweep sequentially, starting at page 1:
   `{SMELT_API_URL}/experimental/v2/maintained/?include_reactive_ltss=true&page_size=200&page={n}`.
   Every request is built from the configured HTTPS API prefix and follows the
   origin and authentication contract of
   `docs/features/packages/product-catalog.md` (SMELT Integration, Origin,
   Authentication, and Pagination): anonymous, without credentials, and
   without following redirects. No other query parameter is sent. The run's
   request delay separates consecutive page requests
   (`docs/features/platform/fetcher-infrastructure.md`, Request Delay).
2. Validate every page before using it:
   - the HTTP status is 200 and the body is JSON under `docs/conventions.md`
     (External JSON Decoding);
   - the body is an object whose `status` is `success` and whose `data` is an
     object with an array `results`, an integer `page` equal to the requested
     page, an integer `page_size` equal to 200, and booleans `has_next` and
     `has_previous`, where `has_previous` is `false` exactly on page 1. A JSON
     boolean is not an integer and a number is not a boolean;
   - a page with `has_next = true` has exactly 200 results; and
   - every result is an object whose `package` is a non-empty string of at
     most 255 characters without an inadmissible character
     (`docs/conventions.md`, External String Admissibility).

   Other result fields are not consumed and are not validated. Any invalid
   page rejects the complete sweep.
3. Add the `package` value of every result, unchanged, to the set of names.
   A page is not retained after its names are collected.
4. Stop after the first page with `has_next = false`, which may have fewer
   than 200 results or none. Request no further page.
5. Require at least one name. An empty sweep is invalid and publishes nothing.
6. Call `publish_maintained_packages()` with the names, in a session with no
   open transaction. No network I/O occurs while its transaction is open.

The sweep is paged by offset (`docs/data-sources.md`, SMELT), and Sentinel does
not assume that its pages form one consistent upstream snapshot: a change in
SMELT during the run can repeat or omit rows. A repeated row adds no name. A name whose
every row is omitted is missing from this snapshot and returns with a later
run. This is accepted: the snapshot only helps a caller find a name, and Add
Package to Ticket resolves every name in SMELT. A snapshot whose name count
decreased is not rejected for that reason, as for the Product catalog.

#### Error Handling

Shared transport retries apply to retryable HTTP failures
(`docs/features/platform/networking.md`, Transport-Level Retry). After they
are exhausted, any retrieval failure, non-200 response, invalid page, empty
sweep, or publication failure aborts the run without publishing; the previous
snapshot remains, and recovery is the next scheduled or manually triggered
run. There is no in-run restart and no cursor.

The fetcher raises `FetcherError` with these sanitized messages, chained to
the caught exception where one exists
(`docs/features/platform/fetcher-infrastructure.md`, Error Message
Sanitization):

| Failure mode | `FetcherError` message |
|--------------|------------------------|
| Connection failure | `"Failed to connect to SMELT"` |
| Request timeout | `"SMELT request timed out"` |
| Non-200 HTTP response | `"SMELT returned HTTP {status_code}"` |
| Undecodable body, invalid envelope, or invalid pagination | `"SMELT returned invalid maintained package response"` |
| Invalid result (not an object, or without a valid `package`) or empty sweep | `"SMELT maintained package validation failed"` |
| Publication database failure | `"Failed to publish SMELT maintained package names"` |

Logs identify the failed page or validation category without a response
payload or a raw upstream value.

#### Metrics

The work unit is one name in the union of the previously published snapshot
and the validated incoming snapshot. Units are selected after complete-sweep
validation; the publication transaction establishes their effects and
outcomes atomically.

| Mapping | Exact behavior |
|---|---|
| Selected | Each distinct name in that union, once. On the first publication, each name of the incoming snapshot |
| Succeeded | `record_succeeded()` once for every selected name after the publication commits, including an unchanged name |
| Failed | No per-name failure. Retrieval, validation, and publication failures escape as whole-run failures before any terminal outcome |
| Created | `record_created()` once for each name that the publication inserted |
| Updated | `record_updated()` once for each name that the publication removed because it left the snapshot. The effect counters have no removal counter; leaving the snapshot is reported as an update, as Product Sync reports a Product that left its current snapshot (`docs/features/packages/product-catalog.md`, Fetcher: `sync_smelt_products`, Metrics) |
| Excluded before selection | Repeated rows of a name and unconsumed result fields are not work units. An invalid result rejects the complete sweep rather than becoming a failed unit |

An unchanged name records neither effect. No unit records both effects.

## Security

- Searching the names requires authentication, with no capability. The names
  are SMELT reference data that SMELT serves without authentication; the
  snapshot holds no Ticket-derived data, and a result reveals nothing about
  which packages a Ticket holds, so no Ticket visibility predicate applies.
- The fetcher uses the anonymous SMELT contract of
  `docs/features/packages/product-catalog.md` (Security). It reads
  `SMELT_API_URL` and no other setting or credential.
- The search term is matched literally (`search_maintained_packages()`,
  step 2), so a term cannot alter the matching or the query.
- SMELT values are validated before they reach PostgreSQL (`docs/conventions.md`,
  External String Admissibility), and no response payload or raw upstream
  value is logged or stored in a public error message.

## Test Requirements

Implementation tests MUST cover:

- **Search**: substring matching without regard to letter case; two names
  that differ only in letter case, both returned; `%`, `_`, and backslash as
  literal characters; outer whitespace trimmed and a whitespace-only term as
  no filter; the order of names that start with the term before the others and
  code-point order within each group and without a term, independent of the
  database collation; pagination, `meta.total`, and a page beyond the last;
  the 500-character limit; the empty result before the first publication; a
  successful search while SMELT is unreachable, with no request to SMELT; one
  consistent snapshot when a publication commits during a request; and `401
  AUTH_NOT_AUTHENTICATED` without a valid credential and success with each
  valid credential kind.
- **Publication**: first publication; names created, removed, and unchanged
  in one publication; idempotent re-publication; an empty set rejected before
  any write; rollback of a failed publication leaving the previous snapshot;
  two overlapping publications leaving the snapshot of the later commit.
- **Fetcher**: contract tests on a sanitized fixture of real sweep pages
  (`docs/conventions.md`, External Integration Contract Verification); the
  request URL, parameters, anonymity, and no redirect following; the run's
  `request_delay` between consecutive pages, zero and non-zero, with no wait
  before page 1; the stop at the first page with `has_next = false`,
  including an empty final page after page 1; every invalid-page case of
  Algorithm step 2, including a non-final page with fewer than 200 results, a
  mismatched `page` or `page_size`, a wrong `has_previous`, a boolean given as
  a number, and a `package` that is missing, empty, too long, not a string, or
  contains U+0000 or a surrogate code point; an empty sweep; repeated names
  across pages; each sanitized error message; the previous snapshot retained
  after every failure; and the metric mapping for created, removed, and
  unchanged names.
- **Example dataset**: the names of
  `docs/features/platform/example-dataset.md` (Maintained Package Names) after
  a load.

## Cross-references

- `docs/api-spec.md` — pagination, query parameter limits, response
  derivation
- `docs/data-model.md` — MaintainedPackage
- `docs/data-sources.md` — SMELT; Fetcher Registry
- `docs/features/identity/rbac.md` — Endpoint Permission Map
- `docs/features/packages/package-model.md` — Add Package to Ticket
- `docs/features/packages/product-catalog.md` — SMELT Integration; Catalog
  Publication Boundaries
- `docs/features/platform/fetcher-infrastructure.md` — fetcher contract
- `docs/features/platform/fetcher-operations.md` — fetcher runs and
  configuration
- `docs/features/platform/example-dataset.md` — Maintained Package Names
- `docs/deployment.md` — Package Name Initialization
