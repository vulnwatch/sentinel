# CNA

## Purpose

Record which CVE Numbering Authority (CNA) owns the record of each CVE, show it
with the CVE and its Ticket, and let an administrator place a CNA under the
auto-ignore policy, which ignores its new Tickets automatically.

Every ingested CVE creates a Ticket
([tickets.md](tickets.md#automatic-cve-ingestion)). Many CVEs concern software
that SUSE does not ship, such as WordPress plugins, and Vulnerability Analysts
ignore their Tickets by hand. Some CNAs publish records almost only for such
software. Knowing the CNA of a CVE helps an analyst judge its Ticket, and the
auto-ignore policy ignores the new Tickets of a CNA that an administrator
selects, with the ignore reason `cna_policy`
([tickets.md](tickets.md#ignore-reason)).

This specification owns:

- the CNA of a CVE and the `CNA` entity;
- the writers of the CNA and their precedence;
- the synchronization of the names, types, and scopes of the CNAs from the CVE
  Program's CNA list (`sync_mitre_cnas`);
- the auto-ignore policy, the operation that changes it, and the CNA audit
  trail; and
- the CNA read operations.

The Ticket transition that applies the policy is owned by `ticket-service.md`
(`ignore_new_for_cna_policy()`), and the point of `upsert_cve()` that invokes
it by `cve-service.md` (Complete `upsert_cve()` Composition).

## Design Rationale

### The Owner of the Record

The CNA of a CVE is the organization that owns its CVE Record: the
`providerMetadata.orgId` of the record's CNA container (`containers.cna`). It
is not `cveMetadata.assignerOrgId`, the organization that assigned the CVE ID.
The two differ after the CVE Program transfers a record to another CNA: the new
owner maintains the content, and the record falls within its scope. In November
2026, 28 transferred records of 2025 and 2026 had an assigner other than their
owner. In each of them NVD's `sourceIdentifier` named the owner, and NVD and
the owner agreed in all 2,767 records checked.

### Writers

The owner is part of the CVE Record, so the fetchers that ingest CVE Records
write it: `sync_mitre_cves` (cvelistV5) and `sync_kernel_cves` (the Linux
kernel CNA). No other source writes it, NVD included, although NVD reports the
owner. When NVD creates a Ticket first, `sync_mitre_cves` usually ingests the
same record in the same scheduled cycle, and the policy then applies to the
Ticket if it is still `New` (Order of Arrival of the Sources). Writing the CNA
from NVD would change the outcome only while `sync_mitre_cves` is not running.
It would require mapping NVD source identifiers to CVE Services organizations,
a CNA row without a short name for every such organization, and a rule for the
degraded mode of the NVD Source API
([cve-sync-nvd.md](cve-sync-nvd.md#nvd-source-api-failure-handling-degraded-mode)).

### A Curated Policy per CNA

Rules that ignore every Ticket of a vendor are not used to ignore the Tickets
of software that SUSE does not ship, because one vendor can publish software
that SUSE ships and software that it does not. The auto-ignore policy differs
from such a rule:

- An administrator sets it per CNA, from measured history. A CNA whose scope
  is, for example, WordPress plugins publishes almost no record for software
  that SUSE ships.
- It applies to a Ticket only when the Ticket is created, or when its CVE's CNA
  is recorded or changes, and only while the Ticket is `New`. It changes no
  Ticket when an administrator enables or disables it.
- It learns nothing from Tickets and derives no rule.

The administrator accepts that a CVE of a CNA under the policy that does
concern software that SUSE ships is ignored without review. Which CNAs are
under the policy is an operational choice made through the API, not part of
this specification. Analysts review the Tickets that the policy ignored with
the `ignore_reason=cna_policy` filter of
[List Tickets](tickets.md#list-tickets) and reopen any of them.

### No Ticket Counts

The CNA read operations return no count of Tickets. A count would have to
apply the visibility of confidential Tickets for each caller
(`docs/features/identity/rbac.md`, Scope and Confidential Ticket Visibility)
and would repeat, as an aggregate, what List Tickets with the `cna` filter
already returns in `meta.total`.

## Scope

Out of scope:

- ignoring existing Tickets when an administrator enables the policy;
- reopening a Ticket that the policy ignored automatically;
- rules learned from Tickets or set per vendor or product;
- the contacts, disclosure policies, advisories, resources, roots, and roles
  that the CNA list also publishes; and
- creating a CNA from the CNA list, which does not carry the identifier of a
  CNA. A CNA row exists from the first ingestion of a record that the CNA owns.

## Related Specifications

| Spec | Relationship |
|---|---|
| `docs/features/tickets/cve-service.md` | `CVEIngestPayload.cna`, the merge of `CVE.cna_id`, and the step of `upsert_cve()` that applies the policy |
| `docs/features/tickets/cve-sync-mitre.md` and `cve-sync-kernel.md` | The two writers of the CNA of a CVE |
| `docs/features/platform/cve-record-parser.md` | `parse_cna_owner()`, which reads the owner of a CVE Record |
| `docs/features/tickets/tickets.md` | Ignore Reason `cna_policy`, the transition matrix, `CNASummary` in the CVE projections, and the `cna` filter of List Tickets |
| `docs/features/tickets/ticket-service.md` | `ignore_new_for_cna_policy()` |
| `docs/features/tickets/cve-tracking.md` | The `cna` filter and field of List CVEs |
| `docs/features/tickets/ticket-audit-log.md` | The `status_change` event of the policy |
| `docs/features/platform/fetcher-infrastructure.md` | The `BaseFetcher` contract of `sync_mitre_cnas` |
| `docs/features/platform/networking.md` | Shared HTTP client, redirect and content-coding policies |
| `docs/features/platform/audit-trail-infrastructure.md` | `BaseAuditLog`, `AuditEventMixin`, and the Audit Trail Index |
| `docs/data-model.md` | `CNA`, `CNAAuditEvent`, and `CVE.cna_id` |
| `docs/data-sources.md` | The CVE Program CNA list and the Fetcher Registry |

## CNA of a CVE

`CVE.cna_id` references the `CNA` row whose `org_id` is the CVE Services UUID
of the owner of the CVE's record. A CVE has at most one CNA. A CVE has none
until a writer ingests a record of it that names a valid owner: for example a
placeholder (`cve-service.md`, Placeholder Records), or a CVE known so far only
from NVD or GHSA.

### The CNA Entity

One `CNA` row exists for every CVE Services organization that owns, or has
owned, the record of at least one CVE that a writer ingested. Only ingestion
creates a row, and no operation deletes one, also when a transfer leaves a CNA
without a CVE. `docs/data-model.md` (CNA) owns the schema.

| Column | Meaning | Written by |
|---|---|---|
| `org_id` | CVE Services UUID of the organization; the public identity of the CNA | Ingestion, when the row is created; never changes |
| `short_name` | Short name of the CNA in CVE Services (`providerMetadata.shortName` of the records it owns); `NULL` until a writer supplies one | Ingestion (Short Name) |
| `short_name_observed_at` | `providerMetadata.dateUpdated` of the record from which the short name or its date was taken; `NULL` when that writer supplies no date | Ingestion (Short Name) |
| `organization_name` | Organization name of the CNA in the CNA list | `sync_mitre_cnas` |
| `types` | CNA types of the CNA list, such as `Vendor` or `Open Source`; empty until the list supplies them | `sync_mitre_cnas` |
| `scope` | Scope of the CNA in the CNA list, as plain text | `sync_mitre_cnas` |
| `auto_ignore` | Whether the CNA is under the auto-ignore policy; `false` when the row is created | Set CNA Auto-Ignore only |

### Display Name

Every CNA representation carries `name`: `organization_name` when set,
otherwise `short_name`, otherwise `null`. No response substitutes `org_id` or
another identifier for it. `name` is `null` exactly while the CNA has no short
name: only a row with a short name can match the CNA list
(`sync_mitre_cnas`), and a short name is never cleared. `organizationName` was
unique across the entries of the CNA list of November 2026.

## Ingestion Writers

### Payload

`CVEIngestPayload.cna` (`cve-service.md`, CVEIngestPayload Schema) carries one
`CNAEntry`: `org_id`, an optional `short_name`, and an optional
`short_name_observed_at`. Only the two writers supply it, and `upsert_cve()`
rejects it from any other source:

| Writer | `org_id` | `short_name` | `short_name_observed_at` |
|---|---|---|---|
| `sync_mitre_cves` | `containers.cna.providerMetadata.orgId` | Trimmed `providerMetadata.shortName`, when valid | `providerMetadata.dateUpdated` |
| `sync_kernel_cves` | The constant organization of the Linux kernel CNA | The constant `Linux` | None |

`parse_cna_owner()` (`docs/features/platform/cve-record-parser.md`) defines the
MITRE values and their validation. The kernel fetcher uses constants because
the records of `vulns.git` carry, as `providerMetadata.orgId`, an identifier
that is not the CNA's CVE Services organization, and no short name; the
constants are those with which cvelistV5 publishes the same records
(`cve-sync-kernel.md`, CVE JSON Field Mapping, which owns their values).

### Merge of `CVE.cna_id`

- An omitted `cna` preserves `CVE.cna_id`. No source clears it.
- A supplied `cna` sets `CVE.cna_id` to the row of its `org_id`, which
  `resolve_ingested_cna()` creates when it does not exist. A different value
  replaces the stored one, as after a transfer of the record. Both writers are
  authoritative and the last writer wins; for a kernel CVE their values are
  equal by construction.
- An effective change of `CVE.cna_id` is an effective change of the CVE, so
  `upsert_cve()` returns `updated`. A write to the `CNA` row alone, such as a
  new short name, is not.
- A rejected record names its owner too and is applied in the same way.

### Short Name

The short name of a CNA can change: the organization
`c09c270a-b464-47c1-9133-acb35b22c19a` publishes as `@huntrdev` in its records
of 2022 and as `@huntr_ai` in those of 2025. Records reach Sentinel in no
particular date order, and an old record keeps its old short name when it is
ingested again, so the last writer cannot decide. `resolve_ingested_cna()`
applies these rules:

| Stored row | Entry | Result |
|---|---|---|
| Any | No `short_name` | Unchanged |
| No `short_name` | `short_name` | `short_name` and `short_name_observed_at` taken from the entry |
| Same `short_name`, `short_name_observed_at` NULL | Date | `short_name_observed_at` taken from the entry |
| Same `short_name` | Otherwise | Unchanged |
| Different `short_name`, `short_name_observed_at` NULL | Date | Both taken from the entry |
| Different `short_name`, `short_name_observed_at` not later than the entry's date | Date | Both taken from the entry |
| Different `short_name` | No date, or a date earlier than the stored one | Unchanged |

The stored short name is therefore that of the latest dated record that
supplied a different one, and a short name is never cleared. The kernel
constant, which has no date, sets the short name only of a row that has none.

## Auto-Ignore Policy

### Flag

`CNA.auto_ignore` is `false` when a row is created. Only
[Set CNA Auto-Ignore](#set-cna-auto-ignore) changes it: neither ingestion nor
`sync_mitre_cnas` writes it. A change applies to the ingestions that read it
after its commit and changes no existing Ticket.

### When the Policy Applies

`upsert_cve()` applies the policy as the last lifecycle decision of its
composition (`cve-service.md`, Complete `upsert_cve()` Composition, step 7)
when all of the following hold for the locked-current state of the
invocation:

1. the post-merge `cve_state` is `PUBLISHED`;
2. the post-merge CNA of the CVE has `auto_ignore = true`, as the invocation
   reads it: from the resolution of a supplied `cna`, or, when the payload
   omits `cna`, from the CNA already recorded for the CVE;
3. the invocation created the Ticket, or changed `CVE.cna_id`; and
4. no earlier lifecycle decision of the same step applies.

It then calls `ticket_service.ignore_new_for_cna_policy()`
(`ticket-service.md`), which ignores the Ticket with the reason `cna_policy`
when the Ticket is `New` and not confidential, and leaves every other Ticket
unchanged. The `status_change` event of the transition is system-attributed,
with `comment = "CNA auto-ignore policy"` and
`detail = {"ignore_reason": "cna_policy"}` (`ticket-audit-log.md`).

Consequences:

- A Ticket that ingestion creates for a published CVE of a CNA under the policy
  is created `New` and ignored in the same transaction, whichever source
  creates it, as long as the CNA is supplied or already recorded. This
  includes re-ticketing an orphan CVE. Its history is
  `ticket_created`, `cve_associated`, every other event of the ingestion in
  the order of `ticket-audit-log.md` (Cross-Event Ordering), then the
  `status_change` of the policy, which is last.
- An existing Ticket is ignored only when an ingestion records the CNA of its
  CVE for the first time or changes it, and only while the Ticket is `New`.
- An unchanged CNA applies nothing: re-ingesting a record does not ignore a
  Ticket that the policy did not ignore before.
- Manual creation and CVE association never apply the policy themselves
  ([tickets.md](tickets.md#cve-resolution-behavior)). A Ticket created in
  `New` by a user who cannot be its assignee, such as a bot account, is
  ignored when a later ingestion records a CNA under the policy for its CVE;
  this includes the freshness fetch of its creation. The rejection of a CVE
  affects such a Ticket in the same way
  ([cve-tracking.md](cve-tracking.md#rejection-handling)). This is accepted:
  Sentinel does not record how a Ticket was created, and doing so only for this
  case is disproportionate.

### Precedence and Exclusions

- **Rejected CVE**: the rejection takes precedence. The policy never applies
  while the post-merge `cve_state` is `REJECTED`, so a Ticket created for a
  rejected record is ignored with `cve_rejected`
  ([cve-tracking.md](cve-tracking.md#rejection-handling)). When a revert of the
  rejection reopens that Ticket, the policy does not apply, because the Ticket
  is no longer `New`.
- **Confidential Ticket**: the policy never ignores a confidential Ticket.
- **Ticket in another status**: the policy never ignores a Ticket that is not
  `New`, for example one that a user assigned or one that auto-assignment moved
  to `Analysis`.
- **Ticket without a CVE**: it has no CNA, so the policy never applies.
- **Exploitation evidence does not exempt**: a KEV entry, an SSVC assessment,
  or an EPSS score of the CVE does not exempt its Ticket from the policy,
  whether the evidence arrives before or after the CNA is recorded. The
  outcome therefore does not depend on the order in which the sources arrive,
  just as no later evidence reopens a Ticket that the policy ignored (No
  Automatic Reopen).

### No Automatic Reopen

A Ticket ignored with `cna_policy` leaves `Ignored` only through a user's
[Reopen](tickets.md#reopen-ticket). Nothing else reopens it: not a KEV entry or
another change of exploitation evidence, not a CNA that leaves the policy, not
a transfer of the CVE to another CNA, and not a rejection of the CVE and its
revert. A rejection of the CVE of an `Ignored` Ticket keeps its reason, and the
revert of a rejection reopens only a Ticket ignored with `cve_rejected`
([tickets.md](tickets.md#ignore-reason)).

### Order of Arrival of the Sources

| Sequence | State of the Ticket |
|---|---|
| `sync_mitre_cves` or `sync_kernel_cves` ingests the published record first | Created and ignored with `cna_policy` in the transaction of that ingestion |
| NVD or GHSA ingests the record first, `sync_mitre_cves` later | Created `New` without a CNA. Post-ingest package resolution may add packages and maintainers, because the Ticket is active (`docs/features/packages/package-service.md`, Post-ingest CVE package resolution). When `sync_mitre_cves` ingests the record, usually in the same scheduled cycle, the Ticket is ignored if it is still `New`; its packages remain |
| `sync_mitre_cves` is not running | The Tickets that other sources create stay `New` without a CNA. When it runs again, each record that it ingests ignores its Ticket if the Ticket is still `New` |
| A user assigns or works on the Ticket before the CNA is recorded | The Ticket is no longer `New` and stays unchanged |
| The record is `REJECTED` when first ingested | Ignored with `cve_rejected`; the policy does not apply, then or after a revert (Precedence and Exclusions) |
| The CVE is rejected after the policy ignored its Ticket | Keeps `cna_policy`; a revert of the rejection does not reopen it |
| The record is transferred to a CNA under the policy | Ignored if the Ticket is `New` |
| The record is transferred to another CNA, or the CNA leaves the policy | Unchanged |
| The Ticket is confidential | Unchanged |
| KEV, EPSS, SSVC, or CVSS data arrive later | Unchanged; no reopen |
| `sync_mitre_cnas` runs | Unchanged: the fetcher writes no CVE or Ticket |

### Concurrency

- An ingestion reads `auto_ignore` from the CNA row when it resolves a
  supplied CNA, or with a plain read of the recorded CNA when the payload
  omits it, after acquiring the CVE root lock and before locking the Ticket
  (`cve-service.md`, Complete `upsert_cve()` Composition, step 4). An
  administrative change committed after that read applies to later ingestions
  only.
- Set CNA Auto-Ignore locks only the CNA row, with `FOR NO KEY UPDATE`. The
  foreign-key check of a CVE that references the row takes `FOR KEY SHARE`,
  which that mode does not block.
- `docs/conventions.md` (Cross-Domain Root Lock Order) owns the position of
  a CNA row in the root order, after the CVE and before the Tickets. This
  specification owns the operations that acquire CNA rows, which are the only
  ones:
  - a CVE ingestion acquires at most one, by creating it or by an effective
    update of its short name, after its CVE root and before its Ticket root;
  - `sync_mitre_cnas` acquires CNA rows in ascending `CNA.id` order and no
    other root; and
  - Set CNA Auto-Ignore acquires only its one CNA row, with
    `FOR NO KEY UPDATE`.

  The foreign-key `FOR KEY SHARE` that a CVE write takes on its CNA row is not
  a root and conflicts with none of these locks.

## Service: `cna_service`

### Module Location

`backend/app/services/cna_service.py`

### Ownership

This module owns the `CNA` rows, the CNA audit trail, and the CNA reads. It
does not own `CVE.cna_id`, which `cve_service` writes during `upsert_cve()`, or
the transition that the policy causes, which `ticket_service` owns.

### Module-Level Defaults

Every function receives the caller-owned `AsyncSession`, flushes when it
writes, and never commits or rolls back (`docs/conventions.md`, Caller-Owned
Service Transactions). Database, flush, and programming exceptions propagate
unchanged. Only `set_cna_auto_ignore()` creates an audit event. The read
functions are Category B operations: they take no lock, write nothing, and
perform no network I/O. No function performs HTTP, Redis, or Celery I/O.

### Service Exceptions

`CNAServiceError` inherits from `ServiceError`, and every exception of this
module inherits from it. API handlers catch each exception below and map it as
the table states (`docs/api-spec.md`, Error Code Categories).

| Exception | HTTP | Code | Raised when |
|---|---|---|---|
| `CNANotFoundError` | 404 | `CNA_NOT_FOUND` | The CNA locator is not a UUID in the hyphenated form, or no CNA has that `org_id` |

### `resolve_ingested_cna()`

```python
async def resolve_ingested_cna(db: AsyncSession, entry: CNAEntry) -> CNA:
```

Trusted internal boundary that only `cve_service.upsert_cve()` calls, while it
holds the CVE root lock and before it locks the Ticket.

**Q3 (behavior)**:

1. Create the row of `entry.org_id` when none exists, with the entry's
   `short_name` and `short_name_observed_at`, `types = []`, and
   `auto_ignore = false`. Creation is conflict-aware on the `org_id` unique key:
   a concurrent creation of the same row makes this call wait for it and use
   the committed winner, never exposing a unique violation or aborting the
   caller's transaction. The SQL statement and savepoint layout are
   implementation choices.
2. For an existing row, apply the Short Name rules with one conditional update
   that writes only the short name and its date, and only when they change.
   `updated_at` advances only with an effective change.
3. Return the row, including `auto_ignore` as this transaction reads it.

**Q4 (audit events)**: none. CNA ingestion writes are source-owned data
without an audit trail; the CNA Audit Log records only administrative
changes.

**Q5 (re-invocation)**: idempotent. A repeated call with the same entry finds
the row and changes nothing.

**Q6 (exceptions)**: none of its own.

**Locking**: an effective update holds the CNA row lock until the caller
commits. The function acquires no other lock.

### `update_cna_metadata()`

```python
async def update_cna_metadata(
    db: AsyncSession,
    *,
    cna_id: UUID,
    organization_name: str | MISSING = MISSING,
    types: Sequence[str] | MISSING = MISSING,
    scope: str | None | MISSING = MISSING,
) -> bool:
```

System operation that `sync_mitre_cnas` calls for each matched row, and the
example dataset loader in its place
(`docs/features/platform/example-dataset.md`). `MISSING`
(`docs/conventions.md`, Omitted Values) keeps the stored value; `scope = None`
clears the scope.

**Q2 (guards)**: before any database access, a supplied value outside the
bounds of Field Mapping (`sync_mitre_cnas`) — an `organization_name` that is
empty or longer than 256 characters, more than 16 `types` or a type that is
empty or longer than 128 characters, a `scope` longer than 4096 characters, or
any value containing an inadmissible character — raises `ValueError`. The
caller validates first, so this path is a programming error.

**Q3 (behavior)**: store the supplied `types` without duplicates in ascending
Unicode code-point order. Update the supplied columns of the row with one
statement that writes only values that differ from the stored ones, and return
whether a value changed. `updated_at` advances only with an effective change.
The function never writes `org_id`, `short_name`, `short_name_observed_at`, or
`auto_ignore`, and writes no CVE or Ticket. A `cna_id` that identifies no row,
which cannot occur because the caller has read the row in the same transaction
and rows are never deleted, raises `ValueError`.

**Q4 (audit events)**: none.

**Q5 (re-invocation)**: idempotent; a repeated call returns `False`.

**Q6 (exceptions)**: `ValueError`.

### `set_cna_auto_ignore()`

```python
async def set_cna_auto_ignore(
    db: AsyncSession,
    *,
    org_id: str,
    auto_ignore: bool,
    acting_user_id: UUID,
) -> CNA:
```

`org_id` is the raw path value; `acting_user_id` is the authenticated
administrator.

**Q2 (guards)**: `org_id` not in the hyphenated 8-4-4-4-12 hexadecimal form,
compared case-insensitively, raises `CNANotFoundError` before any database
access. An `auto_ignore` that is not a `bool` raises `ValueError`.

**Q3 (behavior)**:

1. Select the row by `org_id` with `FOR NO KEY UPDATE` as the first database
   operation. A missing row raises `CNANotFoundError`.
2. If the locked-current `auto_ignore` equals the requested value, return the
   row: no write and no event.
3. Otherwise set `auto_ignore` and create one `CNAAuditEvent` through
   `CNAAuditLog.log_event()`: `auto_ignore_enabled` for `true`,
   `auto_ignore_disabled` for `false`, with `user_id = acting_user_id` and
   `detail = {"cna_name": <display name of the locked row, or null>}`.
4. Flush and return the row.

The function changes no Ticket, CVE, or other CNA. Concurrent requests
serialize on the row lock, and each classifies its request against the value
that it observes under the lock, so two equal requests create one event.

**Q4 (audit events)**: one event per effective change; none for a no-op.

**Q5 (re-invocation)**: idempotent at the value level.

**Q6 (exceptions)**: `CNANotFoundError`, `ValueError`.

### `list_cnas()`

```python
async def list_cnas(
    db: AsyncSession,
    *,
    search: str | None,
    auto_ignore: bool | None,
    page: int,
    per_page: int,
    sort_by: str,
    sort_order: str,
) -> CNAListResult:
```

**Q3 (behavior)**: trim `search` once; an empty result applies no search.
Otherwise match a CNA whose `short_name` or `organization_name` contains the
value as a case-insensitive substring, with `%`, `_`, and `\` matched
literally. `auto_ignore` selects the CNAs with that value. Both filters combine
with AND. Order by `sort_by`: `name` (the display name), `short_name`, or
`created_at`, in Unicode code-point order for the two names, with `NULL` last
in both directions and `CNA.id` as the same-direction tie-breaker. Compute the
total before page slicing; a page beyond the last is empty with the correct
total. Items and total derive from one PostgreSQL observation.
`CNAListResult` is a service-layer value carrying the page items and the
total.

**Q6 (exceptions)**: none of its own.

### `get_cna()`

```python
async def get_cna(db: AsyncSession, org_id: str) -> CNA:
```

**Q3 (behavior)**: parse `org_id` as in `set_cna_auto_ignore()` and select the
row by it.

**Q6 (exceptions)**: `CNANotFoundError` for a malformed or unknown `org_id`.

### `list_cna_audit_events()`

```python
async def list_cna_audit_events(
    db: AsyncSession,
    *,
    event_type: Sequence[str] | None,
    cna: UUID | None,
    actor: str | None,
    from_date: datetime | None,
    to_date: datetime | None,
    page: int,
    per_page: int,
) -> CNAAuditEventListResult:
```

**Q3 (behavior)**: select events, combining the filters with AND. Valid
`event_type` values combine with OR, and a supplied filter whose values are all
invalid yields an empty page (`docs/api-spec.md`, Enum Filter Validation).
`cna` selects the events of the CNA with that `org_id`; an unknown value yields
an empty page. `actor` uses `BaseAuditLog.filter_by_actor()` and the dates
`BaseAuditLog.apply_date_filters()`. Order by `id` descending, compute the
total before page slicing, and project each event with the current
`CNASummary` of its CNA and the current user reference of its actor, from one
PostgreSQL observation.

**Q6 (exceptions)**: none of its own.

## API Endpoints

### Response Schemas

**CNASummary** — compact reference to a CNA, used in `CVESummary` and
`CVEDetail` ([tickets.md](tickets.md#shared-sub-schemas)), in `CVEListItem`
([cve-tracking.md](cve-tracking.md#list-cves)), and in the CNA audit events
([List CNA Audit Events](#list-cna-audit-events)):

| Field | Type | Description |
|-------|------|-------------|
| `org_id` | string | CVE Services UUID of the CNA, lowercase hyphenated form; locates the CNA in [Get CNA](#get-cna) |
| `name` | string \| null | Display name (Display Name) |

**CNAResponse**:

| Field | Type | Description |
|-------|------|-------------|
| `org_id` | string | CVE Services UUID of the CNA, lowercase hyphenated form |
| `name` | string \| null | Display name (Display Name) |
| `short_name` | string \| null | Short name of the CNA in its CVE Records |
| `organization_name` | string \| null | Organization name from the CNA list |
| `types` | string[] | CNA types from the CNA list, ascending Unicode code-point order; empty when unknown. Values are those of the list, such as `Vendor`, `Open Source`, or `Researcher`, and are not a closed set |
| `scope` | string \| null | Scope from the CNA list as plain text, which may contain line feeds; never markup |
| `auto_ignore` | boolean | Whether the new Tickets of the CNA are ignored automatically (Auto-Ignore Policy) |
| `created_at` | datetime | When Sentinel recorded the CNA (UTC) |
| `updated_at` | datetime | Last change of the row (UTC) |

### List CNAs

```
GET /api/v1/cnas
```

**`Access: Authenticated`**

Lists the CNAs through `cna_service.list_cnas()`.

**Query parameters**:

| Parameter | Type | Description |
|-----------|------|-------------|
| `search` | string, optional | Case-insensitive substring of the short name or the organization name; see `list_cnas()` |
| `auto_ignore` | boolean, optional | `true` lists the CNAs under the auto-ignore policy, `false` the others |
| `page` | integer, optional | Page number (default: 1) |
| `per_page` | integer, optional | Items per page (default: 20, max: 100) |
| `sort_by` | string, optional | `name` (default), `short_name`, or `created_at`. The names sort in Unicode code-point order; `NULL` sorts last |
| `sort_order` | string, optional | `asc` (default) or `desc` |

Response: paginated `CNAResponse` array in the standard envelope (200 OK).

### Get CNA

```
GET /api/v1/cnas/{org_id}
```

**`Access: Authenticated`**

Returns one CNA through `cna_service.get_cna()`. `{org_id}` is the CVE
Services UUID of the CNA in the hyphenated 8-4-4-4-12 form, with hexadecimal
digits in either case (`docs/api-spec.md`, CNA Identifier Resolution).

```json
{
  "data": {
    "org_id": "00000000-0000-4000-8000-0000000000a1",
    "name": "Example Corporation",
    "short_name": "example",
    "organization_name": "Example Corporation",
    "types": ["Vendor"],
    "scope": "Example Corporation products only.",
    "auto_ignore": false,
    "created_at": "2026-11-09T10:00:00Z",
    "updated_at": "2026-11-09T10:05:00Z"
  }
}
```

**Error responses**:

| Status | Code | Condition |
|--------|------|-----------|
| 404 | `CNA_NOT_FOUND` | `{org_id}` is malformed or identifies no CNA |

### Set CNA Auto-Ignore

```
PATCH /api/v1/admin/cnas/{org_id}
```

**`Capability: manage_settings`**

Places a CNA under the auto-ignore policy or removes it, through
`cna_service.set_cna_auto_ignore()`. The change applies to the Tickets that
ingestion creates or whose CNA it records after the change, and changes no
existing Ticket (Auto-Ignore Policy).

Request body:

```json
{
  "auto_ignore": true
}
```

- `auto_ignore` (boolean, required): an omitted field, `null`, or a value of
  another type produces the global `422 VALIDATION_ERROR`

An unchanged request is an idempotent success with no audit event. Response:
`CNAResponse` in the standard `{"data": ...}` envelope (200 OK).

**Error responses**:

| Status | Code | Condition |
|--------|------|-----------|
| 404 | `CNA_NOT_FOUND` | `{org_id}` is malformed or identifies no CNA |

### List CNA Audit Events

```
GET /api/v1/admin/cnas/audit-log
```

**`Capability: manage_settings`**

Returns the CNA audit trail through `cna_service.list_cna_audit_events()`,
newest first. Sorting is fixed to `id` descending, which is `created_at`
descending with a deterministic tie-break; client-controlled sorting is not
supported, as for the other audit trails.

**Query parameters**:

| Parameter | Type | Default | Description |
|---|---|---|---|
| `page` | int | 1 | Page number |
| `per_page` | int | 20 | Items per page (max 100) |
| `event_type` | string (repeatable) | — | `auto_ignore_enabled` or `auto_ignore_disabled`. Multiple values use OR semantics; see `docs/api-spec.md` (Enum Filter Validation) |
| `cna` | string | — | `org_id` of a CNA, in the hyphenated form (`docs/api-spec.md`, CNA Identifier Resolution). Another value produces the global `422 VALIDATION_ERROR`; an unknown CNA returns an empty page |
| `actor` | string | — | User UUID or username (User Identifier Resolution); an unknown actor returns an empty page |
| `from_date` | datetime | — | Include events from this date onwards (inclusive) |
| `to_date` | datetime | — | Include events up to this date (inclusive) |

**Response** (200 OK):

```json
{
  "data": [
    {
      "id": "uuid",
      "event_type": "auto_ignore_enabled",
      "cna": {
        "org_id": "00000000-0000-4000-8000-0000000000a2",
        "name": "Fictional Plugin Foundation"
      },
      "detail": {"cna_name": "Fictional Plugin Foundation"},
      "actor": {
        "id": "uuid",
        "username": "jdoe",
        "full_name": "John Doe",
        "active": true,
        "bot": false
      },
      "created_at": "2026-11-09T10:10:00Z"
    }
  ],
  "meta": {
    "total": 1,
    "page": 1,
    "per_page": 20
  }
}
```

`cna` is the current reference of the CNA; `detail.cna_name` is the display
name when the event was recorded. `actor` is always the complete current user
reference, because every event has a human actor.

## CNA Audit Log

Every effective change of `CNA.auto_ignore` creates one `CNAAuditEvent` in the
same transaction (`docs/features/platform/audit-trail-infrastructure.md`,
Atomicity). Ingestion and `sync_mitre_cnas` writes create none.

### CNAAuditEvent

`docs/data-model.md` (CNAAuditEvent) owns the table `cna_audit_event`. Besides
the `AuditEventMixin` columns, it has `cna_id` (the CNA, not null, indexed),
`event_type`, `old_value`, `new_value`, and `detail`.

### CNAAuditEventType

Category B classification enum (Python `StrEnum` only).

| `event_type` | Trigger | `user_id` | `old_value` | `new_value` | `detail` |
|---|---|---|---|---|---|
| `auto_ignore_enabled` | `auto_ignore` changed from `false` to `true` | Acting administrator | `NULL` | `NULL` | `{"cna_name": "<display name or null>"}` |
| `auto_ignore_disabled` | `auto_ignore` changed from `true` to `false` | Acting administrator | `NULL` | `NULL` | `{"cna_name": "<display name or null>"}` |

`cna_name` is an event-time snapshot of the display name, so the event stays
readable when the name changes
(`docs/features/platform/audit-trail-infrastructure.md`, Human-Readable
Subjects); it is `null` when the CNA had no display name.

### CNAAuditLog Service

```python
class CNAAuditLog(BaseAuditLog):
    name = "cna"
    description = "Auto-ignore policy changes of CNAs"
    model_class = CNAAuditEvent

    @classmethod
    async def log_event(
        cls,
        session: AsyncSession,
        *,
        event_type: CNAAuditEventType,
        cna_id: UUID,
        user_id: UUID | None,
        detail: dict,
    ) -> None:
        ...
```

The method accepts only a `CNAAuditEventType` member and raises `ValueError`
for any other value, for a `None` `user_id`, and for a `detail` that is not
exactly one `cna_name` key with a string or `null` value. It stores
`old_value` and `new_value` as `NULL`, creates exactly one event, and flushes
it before returning. It never commits, and every exception propagates to the
caller, whose transaction rolls back the change and the event together.

## Background Tasks

### Fetcher: `sync_mitre_cnas`

| Property | Value |
|----------|-------|
| Fetcher name | `sync_mitre_cnas` |
| Class name | `SyncMitreCnas` |
| Description | `"Sync CNA names, types, and scopes from the CVE Program CNA list"` |
| Inherits | `BaseFetcher` |
| Schedule | Daily at 07:00 UTC (`0 7 * * *`) |
| Source | CVE Program CNA list: `CNAsList.json` of the `CVEProject/cve-website` GitHub repository, read from `raw.githubusercontent.com` |
| Scope | Every entry of the list on every run; updates existing CNA rows only; no cursor |
| Auth | None (anonymous request) |
| Custom settings | No |
| `queue` | Default queue |
| `catch_up()` | Not implemented (`participates_in_catch_up = False`): the fetcher writes no Ticket-scoped data |

#### Source

The fetcher requests exactly
`https://raw.githubusercontent.com/CVEProject/cve-website/main/src/assets/data/CNAsList.json`,
the CNA list that the CVE Program website publishes from the `main` branch of
its repository. The file is a data file of a public repository, not a
versioned API: its format can change without notice, and the repository
declares no license. `docs/data-sources.md` (CVE Program CNA List) records the
source and its observed size; the file is served with
`Content-Type: text/plain`.

#### Algorithm

1. **Request**: one `GET` of the URL through `self.http_client`, with no
   request delay. No redirect is followed
   (`docs/features/platform/networking.md`, Redirect Policy).
2. **Response**: the status must be 200, and the body, decoded from UTF-8
   through `decode_json()` (`docs/conventions.md`, External JSON Decoding),
   must be a JSON array. `Content-Type` is not checked. Any other response
   fails the run (Error Handling).
3. **Entries**: each array element is one selected work unit. An element is a
   valid entry when it is an object whose `shortName` is a string that is not
   empty after trimming and contains no inadmissible character; any other
   element is an invalid entry.
4. **Rows**: read `id`, `org_id`, and `short_name` of every CNA row whose
   `short_name` is set.
5. **Matching**: pair rows with valid entries under CNA Entry Matching.
6. **Fields**: for each pair, validate each field of the entry independently
   under Field Mapping.
7. **Write**: for each matched row, in ascending `CNA.id` order, call
   `cna_service.update_cna_metadata()` with the valid fields; a field that is
   not valid is not passed and keeps its stored value.
8. **Commit** once.
9. **Metrics and logs**: record the outcomes of Work Unit and Metrics and emit
   the warnings of Error Handling.

The fetcher creates no CNA row and never writes `org_id`, `short_name`,
`auto_ignore`, a CVE, or a Ticket. A row that no entry matches, and a row
without a short name, keep their stored values; an entry that matches no row
changes nothing. No network I/O occurs while the transaction of steps 4 to 8
is open.

#### CNA Entry Matching

The CNA list identifies a CNA only by its short name, without the CVE Services
UUID. For each row with short name `s`:

1. its candidates are the valid entries whose trimmed `shortName` equals `s`
   exactly; when there is none, the valid entries whose trimmed `shortName`
   equals `s` after Unicode case folding of both values;
2. the row matches an entry when the entry is its only candidate and the entry
   is the only candidate of no other row; and
3. otherwise the row is ambiguous and is not updated.

In the list of November 2026, two entries, `Snow` and `SNOW`, differed only in
case: a row whose short name equals one of them exactly matches that one,
while a row `snow` would be ambiguous. Short names can also differ between the
records and the list, such as `SamsungMobile` in the records and
`Samsung_Mobile` in the list: such a CNA matches no entry, and its display name
is its short name. No looser comparison is applied, because it could attach
the name and scope of one organization to another.

#### Field Mapping

| Column | Entry field | Valid when | Stored value |
|---|---|---|---|
| `organization_name` | `.organizationName` | A string that is not empty after trimming, at most 256 characters, with no inadmissible character | The trimmed string |
| `types` | `.CNA.type` | `.CNA` is an object and `.type` an array of at most 16 strings, each not empty after trimming, at most 128 characters, with no inadmissible character | The trimmed items without duplicates, in ascending Unicode code-point order; an empty array stores `[]` |
| `scope` | `.scope` | A string whose Scope Plain Text conversion succeeds | The converted text; an empty result stores `NULL` |

Any other value of a field, including an absent or `null` field and an absent
or `null` `.CNA`, keeps the stored value and logs `cna_metadata_field_invalid`.
Every entry of the live list carries all three fields, so a missing one means
that the format of the list has changed, and the warning makes it visible
while the run itself succeeds.

The fetcher reads no other member of an entry: not `contact`,
`disclosurePolicy`, `securityAdvisories`, `resources`, `country`, `cnaID`, or
`.CNA.isRoot`, `.CNA.root`, `.CNA.TLR`, and `.CNA.roles`. The contacts of the
list therefore never reach Sentinel.

#### Scope Plain Text

The scope of the list contains HTML markup; in November 2026 only `<a>` links,
`<strong>`, `<br/>`, and the character reference `&amp;`. Sentinel stores it as
plain text and never as markup. The complete value, including any text after
its last tag, is tokenized as HTML by the standard-library parser
(`html.parser`), with character references converted in text and attribute
values, and its tokens are converted in order:

| Token | Result |
|---|---|
| Text | Appended as is |
| A `br` tag: `<br>`, the self-closing `<br/>`, or `</br>` | One line feed per tag |
| Start or end tag `strong` | Nothing |
| Start tag `a` | Opens a link and keeps its `href` value, if any; other attributes are ignored. An `a` inside an open link makes the scope invalid |
| End tag `a` | Closes the link and appends its text, followed by ` (<href>)` when the `href` is an absolute URL with the scheme `http` or `https` (case-insensitive), contains no whitespace, and differs from the trimmed link text. Without an open link, the scope is invalid |
| Any other tag, a comment, a declaration, or a processing instruction | The scope is invalid |

While a link is open, its text and the line feeds of its `br` tags go to the
link text, not to the result, until its end tag; the link text is compared
with the `href` after trimming. A link still open at the end makes the scope
invalid, and so does a start or end tag that is incomplete at the end of the
value, such as `Example products <a`, which the parser would otherwise drop
without a trace. The result is trimmed of leading and trailing whitespace; an
empty result is `NULL`, and a result longer than 4096 characters or
containing an inadmissible character is invalid. For
example, `Projects listed on its <a href='https://github.com/example'
target='_blank'>Example GitHub website</a> only.` becomes `Projects listed on
its Example GitHub website (https://github.com/example) only.`, and
`<strong>Root Scope:</strong> A.<br/><strong>CNA Scope:</strong> B &amp; C.`
becomes the two lines `Root Scope: A.` and `CNA Scope: B & C.`

#### Error Handling

Transport-level retries of the shared HTTP client apply
(`docs/features/platform/networking.md`, Transport-Level Retry). After them,
these conditions fail the run before any write, and the fetcher raises
`FetcherError` with a sanitized message chained from a content-free cause: the
`httpx.HTTPStatusError` (status line and URL), the transport or decoding error,
or a fixed-message parse error.

| Condition | `FetcherError` message |
|---|---|
| Connection failure, or another transport error | `"Failed to connect to the CNA list"` |
| Request timeout | `"CNA list request timed out"` |
| HTTP status other than 200, including a redirect and an HTTP 429 of GitHub's limits for unauthenticated requests | `"CNA list returned HTTP {status_code}"` |
| Undecodable body, body that is not UTF-8 JSON, or JSON that is not an array | `"CNA list returned unparseable response"` |

A database failure in steps 4 to 8 rolls back every write of the run and takes
the generic fallback of `docs/features/platform/fetcher-infrastructure.md`
(BaseFetcher fallback). After any failure, the stored metadata remain as the
last successful run wrote them, and the next scheduled run retries.

Bounded warnings, which never carry an upstream value:

| Event | Fields | When |
|---|---|---|
| `cna_list_entries_invalid` | `fetcher_name`, `count` | Once per run in which at least one entry is invalid |
| `cna_metadata_match_ambiguous` | `fetcher_name`, `org_id` | Once per ambiguous row |
| `cna_metadata_field_invalid` | `fetcher_name`, `org_id`, `field` (`organization_name`, `types`, or `scope`) | Once per matched row and invalid field |

`org_id` is the identifier of the row, read from PostgreSQL, not a value of the
list.

#### External String Admissibility

Consumed strings follow `docs/conventions.md` (External String Admissibility):

| Field | Outcome for a value containing an inadmissible character |
|---|---|
| `shortName` | The entry is invalid and counts as failed |
| `organizationName`, a `.CNA.type` item | The field is invalid; the stored value is kept |
| `scope` | The converted text contains it, so the field is invalid; the stored value is kept |

#### Work Unit and Metrics

| Mapping | Behavior |
|---|---|
| Selected | Each element of the array of a valid response, once |
| Succeeded | `record_succeeded()` for every valid entry, whether it matches a row, matches none, or is a candidate of an ambiguous row |
| Failed | `record_failed()` for every invalid entry |
| Created | Never: the fetcher creates no row |
| Updated | `record_updated()` for each valid entry whose matched row changed in the committed transaction |
| Excluded before selection | None: an invalid response fails the run before any entry is selected |

The fetcher records every outcome after the commit of step 8. A run in which
every entry is invalid therefore ends in `failure`, and one with some invalid
entries in `partial` (`docs/features/platform/fetcher-infrastructure.md`,
Finalization). An empty array is a successful run with no unit.

#### Expected Processing Time

One download of under 1 MB and an in-memory match against the CNA rows, which
number at most a few thousand; a run takes seconds. `run_timeout` keeps the
`FetcherConfig` bootstrap default of 3600 seconds.

## Security

- Only Set CNA Auto-Ignore, with `manage_settings`, changes the policy. No
  external data changes it: `sync_mitre_cnas` writes only the descriptive
  columns, and ingestion only creates rows and writes short names.
- The scope is stored and returned as plain text, never as markup. A client
  presents `scope`, `name`, `organization_name`, and `types` as text.
- The CNA list is requested anonymously from a fixed URL over TLS, and no
  redirect is followed. A compromised or wrong list can change only the
  descriptive columns, which Sentinel shows but never uses for a decision.
  Because an administrator chooses a CNA by its displayed name, every CNA
  response also returns the short name, which comes from the CVE Records.
- No personal data is read: the contacts of the list are not consumed.
- The CNA reads require authentication like every read of application data
  (`docs/features/identity/rbac.md`, Access Levels). They expose public CVE
  Program data and no Ticket or CVE identifier, so they apply no Ticket
  visibility. `CNASummary` reaches a caller only inside a CVE representation
  that applies CVE accessibility or Ticket visibility.

## Testing Requirements

Tests follow `docs/features/platform/testing-strategy.md`, and cover at
least:

1. **Owner parsing**: `parse_cna_owner()` for a valid container; a missing,
   non-object, or malformed `providerMetadata` or `orgId`; uppercase hexadecimal
   normalized to lowercase; a short name that is absent, empty after trimming,
   longer than 32 characters, or contains an inadmissible character, which
   leaves only the `org_id`; and an unparseable `dateUpdated`.
2. **Writers**: MITRE and kernel mappings, including the kernel constants over
   the `vulns.git` `orgId`; the warning of a MITRE record without a valid
   owner; and `ValueError` before writes when another source supplies `cna`.
3. **Merge**: an omitted `cna` preserves `CVE.cna_id`; a transfer replaces it
   and returns `updated`; a repeated payload is `unchanged`; a short-name-only
   change of the row is not `updated`; every row of the Short Name table; and
   concurrent first ingestions of two CVEs of a new CNA create one row and
   commit both CVEs.
4. **Policy**:
   - every row of Order of Arrival of the Sources and of Precedence and
     Exclusions;
   - the exact event of the transition and its position as the last event of
     the ingestion;
   - no reopen by KEV, a transfer, a policy change, or a rejection revert,
     and a CVE with a KEV entry recorded before its CNA still ignored;
   - a policy change committed concurrently with an ingestion, in both commit
     orders;
   - no call and no event when an ingestion leaves an unchanged CNA under the
     policy and the Ticket is `New`, and for a manual creation or association
     of a CVE whose CNA is under the policy;
   - an orphan CVE whose recorded CNA is under the policy, re-ticketed by a
     source that omits `cna`, whose new Ticket is ignored;
   - a user's assignment or ignore concurrent with the policy ignore of the
     same Ticket, in both commit orders: the boundary is a no-op after the
     user, and the user receives `TICKET_NOT_MUTABLE` after the policy; and
   - one ingestion that reverts a rejection and changes the CNA to one under
     the policy, which reopens a `cve_rejected` Ticket and does not ignore it.
5. **Administrative operation**: the capability check, malformed and unknown
   `org_id`, the idempotent no-op, one event per effective change with its
   `detail`, rollback of the change when the event fails, two concurrent equal
   requests creating one event, and no change to any Ticket.
6. **Reads**: List CNAs filters, search literals, sort orders with `NULL`
   last, pagination; Get CNA; the display-name fallback; `CNASummary` in the
   Ticket and CVE representations; the `cna` filters of List Tickets and List
   CVEs, including Ticket visibility; and the audit-log filters.
7. **Fetcher**: contract tests on a sanitized fixture of the live list, written
   before the parser; every matching rule, including `Snow`/`SNOW`, an entry
   shared by two rows, and a short name absent from the list; every Field
   Mapping and Scope Plain Text rule, including nested and unclosed links,
   relative and `javascript:` links, entities, an incomplete tag at the end,
   and the length bound; every Error Handling condition, including a redirect
   that is not followed;
   metrics and run status; the warnings and their fields; no write to
   `auto_ignore`, CVEs, or Tickets; and no network I/O while the transaction
   is open.

## Cross-references

- `docs/features/tickets/cve-service.md` — `upsert_cve()`, `CVEIngestPayload`
- `docs/features/tickets/cve-sync-mitre.md` — MITRE owner mapping
- `docs/features/tickets/cve-sync-kernel.md` — kernel CNA constants, which it
  owns
- `docs/features/platform/cve-record-parser.md` — `parse_cna_owner()`
- `docs/features/tickets/tickets.md` — Ignore Reason, transitions, List
  Tickets
- `docs/features/tickets/ticket-service.md` — `ignore_new_for_cna_policy()`
- `docs/features/tickets/cve-tracking.md` — List CVEs
- `docs/features/tickets/ticket-audit-log.md` — the policy's `status_change`
- `docs/features/platform/fetcher-infrastructure.md` — `BaseFetcher`
- `docs/features/platform/networking.md` — shared HTTP client
- `docs/features/platform/audit-trail-infrastructure.md` — audit trail rules
- `docs/features/identity/rbac.md` — `manage_settings`, Endpoint Permission
  Map
- `docs/data-model.md` — `CNA`, `CNAAuditEvent`, `CVE.cna_id`
- `docs/data-sources.md` — CVE Program CNA List, Fetcher Registry
- `docs/conventions.md` — Cross-Domain Root Lock Order, External String
  Admissibility, External JSON Decoding
- `docs/api-spec.md` — global API conventions, CNA Identifier Resolution
