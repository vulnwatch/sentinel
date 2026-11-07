# Ticket Priority

## Purpose

Define Ticket **priority**: the urgency of remediating the security issue a
Ticket tracks. Sentinel derives priority automatically from the Ticket's
resolved severity and the exploitation evidence already ingested for its CVE
(CISA KEV, CISA SSVC, FIRST EPSS). An authorized user may override the derived
value.

This specification is the authoritative source for priority semantics, the
exploitation classification, the decision table, persistence of the automatic
and manual values and of the override provenance, the automatic refresh
points, the basis of the automatic priority, the manual override, the
`priority_changed` audit contract, and the priority-related API surface.

## Priority and Severity

Severity and priority answer different questions:

| Concept | Question | Source | Owner |
|---|---|---|---|
| Severity | How large is the intrinsic impact? | CVSS resolution (`CVE.severity`) or `Ticket.severity_manual` | [tickets.md](tickets.md#severity-resolution), [cvss-scoring.md](cvss-scoring.md) |
| Priority | How urgently should the issue be remediated? | Resolved severity combined with exploitation evidence, or a manual override | This specification |

Priority is **informational only**. It is never an input to a Ticket status
gate, `reconcile_ticket_status()`, Product eligibility, package affectedness or
delivery, assignment, auto-assignment eligibility, Ticket accessibility, or any
fetcher scope. No existing behavior changes because a priority value changes.

Priority belongs to the Ticket only. A CVE has no priority; CVE resources expose
the exploitation evidence (see [cve-tracking.md](cve-tracking.md#get-cve)) but
never a derived priority.

## Priority Levels

| Level | Meaning |
|---|---|
| `P1` | Remediate immediately |
| `P2` | Remediate with high urgency |
| `P3` | Remediate in the normal flow |
| `P4` | Remediate when convenient |
| `NULL` | Not yet prioritizable: neither the severity nor strong exploitation evidence is known |

`NULL` is never replaced by `P4` or any other level. The logical values are
`P1`–`P4`; the API wire format is lowercase (`p1`–`p4`) under the Ticket enum
serialization rule in [tickets.md](tickets.md#response-schemas). The
`TicketPriority` enum is defined in `docs/data-model.md`.

## Exploitation Level

The exploitation level is a non-persisted classification of the evidence
attached to the Ticket's associated CVE. The first matching row wins:

| Level | Condition |
|---|---|
| `kev` | A `CVEKEVEntry` exists for the CVE |
| `active` | The CVE's `CVESSVCAssessment.exploitation` is `active` |
| `likely` | The CVE's `CVESSVCAssessment.exploitation` is `poc`, or its `CVEEPSSScore.percentile` is greater than or equal to `0.95` |
| `unknown` | Every other case, including SSVC `exploitation = none`, absent SSVC/EPSS/KEV rows, and a Ticket without a CVE |

The **deciding evidence** of the selected level is the persisted evidence that
satisfies its condition, in the order KEV, SSVC, EPSS:

| Level | Deciding evidence |
|---|---|
| `kev` | The `CVEKEVEntry`, with its `date_added` |
| `active` | SSVC `exploitation = active` |
| `likely` | SSVC `exploitation = poc` when it holds, and the EPSS `percentile` when it is greater than or equal to `0.95`; both when both hold |
| `unknown` | None |

Evidence that satisfies only the condition of a lower level is not deciding
evidence: with a KEV entry, an SSVC `active` assessment and a percentile of
`0.95` or more are not listed, and with SSVC `active`, such a percentile is not
listed. A percentile below `0.95` is never deciding evidence.

Classification uses the persisted evidence as is. Evidence freshness follows
each source's own refresh scope; for example, the periodic EPSS run refreshes
only CVEs with an active Ticket ([cve-sync-epss.md](cve-sync-epss.md),
Retained scores), so an inactive Ticket's priority may reflect its last
persisted percentile.

The EPSS threshold `0.95` is a specification constant, not a setting. It
compares the persisted percentile, never the EPSS probability score. SSVC
`automatable`, SSVC `technical_impact`, the EPSS score, CWE classifications,
and every other CVE field are not inputs.

## Decision Table

The automatic priority is a pure function of the Ticket's resolved severity
(canonical cascade in [tickets.md](tickets.md#resolution-rules)) and the
exploitation level:

| Exploitation | Critical | High | Medium | Low or None | Severity `NULL` |
|---|---|---|---|---|---|
| `kev` | P1 | P1 | P1 | P1 | P1 |
| `active` | P1 | P1 | P2 | P3 | P2 |
| `likely` | P2 | P2 | P3 | P4 | P3 |
| `unknown` | P2 | P3 | P4 | P4 | `NULL` |

A Ticket without a CVE always uses the `unknown` row with its
`severity_manual`; if that value is `NULL`, its automatic priority is `NULL`.

## Pure Resolution Functions

Module: `backend/app/services/ticket_priority.py`. Both functions are
Category B: they perform no database access, write, audit, lock, or external
call, and they raise no exception for any value of their declared input types.

### `classify_exploitation()`

```python
def classify_exploitation(
    *,
    kev_date_added: date | None,
    ssvc_exploitation: str | None,
    epss_percentile: float | None,
) -> ExploitationClassification:
```

`kev_date_added` is the `date_added` of the persisted `CVEKEVEntry` or `None`
when no entry exists. `ssvc_exploitation` is the persisted SSVC `exploitation`
value or `None` when no assessment exists. `epss_percentile` is the persisted
EPSS percentile or `None` when no score exists. The function applies the
[Exploitation Level](#exploitation-level) table in order and returns the
selected `level` together with its deciding `evidence`, an ordered sequence of
`ExploitationEvidence` values. An SSVC value other than `active` or `poc`
contributes no evidence.

Each `ExploitationEvidence` has a `kind` and the persisted `value` of that
input:

| `kind` | `value` |
|---|---|
| `kev` | `kev_date_added` (a date) |
| `ssvc_exploitation` | `ssvc_exploitation` (`active` or `poc`) |
| `epss_percentile` | `epss_percentile` (a number) |

`ExploitationLevel` (`kev`, `active`, `likely`, `unknown`) and
`ExploitationEvidenceKind` (`kev`, `ssvc_exploitation`, `epss_percentile`) are
enums that are never persisted; the API serializes them only in the
[Automatic Priority Basis](#automatic-priority-basis).

### `resolve_priority()`

```python
def resolve_priority(
    severity: Severity | None,
    exploitation: ExploitationLevel,
) -> TicketPriority | None:
```

Returns the [Decision Table](#decision-table) cell for the resolved severity
label (`None` meaning SQL `NULL`, distinct from the `None` severity label) and
the exploitation level.

## Persistence and Effective Priority

`Ticket` persists two nullable priority columns and the provenance of the
override (see `docs/data-model.md`, Ticket):

- `priority_auto` — system-managed. Only
  [`refresh_priority_auto()`](#refresh_priority_auto) writes it.
- `priority_override` — the sticky manual value. Only
  [`set_priority_override()`](#set_priority_override) writes it. Automatic
  processing never modifies or clears it.
- `priority_override_by_id` and `priority_override_at` — the **override
  provenance**: the user who set the current value of `priority_override`
  and the time at which they set it. Only `set_priority_override()` writes
  them, in the same write as `priority_override`. Both are `NULL` exactly
  when `priority_override` is `NULL`
  (`chk_ticket_priority_override_provenance`).

The **effective priority** is `COALESCE(priority_override, priority_auto)`. It
is the value exposed as `priority` in API responses, filtered, sorted, and
recorded in audit events. It is derived at read time and is not stored in a
third column. No override reason or comment is stored.

The override provenance is current state of the override, not its history: it
names the change that set the current value, so that a reader of the Ticket
knows whom to ask about the override and whether it was set before the
current evidence of the automatic priority, which an override masks without
an audit event ([`refresh_priority_auto()`](#refresh_priority_auto), step 6).
Earlier overrides of the Ticket remain only in its `priority_changed` events.
The provenance is never derived from audit history, and neither automatic
processing nor a user lifecycle or profile mutation, such as deactivation or
a rename, changes it; a response shows the setter's current profile.

These columns are introduced without a data backfill because no live or
production database exists: every Ticket receives its automatic value at its
next refresh point, and the provenance has no source outside audit history.
The migration that adds the provenance therefore fails on a database in which
a Ticket holds an override.

## Automatic Refresh

### `refresh_priority_auto()`

Category A primitive in `ticket_mutations`:

```python
async def refresh_priority_auto(
    db: AsyncSession,
    *,
    ticket: Ticket,
) -> bool:
```

`ticket` is the caller's locked Ticket instance. The return value is `True`
exactly when this call changed the persisted `priority_auto`.

**Preconditions (trusted, not rediscovered)**: the caller holds the Ticket
`FOR UPDATE` or inserted it in the current transaction and, when the Ticket has an associated CVE, holds that CVE root
lock acquired before the Ticket under the cross-domain root order. The function
acquires no lock, performs no consumer accessibility check, and does not call
`ensure_ticket_operable()`: automatic priority is maintained in every Ticket
status, like `CVE.severity`.

**Behavior**:

1. Read the resolved severity from locked-current state: `CVE.severity` when
   `ticket.cve_id` is set, otherwise `ticket.severity_manual`. Every read
   observes the writes already made by the enclosing transaction.
2. When the Ticket has a CVE, read its `CVEKEVEntry.date_added`, its SSVC
   `exploitation`, and its EPSS `percentile`, each `None` when the row does not
   exist; otherwise use no evidence.
3. Compute `resolve_priority(severity, level)`, where `level` is the level that
   `classify_exploitation()` returns for that evidence.
4. If the result equals `ticket.priority_auto`, return `False` with no write or
   event.
5. Otherwise capture the old effective priority, persist the new
   `priority_auto`, and compute the new effective priority.
6. If the effective priority changed, create one system-attributed
   `priority_changed` event (see [Audit](#audit)). If an override masks the
   change, create no event.
7. Flush and return `True`.

It never writes the override or its provenance, assigns, reconciles, changes
status, registers Ticket convergence, or performs network, Redis, or Celery
I/O. Re-invocation with unchanged inputs is a no-op. Database, audit, and
flush exceptions propagate unchanged and roll back the caller's complete
transaction.

### Refresh Points

Every workflow that can change a priority input calls
`refresh_priority_auto()` under the locks it already holds. No refresh point
introduces a new root or lock order.

| Priority input change | Workflow and refresh position |
|---|---|
| External CVSS assessments change `CVE.severity` | `upsert_external_cvss_batch()`, after at least one created or updated candidate and its severity and Product steps, before its optional final reconciliation, in every Ticket status ([ticket-mutations.md](ticket-mutations.md#upsert_external_cvss_batch)) |
| KEV, SSVC, or EPSS evidence changes, including enrichment-only payloads and Ticket creation during ingestion | `cve_service.upsert_cve()`, once after the CVSS batch and before the lifecycle decision ([cve-service.md](cve-service.md#complete-upsert_cve-composition)) |
| Manual SUSE assessment create, update, or delete | `upsert_cvss_assessment()` and `delete_cvss_assessment()`, after an effective mutation's severity and Product steps and before the optional final reconciliation, when a Ticket exists |
| Manual severity | `set_severity_manual()`, after its `severity_changed` event and before reconciliation |
| CVE association (severity-source handover and new evidence) | `recalculate_cvss_chain()` in association mode, after the handover and Product events; `associate_cve()` then performs its one final reconciliation |
| Default CVSS version change | `recalculate_cvss_chain()` in default-version mode, after the severity and Product steps and before the optional final reconciliation, in every Ticket status |
| Manual Ticket creation | `create_ticket()` with `source = manual`, after its last creation event. The `cve_ingestion` source does not refresh; its caller `upsert_cve()` owns the refresh |

The refresh in `upsert_cve()` is a no-op when the batch already refreshed from
the same inputs, because KEV, SSVC, and EPSS writes precede the batch.

Status transitions, assignment, reconciliation, manual-zone entry and exit,
package-tree, Product, confidentiality, grant, reference, and priority-override
mutations do not change a priority input and do not refresh. Priority inputs
are never changed by reconciliation or by the CVE rejection lifecycle step.

The default-CVSS impact preview does not project priority: priority is not part
of its result, and no preview count reflects it.

## Automatic Priority Basis

The **automatic priority basis** states what the automatic priority of a Ticket
is based on: the two inputs that select its [Decision Table](#decision-table)
cell and the evidence that decided the exploitation level. Every Ticket has
one:

| Member | Content |
|---|---|
| `severity` | The resolved severity that selects the column (canonical cascade in [tickets.md](tickets.md#resolution-rules)), `NULL` when unresolved |
| `exploitation` | The [exploitation level](#exploitation-level) that selects the row |
| `evidence` | The deciding evidence of that level, in the order KEV, SSVC, EPSS, each with its kind and persisted value; empty for `unknown` |

A Ticket without a CVE has `severity` equal to its `severity_manual`,
`exploitation = unknown`, and no evidence. Because the Decision Table yields
`NULL` only for severity `NULL` with `unknown`, the basis of a `NULL` automatic
priority has `severity` `NULL`, `exploitation = unknown`, and no evidence.

The basis is derived at read time and is never persisted. A read derives it
from the same observation that supplies `priority_auto`: the resolved severity
and the persisted KEV, SSVC, and EPSS rows of the Ticket's CVE, classified by
`classify_exploitation()`, which `refresh_priority_auto()` also uses. Because
every change of a priority input refreshes `priority_auto` in the same
transaction ([Refresh Points](#refresh-points)), the Decision Table cell of the
basis `severity` and `exploitation` equals `priority_auto` in that
observation.

The basis explains only the automatic priority. An override never changes it,
and it is present whether or not an override is set. It states no threshold:
an `epss_percentile` element is present only when the percentile met the
threshold of the `likely` level. It is not an input of any decision, creates no
audit event, and is not recorded in `priority_changed`.

## Manual Override

### `set_priority_override()`

Category A operation in `ticket_service`:

```python
async def set_priority_override(
    db: AsyncSession,
    *,
    ticket_id: UUID,
    priority: TicketPriority | None,
    acting_user_id: UUID,
    evaluation_date: date | None = None,
) -> Ticket:
```

`priority` is the requested override; `None` clears it. `acting_user_id` is the
authorized user; system callers do not exist for this operation.
`evaluation_date` follows the `TicketDetail` workflow-date contract in
[ticket-service.md](ticket-service.md#get_ticket_detail); when omitted, the
function captures one UTC date at entry.

**Behavior**:

1. Acquire `FOR SHARE` on the acting User and stabilize its assignment
   eligibility, then acquire `FOR UPDATE` on the Ticket.
2. Revalidate consumer accessibility from the locked-current Ticket. Missing or
   inaccessible raises `TicketNotFoundError` with no effect.
3. Call `ensure_ticket_operable(ticket)`. `Ignored` and `Duplicated` raise
   `TicketNotMutableError` with no effect.
4. If `priority` equals the current `priority_override` (including `None` when
   no override exists), return the Ticket unchanged: no assignment, write,
   event, or reconciliation. The provenance keeps the change that set the
   current value, also when another user sends the request.
5. Call `auto_assign_actor()` with the stabilized User.
6. Classify the action from the locked pre-state: `set` (no override to a
   value), `changed` (one value to another), or `cleared` (a value to none).
   Capture the old effective priority, persist `priority_override` with its
   provenance, and compute the new effective priority. For `set` and
   `changed` the provenance is `acting_user_id` and the transaction's `now()`;
   for `cleared` both provenance columns are `NULL`.
7. Create one `priority_changed` event attributed to the acting user, with the
   old and new effective priorities and the action in `detail`, even when the
   effective priority is unchanged (for example, an override equal to
   `priority_auto`). Its `created_at` is the same transaction `now()`, so the
   `priority_override_at` of a `set` or `changed` equals the `created_at` of
   its event.
8. Call `reconcile_ticket_status()` exactly once with the one
   `evaluation_date`. Priority is not a gate input; reconciliation is required
   by the [auto-assignment rule](ticket-mutations.md#auto-assignment-rule) and
   performs assignment-eligibility sanitation and gate evaluation after a
   possible `New -> Analysis` promotion.
9. Return the updated Ticket.

`priority_auto` is not modified. Re-invocation with the same value is the
step-4 no-op. The operation propagates `TicketNotFoundError`,
`TicketNotMutableError`, and exceptions from `auto_assign_actor()` and
`reconcile_ticket_status()`; any failure rolls back the override and its
provenance, assignment, status, and every event together.

The consumer endpoint is `PATCH /api/v1/tickets/{ticket_id}/priority` with
`Capability: triage_ticket`, defined in
[tickets.md](tickets.md#set-priority-override).

## Audit

`priority_changed` records a change of priority. The field contract is owned by
[ticket-audit-log.md](ticket-audit-log.md#event-type-contract):

| Trigger | `user_id` | `old_value` / `new_value` | `comment` | `detail` |
|---|---|---|---|---|
| Automatic refresh changes the effective priority | `NULL` | Old and new effective priority (`P1`–`P4` or `NULL`) | `NULL` | `NULL` |
| Override set, changed, or cleared | Acting user | Old and new effective priority; may be equal | `NULL` | `{"override_action": "set" \| "changed" \| "cleared"}` |

An automatic `priority_auto` change masked by an override, an unchanged
refresh, an override no-op, and every rejected or rolled-back operation create
no event. Audit history is never an input to priority resolution.

## API Surface

| Surface | Contract | Owner |
|---|---|---|
| `TicketSummary.priority`, `TicketDetail.priority` | Effective priority | [tickets.md](tickets.md#response-schemas) |
| `priority_automatic`, `priority_override` of `TicketSummary` and `TicketDetail` | Persisted automatic and manual values | [tickets.md](tickets.md#response-schemas) |
| `priority_override_by`, `priority_override_at` of `TicketSummary` and `TicketDetail` | Override provenance ([Persistence and Effective Priority](#persistence-and-effective-priority)) | [tickets.md](tickets.md#response-schemas) |
| `priority_automatic_basis` of `TicketSummary` and `TicketDetail` (`PriorityBasis`) | [Automatic Priority Basis](#automatic-priority-basis) | [tickets.md](tickets.md#shared-sub-schemas) |
| `GET /api/v1/tickets` `priority` filter and `sort_by=priority` | Repeatable filter over effective priority, including `unresolved`; semantic ordering | [tickets.md](tickets.md#list-tickets), [api-spec.md](../../api-spec.md#semantic-sort-fields) |
| `GET /api/v1/tickets` `sort_by=priority_then_current_due` | Effective priority in semantic ordering, then the due date of the Ticket's current phase | [ticket-deadlines.md](ticket-deadlines.md#current-due-date) |
| `PATCH /api/v1/tickets/{ticket_id}/priority` | Set or clear the override | [tickets.md](tickets.md#set-priority-override) |
| `CVEDetail` exploitation and weakness data; `GET /api/v1/cves/{cve_id}` | Evidence inputs, never a CVE priority | [tickets.md](tickets.md#shared-sub-schemas), [cve-tracking.md](cve-tracking.md#get-cve) |

The exploitation level and its deciding evidence are exposed only in the
automatic priority basis. `CVEDetail` exposes every persisted evidence value,
including values that decide no level.

## Testing Requirements

Tests MUST cover:

1. Every decision-table cell, including severity `None` versus `NULL`, and each
   exploitation precedence order (KEV over SSVC, SSVC `active` over `poc`, EPSS
   percentile exactly `0.95` versus just below, EPSS score ignored, SSVC
   `none`, `automatable`, and `technical_impact` ignored).
2. CVE-less Tickets using `severity_manual` with the `unknown` row, and `NULL`
   priority when it is unset.
3. Every refresh point: the persisted `priority_auto`, the exact system event
   and its position (after severity and Product events, before assignment-
   eligibility sanitation and the final gate `status_change`), refresh in every
   Ticket status, the single refresh for ingestion-created Tickets, and
   enrichment-only KEV/SSVC/EPSS payloads.
4. An override masking an automatic change (persisted `priority_auto` change,
   no event, unchanged override provenance) and a later clear exposing the
   automatic value.
5. Override set, changed, and cleared with exact `override_action`, equal
   old/new values when the effective priority does not change, the no-op,
   auto-assignment with `New -> Analysis` followed by one reconciliation,
   `TICKET_NOT_FOUND` for missing and inaccessible Tickets, `TICKET_NOT_MUTABLE`
   in `Ignored` and `Duplicated`, `403` without `triage_ticket`, and rollback.
   Each case asserts the override provenance it leaves: the acting user and a
   `priority_override_at` equal to the `created_at` of the `priority_changed`
   event for `set` and for `changed` by another user in a later transaction,
   both `NULL` after `cleared`, and the unchanged provenance of the earlier
   change after the no-op, also when another user sends it, and after every
   rejection and rollback.
6. Proof that the automatic refresh never alters status, gates, Product
   eligibility, assignment, or accessibility, that the override's assignment
   and status consequences arise only from the auto-assignment rule (item 5),
   and that no refresh consults audit history.
7. Independent-session races between the override and an automatic refresh on
   the same Ticket, proving serialized pre-state and no stale event values.
8. The default-version runner classifying a unit `changed` when only
   `priority_auto` changes.
9. API filter (`p1`–`p4`, `unresolved`, invalid values ignored), semantic
   sort with NULL last, and response fields, including the override
   provenance in `TicketSummary`, `TicketDetail`, and the `PATCH .../priority`
   response, both `null` without an override, and a deactivated setter, whom
   the provenance keeps and projects with `active = false`.
10. The automatic priority basis of `classify_exploitation()` and of
    `TicketSummary` and `TicketDetail`: each level with its exact deciding
    evidence, values, and order (KEV with `date_added`, alone when SSVC
    `active` or `poc` or a percentile of at least `0.95` also exists; SSVC
    `active`, alone when a percentile of at least `0.95` also exists; SSVC
    `poc` alone; an EPSS percentile alone, exactly `0.95` and above it, also
    with SSVC `none`; `poc` with a qualifying percentile listing both; a
    percentile just below `0.95`, SSVC `none`, and no evidence, each yielding
    `unknown` with no evidence), basis severity `none` distinct from `null`, a
    Ticket without a CVE with and without `severity_manual`, a `NULL`
    automatic priority, an override that leaves the basis unchanged, the
    post-mutation basis in the responses of `POST /api/v1/tickets` with a
    CVE, `POST .../associate-cve`, and `PATCH .../severity`, and each
    Decision Table cell, reached at least once through any refresh point,
    with a basis whose cell equals `priority_automatic` in the same response.
11. `chk_ticket_priority_override_provenance` rejecting an override without
    either provenance column and either provenance column without an
    override, and the migration that adds the provenance succeeding on
    Tickets without an override and failing on a Ticket that holds one.

Audit assertions follow `docs/features/platform/testing-strategy.md` (Audit
Trail Testing).

## Cross-references

- `docs/features/tickets/tickets.md` — severity resolution, Ticket schemas,
  list filters, and the override endpoint
- `docs/features/tickets/ticket-mutations.md` — CVSS chains, manual severity,
  auto-assignment, and reconciliation
- `docs/features/tickets/ticket-service.md` — Ticket creation, CVE
  association, and `TicketDetail` assembly
- `docs/features/tickets/cve-service.md` — `upsert_cve()` composition and CVE
  reads
- `docs/features/tickets/cve-tracking.md` — CVE detail endpoint
- `docs/features/tickets/cve-sync-kev.md`, `cve-sync-epss.md`,
  `cve-sync-mitre.md` — exploitation evidence sources
- `docs/features/tickets/ticket-audit-log.md` — `priority_changed` contract
- `docs/features/tickets/ticket-deadlines.md` — the current due date that
  follows priority in `sort_by=priority_then_current_due`
- `docs/features/platform/default-cvss-version-operations.md` — all-CVE
  runner and impact preview
- `docs/data-model.md` — `Ticket` priority and override provenance columns
  and `TicketPriority`
- `docs/api-spec.md` — semantic sorting, filtering, error derivation, and
  User References in Responses
- `docs/features/identity/rbac.md` — `triage_ticket` and the Endpoint
  Permission Map
