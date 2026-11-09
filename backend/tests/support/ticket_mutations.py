"""Shared helpers for the Ticket mutation service tests.

Consumers:

- `tests/test_services/test_ticket_mutations.py` (the primitives);
- `tests/test_services/test_ticket_priority_refresh.py`
  (`refresh_priority_auto()`);
- `tests/test_services/test_set_severity_manual.py`
  (`set_severity_manual()`);
- `tests/test_services/test_recalculate_cvss_chain.py` and
  `tests/test_services/test_recalculate_cvss_chain_atomicity.py`
  (`recalculate_cvss_chain()`, with the chain-specific helpers of
  `tests/support/cvss_chain.py`);
- `tests/test_services/test_set_priority_override.py` and
  `tests/test_services/test_set_priority_override_atomicity.py`
  (`set_priority_override()` and its override provenance).

Consumers import these plain helpers directly. The shared `va_user` and
`tree` fixtures live in the separate plugin module
`tests/support/ticket_mutation_fixtures.py`, which a consumer lists in its
own `pytest_plugins` and never imports: pytest must import a plugin module
itself so that it can rewrite its assertions.

Expected values in the consumers are transcribed from the specifications;
nothing here computes an expectation with the module under test.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
from typing import Any

from sqlalchemy import Connection, Engine, event, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import PackageStatus, Severity, TicketIgnoreReason, TicketStatus
from app.models.ticket import Ticket
from app.models.ticket_audit_event import TicketAuditEvent
from app.models.ticket_package_track import TicketPackageTrack
from app.models.user import User

EVAL = date(2026, 9, 27)
"""The fixed UTC evaluation date passed by gate tests."""

BEFORE_EVAL = EVAL - timedelta(days=30)
"""A General Support end before `EVAL`: the Product is EOL on `EVAL`."""

AFTER_EVAL = EVAL + timedelta(days=365)
"""A General Support end after `EVAL`: the Product is in support on `EVAL`."""

RELEASED_AT = datetime(2026, 9, 1, 12, 0, tzinfo=UTC)

PRIORITY_OVERRIDE_SET_AT = datetime(2001, 2, 3, 4, 5, 6, tzinfo=UTC)
"""Default `priority_override_at` of a `ticket_factory` Ticket created with
a priority override (`tests/conftest.py`)."""

DEFAULT_IGNORE_REASON = TicketIgnoreReason.OTHER
"""Default `ignore_reason` of an `Ignored` Ticket that a test builder writes
without naming one (`chk_ticket_ignore_reason_status_coherence`). `other`
never reopens automatically, so a test that relies on the reopen of a
reverted rejection states `cve_rejected`."""


def ignore_reason_for(status: str) -> str | None:
    """The `ignore_reason` that a test builder writes together with
    `status`: `DEFAULT_IGNORE_REASON` for `Ignored`, otherwise `NULL`."""
    return DEFAULT_IGNORE_REASON.value if status == TicketStatus.IGNORED else None


TicketFactory = Callable[..., Awaitable[Ticket]]
UserFactory = Callable[..., Awaitable[User]]
VAUser = Callable[..., Awaitable[User]]
TreeBuilder = Callable[..., Awaitable[TicketPackageTrack]]


# ---------------------------------------------------------------------------
# Statement recording
# ---------------------------------------------------------------------------


class StatementRecorder:
    """Records every SQL statement and its parameters on the test engine."""

    def __init__(self, db: AsyncSession) -> None:
        # A subclass may narrow the listener target to one connection.
        self._engine: Engine | Connection = db.get_bind().engine
        self.statements: list[str] = []
        self.parameters: list[Any] = []

    def _record(self, *args: Any) -> None:
        self.statements.append(args[2])
        self.parameters.append(args[3])

    def __enter__(self) -> StatementRecorder:
        event.listen(self._engine, "before_cursor_execute", self._record)
        return self

    def __exit__(self, *exc: object) -> None:
        event.remove(self._engine, "before_cursor_execute", self._record)

    def selects_from(self, table: str) -> list[str]:
        return [
            s
            for s in self.statements
            if s.lstrip().upper().startswith("SELECT") and f"FROM {table}" in s
        ]

    def row_locks(self) -> list[str]:
        markers = ("FOR UPDATE", "FOR SHARE", "FOR NO KEY UPDATE", "FOR KEY SHARE")
        return [s for s in self.statements if any(m in s for m in markers)]

    def writes(self) -> list[str]:
        """Every statement that is not a `SELECT`."""
        return [
            s for s in self.statements if not s.lstrip().upper().startswith("SELECT")
        ]


# ---------------------------------------------------------------------------
# Ticket audit events
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class EventRow:
    event_type: str
    user_id: uuid.UUID | None
    old_value: str | None
    new_value: str | None
    comment: str | None
    detail: Any


async def ticket_events(db: AsyncSession, ticket: Ticket) -> list[EventRow]:
    """The Ticket's audit events in insertion (UUIDv7 `id`) order."""
    return await ticket_events_by_id(db, ticket.id)


async def ticket_events_by_id(db: AsyncSession, ticket_id: uuid.UUID) -> list[EventRow]:
    """`ticket_events()` for a Ticket identified only by its UUID."""
    rows = (
        await db.execute(
            select(TicketAuditEvent)
            .where(TicketAuditEvent.ticket_id == ticket_id)
            .order_by(TicketAuditEvent.id)
        )
    ).scalars()
    return [
        EventRow(r.event_type, r.user_id, r.old_value, r.new_value, r.comment, r.detail)
        for r in rows
    ]


async def override_provenance(
    db: AsyncSession, ticket_id: uuid.UUID
) -> tuple[uuid.UUID | None, datetime | None]:
    """The persisted `(priority_override_by_id, priority_override_at)` of a
    Ticket (ticket-priority.md, Persistence and Effective Priority)."""
    row = (
        await db.execute(
            select(Ticket.priority_override_by_id, Ticket.priority_override_at).where(
                Ticket.id == ticket_id
            )
        )
    ).one()
    return row.priority_override_by_id, row.priority_override_at


async def priority_event_times(
    db: AsyncSession, ticket_id: uuid.UUID
) -> list[datetime]:
    """The `created_at` of the Ticket's `priority_changed` events in
    insertion (UUIDv7 `id`) order."""
    return list(
        (
            await db.execute(
                select(TicketAuditEvent.created_at)
                .where(
                    TicketAuditEvent.ticket_id == ticket_id,
                    TicketAuditEvent.event_type == "priority_changed",
                )
                .order_by(TicketAuditEvent.id)
            )
        ).scalars()
    )


def status_event(old: str, new: str) -> EventRow:
    """A system-derived `status_change` event."""
    return EventRow("status_change", None, old, new, None, None)


def unassigned_event(username: str, reason: str) -> EventRow:
    """A system assignment-eligibility sanitation event."""
    return EventRow(
        "assignment",
        None,
        username,
        None,
        f"Unassigned from {username}: {reason}",
        None,
    )


# ---------------------------------------------------------------------------
# Ticket builders
# ---------------------------------------------------------------------------


REACTIVE_GS_END = EVAL - timedelta(days=90)
"""The General Support end of a Product in Reactive Support on `EVAL`."""

REACTIVE_EXTENDED_END = BEFORE_EVAL
"""The extended-support end of a Product in Reactive Support on `EVAL`."""

REACTIVE_END = AFTER_EVAL
"""The Reactive Support end of a Product in Reactive Support on `EVAL`."""


@dataclass(frozen=True, slots=True)
class Prod:
    """One Product occurrence of a factory-built track.

    `lifecycle=False` leaves every lifecycle date `NULL` (phase
    unavailable); `reactive=True` places the catalog Product in Reactive
    Support on `EVAL` and takes precedence over `eol`. `threshold` is the
    catalog `Product.cvss_threshold` (`None` is SQL `NULL`).
    """

    eligible: bool = True
    override: bool = False
    eol: bool = False
    lifecycle: bool = True
    excluded: bool = False
    released: bool = False
    threshold: Decimal | None = None
    reactive: bool = False


async def cveless(
    ticket_factory: TicketFactory,
    *,
    status: TicketStatus = TicketStatus.ANALYSIS,
    severity: Severity | None = Severity.HIGH,
    **overrides: Any,
) -> Ticket:
    """A CVE-less Ticket whose `severity_manual` is `severity`."""
    return await ticket_factory(
        status=status.value,
        severity_manual=severity.value if severity else None,
        **overrides,
    )


async def lock_ticket(db: AsyncSession, ticket: Ticket) -> Ticket:
    """Acquire `FOR UPDATE` on the Ticket, as an owning workflow would."""
    return (
        await db.execute(select(Ticket).where(Ticket.id == ticket.id).with_for_update())
    ).scalar_one()


async def tree_for(target: TicketStatus, ticket: Ticket, tree: TreeBuilder) -> None:
    """Build a CVE-less tree whose gate result is `target`.

    Assumes a resolved severity (tickets.md, Gate: Analysis → Analyzed):
    with SQL `NULL` severity every tree evaluates to `Analysis`.
    """
    status = {
        TicketStatus.ANALYSIS: PackageStatus.ANALYSIS,
        TicketStatus.ANALYZED: PackageStatus.AFFECTED,
        TicketStatus.RESOLVED: PackageStatus.NOT_AFFECTED,
    }[target]
    await tree(ticket, status=status)
