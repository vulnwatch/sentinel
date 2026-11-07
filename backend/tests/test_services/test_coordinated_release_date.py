"""Single-session service integration tests for
`set_coordinated_release_date()` (backend/app/services/ticket_service.py).

Owning specifications:

- docs/features/tickets/ticket-service.md (Caller category and Ticket
  accessibility; Operability guard, explicit opt-outs;
  `set_coordinated_release_date`; Service Exceptions; Architectural Test
  Requirements 15 (single-session part) and 20 (except the manual-creation
  part, owned by the creation tests)).
- docs/features/tickets/tickets.md (Inactive Statuses and Mutability >
  Ignored, explicit exceptions; Confidential Tickets > Coordinated Release
  Date and Audit Trail; Set Coordinated Release Date).
- docs/features/tickets/ticket-audit-log.md (Event Type Contract:
  `coordinated_release_changed` and the bullets after the table; Canonical
  Mutation and No-Event Matrix: Coordinated Release Date set, change, or
  clear; Testing Requirements 1-7, 12, and 29).
- docs/features/tickets/ticket-deadlines.md (Testing Requirements 3 and
  17: immutability of the start, and due dates that follow the
  coordinated release window, across a set, moved, and cleared
  Coordinated Release Date).
- docs/features/platform/testing-strategy.md (Tier Responsibility and
  Proportionality; Ticket Accessibility > Confidentiality and explicit
  access grants, the Coordinated Release Date bullet).

The independent-session races of ATR 20 (with declassification and with
another CRD change) and the locked-current accessibility races of ATR 15
are owned by `tests/test_services/test_confidentiality_atomicity.py`. The
API boundary owns the interpretation of an offset-less request value as
UTC; the service receives only aware instants and rejects a naive one.

Sub-second precision is not specified by the Event Type Contract, which
requires only "UTC ISO 8601"; the expected string follows the
implementation's documented choice to keep microseconds when present.

Expected values are transcribed from the specifications, never computed
with the module under test.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import (
    PackageStatus,
    Role,
    Scope,
    Severity,
    TicketAuditEventType,
    TicketStatus,
)
from app.core.exceptions import TicketNotFoundError
from app.models.ticket import Ticket
from app.models.ticket_access_grant import TicketAccessGrant
from app.models.ticket_audit_event import TicketAuditEvent
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_maintainer import TicketPackageMaintainer
from app.models.user import User
from app.services import ticket_service
from app.services.ticket_audit_log import TicketAuditLog
from app.services.ticket_convergence_registry import (
    pending_ticket_convergence_effects,
)
from app.services.ticket_deadlines import DueDates
from app.services.ticket_service import (
    CoordinatedReleaseBeforeCreationError,
    TicketNotConfidentialError,
    assemble_ticket_detail,
    set_confidentiality,
    set_coordinated_release_date,
)
from app.services.ticket_visibility import TicketCaller, ticket_visibility_condition
from tests.support.cvss_chain import eligibility
from tests.support.database import rollback_test_scope
from tests.support.deadline_matrix import crd_window_offsets
from tests.support.ticket_mutations import (
    EVAL,
    EventRow,
    Prod,
    StatementRecorder,
    TicketFactory,
    TreeBuilder,
    VAUser,
    ticket_events_by_id,
)

pytest_plugins = ["tests.support.ticket_mutation_fixtures"]
"""Provides the shared `va_user` and `tree` fixtures."""

TICKET_CREATED_AT = datetime(2001, 1, 1, 9, 0, tzinfo=UTC)
"""Default creation of this module's Tickets: before every CRD it sets, so
that only the creation-bound tests reach
`CoordinatedReleaseBeforeCreationError`."""


@pytest.fixture
def ticket_factory(ticket_factory: TicketFactory) -> TicketFactory:
    """The shared factory with `created_at` defaulting to
    `TICKET_CREATED_AT`."""

    async def _create(**overrides: Any) -> Ticket:
        overrides.setdefault("created_at", TICKET_CREATED_AT)
        return await ticket_factory(**overrides)

    return _create


GrantFactory = Callable[..., Awaitable[TicketAccessGrant]]

ALL_STATUSES = [
    TicketStatus.NEW,
    TicketStatus.ANALYSIS,
    TicketStatus.ANALYZED,
    TicketStatus.RESOLVED,
    TicketStatus.IGNORED,
    TicketStatus.DUPLICATED,
]

CEST = timezone(timedelta(hours=2))
EST = timezone(timedelta(hours=-5))

CRD = datetime(2026, 10, 6, 14, 0, tzinfo=UTC)
CRD_TEXT = "2026-10-06T14:00:00Z"
"""The Event Type Contract's own example value."""
CRD_CEST = datetime(2026, 10, 6, 16, 0, tzinfo=CEST)
"""The same instant as `CRD`, supplied with a `+02:00` offset."""
LATER = datetime(2026, 11, 3, 9, 30, tzinfo=UTC)
LATER_TEXT = "2026-11-03T09:30:00Z"

FORBIDDEN = (
    "auto_assign_actor",
    "reconcile_ticket_status",
    "ensure_ticket_operable",
    "stabilize_acting_user",
    "refresh_priority_auto",
    "recalculate_cvss_chain",
)
"""`ticket_service` collaborators the embargo-metadata operation never
calls (ticket-service.md, `set_coordinated_release_date`)."""

State = tuple[str, uuid.UUID | None, uuid.UUID | None, bool, datetime | None]
"""The persisted `(status, assignee_id, duplicate_of_id, is_confidential,
coordinated_release_at)` of a Ticket."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _changed(actor: User, old: str | None, new: str | None) -> EventRow:
    """The acting-user `coordinated_release_changed` (`comment` and
    `detail` `NULL`)."""
    return EventRow("coordinated_release_changed", actor.id, old, new, None, None)


async def _set(
    db: AsyncSession,
    ticket_id: uuid.UUID,
    actor: User,
    value: datetime | None,
    *,
    scope: Scope = Scope.ALL,
) -> Ticket:
    """Call the service as an API handler would."""
    return await set_coordinated_release_date(
        db,
        ticket_id=ticket_id,
        coordinated_release_at=value,
        acting_user_id=actor.id,
        caller=TicketCaller.authenticated(actor.id, scope),
    )


async def _state(db: AsyncSession, ticket_id: uuid.UUID) -> State | None:
    row = (
        await db.execute(
            select(
                Ticket.status,
                Ticket.assignee_id,
                Ticket.duplicate_of_id,
                Ticket.is_confidential,
                Ticket.coordinated_release_at,
            ).where(Ticket.id == ticket_id)
        )
    ).one_or_none()
    return tuple(row) if row is not None else None  # type: ignore[return-value]


async def _stored(db: AsyncSession, ticket_id: uuid.UUID) -> datetime | None:
    state = await _state(db, ticket_id)
    assert state is not None
    return state[4]


async def _visible(db: AsyncSession, ticket_id: uuid.UUID, user: User) -> bool:
    """The canonical predicate for a `non_confidential`-scope caller."""
    caller = TicketCaller.authenticated(user.id, Scope.NON_CONFIDENTIAL)
    return bool(
        (
            await db.execute(
                select(ticket_visibility_condition(caller))
                .select_from(Ticket)
                .where(Ticket.id == ticket_id)
            )
        ).scalar_one()
    )


def _forbid(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Replace every `FORBIDDEN` collaborator with a recorder that fails."""
    calls: list[str] = []
    for name in FORBIDDEN:

        def _called(*_args: Any, _name: str = name, **_kwargs: Any) -> Any:
            calls.append(_name)
            raise AssertionError(f"{_name} must not be called")

        monkeypatch.setattr(ticket_service, name, _called)
    return calls


async def _assert_rejected(
    db: AsyncSession,
    error_type: type[Exception],
    *,
    ticket_id: uuid.UUID,
    actor: User,
    value: datetime | None,
    scope: Scope = Scope.ALL,
) -> None:
    """The zero-side-effect contract of a rejected call: the error, no
    write, the Ticket unchanged, and no event."""
    before = await _state(db, ticket_id)

    with StatementRecorder(db) as recorder, pytest.raises(error_type):
        await _set(db, ticket_id, actor, value, scope=scope)

    assert recorder.writes() == []
    assert await _state(db, ticket_id) == before
    assert await ticket_events_by_id(db, ticket_id) == []


# ---------------------------------------------------------------------------
# Effective set, change, and clear
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestEffectiveChange:
    @pytest.mark.parametrize(
        ("stored", "requested", "persisted", "old_text", "new_text"),
        [
            pytest.param(None, CRD, CRD, None, CRD_TEXT, id="set"),
            pytest.param(None, CRD_CEST, CRD, None, CRD_TEXT, id="set-offset"),
            pytest.param(
                None,
                datetime(2026, 10, 6, 22, 30, tzinfo=EST),
                datetime(2026, 10, 7, 3, 30, tzinfo=UTC),
                None,
                "2026-10-07T03:30:00Z",
                id="set-offset-crossing-utc-midnight",
            ),
            pytest.param(CRD, LATER, LATER, CRD_TEXT, LATER_TEXT, id="move-later"),
            pytest.param(LATER, CRD_CEST, CRD, LATER_TEXT, CRD_TEXT, id="move-earlier"),
            pytest.param(CRD, None, None, CRD_TEXT, None, id="clear"),
            pytest.param(
                CRD,
                datetime(2001, 9, 1, 8, 0, tzinfo=UTC),
                datetime(2001, 9, 1, 8, 0, tzinfo=UTC),
                CRD_TEXT,
                "2001-09-01T08:00:00Z",
                id="past-instant",
            ),
            pytest.param(
                None,
                datetime(2026, 10, 6, 16, 0, 0, 250000, tzinfo=CEST),
                datetime(2026, 10, 6, 14, 0, 0, 250000, tzinfo=UTC),
                None,
                "2026-10-06T14:00:00.250000Z",
                id="sub-second",
            ),
        ],
    )
    async def test_persists_the_instant_with_one_exact_utc_event(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
        stored: datetime | None,
        requested: datetime | None,
        persisted: datetime | None,
        old_text: str | None,
        new_text: str | None,
    ) -> None:
        """Steps 5-6 and audit Testing Requirement 29: the stored instant is
        the requested one in UTC; the event carries the preserved and
        requested instants in UTC ISO 8601 with a `Z` suffix, `NULL` for
        an absent side. The flag and every other field are unchanged and no
        post-commit effect is registered."""
        actor = await va_user()
        ticket = await ticket_factory(
            is_confidential=True, coordinated_release_at=stored
        )
        before = await _state(db_session, ticket.id)
        assert before is not None

        result = await _set(db_session, ticket.id, actor, requested)

        assert result.id == ticket.id
        assert result.coordinated_release_at == persisted
        assert await _state(db_session, ticket.id) == (*before[:4], persisted)
        if persisted is not None:
            value = await _stored(db_session, ticket.id)
            assert value is not None
            assert value.utcoffset() == timedelta(0)
        assert await ticket_events_by_id(db_session, ticket.id) == [
            _changed(actor, old_text, new_text)
        ]
        assert pending_ticket_convergence_effects(db_session) == ()

    @pytest.mark.parametrize("status", ALL_STATUSES, ids=str)
    async def test_succeeds_in_every_status_without_lifecycle_effects(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
        status: TicketStatus,
    ) -> None:
        """ticket-service.md, Operability guard (explicit opt-out): an
        unassigned confidential Ticket and an active VA actor make any
        auto-assignment observable. No assignment, reconciliation, or
        status change occurs, in the manual zone as well."""
        actor = await va_user()
        ticket = await ticket_factory(status=status.value, is_confidential=True)
        before = await _state(db_session, ticket.id)
        assert before is not None
        calls = _forbid(monkeypatch)

        await _set(db_session, ticket.id, actor, CRD)

        assert calls == []
        assert await _state(db_session, ticket.id) == (*before[:4], CRD)
        assert await ticket_events_by_id(db_session, ticket.id) == [
            _changed(actor, None, CRD_TEXT)
        ]


# ---------------------------------------------------------------------------
# Unchanged request
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestNoOp:
    @pytest.mark.parametrize(
        ("stored", "requested"),
        [
            pytest.param(CRD, CRD, id="same-instant"),
            pytest.param(CRD, CRD_CEST, id="same-instant-other-offset"),
            pytest.param(None, None, id="both-null"),
        ],
    )
    async def test_equal_value_writes_nothing(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        stored: datetime | None,
        requested: datetime | None,
    ) -> None:
        actor = await va_user()
        ticket = await ticket_factory(
            is_confidential=True, coordinated_release_at=stored
        )

        with StatementRecorder(db_session) as recorder:
            result = await _set(db_session, ticket.id, actor, requested)

        assert result.id == ticket.id
        assert recorder.writes() == []
        assert await _stored(db_session, ticket.id) == stored
        assert await ticket_events_by_id(db_session, ticket.id) == []


# ---------------------------------------------------------------------------
# Guards and their order, with zero side effects
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestGuards:
    @pytest.mark.parametrize(
        "requested",
        [
            pytest.param(CRD, id="set"),
            pytest.param(None, id="would-be-no-op"),
            pytest.param(TICKET_CREATED_AT - timedelta(days=1), id="before-creation"),
        ],
    )
    async def test_non_confidential_ticket_without_crd_is_rejected_first(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        requested: datetime | None,
    ) -> None:
        """Step 3 precedes steps 4 and 5: a non-confidential Ticket without
        a CRD raises `TicketNotConfidentialError` for every request, `null`
        and an instant before `created_at` included."""
        actor = await va_user()
        ticket = await ticket_factory()

        await _assert_rejected(
            db_session,
            TicketNotConfidentialError,
            ticket_id=ticket.id,
            actor=actor,
            value=requested,
        )

    @pytest.mark.parametrize(
        ("requested", "persisted", "events"),
        [
            pytest.param(LATER, LATER, [(CRD_TEXT, LATER_TEXT)], id="change"),
            pytest.param(None, None, [(CRD_TEXT, None)], id="clear"),
            pytest.param(CRD_CEST, CRD, [], id="no-op"),
        ],
    )
    async def test_crd_retained_on_a_non_confidential_ticket_stays_editable(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        requested: datetime | None,
        persisted: datetime | None,
        events: list[tuple[str | None, str | None]],
    ) -> None:
        """tickets.md, Coordinated Release Date: a CRD that a
        declassification retains can be changed or cleared, with one event
        per effective change; an unchanged request is a no-op."""
        actor = await va_user()
        ticket = await ticket_factory(coordinated_release_at=CRD)

        await _set(db_session, ticket.id, actor, requested)

        assert await _stored(db_session, ticket.id) == persisted
        assert await ticket_events_by_id(db_session, ticket.id) == [
            _changed(actor, old, new) for old, new in events
        ]

    async def test_declassified_ticket_keeps_its_crd_editable_until_cleared(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
    ) -> None:
        """Declassification through the service retains the CRD, which can
        then be changed and cleared; once cleared, the non-confidential
        Ticket cannot receive another until it is confidential again."""
        actor = await va_user()
        ticket = await ticket_factory(is_confidential=True, coordinated_release_at=CRD)
        caller = TicketCaller.authenticated(actor.id, Scope.ALL)
        common: dict[str, Any] = {
            "ticket_id": ticket.id,
            "acting_user_id": actor.id,
            "caller": caller,
        }

        await set_confidentiality(db_session, is_confidential=False, **common)
        assert await _stored(db_session, ticket.id) == CRD
        await _set(db_session, ticket.id, actor, LATER)
        await _set(db_session, ticket.id, actor, None)
        with pytest.raises(TicketNotConfidentialError):
            await _set(db_session, ticket.id, actor, CRD)
        await set_confidentiality(db_session, is_confidential=True, **common)
        await _set(db_session, ticket.id, actor, CRD)

        assert await _stored(db_session, ticket.id) == CRD
        assert [
            (e.event_type, e.old_value, e.new_value)
            for e in await ticket_events_by_id(db_session, ticket.id)
        ] == [
            ("confidentiality_changed", "true", "false"),
            ("coordinated_release_changed", CRD_TEXT, LATER_TEXT),
            ("coordinated_release_changed", LATER_TEXT, None),
            ("confidentiality_changed", "false", "true"),
            ("coordinated_release_changed", None, CRD_TEXT),
        ]

    @pytest.mark.parametrize(
        ("confidential", "stored"),
        [
            pytest.param(True, None, id="confidential-set"),
            pytest.param(True, CRD, id="confidential-change"),
            pytest.param(False, CRD, id="retained-change"),
        ],
    )
    async def test_instant_before_created_at_is_rejected(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        confidential: bool,
        stored: datetime | None,
    ) -> None:
        """Step 4: one microsecond before the locked `created_at` raises
        `CoordinatedReleaseBeforeCreationError` with no effect."""
        actor = await va_user()
        ticket = await ticket_factory(
            is_confidential=confidential, coordinated_release_at=stored
        )

        await _assert_rejected(
            db_session,
            CoordinatedReleaseBeforeCreationError,
            ticket_id=ticket.id,
            actor=actor,
            value=TICKET_CREATED_AT - timedelta(microseconds=1),
        )

    async def test_instant_equal_to_created_at_is_accepted(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
    ) -> None:
        actor = await va_user()
        ticket = await ticket_factory(is_confidential=True)

        await _set(db_session, ticket.id, actor, TICKET_CREATED_AT)

        assert await _stored(db_session, ticket.id) == TICKET_CREATED_AT
        assert await ticket_events_by_id(db_session, ticket.id) == [
            _changed(actor, None, "2001-01-01T09:00:00Z")
        ]

    async def test_created_at_loaded_by_the_lock_is_compared(
        self,
        db_session: AsyncSession,
        va_user: VAUser,
    ) -> None:
        """A Ticket created in the same session through the service, whose
        server-generated `created_at` is not loaded yet, is still compared
        with its persisted creation instant."""
        actor = await va_user()
        ticket = await ticket_service.create_ticket(
            db_session,
            acting_user_id=actor.id,
            is_confidential=True,
            source=ticket_service.TicketCreationSource.MANUAL,
        )

        with pytest.raises(CoordinatedReleaseBeforeCreationError):
            await _set(db_session, ticket.id, actor, CRD)

    async def test_missing_ticket_is_not_found(
        self, db_session: AsyncSession, va_user: VAUser
    ) -> None:
        actor = await va_user()

        await _assert_rejected(
            db_session,
            TicketNotFoundError,
            ticket_id=uuid.uuid7(),
            actor=actor,
            value=CRD,
        )

    @pytest.mark.parametrize(
        "requested",
        [
            pytest.param(LATER, id="would-be-effective"),
            pytest.param(CRD, id="would-be-no-op"),
        ],
    )
    async def test_inaccessible_ticket_is_not_found_before_any_other_decision(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_access_grant_factory: GrantFactory,
        va_user: VAUser,
        requested: datetime,
    ) -> None:
        """Step 2: a `non_confidential`-scope caller whose Ticket's only
        grant belongs to another user."""
        actor = await va_user()
        ticket = await ticket_factory(is_confidential=True, coordinated_release_at=CRD)
        await ticket_access_grant_factory(ticket_id=ticket.id)

        await _assert_rejected(
            db_session,
            TicketNotFoundError,
            ticket_id=ticket.id,
            actor=actor,
            value=requested,
            scope=Scope.NON_CONFIDENTIAL,
        )

    @pytest.mark.parametrize("case", ["naive-instant", "caller-mismatch"])
    async def test_value_error_before_any_statement(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        case: str,
    ) -> None:
        actor = await va_user()
        other = await va_user()
        ticket = await ticket_factory(is_confidential=True)
        naive = case == "naive-instant"

        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(
                ValueError, match="timezone-aware" if naive else "acting user"
            ),
        ):
            await set_coordinated_release_date(
                db_session,
                ticket_id=ticket.id,
                coordinated_release_at=CRD.replace(tzinfo=None) if naive else CRD,
                acting_user_id=actor.id,
                caller=TicketCaller.authenticated(
                    actor.id if naive else other.id, Scope.ALL
                ),
            )

        assert recorder.statements == []
        assert await _stored(db_session, ticket.id) is None
        assert await ticket_events_by_id(db_session, ticket.id) == []


# ---------------------------------------------------------------------------
# Locking
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestLocking:
    async def test_only_the_ticket_is_locked_before_the_visibility_statement(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_access_grant_factory: GrantFactory,
        va_user: VAUser,
    ) -> None:
        """Step 1: the Ticket `FOR UPDATE` is the first statement and the
        only row lock; the locked-current visibility statement follows. No
        User row is locked or read, and no audit history is read."""
        actor = await va_user(roles=(Role.RESTRICTED_ANALYST,))
        ticket = await ticket_factory(is_confidential=True)
        await ticket_access_grant_factory(ticket_id=ticket.id, user_id=actor.id)

        with StatementRecorder(db_session) as recorder:
            await _set(db_session, ticket.id, actor, CRD, scope=Scope.NON_CONFIDENTIAL)

        statements = recorder.statements
        assert "FROM ticket" in statements[0]
        assert "FOR UPDATE" in statements[0]
        assert list(recorder.parameters[0]) == [ticket.id]
        assert "ticket_access_grant" in statements[1]
        assert recorder.row_locks() == [statements[0]]
        assert [s for s in statements if 'FROM "user"' in s] == []
        assert recorder.selects_from("ticket_audit_event") == []


# ---------------------------------------------------------------------------
# Rollback (audit Testing Requirement 7) and no commit
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestRollback:
    @pytest.mark.parametrize("failure", ["audit", "flush", "caller"])
    async def test_failure_or_caller_rollback_leaves_neither_value_nor_event(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
        failure: str,
    ) -> None:
        """A change of a stored CRD fails at its audit write or at the
        flush inserting the event, or succeeds and is rolled back by the
        caller: the stored value is the original and no event exists."""
        actor = await va_user()
        ticket = await ticket_factory(is_confidential=True, coordinated_release_at=CRD)
        ticket_id = ticket.id
        reached = False
        original_log = TicketAuditLog.log_event
        original_flush = db_session.flush

        async def failing_log(*args: Any, **kwargs: Any) -> None:
            nonlocal reached
            if kwargs["event_type"] is TicketAuditEventType.COORDINATED_RELEASE_CHANGED:
                reached = True
                raise RuntimeError("injected audit failure")
            await original_log(*args, **kwargs)

        async def failing_flush(*args: Any, **kwargs: Any) -> None:
            nonlocal reached
            if any(isinstance(o, TicketAuditEvent) for o in db_session.new):
                reached = True
                raise RuntimeError("injected flush failure")
            await original_flush(*args, **kwargs)

        async with rollback_test_scope(db_session):
            if failure == "caller":
                await _set(db_session, ticket_id, actor, LATER)
                reached = await _stored(db_session, ticket_id) == LATER
            else:
                if failure == "audit":
                    monkeypatch.setattr(TicketAuditLog, "log_event", failing_log)
                else:
                    monkeypatch.setattr(db_session, "flush", failing_flush)
                with pytest.raises(RuntimeError, match="injected"):
                    await _set(db_session, ticket_id, actor, LATER)
        monkeypatch.undo()

        assert reached
        assert await _stored(db_session, ticket_id) == CRD
        assert await ticket_events_by_id(db_session, ticket_id) == []

    async def test_never_commits(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        actor = await va_user()
        ticket = await ticket_factory(is_confidential=True)

        async def forbidden() -> None:
            raise AssertionError("set_coordinated_release_date() must not commit")

        monkeypatch.setattr(db_session, "commit", forbidden)
        monkeypatch.setattr(db_session, "rollback", forbidden)

        await _set(db_session, ticket.id, actor, CRD)


# ---------------------------------------------------------------------------
# Informational only (tickets.md, Coordinated Release Date;
# ticket-deadlines.md, Testing Requirement 3)
# ---------------------------------------------------------------------------

CREATED_AT = datetime(2026, 9, 26, 10, 15, 30, tzinfo=UTC)
DETAIL_INSTANT = datetime(2026, 9, 27, 12, 0, tzinfo=UTC)
"""The projection's controlled evaluation instant: before every due date."""


@pytest.mark.integration
class TestInformational:
    async def test_crd_alters_no_status_gate_eligibility_deadline_or_visibility(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_access_grant_factory: GrantFactory,
        ticket_package_maintainer_factory: Callable[
            ..., Awaitable[TicketPackageMaintainer]
        ],
        va_user: VAUser,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A confidential CVE-less `High` `Analysis` Ticket whose persisted
        state is deliberately stale: its `AFFECTED` track would gate to
        `Analyzed`, and its Product is persisted eligible although in
        Reactive Support. Setting a later CRD, one equal to `created_at`,
        and clearing it changes neither the status, the Product
        eligibility, the assignee, the priority, `created_at`, nor the
        predicate for a maintainer, a grantee, and an outsider; only the
        due dates follow the deadline window (ticket-deadlines.md,
        Coordinated Release Window), back to +3, +18, +21, +30, +30 days
        after the clear."""
        monkeypatch.setattr(ticket_service, "_utc_now", lambda: DETAIL_INSTANT)
        actor = await va_user()
        owner = await va_user()
        maintainer = await va_user(roles=())
        grantee = await va_user(roles=())
        outsider = await va_user(roles=())
        ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value,
            severity_manual=Severity.HIGH.value,
            created_at=CREATED_AT,
            assignee_id=owner.id,
            is_confidential=True,
        )
        track = await tree(
            ticket,
            status=PackageStatus.AFFECTED,
            products=(Prod(eligible=True, reactive=True),),
        )
        package_id = (
            await db_session.execute(
                select(TicketPackage.id).where(TicketPackage.ticket_id == ticket.id)
            )
        ).scalar_one()
        assert track.ticket_package_id == package_id
        await ticket_package_maintainer_factory(
            ticket_package_id=package_id, user_id=maintainer.id
        )
        await ticket_access_grant_factory(ticket_id=ticket.id, user_id=grantee.id)

        async def snapshot() -> tuple[Any, ...]:
            detail = await assemble_ticket_detail(
                db_session, ticket_id=ticket.id, evaluation_date=EVAL
            )
            return (
                detail.status,
                detail.assignee.id if detail.assignee is not None else None,
                detail.priority,
                detail.is_confidential,
                detail.created_at,
                detail.due_dates,
                await eligibility(db_session, ticket.id),
                [
                    await _visible(db_session, ticket.id, user)
                    for user in (maintainer, grantee, outsider)
                ],
            )

        def window(end: datetime) -> DueDates:
            triage, submission, um, qa, release = (
                CREATED_AT + offset for offset in crd_window_offsets(end - CREATED_AT)
            )
            return DueDates(
                triage=triage, submission=submission, um=um, qa=qa, release=release
            )

        sla = DueDates(
            triage=CREATED_AT + timedelta(days=3),
            submission=CREATED_AT + timedelta(days=18),
            um=CREATED_AT + timedelta(days=21),
            qa=CREATED_AT + timedelta(days=30),
            release=CREATED_AT + timedelta(days=30),
        )
        before = await snapshot()
        assert before[0] == TicketStatus.ANALYSIS
        assert before[1] == owner.id
        assert before[4] == CREATED_AT
        assert before[5] == sla
        assert before[6] == [(True, False)]
        assert before[7] == [True, True, False]
        calls = _forbid(monkeypatch)

        for value, due_dates in (
            (LATER, window(LATER)),
            (CREATED_AT, window(CREATED_AT)),
            (None, sla),
        ):
            await _set(db_session, ticket.id, actor, value)
            after = await snapshot()
            assert after[5] == due_dates
            assert after[:5] + after[6:] == before[:5] + before[6:]

        assert calls == []
