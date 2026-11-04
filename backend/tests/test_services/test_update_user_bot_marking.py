"""Single-session tests of the Ticket unassignment that a change of the bot
marker to `true` triggers in `user_service.update_user()`
(backend/app/services/user_service.py).

Owning specifications:

- docs/features/identity/user-service.md (`update_user()` steps 1 and 6,
  TicketAuditEvent, Transactionality; Private Helpers,
  `_unassign_active_tickets()`).
- docs/features/identity/rbac.md (Business Rule 10: a bot account is never
  eligible to be a Ticket assignee).
- docs/features/identity/user-management.md (Bot Accounts).
- docs/features/identity/identity-audit-log.md (Ticket `assignment` events
  before the call's field-change events).
- docs/conventions.md (Cross-Domain Root Lock Order: the Tickets are locked
  before a `username` or `email` write).
- docs/features/platform/testing-strategy.md (User Lifecycle and
  Management: the bot marker bullets and the `update_user()` lock bullet).

The independent-session races live in
`test_bot_marking_assignment_races.py`. Expected values are transcribed
from the specifications; nothing here computes an expectation with the
module under test.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import IdentityAuditEventType, Role, TicketStatus
from app.models.identity_audit_event import IdentityAuditEvent
from app.models.ticket import Ticket
from app.models.ticket_audit_event import TicketAuditEvent
from app.models.user import User
from app.models.user_role import UserRole
from app.services.identity_audit_log import IdentityAuditLog
from app.services.ticket_audit_log import TicketAuditLog
from app.services.user_service import UserConflictError, update_user
from tests.support.database import rollback_test_scope
from tests.support.ticket_mutations import StatementRecorder

UserFactory = Callable[..., Awaitable[User]]
UserRoleFactory = Callable[..., Awaitable[UserRole]]
TicketFactory = Callable[..., Awaitable[Ticket]]

BOT_ACCOUNT = "bot account"
"""The unassignment reason of bot marking (ticket-audit-log.md, Canonical
Automatic Comment Vocabulary)."""


def _ordered_ids(count: int) -> list[uuid.UUID]:
    """`count` fresh Ticket UUIDs in ascending order."""
    return sorted(uuid.uuid4() for _ in range(count))


async def _states(
    db: AsyncSession, ids: list[uuid.UUID]
) -> dict[uuid.UUID, tuple[str, uuid.UUID | None]]:
    rows = await db.execute(
        select(Ticket.id, Ticket.status, Ticket.assignee_id).where(Ticket.id.in_(ids))
    )
    return {row.id: (row.status, row.assignee_id) for row in rows}


async def _ticket_events(
    db: AsyncSession, ids: list[uuid.UUID]
) -> list[tuple[uuid.UUID, str, uuid.UUID | None, str | None, str | None, str | None]]:
    rows = (
        await db.execute(
            select(TicketAuditEvent)
            .where(TicketAuditEvent.ticket_id.in_(ids))
            .order_by(TicketAuditEvent.id)
        )
    ).scalars()
    return [
        (r.ticket_id, r.event_type, r.user_id, r.old_value, r.new_value, r.comment)
        for r in rows
    ]


async def _identity_events(db: AsyncSession, user_id: uuid.UUID) -> list[str]:
    rows = (
        await db.execute(
            select(IdentityAuditEvent.event_type)
            .where(IdentityAuditEvent.target_user_id == user_id)
            .order_by(IdentityAuditEvent.id)
        )
    ).scalars()
    return list(rows)


def _cleared(
    ticket_id: uuid.UUID, username: str
) -> tuple[uuid.UUID, str, None, str, None, str]:
    """The system unassignment of bot marking (user-service.md,
    `update_user()` TicketAuditEvent)."""
    return (
        ticket_id,
        "assignment",
        None,
        username,
        None,
        f"Unassigned from {username}: {BOT_ACCOUNT}",
    )


def _index(statements: list[str], predicate: Callable[[str], bool]) -> int:
    return next(i for i, s in enumerate(statements) if predicate(s))


def _is_ticket_lock(statement: str) -> bool:
    return "FROM ticket" in statement and statement.rstrip().endswith("FOR UPDATE")


def _is_user_write(statement: str) -> bool:
    return statement.lstrip().startswith('UPDATE "user"')


@pytest.mark.integration
class TestBotMarkingUnassignment:
    async def test_marking_clears_every_active_status_assignment(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
        user_role_factory: UserRoleFactory,
        ticket_factory: TicketFactory,
    ) -> None:
        """user-service.md, `update_user()` step 6 and
        `_unassign_active_tickets()`: a bot account is eligible for no
        Ticket, so every `New`, `Analysis`, and `Analyzed` assignment is
        cleared, confidential or not, with one system `assignment` event
        each in Ticket UUID order; `Resolved`, `Ignored`, and `Duplicated`
        keep the assignee. No status changes."""
        admin = await user_factory(username="alice.admin")
        target = await user_factory(username="bob.va")
        await user_role_factory(
            user_id=target.id, role=Role.VULNERABILITY_ANALYST.value
        )
        ids = _ordered_ids(7)
        tickets = {
            ids[0]: (TicketStatus.RESOLVED, False),
            ids[1]: (TicketStatus.ANALYZED, True),
            ids[2]: (TicketStatus.IGNORED, False),
            ids[3]: (TicketStatus.NEW, False),
            ids[4]: (TicketStatus.DUPLICATED, False),
            ids[5]: (TicketStatus.ANALYSIS, False),
            ids[6]: (TicketStatus.ANALYSIS, True),
        }
        for ticket_id in reversed(ids):
            status, confidential = tickets[ticket_id]
            await ticket_factory(
                id=ticket_id,
                status=status.value,
                assignee_id=target.id,
                is_confidential=confidential,
            )

        result = await update_user(
            db_session, target.id, acting_user_id=admin.id, bot=True
        )

        assert result.changed_fields == ["bot"]
        assert result.user.bot is True
        assert await _states(db_session, ids) == {
            ids[0]: ("Resolved", target.id),
            ids[1]: ("Analyzed", None),
            ids[2]: ("Ignored", target.id),
            ids[3]: ("New", None),
            ids[4]: ("Duplicated", target.id),
            ids[5]: ("Analysis", None),
            ids[6]: ("Analysis", None),
        }
        assert await _ticket_events(db_session, ids) == [
            _cleared(ids[1], "bob.va"),
            _cleared(ids[3], "bob.va"),
            _cleared(ids[5], "bob.va"),
            _cleared(ids[6], "bob.va"),
        ]
        assert await _identity_events(db_session, target.id) == [
            IdentityAuditEventType.BOT_CHANGED.value
        ]

    async def test_ticket_events_precede_the_field_change_events(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
        ticket_factory: TicketFactory,
    ) -> None:
        """identity-audit-log.md: the derived Ticket `assignment` events
        are created before the call's field-change events."""
        target = await user_factory(username="bob.va")
        ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value, assignee_id=target.id
        )

        with StatementRecorder(db_session) as recorder:
            await update_user(
                db_session,
                target.id,
                acting_user_id=None,
                full_name="Bob Scanner",
                bot=True,
            )

        inserts = [s for s in recorder.statements if s.lstrip().startswith("INSERT")]
        assert ["ticket_audit_event" in s for s in inserts] == [True, False, False]
        assert all("identity_audit_event" in s for s in inserts[1:])
        assert await _ticket_events(db_session, [ticket.id]) == [
            _cleared(ticket.id, "bob.va")
        ]

    async def test_user_lock_then_ticket_locks_then_user_write(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
        ticket_factory: TicketFactory,
    ) -> None:
        """user-service.md, `update_user()` steps 1 and 6;
        `docs/conventions.md`, Cross-Domain Root Lock Order: the User is
        locked `FOR NO KEY UPDATE` first, and the Tickets are locked before
        the User row is written, so a `username` or `email` write cannot
        deadlock with the foreign-key validation of a Ticket holder. The
        event records the username before the update."""
        target = await user_factory(username="bob.va", email="bob.va@example.com")
        ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value, assignee_id=target.id
        )

        with StatementRecorder(db_session) as recorder:
            result = await update_user(
                db_session,
                target.id,
                acting_user_id=None,
                username="bob.scanner",
                email="bob.scanner@example.com",
                bot=True,
            )

        statements = recorder.statements
        assert statements[0].rstrip().endswith("FOR NO KEY UPDATE")
        assert 'FROM "user"' in statements[0]
        assert _index(statements, _is_ticket_lock) < _index(statements, _is_user_write)
        assert result.changed_fields == ["username", "email", "bot"]
        assert await _ticket_events(db_session, [ticket.id]) == [
            _cleared(ticket.id, "bob.va")
        ]

    async def test_unmarking_restores_no_assignment(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
        ticket_factory: TicketFactory,
    ) -> None:
        """user-management.md, Bot Accounts: a change of the marker to
        `false` unassigns nothing and restores no assignment."""
        target = await user_factory(username="bob.va")
        ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value, assignee_id=target.id
        )
        await update_user(db_session, target.id, acting_user_id=None, bot=True)

        with StatementRecorder(db_session) as recorder:
            result = await update_user(
                db_session, target.id, acting_user_id=None, bot=False
            )

        assert result.changed_fields == ["bot"]
        assert not any("ticket" in s for s in recorder.statements)
        assert await _states(db_session, [ticket.id]) == {ticket.id: ("Analysis", None)}
        assert await _ticket_events(db_session, [ticket.id]) == [
            _cleared(ticket.id, "bob.va")
        ]

    @pytest.mark.parametrize(
        ("stored", "fields"),
        [
            pytest.param(False, {"full_name": "Bob Renamed"}, id="other-field"),
            pytest.param(True, {"bot": True}, id="already-a-bot"),
            pytest.param(True, {"email": "bob.other@example.com"}, id="bot-renamed"),
        ],
    )
    async def test_no_change_to_true_issues_no_ticket_statement(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
        ticket_factory: TicketFactory,
        stored: bool,
        fields: dict[str, Any],
    ) -> None:
        """Only an effective `false` to `true` change of the marker
        unassigns; an anomalously assigned bot account keeps its
        assignment until such a change or reconciliation sanitation."""
        target = await user_factory(username="bob.va", bot=stored)
        ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value, assignee_id=target.id
        )

        with StatementRecorder(db_session) as recorder:
            await update_user(db_session, target.id, acting_user_id=None, **fields)

        assert not any("ticket" in s for s in recorder.statements)
        assert await _states(db_session, [ticket.id]) == {
            ticket.id: ("Analysis", target.id)
        }

    async def test_external_provisioning_marking_unassigns_like_a_manual_one(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
        ticket_factory: TicketFactory,
    ) -> None:
        """identity-provisioning.md (Concurrency): a provider change of the
        marker to `true` unassigns the User like a manual one."""
        target = await user_factory(username="bob.sync", external_id=uuid.uuid4())
        ticket = await ticket_factory(
            status=TicketStatus.ANALYZED.value, assignee_id=target.id
        )

        await update_user(db_session, target.id, acting_user_id=None, bot=True)

        assert await _ticket_events(db_session, [ticket.id]) == [
            _cleared(ticket.id, "bob.sync")
        ]

    async def test_conflict_raises_before_any_ticket_statement(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
        ticket_factory: TicketFactory,
    ) -> None:
        """user-service.md, `update_user()`: the uniqueness pre-check
        precedes the unassignment, so a rejected call changes no Ticket."""
        await user_factory(email="taken@example.com")
        target = await user_factory(username="bob.va")
        ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value, assignee_id=target.id
        )

        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(UserConflictError),
        ):
            await update_user(
                db_session,
                target.id,
                acting_user_id=None,
                email="taken@example.com",
                bot=True,
            )

        assert not any("ticket" in s for s in recorder.statements)
        assert await _states(db_session, [ticket.id]) == {
            ticket.id: ("Analysis", target.id)
        }


@pytest.mark.integration
class TestBotMarkingRollback:
    @pytest.mark.parametrize("trail", ["ticket", "identity"])
    async def test_audit_failure_rolls_back_both_domains(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
        ticket_factory: TicketFactory,
        monkeypatch: pytest.MonkeyPatch,
        trail: str,
    ) -> None:
        """user-service.md, Transactionality: the Ticket unassignment of a
        change of `bot` to `true` and its events belong to the same unit as
        the marker and `bot_changed`; a failure of either audit trail rolls
        back everything."""
        target = await user_factory(username="bob.va")
        target_id = target.id
        ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value, assignee_id=target_id
        )
        ticket_id = ticket.id

        async def _fail(*args: Any, **kwargs: Any) -> None:
            raise ValueError("simulated audit failure")

        audit = TicketAuditLog if trail == "ticket" else IdentityAuditLog
        monkeypatch.setattr(audit, "log_event", _fail)

        with pytest.raises(ValueError, match="simulated audit failure"):
            async with rollback_test_scope(db_session):
                await update_user(db_session, target_id, acting_user_id=None, bot=True)
        monkeypatch.undo()

        assert await _states(db_session, [ticket_id]) == {
            ticket_id: ("Analysis", target_id)
        }
        assert await _ticket_events(db_session, [ticket_id]) == []
        assert await _identity_events(db_session, target_id) == []
        bot = await db_session.scalar(select(User.bot).where(User.id == target_id))
        assert bot is False
