"""Unit tests for the pure assignment eligibility predicate
(backend/app/services/assignment_eligibility.py) and for the explicit
assignment exception that carries its failing condition.

Owning specifications:

- docs/features/identity/rbac.md (Business Rule 10, Assignment
  eligibility; Predefined Roles).
- docs/features/tickets/ticket-audit-log.md (Canonical Automatic Comment
  Vocabulary: the condition precedence).
- docs/features/tickets/ticket-service.md (`assign_ticket` step 5; Service
  Exceptions: `AssigneeNotEligibleError`).

Expected values are transcribed from the specifications; nothing here
computes an expectation with the module under test.
"""

from __future__ import annotations

import itertools

import pytest

from app.core.enums import Role
from app.services.assignment_eligibility import (
    AssigneeIneligibility,
    assignee_ineligibility,
)
from app.services.ticket_service import AssigneeNotEligibleError
from tests.support.module_imports import APP_ROOT, imported_modules

_VA = Role.VULNERABILITY_ANALYST
_RA = Role.RESTRICTED_ANALYST
_ADMIN = Role.ADMIN

# rbac.md, Business Rule 10, with the predefined roles: `vulnerability_analyst`
# grants `triage_ticket` and scope `all`; `restricted_analyst` grants
# `triage_ticket` and scope `non_confidential`; `admin` grants no
# `triage_ticket` and scope `all`.
_ROLE_SETS: dict[tuple[Role, ...], tuple[bool, bool]] = {
    (): (False, False),
    (_ADMIN,): (False, False),
    (_RA,): (True, False),
    (_VA,): (True, True),
    (_ADMIN, _RA): (True, True),
    (_ADMIN, _VA): (True, True),
    (_RA, _VA): (True, True),
    (_ADMIN, _RA, _VA): (True, True),
}
"""Role set -> (eligible for a public Ticket, eligible for a confidential
Ticket), for an active non-bot user."""


@pytest.mark.unit
class TestPredefinedRoles:
    @pytest.mark.parametrize(
        "roles", list(_ROLE_SETS), ids=lambda roles: "+".join(roles) or "no-role"
    )
    @pytest.mark.parametrize(
        "confidential", [False, True], ids=["public", "confidential"]
    )
    def test_active_non_bot_user_follows_capability_and_scope(
        self, roles: tuple[Role, ...], confidential: bool
    ) -> None:
        eligible = _ROLE_SETS[roles][confidential]
        expected = (
            None
            if eligible
            else (
                AssigneeIneligibility.NO_TRIAGE_TICKET
                if not _ROLE_SETS[roles][False]
                else AssigneeIneligibility.CONFIDENTIAL
            )
        )

        assert (
            assignee_ineligibility(
                active=True, bot=False, roles=roles, is_confidential=confidential
            )
            is expected
        )

    @pytest.mark.parametrize(
        "roles", list(_ROLE_SETS), ids=lambda r: "+".join(r) or "-"
    )
    @pytest.mark.parametrize("confidential", [False, True])
    def test_bot_account_is_never_eligible_whatever_its_roles(
        self, roles: tuple[Role, ...], confidential: bool
    ) -> None:
        assert (
            assignee_ineligibility(
                active=True, bot=True, roles=roles, is_confidential=confidential
            )
            is AssigneeIneligibility.BOT
        )

    @pytest.mark.parametrize(
        ("bot", "roles", "confidential"),
        list(itertools.product([False, True], list(_ROLE_SETS), [False, True])),
    )
    def test_inactive_user_is_never_eligible_and_fails_inactive_first(
        self, bot: bool, roles: tuple[Role, ...], confidential: bool
    ) -> None:
        assert (
            assignee_ineligibility(
                active=False, bot=bot, roles=roles, is_confidential=confidential
            )
            is AssigneeIneligibility.INACTIVE
        )

    def test_repeated_origins_of_one_role_are_one_role(self) -> None:
        assert (
            assignee_ineligibility(
                active=True, bot=False, roles=[_RA, _RA], is_confidential=True
            )
            is AssigneeIneligibility.CONFIDENTIAL
        )

    def test_roles_may_be_any_iterable(self) -> None:
        assert (
            assignee_ineligibility(
                active=True, bot=False, roles=iter([_VA]), is_confidential=True
            )
            is None
        )


@pytest.mark.unit
class TestConditionOrder:
    def test_members_follow_the_canonical_precedence(self) -> None:
        """ticket-audit-log.md: inactive, then bot account, then no
        `triage_ticket`, then confidential without scope `all`."""
        assert list(AssigneeIneligibility) == [
            AssigneeIneligibility.INACTIVE,
            AssigneeIneligibility.BOT,
            AssigneeIneligibility.NO_TRIAGE_TICKET,
            AssigneeIneligibility.CONFIDENTIAL,
        ]


@pytest.mark.unit
class TestModuleBoundary:
    def test_imports_only_core(self) -> None:
        """The predicate is shared by `ticket_mutations` and `user_service`
        without either importing the other: it imports only Core."""
        modules = imported_modules(
            APP_ROOT / "services" / "assignment_eligibility.py", "app.services"
        )

        assert {m for m in modules if m.startswith("app.")} <= {
            "app.core.enums",
            "app.core.permissions",
        }
        assert {m.split(".")[0] for m in modules} <= {
            "__future__",
            "collections",
            "enum",
            "app",
        }


@pytest.mark.unit
class TestAssigneeNotEligibleError:
    @pytest.mark.parametrize(
        ("condition", "message"),
        [
            (AssigneeIneligibility.BOT, "Assignee is a bot account."),
            (
                AssigneeIneligibility.NO_TRIAGE_TICKET,
                "Assignee lacks the triage_ticket capability.",
            ),
            (
                AssigneeIneligibility.CONFIDENTIAL,
                "Assignee cannot be assigned a confidential Ticket.",
            ),
        ],
    )
    def test_carries_the_condition_and_a_static_message(
        self, condition: AssigneeIneligibility, message: str
    ) -> None:
        error = AssigneeNotEligibleError(condition)

        assert error.condition is condition
        assert str(error) == message

    def test_inactive_is_not_a_condition_of_this_error(self) -> None:
        """ticket-service.md, `assign_ticket` step 5: an inactive target
        raises `AssigneeInactiveError` instead."""
        with pytest.raises(ValueError, match="AssigneeInactiveError"):
            AssigneeNotEligibleError(AssigneeIneligibility.INACTIVE)
