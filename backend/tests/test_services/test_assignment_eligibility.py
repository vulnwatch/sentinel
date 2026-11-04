"""Unit tests for the pure assignment eligibility predicate and its
reported outcome (backend/app/services/assignment_eligibility.py) and for
the explicit assignment exception that carries its failing condition.

Owning specifications:

- docs/features/identity/rbac.md (Business Rule 10, Assignment
  eligibility; Assignment Eligibility Wire Format; Predefined Roles).
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

from app.core.enums import AssignmentEligibility, Capability, Role, Scope
from app.core.permissions import ROLE_CAPABILITIES, ROLE_SCOPES
from app.services.assignment_eligibility import (
    SCOPE_ALL_ROLES,
    TRIAGE_TICKET_ROLES,
    AssigneeIneligibility,
    assignee_ineligibility,
    assignment_eligibility,
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

_ALL_ROLE_SUBSETS: list[tuple[Role, ...]] = [
    subset
    for size in range(len(Role) + 1)
    for subset in itertools.combinations(sorted(Role), size)
]
"""Every subset of `Role`, the empty one included, in the key order of
`_ROLE_SETS`."""


def _expected_eligibility(
    *, active: bool, bot: bool, roles: tuple[Role, ...]
) -> AssignmentEligibility:
    """rbac.md, Assignment Eligibility Wire Format, Derivation, applied to
    the transcribed `_ROLE_SETS` table."""
    public, confidential = _ROLE_SETS[roles]
    if not active or bot or not public:
        return AssignmentEligibility.NONE
    if confidential:
        return AssignmentEligibility.ALL
    return AssignmentEligibility.NON_CONFIDENTIAL


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
class TestAssignmentEligibility:
    def test_the_role_table_covers_every_subset_of_role(self) -> None:
        assert set(_ALL_ROLE_SUBSETS) == set(_ROLE_SETS)

    @pytest.mark.parametrize(
        "roles", _ALL_ROLE_SUBSETS, ids=lambda roles: "+".join(roles) or "no-role"
    )
    @pytest.mark.parametrize("bot", [False, True], ids=["human", "bot"])
    @pytest.mark.parametrize("active", [True, False], ids=["active", "inactive"])
    def test_reports_the_derivation_for_every_role_combination(
        self, roles: tuple[Role, ...], bot: bool, active: bool
    ) -> None:
        expected = _expected_eligibility(active=active, bot=bot, roles=roles)

        assert assignment_eligibility(active=active, bot=bot, roles=roles) is expected

    @pytest.mark.parametrize(
        "roles", _ALL_ROLE_SUBSETS, ids=lambda roles: "+".join(roles) or "no-role"
    )
    @pytest.mark.parametrize("bot", [False, True], ids=["human", "bot"])
    @pytest.mark.parametrize("active", [True, False], ids=["active", "inactive"])
    def test_agrees_with_the_predicate_for_both_kinds_of_ticket(
        self, roles: tuple[Role, ...], bot: bool, active: bool
    ) -> None:
        """The value states exactly which Tickets Business Rule 10 admits:
        `all` admits both kinds, `non_confidential` only the public one,
        `none` neither."""
        value = assignment_eligibility(active=active, bot=bot, roles=roles)
        admits = {
            confidential: assignee_ineligibility(
                active=active, bot=bot, roles=roles, is_confidential=confidential
            )
            is None
            for confidential in (False, True)
        }

        assert admits == {
            False: value is not AssignmentEligibility.NONE,
            True: value is AssignmentEligibility.ALL,
        }

    @pytest.mark.parametrize(
        ("roles", "expected"),
        [
            ([_RA, _RA], AssignmentEligibility.NON_CONFIDENTIAL),
            ([_VA, _VA, _RA], AssignmentEligibility.ALL),
            ([_ADMIN, _ADMIN], AssignmentEligibility.NONE),
            ([_RA, _ADMIN, _RA, _ADMIN], AssignmentEligibility.ALL),
        ],
        ids=["ra-twice", "va-twice-ra", "admin-twice", "ra-admin-interleaved"],
    )
    def test_repeated_origins_of_one_role_are_one_role(
        self, roles: list[Role], expected: AssignmentEligibility
    ) -> None:
        assert assignment_eligibility(active=True, bot=False, roles=roles) is expected

    def test_roles_may_be_a_single_use_iterator(self) -> None:
        """The roles are consumed once for both Ticket kinds."""
        assert (
            assignment_eligibility(active=True, bot=False, roles=iter([_RA, _ADMIN]))
            is AssignmentEligibility.ALL
        )
        assert (
            assignment_eligibility(
                active=True, bot=False, roles=(role for role in [_RA])
            )
            is AssignmentEligibility.NON_CONFIDENTIAL
        )

    def test_values_are_exactly_the_wire_values(self) -> None:
        assert [value.value for value in AssignmentEligibility] == [
            "all",
            "non_confidential",
            "none",
        ]


@pytest.mark.unit
class TestRoleSetConstants:
    def test_triage_ticket_roles_are_the_analyst_roles(self) -> None:
        assert frozenset({_VA, _RA}) == TRIAGE_TICKET_ROLES

    def test_scope_all_roles_are_admin_and_vulnerability_analyst(self) -> None:
        assert frozenset({_ADMIN, _VA}) == SCOPE_ALL_ROLES

    def test_triage_ticket_roles_follow_the_role_capabilities(self) -> None:
        assert (
            frozenset(
                role
                for role, capabilities in ROLE_CAPABILITIES.items()
                if Capability.TRIAGE_TICKET in capabilities
            )
            == TRIAGE_TICKET_ROLES
        )

    def test_scope_all_roles_follow_the_role_scopes(self) -> None:
        assert (
            frozenset(role for role, scope in ROLE_SCOPES.items() if scope is Scope.ALL)
            == SCOPE_ALL_ROLES
        )

    def test_every_role_is_classified(self) -> None:
        """Both recomputations above range over every `Role`."""
        assert set(ROLE_CAPABILITIES) == set(Role) == set(ROLE_SCOPES)


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
        without either importing the other: it imports only Core and the
        standard library."""
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
            "typing",
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
