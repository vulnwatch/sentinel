"""Pure assignment eligibility predicate.

The one shared implementation of `docs/features/identity/rbac.md`,
Business Rule 10 (Assignment eligibility): a user can be the assignee of a
Ticket exactly when the user is active, is not a bot account, holds the
`triage_ticket` capability through their roles, and, for a confidential
Ticket, has effective scope `all`. Capabilities and scope are resolved
from the roles of every origin through `app.core.permissions`; the rule
names no role, so a new role obtains eligibility from its capabilities and
scope alone.

Every assignment path (explicit assignment, manual creation,
auto-assignment, and the embedded assignment of reopen and
revert-duplicate), the assignee eligibility observation shared by
reconciliation sanitation and `set_confidentiality()`, and the identity
unassignment helpers of `user_service` apply this predicate instead of
copying it.

The predicate is Category B: no database access, write, audit, lock,
logging, or external call. Its inputs are exactly the user's `active` and
`bot` values, the user's current roles, and the Ticket's confidentiality.
Visibility (an explicit `TicketAccessGrant` or package maintainership) is
deliberately not an input: it never confers eligibility.

The user responses report the outcome of the predicate for one user as
`assignment_eligibility()` (`docs/features/identity/rbac.md`, Assignment
Eligibility Wire Format); the directory filter on that value builds its
database condition from `TRIAGE_TICKET_ROLES` and `SCOPE_ALL_ROLES`.

This module imports only Core, so `ticket_mutations` and `user_service`
may both use it without either importing the other.
"""

from __future__ import annotations

from collections.abc import Iterable
from enum import StrEnum
from typing import Final

from app.core.enums import AssignmentEligibility, Capability, Role, Scope
from app.core.permissions import get_capabilities, get_effective_scope

TRIAGE_TICKET_ROLES: Final[frozenset[Role]] = frozenset(
    role for role in Role if Capability.TRIAGE_TICKET in get_capabilities((role,))
)
"""The roles that grant `triage_ticket`. Capabilities are the union over
the held roles, so a user holds `triage_ticket` exactly when one of their
roles is in this set."""

SCOPE_ALL_ROLES: Final[frozenset[Role]] = frozenset(
    role for role in Role if get_effective_scope((role,)) is Scope.ALL
)
"""The roles whose scope is `all`. The effective scope is the least
restrictive over the held roles, so it is `all` exactly when one of the
user's roles is in this set."""


class AssigneeIneligibility(StrEnum):
    """The first condition of assignment eligibility that a user fails.

    Service-internal: neither persisted nor serialized. Members are
    declared in the canonical precedence of
    `docs/features/tickets/ticket-audit-log.md` (Canonical Automatic
    Comment Vocabulary): `INACTIVE`, then `BOT`, then `NO_TRIAGE_TICKET`,
    then `CONFIDENTIAL`.
    """

    INACTIVE = "inactive"
    """The user is inactive."""
    BOT = "bot"
    """The user is a bot account."""
    NO_TRIAGE_TICKET = "no_triage_ticket"
    """No current role of the user grants `triage_ticket`."""
    CONFIDENTIAL = "confidential"
    """The Ticket is confidential and the user's effective scope is not
    `all`."""


def assignee_ineligibility(
    *, active: bool, bot: bool, roles: Iterable[Role], is_confidential: bool
) -> AssigneeIneligibility | None:
    """Evaluate assignment eligibility for one user and one Ticket.

    Q1: `active` and `bot` are the user's current values; `roles` are the
    distinct or repeated `Role` values of every current role origin;
    `is_confidential` is the Ticket's confidentiality (for manual
    creation, the requested one).

    Q4: returns `None` when the user is eligible to be the assignee of the
    Ticket, otherwise the first failing condition in `AssigneeIneligibility`
    order. Passing `is_confidential=True` decides eligibility for every
    Ticket.
    """
    if not active:
        return AssigneeIneligibility.INACTIVE
    if bot:
        return AssigneeIneligibility.BOT
    held = frozenset(roles)
    if Capability.TRIAGE_TICKET not in get_capabilities(held):
        return AssigneeIneligibility.NO_TRIAGE_TICKET
    if is_confidential and get_effective_scope(held) is not Scope.ALL:
        return AssigneeIneligibility.CONFIDENTIAL
    return None


def assignment_eligibility(
    *, active: bool, bot: bool, roles: Iterable[Role]
) -> AssignmentEligibility:
    """Report for which Tickets one user is eligible to be the assignee.

    Q1: `active` and `bot` are the user's current values; `roles` are the
    distinct or repeated `Role` values of every current role origin.

    Q3: applies `assignee_ineligibility()` to a confidential and to a
    non-confidential Ticket: `ALL` when the user is eligible for the
    former, which implies the latter; otherwise `NON_CONFIDENTIAL` when
    eligible for the latter; otherwise `NONE`
    (`docs/features/identity/rbac.md`, Assignment Eligibility Wire
    Format).
    """
    held = frozenset(roles)
    for is_confidential, eligibility in (
        (True, AssignmentEligibility.ALL),
        (False, AssignmentEligibility.NON_CONFIDENTIAL),
    ):
        failing = assignee_ineligibility(
            active=active, bot=bot, roles=held, is_confidential=is_confidential
        )
        if failing is None:
            return eligibility
    return AssignmentEligibility.NONE
