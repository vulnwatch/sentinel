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

This module imports only Core, so `ticket_mutations` and `user_service`
may both use it without either importing the other.
"""

from __future__ import annotations

from collections.abc import Iterable
from enum import StrEnum

from app.core.enums import Capability, Role, Scope
from app.core.permissions import get_capabilities, get_effective_scope


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
