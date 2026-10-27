"""Shared Ticket caller values for consumer-facing service tests.

Every consumer caller is authenticated (`docs/features/identity/rbac.md`,
Access Levels; Principal to Caller Context). A role-less user is the
read-only profile: effective scope `non_confidential`, and visibility of a
confidential Ticket only through an explicit grant or package
maintainership.
"""

from __future__ import annotations

from typing import Final
from uuid import UUID

from app.core.enums import Scope
from app.services.ticket_visibility import TicketCaller

ROLELESS_CALLER: Final = TicketCaller.authenticated(
    UUID("00000000-0000-7000-8000-00000000c0de"), Scope.NON_CONFIDENTIAL
)
"""A role-less caller whose user ID matches no `User` row, so it holds no
grant and maintains no package: it sees exactly the non-confidential
Tickets. For a read that must not depend on persisted identity rows."""
