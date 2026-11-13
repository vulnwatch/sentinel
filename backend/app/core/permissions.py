"""Static RBAC resolution: role-to-capability, role-to-scope, and wire format.

This module holds the static authorization definitions described in
`docs/features/identity/rbac.md` (Authorization Model, Predefined Roles,
Role Wire Format). Definitions are static, in-code mappings — there are
no capability, scope, or role-mapping tables in the database (see
`docs/data-model.md`, Identity).
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Final

from app.core.enums import Capability, Role, Scope

# Role -> granted capabilities. See `docs/features/identity/rbac.md`
# (Predefined Roles). `admin` does NOT inherit VA capabilities; a user
# needing both must hold both roles.
ROLE_CAPABILITIES: Final[frozendict[Role, frozenset[Capability]]] = frozendict(
    {
        Role.ADMIN: frozenset(
            {
                Capability.MANAGE_USERS,
                Capability.MANAGE_ROLE_MAPPINGS,
                Capability.MANAGE_SETTINGS,
                Capability.MANAGE_FETCHERS,
                Capability.ADMIN_TICKET_OPS,
            }
        ),
        Role.VULNERABILITY_ANALYST: frozenset(
            {
                Capability.CREATE_TICKET,
                Capability.TRIAGE_TICKET,
                Capability.MANAGE_PACKAGES,
                Capability.MANAGE_CVSS,
                Capability.MANAGE_REFERENCES,
                Capability.MANAGE_CONFIDENTIALITY,
            }
        ),
        Role.RESTRICTED_ANALYST: frozenset(
            {
                Capability.CREATE_TICKET,
                Capability.TRIAGE_TICKET,
                Capability.MANAGE_PACKAGES,
                Capability.MANAGE_CVSS,
                Capability.MANAGE_REFERENCES,
            }
        ),
    }
)

# Role -> default visibility scope. See `docs/features/identity/rbac.md`
# (Scope, Predefined Roles).
ROLE_SCOPES: Final[frozendict[Role, Scope]] = frozendict(
    {
        Role.ADMIN: Scope.ALL,
        Role.VULNERABILITY_ANALYST: Scope.ALL,
        Role.RESTRICTED_ANALYST: Scope.NON_CONFIDENTIAL,
    }
)

# Role <-> wire format (lowercase with underscores). See
# `docs/features/identity/rbac.md` (Role Wire Format). Used by all
# endpoints and CLI options that accept or return role values.
_ROLE_TO_WIRE: Final[frozendict[Role, str]] = frozendict(
    {
        Role.ADMIN: "admin",
        Role.VULNERABILITY_ANALYST: "vulnerability_analyst",
        Role.RESTRICTED_ANALYST: "restricted_analyst",
    }
)
_WIRE_TO_ROLE: Final[frozendict[str, Role]] = frozendict(
    {wire: role for role, wire in _ROLE_TO_WIRE.items()}
)


def get_capabilities(roles: Iterable[Role]) -> frozenset[Capability]:
    """Resolve the union of capabilities granted by a set of roles.

    A user holding multiple roles receives the union of all capabilities.
    A user with no roles has no capabilities (returns an empty frozenset).
    See `docs/features/identity/rbac.md` (Predefined Roles).
    """
    result: set[Capability] = set()
    for role in roles:
        result |= ROLE_CAPABILITIES[role]
    return frozenset(result)


def get_effective_scope(roles: Iterable[Role]) -> Scope:
    """Resolve the least-restrictive effective scope for a set of roles.

    If any role has scope `all`, the effective scope is `all`. Otherwise,
    the effective scope is `non_confidential`. A user with no roles has
    an effective scope of `non_confidential`. See
    `docs/features/identity/rbac.md` (Scope, Business Rule 8).
    """
    for role in roles:
        if ROLE_SCOPES[role] == Scope.ALL:
            return Scope.ALL
    return Scope.NON_CONFIDENTIAL


def role_to_wire(role: Role) -> str:
    """Convert a `Role` to its wire format (lowercase with underscores)."""
    return _ROLE_TO_WIRE[role]


def role_from_wire(value: str) -> Role:
    """Convert a wire-format role string to a `Role`.

    Raises:
        ValueError: if `value` does not match any known wire-format role.
    """
    try:
        return _WIRE_TO_ROLE[value]
    except KeyError:
        msg = f"Unknown role wire value: {value!r}"
        raise ValueError(msg) from None
