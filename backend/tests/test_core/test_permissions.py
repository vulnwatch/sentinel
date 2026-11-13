"""Tests for static RBAC resolution (backend/app/core/permissions.py).

See docs/features/identity/rbac.md (Predefined Roles, Scope, Role Wire
Format) for the contract these functions implement.
"""

from __future__ import annotations

import pytest

from app.core import permissions
from app.core.enums import Capability, Role, Scope
from app.core.permissions import (
    ROLE_CAPABILITIES,
    ROLE_SCOPES,
    get_capabilities,
    get_effective_scope,
    role_from_wire,
    role_to_wire,
)


@pytest.mark.unit
class TestRoleCapabilitiesMapping:
    """ROLE_CAPABILITIES must exactly match the Predefined Roles table."""

    def test_admin_capabilities(self) -> None:
        assert ROLE_CAPABILITIES[Role.ADMIN] == frozenset(
            {
                Capability.MANAGE_USERS,
                Capability.MANAGE_ROLE_MAPPINGS,
                Capability.MANAGE_SETTINGS,
                Capability.MANAGE_FETCHERS,
                Capability.ADMIN_TICKET_OPS,
            }
        )

    def test_vulnerability_analyst_capabilities(self) -> None:
        assert ROLE_CAPABILITIES[Role.VULNERABILITY_ANALYST] == frozenset(
            {
                Capability.CREATE_TICKET,
                Capability.TRIAGE_TICKET,
                Capability.MANAGE_PACKAGES,
                Capability.MANAGE_CVSS,
                Capability.MANAGE_REFERENCES,
                Capability.MANAGE_CONFIDENTIALITY,
            }
        )

    def test_restricted_analyst_capabilities(self) -> None:
        """restricted_analyst shares all VA capabilities except
        manage_confidentiality.
        """
        assert ROLE_CAPABILITIES[Role.RESTRICTED_ANALYST] == frozenset(
            {
                Capability.CREATE_TICKET,
                Capability.TRIAGE_TICKET,
                Capability.MANAGE_PACKAGES,
                Capability.MANAGE_CVSS,
                Capability.MANAGE_REFERENCES,
            }
        )
        assert (
            Capability.MANAGE_CONFIDENTIALITY
            not in ROLE_CAPABILITIES[Role.RESTRICTED_ANALYST]
        )

    def test_admin_does_not_inherit_va_capabilities(self) -> None:
        """admin does NOT inherit VA capabilities (Design notes)."""
        va_only = {
            Capability.CREATE_TICKET,
            Capability.TRIAGE_TICKET,
            Capability.MANAGE_PACKAGES,
            Capability.MANAGE_CVSS,
            Capability.MANAGE_REFERENCES,
            Capability.MANAGE_CONFIDENTIALITY,
        }
        assert ROLE_CAPABILITIES[Role.ADMIN].isdisjoint(va_only)


@pytest.mark.unit
class TestRoleScopesMapping:
    """ROLE_SCOPES must exactly match the Predefined Roles table."""

    def test_admin_scope(self) -> None:
        assert ROLE_SCOPES[Role.ADMIN] == Scope.ALL

    def test_vulnerability_analyst_scope(self) -> None:
        assert ROLE_SCOPES[Role.VULNERABILITY_ANALYST] == Scope.ALL

    def test_restricted_analyst_scope(self) -> None:
        assert ROLE_SCOPES[Role.RESTRICTED_ANALYST] == Scope.NON_CONFIDENTIAL


@pytest.mark.unit
class TestGetCapabilities:
    """get_capabilities() resolves the union of capabilities across roles."""

    def test_single_role(self) -> None:
        assert (
            get_capabilities([Role.VULNERABILITY_ANALYST])
            == ROLE_CAPABILITIES[Role.VULNERABILITY_ANALYST]
        )

    def test_multiple_roles_union(self) -> None:
        """A user holding multiple roles receives the union of capabilities."""
        result = get_capabilities([Role.ADMIN, Role.VULNERABILITY_ANALYST])
        assert result == (
            ROLE_CAPABILITIES[Role.ADMIN]
            | ROLE_CAPABILITIES[Role.VULNERABILITY_ANALYST]
        )

    def test_no_roles_yields_no_capabilities(self) -> None:
        """A user with no roles has no capabilities (Business Rule 8)."""
        assert get_capabilities([]) == frozenset()

    def test_duplicate_role_is_neutral(self) -> None:
        """Passing the same role twice (e.g., held from two origins) does
        not change the resolved capability set.
        """
        single = get_capabilities([Role.VULNERABILITY_ANALYST])
        duplicated = get_capabilities(
            [Role.VULNERABILITY_ANALYST, Role.VULNERABILITY_ANALYST]
        )
        assert single == duplicated


@pytest.mark.unit
class TestGetEffectiveScope:
    """get_effective_scope() resolves the least-restrictive scope."""

    def test_single_all_scope_role(self) -> None:
        assert get_effective_scope([Role.ADMIN]) == Scope.ALL

    def test_single_non_confidential_scope_role(self) -> None:
        assert get_effective_scope([Role.RESTRICTED_ANALYST]) == Scope.NON_CONFIDENTIAL

    def test_mixed_roles_yield_all(self) -> None:
        """If any role has scope `all`, the effective scope is `all`."""
        result = get_effective_scope([Role.RESTRICTED_ANALYST, Role.ADMIN])
        assert result == Scope.ALL

    def test_no_roles_yields_non_confidential(self) -> None:
        """A user with no roles has an effective scope of non_confidential
        (Business Rule 8).
        """
        assert get_effective_scope([]) == Scope.NON_CONFIDENTIAL

    def test_duplicate_role_is_neutral(self) -> None:
        single = get_effective_scope([Role.RESTRICTED_ANALYST])
        duplicated = get_effective_scope(
            [Role.RESTRICTED_ANALYST, Role.RESTRICTED_ANALYST]
        )
        assert single == duplicated


@pytest.mark.unit
class TestRoleWireFormat:
    """Role <-> wire format conversion (Role Wire Format)."""

    @pytest.mark.parametrize(
        ("role", "wire"),
        [
            (Role.ADMIN, "admin"),
            (Role.VULNERABILITY_ANALYST, "vulnerability_analyst"),
            (Role.RESTRICTED_ANALYST, "restricted_analyst"),
        ],
    )
    def test_role_to_wire(self, role: Role, wire: str) -> None:
        assert role_to_wire(role) == wire

    @pytest.mark.parametrize(
        ("wire", "role"),
        [
            ("admin", Role.ADMIN),
            ("vulnerability_analyst", Role.VULNERABILITY_ANALYST),
            ("restricted_analyst", Role.RESTRICTED_ANALYST),
        ],
    )
    def test_role_from_wire(self, wire: str, role: Role) -> None:
        assert role_from_wire(wire) == role

    def test_role_from_wire_invalid_raises(self) -> None:
        with pytest.raises(ValueError, match="Unknown role wire value"):
            role_from_wire("not_a_role")

    def test_roundtrip_all_roles(self) -> None:
        for role in Role:
            assert role_from_wire(role_to_wire(role)) == role


_MUTATING_METHODS = (
    "__setitem__",
    "__delitem__",
    "__ior__",
    "update",
    "pop",
    "popitem",
    "setdefault",
    "clear",
)


@pytest.mark.unit
@pytest.mark.parametrize(
    "name", ["ROLE_CAPABILITIES", "ROLE_SCOPES", "_ROLE_TO_WIRE", "_WIRE_TO_ROLE"]
)
class TestRbacTablesRejectMutation:
    """The static RBAC tables are `frozendict` constants, so no code can
    change an access decision process-wide by changing a table at runtime
    (docs/conventions.md, Constant Mappings). Each table is read by name, so
    the writes below reach the runtime rather than the type checker, which
    rejects them statically."""

    def test_table_is_a_frozendict(self, name: str) -> None:
        assert type(getattr(permissions, name)) is frozendict

    def test_item_writes_raise_type_error_and_keep_the_table(self, name: str) -> None:
        table = getattr(permissions, name)
        before = dict(table)
        key = next(iter(table))

        with pytest.raises(TypeError):
            table[key] = table[key]
        with pytest.raises(TypeError):
            table["fictional_role"] = table[key]
        with pytest.raises(TypeError):
            del table[key]

        assert dict(table) == before

    def test_table_has_no_mutating_method(self, name: str) -> None:
        table = getattr(permissions, name)

        assert [m for m in _MUTATING_METHODS if hasattr(table, m)] == []
