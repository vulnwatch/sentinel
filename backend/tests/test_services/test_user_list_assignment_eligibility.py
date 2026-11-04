"""Integration tests for the `assignment_eligibility` filter of
`user_service.list_users()` (backend/app/services/user_service.py).

Owning specifications:

- docs/features/identity/user-service.md (`list_users()`).
- docs/features/identity/rbac.md (Business Rule 10; Assignment Eligibility
  Wire Format).
- docs/features/identity/user-management.md (List Users; List Users
  (Admin)).
- docs/features/platform/testing-strategy.md (User Lifecycle and
  Management: Assignment eligibility in user responses).

The agreement tests prove that the database condition selects exactly the
users whose `assignment_eligibility()` — the derivation that the user
responses apply, computed here from each user's persisted rows — is one of
the requested values. Each derived value is also checked against the value
that rbac.md states for the predefined roles, so the population itself is
verified against the specification.
"""

from __future__ import annotations

import itertools
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import (
    AssignmentEligibility,
    Capability,
    Role,
    Scope,
    SortOrder,
    UserSortField,
    UserType,
)
from app.core.permissions import get_capabilities, get_effective_scope
from app.models.ticket import Ticket
from app.models.ticket_access_grant import TicketAccessGrant
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_maintainer import TicketPackageMaintainer
from app.models.user import User
from app.models.user_role import UserRole
from app.services.assignment_eligibility import assignment_eligibility
from app.services.user_service import list_users

_ALL = AssignmentEligibility.ALL
_NON_CONFIDENTIAL = AssignmentEligibility.NON_CONFIDENTIAL
_NONE = AssignmentEligibility.NONE

_ADMIN = Role.ADMIN
_VA = Role.VULNERABILITY_ANALYST
_RA = Role.RESTRICTED_ANALYST

_MANUAL = "_manual"
_SECURITY_GROUP = "O Example Security"
_PARTNER_GROUP = "O Example Partners"
_ADMIN_GROUP = "O Example Administrators"

_SHORT_ROLE_NAMES = {_ADMIN: "admin", _VA: "va", _RA: "ra"}

_STATES: dict[str, tuple[bool, bool]] = {
    "act": (True, False),
    "bot": (True, True),
    "ina": (False, False),
    "inabot": (False, True),
}
"""State label -> (active, bot)."""

_ROLE_SUBSETS: list[tuple[Role, ...]] = [
    subset
    for size in range(len(Role) + 1)
    for subset in itertools.combinations(list(Role), size)
]
"""Every combination of the predefined roles, the empty one included."""

_VALUE_SUBSETS: list[tuple[AssignmentEligibility, ...]] = [
    subset
    for size in range(1, len(AssignmentEligibility) + 1)
    for subset in itertools.combinations(list(AssignmentEligibility), size)
]
"""Every non-empty subset of the three values."""

_NAMED_EXPECTATIONS: dict[str, AssignmentEligibility] = {
    "m-va-two-origins": _ALL,
    "m-ra-two-origins": _NON_CONFIDENTIAL,
    "m-ra-manual-admin-external": _ALL,
    "m-admin-manual-ra-external": _ALL,
    "m-ra-external-only": _NON_CONFIDENTIAL,
    "m-admin-two-origins": _NONE,
    "m-bot-va-two-origins": _NONE,
    "m-inactive-ra-admin-split": _NONE,
    "m-ra-grant": _NON_CONFIDENTIAL,
    "m-ra-maintainer": _NON_CONFIDENTIAL,
    "m-ra-grant-and-maintainer": _NON_CONFIDENTIAL,
    "m-norole-grant": _NONE,
    "m-admin-maintainer": _NONE,
    "m-bot-ra-grant": _NONE,
}
"""The users with roles from several origins, an explicit grant, or package
maintainership of a confidential Ticket, and their value as rbac.md
(Assignment Eligibility Wire Format) states it."""


def _spec_value(
    *, active: bool, bot: bool, roles: frozenset[Role]
) -> AssignmentEligibility:
    """rbac.md, Assignment Eligibility Wire Format, with the predefined
    roles: `all` for an active non-bot holder of `vulnerability_analyst`
    or of `restricted_analyst` together with `admin`; `non_confidential`
    for `restricted_analyst` without a role whose scope is `all`; `none`
    otherwise."""
    if not active or bot:
        return _NONE
    if _VA in roles or {_RA, _ADMIN} <= roles:
        return _ALL
    if _RA in roles:
        return _NON_CONFIDENTIAL
    return _NONE


@dataclass(frozen=True)
class _Snapshot:
    """The persisted state of one user that the filters read."""

    id: uuid.UUID
    username: str
    email: str
    full_name: str | None
    active: bool
    bot: bool
    external: bool
    roles: frozenset[Role]

    @property
    def derived(self) -> AssignmentEligibility:
        return assignment_eligibility(
            active=self.active, bot=self.bot, roles=self.roles
        )


async def _snapshots(session: AsyncSession) -> dict[uuid.UUID, _Snapshot]:
    """Every user with the roles of every origin, read from the rows."""
    role_rows = (await session.execute(select(UserRole.user_id, UserRole.role))).all()
    roles: dict[uuid.UUID, set[Role]] = {}
    for user_id, role in role_rows:
        roles.setdefault(user_id, set()).add(Role(role))
    users = (await session.execute(select(User))).scalars().all()
    return {
        user.id: _Snapshot(
            id=user.id,
            username=user.username,
            email=user.email,
            full_name=user.full_name,
            active=user.active,
            bot=user.bot,
            external=user.external_id is not None,
            roles=frozenset(roles.get(user.id, ())),
        )
        for user in users
    }


@dataclass
class _Factories:
    user: Callable[..., Awaitable[User]]
    user_role: Callable[..., Awaitable[UserRole]]
    ticket: Callable[..., Awaitable[Ticket]]
    grant: Callable[..., Awaitable[TicketAccessGrant]]
    package: Callable[..., Awaitable[TicketPackage]]
    maintainer: Callable[..., Awaitable[TicketPackageMaintainer]]


async def _create_user(
    factories: _Factories,
    username: str,
    *,
    index: int,
    active: bool = True,
    bot: bool = False,
    external: bool = False,
    origins: tuple[tuple[Role, str], ...] = (),
) -> User:
    """A user with one `UserRole` row per `(role, group_name)` origin.
    `full_name` cycles through a null and two shared values so that the
    `full_name` sort exercises null placement and the `id` tie-break."""
    overrides: dict[str, Any] = {
        "username": username,
        "email": f"{username}@example.com",
        "full_name": (None, "Example Alpha", "Example Beta")[index % 3],
        "active": active,
        "bot": bot,
    }
    if external:
        overrides["external_id"] = uuid.uuid4()
        overrides["password_hash"] = None
    user = await factories.user(**overrides)
    for role, group_name in origins:
        await factories.user_role(
            user_id=user.id, role=role.value, group_name=group_name
        )
    return user


async def _build_population(factories: _Factories) -> dict[str, User]:
    """Every combination of the predefined roles in every state, plus the
    users of `_NAMED_EXPECTATIONS`."""
    users: dict[str, User] = {}
    index = itertools.count()
    for label, (active, bot) in _STATES.items():
        for subset in _ROLE_SUBSETS:
            short = "-".join(_SHORT_ROLE_NAMES[role] for role in subset) or "norole"
            username = f"p-{label}-{short}"
            users[username] = await _create_user(
                factories,
                username,
                index=next(index),
                active=active,
                bot=bot,
                origins=tuple((role, _MANUAL) for role in subset),
            )

    async def named(
        username: str, origins: tuple[tuple[Role, str], ...], **kwargs: Any
    ) -> User:
        external = any(group != _MANUAL for _, group in origins)
        user = await _create_user(
            factories,
            username,
            index=next(index),
            external=external,
            origins=origins,
            **kwargs,
        )
        users[username] = user
        return user

    await named("m-va-two-origins", ((_VA, _MANUAL), (_VA, _SECURITY_GROUP)))
    await named("m-ra-two-origins", ((_RA, _MANUAL), (_RA, _PARTNER_GROUP)))
    await named("m-ra-manual-admin-external", ((_RA, _MANUAL), (_ADMIN, _ADMIN_GROUP)))
    await named(
        "m-admin-manual-ra-external", ((_ADMIN, _MANUAL), (_RA, _PARTNER_GROUP))
    )
    await named("m-ra-external-only", ((_RA, _PARTNER_GROUP),))
    await named("m-admin-two-origins", ((_ADMIN, _MANUAL), (_ADMIN, _ADMIN_GROUP)))
    await named(
        "m-bot-va-two-origins", ((_VA, _MANUAL), (_VA, _SECURITY_GROUP)), bot=True
    )
    await named(
        "m-inactive-ra-admin-split",
        ((_RA, _MANUAL), (_ADMIN, _ADMIN_GROUP)),
        active=False,
    )

    granter = users["p-act-va"]
    confidential = await factories.ticket(is_confidential=True)
    confidential_package = await factories.package(ticket_id=confidential.id)

    async def grant(user: User) -> None:
        await factories.grant(
            ticket_id=confidential.id, user_id=user.id, granted_by_id=granter.id
        )

    async def maintain(user: User) -> None:
        await factories.maintainer(
            ticket_package_id=confidential_package.id, user_id=user.id
        )

    await grant(await named("m-ra-grant", ((_RA, _MANUAL),)))
    await maintain(await named("m-ra-maintainer", ((_RA, _MANUAL),)))
    both = await named("m-ra-grant-and-maintainer", ((_RA, _MANUAL),))
    await grant(both)
    await maintain(both)
    await grant(await named("m-norole-grant", ()))
    await maintain(await named("m-admin-maintainer", ((_ADMIN, _MANUAL),)))
    await grant(await named("m-bot-ra-grant", ((_RA, _MANUAL),), bot=True))
    return users


@pytest.fixture
async def population(
    user_factory: Callable[..., Awaitable[User]],
    user_role_factory: Callable[..., Awaitable[UserRole]],
    ticket_factory: Callable[..., Awaitable[Ticket]],
    ticket_access_grant_factory: Callable[..., Awaitable[TicketAccessGrant]],
    ticket_package_factory: Callable[..., Awaitable[TicketPackage]],
    ticket_package_maintainer_factory: Callable[
        ..., Awaitable[TicketPackageMaintainer]
    ],
) -> dict[str, User]:
    return await _build_population(
        _Factories(
            user=user_factory,
            user_role=user_role_factory,
            ticket=ticket_factory,
            grant=ticket_access_grant_factory,
            package=ticket_package_factory,
            maintainer=ticket_package_maintainer_factory,
        )
    )


def _subset_id(subset: tuple[AssignmentEligibility, ...]) -> str:
    return "+".join(value.value for value in subset)


async def _list_ids(
    session: AsyncSession, **kwargs: Any
) -> tuple[list[uuid.UUID], int]:
    page = await list_users(session, per_page=100, **kwargs)
    return [user.id for user in page.items], page.total


@pytest.mark.integration
class TestPopulation:
    async def test_derived_values_follow_the_specification(
        self, db_session: AsyncSession, population: dict[str, User]
    ) -> None:
        """Guards the agreement tests below: the derivation applied to the
        persisted rows gives the value that rbac.md states, for every user,
        including every role combination in every state and the users with
        several origins, a grant, or maintainership."""
        snapshots = await _snapshots(db_session)

        assert len(snapshots) == len(population) < 100
        for snapshot in snapshots.values():
            expected = _spec_value(
                active=snapshot.active, bot=snapshot.bot, roles=snapshot.roles
            )
            assert snapshot.derived is expected, snapshot.username
        for username, expected in _NAMED_EXPECTATIONS.items():
            assert snapshots[population[username].id].derived is expected, username

    async def test_every_value_is_represented(
        self, db_session: AsyncSession, population: dict[str, User]
    ) -> None:
        snapshots = await _snapshots(db_session)

        assert {snapshot.derived for snapshot in snapshots.values()} == set(
            AssignmentEligibility
        )


@pytest.mark.integration
class TestAssignmentEligibilityFilter:
    @pytest.mark.parametrize("subset", _VALUE_SUBSETS, ids=_subset_id)
    async def test_selects_exactly_the_users_whose_derived_value_is_requested(
        self,
        db_session: AsyncSession,
        population: dict[str, User],
        subset: tuple[AssignmentEligibility, ...],
    ) -> None:
        """testing-strategy.md: the database condition and the derivation
        that the assignment paths apply agree, for every non-empty subset
        of the values; a role from several origins never duplicates a user
        or inflates the total."""
        snapshots = await _snapshots(db_session)
        expected = {s.id for s in snapshots.values() if s.derived in subset}

        ids, total = await _list_ids(db_session, assignment_eligibility=list(subset))

        assert len(ids) == len(set(ids))
        assert set(ids) == expected
        assert total == len(expected)

    async def test_values_partition_the_users(
        self, db_session: AsyncSession, population: dict[str, User]
    ) -> None:
        by_value = {
            value: set((await _list_ids(db_session, assignment_eligibility=[value]))[0])
            for value in AssignmentEligibility
        }
        everyone, _ = await _list_ids(db_session)

        assert by_value[_ALL].isdisjoint(by_value[_NON_CONFIDENTIAL])
        assert by_value[_ALL].isdisjoint(by_value[_NONE])
        assert by_value[_NON_CONFIDENTIAL].isdisjoint(by_value[_NONE])
        assert set().union(*by_value.values()) == set(everyone)

    async def test_all_returns_only_active_non_bot_triagers_with_scope_all(
        self, db_session: AsyncSession, population: dict[str, User]
    ) -> None:
        snapshots = await _snapshots(db_session)

        ids, _ = await _list_ids(db_session, assignment_eligibility=[_ALL])

        assert ids
        for user_id in ids:
            snapshot = snapshots[user_id]
            assert snapshot.active, snapshot.username
            assert not snapshot.bot, snapshot.username
            assert Capability.TRIAGE_TICKET in get_capabilities(snapshot.roles)
            assert get_effective_scope(snapshot.roles) is Scope.ALL

    async def test_non_confidential_returns_only_active_non_bot_triagers(
        self, db_session: AsyncSession, population: dict[str, User]
    ) -> None:
        snapshots = await _snapshots(db_session)

        ids, _ = await _list_ids(db_session, assignment_eligibility=[_NON_CONFIDENTIAL])

        assert ids
        for user_id in ids:
            snapshot = snapshots[user_id]
            assert snapshot.active, snapshot.username
            assert not snapshot.bot, snapshot.username
            assert Capability.TRIAGE_TICKET in get_capabilities(snapshot.roles)
            assert get_effective_scope(snapshot.roles) is Scope.NON_CONFIDENTIAL

    async def test_grant_and_maintainership_confer_no_eligibility(
        self, db_session: AsyncSession, population: dict[str, User]
    ) -> None:
        all_ids, _ = await _list_ids(db_session, assignment_eligibility=[_ALL])
        eligible_ids, _ = await _list_ids(
            db_session, assignment_eligibility=[_ALL, _NON_CONFIDENTIAL]
        )

        for username in (
            "m-ra-grant",
            "m-ra-maintainer",
            "m-ra-grant-and-maintainer",
        ):
            assert population[username].id not in all_ids
            assert population[username].id in eligible_ids
        for username in ("m-norole-grant", "m-admin-maintainer", "m-bot-ra-grant"):
            assert population[username].id not in eligible_ids

    async def test_repeated_value_equals_the_single_value(
        self, db_session: AsyncSession, population: dict[str, User]
    ) -> None:
        single = await _list_ids(db_session, assignment_eligibility=[_NONE])
        repeated = await _list_ids(db_session, assignment_eligibility=[_NONE, _NONE])

        assert repeated == single

    @pytest.mark.parametrize("value", [None, []], ids=["none", "empty"])
    async def test_absent_or_empty_filter_returns_every_user(
        self,
        db_session: AsyncSession,
        population: dict[str, User],
        value: list[AssignmentEligibility] | None,
    ) -> None:
        ids, total = await _list_ids(db_session, assignment_eligibility=value)

        assert set(ids) == {user.id for user in population.values()}
        assert total == len(population)


_COMBINATIONS: list[tuple[str, dict[str, Any], Callable[[_Snapshot], bool]]] = [
    (
        "search",
        {"search": "TWO-ORIGINS"},
        lambda s: "two-origins" in s.username,
    ),
    ("active-true", {"active": True}, lambda s: s.active),
    ("active-false", {"active": False}, lambda s: not s.active),
    ("role-ra", {"roles": [_RA]}, lambda s: _RA in s.roles),
    (
        "role-admin-or-va",
        {"roles": [_ADMIN, _VA]},
        lambda s: bool({_ADMIN, _VA} & s.roles),
    ),
    ("has-role-true", {"has_role": True}, lambda s: bool(s.roles)),
    ("has-role-false", {"has_role": False}, lambda s: not s.roles),
    ("type-local", {"user_type": UserType.LOCAL}, lambda s: not s.external),
    ("type-external", {"user_type": UserType.EXTERNAL}, lambda s: s.external),
    (
        "every-category",
        {
            "search": "m-",
            "active": True,
            "roles": [_RA],
            "has_role": True,
            "user_type": UserType.EXTERNAL,
        },
        lambda s: "m-" in s.username and s.active and _RA in s.roles and s.external,
    ),
]


@pytest.mark.integration
class TestFilterCombinations:
    @pytest.mark.parametrize(
        ("kwargs", "matches"),
        [(kwargs, matches) for _, kwargs, matches in _COMBINATIONS],
        ids=[name for name, _, _ in _COMBINATIONS],
    )
    async def test_combines_with_every_other_filter_via_and(
        self,
        db_session: AsyncSession,
        population: dict[str, User],
        kwargs: dict[str, Any],
        matches: Callable[[_Snapshot], bool],
    ) -> None:
        """user-management.md (List Users (Admin)): filters of different
        kinds combine with AND, and the total counts exactly the filtered
        users."""
        snapshots = await _snapshots(db_session)

        for subset in _VALUE_SUBSETS:
            expected = {
                s.id for s in snapshots.values() if s.derived in subset and matches(s)
            }

            ids, total = await _list_ids(
                db_session, assignment_eligibility=list(subset), **kwargs
            )

            assert len(ids) == len(set(ids)), subset
            assert set(ids) == expected, subset
            assert total == len(expected), subset

    async def test_combination_can_exclude_every_user(
        self, db_session: AsyncSession, population: dict[str, User]
    ) -> None:
        ids, total = await _list_ids(
            db_session, assignment_eligibility=[_ALL, _NON_CONFIDENTIAL], active=False
        )

        assert ids == []
        assert total == 0

    @pytest.mark.parametrize("sort_by", list(UserSortField))
    @pytest.mark.parametrize("sort_order", list(SortOrder))
    async def test_sorts_the_filtered_users_like_the_unfiltered_list(
        self,
        db_session: AsyncSession,
        population: dict[str, User],
        sort_by: UserSortField,
        sort_order: SortOrder,
    ) -> None:
        """The filter only removes users: the remaining order, including
        null placement and the `id` tie-break, is the order of the
        unfiltered list."""
        snapshots = await _snapshots(db_session)
        everyone, _ = await _list_ids(
            db_session, sort_by=sort_by, sort_order=sort_order
        )

        for subset in _VALUE_SUBSETS:
            expected = [
                user_id for user_id in everyone if snapshots[user_id].derived in subset
            ]

            ids, total = await _list_ids(
                db_session,
                assignment_eligibility=list(subset),
                sort_by=sort_by,
                sort_order=sort_order,
            )

            assert ids == expected, subset
            assert total == len(expected), subset

    @pytest.mark.parametrize("subset", _VALUE_SUBSETS, ids=_subset_id)
    async def test_paginates_the_filtered_users(
        self,
        db_session: AsyncSession,
        population: dict[str, User],
        subset: tuple[AssignmentEligibility, ...],
    ) -> None:
        """Pages smaller than the result partition it in order, each page
        reports the filtered total, and a page past the end is empty."""
        full, full_total = await _list_ids(
            db_session, assignment_eligibility=list(subset)
        )
        per_page = 3
        assert full_total > per_page

        collected: list[uuid.UUID] = []
        page_count = -(-full_total // per_page)
        for number in range(1, page_count + 2):
            page = await list_users(
                db_session,
                assignment_eligibility=list(subset),
                page=number,
                per_page=per_page,
            )
            assert page.total == full_total
            if number > page_count:
                assert page.items == []
            else:
                assert 0 < len(page.items) <= per_page
            collected.extend(user.id for user in page.items)

        assert collected == full
