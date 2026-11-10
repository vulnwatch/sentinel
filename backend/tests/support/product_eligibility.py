"""Shared helpers for the `set_product_eligibility()` service tests.

Consumers:

- `tests/test_services/test_set_product_eligibility.py` (override metadata
  transitions, no-ops, reset recalculation matrix, gate transitions,
  auto-assignment, audit payload, caller validation, result projection,
  dimension independence);
- `tests/test_services/test_set_product_eligibility_scope.py` (nested
  ownership, accessibility, manual zone, excluded and EOL occurrences,
  shared evaluation date, rollback, and audit-history independence);
- `tests/test_api/test_ticket_product_eligibility.py` (the endpoint e2e
  tests, `persisted_occurrence()` only). The independent-session module
  `tests/test_services/test_set_product_eligibility_atomicity.py` calls
  the service with an explicit declared path instead, so that no
  statement precedes its locks.

The override provenance helpers (`ELIGIBILITY_OVERRIDE_SET_AT`,
`add_override_setter()`, `override_provenance_columns()`) also serve
`tests/conftest.py` (`ticket_package_product_factory`) and every support
module or test that inserts an overridden occurrence directly, so that the
row satisfies `chk_ticket_package_product_eligibility_override_provenance`.

The track-level helpers (`Spy`, `ticket_state`) are reused from
`tests/support/track_status.py`. The helpers observe persisted state and
record calls; nothing here computes an expectation with the module under
test.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, date, datetime
from typing import Any

import pytest
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import Scope
from app.models.product import Product
from app.models.system_setting import SystemSetting
from app.models.ticket import Ticket
from app.models.ticket_audit_event import TicketAuditEvent
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_product import TicketPackageProduct
from app.models.ticket_package_track import TicketPackageTrack
from app.models.user import User
from app.services.package_service import (
    PackageUserProjection,
    ProductEligibilityResult,
    set_product_eligibility,
)
from app.services.ticket_convergence_registry import (
    pending_ticket_convergence_effects,
)
from app.services.ticket_visibility import TicketCaller
from tests.support.ticket_mutations import (
    EVAL,
    EventRow,
    StatementRecorder,
    ticket_events,
)
from tests.support.track_status import Spy, ticket_state

OccurrencePath = tuple[uuid.UUID, uuid.UUID, uuid.UUID]
"""The declared `(ticket_id, package_id, track_id)` of an occurrence."""

ELIGIBILITY_OVERRIDE_SET_AT = datetime(2001, 2, 3, 4, 5, 6, tzinfo=UTC)
"""Default `eligibility_override_at` of an occurrence created with an
override by `ticket_package_product_factory` (`tests/conftest.py`) or by
`override_provenance_columns()`."""

OverrideProvenance = tuple[uuid.UUID | None, datetime | None]
"""The persisted `(eligibility_override_by_id, eligibility_override_at)`."""


async def add_override_setter(
    session: AsyncSession, user_ids: list[uuid.UUID] | None = None
) -> uuid.UUID:
    """Add and flush a fictional User who set an eligibility override;
    `user_ids` collects its ID for the teardown of a committed world.
    Returns the User ID."""
    suffix = uuid.uuid4().hex[:10]
    user = User(
        username=f"setter.{suffix}",
        email=f"setter.{suffix}@example.com",
        password_hash="$2b$12$" + "s" * 53,
    )
    session.add(user)
    await session.flush()
    if user_ids is not None:
        user_ids.append(user.id)
    return user.id


def override_provenance_columns(
    override: bool, setter_id: uuid.UUID | None
) -> dict[str, Any]:
    """The provenance columns of an occurrence inserted directly with
    `is_eligible_override = override`: `setter_id` and
    `ELIGIBILITY_OVERRIDE_SET_AT` for an override, nothing otherwise, so
    that the row satisfies
    `chk_ticket_package_product_eligibility_override_provenance`."""
    if not override:
        return {}
    assert setter_id is not None, "an override needs the User who set it"
    return {
        "eligibility_override_by_id": setter_id,
        "eligibility_override_at": ELIGIBILITY_OVERRIDE_SET_AT,
    }


def setter_profile(user: User) -> PackageUserProjection:
    """The projected current profile of `user` as an override setter."""
    return PackageUserProjection(
        id=user.id,
        username=user.username,
        full_name=user.full_name,
        active=user.active,
        bot=user.bot,
    )


async def eligibility_event_times(
    db: AsyncSession, ticket_id: uuid.UUID
) -> list[datetime]:
    """The `created_at` of the Ticket's `product_eligibility_changed` events
    in insertion (UUIDv7 `id`) order."""
    return list(
        (
            await db.execute(
                select(TicketAuditEvent.created_at)
                .where(
                    TicketAuditEvent.ticket_id == ticket_id,
                    TicketAuditEvent.event_type == "product_eligibility_changed",
                )
                .order_by(TicketAuditEvent.id)
            )
        ).scalars()
    )


async def persisted_provenance(
    db: AsyncSession, occurrence_id: uuid.UUID
) -> OverrideProvenance:
    """The persisted override provenance of an occurrence (package-model.md,
    Override Model)."""
    row = (
        await db.execute(
            select(
                TicketPackageProduct.eligibility_override_by_id,
                TicketPackageProduct.eligibility_override_at,
            ).where(TicketPackageProduct.id == occurrence_id)
        )
    ).one()
    return row.eligibility_override_by_id, row.eligibility_override_at


async def occurrence_path(
    db: AsyncSession, occurrence: TicketPackageProduct
) -> OccurrencePath:
    """The persisted parent Ticket, package, and track of an occurrence."""
    row = (
        await db.execute(
            select(TicketPackage.ticket_id, TicketPackage.id, TicketPackageTrack.id)
            .join(
                TicketPackageTrack,
                TicketPackageTrack.ticket_package_id == TicketPackage.id,
            )
            .where(TicketPackageTrack.id == occurrence.ticket_package_track_id)
        )
    ).one()
    return row[0], row[1], row[2]


async def track_occurrences(
    db: AsyncSession, track: TicketPackageTrack
) -> list[TicketPackageProduct]:
    """Every Product occurrence of a track, in ascending occurrence-id order."""
    return list(
        (
            await db.execute(
                select(TicketPackageProduct)
                .where(TicketPackageProduct.ticket_package_track_id == track.id)
                .order_by(TicketPackageProduct.id)
            )
        ).scalars()
    )


async def only_occurrence(
    db: AsyncSession, track: TicketPackageTrack
) -> TicketPackageProduct:
    """The single Product occurrence of a factory-built track."""
    (occurrence,) = await track_occurrences(db, track)
    return occurrence


async def set_eligibility(
    db: AsyncSession,
    occurrence: TicketPackageProduct,
    eligible: bool | None,
    actor: User,
    *,
    ticket_id: uuid.UUID | None = None,
    package_id: uuid.UUID | None = None,
    track_id: uuid.UUID | None = None,
    occurrence_id: uuid.UUID | None = None,
    scope: Scope = Scope.ALL,
    evaluation_date: date | None = EVAL,
) -> ProductEligibilityResult:
    """Call the service as the API would (`actor` with effective `scope`),
    for `occurrence`'s own path unless a locator level is overridden."""
    own_ticket, own_package, own_track = await occurrence_path(db, occurrence)
    return await set_product_eligibility(
        db,
        ticket_id=own_ticket if ticket_id is None else ticket_id,
        package_id=own_package if package_id is None else package_id,
        track_id=own_track if track_id is None else track_id,
        ticket_package_product_id=(
            occurrence.id if occurrence_id is None else occurrence_id
        ),
        eligible=eligible,
        acting_user_id=actor.id,
        caller=TicketCaller.authenticated(actor.id, scope),
        evaluation_date=evaluation_date,
    )


async def persisted_occurrence(
    db: AsyncSession, occurrence: TicketPackageProduct
) -> tuple[bool, bool]:
    """The persisted `(eligible, is_eligible_override)` of an occurrence."""
    row = (
        await db.execute(
            select(
                TicketPackageProduct.eligible, TicketPackageProduct.is_eligible_override
            ).where(TicketPackageProduct.id == occurrence.id)
        )
    ).one()
    return row.eligible, row.is_eligible_override


async def product_subject(
    db: AsyncSession, occurrence: TicketPackageProduct
) -> dict[str, str]:
    """The fixture Product subject of an occurrence: track reference,
    package name, catalog display name, and CPE (ticket-audit-log.md,
    detail JSONB Schema Contract: `product_eligibility_changed`)."""
    row = (
        await db.execute(
            select(
                TicketPackageTrack.reference,
                TicketPackage.package_name,
                Product.display_name,
                Product.cpe,
            )
            .select_from(TicketPackageProduct)
            .join(
                TicketPackageTrack,
                TicketPackageTrack.id == TicketPackageProduct.ticket_package_track_id,
            )
            .join(
                TicketPackage, TicketPackage.id == TicketPackageTrack.ticket_package_id
            )
            .join(Product, Product.id == TicketPackageProduct.product_id)
            .where(TicketPackageProduct.id == occurrence.id)
        )
    ).one()
    return {
        "track": row.reference,
        "package": row.package_name,
        "product_name": row.display_name,
        "product_cpe": row.cpe,
    }


async def eligibility_event(
    db: AsyncSession,
    occurrence: TicketPackageProduct,
    actor: User,
    old: bool,
    new: bool,
    action: str,
) -> EventRow:
    """The acting-user `product_eligibility_changed` of an override set,
    change, or clear: `"true"`/`"false"` values, `comment` `NULL`, and the
    Product subject with `reason = va_override` and `override_action`."""
    return EventRow(
        "product_eligibility_changed",
        actor.id,
        "true" if old else "false",
        "true" if new else "false",
        None,
        {
            **await product_subject(db, occurrence),
            "reason": "va_override",
            "override_action": action,
        },
    )


async def set_default_version(db: AsyncSession, version: str) -> None:
    """Change the persisted `default_cvss_version` setting."""
    await db.execute(
        update(SystemSetting)
        .where(SystemSetting.key == "default_cvss_version")
        .values(value=version)
    )


async def assert_no_effects(
    db: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    run: Callable[[], Awaitable[ProductEligibilityResult]],
    *,
    tickets: tuple[Ticket, ...],
    occurrences: tuple[TicketPackageProduct, ...],
    error: type[Exception] | None = None,
) -> ProductEligibilityResult | None:
    """Run the call and assert the zero-side-effect contract: no write, no
    assignment, no reconciliation, no registered convergence effect, and
    unchanged Ticket status, assignee, events, and occurrence eligibility,
    override marker, and override provenance for every given Ticket and
    occurrence. Returns the result of a non-raising call."""

    async def snapshot() -> tuple[Any, ...]:
        return (
            [await ticket_state(db, t) for t in tickets],
            [await ticket_events(db, t) for t in tickets],
            [await persisted_occurrence(db, o) for o in occurrences],
            [await persisted_provenance(db, o.id) for o in occurrences],
        )

    before = await snapshot()
    assign = Spy(monkeypatch, "auto_assign_actor")
    reconcile = Spy(monkeypatch, "reconcile_ticket_status")
    result: ProductEligibilityResult | None = None

    with StatementRecorder(db) as recorder:
        if error is None:
            result = await run()
        else:
            with pytest.raises(error):
                await run()

    assert recorder.writes() == []
    assert (assign.calls, reconcile.calls) == ([], [])
    assert pending_ticket_convergence_effects(db) == ()
    assert await snapshot() == before
    return result
