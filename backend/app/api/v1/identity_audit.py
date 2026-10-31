"""Identity audit log endpoints: self-service and administrative.

See `docs/features/identity/identity-audit-log.md` (API) for the
authoritative endpoint contracts this module implements. Handlers stay
thin: they validate, delegate to `identity_audit_log`
(`docs/features/identity/identity-audit-log.md`), and map the result to
the documented response — no business logic or database query lives
here.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Annotated, Final, get_args

from fastapi import APIRouter, Depends, Query

from app.api.dependencies import AuthenticatedPrincipal, CurrentUser, require_capability
from app.api.openapi import enum_filter_schema
from app.core.dates import parse_date_range_bound, validate_date_range_order
from app.core.enums import Capability, IdentityAuditEventType
from app.database import DatabaseSession
from app.models.identity_audit_event import IdentityAuditEvent
from app.models.user import User
from app.schemas.common import PaginationMeta, UserReference
from app.schemas.identity_audit import (
    AdminIdentityAuditEventData,
    AdminIdentityAuditListResponse,
    AdminIdentityAuditQuery,
    IdentityAuditQuery,
    SelfIdentityAuditEventData,
    SelfIdentityAuditEventTypeValue,
    SelfIdentityAuditListResponse,
)
from app.services import identity_audit_log

router = APIRouter(prefix="/api/v1", tags=["Identity Audit Log"])


# ---------------------------------------------------------------------------
# Query parameter builders
#
# Declared as individual `Query()`-annotated parameters (rather than a
# single `Annotated[Model, Query()]` query-parameter-model field) so
# each field is visible individually to the shared query-length-limit
# dependency's route-dependant walk (`app.core.query_limits`), which
# inspects `Dependant.query_params` at every nesting depth. Mirrors
# `app/api/v1/api_keys.py`.
# ---------------------------------------------------------------------------


# The event types each log can return, which its `event_type` filter
# accepts and publishes (`identity-audit-log.md`, List Identity Audit
# Events; List My Identity Audit Events).
_ADMIN_EVENT_TYPES: Final[Mapping[str, IdentityAuditEventType]] = {
    member.value: member for member in IdentityAuditEventType
}
_SELF_EVENT_TYPES: Final[Mapping[str, IdentityAuditEventType]] = {
    value: IdentityAuditEventType(value)
    for value in get_args(SelfIdentityAuditEventTypeValue.__value__)
}
_EVENT_TYPE_DESCRIPTION: Final = (
    "Filter by event type. Repeatable; OR semantics. Invalid values are "
    "ignored; only invalid values yield an empty page."
)


def _identity_audit_query(
    *,
    from_date: Annotated[
        str | None,
        Query(description="ISO 8601 date/datetime; inclusive lower bound."),
    ] = None,
    to_date: Annotated[
        str | None,
        Query(description="ISO 8601 date/datetime; inclusive upper bound."),
    ] = None,
    page: Annotated[int, Query(ge=1, le=2_147_483_647, description="Page number.")] = 1,
    per_page: Annotated[
        int, Query(ge=1, le=100, description="Items per page; maximum 100.")
    ] = 20,
) -> IdentityAuditQuery:
    """The parameters shared by both logs. `event_type` is declared by each
    log's own builder, because the two logs accept different event types."""
    parsed_from = parse_date_range_bound("from_date", from_date)
    parsed_to = parse_date_range_bound("to_date", to_date)
    validate_date_range_order(parsed_from, parsed_to)
    return IdentityAuditQuery(
        from_date=parsed_from,
        to_date=parsed_to,
        page=page,
        per_page=per_page,
    )


def _self_identity_audit_query(
    common: Annotated[IdentityAuditQuery, Depends(_identity_audit_query)],
    event_type: Annotated[
        list[str],
        Query(
            default_factory=list,
            description=_EVENT_TYPE_DESCRIPTION,
            json_schema_extra=enum_filter_schema(_SELF_EVENT_TYPES, repeatable=True),
        ),
    ],
) -> IdentityAuditQuery:
    return common.model_copy(update={"event_type": event_type})


def _admin_identity_audit_query(
    common: Annotated[IdentityAuditQuery, Depends(_identity_audit_query)],
    event_type: Annotated[
        list[str],
        Query(
            default_factory=list,
            description=_EVENT_TYPE_DESCRIPTION,
            json_schema_extra=enum_filter_schema(_ADMIN_EVENT_TYPES, repeatable=True),
        ),
    ],
    actor: Annotated[
        str | None,
        Query(description="Actor UUID, exact username, or 'system'."),
    ] = None,
    target_user: Annotated[
        str | None,
        Query(description="Target user UUID or exact username."),
    ] = None,
) -> AdminIdentityAuditQuery:
    return AdminIdentityAuditQuery(
        **common.model_dump(exclude={"event_type"}),
        event_type=event_type,
        actor=actor,
        target_user=target_user,
    )


def _parse_event_types(
    raw: list[str], accepted: Mapping[str, IdentityAuditEventType]
) -> tuple[bool, list[IdentityAuditEventType]]:
    """Resolve the raw repeatable `event_type` query values to typed filters,
    against the event types `accepted` by the log.

    Returns `(True, [])` when `raw` is empty (no filter applied),
    `(True, [...])` with the valid subset when at least one value is
    valid, and `(False, [])` when `raw` is non-empty but every value is
    invalid — the caller must then render an empty page without
    querying the service, per `docs/api-spec.md` (Enum Filter
    Validation).
    """
    if not raw:
        return True, []
    valid = [accepted[value] for value in raw if value in accepted]
    if not valid:
        return False, []
    return True, valid


# ---------------------------------------------------------------------------
# Response serialization
# ---------------------------------------------------------------------------


def _user_reference(user: User | None) -> UserReference | None:
    return UserReference.model_validate(user) if user is not None else None


def _serialize_admin_event(event: IdentityAuditEvent) -> AdminIdentityAuditEventData:
    return AdminIdentityAuditEventData(
        id=event.id,
        event_type=event.event_type,
        old_value=event.old_value,
        new_value=event.new_value,
        detail=event.detail,
        created_at=event.created_at,
        actor=_user_reference(event.actor),
        target_user=_user_reference(event.target_user),
    )


def _serialize_self_event(event: IdentityAuditEvent) -> SelfIdentityAuditEventData:
    """The actor is the same user reference as in the admin log, for every
    reader (`docs/features/identity/rbac.md`, Actor Identities)."""
    return SelfIdentityAuditEventData(
        id=event.id,
        event_type=event.event_type,
        old_value=event.old_value,
        new_value=event.new_value,
        detail=event.detail,
        created_at=event.created_at,
        actor=_user_reference(event.actor),
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/users/me/audit-log",
    response_model=SelfIdentityAuditListResponse,
    summary="List my identity audit events",
    description=(
        "Returns a paginated, fixed reverse-chronological list of identity "
        "audit events where the authenticated user is the target. The "
        "actor is the user reference of the user who performed the action, "
        "or null when no user is recorded. Requires authentication (JWT "
        "session or API key)."
    ),
)
async def list_my_identity_audit_events(
    principal: CurrentUser,
    db: DatabaseSession,
    query: Annotated[IdentityAuditQuery, Depends(_self_identity_audit_query)],
) -> SelfIdentityAuditListResponse:
    """List my identity audit events — see
    `docs/features/identity/identity-audit-log.md` (List My Identity
    Audit Events)."""
    types_valid, event_types = _parse_event_types(query.event_type, _SELF_EVENT_TYPES)
    if not types_valid:
        return SelfIdentityAuditListResponse(
            data=[],
            meta=PaginationMeta(total=0, page=query.page, per_page=query.per_page),
        )

    page = await identity_audit_log.list_user_events(
        db,
        user_id=principal.user.id,
        event_types=event_types,
        from_date=query.from_date,
        to_date=query.to_date,
        page=query.page,
        per_page=query.per_page,
    )
    return SelfIdentityAuditListResponse(
        data=[_serialize_self_event(event) for event in page.items],
        meta=PaginationMeta(total=page.total, page=page.page, per_page=page.per_page),
    )


@router.get(
    "/admin/identity/audit-log",
    response_model=AdminIdentityAuditListResponse,
    summary="List identity audit events",
    description=(
        "Returns a paginated, fixed reverse-chronological list of identity "
        "audit events across all users. Supports filtering by event type, "
        "actor, target user, and date range. Requires the manage_users "
        "capability."
    ),
)
async def list_identity_audit_events(
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_capability(Capability.MANAGE_USERS)),
    ],
    db: DatabaseSession,
    query: Annotated[AdminIdentityAuditQuery, Depends(_admin_identity_audit_query)],
) -> AdminIdentityAuditListResponse:
    """List identity audit events — see
    `docs/features/identity/identity-audit-log.md` (List Identity Audit
    Events)."""
    types_valid, event_types = _parse_event_types(query.event_type, _ADMIN_EVENT_TYPES)
    if not types_valid:
        return AdminIdentityAuditListResponse(
            data=[],
            meta=PaginationMeta(total=0, page=query.page, per_page=query.per_page),
        )

    page = await identity_audit_log.list_events(
        db,
        event_types=event_types,
        actor=query.actor,
        target_user=query.target_user,
        from_date=query.from_date,
        to_date=query.to_date,
        page=query.page,
        per_page=query.per_page,
    )
    return AdminIdentityAuditListResponse(
        data=[_serialize_admin_event(event) for event in page.items],
        meta=PaginationMeta(total=page.total, page=page.page, per_page=page.per_page),
    )
