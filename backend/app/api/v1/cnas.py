"""CNA read endpoints, the auto-ignore policy operation, and the CNA audit
log.

See `docs/features/tickets/cna.md` (API Endpoints: Response Schemas, List
CNAs, Get CNA, Set CNA Auto-Ignore, List CNA Audit Events; Security) for the
authoritative endpoint contracts, and `docs/api-spec.md` (CNA Identifier
Resolution) for the shared `{org_id}` locator behavior.

Handlers stay thin: they require authentication or `manage_settings`,
delegate to `cna_service`, map `CNANotFoundError` to `404 CNA_NOT_FOUND`,
and serialize the result. No database query lives here. The reads expose
public CVE Program data and no Ticket or CVE identifier, so they apply no
Ticket visibility.

`serialize_cna_summary()` is the one `CNASummary` serializer, shared by the
CVE representations of the CVE and Ticket endpoints.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Path, Query, status
from pydantic import AfterValidator

from app.api.dependencies import (
    AuthenticatedPrincipal,
    CurrentUser,
    require_capability,
)
from app.api.openapi import enum_filter_schema
from app.core.dates import parse_date_range_bound, validate_date_range_order
from app.core.enums import Capability, CNAAuditEventType, CNASortField, SortOrder
from app.core.errors import AppError, ErrorCode
from app.database import DatabaseSession
from app.models.cna import CNA
from app.schemas.cna import (
    CNA_ORG_ID_SCHEMA,
    CNAAuditEventData,
    CNAAuditListResponse,
    CNAAuditQuery,
    CNAAutoIgnoreRequest,
    CNADetailResponse,
    CNAListQuery,
    CNAListResponse,
    CNAResponse,
    CNASummary,
    validate_cna_org_id,
)
from app.schemas.common import PaginationMeta, UserReference
from app.schemas.errors import ErrorResponse
from app.services import cna_service
from app.services.cna_service import CNAAuditEventItem, CNANotFoundError
from app.services.cve_projection import CNASummaryProjection, cna_display_name

router = APIRouter(prefix="/api/v1", tags=["CNAs"])

CNAOrgIdPath = Annotated[
    str,
    Path(
        description=(
            "CVE Services UUID of the CNA in the hyphenated 8-4-4-4-12 form, "
            "hexadecimal digits in either case. Any other value returns "
            "`404 CNA_NOT_FOUND`."
        ),
        examples=["00000000-0000-4000-8000-0000000000a1"],
    ),
]
"""The `{org_id}` path parameter.

Deliberately an unconstrained string: a malformed value is a locator and
must produce `404 CNA_NOT_FOUND`, not the `422` of a UUID type
(`docs/api-spec.md`, CNA Identifier Resolution; Published Input
Constraints).
"""


def _cna_not_found_error() -> AppError:
    return AppError(
        status_code=status.HTTP_404_NOT_FOUND,
        code=ErrorCode.CNA_NOT_FOUND,
        detail="CNA not found.",
    )


def serialize_cna_summary(summary: CNASummaryProjection | None) -> CNASummary | None:
    """Map a CNA reference projection to its `CNASummary` schema."""
    if summary is None:
        return None
    return CNASummary(org_id=summary.org_id, name=summary.name)


def serialize_cna(cna: CNA) -> CNAResponse:
    """Map a CNA row to its `CNAResponse` schema, with the display name."""
    return CNAResponse(
        org_id=cna.org_id,
        name=cna_display_name(cna.organization_name, cna.short_name),
        short_name=cna.short_name,
        organization_name=cna.organization_name,
        types=list(cna.types),
        scope=cna.scope,
        auto_ignore=cna.auto_ignore,
        created_at=cna.created_at,
        updated_at=cna.updated_at,
    )


def _cna_list_query(
    *,
    search: Annotated[
        str | None,
        Query(
            description=(
                "Case-insensitive substring of the short name or the "
                "organization name. Outer whitespace is trimmed; a "
                "whitespace-only value is ignored. `%`, `_`, and backslash "
                "are literal."
            )
        ),
    ] = None,
    auto_ignore: Annotated[
        bool | None,
        Query(
            description=(
                "`true`: only the CNAs under the auto-ignore policy; `false`: "
                "only the others."
            )
        ),
    ] = None,
    page: Annotated[int, Query(ge=1, le=2_147_483_647, description="Page number.")] = 1,
    per_page: Annotated[
        int, Query(ge=1, le=100, description="Items per page; maximum 100.")
    ] = 20,
    sort_by: Annotated[
        CNASortField,
        Query(
            description=(
                "Sort field (default `name`): `name` (the display name) and "
                "`short_name` in Unicode code-point order, or `created_at`. "
                "`null` values sort last in both directions."
            )
        ),
    ] = CNASortField.NAME,
    sort_order: Annotated[
        SortOrder, Query(description="`asc` (default) or `desc`.")
    ] = SortOrder.ASC,
) -> CNAListQuery:
    """Collect the List CNAs query parameters.

    Declared as individual `Query()` parameters so each one is visible to
    the shared query-length-limit dependency (`app.core.query_limits`).
    """
    return CNAListQuery(
        search=search,
        auto_ignore=auto_ignore,
        page=page,
        per_page=per_page,
        sort_by=sort_by,
        sort_order=sort_order,
    )


@router.get(
    "/cnas",
    response_model=CNAListResponse,
    summary="List CNAs",
    description=(
        "Returns a paginated list of the CVE Numbering Authorities (CNAs) that "
        "own, or have owned, the record of an ingested CVE, with their display "
        "name, short name, the organization name, types, and plain-text scope "
        "of the CVE Program CNA list, and whether their new Tickets are "
        "ignored automatically. Supports search, an auto-ignore filter, and "
        "sorting. Requires authentication (JWT session or API key)."
    ),
)
async def list_cnas(
    db: DatabaseSession,
    _principal: CurrentUser,
    query: Annotated[CNAListQuery, Depends(_cna_list_query)],
) -> CNAListResponse:
    """List CNAs — see `docs/features/tickets/cna.md` (List CNAs).

    `_principal` exists solely to require authentication (`Access:
    Authenticated`); the listing does not vary by caller.
    """
    result = await cna_service.list_cnas(
        db,
        search=query.search,
        auto_ignore=query.auto_ignore,
        page=query.page,
        per_page=query.per_page,
        sort_by=query.sort_by,
        sort_order=query.sort_order,
    )
    return CNAListResponse(
        data=[serialize_cna(cna) for cna in result.items],
        meta=PaginationMeta(
            total=result.total, page=result.page, per_page=result.per_page
        ),
    )


@router.get(
    "/cnas/{org_id}",
    response_model=CNADetailResponse,
    summary="Get CNA",
    description=(
        "Returns one CNA, identified by its CVE Services UUID (`org_id`). "
        "Requires authentication (JWT session or API key)."
    ),
    responses={
        404: {
            "model": ErrorResponse,
            "description": (
                "`CNA_NOT_FOUND`: `{org_id}` is malformed or identifies no CNA."
            ),
        },
    },
)
async def get_cna(
    org_id: CNAOrgIdPath,
    db: DatabaseSession,
    _principal: CurrentUser,
) -> CNADetailResponse:
    """Get CNA — see `docs/features/tickets/cna.md` (Get CNA)."""
    try:
        cna = await cna_service.get_cna(db, org_id)
    except CNANotFoundError:
        raise _cna_not_found_error() from None
    return CNADetailResponse(data=serialize_cna(cna))


@router.patch(
    "/admin/cnas/{org_id}",
    response_model=CNADetailResponse,
    summary="Set CNA auto-ignore",
    description=(
        "Places a CNA under the auto-ignore policy or removes it, and records "
        "one CNA audit event for an effective change. The change applies to "
        "the Tickets that ingestion creates, or whose CNA it records, after "
        "the change; no existing Ticket changes. An unchanged request is an "
        "idempotent success with no audit event. Requires the "
        "manage_settings capability."
    ),
    responses={
        404: {
            "model": ErrorResponse,
            "description": (
                "`CNA_NOT_FOUND`: `{org_id}` is malformed or identifies no CNA."
            ),
        },
    },
)
async def set_cna_auto_ignore(
    org_id: CNAOrgIdPath,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_capability(Capability.MANAGE_SETTINGS)),
    ],
    db: DatabaseSession,
    body: CNAAutoIgnoreRequest,
) -> CNADetailResponse:
    """Set CNA Auto-Ignore — see `docs/features/tickets/cna.md` (Set CNA
    Auto-Ignore)."""
    try:
        cna = await cna_service.set_cna_auto_ignore(
            db,
            org_id=org_id,
            auto_ignore=body.auto_ignore,
            acting_user_id=principal.user.id,
        )
    except CNANotFoundError:
        raise _cna_not_found_error() from None
    return CNADetailResponse(data=serialize_cna(cna))


def _cna_audit_query(
    *,
    event_type: Annotated[
        list[str],
        Query(
            default_factory=list,
            description=(
                "Filter by event type. Repeatable; OR semantics. Invalid values "
                "are ignored; only invalid values yield an empty page."
            ),
            json_schema_extra=enum_filter_schema(CNAAuditEventType, repeatable=True),
        ),
    ],
    cna: Annotated[
        str | None,
        Query(
            description=(
                "`org_id` of a CNA: a UUID in the hyphenated 8-4-4-4-12 form, "
                "hexadecimal digits in either case. A malformed value fails "
                "validation; an unknown CNA yields an empty page."
            ),
            json_schema_extra=CNA_ORG_ID_SCHEMA,
        ),
        AfterValidator(validate_cna_org_id),
    ] = None,
    actor: Annotated[
        str | None,
        Query(
            description=(
                "Actor UUID, exact username, or 'system'. An unknown actor "
                "yields an empty page."
            )
        ),
    ] = None,
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
) -> CNAAuditQuery:
    """Collect the List CNA Audit Events query parameters.

    Declared as individual `Query()` parameters so each one is visible to
    the shared query-length-limit dependency (`app.core.query_limits`).
    """
    parsed_from = parse_date_range_bound("from_date", from_date)
    parsed_to = parse_date_range_bound("to_date", to_date)
    validate_date_range_order(parsed_from, parsed_to)
    return CNAAuditQuery(
        event_type=event_type,
        cna=cna,
        actor=actor,
        from_date=parsed_from,
        to_date=parsed_to,
        page=page,
        per_page=per_page,
    )


def _serialize_audit_event(item: CNAAuditEventItem) -> CNAAuditEventData:
    return CNAAuditEventData(
        id=item.id,
        event_type=CNAAuditEventType(item.event_type),
        cna=CNASummary(org_id=item.cna.org_id, name=item.cna.name),
        detail=item.detail,
        actor=UserReference.model_validate(item.actor),
        created_at=item.created_at,
    )


@router.get(
    "/admin/cnas/audit-log",
    response_model=CNAAuditListResponse,
    summary="List CNA audit events",
    description=(
        "Returns a paginated, fixed reverse-chronological list of the "
        "auto-ignore policy changes of CNAs. Supports filtering by event "
        "type, CNA, actor, and date range. Requires the manage_settings "
        "capability."
    ),
)
async def list_cna_audit_events(
    _principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_capability(Capability.MANAGE_SETTINGS)),
    ],
    db: DatabaseSession,
    query: Annotated[CNAAuditQuery, Depends(_cna_audit_query)],
) -> CNAAuditListResponse:
    """List CNA Audit Events — see `docs/features/tickets/cna.md` (List CNA
    Audit Events)."""
    result = await cna_service.list_cna_audit_events(
        db,
        event_type=query.event_type or None,
        cna=None if query.cna is None else uuid.UUID(query.cna),
        actor=query.actor,
        from_date=query.from_date,
        to_date=query.to_date,
        page=query.page,
        per_page=query.per_page,
    )
    return CNAAuditListResponse(
        data=[_serialize_audit_event(item) for item in result.items],
        meta=PaginationMeta(
            total=result.total, page=result.page, per_page=result.per_page
        ),
    )
