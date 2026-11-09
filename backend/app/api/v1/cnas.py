"""CNA read endpoints.

See `docs/features/tickets/cna.md` (API Endpoints: Response Schemas, List
CNAs, Get CNA; Security) for the authoritative endpoint contracts, and
`docs/api-spec.md` (CNA Identifier Resolution) for the shared `{org_id}`
locator behavior.

Handlers stay thin: they require authentication, delegate to
`cna_service`, map `CNANotFoundError` to `404 CNA_NOT_FOUND`, and serialize
the row. No database query lives here. The reads expose public CVE Program
data and no Ticket or CVE identifier, so they apply no Ticket visibility.

`serialize_cna_summary()` is the one `CNASummary` serializer, shared by the
CVE representations of the CVE and Ticket endpoints.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Path, Query, status

from app.api.dependencies import CurrentUser
from app.core.enums import CNASortField, SortOrder
from app.core.errors import AppError, ErrorCode
from app.database import DatabaseSession
from app.models.cna import CNA
from app.schemas.cna import (
    CNADetailResponse,
    CNAListQuery,
    CNAListResponse,
    CNAResponse,
    CNASummary,
)
from app.schemas.common import PaginationMeta
from app.schemas.errors import ErrorResponse
from app.services import cna_service
from app.services.cna_service import CNANotFoundError
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
