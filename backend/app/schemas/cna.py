"""Schemas for the CNA of a CVE and the CNA read endpoints.

See `docs/features/tickets/cna.md` (Response Schemas: `CNASummary`,
`CNAResponse`; List CNAs; Get CNA; Security) and `docs/api-spec.md` (CNA
Identifier Resolution): the CVE Services `org_id` is the public identity
of a CNA, serialized in lowercase hyphenated form, and the internal
`CNA.id` is never serialized. `name`, `organization_name`, `types`, and
`scope` are plain text that a client presents as text, never as markup.

`CNA_ORG_ID_FILTER_SCHEMA` and `validate_cna_org_id_filter()` are the
published and enforced form of the repeatable `cna` filter shared by List
Tickets and List CVEs.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from app.core.enums import CNASortField, SortOrder
from app.core.identifiers import CNA_ORG_ID_PATTERN, parse_cna_org_id
from app.schemas.common import PaginationMeta

_NAME_DESCRIPTION = (
    "Display name: the organization name from the CVE Program CNA list, "
    "otherwise the short name of the CNA's CVE Records; `null` while the CNA "
    "has no short name. Never an identifier."
)

CNA_ORG_ID_FILTER_SCHEMA: dict[str, Any] = {
    "items": {"type": "string", "pattern": CNA_ORG_ID_PATTERN.pattern}
}
"""The `json_schema_extra` of a repeatable `cna` filter: the hyphenated UUID
grammar that `validate_cna_org_id_filter()` enforces, published on each
value from the same Core pattern (`docs/api-spec.md`, CNA Identifier
Resolution; Published Input Constraints)."""

CNA_ORG_ID_FILTER_DESCRIPTION = (
    "`org_id` of a CNA: a UUID in the hyphenated 8-4-4-4-12 form, hexadecimal "
    "digits in either case. Repeatable; OR semantics. A malformed value fails "
    "validation; an unknown CNA yields no match."
)


def validate_cna_org_id_filter(values: list[str]) -> list[str]:
    """Accept a repeatable `cna` filter only when every value is a UUID in
    the hyphenated form (`docs/api-spec.md`, CNA Identifier Resolution).

    Raises `ValueError`, which validation reports as the global `422
    VALIDATION_ERROR`, for any other value; returns the values unchanged.
    """
    if any(parse_cna_org_id(value) is None for value in values):
        raise ValueError("cna must be a UUID in the hyphenated form.")
    return values


def cna_org_id_filter(values: list[str]) -> list[uuid.UUID] | None:
    """The validated `cna` filter values as UUIDs; `None` when omitted."""
    if not values:
        return None
    return [uuid.UUID(value) for value in values]


class CNASummary(BaseModel):
    """Compact reference to the CNA that owns a CVE Record (cna.md,
    Response Schemas > CNASummary)."""

    org_id: uuid.UUID = Field(
        description=(
            "CVE Services UUID of the CNA, lowercase hyphenated form; locates "
            "the CNA in `GET /api/v1/cnas/{org_id}`."
        )
    )
    name: str | None = Field(description=_NAME_DESCRIPTION)


class CNAResponse(BaseModel):
    """One CNA (cna.md, Response Schemas > CNAResponse)."""

    org_id: uuid.UUID = Field(
        description="CVE Services UUID of the CNA, lowercase hyphenated form."
    )
    name: str | None = Field(description=_NAME_DESCRIPTION)
    short_name: str | None = Field(
        description=(
            "Short name of the CNA in its CVE Records; `null` until a record "
            "supplies one."
        )
    )
    organization_name: str | None = Field(
        description="Organization name from the CVE Program CNA list."
    )
    types: list[str] = Field(
        description=(
            "CNA types from the CVE Program CNA list, in ascending Unicode "
            "code-point order; empty when unknown. Values are those of the "
            "list, such as `Vendor`, `Open Source`, or `Researcher`, and are "
            "not a closed set."
        )
    )
    scope: str | None = Field(
        description=(
            "Scope from the CVE Program CNA list as plain text, which may "
            "contain line feeds; never markup."
        )
    )
    auto_ignore: bool = Field(
        description=(
            "Whether the new Tickets of the CNA are ignored automatically "
            "(auto-ignore policy)."
        )
    )
    created_at: datetime = Field(description="When Sentinel recorded the CNA (UTC).")
    updated_at: datetime = Field(description="Last change of the row (UTC).")


class CNAListResponse(BaseModel):
    """Response body for `GET /api/v1/cnas` (paginated)."""

    data: list[CNAResponse]
    meta: PaginationMeta


class CNADetailResponse(BaseModel):
    """Response body for `GET /api/v1/cnas/{org_id}`."""

    data: CNAResponse


class CNAListQuery(BaseModel):
    """Query parameters of `GET /api/v1/cnas` (cna.md, List CNAs > Query
    parameters). `sort_by` and `sort_order` are typed, so an invalid value
    is the global `422 VALIDATION_ERROR`."""

    search: str | None = None
    auto_ignore: bool | None = None
    page: int = Field(default=1, ge=1, le=2_147_483_647)
    per_page: int = Field(default=20, ge=1, le=100)
    sort_by: CNASortField = CNASortField.NAME
    sort_order: SortOrder = SortOrder.ASC
