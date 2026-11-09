"""Schemas for the CNA of a CVE, the CNA read endpoints, the auto-ignore
policy operation, and the CNA audit log.

See `docs/features/tickets/cna.md` (Response Schemas: `CNASummary`,
`CNAResponse`; List CNAs; Get CNA; Set CNA Auto-Ignore; List CNA Audit
Events; Security) and `docs/api-spec.md` (CNA Identifier Resolution): the
CVE Services `org_id` is the public identity of a CNA, serialized in
lowercase hyphenated form, and the internal `CNA.id` is never serialized.
`name`, `organization_name`, `types`, and `scope` are plain text that a
client presents as text, never as markup.

`CNA_ORG_ID_FILTER_SCHEMA` and `validate_cna_org_id_filter()` are the
published and enforced form of the repeatable `cna` filter shared by List
Tickets and List CVEs; `CNA_ORG_ID_SCHEMA` and `validate_cna_org_id()` are
those of the single-valued `cna` filter of the CNA audit log.
"""

from __future__ import annotations

import uuid
from datetime import date, datetime
from typing import Any

from pydantic import BaseModel, Field

from app.core.enums import CNAAuditEventType, CNASortField, SortOrder
from app.core.identifiers import CNA_ORG_ID_PATTERN, parse_cna_org_id
from app.schemas.common import PaginationMeta, UserReference

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


CNA_ORG_ID_SCHEMA: dict[str, Any] = {"pattern": CNA_ORG_ID_PATTERN.pattern}
"""The `json_schema_extra` of a single-valued `cna` filter: the grammar that
`validate_cna_org_id()` enforces (`docs/api-spec.md`, CNA Identifier
Resolution; Published Input Constraints)."""


def validate_cna_org_id(value: str) -> str:
    """Accept a single-valued `cna` filter only when it is a UUID in the
    hyphenated form.

    Raises `ValueError`, which validation reports as the global `422
    VALIDATION_ERROR`, for any other value; returns the value unchanged.
    """
    if parse_cna_org_id(value) is None:
        raise ValueError("cna must be a UUID in the hyphenated form.")
    return value


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


class CNAAutoIgnoreRequest(BaseModel):
    """Request body of `PATCH /api/v1/admin/cnas/{org_id}` (cna.md, Set CNA
    Auto-Ignore).

    The single field is required (single-field PATCH, `docs/api-spec.md`,
    Partial Update Semantics) and strict (JSON Request Body Scalar Types):
    an omitted field, `null`, or a value of another type is the global
    `422 VALIDATION_ERROR`.
    """

    auto_ignore: bool = Field(
        strict=True,
        description=(
            "`true` places the CNA under the auto-ignore policy, so that the "
            "Tickets that ingestion creates for its published CVEs, or whose "
            "CNA ingestion records afterwards, are ignored with the reason "
            "`cna_policy` while they are `new` and not confidential; `false` "
            "removes it. Applies only to later ingestions; no existing "
            "Ticket changes. Required."
        ),
        examples=[True],
    )


class CNAAuditQuery(BaseModel):
    """Query parameters of `GET /api/v1/admin/cnas/audit-log` (cna.md, List
    CNA Audit Events).

    `event_type` is intentionally `list[str]`, not a list of
    `CNAAuditEventType`: an invalid value is ignored and an entirely
    invalid filter yields an empty page (`docs/api-spec.md`, Enum Filter
    Validation) rather than the `422` of a typed enum. `cna` has already
    passed `validate_cna_org_id()`. `from_date`/`to_date` are already
    parsed by `app.core.dates.parse_date_range_bound()`, and an inverted
    range has been rejected (`400 DATE_RANGE_INVERTED`).
    """

    event_type: list[str] = Field(default_factory=list)
    cna: str | None = None
    actor: str | None = None
    from_date: date | datetime | None = None
    to_date: date | datetime | None = None
    page: int = Field(default=1, ge=1, le=2_147_483_647)
    per_page: int = Field(default=20, ge=1, le=100)


class CNAAuditEventData(BaseModel):
    """One event of the CNA audit log (cna.md, List CNA Audit Events).

    `cna` is the current reference of the CNA; `detail.cna_name` is its
    display name when the event was recorded. `actor` is always the
    complete current user reference, because every CNA audit event has a
    human actor and users are never deleted.
    """

    id: uuid.UUID
    event_type: CNAAuditEventType
    cna: CNASummary = Field(description="Current reference of the CNA.")
    detail: dict[str, Any] = Field(
        description=(
            "`cna_name`: the display name of the CNA when the event was "
            "recorded, or `null` when it had none."
        ),
        examples=[{"cna_name": "Fictional Plugin Foundation"}],
    )
    actor: UserReference
    created_at: datetime


class CNAAuditListResponse(BaseModel):
    """Response body for `GET /api/v1/admin/cnas/audit-log` (paginated)."""

    data: list[CNAAuditEventData]
    meta: PaginationMeta
