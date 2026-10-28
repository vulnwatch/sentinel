"""Request/response/query schemas for identity audit log endpoints.

See `docs/features/identity/identity-audit-log.md` (API) for the
authoritative request/response contract these schemas implement.
"""

from __future__ import annotations

from datetime import date, datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field

from app.schemas.common import PaginationMeta, UserReference


class IdentityAuditQuery(BaseModel):
    """Common list query parameters shared by the self-service and admin
    identity audit log endpoints.

    `event_type` is intentionally `list[str]`, not
    `list[IdentityAuditEventType]`: an invalid value must be silently
    ignored and produce an empty result (`docs/api-spec.md`, Enum Filter
    Validation) rather than the schema-validation `422` a typed enum
    field would raise. The route handler parses each value against
    `IdentityAuditEventType` itself.

    `from_date`/`to_date` are already-parsed `date`/`datetime` values by
    the time this model is constructed — the API layer's
    `app.core.dates.parse_date_range_bound()` performs the strict ISO
    8601 parsing (and its `422` rejection) before this model sees them.
    An inverted normalized range is validated separately by
    `app.core.dates.validate_date_range_order()` (`400
    DATE_RANGE_INVERTED`).
    """

    event_type: list[str] = Field(default_factory=list)
    from_date: date | datetime | None = None
    to_date: date | datetime | None = None
    page: int = Field(default=1, ge=1, le=2_147_483_647)
    per_page: int = Field(default=20, ge=1, le=100)


class AdminIdentityAuditQuery(IdentityAuditQuery):
    """Admin list query parameters: the common set plus `actor` and
    `target_user`."""

    actor: str | None = None
    target_user: str | None = None


class AdminIdentityAuditEventData(BaseModel):
    """One event in the admin identity audit log response
    (`identity-audit-log.md`, List Identity Audit Events). `actor` is
    `None` for a system-initiated event; `target_user` is `None` for a
    configuration event (e.g. `role_mapping_created`) with no single
    affected user."""

    id: UUID
    event_type: str
    old_value: str | None
    new_value: str | None
    detail: dict[str, Any] | None
    created_at: datetime
    actor: UserReference | None
    target_user: UserReference | None


class SelfIdentityAuditEventData(BaseModel):
    """One event in the self-service identity audit log response
    (`identity-audit-log.md`, List My Identity Audit Events). `actor` is the
    user reference of the recorded actor, the caller's own included, or
    `None` for an event with no recorded actor (`rbac.md`, Actor
    Identities). The target is always the caller, so it is omitted."""

    id: UUID
    event_type: str
    old_value: str | None
    new_value: str | None
    detail: dict[str, Any] | None
    created_at: datetime
    actor: UserReference | None


class AdminIdentityAuditListResponse(BaseModel):
    """Response body for `GET /api/v1/admin/identity/audit-log`."""

    data: list[AdminIdentityAuditEventData]
    meta: PaginationMeta


class SelfIdentityAuditListResponse(BaseModel):
    """Response body for `GET /api/v1/users/me/audit-log`."""

    data: list[SelfIdentityAuditEventData]
    meta: PaginationMeta
