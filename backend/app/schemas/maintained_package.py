"""Schemas for the search of maintained package names.

See `docs/features/packages/maintained-package-names.md` (API Endpoints,
Search Maintained Packages). The internal `MaintainedPackage.id` is never
serialized.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from app.schemas.common import PaginationMeta


class MaintainedPackageItem(BaseModel):
    """One name of `GET /api/v1/maintained-packages`."""

    name: str = Field(
        description=(
            "The source package name exactly as SMELT maintains it, with its "
            "letter case."
        )
    )


class MaintainedPackageListResponse(BaseModel):
    """Response body of `GET /api/v1/maintained-packages` (paginated)."""

    data: list[MaintainedPackageItem]
    meta: PaginationMeta
