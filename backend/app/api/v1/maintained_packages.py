"""Search of the source package names that SMELT maintains.

See `docs/features/packages/maintained-package-names.md` (API Endpoints,
Search Maintained Packages) for the authoritative endpoint contract, and
`docs/api-spec.md` (Query Parameter Length Limit; Pagination) for the shared
behavior.

The handler stays thin: it requires authentication, delegates the search to
`search_maintained_packages()`, and serializes the names. It runs no
database query and never contacts SMELT.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Query

from app.api.dependencies import CurrentUser
from app.database import DatabaseSession
from app.schemas.common import PaginationMeta
from app.schemas.maintained_package import (
    MaintainedPackageItem,
    MaintainedPackageListResponse,
)
from app.services.packages import maintained_package_names

router = APIRouter(prefix="/api/v1", tags=["Maintained Packages"])


@router.get(
    "/maintained-packages",
    response_model=MaintainedPackageListResponse,
    summary="Search Maintained Packages",
    description=(
        "Returns a paginated list of the names of the source packages that "
        "SMELT maintains, from the latest snapshot that Sentinel synchronized, "
        "optionally matching a term. Each name is the exact name that Add "
        "Package to Ticket accepts. The order is fixed: the names that start "
        "with the term first, then the others, each group in Unicode "
        "code-point order. The endpoint does not contact SMELT; before the "
        "first snapshot, the list is empty. Requires authentication (JWT "
        "session or API key)."
    ),
)
async def search_maintained_package_names(
    db: DatabaseSession,
    _principal: CurrentUser,
    search: Annotated[
        str | None,
        Query(
            description=(
                "Case-insensitive substring match on the name. Outer whitespace "
                "is trimmed once; an empty result means no filter. `%`, `_`, and "
                "backslash are literal."
            )
        ),
    ] = None,
    page: Annotated[int, Query(ge=1, le=2_147_483_647, description="Page number.")] = 1,
    per_page: Annotated[
        int, Query(ge=1, le=100, description="Items per page; maximum 100.")
    ] = 20,
) -> MaintainedPackageListResponse:
    """Search Maintained Packages — see
    `docs/features/packages/maintained-package-names.md`.

    `_principal` exists solely to require authentication (`Access:
    Authenticated`); the result does not vary by caller.
    """
    result = await maintained_package_names.search_maintained_packages(
        db, search=search, page=page, per_page=per_page
    )
    return MaintainedPackageListResponse(
        data=[MaintainedPackageItem(name=name) for name in result.names],
        meta=PaginationMeta(
            total=result.total, page=result.page, per_page=result.per_page
        ),
    )
