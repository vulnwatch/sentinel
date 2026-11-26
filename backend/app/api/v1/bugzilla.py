"""Bugzilla needinfo count endpoint.

See `docs/features/integrations/bugzilla-needinfo-count.md` (API Endpoint >
Get Bugzilla Needinfo Count) for the authoritative contract and
`docs/features/identity/rbac.md` (Endpoint Permission Map > Bugzilla) for
its access level.

The handler stays thin: it requires `triage_ticket`, delegates to
`bugzilla_needinfo_service.get_needinfo_count()`, and maps
`BugzillaUnavailableError` to `503 BUGZILLA_UNAVAILABLE`.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, status

from app.api.dependencies import AuthenticatedPrincipal, require_capability
from app.core.enums import Capability
from app.core.errors import AppError, ErrorCode
from app.schemas.bugzilla import (
    BugzillaNeedinfoCountData,
    BugzillaNeedinfoCountResponse,
)
from app.schemas.errors import ErrorResponse
from app.services import bugzilla_needinfo_service
from app.services.bugzilla_needinfo_service import BugzillaUnavailableError

router = APIRouter(prefix="/api/v1", tags=["Bugzilla"])


@router.get(
    "/bugzilla/needinfo-count",
    response_model=BugzillaNeedinfoCountResponse,
    summary="Get the Bugzilla needinfo count",
    description=(
        "Returns the number of open SUSE Bugzilla bugs on which a `needinfo?` "
        "flag asks `security-team@suse.de` for information, whether the "
        "Bugzilla read was authenticated with Sentinel's API key, and the URL "
        "of the matching Bugzilla web search. The result is the same for "
        "every caller and is cached for up to 60 seconds; a response can "
        "take up to about 15 seconds while Bugzilla is read. Requires "
        "`triage_ticket`."
    ),
    responses={
        503: {
            "model": ErrorResponse,
            "description": (
                "`BUGZILLA_UNAVAILABLE`: no valid count could be obtained from "
                "SUSE Bugzilla."
            ),
        },
    },
)
async def get_bugzilla_needinfo_count(
    _principal: Annotated[
        AuthenticatedPrincipal, Depends(require_capability(Capability.TRIAGE_TICKET))
    ],
) -> BugzillaNeedinfoCountResponse:
    """Get Bugzilla Needinfo Count — see
    `docs/features/integrations/bugzilla-needinfo-count.md`.

    `_principal` exists solely to require `triage_ticket`; the result does
    not vary by caller.
    """
    try:
        result = await bugzilla_needinfo_service.get_needinfo_count()
    except BugzillaUnavailableError:
        raise AppError(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            code=ErrorCode.BUGZILLA_UNAVAILABLE,
            detail=bugzilla_needinfo_service.UNAVAILABLE_MESSAGE,
        ) from None
    return BugzillaNeedinfoCountResponse(
        data=BugzillaNeedinfoCountData(
            count=result.count, authenticated=result.authenticated, url=result.url
        )
    )
