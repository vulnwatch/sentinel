"""Platform version endpoint.

See `docs/features/platform/platform-version.md` (Get Platform Version) for
the authoritative contract.

The version is process metadata, not application data: the handler reads it
from the FastAPI application that serves the request, which `app.main`
creates with the version of the installed `sentinel` package and publishes as
`info.version` of the OpenAPI document, so the two are equal by construction.
No service or database operation is involved beyond authentication.
"""

from __future__ import annotations

from fastapi import APIRouter, FastAPI, Request

from app.api.dependencies import CurrentUser
from app.schemas.platform import PlatformVersionData, PlatformVersionResponse

router = APIRouter(prefix="/api/v1", tags=["Platform"])


@router.get(
    "/version",
    response_model=PlatformVersionResponse,
    summary="Get platform version",
    description=(
        "Returns the platform version of the Sentinel process that serves the "
        "request: the same value as `info.version` of the OpenAPI document "
        "that it serves, identical for every caller and constant for the life "
        "of the process. Requires authentication (JWT session or API key)."
    ),
)
async def get_platform_version(
    request: Request, _principal: CurrentUser
) -> PlatformVersionResponse:
    """Get Platform Version — see `docs/features/platform/platform-version.md`.

    `_principal` exists solely to require authentication (`Access:
    Authenticated`); the value does not vary by caller.
    """
    application: FastAPI = request.app
    return PlatformVersionResponse(
        data=PlatformVersionData(version=application.version)
    )
