"""Response schema of the platform version endpoint.

See `docs/features/platform/platform-version.md` (Get Platform Version) for
the authoritative contract.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class PlatformVersionData(BaseModel):
    """The platform version of the process that serves the request."""

    version: str = Field(
        description=(
            "Platform version of the process that serves the request, in the "
            "form `<major>.<minor>.<patch>`: the version of its release tag "
            "without the `v` prefix. Equal to `info.version` of the OpenAPI "
            "document that the same process serves."
        ),
        examples=["0.13.1"],
    )


class PlatformVersionResponse(BaseModel):
    """Single-resource envelope of `GET /api/v1/version`."""

    data: PlatformVersionData
