"""Response schema of the Bugzilla needinfo count.

See `docs/features/integrations/bugzilla-needinfo-count.md` (API Endpoint >
Get Bugzilla Needinfo Count) for the authoritative contract.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class BugzillaNeedinfoCountData(BaseModel):
    """The count of open SUSE Bugzilla needinfo requests to the security
    team."""

    count: int = Field(
        description=(
            "The number of open bugs that match the search for a `needinfo?` "
            "flag with the requestee `security-team@suse.de`, among the bugs "
            "that the Bugzilla read could see. At least 0 and at most 10000. "
            "It can lag Bugzilla by up to 60 seconds."
        )
    )
    authenticated: bool = Field(
        description=(
            "Whether the Bugzilla read that produced `count` was authenticated "
            "with Sentinel's API key. `true`: `count` can also include "
            "restricted bugs that the key's Bugzilla account can see. `false`: "
            "no API key is configured, so `count` includes only public bugs. "
            "`true` does not prove that `count` includes every restricted bug."
        )
    )
    url: str = Field(
        description=(
            "The URL of the Bugzilla web search with the same conditions; the "
            "same for every response of a release."
        )
    )


class BugzillaNeedinfoCountResponse(BaseModel):
    """Single-resource envelope of `GET /api/v1/bugzilla/needinfo-count`."""

    data: BugzillaNeedinfoCountData
