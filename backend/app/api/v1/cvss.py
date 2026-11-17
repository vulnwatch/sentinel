"""CVSS calculation endpoint.

See `docs/features/tickets/cvss-scoring.md` (Calculate CVSS Base Score;
Input Rules; Stable Parsed Result; Shared Assessment Item) for the
authoritative contract.

The handler stays thin: it passes the received vector to the pure
`validate_cvss_vector()`, the parser that Set or Update SUSE CVSS
Assessment applies too, maps `InvalidCVSSVectorError` to the response that
the upsert returns, and serializes the parsed result. Beyond
authentication, no application state is read or written.
"""

from __future__ import annotations

from dataclasses import fields
from typing import Annotated

from fastapi import APIRouter, Query
from pydantic import TypeAdapter

from app.api.dependencies import CurrentUser, cvss_invalid_vector_error
from app.schemas.cvss import (
    CVSS_VECTOR_MAX_LENGTH,
    CVSSBaseScore,
    CVSSBaseScoreResponse,
)
from app.schemas.errors import ErrorResponse, ValidationErrorResponse
from app.services.cvss import ParsedCVSSVector, validate_cvss_vector
from app.services.ticket_mutations_errors import InvalidCVSSVectorError

router = APIRouter(prefix="/api/v1", tags=["CVSS"])

_BASE_SCORE: TypeAdapter[CVSSBaseScore] = TypeAdapter(CVSSBaseScore)

CVSSVectorQuery = Annotated[
    str,
    Query(
        max_length=CVSS_VECTOR_MAX_LENGTH,
        description=(
            "CVSS Base vector (v2.0, v3.0, v3.1, or v4.0), at most 200 "
            "characters as received. Leading and trailing whitespace is "
            "trimmed; the rest must be a complete Base vector in official "
            "case, with the prefix of its version (none for v2.0) and every "
            "Base metric exactly once in any order, and no Temporal, "
            "Environmental, Threat, or Supplemental metric. Any other value "
            "returns `422 CVSS_INVALID_VECTOR`."
        ),
        examples=["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"],
    ),
]
"""The `vector_string` query parameter: the received string of the Input
Rules, whose rule 1 replaces the shared 500-character limit."""


def serialize_cvss_base_score(parsed: ParsedCVSSVector) -> CVSSBaseScore:
    """Project one parsed vector onto the version-discriminated result."""
    metrics = parsed.metrics
    return _BASE_SCORE.validate_python(
        {
            "cvss_version": parsed.version.value,
            "score": float(parsed.score),
            "severity": parsed.severity,
            "vector_string": parsed.canonical_vector,
            "metrics": {
                field.name: getattr(metrics, field.name) for field in fields(metrics)
            },
        }
    )


@router.get(
    "/cvss/base-score",
    response_model=CVSSBaseScoreResponse,
    summary="Calculate the Base score of a CVSS vector",
    description=(
        "Parses one CVSS Base vector as Set or Update SUSE CVSS Assessment "
        "does and returns its canonical vector, version, Base score, "
        "assessment severity, and expanded Base metrics, without storing "
        "anything: the result depends only on the vector and is the same "
        "for every caller. A vector that the SUSE upsert rejects is "
        "rejected with the same status and code, and a vector with a "
        "non-Base metric is rejected, never reduced. Requires "
        "authentication (JWT session or API key)."
    ),
    responses={
        422: {
            "model": ValidationErrorResponse | ErrorResponse,
            "description": (
                "`CVSS_INVALID_VECTOR`: the string passes the schema checks but "
                "violates the accepted Base-vector contract. `VALIDATION_ERROR`: "
                "the request fails validation."
            ),
        },
    },
)
async def get_cvss_base_score(
    vector_string: CVSSVectorQuery, _principal: CurrentUser
) -> CVSSBaseScoreResponse:
    """Calculate CVSS Base Score — see
    `docs/features/tickets/cvss-scoring.md`.

    `_principal` exists solely to require authentication (`Access:
    Authenticated`); the result does not vary by caller.
    """
    try:
        parsed = validate_cvss_vector(vector_string)
    except InvalidCVSSVectorError:
        raise cvss_invalid_vector_error() from None
    return CVSSBaseScoreResponse(data=serialize_cvss_base_score(parsed))
