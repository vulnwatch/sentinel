"""Pure syntax of the public CVE and Ticket identifiers.

Core owns only transport-independent identifier syntax; database
resolution and Ticket/CVE visibility belong to the Service layer (see
`docs/architecture.md`, Backend Layer Architecture, and
`docs/conventions.md`, FastAPI Conventions — Model-aware resource
resolution).

- CVE-ID: `docs/api-spec.md` (CVE Identifier Resolution) and
  `docs/features/tickets/cve-service.md` (Caller Validation
  Responsibility). `CVE_ID_PATTERN` is the single source of truth for
  CVE-ID syntax.
- `SNTL-{n}`: `docs/api-spec.md` (Ticket Identifier Resolution) and
  `docs/features/tickets/tickets.md` (SNTL-{n} Format). The canonical
  grammar is `^SNTL-[1-9][0-9]*$` with `n` within the positive
  PostgreSQL `INTEGER` range. Parsing performs no trimming, case,
  sign, or zero-padding normalization.
- CNA `org_id`: `docs/api-spec.md` (CNA Identifier Resolution) and
  `docs/features/platform/cve-record-parser.md` (`parse_cna_owner`). The
  CVE Services UUID of a CNA in the hyphenated 8-4-4-4-12 form, with
  hexadecimal digits in either case; the version and variant digits are not
  checked.

Every value is matched against the complete string (`re.fullmatch`), so
a trailing newline — which `$` alone would tolerate — is rejected. The
`[0-9]` classes accept only ASCII digits.
"""

from __future__ import annotations

import re
import uuid
from typing import Final

CVE_ID_PATTERN: Final[re.Pattern[str]] = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
"""Canonical CVE-ID syntax."""

CVE_ID_MAX_LENGTH: Final = 20
"""Maximum CVE-ID length (matches the `VARCHAR(20)` column)."""

TICKET_ID_PREFIX: Final = "SNTL-"
"""Prefix of the canonical public Ticket identifier."""

TICKET_ID_PATTERN: Final[re.Pattern[str]] = re.compile(r"^SNTL-[1-9][0-9]*$")
"""Canonical `SNTL-{n}` syntax (the range is checked separately)."""

TICKET_SEQUENCE_ID_MAX: Final = 2_147_483_647
"""Largest positive PostgreSQL `INTEGER`, the upper bound of `n`."""

TICKET_ID_MAX_LENGTH: Final = len(TICKET_ID_PREFIX) + len(str(TICKET_SEQUENCE_ID_MAX))
"""Maximum canonical identifier length: `SNTL-` plus the ten digits of
`TICKET_SEQUENCE_ID_MAX`. Longer input is rejected before regex matching and
integer conversion, so the cost of rejecting an arbitrarily long value is
constant."""

CNA_ORG_ID_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$"
)
"""Syntax of a CNA `org_id`: a UUID in the hyphenated form, either case."""


def is_valid_cve_id(value: object) -> bool:
    """Whether `value` is a canonical CVE-ID.

    True only for a string of at most `CVE_ID_MAX_LENGTH` characters that
    fully matches `CVE_ID_PATTERN`. Returns `False` for every non-string
    input, including `None`, to guard against upstream parsing bugs.
    Pure predicate: never raises and has no side effects.
    """
    return (
        isinstance(value, str)
        and len(value) <= CVE_ID_MAX_LENGTH
        and CVE_ID_PATTERN.fullmatch(value) is not None
    )


def parse_ticket_id(value: str) -> int | None:
    """Parse a canonical `SNTL-{n}` identifier into its `sequence_id`.

    Returns `n` when `value` fully matches the canonical grammar and
    `1 <= n <= TICKET_SEQUENCE_ID_MAX`; otherwise `None`. Lowercase
    prefixes, surrounding whitespace, `SNTL-0`, signed or zero-padded
    values, overflow, UUIDs, and every other shape are malformed. Callers
    map `None` to their own contract (for example `404 TICKET_NOT_FOUND`
    for a path, `422 VALIDATION_ERROR` for a request-body field). Pure:
    never raises for a string input and has no side effects.
    """
    if len(value) > TICKET_ID_MAX_LENGTH or TICKET_ID_PATTERN.fullmatch(value) is None:
        return None
    sequence_id = int(value[len(TICKET_ID_PREFIX) :])
    if sequence_id > TICKET_SEQUENCE_ID_MAX:
        return None
    return sequence_id


def format_ticket_id(sequence_id: int) -> str:
    """Format a `Ticket.sequence_id` as its public `SNTL-{n}` identifier.

    No zero-padding is applied. The result always round-trips through
    `parse_ticket_id()`.

    Raises:
        ValueError: `sequence_id` is outside `1..TICKET_SEQUENCE_ID_MAX`
            (an internal contract violation: persisted sequence IDs are
            always in range).
    """
    if not 1 <= sequence_id <= TICKET_SEQUENCE_ID_MAX:
        raise ValueError("Ticket sequence_id must be within 1..2147483647.")
    return f"{TICKET_ID_PREFIX}{sequence_id}"


def parse_cna_org_id(value: object) -> uuid.UUID | None:
    """Parse a CNA `org_id` in the hyphenated 8-4-4-4-12 form.

    Returns the UUID, compared by value, when `value` is a string that fully
    matches `CNA_ORG_ID_PATTERN`; otherwise `None`. The unhyphenated, braced,
    and `urn:uuid:` forms that `uuid.UUID` also accepts, surrounding
    whitespace, and every non-string are malformed. Callers map `None` to
    their own contract (for example `404 CNA_NOT_FOUND` for a path, `422
    VALIDATION_ERROR` for a filter, or an omitted owner for an upstream
    record). Pure: never raises and has no side effects.
    """
    if not isinstance(value, str) or CNA_ORG_ID_PATTERN.fullmatch(value) is None:
        return None
    return uuid.UUID(value)
