"""Typed model and pure selection of SUSE Bugzilla `/rest/bug` responses.

Implements docs/features/tickets/cve-sync-bugzilla.md (The Bug of a CVE;
Response Validation; Field Mapping) for the decoded body of one HTTP 200
response: a page of the periodic window or the `fetch_single()` answer.
The module performs no HTTP, database, or logging work; `SyncBugzillaBugs`
(`sync_bugzilla_bugs.py`) owns the requests and the ingestion.

`parse_response()` validates only the consumed fields, strictly and
without coercion: the root is an object whose `bugs` is an array of
objects carrying `id` as a positive integer (a boolean is not an
integer), `alias` as an array of strings, `summary` as a string, and
`groups` as an array. Unconsumed members are ignored. Any other shape
raises `pydantic.ValidationError`, whose message never renders the input.
`parse_page()` adds the keyset rule of a periodic page. `bugs_by_cve()`
selects the bugs of each CVE: public bugs only, exact canonical CVE
aliases only, in ascending bug ID order. An alias is never checked for
admissibility: a value containing an inadmissible character is not a
canonical CVE ID and names no CVE.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.core.identifiers import is_valid_cve_id


class PageOrderError(ValueError):
    """A periodic page whose bug IDs are not strictly ascending, or not all
    greater than the page's `after_id` (Response Validation). The fixed
    message carries no upstream data."""

    def __init__(self) -> None:
        super().__init__("Bug IDs of the page are not strictly ascending")


class _ConsumedFields(BaseModel):
    """Strict, unknown-field-ignoring shape of consumed fields only."""

    model_config = ConfigDict(
        strict=True, extra="ignore", frozen=True, hide_input_in_errors=True
    )


class BugzillaBug(_ConsumedFields):
    """One element of `bugs`: the four members that `include_fields`
    requests (Field Mapping)."""

    id: int = Field(gt=0)
    alias: list[str]
    summary: str
    groups: list[Any]

    @property
    def is_public(self) -> bool:
        """A bug whose `groups` array is empty (The Bug of a CVE, Public
        bug); the items of `groups` are never consumed."""
        return not self.groups

    def cve_aliases(self) -> tuple[str, ...]:
        """The CVE aliases: the aliases that are canonical CVE IDs, once
        each, in alias order. Another letter case names no CVE."""
        return tuple(dict.fromkeys(a for a in self.alias if is_valid_cve_id(a)))


class BugzillaResponse(_ConsumedFields):
    """The consumed root: `bugs`; other root members are ignored."""

    bugs: list[BugzillaBug]


def parse_response(document: object) -> BugzillaResponse:
    """Validate a decoded response body (Response Validation).

    Raises `pydantic.ValidationError` for a non-object root, a missing or
    non-array `bugs`, or an element that is not an object or whose
    consumed member is missing or mistyped.
    """
    return BugzillaResponse.model_validate(document)


def parse_page(document: object, after_id: int) -> list[BugzillaBug]:
    """Validate one periodic page requested with `after_id`.

    Raises `pydantic.ValidationError` as `parse_response()`, and
    `PageOrderError` when the bug IDs are not strictly ascending or one is
    not greater than `after_id`, so that the pagination progresses and
    ends.
    """
    bugs = parse_response(document).bugs
    previous = after_id
    for item in bugs:
        if item.id <= previous:
            raise PageOrderError()
        previous = item.id
    return bugs


def bugs_by_cve(bugs: Iterable[BugzillaBug]) -> dict[str, list[BugzillaBug]]:
    """The bugs of each CVE (The Bug of a CVE, Bugs of a CVE; Algorithm,
    step 5).

    Every public bug is added once to each of its CVE aliases. A bug that
    is not public, a bug without a CVE alias, and an alias that is not a
    CVE alias contribute nothing. Keys are in ascending code-point order
    of the CVE ID and each list in ascending bug ID order.
    """
    grouped: dict[str, list[BugzillaBug]] = {}
    for item in bugs:
        if not item.is_public:
            continue
        for cve_id in item.cve_aliases():
            grouped.setdefault(cve_id, []).append(item)
    return {
        cve_id: sorted(grouped[cve_id], key=lambda item: item.id)
        for cve_id in sorted(grouped)
    }
