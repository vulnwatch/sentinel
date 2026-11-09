"""The CVE Program CNA list: entries, matching, field mapping, and the
plain-text scope.

Implements docs/features/tickets/cna.md (Fetcher: `sync_mitre_cnas` —
Algorithm step 3, CNA Entry Matching, Field Mapping, Scope Plain Text,
External String Admissibility). Every function is pure: no I/O, no
database access, and no logging; `sync_mitre_cnas` performs the request,
the reads, the writes, the metrics, and the warnings.

The list identifies a CNA only by its short name, so a row matches an
entry by its exact short name, else by its short name after Unicode case
folding, and only when the pairing is unique in both directions. The scope
is HTML and is converted to plain text with the standard-library parser:
only links, `strong`, and `br` are allowed, and anything else makes the
scope invalid rather than being dropped.
"""

from __future__ import annotations

import re
import uuid
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Any, Final, Literal
from urllib.parse import urlsplit

from pydantic import MISSING

from app.core.external_strings import contains_inadmissible_character
from app.services.cna_service import (
    ORGANIZATION_NAME_MAX_LENGTH,
    SCOPE_MAX_LENGTH,
    TYPE_MAX_LENGTH,
    TYPES_MAX_ITEMS,
    is_admissible_text,
)

MetadataField = Literal["organization_name", "types", "scope"]
"""A column written from the list; the `field` of `cna_metadata_field_invalid`."""

# ---------------------------------------------------------------------------
# Entries (Algorithm, step 3)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True, eq=False)
class ListEntry:
    """One valid entry of the list: an object whose `shortName` is a string
    that is not empty after trimming and contains no inadmissible character.

    `short_name` is the trimmed `shortName`; `members` is the raw object.
    Entries compare by identity, so two equal elements remain two entries.
    """

    short_name: str
    members: Mapping[str, Any]


def parse_entry(element: object) -> ListEntry | None:
    """The valid entry of one array element, or `None` for an invalid
    entry (cna.md, Algorithm step 3; External String Admissibility)."""
    if not isinstance(element, dict):
        return None
    short_name = element.get("shortName")
    if (
        not isinstance(short_name, str)
        or not short_name.strip()
        or contains_inadmissible_character(short_name)
    ):
        return None
    return ListEntry(short_name=short_name.strip(), members=element)


# ---------------------------------------------------------------------------
# CNA Entry Matching
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class NamedCNA:
    """A CNA row with a short name, as the fetcher reads it (Algorithm,
    step 4)."""

    id: uuid.UUID
    org_id: uuid.UUID
    short_name: str


@dataclass(frozen=True, slots=True)
class Matching:
    """The pairs of rows and entries, and the ambiguous rows, each in the
    order of the rows given. A row with no candidate is in neither."""

    matched: tuple[tuple[NamedCNA, ListEntry], ...]
    ambiguous: tuple[NamedCNA, ...]


def match_entries(rows: Sequence[NamedCNA], entries: Sequence[ListEntry]) -> Matching:
    """Pair rows with valid entries (cna.md, CNA Entry Matching).

    The candidates of a row with short name `s` are the entries whose
    trimmed `shortName` equals `s`, or, when there is none, those equal to
    it after Unicode case folding of both values. A row matches an entry
    when the entry is its only candidate and the only candidate of no other
    row; otherwise a row with candidates is ambiguous.
    """
    exact: dict[str, list[ListEntry]] = {}
    folded: dict[str, list[ListEntry]] = {}
    for entry in entries:
        exact.setdefault(entry.short_name, []).append(entry)
        folded.setdefault(entry.short_name.casefold(), []).append(entry)

    candidates = [
        (row, exact.get(row.short_name) or folded.get(row.short_name.casefold(), []))
        for row in rows
    ]
    sole_candidate_of = Counter(found[0] for _, found in candidates if len(found) == 1)

    matched: list[tuple[NamedCNA, ListEntry]] = []
    ambiguous: list[NamedCNA] = []
    for row, found in candidates:
        if len(found) == 1 and sole_candidate_of[found[0]] == 1:
            matched.append((row, found[0]))
        elif found:
            ambiguous.append(row)
    return Matching(matched=tuple(matched), ambiguous=tuple(ambiguous))


# ---------------------------------------------------------------------------
# Field Mapping
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CNAMetadata:
    """The valid fields of one entry, as `update_cna_metadata()` takes
    them: an invalid field is `MISSING`, so its stored value is kept, and
    is named in `invalid_fields` in column order. `scope` is `None` when
    the converted text is empty."""

    organization_name: str | MISSING = MISSING
    types: tuple[str, ...] | MISSING = MISSING
    scope: str | MISSING | None = MISSING
    invalid_fields: tuple[MetadataField, ...] = ()


def map_fields(entry: ListEntry) -> CNAMetadata:
    """Validate each field of `entry` independently (cna.md, Field Mapping).

    `organizationName`: the trimmed string, valid when not empty, at most
    256 characters, and admissible. `CNA.type`: the trimmed items, valid
    when `CNA` is an object and `type` an array of at most 16 strings, each
    not empty after trimming, at most 128 characters, and admissible; the
    service removes duplicates and orders them. `scope`: the Scope Plain
    Text conversion of a string, `None` for an empty result. An absent or
    `null` member is invalid like any other value.
    """
    members = entry.members
    invalid: list[MetadataField] = []

    organization_name: str | MISSING = MISSING
    raw_name = members.get("organizationName")
    if isinstance(raw_name, str) and is_admissible_text(
        raw_name.strip(), max_length=ORGANIZATION_NAME_MAX_LENGTH
    ):
        organization_name = raw_name.strip()
    else:
        invalid.append("organization_name")

    types: tuple[str, ...] | MISSING = MISSING
    cna = members.get("CNA")
    raw_types = cna.get("type") if isinstance(cna, dict) else None
    if (
        isinstance(raw_types, list)
        and len(raw_types) <= TYPES_MAX_ITEMS
        and all(
            isinstance(item, str)
            and is_admissible_text(item.strip(), max_length=TYPE_MAX_LENGTH)
            for item in raw_types
        )
    ):
        types = tuple(item.strip() for item in raw_types)
    else:
        invalid.append("types")

    scope: str | MISSING | None = MISSING
    raw_scope = members.get("scope")
    try:
        if not isinstance(raw_scope, str):
            raise InvalidScopeError
        scope = scope_plain_text(raw_scope)
    except InvalidScopeError:
        invalid.append("scope")

    return CNAMetadata(
        organization_name=organization_name,
        types=types,
        scope=scope,
        invalid_fields=tuple(invalid),
    )


# ---------------------------------------------------------------------------
# Scope Plain Text
# ---------------------------------------------------------------------------


class InvalidScopeError(ValueError):
    """The scope cannot be converted to plain text (cna.md, Scope Plain
    Text). The message is fixed and never contains the scope."""

    def __init__(self) -> None:
        super().__init__("CNA scope is not convertible to plain text")


_INCOMPLETE_TAG: Final = re.compile(r"</?[a-zA-Z]")
"""A start or end tag that the parser holds back at the end of the input
and would drop silently when it is closed."""

_URL_SCHEMES: Final = frozenset({"http", "https"})
_WHITESPACE: Final = re.compile(r"\s")


def _appended_url(href: str | None, text: str) -> str | None:
    """The `href` to append after a link's text: an absolute `http` or
    `https` URL with a host and no whitespace that differs from the trimmed
    text; otherwise `None`."""
    if href is None or _WHITESPACE.search(href) or href == text.strip():
        return None
    try:
        parts = urlsplit(href)
    except ValueError:
        return None
    if parts.scheme.lower() not in _URL_SCHEMES or not parts.hostname:
        return None
    return href


class _ScopeParser(HTMLParser):
    """Converts the tokens of a scope in order; any disallowed token raises
    `InvalidScopeError`."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.result: list[str] = []
        self.link_href: str | None = None
        self.link_text: list[str] | None = None

    def _append(self, text: str) -> None:
        (self.link_text if self.link_text is not None else self.result).append(text)

    def handle_data(self, data: str) -> None:
        self._append(data)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "br":
            self._append("\n")
        elif tag == "a":
            if self.link_text is not None:
                raise InvalidScopeError
            self.link_href = next((v for k, v in attrs if k == "href"), None)
            self.link_text = []
        elif tag != "strong":
            raise InvalidScopeError

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        # `<br/>` is one line break; another self-closing tag is its start tag.
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag: str) -> None:
        if tag == "br":
            self._append("\n")
        elif tag == "a":
            if self.link_text is None:
                raise InvalidScopeError
            text = "".join(self.link_text)
            url = _appended_url(self.link_href, text)
            self.link_href, self.link_text = None, None
            self.result.append(text if url is None else f"{text} ({url})")
        elif tag != "strong":
            raise InvalidScopeError

    def handle_comment(self, data: str) -> None:
        raise InvalidScopeError

    def handle_decl(self, decl: str) -> None:
        raise InvalidScopeError

    def handle_pi(self, data: str) -> None:
        raise InvalidScopeError

    def unknown_decl(self, data: str) -> None:
        raise InvalidScopeError

    def convert(self, value: str) -> str:
        self.feed(value)
        if _INCOMPLETE_TAG.match(self.rawdata):
            raise InvalidScopeError
        self.close()
        if self.link_text is not None:
            raise InvalidScopeError
        return "".join(self.result)


def scope_plain_text(value: str) -> str | None:
    """The plain text of a scope of the list, `None` when it is empty.

    Tokenizes the complete value with `html.parser`, character references
    converted in text and attribute values: text is kept as is; `<br>`,
    `<br/>`, and `</br>` are one line feed each; `strong` tags add nothing;
    a link appends its text, followed by ` (<href>)` for an absolute
    `http` or `https` URL without whitespace that differs from the trimmed
    text. A nested, unclosed, or unopened link, any other tag, a comment, a
    declaration, a processing instruction, and a tag that is incomplete at
    the end make the scope invalid. The result is trimmed; a result longer
    than 4096 characters or containing an inadmissible character is
    invalid.

    Raises `InvalidScopeError` for an invalid scope.
    """
    text = _ScopeParser().convert(value).strip()
    if len(text) > SCOPE_MAX_LENGTH or contains_inadmissible_character(text):
        raise InvalidScopeError
    return text or None
