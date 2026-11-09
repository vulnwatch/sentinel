"""Contract tests for the CVE Program CNA list.

Contract under test: docs/features/tickets/cna.md (Fetcher:
`sync_mitre_cnas` — Source, Algorithm steps 2-3, CNA Entry Matching, Field
Mapping, Scope Plain Text, External String Admissibility) and
docs/data-sources.md (CVE Program CNA List), verified against the live list
downloaded anonymously on 2026-11-09 without following redirects
(docs/conventions.md, External Integration Contract Verification). Every
consumed member is asserted for name, nesting, and type through a strict
test-local typed model, independent of the production parser, and then
through the parser itself.

Live verification on 2026-11-09 (`GET` of the documented URL):

- HTTP 200 with no redirect, `Content-Type: text/plain; charset=utf-8`,
  `Content-Encoding: gzip`, 757,202 decoded bytes, UTF-8 without a byte
  order mark, 513 raw non-ASCII bytes and no `\\uXXXX` escape.
- The root is an array of 564 objects. Every object has exactly the
  members `shortName`, `cnaID`, `organizationName`, `scope`, `contact`,
  `disclosurePolicy`, `securityAdvisories`, `resources`, `CNA`, and
  `country`; `CNA` always has `isRoot`, `root`, `type`, `TLR`, and `roles`,
  and two objects also `role`.
- `shortName`: a string, already trimmed, 2 to 30 characters, unique;
  `Snow` and `SNOW` are the only two that are equal after case folding.
- `organizationName`: a string, trimmed, at most 88 characters, unique, with
  no markup or character reference.
- `CNA.type`: an array of 1 to 5 strings, at most 77 characters, without
  duplicates; values `Vendor`, `Open Source`, `Researcher`, `Hosted
  Service`, `CERT`, `Bug Bounty Provider`, `Consortium`, `N/A`, and one AI
  researcher pilot type.
- `scope`: a non-empty string of at most 1,046 characters with no line
  break. Its markup is only `<a href=… target=…>`, `<strong>`, `<br/>`, and
  `&amp;`: 123 links, of which 61 have an absolute URL that differs from
  their text, 59 have their URL as their text, and 3 are relative. Every
  scope converts under Scope Plain Text, to at most 941 characters.
- No string contains an inadmissible character.

Not observable live, and therefore covered by the parser and fetcher tests
only: a root that is not an array; an element that is not an object; an
absent, non-string, empty, or untrimmed `shortName`; an absent, `null`, or
mistyped `organizationName`, `CNA`, `CNA.type`, or `scope`; bounds beyond the
documented lengths and counts; any other markup, an unclosed or nested link,
a `javascript:` URL, and an incomplete tag; non-200 statuses and redirects;
an undecodable or non-JSON body; and an inadmissible character in any
consumed string.
"""

from __future__ import annotations

import json
import re
import uuid
from typing import Any, TypedDict

import pytest
from pydantic import MISSING, TypeAdapter, ValidationError

from app.core.external_strings import contains_inadmissible_character
from app.services.tickets.cna_list import (
    NamedCNA,
    map_fields,
    match_entries,
    parse_entry,
    scope_plain_text,
)
from tests.support.cve_program import (
    FIXTURE_SHORT_NAMES,
    fixture_entry,
    load_list,
    load_raw_list,
)

_ENTRY_MEMBERS = (
    "shortName",
    "cnaID",
    "organizationName",
    "scope",
    "contact",
    "disclosurePolicy",
    "securityAdvisories",
    "resources",
    "CNA",
    "country",
)
"""The live members of an entry, in live order."""

_CNA_MEMBERS = frozenset({"isRoot", "root", "type", "TLR", "roles"})
"""The members of `CNA` in every live entry; two also carry `role`."""

_TAG = re.compile(r"<(/?)([a-zA-Z]+)([^>]*)>")
_REFERENCE = re.compile(r"&[#a-zA-Z0-9]+;")


class _CNA(TypedDict):
    type: list[str]


class _Entry(TypedDict):
    """The consumed members as observed live. Other members are ignored."""

    shortName: str
    organizationName: str
    scope: str
    CNA: _CNA


_LIST = TypeAdapter(list[_Entry])


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for key, item in value.items() for s in (key, *_strings(item))]
    if isinstance(value, list):
        return [s for item in value for s in _strings(item)]
    return []


def _indices() -> list[int]:
    return list(range(len(FIXTURE_SHORT_NAMES)))


@pytest.mark.unit
class TestTypedList:
    def test_root_is_an_array_of_the_documented_entries_in_list_order(self) -> None:
        body = load_list()

        assert isinstance(body, list)
        assert [entry["shortName"] for entry in body] == list(FIXTURE_SHORT_NAMES)

    def test_consumed_members_validate_strictly_without_coercion(self) -> None:
        _LIST.validate_python(load_list(), strict=True)

    @pytest.mark.parametrize(
        ("path", "value"),
        [
            pytest.param(("shortName",), 1, id="short-name-number"),
            pytest.param(("organizationName",), None, id="organization-name-null"),
            pytest.param(("scope",), ["x"], id="scope-array"),
            pytest.param(("CNA", "type"), "Vendor", id="type-string"),
        ],
    )
    def test_typed_model_rejects_a_mistyped_consumed_member(
        self, path: tuple[str, ...], value: Any
    ) -> None:
        body = load_list()
        target = body[0]
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = value

        with pytest.raises(ValidationError):
            _LIST.validate_python(body, strict=True)

    @pytest.mark.parametrize("index", _indices())
    def test_entry_has_exactly_the_live_members_in_live_order(self, index: int) -> None:
        entry = load_list()[index]

        assert tuple(entry) == _ENTRY_MEMBERS
        assert _CNA_MEMBERS <= set(entry["CNA"]) <= _CNA_MEMBERS | {"role"}

    def test_the_role_variant_is_kept(self) -> None:
        assert "role" in fixture_entry("Google")["CNA"]

    def test_no_string_contains_an_inadmissible_character(self) -> None:
        strings = _strings(load_list())

        assert not any(contains_inadmissible_character(s) for s in strings)

    def test_fixture_is_utf8_indented_with_raw_non_ascii_and_a_final_newline(
        self,
    ) -> None:
        raw = load_raw_list()
        text = raw.decode("utf-8")

        assert not raw.startswith(b"\xef\xbb\xbf")
        assert text.endswith("]\n")
        assert "\\u" not in text
        assert "\u2019" in text  # the live right single quotation mark, raw
        assert text == json.dumps(load_list(), ensure_ascii=False, indent=2) + "\n"


@pytest.mark.unit
class TestShortName:
    @pytest.mark.parametrize("index", _indices())
    def test_short_name_is_a_trimmed_non_empty_string(self, index: int) -> None:
        short_name = load_list()[index]["shortName"]

        assert short_name == short_name.strip() != ""
        assert len(short_name) <= 32

    def test_short_names_are_unique_and_collide_only_by_case(self) -> None:
        names = [entry["shortName"] for entry in load_list()]
        folded: dict[str, list[str]] = {}
        for name in names:
            folded.setdefault(name.casefold(), []).append(name)

        assert len(set(names)) == len(names)
        assert [group for group in folded.values() if len(group) > 1] == [
            ["Snow", "SNOW"]
        ]

    @pytest.mark.parametrize("index", _indices())
    def test_every_entry_is_a_valid_entry_with_its_short_name(self, index: int) -> None:
        element = load_list()[index]

        entry = parse_entry(element)

        assert entry is not None
        assert entry.short_name == element["shortName"]

    def test_the_live_case_collision_matches_each_exact_row_only(self) -> None:
        entries = [parse_entry(element) for element in load_list()]
        valid = [entry for entry in entries if entry is not None]
        rows = [
            NamedCNA(id=uuid.uuid7(), org_id=uuid.uuid4(), short_name=name)
            for name in ("Snow", "SNOW", "snow")
        ]

        matching = match_entries(rows, valid)

        pairs = [(row.short_name, entry.short_name) for row, entry in matching.matched]
        assert pairs == [("Snow", "Snow"), ("SNOW", "SNOW")]
        assert [row.short_name for row in matching.ambiguous] == ["snow"]


@pytest.mark.unit
class TestFieldMapping:
    @pytest.mark.parametrize("index", _indices())
    def test_every_live_field_is_valid(self, index: int) -> None:
        element = load_list()[index]
        entry = parse_entry(element)
        assert entry is not None

        metadata = map_fields(entry)

        assert metadata.invalid_fields == ()
        assert metadata.organization_name == element["organizationName"]
        assert metadata.types == tuple(element["CNA"]["type"])
        assert metadata.scope is not MISSING
        assert metadata.scope == scope_plain_text(element["scope"])

    @pytest.mark.parametrize("index", _indices())
    def test_organization_name_and_types_are_within_the_bounds(
        self, index: int
    ) -> None:
        element = load_list()[index]

        assert 0 < len(element["organizationName"]) <= 256
        assert 0 < len(element["CNA"]["type"]) <= 16
        assert all(0 < len(item.strip()) <= 128 for item in element["CNA"]["type"])

    def test_types_cover_one_to_five_items_and_the_documented_values(self) -> None:
        types = [entry["CNA"]["type"] for entry in load_list()]

        assert {len(items) for items in types} == {1, 2, 3, 5}
        assert {"Vendor", "Open Source", "Researcher", "CERT", "N/A"} <= {
            item for items in types for item in items
        }


@pytest.mark.unit
class TestScopeMarkup:
    @pytest.mark.parametrize("index", _indices())
    def test_markup_is_only_links_strong_and_br(self, index: int) -> None:
        scope = load_list()[index]["scope"]

        tags = {(closing, name) for closing, name, _ in _TAG.findall(scope)}

        assert tags <= {
            ("", "a"),
            ("/", "a"),
            ("", "strong"),
            ("/", "strong"),
            ("", "br"),
        }
        assert set(_REFERENCE.findall(scope)) <= {"&amp;"}
        assert "\n" not in scope

    def test_fixture_covers_every_live_markup_form(self) -> None:
        scopes = " ".join(entry["scope"] for entry in load_list())

        assert "<strong>" in scopes
        assert "<br/>" in scopes
        assert "&amp;" in scopes
        assert "href='/" in scopes  # a relative link
        assert "target='_blank'" in scopes

    def test_link_with_other_text_keeps_its_absolute_url(self) -> None:
        assert scope_plain_text(fixture_entry("ZTE")["scope"]) == (
            "ZTE products (https://www.zte.com.cn/global/products) only."
        )

    def test_link_whose_text_is_its_url_appends_no_url_and_references_convert(
        self,
    ) -> None:
        converted = scope_plain_text(fixture_entry("samsung.tv_appliance")["scope"])

        assert converted is not None
        assert converted.startswith(
            "Samsung TV & Appliance products, Samsung-owned open source projects "
            "listed on https://github.com/Samsung/, as well as vulnerabilities"
        )
        assert "<" not in converted

    def test_strong_and_br_become_text_and_lines_and_a_relative_link_its_text(
        self,
    ) -> None:
        scope = fixture_entry("CISA")["scope"]
        expected = (
            scope.replace("<strong>", "")
            .replace("</strong>", "")
            .replace("<br/>", "\n")
            .replace("<a href='/ProgramOrganization/ADPs#ActiveAdps'>here</a>", "here")
        )

        converted = scope_plain_text(scope)

        assert converted == expected
        assert converted is not None
        assert converted.splitlines()[1] == "ADP Scope: View scope here."

    def test_consecutive_br_and_a_link_inside_strong(self) -> None:
        converted = scope_plain_text(fixture_entry("OAI")["scope"])

        assert converted is not None
        assert converted.split("\n") == [
            "CNA Scope: Vulnerabilities in OpenAI installed software including "
            "desktop apps, mobile apps, and SDKs only.",
            "",
            "Frontier AI Researcher CVE Numbering Authorities (CNAs) Pilot Scope: "
            "Vulnerabilities discovered by OpenAI that are not within another "
            "CNA\u2019s scope.",
        ]

    def test_scope_without_markup_is_kept_as_is(self) -> None:
        scope = fixture_entry("GitHub_M")["scope"]

        assert scope_plain_text(scope) == scope

    @pytest.mark.parametrize("index", _indices())
    def test_every_scope_converts_within_the_bound_without_markup(
        self, index: int
    ) -> None:
        converted = scope_plain_text(load_list()[index]["scope"])

        assert converted is not None
        assert 0 < len(converted) <= 4096
        assert _TAG.search(converted) is None
        assert "&amp;" not in converted
