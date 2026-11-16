"""Contract tests for the SUSE Bugzilla REST endpoint `/rest/bug`.

Contract under test: docs/features/tickets/cve-sync-bugzilla.md (The Bug of
a CVE, Bug Reference, Algorithm, Field Mapping, Explicitly Ignored Fields,
Response Validation) and docs/data-sources.md (SUSE Bugzilla), verified
against live responses captured anonymously on 2026-11-16 through
Sentinel's production HTTP client (docs/conventions.md, External
Integration Contract Verification). Every consumed field is asserted for
name, nesting, and type through a strict test-local typed model,
independent of the production parser
(`app/services/tickets/bugzilla_bug_record.py`).

Live verification on 2026-11-16 (Bugzilla 5.0.6 REST, anonymous GET):

- The periodic query of a 13-hour window answered HTTP 200
  `application/json; charset=UTF-8` with a root holding only `bugs`; 162
  bugs, strictly ascending by ID, each with exactly `id` (integer),
  `alias` (array of strings), `summary` (string), and `groups` (an empty
  array). The served member order of a bug object varies. Every bug had a
  CVE alias; the other aliases were GHSA IDs.
- Keyset pagination: two pages of `limit=25` returned the first 50 bugs
  of the `limit=1000` page in the same order, and `v2` set to the last bug
  ID returned `{"bugs":[]}`. Six pages of `limit=40` returned the same
  bugs as two pages of `limit=1000` in a separate run.
- `alias=CVE-2024-3094` and `alias=cve-2024-3094` returned the same one
  bug, whose alias is the canonical upper-case ID; an absent alias returned
  `{"bugs":[]}`. A bug can carry 52 CVE aliases.
- The same query sent with `Accept: text/html` answered HTTP 200
  `text/html` with an HTML page; a request without `Accept` and the
  shared client's `Accept: application/json` both answered JSON.
- An unknown search field answered HTTP 400 with a JSON error object and
  no `bugs` member.
- The production client percent-encodes the commas of `include_fields`
  and the colons of `last_change_time`; the server applied both.

Not observable anonymously, and therefore covered by the parser and fetcher
tests only: a bug with a non-empty `groups` array (restricted bugs are
absent from anonymous search results), a bug whose alias is a CVE ID in
another letter case, HTTP 3xx and 429 answers, a non-ascending page, a
mistyped or missing consumed member, and an inadmissible character
(U+0000 or a surrogate code point) in any string.
"""

from __future__ import annotations

import json
import re
from typing import Any, TypedDict

import pytest
from pydantic import TypeAdapter, ValidationError

from app.core.enums import ReferenceType
from app.core.external_strings import contains_inadmissible_character
from app.core.reference_urls import normalize_reference_url
from app.services.json_decoding import decode_json
from app.services.reference_service import classify_reference_url
from tests.support.bugzilla import (
    ABSENT_CVE_ID,
    ERROR_400_FIXTURE,
    HTML_FIXTURE,
    PAGE_EMPTY_FIXTURE,
    PAGE_FIXTURE,
    PAGE_LAST_BUG_ID,
    SINGLE_BUG_ID,
    SINGLE_CVE_ID,
    SINGLE_EMPTY_FIXTURE,
    SINGLE_FIXTURE,
    SINGLE_MULTI_BUG_ID,
    SINGLE_MULTI_CVE_ID,
    SINGLE_MULTI_FIXTURE,
    bug_reference_url,
    load_fixture,
    load_raw_fixture,
)

_CVE_ID = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")
_GHSA_ID = re.compile(r"GHSA(-[23456789cfghjmpqrvwx]{4}){3}")
_BUG_FIXTURES = (PAGE_FIXTURE, SINGLE_FIXTURE, SINGLE_MULTI_FIXTURE)
_EMPTY_FIXTURES = (PAGE_EMPTY_FIXTURE, SINGLE_EMPTY_FIXTURE)
_JSON_FIXTURES = (*_BUG_FIXTURES, *_EMPTY_FIXTURES, ERROR_400_FIXTURE)
_CONSUMED = frozenset({"id", "alias", "summary", "groups"})
_SUMMARY_MAX_LENGTH = 255
"""Bugzilla's summary limit, below the 500-character reference title."""


class _Bug(TypedDict):
    id: int
    alias: list[str]
    summary: str
    groups: list[Any]


class _Response(TypedDict):
    """The consumed fields as observed live."""

    bugs: list[_Bug]


_RESPONSE = TypeAdapter(_Response)


def _validated(document: Any) -> _Response:
    return _RESPONSE.validate_python(document, strict=True)


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for key, item in value.items() for s in (key, *_strings(item))]
    if isinstance(value, list):
        return [s for item in value for s in _strings(item)]
    return []


@pytest.mark.unit
class TestTypedResponse:
    @pytest.mark.parametrize("name", [*_BUG_FIXTURES, *_EMPTY_FIXTURES])
    def test_root_holds_only_the_bugs_array(self, name: str) -> None:
        document = load_fixture(name)

        assert list(document) == ["bugs"]
        assert isinstance(document["bugs"], list)

    @pytest.mark.parametrize("name", [*_BUG_FIXTURES, *_EMPTY_FIXTURES])
    def test_consumed_fields_validate_strictly_without_coercion(
        self, name: str
    ) -> None:
        _validated(load_fixture(name))

    @pytest.mark.parametrize("name", _BUG_FIXTURES)
    def test_include_fields_returns_exactly_the_consumed_members(
        self, name: str
    ) -> None:
        for item in load_fixture(name)["bugs"]:
            assert set(item) == _CONSUMED

    @pytest.mark.parametrize("name", _BUG_FIXTURES)
    def test_id_is_a_positive_integer_and_not_a_boolean(self, name: str) -> None:
        for item in load_fixture(name)["bugs"]:
            assert type(item["id"]) is int
            assert item["id"] > 0

    @pytest.mark.parametrize("name", _BUG_FIXTURES)
    def test_every_bug_is_public(self, name: str) -> None:
        for item in load_fixture(name)["bugs"]:
            assert item["groups"] == []

    @pytest.mark.parametrize(
        "bug",
        [
            {"id": True, "alias": [], "summary": "x", "groups": []},
            {"id": "1", "alias": [], "summary": "x", "groups": []},
            {"id": 1, "alias": "CVE-2099-0001", "summary": "x", "groups": []},
            {"id": 1, "alias": [1], "summary": "x", "groups": []},
            {"id": 1, "alias": [], "summary": None, "groups": []},
            {"id": 1, "alias": [], "summary": "x", "groups": None},
            {"id": 1, "alias": [], "summary": "x"},
        ],
        ids=[
            "boolean_id",
            "string_id",
            "string_alias",
            "number_alias_item",
            "null_summary",
            "null_groups",
            "missing_groups",
        ],
    )
    def test_typed_model_rejects_a_mistyped_or_missing_consumed_member(
        self, bug: dict[str, Any]
    ) -> None:
        with pytest.raises(ValidationError):
            _validated({"bugs": [bug]})

    @pytest.mark.parametrize("name", _JSON_FIXTURES)
    def test_no_string_contains_an_inadmissible_character(self, name: str) -> None:
        assert not any(
            contains_inadmissible_character(s) for s in _strings(load_fixture(name))
        )


@pytest.mark.unit
class TestPage:
    def test_bug_ids_are_strictly_ascending(self) -> None:
        ids = [item["id"] for item in load_fixture(PAGE_FIXTURE)["bugs"]]

        assert ids == sorted(set(ids))
        assert ids[-1] == PAGE_LAST_BUG_ID

    def test_every_bug_carries_a_canonical_cve_alias(self) -> None:
        for item in load_fixture(PAGE_FIXTURE)["bugs"]:
            assert any(_CVE_ID.fullmatch(alias) for alias in item["alias"])

    def test_other_aliases_are_ghsa_ids(self) -> None:
        others = [
            alias
            for item in load_fixture(PAGE_FIXTURE)["bugs"]
            for alias in item["alias"]
            if not _CVE_ID.fullmatch(alias)
        ]

        assert others
        assert all(_GHSA_ID.fullmatch(alias) for alias in others)

    def test_one_bug_can_carry_many_cve_aliases(self) -> None:
        counts = [
            sum(bool(_CVE_ID.fullmatch(alias)) for alias in item["alias"])
            for item in load_fixture(PAGE_FIXTURE)["bugs"]
        ]

        assert max(counts) == 52
        assert 4 in counts

    def test_aliases_are_unique_within_and_across_bugs(self) -> None:
        aliases = [
            alias
            for item in load_fixture(PAGE_FIXTURE)["bugs"]
            for alias in item["alias"]
        ]

        assert len(aliases) == len(set(aliases))

    def test_closing_page_is_an_empty_array_stored_as_served(self) -> None:
        assert load_raw_fixture(PAGE_EMPTY_FIXTURE) == b'{"bugs":[]}'


@pytest.mark.unit
class TestSingleQuery:
    @pytest.mark.parametrize(
        ("name", "cve_id", "bug_id"),
        [
            (SINGLE_FIXTURE, SINGLE_CVE_ID, SINGLE_BUG_ID),
            (SINGLE_MULTI_FIXTURE, SINGLE_MULTI_CVE_ID, SINGLE_MULTI_BUG_ID),
        ],
    )
    def test_answer_is_the_one_bug_with_the_exact_alias(
        self, name: str, cve_id: str, bug_id: int
    ) -> None:
        [item] = load_fixture(name)["bugs"]

        assert item["id"] == bug_id
        assert cve_id in item["alias"]

    def test_multi_alias_bug_is_the_same_as_in_the_page(self) -> None:
        [single] = load_fixture(SINGLE_MULTI_FIXTURE)["bugs"]
        [paged] = [
            item
            for item in load_fixture(PAGE_FIXTURE)["bugs"]
            if item["id"] == SINGLE_MULTI_BUG_ID
        ]

        assert single["alias"] == paged["alias"]
        assert single["groups"] == paged["groups"] == []

    def test_absent_alias_is_an_empty_array_not_an_error(self) -> None:
        assert load_raw_fixture(SINGLE_EMPTY_FIXTURE) == b'{"bugs":[]}'
        assert _CVE_ID.fullmatch(ABSENT_CVE_ID)


@pytest.mark.unit
class TestBugReference:
    @pytest.mark.parametrize("name", _BUG_FIXTURES)
    def test_reference_url_is_stored_unchanged_and_classified_as_issue(
        self, name: str
    ) -> None:
        for item in load_fixture(name)["bugs"]:
            url = bug_reference_url(item["id"])

            assert url == f"https://bugzilla.suse.com/show_bug.cgi?id={item['id']}"
            assert normalize_reference_url(url) == url
            assert classify_reference_url(url) is ReferenceType.ISSUE

    @pytest.mark.parametrize("name", _BUG_FIXTURES)
    def test_summary_fits_a_reference_title(self, name: str) -> None:
        for item in load_fixture(name)["bugs"]:
            summary = item["summary"]

            assert 1 <= len(summary) <= _SUMMARY_MAX_LENGTH
            assert summary.strip()


@pytest.mark.unit
class TestNonJsonAndErrorAnswers:
    def test_html_answer_is_not_json(self) -> None:
        raw = load_raw_fixture(HTML_FIXTURE)

        assert raw.startswith(b"<!DOCTYPE html>")
        with pytest.raises(json.JSONDecodeError):
            decode_json(raw)

    def test_error_answer_is_an_object_without_bugs(self) -> None:
        document = load_fixture(ERROR_400_FIXTURE)

        assert "bugs" not in document
        assert document["error"] is True
        assert isinstance(document["code"], int)
        assert isinstance(document["message"], str)
