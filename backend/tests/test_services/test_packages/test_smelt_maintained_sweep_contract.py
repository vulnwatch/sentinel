"""Contract tests for the SMELT maintained sweep `experimental/v2/maintained/`.

Contract under test: docs/features/packages/maintained-package-names.md
(Fetcher: `sync_smelt_packages`, Algorithm) and docs/data-sources.md (SMELT,
Contract characteristics), verified against sanitized live pages captured
from the default `SMELT_API_URL` with `include_reactive_ltss=true&page_size=200`
(docs/conventions.md, External Integration Contract Verification; provenance
in `tests/support/smelt.py`). Every consumed field is asserted for name,
type, and pagination semantics: the JSend envelope, `data.results`,
`data.page`, `data.page_size`, `data.has_next`, `data.has_previous`, and
`results[].package`.

The parser-backed tests at the end serve the captured pages through
`fetch_maintained_package_names()` to prove that the live serialization is
accepted and that every `package` value is kept unchanged.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest

from app.services.packages.smelt_maintained_sweep import (
    fetch_maintained_package_names,
)
from tests.support.smelt import SWEEP_FIXTURE_PAGES, SmeltServer, load_sweep_page

_LIVE_API_URL = "https://smelt.suse.de/api"
_LAST_PAGE = 1201
_FICTIONAL_URL_PREFIX = "https://build.example.invalid/"


def _strings(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from _strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)


@pytest.mark.unit
class TestEnvelope:
    @pytest.mark.parametrize("page", SWEEP_FIXTURE_PAGES)
    def test_page_is_a_jsend_success_with_the_pagination_object(
        self, page: int
    ) -> None:
        body = load_sweep_page(page)

        assert set(body) == {"status", "data"}
        assert body["status"] == "success"
        data = body["data"]
        assert set(data) == {
            "results",
            "page",
            "page_size",
            "has_next",
            "has_previous",
        }
        assert isinstance(data["results"], list)
        assert type(data["page"]) is int
        assert data["page"] == page
        assert type(data["page_size"]) is int
        assert data["page_size"] == 200
        assert type(data["has_next"]) is bool
        assert type(data["has_previous"]) is bool

    @pytest.mark.parametrize("page", SWEEP_FIXTURE_PAGES)
    def test_has_previous_is_false_exactly_on_page_1(self, page: int) -> None:
        assert load_sweep_page(page)["data"]["has_previous"] is (page > 1)

    def test_a_page_with_a_next_page_is_full(self) -> None:
        for page in (1, 883):
            data = load_sweep_page(page)["data"]
            assert data["has_next"] is True
            assert len(data["results"]) == 200

    def test_the_last_page_is_partial_and_has_no_next_page(self) -> None:
        data = load_sweep_page(_LAST_PAGE)["data"]

        assert data["has_next"] is False
        assert 0 < len(data["results"]) < 200

    def test_a_page_beyond_the_last_is_empty_and_has_no_next_page(self) -> None:
        data = load_sweep_page(_LAST_PAGE + 1)["data"]

        assert data["results"] == []
        assert data["has_next"] is False
        assert data["has_previous"] is True


@pytest.mark.unit
class TestResults:
    @pytest.mark.parametrize("page", SWEEP_FIXTURE_PAGES)
    def test_every_result_is_an_object_with_a_non_empty_package(
        self, page: int
    ) -> None:
        for result in load_sweep_page(page)["data"]["results"]:
            assert isinstance(result, dict)
            assert type(result["package"]) is str
            assert 0 < len(result["package"]) <= 255

    def test_a_package_appears_in_several_results(self) -> None:
        packages = [r["package"] for r in load_sweep_page(1)["data"]["results"]]

        assert len(set(packages)) < len(packages)

    def test_names_that_differ_only_in_letter_case_are_both_maintained(
        self,
    ) -> None:
        packages = {r["package"] for r in load_sweep_page(883)["data"]["results"]}

        assert {"python-PrettyTable", "python-prettytable"} <= packages


@pytest.mark.unit
class TestSanitization:
    @pytest.mark.parametrize("page", SWEEP_FIXTURE_PAGES)
    def test_fixture_retains_no_real_url_or_email(self, page: int) -> None:
        for value in _strings(load_sweep_page(page)):
            assert "@" not in value
            assert "suse.de" not in value
            if value.startswith(("http://", "https://")):
                assert value.startswith(_FICTIONAL_URL_PREFIX)


# ---------------------------------------------------------------------------
# Parser-backed contract: the live serialization is accepted
# ---------------------------------------------------------------------------


def _live_sweep_server() -> SmeltServer:
    """Serve the captured first page, the captured middle page as page 2,
    and the captured last page as page 3, each with its page number
    rewritten; nothing else of a captured page changes."""
    pages: dict[int, Any] = {}
    for served, captured in ((1, 1), (2, 883), (3, _LAST_PAGE)):
        body = load_sweep_page(captured)
        body["data"]["page"] = served
        pages[served] = body
    return SmeltServer(pages)


@pytest.mark.unit
class TestLiveSerializationAccepted:
    async def test_live_pages_yield_every_package_unchanged(self) -> None:
        server = _live_sweep_server()

        async with server.client() as client:
            names = await fetch_maintained_package_names(
                client, api_url=_LIVE_API_URL, request_delay=0
            )

        expected = {
            result["package"]
            for page in (1, 883, _LAST_PAGE)
            for result in load_sweep_page(page)["data"]["results"]
        }
        assert names == expected
        assert {"python-PrettyTable", "python-prettytable", "zziplib"} <= names
        assert server.requested_urls == [
            f"{_LIVE_API_URL}/experimental/v2/maintained/"
            f"?include_reactive_ltss=true&page_size=200&page={page}"
            for page in (1, 2, 3)
        ]

    async def test_live_page_beyond_the_last_ends_the_sweep(self) -> None:
        """A sweep whose final page holds no result, as SMELT returns after
        a full last page."""
        first = load_sweep_page(1)
        beyond = load_sweep_page(_LAST_PAGE + 1)
        beyond["data"]["page"] = 2
        server = SmeltServer({1: first, 2: beyond})

        async with server.client() as client:
            names = await fetch_maintained_package_names(
                client, api_url=_LIVE_API_URL, request_delay=0
            )

        assert names == {result["package"] for result in first["data"]["results"]}
        assert server.requested_pages == [1, 2]
