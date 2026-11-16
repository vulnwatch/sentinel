"""Tests for the bug record parser (backend/app/services/tickets/
bugzilla_bug_record.py) and `SyncBugzillaBugs.fetch_single()`
(backend/app/services/tickets/sync_bugzilla_bugs.py).

Owning specifications:

- docs/features/tickets/cve-sync-bugzilla.md (The Bug of a CVE; Bug
  Reference; Algorithm, `fetch_single(cve_id)` and step 5; Payload; Field
  Mapping; Response Validation, including External String Admissibility;
  Error Handling, the `fetch_single()` table; Behavioral Notes; Security
  and Privacy).
- docs/features/platform/cve-fetcher-infrastructure.md (`CVEFetchResult`;
  Automatic Reference Caller Contract; `fetch_single` Signaling Convention;
  Retry Policy for `fetch_single`; Error Categorization).
- docs/features/tickets/cve-service.md (Ticket Creation Decision, the
  `SUSE Bugzilla` audit label) and docs/features/tickets/ticket-references.md
  (Automatic Ingestion, Database Merge Rules; URL Boundary).
- docs/features/platform/networking.md (Default Configuration; Redirect
  Policy; Celery Retry Classification; HTTP Response Compression).
- docs/features/platform/testing-strategy.md (CVE Fetcher Infrastructure,
  Typed result; External String Admissibility; External JSON Decoding).

HTTP is the in-process `BugzillaServer` of `tests/support/bugzilla.py`,
injected as the fetcher's HTTP client, serving the sanitized live fixtures
(retargeted to the processed CVE-ID where they must match) or minimal
fictional bugs. Outcome tests that end before any database work use a
session that fails on any use, and spies on `cve_service.upsert_cve()` and
`reference_service.upsert_references()` prove that no mutation was
attempted; they are unit tests. Ingestion tests run the real
`upsert_cve()` and `upsert_references()` on `db_session`, rolled back at
teardown. The periodic `execute()` is tested in
`test_sync_bugzilla_bugs_execute.py`. All identifiers and texts are
fictional, except the public bug, CVE, and GHSA identifiers of the live
fixtures.
"""

from __future__ import annotations

import asyncio
import copy
from collections.abc import AsyncIterator, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any, Final, cast

import httpx
import pytest
from celery.exceptions import SoftTimeLimitExceeded
from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from structlog.testing import capture_logs

import app.services.fetcher_discovery  # noqa: F401
from app.core.enums import (
    CVESourceFetchStatus,
    CVESourceType,
    ReferenceType,
    TicketStatus,
)
from app.models.cve import CVE
from app.models.cve_source import CVESource
from app.models.system_setting import SystemSetting
from app.models.ticket import Ticket
from app.models.ticket_reference import TicketReference
from app.services import cve_service, reference_service
from app.services.base_cve_fetcher import CVEFetchResult, CVENotInSource
from app.services.cve_ingest import CVEIngestPayload, UpsertAction
from app.services.http_client import is_infrastructure_failure, is_retryable_condition
from app.services.json_decoding import JSONNestingError
from app.services.reference_service import AutomaticReferenceInput
from app.services.tickets import sync_bugzilla_bugs as sync_module
from app.services.tickets.bugzilla_bug_record import (
    BugzillaBug,
    PageOrderError,
    bugs_by_cve,
    parse_page,
    parse_response,
)
from app.services.tickets.sync_bugzilla_bugs import (
    BugzillaResponseError,
    SyncBugzillaBugs,
)
from tests.support.bugzilla import (
    BUG_URL,
    CONSUMED_FIELDS,
    ERROR_400_FIXTURE,
    SINGLE_EMPTY_FIXTURE,
    SINGLE_FIXTURE,
    SINGLE_MULTI_FIXTURE,
    BugzillaServer,
    bug,
    bug_reference_url,
    envelope,
    html,
    load_fixture,
    load_raw_fixture,
    page_bugs,
    raising,
    status,
    undecodable,
)
from tests.support.bugzilla import body as json_body
from tests.support.fetch_single_cve import fictional_cve_id
from tests.support.inadmissible import INADMISSIBLE_CHARACTERS, SURROGATE
from tests.support.json_decoding import (
    NESTED_ARRAY,
    OVERSIZED_INTEGER,
    limit_parser_nesting,
)
from tests.support.ticket_mutations import EventRow, ignore_reason_for, ticket_events

NAME: Final = "sync_bugzilla_bugs"
NVD_NAME: Final = "sync_nvd_cves"
SECRET: Final = "Reported by Alice Example <alice.example@example.invalid>"
"""Upstream text that must never reach a log record or an error."""
INGESTION_COMMENT: Final = "CVE ingested from SUSE Bugzilla"


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------


class _NoSession:
    """A session that fails the test on any use."""

    def __getattr__(self, name: str) -> Any:
        raise AssertionError(f"session.{name} used before the final write")


NO_SESSION: Final = cast(AsyncSession, _NoSession())


@dataclass
class Ingestion:
    """Spies on the two ingestion delegates; both call through."""

    upserts: list[tuple[str, CVESourceType, CVEIngestPayload]] = field(
        default_factory=list
    )
    references: list[dict[str, Any]] = field(default_factory=list)

    @property
    def calls(self) -> int:
        return len(self.upserts) + len(self.references)


@pytest.fixture
def ingestion(monkeypatch: pytest.MonkeyPatch) -> Ingestion:
    spy = Ingestion()
    real_upsert = cve_service.upsert_cve
    real_references = reference_service.upsert_references

    async def upsert_cve(
        db: AsyncSession, cve_id: str, source: CVESourceType, payload: CVEIngestPayload
    ) -> Any:
        spy.upserts.append((cve_id, source, payload))
        return await real_upsert(db, cve_id, source, payload)

    async def upsert_references(
        session: AsyncSession,
        ticket_id: Any,
        cve_id: str,
        source: str,
        source_reference: AutomaticReferenceInput | None,
        upstream_references: Iterable[AutomaticReferenceInput],
    ) -> None:
        upstream = list(upstream_references)
        spy.references.append(
            {
                "ticket_id": ticket_id,
                "cve_id": cve_id,
                "source": source,
                "source_reference": source_reference,
                "upstream": upstream,
            }
        )
        await real_references(
            session, ticket_id, cve_id, source, source_reference, upstream
        )

    monkeypatch.setattr(cve_service, "upsert_cve", upsert_cve)
    monkeypatch.setattr(reference_service, "upsert_references", upsert_references)
    return spy


@pytest.fixture
def server() -> BugzillaServer:
    return BugzillaServer()


@pytest.fixture(autouse=True)
def sleeps(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """Every request-delay sleep of the module, recorded instead of slept."""
    recorded: list[float] = []

    async def sleep(delay: float) -> None:
        recorded.append(delay)

    monkeypatch.setattr(sync_module, "asyncio", SimpleNamespace(sleep=sleep))
    return recorded


@pytest.fixture
async def fetcher(server: BugzillaServer) -> AsyncIterator[SyncBugzillaBugs]:
    instance = SyncBugzillaBugs()
    instance._http_client = server.client()
    try:
        yield instance
    finally:
        await instance._teardown_http_client()


@dataclass
class Target:
    cve: CVE
    ticket: Ticket

    @property
    def cve_id(self) -> str:
        return self.cve.cve_id


async def _ensure_default_setting(db: AsyncSession) -> None:
    if await db.get(SystemSetting, "default_cvss_version") is None:
        db.add(SystemSetting(key="default_cvss_version", value="3.1"))


@pytest.fixture
async def target(db_session: AsyncSession) -> Target:
    """A CVE with its `Analysis` Ticket and the default CVSS version the
    trusted-external batch reads."""
    await _ensure_default_setting(db_session)
    cve = CVE(cve_id=fictional_cve_id())
    db_session.add(cve)
    await db_session.flush()
    ticket = Ticket(status="Analysis", cve_id=cve.id)
    db_session.add(ticket)
    await db_session.flush()
    return Target(cve, ticket)


def _retargeted(name: str, cve_id: str) -> dict[str, Any]:
    """The bug of a live single-query fixture with `cve_id` as its first
    alias instead of the captured one."""
    [item] = copy.deepcopy(load_fixture(name)["bugs"])
    item["alias"] = [cve_id, *item["alias"][1:]]
    return dict(item)


async def _references(
    db: AsyncSession, ticket: Ticket
) -> list[tuple[str, str | None, str | None, str]]:
    """Every reference of the Ticket as (url, title, type, source)."""
    rows = await db.execute(
        select(
            TicketReference.url,
            TicketReference.title,
            TicketReference.type,
            TicketReference.source,
        ).where(TicketReference.ticket_id == ticket.id)
    )
    return sorted((url, title, kind, source) for url, title, kind, source in rows)


async def _source_status(db: AsyncSession, cve: CVE) -> str | None:
    value: str | None = await db.scalar(
        select(CVESource.status).where(
            CVESource.cve_id == cve.id, CVESource.source == "bugzilla"
        )
    )
    return value


def _events(logs: Iterable[Mapping[str, Any]], name: str) -> list[Mapping[str, Any]]:
    return [entry for entry in logs if entry["event"] == name]


def _assert_private(logs: Iterable[Mapping[str, Any]], *values: str) -> None:
    for entry in logs:
        rendered = repr(dict(entry))
        assert "\\x00" not in rendered, entry
        assert "\\ud800" not in rendered, entry
        for value in (SECRET, "fictional summary", *values):
            assert value not in rendered, entry


def _serve(server: BugzillaServer, cve_id: str, *bugs: Mapping[str, Any]) -> None:
    server.singles[cve_id] = [dict(item) for item in bugs]


def _parsed(*bugs: Mapping[str, Any]) -> list[BugzillaBug]:
    return parse_response(envelope(bugs)).bugs


# ---------------------------------------------------------------------------
# The bug record (Response Validation; The Bug of a CVE; Algorithm step 5)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestResponseValidation:
    def test_live_page_parses_every_consumed_field(self) -> None:
        live = page_bugs()

        parsed = parse_response({"bugs": live}).bugs

        assert [item.id for item in parsed] == [item["id"] for item in live]
        assert [item.alias for item in parsed] == [item["alias"] for item in live]
        assert [item.summary for item in parsed] == [item["summary"] for item in live]
        assert all(item.is_public for item in parsed)

    def test_unconsumed_members_are_ignored(self) -> None:
        document = {
            "bugs": [{**bug(7, "CVE-2099-0001"), "status": "NEW", "creator": SECRET}],
            "faults": [],
            "total": {"unexpected": True},
        }

        [parsed] = parse_response(document).bugs

        assert parsed.id == 7
        assert not hasattr(parsed, "creator")

    @pytest.mark.parametrize(
        "document",
        [
            [],
            None,
            SECRET,
            1,
            {},
            {"bugs": None},
            {"bugs": {"id": 1}},
            {"bugs": [SECRET]},
            {"bugs": [None]},
            {"bugs": [[1]]},
        ],
        ids=[
            "array_root",
            "null_root",
            "string_root",
            "number_root",
            "missing_bugs",
            "null_bugs",
            "object_bugs",
            "string_element",
            "null_element",
            "array_element",
        ],
    )
    def test_root_or_element_shape_mismatch_raises(self, document: Any) -> None:
        with pytest.raises(ValidationError) as raised:
            parse_response(document)

        assert SECRET not in str(raised.value)

    @pytest.mark.parametrize(
        ("member", "value"),
        [
            ("id", True),
            ("id", False),
            ("id", 1.0),
            ("id", "7"),
            ("id", 0),
            ("id", -7),
            ("id", None),
            ("alias", SECRET),
            ("alias", None),
            ("alias", [7]),
            ("alias", [None]),
            ("alias", {"CVE-2099-0001": SECRET}),
            ("summary", None),
            ("summary", 7),
            ("summary", [SECRET]),
            ("groups", None),
            ("groups", SECRET),
            ("groups", {"name": SECRET}),
        ],
        ids=lambda value: repr(value)[:24],
    )
    def test_mistyped_consumed_member_raises_without_rendering_input(
        self, member: str, value: Any
    ) -> None:
        item = bug(7, "CVE-2099-0001", summary=SECRET)
        item[member] = value

        with pytest.raises(ValidationError) as raised:
            parse_response(envelope([item]))

        assert SECRET not in str(raised.value)

    @pytest.mark.parametrize("member", ["id", "alias", "summary", "groups"])
    def test_missing_consumed_member_raises(self, member: str) -> None:
        item = bug(7, "CVE-2099-0001")
        del item[member]

        with pytest.raises(ValidationError):
            parse_response(envelope([item]))

    def test_restricted_bug_is_not_public_whatever_its_group_items(self) -> None:
        restricted = _parsed(
            bug(7, "CVE-2099-0001", groups=["embargoed"]),
            bug(8, "CVE-2099-0002", groups=[{"name": SECRET}, 7, None]),
        )

        assert [item.is_public for item in restricted] == [False, False]


@pytest.mark.unit
class TestPageOrder:
    def test_strictly_ascending_page_above_the_cursor_is_accepted(self) -> None:
        document = envelope([bug(11, "CVE-2099-0001"), bug(12, "CVE-2099-0002")])

        assert [item.id for item in parse_page(document, 10)] == [11, 12]

    def test_empty_page_is_accepted(self) -> None:
        assert parse_page(load_fixture("page_empty"), 1290610) == []

    @pytest.mark.parametrize(
        ("ids", "after_id"),
        [
            ([10], 10),
            ([9], 10),
            ([12, 11], 10),
            ([11, 11], 10),
            ([11, 13, 12], 10),
            ([1], 1290610),
        ],
        ids=[
            "equal_to_cursor",
            "below_cursor",
            "descending",
            "duplicate",
            "unordered",
            "restarted",
        ],
    )
    def test_non_ascending_or_non_progressing_page_raises(
        self, ids: list[int], after_id: int
    ) -> None:
        document = envelope(
            [bug(bug_id, "CVE-2099-0001", summary=SECRET) for bug_id in ids]
        )

        with pytest.raises(PageOrderError) as raised:
            parse_page(document, after_id)

        assert str(raised.value) == "Bug IDs of the page are not strictly ascending"
        assert SECRET not in str(raised.value)
        assert isinstance(raised.value, ValueError)

    def test_schema_mismatch_of_a_page_is_a_validation_error(self) -> None:
        with pytest.raises(ValidationError):
            parse_page({"bugs": [{"id": 11}]}, 10)


@pytest.mark.unit
class TestBugsOfACve:
    def test_live_page_groups_every_public_bug_by_each_cve_alias(self) -> None:
        live = page_bugs()

        grouped = bugs_by_cve(parse_response({"bugs": live}).bugs)

        expected = {
            alias: [item["id"]]
            for item in live
            for alias in item["alias"]
            if alias.startswith("CVE-")
        }
        assert {cve_id: [b.id for b in bugs] for cve_id, bugs in grouped.items()} == (
            expected
        )
        assert "GHSA-q66g-3m63-78mh" not in grouped
        assert list(grouped) == sorted(grouped)

    def test_one_bug_links_each_of_its_cve_aliases(self) -> None:
        grouped = bugs_by_cve(
            _parsed(bug(7, "CVE-2099-0002", "GHSA-fict-0001-aaaa", "CVE-2099-0001"))
        )

        assert list(grouped) == ["CVE-2099-0001", "CVE-2099-0002"]
        assert [b.id for b in grouped["CVE-2099-0001"]] == [7]
        assert [b.id for b in grouped["CVE-2099-0002"]] == [7]

    def test_two_bugs_of_one_cve_are_in_ascending_bug_id_order(self) -> None:
        grouped = bugs_by_cve(_parsed(bug(9, "CVE-2099-0001"), bug(3, "CVE-2099-0001")))

        assert [b.id for b in grouped["CVE-2099-0001"]] == [3, 9]

    def test_cve_ids_are_in_code_point_order(self) -> None:
        grouped = bugs_by_cve(
            _parsed(
                bug(1, "CVE-2099-10000"),
                bug(2, "CVE-2099-9999"),
                bug(3, "CVE-2098-99999"),
            )
        )

        assert list(grouped) == ["CVE-2098-99999", "CVE-2099-10000", "CVE-2099-9999"]

    def test_repeated_alias_adds_the_bug_once(self) -> None:
        grouped = bugs_by_cve(_parsed(bug(7, "CVE-2099-0001", "CVE-2099-0001")))

        assert [b.id for b in grouped["CVE-2099-0001"]] == [7]

    def test_restricted_bug_contributes_nothing(self) -> None:
        grouped = bugs_by_cve(
            _parsed(
                bug(7, "CVE-2099-0001", groups=["embargoed"]),
                bug(8, "CVE-2099-0002", groups=[]),
            )
        )

        assert list(grouped) == ["CVE-2099-0002"]

    @pytest.mark.parametrize(
        "alias",
        [
            "cve-2099-0001",
            "Cve-2099-0001",
            "CVE-2099-1",
            "CVE-99-0001",
            " CVE-2099-0001",
            "CVE-2099-0001 ",
            "CVE-2099-" + "1" * 12,
            "CVE-2099-0001\x00",
            f"CVE-2099-0001{SURROGATE}",
            "GHSA-fict-0001-aaaa",
            "",
        ],
        ids=[
            "lowercase",
            "mixed_case",
            "short_sequence",
            "short_year",
            "leading_space",
            "trailing_space",
            "over_long",
            "nul",
            "surrogate",
            "ghsa",
            "empty",
        ],
    )
    def test_alias_that_is_not_a_canonical_cve_id_names_no_cve(
        self, alias: str
    ) -> None:
        grouped = bugs_by_cve(_parsed(bug(7, alias), bug(8, alias, "CVE-2099-0002")))

        assert list(grouped) == ["CVE-2099-0002"]
        assert [b.id for b in grouped["CVE-2099-0002"]] == [8]

    def test_bug_without_alias_contributes_nothing(self) -> None:
        assert bugs_by_cve(_parsed(bug(7))) == {}


# ---------------------------------------------------------------------------
# The request (`fetch_single(cve_id)` steps 1-2)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestRequest:
    async def test_one_get_with_the_documented_query(
        self, fetcher: SyncBugzillaBugs, server: BugzillaServer, sleeps: list[float]
    ) -> None:
        cve_id = fictional_cve_id()

        with pytest.raises(CVENotInSource):
            await fetcher.fetch_single(cve_id, NO_SESSION)

        [request] = server.requests
        assert request.method == "GET"
        assert (request.url.scheme, request.url.host, request.url.port) == (
            "https",
            "bugzilla.suse.com",
            None,
        )
        assert str(request.url.copy_with(query=None)) == BUG_URL
        assert request.url.params.multi_items() == [
            ("include_fields", CONSUMED_FIELDS),
            ("alias", cve_id),
        ]
        assert "authorization" not in request.headers
        assert "cookie" not in request.headers
        # One request and no request delay.
        assert sleeps == []

    async def test_production_client_defaults_apply(self) -> None:
        """`Accept: application/json` selects JSON (with `text/html` the
        server answers an HTML page), and no redirect is followed."""
        assert SyncBugzillaBugs.http_client_options == {}
        instance = SyncBugzillaBugs()
        try:
            client = instance.http_client
            assert client.headers["accept"] == "application/json"
            assert client.follow_redirects is False
            assert "authorization" not in client.headers
        finally:
            await instance._teardown_http_client()

    async def test_fetch_single_never_closes_the_client(
        self, fetcher: SyncBugzillaBugs
    ) -> None:
        client = fetcher._http_client
        assert client is not None

        with pytest.raises(CVENotInSource):
            await fetcher.fetch_single(fictional_cve_id(), NO_SESSION)

        assert fetcher._http_client is client
        assert not client.is_closed


# ---------------------------------------------------------------------------
# CVENotInSource before any mutation (`fetch_single(cve_id)` steps 1 and 4)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestMissingBeforeMutation:
    @pytest.mark.parametrize(
        "cve_id",
        [
            "CVE-2099-1",
            "cve-2099-0001",
            "CVE-2099-0001 ",
            "",
            "CVE-2099-" + "1" * 12,
            "CVE-2099-0001\x00",
            f"CVE-2099-0001{SURROGATE}",
        ],
        ids=[
            "short",
            "lowercase",
            "trailing_space",
            "empty",
            "over_long",
            "nul",
            "surrogate",
        ],
    )
    async def test_malformed_requested_cve_id_is_missing_without_http(
        self,
        cve_id: str,
        fetcher: SyncBugzillaBugs,
        server: BugzillaServer,
        ingestion: Ingestion,
    ) -> None:
        with pytest.raises(CVENotInSource):
            await fetcher.fetch_single(cve_id, NO_SESSION)

        assert server.requests == []
        assert ingestion.calls == 0

    async def test_live_empty_array_is_missing(
        self, fetcher: SyncBugzillaBugs, server: BugzillaServer, ingestion: Ingestion
    ) -> None:
        cve_id = fictional_cve_id()
        server.single_responses[cve_id] = status(
            200, load_raw_fixture(SINGLE_EMPTY_FIXTURE)
        )

        with capture_logs() as logs, pytest.raises(CVENotInSource):
            await fetcher.fetch_single(cve_id, NO_SESSION)

        assert len(server.requests) == 1
        assert ingestion.calls == 0
        assert logs == []

    @pytest.mark.parametrize(
        "answer",
        ["restricted", "lowercase_alias", "other_cve", "ghsa_only", "substring"],
    )
    async def test_no_public_bug_with_the_exact_alias_is_missing(
        self,
        answer: str,
        fetcher: SyncBugzillaBugs,
        server: BugzillaServer,
        ingestion: Ingestion,
    ) -> None:
        cve_id = fictional_cve_id()
        bugs = {
            "restricted": [bug(7, cve_id, summary=SECRET, groups=["embargoed"])],
            "lowercase_alias": [bug(7, cve_id.lower(), summary=SECRET)],
            "other_cve": [bug(7, fictional_cve_id(), summary=SECRET)],
            "ghsa_only": [bug(7, "GHSA-fict-0001-aaaa", summary=SECRET)],
            "substring": [bug(7, f"{cve_id}1", summary=SECRET)],
        }[answer]
        _serve(server, cve_id, *bugs)

        with capture_logs() as logs, pytest.raises(CVENotInSource):
            await fetcher.fetch_single(cve_id, NO_SESSION)

        assert ingestion.calls == 0
        assert logs == []


# ---------------------------------------------------------------------------
# Error propagation and classification (`fetch_single()` error table)
# ---------------------------------------------------------------------------


async def _raised(
    fetcher: SyncBugzillaBugs, server: BugzillaServer, responder: Any
) -> BaseException:
    cve_id = fictional_cve_id()
    server.single_responses[cve_id] = responder
    with pytest.raises((httpx.HTTPError, ValueError, BugzillaResponseError)) as raised:
        await fetcher.fetch_single(cve_id, NO_SESSION)
    assert [request.url.params.get("alias") for request in server.requests] == [cve_id]
    return raised.value


@pytest.mark.unit
class TestErrorPropagation:
    async def test_live_400_is_the_unwrapped_non_retryable_status_error(
        self, fetcher: SyncBugzillaBugs, server: BugzillaServer, ingestion: Ingestion
    ) -> None:
        error = await _raised(
            fetcher, server, status(400, load_raw_fixture(ERROR_400_FIXTURE))
        )

        assert type(error) is httpx.HTTPStatusError
        assert error.response.status_code == 400
        assert not is_retryable_condition(error)
        assert ingestion.calls == 0

    @pytest.mark.parametrize("code", [401, 403, 404, 405, 410, 422])
    async def test_other_4xx_is_the_unwrapped_non_retryable_status_error(
        self,
        code: int,
        fetcher: SyncBugzillaBugs,
        server: BugzillaServer,
        ingestion: Ingestion,
    ) -> None:
        """A 404 is not a missing signal: an absent alias is an empty
        array."""
        error = await _raised(fetcher, server, status(code, SECRET.encode()))

        assert type(error) is httpx.HTTPStatusError
        assert error.response.status_code == code
        assert not is_retryable_condition(error)
        assert ingestion.calls == 0

    @pytest.mark.parametrize("code", [429, 500, 502, 503, 504])
    async def test_429_and_5xx_are_unwrapped_and_retryable(
        self, code: int, fetcher: SyncBugzillaBugs, server: BugzillaServer
    ) -> None:
        error = await _raised(fetcher, server, status(code))

        assert type(error) is httpx.HTTPStatusError
        assert error.response.status_code == code
        assert is_retryable_condition(error)

    @pytest.mark.parametrize("code", [301, 302, 303, 307, 308])
    async def test_redirect_is_not_followed_and_is_non_retryable(
        self, code: int, fetcher: SyncBugzillaBugs, server: BugzillaServer
    ) -> None:
        error = await _raised(
            fetcher,
            server,
            status(code, headers={"Location": "https://bugzilla.example.invalid/"}),
        )

        assert type(error) is httpx.HTTPStatusError
        assert error.response.status_code == code
        assert not is_retryable_condition(error)
        assert len(server.requests) == 1

    @pytest.mark.parametrize(
        "error",
        [
            httpx.ConnectError("refused"),
            httpx.ConnectTimeout("timed out"),
            httpx.ReadTimeout("timed out"),
            httpx.RemoteProtocolError("closed"),
        ],
        ids=lambda error: type(error).__name__,
    )
    async def test_transport_error_propagates_unwrapped_and_retryable(
        self, error: Exception, fetcher: SyncBugzillaBugs, server: BugzillaServer
    ) -> None:
        raised = await _raised(fetcher, server, raising(error))

        assert raised is error
        assert is_retryable_condition(raised)

    @pytest.mark.parametrize("code", [201, 202, 203, 204, 206])
    async def test_other_2xx_is_a_fixed_error_that_never_reads_the_body(
        self,
        code: int,
        fetcher: SyncBugzillaBugs,
        server: BugzillaServer,
        ingestion: Ingestion,
    ) -> None:
        cve_id = fictional_cve_id()
        error = await _raised(
            fetcher,
            server,
            lambda request: httpx.Response(
                code,
                json=envelope([bug(7, cve_id, summary=SECRET)]),
                request=request,
            ),
        )

        assert type(error) is BugzillaResponseError
        assert str(error) == "SUSE Bugzilla returned an unexpected response"
        assert error.__cause__ is None
        assert not is_retryable_condition(error)
        assert ingestion.calls == 0

    @pytest.mark.parametrize(
        ("responder", "error_type"),
        [
            (status(200, b""), ValueError),
            (status(200, b"{"), ValueError),
            (status(200, f"<html>{SECRET}</html>".encode()), ValueError),
            (html(), ValueError),
            (status(200, b"\xff\xfe\xfd"), ValueError),
            (status(200, ("[" + NESTED_ARRAY + "]").encode()), JSONNestingError),
            (status(200, b"[" + OVERSIZED_INTEGER.encode() + b"]"), ValueError),
        ],
        ids=[
            "empty",
            "truncated",
            "html",
            "live_html_answer",
            "invalid_utf8",
            "nesting_beyond_the_parser_limit",
            "integer_beyond_the_conversion_limit",
        ],
    )
    async def test_invalid_json_is_non_retryable(
        self,
        responder: Any,
        error_type: type[Exception],
        fetcher: SyncBugzillaBugs,
        server: BugzillaServer,
        ingestion: Ingestion,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """An HTML page with HTTP 200, such as a bot challenge or the answer
        to `Accept: text/html`, is never an empty result."""
        limit_parser_nesting(monkeypatch)

        error = await _raised(fetcher, server, responder)

        assert isinstance(error, error_type)
        assert SECRET not in str(error)
        assert not is_retryable_condition(error)
        assert not is_infrastructure_failure(error)
        assert ingestion.calls == 0

    @pytest.mark.parametrize("code", [200, 404, 503])
    async def test_undecodable_body_is_non_retryable_whatever_the_status(
        self,
        code: int,
        fetcher: SyncBugzillaBugs,
        server: BugzillaServer,
        ingestion: Ingestion,
    ) -> None:
        """The request reads the body before the status is checked
        (networking.md, HTTP Response Compression)."""
        error = await _raised(fetcher, server, undecodable(code))

        assert isinstance(error, httpx.DecodingError)
        assert not is_retryable_condition(error)
        assert ingestion.calls == 0

    @pytest.mark.parametrize(
        "document",
        [
            [],
            {"bugs": None},
            {"bugs": [SECRET]},
            {"bugs": [{"id": True, "alias": [], "summary": SECRET, "groups": []}]},
            {"bugs": [{"id": 7, "alias": SECRET, "summary": "x", "groups": []}]},
            {"bugs": [{"id": 7, "alias": [], "summary": [SECRET], "groups": []}]},
            {"bugs": [{"id": 7, "alias": [], "summary": "x", "groups": SECRET}]},
        ],
        ids=[
            "array_root",
            "null_bugs",
            "string_element",
            "boolean_id",
            "string_alias",
            "list_summary",
            "string_groups",
        ],
    )
    async def test_schema_mismatch_is_non_retryable_and_hides_the_input(
        self,
        document: Any,
        fetcher: SyncBugzillaBugs,
        server: BugzillaServer,
        ingestion: Ingestion,
    ) -> None:
        cve_id = fictional_cve_id()
        server.single_responses[cve_id] = json_body(document)

        with capture_logs() as logs, pytest.raises(ValidationError) as raised:
            await fetcher.fetch_single(cve_id, NO_SESSION)

        assert SECRET not in str(raised.value)
        assert not is_retryable_condition(raised.value)
        assert ingestion.calls == 0
        assert logs == []

    @pytest.mark.parametrize(
        "signal_type",
        [asyncio.CancelledError, SoftTimeLimitExceeded, MemoryError],
        ids=lambda t: t.__name__,
    )
    async def test_whole_run_signal_propagates_unchanged(
        self,
        signal_type: type[BaseException],
        fetcher: SyncBugzillaBugs,
        server: BugzillaServer,
        ingestion: Ingestion,
    ) -> None:
        cve_id = fictional_cve_id()
        signal = signal_type()

        def respond(request: httpx.Request) -> httpx.Response:
            raise signal

        server.single_responses[cve_id] = respond

        with pytest.raises(signal_type) as raised:
            await fetcher.fetch_single(cve_id, NO_SESSION)

        assert raised.value is signal
        assert ingestion.calls == 0


# ---------------------------------------------------------------------------
# Ingestion (`fetch_single(cve_id)` steps 5-6; Bug Reference; Payload)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestIngestion:
    async def test_live_bug_is_linked_with_its_summary_as_an_issue(
        self,
        fetcher: SyncBugzillaBugs,
        server: BugzillaServer,
        ingestion: Ingestion,
        target: Target,
        db_session: AsyncSession,
    ) -> None:
        live = _retargeted(SINGLE_FIXTURE, target.cve_id)
        _serve(server, target.cve_id, live)
        before = (target.cve.title, target.cve.description, target.cve.modified_date)

        result = await fetcher.fetch_single(target.cve_id, db_session)

        assert isinstance(result, CVEFetchResult)
        assert result.action is UpsertAction.UNCHANGED
        assert result.post_ingest is None
        [(cve_id, source, payload)] = ingestion.upserts
        assert (cve_id, source) == (target.cve_id, CVESourceType.BUGZILLA)
        assert payload == CVEIngestPayload()
        [call] = ingestion.references
        assert call["source"] == NAME
        assert call["source_reference"] is None
        assert call["upstream"] == [
            AutomaticReferenceInput(
                url=bug_reference_url(live["id"]),
                title=live["summary"],
                explicit_type=ReferenceType.ISSUE,
            )
        ]
        assert await _references(db_session, target.ticket) == [
            (bug_reference_url(live["id"]), live["summary"], "issue", NAME)
        ]
        assert await _source_status(db_session, target.cve) == (
            CVESourceFetchStatus.SUCCESS
        )
        await db_session.refresh(target.cve)
        assert (
            target.cve.title,
            target.cve.description,
            target.cve.modified_date,
        ) == before

    async def test_live_multi_alias_bug_is_linked_to_the_requested_cve(
        self,
        fetcher: SyncBugzillaBugs,
        server: BugzillaServer,
        target: Target,
        db_session: AsyncSession,
    ) -> None:
        live = _retargeted(SINGLE_MULTI_FIXTURE, target.cve_id)
        _serve(server, target.cve_id, live)

        await fetcher.fetch_single(target.cve_id, db_session)

        assert await _references(db_session, target.ticket) == [
            (bug_reference_url(live["id"]), live["summary"], "issue", NAME)
        ]

    async def test_two_bugs_are_linked_in_ascending_bug_id_order(
        self,
        fetcher: SyncBugzillaBugs,
        server: BugzillaServer,
        ingestion: Ingestion,
        target: Target,
        db_session: AsyncSession,
    ) -> None:
        _serve(
            server,
            target.cve_id,
            bug(1290002, target.cve_id, summary="Second bug"),
            bug(1290001, target.cve_id, summary="First bug"),
            bug(1290003, target.cve_id, summary="Restricted", groups=["embargoed"]),
        )

        await fetcher.fetch_single(target.cve_id, db_session)

        [call] = ingestion.references
        assert [candidate.url for candidate in call["upstream"]] == [
            bug_reference_url(1290001),
            bug_reference_url(1290002),
        ]
        assert await _references(db_session, target.ticket) == [
            (bug_reference_url(1290001), "First bug", "issue", NAME),
            (bug_reference_url(1290002), "Second bug", "issue", NAME),
        ]

    async def test_nvd_reference_of_the_same_url_is_merged(
        self,
        fetcher: SyncBugzillaBugs,
        server: BugzillaServer,
        target: Target,
        db_session: AsyncSession,
    ) -> None:
        """The NVD `Issue Tracking` form is the same normalized URL: the
        different-source rule keeps the NVD owner and fills the title."""
        url = bug_reference_url(1290001)
        db_session.add(
            TicketReference(
                ticket_id=target.ticket.id, url=url, type="issue", source=NVD_NAME
            )
        )
        await db_session.flush()
        _serve(server, target.cve_id, bug(1290001, target.cve_id, summary="Bug"))

        await fetcher.fetch_single(target.cve_id, db_session)

        assert await _references(db_session, target.ticket) == [
            (url, "Bug", "issue", NVD_NAME)
        ]

    async def test_titled_reference_of_another_source_keeps_its_title(
        self,
        fetcher: SyncBugzillaBugs,
        server: BugzillaServer,
        target: Target,
        db_session: AsyncSession,
    ) -> None:
        url = bug_reference_url(1290001)
        db_session.add(
            TicketReference(
                ticket_id=target.ticket.id,
                url=url,
                title="NVD title",
                type="issue",
                source=NVD_NAME,
            )
        )
        await db_session.flush()
        _serve(server, target.cve_id, bug(1290001, target.cve_id, summary="Bug"))

        await fetcher.fetch_single(target.cve_id, db_session)

        assert await _references(db_session, target.ticket) == [
            (url, "NVD title", "issue", NVD_NAME)
        ]

    async def test_other_link_forms_remain_separate_references(
        self,
        fetcher: SyncBugzillaBugs,
        server: BugzillaServer,
        target: Target,
        db_session: AsyncSession,
    ) -> None:
        alias_form = f"https://bugzilla.suse.com/show_bug.cgi?id={target.cve_id}"
        db_session.add(
            TicketReference(ticket_id=target.ticket.id, url=alias_form, source=NVD_NAME)
        )
        await db_session.flush()
        _serve(server, target.cve_id, bug(1290001, target.cve_id, summary="Bug"))

        await fetcher.fetch_single(target.cve_id, db_session)

        assert await _references(db_session, target.ticket) == [
            (bug_reference_url(1290001), "Bug", "issue", NAME),
            (alias_form, None, None, NVD_NAME),
        ]

    async def test_changed_summary_updates_the_title_and_repeats_are_no_ops(
        self,
        fetcher: SyncBugzillaBugs,
        server: BugzillaServer,
        target: Target,
        db_session: AsyncSession,
    ) -> None:
        _serve(server, target.cve_id, bug(1290001, target.cve_id, summary="Before"))
        first = await fetcher.fetch_single(target.cve_id, db_session)
        _serve(server, target.cve_id, bug(1290001, target.cve_id, summary="After"))

        second = await fetcher.fetch_single(target.cve_id, db_session)
        third = await fetcher.fetch_single(target.cve_id, db_session)

        assert [first.action, second.action, third.action] == [
            UpsertAction.UNCHANGED
        ] * 3
        assert await _references(db_session, target.ticket) == [
            (bug_reference_url(1290001), "After", "issue", NAME)
        ]
        count = await db_session.scalar(
            select(func.count())
            .select_from(TicketReference)
            .where(TicketReference.ticket_id == target.ticket.id)
        )
        assert count == 1

    @pytest.mark.parametrize("status_value", ["Ignored", "Duplicated", "Resolved"])
    async def test_bug_is_linked_whatever_the_ticket_status(
        self,
        status_value: str,
        fetcher: SyncBugzillaBugs,
        server: BugzillaServer,
        target: Target,
        db_session: AsyncSession,
    ) -> None:
        if status_value == TicketStatus.DUPLICATED:
            canonical = Ticket(status=TicketStatus.ANALYSIS.value)
            db_session.add(canonical)
            await db_session.flush()
            target.ticket.duplicate_of_id = canonical.id
        target.ticket.status = status_value
        target.ticket.ignore_reason = ignore_reason_for(status_value)
        await db_session.flush()
        _serve(server, target.cve_id, bug(1290001, target.cve_id, summary="Bug"))

        await fetcher.fetch_single(target.cve_id, db_session)

        assert await _references(db_session, target.ticket) == [
            (bug_reference_url(1290001), "Bug", "issue", NAME)
        ]

    async def test_cve_without_a_ticket_receives_one_with_the_bugzilla_label(
        self,
        fetcher: SyncBugzillaBugs,
        server: BugzillaServer,
        db_session: AsyncSession,
    ) -> None:
        await _ensure_default_setting(db_session)
        cve = CVE(cve_id=fictional_cve_id())
        db_session.add(cve)
        await db_session.flush()
        _serve(server, cve.cve_id, bug(1290001, cve.cve_id, summary="Bug"))

        result = await fetcher.fetch_single(cve.cve_id, db_session)

        assert result.action is UpsertAction.UNCHANGED
        ticket = await db_session.scalar(select(Ticket).where(Ticket.cve_id == cve.id))
        assert ticket is not None
        assert ticket.status == "New"
        assert await ticket_events(db_session, ticket) == [
            EventRow("ticket_created", None, None, None, INGESTION_COMMENT, None),
            EventRow("cve_associated", None, None, cve.cve_id, None, None),
        ]
        assert await _references(db_session, ticket) == [
            (bug_reference_url(1290001), "Bug", "issue", NAME)
        ]

    async def test_fetch_single_never_commits_and_records_no_metric(
        self,
        fetcher: SyncBugzillaBugs,
        server: BugzillaServer,
        target: Target,
        db_session: AsyncSession,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _serve(server, target.cve_id, bug(1290001, target.cve_id))
        calls: list[str] = []

        async def commit() -> None:
            calls.append("commit")

        monkeypatch.setattr(db_session, "commit", commit)
        for name in (
            "record_succeeded",
            "record_failed",
            "record_created",
            "record_updated",
        ):
            monkeypatch.setattr(
                fetcher, name, lambda *a, _n=name, **k: calls.append(_n)
            )

        await fetcher.fetch_single(target.cve_id, db_session)

        assert calls == []


# ---------------------------------------------------------------------------
# External String Admissibility (Response Validation)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestExternalStringAdmissibility:
    @pytest.mark.parametrize("character", INADMISSIBLE_CHARACTERS)
    async def test_inadmissible_summary_skips_only_that_candidate(
        self,
        character: str,
        fetcher: SyncBugzillaBugs,
        server: BugzillaServer,
        target: Target,
        db_session: AsyncSession,
    ) -> None:
        _serve(
            server,
            target.cve_id,
            bug(1290001, target.cve_id, summary=f"{SECRET}{character}"),
            bug(1290002, target.cve_id, summary="Valid"),
        )

        with capture_logs() as logs:
            result = await fetcher.fetch_single(target.cve_id, db_session)

        assert result.action is UpsertAction.UNCHANGED
        assert [
            (entry["event"], entry["reason"])
            for entry in logs
            if entry["log_level"] == "warning"
        ] == [("automatic_reference_rejected", "invalid_metadata")]
        _assert_private(logs)
        assert await _references(db_session, target.ticket) == [
            (bug_reference_url(1290002), "Valid", "issue", NAME)
        ]
        assert await _source_status(db_session, target.cve) == (
            CVESourceFetchStatus.SUCCESS
        )

    @pytest.mark.parametrize("character", INADMISSIBLE_CHARACTERS)
    async def test_inadmissible_alias_names_no_cve(
        self,
        character: str,
        fetcher: SyncBugzillaBugs,
        server: BugzillaServer,
        ingestion: Ingestion,
        target: Target,
    ) -> None:
        _serve(server, target.cve_id, bug(1290001, f"{target.cve_id}{character}"))

        with capture_logs() as logs, pytest.raises(CVENotInSource):
            await fetcher.fetch_single(target.cve_id, NO_SESSION)

        assert ingestion.calls == 0
        assert logs == []

    @pytest.mark.parametrize(
        "summary", ["", " ", "x" * 501], ids=["empty", "whitespace", "over_long"]
    )
    async def test_summary_that_is_not_a_valid_title_skips_the_candidate(
        self,
        summary: str,
        fetcher: SyncBugzillaBugs,
        server: BugzillaServer,
        target: Target,
        db_session: AsyncSession,
    ) -> None:
        _serve(server, target.cve_id, bug(1290001, target.cve_id, summary=summary))

        with capture_logs() as logs:
            await fetcher.fetch_single(target.cve_id, db_session)

        assert [entry.get("reason") for entry in logs] == ["invalid_metadata"]
        assert await _references(db_session, target.ticket) == []
        assert await _source_status(db_session, target.cve) == (
            CVESourceFetchStatus.SUCCESS
        )


# ---------------------------------------------------------------------------
# Log privacy (Security and Privacy)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestLogPrivacy:
    async def test_a_full_fetch_logs_no_summary_alias_or_body(
        self,
        fetcher: SyncBugzillaBugs,
        server: BugzillaServer,
        target: Target,
        db_session: AsyncSession,
    ) -> None:
        aliases: Sequence[str] = (target.cve_id, "GHSA-fict-0001-aaaa")
        _serve(
            server,
            target.cve_id,
            bug(1290001, *aliases, summary=SECRET),
            bug(1290002, target.cve_id, summary=f"{SECRET}\x00"),
        )

        with capture_logs() as logs:
            await fetcher.fetch_single(target.cve_id, db_session)

        _assert_private(logs, "GHSA-fict-0001-aaaa")
        assert {entry["event"] for entry in logs} <= {"automatic_reference_rejected"}
