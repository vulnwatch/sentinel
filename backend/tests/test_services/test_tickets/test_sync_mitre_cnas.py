"""Tests for the `sync_mitre_cnas` fetcher
(backend/app/services/tickets/sync_mitre_cnas.py).

Owning specifications:

- docs/features/tickets/cna.md (Fetcher: `sync_mitre_cnas` — properties,
  Source, Algorithm, CNA Entry Matching, Field Mapping, Error Handling,
  External String Admissibility, Work Unit and Metrics; Concurrency;
  Security; Testing Requirements, item 7).
- docs/features/platform/fetcher-infrastructure.md (BaseFetcher Base Class:
  execution-session transaction contract, Finalization, Outcome and effect
  accounting; Error Message Sanitization; Naming Convention; Per-Ticket
  Catch-Up inventory; Fetcher Discovery; FetcherConfig bootstrap; Celery
  Beat Schedule Synchronization).
- docs/features/platform/networking.md (Redirect Policy) and
  docs/conventions.md (External JSON Decoding; External String
  Admissibility).
- docs/features/platform/testing-strategy.md (Fetcher Outcome and Effect
  Accounting; External String Admissibility; External JSON Decoding; CNA
  and Auto-Ignore Policy).

`execute()` tests run against CNA rows seeded in the rolled-back
`db_session`: the fetcher's commit releases a savepoint of the per-test
outer transaction, so every row is rolled back at teardown. The `run()`
tests commit CNA rows, a `FetcherConfig`, and a `FetcherRun` under a
test-only name through `real_session_factory` and delete them at teardown.
The list is the in-process `CnaListServer`, injected as the fetcher's HTTP
client. Every CNA, short name, and value is fictional or from the
sanitized live fixture.
"""

from __future__ import annotations

import uuid
from collections.abc import (
    AsyncIterator,
    Awaitable,
    Callable,
    Mapping,
    Sequence,
)
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

import httpx
import pytest
from celery import Celery
from redbeat import RedBeatSchedulerEntry
from sqlalchemy import delete, event, func, select
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from structlog.testing import capture_logs

import app.services.base_fetcher as base_fetcher_module
from app.models.cna import CNA
from app.models.cve import CVE
from app.models.fetcher_config import FetcherConfig
from app.models.fetcher_run import FetcherRun
from app.models.ticket import Ticket
from app.models.ticket_audit_event import TicketAuditEvent
from app.services import cna_service, fetcher_discovery
from app.services.base_fetcher import (
    FETCHER_REGISTRY,
    FetcherError,
    FetcherRunConfig,
    get_catch_up_fetchers,
)
from app.services.fetcher_bootstrap import bootstrap_fetcher_configs
from app.services.fetcher_schedule import reconcile_beat_schedule
from app.services.tickets.cna_list import scope_plain_text
from app.services.tickets.sync_mitre_cnas import (
    CNA_LIST_URL,
    CNAListStructureError,
    SyncMitreCnas,
)
from tests.support.cve_program import (
    CNA_LIST_URL as FIXTURE_URL,
)
from tests.support.cve_program import (
    CnaListServer,
    entry_for,
    fixture_entry,
    load_list,
    raising,
    raw_body,
    status,
)
from tests.support.inadmissible import INADMISSIBLE_CHARACTERS, json_bytes
from tests.support.json_decoding import (
    NESTED_ARRAY,
    OVERSIZED_INTEGER,
    limit_parser_nesting,
)

NAME: Final = "sync_mitre_cnas"

# The specified messages and events, as literals (cna.md, Error Handling).
CONNECT_FAILED_MESSAGE: Final = "Failed to connect to the CNA list"
TIMED_OUT_MESSAGE: Final = "CNA list request timed out"
UNPARSEABLE_MESSAGE: Final = "CNA list returned unparseable response"
ENTRIES_INVALID_EVENT: Final = "cna_list_entries_invalid"
MATCH_AMBIGUOUS_EVENT: Final = "cna_metadata_match_ambiguous"
FIELD_INVALID_EVENT: Final = "cna_metadata_field_invalid"
STALE: Final = datetime(2000, 1, 1, tzinfo=UTC)
"""An `updated_at` far before the transaction's `now()`."""
OBSERVED: Final = datetime(2026, 1, 1, tzinfo=UTC)

Metrics = tuple[int, int, int, int]
"""`(succeeded, created, updated, failed)` of one fetcher run."""
Stored = tuple[str | None, list[str], str | None]
"""`(organization_name, types, scope)` of one row."""
CNAFactory = Callable[..., Awaitable[CNA]]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _metrics(fetcher: SyncMitreCnas) -> Metrics:
    return (fetcher._succeeded, fetcher._created, fetcher._updated, fetcher._failed)


def _fetcher(server: CnaListServer) -> SyncMitreCnas:
    fetcher = SyncMitreCnas()
    fetcher._http_client = server.client()
    return fetcher


async def _execute(db: AsyncSession, server: CnaListServer) -> SyncMitreCnas:
    fetcher = _fetcher(server)
    try:
        await fetcher.execute(db)
    finally:
        await fetcher._teardown_http_client()
    return fetcher


async def _sync(db: AsyncSession, *entries: Any) -> Metrics:
    """One run over a list of `entries`; returns its metrics."""
    return _metrics(await _execute(db, CnaListServer(list(entries))))


async def _execute_failing(
    db: AsyncSession, server: CnaListServer, error: type[BaseException] = FetcherError
) -> tuple[BaseException, SyncMitreCnas]:
    fetcher = _fetcher(server)
    try:
        with pytest.raises(error) as raised:
            await fetcher.execute(db)
    finally:
        await fetcher._teardown_http_client()
    return raised.value, fetcher


Seed = Callable[..., Awaitable[CNA]]


@pytest.fixture
def seed(cna_factory: CNAFactory) -> Seed:
    """Seed one CNA row with a fresh `org_id`, the given short name, and an
    old `updated_at`."""

    async def _seed(short_name: str | None, **overrides: Any) -> CNA:
        return await cna_factory(
            org_id=uuid.uuid4(), short_name=short_name, updated_at=STALE, **overrides
        )

    return _seed


async def _stored(db: AsyncSession, cna: CNA) -> Stored:
    row = (
        await db.execute(
            select(CNA.organization_name, CNA.types, CNA.scope).where(CNA.id == cna.id)
        )
    ).one()
    return (row[0], row[1], row[2])


async def _updated_at(db: AsyncSession, cna: CNA) -> datetime:
    value = await db.scalar(select(CNA.updated_at).where(CNA.id == cna.id))
    assert value is not None
    return value


def _logged(logs: Sequence[Mapping[str, Any]], name: str) -> list[Mapping[str, Any]]:
    return [entry for entry in logs if entry["event"] == name]


class SqlRecorder:
    """Records each SQL statement the engine executes while attached, and
    appends `("sql", statement)` to `events`."""

    def __init__(self, db: AsyncSession, events: list[tuple[str, str]]) -> None:
        self.engine = db.get_bind().engine
        self.events = events

    def _record(self, *args: Any) -> None:
        self.events.append(("sql", args[2]))

    def __enter__(self) -> SqlRecorder:
        event.listen(self.engine, "before_cursor_execute", self._record)
        return self

    def __exit__(self, *exc: object) -> None:
        event.remove(self.engine, "before_cursor_execute", self._record)


# ---------------------------------------------------------------------------
# Writes (Algorithm; CNA Entry Matching; Field Mapping)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestLiveList:
    async def test_live_fixture_updates_every_matching_row(
        self, db_session: AsyncSession, seed: Seed
    ) -> None:
        rows = {name: await seed(name) for name in ("ZTE", "Linux", "Snow", "SNOW")}
        cisa = await seed("CISA")
        absent = await seed("ExampleMobile")
        unnamed = await seed(None)

        fetcher = await _execute(db_session, CnaListServer())

        assert await _stored(db_session, rows["ZTE"]) == (
            "ZTE Corporation",
            ["Vendor"],
            "ZTE products (https://www.zte.com.cn/global/products) only.",
        )
        assert await _stored(db_session, rows["Linux"]) == (
            "kernel.org",
            ["Open Source", "Vendor"],
            "Any vulnerabilities in the Linux kernel as listed on kernel.org, "
            "excluding end-of-life (EOL) versions.",
        )
        assert await _stored(db_session, rows["Snow"]) == (
            "Snow Software",
            ["Vendor"],
            "All Snow Software products.",
        )
        assert (await _stored(db_session, rows["SNOW"]))[0] == "Snowflake"
        assert await _stored(db_session, cisa) == (
            "Cybersecurity and Infrastructure Security Agency (CISA)",
            ["N/A"],
            scope_plain_text(fixture_entry("CISA")["scope"]),
        )
        for untouched in (absent, unnamed):
            assert await _stored(db_session, untouched) == (None, [], None)
            assert await _updated_at(db_session, untouched) == STALE
        # Every fixture entry is valid; five rows changed.
        assert _metrics(fetcher) == (len(load_list()), 0, 5, 0)

    async def test_second_identical_run_updates_nothing(
        self, db_session: AsyncSession, seed: Seed
    ) -> None:
        cna = await seed("ZTE")
        await _execute(db_session, CnaListServer())
        written = await _updated_at(db_session, cna)

        fetcher = await _execute(db_session, CnaListServer())

        assert _metrics(fetcher) == (len(load_list()), 0, 0, 0)
        assert await _updated_at(db_session, cna) == written


@pytest.mark.integration
class TestMatching:
    async def test_ambiguous_rows_are_unchanged_and_each_warned(
        self, db_session: AsyncSession, seed: Seed
    ) -> None:
        folded = await seed("snow")
        first = await seed("example-shared")
        second = await seed("example-shared")
        exact = await seed("Snow")

        with capture_logs() as logs:
            metrics = _metrics(
                await _execute(
                    db_session,
                    CnaListServer([*load_list(), entry_for("example-shared")]),
                )
            )

        for row in (folded, first, second):
            assert await _stored(db_session, row) == (None, [], None)
            assert await _updated_at(db_session, row) == STALE
        assert (await _stored(db_session, exact))[0] == "Snow Software"
        assert sorted(
            _logged(logs, MATCH_AMBIGUOUS_EVENT), key=lambda entry: entry["org_id"]
        ) == [
            {
                "event": MATCH_AMBIGUOUS_EVENT,
                "log_level": "warning",
                "fetcher_name": NAME,
                "org_id": org_id,
            }
            for org_id in sorted(str(row.org_id) for row in (folded, first, second))
        ]
        assert metrics == (len(load_list()) + 1, 0, 1, 0)

    async def test_entry_without_a_row_creates_nothing(
        self, db_session: AsyncSession, seed: Seed
    ) -> None:
        await seed("example-present")
        before = await db_session.scalar(select(func.count()).select_from(CNA))

        metrics = await _sync(db_session, entry_for("example-missing"))

        assert await db_session.scalar(select(func.count()).select_from(CNA)) == before
        assert metrics == (1, 0, 0, 0)


@pytest.mark.integration
class TestFields:
    async def test_types_are_stored_trimmed_without_duplicates_in_order(
        self, db_session: AsyncSession, seed: Seed
    ) -> None:
        cna = await seed("example")

        await _sync(
            db_session,
            entry_for("example", types=[" Vendor", "CERT", "Vendor ", "Open Source"]),
        )

        assert (await _stored(db_session, cna))[1] == ["CERT", "Open Source", "Vendor"]

    async def test_empty_converted_scope_clears_the_stored_scope(
        self, db_session: AsyncSession, seed: Seed
    ) -> None:
        cna = await seed("example", scope="Old scope.")

        await _sync(db_session, entry_for("example", scope="<br/> "))

        assert (await _stored(db_session, cna))[2] is None

    @pytest.mark.parametrize(
        ("members", "field"),
        [
            pytest.param({"organization_name": None}, "organization_name", id="name"),
            pytest.param({"types": "Vendor"}, "types", id="types"),
            pytest.param({"scope": "Old <p>scope</p>"}, "scope", id="scope"),
        ],
    )
    async def test_invalid_field_keeps_its_value_and_the_others_are_written(
        self,
        db_session: AsyncSession,
        seed: Seed,
        members: dict[str, Any],
        field: str,
    ) -> None:
        cna = await seed(
            "example",
            organization_name="Old Name",
            types=["Researcher"],
            scope="Old scope.",
        )
        written: dict[str, Any] = {
            "organization_name": "New Name",
            "types": ["Vendor"],
            "scope": "New scope.",
        }

        with capture_logs() as logs:
            metrics = await _sync(
                db_session, entry_for("example", **{**written, **members})
            )

        expected = {**written, field: {"organization_name": "Old Name"}.get(field)}
        if field == "types":
            expected["types"] = ["Researcher"]
        elif field == "scope":
            expected["scope"] = "Old scope."
        assert await _stored(db_session, cna) == (
            expected["organization_name"],
            expected["types"],
            expected["scope"],
        )
        assert _logged(logs, FIELD_INVALID_EVENT) == [
            {
                "event": FIELD_INVALID_EVENT,
                "log_level": "warning",
                "fetcher_name": NAME,
                "org_id": str(cna.org_id),
                "field": field,
            }
        ]
        assert metrics == (1, 0, 1, 0)

    async def test_all_fields_invalid_writes_nothing_and_warns_per_field(
        self, db_session: AsyncSession, seed: Seed
    ) -> None:
        cna = await seed("example")
        element = {"shortName": "example"}

        with capture_logs() as logs:
            metrics = await _sync(db_session, element)

        assert await _updated_at(db_session, cna) == STALE
        assert [entry["field"] for entry in _logged(logs, FIELD_INVALID_EVENT)] == [
            "organization_name",
            "types",
            "scope",
        ]
        # A valid entry with no valid field is still a success.
        assert metrics == (1, 0, 0, 0)

    @pytest.mark.parametrize("character", INADMISSIBLE_CHARACTERS)
    @pytest.mark.parametrize(
        ("members", "field"),
        [
            pytest.param(
                lambda c: {"organization_name": f"Example{c}"},
                "organization_name",
                id="organization-name",
            ),
            pytest.param(
                lambda c: {"types": ["Vendor", f"Open{c}"]}, "types", id="type-item"
            ),
            pytest.param(lambda c: {"scope": f"Exa{c}mple"}, "scope", id="scope"),
        ],
    )
    async def test_inadmissible_character_keeps_the_stored_value(
        self,
        db_session: AsyncSession,
        seed: Seed,
        members: Callable[[str], dict[str, Any]],
        field: str,
        character: str,
    ) -> None:
        cna = await seed(
            "example", organization_name="Old Name", types=["CERT"], scope="Old."
        )

        with capture_logs() as logs:
            await _sync(db_session, entry_for("example", **members(character)))

        stored = dict(
            zip(
                ("organization_name", "types", "scope"),
                await _stored(db_session, cna),
                strict=True,
            )
        )
        assert (
            stored[field]
            == {
                "organization_name": "Old Name",
                "types": ["CERT"],
                "scope": "Old.",
            }[field]
        )
        assert [entry["field"] for entry in _logged(logs, FIELD_INVALID_EVENT)] == [
            field
        ]

    @pytest.mark.parametrize("character", INADMISSIBLE_CHARACTERS)
    async def test_short_name_with_an_inadmissible_character_is_a_failed_entry(
        self, db_session: AsyncSession, seed: Seed, character: str
    ) -> None:
        cna = await seed("example")

        metrics = await _sync(
            db_session, entry_for(f"example{character}"), entry_for("other")
        )

        assert await _stored(db_session, cna) == (None, [], None)
        assert metrics == (1, 0, 0, 1)

    async def test_never_writes_identity_short_name_or_policy(
        self, db_session: AsyncSession, seed: Seed
    ) -> None:
        cna = await seed("example", short_name_observed_at=OBSERVED, auto_ignore=True)

        await _sync(db_session, entry_for("example"))

        row = (
            await db_session.execute(
                select(
                    CNA.org_id,
                    CNA.short_name,
                    CNA.short_name_observed_at,
                    CNA.auto_ignore,
                ).where(CNA.id == cna.id)
            )
        ).one()
        assert tuple(row) == (cna.org_id, "example", OBSERVED, True)

    async def test_writes_no_cve_ticket_or_event(
        self,
        db_session: AsyncSession,
        seed: Seed,
        cve_factory: Callable[..., Awaitable[CVE]],
        ticket_factory: Callable[..., Awaitable[Ticket]],
    ) -> None:
        cna = await seed("example")
        cve = await cve_factory(cna_id=cna.id, updated_at=STALE)
        ticket = await ticket_factory(cve_id=cve.id, updated_at=STALE)
        events: list[tuple[str, str]] = []

        with SqlRecorder(db_session, events):
            await _sync(db_session, entry_for("example"))

        writes = [
            statement
            for _, statement in events
            if statement.split(None, 1)[0] in {"INSERT", "UPDATE", "DELETE"}
        ]
        assert writes
        assert all(w.startswith("UPDATE cna SET ") for w in writes)
        for write in writes:
            assignments = write.split(" SET ", 1)[1].split(" WHERE ", 1)[0]
            for column in ("org_id", "short_name", "auto_ignore"):
                assert f"{column}=" not in assignments
        assert await db_session.scalar(
            select(CVE.updated_at).where(CVE.id == cve.id)
        ) == (STALE)
        assert await db_session.scalar(
            select(Ticket.updated_at).where(Ticket.id == ticket.id)
        ) == (STALE)
        assert (
            await db_session.scalar(
                select(func.count())
                .select_from(TicketAuditEvent)
                .where(TicketAuditEvent.ticket_id == ticket.id)
            )
            == 0
        )


# ---------------------------------------------------------------------------
# Transaction boundaries and ordering
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestTransactionBoundaries:
    async def test_the_request_precedes_every_statement(
        self, db_session: AsyncSession, seed: Seed
    ) -> None:
        """No network I/O while the transaction of steps 4 to 8 is open."""
        await seed("example")
        events: list[tuple[str, str]] = []
        server = CnaListServer([entry_for("example")])
        server.on_request = lambda request: events.append(("request", str(request.url)))

        with SqlRecorder(db_session, events):
            await _execute(db_session, server)

        assert events[0] == ("request", CNA_LIST_URL)
        assert [kind for kind, _ in events].count("request") == 1
        assert len(events) > 1

    async def test_rows_are_written_in_ascending_id_order(
        self, db_session: AsyncSession, seed: Seed, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = sorted(uuid.uuid7() for _ in range(3))
        names = ("example-c", "example-a", "example-b")
        # Seed in an order that differs from both the ids and the list.
        for cna_id, name in zip(reversed(ids), names, strict=True):
            await seed(name, id=cna_id)
        calls: list[uuid.UUID] = []
        real = cna_service.update_cna_metadata

        async def recording(
            db: AsyncSession, *, cna_id: uuid.UUID, **kwargs: Any
        ) -> bool:
            calls.append(cna_id)
            return await real(db, cna_id=cna_id, **kwargs)

        monkeypatch.setattr(cna_service, "update_cna_metadata", recording)

        await _sync(db_session, *(entry_for(name) for name in sorted(names)))

        assert calls == ids

    async def test_commits_once_before_any_metric_or_warning(
        self, db_session: AsyncSession, seed: Seed, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        await seed("example")
        await seed("example-shared")
        await seed("example-shared")
        server = CnaListServer(
            [entry_for("example"), entry_for("example-shared"), "invalid"]
        )
        fetcher = _fetcher(server)
        real_commit = db_session.commit
        at_commit: list[tuple[Metrics, int]] = []

        with capture_logs() as logs:

            async def commit() -> None:
                at_commit.append((_metrics(fetcher), len(logs)))
                await real_commit()

            monkeypatch.setattr(db_session, "commit", commit)
            try:
                await fetcher.execute(db_session)
            finally:
                await fetcher._teardown_http_client()

        assert at_commit == [((0, 0, 0, 0), 0)]
        assert _metrics(fetcher) == (2, 0, 1, 1)
        assert {entry["event"] for entry in logs} == {
            ENTRIES_INVALID_EVENT,
            MATCH_AMBIGUOUS_EVENT,
        }

    async def test_failed_commit_records_no_metric(
        self, db_session: AsyncSession, seed: Seed, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        await seed("example")
        failure = OperationalError("COMMIT", {}, Exception("example failure"))

        async def commit() -> None:
            raise failure

        monkeypatch.setattr(db_session, "commit", commit)

        with capture_logs() as logs:
            raised, fetcher = await _execute_failing(
                db_session, CnaListServer([entry_for("example"), 1]), OperationalError
            )

        assert raised is failure
        assert _metrics(fetcher) == (0, 0, 0, 0)
        assert logs == []

    async def test_database_failure_propagates_unchanged(
        self, db_session: AsyncSession, seed: Seed, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        await seed("example-a")
        await seed("example-b")
        failure = OperationalError("UPDATE", {}, Exception("example failure"))
        real = cna_service.update_cna_metadata
        calls: list[uuid.UUID] = []

        async def failing_second(
            db: AsyncSession, *, cna_id: uuid.UUID, **kwargs: Any
        ) -> bool:
            calls.append(cna_id)
            if len(calls) == 2:
                raise failure
            return await real(db, cna_id=cna_id, **kwargs)

        monkeypatch.setattr(cna_service, "update_cna_metadata", failing_second)

        raised, fetcher = await _execute_failing(
            db_session,
            CnaListServer([entry_for("example-a"), entry_for("example-b")]),
            OperationalError,
        )

        assert raised is failure
        assert _metrics(fetcher) == (0, 0, 0, 0)


# ---------------------------------------------------------------------------
# Entries, metrics, and warnings (Work Unit and Metrics; Error Handling)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestEntriesAndMetrics:
    async def test_invalid_entries_fail_and_are_warned_once_with_their_count(
        self, db_session: AsyncSession, seed: Seed
    ) -> None:
        cna = await seed("example")

        with capture_logs() as logs:
            metrics = await _sync(
                db_session,
                entry_for("example"),
                "example",
                None,
                {"organizationName": "No Short Name"},
                entry_for("  "),
            )

        assert (await _stored(db_session, cna))[0] == "Example Corporation"
        assert metrics == (1, 0, 1, 4)
        assert _logged(logs, ENTRIES_INVALID_EVENT) == [
            {
                "event": ENTRIES_INVALID_EVENT,
                "log_level": "warning",
                "fetcher_name": NAME,
                "count": 4,
            }
        ]

    async def test_every_valid_entry_succeeds_whether_or_not_it_matches(
        self, db_session: AsyncSession, seed: Seed
    ) -> None:
        await seed("example-matched")
        await seed("example-shared")
        await seed("example-shared")

        metrics = await _sync(
            db_session,
            entry_for("example-matched"),
            entry_for("example-shared"),
            entry_for("example-unmatched"),
        )

        assert metrics == (3, 0, 1, 0)

    async def test_empty_array_is_an_empty_run(
        self, db_session: AsyncSession, seed: Seed
    ) -> None:
        cna = await seed("example")

        with capture_logs() as logs:
            metrics = await _sync(db_session)

        assert metrics == (0, 0, 0, 0)
        assert logs == []
        assert await _updated_at(db_session, cna) == STALE

    async def test_warnings_carry_no_value_of_the_list(
        self, db_session: AsyncSession, seed: Seed
    ) -> None:
        marker = "Example-Confidential-List-Value"
        await seed("example-shared")
        await seed("example-shared")
        await seed("example")

        with capture_logs() as logs:
            await _sync(
                db_session,
                entry_for("example-shared", organization_name=marker),
                entry_for("example", organization_name=None, scope=f"<p>{marker}</p>"),
                {"shortName": f"{marker}\x00"},
            )

        assert logs
        assert marker not in repr(logs)
        assert all(
            set(entry)
            <= {"event", "log_level", "fetcher_name", "org_id", "field", "count"}
            for entry in logs
        )


# ---------------------------------------------------------------------------
# Request and Error Handling
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestRequest:
    async def test_one_get_of_the_documented_url(
        self, db_session: AsyncSession
    ) -> None:
        server = CnaListServer([])

        await _execute(db_session, server)

        assert CNA_LIST_URL == FIXTURE_URL
        assert [(r.method, str(r.url)) for r in server.requests] == [
            ("GET", CNA_LIST_URL)
        ]
        assert "authorization" not in server.requests[0].headers

    async def test_redirect_is_not_followed(self, db_session: AsyncSession) -> None:
        server = CnaListServer()
        server.response = status(301, location="https://example.com/CNAsList.json")

        error, _ = await _execute_failing(db_session, server)

        assert str(error) == "CNA list returned HTTP 301"
        assert len(server.requests) == 1
        # The cause carries the status line and URL, not the upstream target.
        assert str(error.__cause__) == (
            f"Unexpected status '301 Moved Permanently' for url '{CNA_LIST_URL}'"
        )

    async def test_shared_client_follows_no_redirect(self) -> None:
        """The fetcher keeps the shared client's default (networking.md,
        Redirect Policy)."""
        fetcher = SyncMitreCnas()
        try:
            assert fetcher.http_client.follow_redirects is False
        finally:
            await fetcher._teardown_http_client()

    async def test_content_type_is_not_checked(
        self, db_session: AsyncSession, seed: Seed
    ) -> None:
        cna = await seed("example")
        server = CnaListServer()
        server.response = status(
            200,
            json_bytes([entry_for("example")]),
            content_type="application/octet-stream",
        )

        await _execute(db_session, server)

        assert (await _stored(db_session, cna))[0] == "Example Corporation"


_TRANSPORT_ERRORS: list[Any] = [
    pytest.param(httpx.ConnectError("example"), CONNECT_FAILED_MESSAGE, id="connect"),
    pytest.param(httpx.ReadError("example"), CONNECT_FAILED_MESSAGE, id="read"),
    pytest.param(
        httpx.RemoteProtocolError("example"), CONNECT_FAILED_MESSAGE, id="protocol"
    ),
    pytest.param(httpx.ProxyError("example"), CONNECT_FAILED_MESSAGE, id="proxy"),
    pytest.param(httpx.ConnectTimeout("example"), TIMED_OUT_MESSAGE, id="connect-to"),
    pytest.param(httpx.ReadTimeout("example"), TIMED_OUT_MESSAGE, id="read-timeout"),
    pytest.param(httpx.PoolTimeout("example"), TIMED_OUT_MESSAGE, id="pool-timeout"),
    pytest.param(httpx.DecodingError("example"), UNPARSEABLE_MESSAGE, id="decoding"),
]


@pytest.mark.integration
class TestErrorHandling:
    @pytest.mark.parametrize(("error", "message"), _TRANSPORT_ERRORS)
    async def test_transport_failure_is_a_sanitized_error_chained_from_it(
        self,
        db_session: AsyncSession,
        seed: Seed,
        error: Exception,
        message: str,
    ) -> None:
        cna = await seed("example")
        server = CnaListServer()
        server.response = raising(error)
        events: list[tuple[str, str]] = []

        with SqlRecorder(db_session, events):
            raised, fetcher = await _execute_failing(db_session, server)

        assert str(raised) == message
        assert raised.__cause__ is error
        assert events == []
        assert _metrics(fetcher) == (0, 0, 0, 0)
        assert await _stored(db_session, cna) == (None, [], None)

    @pytest.mark.parametrize(
        "code", [204, 206, 301, 302, 304, 400, 403, 404, 429, 500, 503]
    )
    async def test_status_other_than_200_fails_the_run(
        self, db_session: AsyncSession, code: int
    ) -> None:
        server = CnaListServer()
        server.response = status(code, json_bytes(load_list()))
        events: list[tuple[str, str]] = []

        with SqlRecorder(db_session, events):
            raised, _ = await _execute_failing(db_session, server)

        assert str(raised) == f"CNA list returned HTTP {code}"
        cause = raised.__cause__
        assert isinstance(cause, httpx.HTTPStatusError)
        assert cause.response.status_code == code
        assert str(code) in str(cause)
        assert CNA_LIST_URL in str(cause)
        assert "Example" not in str(cause)
        assert events == []

    @pytest.mark.parametrize(
        ("body", "cause"),
        [
            pytest.param(b"\xff\xfe[]", UnicodeDecodeError, id="not-utf8"),
            pytest.param(b"\xef\xbb\xbf[]", ValueError, id="byte-order-mark"),
            pytest.param(b"", ValueError, id="empty"),
            pytest.param(b"[{]", ValueError, id="invalid-json"),
            pytest.param(b"<html></html>", ValueError, id="html"),
            pytest.param(b"{}", CNAListStructureError, id="object-root"),
            pytest.param(b'"text"', CNAListStructureError, id="string-root"),
            pytest.param(b"null", CNAListStructureError, id="null-root"),
            pytest.param(
                f"[{OVERSIZED_INTEGER}]".encode(), ValueError, id="oversized-integer"
            ),
        ],
    )
    async def test_unparseable_body_fails_the_run(
        self, db_session: AsyncSession, body: bytes, cause: type[Exception]
    ) -> None:
        server = CnaListServer()
        server.response = raw_body(body)
        events: list[tuple[str, str]] = []

        with SqlRecorder(db_session, events):
            raised, _ = await _execute_failing(db_session, server)

        assert str(raised) == UNPARSEABLE_MESSAGE
        assert isinstance(raised.__cause__, cause)
        assert events == []

    async def test_nesting_beyond_the_parser_limit_fails_the_run(
        self, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        limit_parser_nesting(monkeypatch)
        server = CnaListServer()
        server.response = raw_body(f"[{NESTED_ARRAY}]".encode())
        events: list[tuple[str, str]] = []

        with SqlRecorder(db_session, events):
            raised, _ = await _execute_failing(db_session, server)

        assert str(raised) == UNPARSEABLE_MESSAGE
        assert isinstance(raised.__cause__, ValueError)
        assert events == []

    def test_structure_error_message_is_fixed(self) -> None:
        assert str(CNAListStructureError()) == "CNA list is not a JSON array"


# ---------------------------------------------------------------------------
# run() lifecycle: finalized FetcherRun (committed; explicit cleanup)
# ---------------------------------------------------------------------------

RunSetup = Callable[[CnaListServer, Sequence[str]], Awaitable[uuid.UUID]]


@pytest.fixture
async def committed_run(
    real_session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncIterator[RunSetup]:
    """Commit CNA rows with the given short names and a `running` FetcherRun
    under a test-only name; route `run()`.

    `run()` opens its own sessions through `base_fetcher`'s
    `async_session_factory` and creates its HTTP client through
    `create_http_client`; both are redirected here. Every committed row is
    deleted at teardown.
    """
    monkeypatch.setattr(
        base_fetcher_module, "async_session_factory", real_session_factory
    )
    fetcher_name = f"test_cnas_run_{uuid.uuid4().hex[:12]}"
    seeded: list[uuid.UUID] = []

    async def setup(server: CnaListServer, short_names: Sequence[str]) -> uuid.UUID:
        monkeypatch.setattr(
            base_fetcher_module,
            "create_http_client",
            lambda name, **options: server.client(),
        )
        async with real_session_factory() as session:
            for short_name in short_names:
                org_id = uuid.uuid4()
                seeded.append(org_id)
                session.add(CNA(org_id=org_id, short_name=short_name))
            session.add(
                FetcherConfig(
                    fetcher_name=fetcher_name,
                    enabled=True,
                    run_timeout=3600,
                    request_delay=0,
                    custom_settings={},
                )
            )
            run = FetcherRun(
                fetcher_name=fetcher_name,
                started_at=datetime.now(UTC),
                status="running",
                triggered_by="schedule",
            )
            session.add(run)
            await session.commit()
            return run.id

    try:
        yield setup
    finally:
        async with real_session_factory() as session:
            await session.execute(delete(CNA).where(CNA.org_id.in_(seeded)))
            await session.execute(
                delete(FetcherRun).where(FetcherRun.fetcher_name == fetcher_name)
            )
            await session.execute(
                delete(FetcherConfig).where(FetcherConfig.fetcher_name == fetcher_name)
            )
            await session.commit()


def _run_config() -> FetcherRunConfig:
    return FetcherRunConfig(
        hard_time_limit_seconds=3600, request_delay=0, custom_settings={}
    )


async def _finalized(
    real_session_factory: async_sessionmaker[AsyncSession], run_id: uuid.UUID
) -> FetcherRun:
    async with real_session_factory() as session:
        run = await session.get(FetcherRun, run_id)
        assert run is not None
        return run


def _run_metrics(run: FetcherRun) -> Metrics:
    return (run.items_succeeded, run.items_created, run.items_updated, run.items_failed)


async def _committed_names(
    real_session_factory: async_sessionmaker[AsyncSession], short_names: Sequence[str]
) -> dict[str, str | None]:
    async with real_session_factory() as session:
        rows = await session.execute(
            select(CNA.short_name, CNA.organization_name).where(
                CNA.short_name.in_(short_names)
            )
        )
        return {str(row[0]): row[1] for row in rows}


def _unique(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


@pytest.mark.integration
class TestRunLifecycle:
    async def test_updates_are_committed_and_the_run_succeeds(
        self,
        committed_run: RunSetup,
        real_session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        name = _unique("example")
        run_id = await committed_run(
            CnaListServer([entry_for(name), entry_for(_unique("other"))]), [name]
        )

        await SyncMitreCnas().run(run_id=run_id, config=_run_config())

        run = await _finalized(real_session_factory, run_id)
        assert run.status == "success"
        assert _run_metrics(run) == (2, 0, 1, 0)
        assert (run.error_message, run.error_detail, run.error_traceback) == (
            None,
            None,
            None,
        )
        assert await _committed_names(real_session_factory, [name]) == {
            name: "Example Corporation"
        }

    async def test_some_invalid_entries_make_the_run_partial(
        self,
        committed_run: RunSetup,
        real_session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        name = _unique("example")
        run_id = await committed_run(CnaListServer([entry_for(name), 1]), [name])

        await SyncMitreCnas().run(run_id=run_id, config=_run_config())

        run = await _finalized(real_session_factory, run_id)
        assert run.status == "partial"
        assert _run_metrics(run) == (1, 0, 1, 1)

    async def test_every_entry_invalid_fails_the_run_without_an_exception(
        self,
        committed_run: RunSetup,
        real_session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        run_id = await committed_run(CnaListServer([1, None, {}]), [])

        await SyncMitreCnas().run(run_id=run_id, config=_run_config())

        run = await _finalized(real_session_factory, run_id)
        assert run.status == "failure"
        assert run.error_message == "All 3 items failed"
        assert (run.error_detail, run.error_traceback) == (None, None)
        assert _run_metrics(run) == (0, 0, 0, 3)

    async def test_empty_array_is_a_success(
        self,
        committed_run: RunSetup,
        real_session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        run_id = await committed_run(CnaListServer([]), [])

        await SyncMitreCnas().run(run_id=run_id, config=_run_config())

        run = await _finalized(real_session_factory, run_id)
        assert run.status == "success"
        assert _run_metrics(run) == (0, 0, 0, 0)

    async def test_request_failure_is_finalized_with_the_sanitized_message(
        self,
        committed_run: RunSetup,
        real_session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        server = CnaListServer()
        server.response = status(429)
        run_id = await committed_run(server, [])

        with pytest.raises(FetcherError, match=r"^CNA list returned HTTP 429$"):
            await SyncMitreCnas().run(run_id=run_id, config=_run_config())

        run = await _finalized(real_session_factory, run_id)
        assert run.status == "failure"
        assert run.error_message == "CNA list returned HTTP 429"
        assert run.error_detail is not None
        assert "429" in run.error_detail
        assert _run_metrics(run) == (0, 0, 0, 0)

    async def test_database_failure_rolls_back_every_write(
        self,
        committed_run: RunSetup,
        real_session_factory: async_sessionmaker[AsyncSession],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        first, second = _unique("example-a"), _unique("example-b")
        run_id = await committed_run(
            CnaListServer([entry_for(first), entry_for(second)]), [first, second]
        )
        failure = OperationalError("UPDATE", {}, Exception("example failure"))
        real = cna_service.update_cna_metadata
        calls: list[uuid.UUID] = []

        async def failing_second(
            db: AsyncSession, *, cna_id: uuid.UUID, **kwargs: Any
        ) -> bool:
            calls.append(cna_id)
            if len(calls) == 2:
                raise failure
            return await real(db, cna_id=cna_id, **kwargs)

        monkeypatch.setattr(cna_service, "update_cna_metadata", failing_second)

        with pytest.raises(OperationalError):
            await SyncMitreCnas().run(run_id=run_id, config=_run_config())

        run = await _finalized(real_session_factory, run_id)
        assert run.status == "failure"
        assert run.error_message == "Unexpected error"
        assert _run_metrics(run) == (0, 0, 0, 0)
        assert len(calls) == 2
        assert await _committed_names(real_session_factory, [first, second]) == {
            first: None,
            second: None,
        }


# ---------------------------------------------------------------------------
# Registration, configuration bootstrap, and the RedBeat entry
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestRegistration:
    def test_discovery_registers_the_fetcher(self) -> None:
        assert FETCHER_REGISTRY[NAME] is SyncMitreCnas

    def test_properties_match_the_specification(self) -> None:
        assert SyncMitreCnas.name == NAME
        assert SyncMitreCnas.description == (
            "Sync CNA names, types, and scopes from the CVE Program CNA list"
        )
        assert SyncMitreCnas.default_schedule == "0 7 * * *"
        assert SyncMitreCnas.default_request_delay == 0
        assert SyncMitreCnas.participates_in_catch_up is False
        assert SyncMitreCnas.Settings is None
        assert SyncMitreCnas.queue is None
        assert SyncMitreCnas.http_client_options == {}

    def test_class_name_is_derived_from_the_fetcher_name(self) -> None:
        derived = "".join(part.capitalize() for part in NAME.split("_"))

        assert derived == SyncMitreCnas.__name__ == "SyncMitreCnas"

    def test_fetcher_does_not_participate_in_catch_up(self) -> None:
        assert NAME not in get_catch_up_fetchers()

    def test_discovery_module_imports_the_fetcher_module(self) -> None:
        source = Path(fetcher_discovery.__file__).read_text(encoding="utf-8")

        assert "import app.services.tickets.sync_mitre_cnas" in source.splitlines()


@pytest.mark.integration
class TestBootstrapAndSchedule:
    async def test_bootstrap_creates_the_configuration_from_the_class(
        self, db_session: AsyncSession
    ) -> None:
        assert await db_session.get(FetcherConfig, NAME) is None

        await bootstrap_fetcher_configs(db_session)

        config = await db_session.get(FetcherConfig, NAME)
        assert config is not None
        assert config.enabled is True
        assert config.schedule_override is None
        assert config.run_timeout == 3600
        assert config.request_delay == 0
        assert config.custom_settings == {}

    async def test_reconciliation_writes_the_daily_entry(
        self, db_session: AsyncSession, celery_test_app: Celery
    ) -> None:
        await bootstrap_fetcher_configs(db_session)

        await reconcile_beat_schedule(db_session, celery_test_app)

        key = RedBeatSchedulerEntry.generate_key(celery_test_app, NAME)
        entry = RedBeatSchedulerEntry.from_key(key, app=celery_test_app)
        assert entry.task == "run_fetcher"
        assert entry.kwargs == {"fetcher_name": NAME, "triggered_by": "schedule"}
        # 0 7 * * *
        assert entry.schedule.minute == {0}
        assert entry.schedule.hour == {7}
        assert entry.schedule.day_of_month == set(range(1, 32))
        assert entry.schedule.month_of_year == set(range(1, 13))
        assert entry.schedule.day_of_week == set(range(7))
        assert "queue" not in entry.options
