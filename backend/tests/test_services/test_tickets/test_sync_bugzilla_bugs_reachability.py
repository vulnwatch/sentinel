"""Registration, concrete compliance, structural absences, and production
reachability of the real `SyncBugzillaBugs` class
(backend/app/services/tickets/sync_bugzilla_bugs.py): fetcher discovery,
both registries, the on-demand `fetch_single_cve` workflow, the default
catch-up through `run_catch_up`, the explicit refetch preparation, the
bootstrapped `FetcherConfig`, and the RedBeat schedule entry.

Owning specifications:

- docs/features/tickets/cve-sync-bugzilla.md (Fetcher Definition; Class
  Structure; `fetch_single(cve_id)`; Error Handling, the `fetch_single()`
  table and Sanitized error messages; Custom Settings; Security and
  Privacy).
- docs/features/platform/cve-fetcher-infrastructure.md (Class Attributes;
  `__init_subclass__` Validation; Non-Modification Statement; `fetch_single`
  Signaling Convention; Retry Policy for `fetch_single`; Error
  Categorization; CVE Source Type Identity, both registry accessors; Default
  catch_up Implementation).
- docs/features/tickets/cve-service.md (On-Demand Fetch: fetch_single_cve;
  Fetch Orchestration: `trigger_on_demand_fetch()`, Transactional
  Preparation) and docs/features/tickets/cve-tracking.md (the refetch
  endpoint's `source`).
- docs/features/platform/fetcher-infrastructure.md (Naming Convention, Class
  Name Derivation; Per-Ticket Catch-Up, Fetcher inventory and Registry
  accessor `get_catch_up_fetchers()`; Fetcher Discovery, Domain Placement;
  Data Model, FetcherConfig bootstrap; Celery Beat Schedule
  Synchronization, Redbeat Entry Structure and Time Limits).
- docs/features/platform/testing-strategy.md (CVE Fetcher Infrastructure,
  Discovery completeness, Default catch-up, and Concrete compliance,
  "Bugzilla inline paths construct the token"; On-Demand CVE Refetch).

The workflows run against real PostgreSQL with the harnesses of
`tests/support/fetch_single_cve.py` and `tests/support/cve_catch_up.py`
(recording session factories over `real_session_factory`, a recorded
`task_publication.publish_task`, and the real convergence drain). The
production class is resolved from the registries filled by fetcher
discovery; no test-only fetcher is defined, so no registry isolation is
needed. Every HTTP client the fetcher creates is the in-process
`BugzillaServer`. The committed `FetcherConfig` rows, CVEs, Tickets, and
their children are deleted at teardown. Bootstrap and reconciliation run on
`db_session`, rolled back at teardown, and the worker Redis database. All
identifiers are fictional.

The generic task terminal matrix is owned by
`test_fetch_single_cve_workflow.py` and `test_cve_fetcher_catch_up.py`, and
Bugzilla exception classification by `test_sync_bugzilla_bugs.py`; the
cases here prove that each row of the Bugzilla `fetch_single()` error table
reaches its documented latest status and retry decision through the real
wrappers.
"""

from __future__ import annotations

import ast
import enum
import inspect
import textwrap
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from types import ModuleType
from typing import Any, Final

import httpx
import pytest
import redis.asyncio as redis_asyncio
from celery import Celery
from celery.app.task import Task
from pydantic import ValidationError
from redbeat import RedBeatSchedulerEntry
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from structlog.testing import capture_logs

import app.services.base_fetcher as base_fetcher_module
import app.services.fetcher_discovery as fetcher_discovery
from app.core.enums import CVESourceFetchStatus, CVESourceType, Scope
from app.core.errors import ErrorCode
from app.models.cve import CVE
from app.models.fetcher_config import FetcherConfig
from app.models.ticket import Ticket
from app.models.ticket_reference import TicketReference
from app.services import cve_service, task_publication
from app.services.base_cve_fetcher import (
    _CVE_SOURCE_TYPE_MAP,
    BaseCVEFetcher,
    CVEFetchResult,
    get_all_cve_source_types,
    get_fetch_single_fetchers,
)
from app.services.base_fetcher import (
    FETCHER_REGISTRY,
    BaseFetcher,
    FetcherError,
    get_catch_up_fetchers,
)
from app.services.cve_service import FetchSingleRetry
from app.services.fetcher_bootstrap import bootstrap_fetcher_configs
from app.services.fetcher_schedule import reconcile_beat_schedule
from app.services.http_client import is_infrastructure_failure, is_retryable_condition
from app.services.json_decoding import JSONNestingError
from app.services.ticket_visibility import TicketCaller
from app.services.tickets import bugzilla_bug_record
from app.services.tickets import sync_bugzilla_bugs as sync_module
from app.services.tickets.bugzilla_bug_record import PageOrderError
from app.services.tickets.sync_bugzilla_bugs import (
    BugzillaResponseError,
    SyncBugzillaBugs,
)
from app.tasks import fetchers
from tests.support.bugzilla import (
    ERROR_400_FIXTURE,
    BugzillaServer,
    Responder,
    bug,
    bug_reference_url,
    html,
    load_raw_fixture,
    raising,
    status,
    undecodable,
)
from tests.support.bugzilla import body as json_body
from tests.support.cve_catch_up import (
    CatchUpHarness,
    Publications,
    delete_fetcher_rows,
    fetcher_run_count,
    install_harness,
    seed_fetcher_config,
    source_state,
)
from tests.support.cve_ingest import IngestionWorld
from tests.support.fetch_single_cve import (
    COMPLETED,
    FAILED,
    RETRY_SCHEDULED,
    FetchSingleHarness,
    ScriptedRedis,
    events_named,
    install_fetch_single_harness,
)
from tests.support.json_decoding import (
    NESTED_ARRAY,
    OVERSIZED_INTEGER,
    limit_parser_nesting,
)

SessionFactory = Callable[[], Awaitable[AsyncSession]]

NAME: Final = "sync_bugzilla_bugs"
BUGZILLA: Final = CVESourceType.BUGZILLA
SCHEDULE: Final = "0 * * * *"
LAST_ATTEMPT: Final = 3
"""The zero-based attempt index after which no retry remains (3 retries)."""
ALL_SCOPE: Final = TicketCaller.authenticated(uuid.uuid4(), Scope.ALL)
"""A caller that sees every CVE, so accessibility never decides a read."""
BUG_ID: Final = 1290001


def _class_body_assignments(cls: type) -> set[str]:
    """The names assigned in `cls`'s own class body (static, from source)."""
    tree = ast.parse(textwrap.dedent(inspect.getsource(cls)))
    [class_def] = tree.body
    assert isinstance(class_def, ast.ClassDef)
    names: set[str] = set()
    for node in class_def.body:
        if isinstance(node, ast.Assign):
            names.update(t.id for t in node.targets if isinstance(t, ast.Name))
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names.add(node.target.id)
        elif isinstance(node, ast.ClassDef):
            names.add(node.name)
    return names


def _method_names(cls: type) -> set[str]:
    return {
        name
        for name, value in vars(cls).items()
        if inspect.isfunction(value) or inspect.iscoroutinefunction(value)
    }


def _referenced_names(source: str) -> set[str]:
    """Every identifier and attribute name the source references."""
    tree = ast.parse(textwrap.dedent(source))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.Attribute):
            names.add(node.attr)
        elif isinstance(node, ast.alias):
            names.add(node.name)
    return names


def _imported_modules(module: ModuleType) -> set[str]:
    tree = ast.parse(inspect.getsource(module))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            imported.add(node.module)
    return imported


# ---------------------------------------------------------------------------
# Discovery, registration, and capability
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestRegistrationAndCapability:
    def test_discovery_imports_the_module(self) -> None:
        assert sync_module.__name__ in _imported_modules(fetcher_discovery)
        assert SyncBugzillaBugs.__module__ == "app.services.tickets.sync_bugzilla_bugs"

    def test_properties_match_the_specification(self) -> None:
        assert SyncBugzillaBugs.name == NAME
        assert SyncBugzillaBugs.cve_source_type is BUGZILLA
        assert SyncBugzillaBugs.cve_source_type.value == "bugzilla"
        assert SyncBugzillaBugs.description == "Link CVEs to their SUSE Bugzilla bugs"
        assert SyncBugzillaBugs.default_schedule == SCHEDULE
        assert SyncBugzillaBugs.default_request_delay == 1.0
        assert SyncBugzillaBugs.source_reference_url_pattern is None

    def test_class_body_declares_exactly_the_class_structure_attributes(
        self,
    ) -> None:
        """No `Settings`, `queue`, `http_client_options`,
        `supports_fetch_single`, or `participates_in_catch_up` in the class
        body (cve-sync-bugzilla.md, Class Structure; Custom settings: No)."""
        assert _class_body_assignments(SyncBugzillaBugs) == {
            "name",
            "cve_source_type",
            "description",
            "default_schedule",
            "default_request_delay",
            "source_reference_url_pattern",
        }

    def test_inherited_defaults_apply(self) -> None:
        assert SyncBugzillaBugs.Settings is None
        assert SyncBugzillaBugs.queue is None
        assert SyncBugzillaBugs.http_client_options == {}
        assert SyncBugzillaBugs.http_client_options is BaseFetcher.http_client_options
        for inherited in ("Settings", "queue", "http_client_options"):
            assert inherited not in SyncBugzillaBugs.__dict__, inherited

    def test_capability_flags_are_inherited_and_derived(self) -> None:
        assert SyncBugzillaBugs.supports_fetch_single is True
        assert SyncBugzillaBugs.participates_in_catch_up is True
        assert "supports_fetch_single" not in SyncBugzillaBugs.__dict__
        assert "abstract" not in SyncBugzillaBugs.__dict__

    def test_class_name_is_derived_from_the_fetcher_name(self) -> None:
        derived = "".join(part.capitalize() for part in NAME.split("_"))

        assert derived == SyncBugzillaBugs.__name__ == "SyncBugzillaBugs"

    def test_registered_in_both_registries(self) -> None:
        assert FETCHER_REGISTRY[NAME] is SyncBugzillaBugs
        assert _CVE_SOURCE_TYPE_MAP[BUGZILLA] is SyncBugzillaBugs
        assert get_all_cve_source_types()["bugzilla"] is SyncBugzillaBugs

    def test_member_of_both_rosters(self) -> None:
        assert get_fetch_single_fetchers()["bugzilla"] is SyncBugzillaBugs
        assert get_catch_up_fetchers()[NAME] is SyncBugzillaBugs

    def test_no_base_cve_fetcher_member_is_added(self) -> None:
        for name in (
            "_collect_window",
            "_get_page",
            "_process_cve",
            "_cve_exists",
            "_ingest",
            "_cve_failed",
        ):
            assert not hasattr(BaseCVEFetcher, name), name


# ---------------------------------------------------------------------------
# Concrete compliance (testing-strategy.md, CVE Fetcher Infrastructure)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestConcreteCompliance:
    def test_only_fetch_single_and_execute_override_the_base_contract(self) -> None:
        own = _method_names(SyncBugzillaBugs)
        inherited_contract = _method_names(BaseCVEFetcher) | _method_names(BaseFetcher)

        assert own & inherited_contract == {"fetch_single", "execute"}
        assert SyncBugzillaBugs.catch_up is BaseCVEFetcher.catch_up
        assert (
            SyncBugzillaBugs.commit_and_dispatch is BaseCVEFetcher.commit_and_dispatch
        )
        assert (
            SyncBugzillaBugs._isolated_status_commit
            is BaseCVEFetcher._isolated_status_commit
        )
        assert SyncBugzillaBugs.run is BaseFetcher.run

    def test_typed_fetch_single_and_async_execute(self) -> None:
        assert inspect.iscoroutinefunction(SyncBugzillaBugs.fetch_single)
        assert inspect.iscoroutinefunction(SyncBugzillaBugs.execute)
        annotations = inspect.get_annotations(
            SyncBugzillaBugs.fetch_single, eval_str=True
        )
        assert annotations["return"] is CVEFetchResult
        assert (
            inspect.get_annotations(SyncBugzillaBugs._ingest, eval_str=True)["return"]
            is CVEFetchResult
        )

    def test_inline_periodic_path_constructs_the_token(self) -> None:
        """The periodic path processes the collected window inline: it never
        delegates to `fetch_single()`, builds `CVEFetchResult` itself, and
        finalizes through the inherited `commit_and_dispatch()`."""
        periodic = "\n".join(
            inspect.getsource(method)
            for method in (
                SyncBugzillaBugs.execute,
                SyncBugzillaBugs._collect_window,
                SyncBugzillaBugs._get_page,
                SyncBugzillaBugs._process_cve,
                SyncBugzillaBugs._ingest,
                SyncBugzillaBugs._cve_failed,
            )
        )
        names = _referenced_names(periodic)

        assert "fetch_single" not in names
        assert {
            "CVEFetchResult",
            "commit_and_dispatch",
            "record_failed",
            "_isolated_status_commit",
        } <= names
        assert "record_succeeded" not in names
        assert "record_created" not in names
        assert "record_updated" not in names
        assert "get_active_ticket_cve_ids" not in names

    def test_sanitized_messages_match_the_specification(self) -> None:
        assert sync_module.CONNECTION_FAILED == "Failed to connect to SUSE Bugzilla"
        assert sync_module.UNPARSEABLE_RESPONSE == (
            "SUSE Bugzilla returned unparseable response"
        )
        assert sync_module.BUGZILLA_CURSOR_RESET_EVENT == "bugzilla_cursor_reset"
        assert sync_module.BUGZILLA_BUG_URL == "https://bugzilla.suse.com/rest/bug"
        assert sync_module.INCLUDE_FIELDS == "id,alias,summary,groups"
        assert sync_module.PAGE_SIZE == 1000


@pytest.mark.unit
class TestSignalClasses:
    def test_response_error_is_non_retryable_with_a_fixed_message(self) -> None:
        error = BugzillaResponseError()

        assert BugzillaResponseError.__bases__ == (Exception,)
        assert not issubclass(BugzillaResponseError, FetcherError)
        assert str(error) == "SUSE Bugzilla returned an unexpected response"
        assert is_retryable_condition(error) is False
        assert is_infrastructure_failure(error) is False

    def test_page_order_error_is_a_module_local_value_error(self) -> None:
        error = PageOrderError()

        assert PageOrderError.__module__ == bugzilla_bug_record.__name__
        assert issubclass(PageOrderError, ValueError)
        assert str(error) == "Bug IDs of the page are not strictly ascending"
        assert is_retryable_condition(error) is False


# ---------------------------------------------------------------------------
# Structural absences
# ---------------------------------------------------------------------------


_BUGZILLA_MODULES: Final = [sync_module, bugzilla_bug_record]


@pytest.mark.unit
class TestStructuralAbsences:
    @pytest.mark.parametrize(
        "module", _BUGZILLA_MODULES, ids=lambda module: module.__name__
    )
    def test_defines_no_task_model_or_enum(self, module: ModuleType) -> None:
        own = [
            value
            for value in vars(module).values()
            if getattr(value, "__module__", None) == module.__name__
        ]

        assert not [value for value in vars(module).values() if isinstance(value, Task)]
        assert not [
            value
            for value in own
            if isinstance(value, type)
            and issubclass(value, (DeclarativeBase, enum.Enum))
        ]

    @pytest.mark.parametrize(
        "module", _BUGZILLA_MODULES, ids=lambda module: module.__name__
    )
    def test_touches_no_configuration_redis_task_or_api_layer(
        self, module: ModuleType
    ) -> None:
        """Anonymous requests: no setting, credential, or token is read."""
        imported = _imported_modules(module)

        forbidden = {
            name
            for name in imported
            if name in {"app.config", "app.celery_app"}
            or name.split(".")[0] == "redis"
            or name.startswith(("app.tasks", "app.api", "app.schemas"))
        }
        assert forbidden == set()

    def test_record_module_performs_no_http_database_or_logging_work(self) -> None:
        imported = _imported_modules(bugzilla_bug_record)

        assert not {
            name
            for name in imported
            if name.split(".")[0] in {"httpx", "sqlalchemy", "structlog", "logging"}
            or name.startswith(("app.models", "app.database"))
        }

    @pytest.mark.parametrize(
        "module", _BUGZILLA_MODULES, ids=lambda module: module.__name__
    )
    def test_raises_no_api_facing_error(self, module: ModuleType) -> None:
        names = _referenced_names(inspect.getsource(module))

        assert not {"ErrorCode", "ServiceError", "HTTPException"} & names
        assert not [name for name in names if name.endswith("ServiceError")]

    def test_no_route_task_or_error_code_names_the_source(self) -> None:
        """The fetcher adds none. The only Bugzilla route and error code
        belong to the needinfo count
        (docs/features/integrations/bugzilla-needinfo-count.md), which the
        fetcher modules never reference, and the fetcher never reads
        `BUGZILLA_API_KEY` (cve-sync-bugzilla.md, Security and Privacy).
        Routes are discovered with
        `iter_route_contexts()` (see `tests/test_api_conventions.py`)."""
        from fastapi import routing as fastapi_routing

        from app.celery_app import celery_app
        from app.main import app as api

        paths = [
            context.path
            for context in fastapi_routing.iter_route_contexts(api.routes)
            if context.path is not None
        ]
        assert paths
        assert [path for path in paths if "bugzilla" in path.lower()] == [
            "/api/v1/bugzilla/needinfo-count"
        ]
        assert not [name for name in celery_app.tasks if "bugzilla" in name.lower()]
        assert [member for member in ErrorCode if "BUGZILLA" in member.name] == [
            ErrorCode.BUGZILLA_UNAVAILABLE
        ]
        for module in _BUGZILLA_MODULES:
            source = inspect.getsource(module)
            assert "bugzilla_needinfo" not in source
            assert "bugzilla_api_key" not in source


# ---------------------------------------------------------------------------
# Shared harness of the wrapper tests
# ---------------------------------------------------------------------------


@pytest.fixture
async def world(db_session_factory: SessionFactory) -> AsyncIterator[IngestionWorld]:
    created = IngestionWorld(db_session_factory, await db_session_factory())
    try:
        await created.ensure_default_setting()
        yield created
    finally:
        await created.cleanup()


class ClientServer(BugzillaServer):
    """A `BugzillaServer` recording every client it creates."""

    def __init__(self) -> None:
        super().__init__()
        self.clients: list[httpx.AsyncClient] = []

    def client(self) -> httpx.AsyncClient:
        created = super().client()
        self.clients.append(created)
        return created


@pytest.fixture
def server(monkeypatch: pytest.MonkeyPatch) -> ClientServer:
    """Every lazily created fetcher HTTP client serves this fake."""
    fake = ClientServer()

    def create_http_client(name: str, **options: Any) -> httpx.AsyncClient:
        assert name == NAME
        assert options == {}
        return fake.client()

    monkeypatch.setattr(base_fetcher_module, "create_http_client", create_http_client)
    return fake


async def _active_cve(world: IngestionWorld) -> tuple[CVE, Ticket]:
    cve = await world.cve_in()
    ticket = await world.ticket(cve_id=cve.id)
    return cve, ticket


def _serve(server: BugzillaServer, cve: CVE) -> None:
    server.singles[cve.cve_id] = [bug(BUG_ID, cve.cve_id, summary="Bug")]


async def _references(
    factory: async_sessionmaker[AsyncSession], cve: CVE
) -> list[tuple[str, str | None, str | None]]:
    async with factory() as session:
        rows = await session.execute(
            select(TicketReference.url, TicketReference.title, TicketReference.type)
            .join(Ticket, TicketReference.ticket_id == Ticket.id)
            .where(Ticket.cve_id == cve.id)
        )
    return sorted((url, title, kind) for url, title, kind in rows)


def _respond(server: BugzillaServer, cve: CVE, kind: str) -> None:
    """Serve one documented `fetch_single()` error-table condition."""
    responders: dict[str, Responder] = {
        "http_400": status(400, load_raw_fixture(ERROR_400_FIXTURE)),
        "http_403": status(403),
        "http_404": status(404),
        "http_302": status(302, headers={"Location": "https://bugzilla.suse.com/"}),
        "http_204": status(204),
        "invalid_json": status(200, b"{"),
        "html": html(),
        "nesting_beyond_the_parser_limit": status(
            200, ('{"bugs": [' + NESTED_ARRAY + "]}").encode()
        ),
        "integer_beyond_the_conversion_limit": status(
            200, b'{"bugs": [' + OVERSIZED_INTEGER.encode() + b"]}"
        ),
        "undecodable": undecodable(200),
        "schema_mismatch": json_body({"bugs": [{"id": True}]}),
    }
    server.single_responses[cve.cve_id] = responders[kind]


_NON_RETRYABLE: Final[list[tuple[str, type[BaseException], str]]] = [
    ("http_400", httpx.HTTPStatusError, "HTTPStatusError"),
    ("http_403", httpx.HTTPStatusError, "HTTPStatusError"),
    ("http_404", httpx.HTTPStatusError, "HTTPStatusError"),
    ("http_302", httpx.HTTPStatusError, "HTTPStatusError"),
    ("http_204", BugzillaResponseError, "BugzillaResponseError"),
    ("invalid_json", ValueError, "JSONDecodeError"),
    ("html", ValueError, "JSONDecodeError"),
    ("nesting_beyond_the_parser_limit", JSONNestingError, "JSONNestingError"),
    ("integer_beyond_the_conversion_limit", ValueError, "ValueError"),
    ("undecodable", httpx.DecodingError, "DecodingError"),
    ("schema_mismatch", ValidationError, "ValidationError"),
]


def _retryable(kind: str) -> Responder:
    if kind == "connect":
        return raising(httpx.ConnectError("[Errno 111] Connection refused"))
    if kind == "timeout":
        return raising(httpx.ReadTimeout("timed out"))
    return status(int(kind.removeprefix("http_")))


# ---------------------------------------------------------------------------
# On-demand fetch_single_cve
# ---------------------------------------------------------------------------


@pytest.fixture
async def on_demand(
    real_session_factory: async_sessionmaker[AsyncSession],
    redis_client: redis_asyncio.Redis,
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncIterator[FetchSingleHarness]:
    harness = install_fetch_single_harness(
        monkeypatch, real_session_factory, redis_client
    )
    try:
        await seed_fetcher_config(real_session_factory, NAME, enabled=True)
        harness.names.append(NAME)
        yield harness
    finally:
        await harness.cleanup()


@pytest.mark.integration
class TestOnDemandFetch:
    async def test_success_links_the_bug_without_a_package_handoff(
        self,
        world: IngestionWorld,
        on_demand: FetchSingleHarness,
        server: ClientServer,
    ) -> None:
        cve, _ = await _active_cve(world)
        _serve(server, cve)
        token = await on_demand.marker(cve.cve_id, BUGZILLA.value)

        with capture_logs() as logs:
            outcome = await on_demand.run(NAME, cve.cve_id, BUGZILLA.value, token)

        assert outcome is None
        [request] = server.requests
        assert request.url.params["alias"] == cve.cve_id
        state = await source_state(on_demand.factory, cve.id, BUGZILLA)
        assert state is not None
        assert state.status == CVESourceFetchStatus.SUCCESS
        assert await _references(on_demand.factory, cve) == [
            (bug_reference_url(BUG_ID), "Bug", "issue")
        ]
        assert on_demand.published.calls == []
        assert await on_demand.marker_value(cve.cve_id, BUGZILLA.value) is None
        assert await fetcher_run_count(on_demand.factory, NAME) == 0
        assert events_named(logs, COMPLETED) == [
            {
                "event": COMPLETED,
                "log_level": "info",
                "outcome": "unchanged",
                "fetcher_name": NAME,
                "cve_id": cve.cve_id,
                "source": BUGZILLA.value,
            }
        ]
        assert "Bug" not in repr([entry for entry in logs if entry is not None])
        assert server.clients
        assert all(client.is_closed for client in server.clients)

    @pytest.mark.parametrize("answer", ["empty", "restricted", "lowercase"])
    async def test_no_public_bug_with_the_alias_is_missing(
        self,
        answer: str,
        world: IngestionWorld,
        on_demand: FetchSingleHarness,
        server: ClientServer,
    ) -> None:
        cve, _ = await _active_cve(world)
        if answer == "restricted":
            server.singles[cve.cve_id] = [bug(BUG_ID, cve.cve_id, groups=["x"])]
        elif answer == "lowercase":
            server.singles[cve.cve_id] = [bug(BUG_ID, cve.cve_id.lower())]
        token = await on_demand.marker(cve.cve_id, BUGZILLA.value)

        with capture_logs() as logs:
            outcome = await on_demand.run(NAME, cve.cve_id, BUGZILLA.value, token)

        assert outcome is None
        state = await source_state(on_demand.factory, cve.id, BUGZILLA)
        assert state is not None
        assert state.status == CVESourceFetchStatus.MISSING
        assert await _references(on_demand.factory, cve) == []
        assert [entry["outcome"] for entry in events_named(logs, COMPLETED)] == [
            "missing"
        ]
        assert all(client.is_closed for client in server.clients)

    @pytest.mark.parametrize(
        ("kind", "error", "cause"),
        _NON_RETRYABLE,
        ids=[kind for kind, _, _ in _NON_RETRYABLE],
    )
    async def test_non_retryable_condition_is_an_immediate_failure(
        self,
        kind: str,
        error: type[BaseException],
        cause: str,
        world: IngestionWorld,
        on_demand: FetchSingleHarness,
        server: ClientServer,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # The limited parser rejects only the nesting case (External JSON
        # Decoding).
        limit_parser_nesting(monkeypatch)
        cve, _ = await _active_cve(world)
        _respond(server, cve, kind)
        token = await on_demand.marker(cve.cve_id, BUGZILLA.value)

        with capture_logs() as logs, pytest.raises(error):
            await on_demand.run(NAME, cve.cve_id, BUGZILLA.value, token)

        assert len(server.requests) == 1
        state = await source_state(on_demand.factory, cve.id, BUGZILLA)
        assert state is not None
        assert state.status == CVESourceFetchStatus.FAILURE
        assert await _references(on_demand.factory, cve) == []
        assert await on_demand.marker_value(cve.cve_id, BUGZILLA.value) is None
        assert events_named(logs, RETRY_SCHEDULED) == []
        [failed] = events_named(logs, FAILED)
        assert failed["cause"] == cause
        assert failed["retries"] == 0
        assert all(client.is_closed for client in server.clients)

    @pytest.mark.parametrize(
        "kind", ["http_429", "http_500", "http_503", "connect", "timeout"]
    )
    async def test_retryable_condition_schedules_a_retry_without_status(
        self,
        kind: str,
        world: IngestionWorld,
        on_demand: FetchSingleHarness,
        server: ClientServer,
    ) -> None:
        cve, _ = await _active_cve(world)
        server.single_responses[cve.cve_id] = _retryable(kind)
        token = await on_demand.marker(cve.cve_id, BUGZILLA.value)

        with capture_logs() as logs:
            outcome = await on_demand.run(NAME, cve.cve_id, BUGZILLA.value, token)

        assert isinstance(outcome, FetchSingleRetry)
        assert outcome.countdown == 5
        assert is_retryable_condition(outcome.cause)
        assert await source_state(on_demand.factory, cve.id, BUGZILLA) is None
        assert await on_demand.marker_value(cve.cve_id, BUGZILLA.value) == token
        assert len(events_named(logs, RETRY_SCHEDULED)) == 1
        assert all(client.is_closed for client in server.clients)

    async def test_retryable_failure_after_the_last_retry_is_failure(
        self,
        world: IngestionWorld,
        on_demand: FetchSingleHarness,
        server: ClientServer,
    ) -> None:
        cve, _ = await _active_cve(world)
        server.single_responses[cve.cve_id] = status(500)
        token = await on_demand.marker(cve.cve_id, BUGZILLA.value)

        with capture_logs() as logs, pytest.raises(httpx.HTTPStatusError):
            await on_demand.run(
                NAME, cve.cve_id, BUGZILLA.value, token, attempt=LAST_ATTEMPT
            )

        state = await source_state(on_demand.factory, cve.id, BUGZILLA)
        assert state is not None
        assert state.status == CVESourceFetchStatus.FAILURE
        assert events_named(logs, RETRY_SCHEDULED) == []
        assert [entry["stage"] for entry in events_named(logs, FAILED)] == [
            "pre_finalization"
        ]


# ---------------------------------------------------------------------------
# Catch-up through the inherited default
# ---------------------------------------------------------------------------


@pytest.fixture
async def catch_up(
    real_session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncIterator[CatchUpHarness]:
    harness = install_harness(monkeypatch, real_session_factory)
    try:
        await seed_fetcher_config(real_session_factory, NAME, enabled=True)
        harness.names.append(NAME)
        yield harness
    finally:
        await harness.cleanup()


@pytest.mark.integration
class TestCatchUp:
    async def test_run_catch_up_uses_the_inherited_default(
        self,
        world: IngestionWorld,
        catch_up: CatchUpHarness,
        server: ClientServer,
    ) -> None:
        cve, _ticket = await _active_cve(world)
        _serve(server, cve)

        await fetchers.run_catch_up_async(NAME, str(_ticket.id))

        assert [request.url.params["alias"] for request in server.requests] == [
            cve.cve_id
        ]
        # The catch-up flushes, then the finalizer commits once and only
        # then drains.
        events = catch_up.events
        commit = events.index("commit")
        assert events.count("commit") == 1
        assert events[commit - 1] == "flush"
        assert commit < events.index("drain")
        state = await source_state(catch_up.factory, cve.id, BUGZILLA)
        assert state is not None
        assert state.status == CVESourceFetchStatus.SUCCESS
        assert await _references(catch_up.factory, cve) == [
            (bug_reference_url(BUG_ID), "Bug", "issue")
        ]
        assert catch_up.published.calls == []
        assert await fetcher_run_count(catch_up.factory, NAME) == 0
        catch_up.engine.dispose.assert_awaited_once()
        assert all(client.is_closed for client in server.clients)

    async def test_empty_answer_writes_missing_and_returns(
        self,
        world: IngestionWorld,
        catch_up: CatchUpHarness,
        server: ClientServer,
    ) -> None:
        cve, ticket = await _active_cve(world)

        await fetchers.run_catch_up_async(NAME, str(ticket.id))

        state = await source_state(catch_up.factory, cve.id, BUGZILLA)
        assert state is not None
        assert state.status == CVESourceFetchStatus.MISSING
        assert "commit" not in catch_up.events
        assert "status:commit" in catch_up.events
        assert len(server.requests) == 1
        catch_up.engine.dispose.assert_awaited_once()

    async def test_retryable_failure_on_every_attempt_writes_failure(
        self,
        world: IngestionWorld,
        catch_up: CatchUpHarness,
        server: ClientServer,
    ) -> None:
        cve, ticket = await _active_cve(world)
        server.single_responses[cve.cve_id] = status(503)

        for _ in range(LAST_ATTEMPT + 1):
            with pytest.raises(httpx.HTTPStatusError) as raised:
                await fetchers.run_catch_up_async(NAME, str(ticket.id))
            assert is_retryable_condition(raised.value)
            state = await source_state(catch_up.factory, cve.id, BUGZILLA)
            assert state is not None
            assert state.status == CVESourceFetchStatus.FAILURE

        assert len(server.requests) == LAST_ATTEMPT + 1
        assert "commit" not in catch_up.events
        assert catch_up.events.count("status:commit") == LAST_ATTEMPT + 1
        assert catch_up.engine.dispose.await_count == LAST_ATTEMPT + 1
        assert all(client.is_closed for client in server.clients)

    @pytest.mark.parametrize("kind", ["http_404", "schema_mismatch", "html"])
    async def test_non_retryable_failure_writes_failure(
        self,
        kind: str,
        world: IngestionWorld,
        catch_up: CatchUpHarness,
        server: ClientServer,
    ) -> None:
        cve, ticket = await _active_cve(world)
        _respond(server, cve, kind)

        with pytest.raises((httpx.HTTPStatusError, ValueError)) as raised:
            await fetchers.run_catch_up_async(NAME, str(ticket.id))

        assert not is_retryable_condition(raised.value)
        state = await source_state(catch_up.factory, cve.id, BUGZILLA)
        assert state is not None
        assert state.status == CVESourceFetchStatus.FAILURE
        assert await _references(catch_up.factory, cve) == []
        assert "commit" not in catch_up.events
        assert len(server.requests) == 1


# ---------------------------------------------------------------------------
# Refetch preparation (cve-tracking.md, the refetch endpoint's `source`)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestRefetch:
    async def test_explicit_source_and_broadcast_publish_the_fetcher(
        self,
        world: IngestionWorld,
        real_session_factory: async_sessionmaker[AsyncSession],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        registry = get_fetch_single_fetchers()
        assert registry["bugzilla"] is SyncBugzillaBugs
        names = [fetcher_cls.name for fetcher_cls in registry.values()]
        async with real_session_factory() as session:
            assert not await session.scalar(
                select(func.count())
                .select_from(FetcherConfig)
                .where(FetcherConfig.fetcher_name.in_(names))
            )
        published = Publications()
        monkeypatch.setattr(task_publication, "publish_task", published)
        redis = ScriptedRedis()
        redis.install(monkeypatch)
        cve, _ = await _active_cve(world)
        try:
            for fetcher_cls in registry.values():
                await seed_fetcher_config(
                    real_session_factory, fetcher_cls.name, enabled=True
                )

            explicit = await cve_service.refetch_cve(
                cve_id=cve.cve_id,
                source="bugzilla",
                caller=ALL_SCOPE,
                session_factory=real_session_factory,
            )
            broadcast_calls = len(published.calls)
            broadcast = await cve_service.refetch_cve(
                cve_id=cve.cve_id,
                source=None,
                caller=ALL_SCOPE,
                session_factory=real_session_factory,
            )
        finally:
            await delete_fetcher_rows(real_session_factory, names)

        assert explicit.sources_enqueued == ["bugzilla"]
        [call] = published.calls[:broadcast_calls]
        assert call["kwargs"]["fetcher_name"] == NAME
        assert call["kwargs"]["source"] == "bugzilla"
        # The general worker: the fetcher declares no queue.
        assert call.get("queue") is None
        # The broadcast freshness refresh includes the source.
        assert broadcast.sources_enqueued == sorted(registry)
        assert NAME in [
            call["kwargs"]["fetcher_name"] for call in published.calls[broadcast_calls:]
        ]


# ---------------------------------------------------------------------------
# Configuration bootstrap and the RedBeat entry
# ---------------------------------------------------------------------------


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
        assert config.request_delay == SyncBugzillaBugs.default_request_delay == 1.0
        assert config.run_timeout == 3600
        assert config.custom_settings == {}

    async def test_reconciliation_writes_the_hourly_entry_from_the_class(
        self, db_session: AsyncSession, celery_test_app: Celery
    ) -> None:
        await bootstrap_fetcher_configs(db_session)

        await reconcile_beat_schedule(db_session, celery_test_app)

        key = RedBeatSchedulerEntry.generate_key(celery_test_app, NAME)
        entry = RedBeatSchedulerEntry.from_key(key, app=celery_test_app)
        assert entry.task == "run_fetcher"
        assert entry.kwargs == {"fetcher_name": NAME, "triggered_by": "schedule"}
        # 0 * * * *
        assert entry.schedule.minute == {0}
        assert entry.schedule.hour == set(range(24))
        assert entry.schedule.day_of_month == set(range(1, 32))
        assert entry.schedule.month_of_year == set(range(1, 13))
        assert entry.schedule.day_of_week == set(range(7))
        assert "queue" not in entry.options
        assert entry.options["time_limit"] == 3600
        assert entry.options["soft_time_limit"] == 3420
