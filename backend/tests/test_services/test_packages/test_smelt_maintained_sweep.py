"""Tests for the validated retrieval of the SMELT maintained sweep names.

Contract under test: docs/features/packages/maintained-package-names.md
(Fetcher: `sync_smelt_packages`, Algorithm steps 1 to 5; Error Handling;
Test Requirements, Fetcher), docs/features/packages/product-catalog.md
(SMELT Integration, Origin, Authentication, and Pagination: anonymous
requests, no redirect following), docs/features/platform/fetcher-infrastructure.md
(Request Delay; Error Message Sanitization), and docs/conventions.md
(External String Admissibility; External JSON Decoding).

Every test serves a fictional sweep through `httpx.MockTransport`
(`tests/support/smelt.py`); no network and no database are used.
"""

from __future__ import annotations

from collections.abc import Callable
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from structlog.testing import capture_logs

from app.services.base_fetcher import FetcherError
from app.services.packages import smelt_maintained_sweep
from app.services.packages.smelt_maintained_sweep import (
    fetch_maintained_package_names,
)
from tests.support.inadmissible import INADMISSIBLE_CHARACTERS
from tests.support.json_decoding import (
    NESTED_ARRAY,
    OVERSIZED_INTEGER,
    limit_parser_nesting,
)
from tests.support.smelt import (
    SMELT_TEST_API_URL,
    SmeltServer,
    sweep_page,
    sweep_pages,
    sweep_row,
)

INVALID_RESPONSE = "SMELT returned invalid maintained package response"
VALIDATION_FAILED = "SMELT maintained package validation failed"
PORT_API_URL = "https://smelt.example.test:8443/api"


def _packages(total: int, *, prefix: str = "fictional-pkg") -> list[str]:
    return [f"{prefix}-{index:04}" for index in range(total)]


def _url(page: int, api_url: str = SMELT_TEST_API_URL) -> str:
    return (
        f"{api_url}/experimental/v2/maintained/"
        f"?include_reactive_ltss=true&page_size=200&page={page}"
    )


def _three_pages(**kwargs: Any) -> SmeltServer:
    """450 results: pages of 200, 200, and 50."""
    return SmeltServer(sweep_pages(_packages(450)), **kwargs)


async def _fetch(
    server: SmeltServer, *, api_url: str = SMELT_TEST_API_URL, delay: float = 0
) -> frozenset[str]:
    async with server.client() as client:
        return await fetch_maintained_package_names(
            client, api_url=api_url, request_delay=delay
        )


async def _fetch_failure(server: SmeltServer, message: str) -> FetcherError:
    with pytest.raises(FetcherError) as raised:
        await _fetch(server)
    assert str(raised.value) == message
    return raised.value


@pytest.mark.unit
class TestSuccessfulSweep:
    async def test_single_page_sweep_returns_every_name(self) -> None:
        server = SmeltServer(sweep_pages(_packages(3)))

        assert await _fetch(server) == frozenset(_packages(3))
        assert server.requested_urls == [_url(1)]

    async def test_multi_page_sweep_returns_the_names_of_every_page(self) -> None:
        server = _three_pages()

        assert await _fetch(server) == frozenset(_packages(450))
        assert server.requested_urls == [_url(1), _url(2), _url(3)]

    async def test_empty_final_page_after_page_1_ends_the_sweep(self) -> None:
        pages = sweep_pages(_packages(200))
        pages[1]["data"]["has_next"] = True
        pages[2] = sweep_page(2, [], has_next=False)
        server = SmeltServer(pages)

        assert await _fetch(server) == frozenset(_packages(200))
        assert server.requested_pages == [1, 2]

    async def test_no_page_is_requested_after_the_last(self) -> None:
        server = _three_pages()
        server.pages[4] = sweep_page(4, [sweep_row("fictional-extra")], has_next=False)

        names = await _fetch(server)

        assert "fictional-extra" not in names
        assert server.requested_pages == [1, 2, 3]

    async def test_repeated_names_across_pages_are_one_name(self) -> None:
        packages = ["fictional-a"] * 150 + ["fictional-b"] * 100 + ["fictional-a"]
        server = SmeltServer(sweep_pages(packages))

        assert await _fetch(server) == {"fictional-a", "fictional-b"}

    async def test_names_are_kept_unchanged(self) -> None:
        packages = ["python-FictionalTable", "python-fictionaltable", "go1.25", "a+"]
        server = SmeltServer(sweep_pages(packages))

        assert await _fetch(server) == frozenset(packages)

    async def test_a_255_character_name_is_accepted(self) -> None:
        server = SmeltServer(sweep_pages(["a" * 255]))

        assert await _fetch(server) == {"a" * 255}

    async def test_unconsumed_result_fields_are_not_validated(self) -> None:
        server = SmeltServer(
            {
                1: sweep_page(
                    1, [{"package": "fictional-a", "targets": None}], has_next=False
                )
            }
        )

        assert await _fetch(server) == {"fictional-a"}

    async def test_unknown_envelope_fields_are_ignored(self) -> None:
        server = SmeltServer(sweep_pages(_packages(2)))
        server.pages[1]["extra"] = 1
        server.pages[1]["data"]["total"] = 2

        assert await _fetch(server) == frozenset(_packages(2))


@pytest.mark.unit
class TestRequests:
    async def test_requests_use_the_configured_origin_and_exact_parameters(
        self,
    ) -> None:
        server = _three_pages()

        await _fetch(server)

        for request, page in zip(server.requests, (1, 2, 3), strict=True):
            assert request.method == "GET"
            assert request.url.scheme == "https"
            assert request.url.host == "smelt.example.test"
            assert request.url.path == "/api/experimental/v2/maintained/"
            assert list(request.url.params.multi_items()) == [
                ("include_reactive_ltss", "true"),
                ("page_size", "200"),
                ("page", str(page)),
            ]

    async def test_configured_non_default_port_is_used(self) -> None:
        server = SmeltServer(sweep_pages(_packages(1)))

        await _fetch(server, api_url=PORT_API_URL)

        assert server.requested_urls == [_url(1, PORT_API_URL)]

    async def test_requests_are_anonymous_whatever_the_client_defaults(
        self,
    ) -> None:
        server = _three_pages()
        client = httpx.AsyncClient(
            transport=httpx.MockTransport(server.handler),
            auth=("fictional-user", "fictional-password"),
            headers={"Authorization": "Bearer fictional", "Cookie": "a=b"},
            cookies={"session": "fictional"},
        )

        async with client:
            await fetch_maintained_package_names(
                client, api_url=SMELT_TEST_API_URL, request_delay=0
            )

        for request in server.requests:
            assert "authorization" not in request.headers
            assert "cookie" not in request.headers

    async def test_redirect_is_not_followed(self) -> None:
        server = _three_pages()
        server.responses[1] = lambda request: httpx.Response(
            302, headers={"Location": f"{SMELT_TEST_API_URL}/elsewhere"}
        )
        client = httpx.AsyncClient(
            transport=httpx.MockTransport(server.handler), follow_redirects=True
        )

        with pytest.raises(FetcherError) as raised:
            async with client:
                await fetch_maintained_package_names(
                    client, api_url=SMELT_TEST_API_URL, request_delay=0
                )

        assert str(raised.value) == "SMELT returned HTTP 302"
        assert len(server.requests) == 1


@pytest.mark.unit
class TestRequestDelay:
    @staticmethod
    def _record_sleeps(
        monkeypatch: pytest.MonkeyPatch, events: list[tuple[str, str]]
    ) -> None:
        async def sleep(delay: float) -> None:
            events.append(("sleep", repr(delay)))

        monkeypatch.setattr(
            smelt_maintained_sweep, "asyncio", SimpleNamespace(sleep=sleep)
        )

    async def test_delay_separates_consecutive_pages_with_no_wait_before_page_1(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        events: list[tuple[str, str]] = []
        self._record_sleeps(monkeypatch, events)

        await _fetch(_three_pages(events=events), delay=0.5)

        assert events == [
            ("http", _url(1)),
            ("sleep", "0.5"),
            ("http", _url(2)),
            ("sleep", "0.5"),
            ("http", _url(3)),
        ]

    async def test_single_page_never_sleeps(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        events: list[tuple[str, str]] = []
        self._record_sleeps(monkeypatch, events)

        await _fetch(SmeltServer(sweep_pages(_packages(5)), events=events), delay=2.0)

        assert [kind for kind, _ in events] == ["http"]

    async def test_zero_delay_never_sleeps(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        events: list[tuple[str, str]] = []
        self._record_sleeps(monkeypatch, events)

        await _fetch(_three_pages(events=events), delay=0)

        assert [kind for kind, _ in events] == ["http", "http", "http"]


def _set_data(page: int, field: str, value: Any) -> Callable[[SmeltServer], None]:
    def mutate(server: SmeltServer) -> None:
        server.pages[page]["data"][field] = value

    return mutate


def _delete_data(page: int, field: str) -> Callable[[SmeltServer], None]:
    def mutate(server: SmeltServer) -> None:
        del server.pages[page]["data"][field]

    return mutate


def _replace(page: int, body: Any) -> Callable[[SmeltServer], None]:
    def mutate(server: SmeltServer) -> None:
        server.pages[page] = body

    return mutate


def _set_status(page: int, value: Any) -> Callable[[SmeltServer], None]:
    def mutate(server: SmeltServer) -> None:
        server.pages[page]["status"] = value

    return mutate


def _drop_result(page: int) -> Callable[[SmeltServer], None]:
    def mutate(server: SmeltServer) -> None:
        server.pages[page]["data"]["results"].pop()

    return mutate


_INVALID_PAGES = [
    pytest.param(_replace(2, None), id="body-null"),
    pytest.param(_replace(2, []), id="body-array"),
    pytest.param(_set_status(2, "fail"), id="status-fail"),
    pytest.param(_set_status(2, None), id="status-missing-value"),
    pytest.param(_replace(2, {"status": "success"}), id="data-missing"),
    pytest.param(_replace(2, {"status": "success", "data": []}), id="data-array"),
    pytest.param(_delete_data(2, "results"), id="results-missing"),
    pytest.param(_set_data(2, "results", {}), id="results-object"),
    pytest.param(_set_data(2, "page", 3), id="page-mismatch"),
    pytest.param(_set_data(2, "page", "2"), id="page-string"),
    pytest.param(_set_data(2, "page", 2.0), id="page-float"),
    pytest.param(_set_data(1, "page", True), id="page-boolean"),
    pytest.param(_delete_data(2, "page"), id="page-missing"),
    pytest.param(_set_data(2, "page_size", 100), id="page-size-mismatch"),
    pytest.param(_set_data(2, "page_size", "200"), id="page-size-string"),
    pytest.param(_delete_data(2, "page_size"), id="page-size-missing"),
    pytest.param(_set_data(2, "has_next", 1), id="has-next-number"),
    pytest.param(_set_data(2, "has_next", "true"), id="has-next-string"),
    pytest.param(_delete_data(2, "has_next"), id="has-next-missing"),
    pytest.param(_set_data(2, "has_previous", 1), id="has-previous-number"),
    pytest.param(_set_data(1, "has_previous", True), id="has-previous-on-page-1"),
    pytest.param(_set_data(2, "has_previous", False), id="no-previous-after-page-1"),
    pytest.param(_delete_data(2, "has_previous"), id="has-previous-missing"),
    pytest.param(_drop_result(1), id="non-final-page-not-full"),
]


@pytest.mark.unit
class TestInvalidPages:
    @pytest.mark.parametrize("mutate", _INVALID_PAGES)
    async def test_invalid_page_rejects_the_sweep_and_stops_the_requests(
        self, mutate: Callable[[SmeltServer], None]
    ) -> None:
        server = _three_pages()
        mutate(server)

        error = await _fetch_failure(server, INVALID_RESPONSE)

        assert error.__cause__ is not None
        assert server.requested_pages[-1] in (1, 2)
        assert 3 not in server.requested_pages

    async def test_non_json_body_is_an_invalid_response(self) -> None:
        server = _three_pages()
        server.responses[2] = lambda request: httpx.Response(200, content=b"<html>")

        error = await _fetch_failure(server, INVALID_RESPONSE)

        assert str(error.__cause__) == "page 2: body is not valid JSON"

    @pytest.mark.parametrize(
        "body",
        [
            ('{"x": ' + NESTED_ARRAY + "}").encode(),
            b'{"x": ' + OVERSIZED_INTEGER.encode() + b"}",
        ],
        ids=["nesting-beyond-the-parser-limit", "integer-beyond-the-conversion-limit"],
    )
    async def test_json_the_parser_cannot_represent_is_not_valid_json(
        self, body: bytes, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        limit_parser_nesting(monkeypatch)
        server = _three_pages()
        server.responses[1] = lambda request: httpx.Response(200, content=body)

        error = await _fetch_failure(server, INVALID_RESPONSE)

        assert str(error.__cause__) == "page 1: body is not valid JSON"

    async def test_undecodable_body_is_an_invalid_response(self) -> None:
        server = _three_pages()
        server.responses[1] = lambda request: httpx.Response(
            200,
            headers={"content-encoding": "gzip"},
            stream=httpx.ByteStream(b"not gzip at all"),
        )

        error = await _fetch_failure(server, INVALID_RESPONSE)

        assert "undecodable" in str(error.__cause__)


def _set_result(page: int, value: Any) -> Callable[[SmeltServer], None]:
    def mutate(server: SmeltServer) -> None:
        server.pages[page]["data"]["results"][0] = value

    return mutate


def _set_package(page: int, value: Any) -> Callable[[SmeltServer], None]:
    def mutate(server: SmeltServer) -> None:
        server.pages[page]["data"]["results"][0]["package"] = value

    return mutate


def _delete_package(page: int) -> Callable[[SmeltServer], None]:
    def mutate(server: SmeltServer) -> None:
        del server.pages[page]["data"]["results"][0]["package"]

    return mutate


_INVALID_RESULTS = [
    pytest.param(_set_result(2, "fictional-a"), id="result-string"),
    pytest.param(_set_result(2, None), id="result-null"),
    pytest.param(_set_result(2, ["fictional-a"]), id="result-array"),
    pytest.param(_delete_package(2), id="package-missing"),
    pytest.param(_set_package(2, None), id="package-null"),
    pytest.param(_set_package(2, ""), id="package-empty"),
    pytest.param(_set_package(2, 7), id="package-number"),
    pytest.param(_set_package(2, ["fictional-a"]), id="package-array"),
    pytest.param(_set_package(2, "a" * 256), id="package-too-long"),
]


@pytest.mark.unit
class TestInvalidResults:
    @pytest.mark.parametrize("mutate", _INVALID_RESULTS)
    async def test_invalid_result_rejects_the_sweep(
        self, mutate: Callable[[SmeltServer], None]
    ) -> None:
        server = _three_pages()
        mutate(server)

        error = await _fetch_failure(server, VALIDATION_FAILED)

        assert str(error.__cause__).startswith("page 2, result 0: ")
        assert server.requested_pages == [1, 2]

    @pytest.mark.parametrize("character", INADMISSIBLE_CHARACTERS)
    async def test_package_with_an_inadmissible_character_rejects_the_sweep(
        self, character: str
    ) -> None:
        server = _three_pages()
        _set_package(3, f"fictional{character}name")(server)

        error = await _fetch_failure(server, VALIDATION_FAILED)

        assert str(error.__cause__) == (
            "page 3, result 0: package contains an inadmissible character"
        )

    async def test_empty_sweep_is_rejected(self) -> None:
        server = SmeltServer({1: sweep_page(1, [], has_next=False)})

        error = await _fetch_failure(server, VALIDATION_FAILED)

        assert str(error.__cause__) == "the sweep holds no result"


def _raise(error: type[httpx.TransportError]) -> Callable[[httpx.Request], Any]:
    def respond(request: httpx.Request) -> httpx.Response:
        raise error("example failure to smelt.example.test", request=request)

    return respond


@pytest.mark.unit
class TestTransportFailures:
    @pytest.mark.parametrize("status_code", [204, 400, 401, 404, 500, 503])
    async def test_non_200_status_raises_the_http_status_message(
        self, status_code: int
    ) -> None:
        server = _three_pages()
        server.responses[2] = lambda request: httpx.Response(status_code)

        error = await _fetch_failure(server, f"SMELT returned HTTP {status_code}")

        assert server.requested_pages == [1, 2]
        assert error.__cause__ is None

    @pytest.mark.parametrize(
        ("error", "message"),
        [
            (httpx.ConnectError, "Failed to connect to SMELT"),
            (httpx.ReadError, "Failed to connect to SMELT"),
            (httpx.RemoteProtocolError, "Failed to connect to SMELT"),
            (httpx.ReadTimeout, "SMELT request timed out"),
            (httpx.ConnectTimeout, "SMELT request timed out"),
            (httpx.PoolTimeout, "SMELT request timed out"),
        ],
        ids=lambda value: value if isinstance(value, str) else value.__name__,
    )
    async def test_transport_error_raises_a_sanitized_chained_message(
        self, error: type[httpx.TransportError], message: str
    ) -> None:
        server = _three_pages()
        server.responses[2] = _raise(error)

        raised = await _fetch_failure(server, message)

        assert isinstance(raised.__cause__, error)
        assert server.requested_pages == [1, 2]

    async def test_public_messages_name_no_host_or_url(self) -> None:
        for message in (
            smelt_maintained_sweep.CONNECTION_FAILED_MESSAGE,
            smelt_maintained_sweep.TIMEOUT_MESSAGE,
            INVALID_RESPONSE,
            VALIDATION_FAILED,
        ):
            assert "smelt.example.test" not in message
            assert "/" not in message


@pytest.mark.unit
class TestLogs:
    async def test_invalid_page_log_names_page_and_category_without_payload(
        self,
    ) -> None:
        server = _three_pages()
        _set_data(2, "page", 9)(server)

        with capture_logs() as logs:
            await _fetch_failure(server, INVALID_RESPONSE)

        assert logs == [
            {
                "event": "smelt_maintained_sweep_response_invalid",
                "log_level": "warning",
                "page": 2,
                "category": "page 2: page does not equal the requested page",
            }
        ]

    async def test_invalid_result_log_contains_no_upstream_value(self) -> None:
        server = _three_pages()
        _set_package(2, "fictional-secret-value" * 20)(server)

        with capture_logs() as logs:
            await _fetch_failure(server, VALIDATION_FAILED)

        assert len(logs) == 1
        assert "fictional-secret-value" not in str(logs)

    async def test_schema_log_contains_no_upstream_value(self) -> None:
        server = _three_pages()
        _set_status(2, "fictional-secret-value")(server)

        with capture_logs() as logs:
            error = await _fetch_failure(server, INVALID_RESPONSE)

        assert "fictional-secret-value" not in str(logs)
        assert "fictional-secret-value" not in str(error.__cause__)

    async def test_http_status_log_names_page_category_and_status(self) -> None:
        server = _three_pages()
        server.responses[1] = lambda request: httpx.Response(503)

        with capture_logs() as logs:
            await _fetch_failure(server, "SMELT returned HTTP 503")

        assert logs == [
            {
                "event": "smelt_maintained_sweep_request_failed",
                "log_level": "warning",
                "page": 1,
                "category": "http_status",
                "status_code": 503,
            }
        ]

    async def test_successful_sweep_logs_nothing(self) -> None:
        with capture_logs() as logs:
            await _fetch(_three_pages())

        assert logs == []
