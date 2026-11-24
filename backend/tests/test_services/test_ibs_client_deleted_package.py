"""Tests for `IBSClient.get_deleted_package()`.

Contract under test: docs/features/integrations/ibs-integration.md (Deleted
Package Lookup: the request, the consumed `directory/@name`, and the
outcome of each response; Service Layer > IBSClient, the lookup method and
its escaping outcomes); docs/features/packages/ibs-submission-tracking.md
(Effective SR, the lookup after an incident-package history 404). The live
documents, the sanitized chain F captures of 2026-11-24, are read through
this client in `test_packages/test_ibs_request_provenance_contract.py`
(TestDeletedIncidentPackages); the cross-operation behaviour
(credentials, authentication, XML safety, privacy) is covered in
`test_ibs_client_request_common.py`.
"""

from __future__ import annotations

from typing import Any, Final

import httpx
import pytest

from app.services.ibs_client import (
    DeletedPackage,
    IBSCredentialsNotConfiguredError,
    IncompleteReason,
    RequestEvidenceResult,
)
from tests.support.ibs_api import (
    IBSServer,
    Responder,
    ibs_client,
    status_response,
    xml_response,
)
from tests.support.ibs_request_provenance import load_provenance_fixture

pytestmark = pytest.mark.unit
pytest_plugins = ["tests.support.ibs_client_fixtures"]

_PROJECT: Final = "SUSE:Maintenance:80001"
_PACKAGE: Final = "curl+x.SUSE_SLE-15-SP6_Update"
_PATH: Final = f"/source/{_PROJECT}/{_PACKAGE}"


def _directory(name: str | None = _PACKAGE, children: str = "") -> Responder:
    named = "" if name is None else f' name="{name}"'
    return xml_response(f"<directory{named}>{children}</directory>".encode())


async def _read(
    server: IBSServer,
    responder: Responder | None,
    *,
    project: str = _PROJECT,
    package: str = _PACKAGE,
) -> RequestEvidenceResult[DeletedPackage]:
    if responder is not None:
        server.route("GET", f"/source/{project}/{package}", responder)
    async with ibs_client() as client:
        return await client.get_deleted_package(project, package)


def _sent(server: IBSServer) -> tuple[str, str, list[tuple[str, str]]]:
    [request] = [r for r in server.requests if "authorization" in r.headers]
    return request.method, request.url.path, list(request.url.params.multi_items())


class TestRequest:
    async def test_lookup_sends_only_deleted(self, server: IBSServer) -> None:
        await _read(server, _directory())
        assert _sent(server) == ("GET", _PATH, [("deleted", "1")])

    async def test_plus_sign_is_sent_literally_in_the_path(
        self, server: IBSServer
    ) -> None:
        await _read(server, _directory())
        [request, *_] = server.requests
        assert request.url.raw_path.decode().startswith(
            "/source/SUSE:Maintenance:80001/curl+x."
        )


class TestInputValidation:
    @pytest.mark.parametrize(
        ("project", "package"),
        [
            ("home:fictional", _PACKAGE),
            ("openSUSE:Factory", _PACKAGE),
            ("_redacted_", _PACKAGE),
            ("suse:lower", _PACKAGE),
            ("SUSE:a b", _PACKAGE),
            ("", _PACKAGE),
            (_PROJECT, ""),
            (_PROJECT, "a/b"),
            (_PROJECT, ".."),
            (_PROJECT, "x" * 256),
            (_PROJECT, 1),
        ],
    )
    async def test_invalid_input_raises_before_any_request(
        self, server: IBSServer, project: Any, package: Any
    ) -> None:
        async with ibs_client(username="") as client:
            with pytest.raises(ValueError, match=r"\S") as raised:
                await client.get_deleted_package(project, package)
        assert server.requests == []
        assert "home:" not in str(raised.value)

    async def test_credentials_are_checked_after_input_and_before_http(
        self, server: IBSServer
    ) -> None:
        async with ibs_client(username="") as client:
            with pytest.raises(IBSCredentialsNotConfiguredError):
                await client.get_deleted_package(_PROJECT, _PACKAGE)
        assert server.requests == []


class TestDocument:
    async def test_unconsumed_attributes_and_children_are_ignored(
        self, server: IBSServer
    ) -> None:
        children = (
            '<linkinfo project="SUSE:SLE-15-SP6:Update" package="curl" '
            f'srcmd5="{"a" * 32}" baserev="{"b" * 32}"/>'
            '<entry name="curl.spec" md5="0" size="1" mtime="2"/>'
            '<entry name="curl.changes" md5="0" size="1" mtime="2"/>'
        )
        responder = xml_response(
            f'<directory name="{_PACKAGE}" rev="2" vrev="2" srcmd5="{"c" * 32}">'
            f"{children}</directory>".encode()
        )
        result = await _read(server, responder)
        assert result == RequestEvidenceResult(
            value=DeletedPackage(project=_PROJECT, package=_PACKAGE)
        )

    @pytest.mark.parametrize(
        ("responder", "reason"),
        [
            pytest.param(_directory(None), "invalid_document", id="missing-name"),
            pytest.param(_directory(""), "invalid_document", id="empty-name"),
            pytest.param(
                _directory("curl.SUSE_SLE-15-SP6_Update"),
                "invalid_document",
                id="other-name",
            ),
            pytest.param(
                _directory(_PACKAGE.upper()), "invalid_document", id="other-case"
            ),
            pytest.param(
                xml_response(f'<status code="ok" name="{_PACKAGE}"/>'.encode()),
                "invalid_document",
                id="other-root",
            ),
            pytest.param(
                xml_response(
                    f'<collection><directory name="{_PACKAGE}"/></collection>'.encode()
                ),
                "invalid_document",
                id="nested-directory",
            ),
            pytest.param(
                xml_response(f'<directory name="{_PACKAGE}">'.encode()),
                "malformed_xml",
                id="unclosed",
            ),
        ],
    )
    async def test_document_that_is_not_the_named_directory_is_incomplete(
        self, server: IBSServer, responder: Responder, reason: IncompleteReason
    ) -> None:
        result = await _read(server, responder)
        assert result == RequestEvidenceResult(incomplete_reason=reason)


class TestHttpStatus:
    @pytest.mark.parametrize(
        ("status", "reason"), [(400, "rejected"), (404, "not_found")]
    )
    async def test_400_and_404_are_incomplete_without_reading_the_body(
        self, server: IBSServer, status: int, reason: IncompleteReason
    ) -> None:
        read: list[bool] = []

        class Body(httpx.AsyncByteStream):
            async def __aiter__(self) -> Any:
                read.append(True)
                yield load_provenance_fixture("f_deleted_error_exists")

        result = await _read(server, lambda _: httpx.Response(status, stream=Body()))
        assert result == RequestEvidenceResult(incomplete_reason=reason)
        assert read == []

    @pytest.mark.parametrize("status", [403, 410, 429, 500])
    async def test_other_status_propagates(
        self, server: IBSServer, status: int
    ) -> None:
        with pytest.raises(httpx.HTTPStatusError) as raised:
            await _read(server, status_response(status, b"<status/>"))
        assert raised.value.response.status_code == status
