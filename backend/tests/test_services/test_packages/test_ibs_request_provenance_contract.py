"""Contract tests for the IBS provenance chains consumed by the shared
request reconciliation.

Contract under test: docs/features/packages/ibs-submission-tracking.md
(Package and Codestream Identity, Required Roots, Effective SR, Release
Discovery, Accepted RR Provenance) and
docs/features/integrations/ibs-integration.md (Project Source Info, Source
Diff with Issue Extraction, Request Point Detail, Request Action Diff,
Package Source History, Request Contract Verification Status), verified
against the sanitized live captures of 2026-10-14 and 2026-11-12 described
in `tests/support/ibs_request_provenance.py` (docs/conventions.md, External
Integration Contract Verification).

Every document is read through the production `IBSClient` over the fake
IBS API, at the recorded method, path, and query, so each recorded
request equals the form the client builds; the chain properties the
reconciliation relies on are then asserted on the typed results.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Final

import pytest

from app.core.enums import IBSRequestActionType, IBSRequestState
from app.services.ibs_client import (
    IBSClient,
    IBSRequestActionDetail,
    IBSRequestDetail,
    RequestActionDiff,
    SourceHistory,
)
from tests.support.ibs_api import IBSServer, ibs_client
from tests.support.ibs_request_api import load_request_fixture
from tests.support.ibs_request_provenance import (
    A_CVES,
    B_CVE,
    B_INCIDENT,
    B_RR,
    B_SR,
    C_INCIDENT,
    C_INCIDENT_NEWER,
    C_RR,
    C_RR_NEWER,
    C_SR_FIRST,
    C_SR_SECOND,
    CHAIN_D_FIXTURE_DATE,
    CHAIN_D_FIXTURES,
    D_CVE,
    D_INCIDENT,
    D_INCIDENT_REVOKED,
    D_RR,
    D_RR_REPLACING,
    D_RR_REVOKED,
    D_SCAN,
    PROVENANCE_FIXTURE_DATE,
    PROVENANCE_FIXTURES,
    SLE15,
    SP4,
    SP6,
    QueryRoutes,
    load_provenance_fixture,
    load_provenance_responses,
    provenance_fixture_date,
    provenance_fixture_paths,
    provenance_fixture_record,
    serve_provenance_fixture,
)

pytestmark = pytest.mark.unit
pytest_plugins = ["tests.support.ibs_client_fixtures"]

_ALLOWED: Final = {
    "request": {"id"},
    "state": {"name", "created", "when", "superseded_by"},
    "action": {"type"},
    "source": {"project", "package", "rev"},
    "target": {"project", "package", "releaseproject"},
    "acceptinfo": {
        "rev",
        "srcmd5",
        "xsrcmd5",
        "osrcmd5",
        "oxsrcmd5",
        "oproject",
        "opackage",
    },
    "sourcediff": set(),
    "issues": set(),
    "issue": {"state", "tracker", "name", "label"},
    "revisionlist": set(),
    "revision": {"rev"},
    "srcmd5": set(),
    "time": set(),
    "requestid": set(),
    "sourceinfolist": set(),
    "sourceinfo": {"package", "srcmd5"},
    "error": set(),
}
_PROJECT_ATTRIBUTES: Final = ("project", "releaseproject", "oproject")
_FLAVORS: Final = (
    "dtb-aarch64",
    "dtb-armv7l",
    "kernel-64kb",
    "kernel-debug",
    "kernel-default",
    "kernel-docs",
    "kernel-kvmsmall",
    "kernel-lpae",
    "kernel-obs-build",
    "kernel-obs-qa",
    "kernel-syms",
    "kernel-zfcpdump",
)
_FICTIONAL_OWNERS: Final = {"jdoe", "asmith", "bwilson"}
"""The fictional owners that replaced the GitHub accounts of `gh` issues."""


@pytest.fixture
def routes(server: IBSServer) -> Iterator[QueryRoutes]:
    """Every provenance fixture at its recorded method, path, and query;
    each test ends without an unrouted request."""
    query_routes = QueryRoutes(server)
    for name in PROVENANCE_FIXTURES:
        serve_provenance_fixture(query_routes, name)
    yield query_routes
    assert query_routes.unrouted == []


async def _detail(client: IBSClient, number: int) -> IBSRequestDetail:
    result = await client.get_request(number)
    assert result.value is not None, result.incomplete_reason
    return result.value


async def _history(
    client: IBSClient, project: str, package: str, revision: str | None = None
) -> SourceHistory:
    result = await client.get_source_history(project, package, revision=revision)
    assert result.value is not None, result.incomplete_reason
    return result.value


async def _diff(
    client: IBSClient, action: IBSRequestActionDetail, codestream_package: str
) -> RequestActionDiff:
    result = await client.get_request_action_diff(
        action, codestream_package=codestream_package
    )
    assert result.value is not None, result.incomplete_reason
    return result.value


def _release(
    detail: IBSRequestDetail, target_package: str, codestream: str
) -> IBSRequestActionDetail:
    [action] = [
        action
        for action in detail.actions
        if action.action_type is IBSRequestActionType.MAINTENANCE_RELEASE
        and action.target_project == codestream
        and action.target_package == target_package
    ]
    return action


def _codestream_release(
    detail: IBSRequestDetail, package: str, codestream: str
) -> IBSRequestActionDetail:
    """The release action of `package` from the request's own incident to
    `codestream`."""
    [action] = [
        action
        for action in detail.actions
        if action.action_type is IBSRequestActionType.MAINTENANCE_RELEASE
        and action.target_project == codestream
        and action.source_project.startswith("SUSE:Maintenance:")
        and action.target_package
        == f"{package}.{action.source_project.removeprefix('SUSE:Maintenance:')}"
    ]
    return action


def _incident_action(
    detail: IBSRequestDetail, target_package: str
) -> IBSRequestActionDetail:
    [action] = [
        action
        for action in detail.actions
        if action.action_type is IBSRequestActionType.MAINTENANCE_INCIDENT
        and action.target_package == target_package
    ]
    return action


def _cves(issues: RequestActionDiff) -> set[str]:
    return {
        issue.label
        for issue in issues.issues
        if issue.tracker == "cve"
        and issue.state in {"added", "changed"}
        and issue.label is not None
    }


async def _assert_proof(
    client: IBSClient,
    action: IBSRequestActionDetail,
    codestream: str,
    request_number: int,
) -> None:
    """The release proof of Accepted RR Provenance holds structurally: the
    exact lookup of the action's own target package at acceptinfo `rev`
    returns that revision with the acceptinfo `srcmd5` and the RR number."""
    assert action.acceptinfo is not None
    assert action.acceptinfo.rev is not None
    assert action.acceptinfo.srcmd5 is not None
    assert action.target_package is not None
    lookup = await _history(
        client, codestream, action.target_package, revision=action.acceptinfo.rev
    )
    [entry] = lookup.entries
    assert entry.revision == int(action.acceptinfo.rev)
    assert entry.srcmd5 == action.acceptinfo.srcmd5
    assert entry.request_number == request_number


class TestCapture:
    def test_every_fixture_is_listed_recorded_and_successful(self) -> None:
        responses = load_provenance_responses()
        assert responses["captured_at"] == PROVENANCE_FIXTURE_DATE
        assert responses["api_url"] == "https://api.suse.de"
        stored = {path.stem for path in provenance_fixture_paths()}
        assert stored == set(PROVENANCE_FIXTURES)
        assert set(responses["documents"]) == {f"{name}.xml" for name in stored}
        for name in PROVENANCE_FIXTURES:
            assert provenance_fixture_record(name)["status"] == 200
            assert provenance_fixture_date(name) == (
                CHAIN_D_FIXTURE_DATE
                if name in CHAIN_D_FIXTURES
                else PROVENANCE_FIXTURE_DATE
            )

    @pytest.mark.parametrize("name", PROVENANCE_FIXTURES)
    def test_only_consumed_elements_and_attributes_were_kept(self, name: str) -> None:
        root = ET.fromstring(load_provenance_fixture(name))
        for element in root.iter():
            assert element.tag in _ALLOWED, element.tag
            assert set(element.attrib) <= _ALLOWED[element.tag], element.tag
            for attribute in _PROJECT_ATTRIBUTES:
                value = element.get(attribute)
                assert value is None or value.startswith("SUSE:")

    @pytest.mark.parametrize("name", PROVENANCE_FIXTURES)
    def test_request_numbers_are_in_the_fictional_block(self, name: str) -> None:
        root = ET.fromstring(load_provenance_fixture(name))
        numbers = [int(e.text or "") for e in root.iter("requestid")]
        numbers += [int(e.get("id", "")) for e in root.iter("request")]
        assert all(960001 <= number < 961000 for number in numbers)

    @pytest.mark.parametrize("name", PROVENANCE_FIXTURES)
    def test_github_issue_owners_are_fictional(self, name: str) -> None:
        root = ET.fromstring(load_provenance_fixture(name))
        for issue in root.iter("issue"):
            if issue.get("tracker") == "gh":
                reference = issue.get("name", "")
                assert reference.split("/")[0] in _FICTIONAL_OWNERS
                assert issue.get("label") == f"gh#{reference}"


class TestCurrentReleaseEvidence:
    async def test_current_openvpn_sources_carry_the_cves_of_its_last_release(
        self, routes: QueryRoutes
    ) -> None:
        released = ET.fromstring(load_request_fixture("diff_rr_accepted"))
        released_cves = {
            issue.get("label")
            for issue in released.iter("issue")
            if issue.get("tracker") == "cve"
        }
        assert released_cves == set(A_CVES)
        async with ibs_client() as client:
            info = await client.get_source_info(SP6, ["openvpn"])
            current = info["openvpn"].source_info
            assert current is not None
            issues = await client.get_diff_issues(SP6, "openvpn", "0", current.srcmd5)
        labels = {
            issue.label
            for issue in issues
            if issue.tracker == "cve" and issue.state == "added"
        }
        assert set(A_CVES) <= labels

    async def test_current_sources_of_a_release_before_2023_still_carry_its_cve(
        self, routes: QueryRoutes
    ) -> None:
        async with ibs_client() as client:
            info = await client.get_source_info(SLE15, ["openvpn"])
            current = info["openvpn"].source_info
            assert current is not None
            issues = await client.get_diff_issues(SLE15, "openvpn", "0", current.srcmd5)
        assert B_CVE in {issue.label for issue in issues if issue.tracker == "cve"}


class TestReleaseBefore2023:
    async def test_the_release_request_alone_proves_the_release(
        self, routes: QueryRoutes
    ) -> None:
        async with ibs_client() as client:
            rr = await _detail(client, B_RR)
            assert rr.state is IBSRequestState.ACCEPTED
            assert rr.upstream_updated_at < datetime(2023, 1, 1, tzinfo=UTC)
            action = _release(rr, f"openvpn.{B_INCIDENT}", SLE15)
            assert action.source_project == f"SUSE:Maintenance:{B_INCIDENT}"
            await _assert_proof(client, action, SLE15, B_RR)
            assert B_CVE in _cves(await _diff(client, action, "openvpn"))

    async def test_the_sr_expanded_checksum_differs_from_the_release_source(
        self, routes: QueryRoutes
    ) -> None:
        async with ibs_client() as client:
            sr = await _detail(client, B_SR)
            rr = await _detail(client, B_RR)
        incident = _incident_action(sr, "openvpn.SUSE_SLE-15_Update")
        release = _release(rr, f"openvpn.{B_INCIDENT}", SLE15)
        assert incident.acceptinfo is not None
        assert incident.acceptinfo.xsrcmd5 != release.source_revision

    async def test_codestream_history_names_the_release_with_its_link_checksum(
        self, routes: QueryRoutes
    ) -> None:
        async with ibs_client() as client:
            history = await _history(client, SLE15, "openvpn")
            rr = await _detail(client, B_RR)
        release = _release(rr, f"openvpn.{B_INCIDENT}", SLE15)
        assert release.acceptinfo is not None
        newest = history.entries[-1]
        assert newest.request_number == B_RR
        assert newest.srcmd5 != release.acceptinfo.srcmd5
        assert all(entry.request_number is not None for entry in history.entries)

    async def test_the_sr_is_effective_in_its_incident_history(
        self, routes: QueryRoutes
    ) -> None:
        async with ibs_client() as client:
            sr = await _detail(client, B_SR)
            incident = _incident_action(sr, "openvpn.SUSE_SLE-15_Update")
            assert incident.target_project == f"SUSE:Maintenance:{B_INCIDENT}"
            assert incident.acceptinfo is not None
            history = await _history(
                client, f"SUSE:Maintenance:{B_INCIDENT}", "openvpn.SUSE_SLE-15_Update"
            )
            assert B_CVE in _cves(await _diff(client, incident, "openvpn"))
        numbers = [entry.request_number for entry in history.entries]
        assert numbers == [None, B_SR, B_RR]
        [own] = [e for e in history.entries if e.request_number == B_SR]
        assert own.srcmd5 == incident.acceptinfo.srcmd5


class TestKernelIncident:
    async def test_flavor_release_actions_carry_no_acceptinfo(
        self, routes: QueryRoutes
    ) -> None:
        raw = ET.fromstring(load_provenance_fixture("c_request_rr_accepted"))
        assert {action.get("type") for action in raw.iter("action")} == {
            "submit",
            "maintenance_release",
        }
        async with ibs_client() as client:
            rr = await _detail(client, C_RR)
        for flavor in _FLAVORS:
            assert _release(rr, f"{flavor}.{C_INCIDENT}", SP6).acceptinfo is None
        for package in ("kernel-source", "kernel-default-base"):
            assert _release(rr, f"{package}.{C_INCIDENT}", SP6).acceptinfo is not None

    async def test_kernel_default_base_has_no_submission_and_no_cve_in_its_release(
        self, routes: QueryRoutes
    ) -> None:
        async with ibs_client() as client:
            history = await _history(
                client,
                f"SUSE:Maintenance:{C_INCIDENT}",
                "kernel-default-base.SUSE_SLE-15-SP6_Update",
            )
            rr = await _detail(client, C_RR)
            action = _release(rr, f"kernel-default-base.{C_INCIDENT}", SP6)
            await _assert_proof(client, action, SP6, C_RR)
            diff = await _diff(client, action, "kernel-default-base")
        assert [entry.request_number for entry in history.entries] == [None, C_RR]
        assert diff.issues == ()

    async def test_a_second_sr_replaces_the_incident_contents_of_the_first(
        self, routes: QueryRoutes
    ) -> None:
        package = "kernel-source.SUSE_SLE-15-SP6_Update"
        async with ibs_client() as client:
            history = await _history(client, f"SUSE:Maintenance:{C_INCIDENT}", package)
            first = _incident_action(await _detail(client, C_SR_FIRST), package)
            second = _incident_action(await _detail(client, C_SR_SECOND), package)
            first_cves = _cves(await _diff(client, first, "kernel-source"))
            second_cves = _cves(await _diff(client, second, "kernel-source"))
        assert [entry.request_number for entry in history.entries] == [
            None,
            C_SR_FIRST,
            None,
            C_SR_SECOND,
            C_RR,
        ]
        for action in (first, second):
            assert action.acceptinfo is not None
            [own] = [
                entry
                for entry in history.entries
                if entry.request_number == action.request_number
            ]
            assert own.srcmd5 == action.acceptinfo.srcmd5
        assert first_cves
        assert second_cves

    async def test_consecutive_releases_are_proven_by_their_own_requests(
        self, routes: QueryRoutes
    ) -> None:
        async with ibs_client() as client:
            source_history = await _history(client, SP6, "kernel-source")
            default_history = await _history(client, SP6, "kernel-default")
            older = _release(
                await _detail(client, C_RR), f"kernel-source.{C_INCIDENT}", SP6
            )
            newer_rr = await _detail(client, C_RR_NEWER)
            newer = _release(newer_rr, f"kernel-source.{C_INCIDENT_NEWER}", SP6)
            await _assert_proof(client, older, SP6, C_RR)
            await _assert_proof(client, newer, SP6, C_RR_NEWER)
            older_cves = _cves(await _diff(client, older, "kernel-source"))
            newer_cves = _cves(await _diff(client, newer, "kernel-source"))
        assert [e.request_number for e in source_history.entries[-2:]] == [
            C_RR,
            C_RR_NEWER,
        ]
        assert [e.request_number for e in default_history.entries] == [
            e.request_number for e in source_history.entries
        ]
        assert older_cves
        assert newer_cves
        assert older_cves.isdisjoint(newer_cves)
        flavor = _release(newer_rr, f"kernel-default.{C_INCIDENT_NEWER}", SP6)
        assert flavor.acceptinfo is None

    async def test_the_release_source_matches_the_effective_sr_after_2023(
        self, routes: QueryRoutes
    ) -> None:
        async with ibs_client() as client:
            second = _incident_action(
                await _detail(client, C_SR_SECOND),
                "kernel-source.SUSE_SLE-15-SP6_Update",
            )
            release = _release(
                await _detail(client, C_RR), f"kernel-source.{C_INCIDENT}", SP6
            )
        assert second.acceptinfo is not None
        assert second.acceptinfo.xsrcmd5 == release.source_revision


class TestRevertedReleases:
    """Chain D: release requests whose acceptance failed after committing
    their codestream revisions, reverted and revoked, newer than the
    release that the release scan proves."""

    async def test_current_sources_still_carry_the_cve_of_an_older_release(
        self, routes: QueryRoutes
    ) -> None:
        async with ibs_client() as client:
            info = await client.get_source_info(SP4, ["PackageKit"])
            current = info["PackageKit"].source_info
            assert current is not None
            issues = await client.get_diff_issues(
                SP4, "PackageKit", "0", current.srcmd5
            )
        assert D_CVE in {
            issue.label
            for issue in issues
            if issue.tracker == "cve" and issue.state == "added"
        }

    async def test_each_failed_release_commit_is_reverted_and_its_request_revoked(
        self, routes: QueryRoutes
    ) -> None:
        """Each revision of a revoked request is followed by a revision
        without a request number that restores the previous `srcmd5`; the
        incident is released later by an accepted request whose revision
        carries the same link checksum."""
        async with ibs_client() as client:
            history = await _history(client, SP4, "PackageKit")
            revoked = [await _detail(client, number) for number in D_RR_REVOKED]
            replacing = await _detail(client, D_RR_REPLACING)
        entries = history.entries
        index = {
            entry.request_number: position
            for position, entry in enumerate(entries)
            if entry.request_number is not None
        }
        for detail in revoked:
            assert detail.state is IBSRequestState.REVOKED
            action = _release(detail, f"PackageKit.{D_INCIDENT_REVOKED}", SP4)
            assert action.acceptinfo is None
            position = index[detail.request_number]
            revert = entries[position + 1]
            assert revert.request_number is None
            assert revert.srcmd5 == entries[position - 1].srcmd5
            assert revert.srcmd5 != entries[position].srcmd5
        assert replacing.state is IBSRequestState.ACCEPTED
        release = _release(replacing, f"PackageKit.{D_INCIDENT_REVOKED}", SP4)
        assert release.acceptinfo is not None
        assert index[D_RR_REPLACING] == index[D_RR_REVOKED[-1]] + 2
        assert {
            entries[index[number]].srcmd5 for number in (*D_RR_REVOKED, D_RR_REPLACING)
        } == {entries[index[D_RR_REPLACING]].srcmd5}

    async def test_the_complete_history_names_the_scanned_requests_newest_first(
        self, routes: QueryRoutes
    ) -> None:
        async with ibs_client() as client:
            history = await _history(client, SP4, "PackageKit")
        numbers = [
            entry.request_number
            for entry in reversed(history.entries)
            if entry.request_number is not None
        ]
        assert numbers[: len(D_SCAN)] == list(D_SCAN)
        assert [entry.revision for entry in history.entries] == list(
            range(1, len(history.entries) + 1)
        )

    async def test_no_newer_accepted_release_carries_the_cve(
        self, routes: QueryRoutes
    ) -> None:
        async with ibs_client() as client:
            for number in D_SCAN[:-1]:
                detail = await _detail(client, number)
                action = _codestream_release(detail, "PackageKit", SP4)
                if number in D_RR_REVOKED:
                    assert detail.state is IBSRequestState.REVOKED
                    continue
                assert detail.state is IBSRequestState.ACCEPTED
                assert action.acceptinfo is not None
                assert D_CVE not in _cves(await _diff(client, action, "PackageKit"))

    async def test_the_oldest_scanned_release_proves_the_cve(
        self, routes: QueryRoutes
    ) -> None:
        async with ibs_client() as client:
            rr = await _detail(client, D_RR)
            assert rr.state is IBSRequestState.ACCEPTED
            action = _release(rr, f"PackageKit.{D_INCIDENT}", SP4)
            assert action.source_project == f"SUSE:Maintenance:{D_INCIDENT}"
            await _assert_proof(client, action, SP4, D_RR)
            assert D_CVE in _cves(await _diff(client, action, "PackageKit"))
