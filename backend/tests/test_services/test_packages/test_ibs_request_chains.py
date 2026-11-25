"""End-to-end tests of the shared IBS request reconciliation over the
sanitized live provenance chains.

Owning specifications: docs/features/packages/ibs-submission-tracking.md
(Required Roots, Effective SR including a deleted incident package, Release
Discovery, Accepted RR Provenance including deleted release packages,
Delivery Derivation, Shared Authoritative Reconciliation) and
docs/features/packages/package-model.md (Automatic Transitions: delivery
transitions, `PENDING -> IN_PROGRESS -> RELEASED` in one transaction).

Each test reconciles one committed scope through the real boundary, with
the request group of `tests/support/ibs_request_api.py` and the
provenance group of `tests/support/ibs_request_provenance.py` served at
their recorded method, path, and query behind a real `IBSClient`; every
other request is unrouted (HTTP 404) and asserted absent. The rows the
reconciliation writes are deleted at teardown through the world's request
numbers.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import UTC, datetime
from typing import Final

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.enums import DeliveryStatus, IBSRequestActionType, IBSRequestState
from tests.support.ibs_product_release import UnitSessions
from tests.support.ibs_request_provenance import (
    A_CVES,
    B_CVE,
    B_INCIDENT,
    B_RR,
    B_SR,
    C_INCIDENT,
    C_RR,
    C_RR_NEWER,
    C_SR_FIRST,
    C_SR_SECOND,
    CHAIN_D_FIXTURES,
    D_CVE,
    D_INCIDENT,
    D_RR,
    D_RR_REVOKED,
    D_SCAN,
    E_KRB5_SR,
    E_PILLOW_CVE,
    E_PILLOW_SR,
    F_INCIDENT_DELETED,
    F_KERNEL_PACKAGE,
    F_SR_DELETED,
    G_CVE,
    G_INCIDENT,
    G_RR,
    G_RR_WITHDRAWN,
    G_SCAN,
    SLE12_SP5,
    SLE15,
    SP4,
    SP6,
    load_provenance_fixture,
    provenance_fixture_query,
    provenance_fixture_record,
)
from tests.support.ibs_request_reconciliation import (
    Accept,
    Action,
    EvidenceRow,
    FakeRequests,
    RequestSeed,
    RequestWorld,
    cve_issue,
    delivery_of,
    evidence_of,
    install_fake_requests,
    install_request_units,
    kinds,
    reconcile,
    serve_provenance,
    serve_request_group_fixture,
)

pytestmark = pytest.mark.integration

Factory = Callable[[], Awaitable[AsyncSession]]

A_RR: Final = 910051
A_INCIDENT: Final = 80001
A_LOOKUP_SRCMD5: Final = "c40f9d03a8728b65ac857fe47495c082"
C_KERNEL_CVE: Final = "CVE-2024-44981"
"""A CVE released by kernel release request 960035 and not by 960036."""
G_UNRELEASED_CVE: Final = "CVE-2026-90401"
"""A fictional CVE of the current `cpio` sources that no captured release
diff of chain G carries, as when the withdrawn release alone released it."""
G_SCAN_FIXTURES: Final = (
    "g_history_codestream",
    *(
        name
        for number in G_SCAN
        for name in (
            f"g_request_rr_{number}",
            f"g_diff_rr_{number}",
            *(["g_deleted_target"] if number == G_RR_WITHDRAWN else []),
        )
    ),
)
"""The codestream history and the documents that the release scan of chain G
reads for every entry, newest first."""


def _fixture_action(name: str, target_package: str) -> Action:
    """The action of provenance fixture `name` whose target package is
    `target_package`, as served."""
    root = ET.fromstring(load_provenance_fixture(name))
    for element in root.iter("action"):
        target = element.find("target")
        if target is None or target.get("package") != target_package:
            continue
        source = element.find("source")
        assert source is not None
        accept = element.find("acceptinfo")
        return Action(
            type=element.get("type", ""),
            source_project=source.get("project", ""),
            source_package=source.get("package", ""),
            rev=source.get("rev"),
            target_project=target.get("project"),
            target_package=target.get("package"),
            release_project=target.get("releaseproject"),
            accept=None if accept is None else Accept(**accept.attrib),
        )
    raise AssertionError(f"no action for {target_package} in {name}")


def _served_paths(fake: FakeRequests) -> list[str]:
    return [f"{method} {path}" for method, path, _ in fake.served]


def _served_action_diffs(
    fake: FakeRequests,
) -> list[tuple[str, str, tuple[tuple[str, str], ...]]]:
    """The request action diffs served, in order."""
    return [
        served
        for served in fake.served
        if served[0] == "POST" and ("withissues", "1") in served[2]
    ]


def _recorded(*names: str) -> list[tuple[str, str, tuple[tuple[str, str], ...]]]:
    """The recorded requests of provenance fixtures `names`, in order, in
    the form `FakeRequests.served` records them."""
    return [
        (
            provenance_fixture_record(name)["method"],
            provenance_fixture_record(name)["path"],
            tuple(provenance_fixture_query(name)),
        )
        for name in names
    ]


@pytest.fixture(autouse=True)
def fake(monkeypatch: pytest.MonkeyPatch) -> FakeRequests:
    return install_fake_requests(monkeypatch)


@pytest.fixture(autouse=True)
def units(
    real_session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> UnitSessions:
    return install_request_units(monkeypatch, real_session_factory)


@pytest.fixture
async def world(db_session_factory: Factory) -> AsyncIterator[RequestWorld]:
    created = RequestWorld(db_session_factory, await db_session_factory())
    try:
        yield created
    finally:
        await created.cleanup()


class TestReleaseProvenChains:
    async def test_the_openvpn_release_is_proven_through_the_release_scan(
        self, world: RequestWorld, fake: FakeRequests
    ) -> None:
        seed = RequestSeed(world)
        scope = await seed.track(await seed.ticket(cve_id=A_CVES[0]), package="openvpn")
        await seed.commit()
        world.numbers().add(A_RR)
        for name in ("a_sourceinfo_current", "a_diff_current"):
            serve_provenance(fake, name)
        for name in (
            "history_codestream",
            "request_rr_accepted",
            "diff_rr_accepted",
            "history_lookup_revision",
        ):
            serve_request_group_fixture(fake, name)

        outcomes = await reconcile(fake, [scope])

        assert kinds(outcomes) == {scope.track_id: "created"}
        assert fake.unrouted == []
        probe = await world.probe()
        assert await delivery_of(probe, scope.track_id) == DeliveryStatus.RELEASED
        assert await evidence_of(probe, scope.track_id) == [
            EvidenceRow(
                request_number=A_RR,
                state=IBSRequestState.ACCEPTED.value,
                superseded_by_request_number=None,
                action_type=IBSRequestActionType.MAINTENANCE_RELEASE.value,
                logical_package="openvpn",
                codestream_name=SP6,
                incident_number=A_INCIDENT,
                accepted_revision="1",
                accepted_srcmd5=A_LOOKUP_SRCMD5,
                target_project=SP6,
                target_package=f"openvpn.{A_INCIDENT}",
                source_project=f"SUSE:Maintenance:{A_INCIDENT}",
            )
        ]

    async def test_a_release_before_2023_is_proven_by_its_release_request_alone(
        self, world: RequestWorld, fake: FakeRequests
    ) -> None:
        seed = RequestSeed(world)
        scope = await seed.track(
            await seed.ticket(cve_id=B_CVE), package="openvpn", codestream=SLE15
        )
        await seed.commit()
        world.numbers().update({B_RR, B_SR})
        for name in (
            "b_sourceinfo_current",
            "b_diff_current",
            "b_history_codestream",
            "b_request_rr_accepted",
            "b_diff_rr_accepted",
            "b_history_lookup",
        ):
            serve_provenance(fake, name)

        outcomes = await reconcile(fake, [scope])

        assert kinds(outcomes) == {scope.track_id: "created"}
        assert fake.unrouted == []
        probe = await world.probe()
        assert await delivery_of(probe, scope.track_id) == DeliveryStatus.RELEASED
        [row] = await evidence_of(probe, scope.track_id)
        assert (row.request_number, row.incident_number) == (B_RR, B_INCIDENT)

    async def test_a_kernel_release_is_proven_at_an_older_scan_entry(
        self, world: RequestWorld, fake: FakeRequests
    ) -> None:
        seed = RequestSeed(world)
        scope = await seed.track(
            await seed.ticket(cve_id=C_KERNEL_CVE), package="kernel-source"
        )
        await seed.commit()
        world.numbers().update({C_RR, C_RR_NEWER})
        fake.release_evidence(SP6, "kernel-source", cve_issue(C_KERNEL_CVE))
        for name in (
            "c_history_codestream_source",
            "c_request_rr_newer",
            "c_diff_rr_source_newer",
            "c_request_rr_accepted",
            "c_diff_rr_source",
            "c_history_lookup_source",
        ):
            serve_provenance(fake, name)

        outcomes = await reconcile(fake, [scope])

        assert kinds(outcomes) == {scope.track_id: "created"}
        assert fake.unrouted == []
        probe = await world.probe()
        assert await delivery_of(probe, scope.track_id) == DeliveryStatus.RELEASED
        [row] = await evidence_of(probe, scope.track_id)
        assert (row.request_number, row.incident_number) == (C_RR, C_INCIDENT)

    async def test_a_release_is_proven_past_reverted_revoked_release_requests(
        self, world: RequestWorld, fake: FakeRequests
    ) -> None:
        """Two newer release requests of one incident failed during
        acceptance: their codestream revisions were reverted and both are
        revoked. The scan skips them without reading their diffs, continues
        past the newer accepted releases without the CVE, and proves the
        release of the CVE by the oldest scanned request."""
        seed = RequestSeed(world)
        scope = await seed.track(
            await seed.ticket(cve_id=D_CVE), package="PackageKit", codestream=SP4
        )
        await seed.commit()
        world.numbers().update(D_SCAN)
        for name in CHAIN_D_FIXTURES:
            serve_provenance(fake, name)

        outcomes = await reconcile(fake, [scope])

        assert kinds(outcomes) == {scope.track_id: "created"}
        assert fake.unrouted == []
        scan = [
            name
            for number in D_SCAN
            for name in (f"d_request_rr_{number}", f"d_diff_rr_{number}")
            if number not in D_RR_REVOKED or name.startswith("d_request_rr_")
        ]
        assert fake.served == _recorded(
            "d_sourceinfo_current",
            "d_diff_current",
            "d_history_codestream",
            *scan,
            "d_history_lookup",
        )
        probe = await world.probe()
        assert await delivery_of(probe, scope.track_id) == DeliveryStatus.RELEASED
        [row] = await evidence_of(probe, scope.track_id)
        assert (row.request_number, row.incident_number, row.accepted_revision) == (
            D_RR,
            D_INCIDENT,
            "1",
        )


class TestKernelIncident:
    async def test_the_second_sr_replaces_the_first_and_establishes_progress(
        self, world: RequestWorld, fake: FakeRequests
    ) -> None:
        """The track is correlated to the first kernel SR; the incident
        history names a second SR after it, which is the effective one and
        carries the Ticket CVE in its own diff."""
        package = "kernel-source.SUSE_SLE-15-SP6_Update"
        first = _fixture_action("c_request_sr_first", package)
        seed = RequestSeed(world)
        scope = await seed.track(
            await seed.ticket(cve_id=C_KERNEL_CVE), package="kernel-source"
        )
        await seed.evidence(C_SR_FIRST, IBSRequestState.ACCEPTED, first, tracks=[scope])
        await seed.commit()
        world.numbers().update({C_SR_SECOND, C_RR})
        fake.quiet("kernel-source", SP6)
        for name in (
            "c_history_incident_source",
            "c_request_sr_second",
            "c_diff_sr_second",
            "c_request_rr_accepted",
        ):
            serve_provenance(fake, name)

        outcomes = await reconcile(fake, [scope])

        assert kinds(outcomes) == {scope.track_id: "created"}
        assert fake.unrouted == []
        assert f"GET /request/{C_SR_FIRST}" not in _served_paths(fake)
        probe = await world.probe()
        assert await delivery_of(probe, scope.track_id) == DeliveryStatus.IN_PROGRESS
        assert [
            row.request_number for row in await evidence_of(probe, scope.track_id)
        ] == [
            C_SR_FIRST,
            C_SR_SECOND,
        ]

    async def test_a_flavor_release_without_acceptinfo_stops_the_scan(
        self, world: RequestWorld, fake: FakeRequests
    ) -> None:
        """The newest release of the link-only flavor has no acceptinfo:
        neither it nor an older release can be proven, so the observation
        continues with the other roots and finds nothing."""
        seed = RequestSeed(world)
        scope = await seed.track(
            await seed.ticket(cve_id=C_KERNEL_CVE), package="kernel-default"
        )
        await seed.commit()
        world.numbers().add(C_RR_NEWER)
        fake.quiet("kernel-default", SP6)
        fake.release_evidence(SP6, "kernel-default", cve_issue(C_KERNEL_CVE))
        for name in ("c_history_codestream_default", "c_request_rr_newer"):
            serve_provenance(fake, name)

        outcomes = await reconcile(fake, [scope])

        assert kinds(outcomes) == {scope.track_id: "no_op"}
        assert fake.unrouted == []
        assert [
            path for path in _served_paths(fake) if path.startswith("GET /request/")
        ] == [f"GET /request/{C_RR_NEWER}"]
        assert not [
            (path, query)
            for _, path, query in fake.served
            if ("withissues", "1") in query or (path.endswith("/_history") and query)
        ]
        probe = await world.probe()
        assert await delivery_of(probe, scope.track_id) == DeliveryStatus.PENDING
        assert await evidence_of(probe, scope.track_id) == []

    async def test_kernel_default_base_is_released_without_cve_evidence(
        self, world: RequestWorld, fake: FakeRequests
    ) -> None:
        """`kernel-default-base` has no SR in its incident; its release
        request alone passes the exact lookup, but its release diff names
        no CVE, so it proves nothing and is not incomplete."""
        target = f"kernel-default-base.{C_INCIDENT}"
        release_action = _fixture_action("c_request_rr_accepted", target)
        seed = RequestSeed(world)
        scope = await seed.track(
            await seed.ticket(cve_id=C_KERNEL_CVE), package="kernel-default-base"
        )
        await seed.evidence(
            C_RR, IBSRequestState.ACCEPTED, release_action, tracks=[scope]
        )
        await seed.commit()
        fake.quiet("kernel-default-base", SP6)
        for name in (
            "c_request_rr_accepted",
            "c_history_lookup_default_base",
            "c_diff_rr_default_base",
        ):
            serve_provenance(fake, name)

        outcomes = await reconcile(fake, [scope])

        assert kinds(outcomes) == {scope.track_id: "no_op"}
        assert fake.unrouted == []
        probe = await world.probe()
        assert await delivery_of(probe, scope.track_id) == DeliveryStatus.PENDING


class TestReleaseBefore2023Submission:
    async def test_the_effective_sr_establishes_progress_from_retained_provenance(
        self, world: RequestWorld, fake: FakeRequests
    ) -> None:
        """The correlated accepted SR is effective in its incident history
        (a branch commit before it, its release request after it), checked
        from retained provenance without point detail; current release
        evidence without the CVE needs no scan."""
        sr = _fixture_action("b_request_sr_accepted", "openvpn.SUSE_SLE-15_Update")
        seed = RequestSeed(world)
        scope = await seed.track(
            await seed.ticket(cve_id=B_CVE), package="openvpn", codestream=SLE15
        )
        await seed.evidence(B_SR, IBSRequestState.ACCEPTED, sr, tracks=[scope])
        await seed.commit()
        world.numbers().add(B_RR)
        fake.quiet("openvpn", SLE15)
        for name in ("b_history_incident", "b_request_rr_accepted"):
            serve_provenance(fake, name)

        outcomes = await reconcile(fake, [scope])

        assert kinds(outcomes) == {scope.track_id: "updated"}
        assert fake.unrouted == []
        assert f"GET /request/{B_SR}" not in _served_paths(fake)
        probe = await world.probe()
        assert await delivery_of(probe, scope.track_id) == DeliveryStatus.IN_PROGRESS


class TestConflictingSourceLinks:
    """Chain E: open submissions whose source link conflicts with the
    current codestream package. Their not-accepted diff answers HTTP 400 and
    made every scope of their package and codestream fail with `rejected`;
    the link-base diff is the evidence of the action."""

    async def test_a_conflicting_submission_carrying_the_cve_establishes_progress(
        self, world: RequestWorld, fake: FakeRequests
    ) -> None:
        seed = RequestSeed(world)
        scope = await seed.track(
            await seed.ticket(cve_id=E_PILLOW_CVE),
            package="python-Pillow",
            codestream=SP4,
        )
        await seed.commit()
        world.numbers().add(E_PILLOW_SR)
        fake.quiet("python-Pillow", SP4, open_submissions=[E_PILLOW_SR])
        for name in (
            "e_request_sr_pillow",
            "e_diff_sr_pillow",
            "e_diff_sr_pillow_link_base",
        ):
            serve_provenance(fake, name)

        outcomes = await reconcile(fake, [scope])

        assert kinds(outcomes) == {scope.track_id: "created"}
        assert fake.unrouted == []
        assert _served_action_diffs(fake) == _recorded(
            "e_diff_sr_pillow", "e_diff_sr_pillow_link_base"
        )
        probe = await world.probe()
        assert await delivery_of(probe, scope.track_id) == DeliveryStatus.IN_PROGRESS
        assert await evidence_of(probe, scope.track_id) == [
            EvidenceRow(
                request_number=E_PILLOW_SR,
                state=IBSRequestState.NEW.value,
                superseded_by_request_number=None,
                action_type=IBSRequestActionType.MAINTENANCE_INCIDENT.value,
                logical_package="python-Pillow",
                codestream_name=SP4,
                incident_number=None,
                accepted_revision=None,
                accepted_srcmd5=None,
                target_project="SUSE:Maintenance",
                target_package=None,
                source_project=f"SUSE:Maintenance:REQUEST:{E_PILLOW_SR}",
            )
        ]

    async def test_scopes_whose_cve_the_conflicting_submission_lacks_complete(
        self, world: RequestWorld, fake: FakeRequests
    ) -> None:
        """Tickets of the package and codestream whose CVE the request does
        not carry become complete no-matches; the two diffs are requested
        once for every scope."""
        seed = RequestSeed(world)
        scopes = [
            await seed.track(await seed.ticket(), package="krb5", codestream=SLE12_SP5)
            for _ in range(3)
        ]
        await seed.commit()
        world.numbers().add(E_KRB5_SR)
        fake.quiet("krb5", SLE12_SP5, open_submissions=[E_KRB5_SR])
        for name in ("e_request_sr_krb5", "e_diff_sr_krb5", "e_diff_sr_krb5_link_base"):
            serve_provenance(fake, name)

        outcomes = await reconcile(fake, scopes)

        assert kinds(outcomes) == {scope.track_id: "no_op" for scope in scopes}
        assert fake.unrouted == []
        assert _served_action_diffs(fake) == _recorded(
            "e_diff_sr_krb5", "e_diff_sr_krb5_link_base"
        )
        probe = await world.probe()
        for scope in scopes:
            assert await delivery_of(probe, scope.track_id) == DeliveryStatus.PENDING
            assert await evidence_of(probe, scope.track_id) == []


class TestDeletedIncidentPackage:
    """Chain F: the observed case of #1348. An SR correlated to the track
    while it was in review was then accepted into an incident whose project
    IBS deleted; its incident history answers HTTP 404, and the deleted
    package lookup reports the incident package deleted."""

    async def test_the_sr_ends_its_progress_and_the_delivery_returns_to_pending(
        self, world: RequestWorld, fake: FakeRequests
    ) -> None:
        accepted = _fixture_action("f_request_sr_deleted", F_KERNEL_PACKAGE)
        open_form = Action(
            type=accepted.type,
            source_project=accepted.source_project,
            source_package=accepted.source_package,
            rev=accepted.rev,
            target_project="SUSE:Maintenance",
            release_project=SLE12_SP5,
        )
        seed = RequestSeed(world)
        scope = await seed.track(
            await seed.ticket(),
            package="kernel-source",
            codestream=SLE12_SP5,
            delivery=DeliveryStatus.IN_PROGRESS,
        )
        await seed.evidence(
            F_SR_DELETED,
            IBSRequestState.REVIEW,
            open_form,
            tracks=[scope],
            upstream_updated_at=datetime(2026, 11, 24, 2, 30, tzinfo=UTC),
        )
        await seed.commit()
        fake.quiet("kernel-source", SLE12_SP5)
        for name in (
            "f_request_sr_deleted",
            "f_history_incident_deleted",
            "f_deleted_incident_package",
        ):
            serve_provenance(fake, name)

        outcomes = await reconcile(fake, [scope])

        assert kinds(outcomes) == {scope.track_id: "updated"}
        assert fake.unrouted == []
        assert [
            served
            for served in fake.served
            if served[1].startswith(f"/source/SUSE:Maintenance:{F_INCIDENT_DELETED}/")
        ] == _recorded("f_history_incident_deleted", "f_deleted_incident_package")
        probe = await world.probe()
        assert await delivery_of(probe, scope.track_id) == DeliveryStatus.PENDING
        assert accepted.accept is not None
        assert await evidence_of(probe, scope.track_id) == [
            EvidenceRow(
                request_number=F_SR_DELETED,
                state=IBSRequestState.ACCEPTED.value,
                superseded_by_request_number=None,
                action_type=IBSRequestActionType.MAINTENANCE_INCIDENT.value,
                logical_package="kernel-source",
                codestream_name=SLE12_SP5,
                incident_number=F_INCIDENT_DELETED,
                accepted_revision="2",
                accepted_srcmd5=accepted.accept.srcmd5,
                target_project=f"SUSE:Maintenance:{F_INCIDENT_DELETED}",
                target_package=F_KERNEL_PACKAGE,
                source_project=f"SUSE:Maintenance:REQUEST:{F_SR_DELETED}",
            )
        ]


class TestDeletedReleasePackage:
    """Chain G: IBS deleted the target package of an accepted release
    request of `cpio` in `SUSE:SLE-15:Update` after its release, so its
    release diff answers HTTP 404, and the deleted package lookup reports
    the package deleted."""

    async def test_the_scan_continues_past_the_withdrawn_release_to_the_proof(
        self, world: RequestWorld, fake: FakeRequests
    ) -> None:
        seed = RequestSeed(world)
        scope = await seed.track(
            await seed.ticket(cve_id=G_CVE), package="cpio", codestream=SLE15
        )
        await seed.commit()
        world.numbers().update(G_SCAN)
        for name in (
            "g_sourceinfo_current",
            "g_diff_current",
            *G_SCAN_FIXTURES,
            "g_history_lookup",
        ):
            serve_provenance(fake, name)

        outcomes = await reconcile(fake, [scope])

        assert kinds(outcomes) == {scope.track_id: "created"}
        assert fake.unrouted == []
        assert fake.served == _recorded(
            "g_sourceinfo_current",
            "g_diff_current",
            *G_SCAN_FIXTURES,
            "g_history_lookup",
        )
        probe = await world.probe()
        assert await delivery_of(probe, scope.track_id) == DeliveryStatus.RELEASED
        [row] = await evidence_of(probe, scope.track_id)
        assert (row.request_number, row.incident_number, row.accepted_revision) == (
            G_RR,
            G_INCIDENT,
            "1",
        )

    async def test_without_another_release_the_delivery_derives_from_other_roots(
        self, world: RequestWorld, fake: FakeRequests
    ) -> None:
        """The accepted limitation: when the release that cannot be proven
        is the only one of the Ticket CVE, the scan exhausts the history and
        the observation completes; without other progress, a track that was
        `IN_PROGRESS` returns to `PENDING`."""
        seed = RequestSeed(world)
        scope = await seed.track(
            await seed.ticket(cve_id=G_UNRELEASED_CVE),
            package="cpio",
            codestream=SLE15,
            delivery=DeliveryStatus.IN_PROGRESS,
        )
        await seed.commit()
        world.numbers().update(G_SCAN)
        fake.quiet("cpio", SLE15)
        fake.release_evidence(SLE15, "cpio", cve_issue(G_UNRELEASED_CVE))
        for name in G_SCAN_FIXTURES:
            serve_provenance(fake, name)

        outcomes = await reconcile(fake, [scope])

        assert kinds(outcomes) == {scope.track_id: "updated"}
        assert fake.unrouted == []
        assert [
            served for served in fake.served if served[2] == (("deleted", "1"),)
        ] == _recorded("g_deleted_target")
        probe = await world.probe()
        assert await delivery_of(probe, scope.track_id) == DeliveryStatus.PENDING
        assert await evidence_of(probe, scope.track_id) == []
