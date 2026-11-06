"""Unit tests for pure Ticket priority resolution
(backend/app/services/ticket_priority.py).

Covers `docs/features/tickets/ticket-priority.md` (Testing Requirement 1):
every Decision Table cell (including the `None` severity label versus SQL
`NULL`), the exploitation precedence, the EPSS percentile boundary, and
ignored SSVC values and non-inputs; and the `classify_exploitation()` half
of Testing Requirement 10: the deciding evidence of each level, with its
kinds, values, and order (Exploitation Level). The basis in the Ticket
reads and responses is proven in test_ticket_priority_basis.py and
tests/test_api/test_ticket_priority_basis.py. CVE-less Tickets (Testing Requirement 2)
are proven in test_ticket_priority_refresh.py `TestCvelessTickets`. Refresh
points, the override, audit, and the API surface (Requirements 3-9) are
proven by the service and API tests that persist priority, including
test_ticket_priority_refresh.py, test_set_priority_override.py,
test_set_priority_override_atomicity.py (Requirement 7),
test_cvss_recalculation_domain.py (Requirement 8), and the Ticket list
tests (Requirement 9); each refresh point's position is proven with its
calling workflow, and the override's HTTP boundary in
tests/test_api/test_ticket_priority_override.py.

The expected Decision Table is transcribed independently from the
specification rather than read back from the module.
"""

from __future__ import annotations

import inspect
import itertools
from datetime import date

import pytest

from app.core.enums import (
    ExploitationEvidenceKind,
    ExploitationLevel,
    Severity,
    TicketPriority,
)
from app.services import ticket_priority
from app.services.ticket_priority import (
    EPSS_LIKELY_PERCENTILE_THRESHOLD,
    ExploitationClassification,
    ExploitationEvidence,
    classify_exploitation,
    resolve_priority,
)
from tests.support.module_imports import (
    APP_ROOT,
    forbidden_imports,
    imported_modules,
)

P1, P2, P3, P4 = (
    TicketPriority.P1,
    TicketPriority.P2,
    TicketPriority.P3,
    TicketPriority.P4,
)

# ticket-priority.md (Decision Table). Columns: Critical, High, Medium,
# Low or None, Severity NULL.
SPEC_DECISION_TABLE: dict[str, tuple[TicketPriority | None, ...]] = {
    "kev": (P1, P1, P1, P1, P1),
    "active": (P1, P1, P2, P3, P2),
    "likely": (P2, P2, P3, P4, P3),
    "unknown": (P2, P3, P4, P4, None),
}


def _decision_cells() -> list[tuple[str, Severity | None, TicketPriority | None]]:
    cells: list[tuple[str, Severity | None, TicketPriority | None]] = []
    for level, (
        critical,
        high,
        medium,
        low_or_none,
        unresolved,
    ) in SPEC_DECISION_TABLE.items():
        cells += [
            (level, Severity.CRITICAL, critical),
            (level, Severity.HIGH, high),
            (level, Severity.MEDIUM, medium),
            (level, Severity.LOW, low_or_none),
            (level, Severity.NONE, low_or_none),
            (level, None, unresolved),
        ]
    return cells


KEV_DATE = date(2099, 1, 15)
"""A fictional KEV `date_added`."""

KEV = ExploitationEvidence(ExploitationEvidenceKind.KEV, KEV_DATE)
SSVC_ACTIVE = ExploitationEvidence(ExploitationEvidenceKind.SSVC_EXPLOITATION, "active")
SSVC_POC = ExploitationEvidence(ExploitationEvidenceKind.SSVC_EXPLOITATION, "poc")


def _epss(percentile: float) -> ExploitationEvidence:
    return ExploitationEvidence(ExploitationEvidenceKind.EPSS_PERCENTILE, percentile)


def _level(
    *,
    kev: date | None = None,
    ssvc: str | None = None,
    epss: float | None = None,
) -> ExploitationLevel:
    return classify_exploitation(
        kev_date_added=kev, ssvc_exploitation=ssvc, epss_percentile=epss
    ).level


@pytest.mark.unit
class TestResolvePriority:
    @pytest.mark.parametrize(("level", "severity", "expected"), _decision_cells())
    def test_decision_table_cell(
        self,
        level: str,
        severity: Severity | None,
        expected: TicketPriority | None,
    ) -> None:
        assert resolve_priority(severity, ExploitationLevel(level)) == expected

    def test_all_twenty_specified_cells_are_covered(self) -> None:
        cells = {
            (level, column)
            for level, row in SPEC_DECISION_TABLE.items()
            for column in range(len(row))
        }
        assert len(cells) == 20

    def test_null_only_for_unresolved_severity_with_unknown_evidence(self) -> None:
        null_cells = [
            (severity, level)
            for severity, level in itertools.product(
                [*Severity, None], ExploitationLevel
            )
            if resolve_priority(severity, level) is None
        ]

        assert null_cells == [(None, ExploitationLevel.UNKNOWN)]

    def test_returns_ticket_priority_members(self) -> None:
        for severity, level in itertools.product([*Severity, None], ExploitationLevel):
            result = resolve_priority(severity, level)
            assert result is None or type(result) is TicketPriority


@pytest.mark.unit
class TestClassifyExploitation:
    def test_no_evidence_is_unknown(self) -> None:
        assert classify_exploitation(
            kev_date_added=None, ssvc_exploitation=None, epss_percentile=None
        ) == ExploitationClassification(level=ExploitationLevel.UNKNOWN, evidence=())

    @pytest.mark.parametrize("ssvc", [None, "none", "poc", "active"])
    @pytest.mark.parametrize("epss", [None, 0.0, 0.5, 0.95, 1.0])
    def test_kev_wins_over_every_other_evidence(
        self, ssvc: str | None, epss: float | None
    ) -> None:
        assert _level(kev=KEV_DATE, ssvc=ssvc, epss=epss) is ExploitationLevel.KEV

    @pytest.mark.parametrize("epss", [None, 0.0, 0.94, 0.95, 1.0])
    def test_ssvc_active_wins_over_poc_level_evidence(self, epss: float | None) -> None:
        assert _level(ssvc="active", epss=epss) is ExploitationLevel.ACTIVE

    @pytest.mark.parametrize("epss", [None, 0.0, 0.5])
    def test_ssvc_poc_is_likely(self, epss: float | None) -> None:
        assert _level(ssvc="poc", epss=epss) is ExploitationLevel.LIKELY

    def test_epss_threshold_is_the_specified_constant(self) -> None:
        assert EPSS_LIKELY_PERCENTILE_THRESHOLD == 0.95

    @pytest.mark.parametrize(
        ("percentile", "expected"),
        [
            (0.95, ExploitationLevel.LIKELY),
            (0.9500001, ExploitationLevel.LIKELY),
            (1.0, ExploitationLevel.LIKELY),
            (0.9499999, ExploitationLevel.UNKNOWN),
            (0.94, ExploitationLevel.UNKNOWN),
            (0.0, ExploitationLevel.UNKNOWN),
        ],
    )
    def test_epss_percentile_boundary(
        self, percentile: float, expected: ExploitationLevel
    ) -> None:
        assert _level(epss=percentile) is expected

    @pytest.mark.parametrize(
        "ssvc",
        ["none", "", "Active", "POC", "unknown", "total", "yes", " active"],
    )
    def test_other_ssvc_values_contribute_no_evidence(self, ssvc: str) -> None:
        assert classify_exploitation(
            kev_date_added=None, ssvc_exploitation=ssvc, epss_percentile=None
        ) == ExploitationClassification(level=ExploitationLevel.UNKNOWN, evidence=())

    def test_ssvc_none_with_high_epss_is_likely(self) -> None:
        assert _level(ssvc="none", epss=0.99) is ExploitationLevel.LIKELY

    def test_nan_percentile_is_not_evidence_and_does_not_raise(self) -> None:
        assert classify_exploitation(
            kev_date_added=None, ssvc_exploitation=None, epss_percentile=float("nan")
        ) == ExploitationClassification(level=ExploitationLevel.UNKNOWN, evidence=())

    def test_only_specified_inputs_exist(self) -> None:
        """The EPSS score, SSVC `automatable`/`technical_impact`, CWE, and every
        other CVE field cannot influence the result: they are not parameters."""
        parameters = inspect.signature(classify_exploitation).parameters

        assert list(parameters) == [
            "kev_date_added",
            "ssvc_exploitation",
            "epss_percentile",
        ]
        assert all(
            p.kind is inspect.Parameter.KEYWORD_ONLY for p in parameters.values()
        )


@pytest.mark.unit
class TestDecidingEvidence:
    """ticket-priority.md (Exploitation Level: deciding evidence;
    `classify_exploitation()`; Testing Requirement 10). Each case transcribes
    the specified level and its exact evidence, in the order KEV, SSVC,
    EPSS."""

    @pytest.mark.parametrize(
        ("kev", "ssvc", "epss", "level", "evidence"),
        [
            pytest.param(
                KEV_DATE, None, None, ExploitationLevel.KEV, (KEV,), id="kev-alone"
            ),
            pytest.param(
                KEV_DATE,
                "active",
                0.99,
                ExploitationLevel.KEV,
                (KEV,),
                id="kev-hides-active-and-epss",
            ),
            pytest.param(
                KEV_DATE,
                "poc",
                0.95,
                ExploitationLevel.KEV,
                (KEV,),
                id="kev-hides-poc-and-epss",
            ),
            pytest.param(
                None,
                "active",
                None,
                ExploitationLevel.ACTIVE,
                (SSVC_ACTIVE,),
                id="active-alone",
            ),
            pytest.param(
                None,
                "active",
                0.95,
                ExploitationLevel.ACTIVE,
                (SSVC_ACTIVE,),
                id="active-hides-epss",
            ),
            pytest.param(
                None,
                "poc",
                None,
                ExploitationLevel.LIKELY,
                (SSVC_POC,),
                id="poc-alone",
            ),
            pytest.param(
                None,
                "poc",
                0.94,
                ExploitationLevel.LIKELY,
                (SSVC_POC,),
                id="poc-with-epss-below",
            ),
            pytest.param(
                None,
                None,
                0.95,
                ExploitationLevel.LIKELY,
                (_epss(0.95),),
                id="epss-at-threshold",
            ),
            pytest.param(
                None,
                None,
                0.97,
                ExploitationLevel.LIKELY,
                (_epss(0.97),),
                id="epss-above",
            ),
            pytest.param(
                None,
                "none",
                0.97,
                ExploitationLevel.LIKELY,
                (_epss(0.97),),
                id="epss-with-ssvc-none",
            ),
            pytest.param(
                None,
                "poc",
                0.97,
                ExploitationLevel.LIKELY,
                (SSVC_POC, _epss(0.97)),
                id="poc-and-epss",
            ),
            pytest.param(
                None,
                None,
                0.9499999,
                ExploitationLevel.UNKNOWN,
                (),
                id="epss-just-below",
            ),
            pytest.param(
                None,
                "none",
                0.5,
                ExploitationLevel.UNKNOWN,
                (),
                id="ssvc-none-and-low-epss",
            ),
            pytest.param(
                None, None, None, ExploitationLevel.UNKNOWN, (), id="no-evidence"
            ),
        ],
    )
    def test_level_and_exact_evidence(
        self,
        kev: date | None,
        ssvc: str | None,
        epss: float | None,
        level: ExploitationLevel,
        evidence: tuple[ExploitationEvidence, ...],
    ) -> None:
        assert classify_exploitation(
            kev_date_added=kev, ssvc_exploitation=ssvc, epss_percentile=epss
        ) == ExploitationClassification(level=level, evidence=evidence)

    @pytest.mark.parametrize("kev", [None, KEV_DATE])
    @pytest.mark.parametrize("ssvc", [None, "none", "poc", "active", "other"])
    @pytest.mark.parametrize("epss", [None, 0.0, 0.9499999, 0.95, 1.0])
    def test_unknown_exactly_without_evidence(
        self, kev: date | None, ssvc: str | None, epss: float | None
    ) -> None:
        result = classify_exploitation(
            kev_date_added=kev, ssvc_exploitation=ssvc, epss_percentile=epss
        )

        assert (result.level is ExploitationLevel.UNKNOWN) == (result.evidence == ())

    def test_evidence_values_keep_their_persisted_types(self) -> None:
        kev = classify_exploitation(
            kev_date_added=KEV_DATE, ssvc_exploitation=None, epss_percentile=None
        ).evidence
        likely = classify_exploitation(
            kev_date_added=None, ssvc_exploitation="poc", epss_percentile=0.97
        ).evidence

        assert [(type(e.kind), type(e.value)) for e in (*kev, *likely)] == [
            (ExploitationEvidenceKind, date),
            (ExploitationEvidenceKind, str),
            (ExploitationEvidenceKind, float),
        ]


@pytest.mark.unit
class TestTicketPriorityModuleBoundary:
    def test_imports_only_core_enums_from_app(self) -> None:
        modules = imported_modules(
            APP_ROOT / "services" / "ticket_priority.py", "app.services"
        )

        assert {m for m in modules if m.startswith("app.")} == {"app.core.enums"}
        assert forbidden_imports(modules) == set()

    def test_public_functions_are_synchronous(self) -> None:
        assert not inspect.iscoroutinefunction(ticket_priority.classify_exploitation)
        assert not inspect.iscoroutinefunction(ticket_priority.resolve_priority)
