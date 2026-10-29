"""Unit tests for pure remediation deadlines, track milestones, and the
Ticket current phase (backend/app/services/ticket_deadlines.py).

Covers `docs/features/tickets/ticket-deadlines.md` (Testing Requirements
1-6, 13, and 14) at the pure-function level, driven by the shared matrices
in `tests/support/deadline_matrix.py` that the SQL/pure parity tests
(`test_ticket_deadline_expressions.py`, Requirements 10 and 15), the
package-tree projection test, and the Ticket list tests also consume. The
matrices describe persisted evidence; their oracle derives the boolean
inputs of `resolve_track_milestones()`.
Workflow-level parts of Requirements 3-4 (start immutability across real
mutations, manual-zone exit workflows) are proven by the service tests of
those workflows, Requirements 7-9 by the Ticket list and workbench tests,
and Requirement 12 by the Ticket detail, package-tree, and workbench API
tests; their pure analogues are asserted here.
"""

from __future__ import annotations

import dataclasses
import inspect
import itertools
from datetime import UTC, datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import pytest

from app.core.enums import (
    CurrentPhase,
    DeliveryStatus,
    MilestonePhase,
    MilestoneStatus,
    PackageStatus,
    Severity,
    TicketStatus,
    WorkflowType,
)
from app.services import ticket_deadlines
from app.services.ticket_deadlines import (
    PHASE_SHARES,
    SLA_TIER_DAYS,
    UNRESOLVED_SLA_DAYS,
    DueDates,
    TicketCurrentPhase,
    TrackMilestones,
    compute_due_dates,
    resolve_sla_days,
    resolve_ticket_current_phase,
    resolve_track_milestones,
)
from tests.support.deadline_matrix import (
    AFTER_ALL_DUE,
    AFTER_SUBMISSION_DUE,
    BEFORE_ANY_DUE,
    CREATED_AT,
    DEADLINE_CASES,
    TICKET_PHASE_CASES,
    DeadlineCase,
    TicketPhaseCase,
)
from tests.support.module_imports import (
    APP_ROOT,
    forbidden_imports,
    imported_modules,
)

_NON_MANUAL_STATUSES = [
    TicketStatus.NEW,
    TicketStatus.ANALYSIS,
    TicketStatus.ANALYZED,
    TicketStatus.RESOLVED,
]
_MANUAL_STATUSES = [TicketStatus.IGNORED, TicketStatus.DUPLICATED]
_SLA_SEVERITIES: list[Severity | None] = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    None,
]


def _due_tuple(due: DueDates | None) -> tuple[datetime, ...] | None:
    if due is None:
        return None
    return (due.triage, due.submission, due.um, due.qa, due.release)


def _milestone_tuple(
    result: TrackMilestones,
) -> tuple[tuple[MilestoneStatus | None, ...], CurrentPhase | None]:
    return (
        result.triage,
        result.submission,
        result.um,
        result.qa,
    ), result.current_phase


def _evaluate(case: DeadlineCase) -> TrackMilestones:
    due = compute_due_dates(**case.due_dates_kwargs())
    return resolve_track_milestones(due_dates=due, **case.milestone_kwargs())


def _milestones(**overrides: object) -> TrackMilestones:
    """Resolve milestones for a 30-day-tier track with overridable inputs."""
    arguments: dict[str, object] = {
        "due_dates": compute_due_dates(
            created_at=CREATED_AT,
            severity=Severity.HIGH,
            ticket_status=TicketStatus.ANALYSIS,
        ),
        "ticket_has_cve": True,
        "workflow_type": WorkflowType.IBS,
        "track_status": PackageStatus.AFFECTED,
        "track_actionable": True,
        "has_actionable_eligible_product": True,
        "all_actionable_eligible_released": False,
        "delivery_status": DeliveryStatus.PENDING,
        "has_active_release_request": False,
        "evaluation_instant": BEFORE_ANY_DUE,
    }
    arguments.update(overrides)
    return resolve_track_milestones(**arguments)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Constants (Requirement 1)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestPhaseShares:
    def test_shares_match_the_specification(self) -> None:
        assert dict(PHASE_SHARES) == {
            MilestonePhase.TRIAGE: 10,
            MilestonePhase.SUBMISSION: 50,
            MilestonePhase.UM: 10,
            MilestonePhase.QA: 30,
        }

    def test_every_share_is_an_integer_of_at_least_one(self) -> None:
        for share in PHASE_SHARES.values():
            assert type(share) is int
            assert share >= 1

    def test_shares_sum_to_exactly_one_hundred(self) -> None:
        assert sum(PHASE_SHARES.values()) == 100

    def test_shares_cover_every_phase_in_order(self) -> None:
        assert list(PHASE_SHARES) == list(MilestonePhase)
        assert [phase.value for phase in MilestonePhase] == [
            "triage",
            "submission",
            "um",
            "qa",
        ]

    def test_constants_are_immutable(self) -> None:
        with pytest.raises(TypeError):
            PHASE_SHARES[MilestonePhase.QA] = 1  # type: ignore[index]
        with pytest.raises(TypeError):
            SLA_TIER_DAYS[Severity.LOW] = 1  # type: ignore[index]


# ---------------------------------------------------------------------------
# SLA tier (Requirement 2)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestResolveSlaDays:
    @pytest.mark.parametrize(
        ("severity", "expected"),
        [
            (Severity.CRITICAL, 30),
            (Severity.HIGH, 30),
            (Severity.MEDIUM, 90),
            (Severity.LOW, 180),
            (Severity.NONE, None),
            (None, 30),
        ],
    )
    def test_tier_table(self, severity: Severity | None, expected: int | None) -> None:
        assert resolve_sla_days(severity) == expected

    def test_unresolved_tier_is_the_worst_case(self) -> None:
        assert UNRESOLVED_SLA_DAYS == min(SLA_TIER_DAYS.values()) == 30

    def test_none_label_is_distinct_from_sql_null(self) -> None:
        assert resolve_sla_days(Severity.NONE) is None
        assert resolve_sla_days(None) == 30


# ---------------------------------------------------------------------------
# Due dates (Requirements 1-4)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestComputeDueDatesMatrix:
    @pytest.mark.parametrize("case", DEADLINE_CASES, ids=lambda case: case.id)
    def test_matrix_due_dates(self, case: DeadlineCase) -> None:
        assert _due_tuple(compute_due_dates(**case.due_dates_kwargs())) == (
            case.expected_due_dates()
        )


@pytest.mark.unit
class TestComputeDueDates:
    @pytest.mark.parametrize(
        ("severity", "days"),
        [
            (Severity.CRITICAL, 30),
            (Severity.HIGH, 30),
            (Severity.MEDIUM, 90),
            (Severity.LOW, 180),
            (None, 30),
        ],
    )
    def test_exact_formula_offsets_in_seconds(
        self, severity: Severity | None, days: int
    ) -> None:
        due = compute_due_dates(
            created_at=CREATED_AT, severity=severity, ticket_status=TicketStatus.NEW
        )

        assert due is not None
        # due_at = created_at + d * 864 * c seconds (cumulative c: 10/60/70/100).
        assert due.triage - CREATED_AT == timedelta(seconds=days * 864 * 10)
        assert due.submission - CREATED_AT == timedelta(seconds=days * 864 * 60)
        assert due.um - CREATED_AT == timedelta(seconds=days * 864 * 70)
        assert due.qa - CREATED_AT == timedelta(seconds=days * 864 * 100)
        assert due.release - CREATED_AT == timedelta(days=days)

    @pytest.mark.parametrize("severity", _SLA_SEVERITIES)
    def test_qa_equals_release_for_every_tier(self, severity: Severity | None) -> None:
        due = compute_due_dates(
            created_at=CREATED_AT, severity=severity, ticket_status=TicketStatus.NEW
        )

        assert due is not None
        assert due.qa == due.release

    @pytest.mark.parametrize("severity", _SLA_SEVERITIES)
    def test_every_date_preserves_created_at_time_of_day(
        self, severity: Severity | None
    ) -> None:
        due = compute_due_dates(
            created_at=CREATED_AT,
            severity=severity,
            ticket_status=TicketStatus.ANALYSIS,
        )

        assert due is not None
        for value in _due_tuple(due) or ():
            assert value.timetz() == CREATED_AT.timetz()
            assert value.tzinfo is UTC

    @pytest.mark.parametrize("status", _MANUAL_STATUSES)
    @pytest.mark.parametrize("severity", [*Severity, None])
    def test_manual_zone_has_no_dates(
        self, status: TicketStatus, severity: Severity | None
    ) -> None:
        assert (
            compute_due_dates(
                created_at=CREATED_AT, severity=severity, ticket_status=status
            )
            is None
        )

    @pytest.mark.parametrize("status", _NON_MANUAL_STATUSES)
    def test_severity_none_label_has_no_dates_in_every_status(
        self, status: TicketStatus
    ) -> None:
        assert (
            compute_due_dates(
                created_at=CREATED_AT, severity=Severity.NONE, ticket_status=status
            )
            is None
        )

    @pytest.mark.parametrize("status", _NON_MANUAL_STATUSES)
    def test_dates_do_not_depend_on_non_manual_status(
        self, status: TicketStatus
    ) -> None:
        reference = compute_due_dates(
            created_at=CREATED_AT,
            severity=Severity.MEDIUM,
            ticket_status=TicketStatus.NEW,
        )

        assert (
            compute_due_dates(
                created_at=CREATED_AT, severity=Severity.MEDIUM, ticket_status=status
            )
            == reference
        )

    @pytest.mark.parametrize("status", _MANUAL_STATUSES)
    def test_dates_reappear_from_unchanged_start_after_manual_zone_exit(
        self, status: TicketStatus
    ) -> None:
        """Pure analogue of Requirement 4: the same `created_at` yields no
        dates in the manual zone and the original dates after exit."""
        before = compute_due_dates(
            created_at=CREATED_AT, severity=Severity.HIGH, ticket_status=status
        )
        after = compute_due_dates(
            created_at=CREATED_AT,
            severity=Severity.HIGH,
            ticket_status=TicketStatus.ANALYSIS,
        )

        assert before is None
        assert after is not None
        assert after.triage == CREATED_AT + timedelta(days=3)
        assert after.release == CREATED_AT + timedelta(days=30)

    def test_severity_change_moves_dates_but_never_the_start(self) -> None:
        """Pure analogue of Requirement 3: every date is anchored to the same
        `created_at`; only the tier changes."""
        high = compute_due_dates(
            created_at=CREATED_AT,
            severity=Severity.HIGH,
            ticket_status=TicketStatus.ANALYSIS,
        )
        low = compute_due_dates(
            created_at=CREATED_AT,
            severity=Severity.LOW,
            ticket_status=TicketStatus.ANALYSIS,
        )

        assert high is not None
        assert low is not None
        assert high.release - CREATED_AT == timedelta(days=30)
        assert low.release - CREATED_AT == timedelta(days=180)
        assert low.triage - CREATED_AT == timedelta(days=18)

    def test_signature_has_no_other_start_input(self) -> None:
        """The Coordinated Release Date and every mutation timestamp cannot
        move the start: `created_at` is the only time input."""
        parameters = inspect.signature(compute_due_dates).parameters

        assert list(parameters) == ["created_at", "severity", "ticket_status"]

    @pytest.mark.parametrize("status", [*_NON_MANUAL_STATUSES, *_MANUAL_STATUSES])
    def test_naive_created_at_raises_for_every_status(
        self, status: TicketStatus
    ) -> None:
        with pytest.raises(ValueError, match="created_at"):
            compute_due_dates(
                created_at=CREATED_AT.replace(tzinfo=None),
                severity=Severity.HIGH,
                ticket_status=status,
            )

    def test_naive_created_at_raises_with_severity_none_label(self) -> None:
        with pytest.raises(ValueError, match="created_at"):
            compute_due_dates(
                created_at=CREATED_AT.replace(tzinfo=None),
                severity=Severity.NONE,
                ticket_status=TicketStatus.NEW,
            )

    def test_aware_non_utc_start_yields_same_instants_in_utc(self) -> None:
        offset_start = CREATED_AT.astimezone(timezone(timedelta(hours=2)))

        due = compute_due_dates(
            created_at=offset_start,
            severity=Severity.HIGH,
            ticket_status=TicketStatus.NEW,
        )

        assert due is not None
        assert due.triage == CREATED_AT + timedelta(days=3)
        assert due.release == CREATED_AT + timedelta(days=30)
        assert all(value.tzinfo is UTC for value in _due_tuple(due) or ())

    def test_daylight_saving_transition_does_not_shift_offsets(self) -> None:
        """Offsets are elapsed durations: a start in a zone whose 30-day window
        crosses a DST change still ends exactly 2 592 000 seconds later."""
        start = datetime(2026, 3, 10, 14, 0, tzinfo=ZoneInfo("Europe/Rome"))

        due = compute_due_dates(
            created_at=start, severity=Severity.HIGH, ticket_status=TicketStatus.NEW
        )

        assert due is not None
        assert due.release.timestamp() - start.timestamp() == 30 * 86_400
        assert due.release == datetime(2026, 4, 9, 13, 0, tzinfo=UTC)


@pytest.mark.unit
class TestDueDatesValue:
    def test_is_frozen(self) -> None:
        due = compute_due_dates(
            created_at=CREATED_AT,
            severity=Severity.HIGH,
            ticket_status=TicketStatus.NEW,
        )

        assert due is not None
        with pytest.raises(dataclasses.FrozenInstanceError):
            due.triage = CREATED_AT  # type: ignore[misc]

    def test_naive_member_raises(self) -> None:
        naive = CREATED_AT.replace(tzinfo=None)

        with pytest.raises(ValueError, match=r"DueDates\.um"):
            DueDates(
                triage=CREATED_AT,
                submission=CREATED_AT,
                um=naive,
                qa=CREATED_AT,
                release=CREATED_AT,
            )

    def test_for_phase_returns_each_member(self) -> None:
        due = compute_due_dates(
            created_at=CREATED_AT,
            severity=Severity.HIGH,
            ticket_status=TicketStatus.NEW,
        )

        assert due is not None
        assert [due.for_phase(phase) for phase in MilestonePhase] == [
            due.triage,
            due.submission,
            due.um,
            due.qa,
        ]


# ---------------------------------------------------------------------------
# Track milestones and current phase (Requirements 5-6)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestResolveTrackMilestonesMatrix:
    @pytest.mark.parametrize("case", DEADLINE_CASES, ids=lambda case: case.id)
    def test_matrix_milestones(self, case: DeadlineCase) -> None:
        assert _milestone_tuple(_evaluate(case)) == (
            case.expected_statuses,
            case.expected_current_phase,
        )

    def test_matrix_covers_every_status_and_current_phase_outcome(self) -> None:
        statuses = {
            status for case in DEADLINE_CASES for status in case.expected_statuses
        }
        phases = {case.expected_current_phase for case in DEADLINE_CASES}

        assert statuses == {*MilestoneStatus, None}
        assert phases == {*CurrentPhase, None}

    def test_matrix_expectations_are_independent_of_the_module(self) -> None:
        """The shared matrix must never compute expectations with the code
        under test, or the later SQL/pure equivalence test becomes circular."""
        modules = imported_modules(
            APP_ROOT.parent / "tests" / "support" / "deadline_matrix.py",
            "tests.support",
        )

        assert {m for m in modules if m.startswith("app.")} == {"app.core.enums"}

    def test_matrix_case_ids_are_unique(self) -> None:
        ids = [case.id for case in DEADLINE_CASES]

        assert len(ids) == len(set(ids))


@pytest.mark.unit
class TestResolveTrackMilestones:
    def test_no_sla_ignores_every_other_input(self) -> None:
        for actionable, has_cve in itertools.product([True, False], repeat=2):
            result = _milestones(
                due_dates=None,
                track_actionable=actionable,
                ticket_has_cve=has_cve,
                evaluation_instant=AFTER_ALL_DUE,
            )

            assert _milestone_tuple(result) == ((None, None, None, None), None)

    @pytest.mark.parametrize("track_status", list(PackageStatus))
    @pytest.mark.parametrize("workflow_type", list(WorkflowType))
    def test_non_actionable_track_is_all_not_applicable(
        self, track_status: PackageStatus, workflow_type: WorkflowType
    ) -> None:
        result = _milestones(
            track_actionable=False,
            track_status=track_status,
            workflow_type=workflow_type,
            delivery_status=DeliveryStatus.RELEASED,
            all_actionable_eligible_released=True,
            evaluation_instant=AFTER_ALL_DUE,
        )

        na = MilestoneStatus.NOT_APPLICABLE
        assert _milestone_tuple(result) == ((na, na, na, na), CurrentPhase.DONE)

    def test_released_flag_is_ignored_without_actionable_eligible_product(self) -> None:
        result = _milestones(
            track_status=PackageStatus.AFFECTED,
            has_actionable_eligible_product=False,
            all_actionable_eligible_released=True,
        )

        assert result.qa is MilestoneStatus.NOT_APPLICABLE

    def test_naive_instant_raises(self) -> None:
        with pytest.raises(ValueError, match="evaluation_instant"):
            _milestones(evaluation_instant=BEFORE_ANY_DUE.replace(tzinfo=None))

    def test_naive_instant_raises_even_without_sla(self) -> None:
        with pytest.raises(ValueError, match="evaluation_instant"):
            _milestones(
                due_dates=None, evaluation_instant=BEFORE_ANY_DUE.replace(tzinfo=None)
            )

    def test_aware_non_utc_instant_compares_by_instant(self) -> None:
        triage_due = CREATED_AT + timedelta(days=3)
        plus_two = timezone(timedelta(hours=2))

        at_due = _milestones(
            track_status=PackageStatus.ANALYSIS,
            evaluation_instant=triage_due.astimezone(plus_two),
        )
        after_due = _milestones(
            track_status=PackageStatus.ANALYSIS,
            evaluation_instant=(triage_due + timedelta(seconds=1)).astimezone(plus_two),
        )

        assert at_due.triage is MilestoneStatus.PENDING
        assert after_due.triage is MilestoneStatus.OVERDUE

    def test_result_is_frozen_and_exposes_status_by_phase(self) -> None:
        result = _milestones(delivery_status=DeliveryStatus.IN_PROGRESS)

        with pytest.raises(dataclasses.FrozenInstanceError):
            result.qa = None  # type: ignore[misc]
        assert [result.status_of(phase) for phase in MilestonePhase] == [
            result.triage,
            result.submission,
            result.um,
            result.qa,
        ]


@pytest.mark.unit
class TestMilestoneInvariantsExhaustive:
    """Exhaustive invariants over every combination of the discrete inputs
    at several evaluation instants (independent of the matrix)."""

    @staticmethod
    def _combinations() -> list[dict[str, object]]:
        combos: list[dict[str, object]] = []
        for values in itertools.product(
            [True, False],  # ticket_has_cve
            list(WorkflowType),
            list(PackageStatus),
            [True, False],  # has_actionable_eligible_product
            [True, False],  # all_actionable_eligible_released
            list(DeliveryStatus),
            [True, False],  # has_active_release_request
            [BEFORE_ANY_DUE, CREATED_AT + timedelta(days=19), AFTER_ALL_DUE],
        ):
            combos.append(
                dict(
                    zip(
                        [
                            "ticket_has_cve",
                            "workflow_type",
                            "track_status",
                            "has_actionable_eligible_product",
                            "all_actionable_eligible_released",
                            "delivery_status",
                            "has_active_release_request",
                            "evaluation_instant",
                        ],
                        values,
                        strict=True,
                    )
                )
            )
        return combos

    def test_invariants_hold_for_every_actionable_combination(self) -> None:
        evaluated = {
            MilestoneStatus.DONE,
            MilestoneStatus.PENDING,
            MilestoneStatus.OVERDUE,
        }
        for combo in self._combinations():
            result = _milestones(**combo)
            statuses = [result.status_of(phase) for phase in MilestonePhase]
            later = statuses[1:]
            observable = (
                combo["ticket_has_cve"] and combo["workflow_type"] is WorkflowType.IBS
            )

            # Triage is always evaluated on an actionable track with an SLA.
            assert statuses[0] in evaluated
            # Later phases share one observability/applicability outcome.
            if not observable:
                assert later == [None, None, None]
            elif any(status is MilestoneStatus.NOT_APPLICABLE for status in later):
                assert later == [MilestoneStatus.NOT_APPLICABLE] * 3
            # Monotonicity: a done phase implies every earlier evaluated phase done.
            for index, status in enumerate(statuses):
                if status is MilestoneStatus.DONE:
                    assert all(
                        earlier is MilestoneStatus.DONE
                        for earlier in statuses[:index]
                        if earlier in evaluated
                    )
            # Current phase is the first pending/overdue phase, never a null skip.
            expected_current: CurrentPhase | None = CurrentPhase.DONE
            for phase, status in zip(MilestonePhase, statuses, strict=True):
                if status is None:
                    expected_current = None
                    break
                if status in (MilestoneStatus.PENDING, MilestoneStatus.OVERDUE):
                    expected_current = CurrentPhase(phase.value)
                    break
            assert result.current_phase == expected_current


# ---------------------------------------------------------------------------
# Ticket current phase (Requirements 13-14)
# ---------------------------------------------------------------------------

_P = MilestoneStatus.PENDING
_O = MilestoneStatus.OVERDUE
_D = MilestoneStatus.DONE
_NA = MilestoneStatus.NOT_APPLICABLE
_LATER_PHASES = (MilestonePhase.SUBMISSION, MilestonePhase.UM, MilestonePhase.QA)
_HIGH_DUE = compute_due_dates(
    created_at=CREATED_AT, severity=Severity.HIGH, ticket_status=TicketStatus.ANALYZED
)


def _ticket_phase(case: TicketPhaseCase) -> TicketCurrentPhase:
    """The pure Ticket current phase of a matrix case: due dates, then each
    track's milestones from its oracle-derived inputs."""
    due = compute_due_dates(**case.ticket_case().due_dates_kwargs())
    return resolve_ticket_current_phase(
        due_dates=due,
        ticket_status=case.ticket_status,
        track_milestones=[
            resolve_track_milestones(due_dates=due, **track.milestone_kwargs())
            for track in case.track_cases()
        ],
        evaluation_instant=case.evaluation_instant,
    )


def _track(
    triage: MilestoneStatus | None = _D,
    submission: MilestoneStatus | None = _D,
    um: MilestoneStatus | None = _D,
    qa: MilestoneStatus | None = _D,
) -> TrackMilestones:
    """Hand-built track milestones (their `current_phase` is not an input)."""
    return TrackMilestones(
        triage=triage, submission=submission, um=um, qa=qa, current_phase=None
    )


@pytest.mark.unit
class TestResolveTicketCurrentPhaseMatrix:
    @pytest.mark.parametrize("case", TICKET_PHASE_CASES, ids=lambda case: case.id)
    def test_matrix_ticket_current_phase(self, case: TicketPhaseCase) -> None:
        assert _ticket_phase(case) == TicketCurrentPhase(
            phase=case.expected_phase, milestone=case.expected_milestone
        )

    def test_matrix_covers_every_outcome_and_input_shape(self) -> None:
        cases = TICKET_PHASE_CASES
        outcomes = {(c.expected_phase, c.expected_milestone) for c in cases}

        assert {phase for phase, _ in outcomes} == {*CurrentPhase, None}
        for phase in MilestonePhase:
            milestones = {m for p, m in outcomes if p is CurrentPhase(phase.value)}
            assert milestones == {_P, _O}, phase
        assert {m for p, m in outcomes if p in (CurrentPhase.DONE, None)} == {None}
        assert {c.ticket_status for c in cases} == set(TicketStatus)
        assert {c.ticket_has_cve for c in cases} == {True, False}
        assert {c.severity for c in cases} >= {Severity.NONE, None}
        assert any(not c.tracks for c in cases)
        assert any(len(c.tracks) >= 3 for c in cases)

    def test_matrix_case_ids_are_unique(self) -> None:
        ids = [case.id for case in TICKET_PHASE_CASES]

        assert len(ids) == len(set(ids))


@pytest.mark.unit
class TestResolveTicketCurrentPhase:
    def test_no_sla_is_selected_by_due_dates_alone(self) -> None:
        """Rule 1 keys on `due_dates is None`; the function does not
        cross-check the status (ticket-deadlines.md,
        `resolve_ticket_current_phase()`)."""
        without_sla = resolve_ticket_current_phase(
            due_dates=None,
            ticket_status=TicketStatus.ANALYSIS,
            track_milestones=[_track(submission=_O)],
            evaluation_instant=AFTER_ALL_DUE,
        )
        manual_zone_with_dates = resolve_ticket_current_phase(
            due_dates=_HIGH_DUE,
            ticket_status=TicketStatus.IGNORED,
            track_milestones=[_track(submission=_O)],
            evaluation_instant=AFTER_ALL_DUE,
        )

        assert without_sla == TicketCurrentPhase(phase=None, milestone=None)
        assert manual_zone_with_dates == TicketCurrentPhase(
            phase=CurrentPhase.SUBMISSION, milestone=_O
        )

    @pytest.mark.parametrize("status", [TicketStatus.ANALYZED, TicketStatus.RESOLVED])
    def test_without_tracks_after_triage_is_done(self, status: TicketStatus) -> None:
        result = resolve_ticket_current_phase(
            due_dates=_HIGH_DUE,
            ticket_status=status,
            track_milestones=[],
            evaluation_instant=AFTER_ALL_DUE,
        )

        assert result == TicketCurrentPhase(phase=CurrentPhase.DONE, milestone=None)

    @pytest.mark.parametrize("status", [TicketStatus.NEW, TicketStatus.ANALYSIS])
    def test_triage_is_taken_from_the_ticket_status(self, status: TicketStatus) -> None:
        """A `New` or `Analysis` Ticket is in `triage` whatever its tracks
        report, including tracks whose triage is completed."""
        result = resolve_ticket_current_phase(
            due_dates=_HIGH_DUE,
            ticket_status=status,
            track_milestones=[_track(), _track(submission=_O, um=_O, qa=_O)],
            evaluation_instant=BEFORE_ANY_DUE,
        )

        assert result == TicketCurrentPhase(phase=CurrentPhase.TRIAGE, milestone=_P)

    def test_triage_milestone_compares_an_aware_non_utc_instant(self) -> None:
        triage_due = CREATED_AT + timedelta(days=3)
        plus_two = timezone(timedelta(hours=2))

        def milestone(instant: datetime) -> MilestoneStatus | None:
            return resolve_ticket_current_phase(
                due_dates=_HIGH_DUE,
                ticket_status=TicketStatus.NEW,
                track_milestones=[],
                evaluation_instant=instant,
            ).milestone

        assert milestone(triage_due.astimezone(plus_two)) is _P
        assert milestone((triage_due + timedelta(seconds=1)).astimezone(plus_two)) is _O

    def test_later_milestone_is_overdue_when_any_track_has_it_overdue(self) -> None:
        """One SLA gives every track the same dates; the rule is stated per
        track so that differing track dates keep the `overdue` match."""
        tracks = [_track(submission=_P), _track(submission=_O), _track(um=_O)]

        result = resolve_ticket_current_phase(
            due_dates=_HIGH_DUE,
            ticket_status=TicketStatus.ANALYZED,
            track_milestones=tracks,
            evaluation_instant=AFTER_SUBMISSION_DUE,
        )

        assert result == TicketCurrentPhase(phase=CurrentPhase.SUBMISSION, milestone=_O)

    def test_a_null_member_does_not_hold_back_and_blocks_done(self) -> None:
        unobservable = _track(submission=None, um=None, qa=None)

        open_elsewhere = resolve_ticket_current_phase(
            due_dates=_HIGH_DUE,
            ticket_status=TicketStatus.ANALYZED,
            track_milestones=[unobservable, _track(qa=_P)],
            evaluation_instant=BEFORE_ANY_DUE,
        )
        nothing_open = resolve_ticket_current_phase(
            due_dates=_HIGH_DUE,
            ticket_status=TicketStatus.ANALYZED,
            track_milestones=[unobservable, _track(), _track(_NA, _NA, _NA, _NA)],
            evaluation_instant=BEFORE_ANY_DUE,
        )

        assert open_elsewhere == TicketCurrentPhase(phase=CurrentPhase.QA, milestone=_P)
        assert nothing_open == TicketCurrentPhase(phase=None, milestone=None)

    def test_naive_instant_raises_for_every_input(self) -> None:
        for due in (_HIGH_DUE, None):
            with pytest.raises(ValueError, match="evaluation_instant"):
                resolve_ticket_current_phase(
                    due_dates=due,
                    ticket_status=TicketStatus.ANALYZED,
                    track_milestones=[],
                    evaluation_instant=BEFORE_ANY_DUE.replace(tzinfo=None),
                )

    def test_result_is_frozen(self) -> None:
        result = resolve_ticket_current_phase(
            due_dates=None,
            ticket_status=TicketStatus.NEW,
            track_milestones=[],
            evaluation_instant=BEFORE_ANY_DUE,
        )

        with pytest.raises(dataclasses.FrozenInstanceError):
            result.phase = CurrentPhase.DONE  # type: ignore[misc]


@pytest.mark.unit
class TestTicketCurrentPhaseInvariantsExhaustive:
    """Every pair of track milestones that a decided track can produce
    (independent of the matrix), for `Analyzed` and `Resolved` Tickets."""

    @staticmethod
    def _decided_track_milestones(instant: datetime) -> set[TrackMilestones]:
        # `Analyzed` and `Resolved` have no actionable `ANALYSIS` track
        # (tickets.md, Gate: Analysis -> Analyzed).
        results = {_milestones(track_actionable=False, evaluation_instant=instant)}
        for values in itertools.product(
            [True, False],  # ticket_has_cve
            list(WorkflowType),
            [s for s in PackageStatus if s is not PackageStatus.ANALYSIS],
            [True, False],  # has_actionable_eligible_product
            [True, False],  # all_actionable_eligible_released
            list(DeliveryStatus),
            [True, False],  # has_active_release_request
        ):
            names = (
                "ticket_has_cve",
                "workflow_type",
                "track_status",
                "has_actionable_eligible_product",
                "all_actionable_eligible_released",
                "delivery_status",
                "has_active_release_request",
            )
            arguments = dict(zip(names, values, strict=True))
            results.add(_milestones(**arguments, evaluation_instant=instant))
        return results

    @pytest.mark.parametrize(
        "instant", [BEFORE_ANY_DUE, AFTER_SUBMISSION_DUE, AFTER_ALL_DUE]
    )
    def test_invariants_hold_for_every_pair_of_tracks(self, instant: datetime) -> None:
        tracks = self._decided_track_milestones(instant)
        for pair in itertools.product(tracks, repeat=2):
            later_track_phases = [
                t.current_phase
                for t in pair
                if t.current_phase not in (CurrentPhase.DONE, None)
            ]
            for status in (TicketStatus.ANALYZED, TicketStatus.RESOLVED):
                result = resolve_ticket_current_phase(
                    due_dates=_HIGH_DUE,
                    ticket_status=status,
                    track_milestones=pair,
                    evaluation_instant=instant,
                )

                if later_track_phases:
                    # The earliest track current phase: an unobservable
                    # (`null`) track never holds the Ticket back.
                    order = list(CurrentPhase)
                    earliest = min(later_track_phases, key=order.index)
                    assert result.phase is earliest
                    phase = MilestonePhase(earliest.value)
                    statuses = {t.status_of(phase) for t in pair}
                    assert result.milestone is (_O if _O in statuses else _P)
                else:
                    assert result.milestone is None
                    unobservable = any(t.current_phase is None for t in pair)
                    expected = (
                        None
                        if unobservable and status is TicketStatus.ANALYZED
                        else CurrentPhase.DONE
                    )
                    assert result.phase is expected


# ---------------------------------------------------------------------------
# Module boundary
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestTicketDeadlinesModuleBoundary:
    def test_imports_no_other_service_module(self) -> None:
        modules = imported_modules(
            APP_ROOT / "services" / "ticket_deadlines.py", "app.services"
        )

        assert {m for m in modules if m.startswith("app.services")} == set()
        assert {m for m in modules if m.startswith("app.")} == {"app.core.enums"}

    def test_imports_no_model_settings_or_io(self) -> None:
        modules = imported_modules(
            APP_ROOT / "services" / "ticket_deadlines.py", "app.services"
        )

        assert forbidden_imports(modules) == set()

    def test_public_functions_are_synchronous(self) -> None:
        for function in (
            ticket_deadlines.resolve_sla_days,
            ticket_deadlines.compute_due_dates,
            ticket_deadlines.resolve_track_milestones,
            ticket_deadlines.resolve_ticket_current_phase,
        ):
            assert not inspect.iscoroutinefunction(function)
