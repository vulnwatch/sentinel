"""Pure remediation due dates, per-track milestones, and the Ticket
current phase.

Single database-free formula owner for Ticket deadlines. See
`docs/features/tickets/ticket-deadlines.md` (SLA Tier, Phase Shares, Due
Dates, Evaluation Instant, Track Milestones, Ticket Current Phase, Pure
Resolution Functions) for the complete contract.

Every function is Category B: no database access, write, audit, lock, or
external call. Deadlines are informational only and are never persisted.
This module imports no other service module, so `ticket_service` and
`package_service` may both use it without a dependency cycle. Its SQL
twin, `app.services.ticket_deadline_expressions`, builds the equivalent
PostgreSQL expressions from the same public specification constants.

Time handling follows `docs/conventions.md` (Timestamps & Timezones):
naive datetimes are rejected with `ValueError`, and aware inputs are
converted to UTC before arithmetic. The conversion never changes the
instant; it makes every offset an exact elapsed duration (arithmetic on
a zone with daylight-saving transitions would otherwise shift wall-clock
time) and makes every due date a UTC value.
"""

from __future__ import annotations

from collections.abc import Callable, Collection, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from types import MappingProxyType
from typing import Final

from app.core.enums import (
    MANUAL_ZONE_TICKET_STATUSES,
    CurrentPhase,
    DeliveryStatus,
    IBSRequestState,
    MilestonePhase,
    MilestoneStatus,
    PackageStatus,
    Severity,
    TicketStatus,
    WorkflowType,
)

SLA_TIER_DAYS: Final[Mapping[Severity, int]] = MappingProxyType(
    {
        Severity.CRITICAL: 30,
        Severity.HIGH: 30,
        Severity.MEDIUM: 90,
        Severity.LOW: 180,
    }
)
"""SLA tier in days per resolved severity label. `Severity.NONE` has no SLA."""

UNRESOLVED_SLA_DAYS: Final = 30
"""SLA tier for an unresolved (SQL `NULL`) severity: the worst case."""

PHASE_SHARES: Final[Mapping[MilestonePhase, int]] = MappingProxyType(
    {
        MilestonePhase.TRIAGE: 10,
        MilestonePhase.SUBMISSION: 50,
        MilestonePhase.UM: 10,
        MilestonePhase.QA: 30,
    }
)
"""Integer percentage of the SLA window per phase, in phase order.

Invariants: every share is an integer of at least 1 and the shares sum to
exactly 100, so the QA milestone always equals the final release deadline.
"""

SECONDS_PER_DAY_PERCENT: Final = 864
"""Seconds in one percent of a day (86 400 / 100): the Formula's unit."""

_ONE_MICROSECOND: Final = timedelta(microseconds=1)

LATER_PHASE_APPLICABLE_STATUSES: Final = frozenset(
    {PackageStatus.ANALYSIS, PackageStatus.AFFECTED, PackageStatus.FIXED}
)
"""Track statuses under which `submission`, `um`, and `qa` can apply."""

SUBMITTED_DELIVERY_STATUSES: Final = frozenset(
    {DeliveryStatus.IN_PROGRESS, DeliveryStatus.RELEASED}
)
"""Track delivery statuses that are `submission` completion evidence."""

ACTIVE_RELEASE_REQUEST_STATES: Final = frozenset(
    {IBSRequestState.NEW, IBSRequestState.REVIEW, IBSRequestState.ACCEPTED}
)
"""`IBSRequest.state` values whose correlated `maintenance_release` action
is `um` completion evidence (Completion Evidence)."""

TRIAGE_OPEN_TICKET_STATUSES: Final = frozenset(
    {TicketStatus.NEW, TicketStatus.ANALYSIS}
)
"""Ticket statuses with the Ticket-level `triage` phase open (Ticket-Level
Overdue Filter; Ticket Current Phase, Open Phases)."""

CURRENT_PHASE_TICKET_STATUSES: Final[Mapping[CurrentPhase, frozenset[TicketStatus]]] = (
    MappingProxyType(
        {
            CurrentPhase.TRIAGE: TRIAGE_OPEN_TICKET_STATUSES,
            CurrentPhase.SUBMISSION: frozenset({TicketStatus.ANALYZED}),
            CurrentPhase.UM: frozenset({TicketStatus.ANALYZED}),
            CurrentPhase.QA: frozenset({TicketStatus.ANALYZED}),
            CurrentPhase.DONE: frozenset(
                {TicketStatus.ANALYZED, TicketStatus.RESOLVED}
            ),
        }
    )
)
"""The only Ticket statuses that can have each Ticket `current_phase` value,
as the Rules of Ticket Current Phase imply: `triage` comes from a `New` or
`Analysis` status, a `Resolved` Ticket is `done`, the manual zone has no
SLA, so only an `Analyzed` Ticket has a later phase. A filter may test the
status first, before the current phase reads any track."""

_PHASES: Final = tuple(MilestonePhase)
_OPEN_STATUSES: Final = frozenset({MilestoneStatus.PENDING, MilestoneStatus.OVERDUE})


def _require_aware(value: datetime, name: str) -> None:
    if value.utcoffset() is None:
        raise ValueError(f"{name} must be a timezone-aware datetime.")


@dataclass(frozen=True, slots=True)
class DueDates:
    """Ticket-level due dates (UTC) of one Ticket with an SLA.

    Service-internal typed value, not a Pydantic schema. `qa` always
    equals `release`, the final SLA deadline.
    """

    triage: datetime
    submission: datetime
    um: datetime
    qa: datetime
    release: datetime

    def __post_init__(self) -> None:
        for phase in (*_PHASES, "release"):
            _require_aware(getattr(self, phase), f"DueDates.{phase}")

    def for_phase(self, phase: MilestonePhase) -> datetime:
        """Due date of one milestone phase."""
        due_at: datetime = getattr(self, phase.value)
        return due_at


@dataclass(frozen=True, slots=True)
class TrackMilestones:
    """Milestone statuses and current phase of one track.

    Service-internal typed value. Python `None` represents the `null`
    status (no SLA, or the phase is not observable for the track) and the
    `null` current phase.
    """

    triage: MilestoneStatus | None
    submission: MilestoneStatus | None
    um: MilestoneStatus | None
    qa: MilestoneStatus | None
    current_phase: CurrentPhase | None

    def status_of(self, phase: MilestonePhase) -> MilestoneStatus | None:
        """Status of one milestone phase."""
        status: MilestoneStatus | None = getattr(self, phase.value)
        return status


@dataclass(frozen=True, slots=True)
class TicketCurrentPhase:
    """Current phase of one Ticket and the milestone status of that phase.

    Service-internal typed value. Python `None` represents the `null`
    current phase. `milestone` is `PENDING` or `OVERDUE`, or `None` when
    `phase` is `DONE` or `None`.
    """

    phase: CurrentPhase | None
    milestone: MilestoneStatus | None


def resolve_sla_days(severity: Severity | None) -> int | None:
    """Return the SLA tier in days for a resolved severity.

    `severity` is the resolved severity label; `None` means SQL `NULL`
    (unresolved) and selects `UNRESOLVED_SLA_DAYS`. The `Severity.NONE`
    label (resolved score exactly 0.0) has no SLA and returns `None`.
    Infallible.
    """
    if severity is None:
        return UNRESOLVED_SLA_DAYS
    return SLA_TIER_DAYS.get(severity)


def compute_due_dates(
    *,
    created_at: datetime,
    severity: Severity | None,
    ticket_status: TicketStatus,
    coordinated_release_at: datetime | None,
) -> DueDates | None:
    """Compute the Ticket-level due dates over the deadline window.

    Without a Coordinated Release Date (SLA window), each milestone is
    `created_at + d * 864 * c` seconds for SLA tier `d` days and
    cumulative phase share `c` percent, and `release` is `created_at + d`
    days: exact offsets that keep the time of day of `created_at`. With
    one (coordinated release window), each milestone is
    `created_at + floor(w * c / 100)` microseconds for the window length
    `w = coordinated_release_at - created_at` in whole microseconds, and
    `release` is `coordinated_release_at`; the tier then decides no date.
    Returns `None` when the Ticket is `Ignored` or `Duplicated`, or its
    resolved severity is the `Severity.NONE` label (SQL `NULL` uses the
    30-day tier or the CRD), with or without a CRD.

    Raises:
        ValueError: `created_at` or `coordinated_release_at` is naive, or
            `coordinated_release_at` is before `created_at` (validated
            for every input).
    """
    _require_aware(created_at, "created_at")
    if coordinated_release_at is not None:
        _require_aware(coordinated_release_at, "coordinated_release_at")
        if coordinated_release_at < created_at:
            raise ValueError("coordinated_release_at must not precede created_at.")
    sla_days = resolve_sla_days(severity)
    if ticket_status in MANUAL_ZONE_TICKET_STATUSES or sla_days is None:
        return None

    start = created_at.astimezone(UTC)
    if coordinated_release_at is not None:
        end = coordinated_release_at.astimezone(UTC)
        window_us = (end - start) // _ONE_MICROSECOND
        return _divide_window(
            start,
            lambda cumulative: timedelta(microseconds=window_us * cumulative // 100),
            release=end,
        )
    return _divide_window(
        start,
        lambda cumulative: timedelta(
            seconds=sla_days * SECONDS_PER_DAY_PERCENT * cumulative
        ),
        release=start + timedelta(days=sla_days),
    )


def _divide_window(
    start: datetime,
    offset: Callable[[int], timedelta],
    *,
    release: datetime,
) -> DueDates:
    """The milestones at `start + offset(cumulative share)`, in phase order."""
    due: dict[MilestonePhase, datetime] = {}
    cumulative = 0
    for phase in _PHASES:
        cumulative += PHASE_SHARES[phase]
        due[phase] = start + offset(cumulative)
    return DueDates(
        triage=due[MilestonePhase.TRIAGE],
        submission=due[MilestonePhase.SUBMISSION],
        um=due[MilestonePhase.UM],
        qa=due[MilestonePhase.QA],
        release=release,
    )


def resolve_track_milestones(
    *,
    due_dates: DueDates | None,
    ticket_has_cve: bool,
    workflow_type: WorkflowType,
    track_status: PackageStatus,
    track_actionable: bool,
    has_actionable_eligible_product: bool,
    all_actionable_eligible_released: bool,
    delivery_status: DeliveryStatus,
    has_active_release_request: bool,
    evaluation_instant: datetime,
) -> TrackMilestones:
    """Resolve the milestone statuses and current phase of one track.

    Rules, first match wins: (1) `due_dates is None` (no SLA) → every
    status and `current_phase` is `None`; (2) a non-actionable track →
    every status is `not_applicable` and `current_phase` is `done`;
    (3) otherwise `triage` is always evaluated, while `submission`, `um`,
    and `qa` are `None` when the Ticket has no CVE or the track is a Git
    track, and `not_applicable` unless the track status is `ANALYSIS`,
    `AFFECTED`, or `FIXED` with at least one actionable eligible Product.

    An evaluated phase is completed when it, or any later evaluated
    phase, has completion evidence: `triage` — track status is not
    `ANALYSIS`; `submission` — delivery is `IN_PROGRESS` or `RELEASED`;
    `um` — `has_active_release_request` or delivery is `RELEASED`; `qa` —
    `all_actionable_eligible_released` (meaningful only when
    `has_actionable_eligible_product`). A completed phase is `done`; a
    phase whose due date is strictly before `evaluation_instant` is
    `overdue`; otherwise it is `pending`.

    `current_phase` skips `done` and `not_applicable` phases in order; the
    first `pending` or `overdue` phase is current, a `None` status reached
    first yields `None`, and skipping every phase yields `done`.

    Raises:
        ValueError: `evaluation_instant` is naive (validated for every
            input).
    """
    _require_aware(evaluation_instant, "evaluation_instant")

    if due_dates is None:
        return TrackMilestones(
            triage=None, submission=None, um=None, qa=None, current_phase=None
        )

    if not track_actionable:
        na = MilestoneStatus.NOT_APPLICABLE
        return TrackMilestones(
            triage=na, submission=na, um=na, qa=na, current_phase=CurrentPhase.DONE
        )

    later_observable = ticket_has_cve and workflow_type != WorkflowType.GIT
    later_applicable = (
        track_status in LATER_PHASE_APPLICABLE_STATUSES
        and has_actionable_eligible_product
    )
    evidence: dict[MilestonePhase, bool] = {
        MilestonePhase.TRIAGE: track_status != PackageStatus.ANALYSIS,
        MilestonePhase.SUBMISSION: delivery_status in SUBMITTED_DELIVERY_STATUSES,
        MilestonePhase.UM: (
            has_active_release_request or delivery_status == DeliveryStatus.RELEASED
        ),
        MilestonePhase.QA: all_actionable_eligible_released,
    }

    # Phases fixed by observability/applicability; absent phases are evaluated.
    fixed: dict[MilestonePhase, MilestoneStatus | None] = {}
    for phase in _PHASES[1:]:
        if not later_observable:
            fixed[phase] = None
        elif not later_applicable:
            fixed[phase] = MilestoneStatus.NOT_APPLICABLE

    statuses: dict[MilestonePhase, MilestoneStatus | None] = {}
    later_evidence = False
    for phase in reversed(_PHASES):
        if phase in fixed:
            statuses[phase] = fixed[phase]
            continue
        later_evidence = later_evidence or evidence[phase]
        if later_evidence:
            statuses[phase] = MilestoneStatus.DONE
        elif due_dates.for_phase(phase) < evaluation_instant:
            statuses[phase] = MilestoneStatus.OVERDUE
        else:
            statuses[phase] = MilestoneStatus.PENDING

    return TrackMilestones(
        triage=statuses[MilestonePhase.TRIAGE],
        submission=statuses[MilestonePhase.SUBMISSION],
        um=statuses[MilestonePhase.UM],
        qa=statuses[MilestonePhase.QA],
        current_phase=_current_phase(statuses),
    )


def _current_phase(
    statuses: Mapping[MilestonePhase, MilestoneStatus | None],
) -> CurrentPhase | None:
    for phase in _PHASES:
        status = statuses[phase]
        if status is None:
            return None
        if status in (MilestoneStatus.PENDING, MilestoneStatus.OVERDUE):
            return CurrentPhase(phase.value)
    return CurrentPhase.DONE


def resolve_ticket_current_phase(
    *,
    due_dates: DueDates | None,
    ticket_status: TicketStatus,
    track_milestones: Collection[TrackMilestones],
    evaluation_instant: datetime,
) -> TicketCurrentPhase:
    """Resolve the current phase of a Ticket and its milestone status.

    `due_dates` is the Ticket's `compute_due_dates()` result and
    `track_milestones` the `resolve_track_milestones()` result of every
    track of the Ticket, computed from the same `due_dates` and
    `evaluation_instant` (empty without tracks). The caller supplies
    consistent inputs; they are not cross-checked.

    Rules, first match wins: (1) `due_dates is None` (no SLA) → `None`;
    (2) the first open phase: `triage` when `ticket_status` is `New` or
    `Analysis`, otherwise, for a Ticket that is not `Resolved`,
    `submission`, `um`, or `qa` when at least one track has that member
    `pending` or `overdue`; (3) `done` when the Ticket is `Resolved` or no
    track has a `None` member; (4) otherwise `None`. A `Resolved` Ticket
    is therefore `done` whatever its tracks report.

    The milestone of an open phase is `overdue` when the Ticket matches
    the `overdue` filter value of that phase (`triage`: its due date is
    strictly before `evaluation_instant`; a later phase: at least one
    track has it `overdue`), otherwise `pending`; it is `None` when the
    phase is `done` or `None`.

    Raises:
        ValueError: `evaluation_instant` is naive (validated for every
            input).
    """
    _require_aware(evaluation_instant, "evaluation_instant")

    if due_dates is None:
        return TicketCurrentPhase(phase=None, milestone=None)

    if ticket_status in TRIAGE_OPEN_TICKET_STATUSES:
        triage_overdue = due_dates.triage < evaluation_instant
        return TicketCurrentPhase(
            phase=CurrentPhase.TRIAGE,
            milestone=(
                MilestoneStatus.OVERDUE if triage_overdue else MilestoneStatus.PENDING
            ),
        )

    if ticket_status is TicketStatus.RESOLVED:
        return TicketCurrentPhase(phase=CurrentPhase.DONE, milestone=None)

    for phase in _PHASES[1:]:
        statuses = {milestones.status_of(phase) for milestones in track_milestones}
        if statuses & _OPEN_STATUSES:
            return TicketCurrentPhase(
                phase=CurrentPhase(phase.value),
                milestone=(
                    MilestoneStatus.OVERDUE
                    if MilestoneStatus.OVERDUE in statuses
                    else MilestoneStatus.PENDING
                ),
            )

    has_null_member = any(
        milestones.status_of(phase) is None
        for milestones in track_milestones
        for phase in _PHASES
    )
    if not has_null_member:
        return TicketCurrentPhase(phase=CurrentPhase.DONE, milestone=None)
    return TicketCurrentPhase(phase=None, milestone=None)
