"""Ticket due dates, track milestone statuses, and the Ticket current phase
as reusable SQL expressions.

SQL twin of the pure functions in `app.services.ticket_deadlines`. See
`docs/features/tickets/ticket-deadlines.md` (SLA Tier, Phase Shares, Due
Dates, Evaluation Instant, Track Milestones, Ticket Current Phase, Read
Ownership and Query Integration) for the complete contract. Filtering,
sorting, and counting by due dates, milestone statuses, and the Ticket
current phase are evaluated in PostgreSQL through these expressions,
before pagination; for the same inputs and evaluation instant they produce
exactly the values of `compute_due_dates()`, `resolve_track_milestones()`,
and `resolve_ticket_current_phase()` (proven by the SQL/pure parity tests
over the shared matrices of `tests/support/deadline_matrix.py`).

The expressions are built from the same specification constants as the
pure functions (tiers, shares, manual zone, applicable statuses, and
completion-evidence sets), the resolved-severity expression of
`app.services.ticket_severity`, and the actionability expressions of
`app.services.package_actionability`. Track and Product checks use
existence semantics, so they never multiply the rows of the enclosing
statement or inflate a count.

Every builder is Category B: it performs no I/O, write, audit, or lock,
and the expressions only read. Deadlines are informational only and are
never persisted. This module imports only Models, Core, and leaf service
modules, so `ticket_service` (Ticket list) and `package_service` (package
tree, maintainer workbench) can both use it without a dependency cycle.

Time handling follows `docs/conventions.md` (Timestamps & Timezones):
every offset is an exact number of seconds added to the `TIMESTAMPTZ`
start (never a calendar `day` interval), so neither the session
`TimeZone` nor a daylight-saving transition shifts a due date; the
evaluation instant is a bound timezone-aware parameter and a naive
instant is rejected.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import date, datetime
from typing import Any, Final, cast

from sqlalchemy import (
    ColumnElement,
    DateTime,
    Integer,
    Interval,
    and_,
    case,
    exists,
    func,
    literal,
    literal_column,
    null,
    or_,
    select,
)
from sqlalchemy.orm import aliased
from sqlalchemy.orm.util import AliasedClass

from app.core.enums import (
    MANUAL_ZONE_TICKET_STATUSES,
    CurrentPhase,
    DeliveryStatus,
    IBSRequestActionType,
    MilestonePhase,
    MilestoneStatus,
    Severity,
    TicketStatus,
    WorkflowType,
)
from app.models.ibs_request import IBSRequest
from app.models.ibs_request_action import IBSRequestAction
from app.models.ibs_request_action_track import IBSRequestActionTrack
from app.models.product import Product
from app.models.ticket import Ticket
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_product import TicketPackageProduct
from app.models.ticket_package_track import TicketPackageTrack
from app.services.package_actionability import (
    product_actionable_expression,
    track_actionable_expression,
)
from app.services.ticket_deadlines import (
    ACTIVE_RELEASE_REQUEST_STATES,
    LATER_PHASE_APPLICABLE_STATUSES,
    PHASE_SHARES,
    SECONDS_PER_DAY_PERCENT,
    SLA_TIER_DAYS,
    SUBMITTED_DELIVERY_STATUSES,
    TRIAGE_OPEN_TICKET_STATUSES,
    UNRESOLVED_SLA_DAYS,
)
from app.services.ticket_severity import resolved_severity_expression

type TicketEntity = type[Ticket] | AliasedClass[Ticket]
type PackageEntity = type[TicketPackage] | AliasedClass[TicketPackage]
type TrackEntity = type[TicketPackageTrack] | AliasedClass[TicketPackageTrack]

_ONE_SECOND: Final = literal_column("INTERVAL '1 second'", Interval)
_SECONDS_PER_DAY: Final = SECONDS_PER_DAY_PERCENT * 100
_LATER_PHASES: Final = (MilestonePhase.SUBMISSION, MilestonePhase.UM, MilestonePhase.QA)


def _cumulative_shares() -> dict[MilestonePhase, int]:
    cumulative = 0
    shares: dict[MilestonePhase, int] = {}
    for phase in MilestonePhase:
        cumulative += PHASE_SHARES[phase]
        shares[phase] = cumulative
    return shares


_CUMULATIVE_SHARES: Final = _cumulative_shares()


def _sorted_values(members: Iterable[str]) -> list[str]:
    """Stored enum values in a stable order (deterministic compiled SQL)."""
    return sorted(str(member) for member in members)


# ---------------------------------------------------------------------------
# Ticket-level due dates
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class TicketDueDateExpressions:
    """The five Ticket-level due-date expressions of one Ticket entity.

    Each member is a nullable `TIMESTAMPTZ` expression, NULL exactly when
    `compute_due_dates()` returns `None` (manual zone or the `None`
    severity label). Usable in `SELECT`, `WHERE`, and `ORDER BY`.
    """

    triage: ColumnElement[datetime | None]
    submission: ColumnElement[datetime | None]
    um: ColumnElement[datetime | None]
    qa: ColumnElement[datetime | None]
    release: ColumnElement[datetime | None]

    def for_phase(self, phase: MilestonePhase) -> ColumnElement[datetime | None]:
        """Due-date expression of one milestone phase."""
        due_at: ColumnElement[datetime | None] = getattr(self, phase.value)
        return due_at


def sla_days_expression(
    *,
    ticket: TicketEntity = Ticket,
    severity: ColumnElement[str | None] | None = None,
) -> ColumnElement[int | None]:
    """Build the SLA tier in days of `ticket`, NULL when it has no SLA.

    `ticket` is the `Ticket` entity or an alias of it in the enclosing
    statement. `severity` is the resolved-severity expression of that
    Ticket (`resolved_severity_expression(ticket)` when omitted); a caller
    that already selects it passes the same expression so severity is
    resolved once per Ticket. Yields NULL for a manual-zone status
    (`Ignored`, `Duplicated`) or the `None` severity label, the 30-day
    unresolved tier for SQL `NULL` severity, and otherwise the tier of
    `SLA_TIER_DAYS` (`resolve_sla_days()` combined with Null Due Dates).
    Raises no exception.
    """
    resolved = resolved_severity_expression(ticket) if severity is None else severity
    # Simple CASE on the resolved value: rendered once. SQL `NULL` matches
    # no WHEN and takes the unresolved tier; a label without a tier (the
    # `None` label) is NULL, as in `resolve_sla_days()`.
    tier_by_label: dict[str, int | None] = {
        label.value: SLA_TIER_DAYS.get(label) for label in Severity
    }
    days: ColumnElement[int | None] = case(
        (ticket.status.in_(_sorted_values(MANUAL_ZONE_TICKET_STATUSES)), null()),
        else_=case(
            tier_by_label,
            value=resolved,
            else_=literal(UNRESOLVED_SLA_DAYS, Integer),
        ),
    )
    return days


def ticket_due_date_expressions(
    *,
    ticket: TicketEntity = Ticket,
    severity: ColumnElement[str | None] | None = None,
) -> TicketDueDateExpressions:
    """Build the five Ticket-level due-date expressions of `ticket`.

    `ticket` and `severity` are as in `sla_days_expression()`. For SLA
    tier `d` and cumulative phase share `c`, each milestone is
    `ticket.created_at + d * 864 * c` seconds and `release` is
    `ticket.created_at + d * 86400` seconds (ticket-deadlines.md,
    Formula): exact offsets that preserve the time of day of `created_at`
    and are independent of the session `TimeZone`. Every member is NULL
    when `sla_days_expression()` is NULL. Raises no exception.
    """
    days = sla_days_expression(ticket=ticket, severity=severity)

    def offset(seconds_per_tier_day: int) -> ColumnElement[datetime | None]:
        # NULL propagates from `days` through the multiplication and sum.
        return cast(
            ColumnElement[datetime | None],
            ticket.created_at + days * seconds_per_tier_day * _ONE_SECOND,
        )

    shares = _CUMULATIVE_SHARES
    return TicketDueDateExpressions(
        triage=offset(SECONDS_PER_DAY_PERCENT * shares[MilestonePhase.TRIAGE]),
        submission=offset(SECONDS_PER_DAY_PERCENT * shares[MilestonePhase.SUBMISSION]),
        um=offset(SECONDS_PER_DAY_PERCENT * shares[MilestonePhase.UM]),
        qa=offset(SECONDS_PER_DAY_PERCENT * shares[MilestonePhase.QA]),
        release=offset(_SECONDS_PER_DAY),
    )


# ---------------------------------------------------------------------------
# Track milestone evidence and statuses
# ---------------------------------------------------------------------------


def active_release_request_exists(
    *, track: TrackEntity = TicketPackageTrack
) -> ColumnElement[bool]:
    """Build the correlated `um` release-request evidence of `track`.

    True exactly when an `IBSRequestActionTrack` correlates `track` to a
    `maintenance_release` action whose `IBSRequest.state` is in
    `ACTIVE_RELEASE_REQUEST_STATES` (`new`, `review`, `accepted`). Uses
    existence semantics over the persisted evidence; it never writes or
    reconciles it. Raises no exception.
    """
    return exists(
        select(IBSRequestActionTrack.id)
        .join(
            IBSRequestAction,
            IBSRequestAction.id == IBSRequestActionTrack.ibs_request_action_id,
        )
        .join(IBSRequest, IBSRequest.id == IBSRequestAction.ibs_request_id)
        .where(
            IBSRequestActionTrack.ticket_package_track_id == track.id,
            IBSRequestAction.action_type
            == IBSRequestActionType.MAINTENANCE_RELEASE.value,
            IBSRequest.state.in_(_sorted_values(ACTIVE_RELEASE_REQUEST_STATES)),
        )
        .correlate_except(IBSRequestActionTrack, IBSRequestAction, IBSRequest)
    )


def track_milestone_status_expression(
    phase: MilestonePhase,
    *,
    evaluation_date: date,
    evaluation_instant: datetime,
    ticket: TicketEntity = Ticket,
    package: PackageEntity = TicketPackage,
    track: TrackEntity = TicketPackageTrack,
    due_dates: TicketDueDateExpressions | None = None,
) -> ColumnElement[str | None]:
    """Build the `submission`, `um`, or `qa` milestone status of a track.

    `track` is a `TicketPackageTrack` entity or alias of the enclosing
    statement, `package` its parent package, and `ticket` the package's
    Ticket; the enclosing statement joins or correlates them.
    `evaluation_date` is the one UTC date of the response, used for
    actionability; `evaluation_instant` the one timezone-aware instant of
    the response, bound as a parameter for the past-due comparison.
    `due_dates` are the Ticket's due-date expressions
    (`ticket_due_date_expressions(ticket=ticket)` when omitted); a caller
    that already selects them passes the same object.

    Yields the `MilestoneStatus` value or NULL by the first matching rule
    of ticket-deadlines.md (Track Milestones), identically to
    `resolve_track_milestones()`: NULL when no SLA applies (the phase's due
    date is NULL); `not_applicable` for a non-actionable track
    (`track_actionable_expression()`); NULL when the Ticket has no CVE or
    the track is a Git track; `not_applicable` unless the track status is
    `ANALYSIS`, `AFFECTED`, or `FIXED` and at least one actionable Product
    of the track has persisted `eligible = true`. Otherwise the phase is
    `done` when it or a later phase has completion evidence (`submission`:
    delivery `IN_PROGRESS` or `RELEASED`; `um`: an active correlated
    release request or delivery `RELEASED`; `qa`: no actionable eligible
    Product has `released_at IS NULL`), `overdue` when its due date is
    strictly before `evaluation_instant`, and `pending` otherwise.

    Raises:
        ValueError: `phase` is `triage` (the Ticket-level `overdue=triage`
            filter uses Ticket status, not a track milestone), or
            `evaluation_instant` is naive.
    """
    if phase not in _LATER_PHASES:
        raise ValueError(
            "Only the submission, um, and qa track milestones have an SQL form."
        )
    if evaluation_instant.utcoffset() is None:
        raise ValueError("evaluation_instant must be a timezone-aware datetime.")
    due = ticket_due_date_expressions(ticket=ticket) if due_dates is None else due_dates
    instant = literal(evaluation_instant, DateTime(timezone=True))

    occurrence = aliased(TicketPackageProduct)
    catalog = aliased(Product)
    actionable_eligible = (
        select(occurrence.id)
        .join(catalog, catalog.id == occurrence.product_id)
        .where(
            occurrence.ticket_package_track_id == track.id,
            occurrence.eligible.is_(True),
            product_actionable_expression(
                evaluation_date,
                package=package,
                track=track,
                product=occurrence,
                catalog_product=catalog,
            ),
        )
        .correlate_except(occurrence, catalog)
    )
    has_actionable_eligible = exists(actionable_eligible)
    has_unreleased_actionable_eligible = exists(
        actionable_eligible.where(occurrence.released_at.is_(None))
    )

    released = track.delivery_status == DeliveryStatus.RELEASED.value
    evidence: dict[MilestonePhase, ColumnElement[bool]] = {
        MilestonePhase.SUBMISSION: track.delivery_status.in_(
            _sorted_values(SUBMITTED_DELIVERY_STATUSES)
        ),
        MilestonePhase.UM: or_(active_release_request_exists(track=track), released),
        MilestonePhase.QA: ~has_unreleased_actionable_eligible,
    }
    completed = or_(*(evidence[p] for p in _LATER_PHASES[_LATER_PHASES.index(phase) :]))
    due_at = due.for_phase(phase)

    status: ColumnElement[str | None] = case(
        (due_at.is_(None), null()),
        (
            ~track_actionable_expression(evaluation_date, package=package, track=track),
            literal(MilestoneStatus.NOT_APPLICABLE.value),
        ),
        (
            or_(
                ticket.cve_id.is_(None),
                track.workflow_type == WorkflowType.GIT.value,
            ),
            null(),
        ),
        (
            ~and_(
                track.status.in_(_sorted_values(LATER_PHASE_APPLICABLE_STATUSES)),
                has_actionable_eligible,
            ),
            literal(MilestoneStatus.NOT_APPLICABLE.value),
        ),
        (completed, literal(MilestoneStatus.DONE.value)),
        (due_at < instant, literal(MilestoneStatus.OVERDUE.value)),
        else_=literal(MilestoneStatus.PENDING.value),
    )
    return status


# ---------------------------------------------------------------------------
# Ticket current phase
# ---------------------------------------------------------------------------

# Per-track code of the earliest open later phase: `(overdue, pending)` per
# phase, ascending in phase order with `overdue` first, so the minimum over
# the tracks of a Ticket is its earliest open later phase and, for that
# phase, `overdue` when any track has it overdue. Then the marker of a track
# with a `null` member, then a track without an open later phase.
_OPEN_PHASE_CODES: Final[dict[MilestonePhase, tuple[int, int]]] = {
    phase: (2 * index, 2 * index + 1)
    for index, phase in enumerate(_LATER_PHASES, start=1)
}
_NULL_MEMBER_CODE: Final = 2 * len(_LATER_PHASES) + 2
_NO_OPEN_PHASE_CODE: Final = _NULL_MEMBER_CODE + 1
_NULL_STATUS: Final = ""
"""Stand-in for a `null` milestone status in a simple `CASE` (no status value)."""


@dataclass(frozen=True, slots=True)
class TicketCurrentPhaseExpressions:
    """The Ticket `current_phase` and `current_phase_milestone` expressions
    of one Ticket entity.

    `phase` yields a `CurrentPhase` value or NULL; `milestone` yields
    `pending`, `overdue`, or NULL. Usable in `SELECT` and `WHERE`.
    """

    phase: ColumnElement[str | None]
    milestone: ColumnElement[str | None]


def _track_phase_code(
    statuses: dict[MilestonePhase, ColumnElement[str | None]],
) -> ColumnElement[int]:
    """The per-track code of the earliest open later phase.

    Renders each milestone expression once. On a Ticket with an SLA a
    track's later members are either all observable or all `null`
    (Observability of Later Phases), so a `null` `submission` member marks
    the track's `null` members; the Ticket-level rule handles "no SLA"
    before the code is used.
    """
    code: ColumnElement[int] = literal(_NO_OPEN_PHASE_CODE, Integer)
    for phase in reversed(_LATER_PHASES):
        overdue_code, pending_code = _OPEN_PHASE_CODES[phase]
        whens: dict[str, int] = {
            MilestoneStatus.OVERDUE.value: overdue_code,
            MilestoneStatus.PENDING.value: pending_code,
        }
        value = statuses[phase]
        if phase is MilestonePhase.SUBMISSION:
            whens[_NULL_STATUS] = _NULL_MEMBER_CODE
            value = func.coalesce(value, _NULL_STATUS)
        code = case(whens, value=value, else_=code)
    return code


def ticket_current_phase_expressions(
    *,
    evaluation_date: date,
    evaluation_instant: datetime,
    ticket: TicketEntity = Ticket,
    due_dates: TicketDueDateExpressions | None = None,
) -> TicketCurrentPhaseExpressions:
    """Build the Ticket `current_phase` and `current_phase_milestone`.

    `ticket` is the `Ticket` entity or an alias of it in the enclosing
    statement; the expressions correlate to it. `evaluation_date` and
    `evaluation_instant` are the one UTC date and timezone-aware instant
    of the response, as in `track_milestone_status_expression()`.
    `due_dates` are the Ticket's due-date expressions
    (`ticket_due_date_expressions(ticket=ticket)` when omitted).

    Yields, identically to `resolve_ticket_current_phase()`
    (ticket-deadlines.md, Ticket Current Phase): NULL when no SLA applies;
    `triage` for a `New` or `Analysis` Ticket, `overdue` when
    `triage_due_at` is strictly before `evaluation_instant`; otherwise the
    earliest later phase that at least one track of the Ticket has
    `pending` or `overdue`, `overdue` when any track has it `overdue`;
    otherwise `done` when the Ticket is `Resolved` or no track has a
    `null` member, else NULL. The milestone is NULL for `done` and NULL.
    The tracks are read through one correlated scalar subquery that
    aggregates over them, so the expressions never multiply rows.

    Raises:
        ValueError: `evaluation_instant` is naive.
    """
    if evaluation_instant.utcoffset() is None:
        raise ValueError("evaluation_instant must be a timezone-aware datetime.")
    due = ticket_due_date_expressions(ticket=ticket) if due_dates is None else due_dates
    instant = literal(evaluation_instant, DateTime(timezone=True))

    package = aliased(TicketPackage)
    track = aliased(TicketPackageTrack)
    statuses = {
        phase: track_milestone_status_expression(
            phase,
            evaluation_date=evaluation_date,
            evaluation_instant=evaluation_instant,
            ticket=ticket,
            package=package,
            track=track,
            due_dates=due,
        )
        for phase in _LATER_PHASES
    }
    earliest: ColumnElement[int | None] = (
        select(func.min(_track_phase_code(statuses)))
        .select_from(track)
        .join(package, package.id == track.ticket_package_id)
        .where(package.ticket_id == ticket.id)
        .correlate(ticket)
        .scalar_subquery()
    )

    no_sla = due.triage.is_(None)
    triage_open = ticket.status.in_(_sorted_values(TRIAGE_OPEN_TICKET_STATUSES))
    done = literal(CurrentPhase.DONE.value)
    overdue = literal(MilestoneStatus.OVERDUE.value)
    pending = literal(MilestoneStatus.PENDING.value)

    phase_by_code: dict[int, Any] = {}
    milestone_by_code: dict[int, Any] = {}
    for phase, (overdue_code, pending_code) in _OPEN_PHASE_CODES.items():
        phase_by_code[overdue_code] = phase_by_code[pending_code] = phase.value
        milestone_by_code[overdue_code] = overdue
        milestone_by_code[pending_code] = pending
    phase_by_code[_NULL_MEMBER_CODE] = case(
        (ticket.status == TicketStatus.RESOLVED.value, done), else_=null()
    )

    current_phase: ColumnElement[str | None] = case(
        (no_sla, null()),
        (triage_open, literal(CurrentPhase.TRIAGE.value)),
        else_=case(phase_by_code, value=earliest, else_=done),
    )
    milestone: ColumnElement[str | None] = case(
        (no_sla, null()),
        (triage_open, case((due.triage < instant, overdue), else_=pending)),
        else_=case(milestone_by_code, value=earliest, else_=null()),
    )
    return TicketCurrentPhaseExpressions(phase=current_phase, milestone=milestone)
