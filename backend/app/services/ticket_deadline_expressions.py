"""Ticket due dates, track milestone statuses, the Ticket current phase,
and the current due date as reusable SQL expressions.

SQL twin of the pure functions in `app.services.ticket_deadlines`. See
`docs/features/tickets/ticket-deadlines.md` (SLA Tier, Phase Shares, Due
Dates, Evaluation Instant, Track Milestones, Ticket Current Phase, Current
Due Date, Read Ownership and Query Integration) for the complete contract.
Filtering, sorting, and counting by due dates, milestone statuses, the
Ticket current phase, and the current due date are evaluated in
PostgreSQL through these expressions, before pagination; for the same
inputs and evaluation instant they produce exactly the values of
`compute_due_dates()`, `resolve_track_milestones()`, and
`resolve_ticket_current_phase()`, and the date that the current-due-date
rule selects from them (proven by the SQL/pure parity tests over the
shared matrices of `tests/support/deadline_matrix.py`).

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
every offset is an exact number of seconds, or of hours and microseconds
for the coordinated release window, added to the `TIMESTAMPTZ` start
(never a calendar `day` interval), so neither the session
`TimeZone` nor a daylight-saving transition shifts a due date; the
evaluation instant is a bound timezone-aware parameter and a naive
instant is rejected.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import date, datetime
from typing import Any, Final, cast

from sqlalchemy import (
    BigInteger,
    ColumnElement,
    DateTime,
    Integer,
    Interval,
    Numeric,
    Select,
    and_,
    case,
    exists,
    extract,
    func,
    literal,
    literal_column,
    null,
    or_,
    select,
)
from sqlalchemy import cast as sql_cast
from sqlalchemy.orm import aliased
from sqlalchemy.orm.util import AliasedClass

from app.core.enums import (
    ACTIVE_TICKET_STATUSES,
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
_ONE_MICROSECOND: Final = literal_column("INTERVAL '1 microsecond'", Interval)
_SECONDS_PER_DAY: Final = SECONDS_PER_DAY_PERCENT * 100
_MICROSECONDS_PER_SECOND: Final = 1_000_000
_MICROSECONDS_PER_HOUR: Final = 3600 * _MICROSECONDS_PER_SECOND
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

    Each member is a nullable `TIMESTAMPTZ` expression over the Ticket's
    deadline window (the SLA window, or the coordinated release window
    when `coordinated_release_at` is set), NULL exactly when
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

    `ticket` and `severity` are as in `sla_days_expression()`. Every
    member is NULL when `sla_days_expression()` is NULL, with or without a
    Coordinated Release Date (ticket-deadlines.md, Null Due Dates).

    Without a CRD (SLA window, Formula), for SLA tier `d` and cumulative
    phase share `c`, each milestone is `ticket.created_at + d * 864 * c`
    seconds and `release` is `ticket.created_at + d * 86400` seconds:
    exact offsets that preserve the time of day of `created_at`.

    With `ticket.coordinated_release_at` set (Coordinated Release Window),
    each milestone is `ticket.created_at + floor(w * c / 100)`
    microseconds for the window length `w` in whole microseconds, and
    `release` is the CRD itself. The arithmetic is exact `numeric`
    integer arithmetic on the epoch microseconds, identical to the pure
    `compute_due_dates()`: `w` is never negative (the Ticket CHECK), so
    the truncating `div()` is the floor. The offset is added as whole
    hours (`make_interval()`, integer arithmetic) plus the remaining
    microseconds, so no `float8` factor exceeds its exact integer range
    and no step overflows for any CRD that the API accepts.

    Both windows add elapsed durations without a calendar `day` part, so
    neither the session `TimeZone` nor a daylight-saving transition
    shifts a due date. Raises no exception.
    """
    days = sla_days_expression(ticket=ticket, severity=severity)
    crd = ticket.coordinated_release_at
    window_us = (extract("epoch", crd) - extract("epoch", ticket.created_at)) * literal(
        _MICROSECONDS_PER_SECOND, Numeric
    )

    def sla_offset(seconds_per_tier_day: int) -> ColumnElement[datetime | None]:
        # NULL propagates from `days` through the multiplication and sum.
        return cast(
            ColumnElement[datetime | None],
            ticket.created_at + days * seconds_per_tier_day * _ONE_SECOND,
        )

    def crd_offset(cumulative: int) -> ColumnElement[datetime | None]:
        offset_us = func.div(window_us * cumulative, literal(100, Numeric))
        hours = func.div(offset_us, literal(_MICROSECONDS_PER_HOUR, Numeric))
        remainder_us = func.mod(offset_us, literal(_MICROSECONDS_PER_HOUR, Numeric))
        return cast(
            ColumnElement[datetime | None],
            ticket.created_at
            + func.make_interval(0, 0, 0, 0, sql_cast(hours, Integer))
            + sql_cast(remainder_us, BigInteger) * _ONE_MICROSECOND,
        )

    def due_at(
        sla: ColumnElement[datetime | None], window: ColumnElement[datetime | None]
    ) -> ColumnElement[datetime | None]:
        # Evaluated lazily: a Ticket without a CRD computes only `sla`.
        due: ColumnElement[datetime | None] = case(
            (crd.is_(None), sla), (days.is_(None), null()), else_=window
        )
        return due

    def milestone(phase: MilestonePhase) -> ColumnElement[datetime | None]:
        share = _CUMULATIVE_SHARES[phase]
        return due_at(sla_offset(SECONDS_PER_DAY_PERCENT * share), crd_offset(share))

    return TicketDueDateExpressions(
        triage=milestone(MilestonePhase.TRIAGE),
        submission=milestone(MilestonePhase.SUBMISSION),
        um=milestone(MilestonePhase.UM),
        qa=milestone(MilestonePhase.QA),
        release=due_at(
            sla_offset(_SECONDS_PER_DAY),
            cast(ColumnElement[datetime | None], crd),
        ),
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


def _actionable_eligible_products(
    evaluation_date: date,
    *,
    package: PackageEntity,
    track: TrackEntity,
    unreleased: bool = False,
) -> Select[uuid.UUID]:
    """The actionable Product occurrences of `track` with persisted
    `eligible = true` on `evaluation_date`, only those without
    `released_at` when `unreleased`; for an existence check."""
    occurrence = aliased(TicketPackageProduct)
    catalog = aliased(Product)
    statement = (
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
    if unreleased:
        statement = statement.where(occurrence.released_at.is_(None))
    return statement


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

    has_actionable_eligible = exists(
        _actionable_eligible_products(evaluation_date, package=package, track=track)
    )
    has_unreleased_actionable_eligible = exists(
        _actionable_eligible_products(
            evaluation_date, package=package, track=track, unreleased=True
        )
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
_INACTIVE_TICKET_STATUSES: Final = _sorted_values(
    set(TicketStatus) - set(ACTIVE_TICKET_STATUSES)
)


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
    *,
    evaluation_date: date,
    instant: ColumnElement[datetime],
    ticket: TicketEntity,
    package: PackageEntity,
    track: TrackEntity,
    due: TicketDueDateExpressions,
) -> ColumnElement[int]:
    """The per-track code of the earliest open later phase.

    For a Ticket with an SLA (the Ticket-level rule handles "no SLA"
    before the code is used), equal to the code of the track's three
    `track_milestone_status_expression()` statuses, from at most two
    existence checks instead of theirs (ticket-deadlines.md, Track
    Milestones):

    - an unobservable track (a Ticket without a CVE, or a Git track) has
      every later member `null` when it is actionable and
      `not_applicable` otherwise;
    - an observable track has a later phase open exactly when its status
      is applicable and it has an actionable eligible Product without
      `released_at`; otherwise its later members are `not_applicable` or,
      with `qa` evidence, all `done` (Monotonicity). Such a Product also
      makes the track actionable;
    - with `qa` open, the remaining evidence selects the earliest open
      phase: `qa` with `um` evidence (an active correlated release
      request or delivery `RELEASED`), `um` with only `submission`
      evidence left (delivery `IN_PROGRESS`), otherwise `submission`.

    An open phase yields its `overdue` code when its due date is strictly
    before `instant`, otherwise its `pending` code.
    """

    def open_code(phase: MilestonePhase) -> ColumnElement[int]:
        overdue_code, pending_code = _OPEN_PHASE_CODES[phase]
        code: ColumnElement[int] = case(
            (due.for_phase(phase) < instant, overdue_code), else_=pending_code
        )
        return code

    unobservable_code: ColumnElement[int] = case(
        (
            track_actionable_expression(evaluation_date, package=package, track=track),
            _NULL_MEMBER_CODE,
        ),
        else_=_NO_OPEN_PHASE_CODE,
    )
    code: ColumnElement[int] = case(
        (
            or_(
                ticket.cve_id.is_(None),
                track.workflow_type == WorkflowType.GIT.value,
            ),
            unobservable_code,
        ),
        (
            ~track.status.in_(_sorted_values(LATER_PHASE_APPLICABLE_STATUSES)),
            _NO_OPEN_PHASE_CODE,
        ),
        (
            ~exists(
                _actionable_eligible_products(
                    evaluation_date, package=package, track=track, unreleased=True
                )
            ),
            _NO_OPEN_PHASE_CODE,
        ),
        (
            or_(
                track.delivery_status == DeliveryStatus.RELEASED.value,
                active_release_request_exists(track=track),
            ),
            open_code(MilestonePhase.QA),
        ),
        (
            track.delivery_status.in_(_sorted_values(SUBMITTED_DELIVERY_STATUSES)),
            open_code(MilestonePhase.UM),
        ),
        else_=open_code(MilestonePhase.SUBMISSION),
    )
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
    `triage_due_at` is strictly before `evaluation_instant`; `done` for a
    `Resolved` Ticket; otherwise the earliest later phase that at least
    one track of the Ticket has `pending` or `overdue`, `overdue` when any
    track has it `overdue`; otherwise `done` when no track has a `null`
    member, else NULL. The milestone is NULL for `done` and NULL. Only an
    `Analyzed` Ticket reads its tracks, through one correlated scalar
    subquery that aggregates over them, so the expressions never multiply
    rows.

    Raises:
        ValueError: `evaluation_instant` is naive.
    """
    if evaluation_instant.utcoffset() is None:
        raise ValueError("evaluation_instant must be a timezone-aware datetime.")
    due = ticket_due_date_expressions(ticket=ticket) if due_dates is None else due_dates
    instant = literal(evaluation_instant, DateTime(timezone=True))

    package = aliased(TicketPackage)
    track = aliased(TicketPackageTrack)
    code = _track_phase_code(
        evaluation_date=evaluation_date,
        instant=instant,
        ticket=ticket,
        package=package,
        track=track,
        due=due,
    )
    earliest: ColumnElement[int | None] = (
        select(func.min(code))
        .select_from(track)
        .join(package, package.id == track.ticket_package_id)
        .where(package.ticket_id == ticket.id)
        .correlate(ticket)
        .scalar_subquery()
    )

    no_sla = due.triage.is_(None)
    triage_open = ticket.status.in_(_sorted_values(TRIAGE_OPEN_TICKET_STATUSES))
    resolved = ticket.status == TicketStatus.RESOLVED.value
    done = literal(CurrentPhase.DONE.value)
    overdue = literal(MilestoneStatus.OVERDUE.value)
    pending = literal(MilestoneStatus.PENDING.value)

    phase_by_code: dict[int, Any] = {_NULL_MEMBER_CODE: null()}
    milestone_by_code: dict[int, Any] = {}
    for phase, (overdue_code, pending_code) in _OPEN_PHASE_CODES.items():
        phase_by_code[overdue_code] = phase_by_code[pending_code] = phase.value
        milestone_by_code[overdue_code] = overdue
        milestone_by_code[pending_code] = pending

    # Each branch is evaluated only when the previous ones do not match, so
    # the tracks are read only for a Ticket outside these statuses.
    current_phase: ColumnElement[str | None] = case(
        (no_sla, null()),
        (triage_open, literal(CurrentPhase.TRIAGE.value)),
        (resolved, done),
        else_=case(phase_by_code, value=earliest, else_=done),
    )
    milestone: ColumnElement[str | None] = case(
        (no_sla, null()),
        (triage_open, case((due.triage < instant, overdue), else_=pending)),
        (resolved, null()),
        else_=case(milestone_by_code, value=earliest, else_=null()),
    )
    return TicketCurrentPhaseExpressions(phase=current_phase, milestone=milestone)


# ---------------------------------------------------------------------------
# Ticket current due date
# ---------------------------------------------------------------------------


def ticket_current_due_date_expression(
    *,
    current: TicketCurrentPhaseExpressions,
    due_dates: TicketDueDateExpressions,
    ticket: TicketEntity = Ticket,
) -> ColumnElement[datetime | None]:
    """Build the current due date of a Ticket (ticket-deadlines.md, Current
    Due Date).

    `current` and `due_dates` are the current-phase and due-date
    expressions of `ticket`, the `Ticket` entity or an alias of it, built
    for the response's one evaluation date and instant. Yields the due
    date of the current phase for `triage`, `submission`, `um`, and `qa`;
    `release` for a NULL current phase, which is itself NULL when no SLA
    applies; and NULL for `done`. An inactive Ticket yields NULL without
    evaluating its current phase or severity: a `Resolved` Ticket is
    `done`, and an `Ignored` or `Duplicated` one has no SLA. The current
    phase is rendered once. It has no pure twin: no response projects it,
    and the parity tests derive the expected date from
    `compute_due_dates()` and `resolve_ticket_current_phase()`. Raises no
    exception.
    """
    due_at_by_phase: dict[str, ColumnElement[datetime | None]] = {
        phase.value: due_dates.for_phase(phase) for phase in MilestonePhase
    }
    due_at_by_phase[_NULL_STATUS] = due_dates.release
    due_at: ColumnElement[datetime | None] = case(
        (ticket.status.in_(_INACTIVE_TICKET_STATUSES), null()),
        else_=case(
            due_at_by_phase,
            value=func.coalesce(current.phase, _NULL_STATUS),
            else_=null(),
        ),
    )
    return due_at
