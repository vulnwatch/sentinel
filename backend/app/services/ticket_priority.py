"""Pure Ticket priority resolution.

Single database-free formula owner for Ticket priority. See
`docs/features/tickets/ticket-priority.md` (Exploitation Level, Decision
Table, Pure Resolution Functions) for the complete contract.

Both functions are Category B: they perform no database access, write,
audit, lock, or external call, and they raise no exception for any value
of their declared input types. Callers select the resolved severity
(`CVE.severity` for a Ticket with a CVE, otherwise
`Ticket.severity_manual`) and read the persisted exploitation evidence;
a Ticket without a CVE passes no evidence and therefore uses the
`unknown` row. `refresh_priority_auto()` and the Ticket reads that
project the automatic priority basis share `classify_exploitation()`, so
the basis always states the level that selected `priority_auto`.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import date
from types import MappingProxyType
from typing import Final

from app.core.enums import (
    ExploitationEvidenceKind,
    ExploitationLevel,
    Severity,
    TicketPriority,
)

EPSS_LIKELY_PERCENTILE_THRESHOLD: Final = 0.95
"""EPSS percentile (inclusive) at or above which exploitation is `likely`.

A specification constant, not a setting. It compares the persisted
percentile, never the EPSS probability score.
"""

_SSVC_ACTIVE: Final = "active"
_SSVC_POC: Final = "poc"


@dataclass(frozen=True, slots=True)
class ExploitationEvidence:
    """One persisted input that decided an exploitation level.

    `value` is the persisted value of that input: the KEV `date_added`
    for `kev`, the SSVC `exploitation` (`active` or `poc`) for
    `ssvc_exploitation`, and the EPSS percentile for `epss_percentile`.
    """

    kind: ExploitationEvidenceKind
    value: date | str | float


@dataclass(frozen=True, slots=True)
class ExploitationClassification:
    """The exploitation level of a CVE and its deciding evidence, in the
    order KEV, SSVC, EPSS; `evidence` is empty for `unknown`."""

    level: ExploitationLevel
    evidence: tuple[ExploitationEvidence, ...]


_P1, _P2, _P3, _P4 = (
    TicketPriority.P1,
    TicketPriority.P2,
    TicketPriority.P3,
    TicketPriority.P4,
)


def _row(
    critical: TicketPriority,
    high: TicketPriority,
    medium: TicketPriority,
    low_or_none: TicketPriority,
    unresolved: TicketPriority | None,
) -> Mapping[Severity | None, TicketPriority | None]:
    return MappingProxyType(
        {
            Severity.CRITICAL: critical,
            Severity.HIGH: high,
            Severity.MEDIUM: medium,
            Severity.LOW: low_or_none,
            Severity.NONE: low_or_none,
            None: unresolved,
        }
    )


# Decision Table: exploitation level -> resolved severity (Python `None`
# meaning SQL `NULL`, distinct from `Severity.NONE`) -> automatic priority.
_DECISION_TABLE: Final[
    Mapping[ExploitationLevel, Mapping[Severity | None, TicketPriority | None]]
] = MappingProxyType(
    {
        ExploitationLevel.KEV: _row(_P1, _P1, _P1, _P1, _P1),
        ExploitationLevel.ACTIVE: _row(_P1, _P1, _P2, _P3, _P2),
        ExploitationLevel.LIKELY: _row(_P2, _P2, _P3, _P4, _P3),
        ExploitationLevel.UNKNOWN: _row(_P2, _P3, _P4, _P4, None),
    }
)


def classify_exploitation(
    *,
    kev_date_added: date | None,
    ssvc_exploitation: str | None,
    epss_percentile: float | None,
) -> ExploitationClassification:
    """Classify the persisted exploitation evidence of one CVE.

    `kev_date_added` is the persisted `CVEKEVEntry.date_added` or `None`
    when no entry exists; `ssvc_exploitation` is the persisted
    `CVESSVCAssessment.exploitation` or `None` when no assessment exists;
    `epss_percentile` is the persisted `CVEEPSSScore.percentile` or `None`
    when no score exists.

    The first matching level wins: `kev` when KEV-listed; `active` when
    SSVC exploitation is `active`; `likely` when SSVC exploitation is
    `poc` or the EPSS percentile is at least
    `EPSS_LIKELY_PERCENTILE_THRESHOLD`; otherwise `unknown`. Any other
    SSVC value (including `none`) contributes no evidence. The deciding
    evidence is the input that satisfies the selected level's condition
    (for `likely`, SSVC `poc` and a qualifying percentile, both when both
    hold); evidence that satisfies only a lower level is not listed.
    Infallible.
    """
    if kev_date_added is not None:
        return ExploitationClassification(
            level=ExploitationLevel.KEV,
            evidence=(
                ExploitationEvidence(ExploitationEvidenceKind.KEV, kev_date_added),
            ),
        )
    if ssvc_exploitation == _SSVC_ACTIVE:
        return ExploitationClassification(
            level=ExploitationLevel.ACTIVE,
            evidence=(
                ExploitationEvidence(
                    ExploitationEvidenceKind.SSVC_EXPLOITATION, ssvc_exploitation
                ),
            ),
        )
    evidence: list[ExploitationEvidence] = []
    if ssvc_exploitation == _SSVC_POC:
        evidence.append(
            ExploitationEvidence(
                ExploitationEvidenceKind.SSVC_EXPLOITATION, ssvc_exploitation
            )
        )
    if (
        epss_percentile is not None
        and epss_percentile >= EPSS_LIKELY_PERCENTILE_THRESHOLD
    ):
        evidence.append(
            ExploitationEvidence(
                ExploitationEvidenceKind.EPSS_PERCENTILE, epss_percentile
            )
        )
    if evidence:
        return ExploitationClassification(
            level=ExploitationLevel.LIKELY, evidence=tuple(evidence)
        )
    return ExploitationClassification(level=ExploitationLevel.UNKNOWN, evidence=())


def resolve_priority(
    severity: Severity | None,
    exploitation: ExploitationLevel,
) -> TicketPriority | None:
    """Return the Decision Table cell for a resolved severity and evidence.

    `severity` is the resolved severity label; `None` means SQL `NULL`
    (unresolved), distinct from the `Severity.NONE` label, which shares
    the `Low or None` column. Returns `None` (not yet prioritizable) only
    for unresolved severity with `unknown` exploitation. Infallible.
    """
    return _DECISION_TABLE[exploitation][severity]
