"""Unit tests for fetcher cron schedules (backend/app/core/cron.py).

Covers `docs/features/platform/fetcher-operations.md` (Update Fetcher
Config, Validation rules) and `docs/features/platform/fetcher-infrastructure.md`
(Import-time validation, rule 11; Scheduled Run Expiry): a schedule is valid
only when it parses and fires, and its shortest interval is exact under
Celery's `crontab` semantics.
"""

from __future__ import annotations

from datetime import UTC, datetime
from itertools import pairwise

import pytest
from celery.schedules import ParseException, crontab

from app.core.cron import parse_schedule, shortest_interval_seconds

_DAY = 86400


def _celery_shortest_gap(expression: str, *, start: datetime, count: int) -> int:
    """Shortest gap in seconds between `count` consecutive occurrences
    of `expression` after `start`, as Celery's own scheduler computes
    each next occurrence (`remaining_estimate` with `now` pinned to the
    previous occurrence). An independent oracle for the day semantics:
    the minimum over a window can only equal the exact interval when the
    window contains the shortest gap, which each caller's window does."""
    schedule = crontab.from_string(expression)
    occurrences: list[datetime] = []
    current = start
    for _ in range(count):
        schedule.nowfun = lambda pinned=current: pinned
        current = current + schedule.remaining_estimate(current)
        occurrences.append(current)
    return min(
        int((later - earlier).total_seconds())
        for earlier, later in pairwise(occurrences)
    )


@pytest.mark.unit
class TestParseSchedule:
    def test_valid_schedule_returns_the_parsed_crontab(self) -> None:
        assert parse_schedule("0 */6 * * *") == crontab.from_string("0 */6 * * *")

    @pytest.mark.parametrize(
        "expression",
        [
            # 29 February: every four years.
            "0 0 29 2 *",
            # Friday the 13th: Celery combines the day of the month and the
            # day of the week with AND.
            "0 0 13 * 5",
            # 29 February on a Monday: 12 years apart at the closest.
            "0 0 29 2 1",
            # The 31st: only in the months that have one.
            "0 0 31 * *",
        ],
    )
    def test_irregular_schedule_that_fires_is_accepted(self, expression: str) -> None:
        assert parse_schedule(expression) == crontab.from_string(expression)

    @pytest.mark.parametrize(
        "expression",
        [
            "0 0 31 2 *",
            "0 0 30 2 *",
            "0 0 30,31 2 *",
            "0 0 31 4,6,9,11 *",
            # A day of the week cannot add a day: Celery uses AND.
            "0 0 31 4 1",
        ],
    )
    def test_schedule_without_occurrence_raises_value_error(
        self, expression: str
    ) -> None:
        with pytest.raises(ValueError, match=r"^Schedule has no occurrence$"):
            parse_schedule(expression)

    @pytest.mark.parametrize(
        ("expression", "message"),
        [
            # The unpacking messages come from Python's tuple unpacking of
            # the five fields inside `crontab.from_string`, the range
            # message from Celery.
            ("not a cron", "not enough values to unpack"),
            ("0 */6 * *", "not enough values to unpack"),
            ("* * * * * *", "too many values to unpack"),
            ("60 * * * *", "Invalid end range"),
        ],
    )
    def test_invalid_syntax_raises_value_error(
        self, expression: str, message: str
    ) -> None:
        with pytest.raises(ValueError, match=message):
            parse_schedule(expression)

    @pytest.mark.parametrize(
        ("expression", "message"),
        [
            (", * * * *", "empty part"),
            ("*/ * * * *", "empty filter"),
            ("1,,2 * * * *", "empty part"),
            ("-1 * * * *", "negative numbers not supported"),
        ],
        ids=["empty-part", "empty-step", "empty-list-item", "negative"],
    )
    def test_parse_exception_is_raised_as_value_error(
        self, expression: str, message: str
    ) -> None:
        """Celery raises `ParseException`, which is not a `ValueError`, for
        these expressions; a caller that handles `ValueError`, such as a
        Pydantic validator, would let it escape."""
        with pytest.raises(ValueError, match=message) as caught:
            parse_schedule(expression)

        assert isinstance(caught.value.__cause__, ParseException)


@pytest.mark.unit
class TestShortestIntervalSeconds:
    """`shortest_interval_seconds`: the shortest interval between two
    consecutive occurrences (fetcher-infrastructure.md, Scheduled Run
    Expiry)."""

    @pytest.mark.parametrize(
        ("expression", "expected"),
        [
            ("0 * * * *", 3600),
            # Every three hours: 3 h within a day and from 21:00 to 00:00.
            ("0 */3 * * *", 10800),
            ("0 */6 * * *", 21600),
            ("0 14 * * *", _DAY),
            # Weekdays: Monday to Tuesday is the shortest gap.
            ("0 3 * * 1-5", _DAY),
            # Weekly: one day of the week wraps around to itself.
            ("0 3 * * 0", 7 * _DAY),
            # Minutes 0, 7, ..., 56: from minute 56 to minute 0 is 4 min.
            ("*/7 * * * *", 240),
            # Working hours twice an hour: 30 min.
            ("0,30 9-17 * * 1-5", 1800),
            ("* * * * *", 60),
            # Restricted day of the month, every month: days 1 to 5.
            ("0 0 1-5 * *", _DAY),
            # Monthly: 1 February to 1 March of a common year.
            ("0 0 1 * *", 28 * _DAY),
            # Once a year: 365 days in a common year.
            ("0 0 1 1 *", 365 * _DAY),
            # 29 February: four years (1461 days).
            ("0 0 29 2 *", 1461 * _DAY),
            # 29 February on a Monday: 12 years, from 2196 to 2208 across
            # the common year 2200 (checked against the calendar).
            ("0 0 29 2 1", 4382 * _DAY),
            # Celery combines the day of the month and the day of the
            # week with AND: a 31st that is a Monday, at least 91 days
            # apart (OR would fire every Monday and every 31st).
            ("0 0 31 * 1", 91 * _DAY),
            # Friday the 13th: 13 February to 13 March of a common year.
            ("0 0 13 * 5", 28 * _DAY),
        ],
    )
    def test_interval_is_the_shortest_gap_between_occurrences(
        self, expression: str, expected: int
    ) -> None:
        assert shortest_interval_seconds(crontab.from_string(expression)) == expected

    @pytest.mark.parametrize(
        ("expression", "count"),
        [
            ("0 0 1 * *", 4),
            ("0 0 13 * 5", 4),
            ("0 0 31 * 1", 40),
            ("0 3 * * 1-5", 10),
            ("*/7 * * * *", 20),
            ("0,30 9-17 * * 1-5", 40),
        ],
    )
    def test_interval_matches_the_occurrences_of_celerys_scheduler(
        self, expression: str, count: int
    ) -> None:
        start = datetime(2026, 1, 1, tzinfo=UTC)

        assert shortest_interval_seconds(
            crontab.from_string(expression)
        ) == _celery_shortest_gap(expression, start=start, count=count)

    def test_schedule_without_occurrence_raises_value_error(self) -> None:
        """The matrix of schedules without occurrence is in
        `TestParseSchedule`, which reports this error."""
        with pytest.raises(ValueError, match=r"^Schedule has no occurrence$"):
            shortest_interval_seconds(crontab.from_string("0 0 31 4 *"))
