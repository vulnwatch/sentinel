"""Parsing and occurrence analysis of fetcher cron schedules.

A fetcher schedule is a 5-field cron expression as Celery's `crontab`
parses it, interpreted in UTC. It is valid only when it fires at least
once: `parse_schedule` is the single validation of a schedule for the
`PATCH /api/v1/fetchers/{fetcher_name}/config` request schema
(`docs/features/platform/fetcher-operations.md`, Update Fetcher Config,
Validation rules) and for the import-time validation of
`default_schedule` (`docs/features/platform/fetcher-infrastructure.md`,
Import-time validation, rule 11). `shortest_interval_seconds` is the
interval from which the expiry of a scheduled run derives
(`fetcher-infrastructure.md`, Scheduled Run Expiry), so a schedule that
`parse_schedule` accepts always yields one.
"""

from __future__ import annotations

import calendar
from datetime import date
from functools import lru_cache
from itertools import pairwise

from celery.schedules import ParseException, crontab

_MINUTES_PER_DAY = 24 * 60
_DAYS_PER_WEEK = 7
# The Gregorian calendar, days of the week included, repeats every 400
# years (146097 days, a multiple of 7).
_GREGORIAN_CYCLE_START_YEAR = 2000
_GREGORIAN_CYCLE_YEARS = 400
_GREGORIAN_CYCLE_DAYS = 146097
_ALL_DAYS_OF_MONTH = frozenset(range(1, 32))
_ALL_MONTHS = frozenset(range(1, 13))


def parse_schedule(expression: str) -> crontab:
    """Parse `expression` as a fetcher schedule that fires.

    Raises:
        ValueError: `expression` is not a valid 5-field cron expression,
            including Celery's `ParseException`, which is not a
            `ValueError` (an empty part or step, or a negative number),
            or it has no occurrence (for example `0 0 31 2 *`).
    """
    try:
        schedule = crontab.from_string(expression)
    except ParseException as exc:
        raise ValueError(str(exc)) from exc
    shortest_interval_seconds(schedule)
    return schedule


def shortest_interval_seconds(schedule: crontab) -> int:
    """Shortest interval, in seconds, between two consecutive occurrences
    of `schedule` in UTC. An occurrence is a minute whose minute, hour,
    day of the month, month, and day of the week all match: Celery's
    `crontab` combines the day of the month and the day of the week with
    AND, unlike standard cron. Exact over the Gregorian calendar, leap
    years included.

    Raises:
        ValueError: the schedule has no occurrence (for example
            `0 0 31 2 *`).
    """
    return 60 * _shortest_interval_minutes(
        frozenset(schedule.minute),
        frozenset(schedule.hour),
        frozenset(schedule.day_of_month),
        frozenset(schedule.month_of_year),
        frozenset(schedule.day_of_week),
    )


def _shortest_day_gap(
    days_of_month: frozenset[int],
    months: frozenset[int],
    days_of_week: frozenset[int],
) -> int:
    """Shortest number of days between two consecutive days on which a
    schedule fires, with Celery's AND of day of the month, month, and
    day of the week (0 is Sunday).

    When neither the day of the month nor the month is restricted, only
    the day of the week decides, with a period of one week. Otherwise
    every matching day of one 400-year Gregorian cycle is listed; the gap
    from the last one wraps around to the first one of the next cycle.

    Raises:
        ValueError: no day matches.
    """
    if days_of_month == _ALL_DAYS_OF_MONTH and months == _ALL_MONTHS:
        weekdays = sorted(days_of_week)
        if not weekdays:
            raise ValueError("Schedule has no occurrence")
        # The last day of the week wraps around to the first one of the
        # next week; a single day wraps around to itself (seven days).
        return min(
            (later - earlier) % _DAYS_PER_WEEK or _DAYS_PER_WEEK
            for earlier, later in pairwise([*weekdays, weekdays[0]])
        )

    matching: list[int] = []
    for year in range(
        _GREGORIAN_CYCLE_START_YEAR,
        _GREGORIAN_CYCLE_START_YEAR + _GREGORIAN_CYCLE_YEARS,
    ):
        for month in sorted(months):
            last_day = calendar.monthrange(year, month)[1]
            first_ordinal = date(year, month, 1).toordinal()
            for day in sorted(days_of_month):
                ordinal = first_ordinal + day - 1
                # `toordinal() % 7` numbers the days of the week as
                # Celery does: 0 is Sunday.
                if day <= last_day and ordinal % _DAYS_PER_WEEK in days_of_week:
                    matching.append(ordinal)
    if not matching:
        raise ValueError("Schedule has no occurrence")
    gaps = [b - a for a, b in pairwise(matching)]
    gaps.append(matching[0] + _GREGORIAN_CYCLE_DAYS - matching[-1])
    return min(gaps)


@lru_cache(maxsize=128)
def _shortest_interval_minutes(
    minutes: frozenset[int],
    hours: frozenset[int],
    days_of_month: frozenset[int],
    months: frozenset[int],
    days_of_week: frozenset[int],
) -> int:
    """Shortest interval, in minutes, between two consecutive occurrences
    of the crontab fields: the smaller of the shortest gap between two
    times of one day and the gap from the last time of a matching day to
    the first time of the next matching day. Cached because the
    computation can cover a 400-year cycle (see `_shortest_day_gap`).

    Raises:
        ValueError: the fields have no occurrence.
    """
    times = sorted(hour * 60 + minute for hour in hours for minute in minutes)
    if not times:
        raise ValueError("Schedule has no occurrence")
    day_gap = _shortest_day_gap(days_of_month, months, days_of_week)
    across_days = day_gap * _MINUTES_PER_DAY + times[0] - times[-1]
    within_day = min((b - a for a, b in pairwise(times)), default=across_days)
    return min(within_day, across_days)
