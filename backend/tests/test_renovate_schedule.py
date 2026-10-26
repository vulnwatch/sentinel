"""Contract tests for the update schedule of Renovate's pull requests.

`docs/deployment.md` (Workflow Conventions, Update schedule) opens the routine
updates every night between 00:00 and 05:59 UTC, without a limit on the pull
requests that Renovate opens in an hour or keeps open, and keeps lock file
maintenance weekly, on Monday in the same hours. Renovate's defaults differ
without a warning: two pull requests an hour, and a schedule of lock file
maintenance's own ("before 4am on monday") that does not follow the root one.
See issue #1111.
"""

from __future__ import annotations

import re

import pytest

from tests.support.dependency_config import renovate_config

# A schedule in cron syntax. The minutes are always "*", because Renovate does
# not schedule by the minute.
CRON_SCHEDULE = re.compile(r"\* (?P<hours>\S+) \* \* (?P<weekdays>\S+)")
PR_LIMITS = ("prHourlyLimit", "prConcurrentLimit")


def _window(schedule: list[str]) -> tuple[str, str]:
    """The hours and the weekdays of a schedule of one cron expression."""
    assert len(schedule) == 1
    match = CRON_SCHEDULE.fullmatch(schedule[0])
    assert match is not None
    return match["hours"], match["weekdays"]


@pytest.mark.unit
def test_renovate_schedule_opens_routine_updates_every_night() -> None:
    # Six hours, so that a run of the App that is late still falls inside the
    # window, every day, so that an update opens within a day of reaching the
    # release-age cooldown.
    assert _window(renovate_config()["schedule"]) == ("0-5", "*")


@pytest.mark.unit
def test_lock_file_maintenance_runs_weekly_in_the_update_window() -> None:
    # A nightly regeneration of backend/uv.lock would open a pull request
    # almost every night that conflicts with the Python group on the same file.
    config = renovate_config()
    hours, weekdays = _window(config["lockFileMaintenance"]["schedule"])

    assert hours == _window(config["schedule"])[0]
    assert weekdays == "1"


@pytest.mark.unit
def test_renovate_limits_no_pull_requests() -> None:
    # The window may hold a single run, so a limit would defer the updates
    # that are ready beyond it to a later night. A limit set by a package rule
    # would do the same for the branches that it matches.
    config = renovate_config()

    assert {limit: config[limit] for limit in PR_LIMITS} == dict.fromkeys(PR_LIMITS, 0)
    assert [
        rule.get("description")
        for rule in config["packageRules"]
        if any(limit in rule for limit in PR_LIMITS)
    ] == []
