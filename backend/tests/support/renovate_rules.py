"""Evaluation of the `packageRules` of `renovate.jsonc` against an update.

Renovate takes a setting of an update from the last `packageRules` entry that
matches it and sets that setting. `setting()` evaluates the entries against an
`Update` with the properties that Renovate's managers report. It supports the
matchers that `renovate.jsonc` uses and fails on any other in an entry that it
evaluates, so that a new kind of rule is not silently misread.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from typing import Any

from tests.support.dependency_config import renovate_config

SUPPORTED_MATCHERS = frozenset(
    {
        "matchManagers",
        "matchDatasources",
        "matchDepTypes",
        "matchUpdateTypes",
        "matchPackageNames",
        "matchFileNames",
    }
)
# The package patterns that the evaluation reads as Renovate does: an exact
# name, or its negation. A glob or a /regular expression/ would need
# Renovate's own matching.
EXACT_PACKAGE_PATTERN = re.compile(r"!?[A-Za-z0-9@](?:[A-Za-z0-9._/@-]*[A-Za-z0-9])?")
# The file patterns that fnmatch reads as Renovate's minimatch does: an exact
# path, or every file below a directory.
EXACT_FILE_PATTERN = re.compile(r"[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*(?:/\*\*)?")


@dataclass(frozen=True)
class Update:
    """The properties of an update that the package rules of
    `renovate.jsonc` match. Lock file maintenance has no package or depType.
    The datasource is needed only by the rules that match one."""

    manager: str
    package: str | None
    file: str
    update_type: str = "minor"
    dep_type: str | None = None
    datasource: str | None = None


def _matches_package(patterns: list[str], package: str | None) -> bool:
    assert all(EXACT_PACKAGE_PATTERN.fullmatch(p) for p in patterns), patterns
    if package is None:
        return False
    excluded = {p.removeprefix("!") for p in patterns if p.startswith("!")}
    included = {p for p in patterns if not p.startswith("!")}
    return package not in excluded and (not included or package in included)


def _matches_file(patterns: list[str], file: str) -> bool:
    assert all(EXACT_FILE_PATTERN.fullmatch(p) for p in patterns), patterns
    return any(fnmatch.fnmatchcase(file, pattern) for pattern in patterns)


def _rule_matches(rule: dict[str, Any], update: Update) -> bool:
    matchers = {key for key in rule if key.startswith("match")}
    assert matchers <= SUPPORTED_MATCHERS, rule.get("description")
    checks = {
        "matchManagers": lambda values: update.manager in values,
        "matchDatasources": lambda values: update.datasource in values,
        "matchDepTypes": lambda values: update.dep_type in values,
        "matchUpdateTypes": lambda values: update.update_type in values,
        "matchPackageNames": lambda values: _matches_package(values, update.package),
        "matchFileNames": lambda values: _matches_file(values, update.file),
    }
    return all(checks[key](rule[key]) for key in matchers)


def setting(update: Update, name: str) -> Any:
    """The value of a setting for an update: that of the last matching
    package rule that sets it, or None."""
    value = None
    for rule in renovate_config()["packageRules"]:
        if name in rule and _rule_matches(rule, update):
            value = rule[name]
    return value
