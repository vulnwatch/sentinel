"""Contract tests for the release signal of Renovate's update titles.

`docs/deployment.md` (Workflow Conventions, Release signal of dependency
updates) titles an update of what the image contains `chore(deps):`, which
release-please releases as a patch and lists under Dependencies, and an update
of what only CI, development, tests, or the build tools use `ci(deps):`, which
creates no release. Every Renovate PR keeps its generated title, so the
classification in `renovate.jsonc` alone decides whether a merged update
reaches a release. See issue #1298.

Renovate takes the prefix of an update from the last `packageRules` entry that
matches it and sets one. These tests evaluate the entries against the updates
that Renovate raises, with the depTypes that its managers report:
`project.dependencies` for the backend's `[project]` dependencies and for the
PEP 723 pins of the scripts, `dependency-groups` for the backend's development
dependencies, and `build-system.requires` for the `uv_build` requirement. The
evaluation supports the matchers that `renovate.jsonc` uses and fails on any
other, so that a new kind of rule is not silently misread.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from typing import Any

import pytest

from tests.support.dependency_config import backend_pyproject, renovate_config

IMAGE_PREFIX = "chore(deps):"
NON_IMAGE_PREFIX = "ci(deps):"
SECURITY_FIX_PREFIX = "fix(deps):"
RUNTIME_GROUP = "python minor and patch dependencies"
DEVELOPMENT_GROUP = "python development dependencies"
SUPPORTED_MATCHERS = frozenset(
    {
        "matchManagers",
        "matchDepTypes",
        "matchUpdateTypes",
        "matchPackageNames",
        "matchFileNames",
    }
)
# The distribution name that starts a PEP 508 requirement.
REQUIREMENT_NAME = re.compile(r"\s*([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)")
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
    `renovate.jsonc` match. Lock file maintenance has no package or depType."""

    manager: str
    package: str | None
    file: str
    update_type: str = "minor"
    dep_type: str | None = None


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
        "matchDepTypes": lambda values: update.dep_type in values,
        "matchUpdateTypes": lambda values: update.update_type in values,
        "matchPackageNames": lambda values: _matches_package(values, update.package),
        "matchFileNames": lambda values: _matches_file(values, update.file),
    }
    return all(checks[key](rule[key]) for key in matchers)


def _setting(update: Update, setting: str) -> Any:
    """The value of a setting for an update: that of the last matching
    package rule that sets it, or None."""
    value = None
    for rule in renovate_config()["packageRules"]:
        if setting in rule and _rule_matches(rule, update):
            value = rule[setting]
    return value


def _requirement_names(requirements: list[str]) -> list[str]:
    names = []
    for requirement in requirements:
        match = REQUIREMENT_NAME.match(requirement)
        assert match is not None, requirement
        names.append(match[1])
    return names


def _runtime_updates(update_type: str) -> list[Update]:
    names = _requirement_names(backend_pyproject()["project"]["dependencies"])
    assert names
    return [
        Update(
            "pep621",
            name,
            "backend/pyproject.toml",
            update_type,
            "project.dependencies",
        )
        for name in names
    ]


def _development_updates(update_type: str) -> list[Update]:
    groups: dict[str, list[str]] = backend_pyproject()["dependency-groups"]
    names = [name for group in groups.values() for name in _requirement_names(group)]
    assert names
    return [
        Update(
            "pep621",
            name,
            "backend/pyproject.toml",
            update_type,
            "dependency-groups",
        )
        for name in names
    ]


SCRIPT_PIN = Update(
    "pep723",
    "aio-pika",
    "scripts/capture-ibs-rabbitmq.py",
    dep_type="project.dependencies",
)

# Updates of what the image contains, other than the Python runtime
# dependencies.
IMAGE_UPDATES = [
    Update("dockerfile", "python", "backend/Dockerfile", "digest"),
    Update("custom.regex", "swagger-ui-dist", "backend/app/api/interactive_docs.py"),
    Update("custom.regex", "swagger-ui-dist", ".github/workflows/deploy-api-docs.yml"),
]

# Updates of what only CI, development, tests, and the build tools that the
# image does not contain use, other than the Python development dependencies.
NON_IMAGE_UPDATES = [
    Update("github-actions", "actions/checkout", ".github/workflows/ci.yml"),
    Update("github-actions", "postgres", ".github/workflows/ci.yml"),
    Update("custom.regex", "anchore/syft", ".github/sbom-tools.env"),
    Update("custom.regex", "aquasec/trivy", ".github/workflows/image-scan.yml"),
    Update("custom.regex", "pip-audit", ".github/workflows/ci.yml"),
    Update("custom.regex", "koalaman/shellcheck", "scripts/lint-shell.sh"),
    Update("custom.regex", "postgres", "backend/tests/conftest.py"),
    Update("docker-compose", "postgres", "docker-compose.yml", "major"),
    Update("docker-compose", "redis", "docker-compose.smoke.yml", "major"),
    Update("dockerfile", "docker/dockerfile", "backend/Dockerfile"),
    Update("dockerfile", "astral/uv", "backend/Dockerfile", "patch"),
    Update("github-actions", "astral-sh/uv", ".github/workflows/ci.yml", "patch"),
    Update(
        "pep621",
        "uv-build",
        "backend/pyproject.toml",
        dep_type="build-system.requires",
    ),
]


@pytest.mark.unit
@pytest.mark.parametrize("update_type", ["patch", "minor", "major"])
def test_python_runtime_dependency_updates_are_a_release_signal(
    update_type: str,
) -> None:
    # The image installs the [project] dependencies.
    prefixes = {
        update.package: _setting(update, "commitMessagePrefix")
        for update in _runtime_updates(update_type)
    }

    assert prefixes == dict.fromkeys(prefixes, IMAGE_PREFIX)


@pytest.mark.unit
@pytest.mark.parametrize("update_type", ["patch", "minor", "major"])
def test_python_development_dependency_updates_carry_no_release_signal(
    update_type: str,
) -> None:
    # The image is built with `uv sync --no-dev`.
    prefixes = {
        update.package: _setting(update, "commitMessagePrefix")
        for update in _development_updates(update_type)
    }

    assert prefixes == dict.fromkeys(prefixes, NON_IMAGE_PREFIX)


@pytest.mark.unit
def test_runtime_and_development_dependencies_are_grouped_apart() -> None:
    # A PR that mixed both would be a release signal for the development
    # dependencies too. A script pin of a backend dependency stays in the
    # runtime group, so that it moves together with the backend's version.
    runtime = {_setting(update, "groupName") for update in _runtime_updates("minor")}
    development = {
        _setting(update, "groupName") for update in _development_updates("minor")
    }

    assert runtime == {RUNTIME_GROUP}
    assert development == {DEVELOPMENT_GROUP}
    assert _setting(SCRIPT_PIN, "groupName") == RUNTIME_GROUP
    assert _setting(SCRIPT_PIN, "commitMessagePrefix") == IMAGE_PREFIX


@pytest.mark.unit
@pytest.mark.parametrize("update", IMAGE_UPDATES, ids=lambda update: update.file)
def test_updates_of_the_image_are_a_release_signal(update: Update) -> None:
    assert _setting(update, "commitMessagePrefix") == IMAGE_PREFIX


@pytest.mark.unit
@pytest.mark.parametrize(
    "update",
    NON_IMAGE_UPDATES,
    ids=lambda update: f"{update.manager}-{update.package}",
)
def test_updates_outside_the_image_carry_no_release_signal(update: Update) -> None:
    assert _setting(update, "commitMessagePrefix") == NON_IMAGE_PREFIX


@pytest.mark.unit
def test_lock_file_maintenance_is_a_release_signal() -> None:
    # The regeneration moves the transitive runtime dependencies that the image
    # installs. A package rule that matched the update would override the
    # prefix of the lockFileMaintenance block.
    update = Update("pep621", None, "backend/pyproject.toml", "lockFileMaintenance")
    block = renovate_config()["lockFileMaintenance"]["commitMessagePrefix"]

    assert (_setting(update, "commitMessagePrefix") or block) == IMAGE_PREFIX


@pytest.mark.unit
def test_every_prefix_is_one_of_the_documented_release_signals() -> None:
    # Another prefix, such as a bare chore(deps) without the colon or a
    # build(deps): prefix, would be hidden from release-please or rejected by
    # the PR Metadata check.
    config = renovate_config()
    prefixes = {
        rule["commitMessagePrefix"]
        for rule in config["packageRules"]
        if "commitMessagePrefix" in rule
    }

    assert prefixes == {IMAGE_PREFIX, NON_IMAGE_PREFIX}
    assert config["vulnerabilityAlerts"]["commitMessagePrefix"] == SECURITY_FIX_PREFIX
