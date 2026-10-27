"""Contract tests for the release-age cooldown of dependency updates.

`docs/deployment.md` (Workflow Conventions, Release-age cooldown) admits a new
release only once it is seven days old, through two settings that must agree:
uv's `exclude-newer` in `backend/pyproject.toml` and in the PEP 723 metadata of
the standalone scripts, which limits every resolution, lock file maintenance
included, and Renovate's `minimumReleaseAge`, which holds Renovate's update PRs
for the same time so that they never propose a version that uv cannot lock. An
`exclude-newer-package` entry admits a newer version of one package, such as a
security fix, with an absolute cutoff in the past: `false` or a future date
would exempt the package from the cooldown, silently. See issue #1014. The
`uvx` tools are covered in `tests/test_workflow_tool_pins.py` and the pip-audit
step in `tests/test_ci_workflow.py`.

No package is exempt from Renovate's cooldown: the uv image comes from Docker
Hub, the only registry from which Renovate reads the release timestamps of
images, and the Dockerfile frontend is pinned to an exact version, so that its
releases are version updates. The cooldown cannot age a digest update, so every
digest update except the base image's waits for approval on the Dependency
Dashboard instead (Workflow Conventions, Digest updates). See issue #1120.
"""

from __future__ import annotations

import re
import tomllib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from tests.support.dependency_config import (
    backend_cooldown,
    backend_uv_settings,
    renovate_config,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS_DIR = REPO_ROOT / "scripts"
DOCKERFILE_PATH = REPO_ROOT / "backend" / "Dockerfile"

# The reference regular expression of PEP 723 for an inline metadata block.
PEP_723_BLOCK = re.compile(
    r"(?m)^# /// (?P<type>[a-zA-Z0-9-]+)$\s(?P<content>(^#(| .*)$\s)+)^# ///$"
)
UTC_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
UV_GROUP = "uv version (CI + Docker image)"
# The image of the uv binary that backend/Dockerfile copies, by tag and digest.
UV_IMAGE = re.compile(
    r"(?m)^COPY --from=(?P<image>[^:\s]+):[^@\s]+@sha256:[0-9a-f]{64} /uv /bin/uv$"
)
# The parser directive that names the Dockerfile frontend, by tag and digest.
FRONTEND_DIRECTIVE = re.compile(
    r"# syntax=docker/dockerfile:(?P<version>[^@\s]+)@sha256:[0-9a-f]{64}"
)


def _script_uv_settings() -> dict[str, dict[str, Any]]:
    """The `[tool.uv]` table of the PEP 723 metadata of every script under
    `scripts/` that declares it, by path relative to the repository root."""
    settings: dict[str, dict[str, Any]] = {}
    for path in sorted(SCRIPTS_DIR.glob("*.py")):
        block = PEP_723_BLOCK.search(path.read_text(encoding="utf-8"))
        if not block or block["type"] != "script":
            continue
        metadata = tomllib.loads(
            "".join(
                line[2:] if line.startswith("# ") else line[1:]
                for line in block["content"].splitlines(keepends=True)
            )
        )
        relative = path.relative_to(REPO_ROOT).as_posix()
        settings[relative] = metadata.get("tool", {}).get("uv", {})
    return settings


def _paths_of_setting(node: object, name: str, path: str = "") -> list[str]:
    """The paths at which a parsed configuration sets `name`, at any depth."""
    found: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            child = f"{path}.{key}" if path else str(key)
            if key == name:
                found.append(child)
            found.extend(_paths_of_setting(value, name, child))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            found.extend(_paths_of_setting(value, name, f"{path}[{index}]"))
    return found


@pytest.mark.unit
def test_backend_cooldown_is_a_relative_duration() -> None:
    # A duration moves the cutoff with every resolution, and uv records it in
    # uv.lock as a span, so the lock stays valid as time passes. A timestamp
    # would freeze resolution, and false would turn the cooldown off.
    assert re.fullmatch(r"[1-9][0-9]* days", backend_cooldown())


@pytest.mark.unit
def test_scripts_resolve_with_the_backend_cooldown() -> None:
    # `uv run --script` resolves the inline dependencies on the developer's
    # host, outside the backend project and its settings.
    scripts = _script_uv_settings()

    assert "scripts/capture-ibs-rabbitmq.py" in scripts
    assert {
        relative: uv.get("exclude-newer") for relative, uv in scripts.items()
    } == dict.fromkeys(scripts, backend_cooldown())


@pytest.mark.unit
def test_per_package_cutoffs_are_past_absolute_utc_timestamps() -> None:
    # An absolute cutoff admits the needed version and nothing uploaded after
    # it, so an entry left in place holds its package back visibly instead of
    # exempting it from the cooldown. A correct cutoff follows an upload that
    # has already happened; a future one would admit every newer release.
    sources = {"backend/pyproject.toml": backend_uv_settings()}
    sources.update(_script_uv_settings())
    cutoffs = {
        f"{relative}: {package}": cutoff
        for relative, uv in sources.items()
        for package, cutoff in uv.get("exclude-newer-package", {}).items()
    }
    malformed = {
        entry: cutoff
        for entry, cutoff in cutoffs.items()
        if not (isinstance(cutoff, str) and UTC_TIMESTAMP.fullmatch(cutoff))
    }
    now = datetime.now(UTC)

    assert malformed == {}
    assert {
        entry: cutoff
        for entry, cutoff in cutoffs.items()
        if datetime.fromisoformat(cutoff) >= now
    } == {}


@pytest.mark.unit
def test_renovate_holds_every_new_version_for_the_backend_cooldown() -> None:
    # One rule, matching only the update type, applies the cooldown to every
    # manager; digest, pin, and lock file maintenance updates are outside it.
    config = renovate_config()
    rules = config["packageRules"]
    holding = [rule for rule in rules if rule.get("minimumReleaseAge")]

    assert "minimumReleaseAge" not in config
    assert len(holding) == 1
    assert rules.index(holding[0]) == 0
    assert holding[0]["minimumReleaseAge"] == backend_cooldown()
    assert {key for key in holding[0] if key.startswith("match")} == {
        "matchUpdateTypes"
    }
    assert sorted(holding[0]["matchUpdateTypes"]) == ["major", "minor", "patch"]


@pytest.mark.unit
def test_renovate_holds_every_release_without_a_timestamp() -> None:
    # Renovate's default, timestamp-required, holds a release without a
    # timestamp until it is requested from the Dependency Dashboard. A lookup
    # can lack the timestamps of a Docker Hub image with more than 1,000 tags,
    # and timestamp-optional would then admit its releases without the
    # cooldown, so no part of the configuration sets minimumReleaseAgeBehaviour.
    # Issue #1109.
    assert _paths_of_setting(renovate_config(), "minimumReleaseAgeBehaviour") == []


@pytest.mark.unit
def test_renovate_cooldown_exempts_no_package() -> None:
    # A later packageRules entry overrides an earlier one, so a rule that set
    # minimumReleaseAge again, to null or to a shorter duration, would exempt
    # the packages that it matches.
    rules = renovate_config()["packageRules"]

    assert [
        index for index, rule in enumerate(rules) if "minimumReleaseAge" in rule
    ] == [0]


@pytest.mark.unit
def test_dockerfile_copies_uv_from_docker_hub_in_the_uv_group() -> None:
    # From a registry without release timestamps, such as ghcr.io, the cooldown
    # would hold the image indefinitely while the rest of its group moved on.
    match = UV_IMAGE.search(DOCKERFILE_PATH.read_text(encoding="utf-8"))
    group = next(
        rule
        for rule in renovate_config()["packageRules"]
        if rule.get("groupName") == UV_GROUP
    )

    assert match is not None
    assert match["image"] == "astral/uv"
    assert match["image"] in group["matchPackageNames"]


@pytest.mark.unit
def test_dockerfile_frontend_is_pinned_to_an_exact_version_and_digest() -> None:
    # BuildKit runs the frontend that the directive names in every build. A
    # floating tag such as "1" would move to a new release on the day of its
    # publication, outside the cooldown; an exact version makes each release a
    # version update that the cooldown holds.
    first_line = DOCKERFILE_PATH.read_text(encoding="utf-8").splitlines()[0]
    match = FRONTEND_DIRECTIVE.fullmatch(first_line)

    assert match is not None, first_line
    assert re.fullmatch(r"\d+\.\d+\.\d+", match["version"])


@pytest.mark.unit
def test_renovate_holds_digest_updates_for_approval_except_the_base_image() -> None:
    # The cooldown cannot age a digest, which Docker Hub dates by the last push
    # of its tag. Any other pin's digest update means that its tag moved to
    # other content; the base image's tag is republished with every fix, and
    # its digest refresh is the remediation path of the image scan.
    config = renovate_config()
    approving = [
        rule for rule in config["packageRules"] if "dependencyDashboardApproval" in rule
    ]

    assert "dependencyDashboardApproval" not in config
    assert len(approving) == 1
    assert approving[0]["dependencyDashboardApproval"] is True
    assert {
        key: value for key, value in approving[0].items() if key.startswith("match")
    } == {
        "matchUpdateTypes": ["digest"],
        "matchPackageNames": ["!python"],
    }


@pytest.mark.unit
def test_renovate_raises_vulnerability_fixes_without_the_cooldown() -> None:
    # Renovate's vulnerabilityAlerts default sets minimumReleaseAge to null and
    # applies after packageRules; overriding it would hold fix PRs too.
    alerts = renovate_config()["vulnerabilityAlerts"]

    assert "minimumReleaseAge" not in alerts
