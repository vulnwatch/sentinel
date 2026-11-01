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

The scripts pin their dependencies to exact versions, outside `backend/uv.lock`,
the only file that Dependabot alerts and pip-audit read, so a script dependency
that the backend also declares is pinned to the version that the lock holds
(Workflow Conventions, Python dependency updates and vulnerability response).
See issue #1107.

No package is exempt from Renovate's cooldown: the uv image comes from Docker
Hub, the only registry from which Renovate reads the release timestamps of
images, and its tag must match every `setup-uv` version, so a uv PR that lacks
the image's update fails. The Dockerfile frontend is pinned to an exact
version, so that its releases are version updates. The cooldown cannot age a
digest update, so every digest update except the base image's waits for
approval on the Dependency Dashboard instead (Workflow Conventions, Digest
updates). See issue #1120.
"""

from __future__ import annotations

import re
import tomllib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from tests.support.dependency_config import (
    PYPROJECT_PATH,
    backend_cooldown,
    backend_uv_settings,
    renovate_config,
)
from tests.support.yaml_files import job_steps, load_yaml_file, workflow_jobs

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS_DIR = REPO_ROOT / "scripts"
DOCKERFILE_PATH = REPO_ROOT / "backend" / "Dockerfile"
UV_LOCK_PATH = REPO_ROOT / "backend" / "uv.lock"
WORKFLOWS_DIR = REPO_ROOT / ".github" / "workflows"

# The reference regular expression of PEP 723 for an inline metadata block.
PEP_723_BLOCK = re.compile(
    r"(?m)^# /// (?P<type>[a-zA-Z0-9-]+)$\s(?P<content>(^#(| .*)$\s)+)^# ///$"
)
UTC_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
# The distribution name that starts a PEP 508 requirement.
REQUIREMENT_NAME = re.compile(r"\s*([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)")
# A script dependency, pinned to one exact version.
EXACT_PIN = re.compile(
    r"(?P<name>[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)==(?P<version>[^\s;,]+)"
)
UV_GROUP = "uv version (CI + Docker image)"
# The image of the uv binary that backend/Dockerfile copies, by tag and digest.
UV_IMAGE = re.compile(
    r"(?m)^COPY --from=(?P<image>[^:\s]+):(?P<tag>[^@\s]+)@sha256:[0-9a-f]{64}"
    r" /uv /bin/uv$"
)
# The parser directive that names the Dockerfile frontend, by tag and digest.
FRONTEND_DIRECTIVE = re.compile(
    r"# syntax=docker/dockerfile:(?P<version>[^@\s]+)@sha256:[0-9a-f]{64}"
)


def _script_metadata() -> dict[str, dict[str, Any]]:
    """The PEP 723 metadata of every script under `scripts/` that declares it,
    by path relative to the repository root."""
    scripts: dict[str, dict[str, Any]] = {}
    for path in sorted(SCRIPTS_DIR.glob("*.py")):
        block = PEP_723_BLOCK.search(path.read_text(encoding="utf-8"))
        if not block or block["type"] != "script":
            continue
        relative = path.relative_to(REPO_ROOT).as_posix()
        scripts[relative] = tomllib.loads(
            "".join(
                line[2:] if line.startswith("# ") else line[1:]
                for line in block["content"].splitlines(keepends=True)
            )
        )
    return scripts


def _script_uv_settings() -> dict[str, dict[str, Any]]:
    """The `[tool.uv]` table of each script's PEP 723 metadata, empty when the
    script declares none, by path relative to the repository root."""
    return {
        relative: metadata.get("tool", {}).get("uv", {})
        for relative, metadata in _script_metadata().items()
    }


def _normalized(name: str) -> str:
    """A distribution name in the normalized form of PEP 503."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _backend_declared_dependencies() -> set[str]:
    """The normalized names of every dependency that `backend/pyproject.toml`
    declares: runtime, optional, and dependency groups."""
    pyproject = tomllib.loads(PYPROJECT_PATH.read_text(encoding="utf-8"))
    requirements: list[object] = list(pyproject["project"]["dependencies"])
    for extra in pyproject["project"].get("optional-dependencies", {}).values():
        requirements.extend(extra)
    for group in pyproject.get("dependency-groups", {}).values():
        requirements.extend(group)
    return {
        _normalized(match[1])
        for requirement in requirements
        if isinstance(requirement, str)
        and (match := REQUIREMENT_NAME.match(requirement))
    }


def _locked_versions() -> dict[str, set[str]]:
    """The versions of every package in `backend/uv.lock`, by name, which uv
    records normalized; a package locked per environment has several."""
    lock = tomllib.loads(UV_LOCK_PATH.read_text(encoding="utf-8"))
    versions: dict[str, set[str]] = {}
    for package in lock["package"]:
        versions.setdefault(package["name"], set()).add(package["version"])
    return versions


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


def _dockerfile_uv_image() -> re.Match[str]:
    """The uv image reference that backend/Dockerfile copies the binary from."""
    match = UV_IMAGE.search(DOCKERFILE_PATH.read_text(encoding="utf-8"))
    assert match is not None, f"no line of the form {UV_IMAGE.pattern}"
    return match


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
def test_script_pins_of_backend_dependencies_match_the_lock() -> None:
    # Renovate can move a script pin without backend/uv.lock, for example while
    # uv cannot lock the new version yet, and no alert or audit would then see
    # the version that the script runs. Lock file maintenance can likewise move
    # the lock without the pin; the grouped update PR, which moves both, is
    # merged first. A pin that is not exact could not be compared, so every
    # script dependency must be one.
    declared = _backend_declared_dependencies()
    locked = _locked_versions()
    pins = {
        f"{relative}: {requirement}": EXACT_PIN.fullmatch(requirement)
        for relative, metadata in _script_metadata().items()
        for requirement in metadata.get("dependencies", [])
    }
    shared = {
        entry: (pin["version"], locked.get(_normalized(pin["name"]), set()))
        for entry, pin in pins.items()
        if pin is not None and _normalized(pin["name"]) in declared
    }

    assert [entry for entry, pin in pins.items() if pin is None] == []
    assert shared, "no script pins a dependency that the backend declares"
    assert {
        entry: sorted(versions)
        for entry, (version, versions) in shared.items()
        if versions != {version}
    } == {}


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
    # A later packageRules entry overrides an earlier one, so another rule
    # that set minimumReleaseAge, to null or to a shorter duration, would
    # exempt the packages that it matches.
    config = renovate_config()
    rules = config["packageRules"]
    holding = [rule for rule in rules if "minimumReleaseAge" in rule]

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
def test_dockerfile_copies_uv_from_docker_hub_in_the_uv_group() -> None:
    # From a registry without release timestamps, such as ghcr.io, the cooldown
    # would hold the image indefinitely while the rest of its group moved on.
    image = _dockerfile_uv_image()["image"]
    group = next(
        (
            rule
            for rule in renovate_config()["packageRules"]
            if rule.get("groupName") == UV_GROUP
        ),
        None,
    )

    assert group is not None, f"no packageRules entry for the {UV_GROUP!r} group"
    assert image == "astral/uv"
    assert image in group["matchPackageNames"]


@pytest.mark.unit
def test_dockerfile_uv_tag_matches_every_setup_uv_version() -> None:
    # Renovate drops a member whose update is still pending from its group's
    # PR, such as the image when a lookup lacks its timestamps. CI and the
    # image would then run different uv versions.
    tag = _dockerfile_uv_image()["tag"]
    workflows = sorted([*WORKFLOWS_DIR.glob("*.yml"), *WORKFLOWS_DIR.glob("*.yaml")])
    versions = [
        (path.name, job_id, step.get("with", {}).get("version"))
        for path in workflows
        for job_id, job in workflow_jobs(load_yaml_file(path)).items()
        for step in job_steps(job)
        if str(step.get("uses", "")).startswith("astral-sh/setup-uv@")
    ]

    assert versions
    assert [version for version in versions if version[2] != tag] == [], tag


@pytest.mark.unit
def test_dockerfile_frontend_is_pinned_to_an_exact_version_and_digest() -> None:
    # BuildKit runs the frontend that the directive names in every build. A
    # floating tag such as "1" would change every build as soon as Docker moves
    # it to a new release, outside the cooldown; an exact version makes each
    # release a version update that the cooldown holds.
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
