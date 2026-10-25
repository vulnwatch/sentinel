"""Contract tests for the release-age cooldown of dependency updates.

`docs/deployment.md` (Workflow Conventions, Release-age cooldown) admits a new
release only once it is seven days old, through two settings that must agree:
uv's `exclude-newer` in `backend/pyproject.toml` and in the PEP 723 metadata of
the standalone scripts, which limits every resolution, lock file maintenance
included, and Renovate's `minimumReleaseAge`, which holds Renovate's update PRs
for the same time so that they never propose a version that uv cannot lock. An
`exclude-newer-package` entry admits a newer version of one package, such as a
security fix, with an absolute cutoff: `false` would exempt the package from
the cooldown for good, silently. See issue #1014. The `uvx` tools are covered
in `tests/test_workflow_tool_pins.py` and the pip-audit step in
`tests/test_ci_workflow.py`.
"""

from __future__ import annotations

import json
import re
import tomllib
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
PYPROJECT_PATH = REPO_ROOT / "backend" / "pyproject.toml"
RENOVATE_CONFIG_PATH = REPO_ROOT / "renovate.jsonc"
SCRIPTS_DIR = REPO_ROOT / "scripts"

# The reference regular expression of PEP 723 for an inline metadata block.
PEP_723_BLOCK = re.compile(
    r"(?m)^# /// (?P<type>[a-zA-Z0-9-]+)$\s(?P<content>(^#(| .*)$\s)+)^# ///$"
)
UTC_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
UV_GROUP = "uv version (CI + Docker image)"


def _renovate_config() -> dict[str, Any]:
    """`renovate.jsonc` without its comments, which are whole lines."""
    lines = RENOVATE_CONFIG_PATH.read_text(encoding="utf-8").splitlines()
    document = "\n".join(line for line in lines if not line.lstrip().startswith("//"))
    config: dict[str, Any] = json.loads(document)
    return config


def _backend_uv_settings() -> dict[str, Any]:
    settings: dict[str, Any] = tomllib.loads(
        PYPROJECT_PATH.read_text(encoding="utf-8")
    )["tool"]["uv"]
    return settings


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


@pytest.mark.unit
def test_backend_cooldown_is_a_relative_duration() -> None:
    # A duration moves the cutoff with every resolution, and uv records it in
    # uv.lock as a span, so the lock stays valid as time passes. A timestamp
    # would freeze resolution, and false would turn the cooldown off.
    assert re.fullmatch(r"[1-9][0-9]* days", _backend_uv_settings()["exclude-newer"])


@pytest.mark.unit
def test_scripts_resolve_with_the_backend_cooldown() -> None:
    # `uv run --script` resolves the inline dependencies on the developer's
    # host, outside the backend project and its settings.
    cooldown = _backend_uv_settings()["exclude-newer"]
    scripts = _script_uv_settings()

    assert "scripts/capture-ibs-rabbitmq.py" in scripts
    assert {
        relative: uv.get("exclude-newer") for relative, uv in scripts.items()
    } == dict.fromkeys(scripts, cooldown)


@pytest.mark.unit
def test_per_package_cutoffs_are_absolute_utc_timestamps() -> None:
    # An absolute cutoff admits the needed version and nothing uploaded after
    # it, so an entry left in place holds its package back visibly instead of
    # exempting it from the cooldown.
    sources = {"backend/pyproject.toml": _backend_uv_settings()}
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

    assert malformed == {}
    for cutoff in cutoffs.values():
        datetime.fromisoformat(cutoff)


@pytest.mark.unit
def test_renovate_holds_every_new_version_for_the_backend_cooldown() -> None:
    # One rule, matching only the update type, applies the cooldown to every
    # manager; digest, pin, and lock file maintenance updates are outside it.
    config = _renovate_config()
    rules = config["packageRules"]
    holding = [rule for rule in rules if rule.get("minimumReleaseAge")]

    assert "minimumReleaseAge" not in config
    assert len(holding) == 1
    assert rules.index(holding[0]) == 0
    assert holding[0]["minimumReleaseAge"] == _backend_uv_settings()["exclude-newer"]
    assert {key for key in holding[0] if key.startswith("match")} == {
        "matchUpdateTypes"
    }
    assert holding[0]["matchUpdateTypes"] == ["major", "minor", "patch"]


@pytest.mark.unit
def test_renovate_cooldown_exempts_only_the_uv_version_group() -> None:
    # ghcr.io publishes no release timestamps, so the uv image would be held
    # indefinitely and the group would split; the exemption must follow the
    # cooldown rule, since a later packageRules entry overrides an earlier one.
    rules = _renovate_config()["packageRules"]
    exempt = [
        rule
        for rule in rules
        if "minimumReleaseAge" in rule and rule["minimumReleaseAge"] is None
    ]

    assert [rule.get("groupName") for rule in exempt] == [UV_GROUP]
    assert rules.index(exempt[0]) > 0


@pytest.mark.unit
def test_renovate_raises_vulnerability_fixes_without_the_cooldown() -> None:
    # Renovate's vulnerabilityAlerts default sets minimumReleaseAge to null and
    # applies after packageRules; overriding it would hold fix PRs too.
    alerts = _renovate_config()["vulnerabilityAlerts"]

    assert "minimumReleaseAge" not in alerts
