"""Behavioral tests for the Renovate lookup-log validator."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT_PATH = REPO_ROOT / "scripts" / "validate_renovate_log.py"
FIXTURE_DIR = REPO_ROOT / "backend" / "tests" / "fixtures" / "renovate"


def _run_validator(log_path: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT_PATH), str(log_path)],
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.mark.unit
def test_validator_accepts_clean_log_and_missing_warnings_field() -> None:
    result = _run_validator(FIXTURE_DIR / "clean.ndjson")

    assert result.returncode == 0
    assert result.stderr == ""
    assert "without package warnings" in result.stdout


@pytest.mark.unit
def test_validator_rejects_digest_lookup_warning_with_context() -> None:
    result = _run_validator(FIXTURE_DIR / "lookup-warning.ndjson")

    assert result.returncode == 1
    assert result.stdout == ""
    assert "Could not determine new digest" in result.stderr
    assert ".github/sbom-tools.env" in result.stderr
    assert "docker package anchore/syft" in result.stderr


@pytest.mark.unit
def test_validator_rejects_lookup_refused_by_an_ip_allow_list(tmp_path: Path) -> None:
    # No lookup failure is tolerated, including one that GitHub refused
    # because of the owning organization's IP allow list (issue #1097).
    package = "aquasecurity/trivy-action"
    refusal = {
        "name": "renovate",
        "datasource": "github-tags",
        "packageName": package,
        "err": {
            "message": (
                "Although you appear to have the correct authorization "
                "credentials, the `aquasecurity` organization has an IP allow "
                "list enabled, and your IP address is not permitted to access "
                "this resource."
            )
        },
        "msg": "Datasource unknown error",
    }
    warning = f"Failed to look up github-tags package {package}: no-result"
    dependency = {
        "depName": package,
        "datasource": "github-tags",
        "packageName": package,
        "warnings": [{"topic": package, "message": warning}],
    }
    summary = {
        "name": "renovate",
        "config": {
            "github-actions": [
                {"packageFile": ".github/workflows/example.yml", "deps": [dependency]}
            ]
        },
        "msg": "packageFiles with updates",
    }
    log_path = tmp_path / "renovate.ndjson"
    log_path.write_text(
        "".join(json.dumps(record) + "\n" for record in (refusal, summary)),
        encoding="utf-8",
    )

    result = _run_validator(log_path)

    assert result.returncode == 1
    assert result.stdout == ""
    assert f"{warning} (github-tags package {package})" in result.stderr


@pytest.mark.unit
@pytest.mark.parametrize(
    "content",
    [
        pytest.param("not-json\n", id="invalid-json"),
        pytest.param(
            '{"name":"renovate","msg":"Repository finished"}\n',
            id="missing-summary",
        ),
        pytest.param(
            '{"msg":"packageFiles with updates","config":[]}\n',
            id="invalid-summary-shape",
        ),
    ],
)
def test_validator_rejects_unverifiable_log(tmp_path: Path, content: str) -> None:
    log_path = tmp_path / "renovate.ndjson"
    log_path.write_text(content, encoding="utf-8")

    result = _run_validator(log_path)

    assert result.returncode == 2
    assert result.stdout == ""
    assert "Cannot validate Renovate lookup log" in result.stderr
