"""Behavioral tests for the static security analysis (`scripts/bandit-scan.sh`).

The `Backend Security Scan` job of `ci.yml` and the `Makefile` `security`
target run bandit through this script (`docs/features/platform/
testing-strategy.md`, CI Pipeline, gate 6). It passes the version of
`backend/.python-version` in `UV_PYTHON`, because a tool run through uvx
gets the first interpreter that uv finds instead. It fails when bandit
reports a skipped file, or a line on which a `nosec` comment without a known
test ID silenced every test, because bandit still exits 0 then. See issue
#1103.

Each test copies the script into a temporary directory laid out like the
repository (never this repository) and puts first on `PATH` a stubbed
`uvx` that records its environment and arguments and prints the report
that the test selects.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO_ROOT / "scripts" / "bandit-scan.sh"
MAKEFILE_PATH = REPO_ROOT / "Makefile"

# Records UV_PYTHON, the working directory, and one argument per line, then
# prints the report of UVX_STUB_REPORT and exits with UVX_STUB_EXIT.
UVX_STUB = """\
#!/usr/bin/env bash
set -euo pipefail
{
    printf 'UV_PYTHON=%s\\n' "${UV_PYTHON-}"
    printf 'PWD=%s\\n' "${PWD}"
    printf '%s\\n' "$@"
} >"${UVX_STUB_LOG}"
cat "${UVX_STUB_REPORT}"
exit "${UVX_STUB_EXIT}"
"""

NO_ISSUES = "\tNo issues identified."
FINDING = """\
>> Issue: [B307:blacklist] Use of possibly insecure function - consider using \
safer ast.literal_eval.
   Severity: Medium   Confidence: High
   Location: app/example.py:2:11"""
NO_SKIPPED = "Files skipped (0):"
ONE_SKIPPED = """\
Files skipped (1):
\tapp/example.py (syntax error while parsing AST from file)"""


def _report(test_results: str, skipped: str, blanket_suppressions: int = 0) -> str:
    """A report in the shape of bandit's text format; `blanket_suppressions`
    counts the lines on which a `nosec` comment silenced every test."""
    return (
        "Run started:2026-01-01 00:00:00.000000+00:00\n\n"
        f"Test results:\n{test_results}\n\n"
        "Code scanned:\n\tTotal lines of code: 2\n"
        f"\tTotal lines skipped (#nosec): {blanket_suppressions}\n"
        "\tTotal potential issues skipped due to specifically being disabled "
        "(e.g., #nosec BXXX): 1\n\n"
        f"Run metrics:\n\tTotal issues (by severity):\n\t\tHigh: 0\n{skipped}\n"
    )


CLEAN_REPORT = _report(NO_ISSUES, NO_SKIPPED)


def _run(
    tmp_path: Path,
    *,
    report: str = CLEAN_REPORT,
    bandit_exit: int = 0,
    python_version: str | None = "3.14\n",
) -> tuple[subprocess.CompletedProcess[str], Path]:
    """Run a copy of the script against a stubbed uvx; return the result and
    the stub's log, which exists only when uvx ran."""
    root = tmp_path / "repo"
    (root / "scripts").mkdir(parents=True)
    script = root / "scripts" / SCRIPT_PATH.name
    shutil.copy2(SCRIPT_PATH, script)
    (root / "backend").mkdir()
    if python_version is not None:
        (root / "backend" / ".python-version").write_text(
            python_version, encoding="utf-8"
        )
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    stub = bin_dir / "uvx"
    stub.write_text(UVX_STUB, encoding="utf-8")
    stub.chmod(0o755)
    report_path = tmp_path / "report.txt"
    report_path.write_text(report, encoding="utf-8")
    log = tmp_path / "uvx.log"
    env = {
        **os.environ,
        "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
        "UVX_STUB_LOG": str(log),
        "UVX_STUB_REPORT": str(report_path),
        "UVX_STUB_EXIT": str(bandit_exit),
        # A host default that the script must not pass on to bandit.
        "UV_PYTHON": "3.12",
    }
    result = subprocess.run(
        [str(script)],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    return result, log


@pytest.mark.unit
def test_runs_pinned_bandit_on_app_with_the_project_python(tmp_path: Path) -> None:
    result, log = _run(tmp_path)
    uv_python, pwd, *arguments = log.read_text(encoding="utf-8").splitlines()
    backend = (tmp_path / "repo" / "backend").resolve()

    assert result.returncode == 0, result.stderr
    assert result.stdout == CLEAN_REPORT
    assert result.stderr == ""
    assert uv_python == "UV_PYTHON=3.14"
    assert Path(pwd.removeprefix("PWD=")).resolve() == backend
    assert re.fullmatch(r"bandit@\d+\.\d+\.\d+", arguments[0])
    assert arguments[1:] == ["-c", "pyproject.toml", "-r", "app/", "-f", "txt"]


@pytest.mark.unit
def test_skipped_file_fails_although_bandit_exits_zero(tmp_path: Path) -> None:
    # The regression of issue #1103: on Python 3.12, bandit skipped every
    # file with Python 3.14 syntax and exited 0.
    report = _report(NO_ISSUES, ONE_SKIPPED)
    result, _ = _run(tmp_path, report=report)

    assert result.returncode == 1
    assert result.stdout == report
    assert "did not analyze every file of backend/app/" in result.stderr


@pytest.mark.unit
def test_finding_fails_with_the_bandit_exit_code(tmp_path: Path) -> None:
    report = _report(FINDING, NO_SKIPPED)
    result, _ = _run(tmp_path, report=report, bandit_exit=1)

    assert result.returncode == 1
    assert result.stdout == report
    assert result.stderr == ""


@pytest.mark.unit
def test_bandit_error_exit_code_propagates(tmp_path: Path) -> None:
    # Bandit exits 2 on a usage or configuration error, without a report.
    result, _ = _run(tmp_path, report="", bandit_exit=2)

    assert result.returncode == 2
    assert "did not analyze every file of backend/app/" in result.stderr
    assert "silenced every test of its line" in result.stderr


@pytest.mark.unit
@pytest.mark.parametrize(
    "skipped",
    [
        "",  # the line is missing, for example after a format change
        "Files skipped (0): ",  # the exact line only
        "\tFiles skipped (0):",
    ],
)
def test_report_without_the_exact_no_skipped_line_fails(
    tmp_path: Path, skipped: str
) -> None:
    result, _ = _run(tmp_path, report=_report(NO_ISSUES, skipped))

    assert result.returncode == 1
    assert "did not analyze every file of backend/app/" in result.stderr


@pytest.mark.unit
def test_blanket_suppression_fails_although_bandit_exits_zero(
    tmp_path: Path,
) -> None:
    # `# nosec B999` names no test that bandit knows, so bandit silences every
    # test of its line, reports no issue, and counts the line here.
    report = _report(NO_ISSUES, NO_SKIPPED, blanket_suppressions=1)
    result, _ = _run(tmp_path, report=report)

    assert result.returncode == 1
    assert result.stdout == report
    assert "silenced every test of its line" in result.stderr
    assert "did not analyze every file" not in result.stderr


@pytest.mark.unit
def test_report_without_the_suppression_count_fails(tmp_path: Path) -> None:
    report = CLEAN_REPORT.replace("\tTotal lines skipped (#nosec): 0\n", "")
    result, _ = _run(tmp_path, report=report)

    assert result.returncode == 1
    assert "silenced every test of its line" in result.stderr


@pytest.mark.unit
@pytest.mark.parametrize(
    "python_version",
    [
        "",  # UV_PYTHON="" would leave the choice to uv
        "\n",
        "3.14.1\n",  # patch level
        "3\n",
        "python3.14\n",
        "3.14\n3.13\n",
    ],
)
def test_malformed_python_version_fails_before_bandit_runs(
    tmp_path: Path, python_version: str
) -> None:
    result, log = _run(tmp_path, python_version=python_version)

    assert result.returncode == 1
    assert "backend/.python-version must hold a minor version" in result.stderr
    assert not log.exists()


@pytest.mark.unit
def test_missing_python_version_fails_before_bandit_runs(tmp_path: Path) -> None:
    result, log = _run(tmp_path, python_version=None)

    assert result.returncode != 0
    assert not log.exists()


@pytest.mark.unit
def test_makefile_security_target_runs_the_script() -> None:
    # make security and the CI job (tests/test_ci_workflow.py) run the same
    # checks only while both run the script.
    match = re.search(
        r"^security:[^\n]*\n\t(?P<recipe>[^\n]*)\n",
        MAKEFILE_PATH.read_text(encoding="utf-8"),
        re.MULTILINE,
    )

    assert match, "the Makefile has no security target"
    assert match["recipe"] == "./scripts/bandit-scan.sh"
