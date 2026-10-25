"""Tests of the static security analysis of the backend application code.

`docs/features/platform/testing-strategy.md` (CI Pipeline, gate 6) and
`docs/conventions.md` (Static Security Analysis): the analysis is ruff's
flake8-bandit rules (`S`), which `backend/pyproject.toml` enables together
with `PLE2502` (bidirectional Unicode control characters) and `PGH004` (a
`noqa` comment that names no rule code). The `ruff check .` of the lint run,
in CI and in the pre-commit hook, therefore performs it. See issue #1105.

The behavior tests run the locked ruff with the backend configuration on a
source passed on its standard input, under the name of a file of `app/` or
`tests/`; ruff writes no cache and changes no file. The configuration tests
read `backend/pyproject.toml` and the files that `ruff check .` analyzes.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parents[1]
PYPROJECT_PATH = BACKEND_ROOT / "pyproject.toml"

# The rules that the analysis selects besides flake8-bandit.
EXTRA_SECURITY_RULES = frozenset({"PLE2502", "PGH004"})

EVAL = "def run(text: str) -> object:\n    return eval(text)"


def _ruff(*args: str, source: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "ruff", *args],
        cwd=BACKEND_ROOT,
        input=source,
        capture_output=True,
        text=True,
        check=False,
    )


def _check(source: str, filename: str = "app/example.py") -> tuple[int, set[str]]:
    """The exit code of `ruff check` on `source` as the backend file
    `filename`, and the codes that it reports."""
    result = _ruff(
        "check",
        "--no-cache",
        "--output-format",
        "json",
        "--stdin-filename",
        filename,
        "-",
        source=source,
    )
    assert result.stdout, result.stderr
    return result.returncode, {item["code"] for item in json.loads(result.stdout)}


@pytest.mark.unit
@pytest.mark.parametrize(
    ("source", "expected"),
    [
        pytest.param(f"{EVAL}\n", {"S307"}, id="insecure-call"),
        # Bandit's B105 did not check annotated assignments.
        pytest.param(
            'from typing import Final\n\nAPI_TOKEN: Final = "fictional-value"\n',
            {"S105"},
            id="annotated-hardcoded-credential",
        ),
        # Parsed for the version of requires-python, whatever the interpreter
        # (issue #1103).
        pytest.param(
            "def run(text: str) -> object:\n"
            "    try:\n"
            "        return eval(text)\n"
            "    except ValueError, TypeError:\n"
            "        return None\n",
            {"S307"},
            id="project-python-syntax",
        ),
        pytest.param("def run(:\n", {"invalid-syntax"}, id="unparsable-file"),
        pytest.param(
            f"{EVAL}  # noqa: S999 — reason\n", {"RUF102", "S307"}, id="unknown-code"
        ),
        pytest.param(
            f"{EVAL}  # noqa: S105 — reason\n",
            {"RUF100", "S307"},
            id="code-without-finding",
        ),
        pytest.param(f"{EVAL}  # noqa\n", {"PGH004"}, id="line-suppression-no-code"),
        pytest.param(
            f"# ruff: noqa\n{EVAL}\n", {"PGH004"}, id="file-exemption-no-code"
        ),
        pytest.param(
            'TEXT = "left\u202eright"\n', {"PLE2502"}, id="bidirectional-control"
        ),
    ],
)
def test_app_source_with_a_finding_fails_the_analysis(
    source: str, expected: set[str]
) -> None:
    assert _check(source) == (1, expected)


@pytest.mark.unit
@pytest.mark.parametrize(
    ("source", "filename"),
    [
        pytest.param(
            'PASSWORD_RESET = "password_reset"  # noqa: S105 — classification value\n',
            "app/example.py",
            id="suppression-with-its-code",
        ),
        # S101 is disabled: application code uses assert to narrow types.
        pytest.param(
            "def first(value: int | None) -> int:\n"
            "    assert value is not None\n"
            "    return value\n",
            "app/example.py",
            id="assert",
        ),
        pytest.param(f"{EVAL}\n", "tests/test_services/test_example.py", id="tests"),
    ],
)
def test_accepted_source_passes_the_analysis(source: str, filename: str) -> None:
    assert _check(source, filename) == (0, set())


def _security_rules() -> frozenset[str]:
    """The codes of every rule of the analysis."""
    result = _ruff("rule", "--all", "--output-format", "json")
    bandit = {
        str(rule["code"])
        for rule in json.loads(result.stdout)
        if rule.get("linter") == "flake8-bandit"
    }
    assert bandit, result.stderr
    return frozenset(bandit | EXTRA_SECURITY_RULES)


def _disabling(selectors: list[str], rules: frozenset[str]) -> list[str]:
    """The selectors that disable a rule of the analysis: ruff selects rules
    by code prefix, and `ALL` selects every rule."""
    return [
        selector
        for selector in selectors
        if selector == "ALL" or any(code.startswith(selector) for code in rules)
    ]


@pytest.mark.unit
def test_security_rules_are_disabled_only_for_assert_and_tests() -> None:
    config = tomllib.loads(PYPROJECT_PATH.read_text(encoding="utf-8"))
    lint = config["tool"]["ruff"]["lint"]
    rules = _security_rules()
    ignores = [*lint.get("ignore", []), *lint.get("extend-ignore", [])]
    per_file_ignores = {
        **lint.get("per-file-ignores", {}),
        **lint.get("extend-per-file-ignores", {}),
    }

    assert {"S", *EXTRA_SECURITY_RULES} <= set(lint["select"])
    assert _disabling(ignores, rules) == ["S101"]
    assert {
        pattern: disabling
        for pattern, selectors in per_file_ignores.items()
        if (disabling := _disabling(selectors, rules))
    } == {"tests/**": ["S"]}
    # lint.exclude skips files without listing them as skipped; the
    # exclusions that apply to every tool are checked below.
    assert "exclude" not in lint


@pytest.mark.unit
def test_lint_run_analyzes_every_tracked_app_file() -> None:
    # `ruff check .`, as the lint run invokes it, silently skips a file that
    # an exclusion or a .gitignore pattern matches.
    tracked = subprocess.run(
        ["git", "ls-files", "-z", "--", "app/*.py"],
        cwd=BACKEND_ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split("\0")
    expected = {BACKEND_ROOT / path for path in tracked if path}
    shown = _ruff("check", "--no-cache", "--show-files", ".")
    analyzed = {Path(line) for line in shown.stdout.splitlines()}

    assert len(expected) > 100
    assert {path for path in expected if path.exists()} - analyzed == set()
