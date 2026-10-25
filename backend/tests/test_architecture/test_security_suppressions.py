"""Structural test: every suppression of a security rule in `backend/app/`
names its rule codes and gives its reason, and no file of `backend/app/` is
exempt from a security rule.

See `docs/features/platform/testing-strategy.md` (Structural Tests table, row
"Security suppressions") and `docs/conventions.md` (Static Security
Analysis). The security rules are ruff's flake8-bandit rules (`S`), `PLE2502`,
and `PGH004`. Ruff already fails a `noqa` comment that names no code
(`PGH004`), an unknown code (`RUF102`), or a code with no finding on its line
(`RUF100`). This test adds what ruff does not check: a line suppression of a
security rule gives its reason, in the form `# noqa: S105 — reason`, and no
file-level exemption (`# ruff: noqa: S307`) silences a security rule on every
line of a file. `PGH004` does not report a file-level exemption that names a
code.

Comments are read with `tokenize`, as ruff reads them from the tokens, so a
string that contains `# noqa` is not a suppression. See issue #1105.
"""

from __future__ import annotations

import io
import re
import tokenize
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parents[2]
APP_ROOT = BACKEND_ROOT / "app"

# How ruff recognizes a file-level exemption and a line suppression in a
# comment, matched more broadly than ruff (any case and spacing), so that no
# form that ruff accepts escapes the test.
FILE_EXEMPTION = re.compile(r"#\s*(?:ruff|flake8)\s*:\s*noqa\b(?P<rest>.*)", re.I)
LINE_SUPPRESSION = re.compile(r"#\s*noqa\b(?=(?P<rest>.*))", re.I)
CODES = re.compile(r"\s*:\s*(?P<codes>[A-Z]+[0-9]+(?:[\s,]+[A-Z]+[0-9]+)*)", re.I)
SECURITY_CODE = re.compile(r"S[0-9]+|PLE2502|PGH004", re.I)
ACCEPTED = re.compile(r"# noqa: [A-Z]+[0-9]+(?:, [A-Z]+[0-9]+)* — \S.*")


def _codes(rest: str) -> list[str]:
    """The rule codes after a `noqa`; none for a suppression of every rule."""
    match = CODES.match(rest)
    return re.split(r"[\s,]+", match["codes"]) if match else []


def _silences_security_rules(rest: str) -> bool:
    codes = _codes(rest)
    return not codes or any(SECURITY_CODE.fullmatch(code) for code in codes)


def _violation(comment: str) -> str | None:
    """Why `comment` is not an accepted suppression of a security rule, or
    None when it is accepted or suppresses no security rule."""
    exemption = FILE_EXEMPTION.search(comment)
    if exemption and _silences_security_rules(exemption["rest"]):
        return "file-level exemption from a security rule"
    for suppression in LINE_SUPPRESSION.finditer(comment):
        if _silences_security_rules(suppression["rest"]) and not ACCEPTED.fullmatch(
            comment
        ):
            return "not in the form '# noqa: S105 — reason'"
    return None


def _violations(source: str) -> list[tuple[int, str]]:
    """The line and reason of every comment in `source` that suppresses a
    security rule in a form other than the accepted one."""
    tokens = tokenize.generate_tokens(io.StringIO(source).readline)
    return [
        (token.start[0], reason)
        for token in tokens
        if token.type == tokenize.COMMENT
        and (reason := _violation(token.string)) is not None
    ]


@pytest.mark.unit
def test_every_app_security_suppression_names_its_codes_and_a_reason() -> None:
    violations = [
        f"{path.relative_to(BACKEND_ROOT).as_posix()}:{line}: {reason}"
        for path in sorted(APP_ROOT.rglob("*.py"))
        for line, reason in _violations(path.read_text(encoding="utf-8"))
    ]

    assert violations == []


@pytest.mark.unit
@pytest.mark.parametrize(
    "comment",
    [
        "# noqa: S105 — classification value, not a credential",
        "# noqa: S105, S110 — error code, not a credential",
        "# noqa: PLE2502 — reason",
        "# noqa: F401",  # not a security rule
        "# noqa: N818 — specified name",
        "# ruff: noqa: E402",
        "# a comment that mentions no suppression",
    ],
)
def test_accepted_comments_are_not_reported(comment: str) -> None:
    assert _violations(f"VALUE = 1  {comment}\n") == []


@pytest.mark.unit
@pytest.mark.parametrize(
    "comment",
    [
        "# noqa",  # silences every rule
        "# NOQA",
        "# noqa: S105",  # no reason
        "# noqa:S105 — reason",
        "# noqa: S105 reason",
        "# noqa: S105  # reason",
        "# noqa: S105,S110 — reason",
        "# reason  # noqa: S105",
        "# noqa: E501  # noqa: S105 — reason",
    ],
)
def test_other_line_suppressions_are_reported(comment: str) -> None:
    assert _violations(f"VALUE = 1  {comment}\n") == [
        (1, "not in the form '# noqa: S105 — reason'")
    ]


@pytest.mark.unit
@pytest.mark.parametrize(
    "comment",
    [
        "# ruff: noqa",
        "# ruff: noqa: S307",
        "# ruff: noqa: E402, S307",
        "# flake8: noqa: S307",
        "#ruff:noqa:PGH004",
        "# Ruff: NOQA: PLE2502",
    ],
)
def test_file_level_exemptions_from_security_rules_are_reported(comment: str) -> None:
    assert _violations(f"{comment}\nVALUE = 1\n") == [
        (1, "file-level exemption from a security rule")
    ]


@pytest.mark.unit
def test_string_that_contains_noqa_is_not_a_suppression() -> None:
    assert _violations('TEXT = "# noqa: S105"\n') == []
