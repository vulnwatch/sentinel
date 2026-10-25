"""Structural test: every suppression of a security rule in `backend/app/`
names its rule codes and gives its reason, and no file or range of
`backend/app/` is exempt from a security rule.

See `docs/features/platform/testing-strategy.md` (Structural Tests table, row
"Security suppressions") and `docs/conventions.md` (Static Security
Analysis). The security rules are ruff's flake8-bandit rules (`S`), `PLE2502`,
and `PGH004`. Ruff already fails a `noqa` comment that names no code
(`PGH004`), an unknown code (`RUF102`), or a code with no finding on its line
(`RUF100`). This test adds what ruff does not check:

- a line suppression of a security rule gives its reason, in the form
  `# noqa: S105 — reason`;
- no file-level exemption (`# ruff: noqa: S307`) silences a security rule on
  every line of a file: `PGH004` does not report one that names a code; and
- no other ruff suppression comment (`# ruff: ignore[S307]` on a line, or
  `# ruff: disable[S307]` ... `# ruff: enable[S307]` around a range) silences
  a security rule without a reason, or across a whole file.

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

# How ruff recognizes its suppression comments, matched more broadly than ruff
# (any case and spacing), so that no form that ruff accepts escapes the test.
FILE_EXEMPTION = re.compile(r"#\s*(?:ruff|flake8)\s*:\s*noqa\b(?P<rest>.*)", re.I)
LINE_SUPPRESSION = re.compile(r"#\s*noqa\b(?=(?P<rest>.*))", re.I)
RUFF_SUPPRESSION = re.compile(
    r"#\s*ruff\s*:\s*(?:ignore|disable|enable)\b\s*(?:\[(?P<codes>[^\]]*)\])?", re.I
)
NOQA_CODES = re.compile(r"\s*:\s*(?P<codes>[A-Z]+[0-9]+(?:[\s,]+[A-Z]+[0-9]+)*)", re.I)
SECURITY_CODE = re.compile(r"S[0-9]+|PLE2502|PGH004", re.I)
ACCEPTED = re.compile(r"# noqa: [A-Z]+[0-9]+(?:, [A-Z]+[0-9]+)* — \S.*")

FORM = "not in the form '# noqa: S105 — reason'"
FILE_LEVEL = "file-level exemption from a security rule"
RUFF_COMMENT = "'# ruff:' suppression comment of a security rule"


def _silences_security_rules(codes: str | None) -> bool:
    """Whether a suppression with these rule codes silences a security rule;
    one that names no code silences every rule."""
    names = [name for name in re.split(r"[\s,]+", codes or "") if name]
    return not names or any(SECURITY_CODE.fullmatch(name) for name in names)


def _noqa_codes(rest: str) -> str | None:
    """The rule codes after a `noqa`, if any."""
    match = NOQA_CODES.match(rest)
    return match["codes"] if match else None


def _violation(comment: str) -> str | None:
    """Why `comment` is not an accepted suppression of a security rule, or
    None when it is accepted or suppresses no security rule."""
    exemption = FILE_EXEMPTION.search(comment)
    if exemption and _silences_security_rules(_noqa_codes(exemption["rest"])):
        return FILE_LEVEL
    for suppression in RUFF_SUPPRESSION.finditer(comment):
        if _silences_security_rules(suppression["codes"]):
            return RUFF_COMMENT
    for suppression in LINE_SUPPRESSION.finditer(comment):
        if _silences_security_rules(
            _noqa_codes(suppression["rest"])
        ) and not ACCEPTED.fullmatch(comment):
            return FORM
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
        "# ruff: ignore[E501]",
        "# ruff: disable[E501]",
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
    assert _violations(f"VALUE = 1  {comment}\n") == [(1, FORM)]


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
    assert _violations(f"{comment}\nVALUE = 1\n") == [(1, FILE_LEVEL)]


@pytest.mark.unit
@pytest.mark.parametrize(
    "comment",
    [
        "# ruff: ignore[S307]",
        "# ruff: ignore[S307]  # reason",
        "# ruff:ignore[E501, S105]",
        "# ruff: disable[S307]",
        "# ruff: enable[S307]",
        "# ruff: disable[PLE2502]",
        "# ruff: disable[PGH004]",
        "# ruff: ignore",  # names no code
    ],
)
def test_ruff_suppression_comments_of_security_rules_are_reported(
    comment: str,
) -> None:
    assert _violations(f"VALUE = 1  {comment}\n") == [(1, RUFF_COMMENT)]


@pytest.mark.unit
def test_string_that_contains_noqa_is_not_a_suppression() -> None:
    assert _violations('TEXT = "# noqa: S105"\n') == []
