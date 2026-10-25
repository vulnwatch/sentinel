"""Structural test: every bandit suppression in `backend/app/` names only test
IDs and gives its reason in a separate comment.

See `docs/features/platform/testing-strategy.md` (Structural Tests table, row
"Bandit suppressions") and `docs/conventions.md` (Static Security Analysis).
Bandit reads a comment as a suppression when it contains `#` followed by
`nosec`, and reads every word between `nosec` and the next `#` as a test ID
or a test name. In `# nosec B105 -- a random value`, the word `random` names
test B311, which the comment then suppresses too. The accepted form is
therefore `# nosec B105  # reason`, with several IDs separated by `, `.

Comments are read with `tokenize`, as bandit reads them, so a string that
contains `# nosec` is not a suppression. See issue #1103.
"""

from __future__ import annotations

import io
import re
import tokenize
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parents[2]
APP_ROOT = BACKEND_ROOT / "app"

# How bandit recognizes a suppression comment (bandit.core.manager).
SUPPRESSION = re.compile(r"#\s*nosec")
ACCEPTED = re.compile(r"# nosec B\d{3}(?:, B\d{3})*\s+#\s*\S.*")


def _invalid_suppressions(source: str) -> list[tuple[int, str]]:
    """The line and text of every suppression comment in `source` that is not
    in the accepted form."""
    tokens = tokenize.generate_tokens(io.StringIO(source).readline)
    return [
        (token.start[0], token.string)
        for token in tokens
        if token.type == tokenize.COMMENT
        and SUPPRESSION.search(token.string)
        and not ACCEPTED.fullmatch(token.string)
    ]


@pytest.mark.unit
def test_every_app_suppression_names_only_test_ids_and_a_reason() -> None:
    violations = [
        f"{path.relative_to(BACKEND_ROOT).as_posix()}:{line}: {comment}"
        for path in sorted(APP_ROOT.rglob("*.py"))
        for line, comment in _invalid_suppressions(path.read_text(encoding="utf-8"))
    ]

    assert violations == []


@pytest.mark.unit
@pytest.mark.parametrize(
    "comment",
    [
        "# nosec B105  # classification value, not a credential",
        "# nosec B105, B110  # error code, not a credential",
        "# nosec B110 # the primary failure propagates",
        "# a comment that mentions no suppression",
    ],
)
def test_accepted_comments_are_not_reported(comment: str) -> None:
    assert _invalid_suppressions(f"VALUE = 1  {comment}\n") == []


@pytest.mark.unit
@pytest.mark.parametrize(
    "comment",
    [
        "# nosec",  # suppresses every test
        "# nosec B105",  # no reason
        "# nosec B105 -- a random value",  # 'random' names test B311
        "# nosec B105 classification value",
        "# nosec: B105  # reason",
        "# nosec B105 B110  # reason",
        "# nosec hardcoded_password_string  # reason",  # a name, not an ID
        "# reason # nosec B105",
        "#nosec B105  # reason",
    ],
)
def test_other_suppression_forms_are_reported(comment: str) -> None:
    assert _invalid_suppressions(f"VALUE = 1  {comment}\n") == [(1, comment)]


@pytest.mark.unit
def test_string_that_contains_nosec_is_not_a_suppression() -> None:
    assert _invalid_suppressions('TEXT = "# nosec"\n') == []
