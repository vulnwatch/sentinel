"""Structural test: the Slack bot token serves only the lookup of user
pictures.

See `docs/features/identity/user-avatars.md` (Slack App and Bot Token: the
token is read only by the `sync_slack_avatars` module and used only for
`users.lookupByEmail`) and `docs/features/platform/testing-strategy.md`
(Structural Tests, Slack token boundary).

Every module in `backend/app/` is enumerated via AST:

1. every reference to the `slack_bot_token` setting — an attribute named
   `slack_bot_token`, a bare name, or a keyword argument of that name —
   occurs only in `app/services/identity/sync_slack_avatars.py`, except its
   definition in the `Settings` class of `app/config.py`;
2. every string literal other than a docstring that contains `slack.com`,
   compared case-insensitively, equals
   `https://slack.com/api/users.lookupByEmail` and occurs only in that
   module. The parts of an f-string are literals too.

Blind spots: a string reference to the setting (such as the field list of a
validator), `getattr()` with a variable name, a `**` expansion, and a URL
assembled from parts that do not each contain `slack.com`.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Final

import pytest

BACKEND_ROOT = Path(__file__).resolve().parents[2]
APP_ROOT = BACKEND_ROOT / "app"

SETTING: Final = "slack_bot_token"
OWNER: Final = "app/services/identity/sync_slack_avatars.py"
DEFINITION: Final = "app/config.py"
LOOKUP_URL: Final = "https://slack.com/api/users.lookupByEmail"


def _docstrings(tree: ast.AST) -> set[int]:
    """`id()` of every docstring constant in `tree`."""
    found: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(
            node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef
        ):
            first = node.body[0] if node.body else None
            if (
                isinstance(first, ast.Expr)
                and isinstance(first.value, ast.Constant)
                and isinstance(first.value.value, str)
            ):
                found.add(id(first.value))
    return found


def _definitions(tree: ast.AST) -> set[int]:
    """`id()` of the target of every `slack_bot_token` field declared in a
    class body named `Settings`."""
    found: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == "Settings":
            for statement in node.body:
                if (
                    isinstance(statement, ast.AnnAssign | ast.Assign)
                    and isinstance(
                        target := (
                            statement.target
                            if isinstance(statement, ast.AnnAssign)
                            else statement.targets[0]
                        ),
                        ast.Name,
                    )
                    and target.id == SETTING
                ):
                    found.add(id(target))
    return found


def setting_references(source: str, *, module: str) -> list[int]:
    """Line of every reference to the setting in `source`, except its
    definition when `module` is `app/config.py`."""
    tree = ast.parse(source)
    exempt = _definitions(tree) if module == DEFINITION else set()
    lines: list[int] = []
    for node in ast.walk(tree):
        if id(node) in exempt:
            continue
        if (
            (isinstance(node, ast.Attribute) and node.attr == SETTING)
            or (isinstance(node, ast.Name) and node.id == SETTING)
            or (isinstance(node, ast.keyword) and node.arg == SETTING)
        ):
            lines.append(node.lineno)
    return sorted(lines)


def slack_literals(source: str) -> list[str]:
    """Every string literal of `source` other than a docstring that contains
    `slack.com`, case-insensitively."""
    tree = ast.parse(source)
    docstrings = _docstrings(tree)
    values: list[str] = []
    for node in ast.walk(tree):
        if id(node) in docstrings or not isinstance(node, ast.Constant):
            continue
        value = node.value
        text = value.decode("latin-1") if isinstance(value, bytes) else value
        if isinstance(text, str) and "slack.com" in text.lower():
            values.append(text)
    return values


def _app_sources() -> dict[str, str]:
    return {
        path.relative_to(BACKEND_ROOT).as_posix(): path.read_text(encoding="utf-8")
        for path in sorted(APP_ROOT.rglob("*.py"))
    }


@pytest.mark.unit
class TestDetector:
    """The checks on synthetic sources, independent of `app/`."""

    @pytest.mark.parametrize(
        "source",
        [
            "token = settings.slack_bot_token.get_secret_value()",
            "from app.config import settings as s\nvalue = s.slack_bot_token",
            "slack_bot_token = load()",
            "Settings(slack_bot_token=value)",
        ],
    )
    def test_reference_is_detected(self, source: str) -> None:
        assert setting_references(source, module="app/services/example.py") != []

    def test_reference_in_config_outside_the_definition_is_detected(self) -> None:
        source = (
            "class Settings(BaseSettings):\n"
            "    slack_bot_token: SecretStr = SecretStr('')\n"
            "\n"
            "def leak(settings):\n"
            "    return settings.slack_bot_token\n"
        )

        assert setting_references(source, module=DEFINITION) == [5]

    @pytest.mark.parametrize(
        "source",
        [
            "class Settings(BaseSettings):\n    slack_bot_token: SecretStr\n",
            "FIELDS = ('nvd_api_key', 'slack_bot_token')",
            "x = settings.github_token",
        ],
    )
    def test_definition_and_string_reference_are_not_detected(
        self, source: str
    ) -> None:
        assert setting_references(source, module=DEFINITION) == []

    def test_definition_outside_config_is_a_reference(self) -> None:
        source = "class Settings(BaseSettings):\n    slack_bot_token: SecretStr\n"

        assert setting_references(source, module="app/settings2.py") == [2]

    @pytest.mark.parametrize(
        ("source", "expected"),
        [
            (
                'URL = "https://slack.com/api/users.list"',
                ["https://slack.com/api/users.list"],
            ),
            ('URL = "https://SLACK.COM/api/x"', ["https://SLACK.COM/api/x"]),
            ('URL = b"https://slack.com/api/x"', ["https://slack.com/api/x"]),
            ('url = f"https://slack.com/api/{method}"', ["https://slack.com/api/"]),
            (
                'def f():\n    x = 1\n    "https://slack.com/api/x"',
                ["https://slack.com/api/x"],
            ),
        ],
    )
    def test_slack_literal_is_detected(self, source: str, expected: list[str]) -> None:
        assert slack_literals(source) == expected

    @pytest.mark.parametrize(
        "source",
        [
            '"""Calls https://slack.com/api/users.lookupByEmail."""',
            'def f():\n    """See slack.com."""\n',
            'class C:\n    """See slack.com."""\n',
            'URL = "https://avatars.slack-edge.com/x"',
        ],
    )
    def test_docstring_and_other_host_are_not_detected(self, source: str) -> None:
        assert slack_literals(source) == []


@pytest.mark.unit
class TestSlackTokenBoundary:
    def test_only_the_fetcher_module_references_the_token(self) -> None:
        found = {
            module
            for module, source in _app_sources().items()
            if setting_references(source, module=module)
        }

        assert found == {OWNER}, (
            "the Slack bot token is referenced outside the sync_slack_avatars "
            "module (docs/features/identity/user-avatars.md, Slack App and Bot "
            "Token)"
        )

    def test_the_lookup_url_is_the_only_slack_url_and_only_in_the_fetcher(
        self,
    ) -> None:
        found = {
            (module, literal)
            for module, source in _app_sources().items()
            for literal in slack_literals(source)
        }

        assert found == {(OWNER, LOOKUP_URL)}, (
            "a Slack URL other than users.lookupByEmail, or outside the "
            "sync_slack_avatars module "
            "(docs/features/identity/user-avatars.md, Slack App and Bot Token)"
        )
