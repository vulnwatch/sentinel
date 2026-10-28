"""Structural test: Pydantic's `MISSING` is the only omitted-value marker.

See `docs/features/platform/testing-strategy.md` (Structural Tests table, row
"Omitted-value markers") and `docs/conventions.md` (Omitted Values). Every
module in `backend/app/` and `backend/tests/` is read with `ast` and must not
build a marker of its own:

- no `object()` assigned at module or class level (a local stand-in object
  inside a function is not a marker);
- no reference to the `sentinel` or `Sentinel` name of `typing_extensions`,
  and no call of a bare `sentinel(...)` or `Sentinel(...)`, which Python 3.15
  provides as a builtin; and
- no class named like a marker type, such as `_MissingType` or `Unset`.

In `backend/app/`, presence is not read back from Pydantic's set of provided
fields: `model_fields_set` is referenced only in `app/schemas/`, where a
request schema rejects a body that provides no field, and no `exclude_unset`
keyword or `response_model_exclude_unset` argument is used. A marker built in
another way, such as a single-member enum under another name, is out of scope
and remains with review.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parents[2]
APP_ROOT = BACKEND_ROOT / "app"
TESTS_ROOT = BACKEND_ROOT / "tests"
SCHEMAS_ROOT = APP_ROOT / "schemas"

MARKER_CLASS = re.compile(r"_*(?:Missing|MissingType|Unset|UnsetType|NotSet|Sentinel)")
SENTINEL_NAMES = frozenset({"sentinel", "Sentinel"})
UNSET_KEYWORDS = frozenset({"exclude_unset", "response_model_exclude_unset"})

OBJECT_MARKER = "object() assigned at module or class level"
SENTINEL = "sentinel built with typing_extensions or the builtin"
MARKER_TYPE = "class named like an omitted-value marker type"
FIELDS_SET = "model_fields_set outside app/schemas/"
EXCLUDE_UNSET = "exclude_unset keyword"


def _is_object_call(node: ast.expr | None) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "object"
        and not node.args
        and not node.keywords
    )


def _module_and_class_statements(body: list[ast.stmt]) -> Iterator[ast.stmt]:
    """Every statement outside a function body, including those of class
    bodies and of compound statements such as `if TYPE_CHECKING:`."""
    for statement in body:
        if isinstance(statement, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        yield statement
        children: list[ast.stmt] = []
        for field in ("body", "orelse", "finalbody"):
            nested = getattr(statement, field, None)
            if isinstance(nested, list):
                children.extend(nested)
        for handler in getattr(statement, "handlers", ()):
            children.extend(handler.body)
        yield from _module_and_class_statements(children)


def _is_sentinel_reference(node: ast.AST, extensions_aliases: set[str]) -> bool:
    """Whether `node` imports or references the `sentinel` type of
    `typing_extensions`, or calls a bare `sentinel`."""
    if isinstance(node, ast.ImportFrom):
        return node.module == "typing_extensions" and any(
            alias.name in SENTINEL_NAMES for alias in node.names
        )
    if isinstance(node, ast.Attribute):
        return (
            node.attr in SENTINEL_NAMES
            and isinstance(node.value, ast.Name)
            and node.value.id in extensions_aliases
        )
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in SENTINEL_NAMES
    )


def _marker_violations(tree: ast.Module) -> list[tuple[int, str]]:
    """The line and reason of every hand-rolled marker in `tree`."""
    violations: list[tuple[int, str]] = []
    for statement in _module_and_class_statements(tree.body):
        if isinstance(statement, ast.Assign | ast.AnnAssign) and _is_object_call(
            statement.value
        ):
            violations.append((statement.lineno, OBJECT_MARKER))

    extensions_aliases = {
        alias.asname or alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
        if alias.name == "typing_extensions"
    }
    for node in ast.walk(tree):
        if _is_sentinel_reference(node, extensions_aliases):
            violations.append((getattr(node, "lineno", 0), SENTINEL))
        elif isinstance(node, ast.ClassDef) and MARKER_CLASS.fullmatch(node.name):
            violations.append((node.lineno, MARKER_TYPE))
    return sorted(violations)


def _presence_violations(tree: ast.Module, *, schema: bool) -> list[tuple[int, str]]:
    """The line and reason of every presence read in an application module;
    `schema` allows `model_fields_set`."""
    violations: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if not schema and (
            (isinstance(node, ast.Attribute) and node.attr == "model_fields_set")
            or (isinstance(node, ast.Name) and node.id == "model_fields_set")
        ):
            violations.append((node.lineno, FIELDS_SET))
        elif isinstance(node, ast.keyword) and node.arg in UNSET_KEYWORDS:
            violations.append((node.lineno, EXCLUDE_UNSET))
    return sorted(violations)


def _parse(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _sources(*roots: Path) -> list[Path]:
    return sorted(path for root in roots for path in root.rglob("*.py"))


@pytest.mark.unit
def test_no_module_builds_its_own_omitted_value_marker() -> None:
    violations = [
        f"{path.relative_to(BACKEND_ROOT).as_posix()}:{line}: {reason}"
        for path in _sources(APP_ROOT, TESTS_ROOT)
        for line, reason in _marker_violations(_parse(path))
    ]

    assert violations == []


@pytest.mark.unit
def test_app_reads_no_presence_from_the_provided_fields() -> None:
    violations = [
        f"{path.relative_to(BACKEND_ROOT).as_posix()}:{line}: {reason}"
        for path in _sources(APP_ROOT)
        for line, reason in _presence_violations(
            _parse(path), schema=path.is_relative_to(SCHEMAS_ROOT)
        )
    ]

    assert violations == []


@pytest.mark.unit
@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("_UNSET = object()\n", [(1, OBJECT_MARKER)]),
        ("_ABSENT: Final = object()\n", [(1, OBJECT_MARKER)]),
        ("class C:\n    MARK = object()\n", [(2, OBJECT_MARKER)]),
        (
            "if TYPE_CHECKING:\n    pass\nelse:\n    MARK = object()\n",
            [(4, OBJECT_MARKER)],
        ),
        ("from typing_extensions import sentinel\n", [(1, SENTINEL)]),
        ("from typing_extensions import Sentinel as S\n", [(1, SENTINEL)]),
        ("import typing_extensions as te\nX = te.sentinel('X')\n", [(2, SENTINEL)]),
        ("X = sentinel('X')\n", [(1, SENTINEL)]),
        ("class _MissingType:\n    pass\n", [(1, MARKER_TYPE)]),
        ("class Unset(Enum):\n    UNSET = 'unset'\n", [(1, MARKER_TYPE)]),
        ("class __NotSet:\n    pass\n", [(1, MARKER_TYPE)]),
    ],
    ids=[
        "module-object",
        "annotated-object",
        "class-object",
        "compound-object",
        "typing-extensions-sentinel",
        "typing-extensions-aliased-sentinel",
        "typing-extensions-attribute",
        "builtin-sentinel",
        "missing-type-class",
        "unset-enum",
        "not-set-class",
    ],
)
def test_each_marker_form_is_detected(
    source: str, expected: list[tuple[int, str]]
) -> None:
    """Guards the checker itself against passing vacuously."""
    assert _marker_violations(ast.parse(source)) == expected


@pytest.mark.unit
@pytest.mark.parametrize(
    "source",
    [
        "from pydantic import MISSING\nX: int | MISSING = MISSING\n",
        "def f():\n    marker = object()\n    return marker\n",
        "def f(flag):\n    return object() if flag else None\n",
        "from unittest.mock import sentinel\nX = sentinel.value\n",
        "def test_sentinel(sentinel):\n    return sentinel\n",
        "class TestMissingTicket:\n    pass\n",
        "class SentinelAPI:\n    pass\n",
    ],
    ids=[
        "pydantic-missing",
        "local-object",
        "local-conditional-object",
        "mock-sentinel-attribute",
        "parameter-named-sentinel",
        "test-class",
        "longer-class-name",
    ],
)
def test_other_code_is_not_reported(source: str) -> None:
    assert _marker_violations(ast.parse(source)) == []


@pytest.mark.unit
@pytest.mark.parametrize(
    ("source", "schema", "expected"),
    [
        ("present = body.model_fields_set\n", False, [(1, FIELDS_SET)]),
        ("present = body.model_fields_set\n", True, []),
        ("data = model.model_dump(exclude_unset=True)\n", True, [(1, EXCLUDE_UNSET)]),
        (
            "@router.get('/x', response_model_exclude_unset=True)\ndef f(): ...\n",
            False,
            [(1, EXCLUDE_UNSET)],
        ),
        ("data = model.model_dump(exclude_none=True)\n", False, []),
    ],
    ids=[
        "fields-set-outside-schemas",
        "fields-set-in-schemas",
        "exclude-unset",
        "response-model-exclude-unset",
        "other-keyword",
    ],
)
def test_each_presence_read_is_detected(
    source: str, schema: bool, expected: list[tuple[int, str]]
) -> None:
    assert _presence_violations(ast.parse(source), schema=schema) == expected
