"""Structural test: module-level constant mappings are `frozendict`.

See `docs/features/platform/testing-strategy.md` (Structural Tests table, row
"Constant mappings") and `docs/conventions.md` (Constant Mappings). Every
module-level assignment in `backend/app/` that binds an `UPPER_SNAKE_CASE`
name is read with `ast`, outside function and class bodies:

- a binding to a mapping other than a `frozendict` (a dict display or
  comprehension, a call of `dict`, `MappingProxyType`, `OrderedDict`, or
  `defaultdict`, or an annotation with another mapping type) is one of the
  module-level `dict` mappings listed in `DICT_MAPPINGS`, each with the
  registry or third-party API that requires the `dict`;
- a binding to a `frozendict` is annotated `Final[frozendict[K, V]]`; and
- the value of every `frozendict` binding, read from the imported module,
  is a `frozendict` and nests no mutable container and no mapping other than
  a `frozendict`.

A call of a function that the same module defines is classified by the
function's return annotation. A mapping built by any other function call
without a mapping annotation, and a mapping nested in a constant of another
type, such as a dataclass field, are out of scope and remain with review.
"""

from __future__ import annotations

import ast
import importlib
import re
from collections import OrderedDict
from collections.abc import Iterator, Mapping, MutableSequence, MutableSet
from pathlib import Path
from types import MappingProxyType
from typing import Final

import pytest

BACKEND_ROOT = Path(__file__).resolve().parents[2]
APP_ROOT = BACKEND_ROOT / "app"

CONSTANT_NAME = re.compile(r"_*[A-Z][A-Z0-9_]*")
MUTABLE_MAPPING_CALLS = frozenset(
    {"dict", "MappingProxyType", "OrderedDict", "defaultdict"}
)
MAPPING_TYPES = frozenset(
    {
        "dict",
        "Dict",
        "Mapping",
        "MutableMapping",
        "MappingProxyType",
        "OrderedDict",
        "defaultdict",
        "DefaultDict",
        "Counter",
        "ChainMap",
    }
)

FROZEN = "frozendict"
MUTABLE = "mapping that is not a frozendict"
FORM = "frozendict not annotated Final[frozendict[K, V]]"

_RESPONSES = "FastAPI `responses=` requires a dict for every response"
_SCHEMA_EXTRA = "Pydantic and FastAPI ignore a `json_schema_extra` that is not a dict"
_REGISTRY = "registry filled at import time"

DICT_MAPPINGS: Final[frozendict[tuple[str, str], str]] = frozendict(
    {
        ("app/api/openapi.py", "API_V1_RESPONSES"): _RESPONSES,
        ("app/api/v1/fetchers.py", "_NOT_FOUND_RESPONSE"): _RESPONSES,
        ("app/api/v1/ticket_audit.py", "_TICKET_NOT_FOUND_RESPONSE"): _RESPONSES,
        ("app/api/v1/ticket_packages.py", "_NOT_MUTABLE_RESPONSE"): _RESPONSES,
        ("app/celery_app.py", "_BEAT_SCHEDULE"): "Celery `beat_schedule`",
        ("app/core/jwt.py", "_DECODE_OPTIONS"): "PyJWT decoding `options`",
        ("app/schemas/cna.py", "CNA_ORG_ID_FILTER_SCHEMA"): _SCHEMA_EXTRA,
        ("app/schemas/cna.py", "CNA_ORG_ID_SCHEMA"): _SCHEMA_EXTRA,
        ("app/schemas/ticket.py", "_CVE_ID_SCHEMA"): _SCHEMA_EXTRA,
        ("app/schemas/ticket.py", "DUPLICATE_OF_TICKET_ID_SCHEMA"): _SCHEMA_EXTRA,
        ("app/schemas/user.py", "_PASSWORD_SCHEMA"): _SCHEMA_EXTRA,
        ("app/services/base_audit_log.py", "AUDIT_LOG_REGISTRY"): _REGISTRY,
        ("app/services/base_cve_fetcher.py", "_CVE_SOURCE_TYPE_MAP"): _REGISTRY,
        ("app/services/base_fetcher.py", "FETCHER_REGISTRY"): _REGISTRY,
    }
)
"""The module-level `dict` mappings, by module and name, and why each is one
(`docs/conventions.md`, Constant Mappings)."""


def _module_statements(body: list[ast.stmt]) -> Iterator[ast.stmt]:
    """Every statement outside function and class bodies, including those of
    compound statements such as `if TYPE_CHECKING:`."""
    for statement in body:
        if isinstance(statement, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            continue
        yield statement
        children: list[ast.stmt] = []
        for field in ("body", "orelse", "finalbody"):
            nested = getattr(statement, field, None)
            if isinstance(nested, list):
                children.extend(nested)
        for handler in getattr(statement, "handlers", ()):
            children.extend(handler.body)
        yield from _module_statements(children)


def _name(node: ast.expr) -> str | None:
    """The name of a `Name` node or the attribute of an `Attribute` node."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _is_call(node: ast.expr | None, names: frozenset[str]) -> bool:
    return isinstance(node, ast.Call) and _name(node.func) in names


def _type_name(annotation: ast.expr | None) -> str | None:
    """The outermost type name of `annotation`, inside `Final[...]`."""
    node = annotation
    if isinstance(node, ast.Subscript) and _name(node.value) == "Final":
        node = node.slice
    if isinstance(node, ast.Subscript):
        node = node.value
    return _name(node) if node is not None else None


def _is_final_frozendict(annotation: ast.expr | None) -> bool:
    """Whether `annotation` is `Final[frozendict[...]]`."""
    return (
        isinstance(annotation, ast.Subscript)
        and _name(annotation.value) == "Final"
        and isinstance(annotation.slice, ast.Subscript)
        and _name(annotation.slice.value) == "frozendict"
    )


def _local_return_types(tree: ast.Module) -> dict[str, ast.expr]:
    """The return annotation of every function that the module defines at
    its top level, by function name."""
    return {
        statement.name: statement.returns
        for statement in tree.body
        if isinstance(statement, ast.FunctionDef) and statement.returns is not None
    }


def _kind(
    annotation: ast.expr | None,
    value: ast.expr | None,
    returns: Mapping[str, ast.expr],
) -> str | None:
    """`FROZEN` for a `frozendict` binding, `MUTABLE` for a binding to
    another mapping, `None` for any other binding. A call of a function that
    the module defines is classified by the function's return annotation."""
    type_names = {_type_name(annotation)}
    if (
        isinstance(value, ast.Call)
        and isinstance(value.func, ast.Name)
        and value.func.id in returns
    ):
        type_names.add(_type_name(returns[value.func.id]))
    if "frozendict" in type_names or _is_call(value, frozenset({"frozendict"})):
        return FROZEN
    if (
        type_names & MAPPING_TYPES
        or isinstance(value, ast.Dict | ast.DictComp)
        or _is_call(value, MUTABLE_MAPPING_CALLS)
    ):
        return MUTABLE
    return None


def _constant_mapping_bindings(
    tree: ast.Module,
) -> Iterator[tuple[int, str, str, ast.expr | None]]:
    """The line, name, kind, and annotation of every module-level binding of
    a constant name to a mapping."""
    returns = _local_return_types(tree)
    targets: list[ast.expr]
    annotation: ast.expr | None
    for statement in _module_statements(tree.body):
        if isinstance(statement, ast.AnnAssign):
            targets, annotation = [statement.target], statement.annotation
        elif isinstance(statement, ast.Assign):
            targets, annotation = statement.targets, None
        else:
            continue
        kind = _kind(annotation, statement.value, returns)
        if kind is None:
            continue
        for target in targets:
            if isinstance(target, ast.Name) and CONSTANT_NAME.fullmatch(target.id):
                yield statement.lineno, target.id, kind, annotation


def _mapping_bindings(tree: ast.Module) -> list[tuple[int, str, str]]:
    """The line, name, and kind of every module-level binding of a constant
    name to a mapping."""
    return [
        (line, name, kind) for line, name, kind, _ in _constant_mapping_bindings(tree)
    ]


def _form_violations(tree: ast.Module) -> list[tuple[int, str]]:
    """The line and reason of every `frozendict` binding of a constant name
    that is not annotated `Final[frozendict[K, V]]`."""
    return [
        (line, FORM)
        for line, _, kind, annotation in _constant_mapping_bindings(tree)
        if kind == FROZEN and not _is_final_frozendict(annotation)
    ]


def _mutable_parts(value: object, location: str = "") -> list[str]:
    """The location and type of every mutable container, and of every
    mapping other than a `frozendict`, among the values of `value` and of
    each `tuple`, `frozenset`, and `frozendict` nested in it. A key is
    hashable, so it is never a mutable container."""
    if isinstance(value, frozendict):
        return [
            part
            for key, item in value.items()
            for part in _mutable_parts(item, f"{location}[{key!r}]")
        ]
    if isinstance(value, tuple | frozenset):
        return [
            part
            for index, item in enumerate(value)
            for part in _mutable_parts(item, f"{location}[{index}]")
        ]
    if isinstance(value, Mapping | MutableSequence | MutableSet):
        return [f"{location}: {type(value).__name__}"]
    return []


def _value_violations(value: object) -> list[str]:
    """Why the value of a `frozendict` binding breaks the convention: it is
    not a `frozendict`, or it nests a mutable container."""
    if type(value) is not frozendict:
        return [f": is a {type(value).__name__}"]
    return _mutable_parts(value)


def _parse(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _module_name(path: Path) -> str:
    return ".".join(path.relative_to(BACKEND_ROOT).with_suffix("").parts).removesuffix(
        ".__init__"
    )


def _app_bindings() -> list[tuple[Path, int, str, str]]:
    return [
        (path, line, name, kind)
        for path in sorted(APP_ROOT.rglob("*.py"))
        for line, name, kind in _mapping_bindings(_parse(path))
    ]


def _relative(path: Path) -> str:
    return path.relative_to(BACKEND_ROOT).as_posix()


@pytest.mark.unit
def test_every_module_level_dict_mapping_is_listed() -> None:
    violations = [
        f"{_relative(path)}:{line}: {name}: {MUTABLE}"
        for path, line, name, kind in _app_bindings()
        if kind == MUTABLE and (_relative(path), name) not in DICT_MAPPINGS
    ]

    assert violations == []


@pytest.mark.unit
def test_every_listed_dict_mapping_is_a_module_level_dict_mapping() -> None:
    found = {
        (_relative(path), name)
        for path, _, name, kind in _app_bindings()
        if kind == MUTABLE
    }

    assert sorted(set(DICT_MAPPINGS) - found) == []


@pytest.mark.unit
def test_every_frozendict_constant_is_annotated_final_frozendict() -> None:
    violations = [
        f"{_relative(path)}:{line}: {reason}"
        for path in sorted(APP_ROOT.rglob("*.py"))
        for line, reason in _form_violations(_parse(path))
    ]

    assert violations == []


@pytest.mark.unit
def test_every_frozendict_constant_nests_no_mutable_container() -> None:
    violations: list[str] = []
    for path, line, name, kind in _app_bindings():
        if kind != FROZEN:
            continue
        value = getattr(importlib.import_module(_module_name(path)), name)
        violations.extend(
            f"{_relative(path)}:{line}: {name}{violation}"
            for violation in _value_violations(value)
        )

    assert violations == []


@pytest.mark.unit
@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("X = {}\n", [(1, "X", MUTABLE)]),
        ("_X: Final = {k: k for k in 'ab'}\n", [(1, "_X", MUTABLE)]),
        ("X = dict(a=1)\n", [(1, "X", MUTABLE)]),
        ("X: Final[Mapping[str, int]] = MappingProxyType({})\n", [(1, "X", MUTABLE)]),
        ("X = types.MappingProxyType({})\n", [(1, "X", MUTABLE)]),
        ("X = collections.OrderedDict()\n", [(1, "X", MUTABLE)]),
        ("X = defaultdict(list)\n", [(1, "X", MUTABLE)]),
        ("X: dict[str, int] = build()\n", [(1, "X", MUTABLE)]),
        ("X: Final[Mapping[str, int]] = build()\n", [(1, "X", MUTABLE)]),
        ("X: Final[typing.Mapping[str, int]] = build()\n", [(1, "X", MUTABLE)]),
        ("X: types.MappingProxyType[str, int] = build()\n", [(1, "X", MUTABLE)]),
        (
            "def build() -> dict[str, int]:\n    return {}\n\nX: Final = build()\n",
            [(4, "X", MUTABLE)],
        ),
        ("X = Y = {}\n", [(1, "X", MUTABLE), (1, "Y", MUTABLE)]),
        (
            "if TYPE_CHECKING:\n    pass\nelse:\n    X = {}\n",
            [(4, "X", MUTABLE)],
        ),
        ("try:\n    X = {}\nexcept ImportError:\n    pass\n", [(2, "X", MUTABLE)]),
        ("X: Final[frozendict[str, int]] = frozendict({})\n", [(1, "X", FROZEN)]),
        ("X: Final = frozendict(a=1)\n", [(1, "X", FROZEN)]),
        ("X: Final[frozendict[str, int]] = build()\n", [(1, "X", FROZEN)]),
        (
            "def build() -> frozendict[str, int]:\n    return frozendict()\n\n"
            "X = build()\n",
            [(4, "X", FROZEN)],
        ),
    ],
    ids=[
        "dict-display",
        "dict-comprehension",
        "dict-call",
        "mapping-proxy",
        "mapping-proxy-attribute",
        "ordered-dict",
        "defaultdict",
        "dict-annotation",
        "mapping-annotation",
        "typing-mapping-annotation",
        "mapping-proxy-annotation",
        "local-dict-builder",
        "chained-targets",
        "compound-if",
        "compound-try",
        "frozendict",
        "frozendict-final-only",
        "frozendict-annotation",
        "local-frozendict-builder",
    ],
)
def test_each_mapping_binding_is_detected(
    source: str, expected: list[tuple[int, str, str]]
) -> None:
    """Guards the checker itself against passing vacuously."""
    assert _mapping_bindings(ast.parse(source)) == expected


@pytest.mark.unit
@pytest.mark.parametrize(
    "source",
    [
        "def f():\n    X = {}\n    return X\n",
        "class C:\n    TABLE = {}\n",
        "table = {}\n",
        "X = frozenset({1})\n",
        "X: Final = (1, 2)\n",
        "X = build()\n",
        "def build() -> int:\n    return 1\n\nX: Final = build()\n",
        "X: Final = case({1: 2}, value=column)\n",
        "X: Final = Limits(counts={'a': 1})\n",
    ],
    ids=[
        "function-local",
        "class-level",
        "lowercase-name",
        "frozenset",
        "tuple",
        "unannotated-call",
        "local-non-mapping-builder",
        "mapping-argument",
        "dataclass-field",
    ],
)
def test_other_bindings_are_not_reported(source: str) -> None:
    assert _mapping_bindings(ast.parse(source)) == []


@pytest.mark.unit
@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("X: Final = frozendict(a=1)\n", [(1, FORM)]),
        ("X = frozendict(a=1)\n", [(1, FORM)]),
        ("X: frozendict[str, int] = frozendict(a=1)\n", [(1, FORM)]),
        ("X: Final[frozendict] = frozendict(a=1)\n", [(1, FORM)]),
        ("X: Final[Mapping[str, int]] = frozendict(a=1)\n", [(1, FORM)]),
        (
            "def build() -> frozendict[str, int]:\n    return frozendict()\n\n"
            "X: Final = build()\n",
            [(4, FORM)],
        ),
        ("X: Final[frozendict[str, int]] = frozendict(a=1)\n", []),
        ("x = frozendict(a=1)\n", []),
    ],
    ids=[
        "final-only",
        "unannotated",
        "without-final",
        "unsubscripted",
        "mapping-annotation",
        "local-builder-final-only",
        "final-frozendict",
        "lowercase-name",
    ],
)
def test_each_form_violation_is_detected(
    source: str, expected: list[tuple[int, str]]
) -> None:
    assert _form_violations(ast.parse(source)) == expected


@pytest.mark.unit
@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ({"a": 1}, [": is a dict"]),
        (MappingProxyType({"a": 1}), [": is a mappingproxy"]),
        (frozendict(a={}), ["['a']: dict"]),
        (frozendict(a=[1]), ["['a']: list"]),
        (frozendict(a={1}), ["['a']: set"]),
        (frozendict(a=bytearray()), ["['a']: bytearray"]),
        (frozendict(a=(1, [2])), ["['a'][1]: list"]),
        (frozendict(a=frozenset({(1, 2)}), b=({},)), ["['b'][0]: dict"]),
        (
            frozendict(a=frozendict(b=MappingProxyType({}))),
            ["['a']['b']: mappingproxy"],
        ),
        (frozendict(a=OrderedDict(), b=[]), ["['a']: OrderedDict", "['b']: list"]),
        (
            frozendict(
                a=frozendict(b=(1, frozenset({2}))), c="text", d=b"bytes", e=None
            ),
            [],
        ),
    ],
    ids=[
        "dict",
        "mapping-proxy",
        "nested-dict",
        "nested-list",
        "nested-set",
        "nested-bytearray",
        "list-in-tuple",
        "dict-in-tuple",
        "mapping-proxy-in-frozendict",
        "several",
        "immutable",
    ],
)
def test_each_value_violation_is_detected(value: object, expected: list[str]) -> None:
    assert _value_violations(value) == expected
