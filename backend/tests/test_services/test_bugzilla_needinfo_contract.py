"""Contract tests for the SUSE Bugzilla JSON-RPC `Bug.search` of the
needinfo count.

Contract under test: docs/features/integrations/bugzilla-needinfo-count.md
(Search Request, Authentication, Response Contract) and docs/data-sources.md
(SUSE Bugzilla), verified against live answers captured on 2026-11-26
(docs/conventions.md, External Integration Contract Verification; provenance
in `tests/support/bugzilla_jsonrpc.py`). Every consumed field is asserted
for name, nesting, and type through a strict test-local typed model,
independent of the production parser
(`app/services/bugzilla_needinfo_service.py`).

Live verification on 2026-11-26 (Bugzilla 5.0.6, `POST /jsonrpc.cgi`, the
fixed search body of Search Request):

- Every answer was HTTP 200 `application/json; charset=UTF-8`, without a
  content coding, and a JSON object with exactly `error`, `id`, and
  `result`; the member order varied between answers.
- Anonymous: `error` `null`, `result` an object with only `bugs`, one
  element `{"id": 1291903}`, the public test bug. The restricted test bug
  bsc#1291902 was absent.
- With the key of an account that sees the security team's restricted
  bugs: the same shape with both test bugs, `{"id": 1291902}` and
  `{"id": 1291903}`. Each element has only `id`, an integer.
- With an invalid key: `result` `null` and `error` an object with an
  integer `code` 306 and a string `message`.
- Bugzilla answered the search in 0.2 to 0.3 seconds.

Not observable live, and therefore covered by the parser tests only: an
HTTP status other than 200, a Bugzilla error other than 306, an empty
`bugs` array, a mistyped or missing consumed member, a duplicated member,
and a body that is not JSON.
"""

from __future__ import annotations

from collections import Counter
from typing import Any, TypedDict

import pytest
from pydantic import TypeAdapter, ValidationError

from app.services.json_decoding import decode_json
from tests.support.bugzilla_jsonrpc import (
    ANONYMOUS_FIXTURE,
    AUTHENTICATED_FIXTURE,
    INVALID_API_KEY_CODE,
    INVALID_KEY_FIXTURE,
    PUBLIC_TEST_BUG,
    RESTRICTED_TEST_BUG,
    load_fixture,
    load_raw_fixture,
)

_COUNT_FIXTURES = (ANONYMOUS_FIXTURE, AUTHENTICATED_FIXTURE)
_ALL_FIXTURES = (*_COUNT_FIXTURES, INVALID_KEY_FIXTURE)


class _Bug(TypedDict):
    id: int


class _Result(TypedDict):
    bugs: list[_Bug]


class _CountAnswer(TypedDict):
    error: None
    id: int
    result: _Result


class _Error(TypedDict):
    code: int
    message: str


class _ErrorAnswer(TypedDict):
    error: _Error
    id: int
    result: None


_COUNT = TypeAdapter(_CountAnswer)
_ERROR = TypeAdapter(_ErrorAnswer)


def _bug_ids(name: str) -> list[int]:
    return [
        bug["id"]
        for bug in _COUNT.validate_python(load_fixture(name), strict=True)["result"][
            "bugs"
        ]
    ]


def _repeated_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    counts = Counter(name for name, _ in pairs)
    assert all(count == 1 for count in counts.values()), counts
    return dict(pairs)


@pytest.mark.unit
class TestEncoding:
    @pytest.mark.parametrize("name", _ALL_FIXTURES)
    def test_body_is_strict_utf8_json_without_bom_or_duplicates(
        self, name: str
    ) -> None:
        content = load_raw_fixture(name)

        assert not content.startswith(b"\xef\xbb\xbf")
        text = content.decode("utf-8")
        document = decode_json(text, object_pairs_hook=_repeated_members)
        assert isinstance(document, dict)

    @pytest.mark.parametrize("name", _ALL_FIXTURES)
    def test_root_holds_exactly_error_id_and_result(self, name: str) -> None:
        assert set(load_fixture(name)) == {"error", "id", "result"}


@pytest.mark.unit
class TestCountAnswer:
    @pytest.mark.parametrize("name", _COUNT_FIXTURES)
    def test_consumed_fields_validate_strictly_without_coercion(
        self, name: str
    ) -> None:
        _COUNT.validate_python(load_fixture(name), strict=True)

    @pytest.mark.parametrize("name", _COUNT_FIXTURES)
    def test_error_is_null_and_result_holds_only_bugs(self, name: str) -> None:
        document = load_fixture(name)

        assert document["error"] is None
        assert list(document["result"]) == ["bugs"]

    @pytest.mark.parametrize("name", _COUNT_FIXTURES)
    def test_every_bug_has_only_a_positive_integer_id(self, name: str) -> None:
        for bug in load_fixture(name)["result"]["bugs"]:
            assert list(bug) == ["id"]
            assert type(bug["id"]) is int
            assert bug["id"] >= 1

    def test_anonymous_search_returns_only_the_public_test_bug(self) -> None:
        assert _bug_ids(ANONYMOUS_FIXTURE) == [PUBLIC_TEST_BUG]

    def test_authenticated_search_also_returns_the_restricted_test_bug(
        self,
    ) -> None:
        assert sorted(_bug_ids(AUTHENTICATED_FIXTURE)) == [
            RESTRICTED_TEST_BUG,
            PUBLIC_TEST_BUG,
        ]

    @pytest.mark.parametrize(
        "bug",
        [{"id": True}, {"id": 1.0}, {"id": "1"}, {}, None],
        ids=["boolean_id", "float_id", "string_id", "missing_id", "null_bug"],
    )
    def test_typed_model_rejects_a_mistyped_or_missing_id(self, bug: Any) -> None:
        with pytest.raises(ValidationError):
            _COUNT.validate_python(
                {"error": None, "id": 1, "result": {"bugs": [bug]}}, strict=True
            )


@pytest.mark.unit
class TestInvalidKeyAnswer:
    def test_consumed_fields_validate_strictly_without_coercion(self) -> None:
        _ERROR.validate_python(load_fixture(INVALID_KEY_FIXTURE), strict=True)

    def test_error_code_is_the_integer_306_and_result_is_null(self) -> None:
        document = load_fixture(INVALID_KEY_FIXTURE)

        assert document["result"] is None
        assert type(document["error"]["code"]) is int
        assert document["error"]["code"] == INVALID_API_KEY_CODE

    def test_error_carries_no_bugs(self) -> None:
        assert "bugs" not in str(load_fixture(INVALID_KEY_FIXTURE))
