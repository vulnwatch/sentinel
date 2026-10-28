"""Unit tests for response schemas shared across feature areas
(`backend/app/schemas/common.py`).

See `docs/api-spec.md` (Response Format, User References in Responses)
for the authoritative contract under test.
"""

from __future__ import annotations

from uuid import uuid4

import pytest

from app.schemas.common import PaginationMeta, UserReference


def _make_user_reference_kwargs(**overrides: object) -> dict[str, object]:
    defaults: dict[str, object] = {
        "id": uuid4(),
        "username": "jdoe",
        "full_name": "John Doe",
        "active": True,
        "bot": False,
    }
    defaults.update(overrides)
    return defaults


@pytest.mark.unit
class TestUserReference:
    def test_all_fields_populated(self) -> None:
        ref = UserReference(**_make_user_reference_kwargs())
        assert ref.username == "jdoe"
        assert ref.full_name == "John Doe"
        assert ref.active is True
        assert ref.bot is False

    def test_full_name_accepts_none(self) -> None:
        ref = UserReference(**_make_user_reference_kwargs(full_name=None))
        assert ref.full_name is None

    def test_inactive_user_is_represented(self) -> None:
        ref = UserReference(**_make_user_reference_kwargs(active=False))
        assert ref.active is False


@pytest.mark.unit
class TestPaginationMeta:
    def test_all_fields_populated(self) -> None:
        meta = PaginationMeta(total=42, page=2, per_page=20)
        assert meta.total == 42
        assert meta.page == 2
        assert meta.per_page == 20

    def test_zero_total_is_accepted(self) -> None:
        """An empty result set (e.g. no matches) is a valid `meta`
        object, not a validation error."""
        meta = PaginationMeta(total=0, page=1, per_page=20)
        assert meta.total == 0
