"""Unit tests for system settings request/response/query schemas
(`backend/app/schemas/settings.py`).

See `docs/features/platform/system-settings.md` (Get System Settings,
List Settings Audit Events) for the authoritative contract these
schemas implement.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.schemas.common import UserReference
from app.schemas.settings import (
    SettingAuditEventData,
    SettingAuditListResponse,
    SettingAuditQuery,
    SystemSettingsData,
    SystemSettingsResponse,
)


def _make_actor(**overrides: object) -> UserReference:
    defaults: dict[str, object] = {
        "id": uuid4(),
        "username": "asmith",
        "full_name": "Alice Smith",
        "active": True,
        "bot": False,
    }
    defaults.update(overrides)
    return UserReference(**defaults)


def _make_event_data_kwargs(**overrides: object) -> dict[str, object]:
    defaults: dict[str, object] = {
        "id": uuid4(),
        "event_type": "setting_changed",
        "setting_key": "default_cvss_version",
        "old_value": "3.1",
        "new_value": "4.0",
        "created_at": datetime(2026, 5, 13, 14, 0, 0, tzinfo=UTC),
        "actor": _make_actor(),
    }
    defaults.update(overrides)
    return defaults


@pytest.mark.unit
class TestSystemSettingsData:
    def test_holds_the_default_cvss_version(self) -> None:
        data = SystemSettingsData(default_cvss_version="3.1")
        assert data.default_cvss_version == "3.1"


@pytest.mark.unit
class TestSystemSettingsResponse:
    def test_wraps_a_single_object(self) -> None:
        response = SystemSettingsResponse(
            data=SystemSettingsData(default_cvss_version="3.1")
        )
        assert response.data.default_cvss_version == "3.1"


@pytest.mark.unit
class TestSettingAuditQuery:
    def test_defaults(self) -> None:
        query = SettingAuditQuery()
        assert query.event_type == []
        assert query.setting_key is None
        assert query.actor is None
        assert query.from_date is None
        assert query.to_date is None
        assert query.page == 1
        assert query.per_page == 20

    def test_event_type_accepts_arbitrary_strings(self) -> None:
        """Invalid values must not raise at the schema level — the route
        handler parses/ignores them per Enum Filter Validation."""
        query = SettingAuditQuery(event_type=["setting_changed", "not-a-real-type"])
        assert query.event_type == ["setting_changed", "not-a-real-type"]

    def test_page_below_one_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            SettingAuditQuery(page=0)

    def test_per_page_above_100_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            SettingAuditQuery(per_page=101)

    def test_per_page_below_one_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            SettingAuditQuery(per_page=0)

    def test_has_no_sort_fields(self) -> None:
        """Sorting is fixed (created_at DESC, id DESC) — sort_by/sort_order
        are not client-controlled parameters (system-settings.md, List
        Settings Audit Events)."""
        assert "sort_by" not in SettingAuditQuery.model_fields
        assert "sort_order" not in SettingAuditQuery.model_fields


@pytest.mark.unit
class TestSettingAuditEventData:
    def test_holds_all_documented_fields(self) -> None:
        data = SettingAuditEventData(**_make_event_data_kwargs())
        assert data.event_type == "setting_changed"
        assert data.setting_key == "default_cvss_version"
        assert data.old_value == "3.1"
        assert data.new_value == "4.0"
        assert data.actor.username == "asmith"

    def test_actor_is_required_not_nullable(self) -> None:
        """Setting audit events always have a human actor — the field
        is a plain UserReference, never Optional (system-settings.md,
        List Settings Audit Events: "actor is always the complete
        current user reference object ... never null")."""
        assert "actor" in SettingAuditEventData.model_fields
        assert SettingAuditEventData.model_fields["actor"].annotation is UserReference

    def test_old_value_accepts_none(self) -> None:
        data = SettingAuditEventData(**_make_event_data_kwargs(old_value=None))
        assert data.old_value is None

    def test_created_at_serializes_with_utc_z_suffix(self) -> None:
        data = SettingAuditEventData(**_make_event_data_kwargs())
        serialized = data.model_dump(mode="json")
        assert serialized["created_at"] == "2026-05-13T14:00:00Z"


@pytest.mark.unit
class TestSettingAuditListResponse:
    def test_wraps_a_list_with_pagination_meta(self) -> None:
        response = SettingAuditListResponse(
            data=[SettingAuditEventData(**_make_event_data_kwargs())],
            meta={"total": 1, "page": 1, "per_page": 20},
        )
        assert len(response.data) == 1
        assert response.meta.total == 1

    def test_empty_data_with_zero_total(self) -> None:
        response = SettingAuditListResponse(
            data=[],
            meta={"total": 0, "page": 1, "per_page": 20},
        )
        assert response.data == []
        assert response.meta.total == 0
