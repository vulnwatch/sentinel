"""Unit tests for identity audit log request/response/query schemas
(`backend/app/schemas/identity_audit.py`).

See `docs/features/identity/identity-audit-log.md` (API) for the
authoritative contract under test.
"""

from __future__ import annotations

from datetime import UTC, date, datetime
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.schemas.common import PaginationMeta, UserReference
from app.schemas.identity_audit import (
    AdminIdentityAuditEventData,
    AdminIdentityAuditListResponse,
    AdminIdentityAuditQuery,
    IdentityAuditQuery,
    SelfIdentityAuditEventData,
    SelfIdentityAuditListResponse,
)


@pytest.mark.unit
class TestIdentityAuditQuery:
    def test_defaults(self) -> None:
        query = IdentityAuditQuery()
        assert query.event_type == []
        assert query.from_date is None
        assert query.to_date is None
        assert query.page == 1
        assert query.per_page == 20

    def test_event_type_accepts_a_list_of_raw_strings(self) -> None:
        query = IdentityAuditQuery(event_type=["role_added", "not-a-real-type"])
        assert query.event_type == ["role_added", "not-a-real-type"]

    def test_from_date_accepts_a_bare_date(self) -> None:
        query = IdentityAuditQuery(from_date=date(2025, 1, 15))
        assert query.from_date == date(2025, 1, 15)

    def test_from_date_accepts_a_datetime(self) -> None:
        query = IdentityAuditQuery(
            from_date=datetime(2025, 1, 15, 10, 0, 0, tzinfo=UTC)
        )
        assert query.from_date == datetime(2025, 1, 15, 10, 0, 0, tzinfo=UTC)

    def test_page_below_one_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            IdentityAuditQuery(page=0)

    def test_per_page_above_100_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            IdentityAuditQuery(per_page=101)


@pytest.mark.unit
class TestAdminIdentityAuditQuery:
    def test_inherits_common_defaults(self) -> None:
        query = AdminIdentityAuditQuery()
        assert query.actor is None
        assert query.target_user is None
        assert query.event_type == []
        assert query.page == 1

    def test_actor_accepts_the_system_literal(self) -> None:
        assert AdminIdentityAuditQuery(actor="system").actor == "system"

    def test_actor_accepts_a_uuid_string(self) -> None:
        actor = str(uuid4())
        assert AdminIdentityAuditQuery(actor=actor).actor == actor

    def test_actor_accepts_a_username_string(self) -> None:
        assert AdminIdentityAuditQuery(actor="jdoe").actor == "jdoe"

    def test_target_user_accepts_a_username_string(self) -> None:
        assert AdminIdentityAuditQuery(target_user="jdoe").target_user == "jdoe"

    def test_has_no_sort_fields(self) -> None:
        """Structural guarantee: audit endpoints have fixed ordering —
        no client-controlled `sort_by`/`sort_order` field exists on
        either query schema."""
        assert "sort_by" not in AdminIdentityAuditQuery.model_fields
        assert "sort_order" not in AdminIdentityAuditQuery.model_fields


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


def _make_admin_event_kwargs(**overrides: object) -> dict[str, object]:
    defaults: dict[str, object] = {
        "id": uuid4(),
        "event_type": "role_added",
        "old_value": None,
        "new_value": "admin",
        "detail": {"source": "external_sync", "mapping": "SecurityTeam"},
        "created_at": datetime(2026, 5, 13, 10, 30, 0, tzinfo=UTC),
        "actor": None,
        "target_user": UserReference(**_make_user_reference_kwargs()),
    }
    defaults.update(overrides)
    return defaults


def _make_self_event_kwargs(**overrides: object) -> dict[str, object]:
    defaults: dict[str, object] = {
        "id": uuid4(),
        "event_type": "role_added",
        "old_value": None,
        "new_value": "admin",
        "detail": {"source": "external_sync", "mapping": "SecurityTeam"},
        "created_at": datetime(2026, 5, 13, 10, 30, 0, tzinfo=UTC),
        "actor": None,
    }
    defaults.update(overrides)
    return defaults


@pytest.mark.unit
class TestAdminIdentityAuditEventData:
    def test_actor_accepts_null_for_system_event(self) -> None:
        event = AdminIdentityAuditEventData(**_make_admin_event_kwargs(actor=None))
        assert event.actor is None

    def test_actor_accepts_a_user_reference(self) -> None:
        actor = UserReference(**_make_user_reference_kwargs(username="asmith"))
        event = AdminIdentityAuditEventData(**_make_admin_event_kwargs(actor=actor))
        assert event.actor is not None
        assert event.actor.username == "asmith"

    def test_target_user_accepts_null_for_configuration_event(self) -> None:
        event = AdminIdentityAuditEventData(
            **_make_admin_event_kwargs(target_user=None)
        )
        assert event.target_user is None

    def test_detail_is_returned_unredacted(self) -> None:
        event = AdminIdentityAuditEventData(**_make_admin_event_kwargs())
        assert event.detail == {"source": "external_sync", "mapping": "SecurityTeam"}

    def test_old_value_and_new_value_accept_null(self) -> None:
        event = AdminIdentityAuditEventData(
            **_make_admin_event_kwargs(old_value=None, new_value=None)
        )
        assert event.old_value is None
        assert event.new_value is None


@pytest.mark.unit
class TestSelfIdentityAuditEventData:
    def test_actor_accepts_null_for_an_event_without_a_recorded_actor(
        self,
    ) -> None:
        event = SelfIdentityAuditEventData(**_make_self_event_kwargs(actor=None))
        assert event.actor is None

    def test_actor_accepts_a_user_reference(self) -> None:
        actor = UserReference(**_make_user_reference_kwargs(username="asmith"))
        event = SelfIdentityAuditEventData(**_make_self_event_kwargs(actor=actor))
        assert event.actor is not None
        assert event.actor.username == "asmith"

    @pytest.mark.parametrize("actor", ["system", "self", "admin"])
    def test_actor_rejects_the_former_anonymized_strings(self, actor: str) -> None:
        with pytest.raises(ValidationError):
            SelfIdentityAuditEventData(**_make_self_event_kwargs(actor=actor))

    def test_has_no_target_user_field(self) -> None:
        """Structural guarantee: the self-service response never
        exposes a target-user object — the target is always the
        authenticated caller, which the caller already knows."""
        assert "target_user" not in SelfIdentityAuditEventData.model_fields

    def test_detail_is_returned_unredacted(self) -> None:
        """docs/features/identity/identity-audit-log.md ("detail" field
        transparency): external group names are non-sensitive and
        remain visible in the self-service response too."""
        event = SelfIdentityAuditEventData(**_make_self_event_kwargs())
        assert event.detail == {"source": "external_sync", "mapping": "SecurityTeam"}


@pytest.mark.unit
class TestResponseEnvelopes:
    def test_admin_list_response_has_data_and_meta(self) -> None:
        response = AdminIdentityAuditListResponse(
            data=[AdminIdentityAuditEventData(**_make_admin_event_kwargs())],
            meta=PaginationMeta(total=1, page=1, per_page=20),
        )
        assert len(response.data) == 1
        assert response.meta.total == 1

    def test_self_list_response_has_data_and_meta(self) -> None:
        response = SelfIdentityAuditListResponse(
            data=[SelfIdentityAuditEventData(**_make_self_event_kwargs())],
            meta=PaginationMeta(total=1, page=1, per_page=20),
        )
        assert len(response.data) == 1
        assert response.data[0].actor is None
