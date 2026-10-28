"""Unit tests for API key request/response/query schemas
(`backend/app/schemas/api_key.py`).

See `docs/features/identity/api-key-management.md` (API Key Contract,
API) for the authoritative contract under test.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.core.enums import ApiKeySortField, ApiKeyStatus, SortOrder
from app.schemas.api_key import (
    AdminApiKeyData,
    AdminApiKeyListQuery,
    AdminApiKeyListResponse,
    AdminApiKeyResponse,
    ApiKeyCreateRequest,
    ApiKeyData,
    ApiKeyListQuery,
    ApiKeyListResponse,
    ApiKeyResponse,
    CreatedApiKeyData,
    CreatedApiKeyResponse,
)
from app.schemas.common import PaginationMeta, UserReference


@pytest.mark.unit
class TestApiKeyListQuery:
    def test_defaults(self) -> None:
        query = ApiKeyListQuery()
        assert query.status is None
        assert query.page == 1
        assert query.per_page == 20
        assert query.sort_by is ApiKeySortField.CREATED_AT
        assert query.sort_order is SortOrder.DESC

    def test_page_below_one_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ApiKeyListQuery(page=0)

    def test_page_at_int32_max_is_accepted(self) -> None:
        assert ApiKeyListQuery(page=2_147_483_647).page == 2_147_483_647

    def test_page_above_int32_max_is_rejected(self) -> None:
        """A `page` value large enough to overflow the database
        driver's `OFFSET` parameter must be rejected as a standard 422
        at the schema boundary, not reach the database as a 500."""
        with pytest.raises(ValidationError):
            ApiKeyListQuery(page=2_147_483_648)

    def test_per_page_below_one_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ApiKeyListQuery(per_page=0)

    def test_per_page_above_100_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ApiKeyListQuery(per_page=101)

    def test_per_page_at_100_is_accepted(self) -> None:
        assert ApiKeyListQuery(per_page=100).per_page == 100

    def test_values_are_never_clamped(self) -> None:
        """docs/api-spec.md (Pagination): out-of-range values are
        rejected, never silently clamped."""
        with pytest.raises(ValidationError):
            ApiKeyListQuery(per_page=1000)

    @pytest.mark.parametrize("sort_by", ["created_at", "last_used_at"])
    def test_valid_sort_by_is_accepted(self, sort_by: str) -> None:
        assert ApiKeyListQuery(sort_by=sort_by).sort_by == sort_by

    def test_invalid_sort_by_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ApiKeyListQuery(sort_by="name")

    @pytest.mark.parametrize("sort_order", ["asc", "desc"])
    def test_valid_sort_order_is_accepted(self, sort_order: str) -> None:
        assert ApiKeyListQuery(sort_order=sort_order).sort_order == sort_order

    def test_invalid_sort_order_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ApiKeyListQuery(sort_order="ascending")

    def test_status_absent_is_none(self) -> None:
        assert ApiKeyListQuery().status is None

    def test_status_accepts_a_valid_value_as_a_raw_string(self) -> None:
        assert ApiKeyListQuery(status="active").status == "active"

    def test_status_accepts_an_invalid_value_without_raising(self) -> None:
        """`status` is intentionally untyped at the schema level — an
        invalid value must reach the route handler so it can render an
        empty page (docs/api-spec.md, Enum Filter Validation) instead
        of a 422 a typed enum field would raise here."""
        assert ApiKeyListQuery(status="not-a-real-status").status == (
            "not-a-real-status"
        )


@pytest.mark.unit
class TestAdminApiKeyListQuery:
    def test_inherits_common_defaults(self) -> None:
        query = AdminApiKeyListQuery()
        assert query.owner is None
        assert query.page == 1
        assert query.per_page == 20
        assert query.sort_by is ApiKeySortField.CREATED_AT
        assert query.sort_order is SortOrder.DESC

    def test_owner_accepts_a_uuid_string(self) -> None:
        owner = str(uuid4())
        assert AdminApiKeyListQuery(owner=owner).owner == owner

    def test_owner_accepts_a_username_string(self) -> None:
        assert AdminApiKeyListQuery(owner="jdoe").owner == "jdoe"


@pytest.mark.unit
class TestApiKeyCreateRequest:
    def test_expires_at_absent_defaults_to_none(self) -> None:
        assert ApiKeyCreateRequest(name="ci.production").expires_at is None

    def test_expires_at_explicit_none_is_accepted(self) -> None:
        assert (
            ApiKeyCreateRequest(name="ci.production", expires_at=None).expires_at
            is None
        )

    def test_naive_datetime_is_interpreted_as_utc(self) -> None:
        request = ApiKeyCreateRequest(
            name="ci.production", expires_at="2026-12-01T10:00:00"
        )
        assert request.expires_at == datetime(2026, 12, 1, 10, 0, 0, tzinfo=UTC)

    def test_utc_suffixed_datetime_is_accepted(self) -> None:
        request = ApiKeyCreateRequest(
            name="ci.production", expires_at="2026-12-01T10:00:00Z"
        )
        assert request.expires_at == datetime(2026, 12, 1, 10, 0, 0, tzinfo=UTC)

    def test_offset_datetime_is_converted_to_utc(self) -> None:
        request = ApiKeyCreateRequest(
            name="ci.production", expires_at="2026-12-01T10:00:00+02:00"
        )
        assert request.expires_at == datetime(2026, 12, 1, 8, 0, 0, tzinfo=UTC)

    def test_date_only_value_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ApiKeyCreateRequest(name="ci.production", expires_at="2026-12-01")

    def test_malformed_value_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ApiKeyCreateRequest(name="ci.production", expires_at="not-a-datetime")

    def test_numeric_epoch_value_is_rejected(self) -> None:
        """The endpoint accepts only a full ISO 8601 datetime string —
        not a unix timestamp, which Pydantic's default `datetime`
        parsing would otherwise silently accept."""
        with pytest.raises(ValidationError):
            ApiKeyCreateRequest(name="ci.production", expires_at=1893484800)

    def test_max_datetime_with_negative_offset_overflow_is_rejected(self) -> None:
        """A value whose UTC conversion would cross `datetime.max`
        raises `OverflowError` from `astimezone()`, not `ValueError` —
        this must still surface as the standard 422
        VALIDATION_ERROR, not an unhandled 500."""
        with pytest.raises(ValidationError):
            ApiKeyCreateRequest(
                name="ci.production", expires_at="9999-12-31T23:59:59-12:00"
            )

    def test_min_datetime_with_positive_offset_underflow_is_rejected(self) -> None:
        """Symmetric underflow case: a value whose UTC conversion
        would cross `datetime.min`."""
        with pytest.raises(ValidationError):
            ApiKeyCreateRequest(
                name="ci.production", expires_at="0001-01-01T00:00:00+12:00"
            )

    def test_name_is_not_constrained_at_the_schema_level(self) -> None:
        """docs/features/identity/api-key-management.md (API Key Name
        Rule): normalization and validation are the service's
        responsibility, not the schema's — an unnormalized value must
        reach `api_key_service.create_key()` unchanged."""
        request = ApiKeyCreateRequest(name="  CI.Production  ")
        assert request.name == "  CI.Production  "

    def test_missing_name_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ApiKeyCreateRequest()  # type: ignore[call-arg]


def _make_user_reference_kwargs(**overrides: object) -> dict[str, object]:
    """Build kwargs for an embedded `UserReference` (e.g. `revoked_by`,
    `owner`). `UserReference` itself is defined in `app/schemas/common.py`
    and tested in `test_schemas/test_common.py` — this helper exists only
    to construct instances embedded in the API-key-specific schemas
    tested below.
    """
    defaults: dict[str, object] = {
        "id": uuid4(),
        "username": "jdoe",
        "full_name": "John Doe",
        "active": True,
        "bot": False,
    }
    defaults.update(overrides)
    return defaults


def _make_api_key_data_kwargs(**overrides: object) -> dict[str, object]:
    defaults: dict[str, object] = {
        "id": uuid4(),
        "prefix": "stl_ak_7f3a9",
        "name": "ci.production",
        "status": ApiKeyStatus.ACTIVE,
        "created_at": datetime(2026, 8, 1, 10, 0, 0, tzinfo=UTC),
        "last_used_at": None,
        "expires_at": None,
        "revoked_at": None,
        "revoked_by": None,
    }
    defaults.update(overrides)
    return defaults


@pytest.mark.unit
class TestApiKeyData:
    def test_common_fields_populated(self) -> None:
        data = ApiKeyData(**_make_api_key_data_kwargs())
        assert data.name == "ci.production"
        assert data.status is ApiKeyStatus.ACTIVE

    def test_revoked_by_accepts_a_user_reference(self) -> None:
        ref = UserReference(**_make_user_reference_kwargs())
        data = ApiKeyData(
            **_make_api_key_data_kwargs(
                status=ApiKeyStatus.REVOKED,
                revoked_at=datetime(2026, 9, 1, tzinfo=UTC),
                revoked_by=ref,
            )
        )
        assert data.revoked_by == ref

    def test_has_no_key_hash_field(self) -> None:
        """Structural guarantee: the hash must never be representable
        in any response schema, regardless of what the caller passes
        as ORM data upstream."""
        assert "key_hash" not in ApiKeyData.model_fields

    def test_has_no_key_field(self) -> None:
        """Only `CreatedApiKeyData` carries the plaintext `key`."""
        assert "key" not in ApiKeyData.model_fields


@pytest.mark.unit
class TestCreatedApiKeyData:
    def test_carries_the_common_fields_plus_key(self) -> None:
        data = CreatedApiKeyData(
            **_make_api_key_data_kwargs(), key="stl_ak_" + "x" * 32
        )
        assert data.key == "stl_ak_" + "x" * 32
        assert data.name == "ci.production"

    def test_has_no_key_hash_field(self) -> None:
        assert "key_hash" not in CreatedApiKeyData.model_fields

    def test_key_is_hidden_from_repr(self) -> None:
        """`key: str = Field(repr=False)` must keep the plaintext key
        out of `repr()` — the only place the plaintext key is ever
        exposed is the serialized response body, never a debug/log
        representation of the object."""
        secret_key = "stl_ak_" + "s3cr3t-value"
        data = CreatedApiKeyData(**_make_api_key_data_kwargs(), key=secret_key)
        assert secret_key not in repr(data)


@pytest.mark.unit
class TestAdminApiKeyData:
    def test_carries_the_common_fields_plus_owner(self) -> None:
        owner = UserReference(**_make_user_reference_kwargs())
        data = AdminApiKeyData(**_make_api_key_data_kwargs(), owner=owner)
        assert data.owner == owner
        assert data.name == "ci.production"

    def test_has_no_key_field(self) -> None:
        assert "key" not in AdminApiKeyData.model_fields

    def test_has_no_key_hash_field(self) -> None:
        assert "key_hash" not in AdminApiKeyData.model_fields


@pytest.mark.unit
class TestResponseEnvelopes:
    def test_api_key_response_wraps_a_single_object(self) -> None:
        response = ApiKeyResponse(data=ApiKeyData(**_make_api_key_data_kwargs()))
        assert response.data.name == "ci.production"

    def test_created_api_key_response_wraps_the_secret_bearing_object(self) -> None:
        response = CreatedApiKeyResponse(
            data=CreatedApiKeyData(
                **_make_api_key_data_kwargs(), key="stl_ak_" + "x" * 32
            )
        )
        assert response.data.key == "stl_ak_" + "x" * 32

    def test_created_api_key_response_hides_key_from_nested_repr(self) -> None:
        """`repr=False` on `CreatedApiKeyData.key` must also protect the
        plaintext key when the object is embedded inside the
        `{"data": ...}` response envelope, not just in isolation."""
        secret_key = "stl_ak_" + "s3cr3t-value"
        response = CreatedApiKeyResponse(
            data=CreatedApiKeyData(**_make_api_key_data_kwargs(), key=secret_key)
        )
        assert secret_key not in repr(response)

    def test_admin_api_key_response_wraps_the_owner_bearing_object(self) -> None:
        owner = UserReference(**_make_user_reference_kwargs())
        response = AdminApiKeyResponse(
            data=AdminApiKeyData(**_make_api_key_data_kwargs(), owner=owner)
        )
        assert response.data.owner == owner

    def test_api_key_list_response_has_data_and_meta(self) -> None:
        response = ApiKeyListResponse(
            data=[ApiKeyData(**_make_api_key_data_kwargs())],
            meta=PaginationMeta(total=1, page=1, per_page=20),
        )
        assert len(response.data) == 1
        assert response.meta.total == 1

    def test_admin_api_key_list_response_has_data_and_meta(self) -> None:
        owner = UserReference(**_make_user_reference_kwargs())
        response = AdminApiKeyListResponse(
            data=[AdminApiKeyData(**_make_api_key_data_kwargs(), owner=owner)],
            meta=PaginationMeta(total=1, page=1, per_page=20),
        )
        assert len(response.data) == 1
        assert response.data[0].owner == owner
