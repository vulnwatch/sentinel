"""Request/response/query schemas for the user directory endpoints, the
administrator user reads, and the admin user mutation endpoints.

See `docs/features/identity/user-management.md` (Access Level
Requirements, Directory API endpoints, Admin API endpoints) for the
authoritative request/response contract these schemas implement.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from email_validator import EmailNotValidError, validate_email
from pydantic import BaseModel, Field, field_validator, model_validator

from app.core.enums import SortOrder, UserDirectorySortField, UserSortField
from app.core.permissions import role_from_wire
from app.core.usernames import RESERVED_USERNAMES, USERNAME_PATTERN
from app.schemas.common import PaginationMeta


class UserDirectoryListQuery(BaseModel):
    """Query parameters for `GET /api/v1/users` (`user-management.md`,
    List Users).

    The directory filters, searches, and sorts only on fields its entry
    returns, so it declares no `type` filter and no `created_at` sort.
    `role` is intentionally `list[str]`, not a typed enum list: an
    invalid value must be silently ignored (`docs/api-spec.md`, Enum
    Filter Validation) rather than raise the schema-validation `422` a
    typed enum field would. The route handler parses it against `Role`.
    """

    search: str | None = Field(default=None, min_length=2)
    active: bool | None = None
    role: list[str] = Field(default_factory=list)
    has_role: bool | None = None
    page: int = Field(default=1, ge=1, le=2_147_483_647)
    per_page: int = Field(default=20, ge=1, le=100)
    sort_by: UserDirectorySortField = UserDirectorySortField.USERNAME
    sort_order: SortOrder = SortOrder.ASC


class UserListQuery(BaseModel):
    """Query parameters for `GET /api/v1/admin/users`
    (`user-management.md`, List Users (Admin)).

    `type` and `role` are intentionally `str | None` / `list[str]`, not
    typed enums: an invalid value must be silently ignored and produce
    an empty result (`docs/api-spec.md`, Enum Filter Validation) rather
    than the schema-validation `422` a typed enum field would raise. The
    route handler parses them against `UserType`/`Role` itself.
    """

    search: str | None = Field(default=None, min_length=2)
    type: str | None = None
    active: bool | None = None
    role: list[str] = Field(default_factory=list)
    has_role: bool | None = None
    page: int = Field(default=1, ge=1, le=2_147_483_647)
    per_page: int = Field(default=20, ge=1, le=100)
    sort_by: UserSortField = UserSortField.USERNAME
    sort_order: SortOrder = SortOrder.ASC


class UserDirectoryData(BaseModel):
    """The user directory entry returned by `GET /api/v1/users` (list
    items) and `GET /api/v1/users/{user}` (`user-management.md`, Get
    User). It has the fields of the caller's own profile
    (`app.schemas.auth.CurrentUserData`) and none of the fields that
    only the complete user profile (`UserData`) returns. `roles` is the
    distinct, alphabetically wire-sorted set of current role values
    (`rbac.md`, Deterministic ordering); `full_name` is returned `null`
    verbatim with no fallback substitution."""

    id: UUID
    username: str
    email: str
    full_name: str | None
    active: bool
    bot: bool
    roles: list[str]


class UserDirectoryResponse(BaseModel):
    """Response body for `GET /api/v1/users/{user}`."""

    data: UserDirectoryData


class UserDirectoryListResponse(BaseModel):
    """Response body for `GET /api/v1/users`."""

    data: list[UserDirectoryData]
    meta: PaginationMeta


class UserManagerData(BaseModel):
    """The `manager` object in a complete user profile — the standard
    User Reference Object shape plus `email`, per `user-management.md`
    (Get User (Admin))."""

    id: UUID
    username: str
    full_name: str | None
    active: bool
    bot: bool
    email: str


class UserRoleAssignmentData(BaseModel):
    """One entry of a complete user profile's `roles` array
    (`user-management.md`, Get User (Admin))."""

    role: str
    group_name: str
    assigned_by: UUID | None
    created_at: datetime


class UserData(BaseModel):
    """The complete user profile returned by `GET /api/v1/admin/users`
    (list items), `GET /api/v1/admin/users/{user}`, and the admin
    mutation endpoints (`user-management.md`, Get User (Admin)).
    `full_name` and `manager.full_name` are nullable — the API returns
    `null` verbatim with no fallback substitution. `last_login_at` is
    `null` until the user's first login."""

    id: UUID
    username: str
    email: str
    full_name: str | None
    active: bool
    bot: bool
    source: str
    external_id: UUID | None
    manager: UserManagerData | None
    roles: list[UserRoleAssignmentData]
    last_login_at: datetime | None
    created_at: datetime
    updated_at: datetime


class UserResponse(BaseModel):
    """Response body for `GET /api/v1/admin/users/{user}` and the admin
    mutation endpoints that return the complete user profile."""

    data: UserData


class UserListResponse(BaseModel):
    """Response body for `GET /api/v1/admin/users`."""

    data: list[UserData]
    meta: PaginationMeta


# ---------------------------------------------------------------------------
# Admin mutation endpoints (`user-management.md`, Admin API endpoints)
# ---------------------------------------------------------------------------


def _normalize_username_field(value: Any) -> Any:
    """Shared `username` normalize-and-validate step for admin request
    schemas. Trims and lowercases, then validates against the Username
    Format pattern and reserved names (`app.core.usernames`). Raises
    `ValueError` for a non-string value (including explicit `null`), a
    syntactically invalid username, or a reserved one — Pydantic
    converts `ValueError` (unlike `TypeError`) raised inside a validator
    to the standard 422 `VALIDATION_ERROR` response.

    A boundary defense-in-depth check (see `user_service.create_user()`,
    "Defense in depth, not a single guarantee"): the service remains the
    sole guaranteed validation point, also reached by external
    provisioning, which has no Pydantic boundary in front of it.
    """
    if not isinstance(value, str):
        raise ValueError("username must be a string.")
    normalized = value.strip().lower()
    if not USERNAME_PATTERN.fullmatch(normalized):
        raise ValueError(
            "Username must be 1-64 characters, start with a letter, and "
            "contain only lowercase letters, numbers, dots, hyphens, and "
            "underscores."
        )
    if normalized in RESERVED_USERNAMES:
        raise ValueError("Username is reserved.")
    return normalized


def _normalize_email_field(value: Any) -> Any:
    """Shared `email` normalize-and-validate step for admin request
    schemas. Trims and lowercases the entire value, then validates format
    with `email-validator` (`check_deliverability=False` — no DNS
    lookup). Raises `ValueError` for a non-string value or an invalid
    format — Pydantic converts `ValueError` (unlike `TypeError`) raised
    inside a validator to the standard 422 `VALIDATION_ERROR` response.
    Mirrors the normalization performed by `user_service`
    (`docs/features/identity/user-service.md`,
    `create_user()`/`update_user()`) as a defense-in-depth boundary
    check, not a replacement for it.
    """
    if not isinstance(value, str):
        raise ValueError("email must be a string.")
    normalized = value.strip().lower()
    try:
        validate_email(normalized, check_deliverability=False)
    except EmailNotValidError as exc:
        raise ValueError("Invalid email format.") from exc
    return normalized


def _validate_role_list(value: list[str]) -> list[str]:
    """Reject unknown wire-format role values and repeated values within
    one list. Raises `ValueError`, which Pydantic renders as the global 422
    `VALIDATION_ERROR` response."""
    if len(value) != len(set(value)):
        raise ValueError("Duplicate role values are not allowed.")
    for item in value:
        try:
            role_from_wire(item)
        except ValueError as exc:
            raise ValueError(f"Unknown role value: {item!r}") from exc
    return value


class AdminUserCreateRequest(BaseModel):
    """Request body for `POST /api/v1/admin/users`
    (`user-management.md`, Create User (Admin)).

    `password` intentionally carries no length constraint at this layer:
    the 16-128 character policy is domain validation enforced by
    `user_service.create_user()`, which raises the domain-specific
    `PasswordValidationError` mapped to `422
    USER_PASSWORD_POLICY_VIOLATION` — a schema constraint here would
    instead produce the generic `422 VALIDATION_ERROR`, losing that
    documented code (mirrors `ApiKeyCreateRequest.name`).
    """

    username: str
    email: str
    full_name: str | None = Field(default=None, max_length=255)
    password: str = Field(repr=False)
    roles: list[str] = Field(default_factory=list)
    bot: bool = Field(default=False, strict=True)

    @field_validator("username", mode="before")
    @classmethod
    def _validate_username(cls, value: Any) -> Any:
        return _normalize_username_field(value)

    @field_validator("email", mode="before")
    @classmethod
    def _validate_email(cls, value: Any) -> Any:
        return _normalize_email_field(value)

    @field_validator("roles")
    @classmethod
    def _validate_roles(cls, value: list[str]) -> list[str]:
        return _validate_role_list(value)


class AdminUserUpdateRequest(BaseModel):
    """Request body for `PATCH /api/v1/admin/users/{user}`
    (`user-management.md`, Update User (Admin)).

    Every field is optional but at least one must be provided
    (`docs/api-spec.md`, Partial Update Semantics). `email` and `bot`
    reject explicit `null` (non-nullable fields); `full_name` accepts
    explicit `null` to clear the stored display name. `bot` accepts only a
    JSON boolean (`docs/api-spec.md`, JSON Request Body Scalar Types). The
    route distinguishes "omitted" from "explicitly provided" via
    `model_fields_set` — see `docs/features/identity/user-service.md`
    (`update_user()`, the `_MISSING` sentinel pattern) for how the route
    threads this into the service call.
    """

    email: str | None = None
    full_name: str | None = Field(default=None, max_length=255)
    bot: bool | None = Field(default=None, strict=True)

    @field_validator("email", mode="before")
    @classmethod
    def _validate_email(cls, value: Any) -> Any:
        if value is None:
            raise ValueError("email cannot be null.")
        return _normalize_email_field(value)

    @field_validator("bot", mode="before")
    @classmethod
    def _reject_null_bot(cls, value: Any) -> Any:
        if value is None:
            raise ValueError("bot cannot be null.")
        return value

    @model_validator(mode="after")
    def _require_at_least_one_field(self) -> AdminUserUpdateRequest:
        if not self.model_fields_set:
            raise ValueError("At least one field must be provided.")
        return self


class AdminPasswordResetRequest(BaseModel):
    """Request body for `POST /api/v1/admin/users/{user}/password`
    (`user-management.md`, Reset User Password).

    `password` intentionally carries no length constraint at this layer
    for the same reason as `AdminUserCreateRequest.password` — the
    policy is domain validation owned by
    `user_service.reset_password()`.
    """

    password: str = Field(repr=False)


class UserRolesUpdateRequest(BaseModel):
    """Request body for `POST /api/v1/admin/users/{user}/roles`
    (`user-management.md`, Set User Roles).

    Validation is strict, unlike `user_service.update_roles()`'s permissive
    set normalization: an omitted field means `[]`, but explicit `null`, a
    non-array, a non-string element, an unknown role value, a role repeated
    within one list, and a role present in both lists are rejected. An
    absent body is handled by the route as `{}`.
    """

    add: list[str] = Field(default_factory=list)
    remove: list[str] = Field(default_factory=list)

    @field_validator("add", "remove")
    @classmethod
    def _validate_roles(cls, value: list[str]) -> list[str]:
        return _validate_role_list(value)

    @model_validator(mode="after")
    def _reject_overlap(self) -> UserRolesUpdateRequest:
        if set(self.add) & set(self.remove):
            raise ValueError("A role cannot be both added and removed.")
        return self


class UserActionDetailData(BaseModel):
    """The `detail` object shared by the password-reset and unlock
    action responses (`user-management.md`, Reset User Password / Unlock
    User) — a consolidated group per `docs/conventions.md` (Function
    Specification Completeness, Consolidated groups): both endpoints
    return an identical single-field confirmation shape."""

    detail: str


class UserActionDetailResponse(BaseModel):
    """Response body for `POST /api/v1/admin/users/{user}/password` and
    `POST /api/v1/admin/users/{user}/unlock`."""

    data: UserActionDetailData


class DeactivationImpactData(BaseModel):
    """The deactivation preview (`user-management.md`, Get Deactivation
    Impact): the five fields of `user_service.DeactivationImpact`. Explicit
    Ticket grants and package-maintainer associations are intentionally
    absent because deactivation retains them."""

    already_inactive: bool
    is_last_active_admin: bool
    api_keys_count: int
    sessions_count: int
    tickets_count: int


class DeactivationImpactResponse(BaseModel):
    """Response body for `GET /api/v1/admin/users/{user}/deactivation-impact`."""

    data: DeactivationImpactData
