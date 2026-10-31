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
from pydantic import MISSING, BaseModel, Field, field_validator, model_validator

from app.core.enums import SortOrder, UserDirectorySortField, UserSortField, UserType
from app.core.passwords import MAX_PASSWORD_LENGTH, MIN_PASSWORD_LENGTH
from app.core.usernames import RESERVED_USERNAMES, USERNAME_PATTERN
from app.schemas.common import PaginationMeta, RoleValue, UserReference

_PASSWORD_DESCRIPTION = (
    f"{MIN_PASSWORD_LENGTH}-{MAX_PASSWORD_LENGTH} characters; no complexity "
    "rules. A password outside the policy returns `422 "
    "USER_PASSWORD_POLICY_VIOLATION`, not `VALIDATION_ERROR`."
)
_PASSWORD_SCHEMA: dict[str, Any] = {
    "minLength": MIN_PASSWORD_LENGTH,
    "maxLength": MAX_PASSWORD_LENGTH,
}
"""The password policy (`docs/features/identity/local-authentication.md`,
Password validation), published without being enforced by the schema
(`docs/api-spec.md`, Published Input Constraints): the service enforces it
with its dedicated code."""

_EMAIL_DESCRIPTION = (
    "Email address. Leading and trailing whitespace is trimmed and the value "
    "is lowercased before it is validated; an invalid address returns `422 "
    "VALIDATION_ERROR`."
)


class UserDirectoryListQuery(BaseModel):
    """Query parameters for `GET /api/v1/users` (`user-management.md`,
    List Users).

    The directory filters, searches, and sorts only on fields its entry
    returns, so it declares no `type` filter and no `created_at` sort.
    `role` is intentionally `list[str]`, not a typed enum list: an
    invalid value must be silently ignored (`docs/api-spec.md`, Enum
    Filter Validation) rather than raise the schema-validation `422` a
    typed enum field would. The route handler parses it against `Role`
    and publishes the role values as the parameter's `enum`.
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
    route handler parses them against `UserType`/`Role` itself and
    publishes their values as the parameters' `enum`.
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
    (`app.schemas.auth.CurrentUserData`) except `capabilities`, which
    only the own profile returns, and none of the fields that only the
    complete user profile (`UserData`) returns. `roles` is the
    distinct, alphabetically wire-sorted set of current role values
    (`rbac.md`, Role Wire Format, Deterministic ordering); `full_name`
    is returned `null` verbatim with no fallback substitution."""

    id: UUID
    username: str
    email: str
    full_name: str | None
    active: bool
    bot: bool
    roles: list[RoleValue]


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
    (`user-management.md`, Get User (Admin)). `assigned_by` is the user
    reference of the recorded assigning user, or `None` when none is
    recorded (CLI or external-group origin)."""

    role: RoleValue
    group_name: str
    assigned_by: UserReference | None
    created_at: datetime


class UserData(BaseModel):
    """The complete user profile returned by `GET /api/v1/admin/users`
    (list items), `GET /api/v1/admin/users/{user}`, and the admin
    mutation endpoints (`user-management.md`, Get User (Admin)).
    `full_name` and `manager.full_name` are nullable — the API returns
    `null` verbatim with no fallback substitution. `source` is `local` or
    `external`. `last_login_at` is `null` until the user's first login."""

    id: UUID
    username: str
    email: str
    full_name: str | None
    active: bool
    bot: bool
    source: UserType
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


def _validate_role_list(value: list[RoleValue]) -> list[RoleValue]:
    """Reject repeated role values within one list; an unknown value
    already fails the `RoleValue` type. Raises `ValueError`, which Pydantic
    renders as the global 422 `VALIDATION_ERROR` response."""
    if len(value) != len(set(value)):
        raise ValueError("Duplicate role values are not allowed.")
    return value


class AdminUserCreateRequest(BaseModel):
    """Request body for `POST /api/v1/admin/users`
    (`user-management.md`, Create User (Admin)).

    `password` intentionally carries no enforced length constraint at
    this layer: the 16-128 character policy is domain validation enforced
    by `user_service.create_user()`, which raises the domain-specific
    `PasswordValidationError` mapped to `422
    USER_PASSWORD_POLICY_VIOLATION` — an enforced schema constraint here
    would instead produce the generic `422 VALIDATION_ERROR`, losing that
    documented code and its precedence (mirrors `ApiKeyCreateRequest.name`).
    The policy is only published (`_PASSWORD_SCHEMA`). `username` and
    `email` are normalized before they are validated, so their rules are
    stated in their descriptions instead of as keywords, which would apply
    to the raw value (`docs/api-spec.md`, Published Input Constraints).
    """

    username: str = Field(
        description=(
            "Leading and trailing whitespace is trimmed and the value is "
            "lowercased before it is validated. The result has 1-64 "
            "characters, starts with a letter, contains only `a`-`z`, `0`-`9`, "
            "`.`, `_`, and `-`, and is not the reserved `me`; otherwise `422 "
            "VALIDATION_ERROR`."
        ),
        examples=["jdoe"],
    )
    email: str = Field(description=_EMAIL_DESCRIPTION)
    full_name: str | None = Field(default=None, max_length=255)
    password: str = Field(
        repr=False,
        description=_PASSWORD_DESCRIPTION,
        json_schema_extra=_PASSWORD_SCHEMA,
    )
    roles: list[RoleValue] = Field(default_factory=list)
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
    def _validate_roles(cls, value: list[RoleValue]) -> list[RoleValue]:
        return _validate_role_list(value)


class AdminUserUpdateRequest(BaseModel):
    """Request body for `PATCH /api/v1/admin/users/{user}`
    (`user-management.md`, Update User (Admin)).

    Every field is optional but at least one must be provided
    (`docs/api-spec.md`, Partial Update Semantics). An omitted field stays
    `MISSING` (`docs/conventions.md`, Omitted Values), which the route
    passes to `user_service.update_user()` unchanged. `email` and `bot` are
    non-nullable, so their types exclude `None` and an explicit `null` fails
    type validation; `full_name` accepts explicit `null` to clear the stored
    display name. `bot` accepts only a JSON boolean (`docs/api-spec.md`, JSON
    Request Body Scalar Types).
    """

    email: str | MISSING = Field(default=MISSING, description=_EMAIL_DESCRIPTION)
    full_name: str | MISSING | None = Field(default=MISSING, max_length=255)
    bot: bool | MISSING = Field(default=MISSING, strict=True)

    @field_validator("email", mode="before")
    @classmethod
    def _validate_email(cls, value: Any) -> Any:
        return _normalize_email_field(value)

    @model_validator(mode="after")
    def _require_at_least_one_field(self) -> AdminUserUpdateRequest:
        if not self.model_fields_set:
            raise ValueError("At least one field must be provided.")
        return self


class AdminPasswordResetRequest(BaseModel):
    """Request body for `POST /api/v1/admin/users/{user}/password`
    (`user-management.md`, Reset User Password).

    `password` intentionally carries no enforced length constraint at
    this layer for the same reason as `AdminUserCreateRequest.password` —
    the policy is domain validation owned by
    `user_service.reset_password()` — and publishes it the same way.
    """

    password: str = Field(
        repr=False,
        description=_PASSWORD_DESCRIPTION,
        json_schema_extra=_PASSWORD_SCHEMA,
    )


class UserRolesUpdateRequest(BaseModel):
    """Request body for `POST /api/v1/admin/users/{user}/roles`
    (`user-management.md`, Set User Roles).

    Validation is strict, unlike `user_service.update_roles()`'s permissive
    set normalization: an omitted field means `[]`, but explicit `null`, a
    non-array, a non-string element, an unknown role value, a role repeated
    within one list, and a role present in both lists are rejected. An
    absent body is handled by the route as `{}`.
    """

    add: list[RoleValue] = Field(default_factory=list)
    remove: list[RoleValue] = Field(default_factory=list)

    @field_validator("add", "remove")
    @classmethod
    def _validate_roles(cls, value: list[RoleValue]) -> list[RoleValue]:
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
