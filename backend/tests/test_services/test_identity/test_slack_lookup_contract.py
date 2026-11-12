"""Contract tests for Slack `users.lookupByEmail`.

Contract under test: docs/features/identity/user-avatars.md (Slack
Integration — Lookup Request, Response Contract, Accepted Picture URL) and
docs/data-sources.md (Slack), verified live on 2026-11-12 against SUSE's
workspace with the bot token of the Sentinel Slack app and consenting
accounts (docs/conventions.md, External Integration Contract Verification).
Only structural facts were recorded, and the fixtures are fictional
(`tests/support/slack.py`). Every consumed member is asserted for name,
nesting, and type through a strict test-local typed model, independent of
the production parser, and then through the parser itself.

Live verification on 2026-11-12:

- `auth.test`: `is_enterprise_install` is `false` and there is no
  `enterprise_id`: SUSE's workspace is not Enterprise Grid, so the lookup
  needs no `team_id`.
- Every response is HTTP 200 with `Content-Type: application/json;
  charset=utf-8`, whether the lookup succeeds or fails.
- A found member: the root has exactly `ok` (`true`) and `user`; `user` and
  `user.profile` are objects, and `image_192` is a string. The lookup
  matches the address case-insensitively.
- A member with an uploaded picture: every `image_*` member, `image_1024`
  and `image_original` included, is an absolute `https` URL on
  `avatars.slack-edge.com` without user information, port, query, or
  fragment, printable ASCII, of at most 90 characters; `is_custom_image` is
  `true`. The 192-pixel image returns `200 image/jpeg` without a redirect.
- A member without an uploaded picture, with a Gravatar or without one: every
  `image_*` member is a Gravatar URL on `secure.gravatar.com` with the query
  members `s` and `d`; there is no `is_custom_image`, `image_original`, or
  `image_1024`, and `avatar_hash` starts with `g`.
- Errors are `ok: false` with an `error` string: `users_not_found` for an
  unknown address, `invalid_auth` for an invalid token, `not_authed`
  without a token, and `invalid_arguments` (with `response_metadata`)
  without `email`.

Documentation-only, and therefore covered by the parser and fetcher tests
only: `users_not_found` for a member deactivated in Slack, HTTP 429 with
`Retry-After` and the `ratelimited` code, and the token error codes other
than `invalid_auth` and `not_authed`.
"""

from __future__ import annotations

from typing import Any, Literal, TypedDict
from urllib.parse import urlsplit

import pytest
from pydantic import TypeAdapter, ValidationError

from app.core.external_strings import contains_inadmissible_character
from app.services.identity.sync_slack_avatars import Lookup, Outcome, classify_lookup
from app.services.json_decoding import decode_json
from tests.support.slack import FIXTURES, UPLOADED_PICTURE, load, load_raw


class _Profile(TypedDict):
    image_192: str


class _User(TypedDict):
    profile: _Profile


class _Found(TypedDict):
    """The consumed members of a found member. Other members are ignored."""

    ok: Literal[True]
    user: _User


class _Error(TypedDict):
    ok: Literal[False]
    error: str


_FOUND = TypeAdapter(_Found)
_ERROR = TypeAdapter(_Error)

_FOUND_FIXTURES = ("lookup_uploaded", "lookup_gravatar")
_ERROR_FIXTURES = {
    "users_not_found": "users_not_found",
    "invalid_auth": "invalid_auth",
    "not_authed": "not_authed",
    "invalid_arguments": "invalid_arguments",
}

_USER_MEMBERS = (
    "id",
    "name",
    "is_bot",
    "updated",
    "is_app_user",
    "team_id",
    "deleted",
    "color",
    "is_email_confirmed",
    "real_name",
    "tz",
    "tz_label",
    "tz_offset",
    "is_admin",
    "is_owner",
    "is_primary_owner",
    "is_restricted",
    "is_ultra_restricted",
    "is_scim_provisioned",
    "who_can_share_contact_card",
    "profile",
)
"""The live members of `user`, in live order."""

_IMAGES_GRAVATAR = (
    "image_24",
    "image_32",
    "image_48",
    "image_72",
    "image_192",
    "image_512",
)
_IMAGES_UPLOADED = (*_IMAGES_GRAVATAR, "image_1024", "image_original")


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for key, item in value.items() for s in (key, *_strings(item))]
    if isinstance(value, list):
        return [s for item in value for s in _strings(item)]
    return []


@pytest.mark.unit
class TestFixtures:
    @pytest.mark.parametrize("name", FIXTURES)
    def test_fixture_is_an_indented_ascii_json_object(self, name: str) -> None:
        raw = load_raw(name)

        assert raw.isascii()
        assert raw.endswith(b"}\n")
        assert isinstance(load(name), dict)

    @pytest.mark.parametrize("name", FIXTURES)
    def test_no_string_contains_an_inadmissible_character(self, name: str) -> None:
        assert not any(contains_inadmissible_character(s) for s in _strings(load(name)))

    @pytest.mark.parametrize("name", FIXTURES)
    def test_no_fixture_holds_a_real_address_or_workspace(self, name: str) -> None:
        text = load_raw(name).decode("ascii").lower()

        assert "suse" not in text
        for address in (s for s in _strings(load(name)) if "@" in s):
            assert address.endswith("@example.com")


@pytest.mark.unit
class TestFoundMember:
    @pytest.mark.parametrize("name", _FOUND_FIXTURES)
    def test_consumed_members_validate_strictly_without_coercion(
        self, name: str
    ) -> None:
        _FOUND.validate_python(load(name), strict=True)

    @pytest.mark.parametrize(
        ("path", "value"),
        [
            pytest.param(("ok",), "true", id="ok-string"),
            pytest.param(("user",), [], id="user-array"),
            pytest.param(("user", "profile"), None, id="profile-null"),
            pytest.param(("user", "profile", "image_192"), 192, id="image-number"),
        ],
    )
    def test_typed_model_rejects_a_mistyped_consumed_member(
        self, path: tuple[str, ...], value: Any
    ) -> None:
        document = load("lookup_uploaded")
        target = document
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = value

        with pytest.raises(ValidationError):
            _FOUND.validate_python(document, strict=True)

    @pytest.mark.parametrize("name", _FOUND_FIXTURES)
    def test_root_and_user_have_the_live_members(self, name: str) -> None:
        document = load(name)

        assert tuple(document) == ("ok", "user")
        assert tuple(document["user"]) == _USER_MEMBERS

    def test_uploaded_pictures_are_plain_https_urls_on_the_avatar_host(self) -> None:
        profile = load("lookup_uploaded")["user"]["profile"]

        assert profile["is_custom_image"] is True
        for member in _IMAGES_UPLOADED:
            url = profile[member]
            parts = urlsplit(url)
            assert (parts.scheme, parts.hostname, parts.port) == (
                "https",
                "avatars.slack-edge.com",
                None,
            )
            assert "@" not in parts.netloc
            assert (parts.query, parts.fragment) == ("", "")
            assert all(0x21 <= ord(c) <= 0x7E for c in url)
            assert len(url) <= 2048

    def test_member_without_an_uploaded_picture_has_gravatar_urls(self) -> None:
        profile = load("lookup_gravatar")["user"]["profile"]

        assert "is_custom_image" not in profile
        assert "image_original" not in profile
        assert "image_1024" not in profile
        assert profile["avatar_hash"].startswith("g")
        for member in _IMAGES_GRAVATAR:
            parts = urlsplit(profile[member])
            assert (parts.scheme, parts.hostname) == ("https", "secure.gravatar.com")
            assert sorted(p.split("=")[0] for p in parts.query.split("&")) == [
                "d",
                "s",
            ]


@pytest.mark.unit
class TestErrors:
    @pytest.mark.parametrize(("name", "code"), _ERROR_FIXTURES.items())
    def test_error_is_ok_false_with_its_code(self, name: str, code: str) -> None:
        document = load(name)

        _ERROR.validate_python(document, strict=True)
        assert document["error"] == code

    @pytest.mark.parametrize("name", ["users_not_found", "invalid_auth", "not_authed"])
    def test_error_has_only_ok_and_error(self, name: str) -> None:
        assert tuple(load(name)) == ("ok", "error")


@pytest.mark.unit
class TestParser:
    """Every fixture through the production classification, decoded from its
    bytes as the fetcher decodes a body (Response Contract)."""

    @pytest.mark.parametrize(
        ("name", "expected"),
        [
            pytest.param(
                "lookup_uploaded",
                Lookup(Outcome.PICTURE, picture_url=UPLOADED_PICTURE),
                id="uploaded",
            ),
            pytest.param("lookup_gravatar", Lookup(Outcome.NO_PICTURE), id="gravatar"),
            pytest.param(
                "users_not_found", Lookup(Outcome.NO_PICTURE), id="users-not-found"
            ),
            pytest.param(
                "invalid_auth",
                Lookup(Outcome.TOKEN_REJECTED, token_error="invalid_auth"),
                id="invalid-auth",
            ),
            pytest.param(
                "not_authed",
                Lookup(Outcome.TOKEN_REJECTED, token_error="not_authed"),
                id="not-authed",
            ),
            pytest.param(
                "invalid_arguments",
                Lookup(Outcome.LOOKUP_ERROR),
                id="invalid-arguments",
            ),
        ],
    )
    def test_fixture_classifies_as_its_live_outcome(
        self, name: str, expected: Lookup
    ) -> None:
        assert classify_lookup(decode_json(load_raw(name))) == expected

    def test_uploaded_picture_is_the_192_pixel_image_as_returned(self) -> None:
        profile = load("lookup_uploaded")["user"]["profile"]

        lookup = classify_lookup(decode_json(load_raw("lookup_uploaded")))

        assert lookup.picture_url == profile["image_192"] == UPLOADED_PICTURE
