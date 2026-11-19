"""Shared SMELT fixtures and a fake SMELT Product listing server.

The `products_page_*.json` files under `backend/tests/fixtures/smelt/` are
live `v1/basic/products/` pages (first, middle, and final) captured from
the default `SMELT_API_URL` with `page_size=100`, stored as served. They
contain Product catalog data only; no personal identifier was present
(docs/conventions.md, External Integration Contract Verification).

The `maintainership_*.json` files are live
`experimental/v2/packages/{package_name}/maintainership` responses captured
anonymously from the default `SMELT_API_URL` on 2026-10-03 and sanitized
before saving: every username, email, group name, group email, codestream
name and URL, and the package name in the 404 message was replaced with a
deterministic fictional value. Structure, key order, types, nullness, and
duplicate relationships are preserved.

The `maintained_*.json` files are live
`experimental/v2/maintained/{package_name}?include_reactive_ltss=true`
responses captured anonymously from the default `SMELT_API_URL` on
2026-11-16 (SMELT v3.98.0), after `tools/smelt#1499` renamed the
maintenance process type `SLE_15` to `IBS` (#1318). They keep the
properties established by #780 after `tools/smelt#1465`: every SLFO
codestream is typed `SLFO` and resolved only through compose. Compared
with the 2026-10-12 captures, `ibs_only` (formerly `sle15_only`) differs
only in that rename, `not_found` and `case_variant` are identical, and the
other captures also reflect upstream catalog changes. Every URL-valued
string (`codestream.url`, `product_definition.url`) was replaced with a
fictional `build.example.invalid` URL, and the unconsumed `binary_packages`
array was trimmed to its first element per entry. Codestream names, Product CPEs,
and Product friendly names are retained: they are consumed match keys and
public Product identifiers. No personal identifier was present.

The `maintained_sweep_page_*.json` files are live pages of the maintained
sweep `experimental/v2/maintained/?include_reactive_ltss=true&page_size=200`
captured anonymously from the default `SMELT_API_URL` on 2026-11-19: page 1,
page 883 (a middle page that holds both `python-PrettyTable` and
`python-prettytable`), page 1201 (the last page, 159 results,
`has_next = false`), and page 1202 (beyond the last: no result,
`has_next = false`). They were sanitized as the `maintained_*.json` files:
every URL-valued string was replaced with a fictional
`build.example.invalid` URL and the unconsumed `binary_packages` array was
trimmed to its first element per result. Package names, codestream names,
Product CPEs, and Product friendly names are retained; no personal
identifier was present. They are stored in the served serialization.

`SmeltServer` is an in-process `httpx.MockTransport` handler that serves
a paginated `v1/basic/products/` listing in the verified live
serialization (docs/features/packages/product-catalog.md, SMELT
Integration > Origin, Authentication, and Pagination): fixed page size
100, constant `count` and `total_pages`, continuation metadata with the
known `http` scheme defect, and `previous` on page 2 omitting `page`. Tests
mutate `pages` to build negative cases, register raw `responses` (status
codes, undecodable bodies, transport errors), and inspect `requests`. It
serves any page-keyed endpoint, so `sweep_pages()` builds the pages of the
maintained sweep for it.

Consumers: `tests/test_services/test_packages/test_smelt_product_listing.py`,
`test_smelt_product_listing_contract.py`, `test_sync_smelt_products.py`,
`test_smelt_maintainership.py`, `test_smelt_maintainership_contract.py`,
`test_smelt_maintained.py`, `test_smelt_maintained_contract.py`,
`test_smelt_maintained_sweep.py`, `test_smelt_maintained_sweep_contract.py`,
and `test_sync_smelt_packages.py`.
All values are fictional (`smelt.example.test`, `cpe:/o:example:...`).
"""

from __future__ import annotations

import copy
import json
import math
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

import httpx

from tests.support.inadmissible import json_bytes

FIXTURE_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "smelt"

# Page numbers of the captured live pages.
FIXTURE_PAGES = (1, 2, 6)

SMELT_TEST_API_URL = "https://smelt.example.test/api"
"""A fictional, validated `SMELT_API_URL` (no port)."""

SMELT_TEST_ENDPOINT = f"{SMELT_TEST_API_URL}/v1/basic/products/"
"""The Product listing request URL for `SMELT_TEST_API_URL`."""

SMELT_TEST_METADATA_BASE = "http://smelt.example.test/api/v1/basic/products/"
"""Continuation-metadata base in the live serialization (`http` scheme)."""

PAGE_SIZE = 100


def load_products_page(page: int) -> dict[str, Any]:
    """Return one captured live Product listing page as parsed JSON."""
    path = FIXTURE_DIR / f"products_page_{page}.json"
    data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return data


MAINTAINERSHIP_SUCCESS_FIXTURES = (
    "users_only",
    "groups_only",
    "users_and_groups",
    "null_email",
    "empty",
)
"""Sanitized live HTTP 200 maintainership responses, by fixture name."""

MAINTAINERSHIP_NOT_FOUND_FIXTURE = "not_found"
"""The sanitized live HTTP 404 response for an unknown package."""


def load_maintainership_fixture(name: str) -> Any:
    """Return one sanitized live maintainership response as parsed JSON."""
    path = FIXTURE_DIR / f"maintainership_{name}.json"
    return json.loads(path.read_text(encoding="utf-8"))


MAINTAINED_SUCCESS_FIXTURES = ("ibs_only", "slfo_only", "mixed", "reactive_ltss")
"""Sanitized live HTTP 200 maintained-package responses, by fixture name."""

MAINTAINED_NOT_FOUND_FIXTURES = ("not_found", "case_variant")
"""Sanitized live HTTP 404 responses: an unknown package and a case
variant (`Kernel-Default`) of a known one."""


def load_maintained_fixture(name: str) -> Any:
    """Return one sanitized live maintained-package response as parsed JSON."""
    path = FIXTURE_DIR / f"maintained_{name}.json"
    return json.loads(path.read_text(encoding="utf-8"))


SWEEP_FIXTURE_PAGES = (1, 883, 1201, 1202)
"""Page numbers of the captured live maintained sweep pages."""

SWEEP_PAGE_SIZE = 200


def load_sweep_page(page: int) -> dict[str, Any]:
    """Return one captured live maintained sweep page as parsed JSON."""
    path = FIXTURE_DIR / f"maintained_sweep_page_{page}.json"
    data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return data


def sweep_row(package: str) -> dict[str, Any]:
    """One fictional maintained sweep result of `package` with every
    upstream field of the live shape."""
    return {
        "codestream": {
            "name": "EXAMPLE:SLE-15-SP7:Update",
            "url": "https://build.example.invalid/fictional/1",
            "type": "IBS",
        },
        "binary_packages": [
            {
                "name": package,
                "source_package_name": package,
                "support_status": "L3",
            }
        ],
        "targets": [
            {
                "product": {
                    "id": 1001,
                    "friendly_name": "Example Server 15 SP7",
                    "cpe": "cpe:/o:example:server:15:sp7",
                    "support_status": "General Support",
                },
                "repository": "EXAMPLE:Updates:Server:15-SP7:x86_64",
                "product_definition": {
                    "name": "EXAMPLE-SERVER-15-SP7-x86_64",
                    "url": "https://build.example.invalid/fictional/2",
                    "type": "channel",
                },
            }
        ],
        "package": package,
        "support_status": "General Support",
    }


def sweep_page(page: int, results: list[Any], *, has_next: bool) -> dict[str, Any]:
    """One maintained sweep page envelope in the live serialization."""
    return {
        "status": "success",
        "data": {
            "results": results,
            "page": page,
            "page_size": SWEEP_PAGE_SIZE,
            "has_next": has_next,
            "has_previous": page > 1,
        },
    }


def sweep_pages(packages: list[str]) -> dict[int, dict[str, Any]]:
    """Split one result per entry of `packages` into a valid sweep page
    sequence keyed by page number. A multiple of the page size ends with a
    full page followed by no further page, as SMELT derives `has_next`
    from one additional result."""
    pages: dict[int, dict[str, Any]] = {}
    total_pages = max(1, math.ceil(len(packages) / SWEEP_PAGE_SIZE))
    for page in range(1, total_pages + 1):
        start = (page - 1) * SWEEP_PAGE_SIZE
        rows = [sweep_row(name) for name in packages[start : start + SWEEP_PAGE_SIZE]]
        pages[page] = sweep_page(page, rows, has_next=page < total_pages)
    return pages


def product_row(index: int, **overrides: Any) -> dict[str, Any]:
    """One fictional SMELT Product row with every upstream field.

    The ignored fields (`id`, `end_of_life`, `changed`, `details`) are
    present as served upstream; `overrides` replaces or adds any key.
    """
    row: dict[str, Any] = {
        "name": f"Example-Product-{index}",
        "id": 1000 + index,
        "friendly_name": f"Example Product {index}",
        "version": f"{index}",
        "cpe": f"cpe:/o:example:product-{index}:1",
        "end_of_life": None,
        "changed": "2026-09-01T03:00:00.000000Z",
        "repos": [
            f"EXAMPLE:Products:Product{index}:1:x86_64",
            f"EXAMPLE:Updates:Product{index}:1:x86_64",
        ],
        "details": [],
    }
    row.update(overrides)
    return row


def metadata_url(base: str, page: int) -> str:
    """A continuation URL in the live serialization; page 1 omits `page`."""
    if page == 1:
        return f"{base}?page_size={PAGE_SIZE}"
    return f"{base}?page={page}&page_size={PAGE_SIZE}"


def paginate(
    rows: list[dict[str, Any]], *, metadata_base: str = SMELT_TEST_METADATA_BASE
) -> dict[int, dict[str, Any]]:
    """Split `rows` into a valid page sequence keyed by page number."""
    total_pages = max(1, math.ceil(len(rows) / PAGE_SIZE))
    pages: dict[int, dict[str, Any]] = {}
    for page in range(1, total_pages + 1):
        start = (page - 1) * PAGE_SIZE
        pages[page] = {
            "count": len(rows),
            "total_pages": total_pages,
            "next": (
                metadata_url(metadata_base, page + 1) if page < total_pages else None
            ),
            "previous": metadata_url(metadata_base, page - 1) if page > 1 else None,
            "results": copy.deepcopy(rows[start : start + PAGE_SIZE]),
        }
    return pages


def make_rows(total: int, *, start: int = 1) -> list[dict[str, Any]]:
    """`total` distinct fictional Product rows numbered from `start`."""
    return [product_row(index) for index in range(start, start + total)]


Responder = Callable[[httpx.Request], httpx.Response]


class SmeltServer:
    """A fake SMELT `v1/basic/products/` endpoint for `httpx.MockTransport`.

    `pages` maps a page number to the JSON body served for it (any JSON
    value, mutable by tests); `responses` maps a page number to a callable
    that returns a raw response or raises a transport error instead. A
    request for an unknown page is answered with HTTP 404. Every request
    is recorded in `requests`; when `events` is supplied, `("http", url)`
    is also appended to it so a test can order requests against other
    recorded events.
    """

    def __init__(
        self,
        pages: Mapping[int, Any],
        *,
        events: list[tuple[str, str]] | None = None,
    ) -> None:
        self.pages: dict[int, Any] = dict(pages)
        self.responses: dict[int, Responder] = {}
        self.requests: list[httpx.Request] = []
        self.events = events

    @classmethod
    def for_rows(
        cls,
        product_rows: Iterable[dict[str, Any]],
        *,
        metadata_base: str = SMELT_TEST_METADATA_BASE,
        events: list[tuple[str, str]] | None = None,
    ) -> SmeltServer:
        """Serve `product_rows` as a valid paginated listing."""
        return cls(
            paginate(list(product_rows), metadata_base=metadata_base), events=events
        )

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.events is not None:
            self.events.append(("http", str(request.url)))
        page = _requested_page(request)
        if page in self.responses:
            return self.responses[page](request)
        if page not in self.pages:
            return httpx.Response(404, json={"detail": "Invalid page."})
        # A surrogate code point travels as its `\uXXXX` escape
        # (`tests.support.inadmissible.json_bytes`).
        return httpx.Response(
            200,
            content=json_bytes(self.pages[page]),
            headers={"Content-Type": "application/json"},
        )

    def client(self) -> httpx.AsyncClient:
        """A client whose transport is this server (redirects not followed)."""
        return httpx.AsyncClient(transport=httpx.MockTransport(self.handler))

    @property
    def requested_urls(self) -> list[str]:
        return [str(request.url) for request in self.requests]

    @property
    def requested_pages(self) -> list[int | None]:
        return [_requested_page(request) for request in self.requests]


def _requested_page(request: httpx.Request) -> int | None:
    values = parse_qs(request.url.query.decode("ascii")).get("page")
    if not values or not values[0].isdigit():
        return None
    return int(values[0])
