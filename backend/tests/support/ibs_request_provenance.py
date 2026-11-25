"""Sanitized IBS provenance-chain fixtures and their loader.

The documents under `backend/tests/fixtures/ibs/reconciliation/` were
captured read-only from the IBS API (`https://api.suse.de`) on 2026-10-14
(chains A to C), on 2026-11-12 (chain D), on 2026-11-16 (chain E), on
2026-11-24 (chain F), and on 2026-11-25 (chain G) with `secbox osc -A
https://api.suse.de api [-X POST] ...` (chains E to G through the `osc`
library in the same container)
(docs/conventions.md, External Integration Contract Verification;
docs/features/packages/ibs-submission-tracking.md, Required Roots, Effective
SR, Release Discovery, Accepted RR Provenance, Action-Scoped CVE Evidence;
docs/features/integrations/ibs-integration.md, Deleted Package Lookup).
Each call ran in a capture process that kept stdout and stderr in memory
and wrote only an allow-listed rebuild of the document; nothing raw reached
a terminal or a file. The diff requests were built with the production
`request_action_diff_form()` from the captured point detail (chain E: the
same not-accepted form, followed by `linkrev=base` for the link-base form;
chain G: the accepted form, built by the capture from the live detail in the
same way, which the contract tests confirm by serving each recorded query to
the production client), and the current release evidence with the
source-info and `orev=0` source-diff forms of `IBSClient`. Only consumed
elements and attributes were written:

- point detail: `request/@id`; `state/@name`, `@created`, `@when`,
  `@superseded_by`; `action/@type`; `source/@project`, `@package`, `@rev`;
  `target/@project`, `@package`, `@releaseproject`; `acceptinfo/@rev`,
  `@srcmd5`, `@xsrcmd5`, `@osrcmd5`, `@oxsrcmd5`, `@oproject`, `@opackage`;
- source history: `revision/@rev` with its `srcmd5`, `time`, and
  `requestid` children;
- diffs: `sourcediff`, `issues`, `issue/@state`, `@tracker`, `@name`,
  `@label` (chain G: of `cve` issues only; the other trackers were dropped);
  an error response: `status/@code`, `@origin` (the body of an HTTP 400 or
  404 diff is not consumed);
- source info: `sourceinfo/@package`, `@srcmd5`, and an `error` child;
- deleted package lookup: `directory/@name` (its `rev`, `srcmd5`, `entry`,
  and `linkinfo` are not consumed); an error response: `status/@code`.

Everything else was discarded unread, notably the state `who`, the request
`creator`, `description`, `review`, and `history` elements, the history
`user`, `comment`, and `version` children, and all headers, signatures,
and cookies.

Values: the real-to-fictional mapping of the earlier request capture
(`tests/support/ibs_request_api.py`) no longer exists, so this group has
its own fictional block. Request numbers start at 960001, at 960101 in
chain D, at 960201 in chain E, at 960301 in chain F, and at 960401 in chain
G (one value per real number, also inside `SUSE:Maintenance:REQUEST:{n}`
projects and history `requestid`), incident numbers at 81001, at 81101 in
chain D, at 81201 in chain F, and at 81301 in chain G (also in
`SUSE:Maintenance:{n}` projects and `.{n}` package suffixes), and every
checksum is a fictional
MD5-shaped value that keeps the equalities of the live data within its
chain. Revision numbers, timestamps, and the public CVE and bug
identifiers are as served. Every captured project is a `SUSE:` project.
The only personal identifiers present were the owners of the `gh` issue
references of `d_diff_current`, GitHub accounts, which the allow-listed
rebuild kept; before the document was committed, each was replaced by a
fictional username (`jdoe`, `asmith`, `bwilson`), equal owners by equal
names. The chain E capture replaced such owners before printing; its
documents carry none.

Seven chains:

- **A — current release evidence of the `openvpn` chain of
  `tests/support/ibs_request_api.py`** in `SUSE:SLE-15-SP6:Update`:
  `a_sourceinfo_current` (the expanded `srcmd5`, a new fictional value)
  and `a_diff_current` (its `orev=0` diff), which carries the two CVEs
  that release request 910051 of that group released.
- **B — a release before 2023** of `openvpn` in its origin codestream
  `SUSE:SLE-15:Update` (incident 81001): `b_history_codestream` (three
  release requests; the newest, 960003, is the proving one),
  `b_request_rr_accepted` (960003, with the codestream action and
  patchinfo actions), `b_history_lookup` (the exact lookup of its target
  package `openvpn.81001`), `b_diff_rr_accepted` (its release diff),
  `b_history_incident` (branch commit, the SR, the release request),
  `b_request_sr_accepted` (SR 960004, whose acceptinfo `xsrcmd5` differs
  from the release action's `source/@rev`), `b_diff_sr_accepted`, and the
  current release evidence `b_sourceinfo_current` and `b_diff_current`.
- **C — a kernel incident** in `SUSE:SLE-15-SP6:Update` (incident 81003,
  previous incident 81004): `c_history_codestream_source` and
  `c_history_codestream_default` (32 release requests each; the newest
  is 960036, the one before 960035); `c_request_rr_accepted` (960035:
  `submit` actions, flavor release actions without acceptinfo,
  `kernel-source` and `kernel-default-base` with acceptinfo) and
  `c_request_rr_newer` (960036, incident 81005); the exact lookups
  `c_history_lookup_source`, `c_history_lookup_source_newer`, and
  `c_history_lookup_default_base`; the release diffs `c_diff_rr_source`,
  `c_diff_rr_source_newer` (disjoint CVE sets), and
  `c_diff_rr_default_base` (an empty `issues` element: the package's own
  changelog references no CVE); `c_history_incident_source` (branch, SR
  960037, branch, SR 960038, the release request) and
  `c_history_incident_default_base` (branch, release request: no SR);
  `c_request_sr_first` and `c_request_sr_second` with their accepted
  diffs `c_diff_sr_first` and `c_diff_sr_second`.
- **D — a release before two reverted release requests** of `PackageKit`
  in `SUSE:SLE-15-SP4:Update`, whose current sources still carry
  CVE-2024-0217: `d_sourceinfo_current` and `d_diff_current`;
  `d_history_codestream` (16 revisions); `d_request_rr_{n}` for every
  release request that the release scan reads, from the newest, 960114,
  to the proving one, 960103 (incident 81102), with the release diff
  `d_diff_rr_{n}` of each accepted one; and `d_history_lookup` (the exact
  lookup of `PackageKit.81102`). IBS accepted release requests 960106 and
  960107 of incident 81114 automatically, the acceptance failed after
  committing their codestream revisions (6 and 8), and each commit was
  reverted by the next revision, which has no request number and restores
  the `srcmd5` of revision 5; both requests are now `revoked` and their
  actions have no acceptinfo. 960108 then released incident 81114. The
  accepted releases newer than 960103 are rebuilds with an empty release
  diff (960104, 960105, 960108 to 960111) or carry other CVEs (960112 to
  960114). The diffs of the revoked requests were not captured: the scan
  does not read them.
- **E — open submissions whose source link conflicts with the current
  codestream package**: `e_request_sr_pillow` (960201, `python-Pillow` in
  `SUSE:SLE-15-SP4:Update`) and `e_request_sr_krb5` (960202, `krb5` in
  `SUSE:SLE-12-SP5:Update`), each `new`, with a `maintenance_incident`
  action from its staging project and a `delete` action for it. The
  source package of each is a branch link to exactly its codestream and
  logical package, whose expansion failed with `conflict in file
  {package}.spec`: a release of the codestream package after the branch
  touched the same lines. Their not-accepted diffs `e_diff_sr_pillow` and
  `e_diff_sr_krb5` answered HTTP 400 with a backend status document whose
  summary was `bad link: conflict in file {package}.spec`; the link-base
  diffs `e_diff_sr_pillow_link_base` (CVE-2026-106443 and one bug) and
  `e_diff_sr_krb5_link_base` (one bug, no CVE) are complete, and the old
  side of each was the link's `baserev` (not stored: `old` is not
  consumed). Only public issue references are kept: the bug of the krb5
  diff is not public, so its number was replaced by the fictional
  `bsc#1234567`. A third open submission without a conflict gave the same
  issues in both forms; it was not stored, because whether its issue
  references are public was not verified.
- **F — submissions whose incident package IBS deleted**:
  `f_request_sr_deleted` (960301, accepted into incident 81201, whose
  project the Maintenance Team deleted after the acceptance; five
  `maintenance_incident` actions, among them `kernel-source` of
  `SUSE:SLE-12-SP5:Update`, and a `delete` action) with
  `f_history_incident_deleted` (the history of its `kernel-source` incident
  package: HTTP 404 `unknown_project`) and `f_deleted_incident_package` (its
  deleted package lookup: the `<directory>` of that package);
  `f_request_sr_package_deleted` (960302, accepted into incident 81202,
  which still exists) with `f_history_package_deleted` (HTTP 404
  `unknown_package` for its `kernel-livepatch-SLE15-SP7_Update_0` incident
  package, which IBS deleted from the incident) and `f_deleted_package` (its
  `<directory>`); and the lookups that report no deleted package:
  `f_deleted_error_exists` (HTTP 400 `package_exists` for an existing
  codestream package), `f_deleted_error_unknown_package` and
  `f_deleted_error_unknown_package_deleted_project` (HTTP 404
  `unknown_package` for a package that never existed in an existing and in
  the deleted project), and `f_deleted_error_unknown_project` (HTTP 404
  `unknown_project`). The live directories also carried `rev` and `srcmd5`;
  for 960301 they equalled its acceptinfo `rev` and `srcmd5`.
- **G — releases whose target or origin package IBS deleted**. The release
  scan of `cpio` in `SUSE:SLE-15:Update`, whose current sources still carry
  CVE-2019-14866: `g_sourceinfo_current` and `g_diff_current`;
  `g_history_codestream` (six revisions; the third has no request number);
  `g_request_rr_{n}` and the release diff `g_diff_rr_{n}` of every release
  request that the scan reads, from the newest, 960405, to the proving one,
  960401 (incident 81301), with `g_history_lookup` (the exact lookup of
  `cpio.81301`). IBS deleted `cpio.81302`, the target package of 960402,
  after its release (the revision after 960402 has no request number and
  the next release names `cpio.81301` as its origin package): its release
  diff `g_diff_rr_960402` and its exact lookup
  `g_history_lookup_deleted_target` answered HTTP 404 `unknown_package`, and
  its deleted package lookup `g_deleted_target` answered its `<directory>`.
  The releases newer than 960402 carry other CVEs. The origin package of
  `openssl` in `SUSE:SLE-12-SP2:Update`: `g_request_rr_origin_deleted`
  (960406, incident 81306, whose acceptinfo names the origin package
  `openssl.81307`, an older reissued update that IBS deleted after this
  release) with its release diff `g_diff_rr_origin_deleted` (HTTP 404
  `unknown_package`), the available exact lookup of its target package
  `g_history_lookup_origin_deleted`, and the deleted package lookups of its
  target package `g_deleted_target_exists` (HTTP 400 `package_exists`) and
  of its origin package `g_deleted_origin` (its `<directory>`).

The `orev=0` diff of the kernel codestream package was verified live (HTTP
200, about 17,000 issues, 2.4 MB, 4 s) and is not stored because of its
size; its shape is the one of `a_diff_current` and `b_diff_current`.

`responses.json` records the method, decoded path, ordered query, and
status of each request with the fictional values; each document of chains
D to G also records its own `captured_at`, which overrides the date of
the file. Every status is 200 except those of `ERROR_STATUSES`.
`serve_provenance_fixture()` serves the documents at their recorded method,
path, query, and status through the authenticating `IBSServer`, so the
same path can serve an unpaged history and an exact lookup, or the
not-accepted and link-base diffs of one action.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

import httpx

from tests.support.ibs_api import (
    FIXTURE_DIR,
    IBSServer,
    Responder,
    status_response,
    xml_response,
)

PROVENANCE_FIXTURE_DIR: Final = FIXTURE_DIR / "reconciliation"
PROVENANCE_FIXTURE_DATE: Final = "2026-10-14"
CHAIN_D_FIXTURE_DATE: Final = "2026-11-12"
CHAIN_E_FIXTURE_DATE: Final = "2026-11-16"
CHAIN_F_FIXTURE_DATE: Final = "2026-11-24"
CHAIN_G_FIXTURE_DATE: Final = "2026-11-25"

SP4: Final = "SUSE:SLE-15-SP4:Update"
SP6: Final = "SUSE:SLE-15-SP6:Update"
SLE15: Final = "SUSE:SLE-15:Update"
SLE12_SP5: Final = "SUSE:SLE-12-SP5:Update"
SP7: Final = "SUSE:SLE-15-SP7:Update"
SLE12_SP2: Final = "SUSE:SLE-12-SP2:Update"

A_CVES: Final = ("CVE-2026-63650", "CVE-2026-84732")
"""The CVEs that release request 910051 of the request group released."""
B_CVE: Final = "CVE-2022-0547"
B_RR: Final = 960003
B_SR: Final = 960004
B_INCIDENT: Final = 81001
C_RR: Final = 960035
C_RR_NEWER: Final = 960036
C_SR_FIRST: Final = 960037
C_SR_SECOND: Final = 960038
C_INCIDENT: Final = 81003
C_INCIDENT_NEWER: Final = 81005
D_CVE: Final = "CVE-2024-0217"
D_RR: Final = 960103
D_INCIDENT: Final = 81102
D_RR_REVOKED: Final = (960106, 960107)
"""The reverted release requests of `D_INCIDENT_REVOKED`, oldest first."""
D_RR_REPLACING: Final = 960108
"""The accepted release request of `D_INCIDENT_REVOKED`."""
D_INCIDENT_REVOKED: Final = 81114
D_SCAN: Final = tuple(range(960114, D_RR - 1, -1))
"""The release requests that the release scan reads, newest first."""

CHAIN_D_FIXTURES: Final = (
    "d_sourceinfo_current",
    "d_diff_current",
    "d_history_codestream",
    *(f"d_request_rr_{number}" for number in D_SCAN),
    *(f"d_diff_rr_{number}" for number in D_SCAN if number not in D_RR_REVOKED),
    "d_history_lookup",
)

E_PILLOW_SR: Final = 960201
E_PILLOW_CVE: Final = "CVE-2026-106443"
"""The CVE in the link-base diff of `E_PILLOW_SR`."""
E_KRB5_SR: Final = 960202
CHAIN_E_CONFLICTS: Final = ("e_diff_sr_pillow", "e_diff_sr_krb5")
"""The not-accepted diffs of chain E, which answered HTTP 400."""

CHAIN_E_FIXTURES: Final = (
    "e_request_sr_pillow",
    "e_diff_sr_pillow",
    "e_diff_sr_pillow_link_base",
    "e_request_sr_krb5",
    "e_diff_sr_krb5",
    "e_diff_sr_krb5_link_base",
)

F_SR_DELETED: Final = 960301
F_INCIDENT_DELETED: Final = 81201
"""The incident of `F_SR_DELETED`, whose project IBS deleted."""
F_KERNEL_PACKAGE: Final = "kernel-source.SUSE_SLE-12-SP5_Update"
"""The `kernel-source` incident package of `F_SR_DELETED`."""
F_SR_PACKAGE_DELETED: Final = 960302
F_INCIDENT_EXISTING: Final = 81202
"""The incident of `F_SR_PACKAGE_DELETED`, which still exists."""
F_LIVEPATCH: Final = "kernel-livepatch-SLE15-SP7_Update_0"
F_LIVEPATCH_PACKAGE: Final = f"{F_LIVEPATCH}.SUSE_SLE-15-SP7_GA"
"""The incident package of `F_SR_PACKAGE_DELETED` that IBS deleted."""

CHAIN_F_FIXTURES: Final = (
    "f_request_sr_deleted",
    "f_history_incident_deleted",
    "f_deleted_incident_package",
    "f_request_sr_package_deleted",
    "f_history_package_deleted",
    "f_deleted_package",
    "f_deleted_error_exists",
    "f_deleted_error_unknown_package",
    "f_deleted_error_unknown_package_deleted_project",
    "f_deleted_error_unknown_project",
)

G_CVE: Final = "CVE-2019-14866"
"""A CVE of the current `cpio` sources released only by `G_RR`."""
G_RR: Final = 960401
G_INCIDENT: Final = 81301
G_RR_WITHDRAWN: Final = 960402
"""The release request whose target package IBS deleted."""
G_INCIDENT_WITHDRAWN: Final = 81302
G_SCAN: Final = tuple(range(960405, G_RR - 1, -1))
"""The release requests that the release scan reads, newest first."""
G_RR_ORIGIN_DELETED: Final = 960406
G_INCIDENT_ORIGIN_DELETED: Final = 81306
G_ORIGIN_DELETED: Final = "openssl.81307"
"""The origin package of `G_RR_ORIGIN_DELETED`, which IBS deleted."""

CHAIN_G_FIXTURES: Final = (
    "g_sourceinfo_current",
    "g_diff_current",
    "g_history_codestream",
    *(f"g_request_rr_{number}" for number in G_SCAN),
    *(f"g_diff_rr_{number}" for number in G_SCAN),
    "g_history_lookup",
    "g_history_lookup_deleted_target",
    "g_deleted_target",
    "g_request_rr_origin_deleted",
    "g_diff_rr_origin_deleted",
    "g_history_lookup_origin_deleted",
    "g_deleted_target_exists",
    "g_deleted_origin",
)

ERROR_STATUSES: Final = {
    **dict.fromkeys(CHAIN_E_CONFLICTS, 400),
    "f_history_incident_deleted": 404,
    "f_history_package_deleted": 404,
    "f_deleted_error_exists": 400,
    "f_deleted_error_unknown_package": 404,
    "f_deleted_error_unknown_package_deleted_project": 404,
    "f_deleted_error_unknown_project": 404,
    f"g_diff_rr_{G_RR_WITHDRAWN}": 404,
    "g_history_lookup_deleted_target": 404,
    "g_diff_rr_origin_deleted": 404,
    "g_deleted_target_exists": 400,
}
"""The recorded status of every fixture that IBS did not answer with 200."""

PROVENANCE_FIXTURES: Final = (
    "a_sourceinfo_current",
    "a_diff_current",
    "b_history_codestream",
    "b_request_rr_accepted",
    "b_history_lookup",
    "b_diff_rr_accepted",
    "b_history_incident",
    "b_request_sr_accepted",
    "b_diff_sr_accepted",
    "b_sourceinfo_current",
    "b_diff_current",
    "c_history_codestream_source",
    "c_history_codestream_default",
    "c_request_rr_accepted",
    "c_request_rr_newer",
    "c_history_lookup_source",
    "c_history_lookup_source_newer",
    "c_history_lookup_default_base",
    "c_diff_rr_source",
    "c_diff_rr_source_newer",
    "c_diff_rr_default_base",
    "c_history_incident_source",
    "c_history_incident_default_base",
    "c_request_sr_first",
    "c_request_sr_second",
    "c_diff_sr_first",
    "c_diff_sr_second",
    *CHAIN_D_FIXTURES,
    *CHAIN_E_FIXTURES,
    *CHAIN_F_FIXTURES,
    *CHAIN_G_FIXTURES,
)


def load_provenance_fixture(name: str) -> bytes:
    """The bytes of provenance fixture `name` (without the `.xml` suffix)."""
    return (PROVENANCE_FIXTURE_DIR / f"{name}.xml").read_bytes()


def load_provenance_responses() -> dict[str, Any]:
    """The parsed `reconciliation/responses.json`."""
    data: dict[str, Any] = json.loads(
        (PROVENANCE_FIXTURE_DIR / "responses.json").read_text(encoding="utf-8")
    )
    return data


def provenance_fixture_record(name: str) -> dict[str, Any]:
    """The recorded method, path, query, and status of fixture `name`."""
    record: dict[str, Any] = load_provenance_responses()["documents"][f"{name}.xml"]
    return record


def provenance_fixture_date(name: str) -> str:
    """The capture date of fixture `name`: its own `captured_at`, otherwise
    the date of `responses.json`."""
    responses = load_provenance_responses()
    date: str = responses["documents"][f"{name}.xml"].get(
        "captured_at", responses["captured_at"]
    )
    return date


def provenance_fixture_query(name: str) -> list[tuple[str, str]]:
    """The ordered query of the live request that produced fixture `name`."""
    return [(key, value) for key, value in provenance_fixture_record(name)["query"]]


def provenance_fixture_paths() -> list[Path]:
    """Every stored provenance fixture document."""
    return sorted(PROVENANCE_FIXTURE_DIR.glob("*.xml"))


Query = tuple[tuple[str, str], ...]


@dataclass
class QueryRoutes:
    """Query-aware routes on top of `IBSServer`, which routes by method and
    path only: one dispatcher per `(method, path)` selects the responder of
    the request's exact ordered query. An unrouted query is recorded in
    `unrouted` and answered with HTTP 404."""

    server: IBSServer
    unrouted: list[tuple[str, str, Query]] = field(default_factory=list)
    _routes: dict[tuple[str, str], dict[Query, Responder]] = field(default_factory=dict)

    def route(
        self, method: str, path: str, query: list[tuple[str, str]], responder: Responder
    ) -> None:
        key = (method, path)
        if key not in self._routes:
            self._routes[key] = {}
            self.server.route(method, path, self._dispatcher(key))
        self._routes[key][tuple(query)] = responder

    def _dispatcher(self, key: tuple[str, str]) -> Responder:
        def dispatch(request: httpx.Request) -> httpx.Response:
            query = tuple(request.url.params.multi_items())
            responder = self._routes[key].get(query)
            if responder is None:
                self.unrouted.append((key[0], key[1], query))
                return httpx.Response(404)
            return responder(request)

        return dispatch


def provenance_fixture_responder(name: str) -> Responder:
    """Serve fixture `name` with its recorded status."""
    document = load_provenance_fixture(name)
    status = provenance_fixture_record(name)["status"]
    if status == 200:
        return xml_response(document)
    return status_response(status, document)


def serve_provenance_fixture(routes: QueryRoutes, name: str) -> None:
    """Route fixture `name` at its recorded method, path, query, and
    status."""
    record = provenance_fixture_record(name)
    routes.route(
        record["method"],
        record["path"],
        provenance_fixture_query(name),
        provenance_fixture_responder(name),
    )
