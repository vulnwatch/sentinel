"""MITRE `cvelistV5` fixtures.

The files under `backend/tests/fixtures/mitre/` are sanitized captures of
`https://github.com/CVEProject/cvelistV5` consumed by
`app/services/tickets/mitre_cve_record.py`
(docs/features/tickets/cve-sync-mitre.md). One capture, made anonymously on
2026-10-09 (docs/conventions.md, External Integration Contract
Verification):

- `git ls-remote --symref` reported `HEAD` → `refs/heads/main` at
  `dcb449566c4c5d11e6c5a20b8331ad171396e281` (2026-10-09T10:27:14Z).
- The records come from the release asset
  `2026-10-09_all_CVEs_at_midnight.zip.zip` of release
  `cve_2026-10-09_1000Z`. Its inner `cves.zip` holds exactly the 403,377
  `cves/` paths of tag `cve_2026-10-09_0000Z`
  (`b256fd4315d96daee9fc3d69ac23a21ceca90ac8`, 2026-10-09T00:38:14Z), and
  every entry's Git blob ID equals that tree's, so each entry is the
  repository file at that commit. `repository_paths.txt` samples the same
  tree (from an anonymous `git clone --bare --filter=blob:none --depth 1`).
- The source reference URL form `https://cve.org/CVERecord?id={cve_id}`
  answered 200 after a redirect to `www.cve.org`.

Full scan of the 403,375 record files of that snapshot:

- Every `cves/` path except `cves/delta.json` and `cves/deltaLog.json`
  matches `cves/YEAR/NNNxxx/CVE-YEAR-SEQ.json`; the bucket is `seq // 1000`
  and the directory year is the CVE-ID year in every record, and every JSON
  `cveId` equals its file name. Sequences have 4 (167,489), 5 (231,510),
  6 (2,908), and 7 (1,468) digits.
- `state` is `PUBLISHED` (384,931) or `REJECTED` (18,444): no RESERVED
  record exists. No `PUBLISHED` record has `dateRejected`; no date is
  `null`.
- The CNA `providerMetadata.shortName` key is absent in 12 records (all
  `PUBLISHED`, `orgId` a UUID; 11 with CNA `metrics`, all with
  `problemTypes`); it is `suse` in 300 records; it is never untrimmed and
  never starts with `adp:`.
- ADP identities (`shortName`, `orgId`): `CVE` / `af854a3a-…` 250,707;
  `CISA-ADP` / `134c704f-…` 196,712; `siemens-SADP` / `0b142b55-…` 1,360;
  `redhat-SADP` / `0b0ca135-…` 1,170. Every ADP has a trimmed `shortName`;
  no record has two ADPs of one `shortName` or two CISA-ADP containers.
- Every SSVC (196,711) is in a CISA-ADP container, at most one per
  container (one container has none); `options` are the three single-key
  objects, `version` is `2.0.3`. KEV (1,739): at most one per container,
  `dateAdded` `YYYY-MM-DD`, `reference` a string. 196 CNA containers carry
  their own `other.type` `ssvc`, which is not consumed.
- Every `references[]` element is an object with a string `url`; `tags`,
  when present, is an array of strings. Every tag without the `x_` prefix
  is in ticket-references.md § CVE Source Tag Mapping; the 818,799 `x_…`
  tags are unknown.
- 273,506 CVSS vectors: none rejected by the External Base Reduction,
  54,703 reduced. No string contains U+0000.

The CVE Record 5.x field shapes of these records are asserted with the
strict typed model of `tests/test_services/test_cve_record_contract.py`
(the #876 capture of the same repository); this module adds the
source-specific records.

Record fixtures, source path, and purpose:

- `cna_short_name_missing` (`cves/2022/44xxx/CVE-2022-44455.json`, 5.1): a
  CNA `providerMetadata` without `shortName`, with a `cvssV3_1` vector and a
  CWE (the CNA defensive guard), a CISA-ADP container with SSVC only, and a
  CVE Program container;
- `cna_suse_reserved_provider` (`cves/2022/45xxx/CVE-2022-45153.json`, 5.1):
  the CNA short name `suse` (the reserved provider) with a vector and a CWE;
- `cisa_kev_cwe_tags` (`cves/2024/21xxx/CVE-2024-21182.json`, 5.2): a
  CISA-ADP container with SSVC, KEV, a `CWE`-typed `CWE-noinfo` problem
  type without `cweId`, and a `government-resource` reference, a CVE
  Program container, and a CNA `cvssV3_1` vector, a free-text problem type
  without `cweId`, and a `vendor-advisory` reference;
- `cisa_adp_affected` (`cves/2024/42xxx/CVE-2024-42022.json`, 5.1): a
  CISA-ADP container with SSVC, a CWE, and its own `affected`, beside a CNA
  `cvssV3_0` vector and no CNA `problemTypes` or `title`;
- `siemens_sadp` (`cves/2022/23xxx/CVE-2022-23303.json`, 5.2): a
  `siemens-SADP` container with `affected`, beside a CVE Program container;
- `cna_ssvc_not_consumed` (`cves/2026/102xxx/CVE-2026-102670.json`, 5.2): a
  CNA `other.type` `ssvc` entry, `cvssV4_0` and `cvssV3_1` vectors, and no
  ADP container;
- `references_x_tags` (`cves/2025/6xxx/CVE-2025-6545.json`, 5.1): CNA
  references with `patch`, `third-party-advisory`, and an `x_` tag, and a
  CNA `cvssV4_0` vector.

A second capture, made anonymously on 2026-11-09 for the owner of the record
(docs/features/tickets/cna.md, CNA of a CVE), took its records from the
release asset `2026-11-09_all_CVEs_at_midnight.zip.zip` of release
`cve_2026-11-09_1200Z` (`main` at
`7e54ca86be282cb48f6fc8adb7b7640721f635c7`). Full scan of its 421,272
record files (402,131 `PUBLISHED`, 19,141 `REJECTED`):

- `containers.cna.providerMetadata` is an object in every record, also a
  rejected one, and its `orgId` is a lowercase hyphenated UUID in every
  record. `shortName` is absent in 12 (`PUBLISHED`) and otherwise a trimmed
  string of 2 to 30 characters without an inadmissible character;
  `dateUpdated` is absent in 2, `YYYY-MM-DDTHH:MM:SS.fffZ` in 421,268, and
  without offset or fraction in 2.
- 494 organizations own records. 21 of them publish under more than one
  short name over time, such as `@huntrdev` (1,585 records, `dateUpdated`
  2021-06-26 to 2023-12-23) and `@huntr_ai` (911 records, 2023-11-07 to
  2026-09-11) for `c09c270a-b464-47c1-9133-acb35b22c19a`; the date ranges of
  two names of one organization can overlap. One short name, `mitre`,
  occurs for two organizations: `8254265b-…` and, in 2 records,
  `50d0f415-…`, whose other 109 records carry `Hitachi`.
- `cveMetadata.assignerOrgId` differs from the owner in 74 records, the
  transferred ones.
- The Linux kernel CNA publishes 18,678 records as `416baaa9-…` / `Linux`.
  The same capture day, every one of the 18,559 records of `vulns.git`
  (`master` `47a51be7d7ad01c834715700b5969a22982d83d2`) carried only
  `providerMetadata.orgId` `f4215fc3-5b6b-47ff-a258-f7189bd81038`
  (`tests/support/kernel.py`).

Its record fixtures:

- `cna_linux_kernel` (`cves/2021/47xxx/CVE-2021-47658.json`, 5.2): a record
  of the Linux kernel CNA as cvelistV5 publishes it;
- `cna_transferred` (`cves/2025/57xxx/CVE-2025-57790.json`, 5.1): an owner
  (`Commvault`) other than the assigner (`mitre`);
- `cna_short_name_before_change` (`cves/2022/4xxx/CVE-2022-4685.json`, 5.0)
  and `cna_short_name_after_change` (`cves/2024/7xxx/CVE-2024-7959.json`,
  5.2): two rejected records of one organization, `@huntrdev` dated
  2022-12-28 and `@huntr_ai` dated 2026-07-16. Their `rejectedReasons` are
  kept: they are fixed texts of the CVE Program.

Each record was re-serialized with a two-space indent, keeping every kept
key in its original order. Trimming kept `dataType`, `dataVersion`, every
key of `cveMetadata`, and, of each container, `providerMetadata`, `title`,
`descriptions`, `affected`, `metrics`, `problemTypes`, and `references`;
every other container member (`credits`, `datePublic`, `impacts`,
`source`, `timeline`, `x_generator`, `x_adpType`, and, in the second
capture, `cpeApplicability`) was removed. No array was
shortened. Sanitization (docs/conventions.md, Example Data in
Documentation): every CNA `title` is `example: fictional title of
<CVE-ID>` (the ADP titles `CISA ADP Vulnrichment` and `CVE Program
Container` are kept), every `descriptions[].value` is `example: fictional
description of <CVE-ID>.` (their `supportingMedia` removed), every
non-`GENERAL` `metrics[].scenarios[].value` is `Fictional scenario.`, and
the CVE-2022-23303 references to a personal project site and two
mailing-list archives are `https://advisory.example.invalid/upstream/<n>`.
CVE-IDs, organisation UUIDs and short names, versions, vectors, dates,
CWE texts, SSVC and KEV content, and URLs of organisations, vendors,
projects, and advisory databases are public product data and are retained.

Consumers: `tests/test_services/test_tickets/test_mitre_record_contract.py`,
`tests/test_services/test_tickets/test_mitre_cve_record.py`, the
`SyncMitreCves` tests (`test_sync_mitre_cves.py`,
`test_sync_mitre_cves_execute.py`, `test_sync_mitre_cves_reachability.py`,
`test_sync_mitre_cves_kev.py`), and `tests/support/mitre_fetcher.py`.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from tests.support import cve_record

FIXTURE_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "mitre"

RECORD_SOURCES: Mapping[str, str] = {
    "cna_short_name_missing": "cves/2022/44xxx/CVE-2022-44455.json",
    "cna_suse_reserved_provider": "cves/2022/45xxx/CVE-2022-45153.json",
    "cisa_kev_cwe_tags": "cves/2024/21xxx/CVE-2024-21182.json",
    "cisa_adp_affected": "cves/2024/42xxx/CVE-2024-42022.json",
    "siemens_sadp": "cves/2022/23xxx/CVE-2022-23303.json",
    "cna_ssvc_not_consumed": "cves/2026/102xxx/CVE-2026-102670.json",
    "references_x_tags": "cves/2025/6xxx/CVE-2025-6545.json",
    "cna_linux_kernel": "cves/2021/47xxx/CVE-2021-47658.json",
    "cna_transferred": "cves/2025/57xxx/CVE-2025-57790.json",
    "cna_short_name_before_change": "cves/2022/4xxx/CVE-2022-4685.json",
    "cna_short_name_after_change": "cves/2024/7xxx/CVE-2024-7959.json",
}
"""Record fixture name → repository path of its source file."""

CISA_ADP_ORG_ID = "134c704f-9b21-4f2e-91b3-4a467353bcc0"
"""The CISA-ADP `providerMetadata.orgId` (test-local copy)."""

ADP_IDENTITIES: Mapping[str, str] = {
    "CVE": "af854a3a-2127-422b-91ae-364da2661108",
    "CISA-ADP": CISA_ADP_ORG_ID,
    "siemens-SADP": "0b142b55-0307-4c5a-b3c9-f314f3fb7c5e",
    "redhat-SADP": "0b0ca135-0b70-47e7-9f44-1890c2a1c46c",
}
"""Every ADP `shortName` of the snapshot → its `orgId`."""

ALL_RECORDS: tuple[str, ...] = (*RECORD_SOURCES, *cve_record.CVELISTV5_FIXTURES)
"""Every captured `cvelistV5` record: this module's and the parser's
`cvelistv5_*`."""


def record_path(name: str) -> str:
    """The repository path of a `cvelistV5` record fixture of either module."""
    if name in RECORD_SOURCES:
        return RECORD_SOURCES[name]
    return cve_record.FIXTURE_SOURCES[name]


def load_raw_record(name: str) -> bytes:
    """One `cvelistV5` record fixture's bytes, as a fetcher reads a blob."""
    if name in RECORD_SOURCES:
        return (FIXTURE_DIR / f"{name}.json").read_bytes()
    return cve_record.load_raw_fixture(name)


def load_record(name: str) -> dict[str, Any]:
    """One `cvelistV5` record fixture as parsed JSON."""
    data: dict[str, Any] = json.loads(load_raw_record(name))
    return data


def repository_paths() -> list[str]:
    """The sampled repository paths of `repository_paths.txt`."""
    text = (FIXTURE_DIR / "repository_paths.txt").read_text(encoding="utf-8")
    return text.splitlines()
