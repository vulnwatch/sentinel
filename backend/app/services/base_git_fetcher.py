"""BaseGitFetcher: template-method base class of the Git CVE fetchers.

Implements docs/features/platform/git-fetcher-infrastructure.md (BaseGitFetcher
Class: Class Attributes; Template Method: `execute()`; Hook Methods; Default
`fetch_single()` Implementation; Inherited Utility Methods;
`_compute_recovery_delta()`), on the First-Run Detection, Recovery, Cursor SHA
Unreachable, and Error Classification contracts of the same document.

`execute()` keeps a bare clone of `repo_url` under `GIT_CLONE_BASE_DIR`,
records the HEAD commit on the first run, and afterwards processes the files
added or modified since the stored cursor commit, one per-CVE transaction
each, finalized by `BaseCVEFetcher.commit_and_dispatch()` outside the per-item
catch. Concrete subclasses declare the configurable attributes and implement
`process_item()` and `_construct_candidate_paths()`; they never override
`execute()` (a structural test enforces it, since this class defines no
`__init_subclass__` of its own and registration validation flows through
`BaseCVEFetcher`).

Git failures never leave this class as git exceptions: clone and fetch
failures, corruption (after deleting the clone), and deletion failures become
`FetcherError` with a fixed public message and the triggering exception
chained, so git's stderr reaches only `error_detail`. A run that fetched ends
with the clone's maintenance (step 12), which starts only when it can end
before the soft time limit and whose failure is a WARNING that leaves the run
outcome unchanged. Every log event is bounded: no stderr, URL, stored cursor
value, or upstream path, and a `cve_id` only when it is a canonical CVE-ID.

`git_operations` and `config` are dereferenced at call time so tests can
substitute a function or the clone base directory.
"""

from __future__ import annotations

import time
from asyncio import CancelledError
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, ClassVar, Final, NamedTuple

import structlog
from celery.exceptions import SoftTimeLimitExceeded
from sqlalchemy.ext.asyncio import AsyncSession

from app import config
from app.core.enums import CVESourceFetchStatus
from app.services import git_operations
from app.services.base_cve_fetcher import (
    CVE_FETCH_ITEM_FAILED_EVENT,
    BaseCVEFetcher,
    CVEFetchResult,
    CVENotInSource,
)
from app.services.base_fetcher import FetcherError
from app.services.fetcher_schedule import effective_task_time_limits
from app.services.git_operations import (
    GitCorruptionError,
    GitFetchError,
    GitFileError,
    GitMaintenanceError,
)

logger = structlog.get_logger(__name__)

CLONE_FAILED_MESSAGE: Final = "External git repository unreachable — clone failed"
FETCH_FAILED_MESSAGE: Final = "External git repository unreachable — fetch failed"
CORRUPTION_MESSAGE: Final = (
    "Local git clone was damaged and has been removed — "
    "it will be re-cloned on the next run"
)
DELETE_FAILED_MESSAGE: Final = (
    "Local git clone directory could not be removed — manual intervention required"
)
DELETE_FAILED_GUIDANCE: Final = (
    "Manual intervention required — check filesystem permissions and mount state"
)
CLONE_UNAVAILABLE_MESSAGE: Final = "Git clone not available for single-item lookup"
ALL_CANDIDATES_FAILED_MESSAGE: Final = "File read failed for all candidate paths"

CLONE_INVALID_REBUILDING_EVENT: Final = "git_clone_invalid_rebuilding"
CLONE_CORRUPTION_DETECTED_EVENT: Final = "git_clone_corruption_detected"
CLONE_DELETE_FAILED_EVENT: Final = "git_clone_delete_failed"
CURSOR_MALFORMED_EVENT: Final = "git_cursor_malformed"
CURSOR_SHA_UNREACHABLE_EVENT: Final = "git_cursor_sha_unreachable"
CURSOR_COMMITTED_AT_UNUSABLE_EVENT: Final = "git_cursor_committed_at_unusable"
RECOVERY_BOUNDARY_NOT_FOUND_EVENT: Final = "git_recovery_boundary_not_found"
DELTA_FILE_MISSING_AT_HEAD_EVENT: Final = "git_delta_file_missing_at_head"
ITEM_ID_MALFORMED_EVENT: Final = "git_fetch_single_item_id_malformed"
CANDIDATE_READ_FAILED_EVENT: Final = "git_fetch_single_candidate_read_failed"
MAINTENANCE_COMPLETED_EVENT: Final = "git_clone_maintenance_completed"
MAINTENANCE_FAILED_EVENT: Final = "git_clone_maintenance_failed"
MAINTENANCE_SKIPPED_EVENT: Final = "git_clone_maintenance_skipped"

# Seconds kept free, besides the maintenance timeout, between the start of
# the maintenance and the run's soft time limit (step 12): the time before
# `execute()` starts, the termination grace of a timed-out git process, and
# the remaining steps of the run.
MAINTENANCE_START_MARGIN_SECONDS: Final = 60

_RECOVERY_MARGIN: Final = timedelta(days=1)


class _Prepared(NamedTuple):
    """Result of steps 3-7: HEAD, its date, the delta to process (`None` on
    the first-run branch), and whether step 4b fetched."""

    head_sha: str
    head_date: str
    delta: list[str] | None
    fetched: bool


def is_single_path_component(name: object) -> bool:
    """Whether `name` is one non-empty path component: no separator,
    U+0000, `.`, or `..`. Used for `clone_dir_name`."""
    return (
        isinstance(name, str)
        and name not in ("", ".", "..")
        and "/" not in name
        and "\x00" not in name
    )


def recovery_before_date(committed_at: object) -> str | None:
    """The recovery boundary `committed_at - 1 day` as an ISO 8601 UTC
    instant truncated to whole seconds, or `None` when the stored value is
    not usable (not a string, not ISO 8601 with an explicit offset, or not
    movable back by one day)."""
    if not isinstance(committed_at, str):
        return None
    try:
        instant = datetime.fromisoformat(committed_at)
    except ValueError:
        return None
    if instant.tzinfo is None:
        return None
    try:
        boundary = instant.astimezone(UTC) - _RECOVERY_MARGIN
    except OverflowError:
        return None
    return boundary.isoformat(timespec="seconds")


class BaseGitFetcher(BaseCVEFetcher):
    """Intermediate abstract base class of the delta-based Git CVE fetchers.

    Configurable attributes without a default (`repo_url`, `clone_dir_name`,
    `recovery_path_prefix`, `delta_path_prefix`) are only annotated here and
    must be declared by every concrete subclass. `queue` is fixed to `"git"`.
    """

    abstract: ClassVar[bool] = True
    queue: ClassVar[str | None] = "git"

    repo_url: ClassVar[str]
    clone_dir_name: ClassVar[str]
    recovery_path_prefix: ClassVar[str]
    delta_path_prefix: ClassVar[str]
    clone_filter: ClassVar[str | None] = None
    clone_single_branch: ClassVar[bool] = True

    # -- Template method -------------------------------------------------

    async def execute(self, session: AsyncSession) -> None:
        """Run the delta-based Git flow (template steps 1-12)."""
        started = time.monotonic()
        repo_path = self._repo_path()
        cursor_sha = self._get_last_cursor_sha()
        if cursor_sha is None and self.previous_cursor is not None:
            logger.error(CURSOR_MALFORMED_EVENT, fetcher_name=self.name)

        try:
            prepared = await self._prepare(repo_path, cursor_sha)
        except GitCorruptionError as exc:
            logger.warning(
                CLONE_CORRUPTION_DETECTED_EVENT,
                fetcher_name=self.name,
                cause=type(exc).__name__,
            )
            await self._delete_or_fail(repo_path)
            raise FetcherError(CORRUPTION_MESSAGE) from exc

        if prepared.delta is not None:
            selected = self.deduplicate_items(self.filter_delta_files(prepared.delta))
            for path in selected:
                await self._process_delta_path(repo_path, path, session)

        self._cursor = {"sha": prepared.head_sha, "committed_at": prepared.head_date}

        if prepared.fetched:
            await self._maintain_within_budget(repo_path, started)

    async def _prepare(self, repo_path: Path, cursor_sha: str | None) -> _Prepared:
        """Steps 3-7: clone state, HEAD, and the delta to process (`None`
        on the first-run branch, which records HEAD without processing)."""
        clone_valid = await self._is_clone_valid(repo_path)
        if cursor_sha is None:
            if not clone_valid:
                await self._delete_or_fail(repo_path)
                await self._clone_or_fail(repo_path)
            head_sha = await self._get_head_sha(repo_path)
            head_date = await self._get_commit_date(repo_path, "HEAD")
            return _Prepared(head_sha, head_date, None, fetched=False)

        fetched = clone_valid
        if clone_valid:
            try:
                await self._fetch_origin(repo_path)
            except GitFetchError as exc:
                raise FetcherError(FETCH_FAILED_MESSAGE) from exc
        else:
            logger.warning(CLONE_INVALID_REBUILDING_EVENT, fetcher_name=self.name)
            await self._delete_or_fail(repo_path)
            await self._clone_or_fail(repo_path)

        head_sha = await self._get_head_sha(repo_path)
        head_date = await self._get_commit_date(repo_path, "HEAD")

        if await self._check_sha_reachable(repo_path, cursor_sha):
            delta = await self._compute_delta(repo_path, cursor_sha, head_sha)
            return _Prepared(head_sha, head_date, delta, fetched)

        committed_at = self._get_last_cursor_committed_at()
        if committed_at is None or recovery_before_date(committed_at) is None:
            stored = self._stored_cursor_field("committed_at")
            logger.error(
                CURSOR_COMMITTED_AT_UNUSABLE_EVENT,
                fetcher_name=self.name,
                reason="absent" if stored is None else "invalid",
            )
            return _Prepared(head_sha, head_date, [], fetched)

        logger.warning(CURSOR_SHA_UNREACHABLE_EVENT, fetcher_name=self.name)
        delta = await self._compute_recovery_delta(repo_path, head_sha, committed_at)
        return _Prepared(head_sha, head_date, delta, fetched)

    async def _maintain_within_budget(self, repo_path: Path, started: float) -> None:
        """Step 12: maintain the clone when the maintenance can end before
        the run's soft time limit, else skip it until the next run. A
        maintenance failure is a WARNING; whole-run signals propagate."""
        if self.config is not None:
            soft_limit = effective_task_time_limits(
                self.config.hard_time_limit_seconds
            )["soft_time_limit"]
            remaining = soft_limit - (time.monotonic() - started)
            required = (
                git_operations.MAINTENANCE_TIMEOUT_SECONDS
                + MAINTENANCE_START_MARGIN_SECONDS
            )
            if remaining < required:
                logger.warning(
                    MAINTENANCE_SKIPPED_EVENT,
                    fetcher_name=self.name,
                    remaining_seconds=int(remaining),
                    required_seconds=int(required),
                )
                return
        maintenance_started = time.monotonic()
        try:
            await self._maintain_clone(repo_path)
        except GitMaintenanceError as exc:
            logger.warning(
                MAINTENANCE_FAILED_EVENT, fetcher_name=self.name, reason=exc.reason
            )
            return
        logger.info(
            MAINTENANCE_COMPLETED_EVENT,
            fetcher_name=self.name,
            duration_seconds=round(time.monotonic() - maintenance_started, 1),
        )

    async def _process_delta_path(
        self, repo_path: Path, path: str, session: AsyncSession
    ) -> None:
        """Step 10 for one selected path: one per-CVE transaction."""
        result: CVEFetchResult | None
        try:
            content = await self._show_file(repo_path, "HEAD", path)
            if content is None:
                result = None
            else:
                result = await self.process_item(path, content, session)
                if not isinstance(result, CVEFetchResult):
                    raise TypeError("process_item() must return CVEFetchResult")
                await session.flush()
        except CancelledError, SoftTimeLimitExceeded, MemoryError:
            raise  # whole-run signals — never caught per item
        except Exception as exc:
            await session.rollback()
            cve_id = self._extract_item_id(path)
            if self._is_valid_cve_id(cve_id):
                await self._isolated_status_commit(cve_id, CVESourceFetchStatus.FAILURE)
            logger.warning(
                CVE_FETCH_ITEM_FAILED_EVENT,
                **self._cve_id_field(cve_id),
                fetcher_name=self.name,
                cause=type(exc).__name__,
            )
            self.record_failed()
            return

        if result is None:
            logger.warning(
                DELTA_FILE_MISSING_AT_HEAD_EVENT,
                fetcher_name=self.name,
                **self._cve_id_field(self._extract_item_id(path)),
            )
            self.record_succeeded()
            return

        # Finalization stays outside the pre-commit per-item catch.
        await self.commit_and_dispatch(session, result)

    async def _clone_or_fail(self, repo_path: Path) -> None:
        try:
            await self._clone_repo(repo_path)
        except GitFetchError as exc:
            raise FetcherError(CLONE_FAILED_MESSAGE) from exc

    async def _delete_or_fail(self, repo_path: Path) -> None:
        try:
            await self._delete_if_exists(repo_path)
        except OSError as exc:
            logger.error(
                CLONE_DELETE_FAILED_EVENT,
                fetcher_name=self.name,
                repo_path=str(repo_path),
                errno=exc.errno,
                guidance=DELETE_FAILED_GUIDANCE,
            )
            raise FetcherError(DELETE_FAILED_MESSAGE) from exc

    def _cve_id_field(self, cve_id: str) -> dict[str, str]:
        """`{"cve_id": cve_id}` for a canonical CVE-ID, else nothing."""
        return {"cve_id": cve_id} if self._is_valid_cve_id(cve_id) else {}

    # -- Hooks -----------------------------------------------------------

    async def process_item(
        self, path: str, content: bytes, session: AsyncSession
    ) -> CVEFetchResult:
        """Process one delta file in `session`; required on subclasses.

        Returns the `CVEFetchResult` of the item's ingestion. Records no
        `FetcherRun` metric and never commits; any exception is a per-item
        failure of the template.
        """
        raise NotImplementedError(
            f"{type(self).__name__} must implement process_item()"
        )

    def filter_delta_files(self, file_list: list[str]) -> list[str]:
        """Keep the delta files to process. Default: all of them."""
        return file_list

    def deduplicate_items(self, file_list: list[str]) -> list[str]:
        """Resolve paths that represent the same item. Default: unchanged."""
        return file_list

    def _construct_candidate_paths(self, item_id: str) -> list[str]:
        """Ordered candidate paths of `item_id`; required on subclasses.

        Raises `ValueError` when `item_id` does not match this source's
        format.
        """
        raise NotImplementedError(
            f"{type(self).__name__} must implement _construct_candidate_paths()"
        )

    # -- Single-item fetch -----------------------------------------------

    async def fetch_single(self, cve_id: str, session: AsyncSession) -> CVEFetchResult:
        """Look one CVE up in the local clone and process it.

        Reads only (no fetch, clone, or deletion), records no metric, and
        never calls `record_failed()`. Raises `RuntimeError` when the clone
        is unavailable or every candidate read failed, and `CVENotInSource`
        when no candidate exists or `cve_id` is malformed for this source.
        Exceptions of `process_item()` and other hook exceptions propagate.
        """
        repo_path = self._repo_path()
        if not await self._is_clone_valid(repo_path):
            raise RuntimeError(CLONE_UNAVAILABLE_MESSAGE)
        try:
            candidates = self._construct_candidate_paths(cve_id)
        except ValueError:
            logger.error(
                ITEM_ID_MALFORMED_EVENT,
                fetcher_name=self.name,
                **self._cve_id_field(cve_id),
            )
            raise CVENotInSource() from None

        read_failure: GitFileError | None = None
        for path in candidates:
            try:
                content = await self._show_file(repo_path, "HEAD", path)
            except GitFileError as exc:
                logger.warning(
                    CANDIDATE_READ_FAILED_EVENT,
                    fetcher_name=self.name,
                    **self._cve_id_field(cve_id),
                    cause=type(exc).__name__,
                )
                read_failure = exc
                continue
            if content is not None:
                return await self.process_item(path, content, session)

        if read_failure is not None:
            raise RuntimeError(ALL_CANDIDATES_FAILED_MESSAGE) from read_failure
        raise CVENotInSource()

    # -- Inherited utility methods -----------------------------------------

    def _stored_cursor_field(self, key: str) -> Any:
        cursor = self.previous_cursor
        return cursor.get(key) if isinstance(cursor, dict) else None

    def _get_last_cursor_sha(self) -> str | None:
        sha = self._stored_cursor_field("sha")
        return sha if isinstance(sha, str) else None

    def _get_last_cursor_committed_at(self) -> str | None:
        committed_at = self._stored_cursor_field("committed_at")
        return committed_at if isinstance(committed_at, str) else None

    def _repo_path(self) -> Path:
        """`GIT_CLONE_BASE_DIR / clone_dir_name`; `ValueError` before any
        git or filesystem operation for a name that is not one component."""
        if not is_single_path_component(self.clone_dir_name):
            raise ValueError("clone_dir_name must be a single path component")
        return Path(config.settings.git_clone_base_dir) / self.clone_dir_name

    def _extract_item_id(self, path: str) -> str:
        return Path(path).stem

    async def _clone_repo(self, path: Path) -> None:
        await git_operations.clone(
            self.repo_url,
            path,
            filter_spec=self.clone_filter,
            single_branch=self.clone_single_branch,
        )

    async def _fetch_origin(self, path: Path) -> None:
        await git_operations.fetch_origin(path)

    async def _get_head_sha(self, path: Path) -> str:
        return await git_operations.get_head_sha(path)

    async def _get_commit_date(self, path: Path, ref: str) -> str:
        return await git_operations.get_commit_date(path, ref)

    async def _is_clone_valid(self, path: Path) -> bool:
        return await git_operations.is_clone_valid(path)

    async def _check_sha_reachable(self, path: Path, sha: str) -> bool:
        return await git_operations.check_sha_reachable(path, sha)

    async def _compute_delta(self, path: Path, from_sha: str, to_sha: str) -> list[str]:
        return await git_operations.diff_names(
            path, from_sha, to_sha, path_filter=self.delta_path_prefix
        )

    async def _compute_recovery_delta(
        self, repo_path: Path, head_sha: str, cursor_committed_at: str
    ) -> list[str]:
        """The delta from the last commit before `cursor_committed_at - 1
        day`, restricted to `recovery_path_prefix`; empty when no such
        commit exists. `ValueError` for an unusable `cursor_committed_at`."""
        before_date = recovery_before_date(cursor_committed_at)
        if before_date is None:
            raise ValueError("cursor_committed_at is not a usable recovery boundary")
        boundary_sha = await git_operations.rev_list_before(repo_path, before_date)
        if boundary_sha is None:
            logger.warning(RECOVERY_BOUNDARY_NOT_FOUND_EVENT, fetcher_name=self.name)
            return []
        return await git_operations.diff_names(
            repo_path, boundary_sha, head_sha, path_filter=self.recovery_path_prefix
        )

    async def _show_file(self, path: Path, ref: str, file_path: str) -> bytes | None:
        return await git_operations.show_file(path, ref, file_path)

    async def _maintain_clone(self, path: Path) -> None:
        await git_operations.maintain(path)

    async def _delete_if_exists(self, path: Path) -> None:
        await git_operations.delete_clone(path)
