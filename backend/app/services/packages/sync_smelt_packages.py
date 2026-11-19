"""`sync_smelt_packages`: synchronization of the maintained package names.

Implements docs/features/packages/maintained-package-names.md (Fetcher:
`sync_smelt_packages`). Each run reads the complete SMELT maintained sweep
before any database work, validates every page, and publishes the distinct
`package` values as one snapshot through `publish_maintained_packages()`:

- the snapshot replaces the previous one whole; a name that left SMELT's
  maintained set is removed, a new one is inserted;
- any retrieval, validation, or publication failure publishes nothing and
  leaves the previous snapshot in place; recovery is the next run;
- the publication creates no audit event and dispatches no task.
"""

from __future__ import annotations

import structlog
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.services.base_fetcher import BaseFetcher, FetcherError
from app.services.packages.maintained_package_names import (
    publish_maintained_packages,
)
from app.services.packages.smelt_maintained_sweep import (
    fetch_maintained_package_names,
)

logger = structlog.get_logger(__name__)

PUBLICATION_FAILED_MESSAGE = "Failed to publish SMELT maintained package names"


class SyncSmeltPackages(BaseFetcher):
    """Synchronize the names of the source packages that SMELT maintains."""

    name = "sync_smelt_packages"
    description = "Synchronize the names of the source packages that SMELT maintains"
    default_schedule = "0 0 * * *"

    async def execute(self, session: AsyncSession) -> None:
        # Steps 1-5: all network I/O and validation before any database work.
        request_delay = self.config.request_delay if self.config is not None else 0.0
        names = await fetch_maintained_package_names(
            self.http_client,
            api_url=settings.smelt_api_url,
            request_delay=request_delay,
        )

        # Step 6: one atomic publication in a session without a transaction.
        try:
            publication = await publish_maintained_packages(session, names)
        except SQLAlchemyError as exc:
            logger.warning("smelt_maintained_packages_publication_failed")
            raise FetcherError(PUBLICATION_FAILED_MESSAGE) from exc

        # Terminal outcomes and effects only after the commit (§ Metrics): the
        # work unit is one name of the union of both snapshots.
        selected = publication.created + publication.unchanged + publication.removed
        self.record_succeeded(selected)
        self.record_created(publication.created)
        self.record_updated(publication.removed)
        logger.info(
            "smelt_maintained_packages_published",
            names=len(names),
            created=publication.created,
            removed=publication.removed,
            unchanged=publication.unchanged,
        )
