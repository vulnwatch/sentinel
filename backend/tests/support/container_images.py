"""Images of the servers that the test harness starts with `testcontainers`.

Every testcontainers fixture takes its PostgreSQL or Redis image from this
module, pinned by exact version and digest to the version that the Compose
files and the CI service containers pin (`docs/deployment.md`, Workflow
Conventions, Testcontainers image references). A custom manager of
`renovate.jsonc` reads each pin through the `# renovate: depName=<name>` hint
directly above it. A pin is longer than the line length, and splitting the
string would hide it from that manager.
"""

from __future__ import annotations

from typing import Final

# renovate: depName=postgres
POSTGRES_IMAGE: Final = "postgres:18.6@sha256:e3d24f6906d0760bf4da0dae872415391ededefad23fd471c47dc53b0ddf3c42"  # noqa: E501
# renovate: depName=redis
REDIS_IMAGE: Final = "redis:8.12.0@sha256:56a1737794e36c3ebe8a4544a8ab421af3ab1a6488fb2238aec228c404933fed"  # noqa: E501
