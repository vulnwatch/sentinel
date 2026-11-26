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
REDIS_IMAGE: Final = "redis:8.10.3@sha256:7671653d5e27b7e1a4cee76b46e63753b36c75b475dc8fcd88d2d31143a258c2"  # noqa: E501
