"""Parsed dependency-update configuration for tests that read it.

Tests of the Renovate managers and of the release-age cooldown
(`docs/deployment.md`, Workflow Conventions) read `renovate.jsonc` and the
`[tool.uv]` table of `backend/pyproject.toml` through this module.
"""

from __future__ import annotations

import json
import tomllib
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[3]
RENOVATE_CONFIG_PATH = REPO_ROOT / "renovate.jsonc"
PYPROJECT_PATH = REPO_ROOT / "backend" / "pyproject.toml"


def renovate_config() -> dict[str, Any]:
    """`renovate.jsonc` without its comments, which are whole lines."""
    lines = RENOVATE_CONFIG_PATH.read_text(encoding="utf-8").splitlines()
    document = "\n".join(line for line in lines if not line.lstrip().startswith("//"))
    config: dict[str, Any] = json.loads(document)
    return config


def backend_uv_settings() -> dict[str, Any]:
    """The `[tool.uv]` table of `backend/pyproject.toml`."""
    pyproject = tomllib.loads(PYPROJECT_PATH.read_text(encoding="utf-8"))
    settings: dict[str, Any] = pyproject["tool"]["uv"]
    return settings


def backend_cooldown() -> str:
    """The release-age cooldown of the backend project (`exclude-newer`)."""
    cooldown: str = backend_uv_settings()["exclude-newer"]
    return cooldown
