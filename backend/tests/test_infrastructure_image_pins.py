"""Regression tests for the pins of the PostgreSQL and Redis images.

`docs/deployment.md` (Workflow Conventions, PostgreSQL and Redis images) pins
these images by exact version and digest in the Compose files, in the service
containers of the workflows, and in the testcontainers fixtures, each in a
form that a Renovate manager tracks, and every copy names the same version and
digest, so that development, CI, and the tests run the same servers. A copy
outside those forms is silently absent from Renovate's extraction rather than
rejected, which is how the floating `postgres:18` and `redis:8` tags and a
testcontainers copy that no manager read went unnoticed. A new major version
opens as a draft PR. See issue #1367.

The Compose files and the workflows are parsed as YAML
(`tests/support/yaml_files.py`); the Python test sources are read as text.
"""

from __future__ import annotations

import fnmatch
import re
from pathlib import Path
from typing import Any

import pytest

from tests.support import container_images
from tests.support.dependency_config import renovate_config
from tests.support.renovate_rules import Update, setting
from tests.support.yaml_files import load_yaml_file, workflow_jobs

REPO_ROOT = Path(__file__).resolve().parents[2]
TESTS_ROOT = REPO_ROOT / "backend" / "tests"
WORKFLOWS_DIR = REPO_ROOT / ".github" / "workflows"
CONTAINER_IMAGES_RELATIVE = "backend/tests/support/container_images.py"
CONTAINER_IMAGES_PATH = REPO_ROOT / CONTAINER_IMAGES_RELATIVE

SERVER_IMAGES = ("postgres", "redis")
PIN = re.compile(
    r"(?P<image>[a-z0-9._/-]+):(?P<version>\d+\.\d+(?:\.\d+)?)"
    r"@(?P<digest>sha256:[0-9a-f]{64})"
)
# Every copy of the server images, by location: the Compose service, the
# workflow job and its service container, or the constant of the
# testcontainers fixtures.
LOCATIONS = {
    "docker-compose.yml:postgres",
    "docker-compose.yml:redis",
    "docker-compose.smoke.yml:postgres",
    "docker-compose.smoke.yml:redis",
    ".github/workflows/ci.yml:backend-test:postgres",
    ".github/workflows/ci.yml:backend-test:redis",
    ".github/workflows/python-forward-compat.yml:forward-compat:postgres",
    ".github/workflows/python-forward-compat.yml:forward-compat:redis",
    f"{CONTAINER_IMAGES_RELATIVE}:POSTGRES_IMAGE",
    f"{CONTAINER_IMAGES_RELATIVE}:REDIS_IMAGE",
}
# A testcontainers call that names its image in a string literal, positional
# or as the `image` keyword, rather than through the pinned constants, or that
# names no image and falls back to the floating default of testcontainers
# (`postgres:latest`, `redis:latest`).
UNPINNED_CONTAINER_IMAGE = re.compile(
    r"\b[A-Z]\w*Container\(\s*(?:(?:image\s*=\s*)?[rRbBfFuU]*[\"']|\))"
)


def _image_name(reference: str) -> str:
    """The image of a reference, without its tag and digest."""
    return reference.split("@", 1)[0].rsplit(":", 1)[0]


def _server_images() -> dict[str, str]:
    """Every reference to a server image, by location."""
    references: dict[str, str] = {}
    for path in sorted(REPO_ROOT.glob("docker-compose*.yml")):
        for name, service in load_yaml_file(path)["services"].items():
            image = str(service.get("image", ""))
            if _image_name(image) in SERVER_IMAGES:
                references[f"{path.name}:{name}"] = image
    for path in sorted({*WORKFLOWS_DIR.glob("*.yml"), *WORKFLOWS_DIR.glob("*.yaml")}):
        relative = path.relative_to(REPO_ROOT).as_posix()
        for job_id, job in workflow_jobs(load_yaml_file(path)).items():
            services: dict[str, Any] = job.get("services") or {}
            for name, service in services.items():
                image = str(service.get("image", ""))
                if _image_name(image) in SERVER_IMAGES:
                    references[f"{relative}:{job_id}:{name}"] = image
    for constant in ("POSTGRES_IMAGE", "REDIS_IMAGE"):
        image = getattr(container_images, constant)
        references[f"{CONTAINER_IMAGES_RELATIVE}:{constant}"] = image
    return references


def _pins() -> dict[str, re.Match[str]]:
    """The pin of every reference; a reference that is not
    `<image>:<exact version>@<digest>` fails."""
    references = _server_images()
    pins = {location: PIN.fullmatch(image) for location, image in references.items()}
    assert all(pins.values()), references
    return {location: pin for location, pin in pins.items() if pin}


def _testcontainers_manager() -> dict[str, Any]:
    managers = [
        manager
        for manager in renovate_config()["customManagers"]
        if any(
            fnmatch.fnmatchcase(CONTAINER_IMAGES_RELATIVE, pattern)
            for pattern in manager["managerFilePatterns"]
        )
    ]
    assert len(managers) == 1
    manager: dict[str, Any] = managers[0]
    return manager


@pytest.mark.unit
def test_every_server_image_is_pinned_by_exact_version_and_digest() -> None:
    # The digest fixes the server that the copy runs; the version names it
    # for Renovate and for the reader. The locations are explicit, so that a
    # copy that leaves them, or a new one, is a deliberate change.
    pins = _pins()

    assert set(pins) == LOCATIONS


@pytest.mark.unit
def test_every_copy_of_a_server_image_names_the_same_version_and_digest() -> None:
    by_image: dict[str, set[str]] = {}
    for pin in _pins().values():
        by_image.setdefault(pin["image"], set()).add(pin.group())

    assert set(by_image) == set(SERVER_IMAGES)
    assert all(len(references) == 1 for references in by_image.values()), by_image


@pytest.mark.unit
def test_testcontainers_fixtures_take_their_images_from_the_pinned_constants() -> None:
    # A literal image argument is the form that no manager read in
    # tests/support/redis.py. This module holds the samples of the pattern.
    unpinned = [
        f"{path.relative_to(REPO_ROOT).as_posix()}: {match.group()}"
        for path in sorted(TESTS_ROOT.rglob("*.py"))
        if path != Path(__file__).resolve()
        for match in UNPINNED_CONTAINER_IMAGE.finditer(path.read_text(encoding="utf-8"))
    ]

    assert unpinned == []


@pytest.mark.unit
@pytest.mark.parametrize(
    ("call", "unpinned"),
    [
        ('RedisContainer("redis:8")', True),
        ("PostgresContainer('postgres:18')", True),
        ('RedisContainer(image="redis:8")', True),
        ('PostgresContainer(\n    "postgres:18"\n)', True),
        ("RedisContainer()", True),
        ("RedisContainer(REDIS_IMAGE)", False),
        ("PostgresContainer(image=POSTGRES_IMAGE)", False),
        ("DedicatedRedisContainer(host, port, container)", False),
        ('_container("redis:8")', False),
    ],
)
def test_unpinned_container_image_pattern(call: str, unpinned: bool) -> None:
    # The guard above passes vacuously if its pattern misses a form.
    assert bool(UNPINNED_CONTAINER_IMAGE.search(call)) is unpinned


@pytest.mark.unit
def test_testcontainers_manager_extracts_every_pin_with_its_digest() -> None:
    manager = _testcontainers_manager()
    patterns = [
        re.compile(string.replace("(?<", "(?P<")) for string in manager["matchStrings"]
    ]
    source = CONTAINER_IMAGES_PATH.read_text(encoding="utf-8")
    extracted = {
        (match["depName"], match["currentValue"], match["currentDigest"])
        for pattern in patterns
        for match in pattern.finditer(source)
    }
    pinned = {
        (pin["image"], pin["version"], pin["digest"])
        for location, pin in _pins().items()
        if location.startswith(f"{CONTAINER_IMAGES_RELATIVE}:")
    }

    assert manager["datasourceTemplate"] == "docker"
    assert extracted == pinned
    assert len(pinned) == len(SERVER_IMAGES)


@pytest.mark.unit
def test_testcontainers_pins_are_not_ignored_by_renovate() -> None:
    # The "**/tests/**" pattern of the config:recommended preset excludes a
    # file from every manager without a warning (docs/deployment.md,
    # Testcontainers image references).
    ignored = [
        pattern
        for pattern in renovate_config()["ignorePaths"]
        if fnmatch.fnmatchcase(CONTAINER_IMAGES_RELATIVE, pattern)
    ]

    assert ignored == []


# The managers that track the server images, each with a file that it reads.
SERVER_IMAGE_MANAGERS = [
    ("docker-compose", "docker-compose.yml"),
    ("docker-compose", "docker-compose.smoke.yml"),
    ("github-actions", ".github/workflows/ci.yml"),
    ("custom.regex", CONTAINER_IMAGES_RELATIVE),
]


@pytest.mark.unit
@pytest.mark.parametrize("image", SERVER_IMAGES)
@pytest.mark.parametrize(
    ("manager", "file"), SERVER_IMAGE_MANAGERS, ids=lambda value: value
)
def test_major_updates_of_the_server_images_open_as_drafts(
    image: str, manager: str, file: str
) -> None:
    # A draft announces the major and runs CI on it but cannot be merged by
    # accident; a rebase after every merge would only rerun CI on it.
    major = Update(manager, image, file, "major", datasource="docker")

    assert setting(major, "draftPR") is True
    assert setting(major, "rebaseWhen") == "conflicted"
    # Every copy shares the branch, apart from the redis Python package's.
    assert setting(major, "additionalBranchPrefix") == "docker-"


@pytest.mark.unit
@pytest.mark.parametrize("update_type", ["minor", "patch", "digest"])
@pytest.mark.parametrize("image", SERVER_IMAGES)
def test_other_updates_of_the_server_images_open_as_ordinary_prs(
    image: str, update_type: str
) -> None:
    update = Update(
        "docker-compose", image, "docker-compose.yml", update_type, datasource="docker"
    )

    assert setting(update, "draftPR") is None
    assert setting(update, "rebaseWhen") is None
    assert setting(update, "additionalBranchPrefix") is None


@pytest.mark.unit
def test_major_updates_of_the_redis_python_package_are_not_drafts() -> None:
    # The Python client shares the image's package name.
    update = Update(
        "pep621",
        "redis",
        "backend/pyproject.toml",
        "major",
        "project.dependencies",
        "pypi",
    )

    assert setting(update, "draftPR") is None
    assert setting(update, "rebaseWhen") is None
    assert setting(update, "additionalBranchPrefix") is None
