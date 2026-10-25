"""Regression tests for the tool pins that Renovate tracks in the workflows.

`docs/deployment.md` (Workflow Conventions) requires every tool version a
workflow pins to be tracked by Renovate, and lists the forms that the
`renovate.jsonc` custom managers match. These tests keep the images of the
shell lint, the `uvx` tools, and the Swagger UI assets in those forms with
exact versions: a pin that leaves its form is silently dropped from
dependency extraction rather than rejected. See issue #1060. The `Shell Lint`
job and the pre-commit hook run the same images, pinned by version and digest,
through `scripts/lint-shell.sh` (issue #1099). Every `uvx` tool, in a
workflow, a script, a Git hook, or the `Makefile`, runs on the project's
Python version (issue #1103). The Swagger UI of the API's `/api/docs` page
shares the GitHub Pages site's pin, and the site enables the operation filter
(issue #1070).

The workflows are parsed as YAML (`tests/support/yaml_files.py`); only the
`Makefile`, the scripts and the Git hooks, and the `/api/docs` page module are
read as text.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

from app.api.interactive_docs import SWAGGER_UI_DIST
from tests.support.yaml_files import (
    job_steps,
    load_yaml_file,
    named_step,
    string_values,
    workflow_jobs,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS_DIR = REPO_ROOT / ".github" / "workflows"
CI_PATH = WORKFLOWS_DIR / "ci.yml"
DEPLOY_API_DOCS_PATH = WORKFLOWS_DIR / "deploy-api-docs.yml"
MAKEFILE_PATH = REPO_ROOT / "Makefile"
INTERACTIVE_DOCS_PATH = REPO_ROOT / "backend" / "app" / "api" / "interactive_docs.py"
RENOVATE_CONFIG_PATH = REPO_ROOT / "renovate.jsonc"
LINT_SHELL_RELATIVE = "scripts/lint-shell.sh"
LINT_SHELL_PATH = REPO_ROOT / LINT_SHELL_RELATIVE
PRE_COMMIT_PATH = REPO_ROOT / ".githooks" / "pre-commit"

EXACT_VERSION = r"\d+\.\d+\.\d+"

# The official image of each tool that scripts/lint-shell.sh runs, by the
# variable that pins it.
SHELL_LINT_IMAGES = {
    "SHELLCHECK_IMAGE": "koalaman/shellcheck",
    "SHFMT_IMAGE": "mvdan/shfmt",
    "ACTIONLINT_IMAGE": "rhysd/actionlint",
}
IMAGE_ASSIGNMENT = re.compile(r"^[A-Z_]+_IMAGE=.*$", re.MULTILINE)
IMAGE_PIN = re.compile(
    r'(?P<name>[A-Z_]+_IMAGE)="(?P<image>[a-z0-9._/-]+)'
    rf":(?P<version>v?{EXACT_VERSION})@(?P<digest>sha256:[0-9a-f]{{64}})\""
)
# The PR Metadata check rejects a pull request title above 71 characters.
PR_TITLE_LIMIT = 71

UVX_INVOCATION = re.compile(r"\buvx\s+\S+")
UVX_PIN = re.compile(
    rf"uvx\s+(?P<package>[A-Za-z0-9][A-Za-z0-9._-]*)@(?P<version>{EXACT_VERSION})"
)
# The end of the text before a uvx invocation that passes a version read at
# run time, such as "$(cat .python-version)", in UV_PYTHON.
UVX_PROJECT_PYTHON = re.compile(r'\bUV_PYTHON="\$[^"]+"\s+$')
UNPKG_URL = re.compile(r"https://unpkg\.com/[^\s\"']+")
SWAGGER_UI_ASSET = re.compile(
    rf"https://unpkg\.com/swagger-ui-dist@(?P<version>{EXACT_VERSION})/(?P<asset>[\w.-]+)"
)


def _renovate_config() -> dict[str, Any]:
    """`renovate.jsonc` without its comments, which are whole lines."""
    lines = RENOVATE_CONFIG_PATH.read_text(encoding="utf-8").splitlines()
    document = "\n".join(line for line in lines if not line.lstrip().startswith("//"))
    config: dict[str, Any] = json.loads(document)
    return config


def _match_strings(manager: dict[str, Any]) -> list[re.Pattern[str]]:
    """The `matchStrings` of a custom manager as Python patterns: Renovate's
    named groups use the JavaScript `(?<name>)` syntax."""
    return [
        re.compile(string.replace("(?<", "(?P<")) for string in manager["matchStrings"]
    ]


def _file_patterns(manager: dict[str, Any]) -> list[re.Pattern[str]]:
    return [re.compile(p.strip("/")) for p in manager["managerFilePatterns"]]


def _shell_lint_pins() -> list[re.Match[str]]:
    """The image pin of every `*_IMAGE=` assignment of the shell lint script;
    an assignment that is not `<image>:<exact version>@<digest>` fails."""
    assignments = IMAGE_ASSIGNMENT.findall(LINT_SHELL_PATH.read_text(encoding="utf-8"))
    pins = [IMAGE_PIN.fullmatch(assignment) for assignment in assignments]
    assert all(pins), assignments
    return [pin for pin in pins if pin]


def _workflow_files() -> list[Path]:
    return sorted({*WORKFLOWS_DIR.glob("*.yml"), *WORKFLOWS_DIR.glob("*.yaml")})


def _uvx_sources() -> dict[str, list[str]]:
    """The lines of every file that can run a uvx tool, by path relative to
    the repository root, without comment lines: the string values of the
    workflows, and the scripts, the Git hooks, and the Makefile."""
    sources = {
        path.relative_to(REPO_ROOT).as_posix(): [
            line
            for value in string_values(load_yaml_file(path))
            for line in value.splitlines()
        ]
        for path in _workflow_files()
    }
    for path in [
        *sorted((REPO_ROOT / "scripts").glob("*.sh")),
        *sorted(path for path in (REPO_ROOT / ".githooks").iterdir() if path.is_file()),
        MAKEFILE_PATH,
    ]:
        relative = path.relative_to(REPO_ROOT).as_posix()
        sources[relative] = path.read_text(encoding="utf-8").splitlines()
    return {
        relative: [line for line in lines if not line.lstrip().startswith("#")]
        for relative, lines in sources.items()
    }


def _uvx_pins(text: str) -> list[tuple[str, str]]:
    """The (package, version) pin of every `uvx` invocation in `text`; an
    invocation that is not `uvx <package>@<exact version>` fails."""
    pins: list[tuple[str, str]] = []
    for invocation in UVX_INVOCATION.findall(text):
        match = UVX_PIN.fullmatch(invocation)
        assert match, f"{invocation!r} is not uvx <package>@<exact version>"
        pins.append((match["package"], match["version"]))
    return pins


@pytest.mark.unit
def test_shell_lint_images_are_pinned_by_exact_version_and_digest() -> None:
    # The digest fixes the content that CI and the pre-commit hook run; the
    # version names it for Renovate and for the reader.
    pins = _shell_lint_pins()

    assert {pin["name"]: pin["image"] for pin in pins} == SHELL_LINT_IMAGES


@pytest.mark.unit
def test_shell_lint_manager_extracts_every_image_with_its_digest() -> None:
    manager = next(
        manager
        for manager in _renovate_config()["customManagers"]
        if any(p.search(LINT_SHELL_RELATIVE) for p in _file_patterns(manager))
    )
    script = LINT_SHELL_PATH.read_text(encoding="utf-8")
    extracted = {
        (match["depName"], match["currentValue"], match["currentDigest"])
        for pattern in _match_strings(manager)
        for match in pattern.finditer(script)
    }

    assert manager["datasourceTemplate"] == "docker"
    assert extracted == {
        (pin["image"], pin["version"], pin["digest"]) for pin in _shell_lint_pins()
    }


@pytest.mark.unit
def test_shell_lint_image_updates_use_the_ci_prefix_within_the_title_limit() -> None:
    # The images run only in CI and in the developer's local checks, so their
    # updates carry no release signal. The longest title Renovate gives them,
    # in the form of its digest updates ("<prefix> Update python:3.14-slim
    # Docker digest to 35caba8"), must pass the PR Metadata check.
    rules = [
        rule
        for rule in _renovate_config()["packageRules"]
        if LINT_SHELL_RELATIVE in rule.get("matchFileNames", [])
    ]

    assert [rule.get("commitMessagePrefix") for rule in rules] == ["ci(deps):"]
    for pin in _shell_lint_pins():
        title = (
            f"ci(deps): Update {pin['image']}:{pin['version']} "
            f"Docker digest to {pin['digest'].removeprefix('sha256:')[:7]}"
        )
        assert len(title) <= PR_TITLE_LIMIT, title


@pytest.mark.unit
def test_shell_lint_job_and_pre_commit_hook_run_the_script() -> None:
    # The job and the hook run the same pinned images only while both lint
    # through the script, and the job installs no tool of its own.
    job = workflow_jobs(load_yaml_file(CI_PATH))["shell-lint"]
    hook = PRE_COMMIT_PATH.read_text(encoding="utf-8")

    assert "env" not in job
    assert [step["run"] for step in job_steps(job) if "run" in step] == [
        LINT_SHELL_RELATIVE
    ]
    assert re.search(
        rf"^{re.escape(LINT_SHELL_RELATIVE)} --staged$", hook, re.MULTILINE
    )


@pytest.mark.unit
def test_uvx_tools_are_pinned_exactly() -> None:
    # A bare `uvx <package>` resolves to the latest release and escapes
    # tracking.
    packages = {
        package
        for lines in _uvx_sources().values()
        for package, _ in _uvx_pins("\n".join(lines))
    }

    assert packages >= {"bandit", "pip-audit"}


@pytest.mark.unit
def test_uvx_manager_extracts_every_uvx_pin() -> None:
    # A pin in a file that the manager does not read is silently dropped from
    # dependency extraction rather than rejected.
    manager = next(
        manager
        for manager in _renovate_config()["customManagers"]
        if manager.get("datasourceTemplate") == "pypi"
    )
    for relative, lines in _uvx_sources().items():
        pins = set(_uvx_pins("\n".join(lines)))
        if not pins:
            continue
        text = (REPO_ROOT / relative).read_text(encoding="utf-8")
        extracted = {
            (match["depName"], match["currentValue"])
            for pattern in _match_strings(manager)
            for match in pattern.finditer(text)
        }

        assert any(p.search(relative) for p in _file_patterns(manager)), relative
        assert extracted == pins, relative


@pytest.mark.unit
def test_uvx_tools_run_on_the_project_python() -> None:
    # A tool run through uvx gets the first interpreter that uv finds, not the
    # one of backend/.python-version, so every invocation passes a version
    # read at run time in UV_PYTHON, never a literal (docs/conventions.md,
    # Runtime Version; issue #1103). That the value is the file's is tested
    # for each caller: tests/test_bandit_scan_script.py and
    # tests/test_ci_workflow.py.
    without_project_python = [
        f"{relative}: {line.strip()}"
        for relative, lines in _uvx_sources().items()
        for line in lines
        for invocation in UVX_INVOCATION.finditer(line)
        if not UVX_PROJECT_PYTHON.search(line[: invocation.start()])
    ]

    assert without_project_python == []


@pytest.mark.unit
def test_swagger_ui_assets_share_one_exact_unpkg_version() -> None:
    jobs = workflow_jobs(load_yaml_file(DEPLOY_API_DOCS_PATH))
    site_script = named_step(jobs["build"], "Build Swagger UI static site")["run"]
    urls = UNPKG_URL.findall(site_script)
    assets = [SWAGGER_UI_ASSET.fullmatch(url) for url in urls]

    assert all(assets), urls
    assert sorted(asset["asset"] for asset in assets if asset) == [
        "swagger-ui-bundle.js",
        "swagger-ui.css",
    ]
    assert len({asset["version"] for asset in assets if asset}) == 1


@pytest.mark.unit
def test_pages_site_enables_the_operation_filter() -> None:
    jobs = workflow_jobs(load_yaml_file(DEPLOY_API_DOCS_PATH))
    site_script = named_step(jobs["build"], "Build Swagger UI static site")["run"]

    assert "filter: true," in site_script


@pytest.mark.unit
def test_unpkg_manager_extracts_both_swagger_ui_copies_on_one_version() -> None:
    # Renovate updates the GitHub Pages site and the API's /api/docs page in
    # one PR only while its unpkg manager extracts both as the same
    # dependency, and the page loads only the literal it extracts.
    manager = next(
        manager
        for manager in _renovate_config()["customManagers"]
        if manager.get("datasourceTemplate") == "npm"
    )
    file_patterns = _file_patterns(manager)
    match_strings = _match_strings(manager)
    api_version = re.fullmatch(
        rf"https://unpkg\.com/swagger-ui-dist@(?P<version>{EXACT_VERSION})/",
        SWAGGER_UI_DIST,
    )
    assert api_version, SWAGGER_UI_DIST

    for path in (DEPLOY_API_DOCS_PATH, INTERACTIVE_DOCS_PATH):
        relative = path.relative_to(REPO_ROOT).as_posix()
        text = path.read_text(encoding="utf-8")
        extracted = {
            (match["depName"], match["currentValue"])
            for pattern in match_strings
            for match in pattern.finditer(text)
        }

        assert any(pattern.search(relative) for pattern in file_patterns), relative
        assert extracted == {("swagger-ui-dist", api_version["version"])}, relative
    assert UNPKG_URL.findall(INTERACTIVE_DOCS_PATH.read_text(encoding="utf-8")) == [
        SWAGGER_UI_DIST
    ]
