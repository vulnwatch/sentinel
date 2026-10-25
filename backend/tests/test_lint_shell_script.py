"""Behavioral tests for the shell lint (`scripts/lint-shell.sh`).

The `Shell Lint` job of `ci.yml` and the pre-commit hook lint through this
script, which runs shellcheck, shfmt, and actionlint from images pinned by
version and digest (`docs/conventions.md`, Shell Scripting, Enforcement;
issue #1099). Each test copies the script into a throwaway Git repository in
a temporary directory (never this repository), so that it selects that
repository's files, and puts first on `PATH` a stubbed `docker` that records
each call and answers as the test requires.

The Git hooks run this file inside a real commit, so every Git and script
subprocess receives the hermetic environment of `tests/support/git_repos.py`
(see `docs/features/platform/testing-strategy.md`, Tier 1 — Unit Tests).
"""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

from tests.support.git_repos import commit_files, git, hermetic_git_env, init_upstream

SCRIPT_PATH = Path(__file__).resolve().parents[2] / "scripts" / "lint-shell.sh"

IMAGES = dict(
    re.findall(
        r'^([A-Z]+)_IMAGE="([^"]+)"$',
        SCRIPT_PATH.read_text(encoding="utf-8"),
        re.MULTILINE,
    )
)
SHELLCHECK = IMAGES["SHELLCHECK"]
SHFMT = IMAGES["SHFMT"]
ACTIONLINT = IMAGES["ACTIONLINT"]

# Records each call, one argument per tab-separated field, and answers with
# the exit codes that the DOCKER_STUB_* variables select: a run fails when
# its arguments name the image DOCKER_STUB_FAIL_IMAGE.
DOCKER_STUB = """\
#!/usr/bin/env bash
set -euo pipefail
(IFS=$'\\t'; printf '%s\\n' "$*") >> "${DOCKER_STUB_LOG}"
case "$1" in
    version) exit "${DOCKER_STUB_VERSION_EXIT:-0}" ;;
    image) exit "${DOCKER_STUB_INSPECT_EXIT:-0}" ;;
    pull) exit "${DOCKER_STUB_PULL_EXIT:-0}" ;;
    run)
        for argument in "$@"; do
            if [[ "${argument}" == "${DOCKER_STUB_FAIL_IMAGE:-}" ]]; then
                exit 1
            fi
        done
        exit 0
        ;;
esac
exit 64
"""

# The programs that the script runs besides docker, for a PATH without it.
HOST_PROGRAMS = ("bash", "dirname", "git", "id", "sort")

TRACKED_FILES = {
    ".githooks/pre-commit": b"#!/usr/bin/env bash\n",
    ".github/workflows/ci.yml": b"name: CI\n",
    ".github/workflows/release.yaml": b"name: Release\n",
    ".github/workflows/templates/partial.yml": b"name: Partial\n",
    "README.md": b"# Example\n",
    "scripts/build.sh": b"#!/usr/bin/env bash\n",
    "scripts/notes.txt": b"notes\n",
    "tools/nested/helper.sh": b"#!/usr/bin/env bash\n",
}
TRACKED_SHELL_FILES = [
    ".githooks/pre-commit",
    "scripts/build.sh",
    "scripts/lint-shell.sh",
    "tools/nested/helper.sh",
]
TRACKED_WORKFLOWS = [".github/workflows/ci.yml", ".github/workflows/release.yaml"]


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A committed repository holding the script and `TRACKED_FILES`."""
    repo = init_upstream(tmp_path / "repo")
    (repo / "scripts").mkdir()
    shutil.copy2(SCRIPT_PATH, repo / "scripts" / "lint-shell.sh")
    commit_files(repo, TRACKED_FILES)
    return repo


def _bin_dir(directory: Path, *, docker: bool) -> Path:
    """A directory for `PATH` with the stubbed docker, or, without docker,
    links to `HOST_PROGRAMS` only."""
    directory.mkdir()
    if docker:
        stub = directory / "docker"
        stub.write_text(DOCKER_STUB, encoding="utf-8")
        stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
    else:
        for program in HOST_PROGRAMS:
            target = shutil.which(program)
            assert target, program
            (directory / program).symlink_to(target)
    return directory


def _run_lint(
    repo: Path, *arguments: str, docker: bool = True, **stub: str
) -> tuple[subprocess.CompletedProcess[str], list[list[str]]]:
    """Run the repository's copy of the script; return its result and the
    docker calls, each as its list of arguments."""
    bin_dir = _bin_dir(repo.parent / "bin", docker=docker)
    log = repo.parent / "docker.log"
    log.write_text("", encoding="utf-8")
    path = f"{bin_dir}:{os.environ['PATH']}" if docker else str(bin_dir)
    env = hermetic_git_env() | {"PATH": path, "DOCKER_STUB_LOG": str(log)}
    env |= {f"DOCKER_STUB_{name.upper()}": value for name, value in stub.items()}
    result = subprocess.run(
        [str(repo / "scripts" / "lint-shell.sh"), *arguments],
        cwd=repo,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    calls = [line.split("\t") for line in log.read_text(encoding="utf-8").splitlines()]
    return result, calls


def _run_calls(calls: list[list[str]]) -> list[list[str]]:
    return [call for call in calls if call[0] == "run"]


def _run_images(calls: list[list[str]]) -> list[str]:
    """The image of each container run, in order: the argument that follows
    the docker options, the last of which sets the working directory."""
    return [call[call.index("--workdir=/work") + 1] for call in _run_calls(calls)]


def _linted_files(calls: list[list[str]], image: str) -> list[str]:
    """The files of the only run of `image`: its arguments after `--`."""
    (call,) = [call for call in _run_calls(calls) if image in call]
    return call[call.index("--") + 1 :]


def _stage_shell_and_workflow_changes(repo: Path) -> None:
    (repo / "scripts" / "build.sh").write_text("#!/usr/bin/env bash\n# x\n")
    (repo / ".github" / "workflows" / "ci.yml").write_text("name: CI changed\n")
    git(repo, "add", "scripts/build.sh", ".github/workflows/ci.yml")


@pytest.mark.unit
def test_lint_tracked_runs_each_tool_on_the_tracked_files_in_a_hardened_container(
    repo: Path,
) -> None:
    # A new script is linted once it is added to the index, before a commit.
    (repo / "scripts" / "added.sh").write_text("#!/usr/bin/env bash\n")
    git(repo, "add", "scripts/added.sh")
    (repo / "scripts" / "untracked.sh").write_text("#!/usr/bin/env bash\n")
    (repo / ".github" / "workflows" / "untracked.yml").write_text("name: New\n")
    shell_files = sorted([*TRACKED_SHELL_FILES, "scripts/added.sh"])
    container = [
        "run",
        "--rm",
        "--pull=never",
        f"--user={os.getuid()}:{os.getgid()}",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--network=none",
        f"--volume={repo}:/work:ro",
        "--workdir=/work",
    ]

    result, calls = _run_lint(repo)

    assert result.returncode == 0, result.stderr
    assert calls == [
        ["version", "--format", "{{.Server.Version}}"],
        ["image", "inspect", SHELLCHECK],
        ["image", "inspect", SHFMT],
        ["image", "inspect", ACTIONLINT],
        [*container, SHELLCHECK, "--", *shell_files],
        [*container, SHFMT, "-i", "4", "-ci", "-d", "--", *shell_files],
        [*container, ACTIONLINT, "--", *TRACKED_WORKFLOWS],
    ]


@pytest.mark.unit
def test_lint_staged_selects_the_added_modified_and_renamed_files(
    repo: Path,
) -> None:
    _stage_shell_and_workflow_changes(repo)
    (repo / "scripts" / "new.sh").write_text("#!/usr/bin/env bash\n")
    git(repo, "add", "scripts/new.sh")
    git(repo, "mv", "tools/nested/helper.sh", "tools/helper.sh")
    git(repo, "rm", "--quiet", ".github/workflows/release.yaml")
    # Neither an unstaged change nor an untracked file is selected.
    (repo / ".githooks" / "pre-commit").write_text("#!/usr/bin/env bash\n# x\n")
    (repo / "scripts" / "untracked.sh").write_text("#!/usr/bin/env bash\n")

    result, calls = _run_lint(repo, "--staged")

    assert result.returncode == 0, result.stderr
    shell_files = ["scripts/build.sh", "scripts/new.sh", "tools/helper.sh"]
    assert _linted_files(calls, SHELLCHECK) == shell_files
    assert _linted_files(calls, SHFMT) == shell_files
    assert _linted_files(calls, ACTIONLINT) == [".github/workflows/ci.yml"]


@pytest.mark.unit
@pytest.mark.parametrize("staged", [[], ["README.md"]], ids=["nothing", "markdown"])
def test_lint_staged_without_shell_files_or_workflows_starts_no_container(
    repo: Path, staged: list[str]
) -> None:
    for path in staged:
        (repo / path).write_text("changed\n")
        git(repo, "add", path)

    result, calls = _run_lint(repo, "--staged")

    assert result.returncode == 0, result.stderr
    assert calls == []


@pytest.mark.unit
def test_lint_downloads_only_the_missing_images_that_the_files_need(
    repo: Path,
) -> None:
    (repo / "scripts" / "build.sh").write_text("#!/usr/bin/env bash\n# x\n")
    git(repo, "add", "scripts/build.sh")

    result, calls = _run_lint(repo, "--staged", inspect_exit="1")

    assert result.returncode == 0, result.stderr
    assert [call for call in calls if call[0] == "pull"] == [
        ["pull", "--quiet", SHELLCHECK],
        ["pull", "--quiet", SHFMT],
    ]
    assert not any(ACTIONLINT in call for call in calls)
    assert _run_images(calls) == [SHELLCHECK, SHFMT]


@pytest.mark.unit
@pytest.mark.parametrize(
    ("docker", "stub", "error"),
    [
        (False, {}, "the docker command is not installed"),
        (True, {"version_exit": "1"}, "the Docker daemon is unreachable"),
        (
            True,
            {"inspect_exit": "1", "pull_exit": "1"},
            f"cannot download {SHELLCHECK}",
        ),
    ],
    ids=["docker-missing", "daemon-unreachable", "download-failed"],
)
@pytest.mark.parametrize(
    ("arguments", "returncode"),
    [(["--staged"], 0), ([], 1)],
    ids=["staged-warns", "tracked-fails"],
)
def test_lint_without_usable_docker_warns_when_staged_and_fails_when_tracked(
    repo: Path,
    docker: bool,
    stub: dict[str, str],
    error: str,
    arguments: list[str],
    returncode: int,
) -> None:
    # The pre-commit hook lets the commit proceed, because CI enforces the
    # lint; the Shell Lint job fails.
    _stage_shell_and_workflow_changes(repo)

    result, calls = _run_lint(repo, *arguments, docker=docker, **stub)

    assert result.returncode == returncode
    assert f"Error: {error}." in result.stderr
    warned = "Warning: Docker cannot run the images of the shell lint" in result.stderr
    assert warned == (returncode == 0)
    assert _run_calls(calls) == []


@pytest.mark.unit
@pytest.mark.parametrize("failing_image", [SHELLCHECK, SHFMT, ACTIONLINT])
@pytest.mark.parametrize("arguments", [["--staged"], []], ids=["staged", "tracked"])
def test_lint_runs_every_tool_and_fails_when_one_reports_a_finding(
    repo: Path, failing_image: str, arguments: list[str]
) -> None:
    # A finding blocks the commit too: only an unusable Docker is tolerated.
    _stage_shell_and_workflow_changes(repo)

    result, calls = _run_lint(repo, *arguments, fail_image=failing_image)

    assert result.returncode == 1
    assert _run_images(calls) == [SHELLCHECK, SHFMT, ACTIONLINT]


@pytest.mark.unit
@pytest.mark.parametrize("arguments", [["--all"], ["--staged", "extra"], ["-h"]])
def test_lint_rejects_unknown_arguments(repo: Path, arguments: list[str]) -> None:
    result, calls = _run_lint(repo, *arguments)

    assert result.returncode == 2
    assert "Usage:" in result.stderr
    assert calls == []
