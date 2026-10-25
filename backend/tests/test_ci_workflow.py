"""Regression tests for the Python-version drift check in ci.yml.

The `backend-lint` job's "Verify Dockerfile and pyproject.toml Python
version match .python-version" step fails the build when
`backend/Dockerfile`'s `ARG PYTHON_VERSION` or `backend/pyproject.toml`'s
`requires-python` disagree with `backend/.python-version`
(`docs/conventions.md`, Runtime Version -> Source of Truth). See issue
#69, Acceptance Criteria: "The Python-version drift check fails when
`requires-python` and `.python-version` disagree."

This test extracts the exact shell script from the step and executes it
against fixture files in an isolated temporary directory (never against
this repository's real `backend/` files), verifying both the match and
each mismatch case.

The workflow and `codecov.yml` are parsed as YAML
(`tests/support/yaml_files.py`); only the Renovate hint comment and
whole-file absence checks read the workflow text.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import pytest

from tests.support.dependency_config import backend_cooldown
from tests.support.yaml_files import (
    YamlMapping,
    job_steps,
    load_yaml_file,
    named_step,
    step_index,
    string_values,
    workflow_jobs,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "ci.yml"
RELEASE_WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "build-images.yml"
CODECOV_CONFIG_PATH = REPO_ROOT / "codecov.yml"

DRIFT_CHECK_STEP = (
    "Verify Dockerfile and pyproject.toml Python version match .python-version"
)
BUILD_STEP = "Build backend image (load only, no push)"
SMOKE_STEP = "Image smoke test (blocking gate)"
SBOM_STEP = "Generate and validate release SBOM candidate"
SBOM_UPLOAD_STEP = "Upload release SBOM candidate"
SCOPE_STEP = "Determine dependency audit scope"
AUDIT_STEP = "Run pip-audit (dependency vulnerabilities)"


def _ci_jobs() -> dict[str, YamlMapping]:
    return workflow_jobs(load_yaml_file(WORKFLOW_PATH))


def _uses(step: YamlMapping, action: str) -> bool:
    """Whether `step` uses `action` (`owner/name`) at any reference."""
    return str(step.get("uses", "")).startswith(f"{action}@")


def _drift_check_script() -> str:
    """Extract the shell script executed by the version drift check step."""
    script = named_step(_ci_jobs()["backend-lint"], DRIFT_CHECK_STEP)["run"]
    assert isinstance(script, str)
    return script


def _run_drift_check(
    tmp_path: Path,
    *,
    python_version: str = "3.13",
    dockerfile_version: str = "3.13",
    requires_python: str = "3.13",
) -> subprocess.CompletedProcess[str]:
    (tmp_path / ".python-version").write_text(f"{python_version}\n", encoding="utf-8")
    (tmp_path / "Dockerfile").write_text(
        f"ARG PYTHON_VERSION={dockerfile_version}\n"
        "FROM python:${PYTHON_VERSION}-slim\n",
        encoding="utf-8",
    )
    (tmp_path / "pyproject.toml").write_text(
        f'[project]\nrequires-python = ">={requires_python}"\n',
        encoding="utf-8",
    )

    return subprocess.run(
        ["bash", "-c", _drift_check_script()],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.mark.unit
def test_drift_check_passes_when_all_versions_match(tmp_path: Path) -> None:
    result = _run_drift_check(tmp_path)

    assert result.returncode == 0
    assert result.stdout == ""


@pytest.mark.unit
def test_drift_check_fails_on_dockerfile_mismatch(tmp_path: Path) -> None:
    result = _run_drift_check(tmp_path, dockerfile_version="3.12")

    assert result.returncode == 1
    assert "Dockerfile ARG PYTHON_VERSION=3.12 does not match" in result.stdout


@pytest.mark.unit
def test_drift_check_fails_on_requires_python_mismatch(tmp_path: Path) -> None:
    result = _run_drift_check(tmp_path, requires_python="3.14")

    assert result.returncode == 1
    assert "pyproject.toml requires-python=>=3.14 does not match" in result.stdout


@pytest.mark.unit
def test_drift_check_reports_dockerfile_mismatch_before_requires_python(
    tmp_path: Path,
) -> None:
    # When both files disagree, the Dockerfile check runs first and
    # exits immediately — the requires-python check is never reached.
    result = _run_drift_check(
        tmp_path, dockerfile_version="3.12", requires_python="3.14"
    )

    assert result.returncode == 1
    assert "Dockerfile ARG PYTHON_VERSION=3.12 does not match" in result.stdout
    assert "requires-python" not in result.stdout


@pytest.mark.unit
@pytest.mark.parametrize(
    "python_version",
    [
        "3.13.7",  # patch-level — violates minor-only granularity
        "3",  # major only, no minor
        "python3.13",  # non-numeric prefix
        "3.13-slim",  # trailing non-numeric suffix
        "",  # empty
        " 3.13",  # leading whitespace
    ],
)
def test_drift_check_fails_on_malformed_python_version(
    tmp_path: Path, python_version: str
) -> None:
    # The format check runs before the Dockerfile/pyproject.toml
    # comparisons, so a malformed .python-version is rejected even when
    # the other two files happen to carry the exact same (invalid)
    # string — matching values are not sufficient, the shared value
    # itself must be minor-only (docs/conventions.md, Runtime Version ->
    # Source of Truth: ".python-version file uses minor-version
    # granularity").
    result = _run_drift_check(
        tmp_path,
        python_version=python_version,
        dockerfile_version=python_version,
        requires_python=python_version,
    )

    assert result.returncode == 1
    assert "is not a valid minor-only version" in result.stdout


@pytest.mark.unit
def test_drift_check_accepts_well_formed_minor_only_version(tmp_path: Path) -> None:
    result = _run_drift_check(
        tmp_path,
        python_version="3.14",
        dockerfile_version="3.14",
        requires_python="3.14",
    )

    assert result.returncode == 0
    assert result.stdout == ""


@pytest.mark.unit
def test_pull_request_image_job_generates_validated_sbom_candidate() -> None:
    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
    image_job = _ci_jobs()["image-smoke"]
    smoke_step = named_step(image_job, SMOKE_STEP)
    sbom_step = named_step(image_job, SBOM_STEP)
    upload_step = named_step(image_job, SBOM_UPLOAD_STEP)

    assert image_job["if"] == "github.event_name == 'pull_request'"
    assert sbom_step["run"].startswith("./scripts/sbom-gate.sh ")
    assert '"ghcr.io/${IMAGE_NAME,,}"' in sbom_step["run"]
    assert _uses(upload_step, "actions/upload-artifact")
    assert upload_step["with"]["name"] == "sentinel-sbom-candidate"
    assert upload_step["with"]["retention-days"] == 7
    assert "actions/attest@" not in workflow
    assert "gh release upload" not in workflow
    assert smoke_step["id"] == "image-smoke"
    assert (
        sbom_step["env"]["TESTED_IMAGE"] == "${{ steps.image-smoke.outputs.image_id }}"
    )
    assert '"${TESTED_IMAGE}"' in sbom_step["run"]
    assert not any("SMOKE_IMAGE" in value for value in string_values(sbom_step))
    assert (
        step_index(image_job, BUILD_STEP)
        < step_index(image_job, SMOKE_STEP)
        < step_index(image_job, SBOM_STEP)
        < step_index(image_job, SBOM_UPLOAD_STEP)
    )


@pytest.mark.unit
def test_pull_request_image_job_smokes_loaded_image_without_override() -> None:
    image_job = _ci_jobs()["image-smoke"]
    build_steps = [
        step for step in job_steps(image_job) if _uses(step, "docker/build-push-action")
    ]
    smoke_step = named_step(image_job, SMOKE_STEP)

    assert len(build_steps) == 1
    assert build_steps[0]["name"] == BUILD_STEP
    assert build_steps[0]["with"]["push"] is False
    assert build_steps[0]["with"]["load"] is True
    assert smoke_step["env"]["SENTINEL_IMAGE"] == "${{ env.SMOKE_IMAGE }}"
    assert smoke_step["run"] == "./scripts/image-smoke.sh --no-build"
    assert "COMPOSE_CMD" not in WORKFLOW_PATH.read_text(encoding="utf-8")


@pytest.mark.unit
def test_ci_and_release_workflows_share_sbom_gate() -> None:
    for path in (WORKFLOW_PATH, RELEASE_WORKFLOW_PATH):
        workflow = load_yaml_file(path)
        gate_runs = [
            step["run"]
            for job in workflow_jobs(workflow).values()
            for step in job_steps(job)
            if "sbom-gate.sh" in str(step.get("run", ""))
        ]
        mentions = sum(value.count("sbom-gate.sh") for value in string_values(workflow))

        assert len(gate_runs) == 1, path.name
        assert gate_runs[0].startswith("./scripts/sbom-gate.sh "), path.name
        assert mentions == 1, path.name


@pytest.mark.unit
def test_pip_audit_runs_only_when_audit_scope_requires_it() -> None:
    # testing-strategy.md (CI Pipeline, gate 6); issue #708.
    job = _ci_jobs()["backend-security"]
    checkout_step = job_steps(job)[0]
    scope_step = named_step(job, SCOPE_STEP)
    audit_step = named_step(job, AUDIT_STEP)

    assert job["name"] == "Backend Security Scan"
    assert _uses(checkout_step, "actions/checkout")
    assert checkout_step["with"]["fetch-depth"] == 2
    assert scope_step["id"] == "audit-scope"
    assert scope_step["run"] == "../scripts/dependency-audit-scope.sh"
    assert (
        scope_step["env"].items()
        >= {
            "EVENT_NAME": "${{ github.event_name }}",
            "HEAD_REF": "${{ github.head_ref }}",
            "PUSH_BEFORE": "${{ github.event.before }}",
        }.items()
    )
    assert step_index(job, SCOPE_STEP) < step_index(job, AUDIT_STEP)
    assert audit_step["if"] == "steps.audit-scope.outputs.required == 'true'"
    assert "uvx pip-audit@" in audit_step["run"]
    assert "continue-on-error" not in audit_step
    # Untrusted context values reach the script only through env, never by
    # interpolation into the shell command.
    assert "${{" not in scope_step["run"]


@pytest.mark.unit
def test_backend_tests_hand_coverage_report_to_upload_job() -> None:
    # docs/deployment.md (Workflow Conventions, Coverage reporting); issue #823.
    job = _ci_jobs()["backend-test"]
    retain_step = named_step(job, "Retain coverage report")

    assert not any(_uses(step, "codecov/codecov-action") for step in job_steps(job))
    assert retain_step["if"] == "${{ !cancelled() }}"
    assert _uses(retain_step, "actions/upload-artifact")
    assert retain_step["with"]["name"] == "backend-coverage"
    assert retain_step["with"]["path"] == "backend/coverage.xml"
    assert retain_step["with"]["if-no-files-found"] == "error"


@pytest.mark.unit
def test_coverage_upload_job_fails_on_pull_request_error_with_pinned_cli() -> None:
    job = _ci_jobs()["coverage-upload"]
    steps = job_steps(job)
    checkout_step = next(step for step in steps if _uses(step, "actions/checkout"))
    download_step = next(
        step for step in steps if _uses(step, "actions/download-artifact")
    )
    upload_step = named_step(job, "Upload coverage to Codecov")

    assert job["name"] == "Coverage Upload"
    assert job["needs"] == "backend-test"
    assert job["if"] == "${{ !cancelled() }}"
    assert checkout_step["with"]["persist-credentials"] is False
    assert download_step["with"]["name"] == "backend-coverage"
    assert _uses(upload_step, "codecov/codecov-action")
    assert upload_step["with"]["files"] == "backend/coverage.xml"
    assert upload_step["with"]["disable_search"] is True
    # Fails only where the required Codecov status gates a merge; a push to
    # master must not turn the CI run that gates release-please and
    # build-images red because of Codecov.
    assert upload_step["with"]["fail_ci_if_error"] == (
        "${{ github.event_name == 'pull_request' }}"
    )
    # The CLI version is an exact release, never "latest", and carries the
    # hint comment the renovate.jsonc custom manager matches; the comment is
    # not YAML data, so it is read from the text.
    version = upload_step["with"]["version"]
    assert re.fullmatch(r"v\d+\.\d+\.\d+", version)
    assert re.search(
        r"# renovate: datasource=github-releases depName=codecov/codecov-cli\n"
        rf"\s+version: \"{re.escape(version)}\"\n",
        WORKFLOW_PATH.read_text(encoding="utf-8"),
    )


@pytest.mark.unit
def test_codecov_token_is_scoped_to_coverage_upload_job() -> None:
    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
    jobs_with_token = [
        job_id
        for job_id, job in _ci_jobs().items()
        if any("secrets.CODECOV_TOKEN" in value for value in string_values(job))
    ]

    assert workflow.count("secrets.CODECOV_TOKEN") == 1
    assert jobs_with_token == ["coverage-upload"]


@pytest.mark.unit
def test_codecov_patch_status_is_informational_and_project_status_disabled() -> None:
    # The required codecov/patch check must never fail on coverage values
    # nor wait on, or fail because of, other (possibly advisory) CI checks.
    # codecov/project is disabled explicitly: without the key, Codecov would
    # apply its default project status, which is not informational.
    config = load_yaml_file(CODECOV_CONFIG_PATH)
    status = config["coverage"]["status"]

    assert config["codecov"]["require_ci_to_pass"] is False
    assert config["codecov"]["notify"]["wait_for_ci"] is False
    assert config["codecov"]["notify"]["notify_error"] is True
    assert status["patch"]["default"]["informational"] is True
    assert status["project"] is False


@pytest.mark.unit
def test_lint_job_runs_the_static_security_analysis_unconditionally() -> None:
    # The configuration enables ruff's security rules for app/
    # (tests/test_static_security_analysis.py), so the lint run over the
    # whole backend is also the static security analysis of gate 6. The
    # security job keeps the dependency scan. Issue #1105.
    jobs = _ci_jobs()
    job = jobs["backend-lint"]
    lint_steps = [
        step for step in job_steps(job) if step.get("run") == "uv run ruff check ."
    ]

    assert "if" not in job
    assert job["defaults"]["run"]["working-directory"] == "backend"
    assert len(lint_steps) == 1
    assert "if" not in lint_steps[0]
    assert "continue-on-error" not in lint_steps[0]
    assert "if" not in jobs["backend-security"]


# Record their arguments, one per line. uv writes a requirements file to the
# path after --output-file unless UV_STUB_EXIT selects a failure; uvx first
# records UV_PYTHON and UV_EXCLUDE_NEWER, one per line.
UV_STUB = """\
#!/usr/bin/env bash
set -euo pipefail
printf '%s\\n' "$@" >"${UV_STUB_LOG}"
if [[ "${UV_STUB_EXIT}" != 0 ]]; then
    exit "${UV_STUB_EXIT}"
fi
while [[ $# -gt 0 ]]; do
    if [[ "$1" == --output-file ]]; then
        printf 'example==1.0\\n' >"$2"
    fi
    shift
done
"""
UVX_STUB = """\
#!/usr/bin/env bash
set -euo pipefail
{
    printf 'UV_PYTHON=%s\\n' "${UV_PYTHON-}"
    printf 'UV_EXCLUDE_NEWER=%s\\n' "${UV_EXCLUDE_NEWER-}"
    printf '%s\\n' "$@"
} >"${UVX_STUB_LOG}"
"""


def _run_audit_step(
    tmp_path: Path, *, export_exit: int = 0
) -> tuple[subprocess.CompletedProcess[str], Path, Path, Path]:
    """Run the pip-audit step's script against stubbed uv and uvx; return the
    result, the runner's temporary directory, and the two stub logs."""
    script = named_step(_ci_jobs()["backend-security"], AUDIT_STEP)["run"]
    assert isinstance(script, str)
    backend = tmp_path / "backend"
    backend.mkdir()
    (backend / ".python-version").write_text("3.14\n", encoding="utf-8")
    runner_temp = tmp_path / "runner"
    runner_temp.mkdir()
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name, content in (("uv", UV_STUB), ("uvx", UVX_STUB)):
        (bin_dir / name).write_text(content, encoding="utf-8")
        (bin_dir / name).chmod(0o755)
    uv_log = tmp_path / "uv.log"
    uvx_log = tmp_path / "uvx.log"
    env = {
        **os.environ,
        "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
        "RUNNER_TEMP": str(runner_temp),
        "UV_STUB_LOG": str(uv_log),
        "UV_STUB_EXIT": str(export_exit),
        "UVX_STUB_LOG": str(uvx_log),
        # Host defaults that the step must not pass on to pip-audit; the
        # second would turn the release-age cooldown off.
        "UV_PYTHON": "3.12",
        "UV_EXCLUDE_NEWER": "false",
    }
    result = subprocess.run(
        ["bash", "-c", script],
        cwd=backend,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    return result, runner_temp, uv_log, uvx_log


@pytest.mark.unit
def test_pip_audit_audits_the_hashed_locked_set_on_the_project_python(
    tmp_path: Path,
) -> None:
    # With hashes, --disable-pip audits the exported set as it is, instead
    # of installing it into an environment of the host interpreter where
    # pip's own dependencies hide a locked package; --strict fails on a
    # package that cannot be audited. Issue #1103.
    result, runner_temp, uv_log, uvx_log = _run_audit_step(tmp_path)
    uv_arguments = uv_log.read_text(encoding="utf-8").splitlines()
    uv_python, _, *audit_arguments = uvx_log.read_text(encoding="utf-8").splitlines()
    requirements = uv_arguments[uv_arguments.index("--output-file") + 1]
    audited = audit_arguments[audit_arguments.index("--requirement") + 1]

    assert result.returncode == 0, result.stderr
    assert uv_arguments[0] == "export"
    assert {"--locked", "--no-dev", "--no-emit-project"} <= set(uv_arguments)
    assert "--no-hashes" not in uv_arguments
    assert Path(requirements).parent == runner_temp
    assert uv_python == "UV_PYTHON=3.14"
    assert re.fullmatch(r"pip-audit@\d+\.\d+\.\d+", audit_arguments[0])
    assert {"--strict", "--disable-pip"} <= set(audit_arguments)
    assert audited == requirements


@pytest.mark.unit
def test_pip_audit_resolves_with_the_backend_release_age_cooldown(
    tmp_path: Path,
) -> None:
    # uvx resolves pip-audit and its dependencies without a lock file and
    # ignores the project's [tool.uv] settings, so the step passes the
    # cooldown of backend/pyproject.toml itself. Issue #1014.
    result, _, _, uvx_log = _run_audit_step(tmp_path)
    exclude_newer = uvx_log.read_text(encoding="utf-8").splitlines()[1]

    assert result.returncode == 0, result.stderr
    assert exclude_newer == f"UV_EXCLUDE_NEWER={backend_cooldown()}"


@pytest.mark.unit
def test_failed_requirements_export_fails_the_pip_audit_step(tmp_path: Path) -> None:
    # The regression of issue #1103: pip-audit read the export through a
    # process substitution, whose failure left it an empty requirements
    # list, and reported "No known vulnerabilities found".
    result, _, _, uvx_log = _run_audit_step(tmp_path, export_exit=2)

    assert result.returncode == 2
    assert not uvx_log.exists()
