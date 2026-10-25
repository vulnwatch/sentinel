"""Regression tests for the image scan (`.github/workflows/image-scan.yml`).

The scan runs Trivy from its official image, pinned by version and digest,
instead of through `aquasecurity/trivy-action`, whose GitHub lookups the IP
allow list of the `aquasecurity` organization refuses to Renovate (issue
#1097; `docs/deployment.md`, Image Vulnerability Monitoring). The job exports
the published image to an archive, and Trivy reads that archive in a
container that receives neither the Docker socket, the registry credentials,
a token, nor an environment variable of the runner. The fixable-only scan
drives the tracking issue through the step's `fixable` output; a scan that
does not complete fails the step and leaves the issue unchanged.

The workflow is parsed as YAML (`tests/support/yaml_files.py`). The tests run
the `run:` blocks of the export and scan steps with bash, as GitHub Actions
does, with a stubbed `docker` first on `PATH` that records each call and
answers as the test requires.
"""

from __future__ import annotations

import os
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest

from tests.support.yaml_files import (
    YamlMapping,
    job_steps,
    load_yaml_file,
    named_step,
    step_index,
    workflow_jobs,
)

WORKFLOW_PATH = (
    Path(__file__).resolve().parents[2] / ".github" / "workflows" / "image-scan.yml"
)
WORKFLOW = load_yaml_file(WORKFLOW_PATH)
TRIVY_IMAGE = WORKFLOW["env"]["TRIVY_IMAGE"]
IMAGE_REF = "ghcr.io/example-org/sentinel:latest"

EXPORT_STEP = "Pull and export the published image"
PULL_TRIVY_STEP = "Pull the pinned Trivy image"
SCAN_STEP = "Scan for OS vulnerabilities"
UPLOAD_STEP = "Upload complete vulnerability report artifact"
OPEN_ISSUE_STEP = "Open or update tracking issue for fixable findings"
CLOSE_ISSUE_STEP = "Close tracking issue when the scan is clean"

# The exit code of the fixable-only scan on a finding; Trivy exits with 1 on
# an error.
FINDINGS_EXIT_CODE = 3

# Records each call, one argument per tab-separated field. A `docker run`
# exits with DOCKER_STUB_FIXABLE_EXIT for the fixable-only scan, the one with
# --ignore-unfixed, and with DOCKER_STUB_FULL_EXIT for the complete report.
DOCKER_STUB = """\
#!/usr/bin/env bash
set -euo pipefail
(IFS=$'\\t'; printf '%s\\n' "$*") >> "${DOCKER_STUB_LOG}"
if [[ "$1" == run ]]; then
    for argument in "$@"; do
        if [[ "${argument}" == --ignore-unfixed ]]; then
            exit "${DOCKER_STUB_FIXABLE_EXIT:-0}"
        fi
    done
    exit "${DOCKER_STUB_FULL_EXIT:-0}"
fi
exit 0
"""


@dataclass
class StepRun:
    result: subprocess.CompletedProcess[str]
    calls: list[list[str]]
    outputs: str
    runner_temp: Path


def _job() -> YamlMapping:
    return workflow_jobs(WORKFLOW)["image-scan"]


def _run_step(
    tmp_path: Path, name: str, *, fixable_exit: int = 0, full_exit: int = 0
) -> StepRun:
    """Run the `run:` block of the step `name`; return its result, the docker
    calls, each as its list of arguments, and the step outputs it wrote."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    stub = bin_dir / "docker"
    stub.write_text(DOCKER_STUB, encoding="utf-8")
    stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
    log = tmp_path / "docker.log"
    log.write_text("", encoding="utf-8")
    runner_temp = tmp_path / "runner-temp"
    runner_temp.mkdir()
    github_output = tmp_path / "github-output"
    github_output.write_text("", encoding="utf-8")

    env = os.environ | {
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "RUNNER_TEMP": str(runner_temp),
        "GITHUB_OUTPUT": str(github_output),
        "TRIVY_IMAGE": TRIVY_IMAGE,
        "IMAGE_REF": IMAGE_REF,
        "DOCKER_STUB_LOG": str(log),
        "DOCKER_STUB_FIXABLE_EXIT": str(fixable_exit),
        "DOCKER_STUB_FULL_EXIT": str(full_exit),
    }
    result = subprocess.run(
        [
            "bash",
            "--noprofile",
            "--norc",
            "-eo",
            "pipefail",
            "-c",
            named_step(_job(), name)["run"],
        ],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    calls = [line.split("\t") for line in log.read_text(encoding="utf-8").splitlines()]
    return StepRun(
        result, calls, github_output.read_text(encoding="utf-8"), runner_temp
    )


def _trivy_calls(runner_temp: Path) -> list[list[str]]:
    """The two `docker run` calls of a completed scan: the fixable-only scan,
    then the complete report."""
    container = [
        "run",
        "--rm",
        "--pull=never",
        f"--user={os.getuid()}:{os.getgid()}",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        f"--volume={runner_temp}/image.tar:/scan/image.tar:ro",
        f"--volume={runner_temp}/trivy-cache:/scan/cache",
        f"--volume={runner_temp}/trivy:/scan/reports",
        TRIVY_IMAGE,
        "image",
        "--input=/scan/image.tar",
        "--cache-dir=/scan/cache",
        "--scanners=vuln",
        "--pkg-types=os",
        "--format=table",
        "--disable-telemetry",
        "--skip-version-check",
    ]
    return [
        [
            *container,
            "--ignore-unfixed",
            "--severity=HIGH,CRITICAL",
            f"--exit-code={FINDINGS_EXIT_CODE}",
            "--output=/scan/reports/trivy-fixable.txt",
        ],
        [
            *container,
            "--skip-db-update",
            "--exit-code=0",
            "--output=/scan/reports/trivy-full.txt",
        ],
    ]


@pytest.mark.unit
def test_export_step_saves_the_pulled_image_to_the_archive(tmp_path: Path) -> None:
    run = _run_step(tmp_path, EXPORT_STEP)

    assert run.result.returncode == 0, run.result.stderr
    assert run.calls == [
        ["pull", IMAGE_REF],
        ["save", "--output", f"{run.runner_temp}/image.tar", IMAGE_REF],
    ]


@pytest.mark.unit
def test_clean_scan_isolates_trivy_and_reports_no_fixable_finding(
    tmp_path: Path,
) -> None:
    # Any further option, such as an environment variable or another mount,
    # would hand the container something of the runner's.
    run = _run_step(tmp_path, SCAN_STEP)

    assert run.result.returncode == 0, run.result.stderr
    assert run.calls == _trivy_calls(run.runner_temp)
    assert (run.runner_temp / "trivy").is_dir()
    assert (run.runner_temp / "trivy-cache").is_dir()
    assert run.outputs == "fixable=none\n"


@pytest.mark.unit
def test_fixable_finding_sets_found_and_still_writes_the_complete_report(
    tmp_path: Path,
) -> None:
    run = _run_step(tmp_path, SCAN_STEP, fixable_exit=FINDINGS_EXIT_CODE)

    assert run.result.returncode == 0, run.result.stderr
    assert run.calls == _trivy_calls(run.runner_temp)
    assert run.outputs == "fixable=found\n"


@pytest.mark.unit
@pytest.mark.parametrize(
    "exit_code", [pytest.param(1, id="trivy-error"), pytest.param(125, id="docker")]
)
def test_failed_fixable_scan_fails_the_step_without_a_result(
    tmp_path: Path, exit_code: int
) -> None:
    run = _run_step(tmp_path, SCAN_STEP, fixable_exit=exit_code)

    assert run.result.returncode == exit_code
    assert run.calls == _trivy_calls(run.runner_temp)[:1]
    assert run.outputs == ""


@pytest.mark.unit
def test_failed_complete_report_fails_the_step_without_a_result(
    tmp_path: Path,
) -> None:
    run = _run_step(tmp_path, SCAN_STEP, fixable_exit=FINDINGS_EXIT_CODE, full_exit=1)

    assert run.result.returncode == 1
    assert run.calls == _trivy_calls(run.runner_temp)
    assert run.outputs == ""


@pytest.mark.unit
def test_job_runs_trivy_only_from_the_pinned_image_after_the_export() -> None:
    job = _job()
    order = [
        step_index(job, name)
        for name in (EXPORT_STEP, PULL_TRIVY_STEP, SCAN_STEP, UPLOAD_STEP)
    ]

    assert order == sorted(order)
    assert named_step(job, PULL_TRIVY_STEP)["run"] == 'docker pull "${TRIVY_IMAGE}"'
    assert not [
        step["uses"]
        for step in job_steps(job)
        if str(step.get("uses", "")).startswith("aquasecurity/")
    ]


@pytest.mark.unit
def test_tracking_issue_and_artifact_follow_the_scan_result() -> None:
    job = _job()
    scan = named_step(job, SCAN_STEP)
    open_issue = named_step(job, OPEN_ISSUE_STEP)

    # A failed scan step must stop the job instead of reading as a result.
    assert scan["id"] == "trivy"
    assert "continue-on-error" not in scan
    assert open_issue["if"] == "steps.trivy.outputs.fixable == 'found'"
    assert '"${RUNNER_TEMP}/trivy/trivy-fixable.txt"' in open_issue["run"]
    assert (
        named_step(job, CLOSE_ISSUE_STEP)["if"]
        == "steps.trivy.outputs.fixable == 'none'"
    )
    assert named_step(job, UPLOAD_STEP)["with"]["path"] == (
        "${{ runner.temp }}/trivy/trivy-full.txt"
    )
