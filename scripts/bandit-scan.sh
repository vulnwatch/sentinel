#!/usr/bin/env bash
# Run the static security analysis of the backend application code
# (docs/features/platform/testing-strategy.md, CI Pipeline, gate 6): bandit,
# pinned by version, on every file of backend/app/ with the Python version of
# backend/.python-version.
#
# A tool run through uvx gets the first interpreter that uv finds, not the one
# of .python-version, so the script passes that version in UV_PYTHON
# (docs/conventions.md, Runtime Version). Bandit skips a file that it cannot
# read, parse, or scan and still exits 0, so the script also fails unless
# bandit reports that it skipped no file.
#
# Usage:
#   scripts/bandit-scan.sh
#
# The Backend Security Scan job of .github/workflows/ci.yml and the Makefile
# security target run this script. It exits with the exit code of bandit, or
# with 1 when bandit skipped a file or .python-version holds no minor version.

set -euo pipefail

BACKEND_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../backend" && pwd)"

# The line of bandit's text report when it analyzed every file.
NO_SKIPPED_FILES="Files skipped (0):"

main() {
    local python_version output status=0

    python_version="$(<"${BACKEND_DIR}/.python-version")"
    if [[ ! "${python_version}" =~ ^[0-9]+\.[0-9]+$ ]]; then
        echo "Error: backend/.python-version must hold a minor version such as 3.14." >&2
        return 1
    fi

    cd "${BACKEND_DIR}"
    output="$(UV_PYTHON="${python_version}" uvx bandit@1.9.4 -c pyproject.toml -r app/ -f txt)" || status=$?
    printf '%s\n' "${output}"

    if ! grep -Fqx -- "${NO_SKIPPED_FILES}" <<<"${output}"; then
        echo "Error: bandit did not analyze every file of backend/app/ (see Files skipped above)." >&2
        if ((status == 0)); then
            status=1
        fi
    fi
    return "${status}"
}

main "$@"
