#!/usr/bin/env bash
# Run the static security analysis of the backend application code
# (docs/features/platform/testing-strategy.md, CI Pipeline, gate 6): bandit,
# pinned by version, on every file of backend/app/ with the Python version of
# backend/.python-version.
#
# A tool run through uvx gets the first interpreter that uv finds, not the one
# of .python-version, so the script passes that version in UV_PYTHON
# (docs/conventions.md, Runtime Version). Bandit still exits 0 when it skips a
# file that it cannot read, parse, or scan, and when a nosec comment that
# names no test ID that bandit knows silences every test of its line
# (docs/conventions.md, Static Security Analysis). The script therefore also
# fails unless bandit reports that neither happened.
#
# Usage:
#   scripts/bandit-scan.sh
#
# The Backend Security Scan job of .github/workflows/ci.yml and the Makefile
# security target run this script. It exits with the exit code of bandit, or
# with 1 when bandit skipped a file, a nosec comment silenced every test of
# its line, or .python-version holds no minor version.

set -euo pipefail

BACKEND_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../backend" && pwd)"

# The lines of bandit's text report when it analyzed every file, and when no
# nosec comment silenced every test of its line.
NO_SKIPPED_FILES="Files skipped (0):"
NO_BLANKET_SUPPRESSION=$'\tTotal lines skipped (#nosec): 0'

main() {
    local python_version output status=0 complete=true

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
        complete=false
    fi
    if ! grep -Fqx -- "${NO_BLANKET_SUPPRESSION}" <<<"${output}"; then
        echo "Error: a nosec comment without a known test ID silenced every test of its line (see Total lines skipped above)." >&2
        complete=false
    fi
    if [[ "${complete}" == false ]] && ((status == 0)); then
        status=1
    fi
    return "${status}"
}

main "$@"
