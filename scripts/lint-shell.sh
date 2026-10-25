#!/usr/bin/env bash
# Lint the shell code of the repository (docs/conventions.md, Shell
# Scripting): shellcheck and shfmt on every shell script and Git hook, and
# actionlint on every workflow, which also runs the shellcheck of its image on
# their run: blocks. Each tool runs from its official image, pinned by version
# and digest, in a disposable container without network that reads the
# repository only: the script changes no file, and for a file that is not
# formatted, it prints the diff that formats it. The Shell Lint job of
# .github/workflows/ci.yml lints the tracked files, and .githooks/pre-commit
# the staged ones.
#
# Usage:
#   scripts/lint-shell.sh            Lint the tracked files: a new file once
#                                    it is added to the index
#   scripts/lint-shell.sh --staged   Lint the staged files, as the working tree
#                                    holds them; when Docker cannot run the
#                                    images, warn and skip the lint

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# The shell scripts and Git hooks, and the workflows, as Git pathspecs.
SHELL_PATHSPECS=('*.sh' '.githooks/*')
WORKFLOW_PATHSPECS=(':(glob).github/workflows/*.yml' ':(glob).github/workflows/*.yaml')

# The official images of the tools, pinned by version and digest and updated
# by Renovate (docs/deployment.md, Workflow Conventions). On the run: blocks,
# actionlint runs the shellcheck that its own image holds.
SHELLCHECK_IMAGE="koalaman/shellcheck:v0.11.0@sha256:61862eba1fcf09a484ebcc6feea46f1782532571a34ed51fedf90dd25f925a8d"
SHFMT_IMAGE="mvdan/shfmt:v3.14.1@sha256:8c06884a35683d8763fba6c0d9484d11a61a96da65f8d497d6f625825a6043f2"
ACTIONLINT_IMAGE="rhysd/actionlint:1.7.12@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667"

STAGED=false

# Prints, NUL-separated, the tracked files that match the pathspecs $@, or the
# staged ones that are added, copied, modified, or renamed.
selected_files() {
    if [[ "${STAGED}" == true ]]; then
        git diff --cached --name-only -z --diff-filter=ACMR -- "$@"
    else
        git ls-files -z -- "$@"
    fi | sort -z -u
}

# Fails unless Docker can run the images $@: the docker command is installed,
# its daemon answers, and each image is present or is downloaded.
prepare_images() {
    if ! command -v docker >/dev/null 2>&1; then
        echo "Error: the docker command is not installed." >&2
        return 1
    fi
    if ! docker version --format '{{.Server.Version}}' >/dev/null; then
        echo "Error: the Docker daemon is unreachable." >&2
        return 1
    fi
    local image
    for image in "$@"; do
        if ! docker image inspect "${image}" >/dev/null 2>&1; then
            echo "Downloading ${image}" >&2
            if ! docker pull --quiet "${image}" >/dev/null; then
                echo "Error: cannot download ${image}." >&2
                return 1
            fi
        fi
    done
}

# Runs the tool of the image $1 with the arguments $2... in a disposable
# container, with the user and group IDs of the invoking user, without
# capabilities, privilege escalation, or network, in a read-only mount of the
# repository, its working directory.
run_image() {
    local image="$1"
    shift
    docker run --rm --pull=never \
        --user="$(id -u):$(id -g)" \
        --cap-drop=ALL \
        --security-opt=no-new-privileges \
        --network=none \
        --volume="${REPO_ROOT}:/work:ro" \
        --workdir=/work \
        "${image}" "$@"
}

main() {
    case "$#:${1:-}" in
        0:) ;;
        1:--staged) STAGED=true ;;
        *)
            echo "Usage: $0 [--staged]" >&2
            return 2
            ;;
    esac
    cd "${REPO_ROOT}"

    local -a shell_files workflow_files images=()
    local status=0
    mapfile -d '' -t shell_files < <(selected_files "${SHELL_PATHSPECS[@]}")
    mapfile -d '' -t workflow_files < <(selected_files "${WORKFLOW_PATHSPECS[@]}")

    if ((${#shell_files[@]} > 0)); then
        images+=("${SHELLCHECK_IMAGE}" "${SHFMT_IMAGE}")
    fi
    if ((${#workflow_files[@]} > 0)); then
        images+=("${ACTIONLINT_IMAGE}")
    fi
    if ((${#images[@]} == 0)); then
        return 0
    fi
    # The staged files are linted by the pre-commit hook, a supplementary
    # check: the commit proceeds without the lint, which CI enforces.
    if ! prepare_images "${images[@]}"; then
        if [[ "${STAGED}" == true ]]; then
            echo "Warning: Docker cannot run the images of the shell lint; skipping it (CI will enforce)." >&2
            return 0
        fi
        return 1
    fi

    if ((${#shell_files[@]} > 0)); then
        printf 'shellcheck and shfmt on %d file(s):\n' "${#shell_files[@]}"
        printf '  %s\n' "${shell_files[@]}"
        run_image "${SHELLCHECK_IMAGE}" -- "${shell_files[@]}" || status=1
        run_image "${SHFMT_IMAGE}" -i 4 -ci -d -- "${shell_files[@]}" || status=1
    fi
    if ((${#workflow_files[@]} > 0)); then
        printf 'actionlint on %d workflow(s):\n' "${#workflow_files[@]}"
        printf '  %s\n' "${workflow_files[@]}"
        run_image "${ACTIONLINT_IMAGE}" -- "${workflow_files[@]}" || status=1
    fi
    return "${status}"
}

main "$@"
