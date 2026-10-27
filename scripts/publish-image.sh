#!/usr/bin/env bash
# Publish the tested local image under every newline-delimited IMAGE_TAGS
# entry and write the registry image name and digest to GITHUB_OUTPUT.
# The tested image must be one OCI image manifest, and the registry must
# serve every tag under its digest (docs/deployment.md, Container Build
# Conventions → Image builder and format).

set -euo pipefail

readonly OCI_IMAGE_MANIFEST="application/vnd.oci.image.manifest.v1+json"
readonly DIGEST_PATTERN='^sha256:[0-9a-f]{64}$'

main() {
    : "${SMOKE_IMAGE:?SMOKE_IMAGE must name the tested local image}"
    : "${IMAGE_TAGS:?IMAGE_TAGS must contain at least one registry tag}"
    : "${GITHUB_OUTPUT:?GITHUB_OUTPUT must identify the step output file}"

    local descriptor tested_digest tag image_name="" current_name current_digest

    # The containerd image store records the descriptor of the stored image:
    # an index here would also hold another manifest, such as an attestation.
    descriptor="$(docker image inspect --format '{{json .Descriptor}}' "${SMOKE_IMAGE}")"
    if ! jq -e --arg type "${OCI_IMAGE_MANIFEST}" '.mediaType == $type' \
        <<<"${descriptor}" >/dev/null; then
        echo "The tested image ${SMOKE_IMAGE} is not one OCI image manifest: ${descriptor}" >&2
        return 1
    fi
    tested_digest="$(jq -r '.digest' <<<"${descriptor}")"
    if [[ ! "${tested_digest}" =~ ${DIGEST_PATTERN} ]]; then
        echo "The tested image ${SMOKE_IMAGE} has an invalid digest: ${tested_digest}" >&2
        return 1
    fi

    while read -r tag; do
        [[ -z "${tag}" ]] && continue

        echo "Tagging and pushing ${tag}"
        docker tag "${SMOKE_IMAGE}" "${tag}"
        docker push "${tag}"

        current_name="${tag%:*}"
        current_digest="$(
            docker buildx imagetools inspect "${tag}" \
                --format '{{json .Manifest}}' | jq -er '.digest'
        )"
        if [[ ! "${current_digest}" =~ ${DIGEST_PATTERN} ]]; then
            echo "Registry returned an invalid digest for ${tag}: ${current_digest}" >&2
            return 1
        fi
        if [[ "${current_digest}" != "${tested_digest}" ]]; then
            echo "Registry serves ${tag} as ${current_digest}, not as the tested ${tested_digest}" >&2
            return 1
        fi

        if [[ -z "${image_name}" ]]; then
            image_name="${current_name}"
        elif [[ "${current_name}" != "${image_name}" ]]; then
            echo "Published tags do not share one image name" >&2
            return 1
        fi
    done <<<"${IMAGE_TAGS}"

    if [[ -z "${image_name}" ]]; then
        echo "IMAGE_TAGS did not contain a publishable tag" >&2
        return 1
    fi

    {
        echo "image_name=${image_name}"
        echo "digest=${tested_digest}"
    } >>"${GITHUB_OUTPUT}"
}

main "$@"
