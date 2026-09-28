#!/bin/sh

set -eu

if [ "$#" -ne 2 ]; then
    printf 'usage: %s <OCI layout> <reference>\n' "$0" >&2
    exit 1
fi
layout=$1
reference=$2
image=${OCI_IMAGE:?missing OCI_IMAGE}
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
"$script_dir/validate-oci.sh" "$layout" "$reference" rprobe

temp_dir=$(mktemp -d)
trap 'rm -rf "$temp_dir"' 0 HUP INT TERM
oras manifest fetch-config --oci-layout "$layout:$reference" > "$temp_dir/config.json"
version=$(jq -er '.kernelVersion' "$temp_dir/config.json")
revision=$(jq -er '.build.revision' "$temp_dir/config.json")
created=$(jq -er '.build.created' "$temp_dir/config.json")
track=$(jq -er '.track | select(. == "stable")' "$temp_dir/config.json")
revision_tag="$version-$revision"

oras cp --from-oci-layout "$layout:$reference" "$image:$revision_tag-arm64"
oras manifest fetch --descriptor "$image:$revision_tag-arm64" > "$temp_dir/descriptor.json"
jq -n \
    --slurpfile manifest "$temp_dir/descriptor.json" \
    --arg version "$version" \
    --arg revision "$revision" \
    --arg created "$created" \
    --arg source "https://github.com/${GITHUB_REPOSITORY:?missing GITHUB_REPOSITORY}" \
    '{
        schemaVersion: 2,
        mediaType: "application/vnd.oci.image.index.v1+json",
        artifactType: "application/vnd.silo.rprobe-kernel.v1",
        manifests: [
            ($manifest[0] | {mediaType, digest, size, artifactType} + {platform: {os: "linux", architecture: "arm64"}})
        ],
        annotations: {
            "org.opencontainers.image.created": $created,
            "org.opencontainers.image.description": "Silo Rosetta acquisition probe",
            "org.opencontainers.image.revision": $revision,
            "org.opencontainers.image.source": $source,
            "org.opencontainers.image.version": $version
        }
    }' > "$temp_dir/index.json"

oras manifest push "$image:$revision_tag" "$temp_dir/index.json"
oras manifest fetch "$image:$revision_tag" | jq -e '
    .artifactType == "application/vnd.silo.rprobe-kernel.v1" and
    [.manifests[].platform | [.os, .architecture]] == [["linux", "arm64"]]
' > /dev/null
oras manifest fetch --platform linux/arm64 "$image:$revision_tag" | jq -e '
    ([.layers[] | select(.mediaType == "application/vnd.silo.rprobe-kernel.image.v1")] | length) == 1
' > /dev/null
oras manifest fetch-config --platform linux/arm64 "$image:$revision_tag" | jq -e '
    .profile == "rprobe" and .purpose == "rosetta-acquisition-probe" and
    .platform == {os: "linux", architecture: "arm64"}
' > /dev/null
oras tag "$image:$revision_tag" "$track"
printf 'Published %s:%s and %s\n' "$image" "$revision_tag" "$track"
