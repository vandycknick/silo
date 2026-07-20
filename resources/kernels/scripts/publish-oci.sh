#!/bin/sh

set -eu

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
kernel_root=$(dirname "$script_dir")
repo_root=$(CDPATH='' cd -- "$kernel_root/../.." && pwd)

track=${TRACK:-stable}
version=$(make -s -C "$kernel_root" kernel-version TRACK="$track")
revision=${PUBLISH_REVISION:-${GITHUB_SHA:?missing GITHUB_SHA or PUBLISH_REVISION}}

if [ -n "${OCI_IMAGE:-}" ]; then
    image=$OCI_IMAGE
else
    owner=${GITHUB_REPOSITORY_OWNER:?missing GITHUB_REPOSITORY_OWNER or OCI_IMAGE}
    image="ghcr.io/$owner/silo/kernel"
fi

if [ -n "${PUBLISH_SOURCE:-}" ]; then
    source=$PUBLISH_SOURCE
else
    repository=${GITHUB_REPOSITORY:?missing GITHUB_REPOSITORY or PUBLISH_SOURCE}
    source="https://github.com/$repository"
fi

created=${PUBLISH_CREATED:-$(git -C "$repo_root" show -s --format=%cI "$revision")}
arm64_layout=${ARM64_OCI_LAYOUT:-$repo_root/target/kernels/$track/arm64}
amd64_layout=${AMD64_OCI_LAYOUT:-$repo_root/target/kernels/$track/x86_64}

temp_dir=$(mktemp -d)
trap 'rm -rf "$temp_dir"' 0 HUP INT TERM

revision_tag="$version-$revision"
arm64_tag="$revision_tag-arm64"
amd64_tag="$revision_tag-amd64"

oras cp --from-oci-layout "$arm64_layout:$version" "$image:$arm64_tag"
oras cp --from-oci-layout "$amd64_layout:$version" "$image:$amd64_tag"
oras manifest fetch --descriptor "$image:$arm64_tag" > "$temp_dir/arm64-descriptor.json"
oras manifest fetch --descriptor "$image:$amd64_tag" > "$temp_dir/amd64-descriptor.json"

jq -n \
    --slurpfile arm64 "$temp_dir/arm64-descriptor.json" \
    --slurpfile amd64 "$temp_dir/amd64-descriptor.json" \
    --arg created "$created" \
    --arg revision "$revision" \
    --arg source "$source" \
    --arg version "$version" \
    --arg track "$track" \
    '{
        schemaVersion: 2,
        mediaType: "application/vnd.oci.image.index.v1+json",
        artifactType: "application/vnd.silo.kernel.v1",
        manifests: [
            ($arm64[0] | {mediaType, digest, size, artifactType} + {platform: {os: "linux", architecture: "arm64"}}),
            ($amd64[0] | {mediaType, digest, size, artifactType} + {platform: {os: "linux", architecture: "amd64"}})
        ],
        annotations: {
            "org.opencontainers.image.created": $created,
            "org.opencontainers.image.description": "Silo Linux kernel",
            "org.opencontainers.image.revision": $revision,
            "org.opencontainers.image.source": $source,
            "org.opencontainers.image.version": $version,
            "com.silo.kernel.track": $track
        }
    }' > "$temp_dir/kernel-index.json"

oras manifest push "$image:$revision_tag,$version,$track" "$temp_dir/kernel-index.json"
oras manifest fetch "$image:$revision_tag" > "$temp_dir/published-index.json"
jq -e '
    .artifactType == "application/vnd.silo.kernel.v1" and
    ([.manifests[].platform | [.os, .architecture]] | sort) ==
        ([ ["linux", "amd64"], ["linux", "arm64"] ] | sort)
' "$temp_dir/published-index.json" >/dev/null

for platform in linux/arm64 linux/amd64; do
    oras manifest fetch --platform "$platform" "$image:$revision_tag" |
        jq -e '([.layers[] | select(.mediaType == "application/vnd.silo.kernel.image.v1")] | length) == 1' >/dev/null
    oras manifest fetch-config --platform "$platform" "$image:$revision_tag" |
        jq -e --arg platform "$platform" '(.platform.os + "/" + .platform.architecture) == $platform' >/dev/null
done

printf 'Published %s with tags %s, %s, and %s\n' "$image" "$revision_tag" "$version" "$track"
