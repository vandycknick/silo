#!/bin/sh

set -eu

required='KERNEL_BUILD_DIR KERNEL_ARCH KERNEL_OCI_LAYOUT KERNEL_OCI_REFERENCE KERNEL_TRACK KERNEL_VERSION KERNEL_SOURCE_URL KERNEL_SOURCE_SHA256 BUILD_REVISION BUILD_CREATED'
for name in $required; do
    eval "value=\${$name-}"
    if [ -z "$value" ]; then
        printf 'missing required environment variable: %s\n' "$name" >&2
        exit 1
    fi
done

artifact_type=application/vnd.silo.kernel.v1
config_type=application/vnd.silo.kernel.config.v1+json
image_type=application/vnd.silo.kernel.image.v1
kconfig_type=application/vnd.silo.kernel.kconfig.v1
system_map_type=application/vnd.silo.kernel.system-map.v1
debug_type=application/vnd.silo.kernel.debug.v1+xz

case "$KERNEL_ARCH" in
    arm64)
        image_path=arch/arm64/boot/Image
        image_name=Image
        oci_arch=arm64
        kernel_format=arm64-image
        has_debug_elf=1
        ;;
    x86_64)
        image_path=vmlinux
        image_name=vmlinux
        oci_arch=amd64
        kernel_format=elf
        has_debug_elf=0
        ;;
    *)
        printf 'unsupported kernel architecture: %s\n' "$KERNEL_ARCH" >&2
        exit 1
        ;;
esac

package_dir="$KERNEL_BUILD_DIR/.oci-package"
layout_tmp="$KERNEL_OCI_LAYOUT.tmp"

rm -rf "$package_dir" "$layout_tmp"
mkdir -p "$package_dir" "$(dirname "$KERNEL_OCI_LAYOUT")"
cp "$KERNEL_BUILD_DIR/$image_path" "$package_dir/$image_name"
cp "$KERNEL_BUILD_DIR/.config" "$package_dir/.config"
cp "$KERNEL_BUILD_DIR/System.map" "$package_dir/System.map"

if [ "$has_debug_elf" = 1 ]; then
    xz -T0 -6 -c "$KERNEL_BUILD_DIR/vmlinux" > "$package_dir/vmlinux.xz"
fi

jq -n \
    --arg track "$KERNEL_TRACK" \
    --arg version "$KERNEL_VERSION" \
    --arg repository_arch "$KERNEL_ARCH" \
    --arg oci_arch "$oci_arch" \
    --arg image_type "$image_type" \
    --arg format "$kernel_format" \
    --arg source_url "$KERNEL_SOURCE_URL" \
    --arg source_sha256 "$KERNEL_SOURCE_SHA256" \
    --arg revision "$BUILD_REVISION" \
    --arg created "$BUILD_CREATED" \
    '{
        schemaVersion: 1,
        track: $track,
        kernelVersion: $version,
        architecture: $repository_arch,
        platform: {os: "linux", architecture: $oci_arch},
        kernel: {mediaType: $image_type, format: $format},
        source: {url: $source_url, digest: ("sha256:" + $source_sha256)},
        build: {
            revision: $revision,
            created: $created
        }
    }' > "$package_dir/artifact-config.json"

set -- \
    "$image_name:$image_type" \
    ".config:$kconfig_type" \
    "System.map:$system_map_type"
if [ "$has_debug_elf" = 1 ]; then
    set -- "$@" "vmlinux.xz:$debug_type"
fi

(
    cd "$package_dir"
    oras push --oci-layout "$layout_tmp:$KERNEL_OCI_REFERENCE" \
        --artifact-type "$artifact_type" \
        --config "artifact-config.json:$config_type" \
        --annotation "org.opencontainers.image.description=Silo Linux kernel ($KERNEL_TRACK/$KERNEL_ARCH)" \
        --annotation "org.opencontainers.image.created=$BUILD_CREATED" \
        --annotation "org.opencontainers.image.revision=$BUILD_REVISION" \
        --annotation "org.opencontainers.image.source=$KERNEL_SOURCE_URL" \
        --annotation "org.opencontainers.image.version=$KERNEL_VERSION" \
        --annotation "com.silo.kernel.track=$KERNEL_TRACK" \
        "$@"
)

rm -rf "$KERNEL_OCI_LAYOUT"
mv "$layout_tmp" "$KERNEL_OCI_LAYOUT"
rm -rf "$package_dir"
