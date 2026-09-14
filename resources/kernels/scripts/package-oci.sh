#!/bin/sh

set -eu

required='KERNEL_BUILD_DIR KERNEL_ARCH KERNEL_PROFILE KERNEL_IDENTITY KERNEL_OCI_LAYOUT KERNEL_OCI_REFERENCE KERNEL_OCI_ROOT KERNEL_REPO_ROOT KERNEL_PRISTINE_ROOT KERNEL_TRACK KERNEL_VERSION KERNEL_SOURCE_URL KERNEL_SOURCE_SHA256 KERNEL_SOURCE_KEY KERNEL_PATCH_KEY KERNEL_CONFIG_KEY KERNEL_BUILD_INPUT_KEY KERNEL_TOOLCHAIN_KEY KERNEL_COMPILER KERNEL_LINKER BUILD_REVISION BUILD_CREATED'
for name in $required; do
    eval "value=\${$name-}"
    if [ -z "$value" ]; then
        printf 'missing required environment variable: %s\n' "$name" >&2
        exit 1
    fi
done

if [ "$KERNEL_SOURCE_KEY" != "sha256-$KERNEL_SOURCE_SHA256" ]; then
    printf 'kernel source digest/key mismatch\n' >&2
    exit 1
fi

case "$KERNEL_PROFILE" in
    workload)
        purpose=workload
        artifact_type=application/vnd.silo.kernel.v1
        config_type=application/vnd.silo.kernel.config.v1+json
        image_type=application/vnd.silo.kernel.image.v1
        ;;
    rprobe)
        purpose=rosetta-acquisition-probe
        if [ "$KERNEL_ARCH" != arm64 ]; then
            printf 'rprobe kernel packaging only supports arm64\n' >&2
            exit 1
        fi
        artifact_type=application/vnd.silo.rprobe-kernel.v1
        config_type=application/vnd.silo.rprobe-kernel.config.v1+json
        image_type=application/vnd.silo.rprobe-kernel.image.v1
        ;;
    *)
        printf 'unsupported kernel profile: %s\n' "$KERNEL_PROFILE" >&2
        exit 1
        ;;
esac
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

"$(dirname "$0")/validate-owned-path.sh" "$KERNEL_OCI_LAYOUT" "$KERNEL_OCI_ROOT" "$KERNEL_REPO_ROOT" "$KERNEL_PRISTINE_ROOT"
layout_physical=$(realpath -m -- "$KERNEL_OCI_LAYOUT")
pristine_physical=$(realpath -m -- "$KERNEL_PRISTINE_ROOT")
case "$layout_physical/" in
    "$pristine_physical/"*) printf 'canonical OCI destination overlaps pristine storage\n' >&2; exit 1 ;;
esac
mkdir -p "$(dirname "$KERNEL_OCI_LAYOUT")"
package_dir=$(mktemp -d "$KERNEL_BUILD_DIR/.silo-oci-package.XXXXXX")
layout_tmp=$(mktemp -d "$(dirname "$KERNEL_OCI_LAYOUT")/.silo-oci-layout.XXXXXX")
cleanup() {
    rm -rf "$package_dir" "$layout_tmp"
}
trap cleanup 0 HUP INT TERM
cp "$KERNEL_BUILD_DIR/$image_path" "$package_dir/$image_name"
cp "$KERNEL_BUILD_DIR/.config" "$package_dir/.config"
cp "$KERNEL_BUILD_DIR/System.map" "$package_dir/System.map"

image_sha256=$(sha256sum "$package_dir/$image_name" | cut -d' ' -f1)
image_size=$(wc -c < "$package_dir/$image_name" | tr -d ' ')
config_sha256=$(sha256sum "$package_dir/.config" | cut -d' ' -f1)
config_size=$(wc -c < "$package_dir/.config" | tr -d ' ')

if [ "$has_debug_elf" = 1 ]; then
    xz -T0 -6 -c "$KERNEL_BUILD_DIR/vmlinux" > "$package_dir/vmlinux.xz"
fi

jq -n \
    --arg track "$KERNEL_TRACK" \
    --arg profile "$KERNEL_PROFILE" \
    --arg purpose "$purpose" \
    --arg identity "$KERNEL_IDENTITY" \
    --arg version "$KERNEL_VERSION" \
    --arg repository_arch "$KERNEL_ARCH" \
    --arg oci_arch "$oci_arch" \
    --arg image_type "$image_type" \
    --arg format "$kernel_format" \
    --arg source_url "$KERNEL_SOURCE_URL" \
    --arg source_sha256 "$KERNEL_SOURCE_SHA256" \
    --arg source_key "$KERNEL_SOURCE_KEY" \
    --arg patch_key "$KERNEL_PATCH_KEY" \
    --arg config_key "$KERNEL_CONFIG_KEY" \
    --arg build_input_key "$KERNEL_BUILD_INPUT_KEY" \
    --arg toolchain_key "$KERNEL_TOOLCHAIN_KEY" \
    --arg compiler "$KERNEL_COMPILER" \
    --arg linker "$KERNEL_LINKER" \
    --arg image_sha256 "$image_sha256" \
    --argjson image_size "$image_size" \
    --arg config_sha256 "$config_sha256" \
    --argjson config_size "$config_size" \
    --arg revision "$BUILD_REVISION" \
    --arg created "$BUILD_CREATED" \
    '{
        schemaVersion: 1,
        profile: $profile,
        purpose: $purpose,
        identity: $identity,
        track: $track,
        kernelVersion: $version,
        architecture: $repository_arch,
        platform: {os: "linux", architecture: $oci_arch},
        kernel: {mediaType: $image_type, format: $format, size: $image_size, digest: ("sha256:" + $image_sha256)},
        resolvedConfig: {size: $config_size, digest: ("sha256:" + $config_sha256)},
        source: {url: $source_url, digest: ("sha256:" + $source_sha256), key: $source_key},
        inputs: {patchSet: $patch_key, config: $config_key, build: $build_input_key, toolchain: $toolchain_key},
        build: {
            revision: $revision,
            created: $created,
            compiler: $compiler,
            linker: $linker
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
        --annotation "org.opencontainers.image.description=Silo $purpose kernel ($KERNEL_TRACK/$KERNEL_ARCH)" \
        --annotation "org.opencontainers.image.created=$BUILD_CREATED" \
        --annotation "org.opencontainers.image.revision=$BUILD_REVISION" \
        --annotation "org.opencontainers.image.source=$KERNEL_SOURCE_URL" \
        --annotation "org.opencontainers.image.version=$KERNEL_VERSION" \
        --annotation "com.silo.kernel.track=$KERNEL_TRACK" \
        --annotation "com.silo.kernel.profile=$KERNEL_PROFILE" \
        --annotation "com.silo.kernel.purpose=$purpose" \
        "$@"
)

printf '%s\n' "$KERNEL_IDENTITY" > "$layout_tmp/.silo-kernel-oci-canonical"
if [ -e "$KERNEL_OCI_LAYOUT" ]; then
    marker="$KERNEL_OCI_LAYOUT/.silo-kernel-oci-canonical"
    if [ -L "$marker" ] || [ "$(sed -n '1p' "$marker" 2>/dev/null)" != "$KERNEL_IDENTITY" ]; then
        if ! "$(dirname "$0")/validate-oci.sh" "$KERNEL_OCI_LAYOUT" "$KERNEL_OCI_REFERENCE" "$KERNEL_PROFILE" || \
            [ "$(oras manifest fetch-config --oci-layout "$KERNEL_OCI_LAYOUT:$KERNEL_OCI_REFERENCE" | jq -r '.identity')" != "$KERNEL_IDENTITY" ]; then
            printf 'refusing to replace unowned canonical OCI destination: %s\n' "$KERNEL_OCI_LAYOUT" >&2
            exit 1
        fi
    fi
    previous=$(mktemp -d "$(dirname "$KERNEL_OCI_LAYOUT")/.silo-oci-previous.XXXXXX")
    rmdir "$previous"
    mv "$KERNEL_OCI_LAYOUT" "$previous"
    if ! mv "$layout_tmp" "$KERNEL_OCI_LAYOUT"; then
        mv "$previous" "$KERNEL_OCI_LAYOUT"
        exit 1
    fi
    rm -rf "$previous"
else
    mv "$layout_tmp" "$KERNEL_OCI_LAYOUT"
fi
trap - 0 HUP INT TERM
rm -rf "$package_dir"
