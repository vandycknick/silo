#!/bin/sh

set -eu

if [ "$#" -ne 1 ]; then
    printf 'usage: %s KERNEL_ROOT\n' "$0" >&2
    exit 2
fi

kernel_root=$1
temp_dir=$(mktemp -d)
trap 'rm -rf "$temp_dir"' 0 HUP INT TERM

build="$temp_dir/build"
canonical_root="$temp_dir/canonical"
export_root="$temp_dir/exports"
mkdir -p "$canonical_root" "$export_root"
mkdir -p "$build/arch/arm64/boot"
printf 'image fixture\n' > "$build/arch/arm64/boot/Image"
printf 'vmlinux fixture\n' > "$build/vmlinux"
printf 'CONFIG_FIXTURE=y\n' > "$build/.config"
printf 'fixture map\n' > "$build/System.map"

package_profile() {
    profile=$1
    purpose=$2
    layout="${LAYOUT_OVERRIDE:-$canonical_root/$profile-layout}"
    reference="$profile-reference"
    KERNEL_BUILD_DIR="$build" \
    KERNEL_ARCH=arm64 \
    KERNEL_PROFILE="$profile" \
    KERNEL_IDENTITY="$profile-identity" \
    KERNEL_OCI_LAYOUT="$layout" \
    KERNEL_OCI_REFERENCE="$reference" \
    KERNEL_OCI_ROOT="$canonical_root" \
    KERNEL_REPO_ROOT="$temp_dir/repository" \
    KERNEL_PRISTINE_ROOT="$temp_dir/pristine" \
    KERNEL_TRACK=stable \
    KERNEL_VERSION=7.2.2 \
    KERNEL_SOURCE_URL=https://example.invalid/linux.tar.xz \
    KERNEL_SOURCE_SHA256=7d0e7ce14f98c43efe880cffbf354a59be45928fdf7170d7333c374ae91c0d83 \
    KERNEL_SOURCE_KEY="${SOURCE_KEY_OVERRIDE:-sha256-7d0e7ce14f98c43efe880cffbf354a59be45928fdf7170d7333c374ae91c0d83}" \
    KERNEL_PATCH_KEY=sha256-e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 \
    KERNEL_CONFIG_KEY=sha256-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
    KERNEL_TOOLCHAIN_KEY=sha256-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
    KERNEL_BUILD_INPUT_KEY=sha256-cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc \
    KERNEL_COMPILER='fixture cc 1.0' \
    KERNEL_LINKER='fixture ld 1.0' \
    BUILD_REVISION=test \
    BUILD_CREATED=1970-01-01T00:00:00Z \
        "$kernel_root/scripts/package-oci.sh" > /dev/null
    "$kernel_root/scripts/validate-oci.sh" "$layout" "$reference" "$profile"
    oras manifest fetch-config --oci-layout "$layout:$reference"
}

package_profile workload workload > "$temp_dir/workload.json"
package_profile rprobe rosetta-acquisition-probe > "$temp_dir/rprobe.json"
package_profile workload workload > /dev/null
rm "$canonical_root/rprobe-layout/.silo-kernel-oci-canonical"
package_profile rprobe rosetta-acquisition-probe > /dev/null

printf 'root sentinel\n' > "$canonical_root/sentinel"
if LAYOUT_OVERRIDE="$canonical_root" package_profile rprobe rosetta-acquisition-probe > /dev/null 2>&1; then
    printf 'package accepted its ownership root as a destination\n' >&2
    exit 1
fi
grep -q '^root sentinel$' "$canonical_root/sentinel"

compat="$export_root/stable/arm64"
"$kernel_root/scripts/export-workload-oci.sh" "$canonical_root/workload-layout" workload-reference \
    "$compat" 7.2.2 "$export_root" workload-identity "$kernel_root/scripts/validate-oci.sh"
rm "$compat/.silo-kernel-oci-workload"
"$kernel_root/scripts/export-workload-oci.sh" "$canonical_root/workload-layout" workload-reference \
    "$compat" 7.2.2 "$export_root" workload-identity "$kernel_root/scripts/validate-oci.sh"
if [ ! -f "$compat/index.json" ]; then
    printf 'workload compatibility layout was not created\n' >&2
    exit 1
fi

jq -e '.profile == "workload" and .purpose == "workload"' "$temp_dir/workload.json" > /dev/null
jq -e '.profile == "rprobe" and .purpose == "rosetta-acquisition-probe"' "$temp_dir/rprobe.json" > /dev/null

workload_media=$(jq -r '.kernel.mediaType' "$temp_dir/workload.json")
rprobe_media=$(jq -r '.kernel.mediaType' "$temp_dir/rprobe.json")
if [ "$workload_media" = "$rprobe_media" ]; then
    printf 'workload and rprobe OCI image media types collided\n' >&2
    exit 1
fi

if "$kernel_root/scripts/validate-oci.sh" "$canonical_root/rprobe-layout" rprobe-reference workload > /dev/null 2>&1; then
    printf 'validator trusted a manifest profile over the expected profile\n' >&2
    exit 1
fi

if SOURCE_KEY_OVERRIDE=sha256-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
    LAYOUT_OVERRIDE="$canonical_root/source-mismatch" \
    package_profile rprobe rosetta-acquisition-probe > /dev/null 2>&1; then
    printf 'package accepted inconsistent source digest and key\n' >&2
    exit 1
fi

mkdir "$canonical_root/unowned"
printf 'canonical sentinel\n' > "$canonical_root/unowned/sentinel"
if LAYOUT_OVERRIDE="$canonical_root/unowned" package_profile rprobe rosetta-acquisition-probe > /dev/null 2>&1; then
    printf 'package replaced an unowned canonical destination\n' >&2
    exit 1
fi
grep -q '^canonical sentinel$' "$canonical_root/unowned/sentinel"

mkdir "$temp_dir/oci-symlink-target"
printf 'symlink sentinel\n' > "$temp_dir/oci-symlink-target/sentinel"
ln -s "$temp_dir/oci-symlink-target" "$canonical_root/symlink"
if LAYOUT_OVERRIDE="$canonical_root/symlink" package_profile rprobe rosetta-acquisition-probe > /dev/null 2>&1; then
    printf 'package accepted a symlink canonical destination\n' >&2
    exit 1
fi
grep -q '^symlink sentinel$' "$temp_dir/oci-symlink-target/sentinel"

unowned_compat="$export_root/unowned/arm64"
mkdir -p "$unowned_compat"
printf 'compat sentinel\n' > "$unowned_compat/sentinel"
if "$kernel_root/scripts/export-workload-oci.sh" "$canonical_root/workload-layout" workload-reference \
    "$unowned_compat" 7.2.2 "$export_root" workload-identity "$kernel_root/scripts/validate-oci.sh" > /dev/null 2>&1; then
    printf 'export replaced an unowned compatibility destination\n' >&2
    exit 1
fi
grep -q '^compat sentinel$' "$unowned_compat/sentinel"

printf 'OCI profile purpose, metadata, and descriptor checks passed\n'
