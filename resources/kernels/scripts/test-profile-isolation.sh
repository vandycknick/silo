#!/bin/sh

set -eu

if [ "$#" -ne 1 ]; then
    printf 'usage: %s KERNEL_ROOT\n' "$0" >&2
    exit 2
fi

kernel_root=$1
kernel_root=$(CDPATH='' cd -- "$kernel_root" && pwd)
temp_dir=$(mktemp -d)
trap 'rm -rf "$temp_dir"' 0 HUP INT TERM

identities() {
    make -s -C "$kernel_root" HOST_ARCH=aarch64 KERNEL_PROFILE="$1" \
        CACHE_ROOT="$temp_dir/cache" TARGET_ROOT="$temp_dir/target" kernel-identities
}

identities workload > "$temp_dir/workload-first"
identities rprobe > "$temp_dir/rprobe-second"
identities rprobe > "$temp_dir/rprobe-first"
identities workload > "$temp_dir/workload-second"
make -s -C "$kernel_root" HOST_ARCH=aarch64 \
    CACHE_ROOT="$temp_dir/cache" TARGET_ROOT="$temp_dir/target" kernel-identities > "$temp_dir/workload-default"
make -s -C "$kernel_root" HOST_ARCH=aarch64 KERNEL_PROFILE=workload KCFLAGS=-O0 \
    CACHE_ROOT="$temp_dir/cache" TARGET_ROOT="$temp_dir/target" kernel-identities > "$temp_dir/workload-o0"
make -s -C "$kernel_root" HOST_ARCH=aarch64 KERNEL_PROFILE=workload KCFLAGS=-O3 \
    CACHE_ROOT="$temp_dir/cache" TARGET_ROOT="$temp_dir/target" kernel-identities > "$temp_dir/workload-o3"
make -s -C "$kernel_root" HOST_ARCH=aarch64 KERNEL_PROFILE=workload CROSS_COMPILE=aarch64-linux-gnu- \
    CACHE_ROOT="$temp_dir/cache" TARGET_ROOT="$temp_dir/target" kernel-identities > "$temp_dir/workload-cross"

cmp "$temp_dir/workload-first" "$temp_dir/workload-second"
cmp "$temp_dir/workload-first" "$temp_dir/workload-default"
cmp "$temp_dir/rprobe-first" "$temp_dir/rprobe-second"

if [ "$(sed -n 's/^output=//p' "$temp_dir/workload-default")" != "$temp_dir/target/kernels/stable/arm64" ]; then
    printf 'default workload output no longer matches the publisher contract\n' >&2
    exit 1
fi
if [ "$(sed -n 's/^reference=//p' "$temp_dir/workload-default")" != 7.2.2 ]; then
    printf 'default workload reference no longer matches the publisher contract\n' >&2
    exit 1
fi

default_build_key=$(sed -n 's/^build_inputs=//p' "$temp_dir/workload-default")
o0_build_key=$(sed -n 's/^build_inputs=//p' "$temp_dir/workload-o0")
o3_build_key=$(sed -n 's/^build_inputs=//p' "$temp_dir/workload-o3")
cross_build_key=$(sed -n 's/^build_inputs=//p' "$temp_dir/workload-cross")
if [ "$default_build_key" = "$o0_build_key" ] || [ "$o0_build_key" = "$o3_build_key" ] || [ "$default_build_key" = "$cross_build_key" ]; then
    printf 'build-affecting flags did not change the build input key\n' >&2
    exit 1
fi

if [ "$(sed -n 's/^identity=//p' "$temp_dir/workload-o0")" = "$(sed -n 's/^identity=//p' "$temp_dir/workload-o3")" ]; then
    printf 'build-affecting flags did not change the complete identity\n' >&2
    exit 1
fi

workload_identity=$(sed -n 's/^identity=//p' "$temp_dir/workload-first")
rprobe_identity=$(sed -n 's/^identity=//p' "$temp_dir/rprobe-first")
if [ "$workload_identity" = "$rprobe_identity" ]; then
    printf 'workload and rprobe identities collided\n' >&2
    exit 1
fi

workload_source=$(sed -n 's/^source_dir=//p' "$temp_dir/workload-first")
rprobe_source=$(sed -n 's/^source_dir=//p' "$temp_dir/rprobe-first")
if [ "$workload_source" = "$rprobe_source" ]; then
    printf 'workload and rprobe derived sources collided\n' >&2
    exit 1
fi

if ! grep -q '^patches=sha256-e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855$' "$temp_dir/rprobe-first"; then
    printf 'rprobe patch set is not empty\n' >&2
    exit 1
fi

rprobe_fragments=$(sed -n 's/^fragments=//p' "$temp_dir/rprobe-first")
expected_fragments="$kernel_root/configs/rprobe.common.config $kernel_root/configs/rprobe.arm64.config"
if [ "$rprobe_fragments" != "$expected_fragments" ]; then
    printf 'rprobe inherited unexpected config fragments: %s\n' "$rprobe_fragments" >&2
    exit 1
fi

if make -s -C "$kernel_root" HOST_ARCH=x86_64 KERNEL_PROFILE=rprobe kernel-identities > /dev/null 2>&1; then
    printf 'x86_64 rprobe profile was not rejected\n' >&2
    exit 1
fi

if make -s -C "$kernel_root" HOST_ARCH=aarch64 KERNEL_PROFILE=invalid kernel-identities > /dev/null 2>&1; then
    printf 'unknown kernel profile was not rejected\n' >&2
    exit 1
fi

if make -s -C "$kernel_root" HOST_ARCH=aarch64 KERNEL_PROFILE=rprobe publish > /dev/null 2>&1; then
    printf 'rprobe publication was not rejected\n' >&2
    exit 1
fi

printf 'fixture\n' > "$temp_dir/path with whitespace"
if "$kernel_root/scripts/kernel-input-key.sh" config "$temp_dir/path with whitespace" > /dev/null 2>&1; then
    printf 'input key accepted a path containing whitespace\n' >&2
    exit 1
fi

printf 'profile isolation and order identity checks passed\n'
