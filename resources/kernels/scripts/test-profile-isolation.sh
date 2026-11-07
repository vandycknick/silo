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
    profile=$1
    shift
    make -s -C "$kernel_root" HOST_ARCH=aarch64 KERNEL_PROFILE="$profile" \
        CACHE_ROOT="$temp_dir/cache" TARGET_ROOT="$temp_dir/target" "$@" kernel-identities
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
repo_root=$(CDPATH= cd -- "$kernel_root/../.." && pwd)
expected_fragments="$repo_root/guest/rprobe/kernel/common.config $repo_root/guest/rprobe/kernel/arm64.config"
if [ "$rprobe_fragments" != "$expected_fragments" ]; then
    printf 'rprobe inherited unexpected config fragments: %s\n' "$rprobe_fragments" >&2
    exit 1
fi

# Exercise the selected patch inputs, not Makefile source text. Mutating an
# isolated shared patch must affect supported workload identities only.
mkdir -p "$temp_dir/resources"
cp -R "$kernel_root" "$temp_dir/resources/kernels"
isolated_resources="$temp_dir/resources"
live_patch="$isolated_resources/kernels/patches/live/0001-virtio-silo-vmgenid.patch"
shared_key=$("$kernel_root/scripts/kernel-input-key.sh" patches "$live_patch")
empty_key=$("$kernel_root/scripts/kernel-input-key.sh" patches)
for track in stable longterm longterm5; do
    identities workload TRACK="$track" RESOURCE_ROOT="$isolated_resources" REPO_ROOT="$repo_root" > "$temp_dir/workload-$track-before"
    identities rprobe TRACK="$track" RESOURCE_ROOT="$isolated_resources" REPO_ROOT="$repo_root" > "$temp_dir/rprobe-$track-before"
    expected_key=$shared_key
    if [ "$track" = longterm5 ]; then expected_key=$empty_key; fi
    if [ "$(sed -n 's/^patches=//p' "$temp_dir/workload-$track-before")" != "$expected_key" ]; then
        printf 'unexpected shared workload patch selection on %s\n' "$track" >&2
        exit 1
    fi
done
x86_patch="$isolated_resources/kernels/patches/x86_64/0001-x86-krun-i8042-poweroff.patch"
for track in stable longterm longterm5; do
    make -s -C "$kernel_root" HOST_ARCH=x86_64 TRACK="$track" \
        RESOURCE_ROOT="$isolated_resources" REPO_ROOT="$repo_root" kernel-identities > "$temp_dir/x86-$track"
    if [ "$track" = longterm5 ]; then
        expected_key=$("$kernel_root/scripts/kernel-input-key.sh" patches "$x86_patch")
    else
        expected_key=$("$kernel_root/scripts/kernel-input-key.sh" patches "$live_patch" "$x86_patch")
    fi
    if [ "$(sed -n 's/^patches=//p' "$temp_dir/x86-$track")" != "$expected_key" ]; then
        printf 'architecture patch ordering changed on %s\n' "$track" >&2
        exit 1
    fi
done
printf '\n' >> "$live_patch"
for track in stable longterm longterm5; do
    identities workload TRACK="$track" RESOURCE_ROOT="$isolated_resources" REPO_ROOT="$repo_root" > "$temp_dir/workload-$track-after"
    identities rprobe TRACK="$track" RESOURCE_ROOT="$isolated_resources" REPO_ROOT="$repo_root" > "$temp_dir/rprobe-$track-after"
    cmp "$temp_dir/rprobe-$track-before" "$temp_dir/rprobe-$track-after"
    if [ "$track" = longterm5 ]; then
        cmp "$temp_dir/workload-$track-before" "$temp_dir/workload-$track-after"
    else
        for field in patches identity source_dir build_dir canonical_output; do
            before=$(sed -n "s/^$field=//p" "$temp_dir/workload-$track-before")
            after=$(sed -n "s/^$field=//p" "$temp_dir/workload-$track-after")
            if [ "$before" = "$after" ]; then
                printf 'shared patch mutation did not change %s on %s\n' "$field" "$track" >&2
                exit 1
            fi
        done
    fi
done

# Unit boundary for emitted-config validation. Check the actual workload
# fragments against the contract before testing missing or changed settings.
cat > "$temp_dir/required.config" <<'EOF'
CONFIG_VIRTIO_SILO_VMGENID=y
CONFIG_VMGENID=y
CONFIG_BINFMT_MISC=y
CONFIG_EXT4_FS=y
CONFIG_VIRTIO_FS=y
CONFIG_EFI_PARTITION=y
CONFIG_MSDOS_PARTITION=y
CONFIG_VFAT_FS=y
CONFIG_FAT_FS=y
CONFIG_NLS=y
CONFIG_NLS_CODEPAGE_437=y
CONFIG_NLS_ISO8859_1=y
CONFIG_NLS_UTF8=y
CONFIG_FAT_DEFAULT_CODEPAGE=437
CONFIG_FAT_DEFAULT_IOCHARSET="iso8859-1"
CONFIG_ARM64_4K_PAGES=y
CONFIG_ARM64_PAGE_SHIFT=12
EOF
cat "$kernel_root/configs/common.config" "$kernel_root/configs/arm64.config" > "$temp_dir/workload.config"
"$kernel_root/scripts/validate-config.sh" "$temp_dir/workload.config" "$temp_dir/required.config"
cp "$temp_dir/required.config" "$temp_dir/emitted.config"
"$kernel_root/scripts/validate-config.sh" "$temp_dir/emitted.config" "$temp_dir/required.config"
while IFS='=' read -r symbol expected; do
    case "$expected" in
        y) settings='missing n m' ;;
        437) settings='missing 850' ;;
        '"iso8859-1"') settings='missing "utf8"' ;;
        12) settings='missing 14 16' ;;
        *) printf 'unhandled config expectation: %s=%s\n' "$symbol" "$expected" >&2; exit 1 ;;
    esac
    for setting in $settings; do
        awk -F= -v symbol="$symbol" -v setting="$setting" '
            $1 != symbol { print; next }
            setting != "missing" { print symbol "=" setting }
        ' "$temp_dir/required.config" > "$temp_dir/emitted.config"
        if "$kernel_root/scripts/validate-config.sh" "$temp_dir/emitted.config" "$temp_dir/required.config" > /dev/null 2>&1; then
            printf 'emitted config accepted incorrect %s: %s\n' "$symbol" "$setting" >&2
            exit 1
        fi
    done
done < "$temp_dir/required.config"

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

printf 'first archive contents\n' > "$temp_dir/initramfs"
identities rprobe KERNEL_INITRAMFS="$temp_dir/initramfs" > "$temp_dir/embedded-first"
cp "$temp_dir/initramfs" "$temp_dir/relocated"
identities rprobe KERNEL_INITRAMFS="$temp_dir/relocated" > "$temp_dir/embedded-relocated"
cmp "$temp_dir/embedded-first" "$temp_dir/embedded-relocated"
printf 'changed archive contents\n' > "$temp_dir/initramfs"
identities rprobe KERNEL_INITRAMFS="$temp_dir/initramfs" > "$temp_dir/embedded-changed"
if [ "$(sed -n 's/^identity=//p' "$temp_dir/embedded-first")" = "$(sed -n 's/^identity=//p' "$temp_dir/embedded-changed")" ]; then
    printf 'embedded archive contents did not change kernel identity\n' >&2
    exit 1
fi
if identities workload KERNEL_INITRAMFS="$temp_dir/initramfs" > /dev/null 2>&1; then
    printf 'workload accepted a probe initramfs\n' >&2
    exit 1
fi
if identities rprobe KERNEL_INITRAMFS="$temp_dir/missing" > /dev/null 2>&1; then
    printf 'missing archive accepted\n' >&2
    exit 1
fi
printf 'profile isolation, embedded archive and order identity checks passed\n'
