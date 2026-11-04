#!/bin/sh

set -eu

if [ "$#" -ne 1 ]; then
    printf 'usage: %s KERNEL_ROOT\n' "$0" >&2
    exit 2
fi

kernel_root=$1
temp_dir=$(mktemp -d)
cleanup() {
    chmod -R u+w "$temp_dir" 2>/dev/null || true
    rm -rf "$temp_dir"
}
trap cleanup 0 HUP INT TERM
pristine="$temp_dir/pristine"
mkdir -p "$pristine"
printf 'base\n' > "$pristine/value"
printf 'fixture-source-hash\n' > "$pristine/.silo-kernel-pristine"
chmod -R a-w "$pristine"
derived_root="$temp_dir/derived"
mkdir -p "$derived_root"

printf '%s\n' '--- a/value' '+++ b/value' '@@ -1 +1 @@' '-base' '+first' > "$temp_dir/01.patch"
printf '%s\n' '--- a/value' '+++ b/value' '@@ -1 +1 @@' '-first' '+second' > "$temp_dir/02.patch"
# Neither side matches the partially patched tree. Repeating 01.patch is not
# an invalid-patch fixture: patch --batch may legitimately apply it in reverse.
printf '%s\n' '--- a/value' '+++ b/value' '@@ -1 +1 @@' '-absent-before' '+absent-after' > "$temp_dir/invalid.patch"

derive() {
    profile=$1
    shift
    "$kernel_root/scripts/derive-source.sh" fixture-source-hash "$pristine" \
        "$derived_root/$profile" "$derived_root" "$profile-identity" "$@"
}

derive workload "$temp_dir/01.patch"
derive rprobe "$temp_dir/01.patch" "$temp_dir/02.patch"
derive workload "$temp_dir/01.patch"
cmp "$pristine/value" /dev/stdin <<EOF
base
EOF
cmp "$derived_root/rprobe/value" /dev/stdin <<EOF
second
EOF
rm -rf "$derived_root/workload" "$derived_root/rprobe"
derive rprobe "$temp_dir/01.patch" "$temp_dir/02.patch"
derive workload "$temp_dir/01.patch"
cmp "$derived_root/rprobe/value" /dev/stdin <<EOF
second
EOF

# No-patch probe derivation is pristine, regardless of workload patch order.
derive probe-unpatched
cmp "$pristine/value" "$derived_root/probe-unpatched/value"

# Failed ordered application must not replace an existing owned source, make
# pristine writable, or leave a partially published destination.
if derive workload "$temp_dir/02.patch" > /dev/null 2>&1; then
    printf 'out-of-order patch application succeeded\n' >&2
    exit 1
fi
cmp "$derived_root/workload/value" /dev/stdin <<EOF
first
EOF
if derive incomplete "$temp_dir/01.patch" "$temp_dir/invalid.patch" > /dev/null 2>&1; then
    printf 'invalid second patch application succeeded\n' >&2
    exit 1
fi
if [ -e "$derived_root/incomplete" ]; then
    printf 'failed derivation published a partial source\n' >&2
    exit 1
fi
if find "$pristine" \( -type f -o -type d \) -perm /222 -print -quit | grep -q .; then
    printf 'source derivation changed pristine permissions\n' >&2
    exit 1
fi

if "$kernel_root/scripts/derive-source.sh" fixture-source-hash "$pristine" "$pristine" "$derived_root" bad > /dev/null 2>&1; then
    printf 'source derivation accepted the pristine source as its destination\n' >&2
    exit 1
fi
cmp "$pristine/value" /dev/stdin <<EOF
base
EOF

mkdir "$temp_dir/symlink-target"
printf 'symlink sentinel\n' > "$temp_dir/symlink-target/sentinel"
ln -s "$temp_dir/symlink-target" "$derived_root/symlink"
if "$kernel_root/scripts/derive-source.sh" fixture-source-hash "$pristine" "$derived_root/symlink" "$derived_root" bad > /dev/null 2>&1; then
    printf 'source derivation accepted a symlink destination\n' >&2
    exit 1
fi
grep -q '^symlink sentinel$' "$temp_dir/symlink-target/sentinel"

mkdir "$derived_root/unowned"
printf 'unowned sentinel\n' > "$derived_root/unowned/sentinel"
if "$kernel_root/scripts/derive-source.sh" fixture-source-hash "$pristine" "$derived_root/unowned" "$derived_root" bad > /dev/null 2>&1; then
    printf 'source derivation replaced an unowned destination\n' >&2
    exit 1
fi
grep -q '^unowned sentinel$' "$derived_root/unowned/sentinel"

mkdir "$derived_root/wrong-identity"
printf 'identity sentinel\n' > "$derived_root/wrong-identity/sentinel"
printf 'other-identity\n' > "$derived_root/wrong-identity/.silo-kernel-source-identity"
if "$kernel_root/scripts/derive-source.sh" fixture-source-hash "$pristine" "$derived_root/wrong-identity" "$derived_root" bad > /dev/null 2>&1; then
    printf 'source derivation replaced a destination with an unowned identity\n' >&2
    exit 1
fi
grep -q '^identity sentinel$' "$derived_root/wrong-identity/sentinel"

if "$kernel_root/scripts/derive-source.sh" fixture-source-hash "$pristine" \
    "$derived_root/../pristine/attack" "$derived_root" bad > /dev/null 2>&1; then
    printf 'source derivation accepted a normalized pristine alias\n' >&2
    exit 1
fi
cmp "$pristine/value" /dev/stdin <<EOF
base
EOF

printf 'verified pristine copy and ordered patch derivation checks passed\n'
