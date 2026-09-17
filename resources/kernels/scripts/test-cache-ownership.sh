#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then printf 'usage: %s KERNEL_ROOT\n' "$0" >&2; exit 2; fi
kernel_root=$1
temp_dir=$(mktemp -d)
cleanup() { chmod -R u+w "$temp_dir" 2>/dev/null || true; rm -rf "$temp_dir"; }
trap cleanup 0 HUP INT TERM

download_root="$temp_dir/downloads"
mkdir -p "$download_root"
printf 'do not delete\n' > "$download_root/bad.tar.xz"
if "$kernel_root/scripts/fetch-source.sh" https://example.invalid/source \
    aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
    "$download_root/bad.tar.xz" "$download_root" > /dev/null 2>&1; then
    printf 'fetch accepted an existing bad download\n' >&2
    exit 1
fi
grep -q '^do not delete$' "$download_root/bad.tar.xz"

archive_root="$temp_dir/archive/linux-fixture"
mkdir -p "$archive_root"
printf 'fixture\n' > "$archive_root/value"
tar -cJf "$temp_dir/source.tar.xz" -C "$temp_dir/archive" linux-fixture
sha256=$(sha256sum "$temp_dir/source.tar.xz" | cut -d' ' -f1)
pristine_root="$temp_dir/pristine-root"
mkdir -p "$pristine_root"
pristine="$pristine_root/source"
"$kernel_root/scripts/prepare-pristine.sh" "$temp_dir/source.tar.xz" "$sha256" "$pristine" "$pristine_root"
"$kernel_root/scripts/prepare-pristine.sh" "$temp_dir/source.tar.xz" "$sha256" "$pristine" "$pristine_root"
grep -q '^fixture$' "$pristine/value"

unowned="$pristine_root/unowned"
mkdir "$unowned"
printf 'pristine sentinel\n' > "$unowned/sentinel"
if "$kernel_root/scripts/prepare-pristine.sh" "$temp_dir/source.tar.xz" "$sha256" "$unowned" "$pristine_root" > /dev/null 2>&1; then
    printf 'prepare-pristine replaced an unowned destination\n' >&2
    exit 1
fi
grep -q '^pristine sentinel$' "$unowned/sentinel"

mkdir "$temp_dir/pristine-symlink-target"
printf 'symlink sentinel\n' > "$temp_dir/pristine-symlink-target/sentinel"
ln -s "$temp_dir/pristine-symlink-target" "$pristine_root/symlink"
if "$kernel_root/scripts/prepare-pristine.sh" "$temp_dir/source.tar.xz" "$sha256" "$pristine_root/symlink" "$pristine_root" > /dev/null 2>&1; then
    printf 'prepare-pristine accepted a symlink destination\n' >&2
    exit 1
fi
grep -q '^symlink sentinel$' "$temp_dir/pristine-symlink-target/sentinel"

owned_root="$temp_dir/owned"
outside="$temp_dir/outside"
mkdir -p "$owned_root" "$outside"
printf 'outside sentinel\n' > "$outside/sentinel"
for destination in "$owned_root/../outside" "$owned_root/./child" "$owned_root//child"; do
    if "$kernel_root/scripts/validate-owned-path.sh" "$destination" "$owned_root" > /dev/null 2>&1; then
        printf 'path validator accepted a non-normalized destination: %s\n' "$destination" >&2
        exit 1
    fi
done
grep -q '^outside sentinel$' "$outside/sentinel"

fake_home="$temp_dir/home"
fake_repo="$temp_dir/repository"
mkdir -p "$fake_home" "$fake_repo"
printf 'home sentinel\n' > "$fake_home/sentinel"
printf 'repo sentinel\n' > "$fake_repo/sentinel"
if HOME="$fake_home" "$kernel_root/scripts/validate-owned-path.sh" "$fake_home/owned/item" "$owned_root/../home" > /dev/null 2>&1; then
    printf 'path validator accepted a physical home alias as its root\n' >&2
    exit 1
fi
if REPO_ROOT="$fake_repo" "$kernel_root/scripts/validate-owned-path.sh" "$fake_repo/owned/item" "$owned_root/../repository" > /dev/null 2>&1; then
    printf 'path validator accepted a physical repository alias as its root\n' >&2
    exit 1
fi
grep -q '^home sentinel$' "$fake_home/sentinel"
grep -q '^repo sentinel$' "$fake_repo/sentinel"

physical_temp=$(realpath -m -- "$temp_dir")
case "$temp_dir:$physical_temp" in
    /var/*:/private/var/*)
        "$kernel_root/scripts/validate-owned-path.sh" "$temp_dir/var-alias-root/child" "$temp_dir/var-alias-root"
        ;;
esac

printf 'download and pristine ownership checks passed\n'
