#!/bin/sh

set -eu

if [ "$#" -lt 5 ]; then
    printf 'usage: %s SOURCE_SHA256 PRISTINE DERIVED DERIVED_ROOT IDENTITY [PATCH...]\n' "$0" >&2
    exit 2
fi

source_sha256=$1
pristine=$2
derived=$3
derived_root=$4
identity=$5
shift 5
identity_file="$derived/.silo-kernel-source-identity"

for path in "$pristine" "$derived" "$derived_root" "$@"; do
    case "$path" in
        *[[:space:]]*)
            printf 'source derivation path contains unsupported whitespace: %s\n' "$path" >&2
            exit 1
            ;;
    esac
done

if [ ! -d "$pristine" ] || [ "$(sed -n '1p' "$pristine/.silo-kernel-pristine" 2>/dev/null)" != "$source_sha256" ]; then
    printf 'pristine source verification failed: %s\n' "$pristine" >&2
    exit 1
fi

case "$derived" in
    "$derived_root"/*) ;;
    *) printf 'derived source is outside its owned root: %s\n' "$derived" >&2; exit 1 ;;
esac
"$(dirname "$0")/validate-owned-path.sh" "$derived" "$derived_root" "$pristine"
derived_physical=$(realpath -m -- "$derived")
pristine_physical=$(realpath -m -- "$pristine")
case "$derived_physical/" in "$pristine_physical/"*) printf 'derived source overlaps pristine source\n' >&2; exit 1 ;; esac
case "$pristine_physical/" in "$derived_physical/"*) printf 'derived source is an ancestor of pristine source\n' >&2; exit 1 ;; esac
if [ -L "$derived" ]; then
    printf 'derived source destination is a symlink: %s\n' "$derived" >&2
    exit 1
fi
if [ -e "$derived" ] && { [ -L "$identity_file" ] || [ "$(sed -n '1p' "$identity_file" 2>/dev/null)" != "$identity" ]; }; then
    printf 'refusing to replace unowned derived source: %s\n' "$derived" >&2
    exit 1
fi
if find "$pristine" \( -type f -o -type d \) -perm /222 -print -quit | grep -q .; then
    printf 'pristine source is writable: %s\n' "$pristine" >&2
    exit 1
fi

mkdir -p "$(dirname "$derived")"
temporary=$(mktemp -d "$(dirname "$derived")/.silo-source.tmp.XXXXXX")
trap 'rm -rf "$temporary"' 0 HUP INT TERM
cp -a "$pristine/." "$temporary/"
chmod -R u+w "$temporary"
for patch_file in "$@"; do
    patch --fuzz=0 --batch -d "$temporary" -p1 < "$patch_file"
done
printf '%s\n' "$identity" > "$temporary/.silo-kernel-source-identity"
if [ -e "$derived" ]; then
    previous=$(mktemp -d "$(dirname "$derived")/.silo-source.previous.XXXXXX")
    rmdir "$previous"
    mv "$derived" "$previous"
    if ! mv "$temporary" "$derived"; then
        mv "$previous" "$derived"
        exit 1
    fi
    rm -rf "$previous"
else
    mv "$temporary" "$derived"
fi
trap - 0 HUP INT TERM
