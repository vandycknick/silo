#!/bin/sh
set -eu

if [ "$#" -ne 4 ]; then
    printf 'usage: %s TARBALL SHA256 PRISTINE PRISTINE_ROOT\n' "$0" >&2
    exit 2
fi
tarball=$1
sha256=$2
pristine=$3
root=$4
"$(dirname "$0")/validate-owned-path.sh" "$pristine" "$root"
if [ -e "$pristine" ]; then
    if [ ! -L "$pristine/.silo-kernel-pristine" ] && \
        [ "$(sed -n '1p' "$pristine/.silo-kernel-pristine" 2>/dev/null)" = "$sha256" ] && \
        ! find "$pristine" \( -type f -o -type d \) -perm /222 -print -quit | grep -q .; then
        exit 0
    fi
    printf 'refusing to replace unowned pristine destination: %s\n' "$pristine" >&2
    exit 1
fi
mkdir -p "$(dirname "$pristine")"
temporary=$(mktemp -d "$(dirname "$pristine")/.silo-pristine.XXXXXX")
cleanup() { chmod -R u+w "$temporary" 2>/dev/null || true; rm -rf "$temporary"; }
trap cleanup 0 HUP INT TERM
tar -xJf "$tarball" --strip-components=1 -C "$temporary"
printf '%s\n' "$sha256" > "$temporary/.silo-kernel-pristine"
chmod -R a-w "$temporary"
mv "$temporary" "$pristine"
trap - 0 HUP INT TERM
