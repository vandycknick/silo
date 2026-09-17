#!/bin/sh
set -eu

if [ "$#" -ne 4 ]; then
    printf 'usage: %s URL SHA256 TARBALL DOWNLOAD_ROOT\n' "$0" >&2
    exit 2
fi
url=$1
sha256=$2
tarball=$3
root=$4
"$(dirname "$0")/validate-owned-path.sh" "$tarball" "$root"
mkdir -p "$(dirname "$tarball")"
if [ -e "$tarball" ]; then
    if printf '%s  %s\n' "$sha256" "$tarball" | sha256sum --check --status; then exit 0; fi
    printf 'existing download has the wrong checksum; refusing to remove it: %s\n' "$tarball" >&2
    exit 1
fi
temporary=$(mktemp "$(dirname "$tarball")/.silo-download.XXXXXX")
trap 'rm -f "$temporary"' 0 HUP INT TERM
curl -fL "$url" -o "$temporary"
printf '%s  %s\n' "$sha256" "$temporary" | sha256sum --check --status
if ! ln "$temporary" "$tarball" 2>/dev/null; then
    printf '%s  %s\n' "$sha256" "$tarball" | sha256sum --check --status
fi
rm -f "$temporary"
trap - 0 HUP INT TERM
