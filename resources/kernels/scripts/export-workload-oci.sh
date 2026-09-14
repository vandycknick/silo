#!/bin/sh
set -eu

if [ "$#" -ne 7 ]; then
    printf 'usage: %s SOURCE SOURCE_REF DEST DEST_REF DEST_ROOT IDENTITY VALIDATOR\n' "$0" >&2
    exit 2
fi
source=$1; source_ref=$2; dest=$3; dest_ref=$4; root=$5; identity=$6; validator=$7
"$(dirname "$0")/validate-owned-path.sh" "$dest" "$root" "$source"
dest_physical=$(realpath -m -- "$dest")
source_physical=$(realpath -m -- "$source")
case "$dest_physical/" in "$source_physical/"*) printf 'workload OCI destination overlaps canonical source\n' >&2; exit 1 ;; esac
mkdir -p "$(dirname "$dest")"
temporary=$(mktemp -d "$(dirname "$dest")/.silo-workload-export.XXXXXX")
trap 'rm -rf "$temporary"' 0 HUP INT TERM
oras cp --from-oci-layout --to-oci-layout "$source:$source_ref" "$temporary:$dest_ref"
"$validator" "$temporary" "$dest_ref" workload
printf '%s\n' "$identity" > "$temporary/.silo-kernel-oci-workload"
if [ -e "$dest" ]; then
    if [ -L "$dest/.silo-kernel-oci-workload" ] || [ "$(sed -n '1p' "$dest/.silo-kernel-oci-workload" 2>/dev/null)" != "$identity" ]; then
        "$validator" "$dest" "$dest_ref" workload || { printf 'refusing to replace unowned workload OCI destination: %s\n' "$dest" >&2; exit 1; }
    fi
    previous=$(mktemp -d "$(dirname "$dest")/.silo-workload-previous.XXXXXX")
    rmdir "$previous"
    mv "$dest" "$previous"
    if ! mv "$temporary" "$dest"; then mv "$previous" "$dest"; exit 1; fi
    rm -rf "$previous"
else
    mv "$temporary" "$dest"
fi
trap - 0 HUP INT TERM
