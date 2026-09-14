#!/bin/sh
set -eu

if [ "$#" -lt 2 ]; then
    printf 'usage: %s DESTINATION OWNED_ROOT [FORBIDDEN...]\n' "$0" >&2
    exit 2
fi
destination=$1
root=$2
shift 2

for path in "$destination" "$root" "$@"; do
    case "$path" in
        /*) ;;
        *) printf 'owned path must be absolute: %s\n' "$path" >&2; exit 1 ;;
    esac
    case "$path" in *[[:space:]]*) printf 'owned path contains unsupported whitespace: %s\n' "$path" >&2; exit 1 ;; esac
    case "$path" in
        *//*|*/./*|*/../*|*/.|*/..)
            printf 'owned path is not lexically normalized: %s\n' "$path" >&2
            exit 1
            ;;
    esac
done
destination_physical=$(realpath -m -- "$destination")
root_physical=$(realpath -m -- "$root")
home_physical=$(realpath -m -- "${HOME:-/}")
if [ "$root_physical" = / ] || [ "$root_physical" = "$home_physical" ]; then
    printf 'unsafe ownership root: %s\n' "$root" >&2
    exit 1
fi
if [ -n "${REPO_ROOT:-}" ] && [ "$root_physical" = "$(realpath -m -- "$REPO_ROOT")" ]; then
    printf 'unsafe ownership root: %s\n' "$root" >&2
    exit 1
fi
case "$destination_physical" in "$root_physical"/*) ;; *) printf 'destination is outside owned root: %s\n' "$destination" >&2; exit 1 ;; esac
for forbidden in "$@"; do
    forbidden_physical=$(realpath -m -- "$forbidden")
    if [ "$root_physical" = "$forbidden_physical" ]; then printf 'owned root equals forbidden path: %s\n' "$root" >&2; exit 1; fi
    if [ "$destination_physical" = "$forbidden_physical" ]; then printf 'destination equals forbidden path: %s\n' "$destination" >&2; exit 1; fi
    case "$forbidden_physical/" in "$destination_physical/"*) printf 'destination is an ancestor of forbidden path: %s\n' "$destination" >&2; exit 1 ;; esac
done

if [ -L "$root" ]; then
    printf 'owned root is a symlink: %s\n' "$root" >&2
    exit 1
fi
current=$root
old_ifs=$IFS
IFS=/
for component in ${destination#"$root"/}; do
    IFS=$old_ifs
    current="$current/$component"
    if [ -L "$current" ]; then
        printf 'owned path traverses a symlink: %s\n' "$current" >&2
        exit 1
    fi
    IFS=/
done
IFS=$old_ifs
