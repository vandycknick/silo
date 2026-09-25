#!/bin/sh

set -eu

if [ "$#" -lt 1 ]; then
    printf 'usage: %s LABEL [FILE...]\n' "$0" >&2
    exit 2
fi

label=$1
shift

for path in "$@"; do
    case "$path" in
        *[[:space:]]*)
            printf '%s path contains unsupported whitespace: %s\n' "$label" "$path" >&2
            exit 1
            ;;
    esac
    if [ ! -f "$path" ]; then
        printf '%s input is not a regular file (paths containing whitespace are unsupported): %s\n' "$label" "$path" >&2
        exit 1
    fi
done

{
    for path in "$@"; do
        sha256sum "$path" | cut -d' ' -f1
    done
} | sha256sum | sed 's/^/sha256-/' | cut -d' ' -f1
