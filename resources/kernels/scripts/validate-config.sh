#!/bin/sh

set -eu

if [ "$#" -lt 2 ]; then
    echo "usage: $0 RESOLVED_CONFIG FRAGMENT..." >&2
    exit 2
fi

resolved=$1
shift

awk -v resolved="$resolved" '
function symbol(line, value) {
    if (line ~ /^CONFIG_[A-Za-z0-9_]+=/) {
        split(line, parts, "=")
        return parts[1]
    }
    if (line ~ /^# CONFIG_[A-Za-z0-9_]+ is not set$/) {
        value = line
        sub(/^# /, "", value)
        sub(/ is not set$/, "", value)
        return value
    }
    return ""
}

function setting(line, value) {
    if (line ~ /^CONFIG_[A-Za-z0-9_]+=/) {
        value = line
        sub(/^[^=]+=/, "", value)
        return value
    }
    return "n"
}

FILENAME == resolved {
    name = symbol($0)
    if (name != "")
        actual[name] = setting($0)
    next
}

{
    name = symbol($0)
    if (name == "")
        next

    if (name in expected) {
        printf "duplicate config ownership for %s: %s and %s\n", name, owner[name], FILENAME > "/dev/stderr"
        failed = 1
        next
    }

    expected[name] = setting($0)
    owner[name] = FILENAME
}

END {
    for (name in expected) {
        resolved_value = (name in actual) ? actual[name] : "n"
        if (resolved_value != expected[name]) {
            printf "%s requests %s=%s, resolved value is %s\n", owner[name], name, expected[name], resolved_value > "/dev/stderr"
            failed = 1
        }
    }
    exit failed
}
' "$resolved" "$@"
