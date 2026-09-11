#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
    printf 'usage: %s <immutable-system-image-reference>\n' "$0" >&2
    exit 2
fi

image=$1
case "$image" in
    *@sha256:*) ;;
    *)
        printf 'qualification requires an immutable image digest, got %s\n' "$image" >&2
        exit 2
        ;;
esac

root=$(mktemp -d "${TMPDIR:-/tmp}/silo-system-qualification.XXXXXX")
daemon_pid=
cleanup() {
    if [ -n "$daemon_pid" ] && kill -0 "$daemon_pid" 2>/dev/null; then
        kill -TERM "$daemon_pid"
        wait "$daemon_pid" || true
    fi
}
trap cleanup EXIT INT TERM

export HOME="$root/home"
export XDG_CONFIG_HOME="$root/config"
export XDG_CACHE_HOME="$root/cache"
export XDG_DATA_HOME="$root/data"
export XDG_STATE_HOME="$root/state"
export XDG_RUNTIME_DIR="$root/run"
mkdir -p "$HOME" "$XDG_CONFIG_HOME/silo" "$XDG_CACHE_HOME" "$XDG_DATA_HOME" "$XDG_STATE_HOME" "$XDG_RUNTIME_DIR"
chmod 0700 "$XDG_RUNTIME_DIR"

config="$XDG_CONFIG_HOME/silo/config.yaml"
{
    printf 'daemon:\n'
    printf '  version: "1"\n'
    printf '  system:\n'
    printf '    image: "%s"\n' "$image"
    printf '    storage:\n'
    printf '      root-size: "2GiB"\n'
    printf '      data-size: "1GiB"\n'
    printf '    docker:\n'
    printf '      compatibility-socket: disabled\n'
} > "$config"

silo=${SILO_BIN:-target/release/silo}
socket="$HOME/.docker/run/silo.sock"
start_daemon() {
    "$silo" daemon up --foreground >"$root/foreground.log" 2>&1 &
    daemon_pid=$!
    deadline=$(($(date +%s) + 180))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        if [ -S "$socket" ] && docker --host "unix://$socket" version >/dev/null 2>&1; then
            return 0
        fi
        if ! kill -0 "$daemon_pid" 2>/dev/null; then
            wait "$daemon_pid" || true
            cat "$root/foreground.log" >&2
            return 1
        fi
        sleep 1
    done
    printf 'timed out waiting for Docker endpoint %s\n' "$socket" >&2
    cat "$root/foreground.log" >&2
    return 1
}

stop_daemon() {
    kill -TERM "$daemon_pid"
    wait "$daemon_pid"
    daemon_pid=
}

start_daemon
docker --host "unix://$socket" info >/dev/null
docker --host "unix://$socket" volume create silo-qualification >/dev/null
docker --host "unix://$socket" run --rm \
    --volume silo-qualification:/qualification \
    docker.io/library/busybox@sha256:9db7b59979c38555a39def84a31fb98b5296952f9e3afd4f6f11f05b07adfab0 \
    sh -c 'printf qualified > /qualification/marker'
machine_before=$(jq -er '.active_machine_id' "$XDG_DATA_HOME/silo/daemon/system.json")
stop_daemon

start_daemon
machine_after=$(jq -er '.active_machine_id' "$XDG_DATA_HOME/silo/daemon/system.json")
test "$machine_before" = "$machine_after"
test "$(docker --host "unix://$socket" run --rm \
    --volume silo-qualification:/qualification:ro \
    docker.io/library/busybox@sha256:9db7b59979c38555a39def84a31fb98b5296952f9e3afd4f6f11f05b07adfab0 \
    cat /qualification/marker)" = qualified
stop_daemon

printf 'qualified image=%s machine=%s\n' "$image" "$machine_after"
