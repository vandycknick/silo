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
engine() {
    docker --host "unix://$socket" "$@"
}
start_daemon() {
    "$silo" daemon up --foreground >"$root/foreground.log" 2>&1 &
    daemon_pid=$!
    deadline=$(($(date +%s) + 180))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        if [ -S "$socket" ] && engine version >/dev/null 2>&1; then
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
docker --version
docker compose version
docker buildx version
engine info >/dev/null
engine volume create silo-qualification >/dev/null
engine network create silo-qualification >/dev/null
engine run --rm \
    --volume silo-qualification:/qualification \
    docker.io/library/busybox@sha256:9db7b59979c38555a39def84a31fb98b5296952f9e3afd4f6f11f05b07adfab0 \
    sh -c 'printf qualified > /qualification/marker'
engine run --detach --name silo-qualification-restart --restart unless-stopped \
    --network silo-qualification \
    docker.io/library/busybox@sha256:9db7b59979c38555a39def84a31fb98b5296952f9e3afd4f6f11f05b07adfab0 \
    sleep 3600
engine exec silo-qualification-restart true
engine logs silo-qualification-restart >/dev/null
engine run --detach --name silo-qualification-limits --cpus 0.5 --memory 64m \
    docker.io/library/busybox@sha256:9db7b59979c38555a39def84a31fb98b5296952f9e3afd4f6f11f05b07adfab0 sleep 3600
test "$(engine inspect silo-qualification-limits --format '{{.HostConfig.NanoCpus}}')" = 500000000
test "$(engine inspect silo-qualification-limits --format '{{.HostConfig.Memory}}')" = 67108864
engine rm --force silo-qualification-limits >/dev/null

engine run --rm --volume "$HOME:/host" \
    docker.io/library/busybox@sha256:9db7b59979c38555a39def84a31fb98b5296952f9e3afd4f6f11f05b07adfab0 \
    sh -c 'printf shared > /host/qualification-share'
test "$(cat "$HOME/qualification-share")" = shared

engine run --detach --name silo-qualification-http --publish 127.0.0.1::8080 \
    docker.io/library/busybox@sha256:9db7b59979c38555a39def84a31fb98b5296952f9e3afd4f6f11f05b07adfab0 \
    httpd -f -p 8080
published=$(engine port silo-qualification-http 8080/tcp)
curl --fail --silent --show-error "http://$published/" >/dev/null
engine rm --force silo-qualification-http >/dev/null

build_context="$root/build"
mkdir -p "$build_context"
dd if=/dev/zero of="$build_context/payload" bs=1M count=16 >/dev/null 2>&1
{
    printf 'FROM docker.io/library/busybox@sha256:9db7b59979c38555a39def84a31fb98b5296952f9e3afd4f6f11f05b07adfab0\n'
    printf 'COPY payload /payload\n'
} > "$build_context/Dockerfile"
engine build --tag silo-qualification-build "$build_context" >/dev/null

compose="$root/compose.yaml"
{
    printf 'services:\n'
    printf '  fixture:\n'
    printf '    image: docker.io/library/busybox@sha256:9db7b59979c38555a39def84a31fb98b5296952f9e3afd4f6f11f05b07adfab0\n'
    printf '    command: ["sleep", "3600"]\n'
} > "$compose"
docker --host "unix://$socket" compose --file "$compose" up --detach
docker --host "unix://$socket" compose --file "$compose" down

docker --host "unix://$socket" buildx create \
    --name silo-qualification-builder \
    --driver docker-container \
    --driver-opt image=docker.io/moby/buildkit@sha256:28a898719c18a33f4e8000685287fa36fd0dd9560c6440227d3a732d79bb41d8 \
    --use
docker --host "unix://$socket" buildx inspect --bootstrap >/dev/null
docker --host "unix://$socket" buildx build --load --tag silo-qualification-buildx "$build_context" >/dev/null
docker --host "unix://$socket" buildx rm silo-qualification-builder
machine_before=$(jq -er '.active_machine_id' "$XDG_DATA_HOME/silo/daemon/system.json")
stop_daemon

start_daemon
machine_after=$(jq -er '.active_machine_id' "$XDG_DATA_HOME/silo/daemon/system.json")
test "$machine_before" = "$machine_after"
test "$(engine run --rm \
    --volume silo-qualification:/qualification:ro \
    docker.io/library/busybox@sha256:9db7b59979c38555a39def84a31fb98b5296952f9e3afd4f6f11f05b07adfab0 \
    cat /qualification/marker)" = qualified
test "$(engine inspect silo-qualification-restart --format '{{.State.Running}}')" = true
test "$(engine network inspect silo-qualification --format '{{.Name}}')" = silo-qualification
engine rm --force silo-qualification-restart >/dev/null
stop_daemon

printf 'qualified image=%s machine=%s\n' "$image" "$machine_after"
