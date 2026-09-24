#!/bin/sh
# Real systemd integration test against the built appliance, no command stubs.
# Requires a Docker host supporting privileged systemd containers and cgroup v2.
set -eu
image=${IMAGE:-ghcr.io/vandycknick/silo/system:dev}
container=
waiter=
cleanup() {
    if [ -n "$container" ]; then docker rm -f "$container" >/dev/null; fi
    if [ -n "$waiter" ]; then wait "$waiter" 2>/dev/null || true; fi
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
container=$(docker run -d --privileged --cgroupns=private \
    --tmpfs /run --tmpfs /run/lock --tmpfs /tmp \
    --entrypoint /bin/sh "$image" -c '
        until [ -e /run/start-systemd ]; do sleep 0.1; done
        exec /sbin/init
    ')

# A missing manager must fail within the helper deadline (outer timeout guards
# the test against a regression that would otherwise hang forever).
status=0
docker exec "$container" timeout 35s sh -c '
    sh /usr/lib/silo-system/wait-systemd && exit 0
    code=$?
    [ "$code" -eq 124 ] && exit 42
    exit "$code"
' || status=$?
[ "$status" -eq 42 ] || { echo "expected bounded systemd readiness timeout, got $status" >&2; exit 1; }

# Start the real manager only after the readiness waiter has begun.
docker exec "$container" sh -c '
    touch /run/waiter-started
    exec sh /usr/lib/silo-system/wait-systemd
' &
waiter=$!
docker exec "$container" timeout 5s sh -c '
    until [ -e /run/waiter-started ]; do sleep 0.1; done
    sleep 1
    touch /run/start-systemd
'
wait "$waiter"
waiter=

# An already available manager must also succeed.
docker exec "$container" sh /usr/lib/silo-system/wait-systemd
printf 'systemd readiness timeout, delayed startup, and ready-manager tests passed\n'
