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

# Hold the real boot transaction open after the control socket answers.
docker exec "$container" sh -ec '
    mkdir -p /etc/systemd/system/multi-user.target.wants
    printf "%s\n" "[Unit]" "Before=multi-user.target" \
        "[Service]" "Type=oneshot" \
        "ExecStart=/bin/sh -c '\''until test -e /run/release-boot; do sleep 0.1; done'\''" \
        > /etc/systemd/system/silo-readiness-test.service
    ln -s ../silo-readiness-test.service /etc/systemd/system/multi-user.target.wants/
'

# Start the real manager only after the readiness waiter has begun.
docker exec "$container" sh -ec '
    touch /run/waiter-started
    sh /usr/lib/silo-system/wait-systemd
    touch /run/waiter-ready
' &
waiter=$!
docker exec "$container" timeout 5s sh -ec '
    until [ -e /run/waiter-started ]; do sleep 0.1; done
    sleep 1
    touch /run/start-systemd
'
docker exec "$container" timeout 10s sh -ec '
    until timeout 1s systemctl show --property=Version --value >/dev/null 2>&1; do sleep 0.1; done
    sleep 1
    test ! -e /run/waiter-ready
    touch /run/release-boot
'
wait "$waiter"
waiter=

# An already available manager must also succeed.
docker exec "$container" sh /usr/lib/silo-system/wait-systemd
printf 'systemd readiness timeout, unfinished boot, delayed startup, and ready-manager tests passed\n'
