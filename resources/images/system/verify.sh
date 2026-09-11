#!/bin/sh
set -eu

cd "$(dirname "$0")"

jq --exit-status '
    .schema == 1 and .engine == "docker" and
    .activation_contract == 1 and .data_layout == 1 and
    .storage == "containerd-snapshotter"
' files/usr/lib/silo-system/manifest.json >/dev/null
jq --exit-status '
    .["userland-proxy"] == true and
    .["userland-proxy-path"] == "/usr/bin/silo-portd" and
    .["live-restore"] == false and
    .features["containerd-snapshotter"] == true
' files/etc/docker/daemon.json >/dev/null
sh -n files/usr/lib/silo-system/silo-system-activate
printf '%s\n' \
    '{"schema":1,"data_uuid":"01234567-89ab-cdef-0123-456789abcdef","data_layout":1,"required_shares":[{"path":"/home/alice","tag":"/home/alice","writable":true}]}' \
    | jq --exit-status --from-file files/usr/lib/silo-system/activation-request.jq >/dev/null
if printf '%s\n' \
    '{"schema":1,"data_uuid":"not-a-uuid","data_layout":1,"required_shares":[],"unknown":true}' \
    | jq --exit-status --from-file files/usr/lib/silo-system/activation-request.jq >/dev/null; then
    printf 'invalid activation request was accepted\n' >&2
    exit 1
fi
printf '%s\n' \
    '{"layout":1,"installation_id":"installation-1","data_uuid":"01234567-89ab-cdef-0123-456789abcdef"}' \
    | jq --exit-status --arg uuid 01234567-89ab-cdef-0123-456789abcdef \
        --from-file files/usr/lib/silo-system/data-layout.jq >/dev/null
test "$(grep -c '^ARG DEBIAN_BASE=.*@sha256:' Containerfile)" -eq 1
test "$(grep -c '^ARG DOCKER_CE_VERSION=' Containerfile)" -eq 1
test "$(grep -c '^ARG CONTAINERD_VERSION=' Containerfile)" -eq 1
test "$(grep -c 'systemctl disable containerd.service docker.service docker.socket' Containerfile)" -eq 1
test "$(grep -c 'ln -sf /dev/null /etc/systemd/system/ssh.socket' Containerfile)" -eq 1
printf 'system image source contract verified\n'
