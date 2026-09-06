# Docker publication smoke test

This plan verifies a Docker Engine running inside a Silo VM, including:

- runtime installation of the locally built static `silo-portd`;
- Docker's default dual-stack `-p` behavior;
- host-to-container traffic over IPv4 and IPv6 listeners;
- guest-loopback traffic through the chained `docker-proxy`;
- an unmodified Docker CLI on the host connected to the guest daemon;
- normal, failed, crashed, and VM-lifecycle cleanup;
- publication policy and audit records.

The test uses the immutable Arch image tag
`ghcr.io/vandycknick/archlinux:20260831.150324`. At the time this plan was
written, the tag resolved to OCI index digest
`sha256:20409f0c52d3c335dd53e7d086d37c948df360be09a82cf6571f0cb6f305ab5a`.

## Preconditions

- Run the commands from the Silo repository root on a Linux host.
- The host must support IPv4 and IPv6 loopback sockets.
- The host must have `docker`, `curl`, `file`, `sha256sum`, and `ss`.
- The test ports `18053` and `18081` through `18084` must be unused.
- Do not let any command run for more than five minutes without stopping it
  and collecting its output.
- The VM and host socket names below are disposable and reserved for this test.

Set the shared host variables:

```bash
export ROOT="$PWD"
export SILO="$ROOT/target/debug/silo"
export PORTD="$ROOT/target/x86_64-unknown-linux-musl/release/silo-portd"
export IMAGE="ghcr.io/vandycknick/archlinux:20260831.150324"
export VM="adr16-docker-smoke"
export DOCKER_SOCKET="$ROOT/.tmp/adr16-docker.sock"
export DOCKER_HOST="unix://$DOCKER_SOCKET"
```

On an ARM64 host, use this guest artifact instead:

```bash
export PORTD="$ROOT/target/aarch64-unknown-linux-musl/release/silo-portd"
```

Confirm that the selected host ports are free:

```bash
ss -ltn
```

Remove a prior disposable VM before starting only if it is known to belong to
this test:

```bash
"$SILO" rm --force "$VM"
```

The removal command is expected to report that the VM does not exist on a
first run. Do not replace `$VM` with an unrelated machine name.

## 1. Build and identify the artifacts

Build the adjacent runtime and the guest-only portd artifact separately.
`make build` intentionally does not package `silo-portd` as a host runtime
component.

```bash
make build PROFILE=debug
make portd PROFILE=release
```

Record and inspect the exact inputs:

```bash
git rev-parse HEAD
"$SILO" --version
file "$PORTD"
sha256sum "$PORTD"
```

Expected results:

- `silo-portd` is an ELF binary for the host's guest architecture.
- It is statically linked.
- The Git commit and portd checksum are retained with the smoke-test results.

## 2. Create the machine and Docker socket forward

Create a persistent VM with guest publications enabled and a machine-scoped
forward from a known host Unix socket to dockerd's guest Unix socket:

```bash
install -d -m 0700 "$ROOT/.tmp"

"$SILO" create "$IMAGE" \
  --name "$VM" \
  --cpus 4 \
  --memory 4gb \
  --disk-size 20gb \
  --network private \
  --guest-publish any \
  --forward "host:unix:$DOCKER_SOCKET=guest:unix:/var/run/docker.sock"

"$SILO" start "$VM"
```

The socket forward and publication setting have different jobs:

- `--forward` lets the host Docker CLI reach the guest Docker API.
- `--guest-publish any` lets Docker request wildcard host TCP listeners for
  container `-p` mappings.

Inspect the machine and forward:

```bash
"$SILO" show "$VM"
"$SILO" forward "$VM" --list
stat "$DOCKER_SOCKET"
```

Expected results:

- The VM is running and guest-ready.
- The forward is machine-scoped and active.
- The host socket exists with mode `0600`.
- The forward connects to `guest:unix:/var/run/docker.sock`.

## 3. Install and prove stock Docker

Install Docker and the guest diagnostics:

```bash
"$SILO" exec --user root "$VM" -- \
  pacman -Syu --noconfirm --needed \
  docker curl jq procps-ng iproute2
```

Inspect the installed proxy and service before configuring portd:

```bash
"$SILO" exec --user root "$VM" -- bash -c 'command -v docker'
"$SILO" exec --user root "$VM" -- bash -c 'command -v dockerd'
"$SILO" exec --user root "$VM" -- bash -c 'command -v docker-proxy'
"$SILO" exec --user root "$VM" -- systemctl cat docker.service
```

`docker-proxy` must be available at `/usr/bin/docker-proxy`. If it is installed
elsewhere, stop and record the path rather than adding an unexplained symlink.

Start unmodified Docker and prove the image, kernel, cgroups, storage, and
container networking work before introducing portd:

```bash
"$SILO" exec --user root "$VM" -- systemctl enable --now docker.service
"$SILO" exec --user root "$VM" -- docker version
"$SILO" exec --user root "$VM" -- docker info
"$SILO" exec --user root "$VM" -- \
  docker run --rm docker.io/library/busybox:1.37.0 true
```

Stop here if the stock Docker run fails. That failure is below the Silo
publication layer.

The host Docker CLI must now reach the same stock guest daemon through the
machine-scoped socket forward:

```bash
docker version
docker ps
```

Expected results:

- `docker version` reports the host client and guest server versions.
- `docker ps` returns the guest container list.
- `"$SILO" forward "$VM" --list` still reports an active forward with no
  refused connections. Its active connection count may return to zero after
  these short-lived Docker API requests complete.

## 4. Install and configure silo-portd

Transfer the binary through the guest agent's raw stdin stream:

```bash
"$SILO" exec --user root "$VM" -- sh -eu -c '
  tmp=$(mktemp /tmp/silo-portd.XXXXXX)
  trap "rm -f \"$tmp\"" EXIT
  cat > "$tmp"
  install -o root -g root -m 0755 "$tmp" /usr/bin/silo-portd
' < "$PORTD"
```

Verify that the transferred bytes are exact:

```bash
sha256sum "$PORTD"
"$SILO" exec --user root "$VM" -- sha256sum /usr/bin/silo-portd
"$SILO" exec --user root "$VM" -- file /usr/bin/silo-portd
```

The host and guest checksums must match.

Merge the proxy settings into `daemon.json`, validate the candidate, and
install it atomically:

```bash
"$SILO" exec --user root "$VM" -- sh -eu -c '
  install -d -m 0755 /etc/docker
  candidate=$(mktemp /etc/docker/daemon.json.XXXXXX)
  trap "rm -f \"$candidate\"" EXIT
  if test -s /etc/docker/daemon.json; then
    jq '\''. + {
      "userland-proxy": true,
      "userland-proxy-path": "/usr/bin/silo-portd"
    }'\'' /etc/docker/daemon.json > "$candidate"
  else
    jq -n '\''{
      "userland-proxy": true,
      "userland-proxy-path": "/usr/bin/silo-portd"
    }'\'' > "$candidate"
  fi
  dockerd --validate --config-file "$candidate"
  install -o root -g root -m 0644 "$candidate" /etc/docker/daemon.json
'
```

Restart Docker and verify both access paths:

```bash
"$SILO" exec --user root "$VM" -- systemctl restart docker.service
"$SILO" exec --user root "$VM" -- systemctl is-active docker.service
"$SILO" exec --user root "$VM" -- docker info
docker info
```

## 5. Start observability streams

Keep these running in separate terminals while executing the remaining tests.

Host network audit stream:

```bash
"$SILO" logs "$VM" --stream network-audit --follow
```

Guest Docker journal:

```bash
"$SILO" exec --user root "$VM" -- \
  journalctl -u docker.service --follow --no-pager
```

The current publication table should be empty:

```bash
"$SILO" exec --user root "$VM" -- sh -c \
  'curl -fsS http://gateway.containers.internal/services/forwarder/all | jq .'
```

Expected result:

```json
[]
```

## 6. Publish through the guest Docker CLI

Use Docker's ordinary unspecified host address. Do not add `0.0.0.0` to the
publish argument, because this test must exercise Docker's default IPv4 and
IPv6 expansion:

```bash
"$SILO" exec --user root "$VM" -- \
  docker run -d \
  --name adr16-guest-cli \
  --publish 18081:80 \
  docker.io/library/busybox:1.37.0 \
  sh -c 'mkdir -p /www; echo guest-cli-ok >/www/index.html; exec httpd -f -p 80 -h /www'
```

Verify host IPv4, host IPv6, and guest loopback:

```bash
curl --noproxy '*' --fail http://127.0.0.1:18081
curl --noproxy '*' --fail 'http://[::1]:18081'
"$SILO" exec --user root "$VM" -- \
  curl --fail http://127.0.0.1:18081
```

All three requests must return `guest-cli-ok`.

Inspect the host and guest process state:

```bash
ss -ltnp
"$SILO" exec --user root "$VM" -- sh -c \
  'ps -eo pid,ppid,args | grep -E "[s]ilo-portd|[d]ocker-proxy"'
"$SILO" exec --user root "$VM" -- sh -c \
  'curl -fsS http://gateway.containers.internal/services/forwarder/all | jq .'
```

Expected results:

- netd listens on both `0.0.0.0:18081` and `[::]:18081`.
- There are two `dockerd -> silo-portd -> docker-proxy` chains, one per family.
- The table contains `0.0.0.0:18081` and `[::]:18081`.
- Each entry dials a different allocated port on the guest's private IPv4
  address, not the Docker host port `18081`.
- `ss -ltnp` inside the guest shows the portd ingress listeners on that private
  address. A direct guest connection to an ingress is closed without reaching
  the container; only netd's gateway source address is accepted.
- Audit contains two session-scoped `exposed` records.

Remove the container and verify both listeners disappear:

```bash
"$SILO" exec --user root "$VM" -- docker rm --force adr16-guest-cli
curl --noproxy '*' --max-time 2 http://127.0.0.1:18081
curl --noproxy '*' --max-time 2 'http://[::1]:18081'
```

Both curls must fail. The table must return to `[]`, both process chains must
be gone, and audit must contain two `released` records.

### 6.1 Explicit loopback and IPv6-only publications

Keep the main VM's `any` policy for this test. Unlike the default dual-stack
case, the last mapping below must work without a matching IPv4 publication:

```bash
docker run -d --name adr16-explicit \
  --publish 127.0.0.1:18085:80 \
  --publish '[::1]:18086:80' \
  --publish '[::]:18087:80' \
  docker.io/library/busybox:1.37.0 \
  sh -c 'mkdir -p /www; echo explicit-ok >/www/index.html; exec httpd -f -p 80 -h /www'

curl --noproxy '*' --fail http://127.0.0.1:18085
curl --noproxy '*' --fail 'http://[::1]:18086'
curl --noproxy '*' --fail 'http://[::1]:18087'
ss -ltnp
```

All three requests must return `explicit-ok`. Host listeners must be exactly
`127.0.0.1:18085`, `[::1]:18086`, and `[::]:18087`. In particular, there must
not be a `0.0.0.0:18087` companion or a wildcard listener for either localhost
mapping. This request must fail:

```bash
curl --noproxy '*' --max-time 2 http://127.0.0.1:18087
```

The publication table must contain three distinct IPv4 guest ingress targets.
Guest-local access through the original Docker listeners must still work.
Remove the container and verify all host and ingress listeners disappear:

```bash
docker rm --force adr16-explicit
```

## 7. Publish through the host Docker CLI

The following `docker` command runs on the host and reaches the guest daemon
through `$DOCKER_HOST`:

```bash
docker run -d \
  --name adr16-host-cli \
  --publish 18082:80 \
  docker.io/library/busybox:1.37.0 \
  sh -c 'mkdir -p /www; echo host-cli-ok >/www/index.html; exec httpd -f -p 80 -h /www'
```

Verify that the host and guest see the same container:

```bash
docker ps --filter name=adr16-host-cli
"$SILO" exec --user root "$VM" -- \
  docker ps --filter name=adr16-host-cli
docker exec adr16-host-cli cat /www/index.html
```

Verify both host listener families:

```bash
curl --noproxy '*' --fail http://127.0.0.1:18082
curl --noproxy '*' --fail 'http://[::1]:18082'
```

Both requests must return `host-cli-ok`. The publication table and process
tree must have the same two-family shape as the guest-CLI test.

Remove the container using only the host Docker CLI:

```bash
docker rm --force adr16-host-cli
```

Confirm both listeners, both table entries, and both proxy chains disappear.

## 8. Verify a bind conflict is atomic

Start one container on port `18083` through the host Docker CLI:

```bash
docker run -d \
  --name adr16-conflict-owner \
  --publish 18083:80 \
  docker.io/library/busybox:1.37.0 \
  httpd -f -p 80
```

Attempt to start another owner on the same port:

```bash
docker run -d \
  --name adr16-conflict-loser \
  --publish 18083:80 \
  docker.io/library/busybox:1.37.0 \
  httpd -f -p 80
```

Expected results:

- The second command fails with an address or publication conflict.
- The first container remains reachable.
- The table still has exactly the first container's two entries.
- Removing the failed container does not disturb the first publication.

Clean up:

```bash
docker rm --force adr16-conflict-loser
docker rm --force adr16-conflict-owner
```

The first cleanup may report that the failed container is only in `Created`
state, which is acceptable.

## 9. Verify UDP fails explicitly

```bash
docker run --rm \
  --publish 18053:53/udp \
  docker.io/library/busybox:1.37.0 \
  sleep 300
```

Expected results:

- Docker fails promptly.
- The error includes `silo-portd: udp publication is not supported`.
- No host listener and no publication table entry remain for port `18053`.
- No netd protocol-denial audit is expected because portd rejects UDP before
  contacting netd.

## 10. Verify VM stop and restart

Create a restart-policy container through the host Docker CLI:

```bash
docker run -d \
  --name adr16-restart \
  --restart always \
  --publish 18084:80 \
  docker.io/library/busybox:1.37.0 \
  sh -c 'mkdir -p /www; echo restart-ok >/www/index.html; exec httpd -f -p 80 -h /www'

curl --noproxy '*' --fail http://127.0.0.1:18084
"$SILO" exec --user root "$VM" -- sync
```

Stop the VM:

```bash
"$SILO" stop "$VM"
```

Expected while stopped:

- IPv4 and IPv6 host listeners on `18084` are gone.
- `$DOCKER_SOCKET` is removed.
- `docker ps` fails because the forwarded Docker API is unavailable.
- Network audit contains release records for both publication sessions.

Start the VM and wait for Docker:

```bash
"$SILO" start "$VM"
"$SILO" exec --user root "$VM" -- systemctl is-active docker.service
docker ps --filter name=adr16-restart
curl --noproxy '*' --fail http://127.0.0.1:18084
curl --noproxy '*' --fail 'http://[::1]:18084'
```

Expected after start:

- The machine-scoped Docker socket is recreated.
- Docker starts automatically.
- The restart-policy container is running.
- Both publication families are recreated.
- Both curls return `restart-ok`.

Clean up:

```bash
docker rm --force adr16-restart
```

## 11. Verify session cleanup after SIGKILL

Create a dedicated container on an unused test port and inspect its proxy
processes:

```bash
docker run -d \
  --name adr16-kill \
  --publish 18084:80 \
  docker.io/library/busybox:1.37.0 \
  httpd -f -p 80

"$SILO" exec --user root "$VM" -- sh -c \
  'ps -eo pid,ppid,args | grep -E "[s]ilo-portd|[d]ocker-proxy"'
```

Select one `silo-portd` PID for port `18084`, verify its full command line, and
send that PID `SIGKILL` from the guest. Do not use a broad process-name kill.

Expected results for the selected family:

- Its host publication disappears within five seconds.
- Its session entry disappears from `/services/forwarder/all`.
- Audit records a release.
- Its ingress listener and active relay connections are closed.
- Its chained `docker-proxy` terminates through Linux parent-death signaling.
- The other family remains independently owned until its portd exits.

After `docker rm --force adr16-kill`, no proxy process or publication may
remain. Any orphaned `docker-proxy` is a failure.

## 12. Verify loopback policy denial

Docker system VMs use `--guest-publish any`, but policy denial should be tested
with a second disposable VM created with `--guest-publish loopback`.

Repeat the Docker and portd bootstrap using a distinct VM and Docker socket,
then run the ordinary wildcard publication:

```bash
docker run -d --publish 18081:80 docker.io/library/busybox:1.37.0 httpd -f -p 80
```

Expected results:

- Docker fails because wildcard publication is forbidden.
- The error contains `bind policy permits loopback publications only`.
- No host listener or table entry remains.
- Audit records a denied publication with reason `bind_policy`.

Explicit loopback publications are required to work under this policy:

```bash
docker run -d --name adr16-loopback-policy \
  --publish 127.0.0.1:18085:80 --publish '[::1]:18086:80' \
  docker.io/library/busybox:1.37.0 \
  sh -c 'mkdir -p /www; echo loopback-ok >/www/index.html; exec httpd -f -p 80 -h /www'
curl --noproxy '*' --fail http://127.0.0.1:18085
curl --noproxy '*' --fail 'http://[::1]:18086'
docker rm --force adr16-loopback-policy
```

Both requests must return `loopback-ok`. The host listeners must remain
loopback-only. Removal must release both allocated guest ingresses as well as
the host listeners. A publication denial must not leave an ingress behind.

## 13. Optional external-interface test

From a second machine on the same LAN, request the Silo host's non-loopback
address while a wildcard publication is active:

```bash
curl --fail http://SILO_HOST_ADDRESS:18082
```

This proves `--guest-publish any` beyond host-local loopback. Record host
firewall state if the request fails while local IPv4 and IPv6 requests pass.

## 14. Final cleanup

Ensure no smoke containers remain:

```bash
docker ps --all
```

Unset the guest Docker endpoint before using Docker for anything else:

```bash
unset DOCKER_HOST
```

Remove the disposable VM and verify its forwarded socket and published ports
are gone:

```bash
"$SILO" rm --force "$VM"
test ! -e "$DOCKER_SOCKET"
ss -ltn
```

## Acceptance criteria

The smoke test passes only when all of the following are true:

- Stock Docker works before portd is configured.
- Host and guest Docker CLIs operate the same guest daemon.
- Ordinary `-p HOST_PORT:CONTAINER_PORT` creates independent IPv4 and IPv6
  host listeners without a bind conflict.
- Host IPv4, host IPv6, and guest loopback requests reach the container.
- Each Docker mapping has the expected `silo-portd -> docker-proxy` chain.
- Normal removal releases both publication sessions.
- Bind failure does not remove another container's publication.
- UDP fails explicitly without leaked state.
- VM stop removes listeners and the Docker API socket.
- VM start recreates the machine-scoped socket and restart-policy publication.
- Killing one portd releases its session without releasing the other family.
- Explicit IPv4/IPv6 loopback and unpaired IPv6-only publications reach the
  container without widening the host bind.
- Loopback policy rejects Docker's default wildcard publication but permits
  working explicit loopback publications.
- Audit records agree with every exposed, released, and denied transition.

Any leaked host listener, publication table entry, `silo-portd`, or
`docker-proxy` is a failure even when Docker has removed the container.

## Failure triage

| Symptom                                                 | Likely boundary                                               |
| ------------------------------------------------------- | ------------------------------------------------------------- |
| Stock BusyBox run fails                                 | Guest kernel, cgroups, storage, or Docker setup               |
| Host `docker ps` cannot connect while the VM is running | Machine-scoped Unix forward or socket path                    |
| Portd cannot resolve or connect to its endpoint         | Guest DNS or publication endpoint registration                |
| Docker reports HTTP 403 text                            | Machine publication bind policy                               |
| `start docker-proxy` reports a missing file             | Guest `docker-proxy` path                                     |
| `docker run -p` hangs                                   | Docker status pipe or inherited listener descriptor           |
| IPv4 succeeds and IPv6 reports address in use           | Host listener family was not constrained to `tcp4` and `tcp6` |
| Guest loopback works but host traffic fails             | netd listener, gVisor dial, ingress source check, or relay target |
| Host traffic works but guest loopback fails             | Chained `docker-proxy` or descriptor inheritance              |
| Port remains after container removal                    | Signal forwarding or session disconnect cleanup               |
| Port remains after VM stop                              | Publication table or netd attachment cleanup                  |
