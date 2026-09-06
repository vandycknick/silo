# silo-portd

`silo-portd` is the Docker system-VM userland-proxy shim for Silo. Docker
executes it once per published mapping. Each invocation owns:

- a session-scoped netd publication using Docker's requested host bind;
- an automatically allocated IPv4 ingress listener inside the VM;
- the image's real `/usr/bin/docker-proxy`, preserving Docker's guest-local
  listener and inherited-descriptor behavior.

```text
host bind                         guest interface            container
127.0.0.1:8080 -- netd/netstack --> guest-ip:allocated-port --> container-ip:80
                                  portd relay
```

The relay connects directly to Docker's `-container-ip` and `-container-port`.
It does not depend on Docker DNAT accepting traffic at the VM's IPv4 address.
Explicit localhost, IPv6-only, and default dual-stack host publications all
use this path. Containers can have IPv4 or IPv6 addresses. Separate IPv4 and
IPv6 mappings have independent ingress listeners and publication sessions.

## Authority and resource limits

The ingress binds only to the local IPv4 address of the control connection
to netd. It accepts only that connection's gateway peer IP, preventing ordinary
direct guest/container use of the internal listener. This does not protect
against a privileged guest capable of impersonating the gateway.

The requested host bind is unchanged, and netd still enforces the machine's
`loopback` or `any` publication policy. netd is not given permission to dial
container addresses or arbitrary guest destinations.

One nonblocking relay thread serves each mapping. It supports up to 256 active
or connecting streams, with 16 KiB of buffering per direction per stream.
Excess connections are closed. Container connections time out after five
seconds; established data streams have no idle timeout. TCP half-close is
preserved.

## Process contract and cleanup

The inherited process contract follows Moby's
[`cmd/docker-proxy/main_linux.go`](https://github.com/moby/moby/blob/master/cmd/docker-proxy/main_linux.go):

- Descriptor 3 is Docker's status pipe. The original `docker-proxy` writes
  `0\n` after startup. `silo-portd` writes `1\n<message>` if its setup fails,
  releasing any ingress and publication already created.
- Descriptor 4 is Docker's pre-bound listener when `-use-listen-fd` is set.
- `SIGINT` and `SIGTERM` close ingress, active relays, and the publication
  before stopping the proxy. An unresponsive proxy is killed after two seconds
  and reaped. Proxy exit also releases all publication resources.
- Linux sends `SIGTERM` to `docker-proxy` if `silo-portd` dies. Killing portd
  closes its ingress and control sockets without a userspace cleanup handler.
- A broken publication hold or failed relay terminates portd with a nonzero
  status. Control-socket keepalives detect a silently lost gateway in roughly
  eight seconds (five idle seconds, one-second probe interval, three probes).
  Healthy idle publications stay open without an application-level heartbeat.

`SILO_PORTD_ENDPOINT` overrides the netd URL for tests. The production default
is `http://gateway.containers.internal:80`; the control connection must use
IPv4. `SILO_PORTD_DOCKER_PROXY` overrides the chained proxy path for tests;
production defaults to `/usr/bin/docker-proxy`.

## Tests

```sh
cargo test -p silo-portd
```

An opt-in Linux end-to-end test runs actual netd, portd, and docker-proxy
processes. A TAP interface in disposable user/network/PID namespaces supplies
the guest network; real TCP services stand in for container applications.
There are no Docker DNAT rules and no fake network forwarder or proxy.

It requires `ip`, `unshare`, `/dev/net/tun`, unprivileged user namespaces, and
an actual `docker-proxy` binary supporting `-use-listen-fd`:

```sh
go -C net/netd build -o "$PWD/target/debug/netd" ./cmd/netd
SILO_PORTD_TEST_NETD="$PWD/target/debug/netd" \
SILO_PORTD_TEST_DOCKER_PROXY=/path/to/docker-proxy \
  cargo test -p silo-portd --test network -- --ignored --nocapture
```

Set `SILO_PORTD_TEST_PORTD` to the static guest binary produced by
`make portd PROFILE=release` to qualify that artifact instead of the default
Cargo test binary.

The test covers IPv4 and IPv6 targets, loopback and wildcard host binds,
unpaired IPv6 and paired dual-stack publications, unauthorized ingress access,
failed-publication cleanup, loopback policy enforcement, healthy idle holds,
portd stop/kill, proxy exit, stalled-proxy escalation, and netd crash cleanup. It does not replace qualification with a full Docker
engine and image; see `docs/smoke/test_plan_docker.md`.
