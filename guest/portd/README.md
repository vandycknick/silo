# silo-portd

`silo-portd` is the Docker system-VM userland-proxy shim for Silo. Docker
executes it once per published port. It holds a session-scoped netd
publication and then chains the image's real `/usr/bin/docker-proxy` so guest
loopback behavior remains Docker-compatible.

Docker may create separate IPv4 and IPv6 mappings when no host address is
specified. Each invocation owns an independent netd session; both listeners
dial the guest over its private IPv4 attachment.

The inherited process contract follows Moby's
[`cmd/docker-proxy/main_linux.go`](https://github.com/moby/moby/blob/master/cmd/docker-proxy/main_linux.go):

- descriptor 3 is Docker's status pipe; `docker-proxy` writes `0\n` after it
  starts, while `silo-portd` writes `1\n<message>` only when setup fails;
- descriptor 4 is Docker's pre-bound listener when `-use-listen-fd` is set;
- `SIGINT` and `SIGTERM` are forwarded to `docker-proxy`;
- Linux sends `SIGTERM` to `docker-proxy` if `silo-portd` dies before it can
  forward a stop signal;
- closing or killing `silo-portd` closes the netd session and releases the
  host publication.

`SILO_PORTD_ENDPOINT` overrides the netd URL for tests. The production default
is `http://gateway.containers.internal:80`. `SILO_PORTD_DOCKER_PROXY` overrides
the chained proxy path for tests; production defaults to
`/usr/bin/docker-proxy`.
