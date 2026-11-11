# tsgate

Architecture: [ADR 0022](../../docs/adr/0022-lobby-in-silod-and-tsgate.md).
Deployment, credentials, state and restart behavior:
[lobby operator guide](../../docs/lobby/operator.md).

Pure-Go lobby transport for silod. Production invokes `tsgate --control-fd 0`
with an inherited Unix stream socket as stdin, stdout discarded, and stderr
reserved for redacted logs. `tsgate version` prints the protocol implementation
version. Other descriptor numbers are supported; no environment credentials or
additional CLI configuration are accepted. Ambient `TS_`, `TSNET_`, and
`SILO_NET_` variables are cleared before Tailscale package initialization.
Tsgate always disables tsnet log upload, including uploads to `log.tailscale.com`;
this policy cannot be overridden by ambient environment variables. Redacted
local stderr logs remain enabled.

The first length-prefixed JSON frame is version-1 `bootstrap`. The private wire
contract lives in `.tmp/plan/tsgate-L2-wire.md`. tsgate owns enrollment, a private
0700 state directory, a first-write-wins `control-pin.json`, TCP :22 and
TLS-terminated :443. Only a live node bearing the requested tag and matching the
control identity pin can accept connections. Persisted hostname, advertised tag,
profile identity and node key determine whether enrollment needs another key;
this local check does not replace live tag verification. SCM_RIGHTS forwards one
Unix stream per tailnet connection, preserving bidirectional half-close.
Both listeners share a cap of 256 concurrent proxied connections and 32 per
remote IP, regardless of port. Excess connections are closed before allocating
a forwarding socketpair or notifying silod; slots are released when the relay
ends, including failures to hand off the stream.
Owner loss interrupts all streams immediately; explicit shutdown allows up to
four seconds to drain before forced cleanup, with a five-second total limit.
WhoIs lookups run concurrently, capped at 32 in flight; excess requests receive
`WhoIs busy`. Admission-state polling does not wait for lookups; state changes
are pushed to silod without a separate status RPC.

Build and checks (Go automatically selects the pinned toolchain):

```sh
CGO_ENABLED=0 go -C app/tsgate build ./...
go -C app/tsgate vet ./...
CGO_ENABLED=1 go -C app/tsgate test -race -count=1 ./...
gofmt -l app/tsgate
```

`cmd/tsgate-testnet` is a non-shipped end-to-end test helper. It starts a real
loopback testcontrol server, DERP/STUN, and a tagged `peer` tsnet node. Flags
`--capability` and `--cap-value` select one app-capability grant (the value is
JSON). Its first stdout line is `{"control_url":"..."}`; stdin accepts
`probe <hostname> <payload>` and `quit`, with one JSON result per probe. Tests
use the same real control plane, without production-only test configuration.
The control plane advertises certificate domains so :443 can bind, but it does
not issue TLS certificates; offline tests exercise :22, not TLS handshakes.
