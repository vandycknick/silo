# taild, phase 10 lobby

The management node exposes `help`, `whoami`, and `version` over tailnet SSH.
VM operations, templates and enrollment are subsequent phases. Closing this
daemon releases SDK handles and its own node, never stops VMs.

## Build and check

Go minimum 1.26.6, toolchain 1.26.8, CGO **enabled**, target C toolchain and the
actual `silo-go-ffi` bridge are required. Imports use the public Go SDK only.

```sh
cargo build -p silo-go-ffi
CGO_ENABLED=1 go -C app/taild build ./cmd/taild
SILO_GO_FFI_PATH=/absolute/path/libsilo_go_ffi.so app/taild/taild --check --config /etc/silo-taild/config.yaml
```

`--check` validates strict single-document YAML, optional private secret files,
nonroot ownership of the resolved existing home, and actual SDK runtime
validation. It never downloads artifacts. Default home is `/var/lib/silo-taild`,
overridden by `SILO_HOME`, then `home` in YAML. `runtime_root` can select a
complete operator-installed portable runtime; otherwise lookup is under
`<home>/runtimes`. Relative paths and writable-by-other homes are rejected.

The shipped [`config.example.yaml`](config.example.yaml) shows operator defaults.
Secrets are optional files in `/etc/silo-taild/secrets`: `oauth-client-secret`,
`oauth-app-secret`, `api-token`. Files must be regular, private (0600), nonempty.
Missing secrets select interactive login or later-phase fallback behavior.

Startup: config/home/secrets, exclusive home lock and private state/audit,
public SDK, service tailnet node, verified Running status/tag/tailnet pin,
resilient SDK reconciliation, then listeners. Login URLs are logged while
waiting. A different observed tailnet is refused. TCP 22 and TLS 443 are bound
only through tsnet, never host listeners or Funnel. HTTP health/metrics require
fresh WhoIs and configured own-scope `vm.read`; callback returns 404 until phase
13. Shutdown cancels lobby sessions and waits at most 90 seconds for sessions
and operations. The operation registry starts empty on restart.

## Identity and permissions

The accepted connection's fresh WhoIs is the identity boundary. Untagged peers
use numeric `user:<id>`; tagged peers carry each verified `tag:<name>`. SSH
username, display names and forwarded headers have no authority. Capabilities
default to `github.com/vandycknick/silo/cap/taild`. Own-scope entries add actions
and take maximum limits; omitted limits use operator ceilings. `*` expands to
known primitive actions. Unknown actions are logged and ignored, unknown
scopes ignored, malformed applicable entries deny the entire capability.
Scope is inspected before action/limit decoding, so a future-scope schema cannot
invalidate applicable grants. Only omitted optional fields select defaults;
explicit nulls in known fields or action elements are malformed. Explicit zero
limits remain zero, with additive grants still taking their maximum.
`vm.restart` and `vm.reauth` are composite operations requiring **both**
`vm.stop` and `vm.start`, never separate wildcard grants. No admin scope exists.
Authenticated peers without capabilities can use whoami/help/version to
diagnose access, including an explanation naming the configured capability.

The five exact label keys are `io.silo.taild.owner`, `.owner-login`, `.name`,
`.node.mode`, `.instance`. Only this instance's valid labels select managed
machines. Name is exact, globally reserved across owners, with the SDK's native
home-wide name lock authoritative against CLI/SDK writers. There is no prefix
or auto-suffix. Future create must hold the service reservation through SDK
creation, then verify assigned tailnet DNS. Inventory projections exclude host
paths and native issue text. Unreadable indexed records never hide healthy
ones. State readers use public ipn/profile/store types; directory presence does
not prove enrollment. Stopped recovery only promotes validated state, retaining
unknown recovery material for operator inspection. No VM nodes start here.

## SSH contract and pinned evidence (D03)

Pinned Tailscale 1.102.5 `ssh/tailssh/session.go` exposes initial `Pty.Window`,
resize channel, stdin Read/EOF, stderr, `Exit(code)` and disconnect `Context`.
`listen.go` admits separate concurrent Session values. Therefore this phase
uses `ListenSSH`, rather than the x/crypto fallback. The resize converter must
be drained even by the lobby. No subsystem/port/agent forwarding is enabled.
Live PTY/resize and capability-propagation behavior remain qualification work.

Grammar is one line with POSIX single/double quotes and backslash escapes.
No shell expansion, pipelines or redirection. Unquoted shell operators and
expansion syntax fail validation; quoted/escaped bytes are literal. Empty
quoted words are retained. Empty command with PTY opens a prompt; without PTY
prints help and exits 2. `--json` returns exactly one stdout object with `ok`,
human/error text goes to stderr. Exit categories: 2 usage, 3 invisible/missing,
4 capability denial, 6 concurrency limit, 9 unavailable, 255 transport failure.
Every REPL command re-resolves WhoIs; idle identity is checked every 30 seconds.

## Startup environment and credentials

The os-only `internal/bootenv` package sorts ahead of upstream environment
readers and clears TS_, TSNET_ and SILO_NET_ **before package initialization**.
Actual child-process inittrace/cache tests pin this contract. AWS is preserved.
This small duplicate of netd's bootstrap is necessary because Go internal
packages cannot cross module boundaries; a shared leaf package can be considered
later. No unsafe/cgo constructor or main-time integer-cache repair is used.

Pinned tsnet Start calls OAuth discovery synchronously under its own lifetime
context. Taild pre-resolves the standard client-secret auth-key flow over
bounded HTTP (30-second whole budget, no redirects), then supplies only the
literal auth key plus advertised tag. This keeps cancellation out of hanging
Start/Close discovery. Already-enrolled valid state reuses identity without
minting on daemon restart. OAuth client secret URL/query attributes are refused.

## Tests

```sh
CGO_ENABLED=1 SILO_GO_FFI_PATH=/absolute/path/libsilo_go_ffi.so \
  SILO_TEST_RUNTIME_ROOT=/absolute/path/complete/runtime \
  go -C app/taild test -race -count=1 -timeout=4m -v ./...
go -C app/taild vet ./...
```

Unit/domain tests cover grants, authorization, grammar and quotas. Real local
integration uses files/rotation, public SDK runtime validation/inventory,
local HTTP OAuth protocol/cancellation, and SSH channel command dispatch below
the authentication boundary with explicit domain identity. None of these prove
WhoIs. Actual unregistered tsnet against a loopback 503 control endpoint verifies
bounded lifecycle and admission denial, never a fake successful tailnet.

The live SSH identity/capability gate loudly skips unless `SILO_E2E_TS_TAILNET`,
`SILO_E2E_TS_CLIENT_SECRET`, `SILO_E2E_TS_PEER_CLIENT_SECRET` are all set. Its
fixtures require the documented positive `tag:silo-test-vm` capability and
negative `tag:silo-test-peer` reachability. Live tailnet, HTTPS certificate,
interactive consent/PTY and systemd/macOS qualification are not offline passes.

CI sets `SILO_TAILD_REQUIRE_FIXTURES=1`, builds the actual native bridge, and
uses the existing `make stage PROFILE=debug` target to build a complete runtime
(including real guest helpers and the official kernel OCI acquisition).
`SILO_TEST_RUNTIME_ROOT` selects that generated stage. Required offline SDK
inventory/health and consumer/binary-check fixtures fail instead of skipping
when prerequisites are missing. A configured invalid path always fails, even
without strict mode. Local runs can reuse an existing complete stage; no runtime
binaries or assets are fabricated by tests.
