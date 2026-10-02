# taild, owned VM lobby

The management node exposes owned VM operations and templates over tailnet SSH.
VM enrollment completes before boot; `--no-tailnet` retains ordinary networking. Closing this
daemon normally releases SDK handles and its own node without stopping VMs.
Authenticated host shutdown is a separate, bounded lifecycle.

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
`<home>/runtimes` (or `install_root`). Relative paths and writable-by-other homes are rejected.
The selected root must contain `runtime-manifest.json` with exact SDK version,
host target and SHA-256 for every installed regular file except the manifest.
Missing manifests, extra files, symlinks, escaping paths and changed hashes fail
before opening the SDK. Legacy stages need rebuilding by the packaging writer.

`taild version` and `taild --version` report build/SDK versions and the verified
installed runtime's metadata, or `runtime unavailable` when none is installed.
They do not claim that an absent runtime matches the build. The public SDK
verifies its bridge ABI on open; the version command labels this explicitly.
`taild install-runtime --config FILE --runtime-archive /absolute/archive.tar.zst
--install-root /absolute/store` wraps the exact-version public SDK offline
installer. YAML `runtime_archive` and `install_root` provide the same settings.
Installation starts no tailnet node and reads no OAuth secrets. Development SDKs
without compiled release archive digests refuse installation explicitly.

The shipped [`config.example.yaml`](config.example.yaml) shows operator defaults.
Secrets are optional files in `/etc/silo-taild/secrets`: `oauth-client-secret`,
`oauth-app-secret`, `api-token`. Files must be regular, private (0600), nonempty.
Missing OAuth app secrets select per-VM interactive login. Tagged callers require
the configured OAuth client to mint their selected owner tag. Configured errors
fail explicitly, without a silent fallback.

Startup: config/home/secrets, exclusive home lock and private state/audit,
public SDK, service tailnet node, verified Running status/tag/tailnet pin,
resilient SDK reconciliation, then listeners. Login URLs are logged while
waiting. A different observed tailnet is refused. TCP 22 and TLS 443 are bound
only through tsnet, never host listeners or Funnel. HTTP health/metrics require
fresh WhoIs and configured own-scope `vm.read`; the TLS OAuth callback instead
requires an unexpired one-use nonce. Shutdown cancels lobby sessions and waits at most 90 seconds for sessions
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
or auto-suffix. Create holds name and selected-principal quota reservations through
durable SDK creation, releasing them on failure. Assigned VM DNS is checked exactly,
normalizing case/trailing dot only. Inventory projections exclude host
paths and native issue text. Unreadable indexed records never hide healthy
ones. State readers use public ipn/profile/store types; directory presence does
not prove enrollment. Stopped recovery only promotes validated state, retaining
unknown recovery material for operator inspection.

## Enrollment

Human callers use OAuth app consent when `oauth-app-secret` is present, otherwise
interactive login. Tagged callers mint an explicit bounded one-use key for their
selected tag. `enrollment.mode: none` and `--no-tailnet` omit the VM node.
TLS callbacks atomically consume a VM/principal-bound nonce before exchanging a
code. Nonces expire after 15 minutes and disappear on cancellation/restart.
Callback identity is never trusted; actual node status must match the immutable
numeric user (untagged) or owner tag, pinned tailnet/control and exact DNS name.

Consent and enrollment hold a public SDK stopped-machine node-state lease.
Native CLI/SDK Start, Remove and Update fail busy, while Inspect remains available.
Synced transaction fences and pending/backup/unreadable artifacts continue to
block native mutations after a writer crash. Recovery may acquire the lease;
only a committed or safely aborted transaction clears its fence. Unknown state
must be recovered before removal.
Consent holds no global name lock. The temporary server closes before synced,
recoverable pending/backup promotion; netd receives state, never the provisioning
token. `enrollment.timeout` bounds node approval to at most 5 minutes.
Expired/failed approvals leave the VM stopped (exit 8); `start` offers a fresh link.
A control connection that cannot obtain even a login URL times out with exit 9,
leaving the durable machine stopped and resumable. Device API data is validated
before projecting it; a confirmed missing device or elapsed key expiry is shown
as `expired`. Unavailable or corrupt responses do not prove deletion.

`reauth VM` explicitly refreshes the copied existing identity through the pinned
local API, waits for login completion and a changed public key in actual status,
then closes the temporary server and verifies that key in public-package IPN
state with the same stable ID and exact name. Local API preferences redact
private keys and are never used as a changed-key signal. Reauth requires a
stopped VM and both lifecycle capabilities.
Corrupt/unknown state is retained and requires stale-device/recovery cleanup.
Remove snapshots the stable ID before native deletion; API cleanup resolves and
verifies the endpoint device ID, otherwise reports `device_retained`.
`disable_key_expiry: true` requires `api-token`; configured failures are explicit.
Live OAuth consent, ownership/approval semantics and stable-ID reauthentication
remain UNVERIFIED until the live/manual qualification gates run.

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
4 capability denial, 5 state/conflict, 6 limit, 7 operation failure, 8 enrollment
(pending/expired approval), 9 unavailable, 255 transport failure. Guest exit status passes through.
Every REPL command re-resolves WhoIs; idle identity is checked every 30 seconds.

PTY human output uses terminal newlines, including one-shot commands such as
`ssh -t silo ls`. The interactive lobby echoes input and supports Unicode editing,
history, Ctrl-C to cancel a line and Ctrl-D to leave an empty prompt. Bracketed
paste cannot submit commands by itself. Command editing never consumes or rewrites
guest streams or stdin document/userdata payloads.

Human `ls` output uses aligned columns, CLI-style memory sizes (`4G`, `1536M`)
and relative creation ages. `show` includes human sizes and an absolute UTC
creation date. Addresses are hidden from these human views; node hostnames remain.
JSON retains byte counts, timestamp values and its address fields.

## VM commands

```text
create NAME [IMAGE|--image OCI] [--template NAME] [--policy NAME]
             [--cpus N] [--memory SIZE] [--disk-size SIZE]
             [--provision-user NAME:UID:GID:HOME]
            [--userdata INLINE|-] [--label KEY=VALUE]... [--owner tag:NAME]
            [--no-tailnet] [--no-start]
ls
show VM
start VM
stop VM [--force] [--timeout DURATION]
restart VM
reauth VM
rm VM [--force] [--yes]
set VM [name=NAME] [cpus=N] [memory=SIZE] [disk=SIZE]
shell VM [-u USER]
exec VM [-u USER] [-w GUEST_DIR] [-e KEY=VALUE]... [-t] -- CMD [ARG]...
logs VM [--follow] [--stream SOURCE] [--output stdout|stderr]
ops [show op_ULID]
```

Aliases: `new`, `list`, `status`, `ssh`. `--json` is available for queries and
mutations, with [documented schemas](docs/json.md). Flags after the exec `--`
delimiter, including `--json`, are guest arguments. Quotes preserve literal
operators and dollar signs; no host shell evaluates any command. Exec environments
and working directories go only to the guest. `shell` and `exec -t` require an
SSH PTY (`ssh -t`), including its initial size/TERM, resize and signal requests.
Shell uses the selected guest account's login shell and home. New machines
provision no account by default; shell and exec select root. Explicit per-create
`--provision-user nickvd:1000:1000:/home/nickvd` provisions and stores that default
account. Existing machines retain their recorded account, and session `-u` overrides
the default. Remove the obsolete global `vm.guest_user` config setting when upgrading.
For direct SSH, request the guest account explicitly, such as `ssh root@dev` or
`ssh nickvd@dev`. Lost executions return 255; disconnect/revocation cancels only
the guest execution, never the VM.
PTY stdin EOF sends a finite two-EOT sequence: the first flushes an unterminated
canonical line, the second produces EOF on the empty line. No pipe-close request
is sent for a PTY. Raw-mode guests receive the two literal bytes and retain their
own interpretation and session-cancellation lifetime. Empty input and login-shell
exit statuses are preserved. Failed stdout/stderr transport writes return 255.
The prompt consumes CRLF as one command terminator, including the transition into
confirmation or guest stdin, while CR-only input returns without waiting for LF.

Create accepts OCI references under configured registry/namespace prefixes,
bounded inline userdata (`--userdata -` reads at most 16 KiB from client stdin)
and nonreserved labels. `--disk` aliases `--disk-size`. It never accepts a host image,
userdata file, mount, kernel, forward or raw spec. All `io.silo.*` labels are reserved.
Multi-tag callers must select one of their verified tags with `--owner`; humans
cannot supply another owner. Effective resource/count limits are the minimum of
operator ceilings and capability limits. Exact names collide globally with all
local records (including unmanaged/unreadable names) and visible tailnet names.

Create reports actual pull completion/digest, durable creation, start and guest
provisioning readiness. The SDK has no byte-progress callback; percentages are not
invented. `--no-start` persists a stopped VM. Start never repulls its image. Set
requires a stopped VM; disks only grow. Name and display label update through one
atomic native SDK update. Any tailscale declaration, even pending enrollment,
prevents rename.

Remove refuses running VMs without `--force` (5). Force requires stop permission,
uses bounded `StopWith`, then reauthorizes deletion. Confirmation requires a PTY;
unattended callers must use `--yes` or `--json`, and are never left waiting for input.

Mutations are bounded-admission daemon-owned jobs with crypto-entropy canonical
`op_<ULID>` IDs, per-VM serialization and a 24-hour in-memory result/progress history.
The observer subscribes to changes, and disconnect only closes the subscription.
Queued mutations re-resolve production WhoIs at execution, before changing state;
create rechecks after pulling and before boot. Ops requires `vm.read` and exposes
only the caller's principal-scoped operations. Logs, exec and shell recheck fresh
identity, ownership and the exact action every 30 seconds, denying on resolver error.
Log sources: `monitor`, `serial`, `exec`, `network`, `network-audit` (`network_audit`
also accepted). The last 4 MiB
are retained, follow uses bounded line buffering, and path/credential diagnostics
are redacted. Native error text never reaches remote responses.

Shutdown seals admission, closes sessions and drains jobs within a shared 90-second
budget. Operations have a separate daemon-owned context; it is cancelled when the
drain expires. SDK Close starts only after both sessions and jobs drain successfully
and budget remains; its wait is bounded by that same deadline. A timed-out drain or
blocked library close reports incomplete runtime cleanup and leaves handle cleanup
to process exit. No shutdown path calls Stop or Remove. Restart
reconciles libvm records; it neither replays operations nor creates a service database.

## Templates and policies (phase 12)

`template` and `policy` support `ls`, `show NAME`, `create NAME`, `edit NAME`,
`rm NAME`, and `validate`. Create/edit/validate read finite stdin (64 KiB,
30-second budget), never a host filename. `--json` follows the same one-object
contract as VM commands; human documents and summaries use stderr. Reads and
validation require `vm.read`; both kinds' writes require `template.manage` and
fresh identity. Tagged callers select a namespace with `--owner tag:NAME` for
show/write/VM creation; `ls` without an owner lists all their own namespaces.

Principal documents live under `<home>/taild/principals/<base64url-principal>/`
in private `templates/` and `policies/` directories, using atomic synced 0600
files. Operator `templates_dir` and `policies_dir` default to
`/etc/silo-taild/{templates,policies}`. Operator files are read-only, validated
at startup/`--check`, on SIGHUP, and on every list/resolve. Principal names shadow
operator names; editing/removing an operator-only name is forbidden (4), while
create can make a private shadow. Other principals' files remain invisible (3).
All ancestors/files are descriptor-walked without following symlinks; reads are
regular-file-only and size-limited. Document names match `[a-z0-9][a-z0-9-]{0,62}`.

The remote template is a strict single YAML document, based on CLI version **"1"**:
`version`, `description`, OCI `image`, `resources {cpus, memory}`, `disk_size`,
`vsock`, inline `userdata`, `network {kind, policy_ref, publish}`, and `labels`.
Unknown fields, duplicate keys, null, aliases/merges, wrong types, host mounts,
disks, kernels, initramfs, guest agents, forwards and network targets are rejected.
Only `kind: private` is accepted; explicit vsock must be true for guest management.
Userdata must be an inline shebang script (16 KiB maximum), never a file path.
Sizes are positive integer bytes, optionally suffixed by B/KB/MB/GB/TB or
KiB/MiB/GiB/TiB. Resource/capability ceilings apply to the effective VM at create.

**Remote `network.publish: [8080, 8443]` is a list of fixed guest TCP port discovery
hints (1–65535, unique), not CLI/SDK `publish {bind: loopback|any}`.** It is stamped
into immutable VM metadata and exposed as `guest_tcp_ports`. It creates no host
listener and is never mapped to SDK `WithPublish`. Netd's inbound
fallback still accepts every guest TCP port allowed by the tailnet ACL, regardless
of these hints. Configure the ACL to restrict inbound ports; this list does not.

Create resolves the selected principal's template/policy first, then operator
defaults. Only explicit flags override template values, and `--policy NAME`
overrides its policy reference. Labels merge with explicit flags winning;
`io.silo.*` remains reserved. Template/policy names are stamped in immutable
labels and projected by `show`. Description remains template metadata.

Policies are HCL parsed and emitted exclusively by the public Rust-backed SDK.
Any Tailscale declaration, rule tunnel reference or forward is prohibited, even
with `--no-tailnet`. Production enables the one `Service.VMNodesEnabled` switch.
Injection retains the entire canonical JSON, supplies the exact
hostname, verified owner tag (empty for users) and pinned control URL, and appends
TCP routes for both `100.64.0.0/10` and
`fd7a:115c:a1e0::/48` at minimum priority. Explicit user rules retain priority and
order, including deny at minimum priority. User IP allow rules gain neutral tunnel
routing, used only for tailnet destinations by netd. Thus explicit denials win,
while otherwise the tailnet is exempt from default deny. User HTTP rules and
non-tailnet routing remain intact.

Before image pull/admission and again before SDK CreateMachine, public
`Runtime.CheckPolicySecrets` runs the actual start resolver. Missing alternatives
fail with slot and backing key names (2). Corrupt/unavailable stores and invalid
selected projections are separately categorized and redacted (9). Optional
Tailscale auth keys, Machine/Home precedence, AWS profile suppression and complete
explicit overrides follow that resolver. Values and host paths are never returned.
Machine-scoped remote secret writes arrive later.

Operator examples: [`devbox.yaml`](../../packaging/silo-taild/examples/devbox.yaml)
and [`dev-egress.hcl`](../../packaging/silo-taild/examples/dev-egress.hcl).

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

Native KVM qualification uses an actual ephemeral TLS OCI registry serving a
digest-verified tar of the read-only generated minimal guest rootfs. The same
rootfs generated `.tmp/silo-taild/s7-kvm-v3/minimal.ext4`. Native OCI materialization
creates a fresh root disk in a real temporary SDK home, without internet, tailnet
or a production host-image bypass. Ephemeral registry trust exists only in tests.

```sh
CGO_ENABLED=1 SILO_GO_FFI_PATH=/absolute/path/libsilo_go_ffi.so \
  SILO_TEST_RUNTIME_ROOT=/absolute/path/complete/runtime \
  SILO_TAILD_TEST_ROOTFS=/absolute/path/s7-kvm-v3/rootfs SILO_E2E_KVM=1 \
  go -C app/taild test -race -tags=e2e -count=1 -timeout=4m -v ./...
```

These service tests receive explicit principal/capability **input** below
authentication. They use the actual public SDK, OCI, guest PTY and KVM, including
two positive users, disconnect, queued revocation, 30-second stream revocation,
50 shells and genuine SDK close/reopen with an unchanged running VM run ID.
They do not qualify WhoIs or registered tailnet behavior. G1/HUMAN and live gates
remain separately unverified.
