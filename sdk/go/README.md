# Silo Go SDK

The Silo Go SDK provides daemonless local virtual machine management through Rust `libvm`.

```sh
go get github.com/vandycknick/silo/sdk/go
```

Supported hosts are macOS arm64, GNU/Linux amd64, and GNU/Linux arm64. Consumer builds require Go 1.25.5 or newer, `CGO_ENABLED=1`, and a native C toolchain. They do not require Rust or Cargo.

## Runtime installation

Runtime installation is always explicit:

```go
installation, err := silo.InstallRuntime(ctx)
if err != nil { return err }

runtime, err := silo.Open(ctx, silo.WithRuntimeRoot(installation.Root))
if err != nil { return err }
defer runtime.Close()
```

`InstallRuntime` downloads the exact SDK-version archive for the current target, checks its compiled SHA-256 digest, rejects unsafe archive entries, and atomically installs it under `~/.silo/runtimes/<version>/<target>` (`$SILO_HOME/runtimes/...` when `SILO_HOME` is set). Use `WithRuntimeArchive` for an exact offline archive or `WithRuntimeMirror` to replace only the download origin.

Loading the small Go FFI bridge is separate from runtime installation. It may materialize embedded bridge bytes under `~/.silo/cache/go-ffi` (`$SILO_HOME/cache/go-ffi` when `SILO_HOME` is set), but it never accesses the network.

`Open` accepts `WithHome` to select the Silo home holding all persistent state (default `SILO_HOME`, else `~/.silo`; generated sockets live under `/tmp/silo-<euid>` unless `SILO_RUN_ROOT` (absolute) overrides it), `WithRuntimeRoot` to select one complete runtime installation, and `WithSupervisorPath` to override only the `silo-vmm` executable.

Manager-integrated callers can instead use `WithRuntimeComponents(RuntimeComponents{...})`
to pin the exact `SupervisorPath`, `NetdPath`, `KernelPath`, `InitramfsPath`,
`AgentPath`, and `AssetDir` selected by their manager. All six paths are required,
absolute, and natively validated/canonicalized. This bypasses ambient component
discovery and cannot be combined with `WithRuntimeRoot` or `WithSupervisorPath`.
It does not install assets or change the native bridge's version/ABI checks.

Development checkouts deliberately contain no release archive digests or embedded bridge binaries.
From the repository root, build the staged runtime and bridge and run an example with one command:

```sh
make go-sdk-example EXAMPLE=basic
```

The target selects the current host paths and exports the development-only bridge and runtime-root
overrides automatically. Set `PROFILE=release`, `KERNEL_PATH`, or the other standard Make options
when needed.

## Machine-scoped credentials

The SDK supports plain secret writes through the runtime's selected secret store:

```go
if err := machine.SetSecret(ctx, "tailscale.vm.auth_key", authKey); err != nil {
    return err
}
if _, err := machine.Start(ctx); err != nil { return err }
```

`DeleteSecret(ctx, name)` removes a machine-scoped key. Reserved `silo.*`
infrastructure keys cannot be changed through these methods. The default file store
accepts UTF-8 values. Values are not written to machine configuration or returned by
inspection. Running helpers retain their launch-time secret snapshot; this API is
not a live command channel. Use the matching ABI 1 bridge and runtime.

## Sizes

Memory and disk sizes use explicit units at the call site:

```go
silo.WithMemory(silo.Gibibytes(4))
silo.WithRootDiskSize(silo.Gigabytes(40))
```

Decimal (`Gigabytes`) and binary (`Gibibytes`) constructors are intentionally distinct.

## Tailnet policy forwards

`NetworkPolicyConfig.Forwards` configures network-policy listeners, independently
of machine-scoped forwards. `NetworkForward.Protocol` defaults to
`NetworkForwardTCP`; port 443 does not imply TLS. Use `NetworkForwardHTTPS` with
`TLS: &NetworkForwardTLS{Provider: NetworkForwardTLSTailscale}` for managed
HTTPS termination. This shape requires `Kind: NetworkForwardTailscale`,
`Target` pointing to `"self"`, a listen address such as `":443"`, and the guest's
HTTP `TargetPort`. The guest service must listen on its interface or wildcard
address, not only loopback.

`Tunnel` may be omitted for a same-VM forward; managed SSH policy injection
supplies it. A local launch still needs exactly one declared Tailscale node and
its enrollment/state configuration; explicit bindings must reference that node.
These forwards require a dedicated 1:1 network attachment; shared/unknown scopes
reject `self`. TCP cannot configure TLS. Managed certificates require an
eligible tailnet node but introduce no certificate secret requirement.

## Forwards and guest publications

Machine-scoped forwards work without networking and persist across starts:

```go
machine, err := runtime.CreateMachine(ctx, silo.DiskImage("rootfs.img"),
    silo.WithForwards(silo.Forward{
        Name: "docker",
        Listen: "host:unix:docker.sock",
        Connect: "guest:unix:/var/run/docker.sock",
    }),
    silo.WithVsock(true),
    silo.WithMachineNetwork(silo.PrivateNetwork(nil).WithPublish(silo.PublishAny)),
)
```

Relative host Unix paths resolve inside the machine runtime directory. Unix
listener `Mode` is a four-digit octal string and defaults to `0600`.
`Machine.Inspect` returns `Forwards`, `Vsock`, and `Network.Publish`.
Publications are off by default; `PublishLoopback` and `PublishAny` apply only
to private networks. SDK session-scoped forward handles are not yet exposed.

## Execution

| Family | Transport | Result |
|---|---|---|
| `Exec(ctx, program, args, ...)` | Agent RPC, literal argv | `ExecutionOutput` |
| `Spawn(ctx, program, args, ...)` | Agent RPC, caller-driven stream/optional PTY | `ExecutionSession` |
| `ExecScript(ctx, script, ...)` | Agent RPC, `/bin/sh -l -c` | `ExecutionOutput` |
| `Shell(ctx, ...SSHShellOption)` | Pinned certificate SSH login over vsock 22 | `SSHExitStatus` |

```go
literal, err := machine.Exec(ctx, "/usr/bin/printf", []string{"%s\\n", "$HOME"})
if err != nil { return err }
fmt.Print(literal.Stdout()) // prints literal $HOME, not its expansion
script, err := machine.ExecScript(ctx, `printf '%s\n' "$HOME" | cat`)
if err != nil { return err }
fmt.Print(script.Stdout())
```

`ExecScript` invokes a login shell, including its startup files. Do not
concatenate untrusted input into a script; callers own shell-injection safety.
The execution timeout option applies to collected execution after startup;
Spawn does not gain a deadline from it. See [streaming example](examples/streaming)
for the required Started-before-stdin gate, pipe EOF and terminal outcome.
`Wait` discards output, `Collect` buffers it, and neither reconnects a session.
Cancel/Close invalidate surviving controls and input handles.

`Shell(ctx, WithSSHUser("silo"), WithSSHTerm("xterm-256color"))` is a local
interactive login. It requires a Running/non-stopping VM, an existing immutable
host-key pin, vsock-22 transport, and accepted user certificate. Already-pinned
SSH does not require fresh agent readiness; outage access requires an
independently owned guest SSH listener. Working-directory/environment options
use the existing quoted exec wrapper (cwd is best effort), not AcceptEnv.

### Supplied shell I/O

[examples/shell](examples/shell) is a runnable finite-input example against an
already-running machine. It does not provision or stop that VM.

```go
status, err := machine.Shell(ctx, silo.WithSSHTerm("xterm-256color"),
    silo.WithShellAttachment(silo.SSHShellAttachment{
        Rows: 37, Columns: 119,
        Input: func(inputCtx context.Context) io.Reader {
            // A finite strings.Reader cannot block, so cancellation adaptation
            // is unnecessary. Blocking readers MUST unblock on inputCtx cancel.
            return strings.NewReader("printf '%s\\n' \"$USER\"; exit 7\n")
        },
        Stdout: sink, Stderr: sink, // SSHShellWriter, cancellation-cooperative
    }))
if err != nil { return err }
fmt.Printf("SSH exit: %d\n", status.Code)
```

Rows/columns must be nonzero. Nil input is EOF, nil output is discard, and nil
controls disables controls. `SSHShellResize` sends dimensions;
`SSHShellSendSignal` sends one of the supported Linux `SSHShell*` signals.
Supplied bytes are transparent (including Ctrl+]); no host stdio, termios,
terminal-size queries or signal subscriptions are used. Explicit detach keys
cannot be combined with a supplied attachment. TERM is configured only through
`WithSSHTerm`. Channel EOF is not Ctrl-D and is not cancellation: send a command
that exits to finish a login shell. Signal exits currently map to code 128;
local detach maps to success.

Input is constructed once under a child context. Its reader and output
`WriteContext` callbacks MUST return when their respective contexts are canceled.
The SDK does not promise to interrupt arbitrary Go syscalls and provides no
automatic goroutine-based Reader/Writer adapter. Both native output pipes are
read concurrently; sink calls are serialized (one non-thread-safe sink is safe)
with per-stream order and no cross-stream order guarantee. Success stops and
joins input/control, then drains output under a separate live context. Parent
cancellation remains effective during drain; failure cancels/joins all workers.
Borrowed outer SSH sessions and process stdio are never closed by success.


Machine creation provisions no guest account unless `WithGuestUser` is supplied.
Default sessions use root when `MachineData.GuestUser` is nil, or the machine's
persisted account when present. Session-level user options override that default.
Existing machines retain their stored account. See [explicit guest provisioning](examples/guest-user.md).

Non-zero RPC exit status is an `ExecutionResult`, and non-zero SSH exit status is an `SSHExitStatus`, not a Go error. Errors report validation, transport, runtime, or lifecycle failures. Output byte methods preserve arbitrary bytes; string methods perform ordinary Go byte-to-string conversion.

Streaming `Recv` methods return `io.EOF` at the finite end. Only one `Recv`, `Wait`, or `Collect` may be active for an execution session. Closing a session or stream unblocks its active receiver. Lifecycle and image mutations observe context cancellation before entering native work, then run to completion because those `libvm` futures are not yet documented as cancellation-safe.

## Errors

```go
var siloError *silo.Error
if errors.As(err, &siloError) {
    log.Printf("kind=%s native=%s: %s", siloError.Kind, siloError.NativeVariant, siloError.Message)
}
if silo.IsErrorKind(err, silo.ErrorMachineNotFound) { /* ... */ }
```

## Resource ownership

Call `Close` on runtimes, machines, execution sessions, stdin handles, and log streams. Closing a runtime does not stop machines, and closing a machine handle does not stop or remove persisted machine state.

See `examples/` for complete flows and `PARITY.md` for Node SDK capability coverage.
## Redacted policy secret checks

`Runtime.CheckPolicySecrets(ctx, policy, machine, overrides)` uses the public Rust
start resolver without exposing values or mutating secrets. Empty `machine` checks
prospective creation against Home; an existing reference uses Machine then Home.
Nonempty overrides replace the complete store-derived set, as at Start. The typed
result is `ready`, `missing` (slots, backing keys, alternative requirements), or
`unavailable` (selected slot/key and stable error category). Corrupt JSON, wrong
projection types and empty selected values never masquerade as absent secrets.
The older `PolicySecretsReady` boolean API remains available. This uses an optional
operation on the existing runtime-query entry point.

The current native bridge requires ABI **1**, the initial unreleased baseline for
the complete bridge contract. The ABI number tracks binary compatibility, independently
of the product version. Mismatched ABIs are rejected before symbols are resolved.
Rebuild the bridge and reassemble target-local SDK
bundles together. `NativeABIVersion` is the required numeric ABI constant,
available without loading the bridge.
`VerifiedNativeABIVersion()` loads and checks the exact product/ABI and returns
the actual bridge ABI without opening a runtime or starting a VM.

Local `Shell` requires `silo_attachment_cancellation_signal`. Go owns scoped
HUP/INT/QUIT/TERM/WINCH subscriptions and restores inherited ignored dispositions
without removing application subscribers. No cached Tokio process handlers are
installed. Cancellation awaits native transport cleanup before freeing the token
or restoring subscriptions. Supplied Shell uses the bounded attachment exports
instead and never subscribes to host signals.

## Stateless CLI creation planning

`ParseMachineMemory(input string) (ByteSize, error)` and
`ParseRootDiskSize(input string) (ByteSize, error)` use the Rust CLI's integer
unit parser. Units `m/mb/mib/g/gb/gib` are case-insensitive and binary for both
operations; surrounding whitespace and whitespace between quantity and unit are
accepted. `8gb`, `8GB`, `8g`, and `8GiB` all return `8 << 30` bytes; `512mb`
returns `512 << 20`. Zero, fractions, negatives, missing units, and overflow fail.
Memory is limited to u32 MiB; disks are limited to u64 bytes. Explicit decimal
constructors such as `Gigabytes` and `Megabytes` retain their decimal semantics.

`ProposeMachineName() (string, error)` uses the existing Silo Rust generator,
returning an adjective-noun-fourhex proposal without an owner prefix. It does not
check availability or reserve the name. These APIs load the bridge but never open
a runtime, home, database, or network connection. Validation errors contain safe
reasons rather than echoing input; callers can add their appropriate flag context.
