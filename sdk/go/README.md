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

Loading the small Go FFI bridge is separate from runtime installation. It may materialize embedded bridge bytes under `~/.silo/cache/go-ffi`, but it never accesses the network.

`Open` accepts `WithHome` to select the Silo home holding all persistent state (default `SILO_HOME`, else `~/.silo`; generated sockets always live under `/tmp/silo-<euid>`), `WithRuntimeRoot` to select one complete runtime installation, and `WithSupervisorPath` to override only the `silo-vmm` executable.

Development checkouts deliberately contain no release archive digests or embedded bridge binaries.
From the repository root, build the staged runtime and bridge and run an example with one command:

```sh
make go-sdk-example EXAMPLE=basic
```

The target selects the current host paths and exports the development-only bridge and runtime-root
overrides automatically. Set `PROFILE=release`, `KERNEL_PATH`, or the other standard Make options
when needed.

## Sizes

Memory and disk sizes use explicit units at the call site:

```go
silo.WithMemory(silo.Gibibytes(4))
silo.WithRootDiskSize(silo.Gigabytes(40))
```

Decimal (`Gigabytes`) and binary (`Gibibytes`) constructors are intentionally distinct.

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

Machine creation provisions no guest account unless `WithGuestUser` is supplied.
Default sessions use root when `MachineData.GuestUser` is nil, or the machine's
persisted account when present. Session-level user options override that default.
Existing machines retain their stored account. See [explicit guest provisioning](examples/guest-user.md).

Non-zero guest exit status is an `ExecutionResult`, not a Go error. Errors report validation, transport, runtime, or lifecycle failures. Output byte methods preserve arbitrary bytes; string methods perform ordinary Go byte-to-string conversion.

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

The current native bridge requires ABI **4**. ABI 3 bridges lack the required
stateless planning query symbol contract and are rejected before
new symbols are resolved. Rebuild the bridge and reassemble target-local SDK
bundles together. `NativeABIVersion` is the required numeric ABI constant,
available without loading the bridge.
`VerifiedNativeABIVersion()` loads and checks the exact product/ABI and returns
the actual bridge ABI without opening a runtime or starting a VM.

The attachment contract also requires
`silo_attachment_cancellation_signal`. Go owns the scoped signal subscription and
forwards supported notifications through the token's native channel. Each Attach
or AttachShell temporarily enables forwarding of inherited ignored signals and
restores those dispositions on return, while preserving application subscribers.
The Go path installs no cached Tokio process handlers; standalone Rust attachments
retain their narrow native-listener mode. Cancellation joins the native call before
freeing its token or restoring the Go subscription.

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
