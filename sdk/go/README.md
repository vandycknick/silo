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

`InstallRuntime` downloads the exact SDK-version archive for the current target, checks its compiled SHA-256 digest, rejects unsafe archive entries, and atomically installs it under `${XDG_DATA_HOME:-$HOME/.local/share}/silo/runtimes/<version>/<target>`. Use `WithRuntimeArchive` for an exact offline archive or `WithRuntimeMirror` to replace only the download origin.

Loading the small Go FFI bridge is separate from runtime installation. It may materialize embedded bridge bytes under `${XDG_CACHE_HOME:-$HOME/.cache}/silo/go-ffi`, but it never accesses the network.

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

## Execution

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
