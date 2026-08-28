# Go SDK native bridge

The Go SDK in `sdk/go` is an idiomatic facade over `libvm`. It does not invoke the CLI, speak directly to `vmmon`, or recreate machine state in Go.

## Boundary

```text
Go package silo -> internal/ffi -> versioned C ABI -> libvm
```

The C ABI is private to an exact Go SDK release. It uses opaque pointers for resource handles, fixed-width integers, pointer/length byte inputs, Rust-owned output buffers, explicit free functions, and explicit ABI and SDK versions. Complex request and response records use bridge-owned JSON DTOs rather than serializing arbitrary `libvm` public types. cbindgen generates the C header from the Rust exports during `cargo build -p silo-go-ffi`; the cgo trampoline includes that generated header rather than duplicating ABI declarations.

## Ownership

A native runtime handle owns one multi-threaded Tokio runtime and one `libvm::Runtime`. Machine, image, execution, stdin, and log handles retain the runtime context they require. Closing a Go parent handle therefore does not invalidate an already-created child. Go wrappers serialize close against active operations and reject later use with `silo.ErrorClosed`.

Rust copies every Go input that may outlive a cgo call. Go copies every Rust output before calling the matching Rust free function. Rust pointers are never stored in Go memory reachable by C, and Rust never retains Go pointers.

## Failure boundary

Every exported C entry point catches ordinary Rust unwinds. Native errors contain a stable variant and display message; Go never parses display text to classify errors. Adding a `LibVmError` variant requires updating the exhaustive bridge conversion and its test.

## Loading

Consumer builds require `CGO_ENABLED=1`. A small cgo shim uses `dlopen`/`dlsym` with an absolute path and local symbol visibility. Development uses `SILO_GO_FFI_PATH`. Release preparation builds, signs where required, hashes, and embeds one bridge for each supported target. The loaded library remains pinned for process lifetime.

Bridge bytes are materialized under `${XDG_CACHE_HOME:-$HOME/.cache}/silo/go-ffi/<version>/<target>/`. This is independent of the explicit six-component Silo runtime installation under the XDG data root. Bridge loading never downloads a runtime.

## Cancellation

Go context cancellation is cooperative. Cancellation-safe stream waits have explicit native cancellation tokens. Lifecycle and image mutations observe cancellation before entering native work until their `libvm` futures have been audited as cancellation-safe. The binding must not claim that abandoning a cgo caller rolls back a mutation.

### Mutation audit

| Operation | Mid-call context cancellation in v1 | Reason |
|---|---|---|
| Runtime open | No | Database setup and runtime validation have no public cancellation contract. |
| Machine create | No | Image materialization, disk cloning, and persistence form one mutation whose dropped-future contract is not public. |
| Start/stop/remove | No | Lifecycle reconciliation owns locks and process transitions that must reach a defined terminal state. |
| Image pull/remove/prune | No | Cache and datastore transactions must finish their cleanup paths. |
| Execution/log receive | Yes, closes the stream/session | The native handle owns an explicit cancellation channel and waits for the receive operation before freeing it. |
| Installer download/extraction | Yes | Go owns temporary files and removes incomplete staging before returning. |

Methods in the first four rows check a context before entering cgo. Once entered, they finish and return the native result even if the caller's context expires. This is deliberate rather than pretending that dropping a Go waiter rolls back Rust work.

## Compatibility

The ABI version changes for incompatible symbol or layout changes. The SDK version must exactly match the Go package. Runtime components also match the exact product version; compatibility ranges and independently upgraded components are not supported.
