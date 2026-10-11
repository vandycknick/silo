# Silo Go FFI

Private versioned C ABI between `sdk/go` and `libvm`. Build a development bridge with:

```sh
cargo build -p silo-go-ffi
export SILO_GO_FFI_PATH="$PWD/target/debug/libsilo_go_ffi.so" # .dylib on macOS
```

`cargo build -p silo-go-ffi` regenerates `include/silo_go_ffi.h` from the Rust exports with cbindgen. The private CGO bridge includes that generated header directly, keeping Rust as the single source of truth for ABI declarations. Go consumers do not include it directly.

The current contract is ABI 1, the initial unreleased baseline.

## Stateless planning

`silo_planning_query(request, request_len, out_data)` requires no runtime handle.
Strict JSON objects are `{"operation":"memory","input":"8gb"}`,
`{"operation":"disk","input":"64gb"}`, or `{"operation":"name"}`.
Unknown, duplicate, missing, or inapplicable fields are rejected. Responses are
`{"bytes":8589934592}` for the memory example or `{"name":"adjective-noun-1234"}`
for a proposal. Buffers and errors use the existing ownership/freeing contract.
Parsing and name generation delegate to public `libvm::planning` functions without
opening runtime state.

## Scoped secret writes

`silo_machine_secret(machine, request, request_len)` accepts
`{"operation":"set","name":"tailscale.vm.auth_key","value":"BASE64"}` or
`{"operation":"delete","name":"tailscale.vm.auth_key"}`. Requests are bounded
to 32KiB and reject extra/inapplicable fields. Writes use the selected runtime
store and machine scope under the native config lock. Reserved `silo.*` names
cannot be changed. Errors never include the credential value. Bridges with a
mismatched ABI are rejected before resolving API symbols.

## Execution hard cut

The four public Go families are `Exec`, `Spawn`, `ExecScript` (agent RPC) and
`Shell` (certificate-authenticated SSH). Script collection exports
`silo_machine_exec_script`; local SSH exports `silo_machine_shell` and its
`_cancellable` form. The latter accepts a nullable `SshAttachmentHandle` before
the status output. RPC attachment and SSH-as-execution exports are removed;
loaders require the new symbols, without fallback. ABI 1 and product versions
remain unchanged for this atomic unreleased workspace cutover.

Supplied shell I/O uses three 65536-byte simplex pipes and a 64-entry typed
control queue. `silo_ssh_attachment_new` binds the machine runtime and the
already-created cancellation token before shell startup. `write`, `close_stdin`,
`read`, `resize`, `signal`, `cancel` and `free` are private C operations; no Go
pointer or callback is retained. A direction permits only one active byte
operation. Locks are released before waits so cancellation can wake blocked
operations. Single attachment consumption and matching token identity are
required. Raw pointers are borrowed until completion: callers must never invoke
operations after free.

Native success marks input/control complete and explicitly shuts down output
writers, without canceling the shared token. Buffered output remains readable
until EOF. Go stops and joins input/control, drains both output readers under a
separate live context, then joins all operations before freeing attachment and
token. Parent cancellation remains active during output drain. Failure cancels
all scopes and native work, preserves the first error, and joins before free.
Local calls pass cancellation and Go-owned signal subscriptions into the libvm
builder and await its transport cleanup rather than dropping the shell future.
