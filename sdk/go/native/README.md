# Silo Go FFI

Private versioned C ABI between `sdk/go` and `libvm`. Build a development bridge with:

```sh
cargo build -p silo-go-ffi
export SILO_GO_FFI_PATH="$PWD/target/debug/libsilo_go_ffi.so" # .dylib on macOS
```

`cargo build -p silo-go-ffi` regenerates `include/silo_go_ffi.h` from the Rust exports with cbindgen. The private CGO bridge includes that generated header directly, keeping Rust as the single source of truth for ABI declarations. Go consumers do not include it directly.

## Stateless planning (ABI 4)

`silo_planning_query(request, request_len, out_data)` requires no runtime handle.
Strict JSON objects are `{"operation":"memory","input":"8gb"}`,
`{"operation":"disk","input":"64gb"}`, or `{"operation":"name"}`.
Unknown, duplicate, missing, or inapplicable fields are rejected. Responses are
`{"bytes":8589934592}` for the memory example or `{"name":"adjective-noun-1234"}`
for a proposal. Buffers and errors use the existing ownership/freeing contract.
Parsing and name generation delegate to public `libvm::planning` functions without
opening runtime state. ABI 3 bridges are rejected before this symbol is resolved.
