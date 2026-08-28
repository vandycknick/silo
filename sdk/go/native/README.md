# Silo Go FFI

Private versioned C ABI between `sdk/go` and `libvm`. Build a development bridge with:

```sh
cargo build -p silo-go-ffi
export SILO_GO_FFI_PATH="$PWD/target/debug/libsilo_go_ffi.so" # .dylib on macOS
```

`cargo build -p silo-go-ffi` regenerates `include/silo_go_ffi.h` from the Rust exports with cbindgen. The private CGO bridge includes that generated header directly, keeping Rust as the single source of truth for ABI declarations. Go consumers do not include it directly.
