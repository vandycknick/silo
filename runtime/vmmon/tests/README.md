# Vmmon process tests

Run the real executable boundary tests without a working hypervisor:

```sh
cargo test --locked -p vmmon --test krun_worker -- --nocapture
cargo test --locked -p vmmon --all-features --bin vmmon virt::backend::krun::
cargo test --locked -p vmmon --all-features --bin vmmon virt::serial::tests::
cargo test --locked -p libvm machine::lifecycle::tests::
```

`make test` discovers these integration tests on the Linux and macOS CI lanes.
`CARGO_BIN_EXE_vmmon` identifies the actual executable, never the Rust unit-test
harness. The tests exercise the production inheritance policy and private parser,
invalid/aliased descriptors, bounded framing, watchdog closure with deliberately
inheritable opposite pipe endpoints, event backpressure, partial-request signal
and parent-loss cancellation, and native startup-failure finalization. The latter
uses an invalid kernel and may fail host admission instead, so it proves cleanup,
not successful virtualization.

Every launched fixture has a deadline and a separate owned process group for
failure cleanup. Tests never kill system-wide processes. Tests that use a generic
OS child are labeled as signal/output-collection unit tests, not VM tests. The
diagnostic collector test emits more than a pipe capacity without newlines using
real child output. No production fake-VMM mode or successful worker stub exists.

These tests do **not** qualify guest boot, successful backend acknowledgement,
guest I/O, macOS entitlements, graceful HVF/VZ shutdown, or Rosetta. Run the real-host
acceptance checks separately before claiming a supported release.
