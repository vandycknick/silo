# signal-hook-registry 1.4.8

Vendored from the exact crates.io archive already selected by Cargo.lock.

- Upstream: https://github.com/vorner/signal-hook
- Archive VCS revision: `4d5fd6a6663be38e70774e4ac733d65916c70951`
- Archive: https://static.crates.io/crates/signal-hook-registry/signal-hook-registry-1.4.8.crate
- Archive SHA-256: `c4db69cba1110affc0e9f7bcd48bbf87b3f4fc7c61fc9155afd4c469eb3d6c1b`
- License: MIT OR Apache-2.0. Both original license files are retained.
- Original source, manifests, tests, README and VCS metadata are retained.
  The redundant final blank line in `Cargo.toml.orig` is normalized for the
  repository's whitespace checks; this metadata is not used by Cargo builds.

The only upstream source delta is in Unix `Slot::new`:

```diff
-        let flags = flags | siginfo;
+        let flags = flags | siginfo | libc::SA_ONSTACK;
```

The alternate-stack flag is present in the initial atomic sigaction install,
including the registration fallback interval. No post-install repair is used.
Original previous-handler detection, chaining, masks and unregister behavior
are unchanged. This satisfies the Go cgo signal-handler requirement:
https://pkg.go.dev/os/signal#hdr-Go_programs_that_use_cgo_or_SWIG

Silo separately restricts forwarding to HUP, INT, QUIT, TERM, USR1 and USR2;
WINCH is only used for terminal resizing. Runtime/fault/profiling/reserved and
real-time signals are not attachment controls.
