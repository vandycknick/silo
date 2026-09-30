# Pre-initialization environment isolation

Go's [program initialization rule](https://go.dev/ref/spec#Program_initialization)
selects the first uninitialized package, sorted by import path, whose imports
are already initialized. This is about the dependency graph, not source-file
order or the textual position of a blank import.

This package imports **only `os`**. Its `github.com/...` import path sorts before
`tailscale.com/...`, and it becomes eligible as soon as `os` is initialized.
Upstream environment readers also require `os`, directly or through envknob.
Explicit imports in the binary and node package place the guard in both graphs.
Pinned v1.102.5 magicsock registers `TS_DEBUG_DISCO` and
`TS_DEBUG_MAGICSOCK_RING_BUFFER_MAX_SIZE_BYTES` during package initialization.
Invalid values can log/fatal before main. envknob.Setenv does not reset its
registered integer cache, so a main-time cache repair is not a solution.

Clear TS_/TSNET_/legacy SILO_NET_ entries before these packages initialize,
without logging names or values. Preserve ordinary AWS environment. Managed
Rust launches also strip the prefixes before exec; detached Go launches filter
their exec environment. Main-time clearing is defense in depth only.

Actual foreground/detached processes run with invalid boolean/integer knobs.
Init traces assert this guard precedes envknob and magicsock. Pure upstream
leaf initializers without an os dependency (for example types/lazy) may run
earlier, but cannot read the environment. A dependency-graph test pins the
guard's sole os import and its ordering ahead of the upstream namespace.
Actual child-process tests also assert valid nonzero
integer inputs produce default zero cached values. Review this ordering and
rerun these tests on dependency/toolchain changes. No upstream imports may be
added here, and no unsafe or cgo constructor is involved.
