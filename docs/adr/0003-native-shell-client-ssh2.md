# 3. Replace shell command with native SSH client (`ssh2`/libssh2)

Date: 2026-02-23

## Status

Proposed

## Context

Current shell access works through an external OpenSSH process and proxy command:

`silo shell -> host ssh binary -> silo shell-proxy -> vmmon (UDS control) -> VSOCK -> guest socat -> guest sshd`

This implementation is functional and supports concurrent sessions, but it has architectural and UX drawbacks:

- Multiple host-side processes for one shell command.
- Tight coupling to host OpenSSH presence and behavior.
- Extra complexity around ProxyCommand process lifecycle and stdio edge cases.
- Limited ability to provide Silo-native shell behavior and features without shelling out.
- Harder path to unify shell/exec/cp behavior under one in-process client model.

We want `vmmon` to remain the sole VM owner and VSOCK endpoint owner. We also want future per-VM key injection via cloud-init and immediate key-based login.

## Decision

We will replace the external OpenSSH invocation path with an in-process SSH client built in `silo` using `ssh2` (libssh2 bindings).

The `silo shell` command will own:

1. transport setup to `vmmon` control socket,
2. protocol handshake (`open_vsock`),
3. SSH handshake and auth over that stream,
4. PTY shell lifecycle (stdin/stdout relay, resize, teardown).

`vmmon` and guest responsibilities remain unchanged:

- `vmmon` owns VM and VSOCK connect.
- Guest provides SSH endpoint (currently via `socat` bridge to `sshd`).

## Target Architecture

`silo shell -> vmmon vm.sock -> open_vsock(2222) -> guest VSOCK bridge -> guest sshd`

Implementation shape in `silo`:

- `ssh_transport` module:
  - connect to `vm.sock`
  - send `ControlRequest(open_vsock)`
  - parse `ControlResponse`
  - expose upgraded raw stream
- `ssh_native` module (`ssh2`):
  - create `ssh2::Session`
  - bind session to upgraded stream
  - perform handshake and host key verification
  - authenticate (password in dev mode, key-based as default once cloud-init key path lands)
  - open PTY shell channel
  - relay terminal I/O and handle resize signals

## Why `ssh2`/libssh2

We considered pure Rust SSH libraries and external OpenSSH wrappers.

`ssh2` is selected because:

- Faster path to deliver a working native client than building SSH semantics from lower-level primitives.
- Mature SSH client behavior (handshake, channels, auth modes) via libssh2.
- Fits the immediate goal: replace external `ssh` process while preserving current transport model.
- Lets us incrementally move to key-based auth without changing VM transport ownership.

## Consequences

### Positive

- Single Silo command path for shell access (no external `ssh` process required).
- Reduced process chaining and fewer ProxyCommand/stdin/stdout edge cases.
- Better control over UX and error mapping (`instance_not_running`, `guest_port_unreachable`, auth failures, host key issues).
- Foundation for future native `exec` and `cp` primitives reusing the same transport.

### Negative

- Introduces C library dependency considerations (libssh2 and crypto linkage/runtime).
- Additional implementation complexity for robust PTY and terminal signal handling.
- We assume ownership of SSH host key policy and user-facing security defaults.
- Potential packaging differences across environments must be tested and documented.

### Deferred risks to manage

- Host key trust policy must be explicit and safe by default.
- Terminal behavior parity with OpenSSH requires careful implementation.
- Linkage strategy (vendored/static/dynamic) must be nailed down for reproducible builds.

## Rollout Plan

### Phase 1: Native shell MVP

- Add `ssh2` integration and native SSH session over existing `vmmon` transport.
- Support interactive shell with `--user` (default `root`).
- Preserve current failure semantics and improve messages.

### Phase 2: Security and UX parity

- Add per-instance known_hosts handling (`accept-new` equivalent policy).
- Add robust PTY resize and signal forwarding behavior.
- Validate concurrent session behavior and long-running shell stability.

### Phase 3: Key-based login by default

- Integrate per-VM key provisioning via cloud-init.
- Make key auth default path, keep password mode as explicit dev fallback.
- Update docs and troubleshooting for native flow.

### Phase 4: Remove legacy path

- Remove `shell-proxy` command and external `ssh` invocation path.
- Keep protocol compatibility with `vmmon` control interface.

## Follow-ups

1. Define host key policy defaults and per-instance known_hosts location.
2. Decide libssh2 linkage strategy for supported host environments.
3. Add integration tests for handshake/auth failure paths, resize/signal handling, and concurrent shell sessions.
