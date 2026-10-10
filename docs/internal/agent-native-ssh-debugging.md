# Agent Native SSH Debugging

This guide is for testing and debugging the guest agent's native SSH backend.

The native backend is implemented inside `silo-agent` with `russh`. It serves SSH directly on the accepted guest vsock stream. It does not shell out to OpenSSH and should not create `sshd` or `sshd-session` processes.

## Backend Selection

`SshService::new` normally chooses backends in this order:

1. Use OpenSSH when `/usr/sbin/sshd` exists.
2. Use the native `agent` backend when OpenSSH is unavailable.
3. If another process already owns guest `vsock::22`, validate its systemd OpenSSH socket and CA-only policy, then delegate to it.

Production ownership is **first binder wins**. The agent attempts to bind port 22 once. If it wins, it serves its selected `openssh` or `agent` backend. If systemd wins, the agent validates the active socket, exact port, Accept setting, service command, and effective sshd policy before publishing a `systemd-openssh` descriptor. An unrecognized or noncompliant owner fails startup; it is not advertised as trusted SSH.

Trust configuration and service overrides are installed before init handoff. Neither owner steals the listener or polls/rebinds. A generated `sshd-vsock.socket` that loses the bind may remain failed with `EADDRINUSE` while the agent-owned listener is healthy. Do not reset that losing unit, mask it in production, or use `systemd.ssh_auto=no` as the production ownership policy.

For `Accept=yes`, systemd uses the matching `sshd-vsock@.service` template. Validation queries an unstarted inspection instance of that template: `Triggers` lists live instances and can be empty before the first connection, while `systemctl show` cannot directly inspect a bare template. See the [systemd socket activation contract](https://www.freedesktop.org/software/systemd/man/latest/systemd.socket.html#Service=). The inspection instance is never started and does not own a socket.

Expected native-agent logs:

```text
selected SSH backend backend="agent"
listening for SSH vsock connections port=22
native SSH backend is ready
```

This means the native backend was selected and is serving traffic.

When systemd owns the listener, an INFO event records delegation to the validated external OpenSSH listener. The selected agent backend is not serving traffic in that case; the status descriptor identifies the actual owner as `systemd-openssh`.

## Cached Host SSH Verification

Guest status receipts still arrive every five seconds. They describe the listener and its verified configuration, but the guest's `kex_verified` assertion is not trusted. The host independently verifies the advertised listener key and the immutable host-key pin. Initial eligibility and relevant identity/backend/port/key changes trigger an immediate check, after any old attempt's resources drain.

For an unchanged target, the next check starts **60 seconds after the previous check completes**, after either success or failure. Healthy idle operation therefore still makes periodic pre-authentication SSH connections, but no longer one connection per status heartbeat. Status and metrics receipt processing continues while a check connects, shuts down, verifies the pin, or waits for resources to drain.

One attempt has a five-second readiness budget. Successful evidence expires after at most 65 seconds and identical heartbeats do not renew it. A fresh raw Ready report with pending, failed, or expired SSH evidence is exposed as Starting with `SSH_NOT_READY` and `kex_verified=false`. Freshness is independent: a handshake cannot refresh a stale guest observation.

The normal health-detection window is up to **60 + 5 seconds**. Failed checks retry at the same cadence, not on every heartbeat. Configuration changes, identity replacement, loss of the control connection, and stopping invalidate the cached evidence. Normal periodic checks retain prior successful evidence until its deadline.

The probe sends a local SSH disconnect and joins the connection task after KEX. Cancellation closes its owned transport before another attempt can start. Pin locking is nonblocking; a contended lock is a failed check at the normal cadence. Filesystem syscalls already in progress cannot be canceled, so a timed-out pin job is drained before a replacement attempt. The readiness budget does not promise five-second termination of every OS syscall.

Actual authenticated SSH sessions continue to check the host pin and use certificate authentication. Cached readiness is not a replacement for those session security checks.

## OpenSSH Connection Diagnostics

Production OpenSSH children retain their VERBOSE syslog diagnostics; the invocation does not add `-e`. At child exit the agent checks whether a Unix datagram connect to `/dev/log` succeeds, without sending a message. Socket-path existence alone does not establish availability, and this best-effort check is not a delivery guarantee.

- Exit zero is a DEBUG connection-lifecycle event.
- Normal nonzero exit with reachable syslog is DEBUG, retaining the numeric status. A pre-authentication readiness disconnect can legitimately produce such an exit.
- Normal nonzero exit without reachable syslog is WARN, retaining status and noting unavailable syslog. Logger-less guests deliberately retain this conservative fallback.
- Signal termination is WARN regardless of syslog availability. Spawn/wait/stderr-read errors and captured stderr retain their diagnostics.

The systemd-owned listener uses systemd/journal diagnostics instead of the agent child-wait policy. Individual pre-authentication service instances can exit nonzero; do not globally declare exit 255 successful with `SuccessExitStatus=255`. Less frequent probes reduce lifecycle noise but do not establish the cause of slow interactive SSH setup or stalls.

## Process Tree Check

A native-agent-backed shell should look roughly like this:

```text
/run/agent/silo-agent
└─ /bin/bash
   └─ htop
```

If the process tree contains `sshd`, `sshd-session`, or `/usr/bin/sshd -D`, that session is still OpenSSH-backed:

```text
/usr/bin/sshd -D [listener]
└─ sshd-session: nickvd [priv]
   └─ sshd-session: nickvd@pts/0
      └─ /bin/bash -l
```

`russh` cannot produce `sshd-session` processes. If they are present, OpenSSH handled the session.

## Forcing The Native Backend (Diagnostic Only)

The following temporary source change is for isolated local diagnostics only, not production listener ownership policy. On an image that still has OpenSSH installed, temporarily force `SshService::new` to skip OpenSSH detection.

In `guest/agent/src/ssh/mod.rs`, temporarily change:

```rust
if openssh::exists() {
```

to:

```rust
if false && openssh::exists() {
```

Then rebuild the guest assets and boot with the rebuilt initramfs:

```bash
make build-guest-agent
make initramfs
cargo run -p cli -- run agent --initramfs target/resources/assets/initramfs --disk-size 300gb -- true
```

Always pass the rebuilt initramfs while testing local agent changes. Without this, `silo run` may use installed assets and accidentally test an older guest agent.

## Disabling systemd's SSH Vsock Listener (Diagnostic Only)

On systemd 256+ guests, `systemd-ssh-generator` can automatically bind OpenSSH to guest `vsock::22`. Production permits this first-binder-wins race with mandatory trust validation. For an isolated native-backend diagnostic fixture only, the kernel command line switch is:

```text
systemd.ssh_auto=no
```

`0` is also valid:

```text
systemd.ssh_auto=0
```

This disables automatic SSH sockets from `systemd-ssh-generator`, including the generated vsock listener on `vsock::22`.

Explicit listeners still apply. These sources are not disabled by `systemd.ssh_auto=no`:

```text
systemd.ssh_listen=
ssh.listen system credential
```

If the image also enables normal TCP OpenSSH and you want a less confusing process tree, you can separately mask the normal service:

```text
systemd.mask=sshd.service
```

Do not rely on masking `ssh.socket` or `sshd.socket` for the systemd-generated vsock listener. On Arch Linux with modern systemd, the generated unit is named around `sshd-vsock.socket`, not the classic distro socket names.

## No Cmdline Override Workaround (Diagnostic Only)

If passing kernel command line arguments is inconvenient, an isolated diagnostic fixture can use Silo userdata to stop and mask only the generated vsock SSH socket before the agent binds SSH. This masking is not the production ownership policy and must not be applied to existing running VMs for qualification.

Create `disable-systemd-vsock-ssh.sh`:

```sh
#!/bin/sh
set -eu

systemctl stop sshd-vsock.socket 2>/dev/null || true
systemctl stop 'sshd-vsock@*.service' 2>/dev/null || true

mkdir -p /etc/systemd/system
ln -sf /dev/null /etc/systemd/system/sshd-vsock.socket

systemctl daemon-reload 2>/dev/null || true
```

Boot with that userdata script:

```bash
cargo run -p cli -- run agent \
  --initramfs target/resources/assets/initramfs \
  --disk-size 300gb \
  --userdata ./disable-systemd-vsock-ssh.sh \
  -- true
```

This works because Silo userdata runs during agent provisioning, before `silo-agent` tries to listen on guest `vsock::22`.

Only on a disposable diagnostic VM, the equivalent persistent mask requires a reboot:

```bash
sudo systemctl stop sshd-vsock.socket
sudo systemctl mask sshd-vsock.socket
sudo reboot
```

## Useful Checks

Inside the guest:

```bash
cat /proc/cmdline
systemctl list-units 'sshd*' --all
systemctl list-sockets | grep -i ssh
ss -H -f vsock -lpn
ps auxf
```

From the host:

```bash
cargo run -p cli -- logs <vm-name>
cargo run -p cli -- shell <vm-name>
```

If testing an ephemeral VM with local guest-agent changes, keep using the rebuilt initramfs path:

```bash
cargo run -p cli -- run agent --initramfs target/resources/assets/initramfs --disk-size 300gb -- true
```

## Common Clues

```text
selected SSH backend backend="agent"
SSH vsock port is already in use
```

The native backend was selected, but systemd/OpenSSH already owns `vsock::22`.

```text
sshd-session
```

The shell is OpenSSH-backed, not native-agent-backed.

```text
SSH public-key authentication failed
```

Current builds obtain `AgentConfig` from `silo-vmm` metadata. Confirm the VM booted
with the rebuilt initramfs and inspect `silo-vmm` and agent logs for metadata
retrieval, decoding, or schema failures. `/run/agent/config.json` is not
expected in the current implementation.

After [ADR 0009](../adr/0009-per-launch-guest-agent-initramfs-overlay.md) is
implemented, confirm the VM booted with the per-launch composite initramfs. At
that point, a missing or incompatible `/run/agent/config.json` indicates an
overlay selection, extraction, or validation failure.

```text
selected SSH backend backend="agent"
listening for SSH vsock connections port=22
native SSH backend is ready
```

The native backend owns the Silo shell path. If a shell still shows `sshd-session`, verify that you connected through `silo shell` and not direct network SSH.

## Isolated Real KVM Qualification

`runtime/libvm/tests/ssh_verification.rs` covers the agent-owned listener, systemd-owned listener, and systemd socket failure/recovery. The ownership controls in userdata are test-only. Each case uses a temporary Silo home, a machine-local copy of a disposable disk, one vCPU, 1 GiB, vsock, and no guest network. No existing VM or writable disk should be reused.

Required inputs:

- Accessible `/dev/kvm`.
- `SILO_TEST_RUNTIME_ROOT` pointing at a freshly built/staged **release** runtime (normally `target/silo-runtime/<runtime-target>/release`).
- `SILO_TEST_DISK_IMAGE` pointing at a disposable systemd/OpenSSH base image with `systemd-ssh-generator`, `sshd`, `systemctl`, `journalctl`, `systemd-run`, `ss`, and `timeout`.

An unset `SILO_E2E_KVM` skips these gated cases; missing prerequisites after explicitly enabling qualification fail the case. A skipped case is not qualification evidence. Run each case separately, setting the artifact variables first:

```bash
SILO_E2E_KVM=1 cargo test -p libvm --test ssh_verification ssh_verification_agent_owned_real_kvm -- --exact --nocapture
SILO_E2E_KVM=1 cargo test -p libvm --test ssh_verification ssh_verification_systemd_owned_real_kvm -- --exact --nocapture
SILO_E2E_KVM=1 cargo test -p libvm --test ssh_verification ssh_verification_failure_recovery_real_kvm -- --exact --nocapture
```

The healthy cases observe 135 seconds of continued host readiness and fresh status/metrics. The agent-owned case unmasks and attempts the generated socket after readiness to demonstrate the expected EADDRINUSE loss without disrupting its sole agent-owned listener. The systemd-owned case establishes systemd ownership before the agent's bind. Each exercises certificate SSH outside the idle sample; inspections use the agent exec API, not additional SSH sessions.

The recovery case creates and verifies a `systemd-run` timer to restart the socket after 75 seconds, then stops the socket through root exec. It requires `SSH_NOT_READY` within 65 seconds with fresh guest receipts, and recovery on the normal cadence within 140 seconds. It does not attempt a new SSH session while deliberately unhealthy.

Evidence includes listener/process/descriptor snapshots, status and metrics receipt times, readiness transitions, and guest journal output for manual probe accounting without relying on OpenSSH log prose. Host `/proc/<pid>/stat` tick deltas are normalized to one core using `getconf CLK_TCK`, with main-thread context-switch deltas and supervisor/worker children and descriptor counts. Sustained supervisor CPU above 1% of one core fails qualification and requires profiling; compare actual idle measurements to the prior 0.02–0.03% baseline rather than claiming these changes solve interactive stalls.

Each exercise is bounded to 210 seconds plus bounded stop handling, including on errors. Failed fixture artifacts are retained after teardown with `ssh-qualification.log`; successful fixtures are removed. Do not roll out or profile these changes on existing VMs without a separately coordinated restart.
