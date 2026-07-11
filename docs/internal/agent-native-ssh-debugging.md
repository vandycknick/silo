# Agent Native SSH Debugging

This guide is for testing and debugging the guest agent's native SSH backend.

The native backend is implemented inside `silo-agent` with `russh`. It serves SSH directly on the accepted guest vsock stream. It does not shell out to OpenSSH and should not create `sshd` or `sshd-session` processes.

## Backend Selection

`SshService::new` normally chooses backends in this order:

1. Use OpenSSH when `/usr/sbin/sshd` exists.
2. Use the native `agent` backend when OpenSSH is unavailable.
3. If another process already owns guest `vsock::22`, leave that listener alone.

The third point is important. Selecting the native backend is not enough by itself. The agent also has to successfully bind guest `vsock::22`.

Expected native-agent logs:

```text
selected SSH backend backend="agent"
listening for SSH vsock connections port=22
native SSH backend is ready
```

This means the native backend was selected and is serving traffic.

This log means the native backend is not serving traffic:

```text
SSH vsock port is already in use, leaving the existing listener active
```

In that case, the selected backend may be `agent`, but shell traffic still goes to the existing listener.

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

## Forcing The Native Backend

For local testing on an image that still has OpenSSH installed, temporarily force `SshService::new` to skip OpenSSH detection.

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

## Disabling systemd's SSH Vsock Listener

On systemd 256+ guests, `systemd-ssh-generator` can automatically bind OpenSSH to guest `vsock::22` when `sshd` is installed. This races the Silo agent for the same port.

The intended kernel command line switch is:

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

## No Cmdline Override Workaround

If passing kernel command line arguments is inconvenient, use Silo userdata to stop and mask only the generated vsock SSH socket before the agent binds SSH.

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

For a persistent VM, this can be done once from inside the guest, then rebooted:

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

Current builds obtain `AgentConfig` from `vmmon` metadata. Confirm the VM booted
with the rebuilt initramfs and inspect `vmmon` and agent logs for metadata
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
