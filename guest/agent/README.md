# silo-agent

Guest-side agent for Silo VMs.

`silo-agent` runs inside the Linux guest and connects back to Silo's guest control plane over vsock. It is responsible for registration, SSH access, guest-side forwarding, and optional guest provisioning.

## Overview

`silo-agent` currently does four main jobs inside the guest:

- registers with the host-side control service over vsock
- serves SSH on guest `vsock::22` when that port is free
- runs the guest-side forward service used by the `forward` plugin
- runs optional guest provisioning tasks

The control RPC port is selected from the kernel command line via `silo.agent.port`. If that kernel arg is missing or invalid, the agent falls back to Silo's default control port.

At startup the agent:

1. initializes tracing
2. loads guest config from disk
3. reads the control port from `/proc/cmdline`
4. runs provisioning if enabled
5. attempts to bind guest `vsock::22` for SSH, unless another listener already owns it
6. starts the forward service if enabled
7. registers with the host-side control service

## Config

The default guest config path is:

```text
/etc/silo/agent.yaml
```

If the file is missing, the agent falls back to its built-in defaults.

Current config shape:

```yaml
forward:
  enabled: false
  port: 0
  uds: []

provision:
  enabled: false
```

Example with all supported sections populated:

```yaml
forward:
  enabled: true
  port: 4000
  uds:
    - guest_path: /var/run/docker.sock

provision:
  enabled: true
  hostname: silo-dev
  resize_rootfs:
    enabled: true
```

Notes:

- SSH is not configured here. The agent attempts to bind guest `vsock::22`; if another listener already owns `vsock::22`, the agent leaves it alone.
- `forward.port` must be set when `forward.enabled` is true. This is the guest-side vsock port used by the host `forward` plugin endpoint.
- `forward.uds` is an allowlist of guest Unix socket paths the forward service may connect to.
- `provision` controls optional guest provisioning work such as hostname and root filesystem resizing.
- The agent does not read its control RPC port from this file. That comes from the kernel arg owned by the host side.

## SSH

When `silo-agent` owns guest `vsock::22`, it prepares OpenSSH's `/run/sshd` runtime directory before registering with the host. Each incoming connection then starts `/usr/sbin/sshd -i` and passes the accepted vsock stream as the child process stdin/stdout. This matches the inetd-style shape used by systemd socket activation for `sshd-vsock.socket`, while keeping the child stderr attached to the agent logs instead of the SSH byte stream.

Some systemd guests can automatically bind SSH sockets such as `vsock::22` before the agent starts. To disable those automatic systemd SSH bindings and let `silo-agent` own the port, add this kernel command line argument:

```text
systemd.ssh_auto=0
```

Explicit systemd SSH listeners configured with `systemd.ssh_listen=` or the `ssh.listen` system credential still apply even when automatic bindings are disabled.

## Logging

`silo-agent` writes its runtime logs to stderr.

In the default systemd boot path, logs are captured by the service manager, for example through `journalctl -u silo-agent.service`.

## Bootstrap

Today Silo expects `silo-agent` to be handed off by `silo-init` and started by systemd.

The runtime initramfs embeds `/agent/silo-agent` and `/agent/silo-agent.yaml`. `silo-init` copies those files into `/run/agent`, writes a transient `silo-agent.service` unit under `/run/systemd/system`, and lets systemd start it during the normal boot.

When the process is running as PID 1, the current behavior is intentionally minimal. The agent detects PID 1 and logs that init mode is not implemented yet. Direct PID 1 initialization support is planned, but is still to be implemented.

That future mode is expected to cover the pieces currently delegated to the guest OS boot flow, such as early system setup and service supervision.

## Cross-Compilation

The current repo-level helper is:

```bash
make build-guest-agent
```

That target builds the guest agent binary and copies it into Silo's runtime assets directory:

```text
target/resources/assets/agent
```

Current target details:

- target triple: `aarch64-unknown-linux-musl`
- output binary: `target/aarch64-unknown-linux-musl/release/silo-agent`

The current flow still likely needs some tuning, especially around local toolchain assumptions and Linux-target verification on non-Linux hosts.

If you want to run the command manually, it is currently equivalent to:

```bash
cargo zigbuild -p agent --target aarch64-unknown-linux-musl --release
```

## Status

This crate is Linux-guest-only. Host-side validation can be done from macOS, but full agent compilation and runtime verification still depend on having the Linux target toolchain available.
