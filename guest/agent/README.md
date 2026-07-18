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
4. runs provisioning if enabled, with loopback and optional static networking first
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
  network:
    interfaces:
      - mac_address: "02:00:00:00:00:02"
        ipv4:
          address: 192.168.105.2
          prefix_length: 24
          gateway: 192.168.105.1
        dns:
          servers: [192.168.105.1]
          search: []
  hostname: silo-dev
  resize_rootfs:
    enabled: true
```

Notes:

- SSH is not configured here. The agent attempts to bind guest `vsock::22`; if another listener already owns `vsock::22`, the agent leaves it alone.
- `forward.port` must be set when `forward.enabled` is true. This is the guest-side vsock port used by the host `forward` plugin endpoint.
- `forward.uds` is an allowlist of guest Unix socket paths the forward service may connect to.
- `provision` controls optional guest provisioning work such as static networking, hostname, and root filesystem resizing.
- `provision.network` is omitted for a machine without a network attachment. When provisioning is enabled, the network provisioner still brings up loopback but leaves non-loopback links, routes, and `/etc/resolv.conf` untouched.
- Networking is the first provisioner. It brings up loopback, then matches and configures the optional static interface through Linux rtnetlink without invoking DHCP, `ip`, or a network manager.
- The host only configures a guest certificate authority when its network policy contains an HTTPS interception endpoint. VMs without a policy and VMs with only IP or HTTP endpoints do not generate, transfer, or install CA material.
- CA trust installation uses `update-ca-certificates` when available, otherwise p11-kit `trust`. A configured CA is required launch state, so a missing or failed trust backend fails managed boot.
- Ext4 root filesystems grow through the kernel's online resize ioctl. Guest images do not need `findmnt`, `resize2fs`, or e2fsprogs.
- A configured root filesystem resize is required launch state. Discovery or resize failures fail managed boot instead of exposing less capacity than requested.
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

Silo distributes an agent-free base initramfs and a standalone agent. At each
managed launch, `libvm` appends `/agent/silo-agent` and `/agent/config.json` in a
raw CPIO overlay. `silo-init` validates and copies both files to `/run/agent`,
then invokes the agent with `--config=/run/agent/config.json`.

The agent supports ordinary process startup and the managed PID 1 handoff mode.
Custom agents and initramfs implementations must honor the same explicit config
path and guest API contract when managed readiness is enabled.

## Cross-Compilation

The current repo-level helper is:

```bash
make build-guest-agent
```

That target builds the guest agent binary and copies it into Silo's runtime assets directory:

```text
target/resources/assets/agent
```

The helper selects a statically linked musl target matching the host architecture:

- x86_64: `x86_64-unknown-linux-musl`
- arm64: `aarch64-unknown-linux-musl`

Override `GUEST_TARGET` when intentionally cross-building for another architecture.

For example:

```bash
make build-guest-agent GUEST_TARGET=x86_64-unknown-linux-musl
```

## Status

This crate is Linux-guest-only. Host-side validation can be done from macOS, but full agent compilation and runtime verification still depend on having the Linux target toolchain available.
