# BentoBox 🍱

BentoBox is a microVM manager that boots a full Linux environment in seconds. It is built around reusable profiles, a local raw image registry, and a small `bento` CLI for creating, running, and inspecting VMs. Use it as a WSL-like development environment on macOS, a lightweight Docker Desktop alternative, or an isolated throwaway VM for agentic workflows.

## Runtime Backends

- macOS: Apple `Virtualization.framework`
- Linux: libkrun through the `krun` helper

Backend selection is internal to BentoBox and depends on the host platform. `VmSpec` describes the VM; users do not choose the backend.

See [`docs/terminology.md`](docs/terminology.md) for the vocabulary BentoBox uses around VMs, VMMs, hypervisors, KVM, microVMs, and backend drivers.

## Inspiration

BentoBox draws inspiration from these projects, which helped shape its architecture and developer experience:

- [macosvm](https://github.com/s-u/macosvm)
- [UTM](https://github.com/utmapp/UTM)
- [Lima](https://github.com/lima-vm/lima)
- [vfkit](https://github.com/crc-org/vfkit)

## Getting Started

Enter the Nix development shell:

```bash
nix develop
```

The shell provides the Rust, Go, and native build tools used by this repository.

Build BentoBox and its host runtime helpers locally:

```bash
make build
./target/debug/bento --help
```

## CLI Layout

```text
BentoBox VM lifecycle control

Usage: bento [OPTIONS] <COMMAND>
Commands:
  run      Run an ephemeral VM from a profile or image
  create   Create a persistent VM from a profile or image
  start    Start a persistent VM
  stop     Stop a persistent VM
  restart  Restart a persistent VM
  rm       Remove a persistent VM
  shell    Open a shell in a running VM
  exec     Execute a command in a running VM
  list     List VMs [aliases: ls]
  status   Show VM status
  inspect  Show full VM details
  logs     Show VM logs
  profile  Manage reusable VM profiles

Options:
  -v, --verbose...  Increase diagnostic output. Repeat for full error chains
  -h, --help        Print help
```

## Profiles

Profiles are reusable VM definitions stored under `~/.config/bento/profiles/` as `.yaml` or `.yml` files. If `bento run` is used without a profile, BentoBox looks for `default.yaml` or `default.yml`; if neither exists, it uses the built-in `default` profile based on `ghcr.io/vandycknick/archlinux:latest`.

Create, show, validate, edit, and remove profiles through the `profile` command group:

```bash
bento profile create rust-dev \
  --image ghcr.io/vandycknick/archlinux:latest \
  --description "Rust development box" \
  --cpus 4 \
  --memory 4gb \
  --disk-size 40gb \
  --mount .:/workspace:rw \
  --network private \
  --label stack=rust \
  --ssh

bento profile list
bento profile show rust-dev
bento profile validate rust-dev
bento profile edit rust-dev
bento profile rm rust-dev
```

A profile created by the CLI looks like this:

```yaml
version: "1"
description: Rust development box
image:
    ref: ghcr.io/vandycknick/archlinux:latest
resources:
    cpus: 4
    memory: 4gb
disk_size: 40gb
mounts:
    - source: .
      target: /workspace
      mode: rw
network:
    kind: private
ssh:
    enabled: true
labels:
    stack: rust
```

Size values must include a unit suffix. Accepted units are `mb`, `gb`, `mib`, and `gib`, case-insensitive with optional whitespace, such as `512mb`, `4gb`, or `1 GiB`; bare numbers like `4096` are rejected.

## Ephemeral VMs

`bento run` creates a temporary VM, starts it, opens a shell or runs a command, then removes the VM when the session exits.

```bash
# Run the built-in or configured default profile.
bento run

# Run from a named profile.
bento run rust-dev

# Run a command after `--` and delete the VM with the command's exit status.
bento run rust-dev -- cargo test

# Keep the VM only when the command fails, useful for poking the crime scene.
bento run rust-dev --keep-on-failure -- cargo test
```

Run directly from an image when you do not need a profile:

```bash
bento run --image ubuntu:24.04 -- uname -a
```

Override VM shape and profile settings at launch:

```bash
bento run rust-dev \
  --cpus 6 \
  --memory 8gb \
  --disk-size 80gb \
  --mount ~/src:/src:rw \
  --network private \
  --label purpose=ci \
  -- cargo test
```

Ephemeral VM names use the profile or image-derived prefix plus a 1-based index, such as `rust-dev-1`.

## Persistent VMs

`bento create` creates a named VM that stays around until you remove it.

```bash
# Create from a profile.
bento create dev rust-dev

# Create from a profile and start immediately.
bento create dev rust-dev --start

# Create from an image without a profile.
bento create ubuntu --image ubuntu:24.04 --cpus 4 --memory 4gb
```

Lifecycle commands operate on a VM name or ID:

```bash
bento start dev
bento shell dev
bento exec dev -- pwd
bento logs dev --follow
bento status dev
bento inspect dev --json
bento stop dev
bento restart dev
bento rm dev
```

Use `bento shell --attach serial` when the guest agent or SSH is unavailable:

```bash
bento shell dev --attach serial
```

List VMs in table or JSON form:

```bash
bento list
bento ls --json
```

## Images

BentoBox creates VMs from raw disk images registered in `~/.local/share/bento/images/registry.json`. The registry is intentionally small and manually editable:

```json
{
    "version": 1,
    "images": {
        "ghcr.io/vandycknick/archlinuxarm:latest": "sha256-abc123/rootfs.img"
    }
}
```

Registry paths are relative to `~/.local/share/bento/images` and must point to a `rootfs.img` file. For the example above, BentoBox clones or copies `~/.local/share/bento/images/sha256-abc123/rootfs.img` into the VM when creating from `ghcr.io/vandycknick/archlinuxarm:latest`.

## Introspection

Status is concise and readiness-oriented; inspect is the full machine record.

```bash
bento status dev
bento status dev --json
bento inspect dev
bento inspect dev --json
```

`status` includes process state, guest agent readiness, services, network mode, profile, and image. `inspect --json` is the better target for scripts that need labels, metadata, paths, and the resolved VM spec.

## More Docs

- [`docs/terminology.md`](docs/terminology.md): BentoBox vocabulary and backend terminology
- [`resources/README.md`](resources/README.md): bundled resources
- [`builders/README.md`](builders/README.md): image and artifact builders
- [`guest/bento-agent/README.md`](guest/bento-agent/README.md): guest agent details
