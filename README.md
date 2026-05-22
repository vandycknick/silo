# BentoBox 🍱

BentoBox is a microVM manager that boots a full Linux environment in seconds. It is built around reusable profiles and simple VM lifecycle commands. Whether you want a WSL-like development environment on macOS, a fresh Docker Desktop alternative, or an isolated VM for agentic workflows, BentoBox has you covered.

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

Install with Nix profile:

```bash
nix profile install .#bentoctl
```

This installs both `bento` and the compatibility alias `bentoctl`.

Or build locally with Nix:

```bash
nix build .#bentoctl
./result/bin/bento --help
```

## Usage

```text
BentoBox VM lifecycle control

Usage: bento [OPTIONS] <COMMAND>

Commands:
  run
  create
  start
  stop
  restart
  rm
  shell
  exec
  logs
  profile
  delete
  list
  status
  inspect
  images

Options:
  -v, --verbose...
  -h, --help        Print help
```

## Profiles

Profiles are reusable VM definitions stored under `~/.config/bento/profiles/`.

If `bento run` is used without a profile, BentoBox looks for `default.yaml` or `default.yml` in that directory. If neither exists, it uses a built-in `default` profile based on `ghcr.io/vandycknick/archlinux:latest`.

Create a profile:

```bash
bento profile create rust-dev --image ghcr.io/vandycknick/archlinux:latest --network isolated
```

List profiles:

```bash
bento profile list
```

## Ephemeral VMs

Run an ephemeral VM from the default profile:

```bash
bento run
```

Run from a named profile:

```bash
bento run rust-dev
```

Run a command and delete the ephemeral VM when it exits:

```bash
bento run rust-dev -- cargo test
```

Ephemeral VM names use the profile name and a 1-based index, such as `rust-dev-1`.

Keep a failed run for debugging:

```bash
bento run rust-dev --keep-on-failure -- cargo test
```

## Persistent VMs

Create a persistent VM from a profile:

```bash
bento create dev rust-dev
```

Create directly from an image:

```bash
bento create dev --image ghcr.io/vandycknick/archlinux:latest
```

Start it:

```bash
bento start dev
```

Open a shell:

```bash
bento shell dev
```

Run a single command over SSH, while best-effort `cd`-ing into your current host working directory first:

```bash
bento exec dev -- pwd
```

Stop it:

```bash
bento stop dev
```

List persistent VMs:

```bash
bento list
```

## More Docs
