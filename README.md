<p align="center">
  <img src="docs/brand/silo-lockup-transparent-web.webp" alt="Silo" width="520">
</p>

Silo is a local microVM sandbox runtime where machines are created from OCI images.

The short version:

1. OCI image in.
2. Runtime config from policy.
3. Small, isolated VM out.

## Core Principles

- **Image first**: OS images are built from OCI images.
- **API first**: `libvm` is the core runtime interface.
- **Policy first**: networking, kernel access, and userspace access are driven by policy.

Only network policies are implemented today. Kernel and userspace policies are the direction.

The optional system appliance is managed by the separate `silod` executable.
`silo daemon up` starts it through the native service manager; the CLI does not
run the daemon loop. Direct CLI VM operations continue to use libvm in process.

Each running VM is supervised by one `silo-vmm` process, Silo's virtual machine
monitor (VMM). It manages VM configuration, execution, and lifecycle across
virtualization backends.
With the default krun backend, libkrun runs in a private worker: the same
`silo-vmm` executable started with argv[0] `krun`. There is no standalone
krun runtime binary. Runtime packages ship it as `bin/silo-vmm` (or
`Contents/Helpers/silo-vmm` in `Silo.app`). See the
[silo-vmm architecture and qualification notes](docs/architecture/silo-vmm.md).

## Development tests

Run `make test` inside `nix develop` for the host-supported Rust suites and netd
tests. Rust tests use cargo-nextest with process isolation and a single workspace
pass; integration tests share a prebuilt mock `silo-vmm`. `make test-unit` runs
Rust unit tests only, while `make test-integration` runs Rust integration tests
and netd tests. Both Rust unit commands also test rprobe without default features.

With `CI=true`, nextest uses the `ci` profile and writes JUnit results under
`target/nextest/ci/junit.xml` (under `CARGO_TARGET_DIR` when overridden).
Real-VM qualification is separate; see the [smoke suite](smoke/README.md).

## CLI

Build the CLI locally:

```bash
nix develop
make build
```

On Apple Silicon macOS, this also downloads and verifies the prebuilt Rosetta
probe, so no Linux builder is needed for normal development. Use
`RPROBE_PATH=/absolute/path/to/rprobe` to override it with a locally built probe,
or `RPROBE_REFRESH=1` to refresh the cached registry reference. See the
[probe guide](guest/rprobe/README.md#development-builds-and-publication).

Run a temporary workload from an image:

```bash
silo run ubuntu:24.04 -- uname -a
```

Image operands are OCI registry references, or local disk images written as
`disk:PATH`. Without `--name`, `run` creates a generated ephemeral machine and
removes it after the workload finishes.

Detached mode runs the workload in the background. It does not make the VM
independent of that workload: the VM still stops when the workload exits.

```bash
silo run --detach ubuntu:24.04 -- sleep 300
silo run --detach --name worker ubuntu:24.04 -- sleep 300
silo logs worker --stream exec --follow
```

The first detached machine is removed after `sleep` exits. The named machine is
stopped but retained for later inspection. If no command follows `--`, `run`
uses the image's resolved default workload; an interactive shell may exit
immediately when detached because it has no attached terminal or input. See the
[run lifecycle guide](docs/run-lifecycle.md) for the complete behavior matrix.

Create a persistent VM, then start it when you need an idle development
environment:

```bash
silo create ghcr.io/vandycknick/archlinux:latest --name dev
silo start dev
silo shell dev
```

`create` always leaves the VM stopped. `start` and `restart` boot a persistent
VM without starting an application workload. Image process settings are retained
with the machine and provide the default command for `silo exec dev` when no
command follows `--`.

Copy regular files to and from a running VM:

```bash
silo cp ./patch.diff dev:/root/patch.diff
silo cp dev:/root/shot.png ./shot.png
```

Use `-` for stdin/stdout. Uploads accept `--mode OCTAL`, numeric
`--owner UID[:GID]`, `--parents` (`-p`), and best-effort (not atomic)
`--no-clobber` (`-n`). Guest paths must be absolute; prefix local paths
containing `:` with `./` or `/`. Downloads replace the local target atomically.
Use `--format json` for a transfer summary, except when downloading to stdout
(`-`), where stdout carries only file bytes. Human summaries go to stderr.

## Templates

Templates are reusable machine defaults stored below the Silo configuration
directory. They are strict version-1 YAML documents: `version` must be the
string `"1"`, and unknown fields are rejected. A template may provide an image;
a positional image on `create` or `run` takes precedence.

```yaml
version: "1"
description: Development defaults
image: ubuntu:24.04
resources:
  cpus: 4
  memory: 4gb
disk_size: 40gb
network:
  kind: private
labels:
  team: runtime
```

Create and validate one with:

```bash
silo template create dev ubuntu:24.04
silo template edit dev
silo template validate dev
silo run --template dev -- cargo test
```

Inspect and manage machines:

```bash
silo ls
silo status dev
silo stop dev
silo rm dev
```

## Persistent Docker Service

Silo can run an optional per-user Docker Engine in a persistent system VM. Its
engine data survives daemon and appliance replacement, while the host uses the
dedicated `silo` Docker context and `~/.silo/run/docker.sock` endpoint. This is
separate from ordinary Silo VMs and does not require or replace a host Docker
Engine.

See the [system daemon operator guide](docs/system-daemon.md) for setup,
security implications, lifecycle, upgrades, recovery, and deliberate v1
limitations.

## SDK

Use `libvm` when you want to create and manage machines directly from Rust. See
the [libvm guide](runtime/libvm/README.md), [Node SDK guide](sdk/node/README.md), and
[Go SDK guide](sdk/go/README.md) for lifecycle and process details. The Go SDK includes an
explicit, digest-verified installer for the exact matching runtime archive.

```rust
use libvm::{LibVmError, Memory, Runtime};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), LibVmError> {
    let runtime = Runtime::from_env().await?;

    let machine = runtime
        .machine()
        .image("ghcr.io/vandycknick/archlinux:latest")
        .name("devbox")
        .cpus(6)
        .memory(Memory::gibibytes(16))
        .network(|network| network.private())
        .create()
        .await?;

    machine.start().await?;

    Ok(())
}
```

## Docs

- [Packaging](PACKAGING.md)
- [Hybrid vsock](docs/hybrid-vsock.md)
- [Terminology](docs/terminology.md)
- [Guest agent](guest/agent/README.md)
- [System daemon](docs/system-daemon.md)
