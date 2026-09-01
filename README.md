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

## CLI

Build the CLI locally:

```bash
nix develop
make build
```

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
