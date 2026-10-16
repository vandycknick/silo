# Real-VM smoke suite

This suite drives the staged CLI, daemon and runtime against real VMs. It is
intentionally outside CI and does not replace the unit or integration suites.

## Prerequisites and running

- Python 3.12+, `uv`, `openssl` and `sqlite3` on PATH (`nix develop` supplies uv
  and openssl).
- Linux: readable and writable `/dev/kvm`. macOS: Apple Silicon with Hypervisor
  Framework support and a signed silo-vmm with hypervisor/virtualization entitlements.
- Run as an ordinary user, not root.
- Run `make stage` first. Use the same `PROFILE` and `CARGO_TARGET_DIR` when
  staging and running; smoke does not build missing components.

```sh
make stage
make smoke
make smoke SMOKE_ARGS="-k lifecycle"
make smoke SMOKE_ARGS='-m "not daemon"'
make smoke SMOKE_ARGS="--backend vz"   # macOS only
make smoke SMOKE_ARGS="-k tty_resize --keep"
```

Options override environment variables. Paths should be absolute when supplied
explicitly. The Makefile sets binary and runtime directories for the selected
profile; use the corresponding pytest options to override them.

| Environment | pytest option | Default / meaning |
| --- | --- | --- |
| `SILO_SMOKE_BIN_DIR` | `--silo-bin-dir` | `<repo>/target/debug`; must contain silo |
| `SILO_SMOKE_RUNTIME_DIR` | `--silo-runtime-dir` | `<repo>/target/silo-runtime/<host-target>/debug` |
| `SILO_SMOKE_BACKEND` | `--backend krun\|vz` | `krun`; `vz` requires macOS |
| `SILO_SMOKE_CACHE` | `--cache-dir` | `${XDG_CACHE_HOME:-~/.cache}/silo-smoke` |
| `SILO_SMOKE_KEEP` | `--keep` | `1` retains workspaces even on success |
| `SILO_SMOKE_SYSTEM_IMAGE` | none | Appliance OCI reference; defaults to `ghcr.io/vandycknick/silo/system:dev` (the daemon dev default); set it empty to skip system tests |
| `SILO_SMOKE_DISTRO_IMAGES` | none | `label=oci-ref` list for the SSH distro lane; defaults to `arch=ghcr.io/vandycknick/archlinux:latest,system=<system image>`; set it empty to skip |
| `SILO_SMOKE_SYSTEMD_IMAGE` | none | Optional Phase F systemd image with vsock SSH socket activation |
| `SILO_SMOKE_CURL_IMAGE` | none | Optional Phase F image containing curl for live secret-provider tests |

Host targets are `linux-amd64-gnu`, `linux-arm64-gnu` and `darwin-arm64`.

Markers: `daemon` starts a private daemon; `system` needs the appliance image;
`sdk` runs Go/Node examples; `linux_only` and `macos_only` select host-specific
checks. Phase F also uses `slow` for long-running checks and `live` for
internet-dependent tests. Live tests require explicit selection with `-m live`.

The SDK lane skips when Go, Node, the built Node SDK or the Go FFI library is
missing. The system and distro lanes pull their published default images from
ghcr.io; `SILO_SMOKE_SYSTEM_IMAGE= SILO_SMOKE_DISTRO_IMAGES= make smoke` runs
fully offline. Pulled images are kept under `<cache>/images` (the same store
layout as `<SILO_HOME>/images`): tests that boot published images seed their
private Silo Home from it and write new pulls back, so only the first run
downloads anything. The systemd-owned SSH lane and the curl image have no
published default; nothing in this repository builds them yet. On macOS, daemon-managed VMs use krun even when direct CLI tests
select vz.

## Isolation and evidence

Every test creates a short workspace under `/tmp/silo-smoke-*` on Linux or
`/private/tmp/silo-smoke-*` on macOS. It gets private `HOME`, `SILO_HOME`,
`XDG_CONFIG_HOME` and `SILO_RUN_ROOT`. Subprocesses receive an explicit environment,
not the developer's daemon configuration. Socket paths stay within the Unix
socket path-length budget. A session guard records the live daemon's default
control socket inode and modification time and asserts they remain unchanged.

Teardown stops/removes registered VMs and terminates tracked daemons. Failed
runs and runs with `--keep` retain the workspace and print its path; successful
runs otherwise remove it. Command transcripts and daemon output are in
`/tmp/silo-smoke-*/evidence/*.log` (or the macOS equivalent). Keeping evidence
does not keep the VMs running.

## Images and registry

The first run downloads the architecture-matched Alpine 3.21.3 minirootfs and
verifies its pinned SHA-256. Verified cached archives are reused offline. The
base tar plus an overlay forms one gzip-compressed OCI layer, with a config and
manifest served by a session-local HTTPS registry bound to `127.0.0.1`. BASIC
adds `/etc/proof` and the unprivileged silo user/home. The agent is injected by
the initramfs, not included in the image.

To add an image, define an `ImageSpec` in `silo_smoke/images.py`, build it once
in a session fixture, then publish it through the registry:

```python
from silo_smoke.images import GuestDir, GuestFile, ImageSpec, build, fetch_alpine

spec = ImageSpec(
    name="example",
    files={"etc/example": GuestFile(data=b"example\n", mode=0o644)},
    dirs={"opt/example": GuestDir()},
    remove=frozenset(),
    append={},
)
image = build(spec, fetch_alpine(config.cache_dir))
reference = registry.publish(image, spec.name)
```

Paths are relative to the guest root. Overlay entries replace matching base
members; `append` adds bytes to existing text files and `remove` drops base
members. Absolute paths, traversal and duplicate normalized paths are rejected.
Keep scenario-specific additions in separate specs rather than changing BASIC.
BASIC also removes Alpine's busybox `/sbin/init` so the agent stays PID 1
(the agent hands off to any executable init it finds).

Specs can pull real Alpine packages: `ImageSpec.packages` lists
`ApkPackage(name, version)` entries fetched from the v3.21 `main` repository and
verified against the per-architecture hashes in `APK_SHA256`, and their payload
is laid down before `files`. `CA_TRUST` is BASIC plus `ca-certificates`, which
gives the guest the `update-ca-certificates` trust backend the agent needs when
a private network policy installs a certificate authority. Adding a package
means pinning its hashes for both architectures. `IPROUTE` adds `iproute2-ss`
(with `libmnl` and `libcap2`) so a guest can list vsock listeners with
`ss --vsock`; pins come from the v3.21 APKINDEX `P`/`V`/`D` fields and the
SHA-256 of the downloaded archives.

Linux trusts the registry through the workspace's `SSL_CERT_FILE`, which points
at `<workspace>/ca-bundle.pem`: the host's CA bundle plus the suite CA, because
that variable replaces (not extends) the trust store for Go and rustls consumers
and `netd` still has to verify public upstreams. On macOS,
the Rust OCI client's platform verifier ignores that variable. Trust the stable
suite CA once in your login keychain after it has been generated (preflight
prints the instruction):

```sh
security add-trusted-cert -r trustRoot \
  -k ~/Library/Keychains/login.keychain-db <cache>/registry-ca/ca.pem
```

Here `<cache>` is the resolved smoke cache directory. Changing that directory
or replacing its CA requires trusting the new certificate. The registry's leaf
certificate is issued per session with localhost/127.0.0.1 subject alternatives.
