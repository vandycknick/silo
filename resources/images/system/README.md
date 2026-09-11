# Silo system appliance

This directory builds `ghcr.io/vandycknick/system`, the Debian 13 appliance
used by the optional per-user Silo system service. It is an OCI root filesystem,
not a Docker-in-Docker bootstrap container. Silo materializes and boots it as a
normal persistent VM.

## Pinned inputs

- Debian `13-slim` OCI index digest:
  `sha256:d7e12182ce18b85b93007c1dedf31f2d29e01ccf3182cc4017c709b6259bc132`
- Debian archive snapshot: `20260825T000000Z`
- Docker CE and CLI: `5:29.8.0-1~debian.13~trixie`
- containerd.io (including runc): `2.3.5-1~debian.13~trixie`
- Docker apt signing key SHA-256:
  `1500c1f56fa9e26b9b8f42452a553675796ade0807cdce11975eb98170b3a570`
- `silo-portd`: static musl binary built from the image source revision with
  the workspace lockfile

The complete installed package inventory is stored in
`/usr/lib/silo-system/packages.tsv`. Base and package selections were reviewed
against the official Debian image metadata, Debian snapshot archive, and
Docker's Debian repository. Debian packages retain their copyright files under
`/usr/share/doc`; `/usr/lib/silo-system/NOTICE` records source and license
provenance.

## Build

```sh
make ARCH=amd64 build
make ARCH=arm64 build
```

Each architecture is built on a matching native Linux runner. CI
publishes the two images by digest and creates the multi-platform index only
after both builds and qualification lanes pass. `make rootfs` emits the OCI
root filesystem tar consumed by the existing image-to-ext4 path.

`make verify` checks the source contract without requiring a running Docker
daemon. A container build additionally validates packages, configuration,
units, proxy binaries, static portd installation, and records the package lock.

## Activation request

The controller invokes `silo-system-activate activate` as root and sends exactly
one bounded JSON object on stdin:

```json
{
  "schema": 1,
  "data_uuid": "01234567-89ab-cdef-0123-456789abcdef",
  "data_layout": 1,
  "required_shares": [
    {"path": "/home/alice", "tag": "/home/alice", "writable": true}
  ]
}
```

The helper verifies the immutable image contract, cgroup v2, guest route/DNS,
every requested virtiofs mount, the ext4 UUID, and the existing data-layout marker before it
mounts anything. It never formats a disk or creates data directories. It then
bind-mounts the existing `docker` and `containerd` directories over their
upstream locations and starts `silo-system-docker.target` synchronously.
Repeated activation validates an already healthy engine without restarting it.

Docker, containerd, their socket activation, distro networking, and OpenSSH
listeners are not enabled at image boot. SSH transport remains owned by the
injected Silo agent, avoiding a competing systemd-generated vsock listener.
