# 2. Image management

Date: 2026-02-20

## Status

Abandoned

## Context

Silo needs an image workflow that supports:

- OCI-backed VM base images.
- A shared local image store that acts as the persistent cache.
- Pulling remote OCI images into that store.
- Importing OCI tar archives into that store for offline and cross-machine transfer.
- Packing a stopped local VM into the same store.
- Creating instances from image refs.
- Creating lower-level raw instances without requiring a base image.

The core design choice is that OCI is only the transport format. Silo persists normalized
images in its own local store and creates instances from that store. It does not keep a second
long-lived OCI blob cache in V1.

## Decision

### Local image store

Silo stores normalized images under `Directory::with_prefix("images").get_data_home()`:

- `$XDG_DATA_HOME/silo/images`, else
- `~/.local/share/silo/images`

Store layout:

```text
<images-root>/
  registry.json
  <image-id>/
    metadata.json
    rootfs.img
    kernel        # optional
    initramfs     # optional
```

`<image-id>` is derived from the OCI manifest digest by stripping the `sha256:` prefix.

`registry.json` stores image records and tag mappings. A record tracks:

- image ID and manifest digest
- source ref
- artifact type
- metadata payload
- rootfs path
- optional kernel/initramfs paths
- timestamps
- standard OCI annotations retained from the manifest

### OCI artifact format

Silo uses a standard OCI image manifest with custom payload layers.

- Artifact type: `application/vnd.silo.base-image.v1`
- Config media type: `application/vnd.oci.image.config.v1+json`
- Metadata layer: `application/vnd.silo.image.metadata.v1+json`
- Rootfs chunk layer: `application/vnd.silo.disk.chunk.v1+zstd`
- Kernel layer: `application/vnd.silo.boot.kernel.v1` (optional, at most one)
- Initramfs layer: `application/vnd.silo.boot.initramfs.v1` (optional, at most one)

Validation rules:

- exactly one metadata layer
- at least one rootfs chunk layer
- at most one kernel layer
- at most one initramfs layer

The rootfs payload is a raw disk split into fixed-size chunks and compressed chunk-by-chunk with
zstd. Chunks are reconstructed in manifest order into `rootfs.img` on ingest.

The metadata JSON is the source of truth for image defaults and bootstrap support:

```json
{
  "schemaVersion": 1,
  "os": "linux",
  "arch": "arm64",
  "defaults": {
    "cpu": 4,
    "memoryMiB": 4096
  },
  "bootstrap": {
    "cidataCloudInit": true
  }
}
```

Bundled boot assets are inferred from the presence of the optional kernel and initramfs layers, not
from metadata fields.

Bootstrap media for guest initialization is a separate concern from OCI image transport. Silo
uses a local NoCloud seed disk with volume label `CIDATA`, formatted as VFAT, so bootstrap stays
backend-neutral instead of depending on host-specific ISO tooling.

### Instance creation from images

`silo create <ref> <name>` resolves a local image or pulls it on demand, then:

- applies image metadata defaults for CPU, memory, and bootstrap support unless CLI
  overrides them
- prefers bundled `kernel` and `initramfs` when present unless CLI overrides them
- falls back to the global default kernel and initramfs bundle when the image does not provide them
- materializes the instance rootfs from the shared image store using `clonefile` on APFS when
  available, otherwise falls back to a normal copy

### Packing local VMs

`silo images pack <vm> <ref>`:

- requires a stopped VM with a root disk
- captures the VM rootfs and metadata into the Silo OCI format
- can optionally bundle the resolved kernel and/or initramfs with `--include-kernel` and
  `--include-initrd`
- ingests the resulting artifact into the shared local image store under `<ref>` by default

Optional pack output controls:

- `--outfile <path>` writes the generated OCI layout as a tar archive and skips importing it into
  the local image store
- `--debug` keeps the temporary OCI layout work directory on disk for inspection instead of deleting
  it after pack completes

Bundled boot asset rules:

- default: do not bundle kernel or initramfs
- `--include-kernel` resolves the VM-specific kernel first, then the global default
- `--include-initrd` resolves the VM-specific initramfs first, then the global default

### Pulling remote images

`silo images pull <ref>` downloads the OCI artifact, validates it, reconstructs the normalized
image directory, and updates `registry.json`.

### Importing OCI tar archives

`silo images import <path>` ingests an OCI tar archive into the normalized local image store.

- input is restricted to OCI tar archives in V1
- imported artifacts follow the same validation and reconstruction rules as pulled artifacts
- imported images converge onto the same local representation as pulled and packed images

Pulled and packed images must converge onto the same local representation.

### Backend disk policy

For file-backed Linux guests on the VZ backend, Silo sets explicit host caching and
synchronization defaults in the backend rather than relying on framework defaults.

Current policy:

- VZ Linux guests use cached disk image I/O with full synchronization
- the policy is private to the VZ backend
- when VZ macOS guests are added, the backend should choose the best guest-specific default there

The shared VM types should not expose these host-specific disk policy knobs unless multiple
supported backends need a common abstraction.

## Consequences

### Positive

- Pulled and packed images behave the same locally.
- Shared base images are stored once and cloned into instances from a single cache.
- The common image-backed workflow stays simple.
- Chunked compressed payloads reduce transfer overhead and keep retries smaller.
- Optional bundled boot assets improve portability without forcing every image to carry them.

### Negative

- The OCI artifact format is more complex than a single compressed disk blob.
- V1 does not keep a persistent OCI blob cache or implement CAS-style dedupe.
- `images push` is still deferred.
- Fallback copy can still lose sparse behavior when APFS clone is unavailable.

## Deferred

- `silo images push <src> <ref>`
- registry credential integration
- signed artifact verification
- multi-arch index selection
- persistent OCI blob cache or CAS/dedupe layer if needed
- built-in `silo images resize`
