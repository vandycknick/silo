# Kernel Resources

This directory owns the source pins, configuration, build, and OCI packaging
for Silo guest kernels. See [Kernel Build Artifacts](artifacts.md) for the file
formats and the stable OCI contract.

## Supported Tracks

- `stable`: `7.1.3`, supported and validated
- `longterm`: `6.18.33`, best effort
- `longterm5`: `5.15.208`, best effort

`sources.mk` maps each track to an upstream kernel version and kernel.org
archive checksum. It deliberately contains no architecture or packaging
metadata. Stable is the only track whose Kconfig contract is enforced and
built in CI. Older tracks consume the same miniconfigs and may omit symbols
that their Kconfig version does not provide.

## Building

The flake's `kernel` development shell provides the complete kernel and OCI
toolchain. Enter it on Linux before building:

```bash
nix develop .#kernel
make kernel TRACK=stable
```

The build detects the native Linux architecture; architecture is not a build
argument.

Resolve and validate a config without compiling or packaging the kernel with:

```bash
make -C resources/kernels kernel-config TRACK=stable
```

Kernel compilation must run on the target architecture. On macOS, run the
native build inside a Linux VM:

```bash
silo exec arch -- make kernel TRACK=stable
```

Kernel source and build state live under `$HOME/.cache/silo/kernels/`.
Downloaded archives are verified against `sources.mk` before extraction.

A successful build creates a platform-specific OCI image layout at:

```text
target/kernels/<track>/<architecture>/
```

The directory is an OCI layout containing `oci-layout`, `index.json`, and
content-addressed blobs. It is not a loose directory of kernel files. Inspect
or pull a local artifact with:

```bash
oras manifest fetch --oci-layout target/kernels/stable/x86_64:7.1.3 --pretty
oras manifest fetch-config --oci-layout target/kernels/stable/x86_64:7.1.3 --pretty
oras pull --oci-layout target/kernels/stable/x86_64:7.1.3 --output ./kernel
```

## Configuration Model

The maintained inputs are deliberately small, self-documenting miniconfigs:

```text
configs/
|-- common.config
|-- arm64.config
`-- x86_64.config
```

`common.config` owns shared product capabilities such as direct boot, Docker,
Kubernetes networking, virtio devices, filesystems, security, nested
virtualization datapaths, and diagnostics. The architecture files own only CPU
policy, KVM implementations, transports, and virtual-platform devices.

The build resolves:

```text
alldefconfig + common.config + <architecture>.config = generated .config
```

The generated `.config` contains thousands of transitive dependencies and
Kconfig defaults. It is an artifact, not a maintained source file.

## Editing Rules

- Put each symbol in exactly one maintained config.
- Keep related symbols together under a capability heading.
- Explain the product behavior, known failure, or platform contract that makes
  a symbol necessary.
- Request direct product choices, not hidden `HAVE_*`, `ARCH_HAS_*`, or other
  generated dependency symbols.
- Explicitly disable a top-level family when accidentally enabling it would
  reintroduce broad physical-hardware support.
- Keep boot-critical drivers built in because loadable modules are disabled.
- Do not add track compatibility fragments speculatively.

The validator rejects duplicate ownership and any stable assignment that does
not survive Kconfig resolution. Explicitly disabled symbols may disappear when
their parent menu is disabled; that still correctly resolves to disabled.

## Best-Effort Tracks

Longterm tracks use the stable miniconfig contract without strict compatibility
guarantees. If an older track develops a concrete build or runtime failure, add
at most one documented `configs/compat/<track>.config`; the build includes an
existing track fragment last.

Compatibility files should contain only verified version adaptation, never a
second feature or architecture baseline.

## Validation

Stable config changes should be validated at three levels:

1. Resolve both architectures and verify every requested symbol.
2. Build both kernels and validate their OCI manifests and payloads.
3. Boot the relevant architecture and exercise affected capabilities.

The runtime capability suite should cover ext4 mount and resize, Btrfs,
virtio-blk, virtio-net, virtiofs, vsock, RNG, serial, Docker bridge networking
and overlay2, retained Kubernetes networking, and nested `/dev/kvm` support.

## Publication

The kernel workflow builds stable arm64 and x86_64 OCI layouts natively on the
matching Ubuntu 26.04 GitHub-hosted runners. It copies the platform manifests
to GHCR and publishes an OCI image index with three tags:

- `<kernel-version>-<git-revision>` identifies an immutable Silo build.
- `<kernel-version>` identifies the latest Silo build of that upstream version.
- `<track>` is the moving channel, such as `stable`.

The published index contains standard `linux/arm64` and `linux/amd64` platform
descriptors. Consumers select a platform and locate its kernel through the
stable `application/vnd.silo.kernel.image.v1` layer media type, never through a
filename convention.

CI invokes `make -C resources/kernels publish` inside the kernel development
shell. That target uploads both platform manifests, creates the index, applies
the tags, and validates the published artifact.
