# Kernel Resources

This directory owns the source pins, configuration, build, and OCI packaging
for Silo guest kernels. See [Kernel Build Artifacts](artifacts.md) for the file
formats and the stable OCI contract.

## Supported Tracks

- `stable`: `7.2.2`, supported and validated
- `longterm`: `6.18.48`, best effort for workload kernels
- `longterm5`: `5.15.219`, best effort for workload kernels

`sources.mk` maps each track to an upstream kernel version and kernel.org
archive checksum. It deliberately contains no architecture or packaging
metadata. Stable is the only track whose Kconfig contract is enforced and
built in CI. Older workload tracks consume the same miniconfigs and may omit
symbols that their Kconfig version does not provide. The ARM64-only `rprobe`
profile validates every requested setting strictly on every pinned track.

## Building

The flake's `kernel` development shell provides the complete kernel and OCI
toolchain. Enter it on Linux before building:

```bash
nix develop .#kernel
make kernel TRACK=stable
```

`KERNEL_PROFILE` is `workload` by default. The isolated acquisition-probe
kernel uses the fragments in `guest/rprobe/kernel/` and must be built natively
on ARM64 Linux. From the repository root:

```bash
make rprobe PROFILE=release
```

This builds the Rust PID1, creates a deterministic intermediate initramfs, and
embeds it into the kernel. The only installed probe asset is
`target/release/assets/rprobe`. See [the probe guide](../../guest/rprobe/README.md).
For a local OCI layout of that appliance, use the shared kernel target:

```bash
make -C resources/kernels KERNEL_PROFILE=rprobe \
  KERNEL_INITRAMFS="$PWD/target/release/rprobe-build/initramfs.cpio.gz" kernel
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
Downloaded archives are verified against `sources.mk`; pristine extractions
are read-only. Builds use separate derived sources keyed by profile,
architecture, source, ordered patches, configuration, toolchain selectors,
build flags, embedded initramfs content, and reproducibility environment.
When callers do not supply reproducibility metadata, local builds use epoch 0,
build version 1, and `silo` as the build user and host. CI-provided values
override those deterministic defaults and therefore receive distinct keys.
Owned markers protect pristine, derived-source, canonical OCI, and workload
compatibility directories. Existing unmarked destinations are never deleted;
only a validated Silo OCI artifact may be atomically migrated to a marked
destination. Unsafe roots, symlinks, and invalid overridden downloads fail
without removing the pre-existing path.

A successful build creates a platform-specific OCI image layout at:

```text
target/kernels/<track>/<architecture>/
```

This workload compatibility export and its `<kernel-version>` reference remain
the interface consumed by CI and publication. The build first creates an
identity-keyed canonical layout below `target/kernels/.canonical/workload/`,
then copies that verified artifact to the compatibility path. The directory is
an OCI layout containing `oci-layout`, `index.json`, and
content-addressed blobs. It is not a loose directory of kernel files. Inspect
or pull a local artifact with:

```bash
oras manifest fetch --oci-layout target/kernels/stable/x86_64:7.2.2 --pretty
oras manifest fetch-config --oci-layout target/kernels/stable/x86_64:7.2.2 --pretty
oras pull --oci-layout target/kernels/stable/x86_64:7.2.2 --output ./kernel
```

Probe layouts remain identity-keyed below
`target/kernels/.canonical/rprobe/<track>/arm64/`. They use a distinct purpose,
reference, artifact type, and image media type. They are local build artifacts:
`make publish KERNEL_PROFILE=rprobe` is rejected. Dedicated probe OCI publication
and registry acquisition remain future work; local builds install one `rprobe` file.

## Runtime Acquisition

Ordinary Silo builds consume the published stable OCI index rather than compile
a kernel. The default reference is
`ghcr.io/vandycknick/silo/kernel:stable`; it may be replaced for a mirror or
fork without changing runtime discovery:

```bash
make KERNEL_REFERENCE=registry.example/silo/kernel:stable
```

`make KERNEL_PATH=/absolute/path/to/kernel` selects and validates a local
regular architecture-matched kernel file instead. `make KERNEL_OFFLINE=1`
permits no registry access and reuses only verified digest-addressed content already below
`$CARGO_TARGET_DIR/kernel-cache/sha256`. The resolved index, platform manifest,
config, and complete layer descriptor set are written outside the runtime payload under
`$CARGO_TARGET_DIR/kernel-provenance/<target>/<profile>.json`.

The resolver uses ORAS only for OCI registry and digest transport. It validates
the Silo index, exact `linux/amd64` or `linux/arm64` platform manifest, artifact
contract, descriptor media types, SHA-256 digests, and sizes before it copies
only the kernel layer into `assets/kernel-default`.

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

For the probe, the independent equation is:

```text
alldefconfig + guest/rprobe/kernel/{common,arm64}.config + embedded.config = generated .config
```

`embedded.config` is generated by the builder and selects the content-verified
archive copied into the identity-keyed build directory. The probe archive is
required; building a bare rprobe kernel is rejected.

The generated `.config` contains thousands of transitive dependencies and
Kconfig defaults. It is an artifact, not a maintained source file.

## Workload Patches

Workload kernels apply the ordered patches in `patches/<architecture>/` to the
pristine upstream source with `patch --fuzz=0 -p1`. The patch set is part of the
kernel identity (`inputs.patchSet` in the OCI config), so adding, changing, or
removing a patch produces a distinct canonical artifact. Probe kernels apply no patches. See
[Kernel Build Artifacts](artifacts.md#source-patches) for the full contract.

Today the only patch is `patches/x86_64/0001-x86-krun-i8042-poweroff.patch`.
The x86_64 workload kernel has neither ACPI nor an i8042 driver, so a guest
`poweroff` would otherwise halt forever. With `krun.poweroff=i8042` on the
kernel command line, the patch registers a lowest-priority poweroff handler that
writes `0xfe` to port `0x64`, which libkrun's i8042 device turns into a terminal
VMM exit. The krun backend adds that argument on x86_64 only; aarch64 guests
power off through PSCI and carry no patch.

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
