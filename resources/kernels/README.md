# Kernel Resources

This directory owns the source pins, configuration, build, and OCI packaging
for Silo guest kernels. See [Kernel Build Artifacts](artifacts.md) for the file
formats and the stable OCI contract.

## Supported Tracks

- `stable`: `7.2.2`, strict resolved-config validation
- `longterm`: `6.18.48`, strict resolved-config validation
- `longterm5`: `5.15.219`, best-effort workload build, opaque raw only

`sources.mk` maps each track to an upstream kernel version and kernel.org
archive checksum. It deliberately contains no architecture or packaging
metadata. Stable and longterm workload builds enforce every requested Kconfig
setting. Longterm5 may omit unavailable settings and can never qualify a managed
overlay root or live generation activation. The ARM64-only `rprobe` profile
validates every requested setting strictly on every pinned track. A successful
build or a track name is not managed-root or live-generation qualification; see
[exact boot admission](artifacts.md#managed-root-boot-qualification).

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
`make publish KERNEL_PROFILE=rprobe` is rejected by the workload publisher.
The separate `.github/workflows/rprobe.yml` pipeline publishes probe artifacts
using `scripts/publish-rprobe-oci.sh`. macOS runtime builds acquire the published
probe automatically; local builds still install one `rprobe` file. See the
[probe guide](../../guest/rprobe/README.md#development-builds-and-publication).

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
For OCI kernels this provenance also retains the authenticated artifact config,
whose exact kernel and resolved `.config` identities must match the manifest
descriptors. Staging adds `managedOverlayCandidate` to `runtime-manifest.json`
with the actual staged kernel/base-initramfs/native-executable digests, guest
architecture and fixed profile/rendering/attachment contract. This is evidence
inventory, not an admission grant. A local `KERNEL_PATH` has no inferred configuration identity:
the candidate metadata reports configuration evidence unavailable until the
actual build's resolved `.config` is supplied to the controlled qualification.

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

Stable and longterm workload kernels first apply the shared ordered patches in
`patches/live/`, then the ordered patches in `patches/<architecture>/`, to
pristine upstream source with `patch --fuzz=0 -p1`. Longterm5 retains only its
architecture patches: its upstream kernel lacks the VM-fork RNG API and is not
backported or given an RNG shim. The complete selected patch set is part of the
kernel identity (`inputs.patchSet` in the OCI config), so changing the shared
patch changes supported workload source/build/artifact identities. Probe kernels
apply no patches and do not inherit workload config. See
[Kernel Build Artifacts](artifacts.md#source-patches) for the full contract.

`patches/live/0001-virtio-silo-vmgenid.patch` ports the GPL-2.0-only Microsandbox
generation driver with attribution, using only Silo device ID `0x5347`. It owns
the built-in virtio binding and actual kernel RNG completion barrier described
below.

`patches/x86_64/0001-x86-krun-i8042-poweroff.patch` remains selected on all tracks.
The x86_64 workload kernel has neither ACPI nor an i8042 driver, so a guest
`poweroff` would otherwise halt forever. With `krun.poweroff=i8042` on the
kernel command line, the patch registers a lowest-priority poweroff handler that
writes `0xfe` to port `0x64`, which libkrun's i8042 device turns into a terminal
VMM exit. The krun backend adds that argument on x86_64 only; aarch64 guests
power off through PSCI and need no architecture-specific patch.

### VM generation contract and evidence

Supported workload configs request `CONFIG_VIRTIO_SILO_VMGENID=y`,
`CONFIG_VMGENID=y` and `CONFIG_VIRT_DRIVERS=y`, along with built-in virtio-MMIO,
virtio RNG, sysfs and cgroup freezer. `kernel-config` validates the emitted
`.config`, not merely these fragments. An absent, disabled or modular driver
does not pass strict validation. The initial entropy source is still virtio
RNG; generation IDs are not credited as secret entropy.

The driver requires modern virtio-MMIO (`VIRTIO_F_VERSION_1`). Its one unused
queue establishes the config-change IRQ and carries no requests or entropy.
The device-specific config is exactly 68 bytes, all aligned little-endian
32-bit accesses:

| Offset | Field |
| --- | --- |
| 0 | version, exactly 1 |
| 4 | driver status: READY=1, ERROR=2, CLOCK=4, CLOCK_ONLY capability=8 |
| 8, 12 | request sequence low, high (zero is idle) |
| 16, 20, 24, 28 | opaque 16-byte generation ID |
| 32, 36 | processed sequence low, high |
| 40, 44, 48, 52 | processed ID |
| 56 | request flags: SYNC_CLOCK=1, CLOCK_ONLY=2 |
| 60, 64 | host realtime nanoseconds low, high; reading low latches high |

The host installs immutable complete requests while vCPUs are stopped and
advances the device-local sequence without wrap. The driver brackets sampling
with sequence reads, rejects unknown flags, stale sequences and same-sequence
tuple changes before duplicate handling. Zero sequence has no acknowledgement.
Clock-only requires SYNC_CLOCK and the current completed ID (initially all zero
on a never-cloned source); it never calls the fork RNG API. A valid duplicate
can republish the ack without repeating successful RNG or clock work.

A serialized non-freezable work item waits for initialized CRNG readiness,
checks `wait_for_random_bytes()` success, calls the real
`add_vmfork_randomness(id, 16)` synchronously, and records return only after its
blocking notification chain completes. Optional clock correction samples fresh
latched host realtime with raw-clock midpoint compensation, rejects range
errors, and only advances wall time with `do_settimeofday64`. It never injects
pause duration into MONOTONIC/BOOTTIME. Errors set driver ERROR and do not ack.
Superseded captured work is rechecked before publishing; a host must still
reject old staged writes against its current exact request.

Commit ordering is four processed-ID words, processed-sequence high, then
processed-sequence low. The final low-word access is the host commit event,
using ordered MMIO transport accessors, not equality checked after each staged
word. Native Phase 11 must correlate the exact full tuple, readiness/error and
the single irreversible deadline at that event. This driver does not replace
the native activation gate, the agent's Activate wall-time step, or workload
and endpoint fences.

Read `/sys/bus/virtio/devices/<device>/generation_state` after locating the
virtio ID `0x5347`, never a hard-coded `virtioN`. The read-only attribute emits
one coherent bounded `key=value` record:

- `version`, `request_sequence`, `request_id`, `request_flags`;
- `completed_sequence`, `completed_id`, `completed_flags`;
- `rng_ready_before_call`, `reseed_count`, `reseed_sequence`, `reseed_id`,
  `reseed_return_order`;
- `clock_complete_order`;
- `ack_sequence`, `ack_id`, `ack_write_count`, `ack_write_order`,
  `ack_accessor_returned`, `ack_return_order`;
- `error` (negative errno or zero) and shared per-device `event_order`.

IDs are 32 lowercase hex digits in original opaque byte order. Counters/orders
are decimal; booleans are 0/1. Orders start at zero, meaning no such event.
The request is the last sampled tuple; completed means guest work completed,
not host acceptance. Reseed fields describe the last actual RNG call return
and remain unchanged for clock-only/duplicate requests. Ack-write evidence is
attached immediately before the final low-word accessor; its returned flag
and return ordinal are updated only after the accessor returns. A new attempted
ack clears that flag. Take a snapshot after completion and require matching
tuples and `reseed_return_order < ack_write_order < ack_return_order`; for
requested clock work, require `clock_complete_order < ack_write_order` too.
Correlate these with the native accepted commit, not random-output comparisons.
No RNG key, pool or output bytes, writable fault knobs or authorization controls
are exported.

**Real-guest generation qualification remains explicitly unverified and depends
on the Phase 11 native device and restore path.** A built kernel or sysfs
counter alone is not proof. Main must stage the exact local kernel, retain its
resolved config and artifact/native identities, and observe actual restored
guests with frozen workloads: real RNG-return-before-ack, exact host commit,
duplicate idempotence, clock-only resume including zero initial ID, two fresh
children, and absent/wrong/incomplete/late/reordered/missing-reseed/invalid
request controls. Native failure must leave activation fenced and re-pause or
kill/reap the child. ARM64/HVF lanes remain pending until actually executed.


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

The validator rejects duplicate ownership and any stable/longterm assignment
that does not survive Kconfig resolution. Explicitly disabled symbols may
disappear when their parent menu is disabled; that still resolves to disabled.

## Raw-Only Best-Effort Track

Longterm5 uses the workload miniconfig without strict compatibility guarantees.
It remains opaque-raw-only and ineligible for live-generation activation even
when configuration validation succeeds. If it develops a concrete build or
runtime failure, add at most one documented
`configs/compat/longterm5.config`; the build includes an existing track fragment
last.

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
