# Kernel Build Artifacts

Linux produces several files called some variation of "image" during a build.
They are not interchangeable. This page describes the meaningful outputs used
or encountered by Silo and defines the OCI artifact contract.

## Architecture Contract

The boot representation is selected by guest architecture, not by the
virtualization backend:

| OCI platform | Repository architecture | Boot representation |
| --- | --- | --- |
| `linux/arm64` | `arm64` | uncompressed arm64 `Image` |
| `linux/amd64` | `x86_64` | x86-64 ELF `vmlinux` |

Both libkrun and Virtualization.framework consume `Image` for an arm64 guest.
The current x86-64 libkrun path consumes `vmlinux`. Backend names are therefore
not part of the artifact format.

Libkrun uses hardware virtualization rather than cross-architecture CPU
emulation. An arm64 host cannot boot an x86 `bzImage` through libkrun.

## OCI Contract

Workload kernels retain the published contract and compatibility location
`target/kernels/<track>/<architecture>:<kernel-version>`. Their canonical local
layout is identity-keyed below `target/kernels/.canonical/workload/`; the build
copies the verified canonical manifest to the compatibility location.
Canonical and compatibility directories carry separate Silo ownership markers.
A rebuild replaces only a matching marked directory or an unmarked OCI layout
that passes the complete expected-profile contract and provenance validation.

The multi-platform index and each platform manifest use this artifact type:

```text
application/vnd.silo.kernel.v1
```

Every platform manifest must contain exactly one layer with this stable media
type:

```text
application/vnd.silo.kernel.image.v1
```

That layer is the architecture-native boot kernel. Its
`org.opencontainers.image.title` annotation preserves the native `Image` or
`vmlinux` filename for humans and generic ORAS extraction, but the title is not
an API. Consumers locate the kernel by media type.

The remaining media types are:

| Purpose | Media type |
| --- | --- |
| Artifact metadata | `application/vnd.silo.kernel.config.v1+json` |
| Resolved Kconfig | `application/vnd.silo.kernel.kconfig.v1` |
| Symbol map | `application/vnd.silo.kernel.system-map.v1` |
| XZ-compressed diagnostic ELF | `application/vnd.silo.kernel.debug.v1+xz` |

The ARM64 `rprobe` profile is a separate contract:

| Purpose | Media type |
| --- | --- |
| Artifact | `application/vnd.silo.rprobe-kernel.v1` |
| Artifact metadata | `application/vnd.silo.rprobe-kernel.config.v1+json` |
| Boot Image | `application/vnd.silo.rprobe-kernel.image.v1` |

Its purpose is `rosetta-acquisition-probe`, and its canonical layout and
reference include the complete build identity. It is never exported to the
workload compatibility path or accepted by the workload publisher. The dedicated
rprobe pipeline publishes an `application/vnd.silo.rprobe-kernel.v1` OCI index
containing one linux/arm64 manifest to `ghcr.io/vandycknick/silo/rprobe`, tagged
`VERSION-REVISION` and `stable`. Probe builds and runtime acquisition install only
`assets/rprobe`, an ARM64 Image with its Rust PID1 embedded through Linux's
built-in initramfs support. No manifest or external initramfs is installed for
the probe. The embedded archive's content participates in the build identity.

The artifact config records source provenance and how a loader should interpret
the kernel blob:

```json
{
  "schemaVersion": 1,
  "profile": "workload",
  "purpose": "workload",
  "identity": "workload-arm64-sha256-...",
  "track": "stable",
  "kernelVersion": "7.2.2",
  "architecture": "arm64",
  "platform": {
    "os": "linux",
    "architecture": "arm64"
  },
  "kernel": {
    "mediaType": "application/vnd.silo.kernel.image.v1",
    "format": "arm64-image",
    "size": 123,
    "digest": "sha256:..."
  },
  "resolvedConfig": {
    "size": 123,
    "digest": "sha256:..."
  },
  "source": {
    "url": "https://cdn.kernel.org/pub/linux/kernel/v7.x/linux-7.2.2.tar.xz",
    "digest": "sha256:...",
    "key": "sha256-..."
  },
  "inputs": {
    "patchSet": "sha256-...",
    "config": "sha256-...",
    "build": "sha256-...",
    "toolchain": "sha256-..."
  },
  "build": {
    "revision": "...",
    "created": "...",
    "compiler": "...",
    "linker": "..."
  }
}
```

The defined kernel formats are:

| Format | Meaning |
| --- | --- |
| `arm64-image` | Uncompressed arm64 Linux Image with its arm64 boot header |
| `elf` | ELF executable containing the directly loadable kernel |

A consumer must:

1. Resolve the desired platform from the OCI index.
2. Require artifact type `application/vnd.silo.kernel.v1`.
3. Require exactly one `application/vnd.silo.kernel.image.v1` layer.
4. Fetch that layer by digest without interpreting its title.
5. Read `kernel.format` from the config when its loader needs an explicit
   format selection.

Changing filenames does not break this contract. Adding a second kernel-image
layer or changing the meaning of an existing format requires a new artifact
contract rather than a filename heuristic.

## Managed Root Kernel Compatibility

Workload artifact metadata additionally carries a `rootRuntime` object:

```json
{
  "opaqueRaw": true,
  "managedOverlay": {
    "eligible": true,
    "minimumKernelVersion": "6.6",
    "rootProfile": "linux-erofs-overlay-v1",
    "upperProfile": "silo-upper-ext4-v1",
    "overlayProfile": "silo-overlay-v1",
    "renderingAbi": "linux-overlayfs-mountinfo-v1",
    "attachmentFamily": "krun-virtio-blk-v1",
    "qualification": "kernel-config-build-gate"
  }
}
```

`eligible` records the numeric Linux >=6.6 prerequisite for workload kernels.
`longterm5` is opaque-raw-only, and `rprobe` is not a workload root candidate.
Overlay compatibility is a kernel-config property verified by the kernel track's
gate at build time, not per boot. Resolved config validation pins built-in EROFS
and ext4, ACL/security support, OverlayFS and its module defaults.

### Workload Partition and Rosetta Configuration (Qualification Pending)

The shared workload fragments additionally require built-in GPT and MBR
partition discovery (`EFI_PARTITION=y`, `MSDOS_PARTITION=y`), VFAT/FAT and NLS
(`VFAT_FS=y`, `FAT_FS=y`, `NLS=y`). The exact built-in codepages are
`NLS_CODEPAGE_437=y`, `NLS_ISO8859_1=y` and `NLS_UTF8=y`, with
`FAT_DEFAULT_CODEPAGE=437` and `FAT_DEFAULT_IOCHARSET="iso8859-1"`. This supports
the declared default charset and explicit UTF-8 guest fstab requests, not every
NLS codepage. Ext4, binfmt_misc and virtiofs remain built in. Partition discovery
does not require EFI firmware boot or broaden the admitted root filesystem
beyond ext4; arm64 EFI remains disabled.

The arm64 workload fragment explicitly requires `ARM64_4K_PAGES=y` and
`ARM64_PAGE_SHIFT=12` for Rosetta. The existing resolved-config validator checks
these exact values, including numeric and quoted string defaults, against the
selected workload fragments. Source settings and validator unit fixtures are
not evidence of produced kernel page size or runtime boot success. The rprobe
kernel uses independent fragments and is unchanged.

The x86_64 stable and longterm configurations were generated and passed the
resolved-config validator on 2026-11-06; retained evidence is under
`.tmp/plan/evidence/phase-17/workload-{stable,longterm}-x86_64.config`.
Arm64 resolved configuration, kernel builds and guest compatibility gates remain
pending. No partitioned-root, VFAT-mount or Rosetta runtime pass is claimed by a
configuration update alone.

### Raw-root Direct Kernel Admission

libvm checks the pinned kernel's bounded header for native format and
architecture when selecting raw-root boot assets. It does not hash kernel,
initramfs or monitor assets on start or inspect. Content-addressed bundle
identities are computed when importing or capturing assets, not to grant boot
permission. Packaged-update inspection uses object identities recorded at
import and never rehashes installed boot files.

The bytes must be the host's direct-loader format from the architecture
contract above: an x86-64 little-endian ELF64 executable with in-file `PT_LOAD`
segments and program headers in the first 4 KiB, or a little-endian arm64
`Image` whose header declares an effective image size at least as large as the
file. Foreign, compressed and unknown images are rejected before publication.

Admission checks format and architecture only. It does not read the embedded
configuration, so custom kernels without `CONFIG_IKCONFIG` are accepted. A
kernel lacking a filesystem, partition table, device or Rosetta capability that
its root needs fails at boot, not at admission. The workload fragments above
describe what Silo's own kernels build in; passing admission does not qualify a
boot, and guest gates remain the evidence that a kernel actually boots.

### Overlay Kernel Floor and Owned Boot Assets

Overlay roots require Linux 6.6 or newer. libvm reads the version from the held
kernel (the Linux boot protocol header for bzImage, or `linux_banner` in native
ELF vmlinux) and rejects older or unreadable versions before machine or storage
effects. Raw roots retain their independent native-format checks. The selected
backend must support overlay roots; Mock and VZ are rejected before opening
overlay boot assets. Kernel track gates verify the required configuration at
build time; launch does not consult an artifact-specific admission list.

The `owned_boot_assets` module retains read-only CLOEXEC descriptors. Guest
asset copies are bounded by their initial length and check file identity, size
and timestamps before and after copying. The private `kernel-qualified` launch
copy remains mode 0400; the per-launch composite initramfs is built from the held
base plus the current root and agent archive. Atomic source publication never
causes those copies to reopen replacement paths.

Linux executes the held monitor via `/proc/self/fd/N`, normalized to at least
descriptor 3 and kept CLOEXEC in the parent. Immediately before spawn, its
metadata fingerprint must still match; unlink or replacement that changes it
fails closed without rehashing or an executable-path fallback. The worker
reexecutes its loaded image. This relies on cooperative atomic publication, not
protection from malicious same-UID in-place modification.

Pinned bundle identities and checkpoint producer identities are independent of
this version check. Capture receipts retain the monitor digest from its
capability report. Kernel, reusable initramfs or monitor updates do not require
recompiling libvm to authorize new artifact bytes.

Real boot and storage gates still exercise the staged monitor/worker, actual
kernel, upper formatter, effective mount options and device identities. These
are compatibility evidence, not per-boot authorization records.


`linux-overlayfs-mountinfo-v1` decodes omitted index, metacopy, redirect and
nfs_export settings using the current built-in module parameters, not the
requested mount arguments. Distinct lower/upper filesystems require explicit
`xino=on`; omission means AUTO/OFF, never ON, even with xino_auto enabled.
`uuid=null` must also be explicit.
Unknown or weaker effective semantics fail before workload handoff. The shared
core-only `rootfs-spec` carries this closed ABI; host workspace checks include
its codec. Xtask separately tests/lints init's pure library with `--lib
--no-default-features`, never its no_std/no_main binary harness. The static
guest init build remains `no_std`.

Layered OCI roots are the libkrun default. Raw disks remain explicit inputs or
conversion/export products. The development flat lower and root-profile selector
are removed; incompatible state requires an explicit wipe, not a migration.

### Observed Linux KVM Compatibility Evidence

Historical real boot observations recorded these artifacts:

| Identity | Value |
| --- | --- |
| Stable kernel | Linux `7.2.2`, SHA256 `2ce7271136af454c427880212f085271fc2fdea13efb599ba82ff6ebe4d62dc7` |
| Stable resolved Kconfig | SHA256 `b82647103b73ac2f7fafc3b1bdd6ad927ba2f1c68e5b5f11a3e3da4bfdf533f4` |
| Longterm kernel | Linux `6.18.48`, SHA256 `69095b40e489efd67b60ae3aae3098454f39515727b180ce65eb9a3ed0ace6ba` |
| Longterm resolved Kconfig | SHA256 `2184ecc3adae8b99fb194b6fc8c4f0d1d3b40e5429a300edccbb54d0270b678e` |
| Reusable base initramfs | SHA256 `fa47abf63ab4946efaaacb4e0326ea3d1d953795444ba9073dfa23407ce57e3c` |
| Actual monitor and worker executable | SHA256 `0816521bbaf2349c4adb51e5ac1e725af433c1482469a5895ebbfbc9d3a44b02` |
| Native source revision | `8babb9fd9b4a0413ea79ce160e5cc5fab5dea384` |
| Guest / host lane | `amd64` / Linux `x86_64`, KVM |
| Profiles | `linux-erofs-overlay-v1`, `silo-upper-ext4-v1`, `silo-overlay-v1` |
| Rendering / attachment | `linux-overlayfs-mountinfo-v1` / `krun-virtio-blk-v1` |

Phase 22 retained candidate observations in
`.tmp/plan/evidence/phase-22/qualified-boot-candidate.json` and
`qualified-longterm-boot-candidate.json`. Each observed the actual worker,
readonly EROFS lower, writable ext4 upper and successful effective-option
verification before workload handoff. The per-launch composite initramfs is
not the reusable base identity.

Normal production CLI/monitor/worker gates subsequently exercised both tracks,
including large mappings, serial/access fault refusals, upper growth, ENOSPC,
restart, native DISCARD/WRITE_ZEROES, and kernel-mutated flatten export followed
by raw boot and independent namespace comparison. The complete longterm overlay
and flatten matrix passed 99 cases (`longterm-all-overlay-and-flatten.log`);
stable production and corrected fixture observations are retained alongside it.
The separate two-track encoder matrix passed all ten cases, including 1024
occurrences and a sparse mapping beyond 2 GiB (`stable-native-prerequisite-gates.log`).

These boot and storage results grant no public live capability. Capture,
restore, fork and incremental remain subject to their independent live-operation
gates; ordinary overlay boot requires the kernel floor, not these artifact hashes.



## Published Payloads

The platform manifests intentionally differ because the architecture boot
formats differ:

| File | arm64 | amd64 | Purpose |
| --- | --- | --- | --- |
| `Image` | yes | no | arm64 boot kernel |
| `vmlinux` | no | yes | amd64 boot kernel and ELF symbols |
| `.config` | yes | yes | exact resolved build configuration |
| `System.map` | yes | yes | compact symbol-to-address map |
| `vmlinux.xz` | yes | no | compressed arm64 ELF for diagnostics |

The amd64 artifact does not include `vmlinux.xz` because it would duplicate its
required uncompressed `vmlinux` boot layer. The arm64 artifact includes
`vmlinux.xz` because its bootable `Image` no longer contains the ELF container
and symbol table.

OCI descriptors already authenticate every config and layer by digest.
`SHA256SUMS` is therefore redundant. Build provenance lives in the artifact
config rather than a separate `build-info.txt` layer.

## Build Pipeline

The relevant build flow is:

```text
common.config + <architecture>.config
                 |
                 v
            .miniconfig
                 |
                 v
            alldefconfig
                 |
                 v
              .config
                 |
                 v
          linked vmlinux
            /         \
           /           \
 arm64 post-process    x86-64 package
         |                    |
       Image               vmlinux
```

Kbuild always links the resident kernel as an ELF `vmlinux`. Architecture
Makefiles may then transform it into a boot representation. For arm64, `Image`
is the uncompressed direct-boot representation derived from `vmlinux`. For the
current x86-64 direct-boot contract, the ELF itself is the packaged kernel.

## Source Patches

Stable and longterm workload kernels apply ordered `patches/live/*.patch`
first, then ordered `patches/<architecture>/*.patch`, to pristine source with
`patch --fuzz=0 -p1`. Longterm5 retains architecture patches only and remains
raw-only, never generation-qualified: it has no VM-fork RNG API backport.
Rprobe selects no patches. The entire selected patch set is part of source,
build and artifact identity (`inputs.patchSet`), so shared-driver changes
produce new supported workload artifacts without changing rprobe identity.

| Architecture | Patch | Purpose |
| --- | --- | --- |
| x86_64, arm64 (stable/longterm workload only) | `live/0001-virtio-silo-vmgenid.patch` | GPL-attributed built-in `0x5347` virtio-MMIO driver. Waits for CRNG readiness, calls real synchronous `add_vmfork_randomness`, optionally corrects wall time, then commits the exact sequence and ID with the sequence-low word last. Exposes coherent read-only causal sysfs evidence. |
| x86_64 (all workload tracks) | `x86_64/0001-x86-krun-i8042-poweroff.patch` | Adds `arch/x86/kernel/krun_poweroff.c`. When the command line carries `krun.poweroff=i8042`, it registers a lowest-priority poweroff handler that writes `0xfe` to port `0x64`, which libkrun turns into a terminal VMM exit. Without the argument nothing is registered. The krun backend adds the argument on x86_64 only. |

The x86_64 kernel has neither ACPI nor an i8042 driver, so without this patch a
guest `poweroff` halts and the VM never exits. arm64 powers off through PSCI and
carries no architecture-specific poweroff patch.

The emitted `.config` must select `CONFIG_VIRTIO_SILO_VMGENID=y`,
`CONFIG_VMGENID=y`, `CONFIG_VIRT_DRIVERS=y` and the built-in MMIO, initial RNG,
sysfs and freezer prerequisites. `kernel-config` runs the existing validator
against that resolved file; packaging retains and hashes that same file as
`resolvedConfig`. Requested fragments or patch bytes alone do not prove a
running driver's behavior. See [generation ABI and evidence](README.md#vm-generation-contract-and-evidence).

**Live generation qualification is unverified until the Phase 11 native device
and real restore smoke gate run.** Retain exact kernel, resolved-config,
patch/input and native executable identities and correlate guest RNG-return /
low-word-access evidence with the native accepted exact-tuple commit before its
deadline. This does not qualify userspace RNG state or grant live capability.

## Configuration Files

### `.miniconfig`

Silo generates `.miniconfig` by merging the maintained common, architecture,
and optional track compatibility fragments. It records requested product
choices, not all transitive Kconfig results. It is a build input generated in
the cache and is not published because the repository revision reconstructs
it.

### `.config`

Kconfig produces `.config` after resolving defaults, dependencies, selections,
and unavailable symbols. This is the exact configuration compiled into the
kernel and is included in every platform artifact.

## Kernel Images

### `vmlinux`

`vmlinux` is the linked kernel ELF. It contains ELF headers, loadable segments,
the entry point, kernel code and data, and a symbol table. It may also contain
DWARF or BTF data when enabled by Kconfig.

On x86-64, Silo packages this ELF as the boot kernel. On arm64 it remains useful
for symbol-aware diagnostics, while the architecture-specific `Image` is used
for boot.

### `vmlinux.unstripped`

Current Kbuild versions first link `vmlinux.unstripped`, derive `System.map`,
then use `objcopy` to produce the final `vmlinux`. The intermediate can retain
sections and relocation information removed from the final file. It is a
Kbuild implementation detail and is not published.

### `Image`

The arm64 `Image` is an uncompressed, directly bootable kernel representation.
It contains a 64-byte arm64 boot header followed by the loadable kernel image.
It is not an ELF file and does not carry the ELF section or symbol tables.

An arm64 bootloader or VMM places it in guest memory, supplies a device tree and
optional initramfs, prepares the CPU state, and jumps to the image entry point.

### `Image.gz`, `Image.bz2`, and `Image.zst`

These names refer to an arm64 `Image` compressed with gzip, bzip2, or zstd.
They are usable only when the loader understands and decompresses that format.
Silo packages the uncompressed `Image` so the artifact is not tied to a
particular loader's compression support.

### `bzImage`

`bzImage` is an x86 architecture-specific boot image. The name historically
means "big zImage"; it does not mean a bzip2-compressed `Image`. An x86
`bzImage` and an arm64 `Image.bz2` are unrelated formats.

Silo's current x86-64 artifact uses the ELF `vmlinux`, not `bzImage`.

### `vmlinuz`

`vmlinuz` is a conventional installed filename used by distributions for a
compressed bootable kernel. It is not a single architecture-independent file
format and is not a distinct output used by this build.

### `vmlinux.xz`

`vmlinux.xz` is created by Silo, not by the selected Kbuild target. It is an XZ
compression of the final `vmlinux` ELF for storage and diagnostics. It is not
the same as `Image`, `Image.gz`, or `bzImage`, and the current loaders do not
boot it directly.

## Diagnostic Outputs

### `System.map`

`System.map` maps kernel symbol names to linked addresses. It supports log and
crash decoding without carrying the full ELF. It must match the exact kernel
build and is included in every platform artifact.

### Debug information

Symbol tables, DWARF, and BTF serve different tooling. Their presence depends
on Kconfig and Kbuild post-processing. The current artifact contract preserves
the final arm64 ELF as `vmlinux.xz`; it does not promise that a particular DWARF
or BTF configuration is enabled.

## Outputs Not Packaged

### Kernel modules

`*.ko` files are loadable kernel modules. `Module.symvers` describes exported
symbols and versioning for external module builds. `modules.builtin` and
`modules.builtin.modinfo` describe components linked into the kernel that use
module metadata. Silo sets `CONFIG_MODULES=n`, so no loadable modules are part
of the runtime artifact. Kbuild may still generate built-in metadata files.

### Device trees

`*.dtb` files describe physical or virtual hardware platforms. Silo does not
package board-specific DTBs with the generic arm64 kernel because the selected
VMM supplies the virtual platform description at boot.

### Object and archive intermediates

Kbuild creates many `*.o`, `built-in.a`, `vmlinux.a`, generated headers, command
records, and temporary kallsyms files. They are compiler and linker
intermediates, not stable kernel distribution artifacts, and are intentionally
outside the OCI contract.
