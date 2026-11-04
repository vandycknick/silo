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

## Managed Root Boot Qualification

Workload artifact metadata additionally carries a `rootRuntime` object:

```json
{
  "opaqueRaw": true,
  "managedOverlay": {
    "eligible": true,
    "minimumKernelVersion": "6.6",
    "rootProfile": "linux-flat-overlay-v1",
    "upperProfile": "silo-upper-ext4-v1",
    "overlayProfile": "silo-overlay-v1",
    "renderingAbi": "linux-overlayfs-mountinfo-v1",
    "attachmentFamily": "krun-virtio-blk-v1",
    "qualification": "requires-exact-boot-evidence"
  }
}
```

`eligible` is only the numeric Linux >=6.6 prerequisite for workload kernels,
never a claim that a boot or conformance gate passed. `longterm5` is always
opaque-raw-only, and `rprobe` is not a workload root candidate. Resolved config
validation pins built-in ext4, ACL/security support, OverlayFS and its module
defaults. No EROFS or partition support is added by this contract.

Production flat-overlay admission is owned by libvm's focused
`boot_qualification` module, not package metadata or runtime discovery. Its
immutable reviewed tuples bind exact kernel, reusable base-initramfs and native
monitor/worker executable bytes, the actual resolved Kconfig digest, kernel
version, guest architecture, host execution lane, root/upper/overlay profiles,
rendering ABI and attachment family. An arbitrary custom initramfs or a changed
kernel fails admission before
machine/storage effects. A source config hash, `uname`, track, successful
compilation, environment variable, home/database record or staged manifest
cannot grant admission. There is no public bypass or unsupported fallback.
Admission checks the actual selected backend and rejects Mock/VZ before opening
boot assets. Its non-copyable token retains the qualified source descriptors.
Qualification and launch copying are bounded by each descriptor's initial
length, check file identity/size/change timestamps before and after, and hash
the exact copied bytes. Launch stages the kernel and composes the base
initramfs from these retained descriptors into private temporary files,
publishing only after validation succeeds. It never hashes a source pathname
and then reopens that original pathname for use.
Cooperative atomic restaging can unlink any retained source, including the
kernel and reusable base. Only link-count decreases and their ctime changes are
permitted; all other fingerprint fields must remain stable, and copied bytes
must still match the original qualified digest. This applies before and after
the bounded copy, without reopening the replacement pathname.
Linux launches the retained native executable through `/proc/self/fd/N`, with
the parent descriptor normalized to at least 3 and kept CLOEXEC. The token is
retained through spawn and its executable fingerprint is rechecked immediately
beforehand. Atomic restaging may unlink that old inode; link-removal/ctime-only
changes require a bounded rehash of the retained inode against the admitted
native digest. No executable pathname fallback or per-start native binary copy
is used. The worker reexecutes its loaded image rather than a replaced source
path. Non-Linux managed-overlay launch remains unadmitted. This relies on
trusted cooperative atomic publication, not protection from malicious same-UID
in-place executable modification.

The native SHA binds the concrete corrected DISCARD/WRITE_ZEROES implementation.
An older attachment binary cannot borrow qualification from unchanged
kernel/init bytes. Retained build evidence also records its signed dependency
revision and existing capabilities build identity; those provenance strings
alone never grant admission.

Initial qualification uses a controlled smoke-only fixture with the staged real
monitor and worker, the real upper formatter, current root bootstrap and actual
candidate kernel/init bytes. It records sysfs identities/geometry, mountinfo,
current module parameters and the result of init's effective-option verifier.
Main reviews the retained evidence and actual build/OCI resolved-config identity
before an exact tuple can be added. The observed tuple below admits only those
exact bytes. A candidate probe does not prove normal integration: after
recording the tuple, the positive gate must create and boot through the normal
CLI/libvm -> monitor -> worker path. No Cargo test launches a guest, and there
is no second direct-libkrun harness.

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

The flat profile is opt-in and development-only. Opaque raw remains the default.
Flat roots are not published, transferred or snapshotted; they are removed,
not migrated, when the final EROFS profile replaces them.

### Observed Linux KVM Candidate

Main observed the controlled real monitor/worker candidate pass on Linux
x86_64 KVM. The immutable boot-admission entry records exactly:

| Identity | Value |
| --- | --- |
| Kernel | Linux `7.2.2`, SHA256 `ec6fee8b1885a71e78306fea384f4ff6687fd151b6f279c23117785027748f33` |
| Reusable base initramfs | SHA256 `632d14f7ea50ee018a5e7a78f50a27fbdac2bb163589ec56e2e928b36e7015b8` |
| Actual monitor and worker executable | SHA256 `436de3fb42270d2114030e0cd380f89134e4574f3c6d9d3aabf86a7d670ecc7c` |
| Actual resolved Kconfig | SHA256 `f3dab6adffce7cadde5ce693f9403ce88d66ab9f4ec503f7860ce9020cb142e6` |
| Native source revision | `ed13b31a445a500ffc75d3b936cf10468a88fd2c` |
| Guest / host lane | `amd64` / Linux `x86_64`, KVM |
| Profiles | `linux-flat-overlay-v1`, `silo-upper-ext4-v1`, `silo-overlay-v1` |
| Rendering / attachment | `linux-overlayfs-mountinfo-v1` / `krun-virtio-blk-v1` |

Retained candidate evidence:
`/home/nickvd/sm/silo-smoke-w0k73tks/evidence/overlay-candidate-proof.log` and
`/home/nickvd/sm/silo-smoke-w0k73tks/evidence/overlay-candidate-tuple.log`.
The tuple records native build identity
`v2:path:clean:ed13b31a445a500ffc75d3b936cf10468a88fd2c:content=cfa2a0ffd091d9ffc03143476801481860f01e105c0277248589012987be8796:inputs=ed0ad1756fb2c1ab27c5b1a51eab64a70e2d2be46127b23cd7cf7116ad5cefcf`.
Main independently extracted the exact tested kernel's embedded IKCONFIG and
verified byte equality with the supplied resolved `.config`, binding the
configuration to the executable rather than trusting its pathname. The
per-launch composite initramfs is not the reusable base identity.

The observed guest validated exact lower/upper serials, a 512 MiB read-only
lower and 256 MiB writable upper, retained the maintenance mounts and reached
the workload only after init accepted the effective profile. Mountinfo showed
explicit `uuid=null,xino=on`; current module parameters were `index=Y`,
`metacopy=N`, `nfs_export=N`, `redirect_always_follow=N`, `redirect_dir=N`.
The lower mount was `ro,norecovery`, and the retained observation reported
256 MiB upper filesystem span with zero excluded tail.

This is controlled-candidate boot evidence only. Main must restage and confirm
the native executable digest remains unchanged before the normal production
matrix. Full production-path overlay acceptance, >2 GiB mapping, serial and
effective-option fault probes, upper lifecycle/growth/capacity/ENOSPC and native
DISCARD/WRITE_ZEROES gates remain required; this entry does not mark them passed.
Other native binaries, kernels, base initramfs bytes and host lanes are not
admitted by this candidate.



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
