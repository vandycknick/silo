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

The artifact config records source provenance and how a loader should interpret
the kernel blob:

```json
{
  "schemaVersion": 1,
  "track": "stable",
  "kernelVersion": "7.1.3",
  "architecture": "arm64",
  "platform": {
    "os": "linux",
    "architecture": "arm64"
  },
  "kernel": {
    "mediaType": "application/vnd.silo.kernel.image.v1",
    "format": "arm64-image"
  },
  "source": {
    "url": "https://cdn.kernel.org/pub/linux/kernel/v7.x/linux-7.1.3.tar.xz",
    "digest": "sha256:..."
  },
  "build": {
    "revision": "...",
    "created": "..."
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
