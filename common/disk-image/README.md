# disk-image

Pure-Rust ext4 filesystem formatter, reader, and offline grower for Silo root disks.

No kernel mount. No FUSE. No C dependencies.

`disk-image::ext4` creates and reads ext4 filesystem images entirely in userspace, without needing `mkfs.ext4`, `libext2fs`, or Linux tools on the host.

This crate started as a source snapshot of upstream [`arcbox-ext4`](https://github.com/arcboxlabs/ext4-rs). See [`FORK.md`](FORK.md) for the fork point and the Silo-specific filesystem changes.

## Why

Silo needs to build ext4 root filesystems on macOS and Linux. The standard approach requires either shelling out to Linux `mkfs.ext4` (not available on macOS) or linking against C libraries like `lwext4`. This crate does it in pure Rust.

The formatter now emits classic Linux-growable ext4 metadata: `sparse_super` plus `resize_inode`, not `sparse_super2`. That layout is required for the online resize path Silo uses for Linux guests.

## Features

|                         |                                                                                                                                |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| **Formatter**           | Create ext4 images from scratch: superblock, group descriptors, inode table, bitmaps, extent trees, and online-resize metadata |
| **Reader**              | Open existing ext4 images: path resolution, symlink following, file reading                                                    |
| **Offline Grower**      | Grow clean, unmounted Silo ext4 images without host e2fsprogs                                                                  |
| **Journal**             | Internal JBD2 journal for kernel crash recovery                                                                                |
| **Extended Attributes** | Deterministic inline/block placement, raw Linux names/values, explicit POSIX ACL ABI-to-disk conversion                       |
| **Hard Links**          | Correct reference counting with deferred block reclamation                                                                     |
| **Symlinks**            | Fast symlinks (inline, less than 60 bytes) and slow symlinks (data blocks)                                                     |
| **Special Inodes**      | FIFO, socket, character/block device nodes with checked Linux 12:20-bit device IDs                                           |
| **Sparse Files**        | Stored-range streaming without hole scans, unaligned ranges and generalized checked extent trees                            |

## Quick Start

```toml
[dependencies]
disk-image = { path = "common/disk-image" }
```

### Create an ext4 image

```rust
use std::path::Path;
use disk_image::ext4::{FileData, Formatter, constants::{make_mode, file_mode}};

let mut fmt = Formatter::new(Path::new("rootfs.ext4"), 4096, 64 * 1024 * 1024)?;

// Create directories and files.
fmt.create("/etc", make_mode(file_mode::S_IFDIR, 0o755),
    None, None, None, None, None, None, None)?;
fmt.create("/etc/hostname", make_mode(file_mode::S_IFREG, 0o644),
    None, None, Some(FileData::Dense(&mut b"silo\n".as_slice())), None, None, None, None)?;

// Create a symlink.
fmt.create("/etc/localtime", make_mode(file_mode::S_IFLNK, 0o777),
    Some(b"/usr/share/zoneinfo/UTC"), None, None, None, None, None, None)?;

// Finalize: writes superblock, group descriptors, bitmaps, inode table,
// backup metadata, and resize inode metadata.
fmt.close()?;
```

Guest paths, directory names, symlink targets and xattr names are raw bytes;
the same APIs accept UTF-8 strings through `AsRef<[u8]>`. No name or value is
lossily decoded. `create` takes borrowed xattr name/value pairs, and explicit
directory creation updates all supplied metadata, including root. Recursive
parent creation does not overwrite an already supplied directory's metadata.
`FileTimestamps::from_mtime` checks nanoseconds and ext4's signed-seconds epoch
carry (including 2038). Hardlinks retain one inode and its complete metadata.

Public xattrs use the Linux ABI: `system.posix_acl_access` and
`system.posix_acl_default` are version-2 ACL values. The codec explicitly
encodes ext4 version 1 with short base entries and named-entry IDs; the reader
returns version 2 again. Capabilities and other opaque values remain byte-exact.
Only supplied attributes are written, with deterministic placement/order.

`FileData::Sparse(SparseData { reader, length, ranges })` consumes only stored
bytes in ordered, disjoint `FileRange { offset, length }` records. Holes are
not scanned or written. Unaligned ranges sharing a block are merged without
losing either range. The reader returns zeros for holes and unwritten extents.
An all-hole file does not consume its logical length on the image.

For a final composed namespace, use `FormatSizing::add_inode` once per unique
inode (including root), with touched 4K data blocks and input extent records;
hardlink aliases do not repeat data accounting. Use `add_directory` with each
directory's direct child-name bytes, including aliases. `minimum_size_bytes`
includes JBD2, reserved inodes/lost+found, descriptor reservations/backups,
bitmaps, inode tables and extent metadata, with conservative optimizer bounds.
It returns a sufficient whole-group generic image size, not a fixed padding
constant, sparse logical size or usable-capacity promise. This policy is
separate from managed uppers' fixed exact-backing geometry below.

The generic formatter freezes the actual descriptor reservation before placing
the journal. Appends beyond the initial size consume that same reservation;
they never infer a larger physical reservation from the grown file length.
Exhausting the original area fails before descriptor writes could overwrite
the journal. Managed uppers still reserve their separate fixed 64-block area.

Normalized ingestion/composition acceptance and flat ext4 representability are
separate. The generic writer retains its checked 65,000 directory-link bound
(at most 64,998 direct subdirectories); it fails staging rather than clamping
counts or publishing a partial artifact. The same generic flat artifact also
seeds writable opaque-raw roots, so a read-only-only DIR_NLINK sentinel shortcut
would be incorrect after that consumer becomes writable. This change does not
enable generic htrees/DIR_NLINK or claim every admitted namespace topology is
flat-renderable. Managed uppers retain their separate fixed profile.
The 4096-byte ext4 profile also admits symlink targets only through 4095 bytes:
Linux needs one terminating byte in the target block. A longer normalized
target may remain stored/composable, but flat materialization rejects it before
replacing any inode or creating parents, never truncates it.


### Read an ext4 image

```rust
use disk_image::ext4::Reader;

let mut reader = Reader::new(std::path::Path::new("rootfs.ext4"))?;

// Check existence, list directories, read files.
assert!(reader.exists("/etc/hostname"));
let entries = reader.list_dir("/etc")?;
let data = reader.read_file("/etc/hostname", 0, None)?;
assert_eq!(&data, b"silo\n");
```

### Probe an image format

```rust
use disk_image::ext4::{ProbeResult, probe};

assert_eq!(probe(std::path::Path::new("rootfs.ext4"))?, ProbeResult::Ext4);
```

`probe` checks only the ext4 superblock magic. It reports short files and magic
mismatches as `ProbeResult::NotExt4`; it does not validate the filesystem.

### Inspect a partition table

Partition facts are provided by the sibling [`disk-partition`](../disk-partition)
crate, independently of this crate's ext4 and qcow2 code. It is `no_std + alloc`
by default, with an opt-in `std` feature for a held `Read + Seek` source:

```toml
[dependencies]
disk-partition = { path = "common/disk-partition", features = ["std"] }
```

```rust
use disk_partition::{Geometry, ReadMode, read_table, validate_linux_direct_table};

let mut source = std::fs::File::open("root.raw")?;
let geometry = Geometry::new(source.metadata()?.len())?;
let table = read_table(&mut source, geometry, ReadMode::StrictImport)?;
validate_linux_direct_table(&table)?;
```

Guest callers implement `ReadAt` on their held block-device descriptor, with
their own associated error type. `read_table` returns `Error<R::Error>` and
preserves the failing byte offset and source error without allocating strings.
`Geometry::new` performs no I/O and returns `Error<core::convert::Infallible>`,
so its error type never needs a caller-supplied generic argument.

The shared parser bounds disks to 1 TiB with 512-byte sectors, GPT to 128 entries
and 128–4096-byte power-of-two strides, and MBR to four primary slots. It checks
both GPT copies, CRCs, reserved fields, overlaps and duplicate GUIDs. Strict
import requires GPT at current capacity; guest boot can retain matching
original GPT copies after opaque disk growth. Corrupt or unsupported tables
never become a whole-disk fallback.

Linux direct boot additionally requires 128-byte GPT entries, enforced by
`validate_linux_direct_table`; wider entries remain inspectable. This helper
does not select a root or admit a filesystem. A `PartitionTable::None` result
is suitable only for an explicit whole-disk selector.

### Create a private managed upper

```rust
use disk_image::ext4::upper::format_upper;
use rootfs_spec::upper_geometry::UpperCapacity;

let capacity = UpperCapacity::new(64 * 1024 * 1024)?;
let upper = format_upper(std::path::Path::new("upper.raw"), capacity)?;
```

`silo-upper-ext4-v1` is a separate fixed policy over the same writer, not a
change to generic OCI formatting. It creates only a new sparse 0600 file, with
a random v4 UUID, root-owned empty `upper/` (0755), `work/` (0700) and
`lost+found/` (0700). Existing destinations and symlinks are never overwritten.
The caller owns failed staging-file cleanup, synchronization and publication.

Capacity accepts every 4096-byte-aligned length from 64 MiB through 1 TiB.
Backing length is exact. The result separately returns actual filesystem span,
excluded short-group tail, initial free blocks in bytes and free inodes.
Free blocks are not mounted statvfs usable capacity or host physical allocation.
A tail too small for the qualified Linux resize rule adds no filesystem space.
Shared core-only `rootfs-spec::upper_geometry` arithmetic is used by init to
reject unexplained undergrowth, not to treat ioctl success as proof.

The fixed profile uses 4096-byte blocks, 256-byte inodes, 8192 inodes/group,
32-byte descriptors and 64 total active-plus-reserved descriptor blocks
(63 reserved for small uppers, zero at 1 TiB). Flex log size is 13 (8192 groups,
covering 1 TiB without signed flex-size overflow); the default hash is signed
half-MD4 seeded with the UUID's four little-endian words.
The clean internal JBD2 v2 journal uses 4096-byte blocks, first log block and
initial sequence 1, one user, no journal feature bits, and the existing size
ladder evaluated against the actual filesystem span (1024 blocks at 64 MiB).
Independent Linux `e2fsck`, `dumpe2fs` and `debugfs` tests validate images;
they are not production dependencies.

Managed uppers must not use the offline grower below. Stopped growth copies
the old prefix unchanged into a replacement private file of the new exact
length, without host ext4 metadata changes. Init replays and grows upperfs
using `EXT4_IOC_RESIZE_FS`; it never uses `resize2fs` or resizes overlay `/`.
Persistent work/index state is never recreated on restart. Native clean/dirty
growth, descriptor consumption across 16 GiB and sparse 1 TiB growth remain
production-path smoke gates, not Cargo VM tests.

### Grow an ext4 image

```rust
let target = 64 * 1024 * 1024 * 1024;
std::fs::OpenOptions::new()
    .write(true)
    .open("rootfs.ext4")?
    .set_len(target)?;
disk_image::ext4::grow_image(std::path::Path::new("rootfs.ext4"), target)?;
```

Offline growth requires exclusive access and a clean journal. After an unclean
shutdown, boot the image so Linux can replay JBD2 and use the mounted online
resize path instead.

## Architecture

```
user code --> formatter.rs -- close() --> .ext4 image
user code --> reader.rs ----------------> .ext4 image
```

Internally, the formatter writes data sequentially and computes the final metadata layout at `close()` time:

1. File and symlink data blocks are appended as `create()` is called.
2. Directory entries are committed in breadth-first order, sorted for `e2fsck`.
3. Block group layout is optimized to minimize group count.
4. The internal journal, resize inode metadata, backup superblocks, group descriptors, inode tables, bitmaps, and the primary superblock are written.

## ext4 Feature Flags

This table follows the feature list documented in [`ext4(5)`](https://www.man7.org/linux/man-pages/man5/ext4.5.html). Status describes what `ext4` currently emits or supports.

| Feature                  | Status        | Description                                                                                                                                              |
| ------------------------ | ------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `64bit`                  | Not supported | Enables the file system to be larger than 2^32 blocks.                                                                                                   |
| `bigalloc`               | Not supported | Enables clustered block allocation, so the unit of allocation is a power-of-two number of blocks.                                                        |
| `casefold`               | Not supported | Provides file-system-level character encoding support for directories with the casefold flag enabled.                                                    |
| `dir_index`              | Upper profile | Enables half-MD4 directory indexing; the kernel builds htrees when directories grow.                                                                    |
| `dir_nlink`              | Upper profile | Enables the kernel's large-directory link-count convention.                                                                                             |
| `ea_inode`               | Not supported | Allows extended attribute values to be placed in data blocks of a separate inode.                                                                        |
| `encrypt`                | Not supported | Enables file-system-level encryption of data blocks and file names.                                                                                      |
| `ext_attr`               | Enabled       | Enables the use of extended attributes.                                                                                                                  |
| `extent` / `extents`     | Enabled       | Stores logical-to-physical block mappings in extent trees instead of traditional indirect block maps.                                                    |
| `extra_isize`            | Enabled       | Reserves space in each inode for extended metadata such as nanosecond timestamps and file creation time.                                                 |
| `fast_commit`            | Not supported | Enables a fast-commit journal area for low-latency metadata commits.                                                                                     |
| `filetype`               | Enabled       | Stores file type information in directory entries.                                                                                                       |
| `flex_bg`                | Enabled       | Allows per-block-group metadata, such as allocation bitmaps and inode tables, to be placed anywhere on the storage media.                                |
| `has_journal`            | Enabled       | Creates an internal inode-8 JBD2 journal for kernel crash recovery.                                                                                       |
| `huge_file`              | Enabled       | Allows files to be larger than 2 terabytes.                                                                                                              |
| `inline_data`            | Not supported | Allows data to be stored in the inode and extended attribute area.                                                                                       |
| `journal_dev`            | Not supported | Marks the superblock found on an external journal device.                                                                                                |
| `large_dir`              | Not supported | Raises the maximum size of directories and, for hashed b-tree directories, the maximum tree height.                                                      |
| `large_file`             | Enabled       | Allows files larger than 2 GiB and prevents very old kernels from mounting file systems that cannot be understood.                                       |
| `metadata_csum`          | Not supported | Enables checksums for filesystem metadata such as superblocks, group descriptors, bitmaps, directories, and extent tree blocks.                          |
| `metadata_csum_seed`     | Not supported | Stores the metadata checksum seed in the superblock so the UUID can change while mounted.                                                                |
| `meta_bg`                | Not supported | Allows online resize without explicitly reserving space for growth in the block group descriptor table.                                                  |
| `mmp`                    | Not supported | Provides multiple mount protection to prevent the file system from being mounted more than once.                                                         |
| `orphan_file`            | Not supported | Fixes a scalability bottleneck for workloads doing many truncate or file-extension operations in parallel.                                               |
| `project`                | Not supported | Provides project quota support.                                                                                                                          |
| `quota`                  | Not supported | Creates quota inodes and enables quota accounting automatically when mounted.                                                                            |
| `resize_inode`           | Enabled       | Reserves space so the block group descriptor table can be extended while resizing a mounted file system.                                                 |
| `sparse_super`           | Enabled       | Stores backup copies of the superblock and block group descriptors only in selected block groups.                                                        |
| `sparse_super2`          | Not supported | Stores at most two backup superblocks and block group descriptors. Intentionally disabled because this layout breaks the Silo Linux online-resize path. |
| `stable_inodes`          | Not supported | Marks inode numbers and the filesystem UUID as stable, preventing shrinking and UUID changes.                                                            |
| `uninit_bg` / `gdt_csum` | Enabled       | Protects block group descriptors using checksums and makes it safe to create a file system without initializing all block groups.                        |
| `verity`                 | Not supported | Enables readonly verity files whose data is verified against a hidden Merkle tree.                                                                       |

## Limitations

- Block size is fixed at **4096 bytes**.
- Maximum file size is **128 GiB**.
- Extent tree depth is limited to **1**.
- Offline resize supports the Silo formatter profile only and refuses images that require journal recovery.
- Host-side JBD2 replay is intentionally not implemented; Linux performs recovery before the guest online-resize fallback.
- `sparse_super2` is intentionally disabled; use classic `sparse_super` plus `resize_inode` for Linux online resize.
- The formatter writes a focused subset of ext4 metadata. Features outside the table's enabled set should be treated as unsupported even if the reader can tolerate some of their on-disk structures.

## Testing

Tests cover:

- Struct serialization round-trips for on-disk types.
- Formatter and reader end-to-end behavior for files, directories, symlinks, hard links, and xattrs.
- Low-level superblock, group descriptor, bitmap, inode table, backup metadata, and resize inode validation.
- Linux-only e2fsprogs validation for generated images and offline resize.
- Internal journal layout and pure-Rust offline grow behavior.
- Error paths, symlink loops, boundary conditions, and bug regressions.

```sh
cargo test -p disk-image
```

The e2fsprogs integration tests compile and run only on Linux. They call the
host `tune2fs`, `e2fsck`, `resize2fs`, and `debugfs` binaries, and they create
temporary images under the system temp directory outside the workspace.

```sh
cargo test -p disk-image --test e2fsprogs -- --nocapture
```

## Origins

`disk-image::ext4` began as a source snapshot of upstream [`arcbox-ext4`](https://github.com/arcboxlabs/ext4-rs). Silo keeps the fork history explicit in [`FORK.md`](FORK.md) because the code was not born immaculate from a seashell.

The original architecture was also inspired by Apple's [ContainerizationEXT4](https://github.com/apple/containerization) Swift implementation and audited against the ext4 disk layout specification.

## License

Licensed under either of

- [Apache License, Version 2.0](LICENSE-APACHE)
- [MIT License](LICENSE-MIT)

at your option.
