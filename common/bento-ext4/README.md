# bento-ext4

Pure-Rust ext4 filesystem formatter and reader for Bento root disks.

No kernel mount. No FUSE. No C dependencies.

`bento-ext4` creates and reads ext4 filesystem images entirely in userspace. It is designed for one job: converting OCI container image layers into mountable ext4 block devices on macOS and Linux, without needing `mkfs.ext4`, `libext2fs`, or any Linux tools on the host.

This crate started as a source snapshot of upstream [`arcbox-ext4`](https://github.com/arcboxlabs/ext4-rs). See [`FORK.md`](FORK.md) for the fork point and the Bento-specific filesystem changes.

## Why

Container runtimes on macOS need to build ext4 root filesystems from OCI image layers. The standard approach requires either shelling out to Linux `mkfs.ext4` (not available on macOS) or linking against C libraries like `lwext4`. This crate does it in pure Rust.

The formatter now emits classic Linux-growable ext4 metadata: `sparse_super` plus `resize_inode`, not `sparse_super2`. That layout is required for the online resize path Bento uses for Linux guests.

## Features

|                         |                                                                                                                                |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| **Formatter**           | Create ext4 images from scratch: superblock, group descriptors, inode table, bitmaps, extent trees, and online-resize metadata |
| **Reader**              | Open existing ext4 images: path resolution, symlink following, file reading                                                    |
| **OCI Unpack**          | Stream tar layers directly into ext4 with full OCI whiteout support                                                            |
| **Extended Attributes** | Inline and block-level xattrs with name compression                                                                            |
| **Hard Links**          | Correct reference counting with deferred block reclamation                                                                     |
| **Symlinks**            | Fast symlinks (inline, less than 60 bytes) and slow symlinks (data blocks)                                                     |

## Quick Start

```toml
[dependencies]
bento-ext4 = { path = "common/bento-ext4" }
```

### Create an ext4 image

```rust
use std::path::Path;
use bento_ext4::{Formatter, constants::{make_mode, file_mode}};

let mut fmt = Formatter::new(Path::new("rootfs.ext4"), 4096, 64 * 1024 * 1024)?;

// Create directories and files.
fmt.create("/etc", make_mode(file_mode::S_IFDIR, 0o755),
    None, None, None, None, None, None)?;
fmt.create("/etc/hostname", make_mode(file_mode::S_IFREG, 0o644),
    None, None, Some(&mut b"bento\n".as_slice()), None, None, None)?;

// Create a symlink.
fmt.create("/etc/localtime", make_mode(file_mode::S_IFLNK, 0o777),
    Some("/usr/share/zoneinfo/UTC"), None, None, None, None, None)?;

// Finalize: writes superblock, group descriptors, bitmaps, inode table,
// backup metadata, and resize inode metadata.
fmt.close()?;
```

### Read an ext4 image

```rust
use bento_ext4::Reader;

let mut reader = Reader::new(std::path::Path::new("rootfs.ext4"))?;

// Check existence, list directories, read files.
assert!(reader.exists("/etc/hostname"));
let entries = reader.list_dir("/etc")?;
let data = reader.read_file("/etc/hostname", 0, None)?;
assert_eq!(&data, b"bento\n");
```

### Unpack OCI layers

```rust
use bento_ext4::Formatter;

let mut fmt = Formatter::new(path, 4096, 512 * 1024 * 1024)?;

// Apply layers in order. Whiteouts (.wh.* and .wh..wh..opq) are handled.
fmt.unpack_tar(layer1_reader)?;
fmt.unpack_tar(layer2_reader)?;

fmt.close()?;
```

## Architecture

```
                    ┌─────────────┐
  OCI tar layers ──▶│  unpack.rs  │
                    └──────┬──────┘
                           ▼
                    ┌─────────────┐         ┌─────────────┐
    user code ────▶ │formatter.rs │────────▶│   .ext4     │
                    └─────────────┘  close()│   image     │
                                            └──────┬──────┘
                                                   ▼
                                            ┌─────────────┐
                    user code ────────────▶ │  reader.rs  │
                                            └─────────────┘
```

Internally, the formatter writes data sequentially and computes the final metadata layout at `close()` time:

1. File and symlink data blocks are appended as `create()` is called.
2. Directory entries are committed in breadth-first order, sorted for `e2fsck`.
3. Block group layout is optimized to minimize group count.
4. Resize inode metadata, backup superblocks, group descriptors, inode tables, bitmaps, and the primary superblock are written.

## ext4 Feature Flags

This table follows the feature list documented in [`ext4(5)`](https://www.man7.org/linux/man-pages/man5/ext4.5.html). Status describes what `bento-ext4` currently emits or supports.

| Feature                  | Status        | Description                                                                                                                                              |
| ------------------------ | ------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `64bit`                  | Not supported | Enables the file system to be larger than 2^32 blocks.                                                                                                   |
| `bigalloc`               | Not supported | Enables clustered block allocation, so the unit of allocation is a power-of-two number of blocks.                                                        |
| `casefold`               | Not supported | Provides file-system-level character encoding support for directories with the casefold flag enabled.                                                    |
| `dir_index`              | Not supported | Uses hashed b-trees to speed up name lookups in large directories.                                                                                       |
| `dir_nlink`              | Not supported | Lifts the normal ext4 limit of 65,000 hard links for directories by using a link count of 1 when the count is not known.                                 |
| `ea_inode`               | Not supported | Allows extended attribute values to be placed in data blocks of a separate inode.                                                                        |
| `encrypt`                | Not supported | Enables file-system-level encryption of data blocks and file names.                                                                                      |
| `ext_attr`               | Enabled       | Enables the use of extended attributes.                                                                                                                  |
| `extent` / `extents`     | Enabled       | Stores logical-to-physical block mappings in extent trees instead of traditional indirect block maps.                                                    |
| `extra_isize`            | Enabled       | Reserves space in each inode for extended metadata such as nanosecond timestamps and file creation time.                                                 |
| `fast_commit`            | Not supported | Enables a fast-commit journal area for low-latency metadata commits.                                                                                     |
| `filetype`               | Enabled       | Stores file type information in directory entries.                                                                                                       |
| `flex_bg`                | Enabled       | Allows per-block-group metadata, such as allocation bitmaps and inode tables, to be placed anywhere on the storage media.                                |
| `has_journal`            | Not supported | Creates a journal to ensure file-system consistency across unclean shutdowns.                                                                            |
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
| `sparse_super2`          | Not supported | Stores at most two backup superblocks and block group descriptors. Intentionally disabled because this layout breaks the Bento Linux online-resize path. |
| `stable_inodes`          | Not supported | Marks inode numbers and the filesystem UUID as stable, preventing shrinking and UUID changes.                                                            |
| `uninit_bg` / `gdt_csum` | Enabled       | Protects block group descriptors using checksums and makes it safe to create a file system without initializing all block groups.                        |
| `verity`                 | Not supported | Enables readonly verity files whose data is verified against a hidden Merkle tree.                                                                       |

## Limitations

- Block size is fixed at **4096 bytes**.
- Maximum file size is **128 GiB**.
- Extent tree depth is limited to **1**.
- There is no journal. Images are built once as container root filesystems and may be mounted read-write without crash recovery.
- `sparse_super2` is intentionally disabled; use classic `sparse_super` plus `resize_inode` for Linux online resize.
- The formatter writes a focused subset of ext4 metadata. Features outside the table's enabled set should be treated as unsupported even if the reader can tolerate some of their on-disk structures.

## Testing

Tests cover:

- Struct serialization round-trips for on-disk types.
- Formatter and reader end-to-end behavior for files, directories, symlinks, hard links, and xattrs.
- OCI two-layer rootfs simulation.
- Low-level superblock, group descriptor, bitmap, inode table, backup metadata, and resize inode validation.
- Docker/e2fsprogs validation for generated images and offline resize.
- Error paths, symlink loops, boundary conditions, and bug regressions.

```sh
cargo test -p bento-ext4
```

Docker/e2fsprogs validation tests are ignored by default:

```sh
cargo test -p bento-ext4 --test e2fsprogs -- --ignored --nocapture
```

## Origins

`bento-ext4` began as a source snapshot of upstream [`arcbox-ext4`](https://github.com/arcboxlabs/ext4-rs). Bento keeps the fork history explicit in [`FORK.md`](FORK.md) because the code was not born immaculate from a seashell.

The original architecture was also inspired by Apple's [ContainerizationEXT4](https://github.com/apple/containerization) Swift implementation and audited against the ext4 disk layout specification.

## License

Licensed under either of

- [Apache License, Version 2.0](LICENSE-APACHE)
- [MIT License](LICENSE-MIT)

at your option.
