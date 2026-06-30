# Bento ext4 Fork

This crate is a source snapshot of the upstream `arcbox-ext4` crate.

- Upstream repository: <https://github.com/arcboxlabs/ext4-rs>
- Forked from commit: `9e715f6911d31656e960dc1cabe543930de82724`
- Upstream branch at fork time: `master`
- Fork date: 2026-06-05
- Local crate path: `common/ext4`

## Why This Fork Exists

Bento generates ext4 root filesystem images and then grows the backing block
device for VM instances. The guest runs `resize2fs` against the mounted root
filesystem. Linux ext4 refuses mounted online resize when the filesystem has the
`sparse_super2` feature, and upstream `arcbox-ext4` currently emits
`sparse_super2` unconditionally.

Bento needs an online-growable ext4 profile that uses the classic
`sparse_super` layout plus `resize_inode`, with the matching backup superblock,
group descriptor, and reserved GDT metadata. Do not solve this by flipping
feature bits without writing the corresponding on-disk structures.
