//! Observes public production output only. Never used to construct expectations.
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;

use oci::changeset::namespace::{NamespaceKind, ValidatedNamespace};
use sha2::{Digest, Sha256};

use crate::support::oracle::{bytes, Attribute, Row};

pub fn listing(namespace: &ValidatedNamespace, packs: &[PathBuf]) -> Vec<Row> {
    let mut first = BTreeMap::new();
    for (path, name) in namespace.names() {
        first.entry(name.inode).or_insert(path.as_slice());
    }
    namespace
        .names()
        .iter()
        .map(|(path, name)| {
            let inode = &namespace.inodes()[&name.inode];
            let mut row = Row {
                path: bytes(path),
                kind: String::new(),
                mode: inode.metadata.mode,
                uid: inode.metadata.uid,
                gid: inode.metadata.gid,
                mtime_seconds: inode.metadata.mtime_seconds,
                mtime_nanos: inode.metadata.mtime_nanos,
                xattrs: inode
                    .metadata
                    .xattrs
                    .iter()
                    .map(|attr| Attribute {
                        name: bytes(&attr.name),
                        value: bytes(&attr.value),
                    })
                    .collect(),
                length: None,
                content: None,
                target: None,
                device_major: None,
                device_minor: None,
                group: Some(bytes(first[&name.inode])),
                links: Some(inode.link_count),
            };
            match &inode.kind {
                NamespaceKind::Directory => {
                    row.kind = "directory".into();
                    row.group = None;
                    row.links = None;
                }
                NamespaceKind::Regular { body } => {
                    row.kind = "regular".into();
                    row.length = Some(body.length);
                    let mut file = File::open(&packs[body.entry.layer as usize])
                        .expect("retained fixture pack");
                    file.seek(SeekFrom::Start(body.pack_offset))
                        .expect("seek fixture body");
                    let mut limited = file.take(body.length);
                    let mut digest = Sha256::new();
                    let mut buffer = [0_u8; 16384];
                    let mut total = 0_u64;
                    loop {
                        let n = limited.read(&mut buffer).expect("read fixture body");
                        if n == 0 {
                            break;
                        }
                        digest.update(&buffer[..n]);
                        total += n as u64;
                    }
                    assert_eq!(total, body.length, "body extent exists");
                    row.content = Some(crate::support::oracle::digest_text(&digest.finalize()));
                }
                NamespaceKind::Symlink { target } => {
                    row.kind = "symlink".into();
                    row.target = Some(bytes(target));
                }
                NamespaceKind::CharacterDevice { major, minor } => {
                    row.kind = "character-device".into();
                    row.device_major = Some(*major);
                    row.device_minor = Some(*minor);
                }
                NamespaceKind::BlockDevice { major, minor } => {
                    row.kind = "block-device".into();
                    row.device_major = Some(*major);
                    row.device_minor = Some(*minor);
                }
                NamespaceKind::Fifo => row.kind = "fifo".into(),
                NamespaceKind::Socket => row.kind = "socket".into(),
            }
            row
        })
        .collect()
}
