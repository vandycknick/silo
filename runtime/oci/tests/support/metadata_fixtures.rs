//! Expected Linux metadata bytes are literal fixture inputs, never parser output.
use std::collections::BTreeMap;

use crate::support::fixtures::{fixture, rejects, Fixture};
use crate::support::oracle::{bytes, Attribute, Object, Operation, Stat, XattrWire};

// Linux v6.12 POSIX ACL xattr v2, five little-endian 8-byte records:
// USER_OBJ rw-, USER uid7 r--, GROUP_OBJ r--, MASK r--, OTHER r--.
// The four object entries carry the required all-ones object-id sentinel.
pub const ACCESS_ACL: &[u8] = &[
    2, 0, 0, 0, 1, 0, 6, 0, 255, 255, 255, 255, 2, 0, 4, 0, 7, 0, 0, 0, 4, 0, 4, 0, 255, 255, 255,
    255, 16, 0, 4, 0, 255, 255, 255, 255, 32, 0, 4, 0, 255, 255, 255, 255,
];
// Both this ACL and ACCESS_ACL individually agree with ordinary mode0644.
// Only the named user's permission differs, so conflict tests cannot pass merely
// because an alternative ACL changes owner/mask/other mode semantics.
pub const CONFLICTING_ACCESS_ACL: &[u8] = &[
    2, 0, 0, 0, 1, 0, 6, 0, 255, 255, 255, 255, 2, 0, 5, 0, 7, 0, 0, 0, 4, 0, 4, 0, 255, 255, 255,
    255, 16, 0, 4, 0, 255, 255, 255, 255, 32, 0, 4, 0, 255, 255, 255, 255,
];
pub const DEFAULT_ACL: &[u8] = &[
    2, 0, 0, 0, 1, 0, 7, 0, 255, 255, 255, 255, 2, 0, 5, 0, 7, 0, 0, 0, 4, 0, 5, 0, 255, 255, 255,
    255, 16, 0, 5, 0, 255, 255, 255, 255, 32, 0, 5, 0, 255, 255, 255, 255,
];
pub const ACCESS_TEXT: &[u8] = b"user::rw-,user:7:r--,group::r--,mask::r--,other::r--";
pub const CONFLICTING_ACCESS_TEXT: &[u8] = b"user::rw-,user:7:r-x,group::r--,mask::r--,other::r--";
pub const DEFAULT_TEXT: &[u8] = b"user::rwx,user:7:r-x,group::r-x,mask::r-x,other::r-x";

pub const CAP_V1: &[u8] = &[1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0];
pub const CAP_V2: &[u8] = &[1, 0, 0, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
pub const CAP_V3: &[u8] = &[
    1, 0, 0, 3, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];
pub const CAP_V3_HIGH_ROOT: &[u8] = &[
    1, 0, 0, 3, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 254, 255, 255, 255,
];
pub const CAP_40: &[u8] = &[0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
pub const SELINUX: &[u8] = b"system_u:object_r:container_file_t:s0\0";

fn attributes(mut operation: Operation, values: &[(&[u8], &[u8])]) -> Operation {
    let mut sorted = BTreeMap::new();
    for &(name, value) in values {
        assert!(
            sorted.insert(name, value).is_none(),
            "unique declared metadata name"
        );
    }
    operation.stat.xattrs = sorted
        .into_iter()
        .map(|(name, value)| Attribute {
            name: bytes(name),
            value: bytes(value),
        })
        .collect();
    operation.explicit_attrs = true;
    operation
}
fn file(path: &[u8], body: &[u8]) -> Operation {
    let mut operation = Operation::file(path, body);
    operation.stat.mode = 0o644;
    operation
}

pub fn corpus() -> Vec<Fixture> {
    let acl = attributes(
        file(b"acl", b"A"),
        &[(b"system.posix_acl_access", ACCESS_ACL)],
    );
    let mut text_acl = acl.clone();
    text_acl.wire.access_acl = Some(ACCESS_TEXT.to_vec());
    let directory = attributes(
        Operation::put(b"d", Object::Directory),
        &[(b"system.posix_acl_default", DEFAULT_ACL)],
    );
    let mut directory = directory;
    directory.stat.mode = 0o700;
    let mut root = attributes(
        Operation::put(b".", Object::Directory),
        &[(b"system.posix_acl_default", DEFAULT_ACL)],
    );
    root.stat.mode = 0o700;
    root.wire.default_acl = Some(DEFAULT_TEXT.to_vec());
    let label = attributes(file(b"label", b"L"), &[(b"security.selinux", SELINUX)]);
    let mut rht = label.clone();
    rht.wire.rht_selinux = true;
    let smack = attributes(
        file(b"smack", b"S"),
        &[
            (b"security.SMACK64", b"alpha"),
            (b"security.SMACK64EXEC", b"exec"),
            (b"security.SMACK64MMAP", b"mmap"),
        ],
    );
    let transmute = attributes(
        Operation::put(b"d", Object::Directory),
        &[
            (b"security.SMACK64", b"alpha"),
            (b"security.SMACK64TRANSMUTE", b"TRUE"),
        ],
    );
    let transmute_root = attributes(
        Operation::put(b".", Object::Directory),
        &[
            (b"security.SMACK64", b"alpha"),
            (b"security.SMACK64TRANSMUTE", b"TRUE"),
        ],
    );
    let mut capabilities = Vec::new();
    for (name, capability) in [
        (b"cap-v1".as_slice(), CAP_V1),
        (b"cap-v2", CAP_V2),
        (b"cap-v3", CAP_V3),
        (b"cap-v3-high-root", CAP_V3_HIGH_ROOT),
        (b"cap-40", CAP_40),
    ] {
        let mut operation = attributes(file(name, b"C"), &[(b"security.capability", capability)]);
        operation.stat.mode = 0o6755;
        capabilities.push(operation);
    }
    let target = attributes(
        file(b"target", b"old"),
        &[
            (b"security.capability", CAP_V2),
            (b"system.posix_acl_access", ACCESS_ACL),
            (b"user.marker", b"\0\xff\n="),
        ],
    );
    let mut link = attributes(
        Operation::link(b"b", b"target"),
        &[(b"system.posix_acl_access", ACCESS_ACL)],
    );
    link.stat.uid = 42;
    link.stat.gid = 43;
    link.stat.mode = 0o700;
    link.stat.mtime_seconds = 9;
    link.stat.mtime_nanos = 7;
    link.wire.access_acl = Some(ACCESS_TEXT.to_vec());
    let mut omitted = Operation::link(b"c", b"b");
    omitted.stat = Stat {
        uid: 10,
        gid: 11,
        mode: 0o600,
        mtime_seconds: 99,
        ..Stat::default()
    };
    let bad = attributes(
        Operation::link(b"bad", b"target"),
        &[(b"system.posix_acl_access", CONFLICTING_ACCESS_ACL)],
    );
    let mut bad = bad;
    bad.stat.mode = 0o700;
    let mut bad_text = bad.clone();
    bad_text.wire.access_acl = Some(CONFLICTING_ACCESS_TEXT.to_vec());
    let raw_names = attributes(
        file(b"raw-names", b"R"),
        &[
            (b"user.a b", b"space"),
            (b"user.\xc3\xa9", b"utf8"),
            (b"user.\xff", b"\0\xff\n="),
            (b"user.a+b", b"plus"),
        ],
    );
    let mut encoded_names = attributes(
        file(b"encoded-names", b"E"),
        &[
            (b"user.a=b", b"\xfb\xff\0\n="),
            (b"user.a%b", b"percent"),
            (b"user.a%3Db", b"literal-percent3D"),
            (b"user.a%25b", b"literal-percent25"),
            (b"user.a b", b""),
            (b"user.\xc3\xa9", b"utf8"),
            (b"user.\xff", b"raw"),
        ],
    );
    encoded_names.wire.xattrs = XattrWire::Libarchive;
    vec![
        fixture("metadata-access-acl-binary", &["M08"], vec![vec![acl]]),
        fixture("metadata-access-acl-text", &["M08"], vec![vec![text_acl]]),
        fixture(
            "metadata-access-acl-alternate-valid",
            &["M08"],
            vec![vec![attributes(
                file(b"acl", b"A"),
                &[(b"system.posix_acl_access", CONFLICTING_ACCESS_ACL)],
            )]],
        ),
        fixture(
            "metadata-default-acl-directory",
            &["M08"],
            vec![vec![directory, file(b"d/child", b"D")]],
        ),
        fixture(
            "metadata-default-acl-root-text",
            &["M02", "M08"],
            vec![vec![root, file(b"child", b"D")]],
        ),
        fixture(
            "metadata-capability-revisions",
            &["M06", "M08"],
            vec![capabilities],
        ),
        fixture("metadata-selinux-raw", &["M08"], vec![vec![label]]),
        fixture("metadata-selinux-rht", &["M08"], vec![vec![rht]]),
        fixture(
            "metadata-selinux-without-terminal-nul",
            &["M08"],
            vec![vec![attributes(
                file(b"label", b"L"),
                &[(
                    b"security.selinux",
                    b"system_u:object_r:container_file_t:s0",
                )],
            )]],
        ),
        fixture(
            "metadata-smack-labels",
            &["M08"],
            vec![vec![
                smack,
                attributes(file(b"star", b"*"), &[(b"security.SMACK64", b"*")]),
                attributes(file(b"at", b"@"), &[(b"security.SMACK64", b"@")]),
                attributes(
                    file(b"label255", b"255"),
                    &[(b"security.SMACK64", &vec![b'a'; 255])],
                ),
            ]],
        ),
        fixture(
            "metadata-smack-transmute-directory",
            &["M08"],
            vec![vec![transmute, file(b"d/child", b"D")]],
        ),
        fixture(
            "metadata-smack-transmute-root",
            &["M08"],
            vec![vec![transmute_root, file(b"child", b"D")]],
        ),
        fixture(
            "metadata-hardlink-chain",
            &["M07", "M08", "N09"],
            vec![
                vec![target.clone()],
                vec![link, omitted, file(b"target", b"new")],
                vec![Operation::remove(b".wh.target")],
            ],
        ),
        rejects(
            "metadata-hardlink-acl-conflict-binary",
            &["M07"],
            vec![vec![target.clone()], vec![bad]],
        ),
        rejects(
            "metadata-hardlink-acl-conflict-text",
            &["M07"],
            vec![vec![target], vec![bad_text]],
        ),
        fixture(
            "metadata-raw-schily-names",
            &["M08", "M14"],
            vec![vec![raw_names]],
        ),
        fixture(
            "metadata-libarchive-raw-names",
            &["M08", "M14"],
            vec![vec![encoded_names]],
        ),
    ]
}
