use crate::support::oracle::{
    Action, Attribute, Object, Operation, SparseEncoding, SparseSpec, Stat, XattrWire,
};

#[derive(Clone)]
pub struct Fixture {
    pub name: String,
    pub matrix: Vec<&'static str>,
    pub layers: Vec<Vec<Operation>>,
    pub rejection: bool,
}

pub fn fixture(name: &str, matrix: &[&'static str], layers: Vec<Vec<Operation>>) -> Fixture {
    Fixture {
        name: name.into(),
        matrix: matrix.to_vec(),
        layers,
        rejection: false,
    }
}
pub fn rejects(name: &str, matrix: &[&'static str], layers: Vec<Vec<Operation>>) -> Fixture {
    Fixture {
        rejection: true,
        ..fixture(name, matrix, layers)
    }
}
fn dir(path: &[u8]) -> Operation {
    Operation::put(path, Object::Directory)
}
fn symlink(path: &[u8], target: &[u8]) -> Operation {
    Operation::put(path, Object::Symlink(target.to_vec()))
}

/// All names, metadata and content here are inputs, never parser/composer output.
pub fn corpus() -> Vec<Fixture> {
    let file = Operation::file;
    let link = Operation::link;
    let remove = Operation::remove;
    let opaque = Operation::opaque;
    let mut explicit = dir(b"p/q");
    explicit.stat = Stat {
        uid: 7,
        mode: 0o700,
        mtime_seconds: 9,
        ..Stat::default()
    };
    let mut advisory = link(b"b", b"a");
    advisory.stat = Stat {
        uid: 42,
        gid: 43,
        mode: 0o600,
        mtime_seconds: 9,
        mtime_nanos: 7,
        ..Stat::default()
    };
    let mut nanos = file(b"nanos", b"N");
    nanos.stat.mtime_seconds = 1;
    nanos.stat.mtime_nanos = 123_456_789;
    let mut raw = file(b"raw-\xff", b"raw");
    raw.stat.xattrs.push(Attribute {
        name: crate::support::oracle::bytes(b"user.binary"),
        value: crate::support::oracle::bytes(b"\0\xff\n"),
    });
    raw.explicit_attrs = true;
    let mut root = dir(b".");
    root.stat = Stat {
        uid: 7,
        gid: 8,
        mode: 0o1770,
        mtime_seconds: 9,
        mtime_nanos: 10,
        ..Stat::default()
    };
    let mut slash_root = root.clone();
    slash_root.path = b"/".to_vec();
    let mut equal_attr = link(b"raw-link", b"raw-\xff");
    equal_attr.stat.xattrs = raw.stat.xattrs.clone();
    equal_attr.explicit_attrs = true;
    let mut different_attr = equal_attr.clone();
    different_attr.stat.xattrs[0].value = crate::support::oracle::bytes(b"wrong");
    let mut fixtures = vec![
        fixture("empty-repeated", &["N01"], vec![vec![], vec![], vec![]]),
        fixture(
            "replace-repeated",
            &["N02"],
            vec![
                vec![file(b"a", b"old")],
                vec![file(b"a", b"new")],
                vec![file(b"a", b"new")],
            ],
        ),
        fixture(
            "opaque-reverse",
            &["N03"],
            vec![
                vec![file(b"d/old", b"old")],
                vec![file(b"d/new", b"new"), opaque(b"d/.wh..wh..opq")],
            ],
        ),
        fixture(
            "opaque-first",
            &["N03"],
            vec![
                vec![file(b"d/old", b"old")],
                vec![opaque(b"d/.wh..wh..opq"), file(b"d/new", b"new")],
            ],
        ),
        fixture(
            "opaque-implicit-ancestors",
            &["N04"],
            vec![
                vec![file(b"a/b/c/bar", b"old")],
                vec![file(b"a/b/c/foo", b"new"), opaque(b"a/.wh..wh..opq")],
            ],
        ),
        fixture(
            "opaque-explicit-ancestors",
            &["N04"],
            vec![
                vec![file(b"a/b/c/bar", b"old")],
                vec![
                    dir(b"a"),
                    dir(b"a/b"),
                    dir(b"a/b/c"),
                    file(b"a/b/c/foo", b"new"),
                    opaque(b"a/.wh..wh..opq"),
                ],
            ],
        ),
        fixture(
            "whiteout-reverse",
            &["N05"],
            vec![
                vec![file(b"a", b"old")],
                vec![file(b"a", b"new"), remove(b".wh.a")],
            ],
        ),
        fixture(
            "whiteout-first",
            &["N05"],
            vec![
                vec![file(b"a", b"old")],
                vec![remove(b".wh.a"), file(b"a", b"new")],
            ],
        ),
        fixture(
            "directory-to-file",
            &["N06"],
            vec![vec![file(b"d/child", b"old")], vec![file(b"d", b"new")]],
        ),
        fixture(
            "directory-to-symlink",
            &["N06"],
            vec![
                vec![file(b"d/child", b"old")],
                vec![symlink(b"d", b"target")],
            ],
        ),
        fixture(
            "symlink-to-directory",
            &["N06"],
            vec![
                vec![symlink(b"d", b"target")],
                vec![dir(b"d"), file(b"d/child", b"new")],
            ],
        ),
        fixture(
            "directory-attributes",
            &["N06", "N07"],
            vec![
                vec![file(b"p/q/file", b"X"), explicit.clone()],
                vec![file(b"p/q/next", b"Y")],
            ],
        ),
        fixture(
            "link-before-replace",
            &["N08"],
            vec![
                vec![file(b"a", b"old")],
                vec![link(b"b", b"a"), file(b"a", b"new")],
            ],
        ),
        fixture(
            "link-before-replace-other-parent",
            &["N08", "V15"],
            vec![
                vec![file(b"a", b"different")],
                vec![link(b"b", b"a"), file(b"a", b"new")],
            ],
        ),
        fixture(
            "link-chain-delete",
            &["N09"],
            vec![
                vec![file(b"a", b"old")],
                vec![link(b"b", b"a"), link(b"c", b"b"), file(b"a", b"new")],
                vec![remove(b".wh.a")],
            ],
        ),
        rejects(
            "forward-link",
            &["N10"],
            vec![vec![link(b"b", b"a"), file(b"a", b"new")]],
        ),
        rejects(
            "self-link",
            &["N11"],
            vec![vec![file(b"a", b"old")], vec![link(b"a", b"a")]],
        ),
        rejects(
            "cyclic-link",
            &["N11"],
            vec![vec![link(b"a", b"b"), link(b"b", b"a")]],
        ),
        rejects(
            "directory-link",
            &["N11"],
            vec![vec![dir(b"d"), link(b"alias", b"d")]],
        ),
        fixture(
            "same-inode-relink",
            &["N12"],
            vec![
                vec![file(b"a", b"old"), link(b"b", b"a")],
                vec![link(b"b", b"a")],
            ],
        ),
        fixture(
            "hardlink-dangling-symlink",
            &["N13"],
            vec![vec![symlink(b"s", b"missing")], vec![link(b"t", b"s")]],
        ),
        fixture(
            "usrmerge-parent",
            &["N14"],
            vec![
                vec![dir(b"usr/bin"), symlink(b"bin", b"usr/bin")],
                vec![file(b"bin/tool", b"X")],
            ],
        ),
        fixture(
            "absolute-parent-clamp",
            &["N15"],
            vec![
                vec![
                    dir(b"usr/bin"),
                    symlink(b"s", b"/../../usr/bin"),
                    symlink(b"relative", b"s/../bin"),
                ],
                vec![file(b"relative/tool", b"X")],
            ],
        ),
        rejects(
            "dangling-parent",
            &["N16"],
            vec![vec![symlink(b"s", b"missing")], vec![file(b"s/file", b"X")]],
        ),
        rejects(
            "looping-parent",
            &["N16"],
            vec![
                vec![symlink(b"s", b"t"), symlink(b"t", b"s")],
                vec![file(b"s/file", b"X")],
            ],
        ),
        fixture(
            "resolved-alias-collision",
            &["N17"],
            vec![
                vec![dir(b"usr/bin"), symlink(b"bin", b"usr/bin")],
                vec![file(b"bin/x", b"A"), file(b"usr/bin/x", b"B")],
            ],
        ),
        fixture(
            "whiteout-lower-symlink",
            &["N18"],
            vec![
                vec![
                    file(b"target/x", b"old"),
                    file(b"other/x", b"keep"),
                    symlink(b"d", b"target"),
                ],
                vec![symlink(b"d", b"other"), remove(b"d/.wh.x")],
            ],
        ),
        fixture(
            "absent-whiteout",
            &["N19"],
            vec![vec![remove(b"missing/.wh.x")]],
        ),
        fixture(
            "advisory-link-metadata",
            &["M07"],
            vec![vec![file(b"a", b"old")], vec![advisory]],
        ),
        fixture(
            "binary-name-attrs",
            &["M02", "M08"],
            vec![vec![
                raw.clone(),
                symlink(b"link-\xfe", b"raw-\xff"),
                equal_attr,
            ]],
        ),
        rejects(
            "hardlink-attr-conflict",
            &["M07"],
            vec![vec![raw], vec![different_attr]],
        ),
        fixture(
            "root-slash-metadata",
            &["N01", "M02", "M05"],
            vec![vec![slash_root, nanos.clone()]],
        ),
        fixture("root-metadata", &["M02", "M05"], vec![vec![root, nanos]]),
        fixture(
            "special-inodes",
            &["M11", "M12"],
            vec![vec![
                Operation::put(b"null", Object::Character(1, 3)),
                Operation::put(b"block", Object::Block(8, 0)),
                Operation::put(b"fifo", Object::Fifo),
                Operation::put(b"socket", Object::Socket),
                link(b"fifo-link", b"fifo"),
            ]],
        ),
        fixture(
            "pack-A-empty-BC",
            &["V01"],
            vec![vec![
                file(b"a", b"A"),
                dir(b"d"),
                link(b"alias", b"a"),
                file(b"empty", b""),
                remove(b".wh.absent"),
                file(b"bc", b"BC"),
            ]],
        ),
    ];
    for hops in [40, 41] {
        let mut lower = vec![dir(b"end")];
        for n in 0..hops {
            let target = if n + 1 == hops {
                b"end".to_vec()
            } else {
                format!("s{}", n + 1).into_bytes()
            };
            lower.push(symlink(format!("s{n}").as_bytes(), &target));
        }
        fixtures.push(Fixture {
            rejection: hops == 41,
            ..fixture(
                &format!("parent-{hops}-hops"),
                &["N15"],
                vec![lower, vec![file(b"s0/tool", b"X")]],
            )
        });
    }
    let mut components = vec![vec![b'x'; 255]; 16];
    components[15].pop();
    let long_parent = components.join(&b'/');
    assert_eq!(long_parent.len(), 4094);
    fixtures.push(rejects(
        "resolved-destination-overflow",
        &["V11"],
        vec![
            vec![dir(&long_parent), symlink(b"s", &long_parent)],
            vec![file(b"s/xx", b"X")],
        ],
    ));
    for (name, encoding) in [
        ("old-gnu", SparseEncoding::OldGnu),
        ("pax-0.0", SparseEncoding::Pax00),
        ("pax-0.1", SparseEncoding::Pax01),
        ("pax-1.0", SparseEncoding::Pax10),
    ] {
        let mut logical = vec![0; 4097];
        logical[4096] = b'X';
        let mut operation = file(b"sparse", &logical);
        operation.sparse = Some(SparseSpec {
            encoding,
            ranges: vec![(4096, 1)],
        });
        fixtures.push(fixture(
            &format!("sparse-{name}"),
            &["V02"],
            vec![vec![operation]],
        ));
        let mut all_hole = file(b"hole", &vec![0; 4097]);
        all_hole.sparse = Some(SparseSpec {
            encoding,
            ranges: vec![(4097, 0)],
        });
        fixtures.push(fixture(
            &format!("all-hole-{name}"),
            &["V02"],
            vec![vec![all_hole]],
        ));
    }
    let mut chunk_boundary = vec![0_u8; 8_388_608 + 3];
    chunk_boundary[8_388_608..].copy_from_slice(b"END");
    fixtures.push(fixture(
        "stream-full-zero-and-short-tail",
        &["V16"],
        vec![vec![Operation::put(b"large", Object::File(chunk_boundary))]],
    ));
    fixtures.extend(crate::support::metadata_fixtures::corpus());
    fixtures
}

/// A small independent ustar/PAX encoder. Never calls the production tar parser.
pub fn archive(operations: &[Operation]) -> Vec<u8> {
    let mut out = Vec::new();
    for operation in operations {
        if let Some(sparse) = &operation.sparse {
            sparse_member(&mut out, operation, sparse);
            continue;
        }
        let mut pax = Vec::new();
        if operation.stat.mtime_nanos != 0 {
            pax_record(
                &mut pax,
                b"mtime",
                format!(
                    "{}.{:09}",
                    operation.stat.mtime_seconds, operation.stat.mtime_nanos
                )
                .as_bytes(),
            );
        }
        for attr in &operation.stat.xattrs {
            use base64::Engine;
            let name = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(&attr.name)
                .expect("fixture xattr name");
            let value = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(&attr.value)
                .expect("fixture xattr value");
            if name == b"system.posix_acl_access" {
                if let Some(text) = &operation.wire.access_acl {
                    pax_record(&mut pax, b"SCHILY.acl.access", text);
                    continue;
                }
            }
            if name == b"system.posix_acl_default" {
                if let Some(text) = &operation.wire.default_acl {
                    pax_record(&mut pax, b"SCHILY.acl.default", text);
                    continue;
                }
            }
            if name == b"security.selinux" && operation.wire.rht_selinux {
                pax_record(&mut pax, b"RHT.security.selinux", &value);
                continue;
            }
            match operation.wire.xattrs {
                XattrWire::Schily => {
                    let mut key = b"SCHILY.xattr.".to_vec();
                    key.extend_from_slice(&name);
                    pax_record(&mut pax, &key, &value);
                }
                XattrWire::Libarchive => {
                    let mut key = b"LIBARCHIVE.xattr.".to_vec();
                    for byte in name {
                        key.extend_from_slice(format!("%{byte:02X}").as_bytes());
                    }
                    let value = base64::engine::general_purpose::STANDARD_NO_PAD.encode(value);
                    pax_record(&mut pax, &key, value.as_bytes());
                }
            }
        }
        if matches!(operation.action, Action::Put(Object::Socket)) {
            pax_record(&mut pax, b"SCHILY.filetype", b"socket");
        }
        if operation.path.len() > 100 {
            pax_record(&mut pax, b"path", &operation.path);
        }
        let target = match &operation.action {
            Action::Link(target) | Action::Put(Object::Symlink(target)) => target.as_slice(),
            _ => &[],
        };
        if target.len() > 100 {
            pax_record(&mut pax, b"linkpath", target);
        }
        if !pax.is_empty() {
            member(
                &mut out,
                b"PaxHeaders/entry",
                b'x',
                &[],
                &pax,
                &Stat::default(),
                (0, 0),
            );
        }
        let (kind, body, major, minor) = match &operation.action {
            Action::Put(Object::Directory) => (b'5', &b""[..], 0, 0),
            Action::Put(Object::File(body)) => (b'0', body.as_slice(), 0, 0),
            Action::Put(Object::Symlink(_)) => (b'2', &b""[..], 0, 0),
            Action::Link(_) => (b'1', &b""[..], 0, 0),
            Action::Put(Object::Character(major, minor)) => (b'3', &b""[..], *major, *minor),
            Action::Put(Object::Block(major, minor)) => (b'4', &b""[..], *major, *minor),
            Action::Put(Object::Fifo) => (b'6', &b""[..], 0, 0),
            _ => (b'0', &b""[..], 0, 0),
        };
        member(
            &mut out,
            &operation.path[..operation.path.len().min(100)],
            kind,
            &target[..target.len().min(100)],
            body,
            &operation.stat,
            (major, minor),
        );
    }
    out.resize(out.len() + 1024, 0);
    out
}

fn pax_record(out: &mut Vec<u8>, key: &[u8], value: &[u8]) {
    let suffix = key.len() + value.len() + 3;
    let mut length = suffix + 1;
    loop {
        let next = suffix + length.to_string().len();
        if next == length {
            break;
        }
        length = next;
    }
    out.extend_from_slice(length.to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(key);
    out.push(b'=');
    out.extend_from_slice(value);
    out.push(b'\n');
}

fn octal(dst: &mut [u8], value: u64) {
    let text = format!("{value:0width$o}", width = dst.len() - 1);
    assert_eq!(text.len(), dst.len() - 1, "fixture number fits ustar");
    dst[..text.len()].copy_from_slice(text.as_bytes());
}

fn member(
    out: &mut Vec<u8>,
    path: &[u8],
    kind: u8,
    target: &[u8],
    body: &[u8],
    stat: &Stat,
    device: (u32, u32),
) {
    let mut header = [0_u8; 512];
    header[..path.len()].copy_from_slice(path);
    octal(&mut header[100..108], u64::from(stat.mode));
    octal(&mut header[108..116], u64::from(stat.uid));
    octal(&mut header[116..124], u64::from(stat.gid));
    octal(&mut header[124..136], body.len() as u64);
    octal(&mut header[136..148], stat.mtime_seconds);
    header[148..156].fill(b' ');
    header[156] = kind;
    header[157..157 + target.len()].copy_from_slice(target);
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    octal(&mut header[329..337], u64::from(device.0));
    octal(&mut header[337..345], u64::from(device.1));
    let checksum: u64 = header.iter().map(|byte| u64::from(*byte)).sum();
    let checksum = format!("{checksum:06o}\0 ");
    header[148..156].copy_from_slice(checksum.as_bytes());
    out.extend_from_slice(&header);
    out.extend_from_slice(body);
    out.resize(out.len().div_ceil(512) * 512, 0);
}

fn sparse_member(out: &mut Vec<u8>, operation: &Operation, sparse: &SparseSpec) {
    let Action::Put(Object::File(logical)) = &operation.action else {
        panic!("sparse fixture is a regular body");
    };
    let mut stored = Vec::new();
    for &(offset, length) in &sparse.ranges {
        stored.extend_from_slice(&logical[offset as usize..(offset + length) as usize]);
    }
    let mut pax = Vec::new();
    match sparse.encoding {
        SparseEncoding::OldGnu => {
            assert!(sparse.ranges.len() <= 4);
            let start = out.len();
            member(
                out,
                &operation.path,
                b'S',
                &[],
                &stored,
                &operation.stat,
                (0, 0),
            );
            let header = &mut out[start..start + 512];
            header[257..265].copy_from_slice(b"ustar  \0");
            for (slot, &(offset, length)) in sparse.ranges.iter().enumerate() {
                let at = 386 + slot * 24;
                octal(&mut header[at..at + 12], offset);
                octal(&mut header[at + 12..at + 24], length);
            }
            octal(&mut header[483..495], logical.len() as u64);
            header[148..156].fill(b' ');
            let sum: u64 = header.iter().map(|byte| u64::from(*byte)).sum();
            header[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
            return;
        }
        SparseEncoding::Pax00 | SparseEncoding::Pax01 => {
            pax_record(
                &mut pax,
                b"GNU.sparse.size",
                logical.len().to_string().as_bytes(),
            );
            pax_record(
                &mut pax,
                b"GNU.sparse.numblocks",
                sparse.ranges.len().to_string().as_bytes(),
            );
            match sparse.encoding {
                SparseEncoding::Pax00 => {
                    for &(offset, length) in &sparse.ranges {
                        pax_record(
                            &mut pax,
                            b"GNU.sparse.offset",
                            offset.to_string().as_bytes(),
                        );
                        pax_record(
                            &mut pax,
                            b"GNU.sparse.numbytes",
                            length.to_string().as_bytes(),
                        );
                    }
                }
                SparseEncoding::Pax01 => {
                    let map = sparse
                        .ranges
                        .iter()
                        .flat_map(|(offset, length)| [offset.to_string(), length.to_string()])
                        .collect::<Vec<_>>()
                        .join(",");
                    pax_record(&mut pax, b"GNU.sparse.map", map.as_bytes());
                }
                _ => unreachable!("selected PAX 0.x"),
            }
        }
        SparseEncoding::Pax10 => {
            pax_record(&mut pax, b"GNU.sparse.major", b"1");
            pax_record(&mut pax, b"GNU.sparse.minor", b"0");
            pax_record(
                &mut pax,
                b"GNU.sparse.realsize",
                logical.len().to_string().as_bytes(),
            );
            pax_record(&mut pax, b"GNU.sparse.name", &operation.path);
            let mut map = format!("{}\n", sparse.ranges.len()).into_bytes();
            for &(offset, length) in &sparse.ranges {
                map.extend_from_slice(format!("{offset}\n{length}\n").as_bytes());
            }
            map.resize(map.len().div_ceil(512) * 512, 0);
            map.extend_from_slice(&stored);
            stored = map;
        }
    }
    member(
        out,
        b"PaxHeaders/sparse",
        b'x',
        &[],
        &pax,
        &Stat::default(),
        (0, 0),
    );
    member(
        out,
        &operation.path,
        b'0',
        &[],
        &stored,
        &operation.stat,
        (0, 0),
    );
}
