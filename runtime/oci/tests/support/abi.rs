//! Independent fixed-schema byte expectations from the frozen Phase 2 ABI.
//! Inputs are fixture operations, not decoded production model records.
use std::collections::BTreeMap;

use base64::Engine;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::support::oracle::{bytes, hash, Action, Object, Operation};

pub struct ExpectedLayer {
    pub pack: Vec<u8>,
    pub root: Vec<u8>,
    pub objects: BTreeMap<String, Vec<u8>>,
    pub stream_record: Vec<u8>,
    pub stream: String,
    pub recipe_record: Vec<u8>,
    pub recipe: String,
    pub result_record: Vec<u8>,
    pub result: String,
}

pub fn domain(kind: &str, record: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(format!("silo:{kind}:v1\n"));
    digest.update(record);
    crate::support::oracle::digest_text(&digest.finalize())
}

fn encoded(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).expect("fixed fixture JSON")
}

/// The test-only identity writer intentionally does not call StreamMap or OCI.
pub fn stream_identity(pack: &[u8]) -> (Vec<u8>, String) {
    let chunks: Vec<_> = pack
        .chunks(8_388_608)
        .map(|chunk| {
            if chunk.iter().all(|byte| *byte == 0) {
                "zero".into()
            } else {
                hash(chunk)
            }
        })
        .collect();
    let record = encoded(
        &json!({"chunkSize":8388608,"chunks":chunks,"kind":"stream","length":pack.len(),"schema":1}),
    );
    let identity = domain("stream", &record);
    (record, identity)
}

pub fn stream_file_identity(path: &std::path::Path) -> (Vec<u8>, String) {
    use std::io::Read;
    let mut file = std::fs::File::open(path).expect("completed pack");
    let length = file.metadata().expect("pack metadata").len();
    let mut remaining = length;
    let mut buffer = vec![0_u8; 8_388_608];
    let mut chunks = Vec::<String>::new();
    while remaining != 0 {
        let count = remaining.min(buffer.len() as u64) as usize;
        file.read_exact(&mut buffer[..count])
            .expect("complete immutable pack chunk");
        chunks.push(if buffer[..count].iter().all(|byte| *byte == 0) {
            "zero".into()
        } else {
            hash(&buffer[..count])
        });
        remaining -= count as u64;
    }
    let mut suffix = [0_u8; 1];
    assert_eq!(file.read(&mut suffix).expect("pack EOF"), 0);
    let record = encoded(
        &json!({"chunkSize":8388608,"chunks":chunks,"kind":"stream","length":length,"schema":1}),
    );
    let identity = domain("stream", &record);
    (record, identity)
}

pub fn expected(operations: &[Operation], tar: &[u8]) -> ExpectedLayer {
    let mut pack = Vec::new();
    let mut entries = Vec::new();
    let mut objects = BTreeMap::new();
    for (ordinal, operation) in operations.iter().enumerate() {
        let path: Vec<u8> = operation
            .path
            .split(|b| *b == b'/')
            .filter(|p| !p.is_empty() && *p != b".")
            .collect::<Vec<_>>()
            .join(&b'/');
        let attrs = &operation.stat.xattrs;
        let mut access_acl = false;
        let mut default_acl = false;
        for attr in attrs {
            let name = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(&attr.name)
                .expect("declared raw attribute name");
            access_acl |= name == b"system.posix_acl_access";
            default_acl |= name == b"system.posix_acl_default";
        }
        let mut entry = json!({
            "metadata":{"gid":operation.stat.gid,"mode":operation.stat.mode,"mtimeNanos":operation.stat.mtime_nanos,"mtimeSeconds":operation.stat.mtime_seconds,"uid":operation.stat.uid,"xattrs":attrs},
            "ordinal":ordinal,"path":bytes(&path),
            "presence":{"aclAccess":access_acl,"aclDefault":default_acl,"gid":true,"mode":true,"mtime":true,"uid":true,"xattrs":!attrs.is_empty()}
        });
        let kind = match &operation.action {
            Action::Put(Object::Directory) if path.is_empty() => "root-directory",
            Action::Put(Object::Directory) => "directory",
            Action::Put(Object::File(body)) => {
                let mut sparse = Vec::new();
                if let Some(spec) = &operation.sparse {
                    let ranges: Vec<_> = spec
                        .ranges
                        .iter()
                        .map(|(offset, length)| json!({"length":length,"offset":offset}))
                        .collect();
                    for group in ranges.chunks(4096) {
                        let page = encoded(
                            &json!({"kind":"changeset-sparse-page","ranges":group,"schema":1}),
                        );
                        let digest = hash(&page);
                        sparse
                            .push(json!({"count":group.len(),"digest":digest,"length":page.len()}));
                        objects.insert(digest, page);
                    }
                }
                entry["body"] =
                    json!({"length":body.len(),"packOffset":pack.len(),"sparse":sparse});
                pack.extend_from_slice(body);
                pack.resize(pack.len().div_ceil(4096) * 4096, 0);
                "regular"
            }
            Action::Put(Object::Symlink(target)) => {
                entry["target"] = json!(bytes(target));
                "symlink"
            }
            Action::Link(target) => {
                entry["target"] = json!(bytes(target));
                "hardlink"
            }
            Action::Put(Object::Character(major, minor)) => {
                entry["deviceMajor"] = json!(major);
                entry["deviceMinor"] = json!(minor);
                "character-device"
            }
            Action::Put(Object::Block(major, minor)) => {
                entry["deviceMajor"] = json!(major);
                entry["deviceMinor"] = json!(minor);
                "block-device"
            }
            Action::Put(Object::Fifo) => "fifo",
            Action::Put(Object::Socket) => "socket",
            Action::Remove => "whiteout",
            Action::Opaque => "opaque",
        };
        entry["kind"] = json!(kind);
        entries.push(entry);
    }
    let entry_count = entries.len();
    let mut pages = Vec::new();
    let mut pending = Vec::<Vec<u8>>::new();
    let envelope = b"{\"entries\":[],\"kind\":\"changeset-entry-page\",\"schema\":1}".len();
    let mut page_bytes = envelope;
    for entry in entries {
        let record = encoded(&entry);
        if !pending.is_empty()
            && (pending.len() == 4096 || page_bytes + 1 + record.len() > 4_194_304)
        {
            save_page(&mut pending, &mut pages, &mut objects);
            page_bytes = envelope;
        }
        assert!(envelope + record.len() <= 4_194_304);
        page_bytes += record.len() + usize::from(!pending.is_empty());
        pending.push(record);
    }
    save_page(&mut pending, &mut pages, &mut objects);
    let root = encoded(
        &json!({"changesetAbi":"silo-changeset-v1","entries":entry_count,"kind":"changeset-index","packLength":pack.len(),"packProfile":"silo-payload-pack-v1","pages":pages,"schema":1}),
    );
    let (stream_record, stream) = stream_identity(&pack);
    let recipe_record = encoded(
        &json!({"changesetAbi":"silo-changeset-v1","diffId":hash(tar),"kind":"layer-recipe","packProfile":"silo-payload-pack-v1","schema":1}),
    );
    let recipe = domain("layer-recipe", &recipe_record);
    let result_record = encoded(
        &json!({"indexRoot":hash(&root),"kind":"layer-result","packLength":pack.len(),"packStream":stream,"recipe":recipe,"schema":1}),
    );
    let result = domain("layer-result", &result_record);
    ExpectedLayer {
        pack,
        root,
        objects,
        stream_record,
        stream,
        recipe_record,
        recipe,
        result_record,
        result,
    }
}

fn save_page(
    pending: &mut Vec<Vec<u8>>,
    pages: &mut Vec<Value>,
    objects: &mut BTreeMap<String, Vec<u8>>,
) {
    if pending.is_empty() {
        return;
    }
    let mut bytes = b"{\"entries\":[".to_vec();
    for (index, record) in pending.iter().enumerate() {
        if index != 0 {
            bytes.push(b',');
        }
        bytes.extend_from_slice(record);
    }
    bytes.extend_from_slice(b"],\"kind\":\"changeset-entry-page\",\"schema\":1}");
    let digest = hash(&bytes);
    pages.push(json!({"count":pending.len(),"digest":digest,"length":bytes.len()}));
    objects.insert(digest, bytes);
    pending.clear();
}
