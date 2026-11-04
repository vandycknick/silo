use std::collections::BTreeSet;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::changeset::limits::{bounded, JSON_SAFE_INTEGER_MAX, MAX_ROOT_BYTES};
use crate::changeset::{
    validate_layer, ChangeEntry, ChangesetError, ChangesetLimits, ChangesetResult, ContentDigest,
    EntryKind, LayerChangeset, LayerRecipeId, LayerResultId, Metadata, MetadataPresence,
    PayloadRef, SparseRange, Xattr,
};

pub const CHANGESET_ABI: &str = "silo-changeset-v1";
pub const PACK_PROFILE: &str = "silo-payload-pack-v1";
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexObject {
    pub digest: ContentDigest,
    pub bytes: Vec<u8>,
}
impl IndexObject {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            digest: ContentDigest::of_bytes(&bytes),
            bytes,
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedIndex {
    pub root: IndexObject,
    pub pages: Vec<IndexObject>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LayerRecipe {
    pub diff_id: ContentDigest,
}
impl LayerRecipe {
    pub fn canonical_bytes(&self) -> ChangesetResult<Vec<u8>> {
        canonical(
            &json!({"changesetAbi":CHANGESET_ABI,"diffId":self.diff_id,"kind":"layer-recipe","packProfile":PACK_PROFILE,"schema":1}),
        )
    }
    pub fn id(&self) -> ChangesetResult<LayerRecipeId> {
        Ok(LayerRecipeId::of_record(&self.canonical_bytes()?))
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LayerResult {
    pub recipe: LayerRecipeId,
    pub pack_stream: crate::changeset::StreamIdentity,
    pub pack_length: u64,
    pub index_root: ContentDigest,
}
impl LayerResult {
    pub fn canonical_bytes(&self) -> ChangesetResult<Vec<u8>> {
        bounded(
            "pack length",
            self.pack_length,
            crate::changeset::limits::FORMAT_LIMITS.max_pack_bytes,
        )?;
        if !self
            .pack_length
            .is_multiple_of(crate::changeset::limits::PACK_ALIGNMENT)
        {
            return Err(invalid("unaligned result pack length"));
        }
        canonical(
            &json!({"indexRoot":self.index_root,"kind":"layer-result","packLength":self.pack_length,"packStream":self.pack_stream,"recipe":self.recipe,"schema":1}),
        )
    }
    pub fn id(&self) -> ChangesetResult<LayerResultId> {
        Ok(LayerResultId::of_record(&self.canonical_bytes()?))
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Descriptor {
    count: u64,
    digest: ContentDigest,
    length: u64,
}

// A descriptor is below 160 bytes even at safe-integer widths. Keeping at most
// 256 at either bootstrap fits 64 KiB and keeps a regular entry bounded.
const TOP_DESCRIPTORS: usize = 256;
const MAX_DESCRIPTOR_DEPTH: u64 = 53; // ceil(log2(JSON_SAFE_INTEGER_MAX))
#[derive(Default)]
struct DescriptorTree {
    levels: Vec<(Vec<Descriptor>, usize)>,
}
fn descriptor_envelope() -> usize {
    b"{\"kind\":\"changeset-page-list\",\"pages\":[],\"schema\":1}".len()
}
fn descriptor_node(
    group: Vec<Descriptor>,
    sink: &mut impl FnMut(IndexObject) -> ChangesetResult<()>,
) -> ChangesetResult<Descriptor> {
    let count = group
        .iter()
        .try_fold(0u64, |sum, d| sum.checked_add(d.count))
        .ok_or_else(|| invalid("descriptor count overflow"))?;
    bounded("descriptor subtree count", count, JSON_SAFE_INTEGER_MAX)?;
    let object = IndexObject::new(canonical(
        &json!({"kind":"changeset-page-list","pages":group,"schema":1}),
    )?);
    let descriptor = Descriptor {
        count,
        digest: object.digest,
        length: object.bytes.len() as u64,
    };
    sink(object)?;
    Ok(descriptor)
}
impl DescriptorTree {
    fn push(
        &mut self,
        descriptor: Descriptor,
        limits: &ChangesetLimits,
        sink: &mut impl FnMut(IndexObject) -> ChangesetResult<()>,
    ) -> ChangesetResult<()> {
        self.push_at(0, descriptor, limits, sink)
    }
    fn push_at(
        &mut self,
        level: usize,
        descriptor: Descriptor,
        limits: &ChangesetLimits,
        sink: &mut impl FnMut(IndexObject) -> ChangesetResult<()>,
    ) -> ChangesetResult<()> {
        bounded("descriptor tree depth", level as u64, MAX_DESCRIPTOR_DEPTH)?;
        if self.levels.len() <= level {
            self.levels.push((Vec::new(), descriptor_envelope()));
        }
        let length = serde_json::to_vec(&descriptor)?.len();
        let (group, size) = &self.levels[level];
        if !group.is_empty()
            && (group.len() as u64 == limits.max_page_entries
                || *size + 1 + length > limits.max_page_bytes as usize)
        {
            if group.len() < 2 {
                return Err(invalid(
                    "configured descriptor page limits cannot represent a branching index",
                ));
            }
            let group = std::mem::take(&mut self.levels[level].0);
            self.levels[level].1 = descriptor_envelope();
            let parent = descriptor_node(group, sink)?;
            self.push_at(level + 1, parent, limits, sink)?;
        }
        let (group, size) = &mut self.levels[level];
        bounded(
            "descriptor page bytes",
            (*size + length + usize::from(!group.is_empty())) as u64,
            limits.max_page_bytes,
        )?;
        *size += length + usize::from(!group.is_empty());
        group.push(descriptor);
        Ok(())
    }
    fn finish(
        self,
        limits: &ChangesetLimits,
        sink: &mut impl FnMut(IndexObject) -> ChangesetResult<()>,
    ) -> ChangesetResult<Vec<Descriptor>> {
        let mut descriptors = self
            .levels
            .into_iter()
            .rev()
            .flat_map(|(group, _)| group)
            .collect::<Vec<_>>();
        while descriptors.len() > TOP_DESCRIPTORS {
            let mut next = Vec::new();
            let mut group = Vec::new();
            let mut size = descriptor_envelope();
            for descriptor in descriptors {
                let length = serde_json::to_vec(&descriptor)?.len();
                if !group.is_empty()
                    && (group.len() as u64 == limits.max_page_entries
                        || size + 1 + length > limits.max_page_bytes as usize)
                {
                    if group.len() < 2 {
                        return Err(invalid(
                            "configured descriptor limits cannot represent a branching index",
                        ));
                    }
                    next.push(descriptor_node(std::mem::take(&mut group), sink)?);
                    size = descriptor_envelope();
                }
                size += length + usize::from(!group.is_empty());
                group.push(descriptor);
            }
            if group.len() == 1 {
                next.extend(group);
            } else if !group.is_empty() {
                next.push(descriptor_node(group, sink)?);
            }
            descriptors = next;
        }
        Ok(descriptors)
    }
}
fn invalid(message: &str) -> ChangesetError {
    ChangesetError::Invalid(message.into())
}
fn canonical(value: &Value) -> ChangesetResult<Vec<u8>> {
    fn append(value: &Value, out: &mut Vec<u8>, depth: usize) -> ChangesetResult<()> {
        if depth > 128 {
            return Err(invalid("canonical record nesting exceeds closed schema"));
        }
        match value {
            Value::Object(object) => {
                // Every object in this closed ABI has at most seven ASCII keys.
                // Sorting explicitly keeps bytes independent of serde_json's
                // feature-unified map implementation, without a per-object heap.
                if object.len() > 7 {
                    return Err(invalid("unknown closed-schema object fields"));
                }
                let mut keys = [""; 7];
                for (slot, key) in keys.iter_mut().zip(object.keys()) {
                    if !key.is_ascii() {
                        return Err(invalid("non-ASCII closed-schema field"));
                    }
                    *slot = key;
                }
                let keys = &mut keys[..object.len()];
                keys.sort_unstable();
                out.push(b'{');
                for (index, key) in keys.iter().enumerate() {
                    if index != 0 {
                        out.push(b',');
                    }
                    serde_json::to_writer(&mut *out, key)?;
                    out.push(b':');
                    append(
                        object
                            .get(*key)
                            .ok_or_else(|| invalid("missing canonical field"))?,
                        out,
                        depth + 1,
                    )?;
                }
                out.push(b'}');
            }
            Value::Array(values) => {
                out.push(b'[');
                for (index, value) in values.iter().enumerate() {
                    if index != 0 {
                        out.push(b',');
                    }
                    append(value, out, depth + 1)?;
                }
                out.push(b']');
            }
            Value::Number(number) => {
                let number = number
                    .as_u64()
                    .ok_or_else(|| invalid("non-unsigned or floating identity integer"))?;
                bounded("JSON integer", number, JSON_SAFE_INTEGER_MAX)?;
                serde_json::to_writer(&mut *out, &number)?;
            }
            _ => serde_json::to_writer(&mut *out, value)?,
        }
        Ok(())
    }
    let mut out = Vec::new();
    append(value, &mut out, 0)?;
    Ok(out)
}
fn parse(bytes: &[u8]) -> ChangesetResult<Value> {
    let value: Value = serde_json::from_slice(bytes)?;
    if canonical(&value)? != bytes {
        return Err(invalid(
            "noncanonical JSON, duplicate keys or unsupported byte spelling",
        ));
    }
    Ok(value)
}
fn bytes(value: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(value)
}
fn raw(value: &Value, key: &str) -> ChangesetResult<Vec<u8>> {
    let encoded = text(value, key)?;
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| invalid("invalid unpadded base64url"))?;
    if bytes(&decoded) != encoded {
        return Err(invalid("noncanonical base64url"));
    }
    Ok(decoded)
}
fn text<'a>(v: &'a Value, key: &str) -> ChangesetResult<&'a str> {
    v.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("missing or non-string field"))
}
fn number(v: &Value, key: &str) -> ChangesetResult<u64> {
    let n = v
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid("missing or invalid integer"))?;
    bounded("JSON integer", n, JSON_SAFE_INTEGER_MAX)?;
    Ok(n)
}
fn array<'a>(v: &'a Value, key: &str) -> ChangesetResult<&'a Vec<Value>> {
    v.get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("missing or invalid array"))
}
fn shape(v: &Value, keys: &[&str]) -> ChangesetResult<()> {
    let object = v.as_object().ok_or_else(|| invalid("expected object"))?;
    if object.len() != keys.len() || keys.iter().any(|k| !object.contains_key(*k)) {
        return Err(invalid("unknown or missing index field"));
    }
    Ok(())
}
fn envelope(v: &Value, kind: &str, keys: &[&str]) -> ChangesetResult<()> {
    shape(v, keys)?;
    if number(v, "schema")? != 1 || text(v, "kind")? != kind {
        return Err(ChangesetError::Unsupported("schema or object kind".into()));
    }
    Ok(())
}
fn page_bytes(kind: &str, key: &str, records: &[Vec<u8>]) -> Vec<u8> {
    let mut out = format!("{{\"{key}\":[").into_bytes();
    // All page keys sort entries/kind/schema or kind/ranges/schema respectively.
    if key == "ranges" {
        out = format!("{{\"kind\":\"{kind}\",\"ranges\":[").into_bytes();
    }
    for (i, record) in records.iter().enumerate() {
        if i != 0 {
            out.push(b',');
        }
        out.extend_from_slice(record);
    }
    if key == "ranges" {
        out.extend_from_slice(b"],\"schema\":1}");
    } else {
        out.extend_from_slice(format!("],\"kind\":\"{kind}\",\"schema\":1}}").as_bytes());
    }
    out
}
fn emit_leaf_page(
    kind: &str,
    key: &str,
    pending: &mut Vec<Vec<u8>>,
    descriptors: &mut DescriptorTree,
    limits: &ChangesetLimits,
    sink: &mut impl FnMut(IndexObject) -> ChangesetResult<()>,
) -> ChangesetResult<()> {
    if pending.is_empty() {
        return Ok(());
    }
    let object = IndexObject::new(page_bytes(kind, key, pending));
    let descriptor = Descriptor {
        count: pending.len() as u64,
        digest: object.digest,
        length: object.bytes.len() as u64,
    };
    sink(object)?;
    descriptors.push(descriptor, limits, sink)?;
    pending.clear();
    Ok(())
}
fn split_pages(
    kind: &str,
    key: &str,
    records: impl IntoIterator<Item = ChangesetResult<Vec<u8>>>,
    limits: &ChangesetLimits,
    sink: &mut impl FnMut(IndexObject) -> ChangesetResult<()>,
) -> ChangesetResult<Vec<Descriptor>> {
    let envelope = page_bytes(kind, key, &[]).len();
    let mut pending = Vec::new();
    let mut size = envelope;
    let mut descriptors = DescriptorTree::default();
    for record in records {
        let record = record?;
        let added = record.len() + usize::from(!pending.is_empty());
        if !pending.is_empty()
            && (pending.len() as u64 == limits.max_page_entries
                || size + added > limits.max_page_bytes as usize)
        {
            emit_leaf_page(kind, key, &mut pending, &mut descriptors, limits, sink)?;
            size = envelope;
        }
        bounded(
            "index record bytes",
            (envelope + record.len()) as u64,
            limits.max_page_bytes,
        )?;
        size += record.len() + usize::from(!pending.is_empty());
        pending.push(record);
    }
    emit_leaf_page(kind, key, &mut pending, &mut descriptors, limits, sink)?;
    descriptors.finish(limits, sink)
}
fn entry_value(entry: &ChangeEntry, sparse: Vec<Descriptor>) -> Value {
    let kind = match entry.kind {
        EntryKind::RootDirectory => "root-directory",
        EntryKind::Directory => "directory",
        EntryKind::Regular(_) => "regular",
        EntryKind::Symlink { .. } => "symlink",
        EntryKind::Hardlink { .. } => "hardlink",
        EntryKind::CharacterDevice { .. } => "character-device",
        EntryKind::BlockDevice { .. } => "block-device",
        EntryKind::Fifo => "fifo",
        EntryKind::Socket => "socket",
        EntryKind::Whiteout => "whiteout",
        EntryKind::Opaque => "opaque",
    };
    let mut value = json!({"kind":kind,"metadata":{"gid":entry.metadata.gid,"mode":entry.metadata.mode,"mtimeNanos":entry.metadata.mtime_nanos,"mtimeSeconds":entry.metadata.mtime_seconds,"uid":entry.metadata.uid,"xattrs":entry.metadata.xattrs.iter().map(|x|json!({"name":bytes(&x.name),"value":bytes(&x.value)})).collect::<Vec<_>>()},"ordinal":entry.ordinal,"path":bytes(&entry.path),"presence":entry.presence});
    match &entry.kind {
        EntryKind::Regular(body) => {
            value["body"] =
                json!({"length":body.length,"packOffset":body.pack_offset,"sparse":sparse})
        }
        EntryKind::Symlink { target } | EntryKind::Hardlink { target } => {
            value["target"] = json!(bytes(target))
        }
        EntryKind::CharacterDevice { major, minor } | EntryKind::BlockDevice { major, minor } => {
            value["deviceMajor"] = json!(major);
            value["deviceMinor"] = json!(minor);
        }
        _ => {}
    }
    value
}
/// Stream immutable pages to a bounded sink; only the small root is retained here.
pub fn encode_index_to(
    layer: &LayerChangeset,
    limits: &ChangesetLimits,
    mut sink: impl FnMut(IndexObject) -> ChangesetResult<()>,
) -> ChangesetResult<IndexObject> {
    validate_layer(layer, limits)?;
    // Entries are encoded one at a time, and pages are flushed at the first bound.
    let mut entries = Vec::new();
    let envelope = page_bytes("changeset-entry-page", "entries", &[]).len();
    let mut size = envelope;
    let mut descriptors = DescriptorTree::default();
    for entry in &layer.entries {
        let sparse = if let EntryKind::Regular(body) = &entry.kind {
            split_pages(
                "changeset-sparse-page",
                "ranges",
                body.sparse
                    .iter()
                    .map(|r| canonical(&json!({"length":r.length,"offset":r.offset}))),
                limits,
                &mut sink,
            )?
        } else {
            Vec::new()
        };
        let record = canonical(&entry_value(entry, sparse))?;
        if !entries.is_empty()
            && (entries.len() as u64 == limits.max_page_entries
                || size + 1 + record.len() > limits.max_page_bytes as usize)
        {
            emit_leaf_page(
                "changeset-entry-page",
                "entries",
                &mut entries,
                &mut descriptors,
                limits,
                &mut sink,
            )?;
            size = envelope;
        }
        bounded(
            "index record bytes",
            (envelope + record.len()) as u64,
            limits.max_page_bytes,
        )?;
        size += record.len() + usize::from(!entries.is_empty());
        entries.push(record);
    }
    emit_leaf_page(
        "changeset-entry-page",
        "entries",
        &mut entries,
        &mut descriptors,
        limits,
        &mut sink,
    )?;
    let descriptors = descriptors.finish(limits, &mut sink)?;
    let root = IndexObject::new(canonical(
        &json!({"changesetAbi":CHANGESET_ABI,"entries":layer.entries.len(),"kind":"changeset-index","packLength":layer.pack_length,"packProfile":PACK_PROFILE,"pages":descriptors,"schema":1}),
    )?);
    bounded("index root bytes", root.bytes.len() as u64, MAX_ROOT_BYTES)?;
    Ok(root)
}
pub fn encode_index(
    layer: &LayerChangeset,
    limits: &ChangesetLimits,
) -> ChangesetResult<EncodedIndex> {
    let mut pages = Vec::new();
    let mut seen = BTreeSet::new();
    let root = encode_index_to(layer, limits, |object| {
        if seen.insert(object.digest) {
            pages.push(object);
        }
        Ok(())
    })?;
    Ok(EncodedIndex { root, pages })
}
fn visit_pages<R: FnMut(ContentDigest) -> ChangesetResult<Vec<u8>>>(
    desc: &Descriptor,
    page: (&str, &str),
    limits: &ChangesetLimits,
    read: &mut R,
    active: &mut BTreeSet<ContentDigest>,
    depth: u64,
    visit: &mut impl FnMut(&Value, &mut R) -> ChangesetResult<()>,
) -> ChangesetResult<()> {
    let (kind, key) = page;
    bounded("descriptor tree depth", depth, MAX_DESCRIPTOR_DEPTH)?;
    bounded("index page bytes", desc.length, limits.max_page_bytes)?;
    bounded(
        "descriptor subtree count",
        desc.count,
        JSON_SAFE_INTEGER_MAX,
    )?;
    if desc.count == 0 || !active.insert(desc.digest) {
        return Err(invalid("empty or cyclic index page"));
    }
    let bytes = read(desc.digest)?;
    if bytes.len() as u64 != desc.length || ContentDigest::of_bytes(&bytes) != desc.digest {
        return Err(invalid("index page digest or length mismatch"));
    }
    let value = parse(&bytes)?;
    if text(&value, "kind")? == "changeset-page-list" {
        envelope(&value, "changeset-page-list", &["kind", "pages", "schema"])?;
        let pages = array(&value, "pages")?;
        bounded(
            "descriptor page entries",
            pages.len() as u64,
            limits.max_page_entries,
        )?;
        if pages.len() < 2 {
            return Err(invalid("nonbranching descriptor node"));
        }
        let mut count = 0u64;
        for child in pages {
            let child: Descriptor = serde_json::from_value(child.clone())?;
            count = count
                .checked_add(child.count)
                .ok_or_else(|| invalid("descriptor count overflow"))?;
            bounded("descriptor subtree count", count, desc.count)?;
            visit_pages(&child, page, limits, read, active, depth + 1, visit)?;
        }
        if count != desc.count {
            return Err(invalid("descriptor node count mismatch"));
        }
    } else {
        envelope(&value, kind, &[key, "kind", "schema"])?;
        bounded("index page entries", desc.count, limits.max_page_entries)?;
        if array(&value, key)?.len() as u64 != desc.count {
            return Err(invalid("index page count mismatch"));
        }
        for record in array(&value, key)? {
            visit(record, read)?;
        }
    }
    active.remove(&desc.digest);
    Ok(())
}
fn decode_entry(
    value: &Value,
    limits: &ChangesetLimits,
    pack_length: u64,
    read: &mut impl FnMut(ContentDigest) -> ChangesetResult<Vec<u8>>,
) -> ChangesetResult<ChangeEntry> {
    let kind = text(value, "kind")?;
    let mut keys = vec!["kind", "metadata", "ordinal", "path", "presence"];
    let kind = match kind {
        "regular" => {
            keys.push("body");
            let body = &value["body"];
            shape(body, &["length", "packOffset", "sparse"])?;
            let length = number(body, "length")?;
            bounded("regular file bytes", length, limits.max_file_bytes)?;
            let pack_offset = number(body, "packOffset")?;
            let end = pack_offset
                .checked_add(crate::changeset::limits::aligned(length)?)
                .ok_or_else(|| invalid("body extent overflow"))?;
            if !pack_offset.is_multiple_of(crate::changeset::limits::PACK_ALIGNMENT)
                || end > pack_length
            {
                return Err(invalid("body extent is unaligned or outside pack"));
            }
            let maximum_ranges = limits.max_sparse_ranges.min(
                length
                    .checked_add(1)
                    .ok_or_else(|| invalid("body range-count overflow"))?,
            );
            let mut validation = crate::changeset::pack::SparseValidation::new(length);
            let mut sparse = Vec::new();
            bounded(
                "sparse top descriptors",
                array(body, "sparse")?.len() as u64,
                TOP_DESCRIPTORS as u64,
            )?;
            for descriptor in array(body, "sparse")? {
                let descriptor: Descriptor = serde_json::from_value(descriptor.clone())?;
                let total = (sparse.len() as u64)
                    .checked_add(descriptor.count)
                    .ok_or_else(|| invalid("sparse count overflow"))?;
                bounded("sparse ranges for body", total, maximum_ranges)?;
                visit_pages(
                    &descriptor,
                    ("changeset-sparse-page", "ranges"),
                    limits,
                    read,
                    &mut BTreeSet::new(),
                    0,
                    &mut |range, _| {
                        shape(range, &["length", "offset"])?;
                        let range = SparseRange {
                            offset: number(range, "offset")?,
                            length: number(range, "length")?,
                        };
                        validation.push(&range)?;
                        crate::changeset::limits::reserve_vec(&mut sparse, 1)?;
                        sparse.push(range);
                        Ok(())
                    },
                )?;
            }
            EntryKind::Regular(PayloadRef {
                pack_offset,
                length,
                sparse,
            })
        }
        "root-directory" => EntryKind::RootDirectory,
        "directory" => EntryKind::Directory,
        "symlink" => {
            keys.push("target");
            EntryKind::Symlink {
                target: raw(value, "target")?,
            }
        }
        "hardlink" => {
            keys.push("target");
            EntryKind::Hardlink {
                target: raw(value, "target")?,
            }
        }
        "character-device" | "block-device" => {
            keys.extend(["deviceMajor", "deviceMinor"]);
            let major = u32::try_from(number(value, "deviceMajor")?)
                .map_err(|_| invalid("device major overflow"))?;
            let minor = u32::try_from(number(value, "deviceMinor")?)
                .map_err(|_| invalid("device minor overflow"))?;
            if kind == "character-device" {
                EntryKind::CharacterDevice { major, minor }
            } else {
                EntryKind::BlockDevice { major, minor }
            }
        }
        "fifo" => EntryKind::Fifo,
        "socket" => EntryKind::Socket,
        "whiteout" => EntryKind::Whiteout,
        "opaque" => EntryKind::Opaque,
        _ => return Err(ChangesetError::Unsupported("entry kind".into())),
    };
    shape(value, &keys)?;
    let m = &value["metadata"];
    shape(
        m,
        &["gid", "mode", "mtimeNanos", "mtimeSeconds", "uid", "xattrs"],
    )?;
    let mut xattrs = Vec::new();
    bounded(
        "xattrs",
        array(m, "xattrs")?.len() as u64,
        limits.max_xattrs,
    )?;
    for x in array(m, "xattrs")? {
        shape(x, &["name", "value"])?;
        xattrs.push(Xattr {
            name: raw(x, "name")?,
            value: raw(x, "value")?,
        });
    }
    let u32field =
        |key| u32::try_from(number(m, key)?).map_err(|_| invalid("metadata integer overflow"));
    Ok(ChangeEntry {
        ordinal: number(value, "ordinal")?,
        path: raw(value, "path")?,
        presence: serde_json::from_value::<MetadataPresence>(value["presence"].clone())?,
        metadata: Metadata {
            uid: u32field("uid")?,
            gid: u32field("gid")?,
            mode: u32field("mode")?,
            mtime_seconds: number(m, "mtimeSeconds")?,
            mtime_nanos: u32field("mtimeNanos")?,
            xattrs,
        },
        kind,
    })
}
pub fn decode_index(
    root_bytes: &[u8],
    mut read_object: impl FnMut(ContentDigest) -> ChangesetResult<Vec<u8>>,
    diff_id: ContentDigest,
    limits: &ChangesetLimits,
) -> ChangesetResult<LayerChangeset> {
    limits.validate()?;
    bounded("index root bytes", root_bytes.len() as u64, MAX_ROOT_BYTES)?;
    let root = parse(root_bytes)?;
    envelope(
        &root,
        "changeset-index",
        &[
            "changesetAbi",
            "entries",
            "kind",
            "packLength",
            "packProfile",
            "pages",
            "schema",
        ],
    )?;
    if text(&root, "changesetAbi")? != CHANGESET_ABI || text(&root, "packProfile")? != PACK_PROFILE
    {
        return Err(ChangesetError::Unsupported(
            "changeset ABI or pack profile".into(),
        ));
    }
    let count = number(&root, "entries")?;
    bounded("layer entries", count, limits.max_entries)?;
    let pack_length = number(&root, "packLength")?;
    bounded("pack bytes", pack_length, limits.max_pack_bytes)?;
    if !pack_length.is_multiple_of(crate::changeset::limits::PACK_ALIGNMENT) {
        return Err(invalid("unaligned index pack length"));
    }
    let mut entries = Vec::new();
    bounded(
        "index top descriptors",
        array(&root, "pages")?.len() as u64,
        TOP_DESCRIPTORS as u64,
    )?;
    for descriptor in array(&root, "pages")? {
        let descriptor: Descriptor = serde_json::from_value(descriptor.clone())?;
        let total = (entries.len() as u64)
            .checked_add(descriptor.count)
            .ok_or_else(|| invalid("entry count overflow"))?;
        bounded("layer entries", total, count)?;
        visit_pages(
            &descriptor,
            ("changeset-entry-page", "entries"),
            limits,
            &mut read_object,
            &mut BTreeSet::new(),
            0,
            &mut |entry, read| {
                crate::changeset::limits::reserve_vec(&mut entries, 1)?;
                entries.push(decode_entry(entry, limits, pack_length, read)?);
                Ok(())
            },
        )?;
    }
    if entries.len() as u64 != count {
        return Err(invalid("index root entry count mismatch"));
    }
    let layer = LayerChangeset {
        diff_id,
        pack_length,
        entries,
    };
    validate_layer(&layer, limits)?;
    // Regenerated root descriptors recursively commit every canonical page.
    // Initial traversal already authenticated the input pages; comparing this
    // root avoids fetching nonexistent *alternative* partition objects.
    let regenerated = encode_index_to(&layer, limits, |_object| Ok(()))?;
    if regenerated.bytes != root_bytes {
        return Err(invalid("noncanonical page partition"));
    }
    Ok(layer)
}

#[cfg(test)]
mod tests {
    use crate::changeset::index::{decode_index, encode_index, LayerRecipe, LayerResult};
    use crate::changeset::{
        ChangeEntry, ChangesetLimits, ContentDigest, EntryKind, LayerChangeset, Metadata,
        MetadataPresence, PayloadRef, SparseRange,
    };
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;

    fn hash_spelling(hash: impl AsRef<[u8]>) -> String {
        use std::fmt::Write as _;
        let mut text = String::from("sha256:");
        for byte in hash.as_ref() {
            write!(&mut text, "{byte:02x}").unwrap();
        }
        text
    }

    fn entry(ordinal: u64) -> ChangeEntry {
        ChangeEntry {
            ordinal,
            path: format!("f{ordinal:06}").into_bytes(),
            metadata: Metadata {
                uid: 0,
                gid: 0,
                mode: 420,
                mtime_seconds: 0,
                mtime_nanos: 0,
                xattrs: vec![],
            },
            presence: MetadataPresence::default(),
            kind: EntryKind::Regular(PayloadRef {
                pack_offset: 0,
                length: 0,
                sparse: vec![],
            }),
        }
    }
    fn layer(count: u64) -> LayerChangeset {
        LayerChangeset {
            diff_id: ContentDigest::of_bytes(b"fixture tar"),
            pack_length: 0,
            entries: (0..count).map(entry).collect(),
        }
    }
    fn decode(
        encoded: &crate::changeset::index::EncodedIndex,
        diff: ContentDigest,
        limits: &ChangesetLimits,
    ) -> crate::changeset::ChangesetResult<LayerChangeset> {
        let pages = encoded
            .pages
            .iter()
            .map(|p| (p.digest, p.bytes.clone()))
            .collect::<BTreeMap<_, _>>();
        decode_index(
            &encoded.root.bytes,
            |d| {
                pages.get(&d).cloned().ok_or_else(|| {
                    crate::changeset::ChangesetError::Invalid("missing test page".into())
                })
            },
            diff,
            limits,
        )
    }
    #[test]
    fn exact_empty_root_and_independently_domain_separated_identities() {
        let layer = layer(0);
        let encoded = encode_index(&layer, &ChangesetLimits::default()).unwrap();
        assert_eq!(encoded.root.bytes,br#"{"changesetAbi":"silo-changeset-v1","entries":0,"kind":"changeset-index","packLength":0,"packProfile":"silo-payload-pack-v1","pages":[],"schema":1}"#);
        assert!(encoded.pages.is_empty());
        let recipe = LayerRecipe {
            diff_id: layer.diff_id,
        };
        let expected = format!(
            r#"{{"changesetAbi":"silo-changeset-v1","diffId":"{}","kind":"layer-recipe","packProfile":"silo-payload-pack-v1","schema":1}}"#,
            layer.diff_id
        );
        assert_eq!(recipe.canonical_bytes().unwrap(), expected.as_bytes());
        let mut hash = Sha256::new();
        hash.update(b"silo:layer-recipe:v1\n");
        hash.update(expected.as_bytes());
        assert_eq!(
            recipe.id().unwrap().to_string(),
            hash_spelling(hash.finalize())
        );
        assert_ne!(
            recipe.id().unwrap().to_string(),
            ContentDigest::of_bytes(expected.as_bytes()).to_string()
        );
        let stream_record =
            br#"{"chunkSize":8388608,"chunks":[],"kind":"stream","length":0,"schema":1}"#;
        let mut stream_hash = Sha256::new();
        stream_hash.update(b"silo:stream:v1\n");
        stream_hash.update(stream_record);
        let stream = hash_spelling(stream_hash.finalize());
        assert_ne!(stream, ContentDigest::of_bytes(b"").to_string());
        let result = LayerResult {
            recipe: recipe.id().unwrap(),
            pack_stream: stream.parse().unwrap(),
            pack_length: 0,
            index_root: encoded.root.digest,
        };
        let expected = format!(
            r#"{{"indexRoot":"{}","kind":"layer-result","packLength":0,"packStream":"{}","recipe":"{}","schema":1}}"#,
            result.index_root, result.pack_stream, result.recipe
        );
        assert_eq!(result.canonical_bytes().unwrap(), expected.as_bytes());
        let mut hash = Sha256::new();
        hash.update(b"silo:layer-result:v1\n");
        hash.update(expected.as_bytes());
        assert_eq!(
            result.id().unwrap().to_string(),
            hash_spelling(hash.finalize())
        );
    }
    #[test]
    fn greedy_pages_include_envelope_and_split_at_4096_entries() {
        let l = layer(4097);
        let limits = ChangesetLimits::default();
        let encoded = encode_index(&l, &limits).unwrap();
        let root: serde_json::Value = serde_json::from_slice(&encoded.root.bytes).unwrap();
        assert_eq!(root["pages"][0]["count"], 4096);
        assert_eq!(root["pages"][1]["count"], 1);
        assert_eq!(decode(&encoded, l.diff_id, &limits).unwrap(), l);
        let one = encode_index(&layer(1), &limits).unwrap();
        let size = one.pages[0].bytes.len() as u64;
        let tight = ChangesetLimits {
            max_page_bytes: size,
            ..limits
        };
        let two = encode_index(&layer(2), &tight).unwrap();
        assert_eq!(two.pages.len(), 2);
        let too_tight = ChangesetLimits {
            max_page_bytes: size - 1,
            ..limits
        };
        assert!(encode_index(&layer(1), &too_tight).is_err());
    }
    #[test]
    fn sparse_continuations_roundtrip_and_body_extents_are_authenticated() {
        let mut l = layer(1);
        l.pack_length = 4096;
        l.entries[0].kind = EntryKind::Regular(PayloadRef {
            pack_offset: 0,
            length: 7,
            sparse: vec![
                SparseRange {
                    offset: 0,
                    length: 1,
                },
                SparseRange {
                    offset: 2,
                    length: 1,
                },
                SparseRange {
                    offset: 6,
                    length: 1,
                },
            ],
        });
        let limits = ChangesetLimits {
            max_page_entries: 2,
            ..ChangesetLimits::default()
        };
        let encoded = encode_index(&l, &limits).unwrap();
        assert_eq!(encoded.pages.len(), 3);
        assert_eq!(decode(&encoded, l.diff_id, &limits).unwrap(), l);
        let mut damaged = encoded.clone();
        damaged.pages[0].bytes.push(b' ');
        assert!(decode(&damaged, l.diff_id, &limits).is_err());
        let mut bad_extent = encoded.clone();
        let entry_page = bad_extent.pages.last_mut().unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(&entry_page.bytes).unwrap();
        value["entries"][0]["body"]["packOffset"] = json!(4096);
        entry_page.bytes = serde_json::to_vec(&value).unwrap();
        entry_page.digest = ContentDigest::of_bytes(&entry_page.bytes);
        let mut root: serde_json::Value = serde_json::from_slice(&bad_extent.root.bytes).unwrap();
        root["pages"][0]["digest"] = json!(entry_page.digest);
        root["pages"][0]["length"] = json!(entry_page.bytes.len());
        bad_extent.root.bytes = serde_json::to_vec(&root).unwrap();
        assert!(decode(&bad_extent, l.diff_id, &limits).is_err());
        let EntryKind::Regular(body) = &mut l.entries[0].kind else {
            panic!("regular")
        };
        body.pack_offset = 4096;
        assert!(encode_index(&l, &limits).is_err());
    }
    #[test]
    fn rejects_unknown_fields_kinds_unsafe_numbers_and_noncanonical_json() {
        let limits = ChangesetLimits::default();
        let l = layer(0);
        let encoded = encode_index(&l, &limits).unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(&encoded.root.bytes).unwrap();
        value["unexpected"] = json!(1);
        assert!(decode_index(
            &serde_json::to_vec(&value).unwrap(),
            |_| unreachable!(),
            l.diff_id,
            &limits
        )
        .is_err());
        value.as_object_mut().unwrap().remove("unexpected");
        value["kind"] = json!("future-index");
        assert!(decode_index(
            &serde_json::to_vec(&value).unwrap(),
            |_| unreachable!(),
            l.diff_id,
            &limits
        )
        .is_err());
        value["kind"] = json!("changeset-index");
        value["entries"] = json!(9_007_199_254_740_992_u64);
        assert!(decode_index(
            &serde_json::to_vec(&value).unwrap(),
            |_| unreachable!(),
            l.diff_id,
            &limits
        )
        .is_err());
        let mut newline = encoded.root.bytes;
        newline.push(b'\n');
        assert!(decode_index(&newline, |_| unreachable!(), l.diff_id, &limits).is_err());
        assert!(ChangesetLimits {
            max_entries: 1_000_001,
            ..limits
        }
        .validate()
        .is_err());
    }
    #[test]
    fn real_four_mib_boundary_is_greedy_and_unknown_entry_fields_fail() {
        let limits = ChangesetLimits::default();
        let mut l = layer(500);
        for entry in &mut l.entries {
            let mut path = Vec::new();
            for _ in 0..15 {
                path.extend(std::iter::repeat_n(b'p', 255));
                path.push(b'/');
            }
            path.extend_from_slice(&entry.path);
            entry.path = path;
            entry.kind = EntryKind::Symlink {
                target: vec![b'x'; 4096],
            };
        }
        let encoded = encode_index(&l, &limits).unwrap();
        assert!(encoded.pages.len() > 1);
        let first: serde_json::Value = serde_json::from_slice(&encoded.pages[0].bytes).unwrap();
        let second: serde_json::Value = serde_json::from_slice(&encoded.pages[1].bytes).unwrap();
        assert!(encoded.pages[0].bytes.len() <= 4_194_304);
        let next = serde_json::to_vec(&second["entries"][0]).unwrap();
        assert!(encoded.pages[0].bytes.len() + 1 + next.len() > 4_194_304);
        assert_eq!(
            first["entries"].as_array().unwrap().len()
                + second["entries"].as_array().unwrap().len(),
            500
        );
        let mut small = encode_index(&layer(1), &limits).unwrap();
        let mut page: serde_json::Value = serde_json::from_slice(&small.pages[0].bytes).unwrap();
        page["entries"][0]["unexpected"] = json!(true);
        small.pages[0].bytes = serde_json::to_vec(&page).unwrap();
        small.pages[0].digest = ContentDigest::of_bytes(&small.pages[0].bytes);
        let mut root: serde_json::Value = serde_json::from_slice(&small.root.bytes).unwrap();
        root["pages"][0]["digest"] = json!(small.pages[0].digest);
        root["pages"][0]["length"] = json!(small.pages[0].bytes.len());
        small.root.bytes = serde_json::to_vec(&root).unwrap();
        assert!(decode(&small, l.diff_id, &limits).is_err());
    }
    #[test]
    fn indirect_entry_and_sparse_nodes_preserve_order_and_reject_false_counts() {
        let limits = ChangesetLimits {
            max_page_entries: 2,
            ..ChangesetLimits::default()
        };
        let flat = encode_index(&layer(4), &limits).unwrap();
        assert!(!flat
            .pages
            .iter()
            .any(
                |p| serde_json::from_slice::<serde_json::Value>(&p.bytes).unwrap()["kind"]
                    == "changeset-page-list"
            ));
        let l = layer(5);
        let indirect = encode_index(&l, &limits).unwrap();
        assert!(indirect
            .pages
            .iter()
            .any(
                |p| serde_json::from_slice::<serde_json::Value>(&p.bytes).unwrap()["kind"]
                    == "changeset-page-list"
            ));
        assert_eq!(decode(&indirect, l.diff_id, &limits).unwrap(), l);
        let mut l = layer(1);
        l.pack_length = 4096;
        l.entries[0].kind = EntryKind::Regular(PayloadRef {
            pack_offset: 0,
            length: 11,
            sparse: (0..6)
                .map(|n| SparseRange {
                    offset: n * 2,
                    length: 1,
                })
                .collect(),
        });
        let indirect = encode_index(&l, &limits).unwrap();
        assert_eq!(decode(&indirect, l.diff_id, &limits).unwrap(), l);
        let mut broken = encode_index(&layer(5), &limits).unwrap();
        let mut root: serde_json::Value = serde_json::from_slice(&broken.root.bytes).unwrap();
        root["pages"][0]["count"] = json!(1);
        broken.root.bytes = serde_json::to_vec(&root).unwrap();
        assert!(decode(&broken, l.diff_id, &limits).is_err());
    }

    fn expected_bytes(mut value: serde_json::Value) -> Vec<u8> {
        value.sort_all_objects();
        serde_json::to_vec(&value).unwrap()
    }
    fn expected_object(bytes: Vec<u8>) -> crate::changeset::IndexObject {
        let digest = hash_spelling(Sha256::digest(&bytes)).parse().unwrap();
        crate::changeset::IndexObject { digest, bytes }
    }
    fn descriptor(object: &crate::changeset::IndexObject, count: u64) -> serde_json::Value {
        json!({"count":count,"digest":object.digest,"length":object.bytes.len()})
    }
    fn wire_entry() -> serde_json::Value {
        json!({"body":{"length":0,"packOffset":0,"sparse":[]},"kind":"regular","metadata":{"gid":0,"mode":420,"mtimeNanos":0,"mtimeSeconds":0,"uid":0,"xattrs":[]},"ordinal":0,"path":"YQ","presence":{"aclAccess":false,"aclDefault":false,"gid":false,"mode":false,"mtime":false,"uid":false,"xattrs":false}})
    }
    fn wire_root(count: u64, pack: u64, pages: Vec<serde_json::Value>) -> Vec<u8> {
        expected_bytes(
            json!({"changesetAbi":"silo-changeset-v1","entries":count,"kind":"changeset-index","packLength":pack,"packProfile":"silo-payload-pack-v1","pages":pages,"schema":1}),
        )
    }
    fn wire_index(
        entry: serde_json::Value,
        pack: u64,
        mut pages: Vec<crate::changeset::IndexObject>,
    ) -> crate::changeset::EncodedIndex {
        let page = expected_object(expected_bytes(
            json!({"entries":[entry],"kind":"changeset-entry-page","schema":1}),
        ));
        let root = expected_object(wire_root(1, pack, vec![descriptor(&page, 1)]));
        pages.push(page);
        crate::changeset::EncodedIndex { root, pages }
    }
    fn acl() -> Vec<u8> {
        let mut bytes = 2u32.to_le_bytes().to_vec();
        for (tag, permissions) in [(1u16, 6u16), (4, 4), (32, 4)] {
            bytes.extend_from_slice(&tag.to_le_bytes());
            bytes.extend_from_slice(&permissions.to_le_bytes());
            bytes.extend_from_slice(&u32::MAX.to_le_bytes());
        }
        bytes
    }
    #[test]
    fn hardlink_presence_is_category_specific_and_never_hides_supplied_assertions() {
        use crate::changeset::{validate_layer, Xattr};
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine as _;
        let limits = ChangesetLimits::default();
        for (name, presence) in [
            (
                b"user.example".as_slice(),
                json!({"aclAccess":false,"aclDefault":false,"gid":false,"mode":false,"mtime":false,"uid":false,"xattrs":false}),
            ),
            (
                b"system.posix_acl_access".as_slice(),
                json!({"aclAccess":false,"aclDefault":false,"gid":false,"mode":false,"mtime":false,"uid":false,"xattrs":true}),
            ),
        ] {
            let value = if name.starts_with(b"system.") {
                acl()
            } else {
                b"new".to_vec()
            };
            let mut l = layer(1);
            l.entries[0].kind = EntryKind::Hardlink {
                target: b"a".to_vec(),
            };
            l.entries[0].path = b"b".to_vec();
            l.entries[0].metadata.xattrs = vec![Xattr {
                name: name.to_vec(),
                value: value.clone(),
            }];
            l.entries[0].presence = serde_json::from_value(presence.clone()).unwrap();
            assert!(validate_layer(&l, &limits).is_err());
            let mut wire = wire_entry();
            wire.as_object_mut().unwrap().remove("body");
            wire["kind"] = json!("hardlink");
            wire["target"] = json!("YQ");
            wire["path"] = json!("Yg");
            wire["presence"] = presence;
            wire["metadata"]["xattrs"] = json!([{"name":URL_SAFE_NO_PAD.encode(name),"value":URL_SAFE_NO_PAD.encode(value)}]);
            assert!(decode(&wire_index(wire, 0, vec![]), l.diff_id, &limits).is_err());
        }
        for flag in ["aclAccess", "aclDefault"] {
            let mut l = layer(1);
            l.entries[0].path = b"b".to_vec();
            l.entries[0].kind = EntryKind::Hardlink {
                target: b"a".to_vec(),
            };
            if flag == "aclAccess" {
                l.entries[0].presence.acl_access = true;
            } else {
                l.entries[0].presence.acl_default = true;
            }
            assert!(encode_index(&l, &limits).is_err());
            let mut wire = wire_entry();
            wire.as_object_mut().unwrap().remove("body");
            wire["kind"] = json!("hardlink");
            wire["target"] = json!("YQ");
            wire["path"] = json!("Yg");
            wire["presence"][flag] = json!(true);
            assert!(decode(&wire_index(wire, 0, vec![]), layer(0).diff_id, &limits).is_err());
        }
        let mut lower = layer(1);
        lower.entries[0].path = b"a".to_vec();
        lower.entries[0].metadata.xattrs = vec![Xattr {
            name: b"system.posix_acl_access".to_vec(),
            value: acl(),
        }];
        let mut upper = layer(1);
        upper.entries[0].path = b"b".to_vec();
        upper.entries[0].kind = EntryKind::Hardlink {
            target: b"a".to_vec(),
        };
        upper.entries[0].metadata.mode = 0o777;
        upper.entries[0].metadata.xattrs = lower.entries[0].metadata.xattrs.clone();
        upper.entries[0].presence.acl_access = true;
        // Textual ACL presence does not require generic xattr presence, and
        // advisory hardlink mode does not alter or invalidate matching ACLs.
        let tree = crate::changeset::namespace::compose(&[&lower, &upper], &limits).unwrap();
        assert_eq!(tree.inode_at(b"b").unwrap().metadata.mode, 0o644);
        upper.entries[0].metadata.xattrs.clear();
        upper.entries[0].presence.acl_access = false;
        assert!(crate::changeset::namespace::compose(&[&lower, &upper], &limits).is_ok());
        lower.entries[0].metadata.xattrs = vec![Xattr {
            name: b"user.example".to_vec(),
            value: b"old".to_vec(),
        }];
        upper.entries[0].metadata.xattrs = vec![Xattr {
            name: b"user.example".to_vec(),
            value: b"new".to_vec(),
        }];
        upper.entries[0].presence.xattrs = true;
        assert!(matches!(
            crate::changeset::namespace::compose(&[&lower, &upper], &limits),
            Err(crate::changeset::namespace::NamespaceError::HardlinkMetadataMismatch { .. })
        ));
    }
    #[test]
    fn impossible_body_scalars_and_range_counts_fail_before_sparse_fetch() {
        let limits = ChangesetLimits::default();
        let sparse = expected_object(expected_bytes(
            json!({"kind":"changeset-sparse-page","ranges":[{"length":0,"offset":0},{"length":0,"offset":0}],"schema":1}),
        ));
        for fault in ["zero-count", "wrong-type", "oversized", "offset"] {
            let mut entry = wire_entry();
            entry["body"]["sparse"] = json!([descriptor(&sparse, 2)]);
            match fault {
                "wrong-type" => entry["body"]["length"] = json!("0"),
                "oversized" => entry["body"]["length"] = json!(limits.max_file_bytes + 1),
                "offset" => entry["body"]["packOffset"] = json!(4096),
                _ => {}
            }
            let encoded = wire_index(entry, 0, vec![sparse.clone()]);
            let pages = encoded
                .pages
                .iter()
                .map(|p| (p.digest, p.bytes.clone()))
                .collect::<BTreeMap<_, _>>();
            let mut visits = Vec::new();
            assert!(decode_index(
                &encoded.root.bytes,
                |digest| {
                    visits.push(digest);
                    Ok(pages[&digest].clone())
                },
                layer(0).diff_id,
                &limits
            )
            .is_err());
            assert_eq!(
                visits,
                vec![encoded.pages.last().unwrap().digest],
                "{fault}"
            );
        }
        let root = wire_root(
            1,
            limits.max_pack_bytes + 4096,
            vec![descriptor(&sparse, 1)],
        );
        let mut visits = 0;
        assert!(decode_index(
            &root,
            |_| {
                visits += 1;
                Ok(vec![])
            },
            layer(0).diff_id,
            &limits
        )
        .is_err());
        assert_eq!(visits, 0);
    }
    #[test]
    fn malformed_range_stops_before_next_continuation_and_valid_maps_ignore_entry_caps() {
        let limits = ChangesetLimits::default();
        let first = expected_object(expected_bytes(
            json!({"kind":"changeset-sparse-page","ranges":[{"length":1,"offset":4},{"length":1,"offset":2}],"schema":1}),
        ));
        let later = expected_object(expected_bytes(
            json!({"kind":"changeset-sparse-page","ranges":[{"length":1,"offset":8}],"schema":1}),
        ));
        let mut entry = wire_entry();
        entry["body"] = json!({"length":10,"packOffset":0,"sparse":[descriptor(&first,2),descriptor(&later,1)]});
        let encoded = wire_index(entry, 4096, vec![first.clone(), later.clone()]);
        let pages = encoded
            .pages
            .iter()
            .map(|p| (p.digest, p.bytes.clone()))
            .collect::<BTreeMap<_, _>>();
        let mut visits = Vec::new();
        assert!(decode_index(
            &encoded.root.bytes,
            |digest| {
                visits.push(digest);
                Ok(pages[&digest].clone())
            },
            layer(0).diff_id,
            &limits
        )
        .is_err());
        assert_eq!(
            visits,
            vec![encoded.pages.last().unwrap().digest, first.digest]
        );
        let limits = ChangesetLimits {
            max_entries: 1,
            max_page_entries: 2,
            ..limits
        };
        let mut l = layer(1);
        l.pack_length = 4096;
        l.entries[0].kind = EntryKind::Regular(PayloadRef {
            pack_offset: 0,
            length: 11,
            sparse: (0..6)
                .map(|n| SparseRange {
                    offset: n * 2,
                    length: 1,
                })
                .collect(),
        });
        assert_eq!(
            decode(&encode_index(&l, &limits).unwrap(), l.diff_id, &limits).unwrap(),
            l
        );
        l.pack_length = 0;
        l.entries[0].kind = EntryKind::Regular(PayloadRef {
            pack_offset: 0,
            length: 0,
            sparse: vec![SparseRange {
                offset: 0,
                length: 0,
            }],
        });
        assert_eq!(
            decode(&encode_index(&l, &limits).unwrap(), l.diff_id, &limits).unwrap(),
            l
        );
        l.pack_length = 8192;
        l.entries[0].kind = EntryKind::Regular(PayloadRef {
            pack_offset: 0,
            length: 4097,
            sparse: vec![],
        });
        assert_eq!(
            decode(&encode_index(&l, &limits).unwrap(), l.diff_id, &limits).unwrap(),
            l
        );
    }
    #[test]
    fn independently_hashed_noncanonical_spellings_are_rejected_at_the_reader() {
        let limits = ChangesetLimits::default();
        let valid = wire_index(wire_entry(), 0, vec![]);
        let root = String::from_utf8(valid.root.bytes.clone()).unwrap();
        for bytes in [
            root.replace("\"entries\":1", "\"entries\":1,\"entries\":1"),
            root.replace("\"entries\":1", "\"entries\":1.0"),
            root.replace("\"entries\":1", "\"entries\":1e0"),
            root.replace("\"packLength\":0", "\"packLength\":-0"),
            root.replacen("{\"changesetAbi\"", "{ \"changesetAbi\"", 1),
            root.replace(
                "\"entries\":1,\"kind\":\"changeset-index\"",
                "\"kind\":\"changeset-index\",\"entries\":1",
            ),
        ] {
            assert!(decode_index(
                bytes.as_bytes(),
                |_| Ok(valid.pages[0].bytes.clone()),
                layer(0).diff_id,
                &limits
            )
            .is_err());
        }
        let page = String::from_utf8(valid.pages[0].bytes.clone()).unwrap();
        for (from, to) in [
            ("\"uid\":0", "\"uid\":0,\"uid\":0"),
            (
                "\"aclAccess\":false",
                "\"aclAccess\":false,\"aclAccess\":false",
            ),
            ("\"path\":\"YQ\"", "\"path\":\"\\u0059Q\""),
            ("\"path\":\"YQ\"", "\"path\":\"YQ==\""),
            ("\"path\":\"YQ\"", "\"path\":\"/w\""),
            ("\"path\":\"YQ\"", "\"path\":\"_x\""),
            ("\"mode\":420", "\"mode\":420.0"),
        ] {
            let object = expected_object(page.replace(from, to).into_bytes());
            let root = wire_root(1, 0, vec![descriptor(&object, 1)]);
            assert!(
                decode_index(
                    &root,
                    |_| Ok(object.bytes.clone()),
                    layer(0).diff_id,
                    &limits
                )
                .is_err(),
                "{to}"
            );
        }
        let mut wire = wire_entry();
        wire["path"] = json!("_w");
        wire["metadata"]["xattrs"] = json!([{"name":"dXNlci5yYXc","value":"AP8K"}]);
        let decoded = decode(&wire_index(wire, 0, vec![]), layer(0).diff_id, &limits).unwrap();
        assert_eq!(decoded.entries[0].path, [0xff]);
        assert_eq!(
            decoded.entries[0].metadata.xattrs[0].value,
            [0, 0xff, b'\n']
        );
        for digest in [
            "sha256:AB".to_owned() + &"ab".repeat(31),
            "sha256:".to_owned() + &"a".repeat(63),
        ] {
            let mut root: serde_json::Value = serde_json::from_slice(&valid.root.bytes).unwrap();
            root["pages"][0]["digest"] = json!(digest);
            assert!(decode_index(
                &expected_bytes(root),
                |_| unreachable!(),
                layer(0).diff_id,
                &limits
            )
            .is_err());
        }
    }
    #[test]
    fn alternate_leaf_partitions_and_malformed_descriptor_nodes_do_not_roundtrip_as_valid() {
        let limits = ChangesetLimits::default();
        let first = wire_entry();
        let mut second = wire_entry();
        second["ordinal"] = json!(1);
        second["path"] = json!("Yg");
        let a = expected_object(expected_bytes(
            json!({"entries":[first],"kind":"changeset-entry-page","schema":1}),
        ));
        let b = expected_object(expected_bytes(
            json!({"entries":[second],"kind":"changeset-entry-page","schema":1}),
        ));
        let root = wire_root(2, 0, vec![descriptor(&a, 1), descriptor(&b, 1)]);
        let objects = BTreeMap::from([(a.digest, a.bytes.clone()), (b.digest, b.bytes.clone())]);
        assert!(decode_index(
            &root,
            |digest| objects.get(&digest).cloned().ok_or_else(|| {
                crate::changeset::ChangesetError::Invalid("canonical merged page absent".into())
            }),
            layer(0).diff_id,
            &limits
        )
        .is_err());
        let range_a = expected_object(expected_bytes(
            json!({"kind":"changeset-sparse-page","ranges":[{"length":1,"offset":0}],"schema":1}),
        ));
        let range_b = expected_object(expected_bytes(
            json!({"kind":"changeset-sparse-page","ranges":[{"length":1,"offset":1}],"schema":1}),
        ));
        let mut entry = wire_entry();
        entry["body"] = json!({"length":2,"packOffset":0,"sparse":[descriptor(&range_a,1),descriptor(&range_b,1)]});
        assert!(decode(
            &wire_index(entry, 4096, vec![range_a, range_b]),
            layer(0).diff_id,
            &limits
        )
        .is_err());
        for fault in [
            "zero",
            "wrong-leaf-count",
            "single-child",
            "wrong-kind",
            "child-size",
            "oversized-page",
            "fanout",
            "sum-overflow",
            "deep",
        ] {
            let mut leaf = a.clone();
            let mut desc = descriptor(&leaf, 1);
            let mut objects = BTreeMap::from([(a.digest, a.bytes.clone())]);
            match fault {
                "zero" => desc["count"] = json!(0),
                "wrong-leaf-count" => desc["count"] = json!(2),
                "wrong-kind" => {
                    leaf = expected_object(expected_bytes(
                        json!({"kind":"changeset-sparse-page","ranges":[{"length":0,"offset":0}],"schema":1}),
                    ));
                    desc = descriptor(&leaf, 1);
                    objects.insert(leaf.digest, leaf.bytes.clone());
                }
                "child-size" => {
                    desc["length"] = json!(leaf.bytes.len() + 1);
                }
                "oversized-page" => desc["length"] = json!(limits.max_page_bytes + 1),
                "fanout" => {
                    let node = expected_object(expected_bytes(
                        json!({"kind":"changeset-page-list","pages":vec![desc;4097],"schema":1}),
                    ));
                    desc = descriptor(&node, 4097);
                    objects.insert(node.digest, node.bytes);
                }
                "sum-overflow" => {
                    let huge = json!({"count":9_007_199_254_740_991u64,"digest":leaf.digest,"length":leaf.bytes.len()});
                    let node = expected_object(expected_bytes(
                        json!({"kind":"changeset-page-list","pages":[huge.clone(),huge],"schema":1}),
                    ));
                    desc = descriptor(&node, 1);
                    objects.insert(node.digest, node.bytes);
                }
                "deep" => {
                    // Acyclic, correctly hashed, deliberately unbalanced nodes.
                    // Each count sums correctly; depth, not a hash cycle, fails.
                    for count in 2..=56 {
                        let node = expected_object(expected_bytes(
                            json!({"kind":"changeset-page-list","pages":[desc,descriptor(&a,1)],"schema":1}),
                        ));
                        desc = descriptor(&node, count);
                        objects.insert(node.digest, node.bytes);
                    }
                }
                _ => {
                    let node = expected_object(expected_bytes(
                        json!({"kind":"changeset-page-list","pages":[desc],"schema":1}),
                    ));
                    desc = descriptor(&node, 1);
                    objects.insert(node.digest, node.bytes);
                }
            }
            let count = if fault == "deep" {
                56
            } else if fault == "fanout" {
                4097
            } else if fault == "wrong-leaf-count" {
                2
            } else {
                1
            };
            assert!(
                decode_index(
                    &wire_root(count, 0, vec![desc]),
                    |digest| objects.get(&digest).cloned().ok_or_else(|| {
                        crate::changeset::ChangesetError::Invalid("missing test page".into())
                    }),
                    layer(0).diff_id,
                    &limits
                )
                .is_err(),
                "{fault}"
            );
        }
    }
    #[test]
    fn independent_256_to_257_descriptor_bootstrap_transition_pins_complete_bytes() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine as _;
        let limits = ChangesetLimits {
            max_page_bytes: 65536,
            ..ChangesetLimits::default()
        };
        let mut l = layer(0);
        let mut full_pages = Vec::new();
        let mut records = Vec::new();
        let mut full_count = 0;
        loop {
            let ordinal = l.entries.len() as u64;
            let mut e = entry(ordinal);
            let mut path = Vec::new();
            for _ in 0..15 {
                path.extend(std::iter::repeat_n(b'p', 255));
                path.push(b'/');
            }
            path.extend_from_slice(&e.path);
            e.path = path;
            e.kind = EntryKind::Symlink {
                target: vec![b'x'; 4096],
            };
            let mut wire = wire_entry();
            wire.as_object_mut().unwrap().remove("body");
            wire["kind"] = json!("symlink");
            wire["path"] = json!(URL_SAFE_NO_PAD.encode(&e.path));
            wire["target"] = json!(URL_SAFE_NO_PAD.encode(vec![b'x'; 4096]));
            wire["ordinal"] = json!(ordinal);
            let mut candidate = records.clone();
            candidate.push(wire.clone());
            let bytes = expected_bytes(
                json!({"entries":candidate,"kind":"changeset-entry-page","schema":1}),
            );
            if bytes.len() > 65536 {
                full_count += records.len();
                full_pages.push(expected_object(expected_bytes(
                    json!({"entries":records,"kind":"changeset-entry-page","schema":1}),
                )));
                records = Vec::new();
            }
            records.push(wire);
            l.entries.push(e);
            if full_pages.len() == 256 {
                break;
            }
        }
        let last = expected_object(expected_bytes(
            json!({"entries":records,"kind":"changeset-entry-page","schema":1}),
        ));
        let descriptors = full_pages
            .iter()
            .map(|page| {
                let value: serde_json::Value = serde_json::from_slice(&page.bytes).unwrap();
                descriptor(page, value["entries"].as_array().unwrap().len() as u64)
            })
            .collect::<Vec<_>>();
        let mut direct = l.clone();
        direct.entries.truncate(full_count);
        let encoded = encode_index(&direct, &limits).unwrap();
        assert_eq!(
            encoded.root.bytes,
            wire_root(full_count as u64, 0, descriptors.clone())
        );
        let mut descriptors = descriptors;
        descriptors.push(descriptor(&last, 1));
        let node = expected_object(expected_bytes(
            json!({"kind":"changeset-page-list","pages":descriptors,"schema":1}),
        ));
        let indirect = encode_index(&l, &limits).unwrap();
        assert_eq!(
            indirect.root.bytes,
            wire_root(
                l.entries.len() as u64,
                0,
                vec![descriptor(&node, l.entries.len() as u64)]
            )
        );
        let actual = indirect
            .pages
            .iter()
            .map(|object| (object.digest, &object.bytes))
            .collect::<BTreeMap<_, _>>();
        for object in full_pages.iter().chain([&last, &node]) {
            assert_eq!(actual[&object.digest], &object.bytes);
        }
        assert_eq!(decode(&indirect, l.diff_id, &limits).unwrap(), l);
    }

    #[test]
    fn literal_entry_page_anchors_exact_byte_admission_and_one_byte_under() {
        let expected=br#"{"entries":[{"body":{"length":0,"packOffset":0,"sparse":[]},"kind":"regular","metadata":{"gid":0,"mode":420,"mtimeNanos":0,"mtimeSeconds":0,"uid":0,"xattrs":[]},"ordinal":0,"path":"YQ","presence":{"aclAccess":false,"aclDefault":false,"gid":false,"mode":false,"mtime":false,"uid":false,"xattrs":false}}],"kind":"changeset-entry-page","schema":1}"#;
        let mut l = layer(1);
        l.entries[0].path = b"a".to_vec();
        let limits = ChangesetLimits {
            max_page_bytes: expected.len() as u64,
            ..ChangesetLimits::default()
        };
        let encoded = encode_index(&l, &limits).unwrap();
        assert_eq!(encoded.pages[0].bytes, expected);
        assert_eq!(decode(&encoded, l.diff_id, &limits).unwrap(), l);
        assert!(encode_index(
            &l,
            &ChangesetLimits {
                max_page_bytes: expected.len() as u64 - 1,
                ..limits
            }
        )
        .is_err());
    }
    #[test]
    fn strict_ordinals_paths_and_ordered_payload_extents_need_no_body_reader() {
        let limits = ChangesetLimits::default();
        let mut valid = layer(3);
        valid.pack_length = 8192;
        for (entry, (offset, length)) in
            valid.entries.iter_mut().zip([(0, 1), (4096, 0), (4096, 2)])
        {
            entry.kind = EntryKind::Regular(PayloadRef {
                pack_offset: offset,
                length,
                sparse: vec![],
            });
        }
        assert_eq!(
            decode(
                &encode_index(&valid, &limits).unwrap(),
                valid.diff_id,
                &limits
            )
            .unwrap(),
            valid
        );
        for fault in [
            "duplicate-path",
            "duplicate-ordinal",
            "missing-ordinal",
            "reorder",
            "gap",
            "overlap",
            "unaligned",
            "empty-offset",
            "short-pack",
            "extra-pack",
            "oversized-file",
        ] {
            let mut l = valid.clone();
            match fault {
                "duplicate-path" => l.entries[1].path = l.entries[0].path.clone(),
                "duplicate-ordinal" => l.entries[1].ordinal = 0,
                "missing-ordinal" => l.entries[1].ordinal = 2,
                "reorder" => l.entries.swap(0, 1),
                "short-pack" => l.pack_length -= 1,
                "extra-pack" => l.pack_length += 4096,
                "empty-offset" => {
                    let EntryKind::Regular(body) = &mut l.entries[1].kind else {
                        panic!("regular")
                    };
                    body.pack_offset = 0;
                }
                _ => {
                    let EntryKind::Regular(body) = &mut l.entries[2].kind else {
                        panic!("regular")
                    };
                    match fault {
                        "gap" => body.pack_offset = 8192,
                        "overlap" => body.pack_offset = 0,
                        "unaligned" => body.pack_offset = 4097,
                        _ => body.length = u64::MAX,
                    }
                }
            }
            assert!(encode_index(&l, &limits).is_err(), "{fault}");
        }
    }
    #[test]
    fn every_custom_limit_rejects_zero_and_above_maximum_even_for_empty_indexes() {
        let l = layer(0);
        let root = wire_root(0, 0, vec![]);
        macro_rules! check {
            ($($field:ident),+)=>{$(
                let mut limits=ChangesetLimits::default();
                limits.$field=0;
                assert!(encode_index(&l,&limits).is_err(),concat!(stringify!($field)," zero"));
                assert!(decode_index(&root,|_|unreachable!(),l.diff_id,&limits).is_err());
                limits.$field=crate::changeset::limits::FORMAT_LIMITS.$field+1;
                assert!(encode_index(&l,&limits).is_err(),concat!(stringify!($field)," above maximum"));
                assert!(decode_index(&root,|_|unreachable!(),l.diff_id,&limits).is_err());
            )+}
        }
        check!(
            max_entries,
            max_namespace_entries,
            max_layers,
            max_path_bytes,
            max_component_bytes,
            max_depth,
            max_file_bytes,
            max_expanded_bytes,
            max_pack_bytes,
            max_extension_bytes,
            max_sparse_ranges,
            max_hardlinks,
            max_xattrs,
            max_xattr_bytes,
            max_page_entries,
            max_page_bytes,
            max_symlink_hops
        );
    }
    #[test]
    fn result_stream_wire_ids_derive_from_independent_stream_records_not_file_hashes() {
        let recipe = LayerRecipe {
            diff_id: ContentDigest::of_bytes(b"independent source"),
        }
        .id()
        .unwrap();
        for (length, chunks, logical) in [
            (0u64, vec![], vec![]),
            (8_388_608, vec!["zero".to_owned()], vec![0u8; 8_388_608]),
            (
                4096,
                vec![hash_spelling(Sha256::digest([b'A'; 4096]))],
                vec![b'A'; 4096],
            ),
            (
                8_392_704,
                vec![
                    "zero".to_owned(),
                    hash_spelling(Sha256::digest([b'B'; 4096])),
                ],
                {
                    let mut bytes = vec![0u8; 8_388_608];
                    bytes.extend_from_slice(&[b'B'; 4096]);
                    bytes
                },
            ),
        ] {
            let record = expected_bytes(
                json!({"chunkSize":8_388_608,"chunks":chunks,"kind":"stream","length":length,"schema":1}),
            );
            let mut hash = Sha256::new();
            hash.update(b"silo:stream:v1\n");
            hash.update(&record);
            let stream = hash_spelling(hash.finalize());
            assert_ne!(stream, hash_spelling(Sha256::digest(&logical)));
            let result = LayerResult {
                recipe,
                pack_stream: stream.parse().unwrap(),
                pack_length: length,
                index_root: ContentDigest::of_bytes(b"index"),
            };
            let expected = expected_bytes(
                json!({"indexRoot":result.index_root,"kind":"layer-result","packLength":length,"packStream":stream,"recipe":recipe,"schema":1}),
            );
            assert_eq!(result.canonical_bytes().unwrap(), expected);
            let mut hash = Sha256::new();
            hash.update(b"silo:layer-result:v1\n");
            hash.update(expected);
            assert_eq!(
                result.id().unwrap().to_string(),
                hash_spelling(hash.finalize())
            );
        }
    }
}
