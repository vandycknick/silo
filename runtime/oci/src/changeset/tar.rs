use crate::changeset::limits::{memory_preflight, reserve_vec, MAX_MTIME_SECONDS, MAX_UID};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::Read;

use crate::changeset::metadata::{
    decimal, pax_attribute, sorted_xattrs, timestamp, validate_hardlink_metadata, validate_metadata,
};
use crate::changeset::pack::{copy_exact, validate_ranges, PackWriter, SparseValidation};
use crate::changeset::{
    ChangeEntry, ChangesetError, ChangesetLimits, ChangesetResult, EntryKind, Metadata,
    MetadataPresence, SparseRange,
};

fn invalid(message: impl Into<String>) -> ChangesetError {
    ChangesetError::Invalid(message.into())
}

fn bound(resource: &'static str, actual: u64, maximum: u64) -> ChangesetResult<()> {
    if actual > maximum {
        Err(ChangesetError::Limit {
            resource,
            actual,
            maximum,
        })
    } else {
        Ok(())
    }
}

fn source_permissions(mode: u64, flag: u8, socket: bool) -> ChangesetResult<u32> {
    // Common Unix tar writers include st_mode's type alongside the separate
    // typeflag (for example tar-rs HeaderMode::Complete). These are redundant
    // source types, not inode flags. Validate them before separating the
    // canonical permission bits from EntryKind; never mask unknown bits.
    let source_type = mode & !0o7777;
    if source_type != 0 {
        if !matches!(
            source_type,
            0o010000 | 0o020000 | 0o040000 | 0o060000 | 0o100000 | 0o120000 | 0o140000
        ) {
            return Err(invalid("unknown tar mode bits"));
        }
        let agrees = match flag {
            0 | b'0' if socket => matches!(source_type, 0o100000 | 0o140000),
            0 | b'0' | b'S' => source_type == 0o100000,
            // A hardlink has no independent inode type. Its source mode is
            // advisory, just as its permission bits are; composition binds
            // and validates the actual target inode.
            b'1' => true,
            b'2' => source_type == 0o120000,
            b'3' => source_type == 0o020000,
            b'4' => source_type == 0o060000,
            b'5' => source_type == 0o040000,
            b'6' => source_type == 0o010000,
            // Unsupported typeflags still fail in entry-kind decoding.
            _ => true,
        };
        if !agrees {
            return Err(invalid("tar mode type conflicts with member type"));
        }
    }
    Ok((mode & 0o7777) as u32)
}

pub(crate) fn normalize_path(
    raw: &[u8],
    root_allowed: bool,
    limits: &ChangesetLimits,
) -> ChangesetResult<Vec<u8>> {
    bound("path bytes", raw.len() as u64, limits.max_path_bytes)?;
    if raw.is_empty() && root_allowed {
        return Ok(Vec::new());
    }
    if raw.is_empty() || raw.first() == Some(&b'/') || raw.contains(&0) {
        return Err(invalid("empty, absolute or NUL-containing tar path"));
    }
    let mut result = Vec::with_capacity(raw.len());
    let mut depth = 0_u64;
    for part in raw.split(|byte| *byte == b'/') {
        if part == b".." {
            return Err(invalid("parent traversal in tar path"));
        }
        if part.is_empty() || part == b"." {
            continue;
        }
        bound(
            "path component bytes",
            part.len() as u64,
            limits.max_component_bytes,
        )?;
        depth += 1;
        bound("path depth", depth, limits.max_depth)?;
        if !result.is_empty() {
            result.push(b'/');
        }
        result.extend_from_slice(part);
    }
    if result.is_empty() && !root_allowed {
        return Err(invalid("root path is only admitted for explicit directory"));
    }
    Ok(result)
}

/// Fixed-field NUL is a terminator, not a byte in the filename. Anything after
/// it must be padding, so an embedded NUL cannot hide a second name.
fn field(bytes: &[u8]) -> ChangesetResult<Vec<u8>> {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    if bytes[end..].iter().any(|byte| *byte != 0) {
        return Err(invalid("non-padding after tar string terminator"));
    }
    Ok(bytes[..end].to_vec())
}

fn ustar_prefix(block: &[u8; 512]) -> ChangesetResult<Vec<u8>> {
    // star.5 defines a 131-byte prefix followed by fixed atime/ctime.
    // xstar carries "tar\0" at 508; xustar/exustar omit that signature and
    // use the documented NUL + octal-start + space-end discriminator.
    let star = &block[508..512] == b"tar\0"
        || (block[475] == 0
            && matches!(block[476], b'0'..=b'7')
            && block[487] == b' '
            && matches!(block[488], b'0'..=b'7')
            && block[499] == b' ');
    if star {
        if block[475] != 0 {
            return Err(invalid("unterminated star prefix"));
        }
        // These source timestamps are deliberately not retained, but the
        // recognized envelope must still contain valid fixed numeric fields.
        required_number(&block[476..488])?;
        required_number(&block[488..500])?;
        field(&block[345..476])
    } else {
        field(&block[345..500])
    }
}

fn number(bytes: &[u8]) -> ChangesetResult<u64> {
    if bytes.first().is_some_and(|byte| byte & 0x80 != 0) {
        if bytes[0] & 0x40 != 0 {
            return Err(invalid("negative GNU tar numeric field"));
        }
        return bytes
            .iter()
            .enumerate()
            .try_fold(0_u64, |value, (index, byte)| {
                value
                    .checked_mul(256)
                    .and_then(|value| {
                        value.checked_add(u64::from(if index == 0 { byte & 0x7f } else { *byte }))
                    })
                    .ok_or_else(|| invalid("GNU tar numeric overflow"))
            });
    }
    let bytes = bytes.trim_ascii();
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    if bytes[end..].iter().any(|byte| !matches!(*byte, 0 | b' ')) {
        return Err(invalid("invalid tar number padding"));
    }
    let digits = bytes[..end].trim_ascii();
    if digits.is_empty() {
        return Ok(0);
    }
    digits.iter().try_fold(0_u64, |value, digit| {
        if !matches!(digit, b'0'..=b'7') {
            return Err(invalid("invalid octal tar field"));
        }
        value
            .checked_mul(8)
            .and_then(|value| value.checked_add(u64::from(digit - b'0')))
            .ok_or_else(|| invalid("tar numeric overflow"))
    })
}

fn required_number(bytes: &[u8]) -> ChangesetResult<u64> {
    if bytes.first().is_none_or(|byte| byte & 0x80 == 0) && !bytes.iter().any(u8::is_ascii_digit) {
        return Err(invalid("missing required tar numeric metadata"));
    }
    number(bytes)
}

fn header(reader: &mut impl Read) -> ChangesetResult<[u8; 512]> {
    let mut block = [0_u8; 512];
    reader.read_exact(&mut block)?;
    Ok(block)
}

fn padding(reader: &mut impl Read, length: u64) -> ChangesetResult<()> {
    let padding = (512 - length % 512) % 512;
    copy_exact(reader, &mut std::io::sink(), padding)
}

fn attribute_key(key: &[u8]) -> bool {
    key.starts_with(b"SCHILY.xattr.")
        || key.starts_with(b"LIBARCHIVE.xattr.")
        || key.starts_with(b"SCHILY.acl.")
        || key == b"RHT.security.selinux"
}

#[derive(Default)]
struct Pax {
    values: BTreeMap<Vec<u8>, Vec<u8>>,
    // Retain exact PAX keyword identities: removing or overriding one spelling
    // must neither erase another representation nor lose conflict evidence.
    attributes: BTreeMap<Vec<u8>, HashMap<Vec<u8>, Vec<u8>>>,
    pairs: Vec<SparseRange>,
    map: Option<Vec<SparseRange>>,
    pending_offset: Option<u64>,
    pending: bool,
}

fn byte(reader: &mut impl Read) -> ChangesetResult<u8> {
    let mut byte = [0];
    reader.read_exact(&mut byte)?;
    Ok(byte[0])
}

fn ignored_key(key: &[u8]) -> bool {
    matches!(
        key,
        b"uname" | b"gname" | b"atime" | b"ctime" | b"comment" | b"charset" | b"hdrcharset"
    )
}

fn archive_provenance_key(key: &[u8]) -> bool {
    // star.5 documents these as global-only archive facts, not inode metadata:
    // producer/version, writer format, backup start, volume number and tape
    // I/O block size. Ingest interprets the actual tar framing independently.
    // Deliberately do not accept SCHILY.* or SCHILY.volhdr.* by prefix.
    matches!(
        key,
        b"SCHILY.release"
            | b"SCHILY.archtype"
            | b"SCHILY.volhdr.dumpdate"
            | b"SCHILY.volhdr.volno"
            | b"SCHILY.volhdr.blocksize"
    )
}

fn ordinary_key(key: &[u8]) -> bool {
    matches!(
        key,
        b"path"
            | b"linkpath"
            | b"size"
            | b"uid"
            | b"gid"
            | b"mtime"
            | b"SCHILY.filetype"
            | b"SCHILY.devmajor"
            | b"SCHILY.devminor"
            | b"GNU.sparse.name"
            | b"GNU.sparse.size"
            | b"GNU.sparse.realsize"
            | b"GNU.sparse.major"
            | b"GNU.sparse.minor"
            | b"GNU.sparse.numblocks"
            | b"SCHILY.dev"
            | b"SCHILY.ino"
            | b"SCHILY.nlink"
    )
}

fn numeric_key(key: &[u8]) -> bool {
    ordinary_key(key)
        && !matches!(
            key,
            b"path" | b"linkpath" | b"mtime" | b"GNU.sparse.name" | b"SCHILY.filetype"
        )
        || matches!(key, b"GNU.sparse.offset" | b"GNU.sparse.numbytes")
}

impl Pax {
    /// Length framing, CSV maps and ignored textual facts are consumed directly
    /// from the spool. No extension-sized allocation is made, even for maps
    /// larger than an index page or a tiny archive claiming a huge value.
    fn add(
        &mut self,
        reader: &mut impl Read,
        size: u64,
        global: bool,
        limits: &ChangesetLimits,
    ) -> ChangesetResult<()> {
        bound("PAX extension bytes", size, limits.max_extension_bytes)?;
        self.pending = true;
        let mut remaining = size;
        while remaining != 0 {
            let initial = remaining;
            let mut length = 0_u64;
            let mut digits = false;
            loop {
                if remaining == 0 {
                    return Err(invalid("truncated PAX length"));
                }
                let item = byte(reader)?;
                remaining -= 1;
                if item == b' ' && digits {
                    break;
                }
                if !item.is_ascii_digit() {
                    return Err(invalid("invalid PAX record length"));
                }
                digits = true;
                length = length
                    .checked_mul(10)
                    .and_then(|n| n.checked_add(u64::from(item - b'0')))
                    .ok_or_else(|| invalid("PAX length overflow"))?;
            }
            let prefix = initial - remaining;
            if length > initial || length <= prefix + 2 {
                return Err(invalid("truncated or short PAX record"));
            }
            let mut record_left = length - prefix;
            let mut key = Vec::new();
            loop {
                if record_left <= 1 {
                    return Err(invalid("PAX record lacks equals"));
                }
                let item = byte(reader)?;
                record_left -= 1;
                if item == b'=' {
                    break;
                }
                if item == 0
                    || key.len() >= 1024
                    || (!key.starts_with(b"SCHILY.xattr.") && !matches!(item, 33..=126))
                {
                    return Err(invalid("invalid or oversized PAX keyword"));
                }
                reserve_vec(&mut key, 1)?;
                key.push(item);
            }
            if key.is_empty() {
                return Err(invalid("empty PAX keyword"));
            }
            let value_length = record_left - 1;
            if global && (key.starts_with(b"GNU.sparse.") || key == b"SCHILY.filetype") {
                return Err(invalid("sparse/socket metadata must be local PAX"));
            }
            if key == b"GNU.sparse.map" {
                self.map = Some(csv_ranges(reader, value_length, limits)?);
            } else if key == b"hdrcharset" {
                if value_length > 32 {
                    return Err(ChangesetError::Unsupported(
                        "PAX header character set".into(),
                    ));
                }
                let mut charset = [0; 32];
                let count = usize::try_from(value_length)
                    .map_err(|_| invalid("character-set length overflow"))?;
                reader.read_exact(&mut charset[..count])?;
                if !matches!(
                    &charset[..count],
                    b"" | b"BINARY" | b"UTF-8" | b"ISO-IR 10646 2000 UTF-8"
                ) {
                    return Err(ChangesetError::Unsupported(
                        "PAX header character set".into(),
                    ));
                }
            } else if ignored_key(&key) || (global && archive_provenance_key(&key)) {
                copy_exact(reader, &mut std::io::sink(), value_length)?;
            } else if matches!(key.as_slice(), b"SCHILY.acl.access" | b"SCHILY.acl.default") {
                let name = if key == b"SCHILY.acl.access" {
                    b"system.posix_acl_access".as_slice()
                } else {
                    b"system.posix_acl_default".as_slice()
                };
                let value = if global && value_length == 0 {
                    Vec::new()
                } else {
                    crate::changeset::metadata::textual_acl_stream(reader, value_length, limits)?
                };
                self.store_attribute(
                    key,
                    name.to_vec(),
                    value,
                    global && value_length == 0,
                    limits,
                )?;
            } else if key == b"mtime" {
                let value = streaming_time(reader, value_length)?;
                if global && value.is_empty() {
                    self.values.remove(&key);
                } else {
                    self.values.insert(key, value);
                }
            } else {
                let maximum = if attribute_key(&key) {
                    limits
                        .max_xattr_bytes
                        .checked_mul(4)
                        .ok_or_else(|| invalid("xattr envelope overflow"))?
                } else if matches!(key.as_slice(), b"path" | b"linkpath" | b"GNU.sparse.name") {
                    limits.max_path_bytes
                } else {
                    64
                };
                if !attribute_key(&key)
                    && !ordinary_key(&key)
                    && key != b"GNU.sparse.offset"
                    && key != b"GNU.sparse.numbytes"
                {
                    return Err(ChangesetError::Unsupported(format!(
                        "PAX metadata keyword {}",
                        String::from_utf8_lossy(&key)
                    )));
                }
                let value = if numeric_key(&key) {
                    streaming_decimal(reader, value_length)?
                } else {
                    bound("PAX field bytes", value_length, maximum)?;
                    let working = value_length
                        .checked_mul(4)
                        .and_then(|n| n.checked_add(2048))
                        .ok_or_else(|| invalid("PAX working memory overflow"))?;
                    memory_preflight(working)?;
                    let mut value = Vec::new();
                    let length = usize::try_from(value_length)
                        .map_err(|_| invalid("PAX field size overflow"))?;
                    reserve_vec(&mut value, length)?;
                    value.resize(length, 0);
                    reader.read_exact(&mut value)?;
                    value
                };
                if key == b"GNU.sparse.offset" {
                    if self
                        .pending_offset
                        .replace(decimal(&value, "sparse offset")?)
                        .is_some()
                    {
                        return Err(invalid("unpaired sparse 0.0 offset"));
                    }
                } else if key == b"GNU.sparse.numbytes" {
                    let offset = self
                        .pending_offset
                        .take()
                        .ok_or_else(|| invalid("sparse 0.0 length before offset"))?;
                    sparse_push(
                        &mut self.pairs,
                        SparseRange {
                            offset,
                            length: decimal(&value, "sparse length")?,
                        },
                        limits,
                    )?;
                } else if attribute_key(&key) {
                    let delete = global && value.is_empty();
                    let attr = pax_attribute(&key, value)?;
                    self.store_attribute(key, attr.name, attr.value, delete, limits)?;
                } else if global && value.is_empty() {
                    self.values.remove(&key);
                } else {
                    // The remaining known scalar keywords form a fixed set;
                    // arbitrary ignored strings were streamed above.
                    self.values.insert(key, value);
                }
            }
            if byte(reader)? != b'\n' {
                return Err(invalid("PAX record lacks terminator"));
            }
            remaining = initial - length;
        }
        padding(reader, size)
    }

    fn store_attribute(
        &mut self,
        source_key: Vec<u8>,
        name: Vec<u8>,
        value: Vec<u8>,
        delete: bool,
        limits: &ChangesetLimits,
    ) -> ChangesetResult<()> {
        if delete {
            let empty = if let Some(sources) = self.attributes.get_mut(&name) {
                sources.remove(&source_key);
                sources.is_empty()
            } else {
                false
            };
            if empty {
                self.attributes.remove(&name);
            }
        } else {
            if !self.attributes.contains_key(&name) {
                bound(
                    "xattrs per PAX scope",
                    self.attributes.len() as u64 + 1,
                    limits.max_xattrs,
                )?;
            }
            let sources = self.attributes.entry(name).or_default();
            if !sources.contains_key(&source_key) {
                if sources.len() == sources.capacity() {
                    // Conservative bucket-growth working set, not a format cap.
                    let slots = (sources.capacity().max(8) as u64)
                        .checked_mul(4)
                        .ok_or_else(|| invalid("xattr source bucket overflow"))?;
                    let bytes = slots
                        .checked_mul((std::mem::size_of::<(Vec<u8>, Vec<u8>)>() + 1) as u64)
                        .ok_or_else(|| invalid("xattr source allocation overflow"))?;
                    memory_preflight(bytes)?;
                }
                sources
                    .try_reserve(1)
                    .map_err(|error| ChangesetError::Allocation(error.to_string()))?;
            }
            sources.insert(source_key, value);
        }
        Ok(())
    }
}

fn resolved_attributes(
    global: &Pax,
    local: &Pax,
    limits: &ChangesetLimits,
) -> ChangesetResult<BTreeMap<Vec<u8>, Vec<u8>>> {
    let mut attrs = BTreeMap::new();
    for name in global.attributes.keys().chain(local.attributes.keys()) {
        if attrs.contains_key(name) {
            continue;
        }
        bound(
            "xattrs per inode",
            attrs.len() as u64 + 1,
            limits.max_xattrs,
        )?;
        let global_sources = global.attributes.get(name);
        let local_sources = local.attributes.get(name);
        let remaining_global = global_sources
            .into_iter()
            .flat_map(HashMap::iter)
            .filter(|(key, _)| !local_sources.is_some_and(|local| local.contains_key(*key)))
            .map(|(_, value)| value.as_slice());
        let local_values = local_sources
            .into_iter()
            .flat_map(HashMap::values)
            .map(Vec::as_slice);
        let mut selected = None;
        for value in remaining_global.chain(local_values) {
            if selected.is_some_and(|previous| previous != value) {
                return Err(invalid("conflicting xattr representations"));
            }
            selected = Some(value);
        }
        let value = selected.ok_or_else(|| invalid("empty xattr source group"))?;
        memory_preflight(
            ((name.len() + value.len()) as u64)
                .checked_mul(2)
                .and_then(|n| n.checked_add(256))
                .ok_or_else(|| invalid("xattr working memory overflow"))?,
        )?;
        attrs.insert(name.clone(), value.to_vec());
    }
    Ok(attrs)
}

fn streaming_decimal(reader: &mut impl Read, length: u64) -> ChangesetResult<Vec<u8>> {
    if length == 0 {
        return Ok(Vec::new());
    }
    let mut number = 0_u64;
    for _ in 0..length {
        let item = byte(reader)?;
        if !item.is_ascii_digit() {
            return Err(invalid("invalid PAX unsigned numeric field"));
        }
        number = number
            .checked_mul(10)
            .and_then(|n| n.checked_add(u64::from(item - b'0')))
            .ok_or_else(|| invalid("PAX numeric overflow"))?;
    }
    Ok(number.to_string().into_bytes())
}

fn streaming_time(reader: &mut impl Read, size: u64) -> ChangesetResult<Vec<u8>> {
    if size == 0 {
        return Ok(Vec::new());
    }
    let mut seconds = 0_u64;
    let mut second_digits = false;
    let mut fractional = false;
    let mut fraction_digits = 0_u64;
    let mut nanos = 0_u32;
    for _ in 0..size {
        let item = byte(reader)?;
        if item == b'.' && !fractional && second_digits {
            fractional = true;
            continue;
        }
        if !item.is_ascii_digit() {
            return Err(invalid("invalid PAX mtime"));
        }
        if fractional {
            if fraction_digits < 9 {
                nanos = nanos * 10 + u32::from(item - b'0');
            }
            fraction_digits += 1;
        } else {
            second_digits = true;
            seconds = seconds
                .checked_mul(10)
                .and_then(|n| n.checked_add(u64::from(item - b'0')))
                .ok_or_else(|| invalid("mtime seconds overflow"))?;
        }
    }
    if seconds > MAX_MTIME_SECONDS || (fractional && fraction_digits == 0) {
        return Err(invalid("invalid PAX mtime bound/fraction"));
    }
    for _ in fraction_digits..9 {
        nanos *= 10;
    }
    Ok(format!("{seconds}.{nanos:09}").into_bytes())
}

fn csv_ranges(
    reader: &mut impl Read,
    size: u64,
    limits: &ChangesetLimits,
) -> ChangesetResult<Vec<SparseRange>> {
    let mut ranges = Vec::new();
    let mut value = 0_u64;
    let mut digits = false;
    let mut offset = None;
    for index in 0..size {
        let item = byte(reader)?;
        if item == b',' {
            if !digits || index + 1 == size {
                return Err(invalid("empty sparse CSV field"));
            }
            if let Some(start) = offset.take() {
                sparse_push(
                    &mut ranges,
                    SparseRange {
                        offset: start,
                        length: value,
                    },
                    limits,
                )?;
            } else {
                offset = Some(value);
            }
            value = 0;
            digits = false;
        } else {
            if !item.is_ascii_digit() {
                return Err(invalid("invalid sparse CSV number"));
            }
            digits = true;
            value = value
                .checked_mul(10)
                .and_then(|n| n.checked_add(u64::from(item - b'0')))
                .ok_or_else(|| invalid("sparse CSV integer overflow"))?;
        }
    }
    if size != 0 {
        let start = offset.ok_or_else(|| invalid("odd sparse CSV field count"))?;
        sparse_push(
            &mut ranges,
            SparseRange {
                offset: start,
                length: value,
            },
            limits,
        )?;
    }
    Ok(ranges)
}

fn extension(reader: &mut impl Read, size: u64, maximum: u64) -> ChangesetResult<Vec<u8>> {
    bound("tar extension bytes", size, maximum)?;
    let length = usize::try_from(size).map_err(|_| invalid("extension allocation overflow"))?;
    let mut bytes = vec![0; length];
    reader.read_exact(&mut bytes)?;
    padding(reader, size)?;
    Ok(bytes)
}

fn long_string(mut bytes: Vec<u8>, limits: &ChangesetLimits) -> ChangesetResult<Vec<u8>> {
    if bytes.last() == Some(&0) {
        bytes.pop();
    }
    if bytes.contains(&0) {
        return Err(invalid("embedded NUL in GNU long name"));
    }
    bound(
        "GNU long path bytes",
        bytes.len() as u64,
        limits.max_path_bytes,
    )?;
    Ok(bytes)
}

fn sparse_push(
    ranges: &mut Vec<SparseRange>,
    range: SparseRange,
    limits: &ChangesetLimits,
) -> ChangesetResult<()> {
    bound(
        "sparse ranges",
        ranges.len() as u64 + 1,
        limits.max_sparse_ranges,
    )?;
    let end = range
        .offset
        .checked_add(range.length)
        .ok_or_else(|| invalid("sparse range overflow"))?;
    bound("regular file bytes", end, limits.max_file_bytes)?;
    if let Some(previous) = ranges.last() {
        let end = previous
            .offset
            .checked_add(previous.length)
            .ok_or_else(|| invalid("sparse range overflow"))?;
        if range.offset <= previous.offset || range.offset < end || previous.length == 0 {
            return Err(invalid("unordered or overlapping sparse ranges"));
        }
    }
    reserve_vec(ranges, 1)?;
    ranges.push(range);
    Ok(())
}

fn old_sparse(
    reader: &mut impl Read,
    block: &[u8; 512],
    stored: u64,
    limits: &ChangesetLimits,
) -> ChangesetResult<(u64, Vec<SparseRange>)> {
    let logical = required_number(&block[483..495])?;
    bound("regular file bytes", logical, limits.max_file_bytes)?;
    let mut ranges = Vec::new();
    let mut validation = SparseValidation::new(logical);
    let mut unused = false;
    for pair in block[386..482].chunks_exact(24) {
        old_pair(
            pair,
            &mut ranges,
            &mut unused,
            &mut validation,
            stored,
            limits,
        )?;
    }
    let mut extended = block[482];
    let mut extensions = 0_u64;
    while extended != 0 {
        if extended != 1 {
            return Err(invalid("invalid old GNU sparse continuation flag"));
        }
        extensions += 512;
        bound(
            "sparse extension bytes",
            extensions,
            limits.max_extension_bytes,
        )?;
        let extra = header(reader)?;
        for pair in extra[..504].chunks_exact(24) {
            old_pair(
                pair,
                &mut ranges,
                &mut unused,
                &mut validation,
                stored,
                limits,
            )?;
        }
        extended = extra[504];
        if extra[505..].iter().any(|byte| *byte != 0) {
            return Err(invalid("nonzero sparse extension padding"));
        }
    }
    if validation.stored() != stored {
        return Err(invalid("sparse map data count differs from stored body"));
    }
    Ok((logical, ranges))
}

fn old_pair(
    pair: &[u8],
    ranges: &mut Vec<SparseRange>,
    unused: &mut bool,
    validation: &mut SparseValidation,
    stored: u64,
    limits: &ChangesetLimits,
) -> ChangesetResult<()> {
    if pair.iter().all(|byte| *byte == 0) {
        *unused = true;
        return Ok(());
    }
    if *unused {
        return Err(invalid("old sparse records after unused slot"));
    }
    let range = SparseRange {
        offset: number(&pair[..12])?,
        length: number(&pair[12..])?,
    };
    validation.push(&range)?;
    if validation.stored() > stored {
        return Err(invalid("sparse data exceeds stored body budget"));
    }
    sparse_push(ranges, range, limits)
}

fn sparse_line(reader: &mut impl Read, consumed: &mut u64, maximum: u64) -> ChangesetResult<u64> {
    let mut value = 0_u64;
    let mut digits = false;
    loop {
        if *consumed >= maximum {
            return Err(invalid(
                "sparse 1.0 map exceeds member body or extension bound",
            ));
        }
        let mut byte = [0];
        reader.read_exact(&mut byte)?;
        *consumed += 1;
        if byte[0] == b'\n' && digits {
            return Ok(value);
        }
        if !byte[0].is_ascii_digit() {
            return Err(invalid("invalid sparse 1.0 decimal map"));
        }
        digits = true;
        value = value
            .checked_mul(10)
            .and_then(|n| n.checked_add(u64::from(byte[0] - b'0')))
            .ok_or_else(|| invalid("sparse map integer overflow"))?;
    }
}

fn pax_sparse(
    reader: &mut impl Read,
    values: &BTreeMap<Vec<u8>, Vec<u8>>,
    local: &mut Pax,
    stored: u64,
    limits: &ChangesetLimits,
) -> ChangesetResult<Option<(u64, u64, Vec<SparseRange>)>> {
    if local.pending_offset.is_some() {
        return Err(invalid("unpaired sparse 0.0 offset"));
    }
    if !values.keys().any(|key| key.starts_with(b"GNU.sparse."))
        && local.pairs.is_empty()
        && local.map.is_none()
    {
        return Ok(None);
    }
    let get = |key: &[u8]| values.get(key).map(Vec::as_slice);
    let major = get(b"GNU.sparse.major")
        .map(|bytes| decimal(bytes, "sparse major"))
        .transpose()?;
    let minor = get(b"GNU.sparse.minor")
        .map(|bytes| decimal(bytes, "sparse minor"))
        .transpose()?;
    let logical = match (get(b"GNU.sparse.size"), get(b"GNU.sparse.realsize")) {
        (Some(a), Some(b)) if a != b => return Err(invalid("conflicting sparse logical sizes")),
        (Some(bytes), _) | (_, Some(bytes)) => decimal(bytes, "sparse logical size")?,
        _ => return Err(invalid("sparse member lacks logical size")),
    };
    bound("regular file bytes", logical, limits.max_file_bytes)?;
    let mut ranges = Vec::new();
    let mut map_bytes = 0_u64;
    match (major, minor) {
        (Some(1), Some(0)) => {
            if !local.pairs.is_empty()
                || local.map.is_some()
                || get(b"GNU.sparse.numblocks").is_some()
            {
                return Err(invalid("mixed sparse wire versions"));
            }
            let maximum = stored.min(limits.max_extension_bytes);
            let count = sparse_line(reader, &mut map_bytes, maximum)?;
            let maximum_count = logical
                .checked_add(1)
                .ok_or_else(|| invalid("sparse count bound overflow"))?
                .min(limits.max_sparse_ranges);
            bound("sparse ranges", count, maximum_count)?;
            let mut validation = SparseValidation::new(logical);
            for _ in 0..count {
                let offset = sparse_line(reader, &mut map_bytes, maximum)?;
                let length = sparse_line(reader, &mut map_bytes, maximum)?;
                let range = SparseRange { offset, length };
                validation.push(&range)?;
                let minimum_map = map_bytes
                    .checked_add(511)
                    .map(|n| n & !511)
                    .ok_or_else(|| invalid("sparse map padding overflow"))?;
                if minimum_map > stored || validation.stored() > stored - minimum_map {
                    return Err(invalid("sparse data exceeds stored body budget"));
                }
                sparse_push(&mut ranges, range, limits)?;
            }
            let padded = map_bytes
                .checked_add(511)
                .map(|n| n & !511)
                .ok_or_else(|| invalid("sparse map padding overflow"))?;
            if padded > stored || padded > limits.max_extension_bytes {
                return Err(invalid(
                    "sparse map padding exceeds body or extension bound",
                ));
            }
            let mut remaining = padded - map_bytes;
            let mut bytes = [0; 512];
            while remaining != 0 {
                let n = usize::try_from(remaining.min(512))
                    .map_err(|_| invalid("map padding overflow"))?;
                reader.read_exact(&mut bytes[..n])?;
                if bytes[..n].iter().any(|byte| *byte != 0) {
                    return Err(invalid("nonzero sparse map padding"));
                }
                remaining -= n as u64;
            }
            map_bytes = padded;
        }
        (None, None) | (Some(0), Some(0 | 1)) => {
            if let Some(map) = local.map.take() {
                if !local.pairs.is_empty() || minor == Some(0) {
                    return Err(invalid("mixed sparse 0.0/0.1 maps"));
                }
                ranges = map;
            } else {
                if minor == Some(1) {
                    return Err(invalid("sparse 0.1 map missing"));
                }
                ranges = std::mem::take(&mut local.pairs);
            }
            let count = decimal(
                get(b"GNU.sparse.numblocks").ok_or_else(|| invalid("sparse map lacks count"))?,
                "sparse count",
            )?;
            if count != ranges.len() as u64 {
                return Err(invalid("sparse map count mismatch"));
            }
        }
        _ => return Err(ChangesetError::Unsupported("sparse wire version".into())),
    }
    validate_ranges(&ranges, logical, stored - map_bytes, limits)?;
    Ok(Some((logical, stored - map_bytes, ranges)))
}

/// Interpret only tar envelopes, never the host namespace. The decoded spool
/// has already been hashed through true decoder EOF before this function runs.
pub(crate) fn parse(
    reader: &mut impl Read,
    pack: &mut PackWriter<'_>,
    limits: &ChangesetLimits,
) -> ChangesetResult<Vec<ChangeEntry>> {
    let mut entries = Vec::new();
    let mut names = BTreeSet::new();
    let mut global = Pax::default();
    let mut local = Pax::default();
    let mut long_path = None;
    let mut long_link = None;
    loop {
        let block = header(reader)?;
        if block.iter().all(|byte| *byte == 0) {
            if header(reader)?.iter().any(|byte| *byte != 0) {
                return Err(invalid("tar end marker requires two zero blocks"));
            }
            if local.pending || long_path.is_some() || long_link.is_some() {
                return Err(invalid("orphan tar extension at end of archive"));
            }
            break;
        }
        let checksum = number(&block[148..156])?;
        let unsigned: u64 = block
            .iter()
            .enumerate()
            .map(|(n, byte)| {
                if (148..156).contains(&n) {
                    32
                } else {
                    u64::from(*byte)
                }
            })
            .sum();
        let signed: i64 = block
            .iter()
            .enumerate()
            .map(|(n, byte)| {
                if (148..156).contains(&n) {
                    32
                } else {
                    i64::from(*byte as i8)
                }
            })
            .sum();
        if checksum != unsigned && i64::try_from(checksum).ok() != Some(signed) {
            return Err(invalid("tar header checksum mismatch"));
        }
        let old_gnu = &block[257..265] == b"ustar  \0";
        let ustar = &block[257..263] == b"ustar\0";
        if !old_gnu && !ustar && block[257..265].iter().any(|byte| *byte != 0) {
            return Err(ChangesetError::Unsupported("tar header format".into()));
        }
        if ustar && &block[263..265] != b"00" {
            return Err(ChangesetError::Unsupported("ustar version".into()));
        }
        if old_gnu
            && (number(&block[369..381])? != 0 || block[381..386].iter().any(|byte| *byte != 0))
        {
            return Err(ChangesetError::Unsupported(
                "GNU multivolume/offset header fields".into(),
            ));
        }
        let flag = block[156];
        let size_override = local
            .values
            .get(b"size".as_slice())
            .or_else(|| global.values.get(b"size".as_slice()))
            .is_some();
        let raw_size = if matches!(flag, b'x' | b'g' | b'L' | b'K') || !size_override {
            required_number(&block[124..136])?
        } else {
            0
        };
        match flag {
            b'x' | b'g' => {
                if flag == b'g' {
                    global.add(reader, raw_size, true, limits)?;
                } else {
                    local.add(reader, raw_size, false, limits)?;
                }
                continue;
            }
            b'L' | b'K' => {
                let bytes = long_string(
                    extension(
                        reader,
                        raw_size,
                        limits
                            .max_path_bytes
                            .checked_add(1)
                            .ok_or_else(|| invalid("long name bound overflow"))?,
                    )?,
                    limits,
                )?;
                let slot = if flag == b'L' {
                    &mut long_path
                } else {
                    &mut long_link
                };
                if slot.replace(bytes).is_some() {
                    return Err(invalid("duplicate pending GNU long name"));
                }
                continue;
            }
            _ => {}
        }
        bound(
            "changeset entries",
            entries.len() as u64 + 1,
            limits.max_entries,
        )?;
        let mut values = global.values.clone();
        for (key, value) in &local.values {
            values.insert(key.clone(), value.clone());
        }
        for key in [b"path".as_slice(), b"uid", b"gid", b"mtime", b"size"] {
            if local.values.get(key).is_some_and(Vec::is_empty) {
                return Err(invalid(format!(
                    "deleted required PAX field {}",
                    String::from_utf8_lossy(key)
                )));
            }
        }
        if matches!(flag, b'1' | b'2')
            && local
                .values
                .get(b"linkpath".as_slice())
                .is_some_and(Vec::is_empty)
        {
            return Err(invalid("deleted required PAX field linkpath"));
        }
        let value = |key: &[u8]| values.get(key).map(Vec::as_slice);
        let pending_path = long_path.take();
        let name = if let Some(path) = value(b"GNU.sparse.name").or_else(|| value(b"path")) {
            path.to_vec()
        } else if let Some(path) = pending_path {
            path
        } else {
            let mut name = field(&block[..100])?;
            if ustar {
                let prefix = ustar_prefix(&block)?;
                if !prefix.is_empty() {
                    let mut full = prefix;
                    full.push(b'/');
                    full.extend(name);
                    name = full;
                }
            }
            name
        };
        let directory = flag == b'5';
        if name.is_empty() {
            return Err(invalid("empty raw tar member name"));
        }
        // Only the exact effective source-directory spelling "/" aliases ".".
        // Canonical index paths and hardlink targets keep their strict parser.
        let path = if directory && name == b"/" {
            normalize_path(b".", true, limits)?
        } else {
            normalize_path(&name, directory, limits)?
        };
        if !names.insert(path.clone()) {
            return Err(invalid("duplicate normalized tar path"));
        }
        let pending_link = long_link.take();
        let target = if let Some(link) = value(b"linkpath") {
            link.to_vec()
        } else if let Some(link) = pending_link {
            link
        } else {
            field(&block[157..257])?
        };
        if !matches!(flag, b'3' | b'4')
            && (value(b"SCHILY.devmajor").is_some()
                || value(b"SCHILY.devminor").is_some()
                || number(&block[329..337])? != 0
                || number(&block[337..345])? != 0)
        {
            return Err(invalid("device metadata on non-device member"));
        }
        let uid = value(b"uid")
            .map(|bytes| decimal(bytes, "uid"))
            .unwrap_or_else(|| required_number(&block[108..116]))?;
        let gid = value(b"gid")
            .map(|bytes| decimal(bytes, "gid"))
            .unwrap_or_else(|| required_number(&block[116..124]))?;
        if uid > MAX_UID || gid > MAX_UID {
            return Err(invalid("uid/gid outside Linux profile"));
        }
        let socket = match value(b"SCHILY.filetype") {
            None => false,
            Some(b"socket") if local.values.contains_key(b"SCHILY.filetype".as_slice()) => true,
            _ => return Err(ChangesetError::Unsupported("PAX filetype".into())),
        };
        let mode = source_permissions(required_number(&block[100..108])?, flag, socket)?;
        let (mtime_seconds, mtime_nanos) = if let Some(time) = value(b"mtime") {
            timestamp(time)?
        } else {
            (required_number(&block[136..148])?, 0)
        };
        let stored = value(b"size")
            .map(|bytes| decimal(bytes, "size"))
            .unwrap_or(Ok(raw_size))?;
        let mut presence = MetadataPresence {
            uid: true,
            gid: true,
            mode: true,
            mtime: true,
            ..MetadataPresence::default()
        };
        let attrs = resolved_attributes(&global, &local, limits)?;
        presence.xattrs = !attrs.is_empty();
        presence.acl_access = attrs.contains_key(b"system.posix_acl_access".as_slice());
        presence.acl_default = attrs.contains_key(b"system.posix_acl_default".as_slice());
        for (key, value) in &values {
            match key.as_slice() {
                b"SCHILY.dev" | b"SCHILY.ino" | b"SCHILY.nlink" => {
                    decimal(value, "nonpreserved source topology")?;
                }
                key if ordinary_key(key) || ignored_key(key) => {}
                _ => {
                    return Err(ChangesetError::Unsupported(format!(
                        "PAX metadata keyword {}",
                        String::from_utf8_lossy(key)
                    )))
                }
            }
        }
        let metadata = Metadata {
            uid: uid as u32,
            gid: gid as u32,
            mode,
            mtime_seconds,
            mtime_nanos,
            xattrs: sorted_xattrs(attrs),
        };
        if flag == b'1' {
            validate_hardlink_metadata(&metadata, limits)?;
        } else {
            validate_metadata(&metadata, directory, limits)?;
        }
        let sparse = if flag == b'S' {
            if !old_gnu
                || values.keys().any(|key| key.starts_with(b"GNU.sparse."))
                || !local.pairs.is_empty()
                || local.map.is_some()
                || local.pending_offset.is_some()
            {
                return Err(invalid("mixed or non-GNU old sparse header"));
            }
            let (length, ranges) = old_sparse(reader, &block, stored, limits)?;
            Some((length, stored, ranges))
        } else {
            pax_sparse(reader, &values, &mut local, stored, limits)?
        };
        let regular = matches!(flag, 0 | b'0' | b'S');
        if sparse.is_some() && !regular {
            return Err(invalid("sparse metadata on non-regular member"));
        }
        if socket
            && (!regular || flag == b'S' || stored != 0 || sparse.is_some() || !target.is_empty())
        {
            return Err(invalid(
                "socket requires ordinary zero-body regular member without target/sparse map",
            ));
        }
        if !regular && stored != 0 {
            return Err(invalid("non-regular tar member has a body"));
        }
        if !matches!(flag, b'1' | b'2') && !target.is_empty() {
            return Err(invalid("link target on non-link member"));
        }
        if matches!(flag, b'1' | b'2') && (target.is_empty() || target.contains(&0)) {
            return Err(invalid("empty or NUL-containing link target"));
        }
        bound(
            "link target bytes",
            target.len() as u64,
            limits.max_path_bytes,
        )?;
        let components: Vec<&[u8]> = path.split(|byte| *byte == b'/').collect();
        if components
            .iter()
            .take(components.len().saturating_sub(1))
            .any(|part| part.starts_with(b".wh."))
        {
            return Err(invalid("whiteout marker in parent path"));
        }
        let basename = components.last().copied().unwrap_or_default();
        let whiteout = basename.starts_with(b".wh.");
        let kind = if whiteout {
            if !regular || flag == b'S' || socket || sparse.is_some() || stored != 0 {
                return Err(invalid("whiteout must be an empty ordinary regular member"));
            }
            if basename == b".wh..wh..opq" {
                EntryKind::Opaque
            } else {
                let target = &basename[4..];
                if target.is_empty() || target == b"." || target == b".." {
                    return Err(invalid("invalid whiteout target basename"));
                }
                EntryKind::Whiteout
            }
        } else if socket {
            EntryKind::Socket
        } else {
            match flag {
                0 | b'0' | b'S' => {
                    let body = if let Some((logical, data, ranges)) = sparse {
                        pack.append(reader, logical, data, Some(ranges))?
                    } else {
                        pack.append(reader, stored, stored, None)?
                    };
                    EntryKind::Regular(body)
                }
                b'5' if path.is_empty() => EntryKind::RootDirectory,
                b'5' => EntryKind::Directory,
                b'1' => EntryKind::Hardlink {
                    target: normalize_path(&target, false, limits)?,
                },
                b'2' => EntryKind::Symlink { target },
                b'3' | b'4' => {
                    let major = value(b"SCHILY.devmajor")
                        .map(|bytes| decimal(bytes, "device major"))
                        .unwrap_or_else(|| number(&block[329..337]))?;
                    let minor = value(b"SCHILY.devminor")
                        .map(|bytes| decimal(bytes, "device minor"))
                        .unwrap_or_else(|| number(&block[337..345]))?;
                    if major > 0xfff
                        || minor > 0xfffff
                        || (flag == b'3' && major == 0 && minor == 0)
                    {
                        return Err(invalid(
                            "device number outside Linux encoding or reserved 0:0",
                        ));
                    }
                    if flag == b'3' {
                        EntryKind::CharacterDevice {
                            major: major as u32,
                            minor: minor as u32,
                        }
                    } else {
                        EntryKind::BlockDevice {
                            major: major as u32,
                            minor: minor as u32,
                        }
                    }
                }
                b'6' => EntryKind::Fifo,
                _ => {
                    return Err(ChangesetError::Unsupported(format!(
                        "tar entry type {flag}"
                    )))
                }
            }
        };
        padding(reader, stored)?;
        reserve_vec(&mut entries, 1)?;
        entries.push(ChangeEntry {
            ordinal: entries.len() as u64,
            path,
            metadata,
            presence,
            kind,
        });
        local = Pax::default();
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use crate::changeset::tar::Pax;
    use crate::changeset::ChangesetLimits;
    use std::io::{BufReader, Seek, SeekFrom, Write};

    #[test]
    fn source_type_mode_bits_are_validated_not_blindly_masked() {
        use crate::changeset::tar::source_permissions;
        use crate::changeset::ChangesetError;
        let types = [
            0o010000, 0o020000, 0o040000, 0o060000, 0o100000, 0o120000, 0o140000,
        ];
        for (flag, expected) in [
            (0, 0o100000),
            (b'0', 0o100000),
            (b'S', 0o100000),
            (b'2', 0o120000),
            (b'3', 0o020000),
            (b'4', 0o060000),
            (b'5', 0o040000),
            (b'6', 0o010000),
        ] {
            assert_eq!(source_permissions(0o6755, flag, false).unwrap(), 0o6755);
            for source_type in types {
                let result = source_permissions(source_type | 0o6755, flag, false);
                if source_type == expected {
                    assert_eq!(result.unwrap(), 0o6755);
                } else {
                    assert!(matches!(
                        result,
                        Err(ChangesetError::Invalid(message))
                            if message == "tar mode type conflicts with member type"
                    ));
                }
            }
        }
        for source_type in types {
            assert_eq!(
                source_permissions(source_type | 0o7777, b'1', false).unwrap(),
                0o7777
            );
        }
        for source_type in [0, 0o100000, 0o140000] {
            assert_eq!(
                source_permissions(source_type | 0o1777, b'0', true).unwrap(),
                0o1777
            );
        }
        for source_type in [0o010000, 0o020000, 0o040000, 0o060000, 0o120000] {
            assert!(source_permissions(source_type | 0o1777, b'0', true).is_err());
        }
        for unknown in [
            0o030000,
            0o050000,
            0o070000,
            0o110000,
            0o130000,
            0o150000,
            0o160000,
            0o170000,
            0o200000,
            1 << 32,
            1 << 63,
            u64::MAX,
        ] {
            assert!(matches!(
                source_permissions(unknown, b'1', false),
                Err(ChangesetError::Invalid(message)) if message == "unknown tar mode bits"
            ));
        }
    }

    #[test]
    fn pax_sparse_csv_larger_than_a_page_and_one_million_ranges_is_streamed() {
        // This is an actual parser-stream test at both former accidental caps,
        // not a 128GiB file or 1TiB ingest benchmark.
        let count = 1_000_001_u64;
        let value_bytes: u64 = (0..count)
            .map(|n| (n * 2).to_string().len() as u64 + 3)
            .sum::<u64>()
            - 1;
        let key = b"GNU.sparse.map";
        let base = key.len() as u64 + value_bytes + 3;
        let mut length = base + 1;
        loop {
            let next = base + length.to_string().len() as u64;
            if next == length {
                break;
            }
            length = next;
        }
        assert!(length > 4 * 1024 * 1024);
        let mut file = tempfile::tempfile().unwrap();
        write!(file, "{length} ").unwrap();
        file.write_all(key).unwrap();
        file.write_all(b"=").unwrap();
        {
            let mut writer = std::io::BufWriter::with_capacity(16 * 1024, &mut file);
            for index in 0..count {
                if index != 0 {
                    writer.write_all(b",").unwrap();
                }
                write!(writer, "{},1", index * 2).unwrap();
            }
            writer.write_all(b"\n").unwrap();
            writer.flush().unwrap();
        }
        let padded = length.div_ceil(512) * 512;
        file.set_len(padded).unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        let mut state = Pax::default();
        state
            .add(
                &mut BufReader::with_capacity(16 * 1024, &mut file),
                length,
                false,
                &ChangesetLimits::default(),
            )
            .unwrap();
        let ranges = state.map.unwrap();
        assert_eq!(ranges.len() as u64, count);
        assert_eq!(ranges.last().unwrap().offset, 2_000_000);
    }

    #[test]
    fn huge_claimed_extension_and_record_lengths_do_not_allocate_the_claim() {
        let limits = ChangesetLimits::default();
        for bytes in [
            b"1099511627776 GNU.sparse.map=0,1\n".as_slice(),
            b"18446744073709551616 path=a\n",
            b"21 path=a\n",
            b"9 x=y",
        ] {
            let mut state = Pax::default();
            let mut source = bytes;
            assert!(state
                .add(&mut source, bytes.len() as u64, false, &limits)
                .is_err());
        }
        let mut state = Pax::default();
        assert!(state
            .add(&mut b"".as_slice(), 1_u64 << 40, false, &limits)
            .is_err());
    }

    #[test]
    fn known_sparse_eof_count_and_data_budgets_reject_before_more_reads() {
        use crate::changeset::tar::{csv_ranges, old_sparse, pax_sparse};
        use crate::changeset::ChangesetError;
        use std::collections::BTreeMap;
        use std::io::Cursor;
        let limits = ChangesetLimits::default();
        let mut block = [0_u8; 512];
        block[386..398].copy_from_slice(b"00000000000\0");
        block[398..410].copy_from_slice(b"00000000001\0");
        block[483..495].copy_from_slice(b"00000000000\0");
        block[482] = 1;
        let mut source = Cursor::new(b"continuation must not be requested");
        let error = old_sparse(&mut source, &block, 1, &limits).unwrap_err();
        assert!(matches!(error, ChangesetError::Invalid(_)));
        assert_eq!(source.position(), 0);
        let values = |logical: &[u8]| {
            BTreeMap::from([
                (b"GNU.sparse.major".to_vec(), b"1".to_vec()),
                (b"GNU.sparse.minor".to_vec(), b"0".to_vec()),
                (b"GNU.sparse.realsize".to_vec(), logical.to_vec()),
            ])
        };
        let mut source = Cursor::new(b"1000000\n");
        let error = pax_sparse(
            &mut source,
            &values(b"0"),
            &mut Pax::default(),
            512,
            &limits,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            ChangesetError::Limit {
                resource: "sparse ranges",
                actual: 1_000_000,
                maximum: 1
            }
        ));
        assert_eq!(source.position(), 8);
        let mut source = Cursor::new(b"2\n11\n1\n");
        let error = pax_sparse(
            &mut source,
            &values(b"10"),
            &mut Pax::default(),
            513,
            &limits,
        )
        .unwrap_err();
        assert!(matches!(error, ChangesetError::Invalid(_)));
        assert_eq!(source.position(), 7);
        let mut source = Cursor::new(b"1\n2\n2\n");
        let error = pax_sparse(
            &mut source,
            &values(b"10"),
            &mut Pax::default(),
            513,
            &limits,
        )
        .unwrap_err();
        assert!(error.to_string().contains("stored body budget"));
        assert_eq!(source.position(), 6);
        let mut map = b"2\n2\n2\n10\n0\n".to_vec();
        map.resize(512, 0);
        map.extend_from_slice(b"AB");
        let mut source = Cursor::new(map);
        let (logical, stored, ranges) = pax_sparse(
            &mut source,
            &values(b"10"),
            &mut Pax::default(),
            514,
            &limits,
        )
        .unwrap()
        .unwrap();
        assert_eq!((logical, stored, ranges.len()), (10, 2, 2));
        assert_eq!(ranges[1].offset, 10);
        assert_eq!(ranges[1].length, 0);
        assert_eq!(source.position(), 512);
        let tight = ChangesetLimits {
            max_file_bytes: 10,
            ..limits
        };
        let mut source = Cursor::new(b"11,1,9,1");
        let error = csv_ranges(&mut source, 8, &tight).unwrap_err();
        assert!(matches!(
            error,
            ChangesetError::Limit {
                resource: "regular file bytes",
                actual: 12,
                maximum: 10
            }
        ));
        assert_eq!(source.position(), 5);
        let mut source = Cursor::new(b"0,1,2,1");
        let ranges = csv_ranges(
            &mut source,
            7,
            &ChangesetLimits {
                max_entries: 1,
                ..limits
            },
        )
        .unwrap();
        assert_eq!(ranges.len(), 2);
    }
}
