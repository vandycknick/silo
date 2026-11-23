use crate::changeset::limits::{MAX_MTIME_SECONDS, MAX_UID};
use std::collections::BTreeMap;
use std::io::Read;

use base64::Engine;

use crate::changeset::{ChangesetError, ChangesetLimits, ChangesetResult, Metadata, Xattr};

fn invalid(message: impl Into<String>) -> ChangesetError {
    ChangesetError::Invalid(message.into())
}

pub(crate) fn decimal(bytes: &[u8], field: &str) -> ChangesetResult<u64> {
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
        return Err(invalid(format!("invalid unsigned {field}")));
    }
    bytes.iter().try_fold(0_u64, |value, digit| {
        value
            .checked_mul(10)
            .and_then(|value| value.checked_add(u64::from(digit - b'0')))
            .ok_or_else(|| invalid(format!("{field} overflows")))
    })
}

pub(crate) fn timestamp(bytes: &[u8]) -> ChangesetResult<(u64, u32)> {
    let mut parts = bytes.splitn(2, |byte| *byte == b'.');
    let seconds = decimal(parts.next().unwrap_or_default(), "mtime")?;
    if seconds > MAX_MTIME_SECONDS {
        return Err(invalid("mtime seconds exceed Linux profile"));
    }
    let mut nanos = 0_u32;
    if let Some(fraction) = parts.next() {
        if fraction.is_empty() || !fraction.iter().all(u8::is_ascii_digit) {
            return Err(invalid("invalid mtime fraction"));
        }
        for index in 0..9 {
            nanos = nanos * 10 + u32::from(fraction.get(index).copied().unwrap_or(b'0') - b'0');
        }
    }
    Ok((seconds, nanos))
}

/// Decode only metadata that has a defined Linux-profile meaning. Unknown
/// security-bearing extensions must not vanish from a supposedly lossless index.
pub(crate) fn pax_attribute(key: &[u8], value: Vec<u8>) -> ChangesetResult<Xattr> {
    let (name, value) = if let Some(name) = key.strip_prefix(b"SCHILY.xattr.") {
        // GNU/libarchive escape selected bytes here, while star emits literal
        // names. The same spelling can therefore name different source attrs.
        for triplet in name.windows(3) {
            if triplet[0] == b'%' {
                if let (Some(high), Some(low)) = (hex_digit(triplet[1]), hex_digit(triplet[2])) {
                    let decoded = high * 16 + low;
                    if !(33..=126).contains(&decoded) || matches!(decoded, b'%' | b'=') {
                        return Err(ChangesetError::Unsupported(
                            "ambiguous escaped SCHILY xattr name".into(),
                        ));
                    }
                }
            }
        }
        (name.to_vec(), value)
    } else if let Some(name) = key.strip_prefix(b"LIBARCHIVE.xattr.") {
        // libarchive's writer omits base64 padding. Also admit the equivalent
        // padded standard alphabet, never base64url or noncanonical tail bits.
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&value)
            .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(&value))
            .map_err(|_| invalid("invalid LIBARCHIVE xattr base64"))?;
        (percent_decode(name)?, decoded)
    } else if key == b"RHT.security.selinux" {
        (b"security.selinux".to_vec(), value)
    } else {
        return Err(ChangesetError::Unsupported(
            "unsupported ACL metadata encoding".into(),
        ));
    };
    xattr_kind(&name)?;
    Ok(Xattr { name, value })
}

fn percent_decode(bytes: &[u8]) -> ChangesetResult<Vec<u8>> {
    let mut result = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let pair = bytes
                .get(index + 1..index + 3)
                .ok_or_else(|| invalid("short xattr name escape"))?;
            let high = hex_digit(pair[0]).ok_or_else(|| invalid("invalid xattr name escape"))?;
            let low = hex_digit(pair[1]).ok_or_else(|| invalid("invalid xattr name escape"))?;
            result.push(high * 16 + low);
            index += 3;
        } else {
            result.push(bytes[index]);
            index += 1;
        }
    }
    Ok(result)
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

pub(crate) fn validate_metadata(
    metadata: &Metadata,
    directory: bool,
    limits: &ChangesetLimits,
) -> ChangesetResult<()> {
    validate_metadata_inner(metadata, directory, true, limits)
}

pub(crate) fn validate_hardlink_metadata(
    metadata: &Metadata,
    limits: &ChangesetLimits,
) -> ChangesetResult<()> {
    validate_metadata_inner(metadata, false, false, limits)
}

fn validate_metadata_inner(
    metadata: &Metadata,
    directory: bool,
    authoritative_mode: bool,
    limits: &ChangesetLimits,
) -> ChangesetResult<()> {
    if u64::from(metadata.uid) > MAX_UID
        || u64::from(metadata.gid) > MAX_UID
        || metadata.mode & !0o7777 != 0
        || metadata.mtime_seconds > MAX_MTIME_SECONDS
        || metadata.mtime_nanos >= 1_000_000_000
    {
        return Err(invalid("metadata outside Linux uid/gid/mode/time profile"));
    }
    let mut previous: Option<&[u8]> = None;
    let encoded = xattr_admission_charge(
        metadata
            .xattrs
            .iter()
            .map(|attr| (attr.name.len() as u64, attr.value.len() as u64)),
    )?;
    for attr in &metadata.xattrs {
        if previous.is_some_and(|previous| previous >= attr.name.as_slice()) {
            return Err(invalid("xattrs are not unique and raw-name sorted"));
        }
        previous = Some(&attr.name);
        validate_xattr(
            &attr.name,
            &attr.value,
            directory,
            authoritative_mode.then_some(metadata.mode),
        )?;
    }
    for (resource, actual, maximum) in [
        (
            "xattrs per inode",
            metadata.xattrs.len() as u64,
            limits.max_xattrs,
        ),
        ("xattr admission charge", encoded, limits.max_xattr_bytes),
    ] {
        if actual > maximum {
            return Err(ChangesetError::Limit {
                resource,
                actual,
                maximum,
            });
        }
    }
    Ok(())
}

/// Conservative representation-neutral admission charge, not a measured ext4
/// or EROFS encoding: nonempty list header 4, per-entry control reserve 16,
/// full raw namespace-qualified name plus one reserved byte rounded to 4,
/// and independently rounded value. Future encoders must prove their own fit.
pub(crate) fn xattr_admission_charge(
    lengths: impl IntoIterator<Item = (u64, u64)>,
) -> ChangesetResult<u64> {
    let mut charge = 0_u64;
    for (name_length, value_length) in lengths {
        if charge == 0 {
            charge = 4;
        }
        let name = 16_u64
            .checked_add(name_length)
            .and_then(|n| n.checked_add(1))
            .ok_or_else(|| invalid("xattr name charge overflow"))?;
        charge = charge
            .checked_add(align4(name)?)
            .and_then(|n| n.checked_add(align4(value_length).ok()?))
            .ok_or_else(|| invalid("xattr admission charge overflow"))?;
    }
    Ok(charge)
}

fn align4(length: u64) -> ChangesetResult<u64> {
    length
        .checked_add(3)
        .map(|n| n & !3)
        .ok_or_else(|| invalid("xattr alignment overflow"))
}

enum XattrKind {
    Opaque,
    AclAccess,
    AclDefault,
    Capability,
    Selinux,
    SmackLabel { execution: bool },
    SmackTransmute,
}

fn xattr_kind(name: &[u8]) -> ChangesetResult<XattrKind> {
    if name.is_empty()
        || name.len() > 255
        || name.contains(&0)
        || name.starts_with(b"trusted.overlay.")
        || name.starts_with(b"user.overlay.")
    {
        return Err(invalid("invalid or reserved xattr name"));
    }
    if name.starts_with(b"user.") || name.starts_with(b"trusted.") {
        if matches!(name, b"user." | b"trusted.") {
            return Err(invalid("empty xattr suffix"));
        }
        return Ok(XattrKind::Opaque);
    }
    match name {
        b"system.posix_acl_access" => Ok(XattrKind::AclAccess),
        b"system.posix_acl_default" => Ok(XattrKind::AclDefault),
        b"security.capability" => Ok(XattrKind::Capability),
        b"security.selinux" => Ok(XattrKind::Selinux),
        b"security.SMACK64" => Ok(XattrKind::SmackLabel { execution: false }),
        b"security.SMACK64EXEC" | b"security.SMACK64MMAP" => {
            Ok(XattrKind::SmackLabel { execution: true })
        }
        b"security.SMACK64TRANSMUTE" => Ok(XattrKind::SmackTransmute),
        _ => Err(ChangesetError::Unsupported(
            "xattr namespace/security attribute".into(),
        )),
    }
}

fn validate_xattr(
    name: &[u8],
    value: &[u8],
    directory: bool,
    mode: Option<u32>,
) -> ChangesetResult<()> {
    match xattr_kind(name)? {
        XattrKind::Opaque => Ok(()),
        XattrKind::AclAccess => validate_acl(value, mode),
        XattrKind::AclDefault if directory => validate_acl(value, None),
        XattrKind::AclDefault => Err(invalid("default ACL on non-directory")),
        XattrKind::Capability => validate_capability(value),
        XattrKind::Selinux => {
            if value.is_empty() {
                return Err(invalid("empty SELinux context"));
            }
            Ok(())
        }
        XattrKind::SmackLabel { execution } => {
            validate_smack_label(value)?;
            if execution && matches!(value, b"*" | b"@") {
                return Err(invalid("SMACK EXEC/MMAP special label is not meaningful"));
            }
            Ok(())
        }
        XattrKind::SmackTransmute => {
            if directory && value == b"TRUE" {
                Ok(())
            } else {
                Err(invalid(
                    "SMACK transmute requires a directory and exactly TRUE",
                ))
            }
        }
    }
}

fn validate_smack_label(value: &[u8]) -> ChangesetResult<()> {
    // Admit only the exact bytes Linux consumes, with no terminator or suffix
    // that smk_parse_smack would trim. SELinux contexts are policy-opaque.
    if value.is_empty()
        || value.len() >= 256
        || value[0] == b'-'
        || value
            .iter()
            .any(|byte| !(33..=126).contains(byte) || matches!(*byte, b'/' | b'\"' | b'\\' | b'\''))
    {
        return Err(invalid("invalid or truncated Linux SMACK label"));
    }
    Ok(())
}

fn le32(bytes: &[u8]) -> ChangesetResult<u32> {
    let array: [u8; 4] = bytes
        .try_into()
        .map_err(|_| invalid("truncated metadata integer"))?;
    Ok(u32::from_le_bytes(array))
}

fn validate_capability(bytes: &[u8]) -> ChangesetResult<()> {
    let magic = le32(
        bytes
            .get(..4)
            .ok_or_else(|| invalid("truncated capabilities"))?,
    )?;
    let expected = match magic & 0xff00_0000 {
        0x0100_0000 => 12,
        0x0200_0000 => 20,
        0x0300_0000 => 24,
        _ => return Err(ChangesetError::Unsupported("capability revision".into())),
    };
    if bytes.len() != expected || magic & 0x00ff_fffe != 0 {
        return Err(invalid("invalid capability size or flags"));
    }
    // The selected Linux profile has CAP_LAST_CAP=40. Reject bits that the
    // guest cannot represent rather than quietly installing a weaker set.
    if expected >= 20 && (le32(&bytes[12..16])? | le32(&bytes[16..20])?) & !0x1ff != 0 {
        return Err(ChangesetError::Unsupported(
            "capability outside selected Linux profile".into(),
        ));
    }
    if expected == 24 && le32(&bytes[20..24])? == u32::MAX {
        return Err(invalid("invalid capability root ID"));
    }
    Ok(())
}

fn validate_acl(bytes: &[u8], mode: Option<u32>) -> ChangesetResult<()> {
    if bytes.len() < 28 || !(bytes.len() - 4).is_multiple_of(8) || le32(&bytes[..4])? != 2 {
        return Err(invalid("malformed POSIX ACL"));
    }
    let mut last = (0_u16, 0_u32);
    let mut owner = None;
    let mut group = None;
    let mut mask = None;
    let mut other = None;
    let mut named = false;
    for record in bytes[4..].chunks_exact(8) {
        let tag = u16::from_le_bytes([record[0], record[1]]);
        let permission = u16::from_le_bytes([record[2], record[3]]);
        let id = le32(&record[4..])?;
        if permission > 7 || !matches!(tag, 1 | 2 | 4 | 8 | 16 | 32) || (tag, id) <= last {
            return Err(invalid("invalid ACL tag/order/permission"));
        }
        last = (tag, id);
        if matches!(tag, 2 | 8) {
            if id == u32::MAX {
                return Err(invalid("ACL named entry lacks numeric ID"));
            }
            named = true;
        } else if id != u32::MAX {
            return Err(invalid("ACL object entry has named ID"));
        }
        match tag {
            1 => owner = Some(permission),
            4 => group = Some(permission),
            16 => mask = Some(permission),
            32 => other = Some(permission),
            _ => {}
        }
    }
    let (Some(owner), Some(group), Some(other)) = (owner, group, other) else {
        return Err(invalid("ACL lacks required object entries"));
    };
    if named && mask.is_none() {
        return Err(invalid("extended ACL lacks mask"));
    }
    if let Some(mode) = mode {
        if u32::from(owner) != (mode >> 6) & 7
            || u32::from(mask.unwrap_or(group)) != (mode >> 3) & 7
            || u32::from(other) != mode & 7
        {
            return Err(invalid("ACL conflicts with permission mode"));
        }
    }
    Ok(())
}

#[cfg(test)]
fn textual_acl(bytes: &[u8]) -> ChangesetResult<Vec<u8>> {
    let mut source = bytes;
    textual_acl_stream(&mut source, bytes.len() as u64, &ChangesetLimits::default())
}

#[derive(Default)]
struct AclRecord {
    kind: Vec<u8>,
    principal_present: bool,
    principal_number: u64,
    principal_numeric: bool,
    principal_overflow: bool,
    permissions: Vec<u8>,
    identifier: u64,
    identifier_present: bool,
    field: u8,
}

impl AclRecord {
    fn finish(
        &self,
        entries: &mut BTreeMap<(u16, u32), u16>,
        limits: &ChangesetLimits,
    ) -> ChangesetResult<()> {
        if self.kind.is_empty() && self.field == 0 {
            return Ok(());
        }
        if !matches!(self.field, 2 | 3) {
            return Err(invalid("malformed textual ACL"));
        }
        let tag = match self.kind.as_slice() {
            b"user" | b"u" if !self.principal_present => 1_u16,
            b"user" | b"u" => 2,
            b"group" | b"g" if !self.principal_present => 4,
            b"group" | b"g" => 8,
            b"mask" | b"m" if !self.principal_present => 16,
            b"other" | b"o" if !self.principal_present => 32,
            _ => return Err(invalid("unsupported textual ACL principal")),
        };
        let id = if matches!(tag, 2 | 8) {
            if self.principal_numeric
                && (self.principal_overflow || self.principal_number > MAX_UID)
            {
                return Err(invalid("ACL numeric principal outside Linux profile"));
            }
            let value = if self.field == 3 && self.identifier_present {
                if self.principal_numeric && self.principal_number != self.identifier {
                    return Err(invalid("conflicting textual ACL numeric IDs"));
                }
                self.identifier
            } else if self.field == 2 && self.principal_numeric {
                self.principal_number
            } else {
                return Err(invalid("textual ACL principal requires numeric ID"));
            };
            if value > MAX_UID {
                return Err(invalid("ACL ID outside Linux profile"));
            }
            value as u32
        } else {
            if self.field != 2 {
                return Err(invalid("ACL object entry has redundant numeric ID"));
            }
            u32::MAX
        };
        let permissions = &self.permissions;
        if permissions.len() != 3
            || !matches!(permissions[0], b'r' | b'-')
            || !matches!(permissions[1], b'w' | b'-')
            || !matches!(permissions[2], b'x' | b'-')
        {
            return Err(invalid("invalid textual ACL permissions"));
        }
        let permission = u16::from(permissions[0] == b'r') * 4
            + u16::from(permissions[1] == b'w') * 2
            + u16::from(permissions[2] == b'x');
        if entries.contains_key(&(tag, id)) {
            return Err(invalid("duplicate textual ACL principal"));
        }
        let encoded = (entries.len() as u64 + 1)
            .checked_mul(8)
            .and_then(|n| n.checked_add(4))
            .ok_or_else(|| invalid("ACL size overflow"))?;
        if encoded > limits.max_xattr_bytes {
            return Err(ChangesetError::Limit {
                resource: "binary ACL bytes",
                actual: encoded,
                maximum: limits.max_xattr_bytes,
            });
        }
        entries.insert((tag, id), permission);
        Ok(())
    }
}

/// Numeric identities are authoritative. The optional fourth SCHILY field
/// supplies an ID when its advisory textual name is not numeric. Such names
/// are streamed, not resolved against host accounts or buffered unboundedly.
pub(crate) fn textual_acl_stream(
    reader: &mut impl Read,
    length: u64,
    limits: &ChangesetLimits,
) -> ChangesetResult<Vec<u8>> {
    let mut entries = BTreeMap::new();
    let mut record = AclRecord {
        principal_numeric: true,
        ..AclRecord::default()
    };
    for _ in 0..length {
        let mut item = [0];
        reader.read_exact(&mut item)?;
        match item[0] {
            b',' | b'\n' => {
                record.finish(&mut entries, limits)?;
                record = AclRecord {
                    principal_numeric: true,
                    ..AclRecord::default()
                };
            }
            b':' => {
                if record.field >= 3 {
                    return Err(invalid("too many textual ACL fields"));
                }
                record.field += 1;
            }
            item => match record.field {
                0 => {
                    if record.kind.len() >= 5 {
                        return Err(invalid("invalid ACL tag"));
                    }
                    record.kind.push(item);
                }
                1 => {
                    record.principal_present = true;
                    if item.is_ascii_digit() {
                        if !record.principal_overflow {
                            if let Some(number) = record
                                .principal_number
                                .checked_mul(10)
                                .and_then(|n| n.checked_add(u64::from(item - b'0')))
                            {
                                record.principal_number = number;
                            } else {
                                record.principal_overflow = true;
                            }
                        }
                    } else {
                        record.principal_numeric = false;
                    }
                }
                2 => {
                    if record.permissions.len() >= 3 {
                        return Err(invalid("invalid ACL permissions"));
                    }
                    record.permissions.push(item);
                }
                3 => {
                    if !item.is_ascii_digit() {
                        return Err(invalid("nonnumeric explicit ACL ID"));
                    }
                    record.identifier_present = true;
                    record.identifier = record
                        .identifier
                        .checked_mul(10)
                        .and_then(|n| n.checked_add(u64::from(item - b'0')))
                        .ok_or_else(|| invalid("ACL ID overflow"))?;
                }
                _ => return Err(invalid("invalid ACL field")),
            },
        }
    }
    record.finish(&mut entries, limits)?;
    let mut result = 2_u32.to_le_bytes().to_vec();
    for ((tag, id), permission) in entries {
        result.extend(tag.to_le_bytes());
        result.extend(permission.to_le_bytes());
        result.extend(id.to_le_bytes());
    }
    validate_acl(&result, None)?;
    Ok(result)
}

pub(crate) fn sorted_xattrs(attrs: BTreeMap<Vec<u8>, Vec<u8>>) -> Vec<Xattr> {
    attrs
        .into_iter()
        .map(|(name, value)| Xattr { name, value })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::changeset::metadata::{textual_acl, timestamp, validate_metadata};
    use crate::changeset::{ChangesetLimits, Metadata, Xattr};

    fn metadata() -> Metadata {
        Metadata {
            uid: 0,
            gid: 0,
            mode: 0o6755,
            mtime_seconds: 0,
            mtime_nanos: 0,
            xattrs: vec![],
        }
    }

    #[test]
    fn timestamps_preserve_nanoseconds_without_floating_point() {
        assert_eq!(
            timestamp(b"15032385535.9999999999").unwrap(),
            (15032385535, 999999999)
        );
        assert_eq!(timestamp(b"1.1234567899").unwrap(), (1, 123456789));
        for value in [b"-1".as_slice(), b"15032385536", b"1.", b"1.2x"] {
            assert!(timestamp(value).is_err());
        }
    }

    #[test]
    fn acl_mode_capability_and_reserved_metadata_are_validated() {
        let mut item = metadata();
        item.xattrs.push(Xattr {
            name: b"system.posix_acl_access".to_vec(),
            value: textual_acl(b"user::rwx,group::r-x,other::r-x").unwrap(),
        });
        validate_metadata(&item, false, &ChangesetLimits::default()).unwrap();
        item.mode = 0o700;
        assert!(validate_metadata(&item, false, &ChangesetLimits::default()).is_err());
        for name in [
            b"user.overlay.opaque".as_slice(),
            b"trusted.overlay.x",
            b"security.ima",
            b"system.nfs4_acl",
            b"security.capability",
        ] {
            let mut item = metadata();
            item.xattrs.push(Xattr {
                name: name.to_vec(),
                value: b"bad".to_vec(),
            });
            assert!(validate_metadata(&item, false, &ChangesetLimits::default()).is_err());
        }
        assert!(textual_acl(b"user:nobody:rwx,group::r-x,other::r-x").is_err());
    }

    #[test]
    fn encoded_xattr_limits_count_names_headers_and_alignment() {
        let mut item = metadata();
        item.xattrs.push(Xattr {
            name: b"user.a".to_vec(),
            value: vec![0; 3044],
        });
        validate_metadata(&item, false, &ChangesetLimits::default()).unwrap();
        item.xattrs[0].value.push(0);
        assert!(validate_metadata(&item, false, &ChangesetLimits::default()).is_err());
        item.xattrs = (0..64)
            .map(|n| Xattr {
                name: format!("user.{n:02}").into_bytes(),
                value: vec![],
            })
            .collect();
        validate_metadata(&item, false, &ChangesetLimits::default()).unwrap();
        item.xattrs.push(Xattr {
            name: b"user.64".to_vec(),
            value: vec![],
        });
        assert!(validate_metadata(&item, false, &ChangesetLimits::default()).is_err());
    }

    #[test]
    fn admission_charge_has_independent_modulo_four_and_overflow_table() {
        use crate::changeset::metadata::xattr_admission_charge;
        assert_eq!(xattr_admission_charge([]).unwrap(), 0);
        // Rows are independently tabulated full-name lengths5/6/7/8; columns
        // are value lengths0/1/2/3/4/5, including every modulo4 transition.
        let expected = [
            [28, 32, 32, 32, 32, 36],
            [28, 32, 32, 32, 32, 36],
            [28, 32, 32, 32, 32, 36],
            [32, 36, 36, 36, 36, 40],
        ];
        for (row, name) in [5, 6, 7, 8].into_iter().enumerate() {
            for (column, value) in [0, 1, 2, 3, 4, 5].into_iter().enumerate() {
                assert_eq!(
                    xattr_admission_charge([(name, value)]).unwrap(),
                    expected[row][column]
                );
            }
        }
        assert_eq!(xattr_admission_charge([(255, 0)]).unwrap(), 276);
        assert_eq!(xattr_admission_charge([(255, 1)]).unwrap(), 280);
        assert_eq!(xattr_admission_charge([(5, 0), (5, 0)]).unwrap(), 52);
        assert_eq!(xattr_admission_charge([(5, 1), (8, 5)]).unwrap(), 68);
        assert!(xattr_admission_charge([(u64::MAX, 0)]).is_err());
        assert!(xattr_admission_charge([(5, u64::MAX)]).is_err());
        assert!(xattr_admission_charge([(0, u64::MAX - 27), (0, 0)]).is_err());
        let mut item = metadata();
        item.xattrs = vec![Xattr {
            name: b"user.a".to_vec(),
            value: vec![0; 3044],
        }];
        assert_eq!(xattr_admission_charge([(6, 3044)]).unwrap(), 3072);
        let tight = ChangesetLimits {
            max_xattr_bytes: 3071,
            ..ChangesetLimits::default()
        };
        assert!(matches!(
            validate_metadata(&item, false, &tight),
            Err(crate::changeset::ChangesetError::Limit {
                actual: 3072,
                maximum: 3071,
                ..
            })
        ));
        item.xattrs = vec![
            Xattr {
                name: b"user.a".to_vec(),
                value: vec![0; 1512],
            },
            Xattr {
                name: b"user.b".to_vec(),
                value: vec![0; 1512],
            },
        ];
        assert!(matches!(
            validate_metadata(&item, false, &ChangesetLimits::default()),
            Err(crate::changeset::ChangesetError::Limit { actual: 3076, .. })
        ));
    }

    #[test]
    fn direct_smack_metadata_rejects_trimmed_or_inapplicable_values() {
        for (name, value, directory, accepted) in [
            (b"security.SMACK64".as_slice(), b"*".as_slice(), false, true),
            (b"security.SMACK64", b"@", false, true),
            (b"security.SMACK64EXEC", b"*", false, false),
            (b"security.SMACK64MMAP", b"@", false, false),
            (b"security.SMACK64", b"alpha beta", false, false),
            (b"security.SMACK64", b"alpha\0", false, false),
            (b"security.SMACK64TRANSMUTE", b"TRUE", false, false),
            (b"security.SMACK64TRANSMUTE", b"TRUE", true, true),
            (b"security.SMACK64TRANSMUTE", b"TRUE\0", true, false),
        ] {
            let mut item = metadata();
            item.xattrs = vec![Xattr {
                name: name.to_vec(),
                value: value.to_vec(),
            }];
            assert_eq!(
                validate_metadata(&item, directory, &ChangesetLimits::default()).is_ok(),
                accepted
            );
        }
    }
}
