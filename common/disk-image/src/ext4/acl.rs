//! Linux xattr ABI (version 2, eight-byte entries) versus ext4 ACL storage
//! (version 1, four-byte base entries and eight-byte named entries).
//! Layout follows Linux fs/ext4/acl.c and include/uapi/linux/posix_acl_xattr.h.

use crate::ext4::error::FormatError;

fn invalid() -> FormatError {
    FormatError::MalformedAcl
}

pub(crate) fn to_disk(value: &[u8]) -> Result<Vec<u8>, FormatError> {
    if value.len() < 4 || value[..4] != 2u32.to_le_bytes() || (value.len() - 4) % 8 != 0 {
        return Err(invalid());
    }
    let mut out = Vec::with_capacity(value.len());
    out.extend_from_slice(&1u32.to_le_bytes());
    let mut stage = 0;
    let mut named = false;
    let mut mask = false;
    let mut previous_id = None;
    for entry in value[4..].chunks_exact(8) {
        let tag = u16::from_le_bytes([entry[0], entry[1]]);
        let perm = u16::from_le_bytes([entry[2], entry[3]]);
        let id = u32::from_le_bytes([entry[4], entry[5], entry[6], entry[7]]);
        if perm > 7 {
            return Err(invalid());
        }
        match tag {
            1 if stage == 0 && id == u32::MAX => stage = 1,
            2 if stage == 1 && id != u32::MAX => {
                if previous_id.is_some_and(|previous| previous >= id) {
                    return Err(invalid());
                }
                previous_id = Some(id);
                named = true;
            }
            4 if stage == 1 && id == u32::MAX => {
                stage = 2;
                previous_id = None;
            }
            8 if stage == 2 && id != u32::MAX => {
                if previous_id.is_some_and(|previous| previous >= id) {
                    return Err(invalid());
                }
                previous_id = Some(id);
                named = true;
            }
            16 if stage == 2 && id == u32::MAX => {
                stage = 3;
                mask = true;
            }
            32 if (stage == 2 || stage == 3) && id == u32::MAX => stage = 4,
            _ => return Err(invalid()),
        }
        out.extend_from_slice(&entry[..4]);
        if tag == 2 || tag == 8 {
            out.extend_from_slice(&entry[4..]);
        }
    }
    if stage != 4 || (named && !mask) {
        return Err(invalid());
    }
    Ok(out)
}

pub(crate) fn to_linux(value: &[u8]) -> Result<Vec<u8>, FormatError> {
    if value.len() < 4 || value[..4] != 1u32.to_le_bytes() {
        return Err(invalid());
    }
    let mut out = Vec::with_capacity(value.len() * 2);
    out.extend_from_slice(&2u32.to_le_bytes());
    let mut cursor = 4;
    while cursor < value.len() {
        let short = value.get(cursor..cursor + 4).ok_or_else(invalid)?;
        let tag = u16::from_le_bytes([short[0], short[1]]);
        out.extend_from_slice(short);
        cursor += 4;
        if tag == 2 || tag == 8 {
            out.extend_from_slice(value.get(cursor..cursor + 4).ok_or_else(invalid)?);
            cursor += 4;
        } else {
            out.extend_from_slice(&u32::MAX.to_le_bytes());
        }
    }
    // The same semantic validation rejects unknown tags, invalid IDs/permissions
    // and malformed entry order on both sides of the boundary.
    to_disk(&out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use crate::ext4::acl::{to_disk, to_linux};

    #[test]
    fn linux_v2_acl_becomes_ext4_v1_without_base_ids() {
        let mut linux = 2u32.to_le_bytes().to_vec();
        for (tag, perm, id) in [
            (1u16, 7u16, u32::MAX),
            (2, 5, 1001),
            (4, 5, u32::MAX),
            (8, 4, 1002),
            (16, 5, u32::MAX),
            (32, 0, u32::MAX),
        ] {
            linux.extend_from_slice(&tag.to_le_bytes());
            linux.extend_from_slice(&perm.to_le_bytes());
            linux.extend_from_slice(&id.to_le_bytes());
        }
        let disk = to_disk(&linux).unwrap();
        assert_eq!(&disk[..4], &1u32.to_le_bytes());
        assert_eq!(disk.len(), 36);
        assert_eq!(&disk[4..8], &[1, 0, 7, 0]);
        assert_eq!(&disk[8..16], &[2, 0, 5, 0, 233, 3, 0, 0]);
        assert_eq!(to_linux(&disk).unwrap(), linux);
        assert!(to_disk(&disk).is_err());
        assert!(to_linux(&linux).is_err());
        let mut bad = linux.clone();
        bad[6] = 8;
        assert!(to_disk(&bad).is_err());
        assert!(to_disk(&linux[..linux.len() - 1]).is_err());
    }
}
