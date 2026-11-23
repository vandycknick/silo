use std::fs::File;

use sha2::{Digest, Sha256};

use crate::changeset::namespace::NamespaceKind;
use crate::changeset::ContentDigest;
use crate::erofs::plan::{directory_group, inode_union, mode, payload, xattr_name, Plan, Record};
use crate::erofs::{
    add, align, crc32c, invalid, read_at, zero_region, zeros, EncodedFsmeta, Layer, Result, BLOCK,
    BLOCK_SIZE, IO_SIZE,
};

fn field<const N: usize>(bytes: &[u8], at: usize) -> Result<[u8; N]> {
    bytes
        .get(
            at..at
                .checked_add(N)
                .ok_or_else(|| invalid("field offset overflow"))?,
        )
        .ok_or_else(|| invalid("truncated disk field"))?
        .try_into()
        .map_err(|_| invalid("disk field width"))
}
fn le16(bytes: &[u8], at: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(field(bytes, at)?))
}
fn le32(bytes: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(field(bytes, at)?))
}
fn le64(bytes: &[u8], at: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(field(bytes, at)?))
}
fn require(condition: bool, message: &str) -> Result<()> {
    if !condition {
        return Err(invalid(message));
    }
    Ok(())
}

pub(crate) fn validate(
    file: &File,
    plan: &Plan<'_>,
    layers: &[Layer<'_>],
) -> Result<EncodedFsmeta> {
    require(
        file.metadata()?.len() == plan.length,
        "noncanonical fsmeta length",
    )?;
    let mut block = [0; BLOCK];
    read_at(file, &mut block, 0)?;
    zeros(&block[..1024])?;
    let expected_crc = le32(&block, 1028)?;
    block[1028..1032].fill(0);
    require(
        crc32c(&block[1024..]) == expected_crc,
        "superblock CRC32C mismatch",
    )?;
    let sb = &block[1024..1152];
    require(
        le32(sb, 0)? == 0xe0f5e1e2
            && le32(sb, 8)? == 3
            && sb[12] == 12
            && sb[13] == 0
            && le16(sb, 14)? == 0,
        "unsupported superblock profile",
    )?;
    require(
        le64(sb, 16)? == plan.records.len() as u64,
        "inode count mismatch",
    )?;
    zeros(&sb[24..36])?;
    require(
        u64::from(le32(sb, 36)?) * BLOCK_SIZE == plan.length
            && u64::from(le32(sb, 40)?) * BLOCK_SIZE == plan.meta,
        "superblock size or metadata address mismatch",
    )?;
    require(
        le32(sb, 44)? == 0 && sb[48..64] == plan.uuid && le32(sb, 80)? == 12,
        "superblock UUID or feature mismatch",
    )?;
    zeros(&sb[64..80])?;
    zeros(&sb[84..86])?;
    require(
        usize::from(le16(sb, 86)?) == layers.len()
            && le16(sb, 88)? == if layers.is_empty() { 0 } else { 32 },
        "device table count or location mismatch",
    )?;
    zeros(&sb[90..])?;
    zeros(&block[1152..])?;
    for (i, range) in plan.ranges.iter().enumerate() {
        let mut slot = [0; 128];
        read_at(file, &mut slot, BLOCK_SIZE + i as u64 * 128)?;
        // Decode the tag rather than forgiving NULs, uppercase or prefixes.
        let mut digest = [0; 32];
        for (target, pair) in digest.iter_mut().zip(slot[..64].chunks_exact(2)) {
            let digit = |b| match b {
                b'0'..=b'9' => Ok(b - b'0'),
                b'a'..=b'f' => Ok(b - b'a' + 10),
                _ => Err(invalid("noncanonical device tag")),
            };
            *target = digit(pair[0])? * 16 + digit(pair[1])?;
        }
        require(
            &digest == range.stream.as_bytes()
                && u64::from(le32(&slot, 64)?) * BLOCK_SIZE == range.length
                && u64::from(le32(&slot, 68)?) * BLOCK_SIZE == range.offset,
            "device slot identity, order or range mismatch",
        )?;
        zeros(&slot[72..])?;
    }
    zero_region(file, BLOCK_SIZE + layers.len() as u64 * 128, plan.meta)?;
    for (ordinal, record) in plan.records.iter().enumerate() {
        validate_inode(file, record, ordinal)?;
        validate_xattrs(file, record)?;
        let body_end = add(add(record.offset, 64)?, record.xattr_size)?;
        let end = if let NamespaceKind::Regular { body } = &record.inode.kind {
            zero_region(file, body_end, record.index_start)?;
            let (pack, _) = payload(layers, body)?;
            let mut bytes = [0; IO_SIZE];
            let mut indexes = [0; IO_SIZE / BLOCK * 8];
            let chunks = body.length.div_ceil(BLOCK_SIZE);
            let mut chunk = 0;
            while chunk < chunks {
                let count = (chunks - chunk).min((IO_SIZE / BLOCK) as u64) as usize;
                read_at(
                    file,
                    &mut indexes[..count * 8],
                    record.index_start + chunk * 8,
                )?;
                read_at(
                    pack,
                    &mut bytes[..count * BLOCK],
                    body.pack_offset + chunk * BLOCK_SIZE,
                )?;
                for (i, index) in indexes[..count * 8].chunks_exact(8).enumerate() {
                    let device = le16(index, 2)?;
                    let address = le32(index, 4)?;
                    require(le16(index, 0)? == 0, "nonzero chunk reserved field")?;
                    let data = &bytes[i * BLOCK..(i + 1) * BLOCK];
                    if data.iter().all(|b| *b == 0) {
                        require(
                            device == 0 && address == u32::MAX,
                            "noncanonical zero chunk",
                        )?;
                    } else {
                        require(
                            u32::from(device) == body.entry.layer + 1
                                && u64::from(address)
                                    == body.pack_offset / BLOCK_SIZE + chunk + i as u64
                                && address != u32::MAX,
                            "chunk does not address its original body and occurrence",
                        )?;
                        let range = plan
                            .ranges
                            .get(usize::from(device) - 1)
                            .ok_or_else(|| invalid("undeclared chunk device"))?;
                        require(
                            (u64::from(address) + 1) * BLOCK_SIZE <= range.length,
                            "chunk exceeds owning pack",
                        )?;
                    }
                }
                chunk += count as u64;
            }
            add(record.index_start, chunks * 8)?
        } else {
            body_end
        };
        zero_region(file, end, record.end)?;
    }
    let metadata_end = plan
        .records
        .last()
        .ok_or_else(|| invalid("missing root inode"))?
        .end;
    zero_region(file, metadata_end, plan.data_start)?;
    for record in &plan.records {
        match &record.inode.kind {
            NamespaceKind::Directory => validate_directory(file, plan, record)?,
            NamespaceKind::Symlink { target } => {
                let mut bytes = [0; BLOCK];
                let mut at = 0;
                while at < target.len() {
                    let count = (target.len() - at).min(BLOCK);
                    read_at(file, &mut bytes[..count], record.data + at as u64)?;
                    require(
                        bytes[..count] == target[at..at + count],
                        "symlink target mismatch",
                    )?;
                    at += count;
                }
                zero_region(
                    file,
                    add(record.data, record.size)?,
                    add(record.data, align(record.size, BLOCK_SIZE)?)?,
                )?;
            }
            _ => {}
        }
    }
    let mut hash = Sha256::new();
    let mut buffer = [0; IO_SIZE];
    let mut at = 0;
    while at < plan.length {
        let count = (plan.length - at).min(IO_SIZE as u64) as usize;
        read_at(file, &mut buffer[..count], at)?;
        hash.update(&buffer[..count]);
        at += count as u64;
    }
    Ok(EncodedFsmeta {
        digest: ContentDigest::from_sha256(hash.finalize().into()),
        length: plan.length,
        uuid: plan.uuid,
        device_ranges: plan.ranges.clone(),
    })
}

fn validate_inode(file: &File, record: &Record<'_>, ordinal: usize) -> Result<()> {
    let mut bytes = [0; 64];
    read_at(file, &mut bytes, record.offset)?;
    let format = if matches!(record.inode.kind, NamespaceKind::Regular { .. }) {
        9
    } else {
        1
    };
    require(
        le16(&bytes, 0)? == format && le16(&bytes, 4)? == mode(record.inode),
        "inode format or type mismatch",
    )?;
    let count = u64::from(le16(&bytes, 2)?);
    let xattr_size = if count == 0 { 0 } else { 8 + count * 4 };
    require(
        xattr_size == record.xattr_size && count != 1,
        "invalid inline xattr count",
    )?;
    zeros(&bytes[6..8])?;
    require(
        le64(&bytes, 8)? == record.size
            && le32(&bytes, 16)? == inode_union(record)?
            && u64::from(le32(&bytes, 20)?) == ordinal as u64 + 1,
        "inode size, mapping or ordinal mismatch",
    )?;
    let metadata = &record.inode.metadata;
    require(
        le32(&bytes, 24)? == metadata.uid
            && le32(&bytes, 28)? == metadata.gid
            && le64(&bytes, 32)? == metadata.mtime_seconds
            && le32(&bytes, 40)? == metadata.mtime_nanos
            && le32(&bytes, 44)? == record.nlink,
        "inode ownership, timestamp or link count mismatch",
    )?;
    zeros(&bytes[48..])
}

fn validate_xattrs(file: &File, record: &Record<'_>) -> Result<()> {
    if record.xattr_size == 0 {
        return Ok(());
    }
    let mut buffer = [0; 3072];
    let size = record.xattr_size as usize;
    read_at(file, &mut buffer[..size], record.offset + 64)?;
    let bytes = &buffer[..size];
    zeros(&bytes[..12])?;
    let mut cursor = 12;
    let mut previous: Option<&[u8]> = None;
    for expected in &record.inode.metadata.xattrs {
        let suffix_length = usize::from(
            *bytes
                .get(cursor)
                .ok_or_else(|| invalid("truncated xattr header"))?,
        );
        let index = *bytes
            .get(cursor + 1)
            .ok_or_else(|| invalid("truncated xattr header"))?;
        let value_length = usize::from(le16(bytes, cursor + 2)?);
        let name_end = cursor + 4 + suffix_length;
        let value_end = name_end + value_length;
        let end = align(value_end as u64, 4)? as usize;
        require(end <= size, "xattr exceeds inline body")?;
        let (expected_index, suffix) = xattr_name(&expected.name)?;
        require(
            index == expected_index
                && bytes[cursor + 4..name_end] == *suffix
                && bytes[name_end..value_end] == expected.value,
            "xattr name, order or value mismatch",
        )?;
        require(
            previous.is_none_or(|name| name < expected.name.as_slice()),
            "xattrs not strictly byte ordered",
        )?;
        previous = Some(&expected.name);
        zeros(&bytes[value_end..end])?;
        cursor = end;
    }
    require(cursor == size, "extra inline xattr entries")
}

fn validate_directory(file: &File, plan: &Plan<'_>, record: &Record<'_>) -> Result<()> {
    let mut entries = plan.directory(record.id)?;
    let mut logical = 0;
    let mut block = [0; BLOCK];
    let mut previous = [0; 255];
    let mut previous_length = 0;
    loop {
        require(logical < record.size, "directory block exceeds inode size")?;
        read_at(file, &mut block, record.data + logical)?;
        let first = usize::from(le16(&block, 8)?);
        require(
            first != 0 && first % 12 == 0 && first < BLOCK,
            "invalid first directory name offset",
        )?;
        let count = first / 12;
        let (expected_count, expected_used) = directory_group(entries.clone());
        require(count == expected_count, "noncanonical directory partition")?;
        let mut used = first;
        for i in 0..count {
            let at = i * 12;
            let name_start = usize::from(le16(&block, at + 8)?);
            let name_end = if i + 1 < count {
                usize::from(le16(&block, at + 20)?)
            } else {
                require(name_start < BLOCK, "directory name offset exceeds block")?;
                name_start
                    + block[name_start..]
                        .iter()
                        .position(|b| *b == 0)
                        .map_or(BLOCK - name_start, |length| length)
            };
            require(
                name_start == used
                    && name_start < name_end
                    && name_end <= BLOCK
                    && name_end - name_start <= 255,
                "invalid directory name bounds",
            )?;
            let name = &block[name_start..name_end];
            require(
                !name.contains(&0)
                    && !name.contains(&b'/')
                    && (previous_length == 0 || &previous[..previous_length] < name),
                "directory names not strictly ordered",
            )?;
            let expected = entries
                .next()
                .ok_or_else(|| invalid("extra directory entry"))?;
            require(
                name == expected.name
                    && le64(&block, at)? == plan.record(expected.id)?.nid
                    && block[at + 10] == expected.file_type
                    && block[at + 11] == 0,
                "directory target, type, dots or raw name mismatch",
            )?;
            previous[..name.len()].copy_from_slice(name);
            previous_length = name.len();
            used = name_end;
        }
        require(used == expected_used, "directory packing mismatch")?;
        zeros(&block[used..])?;
        logical = add(logical, BLOCK_SIZE)?;
        if entries.clone().next().is_none() {
            return require(
                record.size == logical - BLOCK_SIZE + used as u64,
                "directory logical size mismatch",
            );
        }
    }
}
