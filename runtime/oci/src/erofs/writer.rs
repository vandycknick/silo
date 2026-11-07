use std::fs::File;
use std::io::{BufWriter, Seek, SeekFrom, Write};

use sha2::{Digest, Sha256};

use crate::changeset::namespace::NamespaceKind;
use crate::changeset::ContentDigest;
use crate::erofs::plan::{directory_group, inode_union, mode, payload, xattr_name, Plan, Record};
use crate::erofs::{
    add, align, crc32c, invalid, read_at, u32_field, EncodedFsmeta, Layer, Result, BLOCK,
    BLOCK_SIZE, IO_SIZE,
};

struct Output<'a> {
    file: BufWriter<&'a mut File>,
    hash: Sha256,
    offset: u64,
}
impl Output<'_> {
    fn bytes(&mut self, bytes: &[u8]) -> Result<()> {
        self.file.write_all(bytes)?;
        self.hash.update(bytes);
        self.offset = add(self.offset, bytes.len() as u64)?;
        Ok(())
    }
    fn pad_to(&mut self, end: u64) -> Result<()> {
        if self.offset > end {
            return Err(invalid("encoder allocation overlap"));
        }
        let zeros = [0; BLOCK];
        while self.offset < end {
            let length = (end - self.offset).min(BLOCK_SIZE) as usize;
            self.bytes(&zeros[..length])?;
        }
        Ok(())
    }
}

pub(crate) fn encode(
    plan: &Plan<'_>,
    layers: &[Layer<'_>],
    file: &mut File,
) -> Result<EncodedFsmeta> {
    file.set_len(0)?;
    file.seek(SeekFrom::Start(0))?;
    let mut out = Output {
        file: BufWriter::with_capacity(IO_SIZE, file),
        hash: Sha256::new(),
        offset: 0,
    };
    let mut block = [0; BLOCK];
    let sb = &mut block[1024..1152];
    sb[0..4].copy_from_slice(&0xe0f5e1e2u32.to_le_bytes());
    sb[8..12].copy_from_slice(&3u32.to_le_bytes());
    sb[12] = 12;
    sb[16..24].copy_from_slice(&(plan.records.len() as u64).to_le_bytes());
    sb[36..40].copy_from_slice(&u32_field(plan.length / BLOCK_SIZE)?.to_le_bytes());
    sb[40..44].copy_from_slice(&u32_field(plan.meta / BLOCK_SIZE)?.to_le_bytes());
    sb[48..64].copy_from_slice(&plan.uuid);
    sb[80..84].copy_from_slice(&12u32.to_le_bytes());
    sb[86..88].copy_from_slice(&(layers.len() as u16).to_le_bytes());
    sb[88..90].copy_from_slice(&(if layers.is_empty() { 0u16 } else { 32u16 }).to_le_bytes());
    let crc = crc32c(&block[1024..]);
    block[1028..1032].copy_from_slice(&crc.to_le_bytes());
    out.bytes(&block)?;
    for range in &plan.ranges {
        let mut slot = [0; 128];
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for (i, byte) in range.stream.as_bytes().iter().enumerate() {
            slot[2 * i] = HEX[(byte >> 4) as usize];
            slot[2 * i + 1] = HEX[(byte & 15) as usize];
        }
        slot[64..68].copy_from_slice(&u32_field(range.length / BLOCK_SIZE)?.to_le_bytes());
        slot[68..72].copy_from_slice(&u32_field(range.offset / BLOCK_SIZE)?.to_le_bytes());
        out.bytes(&slot)?;
    }
    out.pad_to(plan.meta)?;
    for (ordinal, record) in plan.records.iter().enumerate() {
        out.pad_to(record.offset)?;
        inode(&mut out, record, ordinal)?;
        xattrs(&mut out, record)?;
        if let NamespaceKind::Regular { body } = &record.inode.kind {
            out.pad_to(record.index_start)?;
            let (pack, _) = payload(layers, body)?;
            let mut bytes = [0; IO_SIZE];
            let mut indexes = [0; IO_SIZE / BLOCK * 8];
            let chunks = body.length.div_ceil(BLOCK_SIZE);
            let mut chunk = 0;
            while chunk < chunks {
                let count = (chunks - chunk).min((IO_SIZE / BLOCK) as u64) as usize;
                read_at(
                    pack,
                    &mut bytes[..count * BLOCK],
                    body.pack_offset + chunk * BLOCK_SIZE,
                )?;
                for (i, data) in bytes[..count * BLOCK].chunks_exact(BLOCK).enumerate() {
                    let index = &mut indexes[i * 8..i * 8 + 8];
                    index.fill(0);
                    if data.iter().all(|b| *b == 0) {
                        index[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
                    } else {
                        index[2..4].copy_from_slice(&((body.entry.layer + 1) as u16).to_le_bytes());
                        index[4..8].copy_from_slice(
                            &u32_field(body.pack_offset / BLOCK_SIZE + chunk + i as u64)?
                                .to_le_bytes(),
                        );
                    }
                }
                out.bytes(&indexes[..count * 8])?;
                chunk += count as u64;
            }
        }
        out.pad_to(record.end)?;
    }
    out.pad_to(plan.data_start)?;
    for record in &plan.records {
        match &record.inode.kind {
            NamespaceKind::Directory => directory(&mut out, plan, record)?,
            NamespaceKind::Symlink { target } => {
                out.pad_to(record.data)?;
                out.bytes(target)?;
                out.pad_to(add(record.data, align(record.size, BLOCK_SIZE)?)?)?;
            }
            _ => {}
        }
    }
    out.pad_to(plan.length)?;
    out.file.flush()?;
    Ok(EncodedFsmeta {
        digest: ContentDigest::from_sha256(out.hash.finalize().into()),
        length: plan.length,
        uuid: plan.uuid,
        device_ranges: plan.ranges.clone(),
    })
}

fn inode(out: &mut Output<'_>, record: &Record<'_>, ordinal: usize) -> Result<()> {
    let mut bytes = [0; 64];
    let format = if matches!(record.inode.kind, NamespaceKind::Regular { .. }) {
        9u16
    } else {
        1u16
    };
    bytes[0..2].copy_from_slice(&format.to_le_bytes());
    let icount = if record.xattr_size == 0 {
        0
    } else {
        ((record.xattr_size - 8) / 4) as u16
    };
    bytes[2..4].copy_from_slice(&icount.to_le_bytes());
    bytes[4..6].copy_from_slice(&mode(record.inode).to_le_bytes());
    bytes[8..16].copy_from_slice(&record.size.to_le_bytes());
    bytes[16..20].copy_from_slice(&inode_union(record)?.to_le_bytes());
    bytes[20..24].copy_from_slice(&u32_field(ordinal as u64 + 1)?.to_le_bytes());
    bytes[24..28].copy_from_slice(&record.inode.metadata.uid.to_le_bytes());
    bytes[28..32].copy_from_slice(&record.inode.metadata.gid.to_le_bytes());
    bytes[32..40].copy_from_slice(&record.inode.metadata.mtime_seconds.to_le_bytes());
    bytes[40..44].copy_from_slice(&record.inode.metadata.mtime_nanos.to_le_bytes());
    bytes[44..48].copy_from_slice(&record.nlink.to_le_bytes());
    out.bytes(&bytes)
}

fn xattrs(out: &mut Output<'_>, record: &Record<'_>) -> Result<()> {
    if record.xattr_size == 0 {
        return Ok(());
    }
    out.bytes(&[0; 12])?;
    for attr in &record.inode.metadata.xattrs {
        let (index, suffix) = xattr_name(&attr.name)?;
        let mut header = [suffix.len() as u8, index, 0, 0];
        header[2..4].copy_from_slice(&(attr.value.len() as u16).to_le_bytes());
        out.bytes(&header)?;
        out.bytes(suffix)?;
        out.bytes(&attr.value)?;
        out.pad_to(align(out.offset, 4)?)?;
    }
    Ok(())
}

fn directory(out: &mut Output<'_>, plan: &Plan<'_>, record: &Record<'_>) -> Result<()> {
    out.pad_to(record.data)?;
    let mut entries = plan.directory(record.id)?;
    loop {
        let (count, _) = directory_group(entries.clone());
        let mut block = [0; BLOCK];
        let mut name_offset = count * 12;
        for i in 0..count {
            let entry = entries
                .next()
                .ok_or_else(|| invalid("directory group underflow"))?;
            let nid = plan.record(entry.id)?.nid;
            block[i * 12..i * 12 + 8].copy_from_slice(&nid.to_le_bytes());
            block[i * 12 + 8..i * 12 + 10].copy_from_slice(&(name_offset as u16).to_le_bytes());
            block[i * 12 + 10] = entry.file_type;
            block[name_offset..name_offset + entry.name.len()].copy_from_slice(entry.name);
            name_offset += entry.name.len();
        }
        out.bytes(&block)?;
        if entries.clone().next().is_none() {
            return Ok(());
        }
    }
}
