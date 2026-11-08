//! Kernel export identities of validated `silo-erofs-v1` inodes.
//!
//! Linux EROFS encodes a non-connectable file handle from the inode's NID and
//! `i_generation`, which EROFS never assigns and is therefore always zero.
//! Kernels 6.16 and newer emit `FILEID_INO64_GEN` (`0x81`: NID high word, NID
//! low word, generation). Admitted kernels 6.6 through 6.15 emit the generic
//! `FILEID_INO32_GEN` (`1`: inode number, generation), where a 64-bit guest's
//! inode number is the NID itself. Words are guest-native little-endian `u32`
//! values (both admitted guest architectures are little-endian).
//!
//! A NID is the inode's 32-byte slot index after the metadata block address,
//! so it derives only from the strictly validated plan, never from guesses
//! about on-disk bytes that `reader::validate` did not check.

use crate::changeset::limits::reserve_vec;
use crate::changeset::namespace::InodeId;
use crate::erofs::plan::Plan;
use crate::erofs::{invalid, Result};

const FILEID_INO32_GEN: u8 = 1;
const FILEID_INO64_GEN: u8 = 0x81;

/// The fid encoding one admitted kernel family emits for EROFS inodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FidEncoding {
    /// Linux 6.6..=6.15 generic `{ino, generation}`.
    Ino32Gen,
    /// Linux 6.16+ EROFS `{nid >> 32, nid & u32::MAX, generation}`.
    Ino64Gen,
}

impl FidEncoding {
    pub(crate) fn from_type(fid_type: u8) -> Option<Self> {
        match fid_type {
            FILEID_INO32_GEN => Some(Self::Ino32Gen),
            FILEID_INO64_GEN => Some(Self::Ino64Gen),
            _ => None,
        }
    }

    pub(crate) fn fid_len(self) -> usize {
        match self {
            Self::Ino32Gen => 8,
            Self::Ino64Gen => 12,
        }
    }
}

/// NID <-> namespace inode identities of one validated fsmeta.
#[derive(Debug)]
pub(crate) struct ExportHandles {
    uuid: [u8; 16],
    /// Strictly ascending NIDs: the plan allocates slots at increasing offsets.
    nids: Vec<(u64, InodeId)>,
}

impl ExportHandles {
    pub(crate) fn from_plan(plan: &Plan<'_>) -> Result<Self> {
        let mut nids = Vec::new();
        reserve_vec(&mut nids, plan.records.len())?;
        for record in &plan.records {
            if nids.last().is_some_and(|(nid, _)| *nid >= record.nid) {
                return Err(invalid("inode slots are not strictly ascending"));
            }
            nids.push((record.nid, record.id));
        }
        Ok(Self {
            uuid: plan.uuid,
            nids,
        })
    }

    /// The superblock UUID the kernel reports as the lower's `s_uuid`.
    pub(crate) fn uuid(&self) -> [u8; 16] {
        self.uuid
    }

    #[cfg(test)]
    pub(crate) fn nid(&self, inode: InodeId) -> Option<u64> {
        self.nids
            .iter()
            .find(|(_, candidate)| *candidate == inode)
            .map(|(nid, _)| *nid)
    }

    /// Decode an exact fid of `encoding`. Anything the kernel would not have
    /// emitted for a live inode of this image (wrong width, nonzero generation,
    /// unallocated NID) is `None`, never a nearest match.
    pub(crate) fn decode(&self, encoding: FidEncoding, fid: &[u8]) -> Option<InodeId> {
        if fid.len() != encoding.fid_len() {
            return None;
        }
        let word = |index: usize| -> Option<u32> {
            let bytes = fid.get(index * 4..index * 4 + 4)?;
            Some(u32::from_le_bytes(bytes.try_into().ok()?))
        };
        let (nid, generation) = match encoding {
            FidEncoding::Ino32Gen => (u64::from(word(0)?), word(1)?),
            FidEncoding::Ino64Gen => ((u64::from(word(0)?) << 32) | u64::from(word(1)?), word(2)?),
        };
        if generation != 0 {
            return None;
        }
        let at = self.nids.binary_search_by_key(&nid, |(nid, _)| *nid).ok()?;
        self.nids.get(at).map(|(_, inode)| *inode)
    }
}
