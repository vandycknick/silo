use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

use crate::changeset::limits::aligned;
use crate::changeset::{ChangesetError, ChangesetLimits, ChangesetResult, PayloadRef, SparseRange};

pub(crate) fn ensure_space(path: &Path, required: u64) -> ChangesetResult<()> {
    let stats = nix::sys::statvfs::statvfs(path).map_err(std::io::Error::from)?;
    let available = stats
        .blocks_available()
        .checked_mul(stats.fragment_size())
        .ok_or_else(|| ChangesetError::Invalid("available staging space overflows".into()))?;
    if required > available {
        return Err(ChangesetError::Resource {
            required,
            available,
        });
    }
    Ok(())
}

pub(crate) fn allocated_bytes(file: &File) -> ChangesetResult<u64> {
    file.metadata()?
        .blocks()
        .checked_mul(512)
        .ok_or_else(|| ChangesetError::Invalid("allocated staging size overflow".into()))
}

/// Incremental validation for streamed index pages and tar range maps. A failed
/// push leaves the state unchanged, so callers cannot retain a partial range.
pub(crate) struct SparseValidation {
    length: u64,
    previous_end: u64,
    previous_offset: Option<u64>,
    stored: u64,
}

impl SparseValidation {
    pub(crate) fn new(length: u64) -> Self {
        Self {
            length,
            previous_end: 0,
            previous_offset: None,
            stored: 0,
        }
    }

    pub(crate) fn push(&mut self, range: &SparseRange) -> ChangesetResult<()> {
        let end = range
            .offset
            .checked_add(range.length)
            .ok_or_else(|| ChangesetError::Invalid("sparse range overflow".into()))?;
        // GNU tar may emit a zero-length EOF sentinel, including for all-hole
        // files. Retain it rather than silently changing source provenance.
        if range.offset < self.previous_end
            || self
                .previous_offset
                .is_some_and(|offset| range.offset <= offset)
            || end > self.length
            || (range.length == 0 && range.offset != self.length)
        {
            return Err(ChangesetError::Invalid(
                "unordered, overlapping or out-of-file sparse range".into(),
            ));
        }
        let stored = self
            .stored
            .checked_add(range.length)
            .ok_or_else(|| ChangesetError::Invalid("sparse data size overflow".into()))?;
        self.previous_offset = Some(range.offset);
        self.previous_end = end;
        self.stored = stored;
        Ok(())
    }

    pub(crate) fn stored(&self) -> u64 {
        self.stored
    }
}

pub(crate) fn validate_ranges(
    ranges: &[SparseRange],
    length: u64,
    stored: u64,
    limits: &ChangesetLimits,
) -> ChangesetResult<()> {
    if ranges.len() as u64 > limits.max_sparse_ranges {
        return Err(ChangesetError::Limit {
            resource: "sparse ranges",
            actual: ranges.len() as u64,
            maximum: limits.max_sparse_ranges,
        });
    }
    let mut validation = SparseValidation::new(length);
    for range in ranges {
        validation.push(range)?;
    }
    if validation.stored() != stored {
        return Err(ChangesetError::Invalid(
            "sparse map data count differs from stored body".into(),
        ));
    }
    Ok(())
}

pub(crate) struct PackWriter<'a> {
    file: File,
    path: &'a Path,
    length: u64,
    spool_length: u64,
    spool_allocated: u64,
    limits: &'a ChangesetLimits,
}

impl<'a> PackWriter<'a> {
    pub(crate) fn create(
        path: &'a Path,
        spool_length: u64,
        spool_allocated: u64,
        limits: &'a ChangesetLimits,
    ) -> ChangesetResult<Self> {
        let parent = path
            .parent()
            .ok_or_else(|| ChangesetError::Invalid("pack has no staging parent".into()))?;
        let reservation = spool_length
            .checked_mul(2)
            .ok_or_else(|| ChangesetError::Invalid("spool reservation overflow".into()))?;
        ensure_space(parent, reservation.saturating_sub(spool_allocated))?;
        let file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(path)?;
        Ok(Self {
            file,
            path,
            length: 0,
            spool_length,
            spool_allocated,
            limits,
        })
    }

    pub(crate) fn append(
        &mut self,
        source: &mut impl Read,
        logical: u64,
        stored: u64,
        sparse: Option<Vec<SparseRange>>,
    ) -> ChangesetResult<PayloadRef> {
        if logical > self.limits.max_file_bytes {
            return Err(ChangesetError::Limit {
                resource: "regular file bytes",
                actual: logical,
                maximum: self.limits.max_file_bytes,
            });
        }
        if let Some(ranges) = &sparse {
            validate_ranges(ranges, logical, stored, self.limits)?;
        } else if logical != stored {
            return Err(ChangesetError::Invalid(
                "ordinary body size mismatch".into(),
            ));
        }
        if logical == 0 {
            return Ok(PayloadRef {
                pack_offset: self.length,
                length: 0,
                sparse: sparse.unwrap_or_default(),
            });
        }
        let growth = aligned(logical)?;
        let end = self
            .length
            .checked_add(growth)
            .ok_or_else(|| ChangesetError::Invalid("payload pack size overflow".into()))?;
        if end > self.limits.max_pack_bytes {
            return Err(ChangesetError::Limit {
                resource: "payload pack bytes",
                actual: end,
                maximum: self.limits.max_pack_bytes,
            });
        }
        let parent = self
            .path
            .parent()
            .ok_or_else(|| ChangesetError::Invalid("pack has no staging parent".into()))?;
        // Both private pack and publication copy may coexist with the spool.
        // Subtract only measured allocated blocks, never logical sparse holes.
        let total = self
            .spool_length
            .checked_add(
                end.checked_mul(2)
                    .ok_or_else(|| ChangesetError::Invalid("pack reservation overflow".into()))?,
            )
            .ok_or_else(|| ChangesetError::Invalid("staging reservation overflow".into()))?;
        let reservation = total.max(
            self.spool_length
                .checked_mul(2)
                .ok_or_else(|| ChangesetError::Invalid("spool reservation overflow".into()))?,
        );
        let allocated = self
            .spool_allocated
            .checked_add(allocated_bytes(&self.file)?)
            .ok_or_else(|| ChangesetError::Invalid("allocated staging size overflow".into()))?;
        ensure_space(parent, reservation.saturating_sub(allocated))?;
        let offset = self.length;
        self.file.set_len(end)?;
        if let Some(ranges) = &sparse {
            for range in ranges {
                if range.length == 0 {
                    continue;
                }
                self.file.seek(SeekFrom::Start(
                    offset
                        .checked_add(range.offset)
                        .ok_or_else(|| ChangesetError::Invalid("pack extent overflow".into()))?,
                ))?;
                copy_exact(source, &mut self.file, range.length)?;
            }
        } else {
            self.file.seek(SeekFrom::Start(offset))?;
            copy_exact(source, &mut self.file, stored)?;
        }
        self.length = end;
        Ok(PayloadRef {
            pack_offset: offset,
            length: logical,
            sparse: sparse.unwrap_or_default(),
        })
    }

    pub(crate) fn finish(self) -> ChangesetResult<u64> {
        self.file.sync_all()?;
        Ok(self.length)
    }
}

pub(crate) fn copy_exact(
    source: &mut impl Read,
    output: &mut impl Write,
    mut length: u64,
) -> ChangesetResult<()> {
    let mut buffer = [0_u8; 16 * 1024];
    while length != 0 {
        let request = usize::try_from(length.min(buffer.len() as u64))
            .map_err(|_| ChangesetError::Invalid("copy size overflow".into()))?;
        source.read_exact(&mut buffer[..request])?;
        output.write_all(&buffer[..request])?;
        length -= request as u64;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::changeset::limits::aligned;
    use crate::changeset::pack::{validate_ranges, PackWriter, SparseValidation};
    use crate::changeset::{ChangesetLimits, SparseRange};
    use std::io::Cursor;

    #[test]
    fn fixed_pack_examples_have_exact_logical_zeros() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pack");
        let limits = ChangesetLimits::default();
        let mut writer = PackWriter::create(&path, 0, 0, &limits).unwrap();
        assert_eq!(
            writer
                .append(&mut Cursor::new(b"A"), 1, 1, None)
                .unwrap()
                .pack_offset,
            0
        );
        assert_eq!(
            writer
                .append(&mut Cursor::new(b""), 0, 0, None)
                .unwrap()
                .pack_offset,
            4096
        );
        assert_eq!(
            writer
                .append(&mut Cursor::new(b"BC"), 2, 2, None)
                .unwrap()
                .pack_offset,
            4096
        );
        assert_eq!(writer.finish().unwrap(), 8192);
        let mut expected = vec![0; 8192];
        expected[0] = b'A';
        expected[4096..4098].copy_from_slice(b"BC");
        assert_eq!(std::fs::read(path).unwrap(), expected);
        let path = dir.path().join("sparse");
        let mut writer = PackWriter::create(&path, 0, 0, &limits).unwrap();
        writer
            .append(
                &mut Cursor::new(b"X"),
                4097,
                1,
                Some(vec![SparseRange {
                    offset: 4096,
                    length: 1,
                }]),
            )
            .unwrap();
        assert_eq!(writer.finish().unwrap(), 8192);
        let mut expected = vec![0; 8192];
        expected[4096] = b'X';
        assert_eq!(std::fs::read(path).unwrap(), expected);
        assert!(aligned(u64::MAX).is_err());
    }

    #[test]
    fn sparse_ranges_are_never_sorted_repaired_or_truncated() {
        let limits = ChangesetLimits::default();
        for ranges in [
            vec![
                SparseRange {
                    offset: 2,
                    length: 3,
                },
                SparseRange {
                    offset: 4,
                    length: 1,
                },
            ],
            vec![
                SparseRange {
                    offset: 3,
                    length: 1,
                },
                SparseRange {
                    offset: 1,
                    length: 1,
                },
            ],
            vec![SparseRange {
                offset: u64::MAX,
                length: 1,
            }],
        ] {
            assert!(validate_ranges(&ranges, 5, 4, &limits).is_err());
        }
        assert!(validate_ranges(
            &[SparseRange {
                offset: 4,
                length: 1
            }],
            4,
            1,
            &limits
        )
        .is_err());
        assert!(validate_ranges(
            &[SparseRange {
                offset: 4,
                length: 1
            }],
            5,
            2,
            &limits
        )
        .is_err());
        assert!(validate_ranges(
            &[SparseRange {
                offset: 4,
                length: 1
            }],
            5,
            1,
            &ChangesetLimits {
                max_sparse_ranges: 0,
                ..limits
            }
        )
        .is_err());
    }

    #[test]
    fn incremental_sparse_validation_preserves_failed_push_state_and_eof_sentinel() {
        let mut state = SparseValidation::new(10);
        state
            .push(&SparseRange {
                offset: 2,
                length: 2,
            })
            .unwrap();
        assert_eq!(state.stored(), 2);
        for range in [
            SparseRange {
                offset: 3,
                length: 2,
            },
            SparseRange {
                offset: 1,
                length: 1,
            },
            SparseRange {
                offset: 9,
                length: 2,
            },
            SparseRange {
                offset: 7,
                length: 0,
            },
            SparseRange {
                offset: u64::MAX,
                length: 1,
            },
        ] {
            assert!(state.push(&range).is_err());
            assert_eq!(state.stored(), 2);
        }
        state
            .push(&SparseRange {
                offset: 6,
                length: 1,
            })
            .unwrap();
        state
            .push(&SparseRange {
                offset: 10,
                length: 0,
            })
            .unwrap();
        assert_eq!(state.stored(), 3);
        assert!(state
            .push(&SparseRange {
                offset: 10,
                length: 0
            })
            .is_err());
        assert_eq!(state.stored(), 3);
        let mut all_hole = SparseValidation::new(10);
        all_hole
            .push(&SparseRange {
                offset: 10,
                length: 0,
            })
            .unwrap();
        assert_eq!(all_hole.stored(), 0);
    }
}
