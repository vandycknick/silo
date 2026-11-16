//! Lossless conversion between host-local disk coverage and native tokens.
use vm_spec::capture::{
    DiskDirtyRun, DiskGenerationToken, DiskTrackingInvalidReason, DiskTrackingReceipt,
    DiskTrackingSeed, Sha256Digest,
};

fn role(value: vm_spec::DiskRole) -> &'static str {
    match value {
        vm_spec::DiskRole::Root => "root",
        vm_spec::DiskRole::RootLower => "root-lower",
        vm_spec::DiskRole::RootUpper => "root-upper",
        vm_spec::DiskRole::Data => "data",
    }
}

pub(crate) fn seed(value: &DiskTrackingSeed) -> Result<libkrun::live::DiskTrackingSeed, String> {
    value.validate()?;
    Ok(libkrun::live::DiskTrackingSeed {
        version: value.version,
        role: role(value.role).into(),
        attachment_index: value.attachment_index,
        file_device: value.file_device,
        file_inode: value.file_inode,
        length: value.length,
        chunk_size: value.chunk_size,
        epoch: *uuid::Uuid::parse_str(value.epoch.as_str())
            .map_err(|error| error.to_string())?
            .as_bytes(),
        baseline: value.baseline.map(|digest| *digest.as_bytes()),
    })
}

pub(crate) fn token(
    value: &DiskGenerationToken,
) -> Result<libkrun::live::DiskGenerationToken, String> {
    Ok(libkrun::live::DiskGenerationToken {
        capture_id: *uuid::Uuid::parse_str(value.capture_id.as_str())
            .map_err(|error| error.to_string())?
            .as_bytes(),
        pause_generation: value.pause_generation,
        epoch: *uuid::Uuid::parse_str(value.epoch.as_str())
            .map_err(|error| error.to_string())?
            .as_bytes(),
        generation: value.generation,
        file_device: value.file_device,
        file_inode: value.file_inode,
    })
}

pub(crate) fn receipt(
    value: &libkrun::live::DiskTrackingReceipt,
    binding: &DiskTrackingSeed,
) -> Result<DiskTrackingReceipt, String> {
    let epoch = *uuid::Uuid::parse_str(binding.epoch.as_str())
        .map_err(|error| error.to_string())?
        .as_bytes();
    if value.seed.version != binding.version
        || value.seed.role != role(binding.role)
        || value.seed.attachment_index != binding.attachment_index
        || value.seed.file_device != binding.file_device
        || value.seed.file_inode != binding.file_inode
        || value.seed.length != binding.length
        || value.seed.chunk_size != binding.chunk_size
        || value.seed.epoch != epoch
    {
        return Err("native disk tracking receipt changed its constructor binding".into());
    }
    let mut binding = binding.clone();
    binding.baseline = value.seed.baseline.map(Sha256Digest::from_bytes);
    let result = DiskTrackingReceipt {
        version: value.version,
        seed: binding,
        token: DiskGenerationToken {
            capture_id: vm_spec::lifecycle::LiveId::parse(
                &uuid::Uuid::from_bytes(value.token.capture_id).to_string(),
            )?,
            pause_generation: value.token.pause_generation,
            epoch: vm_spec::lifecycle::LiveId::parse(
                &uuid::Uuid::from_bytes(value.token.epoch).to_string(),
            )?,
            generation: value.token.generation,
            file_device: value.token.file_device,
            file_inode: value.token.file_inode,
        },
        runs: value
            .runs
            .iter()
            .map(|run| DiskDirtyRun {
                first_chunk: run.first_chunk,
                chunk_count: run.chunk_count,
            })
            .collect(),
        dirty_chunks: value.dirty_chunks,
        total_chunks: value.total_chunks,
        invalid_reason: value.invalid_reason.map(|reason| match reason {
            libkrun::live::DiskTrackingInvalidReason::NeverArmed => {
                DiskTrackingInvalidReason::NeverArmed
            }
            libkrun::live::DiskTrackingInvalidReason::Lost => DiskTrackingInvalidReason::Lost,
            libkrun::live::DiskTrackingInvalidReason::Overflow => {
                DiskTrackingInvalidReason::Overflow
            }
            libkrun::live::DiskTrackingInvalidReason::OutOfDeviceMutationSuspected => {
                DiskTrackingInvalidReason::OutOfDeviceMutationSuspected
            }
        }),
    };
    result.validate()?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use crate::krun::worker::disk_tracking::{receipt, seed, token};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use vm_spec::capture::{
        DiskTrackingSeed, Sha256Digest, DISK_TRACKING_VERSION, STREAM_CHUNK_BYTES,
    };

    struct Backing {
        path: std::path::PathBuf,
        file: std::fs::File,
    }

    impl Drop for Backing {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    fn backing() -> (Backing, DiskTrackingSeed) {
        let path =
            std::env::temp_dir().join(format!("silo-tracking-adapter-{}", uuid::Uuid::new_v4()));
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        file.set_len(2 * STREAM_CHUNK_BYTES + 512).unwrap();
        let metadata = file.metadata().unwrap();
        let seed = DiskTrackingSeed {
            version: DISK_TRACKING_VERSION,
            role: vm_spec::DiskRole::Data,
            attachment_index: 2,
            block_id: vm_spec::BlockId::new("data2").unwrap(),
            file_device: metadata.dev(),
            file_inode: metadata.ino(),
            length: metadata.len(),
            chunk_size: STREAM_CHUNK_BYTES,
            epoch: vm_spec::lifecycle::LiveId::parse(&uuid::Uuid::new_v4().to_string()).unwrap(),
            baseline: Some(Sha256Digest::of_bytes(b"predecessor")),
        };
        (Backing { path, file }, seed)
    }

    fn native(seed: &DiskTrackingSeed) -> libkrun::live::DiskTrackingReceipt {
        let seed = crate::krun::worker::disk_tracking::seed(seed).unwrap();
        libkrun::live::DiskTrackingReceipt {
            version: DISK_TRACKING_VERSION,
            token: libkrun::live::DiskGenerationToken {
                capture_id: *uuid::Uuid::new_v4().as_bytes(),
                pause_generation: 5,
                epoch: seed.epoch,
                generation: 7,
                file_device: seed.file_device,
                file_inode: seed.file_inode,
            },
            seed,
            runs: vec![libkrun::live::DiskDirtyRun {
                first_chunk: 1,
                chunk_count: 2,
            }],
            dirty_chunks: 2,
            total_chunks: 3,
            invalid_reason: None,
        }
    }

    #[test]
    fn disk_tracking_adapter_preserves_backing_epoch_runs_and_new_predecessor() {
        let (backing, binding) = backing();
        assert_eq!(backing.file.metadata().unwrap().ino(), binding.file_inode);
        let mut native = native(&binding);
        native.seed.baseline = Some([9; 32]);
        let converted = receipt(&native, &binding).unwrap();
        assert_eq!(seed(&converted.seed).unwrap(), native.seed);
        assert_eq!(token(&converted.token).unwrap(), native.token);
        assert_eq!(converted.runs[0].first_chunk, 1);
        assert_eq!(converted.runs[0].chunk_count, 2);
        assert_eq!(converted.dirty_chunks, 2);
        assert_eq!(converted.total_chunks, 3);
        assert_eq!(
            converted.seed.baseline,
            Some(Sha256Digest::from_bytes([9; 32]))
        );
        for reason in [
            libkrun::live::DiskTrackingInvalidReason::NeverArmed,
            libkrun::live::DiskTrackingInvalidReason::Lost,
            libkrun::live::DiskTrackingInvalidReason::Overflow,
            libkrun::live::DiskTrackingInvalidReason::OutOfDeviceMutationSuspected,
        ] {
            native.invalid_reason = Some(reason);
            assert!(receipt(&native, &binding).unwrap().invalid_reason.is_some());
        }
    }

    #[test]
    fn disk_tracking_adapter_rejects_foreign_backings_and_incomplete_coverage() {
        let (_backing, binding) = backing();
        for defect in 0..8 {
            let mut native = native(&binding);
            match defect {
                0 => native.seed.file_inode += 1,
                1 => native.seed.epoch[0] ^= 1,
                2 => native.seed.attachment_index += 1,
                3 => native.token.file_device ^= 1,
                4 => native.token.generation = 0,
                5 => native.runs[0].chunk_count = 3,
                6 => native.dirty_chunks = 1,
                _ => native.total_chunks += 1,
            }
            assert!(receipt(&native, &binding).is_err(), "defect {defect}");
        }
    }
}
