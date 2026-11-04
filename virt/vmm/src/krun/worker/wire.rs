use std::io::{self, Read};

use serde::{Deserialize, Serialize};

use crate::krun::KrunConfig;
use crate::virt::exit::StartupStage;

pub(crate) const MAX_CONFIG: usize = 16 * 1024 * 1024;
pub(crate) const MAX_EVENT: usize = 16 * 1024;
pub(crate) const MAX_DIAGNOSTIC: usize = 8 * 1024;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Event {
    StartupStage {
        stage: StartupStage,
    },
    BackendStarted {},
    StartupFailed {
        stage: StartupStage,
        diagnostic: String,
    },
    HostMemoryReclaim {
        status: crate::krun::HostMemoryReclaimStatus,
    },
}

pub(crate) fn encode<T: Serialize>(value: &T, limit: usize) -> io::Result<Vec<u8>> {
    // A bounded writer prevents serialization from allocating beyond the limit.
    struct Bounded {
        data: Vec<u8>,
        limit: usize,
    }
    impl io::Write for Bounded {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if bytes.len() > self.limit.saturating_sub(self.data.len()) {
                return Err(invalid("worker frame exceeds limit"));
            }
            self.data.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut writer = Bounded {
        data: vec![0; 4],
        limit: limit + 4,
    };
    serde_json::to_writer(&mut writer, value)
        .map_err(|_| invalid("cannot encode bounded worker frame"))?;
    let size =
        u32::try_from(writer.data.len() - 4).map_err(|_| invalid("worker frame exceeds u32"))?;
    writer.data[..4].copy_from_slice(&size.to_be_bytes());
    Ok(writer.data)
}

pub(crate) fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> io::Result<T> {
    // Serde diagnostics may include private request values. Deliberately redact them.
    serde_json::from_slice(bytes).map_err(|_| invalid("invalid worker frame"))
}

pub(crate) fn frame_length(header: [u8; 4], limit: usize) -> io::Result<usize> {
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > limit {
        return Err(invalid("worker frame length exceeds limit"));
    }
    Ok(length)
}

/// Encode the private, co-versioned worker config. Never log the bytes.
pub(crate) fn encode_config(config: &KrunConfig) -> io::Result<Vec<u8>> {
    crate::krun::validate_config(config).map_err(io::Error::other)?;
    crate::krun::config::validate_worker_storage(config).map_err(io::Error::other)?;
    let bytes = serde_json::to_vec(config).map_err(|_| invalid("cannot encode worker config"))?;
    if bytes.len() > MAX_CONFIG {
        return Err(invalid("worker config exceeds limit"));
    }
    Ok(bytes)
}

/// Read and validate the whole private config descriptor to EOF, bounded.
pub(crate) fn read_config(reader: &mut impl Read) -> io::Result<KrunConfig> {
    let mut bytes = Vec::new();
    reader.take(MAX_CONFIG as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.is_empty() {
        return Err(invalid("worker config is empty"));
    }
    if bytes.len() > MAX_CONFIG {
        return Err(invalid("worker config exceeds limit"));
    }
    let config: KrunConfig = decode(&bytes)?;
    crate::krun::validate_config(&config).map_err(|_| invalid("invalid worker configuration"))?;
    crate::krun::config::validate_worker_storage(&config).map_err(io::Error::other)?;
    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    if config.rosetta.is_some() {
        return Err(invalid("Rosetta requires macOS aarch64"));
    }
    Ok(config)
}

pub(crate) fn diagnostic(error: &impl std::fmt::Display) -> String {
    let text = error.to_string();
    if text.len() <= MAX_DIAGNOSTIC {
        return text;
    }
    let mut end = MAX_DIAGNOSTIC - " [truncated]".len();
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{} [truncated]", &text[..end])
}

pub(crate) fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use crate::krun::worker::wire::*;

    fn managed(mut config: crate::krun::KrunConfig) -> crate::krun::KrunConfig {
        config.storage_context = protocol::shutdown::WorkerStorageContext {
            version: 1,
            machine_id: "11111111-1111-4111-8111-111111111111".to_string(),
            run_id: "22222222-2222-4222-8222-222222222222".to_string(),
            storage_lease: protocol::shutdown::StorageLeaseBinding {
                operation_id: "33333333-3333-4333-8333-333333333333".to_string(),
                file_device: 1,
                file_inode: 2,
            },
            raw_handles: config
                .disks
                .iter()
                .enumerate()
                .filter(|(_, disk)| disk.format == vm_spec::DiskFormat::Raw)
                .enumerate()
                .map(
                    |(raw_index, (disk_index, disk))| protocol::shutdown::RawHandleBinding {
                        disk_index: disk_index as u32,
                        child_fd: 9 + raw_index as i32,
                        device: 1,
                        inode: 10 + raw_index as u64,
                        length_bytes: disk.geometry.length,
                        read_only: disk.read_only,
                    },
                )
                .collect(),
        };
        config
    }

    #[test]
    fn config_round_trip_preserves_paths_devices_and_rosetta() {
        let config = managed(crate::krun::KrunConfig {
            kernel: Some("/kernel with : spaces".into()),
            disks: vec![vm_spec::Disk {
                block_id: vm_spec::BlockId::new("explicit-root").expect("valid ID"),
                role: vm_spec::DiskRole::Root,
                format: vm_spec::DiskFormat::Raw,
                geometry: vm_spec::DiskGeometry {
                    length: 4096,
                    logical_sector_size: 512,
                },
                path: "/root:disk".into(),
                read_only: false,
            }],
            vsock_mux: true,
            rosetta: Some(
                crate::krun::RosettaLaunchConfig::new(
                    "/Library/Apple/RosettaLinux".into(),
                    [0x11; 32],
                    1,
                    [0x22; 1024],
                )
                .expect("rosetta"),
            ),
            ..crate::krun::KrunConfig::default()
        });
        let wire = encode_config(&config).expect("encode");
        let decoded = read_config(&mut wire.as_slice());
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        assert_eq!(decoded.expect("read"), config);
        #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
        assert!(decoded.is_err());

        let plain = crate::krun::KrunConfig {
            rosetta: None,
            ..config
        };
        let wire = encode_config(&plain).expect("encode");
        assert_eq!(read_config(&mut wire.as_slice()).expect("read"), plain);
    }

    fn overlay_config() -> crate::krun::KrunConfig {
        managed(crate::krun::KrunConfig {
            kernel: Some("/kernel".into()),
            disks: vec![
                vm_spec::Disk {
                    path: "/lower-without-format-suffix".into(),
                    role: vm_spec::DiskRole::RootLower,
                    format: vm_spec::DiskFormat::Vmdk,
                    geometry: vm_spec::DiskGeometry {
                        length: (2 << 30) + 512,
                        logical_sector_size: 512,
                    },
                    block_id: vm_spec::BlockId::new("silo-root-lower").expect("lower ID"),
                    read_only: true,
                },
                vm_spec::Disk {
                    path: "/upper.vmdk".into(),
                    role: vm_spec::DiskRole::RootUpper,
                    format: vm_spec::DiskFormat::Raw,
                    geometry: vm_spec::DiskGeometry {
                        length: 64 << 20,
                        logical_sector_size: 512,
                    },
                    block_id: vm_spec::BlockId::new("silo-root-upper").expect("upper ID"),
                    read_only: false,
                },
                vm_spec::Disk {
                    path: "/data.raw".into(),
                    role: vm_spec::DiskRole::Data,
                    format: vm_spec::DiskFormat::Raw,
                    geometry: vm_spec::DiskGeometry {
                        length: 8192,
                        logical_sector_size: 512,
                    },
                    block_id: vm_spec::BlockId::new("supplied-data-id").expect("data ID"),
                    read_only: true,
                },
            ],
            ..crate::krun::KrunConfig::default()
        })
    }

    #[test]
    fn private_config_round_trip_preserves_typed_overlay_and_following_data() {
        let config = overlay_config();
        let wire = encode_config(&config).expect("encode typed overlay");
        assert_eq!(
            read_config(&mut wire.as_slice()).expect("decode typed overlay"),
            config
        );
    }

    #[test]
    fn private_config_rejects_missing_unknown_and_malformed_disk_fields() {
        let original = serde_json::to_value(overlay_config()).expect("config JSON");
        for field in ["path", "role", "format", "geometry", "blockId", "readOnly"] {
            let mut value = original.clone();
            value["disks"][0]
                .as_object_mut()
                .expect("disk object")
                .remove(field);
            let bytes = serde_json::to_vec(&value).expect("JSON");
            assert!(
                read_config(&mut bytes.as_slice()).is_err(),
                "missing {field}"
            );
        }
        for (field, bad) in [
            ("role", serde_json::json!("unknown")),
            ("format", serde_json::json!("qcow2")),
            ("readOnly", serde_json::json!("true")),
            ("blockId", serde_json::json!("")),
            ("blockId", serde_json::json!("contains space")),
            ("blockId", serde_json::json!("twenty-one-characters!")),
            ("blockId", serde_json::json!("nul\u{0}id")),
            ("blockId", serde_json::json!("nonascii-é")),
            (
                "geometry",
                serde_json::json!({"length": 0, "logicalSectorSize": 512}),
            ),
            (
                "geometry",
                serde_json::json!({"length": 513, "logicalSectorSize": 512}),
            ),
            (
                "geometry",
                serde_json::json!({"length": 1_u64 << 41, "logicalSectorSize": 512}),
            ),
            (
                "geometry",
                serde_json::json!({"length": 4096, "logicalSectorSize": 4096}),
            ),
            ("geometry", serde_json::json!({"length": 4096})),
            ("unknown", serde_json::json!("private-request-value")),
        ] {
            let mut value = original.clone();
            value["disks"][0][field] = bad;
            let bytes = serde_json::to_vec(&value).expect("JSON");
            let error = read_config(&mut bytes.as_slice()).expect_err("reject malformed disk");
            assert!(!error.to_string().contains("private-request-value"));
        }
    }

    #[test]
    fn private_config_validates_direct_and_deserialized_role_combinations() {
        let valid = overlay_config();
        let mut invalid = Vec::new();
        let mut config = valid.clone();
        config.disks[0].read_only = false;
        invalid.push(config);
        let mut config = valid.clone();
        config.disks[1].read_only = true;
        invalid.push(config);
        let mut config = valid.clone();
        config.disks[0].format = vm_spec::DiskFormat::Raw;
        invalid.push(config);
        let mut config = valid.clone();
        config.disks[1].format = vm_spec::DiskFormat::Vmdk;
        invalid.push(config);
        let mut config = valid.clone();
        config.disks.remove(1);
        invalid.push(config);
        let mut config = valid.clone();
        config.disks.remove(0);
        invalid.push(config);
        let mut config = valid.clone();
        config.disks[1].role = vm_spec::DiskRole::Root;
        invalid.push(config);
        let mut config = valid.clone();
        config.disks.swap(0, 1);
        invalid.push(config);
        let mut config = valid.clone();
        config.disks.swap(1, 2);
        invalid.push(config);
        let mut config = valid.clone();
        config.disks[2].block_id = config.disks[0].block_id.clone();
        invalid.push(config);
        let mut config = valid.clone();
        config.disks[0].block_id = vm_spec::BlockId::new("truncated-lower").expect("valid syntax");
        invalid.push(config);
        let mut config = valid.clone();
        config.disks[0].geometry.length = 513;
        invalid.push(config);
        let mut config = valid.clone();
        config.disks.push(config.disks[2].clone());
        invalid.push(config);
        let mut config = valid.clone();
        config.disks[2].format = vm_spec::DiskFormat::Vmdk;
        invalid.push(config);
        let mut config = valid;
        config.disks[1].geometry.length = (64 << 20) | 512;
        invalid.push(config);
        for config in invalid {
            assert!(crate::krun::validate_config(&config).is_err());
            assert!(encode_config(&config).is_err());
            let bytes = serde_json::to_vec(&config).expect("serialize direct invalid config");
            assert!(read_config(&mut bytes.as_slice()).is_err());
        }
    }

    #[test]
    fn config_rejects_empty_truncated_trailing_oversized_and_private_values() {
        assert!(read_config(&mut &b""[..]).is_err());
        assert!(read_config(&mut &b"{"[..]).is_err());
        let config = managed(crate::krun::KrunConfig {
            kernel: Some("/kernel".into()),
            ..crate::krun::KrunConfig::default()
        });
        let mut wire = encode_config(&config).expect("wire");
        wire.extend_from_slice(b"{}");
        assert!(read_config(&mut wire.as_slice()).is_err());
        let oversized = vec![b' '; MAX_CONFIG + 1];
        assert!(read_config(&mut oversized.as_slice()).is_err());
        let error = read_config(&mut &br#"{"secret":"private-request-value"}"#[..])
            .expect_err("reject unknown request");
        assert!(!error.to_string().contains("private-request-value"));
        assert!(encode_config(&crate::krun::KrunConfig::default()).is_err());
    }

    #[test]
    fn worker_wire_rejects_missing_lease_and_incomplete_raw_coverage() {
        let mut config = overlay_config();
        config.storage_context.raw_handles.pop();
        assert!(encode_config(&config).is_err());
        let bytes = serde_json::to_vec(&config).expect("serialize incomplete coverage");
        assert!(read_config(&mut bytes.as_slice()).is_err());
        let config = managed(crate::krun::KrunConfig {
            kernel: Some("/kernel".into()),
            ..crate::krun::KrunConfig::default()
        });
        let mut value = serde_json::to_value(config).expect("worker JSON");
        value
            .as_object_mut()
            .expect("object")
            .remove("storage_context");
        assert!(read_config(&mut serde_json::to_vec(&value).expect("JSON").as_slice()).is_err());
    }

    #[test]
    fn event_framing_rejects_oversize_and_unknown_fields() {
        assert!(frame_length(u32::MAX.to_be_bytes(), MAX_EVENT).is_err());
        assert!(frame_length([0; 4], MAX_EVENT).is_err());
        assert!(encode(&"large", 2).is_err());
        assert!(decode::<Event>(br#"{"event":"backend_started","unknown":1}"#).is_err());
    }

    #[test]
    fn diagnostics_are_bounded_without_splitting_unicode() {
        let text = diagnostic(&"é".repeat(MAX_DIAGNOSTIC));
        assert!(text.len() <= MAX_DIAGNOSTIC);
        assert!(text.ends_with("[truncated]"));
    }
}
