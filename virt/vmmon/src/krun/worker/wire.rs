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
    let bytes = serde_json::to_vec(config).map_err(|_| invalid("cannot encode worker config"))?;
    if bytes.len() > MAX_CONFIG {
        return Err(invalid("worker config exceeds limit"));
    }
    Ok(bytes)
}

/// Read the whole config descriptor to EOF, bounded. The engine validates it.
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

    #[test]
    fn config_round_trip_preserves_paths_devices_and_rosetta() {
        let config = crate::krun::KrunConfig {
            kernel: Some("/kernel with : spaces".into()),
            disks: vec![crate::krun::Disk {
                block_id: "root".to_string(),
                path: "/root:disk".into(),
                read_only: true,
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
        };
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

    #[test]
    fn config_rejects_empty_truncated_trailing_oversized_and_private_values() {
        assert!(read_config(&mut &b""[..]).is_err());
        assert!(read_config(&mut &b"{"[..]).is_err());
        let config = crate::krun::KrunConfig {
            kernel: Some("/kernel".into()),
            ..crate::krun::KrunConfig::default()
        };
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
