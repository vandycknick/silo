use std::io::{self, Read};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::virt::exit::StartupStage;

pub(crate) const MAX_REQUEST: usize = 16 * 1024 * 1024;
pub(crate) const MAX_EVENT: usize = 16 * 1024;
pub(crate) const MAX_DIAGNOSTIC: usize = 8 * 1024;

/// Private, co-versioned launch data. Never format this request into logs.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Launch {
    id: String,
    cpus: u8,
    memory_mib: u32,
    kernel: Option<PathBuf>,
    initramfs: Option<PathBuf>,
    cmdline: Vec<String>,
    disks: Vec<crate::krun::Disk>,
    mounts: Vec<crate::krun::Mount>,
    vsock_mux: bool,
    vsock_cid: Option<u64>,
    network: crate::krun::Network,
    stdio_console: bool,
    balloon: bool,
    rosetta: Option<String>,
}

impl Launch {
    pub(crate) fn from_config(config: crate::krun::KrunConfig) -> io::Result<Self> {
        crate::krun::validate_config(&config).map_err(io::Error::other)?;
        let rosetta = config
            .rosetta
            .as_ref()
            .map(crate::krun::RosettaLaunchConfig::encode)
            .transpose()
            .map_err(io::Error::other)?;
        Ok(Self {
            id: config.id,
            cpus: config.cpus,
            memory_mib: config.memory_mib,
            kernel: config.kernel,
            initramfs: config.initramfs,
            cmdline: config.cmdline,
            disks: config.disks,
            mounts: config.mounts,
            vsock_mux: config.vsock_mux,
            vsock_cid: config.vsock_cid,
            network: config.network,
            stdio_console: config.stdio_console,
            balloon: config.balloon,
            rosetta,
        })
    }

    pub(crate) fn into_config(self) -> io::Result<crate::krun::KrunConfig> {
        let rosetta = self
            .rosetta
            .map(|value| crate::krun::RosettaLaunchConfig::decode(value.as_bytes()))
            .transpose()
            .map_err(io::Error::other)?;
        #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
        if rosetta.is_some() {
            return Err(invalid("Rosetta requires macOS aarch64"));
        }
        let config = crate::krun::KrunConfig {
            id: self.id,
            cpus: self.cpus,
            memory_mib: self.memory_mib,
            kernel: self.kernel,
            initramfs: self.initramfs,
            cmdline: self.cmdline,
            disks: self.disks,
            mounts: self.mounts,
            vsock_mux: self.vsock_mux,
            vsock_cid: self.vsock_cid,
            network: self.network,
            stdio_console: self.stdio_console,
            balloon: self.balloon,
            rosetta,
        };
        crate::krun::validate_config(&config).map_err(io::Error::other)?;
        Ok(config)
    }
}

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

pub(crate) fn read_launch(reader: &mut impl Read) -> io::Result<Launch> {
    let mut header = [0; 4];
    reader.read_exact(&mut header)?;
    let mut bytes = vec![0; frame_length(header, MAX_REQUEST)?];
    reader.read_exact(&mut bytes)?;
    let mut extra = [0];
    if reader.read(&mut extra)? != 0 {
        return Err(invalid("trailing launch data"));
    }
    decode(&bytes)
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
    use crate::krun::worker::protocol::*;

    #[test]
    fn launch_round_trip_preserves_paths_and_devices() {
        let config = crate::krun::KrunConfig {
            kernel: Some("/kernel with : spaces".into()),
            disks: vec![crate::krun::Disk {
                block_id: "root".to_string(),
                path: "/root:disk".into(),
                read_only: true,
            }],
            ..crate::krun::KrunConfig::default()
        };
        let launch = Launch::from_config(config.clone()).expect("launch");
        let wire = encode(&launch, MAX_REQUEST).expect("encode");
        assert_eq!(
            read_launch(&mut wire.as_slice())
                .expect("read")
                .into_config()
                .expect("config"),
            config
        );
    }

    #[test]
    fn framing_rejects_oversize_truncation_trailing_data_and_private_values() {
        assert!(frame_length(u32::MAX.to_be_bytes(), MAX_REQUEST).is_err());
        assert!(frame_length([0; 4], MAX_REQUEST).is_err());
        assert!(read_launch(&mut &[0, 0, 0][..]).is_err());
        assert!(read_launch(&mut &[0, 0, 0, 2, b'{'][..]).is_err());
        let config = crate::krun::KrunConfig {
            kernel: Some("/kernel".into()),
            ..crate::krun::KrunConfig::default()
        };
        let mut wire =
            encode(&Launch::from_config(config).expect("launch"), MAX_REQUEST).expect("wire");
        wire.push(0);
        assert!(read_launch(&mut wire.as_slice()).is_err());
        let error = decode::<Launch>(br#"{"secret":"private-request-value"}"#)
            .err()
            .expect("reject unknown request");
        assert!(!error.to_string().contains("private-request-value"));
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
