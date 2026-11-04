//! Same-boot retired-PIT capture admission evidence from the real Silo guest.
//!
//! Writes exactly the file set native_device_controller.profile() writes for
//! its diagnostic init, so unchanged native `profile DIR` validates it. Every
//! guest file is read to EOF; nothing is fabricated or borrowed from another boot.

use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::attach::dto::{enum_name, Content, Failure};
use crate::attach::observe::Guest;

const MAX_PROFILE_FILE: usize = 1024 * 1024;
const MAX_KERNEL_CONFIG: u64 = 16 * 1024 * 1024;
const MAX_INPUT_NAME: usize = 4096;
const BROADCAST: &str = "/sys/devices/system/clockevents/broadcast/current_device";
const MODULES: &str = "/proc/modules";
const INPUTS: &str = "/sys/class/input";
const SPEAKER_DRIVERS: [&str; 2] = [
    "/sys/devices/platform/pcspkr/driver",
    "/sys/devices/platform/pcspkr.0/driver",
];
/// (profile file name, guest path), exactly the diagnostic observation set.
const RAW_FILES: [(&str, &str); 6] = [
    ("kernel-identity", "/proc/version"),
    ("boot-identity", "/proc/sys/kernel/random/boot_id"),
    (
        "clocksource",
        "/sys/devices/system/clocksource/clocksource0/current_clocksource",
    ),
    (
        "clockevent0",
        "/sys/devices/system/clockevents/clockevent0/current_device",
    ),
    (
        "clockevent1",
        "/sys/devices/system/clockevents/clockevent1/current_device",
    ),
    ("interrupts", "/proc/interrupts"),
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProfileOperation {
    pub(crate) directory: PathBuf,
    pub(crate) kernel_config: PathBuf,
}

#[derive(Debug, Serialize)]
pub(crate) struct ProfileFile {
    pub(crate) name: String,
    pub(crate) bytes: usize,
    pub(crate) sha256: String,
    pub(crate) content: Content,
}

#[derive(Debug, Serialize)]
pub(crate) struct SpeakerDriver {
    pub(crate) path: &'static str,
    pub(crate) present: bool,
    pub(crate) kind: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct InputDevice {
    pub(crate) entry: String,
    pub(crate) name: Content,
    pub(crate) speaker: bool,
}

#[derive(Debug, Serialize)]
pub(crate) struct SpeakerInventory {
    pub(crate) drivers: Vec<SpeakerDriver>,
    pub(crate) inputs_present: bool,
    pub(crate) inputs: Vec<InputDevice>,
}

#[derive(Debug, Serialize)]
pub(crate) struct ProfileOutput {
    pub(crate) directory: PathBuf,
    pub(crate) files: Vec<ProfileFile>,
    pub(crate) speaker_inventory: SpeakerInventory,
    pub(crate) modules_admission: serde_json::Value,
}

fn failure(context: &str, error: Failure) -> eyre::Report {
    eyre::eyre!(
        "{context}: {}",
        serde_json::to_string(&error).unwrap_or_default()
    )
}

async fn read(guest: &Guest, path: &str) -> eyre::Result<Vec<u8>> {
    guest
        .download(path, MAX_PROFILE_FILE)
        .await
        .map_err(|error| failure(path, error))
}

/// The emitted kernel config's CONFIG_MODULES decision, required to be explicit.
pub(crate) fn config_modules(config: &str) -> eyre::Result<bool> {
    let enabled = config.lines().any(|line| line == "CONFIG_MODULES=y");
    let disabled = config
        .lines()
        .any(|line| line == "# CONFIG_MODULES is not set");
    match (enabled, disabled) {
        (true, false) => Ok(true),
        (false, true) => Ok(false),
        _ => eyre::bail!("emitted kernel config lacks one explicit CONFIG_MODULES decision"),
    }
}

/// `{"path":"/proc/modules","status":"absent","errno":2}` as the diagnostic
/// guest printed it, so native/Python admission parses one representation.
pub(crate) fn modules_absence_record() -> Vec<u8> {
    format!(
        "{{\"path\":\"{MODULES}\",\"status\":\"absent\",\"errno\":{}}}\n",
        nix::errno::Errno::ENOENT as i32
    )
    .into_bytes()
}

/// Broadcast bytes plus its read-completion binding, as `profile DIR` requires:
/// an empty actual read is represented as `"\n"` with `kind=no-device`.
pub(crate) fn broadcast_files(raw: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let (file, kind) = if raw.is_empty() {
        (b"\n".to_vec(), "no-device")
    } else {
        (raw.to_vec(), "device")
    };
    let state = format!(
        "path={BROADCAST}\nread_complete=1\nbytes_read={}\nkind={kind}\n",
        raw.len()
    );
    (file, state.into_bytes())
}

pub(crate) fn clockevents(first: &[u8], second: &[u8]) -> eyre::Result<Vec<u8>> {
    Ok(format!(
        "{}\n{}\n",
        std::str::from_utf8(first)?.trim(),
        std::str::from_utf8(second)?.trim()
    )
    .into_bytes())
}

async fn speaker_inventory(guest: &Guest) -> eyre::Result<(SpeakerInventory, Vec<u8>)> {
    let mut consumers = Vec::new();
    let mut drivers = Vec::new();
    for (path, label) in SPEAKER_DRIVERS.into_iter().zip(["pcspkr", "pcspkr.0"]) {
        match guest.entry(path).await {
            Ok(entry) => {
                consumers.extend_from_slice(label.as_bytes());
                consumers.push(b'\n');
                drivers.push(SpeakerDriver {
                    path,
                    present: true,
                    kind: entry.kind.map(|kind| {
                        enum_name(
                            protocol::v1::FilesystemEntryKind::try_from(kind)
                                .ok()
                                .map(|value| value.as_str_name()),
                            "FILESYSTEM_ENTRY_KIND_",
                            kind,
                        )
                    }),
                });
            }
            Err(error) if error.not_found() => drivers.push(SpeakerDriver {
                path,
                present: false,
                kind: None,
            }),
            Err(error) => return Err(failure(path, error)),
        }
    }
    let names = match guest.names(INPUTS).await {
        Ok(names) => Some(names),
        Err(error) if error.not_found() => None,
        Err(error) => return Err(failure(INPUTS, error)),
    };
    let mut inputs = Vec::new();
    for entry in names
        .iter()
        .flatten()
        .filter(|name| name.starts_with("input"))
    {
        let path = format!("{INPUTS}/{entry}/name");
        let name = guest
            .download(&path, MAX_INPUT_NAME)
            .await
            .map_err(|error| failure(&path, error))?;
        let text = String::from_utf8_lossy(&name);
        let speaker = text.contains("Speaker") || text.contains("speaker");
        if speaker {
            consumers.extend_from_slice(&name);
        }
        inputs.push(InputDevice {
            entry: entry.clone(),
            name: Content::new(&name),
            speaker,
        });
    }
    Ok((
        SpeakerInventory {
            drivers,
            inputs_present: names.is_some(),
            inputs,
        },
        consumers,
    ))
}

fn write_new(directory: &Path, name: &str, bytes: &[u8]) -> eyre::Result<ProfileFile> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(directory.join(name))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(ProfileFile {
        name: name.to_string(),
        bytes: bytes.len(),
        sha256: crate::capabilities::scenario_digest(bytes),
        content: Content::new(bytes),
    })
}

pub(crate) async fn profile(
    guest: &Guest,
    operation: &ProfileOperation,
) -> eyre::Result<ProfileOutput> {
    eyre::ensure!(
        operation.directory.is_absolute() && operation.kernel_config.is_absolute(),
        "profile directory and kernel_config must be absolute host paths"
    );
    let config_metadata = std::fs::metadata(&operation.kernel_config)?;
    eyre::ensure!(
        config_metadata.is_file() && config_metadata.len() <= MAX_KERNEL_CONFIG,
        "kernel_config must be a bounded regular file"
    );
    let config = std::fs::read(&operation.kernel_config)?;
    let kernel_modules = config_modules(std::str::from_utf8(&config)?)?;

    // Collect every same-boot observation before creating any output.
    let mut observed = Vec::with_capacity(RAW_FILES.len());
    for (name, path) in RAW_FILES {
        observed.push((name, read(guest, path).await?));
    }
    let broadcast = read(guest, BROADCAST).await?;
    let modules = match guest.download(MODULES, MAX_PROFILE_FILE).await {
        Ok(bytes) => Some(bytes),
        Err(error) if error.not_found() => None,
        Err(error) => return Err(failure(MODULES, error)),
    };
    let (speaker_inventory, consumers) = speaker_inventory(guest).await?;

    let admission = match &modules {
        None => {
            eyre::ensure!(
                !kernel_modules,
                "absent /proc/modules requires the actual emitted CONFIG_MODULES=n kernel config"
            );
            serde_json::json!({
                "path": MODULES, "status": "absent", "errno": nix::errno::Errno::ENOENT as i32,
                "config_modules": false,
                "kernel_config": operation.kernel_config,
                "kernel_config_sha256": crate::capabilities::scenario_digest(&config),
            })
        }
        Some(bytes) => {
            eyre::ensure!(
                kernel_modules,
                "present /proc/modules contradicts the emitted CONFIG_MODULES=n kernel config"
            );
            eyre::ensure!(
                !String::from_utf8_lossy(bytes).contains("pcspkr"),
                "ordinary kernel has a speaker module consumer"
            );
            serde_json::json!({"path": MODULES, "status": "present", "config_modules": kernel_modules})
        }
    };
    let modules = modules.unwrap_or_else(modules_absence_record);
    let observed_file = |wanted: &str| {
        observed
            .iter()
            .find(|(name, _)| *name == wanted)
            .map(|(_, bytes)| bytes.as_slice())
            .ok_or_else(|| eyre::eyre!("missing {wanted} observation"))
    };
    let clockevent_lines =
        clockevents(observed_file("clockevent0")?, observed_file("clockevent1")?)?;
    let (broadcast_file, broadcast_state) = broadcast_files(&broadcast);
    let mut admission_bytes = serde_json::to_vec_pretty(&admission)?;
    admission_bytes.push(b'\n');

    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&operation.directory)?;
    let mut files = Vec::new();
    for (name, bytes) in &observed {
        files.push(write_new(&operation.directory, name, bytes)?);
    }
    for (name, bytes) in [
        ("clockevents", clockevent_lines.as_slice()),
        ("broadcast-clockevent", broadcast_file.as_slice()),
        ("broadcast-clockevent-state", broadcast_state.as_slice()),
        ("speaker-consumers", consumers.as_slice()),
        ("modules", modules.as_slice()),
        ("modules-admission.json", admission_bytes.as_slice()),
    ] {
        files.push(write_new(&operation.directory, name, bytes)?);
    }
    Ok(ProfileOutput {
        directory: operation.directory.clone(),
        files,
        speaker_inventory,
        modules_admission: admission,
    })
}

#[cfg(test)]
mod tests {
    use crate::attach::profile::{broadcast_files, clockevents, config_modules};

    #[test]
    fn kernel_config_requires_one_explicit_modules_decision() {
        assert!(config_modules("A=y\nCONFIG_MODULES=y\n").unwrap());
        assert!(!config_modules("# CONFIG_MODULES is not set\n").unwrap());
        assert!(config_modules("CONFIG_MODULES_TREE_LOOKUP=y\n").is_err());
        assert!(config_modules("CONFIG_MODULES=y\n# CONFIG_MODULES is not set\n").is_err());
    }

    #[test]
    fn broadcast_binding_matches_native_profile_validation() {
        let (file, state) = broadcast_files(b"");
        assert_eq!(file, b"\n");
        assert_eq!(
            state,
            b"path=/sys/devices/system/clockevents/broadcast/current_device\nread_complete=1\nbytes_read=0\nkind=no-device\n"
        );
        let (file, state) = broadcast_files(b"hpet\n");
        assert_eq!(file, b"hpet\n");
        let state = String::from_utf8(state).unwrap();
        assert!(state.ends_with("bytes_read=5\nkind=device\n"), "{state}");
    }

    #[test]
    fn clockevents_join_trimmed_device_names() {
        assert_eq!(
            clockevents(b"lapic-deadline\n", b" lapic-deadline \n").unwrap(),
            b"lapic-deadline\nlapic-deadline\n"
        );
        assert!(clockevents(&[0xff], b"x").is_err());
    }
}
