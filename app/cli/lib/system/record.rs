use std::fs::{File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};

use eyre::{bail, Context as _};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use uuid::Uuid;

use crate::system::config::ResolvedSystemConfig;

const MAX_RECORD_BYTES: u64 = 256 * 1024;

#[derive(Debug, Clone)]
pub(crate) struct SystemPaths {
    pub(crate) config_root: PathBuf,
    pub(crate) data_root: PathBuf,
    pub(crate) state_root: PathBuf,
    pub(crate) run_root: PathBuf,
}

impl SystemPaths {
    pub(crate) fn new(
        config_root: PathBuf,
        data_root: PathBuf,
        state_root: PathBuf,
        run_root: PathBuf,
    ) -> Self {
        Self {
            config_root,
            data_root,
            state_root,
            run_root,
        }
    }

    pub(crate) fn daemon_data(&self) -> PathBuf {
        self.data_root.join("daemon")
    }
    pub(crate) fn installation(&self) -> PathBuf {
        self.daemon_data().join("installation.json")
    }
    pub(crate) fn system_record(&self) -> PathBuf {
        self.daemon_data().join("system.json")
    }
    pub(crate) fn data_image(&self) -> PathBuf {
        self.daemon_data().join("system/data.img")
    }
    pub(crate) fn registration(&self) -> PathBuf {
        self.config_root.join("daemon/registration.json")
    }
    pub(crate) fn lifetime_lock(&self) -> PathBuf {
        self.daemon_data().join("daemon.lock")
    }
    pub(crate) fn operation_lock(&self) -> PathBuf {
        self.daemon_data().join("operation.lock")
    }
    pub(crate) fn owner(&self) -> PathBuf {
        self.daemon_data().join("owner.json")
    }
    pub(crate) fn status(&self) -> PathBuf {
        self.run_root.join("daemon/status.json")
    }
    pub(crate) fn log(&self) -> PathBuf {
        self.state_root.join("logs/daemon/daemon.log")
    }
    pub(crate) fn upgrade(&self) -> PathBuf {
        self.daemon_data().join("upgrade.json")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InstallationRecord {
    pub(crate) schema: u32,
    pub(crate) installation_id: Uuid,
    pub(crate) data_uuid: Uuid,
    pub(crate) data_layout: u32,
    pub(crate) data_size_bytes: u64,
    pub(crate) config: ResolvedSystemConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SystemRecord {
    pub(crate) schema: u32,
    pub(crate) installation_id: Uuid,
    pub(crate) engine: String,
    pub(crate) active_machine_id: String,
    pub(crate) image_reference: String,
    pub(crate) image_digest: String,
    pub(crate) data_uuid: Uuid,
    pub(crate) data_layout: u32,
    pub(crate) config_identity: String,
}

pub(crate) fn load_record<T: DeserializeOwned>(path: &Path) -> eyre::Result<Option<T>> {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("open {}", path.display())),
    };
    let length = file.metadata()?.len();
    if length > MAX_RECORD_BYTES {
        bail!(
            "record {} exceeds {} bytes",
            path.display(),
            MAX_RECORD_BYTES
        );
    }
    let mut bytes = Vec::with_capacity(length as usize);
    file.read_to_end(&mut bytes)?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("parse strict record {}", path.display()))
        .map(Some)
}

pub(crate) fn write_record<T: Serialize>(path: &Path, value: &T) -> eyre::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| eyre::eyre!("record path has no parent: {}", path.display()))?;
    std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    set_private_directory(parent)?;
    let bytes = serde_json::to_vec_pretty(value).context("serialize system record")?;
    if bytes.len() as u64 > MAX_RECORD_BYTES {
        bail!("serialized record exceeds {} bytes", MAX_RECORD_BYTES);
    }
    let temporary = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("record"),
        Uuid::new_v4()
    ));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)
        .with_context(|| format!("create {}", temporary.display()))?;
    set_private_file(&temporary)?;
    file.write_all(&bytes)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    std::fs::rename(&temporary, path).with_context(|| format!("replace {}", path.display()))?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(unix)]
fn set_private_directory(path: &Path) -> eyre::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_directory(_path: &Path) -> eyre::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_private_file(path: &Path) -> eyre::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_file(_path: &Path) -> eyre::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    use crate::system::record::{load_record, write_record};

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Fixture {
        schema: u32,
        value: String,
    }

    #[test]
    fn atomically_round_trips_strict_record() {
        let temp = tempfile::tempdir().expect("temp");
        let path = temp.path().join("daemon/fixture.json");
        let fixture = Fixture {
            schema: 1,
            value: "kept".to_string(),
        };
        write_record(&path, &fixture).expect("write");
        assert_eq!(load_record(&path).expect("load"), Some(fixture));
        std::fs::write(&path, r#"{"schema":1,"value":"kept","unknown":true}"#).expect("corrupt");
        assert!(load_record::<Fixture>(&path).is_err());
    }
}
