use std::fs::{File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};

use eyre::{bail, Context as _};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use uuid::Uuid;

use crate::system::config::ResolvedSystemConfig;

const MAX_RECORD_BYTES: u64 = 256 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SystemPaths {
    pub(crate) config_root: PathBuf,
    pub(crate) home: PathBuf,
    pub(crate) run_root: PathBuf,
}

impl SystemPaths {
    pub(crate) fn new(config_root: PathBuf, home: PathBuf, run_root: PathBuf) -> Self {
        Self {
            config_root,
            home,
            run_root,
        }
    }

    pub(crate) fn daemon_data(&self) -> PathBuf {
        self.home.join("daemon")
    }
    pub(crate) fn daemon(&self) -> PathBuf {
        self.daemon_data().join("daemon.json")
    }
    pub(crate) fn data_image(&self) -> PathBuf {
        self.daemon_data().join("system/data.img")
    }
    pub(crate) fn lifetime_lock(&self) -> PathBuf {
        self.daemon_data().join("daemon.lock")
    }
    pub(crate) fn operation_lock(&self) -> PathBuf {
        self.daemon_data().join("operation.lock")
    }
    pub(crate) fn status(&self) -> PathBuf {
        self.daemon_data().join("status.json")
    }
    pub(crate) fn log(&self) -> PathBuf {
        self.home.join("logs/daemon/daemon.log")
    }
    /// Captured stdout/stderr of the native service process (launchd only; systemd
    /// keeps it in the journal). Surfaces panics and failures that happen before the
    /// supervisor publishes a status record.
    pub(crate) fn native_log(&self) -> PathBuf {
        self.home.join("logs/daemon/native.log")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DaemonRecord {
    pub(crate) schema: u32,
    pub(crate) installation_id: Uuid,
    pub(crate) data_uuid: Uuid,
    pub(crate) data_layout: u32,
    pub(crate) data_size_bytes: u64,
    pub(crate) configured_image: String,
    pub(crate) config: ResolvedSystemConfig,
    pub(crate) machine_id: Option<String>,
    pub(crate) service: crate::system::service::ServiceConfig,
    pub(crate) upgrade: Option<crate::system::upgrade::UpgradeRecord>,
}

impl DaemonRecord {
    pub(crate) fn new(paths: &SystemPaths, config: ResolvedSystemConfig) -> eyre::Result<Self> {
        Ok(Self {
            schema: 1,
            installation_id: Uuid::new_v4(),
            data_uuid: Uuid::new_v4(),
            data_layout: 1,
            data_size_bytes: config.data_size_bytes,
            configured_image: config.image.clone(),
            config,
            machine_id: None,
            service: crate::system::service::ServiceConfig::new(paths)?,
            upgrade: None,
        })
    }

    pub(crate) fn load(paths: &SystemPaths) -> eyre::Result<Option<Self>> {
        Self::load_from(&paths.daemon())
    }

    pub(crate) fn load_from(path: &Path) -> eyre::Result<Option<Self>> {
        if !path.is_absolute() {
            bail!("daemon state path must be absolute");
        }
        let record = load_record::<Self>(path)?;
        if let Some(record) = &record {
            record.validate()?;
        }
        Ok(record)
    }

    pub(crate) fn validate(&self) -> eyre::Result<()> {
        if self.schema != 1 || self.data_layout != 1 {
            bail!("unsupported daemon state schema or data layout");
        }
        if let Some(upgrade) = &self.upgrade {
            upgrade.validate(self)?;
        }
        Ok(())
    }

    pub(crate) fn save(&self, paths: &SystemPaths) -> eyre::Result<()> {
        self.validate()?;
        write_record(&paths.daemon(), self)
    }

    pub(crate) fn machine_id(&self) -> eyre::Result<&str> {
        self.machine_id.as_deref().ok_or_else(|| {
            eyre::eyre!("system VM has not been created yet; run `silo daemon up` to finish setup")
        })
    }

    pub(crate) fn owns_machine(&self, id: &str) -> bool {
        self.machine_id.as_deref() == Some(id)
            || self
                .upgrade
                .as_ref()
                .is_some_and(|upgrade| upgrade.owns_machine(id))
    }

    pub(crate) fn require_no_pending_upgrade(&self) -> eyre::Result<()> {
        if self
            .upgrade
            .as_ref()
            .is_some_and(|upgrade| !upgrade.is_complete())
        {
            bail!("a system image upgrade is pending; run `silo daemon upgrade --recover`");
        }
        Ok(())
    }
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
pub(crate) mod tests {
    use serde::{Deserialize, Serialize};

    use crate::system::record::{load_record, write_record, DaemonRecord, SystemPaths};

    pub(crate) fn fixture(root: &std::path::Path) -> (SystemPaths, DaemonRecord) {
        let paths = SystemPaths::new(root.join("config"), root.join("home"), root.join("run"));
        let config: crate::system::config::SystemConfig = serde_yaml_ng::from_str(
            "version: '1'\nsystem:\n  image: registry.example/system@sha256:old\n",
        )
        .expect("config");
        let mut config = config.resolve(root, root, None).expect("resolve");
        config.data_size_bytes = 256 * 1024 * 1024;
        let state = DaemonRecord::new(&paths, config).expect("state");
        (paths, state)
    }

    #[test]
    fn daemon_record_tracks_identity_not_vm_status_or_image_metadata() {
        let temp = tempfile::tempdir().expect("temp");
        let (paths, mut state) = fixture(temp.path());
        assert!(DaemonRecord::load(&paths).expect("load").is_none());
        assert!(state.machine_id().is_err());
        state.save(&paths).expect("save incomplete setup");
        assert_eq!(
            DaemonRecord::load(&paths).expect("load"),
            Some(state.clone())
        );
        state.machine_id = Some("vm-1".to_string());
        state.save(&paths).expect("save provisioned setup");
        assert!(state.owns_machine("vm-1"));
        assert!(!state.owns_machine("other"));
        let json: serde_json::Value = load_record(&paths.daemon()).expect("json").expect("exists");
        for field in [
            "phase",
            "status",
            "image_digest",
            "image_reference",
            "config_identity",
        ] {
            assert!(json.get(field).is_none(), "redundant field {field}");
        }
        assert_eq!(
            DaemonRecord::load(&paths).expect("load"),
            Some(state.clone())
        );
        state.schema = 2;
        assert!(state.save(&paths).is_err());
        assert_eq!(
            DaemonRecord::load(&paths)
                .expect("original remains")
                .expect("exists")
                .schema,
            1
        );
    }

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
