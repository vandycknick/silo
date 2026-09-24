use std::fs::{File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::path::Path;

use eyre::{bail, Context as _};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use uuid::Uuid;

use crate::config::ResolvedSystemConfig;
use crate::paths::SystemPaths;

const MAX_RECORD_BYTES: u64 = 256 * 1024;

/// The installation record. Strict, unlike the published status: an unknown field
/// means a different silod wrote it, and guessing could orphan engine data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DaemonRecord {
    pub(crate) schema: u32,
    pub(crate) installation_id: Uuid,
    pub(crate) data_uuid: Uuid,
    pub(crate) data_layout: u32,
    pub(crate) data_size_bytes: u64,
    /// The image reference the active system VM was created or upgraded from.
    pub(crate) configured_image: String,
    pub(crate) config: ResolvedSystemConfig,
    pub(crate) machine_id: Option<String>,
    pub(crate) upgrade: Option<crate::upgrade::UpgradeRecord>,
}

impl DaemonRecord {
    pub(crate) fn new(config: ResolvedSystemConfig) -> Self {
        Self {
            schema: 1,
            installation_id: Uuid::new_v4(),
            data_uuid: Uuid::new_v4(),
            data_layout: 1,
            data_size_bytes: config.data_size_bytes,
            configured_image: config.image.clone(),
            config,
            machine_id: None,
            upgrade: None,
        }
    }

    pub(crate) fn load(paths: &SystemPaths) -> eyre::Result<Option<Self>> {
        let Some(value) = load_record::<serde_json::Value>(&paths.record())? else {
            return Ok(None);
        };
        let record: Self = serde_json::from_value(without_controller_fields(value))
            .with_context(|| format!("parse strict record {}", paths.record().display()))?;
        record.validate()?;
        Ok(Some(record))
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
        write_record(&paths.record(), self)
    }

    pub(crate) fn machine_id(&self) -> eyre::Result<&str> {
        self.machine_id
            .as_deref()
            .ok_or_else(|| eyre::eyre!("the system VM has not been created yet"))
    }
}

/// Records written while the CLI embedded the daemon also carried its service
/// registration. That belongs to the controller now; drop it rather than refuse
/// an installation whose engine data is otherwise intact.
fn without_controller_fields(mut value: serde_json::Value) -> serde_json::Value {
    if let Some(record) = value.as_object_mut() {
        record.remove("service");
        if let Some(upgrade) = record
            .get_mut("upgrade")
            .and_then(serde_json::Value::as_object_mut)
        {
            upgrade.remove("service_was_enabled");
        }
    }
    value
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

    use crate::paths::SystemPaths;
    use crate::record::{load_record, write_record, DaemonRecord};

    pub(crate) fn fixture(root: &std::path::Path) -> (SystemPaths, DaemonRecord) {
        let paths = SystemPaths::new(root.join("home"), root.join("run"));
        let overrides = silod_spec::arguments::SystemOverrides {
            image: Some("registry.example/system@sha256:old".into()),
            data_size: Some("512MiB".into()),
            ..Default::default()
        };
        let desired = crate::config::resolve(&overrides, root, &paths.docker_socket(), None)
            .expect("resolve");
        (paths, DaemonRecord::new(desired.config))
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
        let json: serde_json::Value = load_record(&paths.record()).expect("json").expect("exists");
        for field in [
            "phase",
            "status",
            "image_digest",
            "image_reference",
            "config_identity",
            "service",
        ] {
            assert!(json.get(field).is_none(), "redundant field {field}");
        }
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

    #[test]
    fn records_from_the_embedded_daemon_drop_only_service_registration() {
        let temp = tempfile::tempdir().expect("temp");
        let (paths, state) = fixture(temp.path());
        let mut legacy = serde_json::to_value(&state).expect("serialize");
        legacy["service"] = serde_json::json!({
            "executable": "/bin/silo", "config_root": "/c", "home": "/h",
            "native_service_path": "/s",
        });
        write_record(&paths.record(), &legacy).expect("legacy record");
        assert_eq!(DaemonRecord::load(&paths).expect("migrate"), Some(state));

        legacy["unexpected"] = serde_json::json!(true);
        write_record(&paths.record(), &legacy).expect("foreign record");
        assert!(DaemonRecord::load(&paths).is_err());
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
