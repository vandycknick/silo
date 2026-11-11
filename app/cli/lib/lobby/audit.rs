use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use serde::Serialize;

use crate::lobby::failure::Code;
use crate::lobby::identity::Principal;
use crate::lobby::state::{private_dir, sync_dir};

#[derive(Debug, Clone, Serialize)]
pub(crate) struct Decision {
    pub(crate) time: DateTime<Utc>,
    pub(crate) principals: Vec<Principal>,
    pub(crate) node_id: String,
    pub(crate) action: String,
    pub(crate) allowed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) code: Option<Code>,
}

struct Writer {
    file: Option<File>,
    size: u64,
}

pub(crate) struct Audit {
    path: PathBuf,
    limit: u64,
    backups: usize,
    writer: Mutex<Writer>,
}

impl Audit {
    pub(crate) fn open(home: impl AsRef<Path>, limit: u64, backups: usize) -> io::Result<Self> {
        if limit == 0 || backups == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid audit rotation limits",
            ));
        }
        let dir = home.as_ref().join("lobby");
        private_dir(&dir)?;
        let path = dir.join("audit.log");
        let (file, size) = open_file(&path)?;
        Ok(Self {
            path,
            limit,
            backups,
            writer: Mutex::new(Writer {
                file: Some(file),
                size,
            }),
        })
    }

    pub(crate) fn append(&self, mut decision: Decision) -> io::Result<()> {
        let mut writer = self.writer.lock();
        if writer.file.is_none() {
            return Err(io::Error::other("audit closed"));
        }
        decision.time = Utc::now();
        let mut bytes = serde_json::to_vec(&decision)?;
        bytes.push(b'\n');
        if writer.size > 0 && writer.size.saturating_add(bytes.len() as u64) > self.limit {
            if let Some(file) = writer.file.take() {
                file.sync_all()?;
            }
            for index in (2..=self.backups).rev() {
                match fs::rename(self.backup(index - 1), self.backup(index)) {
                    Ok(()) => {}
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error),
                }
            }
            fs::rename(&self.path, self.backup(1))?;
            let (file, size) = open_file(&self.path)?;
            writer.file = Some(file);
            writer.size = size;
            if let Some(parent) = self.path.parent() {
                sync_dir(parent)?;
            }
        }
        let mut written = 0;
        let result = {
            let Some(file) = writer.file.as_mut() else {
                return Err(io::Error::other("audit closed"));
            };
            loop {
                match file.write(&bytes[written..]) {
                    Ok(0) => {
                        break Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "failed to append audit decision",
                        ))
                    }
                    Ok(count) => {
                        written += count;
                        if written == bytes.len() {
                            break file.sync_all();
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(error) => break Err(error),
                }
            }
        };
        writer.size += written as u64;
        result?;
        Ok(())
    }

    fn backup(&self, index: usize) -> PathBuf {
        let mut name = self.path.as_os_str().to_os_string();
        name.push(format!(".{index}"));
        PathBuf::from(name)
    }

    pub(crate) fn close(&self) -> io::Result<()> {
        if let Some(file) = self.writer.lock().file.take() {
            file.sync_all()?;
        }
        Ok(())
    }
}

fn open_file(path: &Path) -> io::Result<(File, u64)> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if !metadata.is_file() || metadata.mode() & 0o077 != 0 => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "audit must be a private regular file",
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags((nix::fcntl::OFlag::O_NOFOLLOW | nix::fcntl::OFlag::O_CLOEXEC).bits())
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "audit must be a private regular file",
        ));
    }
    Ok((file, metadata.len()))
}

#[cfg(test)]
mod tests {
    use crate::lobby::audit::{Audit, Decision};
    use crate::lobby::identity::Principal;
    use std::{
        collections::HashSet,
        fs,
        os::unix::fs::{symlink, PermissionsExt},
        sync::Arc,
    };

    fn decision(node_id: String) -> Decision {
        Decision {
            time: chrono::DateTime::default(),
            principals: vec![Principal::parse("user:1").unwrap()],
            node_id,
            action: "vm.read".into(),
            allowed: true,
            code: None,
        }
    }

    #[test]
    fn rotation_concurrent_real_files() {
        let home = tempfile::tempdir().unwrap();
        let audit = Arc::new(Audit::open(home.path(), 1024, 100).unwrap());
        let workers: Vec<_> = (0..8)
            .map(|worker| {
                let audit = audit.clone();
                std::thread::spawn(move || {
                    for i in 0..20 {
                        audit.append(decision(format!("{worker}-{i}"))).unwrap();
                    }
                })
            })
            .collect();
        for worker in workers {
            worker.join().unwrap();
        }
        audit.close().unwrap();
        audit.close().unwrap();
        assert!(audit.append(decision("closed".into())).is_err());
        let mut seen = HashSet::new();
        for entry in fs::read_dir(home.path().join("lobby")).unwrap() {
            let path = entry.unwrap().path();
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            for line in fs::read_to_string(path).unwrap().lines() {
                let value: serde_json::Value = serde_json::from_str(line).unwrap();
                assert!(seen.insert(value["node_id"].as_str().unwrap().to_owned()));
                assert_ne!(value["time"], "1970-01-01T00:00:00Z");
                assert!(value.get("code").is_none());
            }
        }
        assert_eq!(seen.len(), 160);
    }

    #[test]
    fn unsafe_files_and_invalid_rotation_limits_are_rejected() {
        let home = tempfile::tempdir().unwrap();
        assert!(Audit::open(home.path(), 0, 1).is_err());
        assert!(Audit::open(home.path(), 1, 0).is_err());
        let dir = home.path().join("lobby");
        crate::lobby::state::private_dir(&dir).unwrap();
        let path = dir.join("audit.log");
        fs::write(&path, "").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(Audit::open(home.path(), 1024, 1).is_err());
        fs::remove_file(&path).unwrap();
        symlink(home.path().join("target"), &path).unwrap();
        assert!(Audit::open(home.path(), 1024, 1).is_err());
    }

    #[test]
    fn backups_are_bounded_and_reopening_appends() {
        let home = tempfile::tempdir().unwrap();
        let audit = Audit::open(home.path(), 1, 2).unwrap();
        for i in 0..5 {
            audit.append(decision(i.to_string())).unwrap();
        }
        audit.close().unwrap();
        assert_eq!(fs::read_dir(home.path().join("lobby")).unwrap().count(), 3);
        let audit = Audit::open(home.path(), 4096, 2).unwrap();
        audit.append(decision("last".into())).unwrap();
        audit.close().unwrap();
        assert_eq!(
            fs::read_to_string(home.path().join("lobby/audit.log"))
                .unwrap()
                .lines()
                .count(),
            2
        );
    }
}
