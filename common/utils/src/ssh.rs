use ssh_key::PublicKey;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

pub fn read_host_key_pin(machine_dir: &Path) -> std::io::Result<PublicKey> {
    PublicKey::from_openssh(&fs::read_to_string(machine_dir.join("ssh/known_host"))?)
        .map_err(std::io::Error::other)
}

/// Verify or create an immutable host key pin, waiting for its exclusive lock.
pub fn verify_host_key_pin(machine_dir: &Path, key: &PublicKey) -> std::io::Result<()> {
    verify_host_key_pin_with_lock(machine_dir, key, File::lock)
}

/// Verify or create an immutable host key pin without waiting for its lock.
///
/// Returns [`std::io::ErrorKind::WouldBlock`] if another operation holds the
/// lock. Filesystem operations after lock acquisition may still block.
pub fn try_verify_host_key_pin(machine_dir: &Path, key: &PublicKey) -> std::io::Result<()> {
    verify_host_key_pin_with_lock(machine_dir, key, |lock| {
        lock.try_lock().map_err(|error| match error {
            fs::TryLockError::WouldBlock => std::io::ErrorKind::WouldBlock.into(),
            fs::TryLockError::Error(error) => error,
        })
    })
}

fn verify_host_key_pin_with_lock(
    machine_dir: &Path,
    key: &PublicKey,
    acquire_lock: impl FnOnce(&File) -> std::io::Result<()>,
) -> std::io::Result<()> {
    let dir = machine_dir.join("ssh");
    fs::create_dir_all(&dir)?;
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(dir.join("known_host.lock"))?;
    acquire_lock(&lock)?;
    let path = dir.join("known_host");
    match fs::read_to_string(&path) {
        Ok(existing) => {
            let existing = PublicKey::from_openssh(&existing).map_err(std::io::Error::other)?;
            if existing.key_data() != key.key_data() {
                return Err(std::io::Error::other(
                    "guest SSH host key changed; existing pin is preserved",
                ));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let nonce = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(std::io::Error::other)?
                .as_nanos();
            let temp = dir.join(format!(".known_host.{}.{nonce}", std::process::id()));
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temp)?;
            let result = (|| -> std::io::Result<()> {
                writeln!(file, "{}", key.to_openssh().map_err(std::io::Error::other)?)?;
                file.sync_all()?;
                fs::rename(&temp, &path)?;
                File::open(&dir)?.sync_all()?;
                Ok(())
            })();
            if result.is_err() {
                let _ = fs::remove_file(temp);
            }
            result?;
        }
        Err(error) => return Err(error),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::ssh::{
        read_host_key_pin as read, try_verify_host_key_pin as try_verify,
        verify_host_key_pin as verify,
    };
    use ssh_key::{private::Ed25519Keypair, PrivateKey};
    #[test]
    fn concurrent_pin_is_immutable_and_malformed_pin_is_not_replaced() {
        let home = tempfile::tempdir().unwrap();
        let key = PrivateKey::from(Ed25519Keypair::from_seed(&[1; 32]));
        std::thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| verify(home.path(), key.public_key()).unwrap());
            }
        });
        assert_eq!(
            read(home.path()).unwrap().key_data(),
            key.public_key().key_data()
        );
        let pin = home.path().join("ssh/known_host");
        let before = std::fs::read(&pin).unwrap();
        let other = PrivateKey::from(Ed25519Keypair::from_seed(&[2; 32]));
        assert!(verify(home.path(), other.public_key()).is_err());
        assert_eq!(before, std::fs::read(&pin).unwrap());
        std::fs::write(&pin, "corrupt").unwrap();
        assert!(verify(home.path(), key.public_key()).is_err());
        assert_eq!(std::fs::read(&pin).unwrap(), b"corrupt");
    }

    #[test]
    fn nonblocking_pin_is_immutable_and_malformed_pin_is_not_replaced() {
        let home = tempfile::tempdir().unwrap();
        let key = PrivateKey::from(Ed25519Keypair::from_seed(&[3; 32]));
        try_verify(home.path(), key.public_key()).unwrap();
        assert_eq!(
            read(home.path()).unwrap().key_data(),
            key.public_key().key_data()
        );
        let pin = home.path().join("ssh/known_host");
        let before = std::fs::read(&pin).unwrap();
        try_verify(home.path(), key.public_key()).unwrap();
        assert_eq!(before, std::fs::read(&pin).unwrap());
        let other = PrivateKey::from(Ed25519Keypair::from_seed(&[4; 32]));
        assert!(try_verify(home.path(), other.public_key()).is_err());
        assert_eq!(before, std::fs::read(&pin).unwrap());
        std::fs::write(&pin, "corrupt").unwrap();
        assert!(try_verify(home.path(), key.public_key()).is_err());
        assert_eq!(std::fs::read(&pin).unwrap(), b"corrupt");
    }

    #[test]
    fn nonblocking_pin_reports_lock_contention_without_changing_pin() {
        let home = tempfile::tempdir().unwrap();
        let key = PrivateKey::from(Ed25519Keypair::from_seed(&[5; 32]));
        verify(home.path(), key.public_key()).unwrap();
        let pin = home.path().join("ssh/known_host");
        let before = std::fs::read(&pin).unwrap();
        let lock = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(home.path().join("ssh/known_host.lock"))
            .unwrap();
        lock.lock().unwrap();
        std::thread::scope(|scope| {
            let (sender, receiver) = std::sync::mpsc::channel();
            let path = home.path();
            let key = key.public_key();
            scope.spawn(move || {
                sender.send(try_verify(path, key)).unwrap();
            });
            let result = receiver.recv_timeout(std::time::Duration::from_secs(2));
            // Release before asserting so a blocking regression cannot hang the test.
            drop(lock);
            assert_eq!(
                result
                    .expect("pin verification waited for the held lock")
                    .unwrap_err()
                    .kind(),
                std::io::ErrorKind::WouldBlock
            );
        });
        assert_eq!(before, std::fs::read(&pin).unwrap());
        try_verify(home.path(), key.public_key()).unwrap();
        assert_eq!(before, std::fs::read(&pin).unwrap());
    }
}
