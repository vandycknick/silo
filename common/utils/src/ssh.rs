use ssh_key::PublicKey;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

pub fn read_host_key_pin(machine_dir: &Path) -> std::io::Result<PublicKey> {
    PublicKey::from_openssh(&fs::read_to_string(machine_dir.join("ssh/known_host"))?)
        .map_err(std::io::Error::other)
}

pub fn verify_host_key_pin(machine_dir: &Path, key: &PublicKey) -> std::io::Result<()> {
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
    lock.lock()?;
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
    use crate::ssh::{read_host_key_pin as read, verify_host_key_pin as verify};
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
}
