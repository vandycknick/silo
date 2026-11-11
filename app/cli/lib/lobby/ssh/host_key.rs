use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};

use russh::keys::{
    ssh_key::{private::Ed25519Keypair, LineEnding},
    Algorithm, PrivateKey,
};

use crate::lobby::state;

pub(crate) fn load(home: &Path) -> io::Result<PrivateKey> {
    let dir = home.join("lobby");
    state::private_dir(&dir)?;
    let path = dir.join("ssh_host_ed25519_key");
    match read(&path) {
        Ok(key) => return Ok(key),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let mut seed = [0; 32];
    File::open("/dev/urandom")?.read_exact(&mut seed)?;
    let key = PrivateKey::new(Ed25519Keypair::from_seed(&seed).into(), "silo lobby")
        .map_err(io::Error::other)?;
    seed.fill(0);
    let encoded = key.to_openssh(LineEnding::LF).map_err(io::Error::other)?;
    let mut temp = tempfile::NamedTempFile::new_in(&dir)?;
    temp.as_file()
        .set_permissions(std::fs::Permissions::from_mode(0o600))?;
    temp.write_all(encoded.as_bytes())?;
    temp.as_file().sync_all()?;
    match temp.persist_noclobber(&path) {
        Ok(_) => {
            state::sync_dir(&dir)?;
            Ok(key)
        }
        Err(error) if error.error.kind() == io::ErrorKind::AlreadyExists => read(&path),
        Err(error) => Err(error.error),
    }
}

fn read(path: &Path) -> io::Result<PrivateKey> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits())
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != nix::unistd::Uid::effective().as_raw()
        || metadata.mode() & 0o077 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "SSH host key must be owned and private",
        ));
    }
    let mut bytes = Vec::new();
    (&mut file).take(16385).read_to_end(&mut bytes)?;
    let key = PrivateKey::from_openssh(&bytes).map_err(io::Error::other)?;
    if key.algorithm() != Algorithm::Ed25519 || key.is_encrypted() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "SSH host key must be unencrypted Ed25519",
        ));
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use crate::lobby::ssh::host_key::load;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn key_is_private_and_stable() {
        let home = tempfile::tempdir().unwrap();
        let first = load(home.path()).unwrap();
        let second = load(home.path()).unwrap();
        assert_eq!(first.public_key(), second.public_key());
        assert_eq!(
            std::fs::metadata(home.path().join("lobby/ssh_host_ed25519_key"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}
