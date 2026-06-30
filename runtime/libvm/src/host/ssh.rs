use std::fs;
use std::path::{Path, PathBuf};

use eyre::{eyre, Context};
use ssh_key::private::Ed25519Keypair;
use ssh_key::{LineEnding, PrivateKey};

#[derive(Debug, Clone)]
pub struct SshKeyPair {
    pub private_key_path: PathBuf,
    pub public_key_path: PathBuf,
    pub public_key_openssh: String,
}

#[derive(Debug, Clone, Copy, Default)]
pub enum SshKeyAlgorithm {
    #[default]
    Ed25519,
}

pub fn generate_ssh_keypair(
    private_key_path: &Path,
    public_key_path: &Path,
    algorithm: Option<SshKeyAlgorithm>,
) -> eyre::Result<SshKeyPair> {
    ensure_parent_dir(private_key_path)?;
    ensure_parent_dir(public_key_path)?;

    let private_key = match algorithm.unwrap_or_default() {
        SshKeyAlgorithm::Ed25519 => generate_ed25519_private_key()?,
    };

    private_key
        .write_openssh_file(private_key_path, LineEnding::LF)
        .with_context(|| format!("write SSH private key {}", private_key_path.display()))?;
    set_private_key_permissions(private_key_path)?;

    let public_key_openssh = private_key
        .public_key()
        .to_openssh()
        .context("encode SSH public key")?;
    fs::write(public_key_path, format!("{public_key_openssh}\n"))
        .with_context(|| format!("write SSH public key {}", public_key_path.display()))?;
    set_public_key_permissions(public_key_path)?;

    Ok(SshKeyPair {
        private_key_path: private_key_path.to_path_buf(),
        public_key_path: public_key_path.to_path_buf(),
        public_key_openssh,
    })
}

fn generate_ed25519_private_key() -> eyre::Result<PrivateKey> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed)
        .map_err(|err| eyre!("collect random bytes for SSH keypair failed: {err}"))?;
    Ok(PrivateKey::from(Ed25519Keypair::from_seed(&seed)))
}

fn ensure_parent_dir(path: &Path) -> eyre::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| eyre!("SSH key path has no parent directory: {}", path.display()))?;
    fs::create_dir_all(parent)
        .with_context(|| format!("create SSH key directory {}", parent.display()))?;
    set_keys_dir_permissions(parent)
}

#[cfg(unix)]
fn set_keys_dir_permissions(path: &Path) -> eyre::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("set permissions for {}", path.display()))
}

#[cfg(not(unix))]
fn set_keys_dir_permissions(_path: &Path) -> eyre::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_private_key_permissions(path: &Path) -> eyre::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("set permissions for {}", path.display()))
}

#[cfg(not(unix))]
fn set_private_key_permissions(_path: &Path) -> eyre::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_public_key_permissions(path: &Path) -> eyre::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o644))
        .with_context(|| format!("set permissions for {}", path.display()))
}

#[cfg(not(unix))]
fn set_public_key_permissions(_path: &Path) -> eyre::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{generate_ssh_keypair, SshKeyAlgorithm};

    #[test]
    fn generate_ssh_keypair_writes_private_and_public_keys() {
        let temp = tempfile::tempdir().expect("create tempdir");
        let private_key_path = temp.path().join("id_ed25519");
        let public_key_path = temp.path().join("id_ed25519.pub");

        let keys = generate_ssh_keypair(&private_key_path, &public_key_path, None)
            .expect("generate SSH keypair");

        assert_eq!(keys.private_key_path, private_key_path);
        assert_eq!(keys.public_key_path, public_key_path);
        assert!(keys.private_key_path.is_file());
        assert!(keys.public_key_path.is_file());
        assert!(keys.public_key_openssh.starts_with("ssh-ed25519 "));
    }

    #[test]
    fn generate_ssh_keypair_accepts_explicit_algorithm() {
        let temp = tempfile::tempdir().expect("create tempdir");
        let keys = generate_ssh_keypair(
            &temp.path().join("id_ed25519"),
            &temp.path().join("id_ed25519.pub"),
            Some(SshKeyAlgorithm::Ed25519),
        )
        .expect("generate SSH keypair");

        assert!(keys.public_key_openssh.starts_with("ssh-ed25519 "));
    }

    #[cfg(unix)]
    #[test]
    fn generate_ssh_keypair_sets_key_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().expect("create tempdir");
        let private_key_path = temp.path().join("id_ed25519");
        let public_key_path = temp.path().join("id_ed25519.pub");

        generate_ssh_keypair(&private_key_path, &public_key_path, None)
            .expect("generate SSH keypair");

        let private_mode = std::fs::metadata(private_key_path)
            .expect("stat private key")
            .permissions()
            .mode()
            & 0o777;
        let public_mode = std::fs::metadata(public_key_path)
            .expect("stat public key")
            .permissions()
            .mode()
            & 0o777;

        assert_eq!(private_mode, 0o600);
        assert_eq!(public_mode, 0o644);
    }
}
