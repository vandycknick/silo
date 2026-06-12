use std::fs;
use std::path::PathBuf;

use eyre::{eyre, Context};
use ssh_key::private::Ed25519Keypair;
use ssh_key::{LineEnding, PrivateKey};

use crate::paths::resolve_default_config_dir;

#[derive(Debug, Clone)]
pub struct UserSshKeys {
    pub private_key_path: PathBuf,
    pub public_key_path: PathBuf,
    pub public_key_openssh: String,
}

pub fn ensure_user_ssh_keys() -> eyre::Result<UserSshKeys> {
    let config_home = resolve_default_config_dir().map_err(|err| eyre!(err))?;
    fs::create_dir_all(&config_home).context("create bento config home")?;

    let private_key_path = config_home.join("id_ed25519");
    let public_key_path = config_home.join("id_ed25519.pub");

    let private_exists = private_key_path.is_file();
    let public_exists = public_key_path.is_file();

    let public_key_openssh = if private_exists {
        let private_key =
            PrivateKey::read_openssh_file(&private_key_path).context("read bento private key")?;
        let public_key = private_key
            .public_key()
            .to_openssh()
            .context("encode bento public key")?;

        if !public_exists {
            fs::write(&public_key_path, format!("{public_key}\n"))
                .context("write bento public key")?;
            set_public_key_permissions(&public_key_path)?;
        }

        public_key
    } else {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed)
            .map_err(|err| eyre!("collect random bytes for SSH keypair failed: {err}"))?;
        let private_key = PrivateKey::from(Ed25519Keypair::from_seed(&seed));
        private_key
            .write_openssh_file(&private_key_path, LineEnding::LF)
            .context("write bento private key")?;

        let public_key = private_key
            .public_key()
            .to_openssh()
            .context("encode bento public key")?;
        fs::write(&public_key_path, format!("{public_key}\n")).context("write bento public key")?;
        set_public_key_permissions(&public_key_path)?;
        public_key
    };

    Ok(UserSshKeys {
        private_key_path,
        public_key_path,
        public_key_openssh,
    })
}

fn set_public_key_permissions(path: &PathBuf) -> eyre::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let perms = fs::Permissions::from_mode(0o644);
    fs::set_permissions(path, perms)
        .with_context(|| format!("set permissions for {}", path.display()))
}
