use crate::provision::write_file;
use agent_spec::AgentSshConfig;
use eyre::Context;
use russh::keys::PublicKey;
use std::fs;
use std::path::Path;

pub(crate) const CONFIG: &str = "/etc/ssh/silo_sshd_config";
pub(crate) const CA: &str = "/etc/ssh/silo_ca.pub";
pub(crate) const HOST_KEY: &str = "/var/lib/silo-agent/ssh/ssh_host_ed25519_key";

pub(crate) fn policy(ca: &Path, host: &Path) -> String {
    // PAM handles account/session policy for provisioned password-locked users;
    // both password and keyboard-interactive authentication remain disabled.
    // Command directives are omitted from this Include-free authoritative file:
    // their disabled defaults render as `none` in -T. Explicit `none` can be
    // retained as a non-null principal command by OpenSSH's inetd re-exec.
    format!("HostKey {}\nTrustedUserCAKeys {}\nAuthenticationMethods publickey\nPubkeyAuthentication yes\nPubkeyAcceptedAlgorithms ssh-ed25519-cert-v01@openssh.com\nCASignatureAlgorithms ssh-ed25519\nAuthorizedKeysFile none\nAuthorizedPrincipalsFile none\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nHostbasedAuthentication no\nGSSAPIAuthentication no\nPermitEmptyPasswords no\nUsePAM yes\nPermitRootLogin yes\nAcceptEnv SILO_*\nSubsystem sftp internal-sftp\nLogLevel VERBOSE\n", host.display(), ca.display())
}

pub(crate) fn systemd_override(config: &Path, inetd: bool) -> String {
    let mode = if inetd { "-i" } else { "-D" };
    format!("[Service]\nExecStartPre=\nExecStartPre=/usr/sbin/sshd -t -f {}\nExecStart=\nExecStart=/usr/sbin/sshd {mode} -f {}\n", config.display(), config.display())
}

pub(crate) fn prepare(config: &AgentSshConfig) -> eyre::Result<()> {
    prepare_at(config, Path::new("/"))
}

pub(crate) fn parse_ca(value: &str) -> eyre::Result<PublicKey> {
    if value.trim().contains(['\n', '\r']) || value.len() > 1024 {
        eyre::bail!("SSH CA trust must contain exactly one bounded public key line");
    }
    let ca = PublicKey::from_openssh(value).context("parse SSH CA trust")?;
    if ca.algorithm() != russh::keys::ssh_key::Algorithm::Ed25519 {
        eyre::bail!("SSH CA trust must be Ed25519");
    }
    Ok(ca)
}

pub(crate) fn replace_trust(value: &str) -> eyre::Result<PublicKey> {
    replace_trust_at(value, Path::new(CA))
}

fn replace_trust_at(value: &str, path: &Path) -> eyre::Result<PublicKey> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let ca = parse_ca(value)?;
    let parent = path
        .parent()
        .ok_or_else(|| eyre::eyre!("SSH CA has no parent"))?;
    let temporary = parent.join(format!(".silo-ca-{}", uuid::Uuid::new_v4()));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(&temporary)?;
    let result = (|| -> eyre::Result<()> {
        writeln!(file, "{}", ca.to_openssh()?)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        fs::File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result?;
    Ok(ca)
}

fn prepare_at(config: &AgentSshConfig, root: &Path) -> eyre::Result<()> {
    let ca =
        parse_ca(config.trusted_ca.as_deref().ok_or_else(|| {
            eyre::eyre!("missing mandatory SSH CA trust; recreate this machine")
        })?)?;
    let line = ca.to_openssh()?;
    let ca_path = root.join(&CA[1..]);
    let host_path = root.join(&HOST_KEY[1..]);
    let config_path = root.join(&CONFIG[1..]);
    fs::create_dir_all(root.join("etc/ssh"))?;
    write_file(&ca_path, format!("{line}\n"), 0o644)?;
    crate::ssh::agent::persistent_host_key(&host_path)?;
    write_file(&config_path, policy(&ca_path, &host_path), 0o600)?;
    // Install before handing PID1 to systemd, so its generated socket services
    // cannot start a connection handler with image-owned authentication rules.
    for unit in [
        "sshd-vsock@.service",
        "sshd-vsock.service",
        "sshd.service",
        "ssh.service",
    ] {
        let dir = root.join("run/systemd/system").join(format!("{unit}.d"));
        fs::create_dir_all(&dir)?;
        write_file(
            &dir.join("00-silo-ca.conf"),
            systemd_override(&config_path, unit.starts_with("sshd-vsock")),
            0o644,
        )?;
    }
    Ok(())
}

pub(crate) fn verify_trust(config: &AgentSshConfig) -> eyre::Result<()> {
    verify_at(config, Path::new("/"))
}

fn verify_at(config: &AgentSshConfig, root: &Path) -> eyre::Result<()> {
    let expected = PublicKey::from_openssh(
        config
            .trusted_ca
            .as_deref()
            .ok_or_else(|| eyre::eyre!("missing mandatory SSH CA trust"))?,
    )?;
    let ca_path = root.join(&CA[1..]);
    let host_path = root.join(&HOST_KEY[1..]);
    let config_path = root.join(&CONFIG[1..]);
    let actual = PublicKey::from_openssh(&fs::read_to_string(&ca_path)?)?;
    if actual.key_data() != expected.key_data() {
        eyre::bail!("SSH CA trust changed during provisioning");
    }
    if fs::read_to_string(config_path)? != policy(&ca_path, &host_path) {
        eyre::bail!("SSH policy changed during provisioning");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::provision::ssh::{prepare_at, verify_at, CONFIG, HOST_KEY};
    use agent_spec::AgentSshConfig;
    use russh::keys::ssh_key::{private::Ed25519Keypair, PrivateKey};
    #[test]
    fn activation_replaces_ca_without_modifying_trust_on_invalid_input() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("ca.pub");
        let source = PrivateKey::from(Ed25519Keypair::from_seed(&[1; 32]));
        let destination = PrivateKey::from(Ed25519Keypair::from_seed(&[2; 32]));
        let source_line = source.public_key().to_openssh().unwrap();
        std::fs::write(&path, &source_line).unwrap();
        let held_source = std::fs::File::open(&path).unwrap();
        for invalid in ["", "ssh-ed25519 broken", "key\nsecond"] {
            assert!(crate::provision::ssh::replace_trust_at(invalid, &path).is_err());
            assert_eq!(std::fs::read_to_string(&path).unwrap(), source_line);
        }
        let new_key = crate::provision::ssh::replace_trust_at(
            &destination.public_key().to_openssh().unwrap(),
            &path,
        )
        .unwrap();
        assert_eq!(new_key.key_data(), destination.public_key().key_data());
        let persisted =
            russh::keys::PublicKey::from_openssh(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(persisted.key_data(), destination.public_key().key_data());
        use std::os::unix::fs::MetadataExt;
        assert_ne!(
            held_source.metadata().unwrap().ino(),
            std::fs::metadata(&path).unwrap().ino()
        );
    }
    #[test]
    fn trust_is_mandatory_idempotent_and_userdata_changes_are_fatal() {
        let root = tempfile::tempdir().unwrap();
        assert!(prepare_at(&AgentSshConfig::default(), root.path()).is_err());
        assert!(!root.path().join("etc/ssh").exists());
        let key = PrivateKey::from(Ed25519Keypair::from_seed(&[1; 32]));
        let config = AgentSshConfig {
            trusted_ca: Some(key.public_key().to_openssh().unwrap()),
        };
        let stale = root.path().join("home/silo/.ssh/authorized_keys");
        std::fs::create_dir_all(stale.parent().unwrap()).unwrap();
        std::fs::write(&stale, "user-owned-keys").unwrap();
        prepare_at(&config, root.path()).unwrap();
        let host = root.path().join(&HOST_KEY[1..]);
        let before = std::fs::read(&host).unwrap();
        prepare_at(&config, root.path()).unwrap();
        verify_at(&config, root.path()).unwrap();
        assert_eq!(before, std::fs::read(&host).unwrap());
        assert_eq!(std::fs::read(&stale).unwrap(), b"user-owned-keys");
        std::fs::write(root.path().join(&CONFIG[1..]), "PasswordAuthentication yes").unwrap();
        assert!(verify_at(&config, root.path()).is_err());
        let broken = tempfile::tempdir().unwrap();
        std::fs::write(broken.path().join("etc"), "not a directory").unwrap();
        assert!(prepare_at(&config, broken.path()).is_err());
    }
}
