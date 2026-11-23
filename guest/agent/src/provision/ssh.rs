use crate::provision::write_file;
use agent_spec::AgentSshConfig;
use eyre::Context;
use russh::keys::PublicKey;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

pub(crate) const CONFIG: &str = "/etc/ssh/silo_sshd_config";
pub(crate) const CA: &str = "/etc/ssh/silo_ca.pub";
pub(crate) const HOST_KEY: &str = "/var/lib/silo-agent/ssh/ssh_host_ed25519_key";

pub(crate) fn policy(ca: &Path, host: &Path, environment: &BTreeMap<String, String>) -> String {
    // PAM handles account/session policy for provisioned password-locked users;
    // both password and keyboard-interactive authentication remain disabled.
    // Command directives are omitted from this Include-free authoritative file:
    // their disabled defaults render as `none` in -T. Explicit `none` can be
    // retained as a non-null principal command by OpenSSH's inetd re-exec.
    let mut policy = format!("HostKey {}\nTrustedUserCAKeys {}\nAuthenticationMethods publickey\nPubkeyAuthentication yes\nPubkeyAcceptedAlgorithms ssh-ed25519-cert-v01@openssh.com\nCASignatureAlgorithms ssh-ed25519\nAuthorizedKeysFile none\nAuthorizedPrincipalsFile none\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nHostbasedAuthentication no\nGSSAPIAuthentication no\nPermitEmptyPasswords no\nUsePAM yes\nPermitRootLogin yes\nAcceptEnv SILO_*\nSubsystem sftp internal-sftp\nLogLevel VERBOSE\n", host.display(), ca.display());
    // sshd honors only the first SetEnv line, so every variable shares one.
    // Each `NAME=VALUE` is one double-quoted argv token; inside quotes sshd's
    // argv_split unescapes only `\"` and `\\`, and `#` is literal.
    let mut set_env = String::new();
    for (name, value) in sshd_environment(environment) {
        set_env.push_str(" \"");
        set_env.push_str(name);
        set_env.push('=');
        for character in value.chars() {
            if matches!(character, '"' | '\\') {
                set_env.push('\\');
            }
            set_env.push(character);
        }
        set_env.push('"');
    }
    if !set_env.is_empty() {
        policy.push_str("SetEnv");
        policy.push_str(&set_env);
        policy.push('\n');
    }
    policy
}

/// sshd_config is line based, so a value spanning lines cannot be expressed.
fn sshd_environment(environment: &BTreeMap<String, String>) -> impl Iterator<Item = (&str, &str)> {
    crate::ssh::inherited_environment(environment)
        .filter(|(_, value)| !value.contains(['\n', '\r']))
}

pub(crate) fn systemd_override(config: &Path, inetd: bool) -> String {
    let mode = if inetd { "-i" } else { "-D" };
    format!("[Service]\nExecStartPre=\nExecStartPre=/usr/sbin/sshd -t -f {}\nExecStart=\nExecStart=/usr/sbin/sshd {mode} -f {}\n", config.display(), config.display())
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

pub(crate) fn prepare(config: &AgentSshConfig) -> eyre::Result<()> {
    if crate::ssh::openssh::exists() {
        // `sshd -t` refuses to parse anything as root without its privilege
        // separation directory; the policy probe below needs a real answer.
        if let Err(error) = crate::ssh::openssh::ensure_runtime_dir() {
            tracing::warn!(%error, "cannot prepare OpenSSH runtime directory for policy check");
        }
    }
    prepare_at(config, Path::new("/"))
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
    for (name, value) in crate::ssh::inherited_environment(&config.environment) {
        if value.contains(['\n', '\r']) {
            tracing::warn!(
                name,
                "multi-line environment value cannot be expressed in sshd_config; OpenSSH sessions will not inherit it"
            );
        }
    }
    let full = policy(&ca_path, &host_path, &config.environment);
    let bare = policy(&ca_path, &host_path, &BTreeMap::new());
    let sshd = root.join(&crate::ssh::openssh::OPENSSH_SERVER_PATH[1..]);
    if full == bare || !sshd.is_file() {
        write_file(&config_path, &full, 0o600)?;
    } else if select_policy(&sshd, &config_path, [&full, &bare])? == bare {
        tracing::warn!(
            "image sshd rejects SetEnv (OpenSSH older than 7.8); OpenSSH sessions start from sshd's default environment, not the machine environment"
        );
    }
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

/// `SetEnv` needs OpenSSH 7.8 and older sshd refuses to start on an unknown
/// option. Ask the image's own sshd instead of parsing its version: distros
/// backport options without bumping it. Writes and returns the first candidate
/// `sshd -t` accepts. When it rejects every candidate the cause is not the
/// difference between them, so the first is kept for SSH readiness to report.
fn select_policy<'a>(
    sshd: &Path,
    config_path: &Path,
    candidates: [&'a str; 2],
) -> eyre::Result<&'a str> {
    for candidate in candidates {
        write_file(config_path, candidate, 0o600)?;
        if sshd_accepts(sshd, config_path) {
            return Ok(candidate);
        }
    }
    write_file(config_path, candidates[0], 0o600)?;
    Ok(candidates[0])
}

fn sshd_accepts(sshd: &Path, config_path: &Path) -> bool {
    let Some(program) = sshd.to_str() else {
        return false;
    };
    // Early provisioning runs before the PID1 supervisor is active.
    match crate::pid1::ProcessSupervisor::default().output(
        program,
        [
            std::ffi::OsStr::new("-t"),
            "-f".as_ref(),
            config_path.as_os_str(),
        ],
    ) {
        Ok(output) => output.status.success(),
        Err(error) => {
            tracing::warn!(%error, sshd = %sshd.display(), "cannot run sshd policy check");
            false
        }
    }
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
    // Either Silo-rendered policy is valid: prepare drops SetEnv when the
    // image's sshd does not support it.
    let actual = fs::read_to_string(config_path)?;
    if actual != policy(&ca_path, &host_path, &config.environment)
        && actual != policy(&ca_path, &host_path, &BTreeMap::new())
    {
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
            ..Default::default()
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

    #[test]
    fn image_sshd_decides_whether_set_env_is_kept() {
        use crate::provision::ssh::{policy, select_policy, CA};
        use std::collections::BTreeMap;
        let sshd = crate::ssh::openssh::tests::test_sshd();
        let root = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(&sshd, {
            let path = root.path().join("usr/sbin/sshd");
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            path
        })
        .unwrap();
        let key = PrivateKey::from(Ed25519Keypair::from_seed(&[1; 32]));
        let config = AgentSshConfig {
            trusted_ca: Some(key.public_key().to_openssh().unwrap()),
            environment: BTreeMap::from([("PATH".into(), "/nix/bin:/bin".into())]),
        };
        let ca = root.path().join(&CA[1..]);
        let host = root.path().join(&HOST_KEY[1..]);
        let config_path = root.path().join(&CONFIG[1..]);
        let full = policy(&ca, &host, &config.environment);
        let bare = policy(&ca, &host, &BTreeMap::new());
        assert_ne!(full, bare);

        // The production path asks the image's sshd, which supports SetEnv.
        prepare_at(&config, root.path()).unwrap();
        assert_eq!(std::fs::read_to_string(&config_path).unwrap(), full);
        verify_at(&config, root.path()).unwrap();

        // OpenSSH < 7.8 rejects SetEnv exactly as any sshd rejects an option it
        // does not know: the real sshd plays that role with an unknown option.
        let unsupported = full.replace("SetEnv ", "SiloUnknownOption ");
        assert_eq!(
            select_policy(&sshd, &config_path, [&unsupported, &bare]).unwrap(),
            bare
        );
        assert_eq!(std::fs::read_to_string(&config_path).unwrap(), bare);
        verify_at(&config, root.path()).unwrap();

        // A failure both candidates share is not about SetEnv: keep the first
        // so SSH readiness reports the real cause.
        let host_text = host.to_str().unwrap();
        let (broken_full, broken_bare) = (
            full.replace(host_text, "/nonexistent/host_key"),
            bare.replace(host_text, "/nonexistent/host_key"),
        );
        assert_eq!(
            select_policy(&sshd, &config_path, [&broken_full, &broken_bare]).unwrap(),
            broken_full
        );
        assert_eq!(std::fs::read_to_string(&config_path).unwrap(), broken_full);
    }
}
