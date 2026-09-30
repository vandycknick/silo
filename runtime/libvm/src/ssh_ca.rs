use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use silo_secrets::{
    MachineScopeId, Secret, SecretBytes, SecretError, SecretName, SecretScope, SecretStore,
};
use ssh_key::{
    certificate::{Builder, CertType},
    private::Ed25519Keypair,
    Certificate, LineEnding, PrivateKey, PublicKey,
};
use zeroize::Zeroizing;

use crate::store::models::MachineId;

pub(crate) const PRIVATE: &str = "silo.ssh_ca.private_key";
const PUBLIC: &str = "silo.ssh_ca.public_key";

pub(crate) fn scope(id: MachineId) -> Result<SecretScope, SecretError> {
    Ok(SecretScope::Machine {
        id: MachineScopeId::new(id.to_string())?,
    })
}

pub(crate) fn delete_scope(store: &dyn SecretStore, id: MachineId) -> Result<(), SecretError> {
    match store.delete_scope(&scope(id)?) {
        Err(SecretError::NotFound) => Ok(()),
        result => result,
    }
}

pub(crate) struct CaPair {
    pub(crate) public: String,
    pub(crate) private: SecretBytes,
}

fn invalid(message: impl Into<String>) -> SecretError {
    SecretError::InvalidRequest(message.into())
}

fn key() -> Result<PrivateKey, SecretError> {
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::fill(seed.as_mut()).map_err(|e| SecretError::Internal(e.to_string()))?;
    Ok(PrivateKey::from(Ed25519Keypair::from_seed(&seed)))
}

pub(crate) fn resolve(
    store: &dyn SecretStore,
    id: MachineId,
    create: bool,
) -> Result<CaPair, SecretError> {
    let private_name = SecretName::new(PRIVATE)?;
    let public_name = SecretName::new(PUBLIC)?;
    let mut result = None;
    let mut operation = |tx: &mut dyn silo_secrets::SecretScopeTransaction| {
        let pair = match (tx.get(&private_name)?, tx.get(&public_name)?) {
            (None, None) if create => {
                let key = key()?;
                let pair = CaPair {
                    public: key.public_key().to_openssh().map_err(|e| invalid(e.to_string()))?,
                    private: SecretBytes::new(key.to_openssh(LineEnding::LF).map_err(|e| invalid(e.to_string()))?.as_bytes().to_vec()),
                };
                tx.put(&private_name, Secret::Plain(pair.private.clone()))?;
                tx.put(&public_name, Secret::Plain(SecretBytes::new(pair.public.as_bytes().to_vec())))?;
                pair
            }
            (Some(Secret::Plain(private)), Some(Secret::Plain(public))) => {
                if public.as_str()?.trim().contains(['\n', '\r']) { return Err(invalid("SSH CA public key must contain exactly one key line")); }
                let key = PrivateKey::from_openssh(private.as_bytes()).map_err(|e| invalid(format!("invalid SSH CA private key: {e}")))?;
                let public_key = PublicKey::from_openssh(public.as_str()?).map_err(|e| invalid(format!("invalid SSH CA public key: {e}")))?;
                if key.is_encrypted() || key.algorithm() != ssh_key::Algorithm::Ed25519 || key.public_key().key_data() != public_key.key_data() {
                    return Err(invalid("SSH CA keys do not form an unencrypted matching Ed25519 pair"));
                }
                CaPair { public: public_key.to_openssh().map_err(|e| invalid(e.to_string()))?, private }
            }
            _ => return Err(invalid("machine SSH CA is missing or incomplete; recreate this machine (older machines are not migrated)")),
        };
        result = Some(pair);
        Ok(())
    };
    if create {
        store.initialize_scope(&scope(id)?, &mut operation)?;
    } else {
        store.update_scope(&scope(id)?, &mut operation)?;
    }
    result.ok_or_else(|| {
        SecretError::Internal("secret store did not execute atomic scope operation".into())
    })
}

pub(crate) fn issue(
    store: &dyn SecretStore,
    id: MachineId,
    user: &str,
) -> Result<(Arc<PrivateKey>, Certificate), SecretError> {
    let pair = resolve(store, id, false)?;
    let ca =
        PrivateKey::from_openssh(pair.private.as_bytes()).map_err(|e| invalid(e.to_string()))?;
    let subject = key()?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| invalid(e.to_string()))?
        .as_secs();
    let mut nonce = [0u8; 32];
    getrandom::fill(&mut nonce).map_err(|e| SecretError::Internal(e.to_string()))?;
    let mut builder = Builder::new(
        nonce,
        subject.public_key().key_data().clone(),
        now.saturating_sub(60),
        now.checked_add(300)
            .ok_or_else(|| invalid("certificate time overflow"))?,
    )
    .map_err(|e| invalid(e.to_string()))?;
    builder
        .serial(u64::from_be_bytes(
            nonce[..8]
                .try_into()
                .map_err(|_| invalid("invalid nonce"))?,
        ))
        .map_err(|e| invalid(e.to_string()))?;
    builder
        .cert_type(CertType::User)
        .map_err(|e| invalid(e.to_string()))?;
    builder
        .key_id(format!(
            "silo:cli:uid{}:{}",
            nix::unistd::Uid::current(),
            uuid::Uuid::new_v4()
        ))
        .map_err(|e| invalid(e.to_string()))?;
    builder
        .valid_principal(user)
        .map_err(|e| invalid(e.to_string()))?;
    for extension in [
        "permit-pty",
        "permit-agent-forwarding",
        "permit-port-forwarding",
    ] {
        builder
            .extension(extension, "")
            .map_err(|e| invalid(e.to_string()))?;
    }
    let certificate = builder.sign(&ca).map_err(|e| invalid(e.to_string()))?;
    Ok((Arc::new(subject), certificate))
}

#[cfg(test)]
mod tests {
    use crate::ssh_ca::{issue, resolve, scope, PRIVATE, PUBLIC};
    use crate::store::models::MachineId;
    use silo_secrets::{FileStore, Secret, SecretBytes, SecretName, SecretStore};
    use ssh_key::{Certificate, HashAlg, PrivateKey};
    use std::sync::Arc;

    #[tokio::test]
    async fn actual_machine_create_remove_and_failed_create_own_ca_scope() {
        let home = tempfile::tempdir().unwrap();
        let disk = home.path().join("root.raw");
        std::fs::write(&disk, "root-disk").unwrap();
        let runtime = crate::Runtime::open(
            crate::paths::LocalPaths::new(home.path().join("silo")),
            crate::RuntimeNetworkingConfig::default(),
        )
        .await
        .unwrap();
        let machine = runtime
            .machine()
            .name("ca-lifecycle")
            .image_source(crate::ImageSource::disk(&disk))
            .agent_mode(Some(crate::MachineAgent::Disabled))
            .create()
            .await
            .unwrap();
        let id: MachineId = machine.id().parse().unwrap();
        let pair = resolve(runtime.secret_store(), id, false).unwrap();
        assert!(pair.public.starts_with("ssh-ed25519 "));
        let scope_path = runtime
            .local_home()
            .join("machines")
            .join(id.to_string())
            .join("secrets.json");
        assert!(scope_path.is_file());
        machine.remove().await.unwrap();
        assert!(!scope_path.exists());
        let bad = runtime
            .machine()
            .name("failed-ca")
            .image_source(crate::ImageSource::disk(&disk))
            .root_disk_size(1)
            .create()
            .await;
        assert!(bad.is_err());
        assert!(runtime.secret_store().list_scopes().unwrap().is_empty());
    }

    #[tokio::test]
    async fn injected_file_store_owns_ca_for_create_boot_resolution_and_remove() {
        let home = tempfile::tempdir().unwrap();
        let external = tempfile::tempdir().unwrap();
        let disk = home.path().join("root.raw");
        std::fs::write(&disk, "root-disk").unwrap();
        let selected =
            Arc::new(FileStore::with_store_file(external.path().join("custom.json")).unwrap());
        let runtime = crate::Runtime::open(
            crate::paths::LocalPaths::new(home.path().join("silo")),
            crate::RuntimeNetworkingConfig::default(),
        )
        .await
        .unwrap()
        .with_secret_store(selected.clone());
        let machine = runtime
            .machine()
            .name("external-ca")
            .image_source(crate::ImageSource::disk(&disk))
            .create()
            .await
            .unwrap();
        let id: MachineId = machine.id().parse().unwrap();
        assert!(!runtime
            .local_home()
            .join("machines")
            .join(id.to_string())
            .join("secrets.json")
            .exists());
        let mut config = runtime
            .resolve_machine_config(&crate::MachineRef::id(id))
            .await
            .unwrap();
        let resolved = runtime
            .resolve_machine_secrets(&config, "test-run", &crate::EgressCredentials::new())
            .unwrap();
        let pair = resolve(selected.as_ref(), id, false).unwrap();
        assert_eq!(resolved.ssh_trusted_ca, Some(pair.public));
        assert_eq!(resolved.infrastructure[0].1, pair.private);
        assert!(resolved.oauth_refresh_hook.is_none());
        assert!(resolved.tls_certificate.is_none());
        assert!(
            !selected.path().exists(),
            "non-intercepting start must not create a Home CA"
        );
        let frame = crate::network::secret_transport::frame(&resolved, None, "test").unwrap();
        let body = frame
            .windows(4)
            .position(|bytes| bytes == b"\r\n\r\n")
            .unwrap()
            + 4;
        let payload: serde_json::Value = serde_json::from_slice(&frame[body..]).unwrap();
        assert_eq!(payload["secrets"][0]["name"], PRIVATE);
        use base64::Engine;
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(payload["secrets"][0]["value"].as_str().unwrap())
                .unwrap(),
            pair.private.as_bytes()
        );
        assert!(payload.get("provider").is_none());
        config.network = crate::store::models::MachineNetworkConfig::Private {
            policy: Some(crate::NetworkPolicy::from_json_str(r#"{"version":1,"endpoints":[{"name":"api","kind":"https","family":"http","transport":"https-mitm","tls":"terminate","capabilities":["credential-injection"],"hosts":["example.com"]}],"credentials":[{"name":"personal","kind":"bearer_token","endpoint":"api"}]}"#).unwrap()), publish: None,
        };
        let explicit = crate::EgressCredentials::new().secret("personal.token", "explicit-token");
        let resolved = runtime
            .resolve_machine_secrets(&config, "explicit-run", &explicit)
            .unwrap();
        assert_eq!(resolved.infrastructure[0].1, pair.private);
        assert_eq!(resolved.credentials.secrets[0].slot, "personal.token");
        let home_ca = crate::host::certificates::resolve(
            selected.as_ref(),
            &crate::paths::LocalPaths::new(runtime.local_home()),
            &crate::NetdRuntimeConfig::default(),
        )
        .unwrap();
        assert_eq!(
            resolved.tls_certificate.as_deref(),
            Some(home_ca.certificate.as_str())
        );
        assert_eq!(
            resolved.infrastructure[1].0,
            crate::host::certificates::CERTIFICATE
        );
        assert_eq!(
            resolved.infrastructure[1].1.as_bytes(),
            home_ca.certificate.as_bytes()
        );
        assert_eq!(resolved.infrastructure[2].1, home_ca.private);
        let crate::store::models::MachineNetworkConfig::Private { policy, .. } = &config.network
        else {
            panic!("private")
        };
        let frame =
            crate::network::secret_transport::frame(&resolved, policy.as_ref(), "test").unwrap();
        let body = frame
            .windows(4)
            .position(|bytes| bytes == b"\r\n\r\n")
            .unwrap()
            + 4;
        let payload: serde_json::Value = serde_json::from_slice(&frame[body..]).unwrap();
        assert!(payload.get("provider").is_none());
        let tls_cert = payload["secrets"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["name"] == crate::host::certificates::CERTIFICATE)
            .unwrap();
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(tls_cert["value"].as_str().unwrap())
                .unwrap(),
            home_ca.certificate.as_bytes()
        );
        let network = crate::network::VmmNetworkAttachment::UnixDatagram {
            path: "/tmp/net.sock".into(),
            mac: "02:00:00:00:00:01".into(),
            ipv4: agent_spec::NetworkIpv4Config {
                address: "192.168.105.2".parse().unwrap(),
                prefix_length: 24,
                gateway: "192.168.105.1".parse().unwrap(),
            },
            dns: agent_spec::NetworkDnsConfig {
                servers: vec![],
                search: vec![],
            },
            requires_certificate_authority: true,
            exit_writer: None,
        };
        // Change the store after resolution: guest composition must still use
        // the exact launch snapshot, with no second lookup or CA generator.
        selected
            .put(
                &silo_secrets::SecretScope::Home,
                &silo_secrets::SecretName::new(crate::host::certificates::CERTIFICATE).unwrap(),
                silo_secrets::Secret::Plain(silo_secrets::SecretBytes::new(
                    b"corrupt-after-resolution".to_vec(),
                )),
            )
            .unwrap();
        let guest = crate::guest_agent::build_config(crate::guest_agent::GuestAgentConfigInput {
            machine_name: "snapshot",
            spec: &config.spec,
            network: &network,
            resize_rootfs: false,
            user: None,
            ssh_trusted_ca: resolved.ssh_trusted_ca.as_deref().unwrap(),
            tls_certificate: resolved.tls_certificate.as_deref(),
        })
        .unwrap();
        assert_eq!(
            guest.provision.certificate_authority.unwrap().pem,
            home_ca.certificate
        );
        selected
            .put(
                &silo_secrets::SecretScope::Home,
                &silo_secrets::SecretName::new(crate::host::certificates::CERTIFICATE).unwrap(),
                silo_secrets::Secret::Plain(silo_secrets::SecretBytes::new(
                    home_ca.certificate.into_bytes(),
                )),
            )
            .unwrap();
        assert!(!runtime.local_home().join("keys").exists());
        let mut oversized = resolved.clone();
        oversized.credentials =
            crate::EgressCredentials::new().secret("personal.token", "x".repeat(12_000));
        assert!(
            crate::network::secret_transport::frame(&oversized, policy.as_ref(), "test")
                .unwrap_err()
                .to_string()
                .contains("16384")
        );
        let before = std::fs::read(selected.path()).unwrap();
        machine.remove().await.unwrap();
        assert_eq!(
            selected.list_scopes().unwrap(),
            vec![silo_secrets::SecretScope::Home]
        );
        assert_eq!(std::fs::read(selected.path()).unwrap(), before);
        assert!(runtime
            .machine()
            .name("external-rollback")
            .image_source(crate::ImageSource::disk(&disk))
            .root_disk_size(1)
            .create()
            .await
            .is_err());
        assert_eq!(
            selected.list_scopes().unwrap(),
            vec![silo_secrets::SecretScope::Home]
        );
        assert!(std::fs::read_dir(runtime.local_home().join("machines"))
            .unwrap()
            .next()
            .is_none());
    }

    #[tokio::test]
    async fn real_scope_cleanup_failures_are_reported_while_machine_removal_continues() {
        for ephemeral in [false, true] {
            let home = tempfile::tempdir().unwrap();
            let external = tempfile::tempdir().unwrap();
            let disk = home.path().join("root.raw");
            std::fs::write(&disk, "root-disk").unwrap();
            let selected = Arc::new(FileStore::new(external.path()));
            let runtime = crate::Runtime::open(
                crate::paths::LocalPaths::new(home.path().join("silo")),
                crate::RuntimeNetworkingConfig::default(),
            )
            .await
            .unwrap()
            .with_secret_store(selected.clone());
            let retention = if ephemeral {
                crate::MachineRetention::Ephemeral
            } else {
                crate::MachineRetention::Persistent
            };
            let machine = runtime
                .machine()
                .name("cleanup-error")
                .image_source(crate::ImageSource::disk(&disk))
                .agent_mode(Some(crate::MachineAgent::Disabled))
                .retention(retention)
                .create()
                .await
                .unwrap();
            let id: MachineId = machine.id().parse().unwrap();
            let path = selected.scope_path(&scope(id).unwrap());
            std::fs::remove_file(&path).unwrap();
            std::fs::create_dir(&path).unwrap();
            let message = if ephemeral {
                machine.start().await.err().unwrap().to_string()
            } else {
                machine.remove().await.err().unwrap().to_string()
            };
            assert!(
                message.contains("scope cleanup failed")
                    || message.contains("delete ephemeral machine secret scope"),
                "{message}"
            );
            assert!(runtime.machine_config(id).await.unwrap().is_none());
            assert!(!runtime
                .local_home()
                .join("machines")
                .join(id.to_string())
                .exists());
            assert!(
                path.exists(),
                "failed external cleanup must not be silently claimed successful"
            );
        }
    }

    #[test]
    fn real_store_pair_is_atomic_stable_and_certificates_are_ephemeral() {
        let home = tempfile::tempdir().unwrap();
        let id = MachineId::new();
        let dir = home.path().join("machines").join(id.to_string());
        std::fs::create_dir_all(&dir).unwrap();
        let store = FileStore::new(home.path());
        let first = resolve(&store, id, true).unwrap();
        let mut threads = Vec::new();
        for _ in 0..8 {
            let store = store.clone();
            threads.push(std::thread::spawn(move || {
                resolve(&store, id, true).unwrap().public
            }));
        }
        for thread in threads {
            assert_eq!(thread.join().unwrap(), first.public);
        }
        assert_eq!(store.list(&scope(id).unwrap()).unwrap().len(), 2);
        let (key, cert) = issue(&store, id, "silo").unwrap();
        let (other, _) = issue(&store, id, "silo").unwrap();
        assert_ne!(key.public_key(), other.public_key());
        let parsed = Certificate::from_openssh(&cert.to_openssh().unwrap()).unwrap();
        assert_eq!(parsed.valid_principals(), ["silo"]);
        assert!(parsed.key_id().starts_with("silo:cli:uid"));
        assert_eq!(parsed.valid_before() - parsed.valid_after(), 360);
        let ca = PrivateKey::from_openssh(first.private.as_bytes()).unwrap();
        parsed
            .validate_at(
                parsed.valid_after() + 60,
                [&ca.public_key().fingerprint(HashAlg::Sha256)],
            )
            .unwrap();
        let cert_path = home.path().join("user-cert.pub");
        std::fs::write(&cert_path, cert.to_openssh().unwrap()).unwrap();
        match std::process::Command::new("ssh-keygen").arg("-L").arg("-f").arg(cert_path).output() {
            Ok(output) => { assert!(output.status.success()); assert!(String::from_utf8(output.stdout).unwrap().contains("silo:cli:uid")); }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => eprintln!("SKIPPED ssh-keygen display: binary unavailable; ssh-key parse and validation exercised"),
            Err(error) => panic!("ssh-keygen: {error}"),
        }
        store
            .delete(&scope(id).unwrap(), &SecretName::new(PUBLIC).unwrap())
            .unwrap();
        let before = std::fs::read(dir.join("secrets.json")).unwrap();
        assert!(resolve(&store, id, true).is_err());
        assert_eq!(before, std::fs::read(dir.join("secrets.json")).unwrap());
        let wrong = PrivateKey::from(ssh_key::private::Ed25519Keypair::from_seed(&[9; 32]));
        store
            .put(
                &scope(id).unwrap(),
                &SecretName::new(PUBLIC).unwrap(),
                Secret::Plain(SecretBytes::new(
                    wrong.public_key().to_openssh().unwrap().into_bytes(),
                )),
            )
            .unwrap();
        assert!(resolve(&store, id, false).is_err());
        assert!(store
            .get(&scope(id).unwrap(), &SecretName::new(PRIVATE).unwrap())
            .unwrap()
            .is_some());
    }

    #[test]
    fn missing_ca_never_lazily_migrates_old_machine() {
        let home = tempfile::tempdir().unwrap();
        let id = MachineId::new();
        std::fs::create_dir_all(home.path().join("machines").join(id.to_string())).unwrap();
        let error = resolve(&FileStore::new(home.path()), id, false)
            .err()
            .unwrap();
        assert!(error.to_string().contains("recreate"));
        assert!(!home
            .path()
            .join("machines")
            .join(id.to_string())
            .join("secrets.json")
            .exists());
    }
}
