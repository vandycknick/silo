//! Start-time resolution with exact-scope provider grants.
use std::collections::BTreeMap;

use silo_secrets::grant::{AllowedSecret, SecretGrant};
use silo_secrets::{
    MachineScopeId, Secret, SecretError, SecretField, SecretName, SecretScope, SecretStore,
    SecretStoreDescriptor,
};

use crate::machine::SecretProvider;
use crate::store::models::{MachineId, MachineNetworkConfig};
use crate::{EgressCredentials, HostCommand, LibVmError};

#[derive(Debug, Clone, Default)]
pub(crate) struct ResolvedSecrets {
    pub(crate) credentials: EgressCredentials,
    pub(crate) oauth_refresh_hook: Option<SecretProvider>,
    pub(crate) provenance: Vec<Provenance>,
    pub(crate) infrastructure: Vec<(String, silo_secrets::SecretBytes)>,
    pub(crate) ssh_trusted_ca: Option<String>,
    pub(crate) tls_certificate: Option<String>,
}

impl std::ops::Deref for ResolvedSecrets {
    type Target = EgressCredentials;
    fn deref(&self) -> &Self::Target {
        &self.credentials
    }
}

impl From<EgressCredentials> for ResolvedSecrets {
    fn from(credentials: EgressCredentials) -> Self {
        Self {
            credentials,
            ..Self::default()
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Provenance {
    slot: String,
    scope: SecretScope,
    key: SecretName,
    field: SecretField,
}

fn refreshable_oauth_prefixes(provenance: &[Provenance]) -> std::collections::BTreeSet<String> {
    provenance
        .iter()
        .filter_map(|token| {
            if token.field != SecretField::OAuthAccessToken {
                return None;
            }
            let prefix = token.slot.strip_suffix(".access_token")?;
            let expiry = provenance.iter().find(|p| {
                p.slot == format!("{prefix}.expires_at") && p.field == SecretField::OAuthExpiresAt
            })?;
            (token.scope == expiry.scope && token.key == expiry.key).then(|| prefix.to_owned())
        })
        .collect()
}

pub(crate) fn resolve_for_start(
    store: &dyn SecretStore,
    network: &MachineNetworkConfig,
    machine_id: MachineId,
    run: &str,
    explicit: &EgressCredentials,
    provider: Option<&HostCommand>,
    reference: &str,
) -> Result<ResolvedSecrets, LibVmError> {
    let error = |message| LibVmError::NetworkRuntime {
        reference: reference.into(),
        message,
    };
    if !explicit.is_empty() {
        explicit.validate_for_network_config(network, reference)?;
        return Ok(explicit.clone().into());
    }
    let MachineNetworkConfig::Private {
        policy: Some(policy),
        ..
    } = network
    else {
        return Ok(ResolvedSecrets::default());
    };
    let machine = SecretScope::Machine {
        id: MachineScopeId::new(machine_id.to_string()).map_err(|e| error(e.to_string()))?,
    };
    let mut cache = BTreeMap::<(u8, SecretName), Option<Secret>>::new();
    let mut resolved = ResolvedSecrets::default();
    let slots = policy.secret_slots();
    let mut profiles = std::collections::BTreeSet::new();
    // Resolve profiles first so even malformed stale static records are ignored.
    let ordered = slots
        .iter()
        .filter(|s| {
            s.source.key.as_str().starts_with("aws_credential.") && s.name.ends_with(".profile")
        })
        .chain(slots.iter().filter(|s| {
            !(s.source.key.as_str().starts_with("aws_credential.") && s.name.ends_with(".profile"))
        }));
    for slot in ordered {
        if slot.source.key.as_str().starts_with("aws_credential.")
            && slot.name.rsplit_once('.').is_some_and(|(owner, field)| {
                profiles.contains(owner)
                    && matches!(
                        field,
                        "access_key_id" | "secret_access_key" | "session_token"
                    )
            })
        {
            continue;
        }
        let mut selected = None;
        for (index, scope) in [(0, &machine), (1, &SecretScope::Home)] {
            for (key, field) in [
                (SecretName::legacy(&slot.name), SecretField::Value),
                (slot.source.key.clone(), slot.source.field),
            ] {
                let address = (index, key.clone());
                if !cache.contains_key(&address) {
                    let record = match store.get(scope, &key) {
                        Ok(record) => record,
                        Err(SecretError::NotFound) => None,
                        Err(e) => {
                            return Err(error(format!(
                                "network secret slot {:?}, store key {:?}: {e}",
                                slot.name,
                                key.as_str()
                            )))
                        }
                    };
                    cache.insert(address.clone(), record);
                }
                if let Some(Some(record)) = cache.get(&address) {
                    selected = Some((scope.clone(), key, field, record.clone()));
                    break;
                }
            }
            if selected.is_some() {
                break;
            }
        }
        let Some((scope, key, field, record)) = selected else {
            continue;
        };
        let right_kind = matches!(
            (&record, field),
            (Secret::Plain(_), SecretField::Value)
                | (
                    Secret::OAuth(_),
                    SecretField::OAuthAccessToken
                        | SecretField::OAuthExpiresAt
                        | SecretField::OAuthAccountId
                )
        );
        if !right_kind {
            return Err(error(format!("network secret slot {:?}, store key {:?} has type {}, incompatible projection {field:?}", slot.name, key.as_str(), record.secret_type())));
        }
        let Some(value) = record.project(field) else {
            continue;
        };
        if value.is_empty() {
            return Err(error(format!(
                "network secret slot {:?}, store key {:?} has an empty value",
                slot.name,
                key.as_str()
            )));
        }
        if slot.name.ends_with(".profile") {
            if let Some((owner, _)) = slot.name.rsplit_once('.') {
                profiles.insert(owner.to_owned());
            }
        }
        resolved.credentials = resolved
            .credentials
            .secret_bytes(&slot.name, value.as_bytes().to_vec());
        resolved.provenance.push(Provenance {
            slot: slot.name.clone(),
            scope,
            key,
            field,
        });
    }
    resolved
        .credentials
        .validate_for_policy(Some(policy), reference)?;
    if let Some(provider) = provider {
        // An access token and its expiry are one value: a refresh must never
        // extend a raw token's lifetime by replacing only its canonical expiry.
        let refreshable = refreshable_oauth_prefixes(&resolved.provenance);
        let allowed = resolved
            .provenance
            .iter()
            .filter(|p| {
                p.field != SecretField::Value
                    && !p.slot.starts_with("silo.")
                    && p.slot
                        .rsplit_once('.')
                        .is_some_and(|(prefix, _)| refreshable.contains(prefix))
            })
            .map(|p| {
                Ok(AllowedSecret {
                    slot: SecretName::new(&p.slot).map_err(|e| error(e.to_string()))?,
                    key: p.key.clone(),
                    field: p.field,
                    backing_scope: p.scope.clone(),
                })
            })
            .collect::<Result<Vec<_>, LibVmError>>()?;
        if !allowed.is_empty() {
            let store_file = match store.descriptor() {
                Some(SecretStoreDescriptor::File { store_file }) => store_file,
                _ => return Err(error("secret provider requires a compatible file-store descriptor from the selected secret store".into())),
            };
            if !provider.command.is_absolute()
                || provider
                    .command
                    .to_str()
                    .is_none_or(|command| command.contains('\0'))
            {
                return Err(error(
                    "secret provider command must be an absolute UTF-8 path".into(),
                ));
            }
            let args = provider
                .args
                .iter()
                .map(|arg| {
                    arg.to_str()
                        .filter(|arg| !arg.contains('\0'))
                        .map(str::to_owned)
                        .ok_or_else(|| {
                            error("secret provider arguments must be valid UTF-8".into())
                        })
                })
                .collect::<Result<Vec<_>, _>>()?;
            let grant = SecretGrant::issue(
                &store_file,
                MachineScopeId::new(machine_id.to_string()).map_err(|e| error(e.to_string()))?,
                run.into(),
                allowed,
            )
            .map_err(|e| error(e.to_string()))?;
            let auth = serde_json::to_vec(&grant).map_err(|e| error(e.to_string()))?;
            resolved.oauth_refresh_hook = Some(
                SecretProvider::new(&provider.command, auth)
                    .args(args)
                    .timeout_ms(10000)
                    .refresh_skew_seconds(300),
            );
        }
    }
    Ok(resolved)
}

#[cfg(test)]
mod tests {
    use crate::secrets::resolve_for_start;
    use crate::store::models::{MachineId, MachineNetworkConfig};
    use crate::{EgressCredentials, HostCommand, LibVmError, NetworkPolicy};
    use silo_secrets::{
        FileStore, MachineScopeId, OAuthSecret, Secret, SecretBytes, SecretError, SecretName,
        SecretScope, SecretStore,
    };

    const ID: &str = "0123456789abcdef0123456789abcdef";
    fn machine() -> SecretScope {
        SecretScope::Machine {
            id: MachineScopeId::new(ID).unwrap(),
        }
    }
    fn fixture(kind: &str) -> (tempfile::TempDir, FileStore, MachineNetworkConfig) {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("machines").join(ID)).unwrap();
        let store = FileStore::new(dir.path());
        let policy = NetworkPolicy::from_json_str(&format!(r#"{{"version":1,"endpoints":[{{"name":"api","kind":"https","family":"http","transport":"https-mitm","tls":"terminate","capabilities":["credential-injection"],"hosts":["example.com"]}}],"credentials":[{{"name":"personal","kind":"{kind}","endpoint":"api"}}],"tailscale":[{{"name":"work"}}]}}"#)).unwrap();
        (
            dir,
            store,
            MachineNetworkConfig::Private {
                policy: Some(policy),
                publish: None,
            },
        )
    }
    fn plain(value: &str) -> Secret {
        Secret::Plain(SecretBytes::new(value.as_bytes().to_vec()))
    }
    fn oauth() -> Secret {
        Secret::OAuth(OAuthSecret {
            provider: None,
            access_token: SecretBytes::new(b"access".to_vec()),
            refresh_token: SecretBytes::new(b"never-deliver".to_vec()),
            expires_at: "2026-09-30T00:00:00Z".parse().unwrap(),
            account_id: Some("account".into()),
            created_at: None,
            updated_at: None,
        })
    }
    fn put(store: &FileStore, scope: &SecretScope, key: &str, value: Secret) {
        store
            .put(scope, &SecretName::new(key).unwrap(), value)
            .unwrap();
    }
    fn resolve(
        store: &FileStore,
        network: &MachineNetworkConfig,
        explicit: &EgressCredentials,
    ) -> Result<crate::secrets::ResolvedSecrets, LibVmError> {
        resolve_for_start(
            store,
            network,
            ID.parse::<MachineId>().unwrap(),
            "run-123",
            explicit,
            Some(&HostCommand::new("/usr/bin/silo").args(["secret", "provide"])),
            "test",
        )
    }
    fn value(resolved: &crate::secrets::ResolvedSecrets, slot: &str) -> Vec<u8> {
        resolved
            .secrets
            .iter()
            .find(|s| s.slot == slot)
            .unwrap()
            .value
            .clone()
    }

    async fn runtime_machine(
        network: &MachineNetworkConfig,
    ) -> (
        tempfile::TempDir,
        crate::Runtime,
        crate::store::models::MachineConfig,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let runtime = crate::Runtime::open(
            crate::paths::LocalPaths::new(dir.path().join("runtime-home")),
            crate::RuntimeNetworkingConfig::default(),
        )
        .await
        .unwrap();
        let disk = dir.path().join("rootfs.img");
        std::fs::write(&disk, b"disk fixture, never booted").unwrap();
        let MachineNetworkConfig::Private {
            policy: Some(policy),
            ..
        } = network
        else {
            panic!("private policy")
        };
        let machine = runtime
            .machine()
            .name("external-store")
            .image_source(crate::ImageSource::disk(disk))
            .agent_mode(Some(crate::MachineAgent::Disabled))
            .network(|network| network.private().policy(policy.clone()))
            .create()
            .await
            .unwrap();
        let config = runtime
            .resolve_machine_config(&crate::MachineRef::parse(machine.id()).unwrap())
            .await
            .unwrap();
        (dir, runtime, config)
    }

    #[tokio::test]
    async fn tls_home_resolution_is_lazy_and_reserved_material_stays_out_of_grants() {
        let (_fixture, _, network) = fixture("openai_codex_oauth");
        let (_dir, runtime, mut config) = runtime_machine(&network).await;
        let store = FileStore::new(runtime.local_home());
        assert!(!store.path().exists());
        let saved = config.network.clone();
        config.network = MachineNetworkConfig::None;
        let idle = runtime
            .resolve_machine_secrets(&config, "no-policy", &EgressCredentials::new())
            .unwrap();
        assert!(idle.tls_certificate.is_none());
        assert!(!store.path().exists());
        config.network = saved;
        put(
            &store,
            &SecretScope::Home,
            "openai_codex_oauth.personal.oauth",
            oauth(),
        );
        let runtime = runtime
            .with_secret_provider(HostCommand::new("/usr/bin/silo").args(["secret", "provide"]));
        let resolved = runtime
            .resolve_machine_secrets(&config, "tls-provider", &EgressCredentials::new())
            .unwrap();
        let grant: silo_secrets::grant::SecretGrant =
            serde_json::from_slice(&resolved.oauth_refresh_hook.as_ref().unwrap().auth).unwrap();
        assert!(grant
            .allowed
            .iter()
            .all(|entry| !entry.slot.as_str().starts_with("silo.")));
        assert!(resolved
            .infrastructure
            .iter()
            .any(|(name, _)| name == crate::host::certificates::PRIVATE));
        let ca = store
            .get(
                &SecretScope::Home,
                &SecretName::new(crate::host::certificates::CERTIFICATE).unwrap(),
            )
            .unwrap()
            .unwrap();
        assert_eq!(
            ca.project(silo_secrets::SecretField::Value)
                .unwrap()
                .as_str()
                .unwrap(),
            resolved.tls_certificate.as_ref().unwrap()
        );
        let before = std::fs::read(store.path()).unwrap();
        runtime
            .resolve_machine_secrets(&config, "second", &EgressCredentials::new())
            .unwrap();
        assert_eq!(std::fs::read(store.path()).unwrap(), before);
        assert!(!runtime.local_home().join("keys").exists());
    }

    #[tokio::test]
    async fn injected_external_home_resolves_without_machine_directory() {
        let (_fixture, _, network) = fixture("bearer_token");
        let (_runtime_dir, runtime, config) = runtime_machine(&network).await;
        let home = tempfile::tempdir().unwrap();
        let store = FileStore::new(home.path());
        put(
            &store,
            &SecretScope::Home,
            "bearer_token.personal.token",
            plain("external-canonical"),
        );
        let runtime = runtime.with_secret_store(std::sync::Arc::new(store.clone()));
        let resolved = runtime
            .resolve_secrets(&config, "run", &EgressCredentials::new())
            .unwrap();
        assert_eq!(value(&resolved, "personal.token"), b"external-canonical");
        assert_eq!(resolved.provenance[0].scope, SecretScope::Home);
        assert!(!home.path().join("machines").exists());
        put(
            &store,
            &SecretScope::Home,
            "personal.token",
            plain("external-raw"),
        );
        assert_eq!(
            value(
                &runtime
                    .resolve_secrets(&config, "run", &EgressCredentials::new())
                    .unwrap(),
                "personal.token"
            ),
            b"external-raw"
        );
        let machine_dir = home.path().join("machines").join(config.id.to_string());
        std::fs::create_dir_all(&machine_dir).unwrap();
        std::fs::write(machine_dir.join("secrets.json"), "{corrupt").unwrap();
        assert!(runtime
            .resolve_secrets(&config, "run", &EgressCredentials::new())
            .unwrap_err()
            .to_string()
            .contains("store key"));
        std::fs::remove_dir_all(&machine_dir).unwrap();
        std::fs::write(&machine_dir, "not a directory").unwrap();
        assert!(runtime
            .resolve_secrets(&config, "run", &EgressCredentials::new())
            .unwrap_err()
            .to_string()
            .contains("not a directory"));
        std::fs::remove_file(&machine_dir).unwrap();
        runtime
            .get_machine(&crate::MachineRef::id(config.id))
            .await
            .unwrap()
            .remove()
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn injected_external_oauth_grant_and_provider_use_actual_store_file() {
        let (_fixture, _, network) = fixture("openai_codex_oauth");
        let (_runtime_dir, runtime, config) = runtime_machine(&network).await;
        let key = "openai_codex_oauth.personal.oauth";
        let mut runtime_record = oauth();
        if let Secret::OAuth(record) = &mut runtime_record {
            record.access_token = SecretBytes::new(b"runtime-token-must-not-be-refreshed".to_vec());
        }
        let runtime_store = FileStore::new(runtime.local_home());
        put(&runtime_store, &SecretScope::Home, key, runtime_record);
        let runtime_before = std::fs::read(runtime_store.path()).unwrap();
        let external_home = tempfile::tempdir().unwrap();
        for filename in ["secrets.json", "custom-oauth.json"] {
            let store = FileStore::with_store_file(external_home.path().join(filename)).unwrap();
            let mut external_record = oauth();
            if let Secret::OAuth(record) = &mut external_record {
                record.access_token = SecretBytes::new(b"external-selected-token".to_vec());
            }
            put(&store, &SecretScope::Home, key, external_record);
            assert!(!external_home.path().join("machines").exists());
            let command = HostCommand::new("/usr/bin/silo")
                .args(["secret", "provide", "--store-file"])
                .arg(store.path());
            let configured = runtime
                .clone()
                .with_secret_store(std::sync::Arc::new(store.clone()))
                .with_secret_provider(command.clone());
            let resolved = configured
                .resolve_secrets(&config, "external-run", &EgressCredentials::new())
                .unwrap();
            assert_eq!(
                value(&resolved, "personal.oauth.access_token"),
                b"external-selected-token"
            );
            let hook = resolved.oauth_refresh_hook.unwrap();
            assert_eq!(hook.command, command.command);
            assert_eq!(
                hook.args
                    .iter()
                    .map(std::ffi::OsString::from)
                    .collect::<Vec<_>>(),
                command.args
            );
            let grant: serde_json::Value = serde_json::from_slice(&hook.auth).unwrap();
            assert_eq!(grant["store"], format!("file:{}", store.path().display()));
            assert_ne!(
                grant["store"],
                format!("file:{}", runtime_store.path().display())
            );
            assert_eq!(grant["allowed"][0]["backing_scope"], "Home");
            assert_eq!(grant["allowed"][0]["key"], key);
            assert_eq!(grant["machine"], config.id.to_string());
            assert_eq!(grant["run"], "external-run");
            assert_eq!(std::fs::read(runtime_store.path()).unwrap(), runtime_before);
        }
        runtime
            .get_machine(&crate::MachineRef::id(config.id))
            .await
            .unwrap()
            .remove()
            .await
            .unwrap();
    }

    // A real forwarding store without an out-of-process address, exercising the
    // default trait method while every operation still uses actual files.
    #[derive(Debug)]
    struct UnaddressedFileStore(FileStore);
    impl SecretStore for UnaddressedFileStore {
        fn get(
            &self,
            scope: &SecretScope,
            name: &SecretName,
        ) -> Result<Option<Secret>, SecretError> {
            self.0.get(scope, name)
        }
        fn put(
            &self,
            scope: &SecretScope,
            name: &SecretName,
            secret: Secret,
        ) -> Result<(), SecretError> {
            self.0.put(scope, name, secret)
        }
        fn delete(&self, scope: &SecretScope, name: &SecretName) -> Result<bool, SecretError> {
            self.0.delete(scope, name)
        }
        fn list(&self, scope: &SecretScope) -> Result<Vec<silo_secrets::SecretEntry>, SecretError> {
            self.0.list(scope)
        }
        fn delete_scope(&self, scope: &SecretScope) -> Result<(), SecretError> {
            self.0.delete_scope(scope)
        }
    }

    #[test]
    fn descriptor_is_required_only_for_configured_oauth_refresh() {
        let (_dir, store, network) = fixture("bearer_token");
        put(
            &store,
            &SecretScope::Home,
            "bearer_token.personal.token",
            plain("static"),
        );
        let store = UnaddressedFileStore(store);
        let erased: &dyn SecretStore = &store;
        assert!(erased.descriptor().is_none());
        let provider = HostCommand::new("/usr/bin/provider");
        let resolve = |store: &dyn SecretStore, network: &MachineNetworkConfig, provider| {
            resolve_for_start(
                store,
                network,
                ID.parse().unwrap(),
                "run",
                &EgressCredentials::new(),
                provider,
                "test",
            )
        };
        assert_eq!(
            value(
                &resolve(erased, &network, Some(&provider)).unwrap(),
                "personal.token"
            ),
            b"static"
        );
        let (_dir, store, network) = fixture("openai_codex_oauth");
        put(
            &store,
            &SecretScope::Home,
            "openai_codex_oauth.personal.oauth",
            oauth(),
        );
        let store = UnaddressedFileStore(store);
        assert!(resolve(&store, &network, None)
            .unwrap()
            .oauth_refresh_hook
            .is_none());
        let error = resolve(&store, &network, Some(&provider))
            .unwrap_err()
            .to_string();
        assert!(error.contains("compatible file-store descriptor"));
    }

    #[test]
    fn file_store_precedence_table() {
        let addresses = [
            (machine(), "personal.token"),
            (machine(), "bearer_token.personal.token"),
            (SecretScope::Home, "personal.token"),
            (SecretScope::Home, "bearer_token.personal.token"),
        ];
        for winner in 0..addresses.len() {
            let (_dir, store, network) = fixture("bearer_token");
            for (index, (scope, key)) in addresses.iter().enumerate().skip(winner) {
                put(&store, scope, key, plain(&index.to_string()));
            }
            let resolved = resolve(&store, &network, &EgressCredentials::new()).unwrap();
            assert_eq!(
                value(&resolved, "personal.token"),
                winner.to_string().as_bytes()
            );
            assert_eq!(resolved.provenance[0].scope, addresses[winner].0);
            assert_eq!(resolved.provenance[0].key.as_str(), addresses[winner].1);
        }
    }

    #[test]
    fn selected_wrong_type_empty_or_malformed_fails_without_fallback() {
        for bad in [plain(""), oauth()] {
            let (_dir, store, network) = fixture("bearer_token");
            put(&store, &machine(), "personal.token", bad);
            put(
                &store,
                &SecretScope::Home,
                "bearer_token.personal.token",
                plain("fallback"),
            );
            let error = resolve(&store, &network, &EgressCredentials::new())
                .unwrap_err()
                .to_string();
            assert!(error.contains("personal.token"));
        }
        let (_dir, store, network) = fixture("bearer_token");
        std::fs::write(store.scope_path(&machine()), "{broken").unwrap();
        assert!(resolve(&store, &network, &EgressCredentials::new()).is_err());
    }

    #[test]
    fn explicit_is_whole_set_override_and_bypasses_unavailable_store() {
        let (_dir, store, network) = fixture("bearer_token");
        for path in [store.path().to_path_buf(), store.scope_path(&machine())] {
            std::fs::write(path, "{malformed").unwrap();
        }
        let explicit = EgressCredentials::new().secret_bytes("personal.token", vec![0, 255]);
        let resolved = resolve(&store, &network, &explicit).unwrap();
        assert_eq!(resolved.credentials, explicit);
        assert!(resolved.provenance.is_empty());
        assert!(resolved.oauth_refresh_hook.is_none());
        assert!(resolve(
            &store,
            &network,
            &EgressCredentials::new().secret("unknown", "bad")
        )
        .is_err());
        assert!(resolve(&store, &network, &EgressCredentials::new()).is_err());
        let (_dir, store, network) = fixture("openai_codex_oauth");
        std::fs::write(store.path(), "{malformed").unwrap();
        assert!(matches!(
            resolve(
                &store,
                &network,
                &EgressCredentials::new().secret("personal.oauth.access_token", "only-token")
            ),
            Err(LibVmError::MissingNetworkSecrets { .. })
        ));
    }

    #[test]
    fn unavailable_store_and_missing_required_names_slot_and_key() {
        let (_dir, store, network) = fixture("bearer_token");
        let error = resolve(&store, &network, &EgressCredentials::new()).unwrap_err();
        match error {
            LibVmError::MissingNetworkSecrets {
                requirements,
                policy,
                ..
            } => {
                assert_eq!(requirements[0].alternatives[0].slots, ["personal.token"]);
                assert_eq!(
                    policy.secret_slots()[0].source.key.as_str(),
                    "bearer_token.personal.token"
                );
            }
            other => panic!("unexpected {other}"),
        }
        // A directory cannot be read as a record file, including when running as root.
        std::fs::create_dir(store.path()).unwrap();
        assert!(resolve(&store, &network, &EgressCredentials::new())
            .unwrap_err()
            .to_string()
            .contains("personal.token"));
    }

    #[test]
    fn aws_alternatives_and_profile_suppression_precede_static_reads() {
        for scope in [SecretScope::Home, machine()] {
            let (_dir, store, network) = fixture("aws_credential");
            put(
                &store,
                &scope,
                "aws_credential.personal.access_key_id",
                plain("key"),
            );
            put(
                &store,
                &scope,
                "aws_credential.personal.secret_access_key",
                plain("secret"),
            );
            put(
                &store,
                &scope,
                "aws_credential.personal.session_token",
                plain("session"),
            );
            let resolved = resolve(&store, &network, &EgressCredentials::new()).unwrap();
            assert_eq!(resolved.secrets.len(), 3);
            assert_eq!(value(&resolved, "personal.access_key_id"), b"key");
            put(&store, &scope, "personal.profile", plain("legacy-profile"));
            // Store JSON is valid but these selected records cannot decode.
            let path = store.scope_path(&scope);
            let mut records: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            records["aws_credential.personal.access_key_id"] = serde_json::json!({"type":"wrong"});
            records["personal.secret_access_key"] = serde_json::json!({"type":"plain","value":""});
            std::fs::write(&path, serde_json::to_vec(&records).unwrap()).unwrap();
            let resolved = resolve(&store, &network, &EgressCredentials::new()).unwrap();
            assert_eq!(resolved.secrets.len(), 1);
            assert_eq!(value(&resolved, "personal.profile"), b"legacy-profile");
        }
        let (_dir, store, network) = fixture("aws_credential");
        put(
            &store,
            &SecretScope::Home,
            "aws_credential.personal.session_token",
            plain("session"),
        );
        assert!(matches!(
            resolve(&store, &network, &EgressCredentials::new()),
            Err(LibVmError::MissingNetworkSecrets { .. })
        ));
    }

    #[test]
    fn oauth_projections_scoped_grants_and_raw_override_provenance() {
        for scope in [SecretScope::Home, machine()] {
            let (_dir, store, network) = fixture("openai_codex_oauth");
            put(&store, &scope, "openai_codex_oauth.personal.oauth", oauth());
            let resolved = resolve(&store, &network, &EgressCredentials::new()).unwrap();
            assert_eq!(value(&resolved, "personal.oauth.access_token"), b"access");
            assert_eq!(
                value(&resolved, "personal.oauth.expires_at"),
                b"2026-09-30T00:00:00Z"
            );
            assert_eq!(value(&resolved, "personal.oauth.account_id"), b"account");
            assert_eq!(resolved.provenance.len(), 3);
            assert!(resolved
                .secrets
                .iter()
                .all(|secret| secret.value != b"never-deliver"));
            let hook = resolved.oauth_refresh_hook.unwrap();
            let grant: serde_json::Value = serde_json::from_slice(&hook.auth).unwrap();
            assert_eq!(
                grant["allowed"][0]["backing_scope"],
                serde_json::to_value(&scope).unwrap()
            );
            assert_eq!(grant["machine"], ID);
            assert_eq!(grant["run"], "run-123");
            assert!(!String::from_utf8(hook.auth)
                .unwrap()
                .contains("never-deliver"));
            put(
                &store,
                &scope,
                "personal.oauth.access_token",
                plain("raw-access"),
            );
            let resolved = resolve(&store, &network, &EgressCredentials::new()).unwrap();
            assert_eq!(
                value(&resolved, "personal.oauth.access_token"),
                b"raw-access"
            );
            assert!(resolved.oauth_refresh_hook.is_none());
            assert_eq!(
                resolved.provenance[0].key.as_str(),
                "personal.oauth.access_token"
            );
        }
    }

    #[test]
    fn oauth_token_and_expiry_are_inseparable_but_account_override_is_independent() {
        for scope in [SecretScope::Home, machine()] {
            for suffix in ["access_token", "expires_at", "account_id"] {
                let (_dir, store, network) = fixture("openai_codex_oauth");
                put(&store, &scope, "openai_codex_oauth.personal.oauth", oauth());
                let raw = if suffix == "expires_at" {
                    "2026-09-30T00:00:00Z"
                } else {
                    "raw"
                };
                put(
                    &store,
                    &scope,
                    &format!("personal.oauth.{suffix}"),
                    plain(raw),
                );
                let resolved = resolve(&store, &network, &EgressCredentials::new()).unwrap();
                if suffix == "account_id" {
                    let grant: silo_secrets::grant::SecretGrant =
                        serde_json::from_slice(&resolved.oauth_refresh_hook.unwrap().auth).unwrap();
                    assert_eq!(grant.allowed.len(), 2);
                    assert!(grant
                        .allowed
                        .iter()
                        .all(|p| p.slot.as_str() != "personal.oauth.account_id"));
                    assert_eq!(grant.allowed[0].key, grant.allowed[1].key);
                    assert_eq!(
                        grant.allowed[0].backing_scope,
                        grant.allowed[1].backing_scope
                    );
                } else {
                    assert!(
                        resolved.oauth_refresh_hook.is_none(),
                        "raw {suffix} must disable the whole credential's refresh"
                    );
                }
            }
        }
        // Pure provenance invariant: even two canonical projections cannot be
        // refreshed together if an external resolver ever splits their address.
        let (_dir, store, network) = fixture("openai_codex_oauth");
        put(
            &store,
            &machine(),
            "openai_codex_oauth.personal.oauth",
            oauth(),
        );
        let mut provenance = resolve(&store, &network, &EgressCredentials::new())
            .unwrap()
            .provenance;
        assert_eq!(
            crate::secrets::refreshable_oauth_prefixes(&provenance).len(),
            1
        );
        let expiry = provenance
            .iter_mut()
            .find(|p| p.field == silo_secrets::SecretField::OAuthExpiresAt)
            .unwrap();
        expiry.scope = SecretScope::Home;
        assert!(crate::secrets::refreshable_oauth_prefixes(&provenance).is_empty());
        let expiry = provenance
            .iter_mut()
            .find(|p| p.field == silo_secrets::SecretField::OAuthExpiresAt)
            .unwrap();
        expiry.scope = machine();
        expiry.key = SecretName::new("openai_codex_oauth.other.oauth").unwrap();
        assert!(crate::secrets::refreshable_oauth_prefixes(&provenance).is_empty());
    }

    #[test]
    fn optional_tail_auth_raw_precedence_and_provider_path_validation() {
        let (_dir, store, network) = fixture("openai_codex_oauth");
        put(
            &store,
            &SecretScope::Home,
            "personal.oauth.access_token",
            plain("raw"),
        );
        put(
            &store,
            &SecretScope::Home,
            "personal.oauth.expires_at",
            plain("2026-09-30T00:00:00Z"),
        );
        assert_eq!(
            resolve(&store, &network, &EgressCredentials::new())
                .unwrap()
                .secrets
                .len(),
            2
        );
        put(
            &store,
            &SecretScope::Home,
            "tailscale.work.auth_key",
            plain("canonical"),
        );
        put(
            &store,
            &SecretScope::Home,
            "work.tailscale.auth_key",
            plain("legacy"),
        );
        assert_eq!(
            value(
                &resolve(&store, &network, &EgressCredentials::new()).unwrap(),
                "work.tailscale.auth_key"
            ),
            b"legacy"
        );
        store
            .delete(
                &SecretScope::Home,
                &SecretName::new("personal.oauth.access_token").unwrap(),
            )
            .unwrap();
        store
            .delete(
                &SecretScope::Home,
                &SecretName::new("personal.oauth.expires_at").unwrap(),
            )
            .unwrap();
        put(
            &store,
            &SecretScope::Home,
            "openai_codex_oauth.personal.oauth",
            oauth(),
        );
        let no_provider = resolve_for_start(
            &store,
            &network,
            ID.parse().unwrap(),
            "run",
            &EgressCredentials::new(),
            None,
            "test",
        )
        .unwrap();
        assert!(no_provider.oauth_refresh_hook.is_none());
        let command = HostCommand::new("/usr/bin/silo").args(["space argument", "quote\"argument"]);
        let provider = resolve_for_start(
            &store,
            &network,
            ID.parse().unwrap(),
            "run",
            &EgressCredentials::new(),
            Some(&command),
            "test",
        )
        .unwrap()
        .oauth_refresh_hook
        .unwrap();
        assert_eq!(provider.args, ["space argument", "quote\"argument"]);
        let command = HostCommand::new("/bin/true").arg("nul\0argument");
        assert!(resolve_for_start(
            &store,
            &network,
            ID.parse().unwrap(),
            "run",
            &EgressCredentials::new(),
            Some(&command),
            "test"
        )
        .is_err());
        assert!(resolve_for_start(
            &store,
            &network,
            ID.parse().unwrap(),
            "run",
            &EgressCredentials::new(),
            Some(&HostCommand::new("relative")),
            "test"
        )
        .is_err());
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt;
            let command =
                HostCommand::new("/bin/true").arg(std::ffi::OsString::from_vec(vec![255]));
            assert!(resolve_for_start(
                &store,
                &network,
                ID.parse().unwrap(),
                "run",
                &EgressCredentials::new(),
                Some(&command),
                "test"
            )
            .unwrap_err()
            .to_string()
            .contains("UTF-8"));
        }
    }

    #[tokio::test]
    async fn resolution_failure_rolls_back_start_before_network_or_vmm_spawn() {
        let (dir, _, network) = fixture("bearer_token");
        let home = dir.path().join("runtime-home");
        let paths = crate::paths::LocalPaths::new(home.clone());
        let runtime =
            crate::Runtime::open(paths.clone(), crate::RuntimeNetworkingConfig::default())
                .await
                .unwrap();
        assert!(runtime
            .secret_store()
            .list(&SecretScope::Home)
            .unwrap()
            .is_empty());
        let disk = dir.path().join("rootfs.img");
        std::fs::write(&disk, b"disk fixture, never booted").unwrap();
        let MachineNetworkConfig::Private {
            policy: Some(policy),
            ..
        } = network
        else {
            panic!("private policy")
        };
        let machine = runtime
            .machine()
            .name("missing-secret")
            .image_source(crate::ImageSource::disk(disk))
            .agent_mode(Some(crate::MachineAgent::Disabled))
            .network(|network| network.private().policy(policy))
            .create()
            .await
            .unwrap();
        let error = machine.start().await.unwrap_err();
        assert!(matches!(error, LibVmError::MissingNetworkSecrets { .. }));
        let data = machine.inspect().await.unwrap();
        assert_eq!(data.status, crate::MachineStatus::Stopped);
        let machine_paths = paths.machine(machine.id().parse().unwrap());
        assert!(!machine_paths.vmm_pid_path().exists());
        assert!(
            !home.join("secrets.json").exists(),
            "policy validation must precede TLS CA generation"
        );
        assert!(!machine_paths.network_audit_log_path().exists());
        machine.remove().await.unwrap();
        let external = std::sync::Arc::new(FileStore::new(dir.path().join("external")));
        put(
            &external,
            &SecretScope::Home,
            "bearer_token.personal.token",
            plain("external"),
        );
        let runtime = runtime.with_secret_store(external);
        assert_eq!(runtime.local_home(), home);
        assert!(runtime
            .secret_store()
            .get(
                &SecretScope::Home,
                &SecretName::new("bearer_token.personal.token").unwrap()
            )
            .unwrap()
            .is_some());
    }
}
