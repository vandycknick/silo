use silo_secrets::{MachineScopeId, Secret, SecretBytes, SecretName, SecretScope};

use crate::{LibVmError, Machine};

impl Machine {
    /// Store a plain credential in this machine's scope in the selected secret store.
    /// The config lock serializes scope access with native machine removal.
    pub async fn set_secret(&self, name: &str, value: Vec<u8>) -> Result<(), LibVmError> {
        self.change_secret(name, Some(SecretBytes::new(value)))
            .await
    }

    /// Remove a machine-scoped credential. Missing keys are already deleted.
    pub async fn delete_secret(&self, name: &str) -> Result<(), LibVmError> {
        self.change_secret(name, None).await
    }

    async fn change_secret(
        &self,
        name: &str,
        value: Option<SecretBytes>,
    ) -> Result<(), LibVmError> {
        let failure = |code: &str| LibVmError::SecretResolution {
            slot: "machine secret".into(),
            key: name.into(),
            code: code.into(),
        };
        let key = SecretName::new(name).map_err(|_| failure("invalid_name"))?;
        if name.starts_with("silo.") || name.len() > 256 {
            return Err(failure("reserved_or_invalid_name"));
        }
        let runtime = self.runtime();
        let (_lock, config) = runtime.lock_machine_config(self.machine_id()).await?;
        runtime.validate_machine_data_dir(&config)?;
        let scope = SecretScope::Machine {
            id: MachineScopeId::new(config.id.to_string()).map_err(|_| failure("invalid_scope"))?,
        };
        match value {
            Some(value) => runtime
                .secret_store()
                .put(&scope, &key, Secret::Plain(value)),
            None => runtime.secret_store().delete(&scope, &key).map(|_| ()),
        }
        .map_err(|error| failure(error.wire_code()))
    }
}

#[cfg(test)]
mod tests {
    use crate::{ImageSource, Runtime, RuntimeNetworkingConfig};
    use silo_secrets::{MachineScopeId, SecretName, SecretScope};

    #[tokio::test]
    async fn scoped_secret_mutations_use_the_runtime_store_and_exclude_removal() {
        let home = tempfile::tempdir().unwrap();
        let disk = home.path().join("input.raw");
        std::fs::write(&disk, b"stopped fixture").unwrap();
        let runtime = Runtime::open(
            crate::paths::LocalPaths::new(home.path().join("home")),
            RuntimeNetworkingConfig::default(),
        )
        .await
        .unwrap();
        let machine = runtime
            .machine()
            .name("secret-scope")
            .image_source(ImageSource::disk(&disk))
            .create()
            .await
            .unwrap();
        machine
            .set_secret("tailscale.vm.auth_key", b"private-bootstrap".to_vec())
            .await
            .unwrap();
        let scope = SecretScope::Machine {
            id: MachineScopeId::new(machine.machine_id().to_string()).unwrap(),
        };
        let key = SecretName::new("tailscale.vm.auth_key").unwrap();
        assert!(runtime
            .secret_store()
            .get(&SecretScope::Home, &key)
            .unwrap()
            .is_none());
        let stored = runtime.secret_store().get(&scope, &key).unwrap().unwrap();
        assert_eq!(
            stored
                .project(silo_secrets::SecretField::Value)
                .unwrap()
                .as_bytes(),
            b"private-bootstrap"
        );
        assert!(machine
            .set_secret("silo.ssh_ca.private_key", b"replacement".to_vec())
            .await
            .is_err());
        machine.delete_secret(key.as_str()).await.unwrap();
        machine.delete_secret(key.as_str()).await.unwrap();
        assert!(runtime.secret_store().get(&scope, &key).unwrap().is_none());
        machine.clone().remove().await.unwrap();
        assert!(machine
            .set_secret(key.as_str(), b"late".to_vec())
            .await
            .is_err());
    }
}
