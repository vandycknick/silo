use std::fs;

use crate::LibVmError;

use super::core::{
    NetworkDriver, NetworkDriverContext, NetworkRequest, NetworkScope, PreparedNetwork,
};
use super::{remove_attached_network, RuntimeNetwork, DRIVER_VZNAT};

pub(super) struct VzNatDriver;

impl NetworkDriver for VzNatDriver {
    fn id(&self) -> &'static str {
        DRIVER_VZNAT
    }

    fn supports(&self, reference: &str, request: &NetworkRequest<'_>) -> Result<(), LibVmError> {
        if !matches!(request.scope, NetworkScope::Private | NetworkScope::Named) {
            return Err(LibVmError::NetworkRuntime {
                reference: reference.to_string(),
                message: "vznat only supports private and named nat networking".to_string(),
            });
        }
        if request.policy_ref.is_some() {
            return Err(LibVmError::NetworkRuntime {
                reference: reference.to_string(),
                message: "vznat does not support network policy_ref".to_string(),
            });
        }
        Ok(())
    }

    async fn prepare(
        &self,
        ctx: &NetworkDriverContext<'_>,
        _request: &NetworkRequest<'_>,
    ) -> Result<PreparedNetwork, LibVmError> {
        remove_attached_network(ctx.paths, ctx.db, ctx.metadata.id).await?;
        let runtime_dir = ctx.paths.machine(ctx.metadata.id).network_link();
        fs::create_dir_all(&runtime_dir)?;
        let attachment = RuntimeNetwork::VzNat { mac: None };
        Ok(PreparedNetwork { attachment })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::Path;

    use super::VzNatDriver;
    use crate::global_config::{NetdConfig, NetworkingConfig};
    use crate::models::{MachineConfig, RequestedNetwork};
    use crate::network::core::{NetworkDriver, NetworkDriverContext, NetworkRequest, NetworkScope};
    use crate::network::NetworkDriverKind;
    use crate::network::RuntimeNetwork;
    use crate::paths::LocalPaths;
    use crate::store::{Database, Sqlite};
    use crate::MachineId;
    use bento_vm_spec::VmSpec;

    use crate::NetworkPolicyRef;

    fn machine_from_path(id: MachineId, name: String, instance_dir: &Path) -> MachineConfig {
        let spec = sample_vm_spec();
        MachineConfig {
            id,
            name,
            spec,
            instance_dir: instance_dir.to_path_buf(),
            created_at: 1,
            modified_at: 1,
            image_ref: String::new(),
            labels: BTreeMap::new(),
            metadata: BTreeMap::new(),
            network: RequestedNetwork::default(),
        }
    }

    fn sample_vm_spec() -> VmSpec {
        VmSpec::current()
    }

    #[test]
    fn vznat_driver_supports_private_and_named_nat_networks() {
        let driver = VzNatDriver;

        driver
            .supports(
                "devbox",
                &NetworkRequest {
                    scope: NetworkScope::Private,
                    definition_name: None,
                    policy_ref: None,
                },
            )
            .expect("private vznat should be supported");
        driver
            .supports(
                "devbox",
                &NetworkRequest {
                    scope: NetworkScope::Named,
                    definition_name: Some("devnet"),
                    policy_ref: None,
                },
            )
            .expect("named nat vznat should be supported");
    }

    #[test]
    fn vznat_driver_rejects_network_policies() {
        let driver = VzNatDriver;
        let policy_ref = NetworkPolicyRef::new("private").expect("policy ref");

        let result = driver.supports(
            "devbox",
            &NetworkRequest {
                scope: NetworkScope::Named,
                definition_name: Some("devnet"),
                policy_ref: Some(&policy_ref),
            },
        );

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn vznat_prepare_writes_instance_runtime_file() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let paths = LocalPaths::new(dir.path());
        let db = Sqlite::new(&paths).await.expect("open db");
        let machine_id = MachineId::new();
        let metadata = machine_from_path(
            machine_id,
            "devbox".to_string(),
            paths.machine(machine_id).dir(),
        );
        let config = NetworkingConfig {
            private_driver: NetworkDriverKind::VzNat,
            netd: NetdConfig::default(),
        };
        let driver = VzNatDriver;

        let prepared = driver
            .prepare(
                &NetworkDriverContext {
                    paths: &paths,
                    db: &db,
                    metadata: &metadata,
                    config: &config,
                },
                &NetworkRequest {
                    scope: NetworkScope::Named,
                    definition_name: Some("devnet"),
                    policy_ref: None,
                },
            )
            .await
            .expect("prepare vznat runtime");

        assert_eq!(prepared.attachment, RuntimeNetwork::VzNat { mac: None });
    }
}
