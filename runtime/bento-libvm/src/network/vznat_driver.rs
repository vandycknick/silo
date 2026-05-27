use std::fs;

use bento_core::Network;

use crate::LibVmError;

use super::core::{
    NetworkDriver, NetworkDriverContext, NetworkRequest, NetworkScope, PreparedNetwork,
};
use super::{remove_attached_network, write_runtime_file, DRIVER_VZNAT};

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
        if request.policy.is_some() {
            return Err(LibVmError::NetworkRuntime {
                reference: reference.to_string(),
                message: "vznat does not support network policies".to_string(),
            });
        }
        Ok(())
    }

    async fn prepare(
        &self,
        ctx: &NetworkDriverContext<'_>,
        _request: &NetworkRequest<'_>,
    ) -> Result<PreparedNetwork, LibVmError> {
        remove_attached_network(ctx.layout, ctx.state, ctx.metadata.id)?;
        let runtime_dir = ctx.layout.instance_network_link(ctx.metadata.id);
        fs::create_dir_all(&runtime_dir)?;
        let attachment = Network::VzNat { mac: None };
        write_runtime_file(&runtime_dir, &attachment)?;
        Ok(PreparedNetwork { attachment })
    }
}

#[cfg(test)]
mod tests {
    use super::VzNatDriver;
    use crate::global_config::{NetdConfig, NetworkingConfig};
    use crate::network::config::NetworkDriverKind;
    use crate::network::core::{NetworkDriver, NetworkDriverContext, NetworkRequest, NetworkScope};
    use crate::state::{machine_state_from_path, StateStore};
    use crate::Layout;
    use bento_core::{NetworkPolicySpec, PolicyAction};

    #[test]
    fn vznat_driver_supports_private_and_named_nat_networks() {
        let driver = VzNatDriver;

        driver
            .supports(
                "devbox",
                &NetworkRequest {
                    scope: NetworkScope::Private,
                    definition_name: None,
                    policy: None,
                },
            )
            .expect("private vznat should be supported");
        driver
            .supports(
                "devbox",
                &NetworkRequest {
                    scope: NetworkScope::Named,
                    definition_name: Some("devnet"),
                    policy: None,
                },
            )
            .expect("named nat vznat should be supported");
    }

    #[test]
    fn vznat_driver_rejects_network_policies() {
        let driver = VzNatDriver;
        let policy = NetworkPolicySpec {
            default_action: PolicyAction::Allow,
            audit_log: None,
            cidr_rules: Vec::new(),
        };

        let result = driver.supports(
            "devbox",
            &NetworkRequest {
                scope: NetworkScope::Named,
                definition_name: Some("devnet"),
                policy: Some(&policy),
            },
        );

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn vznat_prepare_writes_instance_runtime_file() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let layout = Layout::new(dir.path());
        let state = StateStore::open(&layout).expect("open store");
        let machine_id = bento_core::MachineId::new();
        let metadata = machine_state_from_path(
            machine_id,
            "devbox".to_string(),
            &layout.instance_dir(machine_id),
        );
        let config = NetworkingConfig {
            private_driver: NetworkDriverKind::VzNat,
            netd: NetdConfig::default(),
        };
        let driver = VzNatDriver;

        let prepared = driver
            .prepare(
                &NetworkDriverContext {
                    layout: &layout,
                    state: &state,
                    metadata: &metadata,
                    config: &config,
                },
                &NetworkRequest {
                    scope: NetworkScope::Named,
                    definition_name: Some("devnet"),
                    policy: None,
                },
            )
            .await
            .expect("prepare vznat runtime");

        assert_eq!(
            prepared.attachment,
            bento_core::Network::VzNat { mac: None }
        );
        let raw = std::fs::read_to_string(
            layout
                .instance_network_link(machine_id)
                .join("runtime.json"),
        )
        .expect("read runtime file");
        let value: serde_json::Value = serde_json::from_str(&raw).expect("parse runtime");

        assert_eq!(value["attachment"]["kind"], "vz_nat");
    }
}
