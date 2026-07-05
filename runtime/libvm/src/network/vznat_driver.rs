use std::fs;

use async_trait::async_trait;

use crate::LibVmError;

use super::core::{NetworkAttachmentRequest, NetworkDriverBackend, NetworkDriverContext};
use super::{remove_attached_network, VmmonNetworkAttachment, DRIVER_VZNAT};

pub(super) struct VzNatDriver;

#[async_trait]
impl NetworkDriverBackend for VzNatDriver {
    fn id(&self) -> &'static str {
        DRIVER_VZNAT
    }

    fn supports(
        &self,
        reference: &str,
        request: &NetworkAttachmentRequest<'_>,
    ) -> Result<(), LibVmError> {
        if request.policy().is_some() {
            return Err(LibVmError::NetworkRuntime {
                reference: reference.to_string(),
                message: "vznat does not support network policy".to_string(),
            });
        }
        Ok(())
    }

    async fn prepare(
        &self,
        ctx: &NetworkDriverContext<'_>,
        _request: &NetworkAttachmentRequest<'_>,
    ) -> Result<VmmonNetworkAttachment, LibVmError> {
        remove_attached_network(ctx.paths, ctx.store, ctx.metadata.id).await?;
        let runtime_dir = ctx.paths.machine(ctx.metadata.id).network_link();
        fs::create_dir_all(&runtime_dir)?;
        Ok(VmmonNetworkAttachment::VzNat { mac: None })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::Path;

    use super::VzNatDriver;
    use crate::lock_manager::LockId;
    use crate::network::core::{
        NetworkAttachmentRequest, NetworkDriverBackend, NetworkDriverContext,
    };
    use crate::network::NetworkDriverKind;
    use crate::network::VmmonNetworkAttachment;
    use crate::paths::LocalPaths;
    use crate::store::models::MachineId;
    use crate::store::models::{MachineConfig, MachineNetworkConfig};
    use crate::store::MockDataStore;
    use crate::{NetdRuntimeConfig, NetworkPolicy, RuntimeNetworkingConfig};
    use vm_spec::VmSpec;

    fn machine_from_path(id: MachineId, name: String, machine_dir: &Path) -> MachineConfig {
        let spec = sample_vm_spec();
        MachineConfig {
            id,
            lock_id: LockId::from(0),
            name,
            spec,
            machine_dir: machine_dir.to_path_buf(),
            created_at: 1,
            modified_at: 1,
            image_ref: String::new(),
            root_disk_size: None,
            labels: BTreeMap::new(),
            metadata: BTreeMap::new(),
            network: MachineNetworkConfig::default(),
        }
    }

    fn sample_vm_spec() -> VmSpec {
        VmSpec::current()
    }

    #[test]
    fn vznat_driver_supports_private_and_named_nat_networks() {
        let driver = VzNatDriver;

        driver
            .supports("devbox", &NetworkAttachmentRequest::private(None))
            .expect("private vznat should be supported");
        driver
            .supports("devbox", &NetworkAttachmentRequest::named("devnet"))
            .expect("named nat vznat should be supported");
    }

    #[test]
    fn vznat_driver_rejects_network_policies() {
        let driver = VzNatDriver;
        let policy =
            NetworkPolicy::from_json_str(r#"{ "version": 1, "metadata": {} }"#).expect("policy");

        let result = driver.supports("devbox", &NetworkAttachmentRequest::private(Some(&policy)));

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn vznat_prepare_writes_instance_runtime_file() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let paths = LocalPaths::new(dir.path());
        let machine_id = MachineId::new();
        let mut store = MockDataStore::new();
        store
            .expect_network_attachment()
            .withf(move |id| *id == machine_id)
            .once()
            .returning(|_| Ok(None));
        let metadata = machine_from_path(
            machine_id,
            "devbox".to_string(),
            paths.machine(machine_id).dir(),
        );
        let config = RuntimeNetworkingConfig {
            private_driver: NetworkDriverKind::VzNat,
            netd: NetdRuntimeConfig::default(),
            ..RuntimeNetworkingConfig::default()
        };
        let driver = VzNatDriver;

        let prepared = driver
            .prepare(
                &NetworkDriverContext {
                    paths: &paths,
                    store: &store,
                    metadata: &metadata,
                    config: &config,
                    network_launch: &crate::NetworkLaunch::default(),
                },
                &NetworkAttachmentRequest::named("devnet"),
            )
            .await
            .expect("prepare vznat runtime");

        assert_eq!(prepared, VmmonNetworkAttachment::VzNat { mac: None });
    }
}
