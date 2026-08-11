use std::path::Path;

mod api;
mod builder;
mod core;
mod netd_driver;

pub use api::{
    MachineNetworkBuilder, MachineNetworkConfig, NetworkDefinition, NetworkDriver, NetworkTopology,
};
pub use builder::NetworkBuilder;

pub(crate) use api::validate_network_name;

use serde::{Deserialize, Serialize};

use crate::paths::LocalPaths;
use crate::store::models::MachineId;
use crate::store::models::{
    MachineConfig, MachineNetworkConfig as ModelMachineNetworkConfig,
    NetworkDefinition as ModelNetworkDefinition, NetworkInstance,
};
use crate::store::DataStore;
use crate::{EgressCredentials, LibVmError, RuntimeNetworkingConfig};

use self::core::{NetworkAttachmentRequest, NetworkDriverBackend, NetworkDriverContext};
use self::netd_driver::NetdDriver;

const DRIVER_NETD: &str = "netd";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
/// Resolved network attachment projected into vmmon and guest-agent inputs.
///
/// This is neither the public desired network (`MachineNetworkConfig`) nor the stored
/// network model. Drivers produce this after resolving policy, named networks,
/// runtime directories, guest settings, and persisted attachments.
pub(crate) enum VmmonNetworkAttachment {
    None,
    UnixDatagram {
        path: std::path::PathBuf,
        mac: String,
        ipv4: agent_spec::NetworkIpv4Config,
        dns: agent_spec::NetworkDnsConfig,
        #[serde(default)]
        requires_certificate_authority: bool,
    },
}

impl VmmonNetworkAttachment {
    pub(crate) fn to_vmmon_arg(&self) -> String {
        match self {
            Self::None => "none".to_string(),
            Self::UnixDatagram { path, mac, .. } => {
                format!("unixdg,{},mac={mac}", path.display())
            }
        }
    }

    pub(crate) fn requires_certificate_authority(&self) -> bool {
        matches!(
            self,
            Self::UnixDatagram {
                requires_certificate_authority: true,
                ..
            }
        )
    }
}

pub(crate) async fn prepare_network_runtime(
    paths: &LocalPaths,
    store: &dyn DataStore,
    metadata: &MachineConfig,
    run_id: &str,
    config: &RuntimeNetworkingConfig,
    netd_path: &Path,
    egress_credentials: &EgressCredentials,
) -> Result<VmmonNetworkAttachment, LibVmError> {
    reconcile_network_runtime(paths, store, metadata, false).await?;

    match metadata.network.clone() {
        ModelMachineNetworkConfig::None => {
            remove_attached_network(paths, store, metadata.id).await?;
            Ok(VmmonNetworkAttachment::None)
        }
        ModelMachineNetworkConfig::Private { policy } => {
            let request = NetworkAttachmentRequest::private(policy.as_ref());
            prepare_with_driver(
                NetdDriver,
                &NetworkDriverContext {
                    paths,
                    store,
                    metadata,
                    run_id,
                    config,
                    netd_path,
                    egress_credentials,
                },
                &request,
            )
            .await
        }
        ModelMachineNetworkConfig::Named { name } => {
            let definition = store.network_definition(&name).await?.ok_or_else(|| {
                LibVmError::NetworkRuntime {
                    reference: metadata.name.clone(),
                    message: format!("named network {:?} is not defined", name),
                }
            })?;
            resolve_named_network(
                paths,
                store,
                metadata,
                run_id,
                &definition,
                config,
                egress_credentials,
            )
            .await
        }
    }
}

pub(crate) async fn reconcile_network_runtime(
    paths: &LocalPaths,
    store: &dyn DataStore,
    metadata: &MachineConfig,
    monitor_running: bool,
) -> Result<(), LibVmError> {
    let Some(attachment) = store.network_attachment(metadata.id).await? else {
        return Ok(());
    };
    let Some(instance) = store
        .network_instance(&attachment.network_instance_id)
        .await?
    else {
        return teardown_network_attachment(
            paths,
            store,
            metadata.id,
            &metadata.name,
            attachment,
            None,
        )
        .await;
    };

    if monitor_running && network_instance_is_alive(&instance)? {
        return Ok(());
    }

    teardown_network_attachment(
        paths,
        store,
        metadata.id,
        &metadata.name,
        attachment,
        Some(instance),
    )
    .await
}

async fn resolve_named_network(
    paths: &LocalPaths,
    store: &dyn DataStore,
    metadata: &MachineConfig,
    run_id: &str,
    definition: &ModelNetworkDefinition,
    config: &RuntimeNetworkingConfig,
    egress_credentials: &EgressCredentials,
) -> Result<VmmonNetworkAttachment, LibVmError> {
    let _ = (paths, store, run_id, config, egress_credentials, definition);
    Err(LibVmError::NetworkRuntime {
        reference: metadata.name.clone(),
        message:
            "named network launches require the netd attachment API, which is not implemented yet"
                .to_string(),
    })
}

async fn prepare_with_driver(
    driver: impl NetworkDriverBackend,
    ctx: &NetworkDriverContext<'_>,
    request: &NetworkAttachmentRequest<'_>,
) -> Result<VmmonNetworkAttachment, LibVmError> {
    driver.supports(&ctx.metadata.name, request)?;
    driver.prepare(ctx, request).await
}

pub(super) async fn remove_attached_network(
    paths: &LocalPaths,
    store: &dyn DataStore,
    machine_id: MachineId,
) -> Result<(), LibVmError> {
    let Some(attachment) = store.network_attachment(machine_id).await? else {
        return Ok(());
    };
    let instance = store
        .network_instance(&attachment.network_instance_id)
        .await?;
    teardown_network_attachment(
        paths,
        store,
        machine_id,
        &machine_id.to_string(),
        attachment,
        instance,
    )
    .await
}

pub(crate) fn mac_from_machine_id(machine_id: MachineId) -> [u8; 6] {
    let id = machine_id.to_string();
    let bytes = id.as_bytes();
    let mut mac = [0x02, 0, 0, 0, 0, 0];
    for (index, byte) in mac.iter_mut().enumerate().skip(1) {
        let offset = (index - 1) * 2;
        *byte = hex_byte(bytes.get(offset).copied(), bytes.get(offset + 1).copied());
    }
    mac
}

fn hex_byte(high: Option<u8>, low: Option<u8>) -> u8 {
    let high = high.and_then(hex_nibble).unwrap_or(0);
    let low = low.and_then(hex_nibble).unwrap_or(0);
    (high << 4) | low
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn network_instance_is_alive(instance: &NetworkInstance) -> Result<bool, LibVmError> {
    match instance.driver.as_str() {
        DRIVER_NETD => netd_driver::instance_is_alive(instance),
        _ => Ok(false),
    }
}

async fn terminate_network_instance(
    instance: &NetworkInstance,
    reference: &str,
) -> Result<(), LibVmError> {
    if instance.driver == DRIVER_NETD {
        netd_driver::terminate_instance(instance, reference).await?;
    }
    Ok(())
}

async fn teardown_network_attachment(
    paths: &LocalPaths,
    store: &dyn DataStore,
    machine_id: MachineId,
    reference: &str,
    attachment: crate::store::models::NetworkAttachment,
    instance: Option<NetworkInstance>,
) -> Result<(), LibVmError> {
    let Some(instance) = instance else {
        paths.remove_network_run_tree(&attachment.network_instance_id)?;
        store.detach_network(machine_id).await?;
        return Ok(());
    };

    if store.network_attachment_count(&instance.id).await? > 1 {
        store.detach_network(machine_id).await?;
        return Ok(());
    }

    // Keep the attachment and instance rows until their external generation and
    // all runtime artifacts are gone. A failed cleanup is therefore retryable.
    terminate_network_instance(&instance, reference).await?;
    paths.remove_network_run_tree(&instance.id)?;
    store.remove_network_instance(&instance.id).await?;
    Ok(())
}

pub(super) fn serialize_json<T: Serialize>(value: &T, label: &str) -> Result<String, LibVmError> {
    serde_json::to_string(value).map_err(|err| LibVmError::NetworkRuntime {
        reference: label.to_string(),
        message: format!("serialize {label}: {err}"),
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::Path;

    use serde_json::json;
    use vm_spec::VmSpec;

    use crate::lock_manager::LockId;
    use crate::paths::{LocalPaths, LocalRoots};
    use crate::store::models::MachineId;
    use crate::store::models::{
        MachineConfig, MachineNetworkConfig as ModelMachineNetworkConfig, MachineRuntimeState,
        MachineState, NetworkAttachment, NetworkDefinition as ModelNetworkDefinition,
        NetworkDriverPreference as ModelNetworkDriverPreference, NetworkInstance,
        NetworkInstanceState, NetworkTopology as ModelNetworkTopology,
    };
    use crate::store::{MachineStore, MockDataStore, NetworkStore, Store};
    use crate::{LibVmError, RuntimeNetworkingConfig};

    use super::{prepare_network_runtime, reconcile_network_runtime, VmmonNetworkAttachment};

    fn machine_config(
        paths: &LocalPaths,
        id: MachineId,
        name: &str,
        network: ModelMachineNetworkConfig,
    ) -> MachineConfig {
        MachineConfig {
            id,
            lock_id: LockId::from(0),
            name: name.to_string(),
            spec: VmSpec::current(),
            retention: crate::MachineRetention::Persistent,
            process: crate::ProcessConfig::default(),
            template_name: None,
            agent_mode: None,
            machine_dir: paths.machine(id).dir().to_path_buf(),
            created_at: 1,
            modified_at: 1,
            image_ref: String::new(),
            root_disk_size: None,
            labels: BTreeMap::new(),
            metadata: BTreeMap::new(),
            network,
            guest: crate::machine::MachineGuestConfig::default(),
        }
    }

    fn attachment(machine_id: MachineId, network_instance_id: &str) -> NetworkAttachment {
        NetworkAttachment {
            machine_id,
            network_instance_id: network_instance_id.to_string(),
            guest_mac: "02:11:22:33:44:55".to_string(),
            created_at: 1,
            modified_at: 1,
        }
    }

    fn instance(id: &str) -> NetworkInstance {
        NetworkInstance {
            id: id.to_string(),
            driver: "removed-driver".to_string(),
            definition_name: None,
            attachment_json: r#"{"kind":"none"}"#.to_string(),
            driver_state_json: "{}".to_string(),
            state: NetworkInstanceState::Running,
            created_at: 1,
            modified_at: 1,
        }
    }

    fn named_definition(name: &str, topology: ModelNetworkTopology) -> ModelNetworkDefinition {
        ModelNetworkDefinition {
            name: name.to_string(),
            topology,
            driver_preference: ModelNetworkDriverPreference::Auto,
            created_at: 1,
            modified_at: 1,
        }
    }

    #[test]
    fn persisted_attachment_without_ca_requirement_defaults_to_false() {
        let attachment: VmmonNetworkAttachment = serde_json::from_value(json!({
            "kind": "unix_datagram",
            "path": "/tmp/net.sock",
            "mac": "02:11:22:33:44:55",
            "ipv4": {
                "address": "192.168.105.2",
                "prefix_length": 24,
                "gateway": "192.168.105.1"
            },
            "dns": {
                "servers": ["192.168.105.1"],
                "search": []
            }
        }))
        .expect("decode attachment");

        assert!(!attachment.requires_certificate_authority());
        assert_eq!(
            attachment.to_vmmon_arg(),
            "unixdg,/tmp/net.sock,mac=02:11:22:33:44:55"
        );
    }

    #[tokio::test]
    async fn reconcile_detaches_attachment_when_instance_is_missing() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let paths = LocalPaths::new(temp.path().join("silo"));
        let machine_id = MachineId::new();
        let metadata = machine_config(
            &paths,
            machine_id,
            "devbox",
            ModelMachineNetworkConfig::default(),
        );
        let mut store = MockDataStore::new();
        store
            .expect_network_attachment()
            .withf(move |id| *id == machine_id)
            .once()
            .returning(move |_| Ok(Some(attachment(machine_id, "missing"))));
        store
            .expect_network_instance()
            .withf(|network_id| network_id == "missing")
            .once()
            .returning(|_| Ok(None));
        store
            .expect_detach_network()
            .withf(move |id| *id == machine_id)
            .once()
            .returning(|_| Ok(()));

        reconcile_network_runtime(&paths, &store, &metadata, false)
            .await
            .expect("reconcile missing instance");
    }

    #[tokio::test]
    async fn reconcile_removes_inactive_last_network_instance() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let paths = LocalPaths::new(temp.path().join("silo"));
        let machine_id = MachineId::new();
        let runtime_dir = paths
            .network("net-1")
            .expect("network paths")
            .runtime_dir()
            .to_path_buf();
        paths
            .ensure_network_run_dir("net-1")
            .expect("create runtime dir");
        let instance = instance("net-1");
        let metadata = machine_config(
            &paths,
            machine_id,
            "devbox",
            ModelMachineNetworkConfig::default(),
        );
        let mut store = MockDataStore::new();
        store
            .expect_network_attachment()
            .withf(move |id| *id == machine_id)
            .once()
            .returning(move |_| Ok(Some(attachment(machine_id, "net-1"))));
        let instance_for_lookup = instance.clone();
        store
            .expect_network_instance()
            .withf(|network_id| network_id == "net-1")
            .once()
            .return_once(move |_| Ok(Some(instance_for_lookup)));
        store
            .expect_network_attachment_count()
            .withf(|network_id| network_id == "net-1")
            .once()
            .returning(|_| Ok(0));
        store
            .expect_remove_network_instance()
            .withf(|network_id| network_id == "net-1")
            .once()
            .returning(|_| Ok(()));

        reconcile_network_runtime(&paths, &store, &metadata, false)
            .await
            .expect("reconcile inactive instance");

        assert!(
            !runtime_dir.exists(),
            "last attachment should remove runtime dir"
        );
    }

    #[tokio::test]
    async fn reconcile_keeps_inactive_network_instance_with_other_attachments() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let paths = LocalPaths::new(temp.path().join("silo"));
        let machine_id = MachineId::new();
        let runtime_dir = paths
            .network("net-1")
            .expect("network paths")
            .runtime_dir()
            .to_path_buf();
        paths
            .ensure_network_run_dir("net-1")
            .expect("create runtime dir");
        let instance = instance("net-1");
        let metadata = machine_config(
            &paths,
            machine_id,
            "devbox",
            ModelMachineNetworkConfig::default(),
        );
        let mut store = MockDataStore::new();
        store
            .expect_network_attachment()
            .withf(move |id| *id == machine_id)
            .once()
            .returning(move |_| Ok(Some(attachment(machine_id, "net-1"))));
        store
            .expect_network_instance()
            .withf(|network_id| network_id == "net-1")
            .once()
            .return_once(move |_| Ok(Some(instance)));
        store
            .expect_detach_network()
            .withf(move |id| *id == machine_id)
            .once()
            .returning(|_| Ok(()));
        store
            .expect_network_attachment_count()
            .withf(|network_id| network_id == "net-1")
            .once()
            .returning(|_| Ok(2));

        reconcile_network_runtime(&paths, &store, &metadata, false)
            .await
            .expect("reconcile shared instance");

        assert!(
            runtime_dir.exists(),
            "shared instance runtime dir should stay"
        );
    }

    #[tokio::test]
    async fn reconciliation_uses_current_run_root_for_fresh_database_cleanup() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let data_root = temp.path().join("data");
        let current_run_root = temp.path().join("run-current");
        let old_run_root = temp.path().join("run-old");
        let paths = LocalPaths::from_roots(LocalRoots::with_roots(
            &data_root,
            &data_root,
            &current_run_root,
            data_root.join("images"),
        ));
        let store = Store::new(&paths).await.expect("open fresh database");
        let machine_id = MachineId::new();
        let metadata = machine_config(
            &paths,
            machine_id,
            "devbox",
            ModelMachineNetworkConfig::default(),
        );
        let state = MachineState {
            machine_id,
            status: MachineRuntimeState::Stopped,
            vmmon_pid: None,
            started_at: None,
            run_id: None,
            last_error: None,
            updated_at: 1,
        };
        store
            .add_machine(&metadata, &state)
            .await
            .expect("seed machine");

        let network_id = "net-1";
        let current_runtime_dir = paths
            .network(network_id)
            .expect("network paths")
            .runtime_dir()
            .to_path_buf();
        let old_runtime_dir = old_run_root.join("net").join(network_id);
        paths
            .ensure_network_run_dir(network_id)
            .expect("create current runtime dir");
        std::fs::create_dir_all(&old_runtime_dir).expect("create old runtime dir");
        store
            .save_network_instance(&instance(network_id))
            .await
            .expect("save network instance");
        store
            .attach_network(&attachment(machine_id, network_id))
            .await
            .expect("attach network");

        reconcile_network_runtime(&paths, &store, &metadata, false)
            .await
            .expect("reconcile inactive network");

        assert!(!current_runtime_dir.exists());
        assert!(old_runtime_dir.exists());
        assert!(store
            .network_instance(network_id)
            .await
            .expect("read instance")
            .is_none());
    }

    #[tokio::test]
    async fn prepare_named_network_requires_attachment_api() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let paths = LocalPaths::new(temp.path().join("silo"));
        let machine_id = MachineId::new();
        let metadata = machine_config(
            &paths,
            machine_id,
            "devbox",
            ModelMachineNetworkConfig::Named {
                name: "bridge-net".to_string(),
            },
        );
        let mut store = MockDataStore::new();
        store
            .expect_network_attachment()
            .withf(move |id| *id == machine_id)
            .once()
            .returning(|_| Ok(None));
        store
            .expect_network_definition()
            .withf(|name| name == "bridge-net")
            .once()
            .returning(|_| {
                Ok(Some(named_definition(
                    "bridge-net",
                    ModelNetworkTopology::Bridge,
                )))
            });

        let err = prepare_network_runtime(
            &paths,
            &store,
            &metadata,
            "run-123",
            &RuntimeNetworkingConfig::default(),
            Path::new("/tmp/netd"),
            &crate::EgressCredentials::default(),
        )
        .await
        .expect_err("named attachment API should be required");

        assert!(matches!(
            err,
            LibVmError::NetworkRuntime { ref reference, ref message }
                if reference == "devbox" && message.contains("attachment API")
        ));
    }
}
