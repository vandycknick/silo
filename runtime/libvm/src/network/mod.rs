use std::fs;
use std::os::unix::fs::symlink;
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
use crate::{LibVmError, NetworkLaunch, RuntimeNetworkingConfig};

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
    config: &RuntimeNetworkingConfig,
    network_launch: &NetworkLaunch,
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
                    config,
                    network_launch,
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
            resolve_named_network(paths, store, metadata, &definition, config, network_launch).await
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
        remove_instance_network_link(paths, metadata.id)?;
        store.detach_network(metadata.id).await?;
        return Ok(());
    };

    if monitor_running && network_instance_is_alive(&instance) {
        ensure_instance_network_link(paths, metadata.id, Path::new(&instance.runtime_dir))?;
        return Ok(());
    }

    store.detach_network(metadata.id).await?;
    remove_instance_network_link(paths, metadata.id)?;
    if store.network_attachment_count(&instance.id).await? == 0 {
        terminate_network_instance(&instance)?;
        store.remove_network_instance(&instance.id).await?;
        remove_runtime_dir(Path::new(&instance.runtime_dir))?;
    }
    Ok(())
}

async fn resolve_named_network(
    paths: &LocalPaths,
    store: &dyn DataStore,
    metadata: &MachineConfig,
    definition: &ModelNetworkDefinition,
    config: &RuntimeNetworkingConfig,
    network_launch: &NetworkLaunch,
) -> Result<VmmonNetworkAttachment, LibVmError> {
    let _ = (paths, store, config, network_launch, definition);
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
        remove_instance_network_link(paths, machine_id)?;
        return Ok(());
    };
    let instance = store
        .network_instance(&attachment.network_instance_id)
        .await?;
    store.detach_network(machine_id).await?;
    remove_instance_network_link(paths, machine_id)?;
    if let Some(instance) = instance {
        if store.network_attachment_count(&instance.id).await? == 0 {
            terminate_network_instance(&instance)?;
            store.remove_network_instance(&instance.id).await?;
            remove_runtime_dir(Path::new(&instance.runtime_dir))?;
        }
    }
    Ok(())
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

fn network_instance_is_alive(instance: &NetworkInstance) -> bool {
    match instance.driver.as_str() {
        DRIVER_NETD => netd_driver::instance_is_alive(instance),
        _ => false,
    }
}

fn terminate_network_instance(instance: &NetworkInstance) -> Result<(), LibVmError> {
    if instance.driver == DRIVER_NETD {
        netd_driver::terminate_instance(instance)?;
    }
    Ok(())
}

pub(super) fn serialize_json<T: Serialize>(value: &T, label: &str) -> Result<String, LibVmError> {
    serde_json::to_string(value).map_err(|err| LibVmError::NetworkRuntime {
        reference: label.to_string(),
        message: format!("serialize {label}: {err}"),
    })
}

pub(super) fn ensure_instance_network_link(
    paths: &LocalPaths,
    machine_id: MachineId,
    runtime_dir: &Path,
) -> Result<(), LibVmError> {
    let link = paths.machine(machine_id).network_link();
    remove_instance_network_link(paths, machine_id)?;
    symlink(runtime_dir, link)?;
    Ok(())
}

pub(super) fn remove_instance_network_link(
    paths: &LocalPaths,
    machine_id: MachineId,
) -> Result<(), LibVmError> {
    let link = paths.machine(machine_id).network_link();
    let metadata = match fs::symlink_metadata(&link) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err.into()),
    };

    if metadata.file_type().is_dir() {
        fs::remove_dir_all(&link)?;
    } else {
        fs::remove_file(&link)?;
    }
    Ok(())
}

pub(super) fn remove_runtime_dir(path: &Path) -> Result<(), LibVmError> {
    match fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
}

pub(super) fn remove_file_if_exists(path: &Path) -> Result<(), LibVmError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde_json::json;
    use vm_spec::VmSpec;

    use crate::lock_manager::LockId;
    use crate::paths::LocalPaths;
    use crate::store::models::MachineId;
    use crate::store::models::{
        MachineConfig, MachineNetworkConfig as ModelMachineNetworkConfig, NetworkAttachment,
        NetworkDefinition as ModelNetworkDefinition,
        NetworkDriverPreference as ModelNetworkDriverPreference, NetworkInstance,
        NetworkInstanceState, NetworkTopology as ModelNetworkTopology,
    };
    use crate::store::MockDataStore;
    use crate::{LibVmError, RuntimeNetworkingConfig};

    use super::{
        ensure_instance_network_link, prepare_network_runtime, reconcile_network_runtime,
        VmmonNetworkAttachment,
    };

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

    fn instance(id: &str, runtime_dir: &std::path::Path) -> NetworkInstance {
        NetworkInstance {
            id: id.to_string(),
            driver: "removed-driver".to_string(),
            definition_name: None,
            runtime_dir: runtime_dir.display().to_string(),
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
        let runtime_dir = temp.path().join("missing-runtime");
        std::fs::create_dir_all(&runtime_dir).expect("create runtime dir");
        std::fs::create_dir_all(paths.machine(machine_id).dir()).expect("create machine dir");
        ensure_instance_network_link(&paths, machine_id, &runtime_dir)
            .expect("create network link");
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

        assert!(!paths.machine(machine_id).network_link().exists());
        assert!(
            runtime_dir.exists(),
            "missing DB instance should not remove unrelated dir"
        );
    }

    #[tokio::test]
    async fn reconcile_removes_inactive_last_network_instance() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let paths = LocalPaths::new(temp.path().join("silo"));
        let machine_id = MachineId::new();
        let runtime_dir = temp.path().join("runtime-dir");
        std::fs::create_dir_all(&runtime_dir).expect("create runtime dir");
        std::fs::create_dir_all(paths.machine(machine_id).dir()).expect("create machine dir");
        ensure_instance_network_link(&paths, machine_id, &runtime_dir)
            .expect("create network link");
        let instance = instance("net-1", &runtime_dir);
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
            .expect_detach_network()
            .withf(move |id| *id == machine_id)
            .once()
            .returning(|_| Ok(()));
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

        assert!(!paths.machine(machine_id).network_link().exists());
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
        let runtime_dir = temp.path().join("shared-runtime-dir");
        std::fs::create_dir_all(&runtime_dir).expect("create runtime dir");
        std::fs::create_dir_all(paths.machine(machine_id).dir()).expect("create machine dir");
        ensure_instance_network_link(&paths, machine_id, &runtime_dir)
            .expect("create network link");
        let instance = instance("net-1", &runtime_dir);
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
            .returning(|_| Ok(1));

        reconcile_network_runtime(&paths, &store, &metadata, false)
            .await
            .expect("reconcile shared instance");

        assert!(!paths.machine(machine_id).network_link().exists());
        assert!(
            runtime_dir.exists(),
            "shared instance runtime dir should stay"
        );
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
            &RuntimeNetworkingConfig::default(),
            &crate::NetworkLaunch::default(),
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
