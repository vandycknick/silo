use std::fs;
use std::os::unix::fs::symlink;
use std::path::Path;

mod api;
mod builder;
mod core;
mod netd_driver;
mod policy;
mod vznat_driver;

pub use api::{
    MachineNetworkConfig, NetworkDefinition, NetworkDriver, NetworkDriverKind, NetworkTopology,
};
pub use builder::NetworkBuilder;
pub use policy::NetworkPolicyRef;

pub(crate) use api::validate_network_name;

use serde::{Deserialize, Serialize};

use crate::paths::LocalPaths;
use crate::store::models::MachineId;
use crate::store::models::{
    MachineConfig, MachineNetworkConfig as ModelMachineNetworkConfig,
    NetworkDefinition as ModelNetworkDefinition,
    NetworkDriverPreference as ModelNetworkDriverPreference, NetworkInstance,
    NetworkTopology as ModelNetworkTopology,
};
use crate::store::DataStore;
use crate::{LibVmError, RuntimeNetworkingConfig};

use self::core::{NetworkAttachmentRequest, NetworkDriverBackend, NetworkDriverContext};
use self::netd_driver::NetdDriver;
use self::vznat_driver::VzNatDriver;

const DRIVER_NETD: &str = "netd";
const DRIVER_VZNAT: &str = "vznat";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
/// Resolved network attachment passed to vmmon.
///
/// This is neither the public desired network (`MachineNetworkConfig`) nor the stored
/// network model. Drivers produce this after resolving policy, named networks,
/// runtime directories, and persisted attachments.
pub(crate) enum VmmonNetworkAttachment {
    None,
    VzNat {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mac: Option<String>,
    },
    UnixDatagram {
        path: std::path::PathBuf,
        mac: String,
    },
}

impl VmmonNetworkAttachment {
    pub(crate) fn to_vmmon_arg(&self) -> String {
        match self {
            Self::None => "none".to_string(),
            Self::VzNat { mac: None } => "vznat".to_string(),
            Self::VzNat { mac: Some(mac) } => format!("vznat,mac={mac}"),
            Self::UnixDatagram { path, mac } => format!("unixdg,{},mac={mac}", path.display()),
        }
    }
}

pub(crate) async fn prepare_network_runtime(
    paths: &LocalPaths,
    store: &dyn DataStore,
    metadata: &MachineConfig,
    config: &RuntimeNetworkingConfig,
) -> Result<VmmonNetworkAttachment, LibVmError> {
    reconcile_network_runtime(paths, store, metadata, false).await?;

    match metadata.network.clone() {
        ModelMachineNetworkConfig::None => {
            remove_attached_network(paths, store, metadata.id).await?;
            Ok(VmmonNetworkAttachment::None)
        }
        ModelMachineNetworkConfig::Private { policy_ref } => {
            let request = NetworkAttachmentRequest::private(policy_ref.as_ref());
            prepare_with_driver(
                selected_private_driver(config.private_driver),
                &NetworkDriverContext {
                    paths,
                    store,
                    metadata,
                    config,
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
            resolve_named_network(paths, store, metadata, &definition, config).await
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
) -> Result<VmmonNetworkAttachment, LibVmError> {
    match definition.topology {
        ModelNetworkTopology::Nat => {
            let driver = match definition.driver_preference {
                ModelNetworkDriverPreference::Auto | ModelNetworkDriverPreference::Netd => {
                    NetworkDriverKind::Netd
                }
                ModelNetworkDriverPreference::VzNat => NetworkDriverKind::VzNat,
            };
            let request = NetworkAttachmentRequest::named(definition.name.as_str());
            prepare_with_driver(
                selected_private_driver(driver),
                &NetworkDriverContext {
                    paths,
                    store,
                    metadata,
                    config,
                },
                &request,
            )
            .await
        }
        ModelNetworkTopology::Bridge => Err(LibVmError::NetworkRuntime {
            reference: metadata.name.clone(),
            message: format!(
                "named network {:?} uses bridge mode, which is not implemented yet",
                definition.name
            ),
        }),
        ModelNetworkTopology::Isolated => Err(LibVmError::NetworkRuntime {
            reference: metadata.name.clone(),
            message: format!(
                "named network {:?} uses isolated mode, which is not implemented yet",
                definition.name
            ),
        }),
    }
}

fn selected_private_driver(kind: NetworkDriverKind) -> impl NetworkDriverBackend {
    match kind {
        NetworkDriverKind::Netd => SelectedNetworkDriver::Netd(NetdDriver),
        NetworkDriverKind::VzNat => SelectedNetworkDriver::VzNat(VzNatDriver),
    }
}

enum SelectedNetworkDriver {
    Netd(NetdDriver),
    VzNat(VzNatDriver),
}

impl NetworkDriverBackend for SelectedNetworkDriver {
    fn id(&self) -> &'static str {
        match self {
            Self::Netd(driver) => driver.id(),
            Self::VzNat(driver) => driver.id(),
        }
    }

    fn supports(
        &self,
        reference: &str,
        request: &NetworkAttachmentRequest<'_>,
    ) -> Result<(), LibVmError> {
        match self {
            Self::Netd(driver) => driver.supports(reference, request),
            Self::VzNat(driver) => driver.supports(reference, request),
        }
    }

    async fn prepare(
        &self,
        ctx: &NetworkDriverContext<'_>,
        request: &NetworkAttachmentRequest<'_>,
    ) -> Result<VmmonNetworkAttachment, LibVmError> {
        match self {
            Self::Netd(driver) => driver.prepare(ctx, request).await,
            Self::VzNat(driver) => driver.prepare(ctx, request).await,
        }
    }
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

pub(super) fn network_attachment_from_instance(
    instance: &NetworkInstance,
    mac: String,
) -> Result<VmmonNetworkAttachment, LibVmError> {
    let mut attachment: VmmonNetworkAttachment = serde_json::from_str(&instance.attachment_json)
        .map_err(|err| LibVmError::NetworkRuntime {
            reference: instance.id.clone(),
            message: format!("parse network attachment: {err}"),
        })?;
    if let VmmonNetworkAttachment::UnixDatagram { mac: existing, .. } = &mut attachment {
        *existing = mac;
    }
    Ok(attachment)
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
        DRIVER_VZNAT,
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
            driver: DRIVER_VZNAT.to_string(),
            definition_name: None,
            runtime_dir: runtime_dir.display().to_string(),
            attachment_json: r#"{"kind":"vznat"}"#.to_string(),
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

    #[tokio::test]
    async fn reconcile_detaches_attachment_when_instance_is_missing() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let paths = LocalPaths::new(temp.path().join("bento"));
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
        let paths = LocalPaths::new(temp.path().join("bento"));
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
        let paths = LocalPaths::new(temp.path().join("bento"));
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
    async fn prepare_named_bridge_network_fails_before_driver_setup() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let paths = LocalPaths::new(temp.path().join("bento"));
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
        )
        .await
        .expect_err("bridge topology should not be implemented yet");

        assert!(matches!(
            err,
            LibVmError::NetworkRuntime { ref reference, ref message }
                if reference == "devbox" && message.contains("bridge mode")
        ));
    }
}
