use async_trait::async_trait;
use silo_policy::NetworkPolicy;

use crate::paths::LocalPaths;
use crate::store::models::MachineConfig;
use crate::store::DataStore;
use crate::{LibVmError, NetworkLaunch, RuntimeNetworkingConfig};

use super::VmmonNetworkAttachment;

pub(super) struct NetworkAttachmentRequest<'a> {
    policy: Option<&'a NetworkPolicy>,
}

impl<'a> NetworkAttachmentRequest<'a> {
    pub(super) fn private(policy: Option<&'a NetworkPolicy>) -> Self {
        Self { policy }
    }

    pub(super) fn policy(&self) -> Option<&'a NetworkPolicy> {
        self.policy
    }
}

pub(super) struct NetworkDriverContext<'a> {
    pub(super) paths: &'a LocalPaths,
    pub(super) store: &'a dyn DataStore,
    pub(super) metadata: &'a MachineConfig,
    pub(super) config: &'a RuntimeNetworkingConfig,
    pub(super) network_launch: &'a NetworkLaunch,
}

#[async_trait]
pub(super) trait NetworkDriverBackend: Send + Sync {
    fn id(&self) -> &'static str;
    fn supports(
        &self,
        reference: &str,
        request: &NetworkAttachmentRequest<'_>,
    ) -> Result<(), LibVmError>;
    async fn prepare(
        &self,
        ctx: &NetworkDriverContext<'_>,
        request: &NetworkAttachmentRequest<'_>,
    ) -> Result<VmmonNetworkAttachment, LibVmError>;
}
