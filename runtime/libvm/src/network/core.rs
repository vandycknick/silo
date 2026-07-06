use async_trait::async_trait;
use silo_policy::NetworkPolicy;

use crate::paths::LocalPaths;
use crate::store::models::MachineConfig;
use crate::store::DataStore;
use crate::{LibVmError, NetworkLaunch, RuntimeNetworkingConfig};

use super::VmmonNetworkAttachment;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum NetworkAttachmentTarget<'a> {
    Private { policy: Option<&'a NetworkPolicy> },
    Named { definition_name: &'a str },
}

pub(super) struct NetworkAttachmentRequest<'a> {
    pub(super) target: NetworkAttachmentTarget<'a>,
}

impl<'a> NetworkAttachmentRequest<'a> {
    pub(super) fn private(policy: Option<&'a NetworkPolicy>) -> Self {
        Self {
            target: NetworkAttachmentTarget::Private { policy },
        }
    }

    pub(super) fn named(definition_name: &'a str) -> Self {
        Self {
            target: NetworkAttachmentTarget::Named { definition_name },
        }
    }

    pub(super) fn policy(&self) -> Option<&'a NetworkPolicy> {
        match self.target {
            NetworkAttachmentTarget::Private { policy } => policy,
            NetworkAttachmentTarget::Named { .. } => None,
        }
    }

    pub(super) fn definition_name(&self) -> Option<&'a str> {
        match self.target {
            NetworkAttachmentTarget::Private { .. } => None,
            NetworkAttachmentTarget::Named { definition_name } => Some(definition_name),
        }
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
