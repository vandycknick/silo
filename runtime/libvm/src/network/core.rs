use crate::paths::LocalPaths;
use crate::store::models::MachineConfig;
use crate::store::DataStore;
use crate::{LibVmError, NetworkPolicyRef, RuntimeNetworkingConfig};

use super::VmmonNetworkAttachment;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum NetworkAttachmentTarget<'a> {
    Private {
        policy_ref: Option<&'a NetworkPolicyRef>,
    },
    Named {
        definition_name: &'a str,
    },
}

pub(super) struct NetworkAttachmentRequest<'a> {
    pub(super) target: NetworkAttachmentTarget<'a>,
}

impl<'a> NetworkAttachmentRequest<'a> {
    pub(super) fn private(policy_ref: Option<&'a NetworkPolicyRef>) -> Self {
        Self {
            target: NetworkAttachmentTarget::Private { policy_ref },
        }
    }

    pub(super) fn named(definition_name: &'a str) -> Self {
        Self {
            target: NetworkAttachmentTarget::Named { definition_name },
        }
    }

    pub(super) fn policy_ref(&self) -> Option<&'a NetworkPolicyRef> {
        match self.target {
            NetworkAttachmentTarget::Private { policy_ref } => policy_ref,
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
}

pub(super) trait NetworkDriverBackend {
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
