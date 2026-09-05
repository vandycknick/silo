use async_trait::async_trait;
use silo_policy::NetworkPolicy;
use std::path::Path;

use crate::paths::LocalPaths;
use crate::store::models::MachineConfig;
use crate::store::DataStore;
use crate::{EgressCredentials, LibVmError, RuntimeNetworkingConfig};

use super::VmmonNetworkAttachment;
use crate::network::GuestPublish;

pub(super) struct NetworkAttachmentRequest<'a> {
    policy: Option<&'a NetworkPolicy>,
    publish: Option<GuestPublish>,
}

impl<'a> NetworkAttachmentRequest<'a> {
    pub(super) fn private(
        policy: Option<&'a NetworkPolicy>,
        publish: Option<GuestPublish>,
    ) -> Self {
        Self { policy, publish }
    }

    pub(super) fn policy(&self) -> Option<&'a NetworkPolicy> {
        self.policy
    }

    pub(super) fn publish(&self) -> Option<GuestPublish> {
        self.publish
    }
}

pub(super) struct NetworkDriverContext<'a> {
    pub(super) paths: &'a LocalPaths,
    pub(super) store: &'a dyn DataStore,
    pub(super) metadata: &'a MachineConfig,
    pub(super) run_id: &'a str,
    pub(super) config: &'a RuntimeNetworkingConfig,
    pub(super) netd_path: &'a Path,
    pub(super) egress_credentials: &'a EgressCredentials,
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
