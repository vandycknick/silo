use crate::global_config::NetworkingConfig;
use crate::models::MachineConfig;
use crate::store::Sqlite;
use crate::{Layout, LibVmError, NetworkPolicyRef};

use super::RuntimeNetwork;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum NetworkScope {
    Private,
    Named,
}

pub(super) struct NetworkRequest<'a> {
    pub(super) scope: NetworkScope,
    pub(super) definition_name: Option<&'a str>,
    pub(super) policy_ref: Option<&'a NetworkPolicyRef>,
}

pub(super) struct NetworkDriverContext<'a> {
    pub(super) layout: &'a Layout,
    pub(super) db: &'a Sqlite,
    pub(super) metadata: &'a MachineConfig,
    pub(super) config: &'a NetworkingConfig,
}

pub(super) struct PreparedNetwork {
    pub(super) attachment: RuntimeNetwork,
}

pub(super) trait NetworkDriver {
    fn id(&self) -> &'static str;
    fn supports(&self, reference: &str, request: &NetworkRequest<'_>) -> Result<(), LibVmError>;
    async fn prepare(
        &self,
        ctx: &NetworkDriverContext<'_>,
        request: &NetworkRequest<'_>,
    ) -> Result<PreparedNetwork, LibVmError>;
}
