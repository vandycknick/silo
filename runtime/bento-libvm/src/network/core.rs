use bento_core::{Network, NetworkPolicySpec};

use crate::global_config::NetworkingConfig;
use crate::state::{MachineState, StateStore};
use crate::{Layout, LibVmError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum NetworkScope {
    Private,
    Named,
}

pub(super) struct NetworkRequest<'a> {
    pub(super) scope: NetworkScope,
    pub(super) definition_name: Option<&'a str>,
    pub(super) policy: Option<&'a NetworkPolicySpec>,
}

pub(super) struct NetworkDriverContext<'a> {
    pub(super) layout: &'a Layout,
    pub(super) state: &'a StateStore,
    pub(super) metadata: &'a MachineState,
    pub(super) config: &'a NetworkingConfig,
}

pub(super) struct PreparedNetwork {
    pub(super) attachment: Network,
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
