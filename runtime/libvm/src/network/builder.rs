use crate::network::{NetworkDefinition, NetworkDriver, NetworkTopology};
use crate::runtime::Runtime;
use crate::LibVmError;

/// Builder for creating a named network definition.
///
/// Network definitions are durable named-network config. Creating one does not
/// attach any machine; machines opt into it with `MachineNetworkConfig::named`.
///
/// ```rust,no_run
/// use libvm::{MachineNetworkConfig, NetworkDriver, Runtime};
///
/// # async fn example(runtime: Runtime) -> Result<(), libvm::LibVmError> {
/// runtime
///     .network("devnet")
///     .nat()
///     .driver(NetworkDriver::Netd)
///     .create()
///     .await?;
///
/// let _machine_network = MachineNetworkConfig::named("devnet");
/// # Ok(())
/// # }
/// ```
pub struct NetworkBuilder {
    runtime: Runtime,
    definition: NetworkDefinition,
}

impl NetworkBuilder {
    pub(crate) fn new(runtime: Runtime, name: impl Into<String>) -> Self {
        Self {
            runtime,
            definition: NetworkDefinition::nat(name),
        }
    }

    /// Sets NAT topology.
    pub fn nat(mut self) -> Self {
        self.definition.topology = NetworkTopology::Nat;
        self
    }

    /// Sets bridge topology.
    pub fn bridge(mut self) -> Self {
        self.definition.topology = NetworkTopology::Bridge;
        self
    }

    /// Sets isolated topology.
    pub fn isolated(mut self) -> Self {
        self.definition.topology = NetworkTopology::Isolated;
        self
    }

    /// Sets the network topology directly.
    pub fn topology(mut self, topology: NetworkTopology) -> Self {
        self.definition.topology = topology;
        self
    }

    /// Sets the network driver.
    pub fn driver(mut self, driver: NetworkDriver) -> Self {
        self.definition.driver = driver;
        self
    }

    /// Creates the named network definition.
    pub async fn create(self) -> Result<(), LibVmError> {
        self.runtime
            .create_network_definition(self.definition)
            .await
    }
}
