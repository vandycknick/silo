//! The contract between the `silo` controller and the `silod` daemon.
//!
//! ```text
//!  silo ── --system-* argv (arguments) ──────────────► silod
//!  silo ◄─ status.json, daemon.log (paths, status) ─── silod
//!  both ── io.silo.system.* machine labels (labels) ── libvm
//! ```
//!
//! Only data and its encoding live here. Neither side's behavior does: silod owns
//! resolution, provisioning, and upgrades; silo owns service registration.
pub mod arguments;
pub mod labels;
pub mod paths;
pub mod process;
pub mod status;

/// Typed local management API. Guest execution remains a native session API.
pub mod daemon {
    pub mod v1 {
        tonic::include_proto!("silo.daemon.v1");
    }
}

impl std::fmt::Debug for daemon::v1::HelperBootstrap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HelperBootstrap")
            .field("protocol_major", &self.protocol_major)
            .field("product_version", &self.product_version)
            .field("daemon_generation", &self.daemon_generation)
            .field("helper_generation", &self.helper_generation)
            .field("credentials", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for daemon::v1::EgressSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EgressSecret")
            .field("slot", &self.slot)
            .field("value", &"<redacted>")
            .finish()
    }
}

impl std::fmt::Debug for daemon::v1::SetMachineSecretRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SetMachineSecretRequest")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("value", &"<redacted>")
            .finish()
    }
}
