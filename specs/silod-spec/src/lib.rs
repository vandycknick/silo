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
