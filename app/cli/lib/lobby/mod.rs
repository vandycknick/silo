//! The lobby: SSH-reachable VM management for tailnet peers, served by silod.
//! tsgate (Go) owns the tailnet node; everything else lives here.
//!
//! Consent results and cancellation are checked against a unique creation attempt
//! and verified owner. SSH channels and queued/running jobs share the HTTP metrics
//! registry. Native-handle gauges count lobby-owned runtime/machine references and
//! active exec/shell/log attachments, released by RAII on failure or cancellation.
//! Node status arrives through pushed gate state, not a separate status RPC.
pub(crate) mod audit;
pub(crate) mod caller;
pub(crate) mod consent;
pub(crate) mod dispatch;
pub(crate) mod failure;
pub(crate) mod grammar;
pub(crate) mod http;
pub(crate) mod identity;
pub(crate) mod identity_source;
pub(crate) mod jobs;
pub(crate) mod metrics;
pub(crate) mod redact;
pub(crate) mod service;
pub(crate) mod session;
pub(crate) mod ssh;
pub(crate) mod state;
pub(crate) mod supervisor;
pub(crate) mod tailnet;
pub(crate) mod units;
pub(crate) mod views;
