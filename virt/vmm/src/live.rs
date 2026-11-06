//! ADR 0021 live commands on `vm.sock`: Pause, Resume, GetOperation,
//! CancelOperation, Capture and ReleaseCapture.
#[path = "live/coordinator.rs"]
pub(crate) mod coordinator;
#[path = "live/gate.rs"]
pub(crate) mod gate;
#[path = "live/journal.rs"]
pub(crate) mod journal;
#[path = "live/staging.rs"]
mod staging;
#[cfg(all(test, feature = "mock-backend"))]
#[path = "live/tests.rs"]
mod tests;
