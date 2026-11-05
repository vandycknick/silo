//! ADR 0021 live commands on `vm.sock`: Pause, Resume, GetOperation,
//! CancelOperation (pause), and typed not-delivered Capture/ReleaseCapture.
#[path = "live/coordinator.rs"]
pub(crate) mod coordinator;
#[path = "live/gate.rs"]
pub(crate) mod gate;
#[path = "live/journal.rs"]
mod journal;
#[cfg(all(test, feature = "mock-backend"))]
#[path = "live/tests.rs"]
mod tests;
