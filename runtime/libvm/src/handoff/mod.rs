//! Stopped storage handoff between two Silo runtimes (ADR 0014 "Local-To-Cloud
//! Handoff"): fork to a new destination identity, or relocation of the same
//! machine with operation, runtime, capture and ownership-epoch binding.
//!
//! This is a stopped restart, never execution transfer. The source cut is the
//! reserved machine's own stopped private files: the ownership ledger records
//! `Reserved(op)` under the lifecycle lock, after which no start, update,
//! removal or offline write is admitted until a terminal decision, so those
//! files are the immutable cut (no clone or copy is made). Only bytes the
//! destination cannot verify locally travel, as exact objects, canonical
//! stream maps and decoded 8 MiB chunks.
pub mod destination;
pub mod plan;
pub mod service;
pub mod types;

mod chunks;
mod files;
mod source;

#[cfg(test)]
mod control_tests;

#[cfg(test)]
mod tests;
