//! Internal adapter for the `bento-vmmon` supervisor process.
//!
//! This module is deliberately thin: it launches vmmon, speaks the vmmon
//! control protocol, reads vmmon-owned files, and probes vmmon process
//! identity. It does not read or write the machine store, take machine locks, or
//! decide whether a lifecycle operation is valid. Those policies live in
//! `Machine` and `Runtime`.

use std::path::Path;

use std::os::fd::OwnedFd;
use tokio::net::UnixStream;

use crate::LibVmError;

mod client;
pub(crate) mod exit_status;
mod launch;
pub(crate) mod process;

pub use client::DEFAULT_GUEST_READINESS_TIMEOUT;
pub(crate) use launch::{VmmonHandshake, VmmonLaunch};

/// Thin crate-private handle for operations owned by the vmmon adapter.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Vmmon;

impl Vmmon {
    /// Creates a stateless vmmon adapter.
    pub(crate) fn new() -> Self {
        Self
    }

    pub(crate) async fn spawn(
        &self,
        launch: &VmmonLaunch<'_>,
    ) -> Result<VmmonHandshake, LibVmError> {
        launch::spawn(launch).await
    }

    pub(crate) async fn wait_for_start(
        &self,
        syncpipe: OwnedFd,
        trace_path: &Path,
    ) -> Result<(), LibVmError> {
        launch::wait_for_start(syncpipe, trace_path).await
    }

    pub(crate) fn release_startpipe(&self, startpipe: OwnedFd) -> std::io::Result<()> {
        launch::release_startpipe(startpipe)
    }

    pub(crate) async fn wait_for_guest_running(
        &self,
        socket_path: &Path,
        timeout: std::time::Duration,
    ) -> Result<(), String> {
        client::wait_for_guest_running(socket_path, timeout).await
    }

    pub(crate) async fn inspect(
        &self,
        socket_path: &Path,
    ) -> Result<bento_protocol::v1::InspectResponse, String> {
        client::inspect(socket_path).await
    }

    pub(crate) async fn wait_for_shell_with_timeout(
        &self,
        socket_path: &Path,
        timeout: std::time::Duration,
        poll_interval: std::time::Duration,
    ) -> Result<(), String> {
        client::wait_for_shell_with_timeout(socket_path, timeout, poll_interval).await
    }

    pub(crate) async fn open_serial_stream(
        &self,
        socket_path: &Path,
    ) -> Result<UnixStream, String> {
        client::open_serial_stream(socket_path).await
    }

    pub(crate) async fn open_shell_stream(&self, socket_path: &Path) -> Result<UnixStream, String> {
        client::open_shell_stream(socket_path).await
    }
}
