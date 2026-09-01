// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

//! In-process vhost-user virtio-vsock backend for Silo.

use std::collections::VecDeque;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use thiserror::Error;
use vhost::vhost_user::{Error as VhostUserError, Listener};
use vhost_user_backend::{Error as DaemonError, ShutdownHandle, VhostUserDaemon};
use vm_memory::{GuestMemoryAtomic, GuestMemoryMmap};
use vmm_sys_util::eventfd::{EventFd, EFD_NONBLOCK};

/// Metadata for a guest-initiated connection proposed to the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionRequest {
    pub source_port: u32,
    pub destination_port: u32,
}

pub(crate) type GuestConnectionAcceptor =
    Arc<dyn Fn(ConnectionRequest) -> Option<UnixStream> + Send + Sync + 'static>;

const QUEUE_SIZE: usize = 128;
const TX_BUFFER_SIZE: u32 = 64 * 1024;
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(1);

pub(crate) struct HostConnectionRequest {
    pub stream: UnixStream,
    pub destination_port: u32,
}

pub(crate) struct HostConnectionQueue {
    pub requests: Mutex<VecDeque<HostConnectionRequest>>,
    pub event: EventFd,
}

/// Handle for initiating host-to-guest connections through the embedded device.
#[derive(Clone)]
pub struct HostConnector {
    queue: Arc<HostConnectionQueue>,
    active: Arc<AtomicBool>,
}

impl HostConnector {
    pub fn connect(&self, destination_port: u32) -> io::Result<UnixStream> {
        let (client, backend) = UnixStream::pair()?;
        client.set_nonblocking(true)?;
        let mut requests = self
            .queue
            .requests
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if !self.active.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "vhost-user vsock backend is stopped",
            ));
        }
        if requests.len() >= vhu_vsock::MAX_CONNECTIONS {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "vhost-user vsock connection table is full",
            ));
        }
        requests.push_back(HostConnectionRequest {
            stream: backend,
            destination_port,
        });
        self.queue.event.write(1)?;
        Ok(client)
    }
}

/// Errors produced while starting or stopping an embedded vsock backend.
#[derive(Debug, Error)]
pub enum BackendError {
    #[error("vhost-user socket operation failed: {0}")]
    Socket(#[from] io::Error),
    #[error("failed to initialize vhost-user vsock backend: {0}")]
    Backend(String),
    #[error("vhost-user daemon failed: {0}")]
    Daemon(String),
    #[error("vhost-user backend thread panicked")]
    ThreadPanicked,
    #[error("timed out waiting for the vhost-user frontend to become interruptible")]
    ShutdownTimeout,
}

/// An embedded vhost-user vsock server and its host connection endpoint.
pub struct BackendServer {
    vhost_socket: PathBuf,
    host_connector: HostConnector,
    shutdown_event: Arc<EventFd>,
    shutdown_rx: mpsc::Receiver<ShutdownHandle>,
    thread: Option<JoinHandle<Result<(), BackendError>>>,
}

impl BackendServer {
    /// Bind the vhost socket and start serving one libkrun frontend connection.
    pub fn start<F>(
        vhost_socket: impl Into<PathBuf>,
        guest_cid: u64,
        guest_acceptor: F,
    ) -> Result<Self, BackendError>
    where
        F: Fn(ConnectionRequest) -> Option<UnixStream> + Send + Sync + 'static,
    {
        let vhost_socket = vhost_socket.into();
        remove_socket(&vhost_socket)?;

        let host_queue = Arc::new(HostConnectionQueue {
            requests: Mutex::new(VecDeque::new()),
            event: EventFd::new(EFD_NONBLOCK)?,
        });
        let active = Arc::new(AtomicBool::new(true));
        let host_connector = HostConnector {
            queue: host_queue.clone(),
            active,
        };
        let shutdown_event = Arc::new(EventFd::new(EFD_NONBLOCK)?);

        let config = vhu_vsock::VsockConfig::new_with_acceptor(
            guest_cid,
            TX_BUFFER_SIZE,
            QUEUE_SIZE,
            host_queue,
            Arc::new(guest_acceptor),
        );
        let backend = Arc::new(
            vhu_vsock::VhostUserVsockBackend::new(config)
                .map_err(|error| BackendError::Backend(error.to_string()))?,
        );
        let memory = GuestMemoryAtomic::new(GuestMemoryMmap::<()>::new());
        let mut daemon =
            VhostUserDaemon::new("silo-vhost-vsock".to_string(), backend.clone(), memory)
                .map_err(|error| BackendError::Daemon(error.to_string()))?;
        let epoll_handler = daemon
            .get_epoll_handlers()
            .into_iter()
            .next()
            .ok_or_else(|| BackendError::Backend("daemon created no epoll handler".to_string()))?;
        let backend_thread = backend
            .threads
            .first()
            .ok_or_else(|| BackendError::Backend("backend created no worker thread".to_string()))?;
        backend_thread
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .register_listeners(epoll_handler)
            .map_err(|error| BackendError::Backend(error.to_string()))?;

        // Bind before returning so libkrun can connect immediately after start().
        let mut listener = Listener::new(&vhost_socket, true)
            .map_err(|error| BackendError::Daemon(error.to_string()))?;
        let (shutdown_tx, shutdown_rx) = mpsc::channel();
        let shutdown_for_thread = shutdown_event.clone();
        let thread = thread::Builder::new()
            .name("silo-vhost-vsock".to_string())
            .spawn(move || {
                if !wait_for_frontend(&listener, &shutdown_for_thread)? {
                    return Ok(());
                }
                daemon
                    .start(&mut listener)
                    .map_err(|error| BackendError::Daemon(error.to_string()))?;
                if let Some(handle) = daemon.shutdown_handle() {
                    let _ = shutdown_tx.send(handle);
                }
                match daemon.wait() {
                    Ok(())
                    | Err(DaemonError::HandleRequest(VhostUserError::Disconnected))
                    | Err(DaemonError::HandleRequest(VhostUserError::PartialMessage)) => Ok(()),
                    Err(error) => Err(BackendError::Daemon(error.to_string())),
                }
            })?;

        Ok(Self {
            vhost_socket,
            host_connector,
            shutdown_event,
            shutdown_rx,
            thread: Some(thread),
        })
    }

    pub fn vhost_socket(&self) -> &Path {
        &self.vhost_socket
    }

    pub fn host_connector(&self) -> HostConnector {
        self.host_connector.clone()
    }

    /// Stop the daemon and remove its private sockets. Safe to call repeatedly.
    pub fn shutdown(&mut self) -> Result<(), BackendError> {
        self.host_connector.active.store(false, Ordering::Release);
        self.host_connector
            .queue
            .requests
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
        let _ = self.shutdown_event.write(1);
        let Some(thread) = self.thread.take() else {
            return Ok(());
        };

        let shutdown = match self.shutdown_rx.try_recv() {
            Ok(handle) => Some(handle),
            Err(mpsc::TryRecvError::Empty) => {
                match self.shutdown_rx.recv_timeout(SHUTDOWN_TIMEOUT) {
                    Ok(handle) => Some(handle),
                    Err(mpsc::RecvTimeoutError::Disconnected) => None,
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        self.thread = Some(thread);
                        return Err(BackendError::ShutdownTimeout);
                    }
                }
            }
            Err(mpsc::TryRecvError::Disconnected) => None,
        };
        if let Some(shutdown) = shutdown {
            shutdown.shutdown();
        }

        let result = thread.join().map_err(|_| BackendError::ThreadPanicked);
        let cleanup = remove_socket(&self.vhost_socket);
        result?.and(cleanup.map_err(BackendError::Socket))
    }
}

fn wait_for_frontend(listener: &Listener, shutdown: &EventFd) -> Result<bool, BackendError> {
    const FRONTEND_EVENT: u64 = 1;
    const SHUTDOWN_EVENT: u64 = 2;

    let epoll_fd = epoll::create(true)?;
    // SAFETY: epoll::create returned a new owned descriptor.
    let epoll_file = unsafe { File::from_raw_fd(epoll_fd) };
    epoll::ctl(
        epoll_fd,
        epoll::ControlOptions::EPOLL_CTL_ADD,
        listener.as_raw_fd(),
        epoll::Event::new(epoll::Events::EPOLLIN, FRONTEND_EVENT),
    )?;
    epoll::ctl(
        epoll_fd,
        epoll::ControlOptions::EPOLL_CTL_ADD,
        shutdown.as_raw_fd(),
        epoll::Event::new(epoll::Events::EPOLLIN, SHUTDOWN_EVENT),
    )?;

    let mut events = [epoll::Event::new(epoll::Events::empty(), 0); 2];
    loop {
        match epoll::wait(epoll_file.as_raw_fd(), -1, &mut events) {
            Ok(count) => {
                if events[..count]
                    .iter()
                    .any(|event| event.data == SHUTDOWN_EVENT)
                {
                    let _ = shutdown.read();
                    return Ok(false);
                }
                if events[..count]
                    .iter()
                    .any(|event| event.data == FRONTEND_EVENT)
                {
                    return Ok(true);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(BackendError::Socket(error)),
        }
    }
}

impl std::fmt::Debug for BackendServer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BackendServer")
            .field("vhost_socket", &self.vhost_socket)
            .finish_non_exhaustive()
    }
}

impl Drop for BackendServer {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

fn remove_socket(path: &Path) -> io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use crate::BackendServer;

    #[test]
    fn server_binds_and_cleans_up_without_a_frontend() {
        let directory = tempdir().expect("create temporary directory");
        let vhost_socket = directory.path().join("vhost.sock");
        let mut server =
            BackendServer::start(&vhost_socket, 3, |_| None).expect("start backend server");

        assert_eq!(server.vhost_socket(), vhost_socket);
        assert!(vhost_socket.exists());
        let connector = server.host_connector();

        server.shutdown().expect("stop backend server");
        assert!(!vhost_socket.exists());
        assert_eq!(
            connector
                .connect(7000)
                .expect_err("stopped connector must reject")
                .kind(),
            std::io::ErrorKind::NotConnected
        );
    }
}

mod rxops;
mod rxqueue;
mod thread_backend;
mod txbuf;
mod vhu_vsock;
mod vhu_vsock_thread;
mod vsock_conn;
