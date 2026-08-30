// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use std::{
    io::Result as IoResult,
    sync::{Arc, Mutex, PoisonError},
};

use log::warn;
use thiserror::Error as ThisError;
use vhost::vhost_user::message::{VhostUserProtocolFeatures, VhostUserVirtioFeatures};
use vhost_user_backend::{VhostUserBackend, VringRwLock};
use virtio_bindings::bindings::{
    virtio_config::{VIRTIO_F_NOTIFY_ON_EMPTY, VIRTIO_F_VERSION_1},
    virtio_ring::VIRTIO_RING_F_EVENT_IDX,
};
use vm_memory::{ByteValued, GuestMemoryAtomic, GuestMemoryMmap, Le64};
use vmm_sys_util::{
    epoll::EventSet,
    event::{new_event_consumer_and_notifier, EventConsumer, EventFlag, EventNotifier},
};

use crate::{vhu_vsock_thread::*, GuestConnectionAcceptor, HostConnectionQueue};

const NUM_QUEUES: usize = 3;

// New descriptors pending on the rx queue
const RX_QUEUE_EVENT: u16 = 0;
// New descriptors are pending on the tx queue.
const TX_QUEUE_EVENT: u16 = 1;
// New descriptors are pending on the event queue.
const EVT_QUEUE_EVENT: u16 = 2;

/// Notification coming from the backend.
/// Event range [0...num_queues] is reserved for queues and exit event.
/// So NUM_QUEUES + 1 is used.
pub(crate) const BACKEND_EVENT: u16 = (NUM_QUEUES + 1) as u16;

/// CID of the host
pub(crate) const VSOCK_HOST_CID: u64 = 2;

/// Connection oriented packet
pub(crate) const VSOCK_TYPE_STREAM: u16 = 1;

/// Vsock packet operation ID - Connection request
pub(crate) const VSOCK_OP_REQUEST: u16 = 1;
/// Vsock packet operation ID - Connection response
pub(crate) const VSOCK_OP_RESPONSE: u16 = 2;
/// Vsock packet operation ID - Connection reset
pub(crate) const VSOCK_OP_RST: u16 = 3;
/// Vsock packet operation ID - Shutdown connection
pub(crate) const VSOCK_OP_SHUTDOWN: u16 = 4;
/// Vsock packet operation ID - Data read/write
pub(crate) const VSOCK_OP_RW: u16 = 5;
/// Vsock packet operation ID - Flow control credit update
pub(crate) const VSOCK_OP_CREDIT_UPDATE: u16 = 6;
/// Vsock packet operation ID - Flow control credit request
pub(crate) const VSOCK_OP_CREDIT_REQUEST: u16 = 7;

/// Vsock packet flags - `VSOCK_OP_SHUTDOWN`: Packet sender will receive no more
/// data
pub(crate) const VSOCK_FLAGS_SHUTDOWN_RCV: u32 = 1;
/// Vsock packet flags - `VSOCK_OP_SHUTDOWN`: Packet sender will send no more
/// data
pub(crate) const VSOCK_FLAGS_SHUTDOWN_SEND: u32 = 2;

// Queue mask to select vrings.
const QUEUE_MASK: u64 = 0b11;
pub(crate) const MAX_CONNECTIONS: usize = 1023;
pub(crate) const MIN_HOST_PORT: u32 = 1 << 30;
pub(crate) const MAX_HOST_PORT: u32 = 1 << 31;

pub(crate) type Result<T> = std::result::Result<T, Error>;

/// Custom error types
#[derive(Debug, ThisError)]
pub(crate) enum Error {
    #[error("Failed to handle event other than EPOLLIN event")]
    HandleEventNotEpollIn,
    #[error("Failed to handle unknown event")]
    HandleUnknownEvent,
    #[error("Failed to create an epoll fd")]
    EpollFdCreate(std::io::Error),
    #[error("Failed to add to epoll")]
    EpollAdd(std::io::Error),
    #[error("Failed to modify evset associated with epoll")]
    EpollModify(std::io::Error),
    #[error("Failed to de-register fd from epoll")]
    EpollRemove(std::io::Error),
    #[error("No memory configured")]
    NoMemoryConfigured,
    #[error("Unable to iterate queue")]
    IterateQueue,
    #[error("No rx request available")]
    NoRequestRx,
    #[error("Packet missing data buffer")]
    PktBufMissing,
    #[error("Failed to connect to unix socket")]
    UnixConnect(std::io::Error),
    #[error("Unable to write to stream")]
    StreamWrite,
    #[error("Unable to push data to local tx buffer")]
    LocalTxBufFull,
    #[error("Unable to flush data from local tx buffer")]
    LocalTxBufFlush(std::io::Error),
    #[error("No free local port available for new host inititated connection")]
    NoFreeLocalPort,
    #[error("Backend rx queue is empty")]
    EmptyBackendRxQ,
    #[error("Failed to create an EventFd")]
    EventFdCreate(std::io::Error),
    #[error("Vring operation failed: {0}")]
    Vring(String),
    #[error("Vring completion worker stopped")]
    EventChannelClosed,
}

impl std::convert::From<Error> for std::io::Error {
    fn from(e: Error) -> Self {
        std::io::Error::other(e)
    }
}

#[derive(Clone)]
/// This structure is the public API through which an external program
/// is allowed to configure the backend.
pub(crate) struct VsockConfig {
    guest_cid: u64,
    tx_buffer_size: u32,
    queue_size: usize,
    host_connections: Arc<HostConnectionQueue>,
    guest_acceptor: GuestConnectionAcceptor,
}

impl std::fmt::Debug for VsockConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VsockConfig")
            .field("guest_cid", &self.guest_cid)
            .field("tx_buffer_size", &self.tx_buffer_size)
            .field("queue_size", &self.queue_size)
            .finish()
    }
}

impl VsockConfig {
    /// Create a new instance of the VsockConfig struct, containing the
    /// parameters to be fed into the vsock-backend server.
    #[cfg(test)]
    pub fn new(
        guest_cid: u64,
        tx_buffer_size: u32,
        queue_size: usize,
        host_connections: Arc<HostConnectionQueue>,
    ) -> Self {
        Self::new_with_acceptor(
            guest_cid,
            tx_buffer_size,
            queue_size,
            host_connections,
            std::sync::Arc::new(|_| None),
        )
    }

    pub fn new_with_acceptor(
        guest_cid: u64,
        tx_buffer_size: u32,
        queue_size: usize,
        host_connections: Arc<HostConnectionQueue>,
        guest_acceptor: GuestConnectionAcceptor,
    ) -> Self {
        Self {
            guest_cid,
            tx_buffer_size,
            queue_size,
            host_connections,
            guest_acceptor,
        }
    }

    /// Return the guest's current CID.
    pub fn get_guest_cid(&self) -> u64 {
        self.guest_cid
    }

    /// Return the path of the unix domain socket which is listening to
    /// requests from the guest.
    pub fn get_tx_buffer_size(&self) -> u32 {
        self.tx_buffer_size
    }

    pub fn get_queue_size(&self) -> usize {
        self.queue_size
    }

    pub fn get_guest_acceptor(&self) -> GuestConnectionAcceptor {
        self.guest_acceptor.clone()
    }
}

/// A local port and peer port pair used to retrieve
/// the corresponding connection.
#[derive(Hash, PartialEq, Eq, Debug, Clone)]
pub(crate) struct ConnMapKey {
    pub(crate) local_port: u32,
    pub(crate) peer_port: u32,
}

impl ConnMapKey {
    pub fn new(local_port: u32, peer_port: u32) -> Self {
        Self {
            local_port,
            peer_port,
        }
    }
}

/// Virtio Vsock Configuration
#[derive(Copy, Clone, Debug, Default, PartialEq)]
#[repr(C)]
struct VirtioVsockConfig {
    pub guest_cid: Le64,
}

// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for VirtioVsockConfig {}

pub(crate) struct VhostUserVsockBackend {
    config: VirtioVsockConfig,
    queue_size: usize,
    pub threads: Vec<Mutex<VhostUserVsockThread>>,
    queues_per_thread: Vec<u64>,
    exit_consumer: EventConsumer,
    exit_notifier: EventNotifier,
}

impl VhostUserVsockBackend {
    pub fn new(config: VsockConfig) -> Result<Self> {
        let thread = Mutex::new(VhostUserVsockThread::new_with_acceptor(
            config.get_guest_cid(),
            config.get_tx_buffer_size(),
            config.host_connections.clone(),
            config.get_guest_acceptor(),
        )?);
        let queues_per_thread = vec![QUEUE_MASK];

        let (exit_consumer, exit_notifier) =
            new_event_consumer_and_notifier(EventFlag::NONBLOCK).map_err(Error::EventFdCreate)?;

        Ok(Self {
            config: VirtioVsockConfig {
                guest_cid: From::from(config.get_guest_cid()),
            },
            queue_size: config.get_queue_size(),
            threads: vec![thread],
            queues_per_thread,
            exit_consumer,
            exit_notifier,
        })
    }
}

impl VhostUserBackend for VhostUserVsockBackend {
    type Vring = VringRwLock;
    type Bitmap = ();

    fn num_queues(&self) -> usize {
        NUM_QUEUES
    }

    fn max_queue_size(&self) -> usize {
        self.queue_size
    }

    fn features(&self) -> u64 {
        (1 << VIRTIO_F_VERSION_1)
            | (1 << VIRTIO_F_NOTIFY_ON_EMPTY)
            | (1 << VIRTIO_RING_F_EVENT_IDX)
            | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits()
    }

    fn protocol_features(&self) -> VhostUserProtocolFeatures {
        VhostUserProtocolFeatures::MQ | VhostUserProtocolFeatures::CONFIG
    }

    fn set_event_idx(&self, enabled: bool) {
        for thread in self.threads.iter() {
            thread
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .event_idx = enabled;
        }
    }

    fn update_memory(&self, atomic_mem: GuestMemoryAtomic<GuestMemoryMmap>) -> IoResult<()> {
        for thread in self.threads.iter() {
            let mut thread = thread.lock().unwrap_or_else(PoisonError::into_inner);
            thread.mem = Some(atomic_mem.clone());
            let _ = thread.host_connections.event.write(1);
        }
        Ok(())
    }

    fn handle_event(
        &self,
        device_event: u16,
        evset: EventSet,
        vrings: &[VringRwLock],
        thread_id: usize,
    ) -> IoResult<()> {
        let vring_rx = &vrings[0];
        let vring_tx = &vrings[1];

        if evset != EventSet::IN {
            return Err(Error::HandleEventNotEpollIn.into());
        }

        let Some(thread) = self.threads.get(thread_id) else {
            return Err(Error::HandleUnknownEvent.into());
        };
        let mut thread = thread.lock().unwrap_or_else(PoisonError::into_inner);
        let evt_idx = thread.event_idx;

        match device_event {
            RX_QUEUE_EVENT => {}
            TX_QUEUE_EVENT => {
                thread.process_tx(vring_tx, evt_idx)?;
            }
            EVT_QUEUE_EVENT => {
                warn!("Received an unexpected EVT_QUEUE_EVENT");
            }
            BACKEND_EVENT => {
                thread.process_backend_evt(evset);
                if let Err(e) = thread.process_tx(vring_tx, evt_idx) {
                    match e {
                        Error::NoMemoryConfigured => {
                            warn!("Received a backend event before vring initialization")
                        }
                        _ => return Err(e.into()),
                    }
                }
            }
            _ => {
                return Err(Error::HandleUnknownEvent.into());
            }
        }

        if device_event != EVT_QUEUE_EVENT {
            thread.process_rx(vring_rx, evt_idx)?;
        }

        Ok(())
    }

    fn get_config(&self, offset: u32, size: u32) -> Vec<u8> {
        let offset = offset as usize;
        let size = size as usize;

        let buf = self.config.as_slice();

        if offset + size > buf.len() {
            return Vec::new();
        }

        buf[offset..offset + size].to_vec()
    }

    fn queues_per_thread(&self) -> Vec<u64> {
        self.queues_per_thread.clone()
    }

    fn exit_event(&self, _thread_index: usize) -> Option<(EventConsumer, EventNotifier)> {
        let consumer = self.exit_consumer.try_clone().ok()?;
        let notifier = self.exit_notifier.try_clone().ok()?;
        Some((consumer, notifier))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::convert::TryInto;
    use std::sync::Arc;

    use vhost_user_backend::VringT;
    use vm_memory::GuestAddress;
    use vmm_sys_util::eventfd::{EventFd, EFD_NONBLOCK};

    use super::*;

    const CONN_TX_BUF_SIZE: u32 = 64 * 1024;
    const QUEUE_SIZE: usize = 1024;

    fn host_connections() -> Arc<HostConnectionQueue> {
        Arc::new(HostConnectionQueue {
            requests: Mutex::new(VecDeque::new()),
            event: EventFd::new(EFD_NONBLOCK).expect("create host event"),
        })
    }

    fn test_vsock_backend(config: VsockConfig, expected_cid: u64) {
        let backend = VhostUserVsockBackend::new(config);

        assert!(backend.is_ok());
        let backend = backend.unwrap();

        assert_eq!(backend.num_queues(), NUM_QUEUES);
        assert_eq!(backend.max_queue_size(), QUEUE_SIZE);
        assert_ne!(backend.features(), 0);
        assert!(!backend.protocol_features().is_empty());
        backend.set_event_idx(false);

        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap(),
        );
        let vrings = [
            VringRwLock::new(mem.clone(), 0x1000).unwrap(),
            VringRwLock::new(mem.clone(), 0x2000).unwrap(),
        ];
        vrings[0].set_queue_info(0x100, 0x200, 0x300).unwrap();
        vrings[0].set_queue_ready(true);
        vrings[1].set_queue_info(0x1100, 0x1200, 0x1300).unwrap();
        vrings[1].set_queue_ready(true);

        backend.update_memory(mem).unwrap();

        let queues_per_thread = backend.queues_per_thread();
        assert_eq!(queues_per_thread.len(), 1);
        assert_eq!(queues_per_thread[0], 0b11);

        let config = backend.get_config(0, 8);
        assert_eq!(config.len(), 8);
        let cid = u64::from_le_bytes(config.try_into().unwrap());
        assert_eq!(cid, expected_cid);

        let exit = backend.exit_event(0);
        assert!(exit.is_some());
        let (_, notifier) = exit.unwrap();
        notifier.notify().unwrap();

        let ret = backend.handle_event(RX_QUEUE_EVENT, EventSet::IN, &vrings, 0);
        ret.unwrap();

        let ret = backend.handle_event(TX_QUEUE_EVENT, EventSet::IN, &vrings, 0);
        ret.unwrap();

        let ret = backend.handle_event(EVT_QUEUE_EVENT, EventSet::IN, &vrings, 0);
        ret.unwrap();

        let ret = backend.handle_event(BACKEND_EVENT, EventSet::IN, &vrings, 0);
        ret.unwrap();
    }

    #[test]
    fn test_vsock_backend_unix() {
        const CID: u64 = 3;

        let config = VsockConfig::new(CID, CONN_TX_BUF_SIZE, QUEUE_SIZE, host_connections());

        test_vsock_backend(config, CID);
    }

    #[test]
    fn test_vsock_backend_failures() {
        const CID: u64 = 3;

        let config = VsockConfig::new(CID, CONN_TX_BUF_SIZE, QUEUE_SIZE, host_connections());

        let backend = VhostUserVsockBackend::new(config).unwrap();
        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap(),
        );
        let vrings = [
            VringRwLock::new(mem.clone(), 0x1000).unwrap(),
            VringRwLock::new(mem.clone(), 0x2000).unwrap(),
        ];

        backend.update_memory(mem).unwrap();

        // reading out of the config space, expecting empty config
        let config = backend.get_config(2, 8);
        assert_eq!(config.len(), 0);

        assert_eq!(
            backend
                .handle_event(RX_QUEUE_EVENT, EventSet::OUT, &vrings, 0)
                .unwrap_err()
                .to_string(),
            Error::HandleEventNotEpollIn.to_string()
        );
        assert_eq!(
            backend
                .handle_event(BACKEND_EVENT + 1, EventSet::IN, &vrings, 0)
                .unwrap_err()
                .to_string(),
            Error::HandleUnknownEvent.to_string()
        );
    }

    #[test]
    fn test_vhu_vsock_structs() {
        let unix_config = VsockConfig::new(0, 0, 0, host_connections());
        assert_eq!(
            format!("{unix_config:?}"),
            "VsockConfig { guest_cid: 0, tx_buffer_size: 0, queue_size: 0 }"
        );

        let conn_map = ConnMapKey::new(0, 0);
        assert_eq!(
            format!("{conn_map:?}"),
            "ConnMapKey { local_port: 0, peer_port: 0 }"
        );
        assert_eq!(conn_map, conn_map.clone());

        let virtio_config = VirtioVsockConfig::default();
        assert_eq!(
            format!("{virtio_config:?}"),
            "VirtioVsockConfig { guest_cid: Le64(0) }"
        );
        assert_eq!(virtio_config, virtio_config.clone());

        let error = Error::HandleEventNotEpollIn;
        assert_eq!(format!("{error:?}"), "HandleEventNotEpollIn");
    }
}
