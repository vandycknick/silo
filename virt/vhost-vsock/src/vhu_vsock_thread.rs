// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use std::{
    fs::File,
    io,
    num::Wrapping,
    ops::Deref,
    os::unix::prelude::{AsRawFd, FromRawFd, RawFd},
    sync::{
        mpsc::{self, SyncSender},
        Arc,
    },
    thread,
};

use log::{error, warn};
use vhost_user_backend::{VringEpollHandler, VringRwLock, VringT};
use virtio_queue::QueueOwnedT;
use virtio_vsock::packet::{VsockPacket, PKT_HEADER_SIZE};
use vm_memory::{GuestAddressSpace, GuestMemoryAtomic, GuestMemoryMmap};
use vmm_sys_util::epoll::EventSet;

use crate::{
    rxops::*,
    thread_backend::*,
    vhu_vsock::{
        ConnMapKey, Error, Result, VhostUserVsockBackend, BACKEND_EVENT, MAX_CONNECTIONS,
        MAX_HOST_PORT, MIN_HOST_PORT, VSOCK_HOST_CID,
    },
    vsock_conn::*,
    GuestConnectionAcceptor, HostConnectionQueue,
};

type ArcVhostBknd = Arc<VhostUserVsockBackend>;

// Data which is required by a worker handling event idx.
struct EventData {
    vring: VringRwLock,
    event_idx: bool,
    head_idx: u16,
    used_len: usize,
}

pub(crate) struct VhostUserVsockThread {
    /// Guest memory map.
    pub mem: Option<GuestMemoryAtomic<GuestMemoryMmap>>,
    /// VIRTIO_RING_F_EVENT_IDX.
    pub event_idx: bool,
    pub host_connections: Arc<HostConnectionQueue>,
    /// epoll fd to which new host connections are added.
    epoll_file: File,
    /// VsockThreadBackend instance.
    pub thread_backend: VsockThreadBackend,
    /// CID of the guest.
    guest_cid: u64,
    /// Channel to a worker which handles event idx.
    sender: SyncSender<EventData>,
    /// host side port on which application listens.
    local_port: Wrapping<u32>,
    /// The tx buffer size
    tx_buffer_size: u32,
}

impl VhostUserVsockThread {
    /// Create a new instance of VhostUserVsockThread.
    #[cfg(test)]
    pub fn new(guest_cid: u64, tx_buffer_size: u32) -> Result<Self> {
        let host_connections = Arc::new(HostConnectionQueue {
            requests: std::sync::Mutex::new(std::collections::VecDeque::new()),
            event: vmm_sys_util::eventfd::EventFd::new(vmm_sys_util::eventfd::EFD_NONBLOCK)
                .map_err(Error::EventFdCreate)?,
        });
        Self::new_with_acceptor(
            guest_cid,
            tx_buffer_size,
            host_connections,
            Arc::new(|_| None),
        )
    }

    pub fn new_with_acceptor(
        guest_cid: u64,
        tx_buffer_size: u32,
        host_connections: Arc<HostConnectionQueue>,
        guest_acceptor: GuestConnectionAcceptor,
    ) -> Result<Self> {
        let epoll_fd = epoll::create(true).map_err(Error::EpollFdCreate)?;
        // SAFETY: Safe as the fd is guaranteed to be valid here.
        let epoll_file = unsafe { File::from_raw_fd(epoll_fd) };

        let thread_backend = VsockThreadBackend::new_with_acceptor(
            epoll_fd,
            guest_cid,
            tx_buffer_size,
            guest_acceptor,
        );
        let (sender, receiver) = mpsc::sync_channel::<EventData>(MAX_CONNECTIONS);
        thread::spawn(move || loop {
            // TODO: Understand why doing the following in the background thread works.
            // maybe we'd better have thread pool for the entire application if necessary.
            let Ok(event_data) = receiver.recv() else {
                break;
            };
            Self::vring_handle_event(event_data);
        });

        let thread = VhostUserVsockThread {
            mem: None,
            event_idx: false,
            host_connections,
            epoll_file,
            thread_backend,
            guest_cid,
            sender,
            local_port: Wrapping(MIN_HOST_PORT),
            tx_buffer_size,
        };

        VhostUserVsockThread::epoll_register(
            epoll_fd,
            thread.host_connections.event.as_raw_fd(),
            epoll::Events::EPOLLIN,
        )?;

        Ok(thread)
    }

    fn vring_handle_event(event_data: EventData) {
        if event_data.event_idx {
            if event_data
                .vring
                .add_used(event_data.head_idx, event_data.used_len as u32)
                .is_err()
            {
                warn!("Could not return used descriptors to ring");
            }
            match event_data.vring.needs_notification() {
                Err(_) => {
                    warn!("Could not check if queue needs to be notified");
                    if event_data.vring.signal_used_queue().is_err() {
                        warn!("Could not signal used queue");
                    }
                }
                Ok(needs_notification) => {
                    if needs_notification && event_data.vring.signal_used_queue().is_err() {
                        warn!("Could not signal used queue");
                    }
                }
            }
        } else {
            if event_data
                .vring
                .add_used(event_data.head_idx, event_data.used_len as u32)
                .is_err()
            {
                warn!("Could not return used descriptors to ring");
            }
            if event_data.vring.signal_used_queue().is_err() {
                warn!("Could not signal used queue");
            }
        }
    }
    /// Register a file with an epoll to listen for events in evset.
    pub fn epoll_register(epoll_fd: RawFd, fd: RawFd, evset: epoll::Events) -> Result<()> {
        epoll::ctl(
            epoll_fd,
            epoll::ControlOptions::EPOLL_CTL_ADD,
            fd,
            epoll::Event::new(evset, fd as u64),
        )
        .map_err(Error::EpollAdd)?;

        Ok(())
    }

    /// Remove a file from the epoll.
    pub fn epoll_unregister(epoll_fd: RawFd, fd: RawFd) -> Result<()> {
        epoll::ctl(
            epoll_fd,
            epoll::ControlOptions::EPOLL_CTL_DEL,
            fd,
            epoll::Event::new(epoll::Events::empty(), 0),
        )
        .map_err(Error::EpollRemove)?;

        Ok(())
    }

    /// Modify the events we listen to for the fd in the epoll.
    pub fn epoll_modify(epoll_fd: RawFd, fd: RawFd, evset: epoll::Events) -> Result<()> {
        epoll::ctl(
            epoll_fd,
            epoll::ControlOptions::EPOLL_CTL_MOD,
            fd,
            epoll::Event::new(evset, fd as u64),
        )
        .map_err(Error::EpollModify)?;

        Ok(())
    }

    /// Return raw file descriptor of the epoll file.
    fn get_epoll_fd(&self) -> RawFd {
        self.epoll_file.as_raw_fd()
    }

    /// Register our listeners in the VringEpollHandler
    pub fn register_listeners(
        &mut self,
        epoll_handler: Arc<VringEpollHandler<ArcVhostBknd>>,
    ) -> Result<()> {
        epoll_handler
            .register_listener(self.get_epoll_fd(), EventSet::IN, u64::from(BACKEND_EVENT))
            .map_err(|error| Error::Vring(error.to_string()))?;
        Ok(())
    }

    /// Process a BACKEND_EVENT received by VhostUserVsockBackend.
    pub fn process_backend_evt(&mut self, _evset: EventSet) {
        let mut epoll_events = vec![epoll::Event::new(epoll::Events::empty(), 0); 32];
        'epoll: loop {
            match epoll::wait(self.epoll_file.as_raw_fd(), 0, epoll_events.as_mut_slice()) {
                Ok(ev_cnt) => {
                    for evt in epoll_events.iter().take(ev_cnt) {
                        self.handle_event(
                            evt.data as RawFd,
                            epoll::Events::from_bits_truncate(evt.events),
                        );
                    }
                }
                Err(e) => {
                    if e.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    warn!("failed to consume new epoll event");
                }
            }
            break 'epoll;
        }
    }

    /// Handle a BACKEND_EVENT by either accepting a new connection or
    /// forwarding a request to the appropriate connection object.
    fn handle_event(&mut self, fd: RawFd, evset: epoll::Events) {
        if fd == self.host_connections.event.as_raw_fd() {
            let _ = self.host_connections.event.read();
            self.process_host_connections();
            return;
        }

        let epoll_fd = self.get_epoll_fd();
        let Some(key) = self.thread_backend.listener_map.get(&fd).cloned() else {
            return;
        };
        let mut queue_rx = false;
        let mut reject_pending = false;
        {
            let Some(conn) = self.thread_backend.conn_map.get_mut(&key) else {
                return;
            };

            if evset.contains(epoll::Events::EPOLLOUT) {
                match conn.tx_buf.flush_to(&mut conn.stream) {
                    Ok(count) => {
                        if count > 0 {
                            conn.fwd_cnt += Wrapping(count as u32);
                            conn.rx_queue.enqueue(RxOps::CreditUpdate);
                        } else if Self::epoll_modify(epoll_fd, fd, epoll::Events::EPOLLIN).is_err()
                        {
                            error!("Failed to disable EPOLLOUT");
                        }
                        queue_rx = true;
                    }
                    Err(error) => {
                        log::debug!("Failed to flush host stream: {error:?}");
                        conn.rx_queue.enqueue(RxOps::Reset);
                        queue_rx = true;
                    }
                }
            }

            if evset.intersects(
                epoll::Events::EPOLLIN
                    | epoll::Events::EPOLLRDHUP
                    | epoll::Events::EPOLLHUP
                    | epoll::Events::EPOLLERR,
            ) {
                if let Err(error) = Self::epoll_unregister(epoll_fd, fd) {
                    warn!("Failed to stop monitoring host stream: {error}");
                }
                if conn.connect {
                    conn.rx_queue.enqueue(RxOps::Rw);
                    queue_rx = true;
                } else {
                    reject_pending = true;
                }
            }
        }
        if reject_pending {
            self.thread_backend.reject_connection(&key);
            return;
        }
        if queue_rx {
            self.thread_backend.enqueue_rx(key);
        }
    }

    fn process_host_connections(&mut self) {
        if self.mem.is_none() {
            return;
        }
        loop {
            let request = self
                .host_connections
                .requests
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .pop_front();
            let Some(request) = request else {
                break;
            };
            if !connection_capacity_available(self.thread_backend.conn_map.len()) {
                continue;
            }
            let local_port = match self.allocate_local_port() {
                Ok(port) => port,
                Err(error) => {
                    warn!("Failed to allocate host vsock port: {error}");
                    continue;
                }
            };
            if let Err(error) = request.stream.set_nonblocking(true) {
                self.thread_backend.local_port_set.remove(&local_port);
                warn!("Failed to configure host vsock stream: {error}");
                continue;
            }
            let fd = request.stream.as_raw_fd();
            if let Err(error) = Self::epoll_register(
                self.get_epoll_fd(),
                fd,
                epoll::Events::EPOLLIN | epoll::Events::EPOLLOUT,
            ) {
                self.thread_backend.local_port_set.remove(&local_port);
                warn!("Failed to monitor host vsock stream: {error}");
                continue;
            }
            self.add_new_connection_from_host(
                fd,
                StreamType::Unix(request.stream),
                local_port,
                request.destination_port,
            );
        }
    }

    fn add_new_connection_from_host(
        &mut self,
        fd: RawFd,
        stream: StreamType,
        local_port: u32,
        peer_port: u32,
    ) {
        if !connection_capacity_available(self.thread_backend.conn_map.len()) {
            return;
        }
        // Insert the fd into the backend's maps
        self.thread_backend
            .listener_map
            .insert(fd, ConnMapKey::new(local_port, peer_port));

        // Create a new connection object an enqueue a connection request
        // packet to be sent to the guest
        let conn_map_key = ConnMapKey::new(local_port, peer_port);
        let mut new_conn = VsockConnection::new_local_init(
            stream,
            VSOCK_HOST_CID,
            local_port,
            self.guest_cid,
            peer_port,
            self.get_epoll_fd(),
            self.tx_buffer_size,
        );
        new_conn.rx_queue.enqueue(RxOps::Request);
        new_conn.set_peer_port(peer_port);

        // Add connection object into the backend's maps
        self.thread_backend.conn_map.insert(conn_map_key, new_conn);

        self.thread_backend
            .enqueue_rx(ConnMapKey::new(local_port, peer_port));
    }

    /// Allocate a new local port number.
    fn allocate_local_port(&mut self) -> Result<u32> {
        self.allocate_local_port_in_range(MIN_HOST_PORT, MAX_HOST_PORT)
    }

    fn allocate_local_port_in_range(&mut self, min_port: u32, max_port: u32) -> Result<u32> {
        let mut alloc_local_port = self.local_port.0;
        loop {
            if !self
                .thread_backend
                .local_port_set
                .contains(&alloc_local_port)
            {
                // The port set doesn't contain the newly allocated port number.
                self.local_port = Wrapping(if alloc_local_port + 1 == max_port {
                    min_port
                } else {
                    alloc_local_port + 1
                });
                self.thread_backend.local_port_set.insert(alloc_local_port);
                return Ok(alloc_local_port);
            } else {
                alloc_local_port = if alloc_local_port + 1 == max_port {
                    min_port
                } else {
                    alloc_local_port + 1
                };
                if alloc_local_port == self.local_port.0 {
                    // We have exhausted our search and wrapped back to the starting port
                    return Err(Error::NoFreeLocalPort);
                }
            }
        }
    }

    /// Iterate over the rx queue and process rx requests.
    fn process_rx_queue(&mut self, vring: &VringRwLock) -> Result<()> {
        let atomic_mem = match &self.mem {
            Some(m) => m,
            None => return Err(Error::NoMemoryConfigured),
        };

        let mut vring_mut = vring.get_mut();

        let queue = vring_mut.get_queue_mut();

        while let Some(mut avail_desc) = queue
            .iter(atomic_mem.memory())
            .map_err(|_| Error::IterateQueue)?
            .next()
        {
            let mem = atomic_mem.clone().memory();

            let head_idx = avail_desc.head_index();
            let used_len = match VsockPacket::from_rx_virtq_chain(
                mem.deref(),
                &mut avail_desc,
                self.tx_buffer_size,
            ) {
                Ok(mut pkt) => {
                    let recv_result = self.thread_backend.recv_pkt(&mut pkt);

                    if recv_result.is_ok() {
                        PKT_HEADER_SIZE + pkt.len() as usize
                    } else {
                        queue
                            .iter(mem)
                            .map_err(|_| Error::IterateQueue)?
                            .go_to_previous_position();
                        break;
                    }
                }
                Err(e) => {
                    warn!("vsock: RX queue error: {e:?}");
                    0
                }
            };

            let vring = vring.clone();
            let event_idx = self.event_idx;
            self.sender
                .send(EventData {
                    vring,
                    event_idx,
                    head_idx,
                    used_len,
                })
                .map_err(|_| Error::EventChannelClosed)?;

            if !self.thread_backend.pending_rx() {
                break;
            }
        }
        Ok(())
    }

    /// Wrapper to process rx queue based on whether event idx is enabled or
    /// not.
    fn process_unix_sockets(&mut self, vring: &VringRwLock, event_idx: bool) -> Result<()> {
        if event_idx {
            // To properly handle EVENT_IDX we need to keep calling
            // process_rx_queue until it stops finding new requests
            // on the queue, as vm-virtio's Queue implementation
            // only checks avail_index once
            loop {
                if !self.thread_backend.pending_rx() {
                    break;
                }
                vring
                    .disable_notification()
                    .map_err(|error| Error::Vring(error.to_string()))?;

                self.process_rx_queue(vring)?;
                if !vring
                    .enable_notification()
                    .map_err(|error| Error::Vring(error.to_string()))?
                {
                    break;
                }
            }
        } else {
            self.process_rx_queue(vring)?;
        }
        Ok(())
    }

    pub fn process_rx(&mut self, vring: &VringRwLock, event_idx: bool) -> Result<()> {
        if self.thread_backend.pending_rx() {
            self.process_unix_sockets(vring, event_idx)?;
        }
        Ok(())
    }

    /// Process tx queue and send requests to the backend for processing.
    fn process_tx_queue(&mut self, vring: &VringRwLock) -> Result<()> {
        let atomic_mem = match &self.mem {
            Some(m) => m,
            None => return Err(Error::NoMemoryConfigured),
        };

        while let Some(mut avail_desc) = vring
            .get_mut()
            .get_queue_mut()
            .iter(atomic_mem.memory())
            .map_err(|_| Error::IterateQueue)?
            .next()
        {
            let mem = atomic_mem.clone().memory();

            let head_idx = avail_desc.head_index();
            match VsockPacket::from_tx_virtq_chain(
                mem.deref(),
                &mut avail_desc,
                self.tx_buffer_size,
            ) {
                Ok(pkt) => {
                    if let Err(error) = self.thread_backend.send_pkt(&pkt) {
                        log::debug!("vsock: error handling TX packet: {error:?}");
                    }
                }
                Err(error) => log::debug!("vsock: error reading TX packet: {error:?}"),
            }

            // TODO: Check if the protocol requires read length to be correct
            let used_len = 0;

            let vring = vring.clone();
            let event_idx = self.event_idx;
            self.sender
                .send(EventData {
                    vring,
                    event_idx,
                    head_idx,
                    used_len,
                })
                .map_err(|_| Error::EventChannelClosed)?;
        }

        Ok(())
    }

    /// Wrapper to process tx queue based on whether event idx is enabled or
    /// not.
    pub fn process_tx(&mut self, vring_lock: &VringRwLock, event_idx: bool) -> Result<()> {
        if event_idx {
            // To properly handle EVENT_IDX we need to keep calling
            // process_rx_queue until it stops finding new requests
            // on the queue, as vm-virtio's Queue implementation
            // only checks avail_index once
            loop {
                vring_lock
                    .disable_notification()
                    .map_err(|error| Error::Vring(error.to_string()))?;
                self.process_tx_queue(vring_lock)?;
                if !vring_lock
                    .enable_notification()
                    .map_err(|error| Error::Vring(error.to_string()))?
                {
                    break;
                }
            }
        } else {
            self.process_tx_queue(vring_lock)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read;
    use std::os::unix::net::UnixStream;

    use vm_memory::GuestAddress;
    use vmm_sys_util::eventfd::EventFd;

    use super::*;

    const CONN_TX_BUF_SIZE: u32 = 64 * 1024;

    impl VhostUserVsockThread {
        fn get_epoll_file(&self) -> &File {
            &self.epoll_file
        }
    }

    fn test_vsock_thread() {
        let t = VhostUserVsockThread::new(3, CONN_TX_BUF_SIZE);
        assert!(t.is_ok());

        let mut t = t.unwrap();
        let epoll_fd = t.get_epoll_file().as_raw_fd();

        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap(),
        );

        t.mem = Some(mem.clone());

        let dummy_fd = EventFd::new(0).unwrap();

        VhostUserVsockThread::epoll_register(
            epoll_fd,
            dummy_fd.as_raw_fd(),
            epoll::Events::EPOLLOUT,
        )
        .unwrap();
        VhostUserVsockThread::epoll_modify(epoll_fd, dummy_fd.as_raw_fd(), epoll::Events::EPOLLIN)
            .unwrap();
        VhostUserVsockThread::epoll_unregister(epoll_fd, dummy_fd.as_raw_fd()).unwrap();
        VhostUserVsockThread::epoll_register(
            epoll_fd,
            dummy_fd.as_raw_fd(),
            epoll::Events::EPOLLIN,
        )
        .unwrap();

        let vring = VringRwLock::new(mem, 0x1000).unwrap();
        vring.set_queue_info(0x100, 0x200, 0x300).unwrap();
        vring.set_queue_ready(true);

        t.process_tx(&vring, false).unwrap();
        t.process_tx(&vring, true).unwrap();
        // add backend_rxq to avoid that RX processing is skipped
        t.thread_backend
            .backend_rxq
            .push_back(ConnMapKey::new(0, 0));
        t.process_rx(&vring, false).unwrap();
        t.process_rx(&vring, true).unwrap();

        VhostUserVsockThread::vring_handle_event(EventData {
            vring: vring.clone(),
            event_idx: false,
            head_idx: 0,
            used_len: 0,
        });
        VhostUserVsockThread::vring_handle_event(EventData {
            vring,
            event_idx: true,
            head_idx: 0,
            used_len: 0,
        });

        dummy_fd.write(1).unwrap();

        t.process_backend_evt(EventSet::empty());
    }

    #[test]
    fn test_vsock_thread_unix() {
        test_vsock_thread();
    }

    #[test]
    fn test_vsock_thread_failures() {
        let mut t = VhostUserVsockThread::new(3, CONN_TX_BUF_SIZE).unwrap();
        assert!(VhostUserVsockThread::epoll_register(-1, -1, epoll::Events::EPOLLIN).is_err());
        assert!(VhostUserVsockThread::epoll_modify(-1, -1, epoll::Events::EPOLLIN).is_err());
        assert!(VhostUserVsockThread::epoll_unregister(-1, -1).is_err());

        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap(),
        );

        let vring = VringRwLock::new(mem, 0x1000).unwrap();

        // memory is not configured, so processing TX should fail
        assert!(t.process_tx(&vring, false).is_err());
        assert!(t.process_tx(&vring, true).is_err());

        // add backend_rxq to avoid that RX processing is skipped
        t.thread_backend
            .backend_rxq
            .push_back(ConnMapKey::new(0, 0));
        assert!(t.process_rx(&vring, false).is_err());
        assert!(t.process_rx(&vring, true).is_err());
    }

    #[test]
    fn host_ports_use_firecracker_dynamic_range_and_wrap() {
        let mut thread =
            VhostUserVsockThread::new(3, CONN_TX_BUF_SIZE).expect("create backend thread");
        thread.local_port = Wrapping(MAX_HOST_PORT - 1);

        assert_eq!(
            thread.allocate_local_port().expect("allocate final port"),
            MAX_HOST_PORT - 1
        );
        assert_eq!(
            thread.allocate_local_port().expect("wrap to first port"),
            MIN_HOST_PORT
        );
    }

    #[test]
    fn host_port_allocator_skips_collisions_and_reports_exhaustion() {
        let mut thread =
            VhostUserVsockThread::new(3, CONN_TX_BUF_SIZE).expect("create backend thread");
        thread.local_port = Wrapping(10);
        thread.thread_backend.local_port_set.insert(10);

        assert_eq!(
            thread
                .allocate_local_port_in_range(10, 12)
                .expect("skip occupied port"),
            11
        );
        assert!(matches!(
            thread.allocate_local_port_in_range(10, 12),
            Err(Error::NoFreeLocalPort)
        ));
    }

    #[test]
    fn test_vsock_thread_unix_backend() {
        let mut t = VhostUserVsockThread::new(3, CONN_TX_BUF_SIZE).unwrap();

        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap(),
        );

        t.mem = Some(mem.clone());

        let (mut client, backend) = UnixStream::pair().unwrap();
        t.host_connections
            .requests
            .lock()
            .unwrap()
            .push_back(crate::HostConnectionRequest {
                stream: backend,
                destination_port: 1234,
            });
        t.host_connections.event.write(1).unwrap();
        t.process_backend_evt(EventSet::empty());
        assert_eq!(t.thread_backend.conn_map.len(), 1);

        let mut buf = vec![0u8; 16];
        client.set_nonblocking(true).unwrap();
        client.read(&mut buf).unwrap_err();

        t.process_backend_evt(EventSet::empty());
    }

    #[test]
    fn host_connection_waits_for_frontend_memory_setup() {
        let mut thread = VhostUserVsockThread::new(3, CONN_TX_BUF_SIZE).unwrap();
        let (_client, backend) = UnixStream::pair().unwrap();
        thread
            .host_connections
            .requests
            .lock()
            .unwrap()
            .push_back(crate::HostConnectionRequest {
                stream: backend,
                destination_port: 7000,
            });
        thread.host_connections.event.write(1).unwrap();

        thread.process_backend_evt(EventSet::empty());
        assert_eq!(thread.host_connections.requests.lock().unwrap().len(), 1);
        assert!(thread.thread_backend.conn_map.is_empty());

        thread.mem = Some(GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap(),
        ));
        thread.host_connections.event.write(1).unwrap();
        thread.process_backend_evt(EventSet::empty());
        assert!(thread.host_connections.requests.lock().unwrap().is_empty());
        assert_eq!(thread.thread_backend.conn_map.len(), 1);
    }

    #[test]
    fn canceled_pending_host_connection_releases_device_slot() {
        let mut thread = VhostUserVsockThread::new(3, CONN_TX_BUF_SIZE).unwrap();
        thread.mem = Some(GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap(),
        ));
        let (client, backend) = UnixStream::pair().unwrap();
        thread
            .host_connections
            .requests
            .lock()
            .unwrap()
            .push_back(crate::HostConnectionRequest {
                stream: backend,
                destination_port: 7000,
            });
        thread.host_connections.event.write(1).unwrap();
        thread.process_backend_evt(EventSet::empty());
        assert_eq!(thread.thread_backend.conn_map.len(), 1);

        drop(client);
        thread.process_backend_evt(EventSet::empty());

        assert!(thread.thread_backend.conn_map.is_empty());
        assert!(thread.thread_backend.pending_rx());
    }
}
