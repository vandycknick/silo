// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use std::{
    collections::{HashMap, HashSet, VecDeque},
    io::{Read, Result as StdIOResult, Write},
    net::Shutdown,
    os::unix::{
        net::UnixStream,
        prelude::{AsRawFd, RawFd},
    },
    result::Result as StdResult,
};

use log::{info, warn};
use virtio_vsock::packet::VsockPacket;
use vm_memory::{
    bitmap::BitmapSlice, ReadVolatile, VolatileMemoryError, VolatileSlice, WriteVolatile,
};

use crate::{
    rxops::*,
    vhu_vsock::{
        ConnMapKey, Error, Result, MAX_CONNECTIONS, VSOCK_HOST_CID, VSOCK_OP_REQUEST, VSOCK_OP_RST,
        VSOCK_TYPE_STREAM,
    },
    vhu_vsock_thread::VhostUserVsockThread,
    vsock_conn::*,
    ConnectionRequest, GuestConnectionAcceptor,
};

pub(crate) enum StreamType {
    Unix(UnixStream),
}

impl StreamType {
    pub fn shutdown(&self, how: Shutdown) -> StdIOResult<()> {
        match self {
            StreamType::Unix(stream) => stream.shutdown(how),
        }
    }
}

impl Read for StreamType {
    fn read(&mut self, buf: &mut [u8]) -> StdIOResult<usize> {
        match self {
            StreamType::Unix(stream) => stream.read(buf),
        }
    }
}

impl Write for StreamType {
    fn write(&mut self, buf: &[u8]) -> StdIOResult<usize> {
        match self {
            StreamType::Unix(stream) => stream.write(buf),
        }
    }

    fn flush(&mut self) -> StdIOResult<()> {
        match self {
            StreamType::Unix(stream) => stream.flush(),
        }
    }
}

impl AsRawFd for StreamType {
    fn as_raw_fd(&self) -> RawFd {
        match self {
            StreamType::Unix(stream) => stream.as_raw_fd(),
        }
    }
}

impl ReadVolatile for StreamType {
    fn read_volatile<B: BitmapSlice>(
        &mut self,
        buf: &mut VolatileSlice<'_, B>,
    ) -> StdResult<usize, VolatileMemoryError> {
        match self {
            StreamType::Unix(stream) => stream.read_volatile(buf),
        }
    }
}

impl WriteVolatile for StreamType {
    fn write_volatile<B: BitmapSlice>(
        &mut self,
        buf: &VolatileSlice<'_, B>,
    ) -> StdResult<usize, VolatileMemoryError> {
        match self {
            StreamType::Unix(stream) => stream.write_volatile(buf),
        }
    }
}

pub(crate) trait IsHybridVsock {
    fn is_hybrid_vsock(&self) -> bool;
    fn shutdown(&self, how: Shutdown) -> StdIOResult<()>;
}

impl IsHybridVsock for StreamType {
    fn is_hybrid_vsock(&self) -> bool {
        matches!(self, StreamType::Unix(_))
    }

    fn shutdown(&self, how: Shutdown) -> StdIOResult<()> {
        self.shutdown(how)
    }
}

pub(crate) struct VsockThreadBackend {
    /// Map of ConnMapKey objects indexed by raw file descriptors.
    pub listener_map: HashMap<RawFd, ConnMapKey>,
    /// Map of vsock connection objects indexed by ConnMapKey objects.
    pub conn_map: HashMap<ConnMapKey, VsockConnection<StreamType>>,
    /// Queue of ConnMapKey objects indicating pending rx operations.
    pub backend_rxq: VecDeque<ConnMapKey>,
    reset_queue: VecDeque<ConnMapKey>,
    /// epoll for registering new host-side connections.
    epoll_fd: i32,
    /// CID of the guest.
    guest_cid: u64,
    /// Set of allocated local ports.
    pub local_port_set: HashSet<u32>,
    tx_buffer_size: u32,
    guest_acceptor: GuestConnectionAcceptor,
}

impl VsockThreadBackend {
    /// New instance of VsockThreadBackend.
    #[cfg(test)]
    pub fn new(epoll_fd: i32, guest_cid: u64, tx_buffer_size: u32) -> Self {
        Self::new_with_acceptor(
            epoll_fd,
            guest_cid,
            tx_buffer_size,
            std::sync::Arc::new(|_| None),
        )
    }

    pub fn new_with_acceptor(
        epoll_fd: i32,
        guest_cid: u64,
        tx_buffer_size: u32,
        guest_acceptor: GuestConnectionAcceptor,
    ) -> Self {
        Self {
            listener_map: HashMap::new(),
            conn_map: HashMap::new(),
            backend_rxq: VecDeque::new(),
            reset_queue: VecDeque::new(),
            epoll_fd,
            guest_cid,
            local_port_set: HashSet::new(),
            tx_buffer_size,
            guest_acceptor,
        }
    }

    /// Checks if there are pending rx requests in the backend rxq.
    pub fn pending_rx(&self) -> bool {
        !self.reset_queue.is_empty() || !self.backend_rxq.is_empty()
    }

    pub fn enqueue_rx(&mut self, key: ConnMapKey) {
        if self.backend_rxq.len() < MAX_CONNECTIONS && !self.backend_rxq.contains(&key) {
            self.backend_rxq.push_back(key);
        }
    }

    pub fn reject_connection(&mut self, key: &ConnMapKey) {
        if let Some(conn) = self.remove_connection(key) {
            self.enq_rst(conn.local_port, conn.peer_port);
        }
    }

    /// Deliver a vsock packet to the guest vsock driver.
    ///
    /// Returns:
    /// - `Ok(())` if the packet was successfully filled in
    /// - `Err(Error::EmptyBackendRxQ) if there was no available data
    pub fn recv_pkt<B: BitmapSlice>(&mut self, pkt: &mut VsockPacket<B>) -> Result<()> {
        if let Some(key) = self.reset_queue.pop_front() {
            pkt.set_src_cid(VSOCK_HOST_CID)
                .set_dst_cid(self.guest_cid)
                .set_src_port(key.local_port)
                .set_dst_port(key.peer_port)
                .set_type(VSOCK_TYPE_STREAM)
                .set_op(VSOCK_OP_RST)
                .set_flags(0)
                .set_len(0)
                .set_buf_alloc(0)
                .set_fwd_cnt(0);
            return Ok(());
        }
        let key = loop {
            let key = self.backend_rxq.pop_front().ok_or(Error::EmptyBackendRxQ)?;
            if self.conn_map.contains_key(&key) {
                break key;
            }
        };
        let Some(conn) = self.conn_map.get_mut(&key) else {
            return Err(Error::EmptyBackendRxQ);
        };

        if conn.rx_queue.peek() == Some(RxOps::Reset) {
            // Handle RST events here
            let Some(conn) = self.remove_connection(&key) else {
                return Ok(());
            };

            // Initialize the packet header to contain a VSOCK_OP_RST operation
            pkt.set_op(VSOCK_OP_RST)
                .set_src_cid(VSOCK_HOST_CID)
                .set_dst_cid(conn.guest_cid)
                .set_src_port(conn.local_port)
                .set_dst_port(conn.peer_port)
                .set_len(0)
                .set_type(VSOCK_TYPE_STREAM)
                .set_flags(0)
                .set_buf_alloc(0)
                .set_fwd_cnt(0);

            return Ok(());
        }

        let result = conn.recv_pkt(pkt);
        let terminal = (pkt.op() == VSOCK_OP_RST
            || (pkt.op() == crate::vhu_vsock::VSOCK_OP_SHUTDOWN
                && pkt.flags()
                    == (crate::vhu_vsock::VSOCK_FLAGS_SHUTDOWN_RCV
                        | crate::vhu_vsock::VSOCK_FLAGS_SHUTDOWN_SEND)))
            && conn.rx_queue.peek() == Some(RxOps::Reset);
        let pending = conn.rx_queue.pending_rx();
        if terminal {
            self.remove_connection(&key);
            return result;
        }
        if pending {
            self.enqueue_rx(key);
        }
        result
    }

    /// Deliver a guest generated packet to its destination in the backend.
    ///
    /// Absorbs unexpected packets, handles rest to respective connection
    /// object.
    ///
    /// Returns:
    /// - always `Ok(())` if packet has been consumed correctly
    pub fn send_pkt<B: BitmapSlice>(&mut self, pkt: &VsockPacket<B>) -> Result<()> {
        if pkt.src_cid() != self.guest_cid {
            warn!(
                "vsock: dropping packet with inconsistent src_cid: {:?} from guest configured with CID: {:?}",
                pkt.src_cid(), self.guest_cid
            );
            return Ok(());
        }

        if pkt.dst_cid() != VSOCK_HOST_CID {
            warn!(
                "vsock: rejecting packet for unsupported cid: {:?}",
                pkt.dst_cid()
            );
            self.enq_rst(pkt.dst_port(), pkt.src_port());
            return Ok(());
        }

        if pkt.type_() != VSOCK_TYPE_STREAM {
            info!("vsock: rejecting packet of unknown type");
            self.enq_rst(pkt.dst_port(), pkt.src_port());
            return Ok(());
        }

        let key = ConnMapKey::new(pkt.dst_port(), pkt.src_port());

        // TODO: Handle cases where connection does not exist and packet op
        // is not VSOCK_OP_REQUEST
        if !self.conn_map.contains_key(&key) {
            // The packet contains a new connection request
            if pkt.op() == VSOCK_OP_REQUEST {
                self.handle_new_guest_conn(pkt);
            } else {
                self.enq_rst(pkt.dst_port(), pkt.src_port());
            }
            return Ok(());
        }

        if pkt.op() == VSOCK_OP_RST {
            // Handle an RST packet from the guest here
            if self
                .conn_map
                .get(&key)
                .is_some_and(|conn| conn.rx_queue.contains(RxOps::Reset.bitmask()))
            {
                return Ok(());
            }
            let Some(_conn) = self.remove_connection(&key) else {
                return Ok(());
            };
            return Ok(());
        }

        // Forward this packet to its listening connection
        let Some(conn) = self.conn_map.get_mut(&key) else {
            return Ok(());
        };
        conn.send_pkt(pkt)?;

        if conn.rx_queue.pending_rx() {
            // Required if the connection object adds new rx operations
            self.enqueue_rx(key);
        }

        Ok(())
    }

    /// Handle a new guest initiated connection, i.e from the peer, the guest
    /// driver.
    ///
    /// In case of proxying using unix domain socket, attempts to connect to a
    /// host side unix socket listening on a path corresponding to the
    /// destination port as follows:
    /// - "{self.host_sock_path}_{local_port}""
    ///
    /// In case of proxying using vosck, attempts to connect to the
    /// {forward_cid, local_port}
    fn handle_new_guest_conn<B: BitmapSlice>(&mut self, pkt: &VsockPacket<B>) {
        if !connection_capacity_available(self.conn_map.len()) {
            self.enq_rst(pkt.dst_port(), pkt.src_port());
            return;
        }
        let request = ConnectionRequest {
            source_port: pkt.src_port(),
            destination_port: pkt.dst_port(),
        };
        (self.guest_acceptor)(request)
            .ok_or_else(|| {
                Error::UnixConnect(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    "guest connection rejected by host",
                ))
            })
            .and_then(|stream| {
                stream
                    .set_nonblocking(true)
                    .map(|_| stream)
                    .map_err(Error::UnixConnect)
            })
            .and_then(|stream| self.add_new_guest_conn(StreamType::Unix(stream), pkt))
            .unwrap_or_else(|_| self.enq_rst(pkt.dst_port(), pkt.src_port()));
    }

    /// Wrapper to add new connection to relevant HashMaps.
    fn add_new_guest_conn<B: BitmapSlice>(
        &mut self,
        stream: StreamType,
        pkt: &VsockPacket<B>,
    ) -> Result<()> {
        let stream_fd = stream.as_raw_fd();
        VhostUserVsockThread::epoll_register(
            self.epoll_fd,
            stream_fd,
            epoll::Events::EPOLLIN | epoll::Events::EPOLLOUT,
        )?;
        let conn = VsockConnection::new_peer_init(
            stream,
            pkt.dst_cid(),
            pkt.dst_port(),
            pkt.src_cid(),
            pkt.src_port(),
            self.epoll_fd,
            pkt.buf_alloc(),
            self.tx_buffer_size,
        );
        self.listener_map
            .insert(stream_fd, ConnMapKey::new(pkt.dst_port(), pkt.src_port()));

        self.conn_map
            .insert(ConnMapKey::new(pkt.dst_port(), pkt.src_port()), conn);
        self.enqueue_rx(ConnMapKey::new(pkt.dst_port(), pkt.src_port()));

        self.local_port_set.insert(pkt.dst_port());

        Ok(())
    }

    /// Enqueue RST packets to be sent to guest.
    fn enq_rst(&mut self, local_port: u32, peer_port: u32) {
        let key = ConnMapKey::new(local_port, peer_port);
        if self.reset_queue.len() < MAX_CONNECTIONS && !self.reset_queue.contains(&key) {
            self.reset_queue.push_back(key);
        }
    }

    fn remove_connection(&mut self, key: &ConnMapKey) -> Option<VsockConnection<StreamType>> {
        let conn = self.conn_map.remove(key)?;
        self.backend_rxq.retain(|queued| queued != key);
        self.listener_map.remove(&conn.stream.as_raw_fd());
        self.local_port_set.remove(&conn.local_port);
        if let Err(error) =
            VhostUserVsockThread::epoll_unregister(conn.epoll_fd, conn.stream.as_raw_fd())
        {
            warn!(
                "Could not remove epoll listener for fd {:?}: {:?}",
                conn.stream.as_raw_fd(),
                error
            );
        }
        Some(conn)
    }
}

pub(crate) const fn connection_capacity_available(active_connections: usize) -> bool {
    active_connections < MAX_CONNECTIONS
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use virtio_vsock::packet::{VsockPacket, PKT_HEADER_SIZE};

    use super::*;
    use crate::vhu_vsock::VSOCK_OP_RW;

    const DATA_LEN: usize = 16;
    const CONN_TX_BUF_SIZE: u32 = 64 * 1024;
    const VSOCK_PEER_PORT: u32 = 1234;

    #[test]
    fn test_vsock_thread_backend_unix() {
        const CID: u64 = 3;

        let epoll_fd = epoll::create(false).unwrap();
        let mut vtp = VsockThreadBackend::new(epoll_fd, CID, CONN_TX_BUF_SIZE);

        assert!(!vtp.pending_rx());

        let mut pkt_raw = [0u8; PKT_HEADER_SIZE + DATA_LEN];
        let (hdr_raw, data_raw) = pkt_raw.split_at_mut(PKT_HEADER_SIZE);

        // SAFETY: Safe as hdr_raw and data_raw are guaranteed to be valid.
        let mut packet = unsafe { VsockPacket::new(hdr_raw, Some(data_raw)).unwrap() };

        assert_eq!(
            vtp.recv_pkt(&mut packet).unwrap_err().to_string(),
            Error::EmptyBackendRxQ.to_string()
        );

        vtp.send_pkt(&packet).unwrap();

        packet.set_type(VSOCK_TYPE_STREAM);
        vtp.send_pkt(&packet).unwrap();

        packet.set_src_cid(CID);
        packet.set_dst_cid(VSOCK_HOST_CID);
        packet.set_dst_port(VSOCK_PEER_PORT);
        vtp.send_pkt(&packet).unwrap();

        packet.set_op(VSOCK_OP_REQUEST);
        vtp.send_pkt(&packet).unwrap();

        packet.set_op(VSOCK_OP_RW);
        vtp.send_pkt(&packet).unwrap();

        packet.set_op(VSOCK_OP_RST);
        vtp.send_pkt(&packet).unwrap();

        vtp.recv_pkt(&mut packet).unwrap();

        vtp.enq_rst(1, 2);
    }

    #[test]
    fn guest_request_uses_dynamic_acceptor() {
        const CID: u64 = 3;
        const SOURCE_PORT: u32 = 4000;
        const DESTINATION_PORT: u32 = 7000;

        let accepted = Arc::new(Mutex::new(Vec::new()));
        let accepted_for_callback = accepted.clone();
        let mut backend = VsockThreadBackend::new_with_acceptor(
            epoll::create(false).expect("create epoll"),
            CID,
            CONN_TX_BUF_SIZE,
            Arc::new(move |request| {
                assert_eq!(request.source_port, SOURCE_PORT);
                assert_eq!(request.destination_port, DESTINATION_PORT);
                let (backend, host) = UnixStream::pair().ok()?;
                accepted_for_callback
                    .lock()
                    .expect("lock accepted streams")
                    .push(host);
                Some(backend)
            }),
        );
        let mut packet_bytes = [0_u8; PKT_HEADER_SIZE];
        // SAFETY: packet_bytes contains the complete fixed-size vsock header.
        let mut packet = unsafe { VsockPacket::new(&mut packet_bytes, None).expect("packet") };
        packet
            .set_src_cid(CID)
            .set_dst_cid(VSOCK_HOST_CID)
            .set_src_port(SOURCE_PORT)
            .set_dst_port(DESTINATION_PORT)
            .set_type(VSOCK_TYPE_STREAM)
            .set_op(VSOCK_OP_REQUEST)
            .set_buf_alloc(CONN_TX_BUF_SIZE);

        backend.send_pkt(&packet).expect("route guest request");

        assert_eq!(backend.conn_map.len(), 1);
        assert_eq!(accepted.lock().expect("lock accepted streams").len(), 1);
    }

    #[test]
    fn active_connection_limit_has_exact_firecracker_boundary() {
        assert!(connection_capacity_available(MAX_CONNECTIONS - 1));
        assert!(!connection_capacity_available(MAX_CONNECTIONS));
    }

    #[test]
    fn stale_rx_keys_are_drained_without_emitting_packets() {
        let mut backend = VsockThreadBackend::new(
            epoll::create(false).expect("create epoll"),
            3,
            CONN_TX_BUF_SIZE,
        );
        backend.enqueue_rx(ConnMapKey::new(7000, 4000));
        let mut header = [0_u8; PKT_HEADER_SIZE];
        // SAFETY: header contains the complete fixed-size vsock header.
        let mut packet = unsafe { VsockPacket::new(&mut header, None).expect("create packet") };

        assert!(matches!(
            backend.recv_pkt(&mut packet),
            Err(Error::EmptyBackendRxQ)
        ));
        assert!(backend.backend_rxq.is_empty());
    }
}
