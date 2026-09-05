use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::os::fd::{AsFd, AsRawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use nix::errno::Errno;
use nix::poll::{poll, PollFd, PollFlags};
use nix::sys::socket::{connect, socket, AddressFamily, SockFlag, SockType, SockaddrStorage};

const MAX_CONNECTIONS: usize = 256;
const BUFFER_SIZE: usize = 16 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const POLL_INTERVAL_MS: u16 = 100;

/// One publication's IPv4 ingress, independent of Docker's host bind address.
/// Only the gateway that accepted the control connection may use this listener.
pub(crate) struct Relay {
    address: SocketAddrV4,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<io::Result<()>>>,
}

impl Relay {
    pub(crate) fn start(
        guest: Ipv4Addr,
        gateway: Ipv4Addr,
        target: SocketAddr,
    ) -> io::Result<Self> {
        let listener = TcpListener::bind(SocketAddrV4::new(guest, 0))?;
        listener.set_nonblocking(true)?;
        let SocketAddr::V4(address) = listener.local_addr()? else {
            return Err(io::Error::other("publication ingress must use IPv4"));
        };
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let worker = thread::Builder::new()
            .name("publication-relay".into())
            .spawn(move || run(listener, gateway, target, &worker_stop))?;
        Ok(Self {
            address,
            stop,
            worker: Some(worker),
        })
    }

    pub(crate) fn address(&self) -> SocketAddrV4 {
        self.address
    }

    pub(crate) fn is_finished(&self) -> bool {
        self.worker.as_ref().is_none_or(JoinHandle::is_finished)
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            match worker.join() {
                Ok(Ok(())) => {}
                Ok(Err(error)) => eprintln!("silo-portd: publication relay failed: {error}"),
                Err(_) => eprintln!("silo-portd: publication relay thread panicked"),
            }
        }
    }
}

fn run(
    listener: TcpListener,
    gateway: Ipv4Addr,
    target: SocketAddr,
    stop: &AtomicBool,
) -> io::Result<()> {
    let mut connections: Vec<Connection> = Vec::new();
    while !stop.load(Ordering::Relaxed) {
        let (accept, events) = {
            let mut polls = vec![PollFd::new(listener.as_fd(), PollFlags::POLLIN)];
            let mut keys = Vec::new();
            for (index, connection) in connections.iter().enumerate() {
                for (is_target, stream, interest) in [
                    (false, &connection.client, connection.client_interest()),
                    (true, &connection.target, connection.target_interest()),
                ] {
                    // A descriptor with no interest can still report HUP forever.
                    // Omit it while the other direction drains its buffered data.
                    if !interest.is_empty() {
                        polls.push(PollFd::new(stream.as_fd(), interest));
                        keys.push((index, is_target));
                    }
                }
            }
            match poll(&mut polls, POLL_INTERVAL_MS) {
                Ok(_) => {}
                Err(Errno::EINTR) => continue,
                Err(error) => return Err(error.into()),
            }
            let accept = polls
                .first()
                .and_then(PollFd::revents)
                .unwrap_or_else(PollFlags::empty);
            let mut events = vec![(PollFlags::empty(), PollFlags::empty()); connections.len()];
            for ((index, is_target), fd) in keys.into_iter().zip(polls.iter().skip(1)) {
                if let Some(event) = events.get_mut(index) {
                    let flags = fd.revents().unwrap_or_else(PollFlags::empty);
                    if is_target {
                        event.1 = flags;
                    } else {
                        event.0 = flags;
                    }
                }
            }
            (accept, events)
        };
        let mut events = events.into_iter();
        connections.retain_mut(|connection| {
            let (client, target) = events
                .next()
                .unwrap_or((PollFlags::empty(), PollFlags::empty()));
            connection.step(client, target).unwrap_or(false)
        });
        if accept.intersects(PollFlags::POLLERR | PollFlags::POLLHUP | PollFlags::POLLNVAL) {
            return Err(io::Error::other("publication listener stopped"));
        }
        if accept.contains(PollFlags::POLLIN) {
            // Bound work per iteration so a busy listener cannot starve existing
            // streams or postpone cancellation indefinitely.
            for _ in 0..64 {
                match listener.accept() {
                    Ok((client, peer)) => {
                        if peer.ip() == IpAddr::V4(gateway) && connections.len() < MAX_CONNECTIONS {
                            if let Ok(connection) = Connection::start(client, target) {
                                connections.push(connection);
                            }
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) => return Err(error),
                }
            }
        }
    }
    Ok(())
}

struct Connection {
    client: TcpStream,
    target: TcpStream,
    connecting: Option<Instant>,
    to_target: Pump,
    to_client: Pump,
}

impl Connection {
    fn start(client: TcpStream, address: SocketAddr) -> io::Result<Self> {
        client.set_nonblocking(true)?;
        let family = if address.is_ipv4() {
            AddressFamily::Inet
        } else {
            AddressFamily::Inet6
        };
        let fd = socket(
            family,
            SockType::Stream,
            SockFlag::SOCK_NONBLOCK | SockFlag::SOCK_CLOEXEC,
            None,
        )?;
        let connecting = match connect(fd.as_raw_fd(), &SockaddrStorage::from(address)) {
            Ok(()) => None,
            Err(Errno::EINPROGRESS) => Some(Instant::now()),
            Err(error) => return Err(error.into()),
        };
        Ok(Self {
            client,
            target: TcpStream::from(fd),
            connecting,
            to_target: Pump::new(),
            to_client: Pump::new(),
        })
    }

    fn client_interest(&self) -> PollFlags {
        if self.connecting.is_some() {
            return PollFlags::empty();
        }
        self.to_target.read_interest() | self.to_client.write_interest()
    }

    fn target_interest(&self) -> PollFlags {
        if self.connecting.is_some() {
            return PollFlags::POLLOUT;
        }
        self.to_client.read_interest() | self.to_target.write_interest()
    }

    fn step(&mut self, client: PollFlags, target: PollFlags) -> io::Result<bool> {
        if (client | target).intersects(PollFlags::POLLERR | PollFlags::POLLNVAL) {
            return Ok(false);
        }
        if let Some(started) = self.connecting {
            if started.elapsed() >= CONNECT_TIMEOUT {
                return Ok(false);
            }
            if !target.intersects(PollFlags::POLLOUT | PollFlags::POLLHUP) {
                return Ok(true);
            }
            if self.target.take_error()?.is_some() {
                return Ok(false);
            }
            self.connecting = None;
        }
        self.to_target
            .step(&mut self.client, &mut self.target, client, target)?;
        self.to_client
            .step(&mut self.target, &mut self.client, target, client)?;
        Ok(!(self.to_target.finished && self.to_client.finished))
    }
}

/// One direction, with bounded buffering and independent TCP half-close.
struct Pump {
    buffer: Vec<u8>,
    start: usize,
    end: usize,
    eof: bool,
    finished: bool,
}

impl Pump {
    fn new() -> Self {
        Self {
            buffer: vec![0; BUFFER_SIZE],
            start: 0,
            end: 0,
            eof: false,
            finished: false,
        }
    }

    fn read_interest(&self) -> PollFlags {
        if !self.eof && self.end < self.buffer.len() {
            PollFlags::POLLIN
        } else {
            PollFlags::empty()
        }
    }

    fn write_interest(&self) -> PollFlags {
        if self.start < self.end {
            PollFlags::POLLOUT
        } else {
            PollFlags::empty()
        }
    }

    fn step(
        &mut self,
        source: &mut TcpStream,
        sink: &mut TcpStream,
        read: PollFlags,
        write: PollFlags,
    ) -> io::Result<()> {
        if !self.eof && read.intersects(PollFlags::POLLIN | PollFlags::POLLHUP) {
            if let Some(buffer) = self
                .buffer
                .get_mut(self.end..)
                .filter(|buffer| !buffer.is_empty())
            {
                match source.read(buffer) {
                    Ok(0) => self.eof = true,
                    Ok(count) => self.end += count,
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                        ) => {}
                    Err(error) => return Err(error),
                }
            }
        }
        if self.start < self.end && write.intersects(PollFlags::POLLOUT | PollFlags::POLLHUP) {
            if let Some(buffer) = self.buffer.get(self.start..self.end) {
                match sink.write(buffer) {
                    Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                    Ok(count) => self.start += count,
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                        ) => {}
                    Err(error) => return Err(error),
                }
            }
        }
        if self.start == self.end {
            self.start = 0;
            self.end = 0;
            if self.eof && !self.finished {
                sink.shutdown(Shutdown::Write)?;
                self.finished = true;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::{Ipv4Addr, Shutdown, SocketAddrV4, TcpListener, TcpStream};
    use std::os::fd::{AsFd, AsRawFd};
    use std::thread;
    use std::time::{Duration, Instant};

    use nix::poll::{poll, PollFd, PollFlags};
    use nix::sys::socket::{bind, connect, socket, AddressFamily, SockFlag, SockType, SockaddrIn};

    use crate::relay::{Connection, Relay, CONNECT_TIMEOUT, MAX_CONNECTIONS};

    fn configure(stream: &TcpStream) {
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
    }

    #[test]
    fn transfers_large_payloads_and_half_closes_to_ipv4_and_ipv6_targets() {
        for address in ["127.0.0.1:0", "[::1]:0"] {
            let target = TcpListener::bind(address).unwrap();
            let relay = Relay::start(
                Ipv4Addr::LOCALHOST,
                Ipv4Addr::LOCALHOST,
                target.local_addr().unwrap(),
            )
            .unwrap();
            let payload: Vec<u8> = (0..512 * 1024).map(|index| (index % 251) as u8).collect();
            let expected = payload.clone();
            let server = thread::spawn(move || {
                let (mut stream, _) = target.accept().unwrap();
                configure(&stream);
                let mut received = Vec::new();
                stream.read_to_end(&mut received).unwrap();
                assert_eq!(received, expected);
                stream.write_all(&received).unwrap();
                stream.shutdown(Shutdown::Write).unwrap();
            });
            let mut client = TcpStream::connect(relay.address()).unwrap();
            configure(&client);
            client.write_all(&payload).unwrap();
            client.shutdown(Shutdown::Write).unwrap();
            let mut response = Vec::new();
            client.read_to_end(&mut response).unwrap();
            assert_eq!(response, payload);
            server.join().unwrap();
        }
    }

    #[test]
    fn target_half_close_does_not_discard_the_client_request() {
        let target = TcpListener::bind("127.0.0.1:0").unwrap();
        let relay = Relay::start(
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::LOCALHOST,
            target.local_addr().unwrap(),
        )
        .unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = target.accept().unwrap();
            configure(&stream);
            stream.write_all(b"greeting").unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
            let mut request = Vec::new();
            stream.read_to_end(&mut request).unwrap();
            assert_eq!(request, b"request after EOF");
        });
        let mut client = TcpStream::connect(relay.address()).unwrap();
        configure(&client);
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();
        assert_eq!(response, b"greeting");
        client.write_all(b"request after EOF").unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn shutdown_closes_listener_and_both_ends_of_idle_connections() {
        let target = TcpListener::bind("127.0.0.1:0").unwrap();
        let relay = Relay::start(
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::LOCALHOST,
            target.local_addr().unwrap(),
        )
        .unwrap();
        let address = relay.address();
        let mut client = TcpStream::connect(address).unwrap();
        let (mut backend, _) = target.accept().unwrap();
        configure(&client);
        configure(&backend);
        let started = Instant::now();
        drop(relay);
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(client.read(&mut [0]).unwrap(), 0);
        assert_eq!(backend.read(&mut [0]).unwrap(), 0);
        assert!(TcpStream::connect(address).is_err());
        TcpListener::bind(address).expect("ingress port was not released");
    }

    #[test]
    fn only_the_control_connections_gateway_may_dial_the_target() {
        let target = TcpListener::bind("127.0.0.1:0").unwrap();
        target.set_nonblocking(true).unwrap();
        let relay = Relay::start(
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::new(127, 0, 0, 2),
            target.local_addr().unwrap(),
        )
        .unwrap();
        let mut unauthorized = TcpStream::connect(relay.address()).unwrap();
        configure(&unauthorized);
        assert_eq!(unauthorized.read(&mut [0]).unwrap(), 0);
        assert_eq!(
            target.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );

        let fd = socket(
            AddressFamily::Inet,
            SockType::Stream,
            SockFlag::SOCK_CLOEXEC,
            None,
        )
        .unwrap();
        bind(
            fd.as_raw_fd(),
            &SockaddrIn::from(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 2), 0)),
        )
        .unwrap();
        connect(fd.as_raw_fd(), &SockaddrIn::from(relay.address())).unwrap();
        let mut authorized = TcpStream::from(fd);
        configure(&authorized);
        target.set_nonblocking(false).unwrap();
        let (mut backend, _) = target.accept().unwrap();
        configure(&backend);
        authorized.write_all(b"allowed").unwrap();
        let mut received = [0; 7];
        backend.read_exact(&mut received).unwrap();
        assert_eq!(&received, b"allowed");
    }

    #[test]
    fn refused_targets_do_not_stop_the_listener() {
        let reserved = TcpListener::bind("127.0.0.1:0").unwrap();
        let target = reserved.local_addr().unwrap();
        drop(reserved);
        let relay = Relay::start(Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST, target).unwrap();
        let mut client = TcpStream::connect(relay.address()).unwrap();
        configure(&client);
        assert_eq!(client.read(&mut [0]).unwrap(), 0);
        let target = TcpListener::bind(target).unwrap();
        let mut client = TcpStream::connect(relay.address()).unwrap();
        configure(&client);
        let (mut backend, _) = target.accept().unwrap();
        configure(&backend);
        backend.write_all(b"recovered").unwrap();
        let mut response = [0; 9];
        client.read_exact(&mut response).unwrap();
        assert_eq!(&response, b"recovered");
    }

    #[test]
    fn pending_dials_expire_without_blocking_the_reactor() {
        let target = TcpListener::bind("127.0.0.1:0").unwrap();
        let ingress = TcpListener::bind("127.0.0.1:0").unwrap();
        let _client = TcpStream::connect(ingress.local_addr().unwrap()).unwrap();
        let (client, _) = ingress.accept().unwrap();
        let mut connection = Connection::start(client, target.local_addr().unwrap()).unwrap();
        connection.connecting = Some(Instant::now() - CONNECT_TIMEOUT);
        assert!(!connection
            .step(PollFlags::empty(), PollFlags::empty())
            .unwrap());
    }

    #[test]
    fn bounds_connections_and_reclaims_capacity() {
        let target = TcpListener::bind("127.0.0.1:0").unwrap();
        let relay = Relay::start(
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::LOCALHOST,
            target.local_addr().unwrap(),
        )
        .unwrap();
        // Drain the listen backlog without retaining another 256 descriptors.
        // Backend EOF must leave each client's sending direction alive, so
        // these streams still consume capacity until the clients also close.
        let server = thread::spawn(move || {
            for _ in 0..MAX_CONNECTIONS {
                let mut fds = [PollFd::new(target.as_fd(), PollFlags::POLLIN)];
                assert!(poll(&mut fds, 5000_u16).unwrap() > 0);
                drop(target.accept().unwrap());
            }
            target
        });
        let mut clients = Vec::new();
        for _ in 0..MAX_CONNECTIONS {
            clients.push(TcpStream::connect(relay.address()).unwrap());
        }
        let mut rejected = TcpStream::connect(relay.address()).unwrap();
        configure(&rejected);
        assert_eq!(rejected.read(&mut [0]).unwrap(), 0);
        let target = server.join().unwrap();
        for client in &mut clients {
            configure(client);
            client.shutdown(Shutdown::Write).unwrap();
            assert_eq!(client.read(&mut [0]).unwrap(), 0);
        }
        let mut client = TcpStream::connect(relay.address()).unwrap();
        configure(&client);
        let (mut backend, _) = target.accept().unwrap();
        backend.write_all(b"new").unwrap();
        let mut response = [0; 3];
        client.read_exact(&mut response).unwrap();
        assert_eq!(&response, b"new");
    }
}
