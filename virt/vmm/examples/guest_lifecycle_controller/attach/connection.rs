//! Adoption of one inherited, already-connected native mux stream.
//!
//! ```text
//!  orchestrator (native owner)            this process (attach)
//!  CONNECT 1027 + SCM_RIGHTS ──► mux      fd N ──► "OK <source-port>\n" ──► one HTTP/2 conn
//!  pass_fds=(N,) ─────────────────────────┘        (bytes after '\n' belong to HTTP/2)
//! ```
//!
//! The native owner keeps the VM, mux owner, leases and fences. This side owns
//! only the stream; reconnecting means the owner opens a new mux connection.

use std::os::fd::{BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::sync::{Arc, Mutex};

use eyre::ensure;
use hyper_util::rt::TokioIo;
use tokio::io::AsyncReadExt;
use tonic::transport::{Channel, Endpoint};
use tower::service_fn;

/// `OK 4294967295\n` is 14 bytes; anything longer is not a native acknowledgement.
const MAX_ACKNOWLEDGEMENT_BYTES: usize = 16;

/// Validates and adopts one inherited connected Unix stream descriptor.
pub(crate) fn adopt(raw: RawFd) -> eyre::Result<std::os::unix::net::UnixStream> {
    use nix::fcntl::{fcntl, FcntlArg, FdFlag};
    use nix::sys::socket::{getpeername, getsockopt, sockopt, SockType, UnixAddr};
    use nix::sys::stat::{fstat, SFlag};

    ensure!(
        raw > 2,
        "attach descriptor must be an inherited fd above stdio"
    );
    // nix's fcntl API requires an already-valid AsFd. Probe the untrusted
    // numeric argument with libc before constructing a Rust FD borrow.
    // SAFETY: F_GETFD only reads descriptor flags; an invalid number yields EBADF.
    let probed = unsafe { nix::libc::fcntl(raw, nix::libc::F_GETFD) };
    ensure!(
        probed >= 0,
        "attach descriptor {raw} is not open: {}",
        std::io::Error::last_os_error()
    );
    // SAFETY: the number was probed open and this scope neither closes nor
    // transfers it; ownership is taken only after every validation passes.
    let borrowed = unsafe { BorrowedFd::borrow_raw(raw) };
    let stat = fstat(borrowed)?;
    ensure!(
        SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT == SFlag::S_IFSOCK,
        "attach descriptor {raw} is not a socket"
    );
    ensure!(
        getsockopt(&borrowed, sockopt::SockType)? == SockType::Stream,
        "attach descriptor {raw} is not a stream socket"
    );
    getpeername::<UnixAddr>(raw).map_err(|error| {
        eyre::eyre!("attach descriptor {raw} is not a connected Unix stream: {error}")
    })?;
    let flags = FdFlag::from_bits_retain(fcntl(borrowed, FcntlArg::F_GETFD)?);
    fcntl(borrowed, FcntlArg::F_SETFD(flags | FdFlag::FD_CLOEXEC))?;
    // SAFETY: the request transfers this validated inherited descriptor exactly
    // once; nothing else in this process owns or closes it.
    let owned = unsafe { OwnedFd::from_raw_fd(raw) };
    let stream = std::os::unix::net::UnixStream::from(owned);
    stream.set_nonblocking(true)?;
    Ok(stream)
}

/// Consumes exactly the native `OK <source-port>\n` line, one byte at a time,
/// so no following HTTP/2 or SSH byte is swallowed.
pub(crate) async fn acknowledge(stream: &mut tokio::net::UnixStream) -> eyre::Result<u32> {
    let mut line = Vec::with_capacity(MAX_ACKNOWLEDGEMENT_BYTES);
    loop {
        let mut byte = [0_u8; 1];
        let count = stream.read(&mut byte).await?;
        ensure!(
            count == 1,
            "native mux closed before its connection acknowledgement (read {:?})",
            String::from_utf8_lossy(&line)
        );
        if byte[0] == b'\n' {
            return parse_acknowledgement(&line);
        }
        line.push(byte[0]);
        ensure!(
            line.len() < MAX_ACKNOWLEDGEMENT_BYTES,
            "oversized native mux acknowledgement {:?}",
            String::from_utf8_lossy(&line)
        );
    }
}

fn parse_acknowledgement(line: &[u8]) -> eyre::Result<u32> {
    let port = line.strip_prefix(b"OK ").ok_or_else(|| {
        eyre::eyre!(
            "native mux refused or malformed acknowledgement {:?}",
            String::from_utf8_lossy(line)
        )
    })?;
    ensure!(
        !port.is_empty()
            && port.iter().all(u8::is_ascii_digit)
            && (port == b"0" || port[0] != b'0'),
        "noncanonical native mux source port {:?}",
        String::from_utf8_lossy(port)
    );
    Ok(std::str::from_utf8(port)?.parse()?)
}

/// Adopts, acknowledges and returns the ready byte stream plus its source port.
pub(crate) async fn open(raw: RawFd) -> eyre::Result<(tokio::net::UnixStream, u32)> {
    let mut stream = tokio::net::UnixStream::from_std(adopt(raw)?)?;
    let port = acknowledge(&mut stream).await?;
    Ok((stream, port))
}

/// One tonic channel over exactly one stream. A reconnect attempt fails
/// instead of silently opening a lookalike connection.
pub(crate) async fn channel(stream: tokio::net::UnixStream) -> eyre::Result<Channel> {
    let slot = Arc::new(Mutex::new(Some(stream)));
    let channel = Endpoint::from_static("http://guest-agent.invalid")
        .connect_with_connector(service_fn(move |_| {
            let taken = slot
                .lock()
                .map_err(|_| std::io::Error::other("attach stream slot poisoned"))
                .and_then(|mut slot| {
                    slot.take().ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::NotConnected,
                            "single-use attach stream already consumed; open a new native mux connection",
                        )
                    })
                });
            async move { taken.map(TokioIo::new) }
        }))
        .await?;
    Ok(channel)
}

#[cfg(test)]
mod tests {
    use crate::attach::connection::{acknowledge, adopt, parse_acknowledgement};
    use std::os::fd::IntoRawFd;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn acknowledgement_requires_canonical_port() {
        assert_eq!(parse_acknowledgement(b"OK 0").unwrap(), 0);
        assert_eq!(parse_acknowledgement(b"OK 1027").unwrap(), 1027);
        assert_eq!(parse_acknowledgement(b"OK 4294967295").unwrap(), u32::MAX);
        for malformed in [
            &b"OK "[..],
            b"OK 01",
            b"OK 1 ",
            b"OK -1",
            b"OK 4294967296",
            b"ERROR 1027",
            b"ok 1",
        ] {
            assert!(parse_acknowledgement(malformed).is_err(), "{malformed:?}");
        }
    }

    #[tokio::test]
    async fn acknowledgement_never_consumes_following_bytes() {
        let (mut ours, mut peer) = tokio::net::UnixStream::pair().unwrap();
        peer.write_all(b"OK 42\nPRI * HTTP/2.0").await.unwrap();
        assert_eq!(acknowledge(&mut ours).await.unwrap(), 42);
        let mut rest = [0_u8; 14];
        ours.read_exact(&mut rest).await.unwrap();
        assert_eq!(&rest, b"PRI * HTTP/2.0");
    }

    #[tokio::test]
    async fn acknowledgement_rejects_eof_and_oversized_lines() {
        let (mut ours, mut peer) = tokio::net::UnixStream::pair().unwrap();
        peer.write_all(b"OK 4").await.unwrap();
        drop(peer);
        assert!(acknowledge(&mut ours).await.is_err());
        let (mut ours, mut peer) = tokio::net::UnixStream::pair().unwrap();
        peer.write_all(b"OK 1234567890123456\n").await.unwrap();
        assert!(acknowledge(&mut ours).await.is_err());
    }

    #[test]
    fn adoption_rejects_stdio_and_non_stream_descriptors() {
        assert!(adopt(1).is_err());
        let (datagram, _peer) = std::os::unix::net::UnixDatagram::pair().unwrap();
        let raw = datagram.into_raw_fd();
        assert!(adopt(raw).is_err());
        // The rejected descriptor was never adopted, so its creator closes it.
        nix::unistd::close(raw).unwrap();
        let file = std::fs::File::open("/dev/null").unwrap();
        assert!(adopt(std::os::fd::AsRawFd::as_raw_fd(&file)).is_err());
    }

    #[tokio::test]
    async fn adopted_stream_carries_acknowledgement_then_payload() {
        let (ours, mut peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let adopted = adopt(ours.into_raw_fd()).unwrap();
        let mut adopted = tokio::net::UnixStream::from_std(adopted).unwrap();
        std::io::Write::write_all(&mut peer, b"OK 7\nx").unwrap();
        assert_eq!(acknowledge(&mut adopted).await.unwrap(), 7);
        let mut payload = [0_u8; 1];
        adopted.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"x");
    }
}
