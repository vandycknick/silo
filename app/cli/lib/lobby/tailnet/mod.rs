//! The lobby's view of the tailnet: incoming streams, peer identity and node
//! state. tsgate is the only implementation today; an in-process tailnet can
//! replace it behind the same types.

pub(crate) mod tsgate;
pub(crate) mod wire;

use std::fmt;
use std::io;

use tokio::net::UnixStream;

use wire::Listener;

/// One accepted tailnet connection. For `Listener::Http` TLS is already
/// terminated; for `Listener::Ssh` the bytes are the raw SSH stream.
#[derive(Debug)]
pub(crate) struct Connection {
    pub(crate) listener: Listener,
    /// Peer address as `ip:port`, the input to `whois`.
    pub(crate) remote: String,
    pub(crate) stream: UnixStream,
}

#[derive(Debug)]
pub(crate) enum TailnetError {
    Io(io::Error),
    Protocol(String),
    /// tsgate answered the request with an error.
    Remote(String),
    Timeout,
    Closed,
}

impl fmt::Display for TailnetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "tsgate i/o: {e}"),
            Self::Protocol(e) => write!(f, "tsgate protocol: {e}"),
            Self::Remote(e) => write!(f, "tsgate: {e}"),
            Self::Timeout => f.write_str("tsgate did not answer in time"),
            Self::Closed => f.write_str("tsgate control seam closed"),
        }
    }
}

impl std::error::Error for TailnetError {}

impl From<io::Error> for TailnetError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<nix::Error> for TailnetError {
    fn from(e: nix::Error) -> Self {
        Self::Io(e.into())
    }
}

impl From<wire::WireError> for TailnetError {
    fn from(e: wire::WireError) -> Self {
        Self::Protocol(e.to_string())
    }
}
