use std::fs;
use std::io;
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};

use nix::sys::socket::{setsockopt, sockopt};

const DEFAULT_SOCKET_BUF_SIZE: usize = 7 * 1024 * 1024;
#[cfg(target_os = "macos")]
const SOCKET_SNDBUF: usize = 65_562 - 12;
#[cfg(not(target_os = "macos"))]
const SOCKET_SNDBUF: usize = DEFAULT_SOCKET_BUF_SIZE;

pub(crate) fn open_local_unix_datagram_socket(
    peer_path: &Path,
    vm_id: &str,
    backend: &str,
) -> io::Result<UnixDatagram> {
    let local_path = local_unix_datagram_path(peer_path, vm_id, backend);
    match fs::remove_file(&local_path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let socket = UnixDatagram::bind(&local_path)?;
    socket.connect(peer_path)?;
    if let Err(error) = setsockopt(&socket, sockopt::SndBuf, &SOCKET_SNDBUF) {
        tracing::warn!(%error, "failed to set krun unixgram SO_SNDBUF");
    }
    if let Err(error) = setsockopt(&socket, sockopt::RcvBuf, &DEFAULT_SOCKET_BUF_SIZE) {
        tracing::warn!(%error, "failed to set krun unixgram SO_RCVBUF");
    }
    Ok(socket)
}

fn local_unix_datagram_path(peer_path: &Path, vm_id: &str, backend: &str) -> PathBuf {
    let id = vm_id.get(..12).unwrap_or(vm_id);
    peer_path.with_file_name(format!("{id}-{backend}.sock"))
}

#[cfg(test)]
mod tests {
    use crate::network::local_unix_datagram_path;
    use std::path::Path;

    #[test]
    fn local_socket_names_preserve_short_ids_and_shorten_long_ids() {
        for (id, name) in [
            ("vm123", "vm123-krun.sock"),
            ("1234567890abcdef", "1234567890ab-krun.sock"),
        ] {
            assert_eq!(
                local_unix_datagram_path(Path::new("/tmp/net/peer.sock"), id, "krun"),
                Path::new("/tmp/net").join(name)
            );
        }
    }

    #[test]
    fn non_ascii_ids_are_not_split_inside_a_character() {
        assert_eq!(
            local_unix_datagram_path(Path::new("/tmp/peer.sock"), "12345678901é", "krun"),
            Path::new("/tmp/12345678901é-krun.sock")
        );
    }
}
