use std::fs;
use std::io;
use std::os::fd::IntoRawFd;
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};

use nix::sys::socket::{setsockopt, sockopt};
use objc2::{rc::Retained, AllocAnyThread, ClassType};
use objc2_foundation::{NSFileHandle, NSString};
use objc2_virtualization::{
    VZFileHandleNetworkDeviceAttachment, VZMACAddress, VZNATNetworkDeviceAttachment,
    VZNetworkDeviceConfiguration, VZVirtioNetworkDeviceConfiguration,
};
use utils::format_mac;

use crate::error::VzError;

const LOCAL_SOCKET_ID_LEN: usize = 12;
const VNET_HDR_LEN: usize = 12;
const MAX_BUFFER_SIZE: usize = 65_562;
const SOCKET_SNDBUF: usize = MAX_BUFFER_SIZE - VNET_HDR_LEN;
const SOCKET_RCVBUF: usize = 7 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct NetworkDeviceConfiguration {
    inner: Retained<VZVirtioNetworkDeviceConfiguration>,
}

impl NetworkDeviceConfiguration {
    pub fn nat() -> Self {
        unsafe {
            let inner = VZVirtioNetworkDeviceConfiguration::new();
            let attachment = VZNATNetworkDeviceAttachment::new();
            inner.setAttachment(Some(attachment.as_super()));
            Self { inner }
        }
    }

    pub fn unix_datagram_file_handle(
        socket: impl IntoRawFd,
        mac: [u8; 6],
    ) -> Result<Self, VzError> {
        unsafe {
            let file_handle = NSFileHandle::initWithFileDescriptor_closeOnDealloc(
                NSFileHandle::alloc(),
                socket.into_raw_fd(),
                true,
            );
            let attachment = VZFileHandleNetworkDeviceAttachment::initWithFileHandle(
                VZFileHandleNetworkDeviceAttachment::alloc(),
                &file_handle,
            );
            let inner = VZVirtioNetworkDeviceConfiguration::new();
            set_mac_address(&inner, mac)?;
            inner.setAttachment(Some(attachment.as_super()));
            Ok(Self { inner })
        }
    }

    pub fn unix_datagram(peer_path: &Path, vm_id: &str, mac: [u8; 6]) -> Result<Self, VzError> {
        let socket = open_local_unix_datagram_socket(peer_path, vm_id, "vz")?;
        Self::unix_datagram_file_handle(socket, mac)
    }

    pub(crate) fn as_inner(&self) -> &VZNetworkDeviceConfiguration {
        self.inner.as_super()
    }
}

fn open_local_unix_datagram_socket(
    peer_path: &Path,
    vm_id: &str,
    backend: &str,
) -> Result<UnixDatagram, VzError> {
    let local_path = local_unix_datagram_path(peer_path, vm_id, backend);
    remove_file_if_exists(&local_path)?;
    let socket = UnixDatagram::bind(&local_path).map_err(VzError::from)?;
    socket.connect(peer_path).map_err(VzError::from)?;
    configure_socket_buffers(&socket)?;
    Ok(socket)
}

fn configure_socket_buffers(socket: &UnixDatagram) -> Result<(), VzError> {
    setsockopt(socket, sockopt::SndBuf, &SOCKET_SNDBUF).map_err(io_error)?;
    setsockopt(socket, sockopt::RcvBuf, &SOCKET_RCVBUF).map_err(io_error)?;
    Ok(())
}

unsafe fn set_mac_address(
    inner: &VZVirtioNetworkDeviceConfiguration,
    mac: [u8; 6],
) -> Result<(), VzError> {
    let mac_string = NSString::from_str(&format_mac(mac));
    let mac_address = VZMACAddress::initWithString(VZMACAddress::alloc(), &mac_string)
        .ok_or_else(|| VzError::Backend(format!("invalid MAC address: {}", format_mac(mac))))?;
    inner.setMACAddress(&mac_address);
    Ok(())
}

fn io_error(err: nix::errno::Errno) -> VzError {
    VzError::from(io::Error::from_raw_os_error(err as i32))
}

fn local_unix_datagram_path(peer_path: &Path, vm_id: &str, backend: &str) -> PathBuf {
    peer_path.with_file_name(format!("{}-{backend}.sock", local_socket_id(vm_id)))
}

fn local_socket_id(vm_id: &str) -> &str {
    vm_id.get(..LOCAL_SOCKET_ID_LEN).unwrap_or(vm_id)
}

fn remove_file_if_exists(path: &Path) -> Result<(), VzError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(VzError::from(err)),
    }
}

#[cfg(test)]
mod tests {
    use super::local_unix_datagram_path;
    use std::path::Path;
    use utils::format_mac;

    #[test]
    fn local_unix_datagram_path_uses_vm_id_and_backend() {
        assert_eq!(
            local_unix_datagram_path(
                Path::new("/tmp/bento-net/gvproxy.sock"),
                "1234567890abcdef",
                "vz"
            ),
            Path::new("/tmp/bento-net/1234567890ab-vz.sock")
        );
    }

    #[test]
    fn local_unix_datagram_path_keeps_short_vm_id() {
        assert_eq!(
            local_unix_datagram_path(Path::new("/tmp/bento-net/gvproxy.sock"), "vm123", "vz"),
            Path::new("/tmp/bento-net/vm123-vz.sock")
        );
    }

    #[test]
    fn format_mac_uses_colon_separated_lower_hex() {
        assert_eq!(
            format_mac([0x02, 0xb2, 0xe4, 0x04, 0xd2, 0xcc]),
            "02:b2:e4:04:d2:cc"
        );
    }
}
