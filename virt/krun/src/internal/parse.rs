use std::path::PathBuf;

use krun::{Disk, Mount, VsockPort};
use utils::parse_mac;

pub(crate) fn disk(input: &str) -> Result<Disk, String> {
    let parts: Vec<&str> = input.split(':').collect();
    if parts.len() != 3 {
        return Err("expected BLOCK_ID:PATH:ro|rw".to_string());
    }
    Ok(Disk {
        block_id: parts[0].to_string(),
        path: PathBuf::from(parts[1]),
        read_only: read_only(parts[2])?,
    })
}

pub(crate) fn mount(input: &str) -> Result<Mount, String> {
    let parts: Vec<&str> = input.split(':').collect();
    if parts.len() != 3 {
        return Err("expected TAG:PATH:ro|rw".to_string());
    }
    Ok(Mount {
        tag: parts[0].to_string(),
        path: PathBuf::from(parts[1]),
        read_only: read_only(parts[2])?,
    })
}

pub(crate) fn vsock_port(input: &str) -> Result<VsockPort, String> {
    let parts: Vec<&str> = input.split(':').collect();
    if parts.len() != 3 {
        return Err("expected PORT:PATH:connect|listen".to_string());
    }
    let port = parts[0]
        .parse::<u32>()
        .map_err(|err| format!("invalid port: {err}"))?;
    let listen = match parts[2] {
        "connect" => true,
        "listen" => false,
        other => return Err(format!("invalid vsock direction {other:?}")),
    };
    Ok(VsockPort {
        port,
        path: PathBuf::from(parts[1]),
        listen,
    })
}

pub(crate) fn mac(input: &str) -> Result<[u8; 6], String> {
    parse_mac(input)
}

fn read_only(input: &str) -> Result<bool, String> {
    match input {
        "ro" => Ok(true),
        "rw" => Ok(false),
        other => Err(format!("invalid mode {other:?}, expected ro or rw")),
    }
}

#[cfg(test)]
mod tests {
    use crate::parse::{disk, mac, vsock_port};

    #[test]
    fn parses_disk_arg() {
        let disk = disk("root:/tmp/root.img:rw").expect("valid disk");
        assert_eq!(disk.block_id, "root");
        assert!(!disk.read_only);
    }

    #[test]
    fn parses_vsock_direction_for_libkrun() {
        let connect = vsock_port("1027:/tmp/agent.sock:connect").expect("valid port");
        let listen = vsock_port("2000:/tmp/shell.sock:listen").expect("valid port");
        assert!(connect.listen);
        assert!(!listen.listen);
    }

    #[test]
    fn parses_network_mac() {
        assert_eq!(
            mac("02:94:ef:e4:0c:ee"),
            Ok([0x02, 0x94, 0xef, 0xe4, 0x0c, 0xee])
        );
        assert!(mac("").is_err());
    }
}
