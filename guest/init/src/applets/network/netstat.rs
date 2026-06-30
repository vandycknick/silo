//! netstat - print network connections
//!
//! Adapted from Armybox `src/applets/network/netstat.rs`.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use crate::io;
use crate::sys;

use super::get_arg;

const TCP_ESTABLISHED: u8 = 1;
const TCP_SYN_SENT: u8 = 2;
const TCP_SYN_RECV: u8 = 3;
const TCP_FIN_WAIT1: u8 = 4;
const TCP_FIN_WAIT2: u8 = 5;
const TCP_TIME_WAIT: u8 = 6;
const TCP_CLOSE: u8 = 7;
const TCP_CLOSE_WAIT: u8 = 8;
const TCP_LAST_ACK: u8 = 9;
const TCP_LISTEN: u8 = 10;
const TCP_CLOSING: u8 = 11;

pub fn netstat(argc: i32, argv: *const *const u8) -> i32 {
    let mut show_tcp = false;
    let mut show_udp = false;
    let mut show_listening = false;
    let mut show_all = false;
    let mut numeric = false;
    let mut show_pid = false;
    let mut show_routes = false;
    let mut show_interfaces = false;

    let mut i = 1;
    while i < argc {
        if let Some(arg) = unsafe { get_arg(argv, i) } {
            if arg == b"-t" || arg == b"--tcp" {
                show_tcp = true;
            } else if arg == b"-u" || arg == b"--udp" {
                show_udp = true;
            } else if arg == b"-l" || arg == b"--listening" {
                show_listening = true;
            } else if arg == b"-a" || arg == b"--all" {
                show_all = true;
            } else if arg == b"-n" || arg == b"--numeric" {
                numeric = true;
            } else if arg == b"-p" || arg == b"--programs" {
                show_pid = true;
            } else if arg == b"-r" || arg == b"--route" {
                show_routes = true;
            } else if arg == b"-i" || arg == b"--interfaces" {
                show_interfaces = true;
            } else if arg == b"-h" || arg == b"--help" {
                print_help();
                return 0;
            } else if arg.starts_with(b"-") {
                for &c in &arg[1..] {
                    match c {
                        b't' => show_tcp = true,
                        b'u' => show_udp = true,
                        b'l' => show_listening = true,
                        b'a' => show_all = true,
                        b'n' => numeric = true,
                        b'p' => show_pid = true,
                        b'r' => show_routes = true,
                        b'i' => show_interfaces = true,
                        _ => {}
                    }
                }
            }
        }
        i += 1;
    }

    if !show_tcp && !show_udp && !show_routes && !show_interfaces {
        show_tcp = true;
        show_udp = true;
    }

    if show_routes {
        show_routing_table();
        return 0;
    }

    if show_interfaces {
        show_interface_stats();
        return 0;
    }

    io::write(io::STDOUT, "Active Internet connections");
    if show_listening && !show_all {
        io::write(io::STDOUT, " (only servers)");
    } else if show_all {
        io::write(io::STDOUT, " (servers and established)");
    } else {
        io::write(io::STDOUT, " (w/o servers)");
    }
    io::write(io::STDOUT, "\n");

    if show_pid {
        io::write(
            io::STDOUT,
            "Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program\n",
        );
    } else {
        io::write(
            io::STDOUT,
            "Proto Recv-Q Send-Q Local Address           Foreign Address         State\n",
        );
    }

    if show_tcp {
        show_tcp_connections(show_listening, show_all, numeric, show_pid, false);
        show_tcp_connections(show_listening, show_all, numeric, show_pid, true);
    }

    if show_udp {
        show_udp_connections(show_listening, show_all, numeric, show_pid, false);
        show_udp_connections(show_listening, show_all, numeric, show_pid, true);
    }

    0
}

fn show_tcp_connections(
    listening_only: bool,
    show_all: bool,
    numeric: bool,
    show_pid: bool,
    ipv6: bool,
) {
    let path = if ipv6 {
        b"/proc/net/tcp6" as &[u8]
    } else {
        b"/proc/net/tcp"
    };
    let proto = if ipv6 { b"tcp6  " } else { b"tcp   " };

    let fd = io::open(path, libc::O_RDONLY, 0);
    if fd < 0 {
        return;
    }

    let content = io::read_all(fd);
    io::close(fd);

    for (i, line) in content.split(|&c| c == b'\n').enumerate() {
        if i == 0 || line.is_empty() {
            continue;
        }

        if let Some(entry) = parse_tcp_entry(line, ipv6) {
            if listening_only && entry.state != TCP_LISTEN {
                continue;
            }
            if !show_all && !listening_only && entry.state == TCP_LISTEN {
                continue;
            }

            print_connection(proto, &entry, numeric, show_pid);
        }
    }
}

fn show_udp_connections(
    listening_only: bool,
    show_all: bool,
    numeric: bool,
    show_pid: bool,
    ipv6: bool,
) {
    let path = if ipv6 {
        b"/proc/net/udp6" as &[u8]
    } else {
        b"/proc/net/udp"
    };
    let proto = if ipv6 { b"udp6  " } else { b"udp   " };

    let fd = io::open(path, libc::O_RDONLY, 0);
    if fd < 0 {
        return;
    }

    let content = io::read_all(fd);
    io::close(fd);

    for (i, line) in content.split(|&c| c == b'\n').enumerate() {
        if i == 0 || line.is_empty() {
            continue;
        }

        if let Some(entry) = parse_udp_entry(line, ipv6) {
            let is_listening = entry.remote_port == 0;

            if listening_only && !is_listening {
                continue;
            }
            if !show_all && !listening_only && is_listening {
                continue;
            }

            print_connection(proto, &entry, numeric, show_pid);
        }
    }
}

struct NetEntry {
    local_addr: u32,
    local_addr6: [u8; 16],
    local_port: u16,
    remote_addr: u32,
    remote_addr6: [u8; 16],
    remote_port: u16,
    state: u8,
    inode: u64,
    recv_q: u32,
    send_q: u32,
    is_ipv6: bool,
}

fn parse_tcp_entry(line: &[u8], ipv6: bool) -> Option<NetEntry> {
    let fields: Vec<&[u8]> = line
        .split(|&c| c == b' ')
        .filter(|s| !s.is_empty())
        .collect();

    if fields.len() < 10 {
        return None;
    }

    let (local_addr, local_addr6, local_port) = parse_addr_port(fields[1], ipv6)?;
    let (remote_addr, remote_addr6, remote_port) = parse_addr_port(fields[2], ipv6)?;
    let state = parse_hex_u8(fields[3])?;
    let (send_q, recv_q) = parse_queue(fields[4])?;
    let inode = if fields.len() > 9 {
        sys::parse_u64(fields[9]).unwrap_or(0)
    } else {
        0
    };

    Some(NetEntry {
        local_addr,
        local_addr6,
        local_port,
        remote_addr,
        remote_addr6,
        remote_port,
        state,
        inode,
        recv_q,
        send_q,
        is_ipv6: ipv6,
    })
}

fn parse_udp_entry(line: &[u8], ipv6: bool) -> Option<NetEntry> {
    parse_tcp_entry(line, ipv6)
}

fn parse_addr_port(s: &[u8], ipv6: bool) -> Option<(u32, [u8; 16], u16)> {
    let colon = s.iter().position(|&c| c == b':')?;
    let addr_hex = &s[..colon];
    let port_hex = &s[colon + 1..];

    let port = parse_hex_u16(port_hex)?;

    if ipv6 {
        let addr6 = parse_ipv6_addr(addr_hex)?;
        Some((0, addr6, port))
    } else {
        let addr = parse_hex_u32(addr_hex)?;
        Some((addr, [0u8; 16], port))
    }
}

fn parse_queue(s: &[u8]) -> Option<(u32, u32)> {
    let colon = s.iter().position(|&c| c == b':')?;
    let tx = parse_hex_u32(&s[..colon])?;
    let rx = parse_hex_u32(&s[colon + 1..])?;
    Some((tx, rx))
}

fn parse_hex_u8(s: &[u8]) -> Option<u8> {
    parse_hex_u32(s).map(|v| v as u8)
}

fn parse_hex_u16(s: &[u8]) -> Option<u16> {
    parse_hex_u32(s).map(|v| v as u16)
}

fn parse_hex_u32(s: &[u8]) -> Option<u32> {
    let mut result: u32 = 0;
    for &c in s {
        let digit = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => return None,
        };
        result = result.wrapping_mul(16).wrapping_add(digit as u32);
    }
    Some(result)
}

fn parse_ipv6_addr(s: &[u8]) -> Option<[u8; 16]> {
    if s.len() != 32 {
        return None;
    }
    let mut addr = [0u8; 16];
    for i in 0..16 {
        addr[i] = parse_hex_u8(&s[i * 2..i * 2 + 2])?;
    }
    Some(addr)
}

fn print_connection(proto: &[u8], entry: &NetEntry, numeric: bool, show_pid: bool) {
    io::write_buf(io::STDOUT, proto);

    let mut buf = [0u8; 16];
    let recv = sys::format_u64(entry.recv_q as u64, &mut buf);
    for _ in recv.len()..6 {
        io::write(io::STDOUT, " ");
    }
    io::write_buf(io::STDOUT, recv);
    io::write(io::STDOUT, " ");

    let send = sys::format_u64(entry.send_q as u64, &mut buf);
    for _ in send.len()..6 {
        io::write(io::STDOUT, " ");
    }
    io::write_buf(io::STDOUT, send);
    io::write(io::STDOUT, " ");

    let local = format_addr(
        entry.local_addr,
        &entry.local_addr6,
        entry.local_port,
        entry.is_ipv6,
        numeric,
    );
    io::write_buf(io::STDOUT, local.as_bytes());
    for _ in local.len()..24 {
        io::write(io::STDOUT, " ");
    }

    let remote = format_addr(
        entry.remote_addr,
        &entry.remote_addr6,
        entry.remote_port,
        entry.is_ipv6,
        numeric,
    );
    io::write_buf(io::STDOUT, remote.as_bytes());
    for _ in remote.len()..24 {
        io::write(io::STDOUT, " ");
    }

    let state_str = tcp_state_name(entry.state);
    io::write_buf(io::STDOUT, state_str);

    if show_pid && entry.inode > 0 {
        io::write(io::STDOUT, "    ");
        if let Some((pid, name)) = find_process_by_inode(entry.inode) {
            let pid_str = sys::format_u64(pid, &mut buf);
            io::write_buf(io::STDOUT, pid_str);
            io::write(io::STDOUT, "/");
            io::write_buf(io::STDOUT, name.as_bytes());
        } else {
            io::write(io::STDOUT, "-");
        }
    }

    io::write(io::STDOUT, "\n");
}

fn format_addr(addr: u32, addr6: &[u8; 16], port: u16, ipv6: bool, numeric: bool) -> String {
    let _ = numeric;
    let mut result = String::new();

    if ipv6 {
        if addr6.iter().all(|&b| b == 0) {
            result.push_str("::");
        } else if addr6[..10].iter().all(|&b| b == 0) && addr6[10] == 0xff && addr6[11] == 0xff {
            result.push_str("::ffff:");
            format_ipv4(
                &mut result,
                u32::from_be_bytes([addr6[12], addr6[13], addr6[14], addr6[15]]),
            );
        } else {
            format_ipv6(&mut result, addr6);
        }
    } else if addr == 0 {
        result.push_str("0.0.0.0");
    } else {
        format_ipv4(&mut result, addr);
    }

    result.push(':');

    if port == 0 {
        result.push('*');
    } else {
        let mut buf = [0u8; 8];
        let port_str = sys::format_u64(port as u64, &mut buf);
        for &b in port_str {
            result.push(b as char);
        }
    }

    result
}

fn format_ipv4(result: &mut String, addr: u32) {
    let bytes = addr.to_le_bytes();
    let mut buf = [0u8; 8];

    let s = sys::format_u64(bytes[0] as u64, &mut buf);
    for &b in s {
        result.push(b as char);
    }
    result.push('.');

    let s = sys::format_u64(bytes[1] as u64, &mut buf);
    for &b in s {
        result.push(b as char);
    }
    result.push('.');

    let s = sys::format_u64(bytes[2] as u64, &mut buf);
    for &b in s {
        result.push(b as char);
    }
    result.push('.');

    let s = sys::format_u64(bytes[3] as u64, &mut buf);
    for &b in s {
        result.push(b as char);
    }
}

fn format_ipv6(result: &mut String, addr: &[u8; 16]) {
    for i in 0..8 {
        if i > 0 {
            result.push(':');
        }
        let val = ((addr[i * 2] as u16) << 8) | (addr[i * 2 + 1] as u16);
        let mut buf = [0u8; 8];
        let s = sys::format_hex(val as u64, &mut buf);
        for &b in s {
            result.push(b as char);
        }
    }
}

fn tcp_state_name(state: u8) -> &'static [u8] {
    match state {
        TCP_ESTABLISHED => b"ESTABLISHED",
        TCP_SYN_SENT => b"SYN_SENT",
        TCP_SYN_RECV => b"SYN_RECV",
        TCP_FIN_WAIT1 => b"FIN_WAIT1",
        TCP_FIN_WAIT2 => b"FIN_WAIT2",
        TCP_TIME_WAIT => b"TIME_WAIT",
        TCP_CLOSE => b"CLOSE",
        TCP_CLOSE_WAIT => b"CLOSE_WAIT",
        TCP_LAST_ACK => b"LAST_ACK",
        TCP_LISTEN => b"LISTEN",
        TCP_CLOSING => b"CLOSING",
        _ => b"UNKNOWN",
    }
}

fn find_process_by_inode(inode: u64) -> Option<(u64, String)> {
    let proc_dir = io::opendir(b"/proc");
    if proc_dir.is_null() {
        return None;
    }

    let mut result = None;
    let mut socket_prefix = Vec::new();
    socket_prefix.extend_from_slice(b"socket:[");
    let mut num_buf = [0u8; 24];
    let inode_str = sys::format_u64(inode, &mut num_buf);
    socket_prefix.extend_from_slice(inode_str);
    socket_prefix.push(b']');

    loop {
        let entry = io::readdir(proc_dir);
        if entry.is_null() {
            break;
        }

        let name = dirent_name(entry);
        if name.iter().all(u8::is_ascii_digit) {
            let pid = sys::parse_u64(name).unwrap_or(0);

            let mut fd_path = Vec::new();
            fd_path.extend_from_slice(b"/proc/");
            fd_path.extend_from_slice(name);
            fd_path.extend_from_slice(b"/fd");

            let fd_dir = io::opendir(&fd_path);
            if !fd_dir.is_null() {
                loop {
                    let fd_entry = io::readdir(fd_dir);
                    if fd_entry.is_null() {
                        break;
                    }

                    let fd_name = dirent_name(fd_entry);
                    if fd_name == b"." || fd_name == b".." {
                        continue;
                    }

                    let mut link_path = fd_path.clone();
                    link_path.push(b'/');
                    link_path.extend_from_slice(fd_name);

                    let mut link_buf = [0u8; 128];
                    let n = io::readlink(&link_path, &mut link_buf);
                    if n > 0 {
                        let link = &link_buf[..n as usize];
                        if link == socket_prefix.as_slice() {
                            let mut comm_path = Vec::new();
                            comm_path.extend_from_slice(b"/proc/");
                            comm_path.extend_from_slice(name);
                            comm_path.extend_from_slice(b"/comm");

                            let comm_fd = io::open(&comm_path, libc::O_RDONLY, 0);
                            let proc_name = if comm_fd >= 0 {
                                let mut buf = [0u8; 64];
                                let n = io::read(comm_fd, &mut buf);
                                io::close(comm_fd);
                                if n > 0 {
                                    let end = buf[..n as usize]
                                        .iter()
                                        .position(|&c| c == b'\n' || c == 0)
                                        .unwrap_or(n as usize);
                                    let mut s = String::new();
                                    for &b in &buf[..end] {
                                        s.push(if b.is_ascii() { b as char } else { '?' });
                                    }
                                    s
                                } else {
                                    String::from("-")
                                }
                            } else {
                                String::from("-")
                            };

                            result = Some((pid, proc_name));
                            break;
                        }
                    }
                }
                io::closedir(fd_dir);
            }

            if result.is_some() {
                break;
            }
        }
    }

    io::closedir(proc_dir);
    result
}

fn show_routing_table() {
    io::write(io::STDOUT, "Kernel IP routing table\n");
    io::write(
        io::STDOUT,
        "Destination     Gateway         Genmask         Flags Metric Ref    Use Iface\n",
    );

    let fd = io::open(b"/proc/net/route", libc::O_RDONLY, 0);
    if fd < 0 {
        return;
    }

    let content = io::read_all(fd);
    io::close(fd);

    for (i, line) in content.split(|&c| c == b'\n').enumerate() {
        if i == 0 || line.is_empty() {
            continue;
        }

        let fields: Vec<&[u8]> = line
            .split(|&c| c == b'\t')
            .filter(|s| !s.is_empty())
            .collect();

        if fields.len() < 8 {
            continue;
        }

        let iface = fields[0];
        let dest = parse_hex_u32(fields[1]).unwrap_or(0);
        let gateway = parse_hex_u32(fields[2]).unwrap_or(0);
        let flags = parse_hex_u32(fields[3]).unwrap_or(0);
        let metric = sys::parse_u64(fields[6]).unwrap_or(0);
        let mask = parse_hex_u32(fields[7]).unwrap_or(0);

        let dest_str = format_route_addr(dest);
        io::write_buf(io::STDOUT, dest_str.as_bytes());
        for _ in dest_str.len()..16 {
            io::write(io::STDOUT, " ");
        }

        let gw_str = format_route_addr(gateway);
        io::write_buf(io::STDOUT, gw_str.as_bytes());
        for _ in gw_str.len()..16 {
            io::write(io::STDOUT, " ");
        }

        let mask_str = format_route_addr(mask);
        io::write_buf(io::STDOUT, mask_str.as_bytes());
        for _ in mask_str.len()..16 {
            io::write(io::STDOUT, " ");
        }

        let mut flag_str = Vec::new();
        if flags & 0x01 != 0 {
            flag_str.push(b'U');
        }
        if flags & 0x02 != 0 {
            flag_str.push(b'G');
        }
        if flags & 0x04 != 0 {
            flag_str.push(b'H');
        }
        if flag_str.is_empty() {
            flag_str.push(b'-');
        }
        io::write_buf(io::STDOUT, &flag_str);
        for _ in flag_str.len()..6 {
            io::write(io::STDOUT, " ");
        }

        let mut buf = [0u8; 16];
        let m = sys::format_u64(metric, &mut buf);
        io::write_buf(io::STDOUT, m);
        for _ in m.len()..7 {
            io::write(io::STDOUT, " ");
        }

        io::write(io::STDOUT, "0      0 ");
        io::write_buf(io::STDOUT, iface);
        io::write(io::STDOUT, "\n");
    }
}

fn format_route_addr(addr: u32) -> String {
    if addr == 0 {
        return String::from("0.0.0.0");
    }

    let bytes = addr.to_le_bytes();
    let mut result = String::new();
    let mut buf = [0u8; 8];

    let s = sys::format_u64(bytes[0] as u64, &mut buf);
    for &b in s {
        result.push(b as char);
    }
    result.push('.');
    let s = sys::format_u64(bytes[1] as u64, &mut buf);
    for &b in s {
        result.push(b as char);
    }
    result.push('.');
    let s = sys::format_u64(bytes[2] as u64, &mut buf);
    for &b in s {
        result.push(b as char);
    }
    result.push('.');
    let s = sys::format_u64(bytes[3] as u64, &mut buf);
    for &b in s {
        result.push(b as char);
    }

    result
}

fn show_interface_stats() {
    io::write(io::STDOUT, "Kernel Interface table\n");
    io::write(
        io::STDOUT,
        "Iface      MTU    RX-OK RX-ERR RX-DRP RX-OVR    TX-OK TX-ERR TX-DRP TX-OVR Flg\n",
    );

    let fd = io::open(b"/proc/net/dev", libc::O_RDONLY, 0);
    if fd < 0 {
        return;
    }

    let content = io::read_all(fd);
    io::close(fd);

    for (i, line) in content.split(|&c| c == b'\n').enumerate() {
        if i < 2 || line.is_empty() {
            continue;
        }

        if let Some(colon) = line.iter().position(|&c| c == b':') {
            let iface = &line[..colon];
            let iface_trimmed = iface
                .iter()
                .skip_while(|&&c| c == b' ')
                .copied()
                .collect::<Vec<u8>>();

            let stats = &line[colon + 1..];
            let fields: Vec<u64> = stats
                .split(|&c| c == b' ')
                .filter(|s| !s.is_empty())
                .filter_map(sys::parse_u64)
                .collect();

            if fields.len() >= 16 {
                io::write_buf(io::STDOUT, &iface_trimmed);
                for _ in iface_trimmed.len()..11 {
                    io::write(io::STDOUT, " ");
                }

                let mut mtu_path = Vec::new();
                mtu_path.extend_from_slice(b"/sys/class/net/");
                mtu_path.extend_from_slice(&iface_trimmed);
                mtu_path.extend_from_slice(b"/mtu");

                let mtu = read_sysfs_value(&mtu_path).unwrap_or(0);
                let mut buf = [0u8; 16];
                let m = sys::format_u64(mtu, &mut buf);
                io::write_buf(io::STDOUT, m);
                for _ in m.len()..7 {
                    io::write(io::STDOUT, " ");
                }

                let rx_ok = sys::format_u64(fields[1], &mut buf);
                io::write_buf(io::STDOUT, rx_ok);
                for _ in rx_ok.len()..6 {
                    io::write(io::STDOUT, " ");
                }

                let rx_err = sys::format_u64(fields[2], &mut buf);
                io::write_buf(io::STDOUT, rx_err);
                for _ in rx_err.len()..7 {
                    io::write(io::STDOUT, " ");
                }

                let rx_drp = sys::format_u64(fields[3], &mut buf);
                io::write_buf(io::STDOUT, rx_drp);
                for _ in rx_drp.len()..7 {
                    io::write(io::STDOUT, " ");
                }

                let rx_ovr = sys::format_u64(fields[4], &mut buf);
                io::write_buf(io::STDOUT, rx_ovr);
                for _ in rx_ovr.len()..10 {
                    io::write(io::STDOUT, " ");
                }

                let tx_ok = sys::format_u64(fields[9], &mut buf);
                io::write_buf(io::STDOUT, tx_ok);
                for _ in tx_ok.len()..7 {
                    io::write(io::STDOUT, " ");
                }

                let tx_err = sys::format_u64(fields[10], &mut buf);
                io::write_buf(io::STDOUT, tx_err);
                for _ in tx_err.len()..7 {
                    io::write(io::STDOUT, " ");
                }

                let tx_drp = sys::format_u64(fields[11], &mut buf);
                io::write_buf(io::STDOUT, tx_drp);
                for _ in tx_drp.len()..7 {
                    io::write(io::STDOUT, " ");
                }

                let tx_ovr = sys::format_u64(fields[12], &mut buf);
                io::write_buf(io::STDOUT, tx_ovr);
                for _ in tx_ovr.len()..5 {
                    io::write(io::STDOUT, " ");
                }

                io::write(io::STDOUT, "BMRU\n");
            }
        }
    }
}

fn read_sysfs_value(path: &[u8]) -> Option<u64> {
    let fd = io::open(path, libc::O_RDONLY, 0);
    if fd < 0 {
        return None;
    }
    let mut buf = [0u8; 32];
    let n = io::read(fd, &mut buf);
    io::close(fd);

    if n <= 0 {
        return None;
    }

    let end = buf[..n as usize]
        .iter()
        .position(|&c| c == b'\n' || c == 0)
        .unwrap_or(n as usize);

    sys::parse_u64(&buf[..end])
}

fn print_help() {
    io::write(io::STDOUT, "Usage: netstat [OPTIONS]\n\n");
    io::write(
        io::STDOUT,
        "Display network connections, routing tables, interface statistics.\n\n",
    );
    io::write(io::STDOUT, "Options:\n");
    io::write(io::STDOUT, "  -t, --tcp         Show TCP connections\n");
    io::write(io::STDOUT, "  -u, --udp         Show UDP connections\n");
    io::write(
        io::STDOUT,
        "  -l, --listening   Show only listening sockets\n",
    );
    io::write(io::STDOUT, "  -a, --all         Show all sockets\n");
    io::write(io::STDOUT, "  -n, --numeric     Show numerical addresses\n");
    io::write(io::STDOUT, "  -p, --programs    Show PID/program name\n");
    io::write(io::STDOUT, "  -r, --route       Show routing table\n");
    io::write(
        io::STDOUT,
        "  -i, --interfaces  Show interface statistics\n",
    );
    io::write(io::STDOUT, "  -h, --help        Show this help\n");
}

fn dirent_name(entry: *mut libc::dirent) -> &'static [u8] {
    let ptr = unsafe { (*entry).d_name.as_ptr().cast::<u8>() };
    let len = io::strlen(ptr);
    unsafe { core::slice::from_raw_parts(ptr, len) }
}
