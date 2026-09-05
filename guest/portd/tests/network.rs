#![cfg(target_os = "linux")]

//! Real netd -> TAP -> portd -> TCP service coverage, with the real docker-proxy.
//! Run explicitly with SILO_PORTD_TEST_NETD and SILO_PORTD_TEST_DOCKER_PROXY.
//! Each guest runs in disposable user/network/PID namespaces, without Docker
//! DNAT rules. Publication delivery therefore cannot accidentally rely on them.

use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixDatagram;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus};
use std::thread;
use std::time::{Duration, Instant};

use nix::fcntl::{fcntl, FcntlArg, FdFlag, OFlag};
use nix::poll::{poll, PollFd, PollFlags};
use nix::sys::signal::{kill, Signal};
use nix::sys::socket::{
    bind, listen, setsockopt, socket, sockopt, AddressFamily, Backlog, SockFlag, SockType,
    SockaddrStorage,
};
use nix::unistd::{dup2_raw, pipe, Pid};

const GATEWAY: &str = "192.168.127.1";
const GUEST: &str = "192.168.127.2";

#[test]
#[ignore = "requires real netd, docker-proxy, ip, unshare, and /dev/net/tun"]
fn network_publication_lifecycle() {
    if let Some(root) = std::env::var_os("SILO_PORTD_TEST_NAMESPACE") {
        guest(Path::new(&root));
        return;
    }
    let netd = required_path("SILO_PORTD_TEST_NETD");
    let proxy = required_path("SILO_PORTD_TEST_DOCKER_PROXY");
    for mode in ["signal", "hold", "proxy", "stalled", "policy"] {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path();
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut netd = start_netd(
            &netd,
            root,
            if mode == "policy" { "loopback" } else { "any" },
        );
        wait_for(|| root.join("net.sock").exists());
        let mut guest = Process(
            Command::new("unshare")
                .args([
                    "--user",
                    "--map-root-user",
                    "--net",
                    "--pid",
                    "--fork",
                    "--kill-child",
                ])
                .arg(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "network_publication_lifecycle",
                    "--ignored",
                    "--nocapture",
                ])
                .env("SILO_PORTD_TEST_NAMESPACE", root)
                .env("SILO_PORTD_TEST_MODE", mode)
                .env("SILO_PORTD_TEST_DOCKER_PROXY", &proxy)
                .spawn()
                .unwrap(),
        );
        wait_for(|| root.join("ready.json").exists());
        let endpoints: Vec<(SocketAddr, String)> =
            serde_json::from_slice(&std::fs::read(root.join("ready.json")).unwrap()).unwrap();
        let mut idle = Vec::new();
        for (address, label) in &endpoints {
            let mut stream = TcpStream::connect_timeout(address, Duration::from_secs(5)).unwrap();
            configure(&stream);
            let payload = vec![42; 128 * 1024];
            stream.write_all(&payload).unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
            let mut response = Vec::new();
            stream.read_to_end(&mut response).unwrap();
            let mut expected = label.as_bytes().to_vec();
            expected.extend_from_slice(&payload);
            assert_eq!(
                response, expected,
                "{mode}: {address} did not reach {label}"
            );
            let mut stream = TcpStream::connect_timeout(address, Duration::from_secs(5)).unwrap();
            configure(&stream);
            // A reply proves the idle connection is established all the way
            // to the backend before we test cancellation.
            stream.write_all(b"ping").unwrap();
            let mut pong = [0; 4];
            stream.read_exact(&mut pong).unwrap();
            assert_eq!(&pong, b"pong");
            idle.push(stream);
        }
        if mode == "signal" {
            // Healthy idle holds must survive keepalive probes.
            thread::sleep(Duration::from_secs(6));
            for stream in &idle {
                stream.set_nonblocking(true).unwrap();
                assert_eq!(
                    stream.peek(&mut [0]).unwrap_err().kind(),
                    std::io::ErrorKind::WouldBlock
                );
                stream.set_nonblocking(false).unwrap();
            }
        }
        if mode == "hold" {
            netd.0.kill().unwrap();
            netd.wait();
        }
        if mode == "proxy" || mode == "stalled" {
            signal_proxies(
                guest.0.id(),
                &proxy,
                endpoints.len(),
                if mode == "proxy" {
                    Signal::SIGKILL
                } else {
                    Signal::SIGSTOP
                },
            );
        }
        std::fs::write(root.join("stop"), b"").unwrap();
        assert!(guest.wait().success(), "guest checks failed for {mode}");
        for stream in &mut idle {
            assert_eq!(
                stream.read(&mut [0]).unwrap(),
                0,
                "{mode}: active publication survived teardown"
            );
        }
        for (address, _) in endpoints {
            wait_for(|| TcpStream::connect_timeout(&address, Duration::from_millis(100)).is_err());
        }
        eprintln!("qualified {mode}: IPv4/IPv6 targets, loopback/wildcard/dual-stack host binds, active connection cleanup");
    }
}

fn guest(root: &Path) {
    let mode = std::env::var("SILO_PORTD_TEST_MODE").unwrap();
    for args in [
        vec!["link", "set", "lo", "up"],
        vec!["addr", "add", "172.17.0.2/32", "dev", "lo"],
        vec!["-6", "addr", "add", "fd00::2/128", "dev", "lo", "nodad"],
    ] {
        ip(&args);
    }
    let tap = start_tap(root);
    let ipv4 = echo_server("172.17.0.2:0");
    let ipv6 = echo_server("[fd00::2]:0");
    let mut children = Vec::new();
    let mut endpoints = Vec::new();
    for target in [ipv4, ipv6] {
        let mut dual_port = 0;
        for (host, paired) in [
            ("127.0.0.1", false),
            ("::1", false),
            ("::", false),
            ("0.0.0.0", false),
            ("::", true),
        ] {
            let host: IpAddr = host.parse().unwrap();
            if mode == "policy" && host.is_unspecified() {
                continue;
            }
            let listener =
                docker_listener(SocketAddr::new(host, if paired { dual_port } else { 0 }));
            let port = listener.local_addr().unwrap().port();
            if host == IpAddr::V4(Ipv4Addr::UNSPECIFIED) {
                dual_port = port;
            }
            children.push(start_portd(root, host, port, target, listener, "0\n"));
            let client_ip = if host.is_ipv4() {
                IpAddr::V4(Ipv4Addr::LOCALHOST)
            } else {
                IpAddr::V6(Ipv6Addr::LOCALHOST)
            };
            endpoints.push((SocketAddr::new(client_ip, port), target.to_string()));
        }
    }
    // A second owner of an existing host address must fail without retaining
    // its newly allocated ingress or disturbing the original publication.
    let conflicting_port = endpoints[0].0.port();
    let listener = docker_listener("127.0.0.1:0".parse().unwrap());
    let mut rejected = start_portd(
        root,
        Ipv4Addr::LOCALHOST.into(),
        conflicting_port,
        ipv4,
        listener,
        "1\n",
    );
    assert_eq!(rejected.wait().code(), Some(1));
    if mode == "policy" {
        let listener = docker_listener("0.0.0.0:0".parse().unwrap());
        let port = listener.local_addr().unwrap().port();
        let mut denied = start_portd(
            root,
            Ipv4Addr::UNSPECIFIED.into(),
            port,
            ipv4,
            listener,
            "1\n",
        );
        assert_eq!(denied.wait().code(), Some(1));
    }
    let audit = std::fs::read_to_string(root.join("audit.log")).unwrap();
    let denials: Vec<SocketAddr> = audit
        .lines()
        .filter_map(|line| {
            let event: serde_json::Value = serde_json::from_str(line).unwrap();
            if event["phase"] != "denied" {
                return None;
            }
            Some(
                event["publication"]["remote"]
                    .as_str()
                    .unwrap()
                    .parse()
                    .unwrap(),
            )
        })
        .collect();
    assert_eq!(denials.len(), if mode == "policy" { 2 } else { 1 });
    for ingress in denials {
        assert!(
            TcpStream::connect_timeout(&ingress, Duration::from_millis(100)).is_err(),
            "denied publication retained its ingress"
        );
    }
    let ingresses: Vec<SocketAddr> = audit
        .lines()
        .filter_map(|line| {
            let event: serde_json::Value = serde_json::from_str(line).unwrap();
            if event["phase"] != "exposed" {
                return None;
            }
            Some(
                event["publication"]["remote"]
                    .as_str()
                    .unwrap()
                    .parse()
                    .unwrap(),
            )
        })
        .collect();
    assert_eq!(ingresses.len(), endpoints.len());
    for ingress in &ingresses {
        assert_eq!(ingress.ip().to_string(), GUEST);
        let mut unauthorized = TcpStream::connect_timeout(ingress, Duration::from_secs(5)).unwrap();
        configure(&unauthorized);
        assert_eq!(
            unauthorized.read(&mut [0]).unwrap(),
            0,
            "guest-local traffic bypassed gateway restriction"
        );
    }
    std::fs::write(
        root.join("ready.tmp"),
        serde_json::to_vec(&endpoints).unwrap(),
    )
    .unwrap();
    std::fs::rename(root.join("ready.tmp"), root.join("ready.json")).unwrap();
    wait_for(|| root.join("stop").exists());
    if mode == "signal" || mode == "stalled" || mode == "policy" {
        for (index, child) in children.iter().enumerate() {
            signal(
                child.0.id(),
                if mode == "stalled" || index % 2 == 0 {
                    Signal::SIGTERM
                } else {
                    Signal::SIGKILL
                },
            );
        }
    }
    for (index, child) in children.iter_mut().enumerate() {
        let status = child.wait();
        if mode == "hold" {
            assert_eq!(status.code(), Some(1));
        }
        if mode == "proxy" || mode == "stalled" {
            assert_eq!(status.code(), Some(137));
        }
        if (mode == "signal" || mode == "policy") && index % 2 == 0 {
            assert!(status.success());
        }
    }
    assert!(
        !tap.is_finished(),
        "TAP transport failed during qualification"
    );
    for ingress in ingresses {
        assert!(
            TcpStream::connect_timeout(&ingress, Duration::from_millis(100)).is_err(),
            "ingress survived publication teardown"
        );
    }
}

fn start_netd(binary: &Path, root: &Path, bind: &str) -> Process {
    let logs = File::open(root).unwrap();
    let runtime = File::open(root).unwrap();
    let mut command = Command::new(binary);
    command
        .args([
            "--log-dir-fd",
            "3",
            "--runtime-dir-fd",
            "4",
            "--log-file",
            "netd.log",
            "--audit-log-file",
            "audit.log",
            "--vm-id",
            "portd-e2e",
            "--run-id",
            "portd-e2e",
            "--network-id",
            "portd-e2e",
            "--guest-publish",
            bind,
            "--listen-vfkit",
        ])
        .arg(format!("unixgram://{}", root.join("net.sock").display()));
    unsafe {
        command.pre_exec(move || {
            inherit(&logs, 3)?;
            inherit(&runtime, 4)?;
            Ok(())
        });
    }
    Process(command.spawn().unwrap())
}

fn start_portd(
    root: &Path,
    host: IpAddr,
    port: u16,
    target: SocketAddr,
    listener: TcpListener,
    expected_status: &str,
) -> Process {
    let (status_read, status_write) = pipe().unwrap();
    let binary = std::env::var_os("SILO_PORTD_TEST_PORTD")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_silo-portd")));
    let mut command = Command::new(binary);
    command
        .args([
            "-proto",
            "tcp",
            "-host-ip",
            &host.to_string(),
            "-host-port",
            &port.to_string(),
            "-container-ip",
            &target.ip().to_string(),
            "-container-port",
            &target.port().to_string(),
            "-use-listen-fd",
        ])
        .env("SILO_PORTD_ENDPOINT", format!("http://{GATEWAY}:80"))
        .env(
            "SILO_PORTD_DOCKER_PROXY",
            required_path("SILO_PORTD_TEST_DOCKER_PROXY"),
        )
        .stderr(File::create(root.join(format!("portd-{host}-{port}.log"))).unwrap());
    unsafe {
        command.pre_exec(move || {
            inherit(&status_write, 3)?;
            inherit(&listener, 4)?;
            Ok(())
        });
    }
    let child = Process(command.spawn().unwrap());
    drop(command);
    let mut fds = [PollFd::new(status_read.as_fd(), PollFlags::POLLIN)];
    assert!(
        poll(&mut fds, 5000_u16).unwrap() > 0,
        "portd readiness timed out"
    );
    let mut status = String::new();
    BufReader::new(File::from(status_read))
        .read_line(&mut status)
        .unwrap();
    assert_eq!(
        status,
        expected_status,
        "unexpected portd status: {}",
        std::fs::read_to_string(root.join(format!("portd-{host}-{port}.log"))).unwrap()
    );
    child
}

fn inherit(source: &impl AsFd, destination: i32) -> std::io::Result<()> {
    let fd = unsafe { dup2_raw(source, destination)? };
    // dup2 is a no-op when source already has the destination number.
    fcntl(&fd, FcntlArg::F_SETFD(FdFlag::empty()))?;
    std::mem::forget(fd);
    Ok(())
}

fn docker_listener(address: SocketAddr) -> TcpListener {
    let family = if address.is_ipv4() {
        AddressFamily::Inet
    } else {
        AddressFamily::Inet6
    };
    let fd = socket(family, SockType::Stream, SockFlag::SOCK_CLOEXEC, None).unwrap();
    if address.is_ipv6() {
        setsockopt(&fd, sockopt::Ipv6V6Only, &true).unwrap();
    }
    bind(fd.as_raw_fd(), &SockaddrStorage::from(address)).unwrap();
    listen(&fd, Backlog::new(128).unwrap()).unwrap();
    TcpListener::from(fd)
}

fn echo_server(address: &str) -> SocketAddr {
    let listener = TcpListener::bind(address).unwrap();
    let address = listener.local_addr().unwrap();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            thread::spawn(move || {
                configure(&stream);
                let mut first = [0; 4];
                stream.read_exact(&mut first).unwrap();
                if &first == b"ping" {
                    stream.write_all(b"pong").unwrap();
                    stream
                        .set_read_timeout(Some(Duration::from_secs(15)))
                        .unwrap();
                    let _ = stream.read(&mut [0]);
                } else {
                    let mut payload = Vec::new();
                    stream.read_to_end(&mut payload).unwrap();
                    stream.write_all(address.to_string().as_bytes()).unwrap();
                    stream.write_all(&first).unwrap();
                    stream.write_all(&payload).unwrap();
                }
            });
        }
    });
    address
}

fn start_tap(root: &Path) -> thread::JoinHandle<()> {
    // nix supplies the ioctl macro, but no TUNSETIFF wrapper.
    nix::ioctl_write_ptr_bad!(tun_set_iff, 0x400454ca, nix::libc::ifreq);
    let mut tap = File::options()
        .read(true)
        .write(true)
        .open("/dev/net/tun")
        .unwrap();
    let mut request: nix::libc::ifreq = unsafe { std::mem::zeroed() };
    for (destination, source) in request.ifr_name.iter_mut().zip(b"portd0") {
        *destination = *source as nix::libc::c_char;
    }
    request.ifr_ifru.ifru_flags = (nix::libc::IFF_TAP | nix::libc::IFF_NO_PI) as i16;
    unsafe {
        tun_set_iff(tap.as_raw_fd(), &request).unwrap();
    }
    ip(&["link", "set", "portd0", "address", "5a:94:ef:e4:0c:ee"]);
    ip(&["addr", "add", &format!("{GUEST}/24"), "dev", "portd0"]);
    ip(&["link", "set", "portd0", "up"]);
    let socket = UnixDatagram::bind(root.join("guest.sock")).unwrap();
    socket.connect(root.join("net.sock")).unwrap();
    socket.send(b"VFKT").unwrap();
    socket.set_nonblocking(true).unwrap();
    fcntl(&tap, FcntlArg::F_SETFL(OFlag::O_NONBLOCK)).unwrap();
    thread::spawn(move || loop {
        let ready = {
            let mut fds = [
                PollFd::new(tap.as_fd(), PollFlags::POLLIN),
                PollFd::new(socket.as_fd(), PollFlags::POLLIN),
            ];
            poll(&mut fds, 100_u16).unwrap();
            (
                fds[0].revents().unwrap().contains(PollFlags::POLLIN),
                fds[1].revents().unwrap().contains(PollFlags::POLLIN),
            )
        };
        let mut packet = [0; 65536];
        if ready.0 {
            let size = tap.read(&mut packet).unwrap();
            if let Err(error) = socket.send(&packet[..size]) {
                // In the crash case the gateway socket disappears. Keep the
                // TAP alive to model packet loss, not an artificial link reset.
                assert!(matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionRefused
                        | std::io::ErrorKind::NotFound
                        | std::io::ErrorKind::NotConnected
                        | std::io::ErrorKind::WouldBlock
                ));
            }
        }
        if ready.1 {
            let size = socket.recv(&mut packet).unwrap();
            tap.write_all(&packet[..size]).unwrap();
        }
    })
}

fn signal_proxies(guest: u32, proxy: &Path, expected: usize, action: Signal) {
    // Inspect from the outer PID namespace. Mounting a private /proc inside
    // an unprivileged user namespace is restricted on some qualification hosts.
    let mut pending = vec![guest];
    let mut proxies = Vec::new();
    while let Some(pid) = pending.pop() {
        for task in std::fs::read_dir(format!("/proc/{pid}/task")).unwrap() {
            let children = std::fs::read_to_string(task.unwrap().path().join("children")).unwrap();
            pending.extend(
                children
                    .split_whitespace()
                    .map(|pid| pid.parse::<u32>().unwrap()),
            );
        }
        if std::fs::read_link(format!("/proc/{pid}/exe")).unwrap() == proxy {
            proxies.push(pid);
        }
    }
    assert_eq!(
        proxies.len(),
        expected,
        "expected one real docker-proxy per publication"
    );
    for pid in proxies {
        signal(pid, action);
    }
}

fn configure(stream: &TcpStream) {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
}

fn required_path(name: &str) -> PathBuf {
    std::env::var_os(name)
        .map(PathBuf::from)
        .unwrap_or_else(|| panic!("{name} is required"))
        .canonicalize()
        .unwrap()
}

fn ip(args: &[&str]) {
    assert!(Command::new("ip").args(args).status().unwrap().success());
}

fn signal(pid: u32, signal: Signal) {
    kill(Pid::from_raw(i32::try_from(pid).unwrap()), signal).unwrap();
}

fn wait_for(condition: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while !condition() {
        assert!(
            Instant::now() < deadline,
            "timed out waiting for network lifecycle transition"
        );
        thread::sleep(Duration::from_millis(20));
    }
}

struct Process(Child);

impl Process {
    fn wait(&mut self) -> ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = self.0.try_wait().unwrap() {
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "child {} did not exit",
                self.0.id()
            );
            thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}
