#![cfg(target_os = "linux")]

use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::sync::mpsc;
use std::time::Duration;

use nix::sys::signal::{kill, Signal};
use nix::unistd::{dup2_raw, pipe, Pid};

#[test]
fn unsupported_protocol_reports_failure_through_docker_status_pipe() {
    let (status_read, status_write) = pipe().expect("create status pipe");
    let mut command = Command::new(env!("CARGO_BIN_EXE_silo-portd"));
    command.args([
        "-proto",
        "udp",
        "-host-ip",
        "0.0.0.0",
        "-host-port",
        "53",
        "-container-ip",
        "172.17.0.2",
        "-container-port",
        "53",
    ]);
    unsafe {
        command.pre_exec(move || {
            let status_fd = dup2_raw(&status_write, 3).map_err(std::io::Error::other)?;
            std::mem::forget(status_fd);
            Ok(())
        });
    }
    let exit = command.status().expect("run silo-portd");
    drop(command);
    let mut status = String::new();
    File::from(status_read)
        .read_to_string(&mut status)
        .expect("read status pipe");

    assert_eq!(exit.code(), Some(1));
    assert_eq!(status, "1\nsilo-portd: udp publication is not supported");
}

#[test]
fn holds_publication_and_forwards_stop_signal_to_proxy() {
    let temporary = tempfile::tempdir().expect("create tempdir");
    let signal_path = temporary.path().join("signal-received");
    let proxy_path = temporary.path().join("docker-proxy-fixture");
    std::fs::write(
        &proxy_path,
        "#!/bin/sh\ntrap 'printf term > \"$SILO_PORTD_TEST_SIGNAL_FILE\"; exit 0' INT TERM\nif [ ! -e /proc/self/fd/4 ]; then printf '1\\nmissing fd 4' >&3; exit 1; fi\nprintf '0\\n' >&3\nwhile :; do sleep 1; done\n",
    )
    .expect("write proxy fixture");
    std::fs::set_permissions(&proxy_path, std::fs::Permissions::from_mode(0o755))
        .expect("make proxy executable");

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind netd fixture");
    let endpoint = format!("http://{}", listener.local_addr().expect("fixture address"));
    let (request_seen_tx, request_seen_rx) = mpsc::channel();
    let (connection_closed_tx, connection_closed_rx) = mpsc::channel();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept publication request");
        read_request(&mut stream);
        request_seen_tx.send(()).expect("report request");
        let publication = b"{\"local\":\"0.0.0.0:8080\",\"remote\":\"192.168.127.2:8080\",\"protocol\":\"tcp\"}\n";
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n",
            publication.len()
        )
        .expect("write response headers");
        stream.write_all(publication).expect("write publication");
        stream.write_all(b"\r\n").expect("write chunk terminator");
        let mut byte = [0; 1];
        while stream.read(&mut byte).expect("read publication hold") != 0 {}
        connection_closed_tx.send(()).expect("report close");
    });

    let (status_read, status_write) = pipe().expect("create status pipe");
    let inherited_listener = TcpListener::bind("127.0.0.1:0").expect("bind inherited listener");
    let mut command = Command::new(env!("CARGO_BIN_EXE_silo-portd"));
    command
        .args([
            "-proto",
            "tcp",
            "-host-ip",
            "0.0.0.0",
            "-host-port",
            "8080",
            "-container-ip",
            "172.17.0.2",
            "-container-port",
            "80",
            "-use-listen-fd",
        ])
        .env("SILO_PORTD_ENDPOINT", endpoint)
        .env("SILO_PORTD_DOCKER_PROXY", &proxy_path)
        .env("SILO_PORTD_TEST_SIGNAL_FILE", &signal_path);
    unsafe {
        command.pre_exec(move || {
            let status_fd = dup2_raw(&status_write, 3).map_err(std::io::Error::other)?;
            std::mem::forget(status_fd);
            let listener_fd = dup2_raw(&inherited_listener, 4).map_err(std::io::Error::other)?;
            std::mem::forget(listener_fd);
            Ok(())
        });
    }
    let mut portd = command.spawn().expect("spawn silo-portd");
    let status_file = File::from(status_read);
    let (status_tx, status_rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut line = String::new();
        BufReader::new(status_file)
            .read_line(&mut line)
            .expect("read Docker status");
        status_tx.send(line).expect("report Docker status");
    });

    request_seen_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("netd request was not received");
    assert_eq!(
        status_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("docker-proxy did not report readiness"),
        "0\n"
    );
    assert!(connection_closed_rx
        .recv_timeout(Duration::from_millis(200))
        .is_err());

    let pid = Pid::from_raw(i32::try_from(portd.id()).expect("portd PID fits i32"));
    kill(pid, Signal::SIGTERM).expect("signal silo-portd");
    let exit = portd.wait().expect("wait for silo-portd");
    assert!(exit.success(), "unexpected silo-portd exit: {exit}");
    assert_eq!(
        std::fs::read_to_string(&signal_path).expect("proxy signal marker"),
        "term"
    );
    connection_closed_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("publication connection stayed open");
    server.join().expect("join netd fixture");
}

fn read_request(stream: &mut TcpStream) {
    let mut reader = BufReader::new(stream.try_clone().expect("clone request stream"));
    let mut content_length = None;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).expect("read request line");
        if let Some(value) = line.strip_prefix("Content-Length: ") {
            content_length = Some(value.trim().parse::<usize>().expect("content length"));
        }
        if line == "\r\n" {
            break;
        }
    }
    let mut body = vec![0; content_length.expect("request content length")];
    reader.read_exact(&mut body).expect("read request body");
    assert_eq!(
        body,
        br#"{"local":"0.0.0.0:8080","remote":":8080","protocol":"tcp"}"#
    );
}
