//! Real executable bootstrap tests, no hypervisor or synthetic VMM required.

use std::io::{Read, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

struct Process(Option<Child>);
impl Process {
    fn output(mut self) -> Output {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if self
                .0
                .as_mut()
                .expect("child")
                .try_wait()
                .expect("probe child")
                .is_some()
            {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "worker failed to exit before deadline"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        self.0
            .take()
            .expect("child")
            .wait_with_output()
            .expect("read output")
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        if let Some(child) = &mut self.0 {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_vmmon"));
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

fn pipe() -> (OwnedFd, OwnedFd) {
    let pair = nix::unistd::pipe().expect("pipe");
    for fd in [&pair.0, &pair.1] {
        nix::fcntl::fcntl(
            fd,
            nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::FD_CLOEXEC),
        )
        .expect("cloexec");
    }
    pair
}

fn worker() -> (Process, std::fs::File, OwnedFd, std::fs::File, OwnedFd) {
    let (request, writer) = pipe();
    let (events, reporter) = pipe();
    let (watchdog, keepalive) = pipe();
    let pty = nix::pty::openpty(None, None).expect("pty");
    for fd in [&pty.master, &pty.slave] {
        nix::fcntl::fcntl(
            fd,
            nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::FD_CLOEXEC),
        )
        .expect("cloexec");
    }
    let roles = [
        request.as_raw_fd(),
        reporter.as_raw_fd(),
        watchdog.as_raw_fd(),
        pty.slave.as_raw_fd(),
    ];
    let mut command = command();
    command.arg0("krun").arg("__krun");
    for (flag, fd) in [
        "--request-fd",
        "--events-fd",
        "--watchdog-fd",
        "--console-fd",
    ]
    .into_iter()
    .zip(roles)
    {
        command.arg(flag).arg(fd.to_string());
    }
    // SAFETY: only async-signal-safe raw fcntl calls run after fork. nix requires
    // borrowed descriptors; the raw allowlist outlives this immediate spawn.
    unsafe {
        command.pre_exec(move || {
            for raw in roles {
                let flags = nix::libc::fcntl(raw, nix::libc::F_GETFD);
                if flags < 0
                    || nix::libc::fcntl(raw, nix::libc::F_SETFD, flags & !nix::libc::FD_CLOEXEC) < 0
                {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    let child = Process(Some(command.spawn().expect("spawn actual worker")));
    (child, writer.into(), keepalive, events.into(), pty.master)
}

#[test]
fn worker_parser_never_falls_through_to_supervisor_arguments() {
    for argv in [
        vec!["__krun"],
        vec!["__krun", "--id", "not-a-supervisor"],
        vec![
            "__krun",
            "--request-fd",
            "0",
            "--events-fd",
            "1",
            "--watchdog-fd",
            "2",
            "--console-fd",
            "3",
        ],
    ] {
        let output = Process(Some(command().args(argv).spawn().expect("spawn parser"))).output();
        assert!(!output.status.success());
        let diagnostic = String::from_utf8_lossy(&output.stderr);
        assert!(
            !diagnostic.contains("--data-dir"),
            "supervisor parser ran: {diagnostic}"
        );
    }
    let output = Process(Some(
        command()
            .arg0("krun")
            .arg("--help")
            .spawn()
            .expect("basename guard"),
    ))
    .output();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("private __krun marker"));
}

#[test]
fn watchdog_runs_before_a_complete_launch_request_exists() {
    let (child, mut request, keepalive, mut events, _console) = worker();
    // Receipt of the first event proves adoption and watchdog setup completed.
    let mut header = [0; 4];
    // Set a read deadline using poll, rather than risking a hung integration test.
    use std::os::fd::AsFd;
    let mut ready = [nix::poll::PollFd::new(
        events.as_fd(),
        nix::poll::PollFlags::POLLIN,
    )];
    assert!(nix::poll::poll(&mut ready, 3000u16).expect("poll startup event") > 0);
    events.read_exact(&mut header).expect("startup stage frame");
    request.write_all(&[0, 0]).expect("partial frame");
    drop(keepalive);
    let output = child.output();
    assert_eq!(output.status.code(), Some(125));
}

#[test]
fn malformed_request_is_redacted_and_does_not_require_a_hypervisor() {
    let (child, mut request, _keepalive, _events, _console) = worker();
    let private = br#"{"secret":"must-not-appear-in-diagnostics"}"#;
    request
        .write_all(&(private.len() as u32).to_be_bytes())
        .expect("header");
    request.write_all(private).expect("payload");
    drop(request);
    let output = child.output();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("invalid worker frame"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!String::from_utf8_lossy(&output.stderr).contains("must-not-appear"));
}
