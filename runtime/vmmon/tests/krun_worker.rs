//! Real executable bootstrap tests, no hypervisor or synthetic VMM required.

use std::io::{Read, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

// Exercise the exact production inheritance policy against the actual executable.
#[path = "../src/virt/backend/krun/inherit.rs"]
mod fd_policy;

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
            if child.try_wait().ok().flatten().is_none() {
                // Each fixture owns a new process group; never touch unrelated processes.
                let _ = nix::sys::signal::kill(
                    nix::unistd::Pid::from_raw(-(child.id() as i32)),
                    nix::sys::signal::Signal::SIGKILL,
                );
                let _ = child.kill();
            }
            let _ = child.wait();
        }
    }
}

fn command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_vmmon"));
    command
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    fd_policy::install(&mut command, &[]);
    command
}

fn pipe() -> (OwnedFd, OwnedFd) {
    let (read, write) = nix::unistd::pipe().expect("pipe");
    (
        fd_policy::normalize(read).expect("normalize reader"),
        fd_policy::normalize(write).expect("normalize writer"),
    )
}

fn worker() -> (Process, std::fs::File, OwnedFd, std::fs::File, OwnedFd) {
    worker_with_events(|_| {})
}

fn worker_with_events(
    prepare: impl FnOnce(&OwnedFd),
) -> (Process, std::fs::File, OwnedFd, std::fs::File, OwnedFd) {
    let (request, writer) = pipe();
    let (events, reporter) = pipe();
    let (watchdog, keepalive) = pipe();
    prepare(&reporter);
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
    let mut command = private_command(roles);
    // Deliberately inheritable opposite endpoints must still be closed by exec.
    for fd in [&writer, &events, &keepalive] {
        nix::fcntl::fcntl(
            fd,
            nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::empty()),
        )
        .expect("inheritable sentinel");
    }
    fd_policy::install(&mut command, &[&request, &reporter, &watchdog, &pty.slave]);
    let child = Process(Some(command.spawn().expect("spawn actual worker")));
    (child, writer.into(), keepalive, events.into(), pty.master)
}

fn private_command(roles: [i32; 4]) -> Command {
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
    command
}

struct SupervisorFixture(std::path::PathBuf);

impl SupervisorFixture {
    fn new() -> Self {
        use std::os::unix::fs::PermissionsExt;
        let root =
            std::path::Path::new("/tmp").join(format!("vmmon-worker-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).expect("fixture root");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
            .expect("private root");
        std::fs::write(root.join("kernel"), b"not a native kernel").expect("invalid payload");
        let spec = vm_spec::VmSpec {
            boot: Some(vm_spec::Boot {
                kernel: Some(vm_spec::Kernel {
                    path: Some("kernel".into()),
                    cmdline: vec![],
                    initramfs: None,
                }),
                userdata: None,
            }),
            hardware: Some(vm_spec::Hardware {
                cpus: Some(1),
                memory: Some(128),
                nested_virtualization: Some(false),
                rosetta: Some(false),
            }),
            ..vm_spec::VmSpec::current()
        };
        std::fs::write(
            root.join("spec.json"),
            serde_json::to_vec(&spec).expect("spec encoding"),
        )
        .expect("write spec");
        Self(root)
    }

    fn command(&self) -> Command {
        let mut command = command();
        command.arg("--foreground").args([
            "--id",
            &uuid::Uuid::new_v4().to_string(),
            "--run-id",
            &uuid::Uuid::new_v4().to_string(),
            "--name",
            "worker-failure",
        ]);
        for (flag, path) in [
            ("--data-dir", self.0.clone()),
            ("--runtime-dir", self.0.clone()),
            ("--pidfile", self.0.join("vm.pid")),
            ("--exit-status", self.0.join("vm.exit.json")),
            ("--config", self.0.join("spec.json")),
            ("--socket", self.0.join("vm.sock")),
            ("--serial-log", self.0.join("serial.log")),
            ("--trace-log", self.0.join("trace.log")),
        ] {
            command.arg(flag).arg(path);
        }
        for name in [
            "_VM_STARTPIPE",
            "_VM_SYNCPIPE",
            "_VM_MACHINE_LOCK",
            "_VM_MACHINE_LOG_DIR",
        ] {
            command.env_remove(name);
        }
        command
    }

    fn wait_for_request(&self) {
        let deadline = Instant::now() + Duration::from_secs(3);
        while !std::fs::read_to_string(self.0.join("trace.log"))
            .unwrap_or_default()
            .contains("start_request_wait")
        {
            assert!(
                Instant::now() < deadline,
                "supervisor never waited for launch request"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for SupervisorFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn supervisor_launches_one_real_worker_and_exits_on_native_startup_failure() {
    let fixture = SupervisorFixture::new();
    let marker = fixture.0.join("exit-command");
    let mut command = fixture.command();
    command
        .args([
            "--exit-command",
            "/bin/sh",
            "--exit-command-arg=-c",
            "--exit-command-arg=printf '%s\\n' \"$SILO_MACHINE_RUN_ID\" >> \"$1\"",
            "--exit-command-arg=record",
        ])
        .arg("--exit-command-arg")
        .arg(&marker);
    let process = Process(Some(command.spawn().expect("supervisor")));
    let supervisor_pid = process.0.as_ref().expect("child").id();
    let output = process.output();
    assert!(!output.status.success());
    let trace = std::fs::read_to_string(fixture.0.join("trace.log")).expect("supervisor trace");
    assert_eq!(trace.matches("krun worker spawned").count(), 1, "{trace}");
    let status: serde_json::Value = serde_json::from_slice(
        &std::fs::read(fixture.0.join("vm.exit.json")).expect("exit metadata"),
    )
    .expect("exit record");
    assert_eq!(status["outcome"], "error");
    assert_eq!(status["pid"], supervisor_pid);
    let worker_pid = status["worker"]["pid"]
        .as_u64()
        .expect("retained startup worker identity");
    assert_ne!(worker_pid, u64::from(supervisor_pid));
    assert!(status["worker"]["rawStatus"].is_i64());
    assert_eq!(
        nix::sys::signal::kill(nix::unistd::Pid::from_raw(worker_pid as i32), None),
        Err(nix::errno::Errno::ESRCH),
        "worker was not reaped"
    );
    assert!(!fixture.0.join("vm.pid").exists());
    let deadline = Instant::now() + Duration::from_secs(3);
    while !marker.exists() {
        assert!(Instant::now() < deadline, "exit command not invoked");
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        std::fs::read_to_string(marker).expect("exit command record"),
        format!("{}\n", status["runId"].as_str().expect("run identity"))
    );
}

#[test]
fn startup_signal_cancels_an_incomplete_request_without_a_blocking_reader() {
    let fixture = SupervisorFixture::new();
    let (reader, writer) = pipe();
    let mut command = fixture.command();
    command.env("_VM_STARTPIPE", reader.as_raw_fd().to_string());
    fd_policy::install(&mut command, &[&reader]);
    let process = Process(Some(command.spawn().expect("supervisor")));
    drop(reader);
    let mut writer = std::fs::File::from(writer);
    writer.write_all(b"{").expect("partial supervisor request");
    fixture.wait_for_request();
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(process.0.as_ref().expect("child").id() as i32),
        nix::sys::signal::Signal::SIGINT,
    )
    .expect("cancel startup");
    assert!(!process.output().status.success());
    assert!(fixture.0.join("vm.exit.json").exists());
    assert!(!std::fs::read_to_string(fixture.0.join("trace.log"))
        .expect("trace")
        .contains("krun worker spawned"));
    drop(writer);
}

#[test]
fn parent_loss_cancels_an_incomplete_supervisor_request() {
    let fixture = SupervisorFixture::new();
    let (request, _keep_request_open) = pipe();
    let (parent, sync) = pipe();
    let mut command = fixture.command();
    command
        .env("_VM_STARTPIPE", request.as_raw_fd().to_string())
        .env("_VM_SYNCPIPE", sync.as_raw_fd().to_string());
    fd_policy::install(&mut command, &[&request, &sync]);
    let process = Process(Some(command.spawn().expect("supervisor")));
    drop((request, sync));
    fixture.wait_for_request();
    drop(parent);
    assert!(!process.output().status.success());
    assert!(fixture.0.join("vm.exit.json").exists());
    assert!(!std::fs::read_to_string(fixture.0.join("trace.log"))
        .expect("trace")
        .contains("krun worker spawned"));
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
fn invalid_descriptor_roles_fail_before_any_worker_event() {
    let (request, _writer) = pipe();
    let (events, reporter) = pipe();
    let (watchdog, keepalive) = pipe();
    let alias = request.try_clone().expect("aliased resource");
    let pty = nix::pty::openpty(None, None).expect("PTY");
    let valid = [
        request.as_raw_fd(),
        reporter.as_raw_fd(),
        watchdog.as_raw_fd(),
        pty.slave.as_raw_fd(),
    ];
    for (label, slot, bad) in [
        ("stdio role", 0, 0),
        ("closed role", 0, i32::MAX),
        ("write-only request", 0, keepalive.as_raw_fd()),
        ("read-only events", 1, events.as_raw_fd()),
        ("repeated number", 2, request.as_raw_fd()),
        ("aliased resource", 2, alias.as_raw_fd()),
        ("opposite pipe ends", 1, _writer.as_raw_fd()),
        ("pipe instead of TTY", 3, events.as_raw_fd()),
    ] {
        let mut roles = valid;
        roles[slot] = bad;
        let mut command = private_command(roles);
        fd_policy::install(
            &mut command,
            &[
                &request, &_writer, &reporter, &events, &watchdog, &keepalive, &alias, &pty.slave,
            ],
        );
        let output = Process(Some(command.spawn().expect("worker"))).output();
        assert!(!output.status.success(), "{label}");
        assert!(
            !String::from_utf8_lossy(&output.stderr).contains("--data-dir"),
            "{label}"
        );
    }
    let (datagram, _peer) = std::os::unix::net::UnixDatagram::pair().expect("datagram");
    let datagram: OwnedFd = datagram.into();
    let unconnected = nix::sys::socket::socket(
        nix::sys::socket::AddressFamily::Unix,
        nix::sys::socket::SockType::Stream,
        nix::sys::socket::SockFlag::SOCK_CLOEXEC,
        None,
    )
    .expect("unconnected stream");
    for mux in [&datagram, &unconnected] {
        let mut command = private_command(valid);
        command
            .arg("--vsock-mux-fd")
            .arg(mux.as_raw_fd().to_string());
        fd_policy::install(
            &mut command,
            &[&request, &reporter, &watchdog, &pty.slave, mux],
        );
        assert!(!Process(Some(command.spawn().expect("invalid mux worker")))
            .output()
            .status
            .success());
    }
    drop(reporter);
    let mut bytes = Vec::new();
    std::fs::File::from(events)
        .read_to_end(&mut bytes)
        .expect("events EOF");
    assert!(bytes.is_empty(), "invalid roles reached request processing");
}

#[test]
fn worker_rejects_truncated_oversized_zero_and_trailing_frames() {
    for bytes in [
        vec![],
        vec![0, 0, 0],
        vec![0, 0, 0, 3, b'{'],
        vec![0; 4],
        u32::MAX.to_be_bytes().to_vec(),
        vec![0, 0, 0, 2, b'{', b'}', 0],
    ] {
        let (child, mut request, _keepalive, _events, _console) = worker();
        request.write_all(&bytes).expect("invalid frame");
        drop(request);
        assert!(!child.output().status.success());
    }
}

#[test]
fn watchdog_terminates_worker_with_a_full_event_channel() {
    let (child, _request, keepalive, _events, _console) = worker_with_events(|events| {
        nix::fcntl::fcntl(
            events,
            nix::fcntl::FcntlArg::F_SETFL(nix::fcntl::OFlag::O_NONBLOCK),
        )
        .expect("nonblocking event pipe");
        loop {
            match nix::unistd::write(events, &[b'x'; 4096]) {
                Ok(_) => {}
                Err(nix::errno::Errno::EAGAIN) => break,
                Err(error) => panic!("fill event pipe: {error}"),
            }
        }
    });
    std::thread::sleep(Duration::from_millis(50));
    drop(keepalive);
    assert_eq!(child.output().status.code(), Some(125));
}

#[test]
fn later_marker_remains_supervisor_data_and_non_utf8_basename_fails_closed() {
    use std::os::unix::ffi::OsStringExt;
    let output = Process(Some(
        command()
            .args(["--name", "__krun", "--help"])
            .spawn()
            .expect("supervisor help"),
    ))
    .output();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("--data-dir"));
    let output = Process(Some(
        command()
            .arg0(std::ffi::OsString::from_vec(b"/private/\xff/krun".to_vec()))
            .arg("--help")
            .spawn()
            .expect("basename guard"),
    ))
    .output();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("private __krun marker"));
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
