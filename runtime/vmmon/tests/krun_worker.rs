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
    fn output(self) -> Output {
        self.output_with_timeout(Duration::from_secs(5))
    }

    fn output_with_timeout(mut self, timeout: Duration) -> Output {
        let deadline = Instant::now() + timeout;
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
            if matches!(child.try_wait(), Ok(None)) {
                let pid = nix::unistd::Pid::from_raw(child.id() as i32);
                let started = Instant::now();
                let mut escalated = false;
                let _ = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGINT);
                // Prefer supervisor-owned reaping, including on assertion failure.
                while matches!(child.try_wait(), Ok(None)) {
                    if !escalated && started.elapsed() >= Duration::from_millis(100) {
                        let _ = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGINT);
                        escalated = true;
                    }
                    if started.elapsed() >= Duration::from_secs(3) {
                        // Each fixture owns this process group, never a system-wide kill.
                        let _ = nix::sys::signal::kill(
                            nix::unistd::Pid::from_raw(-pid.as_raw()),
                            nix::sys::signal::Signal::SIGKILL,
                        );
                        let _ = child.kill();
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
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
    command.arg("worker");
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

struct SupervisorFixture(std::path::PathBuf, uuid::Uuid);

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
        Self(root, uuid::Uuid::new_v4())
    }

    fn command(&self) -> Command {
        let mut command = command();
        command.arg("--foreground").args([
            "--id",
            &self.1.to_string(),
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

    fn native() -> Self {
        let fixture = Self::new();
        let asset = |name| {
            let path = std::path::PathBuf::from(
                std::env::var_os(name)
                    .unwrap_or_else(|| panic!("set {name} to run ignored native qualification")),
            );
            std::fs::canonicalize(path).expect("native asset must exist")
        };
        let mut spec: vm_spec::VmSpec =
            serde_json::from_slice(&std::fs::read(fixture.0.join("spec.json")).expect("spec"))
                .expect("spec schema");
        let kernel = spec
            .boot
            .as_mut()
            .expect("boot")
            .kernel
            .as_mut()
            .expect("kernel");
        kernel.path = Some(asset("SILO_TEST_KERNEL"));
        kernel.initramfs = Some(asset("SILO_TEST_INITRAMFS"));
        kernel.cmdline = vec![
            "loglevel=4".to_string(),
            "silo.qualification=krun-worker".to_string(),
        ];
        spec.hardware.as_mut().expect("hardware").memory = Some(256);
        let share = fixture.0.join("share");
        std::fs::create_dir(&share).expect("share");
        std::fs::write(share.join("proof"), b"SILO_NATIVE_MOUNT\n").expect("mount proof");
        std::fs::copy(asset("SILO_TEST_SHUTDOWN"), share.join("shutdown"))
            .expect("guest-only shutdown utility");
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            share.join("shutdown"),
            std::fs::Permissions::from_mode(0o755),
        )
        .expect("executable guest fixture");
        spec.mounts.push(vm_spec::Mount {
            source: share,
            tag: "acceptance".to_string(),
            read_only: true,
        });
        let mut disks = Vec::new();
        for (name, read_only) in [("first.raw", false), ("second.raw", true)] {
            let path = fixture.0.join(name);
            std::fs::File::create(&path)
                .expect("disk")
                .set_len(8 * 1024 * 1024)
                .expect("disk size");
            disks.push(vm_spec::Disk { path, read_only });
        }
        spec.storage = Some(vm_spec::Storage { disks });
        std::fs::write(
            fixture.0.join("spec.json"),
            serde_json::to_vec(&spec).expect("native spec"),
        )
        .expect("write native spec");
        fixture
    }

    async fn wait_for_guest(&self, process: &mut Process, previous_generations: usize) {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let console = std::fs::read_to_string(self.0.join("serial.log")).unwrap_or_default();
            if console.matches("starting rescue shell").count() > previous_generations {
                return;
            }
            assert!(
                process
                    .0
                    .as_mut()
                    .expect("supervisor")
                    .try_wait()
                    .expect("probe supervisor")
                    .is_none(),
                "native startup failed: {}",
                std::fs::read_to_string(self.0.join("trace.log")).unwrap_or_default()
            );
            assert!(Instant::now() < deadline, "guest boot timed out: {console}");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
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
        if std::thread::panicking() {
            for name in ["serial.log", "trace.log"] {
                if let Ok(bytes) = std::fs::read(self.0.join(name)) {
                    eprintln!(
                        "{name} tail: {}",
                        String::from_utf8_lossy(&bytes[bytes.len().saturating_sub(8192)..])
                    );
                }
            }
        }
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
    }
    let (datagram, _peer) = std::os::unix::net::UnixDatagram::pair().expect("datagram");
    let datagram: OwnedFd = datagram.into();
    let unconnected = nix::sys::socket::socket(
        nix::sys::socket::AddressFamily::Unix,
        nix::sys::socket::SockType::Stream,
        nix::sys::socket::SockFlag::empty(),
        None,
    )
    .expect("unconnected stream");
    let unconnected = fd_policy::normalize(unconnected).expect("normalize unconnected stream");
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

async fn native_serial(
    path: &std::path::Path,
) -> (
    tokio::sync::mpsc::Sender<protocol::v1::ByteChunk>,
    tonic::Streaming<protocol::v1::ByteChunk>,
) {
    let path = path.to_owned();
    let channel = tonic::transport::Endpoint::from_static("http://localhost")
        .connect_with_connector(tower::service_fn(move |_| {
            let path = path.clone();
            async move {
                tokio::net::UnixStream::connect(path)
                    .await
                    .map(hyper_util::rt::TokioIo::new)
            }
        }))
        .await
        .expect("real vmmon API");
    let mut client = protocol::v1::vm_access_service_client::VmAccessServiceClient::new(channel);
    let (send, input) = tokio::sync::mpsc::channel(4);
    let stream = client
        .open_serial(tokio_stream::wrappers::ReceiverStream::new(input))
        .await
        .expect("real guest serial")
        .into_inner();
    (send, stream)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NativeExit {
    Stop,
    WorkerSignal,
    GuestReboot,
    GuestPoweroff,
}

#[tokio::test]
#[ignore = "requires native hypervisor and SILO_TEST_KERNEL/INITRAMFS/SHUTDOWN; macOS vmmon must be signed"]
async fn native_guest_devices_shutdown_crash_and_new_generation() {
    native_guest_cases(&[
        NativeExit::Stop,
        NativeExit::Stop,
        NativeExit::WorkerSignal,
        NativeExit::GuestReboot,
    ])
    .await;
}

#[tokio::test]
#[ignore = "power-off acceptance gate; requires native assets, currently blocked with the available x86-64 kernel"]
async fn native_guest_poweroff() {
    native_guest_cases(&[NativeExit::GuestPoweroff]).await;
}

async fn native_guest_cases(scenarios: &[NativeExit]) {
    let fixture = SupervisorFixture::native();
    let mut previous_run = None;
    let mut previous_worker = None;
    for (generation, &scenario) in scenarios.iter().enumerate() {
        let mut process = Process(Some(fixture.command().spawn().expect("native supervisor")));
        fixture.wait_for_guest(&mut process, generation).await;
        let supervisor = process.0.as_ref().expect("supervisor").id();
        let children = Command::new("pgrep")
            .args(["-P", &supervisor.to_string()])
            .output()
            .expect("inspect owned process tree");
        let children: Vec<u32> = String::from_utf8(children.stdout)
            .expect("PIDs")
            .split_whitespace()
            .map(|pid| pid.parse().expect("worker PID"))
            .collect();
        assert_eq!(
            children.len(),
            1,
            "one primary worker, no helper descendants"
        );
        let worker = children[0];
        assert_ne!(Some(worker), previous_worker);
        #[cfg(target_os = "linux")]
        {
            assert_eq!(
                std::fs::read_link(format!("/proc/{worker}/exe")).expect("worker executable"),
                std::fs::canonicalize(env!("CARGO_BIN_EXE_vmmon")).expect("vmmon executable")
            );
        }
        let (send, mut serial) = native_serial(&fixture.0.join("vm.sock")).await;
        let mut input =
            "echo DISKS_BEGIN; cat /sys/block/vda/ro /sys/block/vdb/ro; echo DISKS_END; "
                .to_string();
        // The rescue shell does not expand globs. Enumerate the console, two
        // block devices, filesystem, vsock, RNG, and balloon explicitly.
        for index in 0..7 {
            input.push_str(&format!(
                "cat /sys/bus/virtio/devices/virtio{index}/device; "
            ));
        }
        input.push_str("mount -t virtiofs acceptance /mnt; cat /mnt/proof; echo denied > /mnt/denied; echo SILO_NATIVE_DONE\n");
        send.send(protocol::v1::ByteChunk {
            data: Some(bytes::Bytes::from(input)),
        })
        .await
        .expect("guest input");
        let output = tokio::time::timeout(Duration::from_secs(10), async {
            let mut output = String::new();
            loop {
                let chunk = serial
                    .message()
                    .await
                    .expect("serial response")
                    .expect("live guest");
                output.push_str(&String::from_utf8_lossy(&chunk.data.unwrap_or_default()));
                assert!(output.len() <= 1024 * 1024, "bounded guest output");
                if output
                    .replace('\r', "")
                    .lines()
                    .any(|line| line == "SILO_NATIVE_DONE")
                {
                    return output.replace('\r', "");
                }
            }
        })
        .await
        .expect("real guest round trip");
        assert!(output.contains("DISKS_BEGIN\n0\n1\nDISKS_END"), "{output}");
        assert!(
            output.lines().any(|line| line == "SILO_NATIVE_MOUNT"),
            "{output}"
        );
        let devices: Vec<u32> = output
            .lines()
            .filter_map(|line| line.strip_prefix("0x"))
            .filter_map(|id| u32::from_str_radix(id, 16).ok())
            .collect();
        assert!(devices.contains(&5), "balloon device missing: {output}");
        assert!(devices.contains(&19), "vsock device missing: {output}");
        assert!(
            !fixture.0.join("share/denied").exists(),
            "read-only virtio-fs share accepted a write"
        );
        if matches!(
            scenario,
            NativeExit::GuestReboot | NativeExit::GuestPoweroff
        ) {
            let command: &'static [u8] = if scenario == NativeExit::GuestPoweroff {
                b"/mnt/shutdown poweroff\n"
            } else {
                b"/mnt/shutdown\n"
            };
            send.send(protocol::v1::ByteChunk {
                data: Some(bytes::Bytes::from_static(command)),
            })
            .await
            .expect("guest shutdown request");
            // Poll the response while the guest consumes the final request.
            let _ = tokio::time::timeout(Duration::from_secs(3), async {
                while let Some(chunk) = serial.message().await.expect("shutdown serial response") {
                    let text =
                        String::from_utf8_lossy(&chunk.data.unwrap_or_default()).into_owned();
                    if text.contains("SILO_NATIVE_SHUTDOWN") {
                        break;
                    }
                }
            })
            .await;
        }
        drop((send, serial));
        if scenario == NativeExit::Stop {
            nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(supervisor as i32),
                nix::sys::signal::Signal::SIGINT,
            )
            .expect("supervised stop");
        } else if scenario == NativeExit::WorkerSignal {
            nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(worker as i32),
                nix::sys::signal::Signal::SIGKILL,
            )
            .expect("unexpected worker death");
        }
        let result = process.output_with_timeout(Duration::from_secs(45));
        assert_eq!(
            result.stdout, b"started\n",
            "guest and native diagnostics must not contaminate the supervisor protocol"
        );
        assert!(!fixture.0.join("vm.pid").exists());
        let status: serde_json::Value = serde_json::from_slice(
            &std::fs::read(fixture.0.join("vm.exit.json")).expect("native exit metadata"),
        )
        .expect("exit record");
        assert_eq!(status["pid"], supervisor);
        assert_eq!(status["machineId"], fixture.1.to_string());
        assert_eq!(status["worker"]["pid"], worker);
        assert_eq!(status["worker"]["coreDumped"], false);
        assert_eq!(status["worker"]["stage"], "started");
        assert_ne!(Some(&status["runId"]), previous_run.as_ref());
        let expected = match scenario {
            NativeExit::WorkerSignal => {
                assert!(!result.status.success());
                assert!(status["worker"]["forceReason"].is_null());
                "error"
            }
            NativeExit::Stop if cfg!(target_os = "linux") => {
                assert!(result.status.success());
                assert_eq!(status["worker"]["signal"], 9);
                "forced"
            }
            NativeExit::Stop if status["worker"]["signal"] == 9 => {
                assert!(result.status.success());
                assert_eq!(status["worker"]["forceReason"], "graceful_timeout");
                "forced"
            }
            _ => {
                assert!(result.status.success());
                assert_eq!(status["worker"]["code"], 0);
                "clean"
            }
        };
        assert_eq!(status["outcome"], expected, "{status}");
        assert_eq!(
            nix::sys::signal::kill(nix::unistd::Pid::from_raw(worker as i32), None),
            Err(nix::errno::Errno::ESRCH)
        );
        assert_eq!(
            std::fs::read_to_string(fixture.0.join("trace.log"))
                .expect("trace")
                .matches("krun worker spawned")
                .count(),
            generation + 1
        );
        eprintln!(
            "native {scenario:?}: supervisor={supervisor}, worker={worker}, outcome={expected}"
        );
        previous_run = Some(status["runId"].clone());
        previous_worker = Some(worker);
    }
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
