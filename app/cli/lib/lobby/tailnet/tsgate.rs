//! The tsgate child process and its control socket.
//!
//! ```text
//!  silod                                tsgate (Go, tsnet)
//!  ┌──────────────┐  stdin = socket   ┌─────────────────┐
//!  │ Tsgate       │◄─────────────────►│ gateway         │
//!  │  reader task │  frames + fds     │  :22  :443(TLS) │
//!  └──────┬───────┘                   └─────────────────┘
//!         ├─► watch<NodeState>     (state frames)
//!         ├─► mpsc<Connection>     (conn frames, one socket each)
//!         └─► oneshot per request  (reply frames)
//! ```
//!
//! Closing our end is owner loss: tsgate exits on its own within five seconds.

use std::collections::HashMap;
use std::io::{self, IoSliceMut};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use nix::sys::socket::{recvmsg, ControlMessageOwned, MsgFlags};
use parking_lot::Mutex;
use tokio::io::{AsyncWriteExt, Interest};
use tokio::net::unix::OwnedWriteHalf;
use tokio::net::UnixStream;
use tokio::process::{Child, Command};
use tokio::sync::{mpsc, oneshot, watch};

use crate::lobby::tailnet::wire::{
    encode, Bootstrap, Decoder, Event, NodeState, Phase, Request, Whois, MAX_FRAME,
};
use crate::lobby::tailnet::{Connection, TailnetError};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const SHUTDOWN_GRACE: Duration = Duration::from_secs(6);

type Pending = Arc<Mutex<HashMap<u64, oneshot::Sender<Result<Whois, String>>>>>;

pub(crate) struct Tsgate {
    child: tokio::sync::Mutex<Child>,
    writer: tokio::sync::Mutex<OwnedWriteHalf>,
    pending: Pending,
    next_id: AtomicU64,
    state: watch::Receiver<NodeState>,
}

impl Tsgate {
    /// Spawns tsgate, sends `bootstrap`, and starts the reader task. Accepted
    /// tailnet connections arrive on the returned receiver.
    pub(crate) async fn spawn(
        binary: &Path,
        bootstrap: Bootstrap,
    ) -> Result<(Self, mpsc::Receiver<Connection>), TailnetError> {
        let executable = open_helper(binary)?;
        #[cfg(target_os = "linux")]
        let exec_path = PathBuf::from(format!("/proc/self/fd/{}", executable.as_raw_fd()));
        #[cfg(not(target_os = "linux"))]
        let exec_path = binary;
        let (ours, theirs) = std::os::unix::net::UnixStream::pair()?;
        // Command dup2()s the socket onto fd 0, which clears close-on-exec for
        // the child only; our copies keep CLOEXEC from UnixStream::pair.
        let mut command = Command::new(exec_path);
        command.as_std_mut().arg0(binary);
        let child = command
            .args(["--control-fd", "0"])
            .env_clear()
            .stdin(Stdio::from(OwnedFd::from(theirs)))
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()?;
        drop(executable);
        ours.set_nonblocking(true)?;
        let (read, write) = UnixStream::from_std(ours)?.into_split();
        let (state_tx, state) = watch::channel(NodeState::starting());
        let (conn_tx, conns) = mpsc::channel(64);
        let pending: Pending = Arc::default();
        tokio::spawn(read_loop(read, state_tx, conn_tx, pending.clone()));
        let gate = Self {
            child: tokio::sync::Mutex::new(child),
            writer: tokio::sync::Mutex::new(write),
            pending,
            next_id: AtomicU64::new(1),
            state,
        };
        gate.send(&Request::Bootstrap(bootstrap)).await?;
        Ok((gate, conns))
    }

    pub(crate) fn state(&self) -> watch::Receiver<NodeState> {
        self.state.clone()
    }

    pub(crate) async fn whois(&self, remote: &str) -> Result<Whois, TailnetError> {
        self.request(|id| Request::Whois {
            id,
            remote: remote.to_owned(),
        })
        .await
    }

    /// Asks tsgate to stop, then waits for it, killing it after the grace
    /// period. Returns the child's exit status.
    pub(crate) async fn shutdown(&self) -> io::Result<std::process::ExitStatus> {
        // A closed seam already means tsgate is on its way out.
        let _ = self.send(&Request::Shutdown).await;
        let mut child = self.child.lock().await;
        match tokio::time::timeout(SHUTDOWN_GRACE, child.wait()).await {
            Ok(status) => status,
            Err(_) => {
                child.kill().await?;
                child.wait().await
            }
        }
    }

    /// Waits for tsgate to exit on its own (crash, fatal state, owner loss).
    pub(crate) async fn wait(&self) -> io::Result<std::process::ExitStatus> {
        self.child.lock().await.wait().await
    }

    async fn request(&self, build: impl FnOnce(u64) -> Request) -> Result<Whois, TailnetError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.pending.lock().insert(id, tx);
        if let Err(error) = self.send(&build(id)).await {
            self.pending.lock().remove(&id);
            return Err(error);
        }
        match tokio::time::timeout(REQUEST_TIMEOUT, rx).await {
            Ok(Ok(Ok(body))) => Ok(body),
            Ok(Ok(Err(message))) => Err(TailnetError::Remote(message)),
            Ok(Err(_)) => Err(TailnetError::Closed),
            Err(_) => {
                self.pending.lock().remove(&id);
                Err(TailnetError::Timeout)
            }
        }
    }

    async fn send(&self, request: &Request) -> Result<(), TailnetError> {
        let frame = encode(request)?;
        let mut writer = self.writer.lock().await;
        writer
            .write_all(&frame)
            .await
            .map_err(|_| TailnetError::Closed)
    }
}

async fn read_loop(
    read: tokio::net::unix::OwnedReadHalf,
    state: watch::Sender<NodeState>,
    conns: mpsc::Sender<Connection>,
    pending: Pending,
) {
    let error = match pump(read.as_ref(), &state, &conns, &pending).await {
        Ok(()) => "tsgate closed its control socket".to_string(),
        Err(error) => error.to_string(),
    };
    tracing::warn!(%error, "tsgate control seam ended");
    state.send_modify(|current| {
        if current.phase != Phase::Failed {
            current.phase = Phase::Failed;
            current.error = Some(error);
        }
    });
    // Dropping the senders fails every outstanding request with `Closed`.
    pending.lock().clear();
}

async fn pump(
    stream: &UnixStream,
    state: &watch::Sender<NodeState>,
    conns: &mpsc::Sender<Connection>,
    pending: &Pending,
) -> Result<(), TailnetError> {
    let mut decoder = Decoder::default();
    let mut chunk = vec![0u8; MAX_FRAME];
    loop {
        let (n, fds) = stream
            .async_io(Interest::READABLE, || {
                receive(stream.as_raw_fd(), &mut chunk)
            })
            .await?;
        if n == 0 && fds.is_empty() {
            decoder.finish()?;
            return Ok(());
        }
        decoder.push(&chunk[..n], fds)?;
        while let Some(event) = decoder.next()? {
            match event {
                Event::State(next) => {
                    state.send_replace(next);
                }
                Event::Conn {
                    listener,
                    remote,
                    stream,
                } => {
                    let stream = into_tokio(stream)?;
                    let connection = Connection {
                        listener,
                        remote,
                        stream,
                    };
                    if conns.send(connection).await.is_err() {
                        // Nobody consumes connections any more; the socket
                        // closes on drop and tsgate tears the stream down.
                        tracing::debug!("dropping tailnet connection without a consumer");
                    }
                }
                Event::Reply { id, result } => {
                    if let Some(waiter) = pending.lock().remove(&id) {
                        let _ = waiter.send(result);
                    }
                }
            }
        }
    }
}

fn receive(fd: RawFd, chunk: &mut [u8]) -> io::Result<(usize, Vec<OwnedFd>)> {
    let mut iov = [IoSliceMut::new(chunk)];
    // Room for two descriptors so a misbehaving peer is detected, not truncated.
    let mut space = nix::cmsg_space!([RawFd; 2]);
    let message = recvmsg::<()>(fd, &mut iov, Some(&mut space), cmsg_flags())?;
    let mut fds = Vec::new();
    for cmsg in message.cmsgs()? {
        if let ControlMessageOwned::ScmRights(raw) = cmsg {
            for fd in raw {
                // SAFETY: the kernel just installed `fd` in our table for this
                // message; nothing else owns it.
                fds.push(unsafe { OwnedFd::from_raw_fd(fd) });
            }
        }
    }
    if message.flags.contains(MsgFlags::MSG_CTRUNC) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "control message truncated",
        ));
    }
    for fd in &fds {
        set_cloexec(fd)?;
    }
    Ok((message.bytes, fds))
}

#[cfg(target_os = "linux")]
fn cmsg_flags() -> MsgFlags {
    MsgFlags::MSG_CMSG_CLOEXEC
}

#[cfg(not(target_os = "linux"))]
fn cmsg_flags() -> MsgFlags {
    MsgFlags::empty()
}

fn set_cloexec(fd: &OwnedFd) -> io::Result<()> {
    use nix::fcntl::{fcntl, FcntlArg, FdFlag};
    fcntl(fd, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))?;
    Ok(())
}

fn into_tokio(fd: OwnedFd) -> io::Result<UnixStream> {
    let stream = std::os::unix::net::UnixStream::from(fd);
    stream.set_nonblocking(true)?;
    UnixStream::from_std(stream)
}

/// Locates tsgate in the portable archive or Silo.app helper directory.
pub(crate) fn adjacent_binary() -> io::Result<PathBuf> {
    helper_for_executable(&std::env::current_exe()?.canonicalize()?)
}

fn helper_for_executable(exe: &Path) -> io::Result<PathBuf> {
    let dir = exe
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "executable has no directory"))?;
    if exe.file_name().is_some_and(|name| name == "silo")
        && dir.file_name().is_some_and(|name| name == "MacOS")
        && dir.parent().is_some_and(|contents| {
            contents.file_name().is_some_and(|name| name == "Contents")
                && contents
                    .parent()
                    .is_some_and(|bundle| bundle.file_name().is_some_and(|name| name == "Silo.app"))
        })
    {
        let contents = dir.parent().ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "bundle has no Contents directory")
        })?;
        validated_helper(&contents.join("Helpers"))
    } else {
        validated_helper(dir)
    }
}

fn validated_helper(dir: &Path) -> io::Result<PathBuf> {
    let dir = dir.canonicalize()?;
    let helper = dir.join("tsgate");
    open_helper(&helper)?;
    Ok(helper)
}

fn trusted_ancestor(uid: u32, gid: u32, mode: u32, euid: u32) -> bool {
    if uid != 0 && uid != euid {
        return false;
    }
    if mode & 0o022 == 0 {
        return true;
    }
    uid == 0
        && (mode & 0o1000 != 0
            || (mode & 0o002 == 0 && (gid == 0 || (cfg!(target_os = "macos") && gid == 80))))
}

pub(crate) fn open_helper(helper: &Path) -> io::Result<std::fs::File> {
    let dir = helper
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "tsgate has no directory"))?
        .canonicalize()?;
    for ancestor in dir.ancestors() {
        let metadata = std::fs::metadata(ancestor)?;
        if !metadata.is_dir()
            || !trusted_ancestor(
                metadata.uid(),
                metadata.gid(),
                metadata.mode(),
                nix::unistd::geteuid().as_raw(),
            )
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "tsgate package ancestors must have trusted ownership and permissions",
            ));
        }
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags((nix::fcntl::OFlag::O_NOFOLLOW | nix::fcntl::OFlag::O_CLOEXEC).bits())
        .open(helper)?;
    let metadata = file.metadata()?;
    let euid = nix::unistd::geteuid().as_raw();
    if !metadata.is_file()
        || (metadata.uid() != euid && metadata.uid() != 0)
        || metadata.mode() & 0o022 != 0
        || metadata.mode() & 0o111 == 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "tsgate must be a trusted executable in the package directory",
        ));
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    use std::io::{IoSlice, Read, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    use nix::sys::socket::{sendmsg, ControlMessage, MsgFlags};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::{mpsc, watch};

    use crate::lobby::tailnet::tsgate::{pump, Pending};
    use crate::lobby::tailnet::wire::{NodeState, Phase};

    #[test]
    fn helpers_follow_portable_and_app_bundle_layouts() {
        let root = tempfile::tempdir().unwrap();
        let portable = root.path().join("bin");
        let contents = root.path().join("Silo.app/Contents");
        std::fs::create_dir_all(&portable).unwrap();
        std::fs::create_dir_all(contents.join("MacOS")).unwrap();
        std::fs::create_dir_all(contents.join("Helpers")).unwrap();
        for (exe, helper) in [
            (portable.join("silo"), portable.join("tsgate")),
            (contents.join("MacOS/silo"), contents.join("Helpers/tsgate")),
        ] {
            std::fs::write(&exe, b"executable").unwrap();
            std::fs::write(&helper, b"helper").unwrap();
            std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o755)).unwrap();
            assert_eq!(
                crate::lobby::tailnet::tsgate::helper_for_executable(&exe).unwrap(),
                helper
            );
        }
        let ordinary = root.path().join("not-a-bundle/Contents/MacOS/silo");
        std::fs::create_dir_all(ordinary.parent().unwrap()).unwrap();
        let helper = ordinary.parent().unwrap().join("tsgate");
        std::fs::write(&helper, b"helper").unwrap();
        std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            crate::lobby::tailnet::tsgate::helper_for_executable(&ordinary).unwrap(),
            helper
        );
    }

    #[test]
    fn helpers_reject_symlinks_group_writes_and_non_executables() {
        let root = tempfile::tempdir().unwrap();
        let exe = root.path().join("silo");
        let helper = root.path().join("tsgate");
        let target = root.path().join("target");
        std::fs::write(&target, b"helper").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
        symlink(&target, &helper).unwrap();
        assert!(crate::lobby::tailnet::tsgate::helper_for_executable(&exe).is_err());
        std::fs::remove_file(&helper).unwrap();
        std::fs::write(&helper, b"helper").unwrap();
        for mode in [0o775, 0o757, 0o644] {
            std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(mode)).unwrap();
            assert!(crate::lobby::tailnet::tsgate::helper_for_executable(&exe).is_err());
        }
    }
    #[test]
    fn ancestor_permissions_allow_only_platform_root_equivalent_groups() {
        use crate::lobby::tailnet::tsgate::trusted_ancestor;
        assert!(trusted_ancestor(0, 0, 0o775, 1000));
        assert!(trusted_ancestor(0, 0, 0o2775, 1000));
        assert_eq!(
            trusted_ancestor(0, 80, 0o775, 1000),
            cfg!(target_os = "macos")
        );
        assert!(!trusted_ancestor(0, 50, 0o2775, 1000));
        assert!(!trusted_ancestor(0, 0, 0o777, 1000));
        assert!(trusted_ancestor(0, 50, 0o1777, 1000));
        assert!(!trusted_ancestor(1000, 0, 0o775, 1000));
    }

    #[test]
    fn ancestor_ownership_must_be_root_or_the_daemon_user() {
        use crate::lobby::tailnet::tsgate::trusted_ancestor;
        assert!(trusted_ancestor(0, 123, 0o755, 1000));
        assert!(trusted_ancestor(1000, 123, 0o755, 1000));
        assert!(!trusted_ancestor(1001, 123, 0o755, 1000));
        assert!(!trusted_ancestor(1001, 0, 0o1777, 1000));
    }

    #[test]
    fn helpers_reject_writable_package_directories_and_ancestors() {
        use crate::lobby::tailnet::tsgate::open_helper;
        let root = tempfile::tempdir().unwrap();
        let package = root.path().join("package");
        std::fs::create_dir(&package).unwrap();
        let helper = package.join("tsgate");
        std::fs::write(&helper, b"helper").unwrap();
        std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(open_helper(&helper).is_ok());
        for unsafe_dir in [&package, &root.path().to_path_buf()] {
            for mode in [0o775, 0o777, 0o1777] {
                if nix::unistd::geteuid().is_root() && matches!(mode, 0o775 | 0o1777) {
                    continue;
                }
                std::fs::set_permissions(unsafe_dir, std::fs::Permissions::from_mode(mode))
                    .unwrap();
                assert!(open_helper(&helper).is_err());
            }
            std::fs::set_permissions(unsafe_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
    }

    #[tokio::test]
    async fn spawn_revalidates_a_previously_validated_helper() {
        use crate::lobby::tailnet::{
            tsgate::{helper_for_executable, Tsgate},
            wire::Bootstrap,
        };
        let root = tempfile::tempdir().unwrap();
        let helper = root.path().join("tsgate");
        std::fs::write(&helper, b"not executed").unwrap();
        std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o755)).unwrap();
        let binary = helper_for_executable(&root.path().join("silo")).unwrap();
        std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o777)).unwrap();
        let bootstrap = Bootstrap {
            version: 1,
            hostname: "test".into(),
            tag: "tag:silo".into(),
            control_url: String::new(),
            state_dir: String::new(),
            capability: String::new(),
            client_secret: None,
            api_base_url: None,
        };
        let error = Tsgate::spawn(&binary, bootstrap).await.err().unwrap();
        assert!(error.to_string().contains("trusted executable"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn fd_exec_uses_the_validated_inode_after_path_replacement() {
        use crate::lobby::tailnet::tsgate::open_helper;
        let root = tempfile::tempdir().unwrap();
        let helper = root.path().join("tsgate");
        std::fs::copy(std::env::current_exe().unwrap(), &helper).unwrap();
        let executable = open_helper(&helper).unwrap();
        std::fs::rename(&helper, root.path().join("original")).unwrap();
        std::fs::write(&helper, b"invalid replacement executable").unwrap();
        std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o755)).unwrap();
        let output =
            std::process::Command::new(format!("/proc/self/fd/{}", executable.as_raw_fd()))
                .args([
                    "--list",
                    "fd_exec_uses_the_validated_inode_after_path_replacement",
                ])
                .output()
                .unwrap();
        assert!(output.status.success());
        assert!(String::from_utf8(output.stdout)
            .unwrap()
            .contains("fd_exec_uses_the_validated_inode_after_path_replacement"));
    }

    fn frame(json: &str) -> Vec<u8> {
        let mut out = (json.len() as u32).to_be_bytes().to_vec();
        out.extend_from_slice(json.as_bytes());
        out
    }

    // Real sockets and real SCM_RIGHTS: proves the fd is received, usable and
    // carries bytes both ways, including a half-close.
    #[tokio::test]
    async fn conn_frame_delivers_a_working_socket_through_scm_rights() {
        let (ours, mut gate) = UnixStream::pair().unwrap();
        ours.set_nonblocking(true).unwrap();
        let ours = tokio::net::UnixStream::from_std(ours).unwrap();
        let (state_tx, state_rx) = watch::channel(NodeState::starting());
        let (conn_tx, mut conns) = mpsc::channel(4);
        let pending: Pending = Default::default();
        let reader = tokio::spawn(async move { pump(&ours, &state_tx, &conn_tx, &pending).await });

        gate.write_all(&frame(
            r#"{"type":"state","phase":"running","dns_name":"silo.ts.net.","tags":["tag:silo"]}"#,
        ))
        .unwrap();
        let (mut remote, passed) = UnixStream::pair().unwrap();
        let conn = frame(r#"{"type":"conn","listener":"ssh","remote":"100.64.0.7:2200"}"#);
        let fds = [passed.as_raw_fd()];
        sendmsg::<()>(
            gate.as_raw_fd(),
            &[IoSlice::new(&conn)],
            &[ControlMessage::ScmRights(&fds)],
            MsgFlags::empty(),
            None,
        )
        .unwrap();
        drop(passed);

        let mut connection = tokio::time::timeout(Duration::from_secs(5), conns.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(connection.remote, "100.64.0.7:2200");
        assert_eq!(state_rx.borrow().phase, Phase::Running);

        remote.write_all(b"ping").unwrap();
        remote.shutdown(std::net::Shutdown::Write).unwrap();
        let mut got = Vec::new();
        connection.stream.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"ping");
        connection.stream.write_all(b"pong").await.unwrap();
        connection.stream.shutdown().await.unwrap();
        let mut back = Vec::new();
        remote.read_to_end(&mut back).unwrap();
        assert_eq!(back, b"pong");

        drop(gate);
        let ended = tokio::time::timeout(Duration::from_secs(5), reader)
            .await
            .unwrap()
            .unwrap();
        assert!(ended.is_ok(), "clean EOF ends the pump: {ended:?}");
    }

    #[tokio::test]
    async fn fd_on_a_non_conn_frame_is_a_protocol_error() {
        let (ours, gate) = UnixStream::pair().unwrap();
        ours.set_nonblocking(true).unwrap();
        let ours = tokio::net::UnixStream::from_std(ours).unwrap();
        let (state_tx, _state_rx) = watch::channel(NodeState::starting());
        let (conn_tx, _conns) = mpsc::channel(4);
        let pending: Pending = Default::default();
        let (_keep, passed) = UnixStream::pair().unwrap();
        let state = frame(r#"{"type":"state","phase":"starting"}"#);
        let fds = [passed.as_raw_fd()];
        sendmsg::<()>(
            gate.as_raw_fd(),
            &[IoSlice::new(&state)],
            &[ControlMessage::ScmRights(&fds)],
            MsgFlags::empty(),
            None,
        )
        .unwrap();
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            pump(&ours, &state_tx, &conn_tx, &pending),
        )
        .await
        .unwrap();
        assert!(result.is_err());
        drop(gate);
    }

    /// Builds a Go command from `app/tsgate` into `dir`, pure Go (no cgo).
    fn go_build(dir: &std::path::Path, package: &str, name: &str) -> std::path::PathBuf {
        let module = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../tsgate");
        let output = dir.join(name);
        let status = std::process::Command::new("go")
            .current_dir(&module)
            .env("CGO_ENABLED", "0")
            .args(["build", "-mod=readonly", "-o"])
            .arg(&output)
            .arg(package)
            .status()
            .expect("go toolchain required for the tsgate end-to-end test");
        assert!(status.success(), "go build {package} failed");
        output
    }

    // Real tsgate, real tsnet peer, real testcontrol, this Rust client. The
    // peer writes, half-closes, and must read our reply then EOF; whois must
    // carry the peer's tag and the granted capability value; dropping our
    // end of the seam must make tsgate exit within five seconds.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tsgate_forwards_tailnet_streams_and_resolves_identity_offline() {
        use tokio::io::{AsyncBufReadExt, BufReader};

        use crate::lobby::tailnet::tsgate::Tsgate;
        use crate::lobby::tailnet::wire::Bootstrap;

        const CAPABILITY: &str = "github.com/vandycknick/silo";
        let bin = tempfile::tempdir().unwrap();
        let tsgate = go_build(bin.path(), "./cmd/tsgate", "tsgate");
        let testnet = go_build(bin.path(), "./cmd/tsgate-testnet", "tsgate-testnet");

        let mut net = tokio::process::Command::new(&testnet)
            .args([
                "--capability",
                CAPABILITY,
                "--cap-value",
                r#"{"actions":["*"]}"#,
            ])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let mut net_in = net.stdin.take().unwrap();
        let mut net_out = BufReader::new(net.stdout.take().unwrap()).lines();
        let ready = tokio::time::timeout(Duration::from_secs(60), net_out.next_line())
            .await
            .expect("testnet ready in time")
            .unwrap()
            .expect("testnet ready line");
        let control_url = serde_json::from_str::<serde_json::Value>(&ready).unwrap()["control_url"]
            .as_str()
            .unwrap()
            .to_string();

        let home = tempfile::tempdir().unwrap();
        let state_dir = home.path().join("tsgate");
        let (gate, mut conns) = Tsgate::spawn(
            &tsgate,
            Bootstrap {
                version: 1,
                hostname: "lobby".into(),
                tag: "tag:silo".into(),
                control_url,
                state_dir: state_dir.to_string_lossy().into_owned(),
                capability: CAPABILITY.into(),
                client_secret: None,
                api_base_url: None,
            },
        )
        .await
        .unwrap();
        let mut state = gate.state();
        tokio::time::timeout(
            Duration::from_secs(60),
            state.wait_for(|s| s.phase == Phase::Running),
        )
        .await
        .expect("lobby node running in time")
        .unwrap();
        assert_eq!(state.borrow().tags, vec!["tag:silo".to_string()]);
        assert_eq!(gate.state().borrow().phase, Phase::Running);

        net_in
            .write_all(b"probe lobby hello-lobby\n")
            .await
            .unwrap();
        let mut connection = tokio::time::timeout(Duration::from_secs(30), conns.recv())
            .await
            .expect("conn in time")
            .expect("conn delivered");
        let whois = gate.whois(&connection.remote).await.unwrap();
        assert_eq!(whois.tags, vec!["tag:peer".to_string()]);
        assert_eq!(
            whois.capability,
            vec![serde_json::json!({"actions": ["*"]})]
        );
        let mut got = Vec::new();
        connection.stream.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"hello-lobby", "peer half-close reaches us as EOF");
        connection
            .stream
            .write_all(b"reply-after-eof")
            .await
            .unwrap();
        connection.stream.shutdown().await.unwrap();
        drop(connection);
        let probe = tokio::time::timeout(Duration::from_secs(30), net_out.next_line())
            .await
            .expect("probe result in time")
            .unwrap()
            .unwrap();
        let probe: serde_json::Value = serde_json::from_str(&probe).unwrap();
        assert_eq!(probe["probe"], "ok", "{probe}");
        assert_eq!(probe["received"], "reply-after-eof");

        // Owner loss: close our end without a shutdown request.
        let Tsgate { child, writer, .. } = gate;
        drop(writer);
        let mut child = child.into_inner();
        let exit = tokio::time::timeout(Duration::from_secs(5), child.wait())
            .await
            .expect("tsgate exits within five seconds of owner loss")
            .unwrap();
        assert!(exit.code().is_some(), "tsgate exited, not killed: {exit:?}");
        net_in.write_all(b"quit\n").await.unwrap();
        let _ = net.wait().await;
    }
}
