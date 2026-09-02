mod discovery;
mod mux;
pub(crate) mod paths;
pub(crate) mod peer;
pub(crate) mod relay;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use notify::RecommendedWatcher;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;
use tokio::task::{JoinHandle, JoinSet};
use tokio_util::sync::CancellationToken;

use crate::virt::{VirtualMachine, VsockListener};
use crate::vsock::discovery::MAX_LISTENER_REGISTRATIONS;
use crate::vsock::paths::OwnedMux;

const WATCHER_RETRY_INTERVAL: Duration = Duration::from_secs(1);

pub(crate) struct PreparedVsockSurface {
    runtime_dir: PathBuf,
    mux_filename: std::ffi::OsString,
    mux: OwnedMux,
    watcher: Option<RecommendedWatcher>,
    dirty_tx: mpsc::Sender<()>,
    dirty_rx: mpsc::Receiver<()>,
    watcher_failed: Arc<AtomicBool>,
}

impl PreparedVsockSurface {
    pub(crate) fn prepare(runtime_dir: &Path, mux_filename: &Path) -> eyre::Result<Self> {
        let mux = OwnedMux::bind(runtime_dir, mux_filename)?;
        let (dirty_tx, dirty_rx) = mpsc::channel(1);
        let watcher_failed = Arc::new(AtomicBool::new(false));
        let watcher =
            match discovery::install_watcher(runtime_dir, dirty_tx.clone(), watcher_failed.clone())
            {
                Ok(watcher) => Some(watcher),
                Err(error) => {
                    tracing::warn!(
                        path = %runtime_dir.display(),
                        %error,
                        "vsock listener discovery watcher is unavailable; retrying"
                    );
                    None
                }
            };
        Ok(Self {
            runtime_dir: runtime_dir.to_path_buf(),
            mux_filename: mux_filename.as_os_str().to_os_string(),
            mux,
            watcher,
            dirty_tx,
            dirty_rx,
            watcher_failed,
        })
    }

    pub(crate) async fn activate(
        mut self,
        machine: VirtualMachine,
        forwards: Arc<crate::forward::ForwardTable>,
    ) -> eyre::Result<VsockSurface> {
        let _registration = forwards.lock_registrations().await;
        let discovered = discovery::scan(&self.runtime_dir, &self.mux_filename)?;
        let mut registered = forwards.registered_ports();
        let mut listeners = Vec::new();
        let _ = register_discovered(&machine, &mut registered, &mut listeners, discovered, true)
            .await?;
        drop(_registration);

        let mux_listener = self.mux.take_listener()?;
        let mux_owner_uid = self.mux.owner_uid();
        let mux_path = self.mux.path().to_path_buf();
        let shutdown = CancellationToken::new();
        let task_shutdown = shutdown.clone();
        let task = tokio::spawn(async move {
            run_surface(
                self.runtime_dir,
                self.mux_filename,
                mux_path,
                mux_listener,
                mux_owner_uid,
                machine,
                forwards,
                registered,
                listeners,
                self.watcher,
                self.dirty_tx,
                self.dirty_rx,
                self.watcher_failed,
                task_shutdown,
            )
            .await
        });
        Ok(VsockSurface {
            shutdown,
            task: Some(task),
            mux: Some(self.mux),
        })
    }
}

pub(crate) struct VsockSurface {
    shutdown: CancellationToken,
    task: Option<JoinHandle<eyre::Result<()>>>,
    mux: Option<OwnedMux>,
}

impl VsockSurface {
    pub(crate) async fn shutdown(&mut self) -> eyre::Result<()> {
        self.shutdown.cancel();
        if let Some(task) = self.task.take() {
            task.await
                .map_err(|error| eyre::eyre!("vsock surface task failed: {error}"))??;
        }
        if let Some(mut mux) = self.mux.take() {
            mux.cleanup()?;
        }
        Ok(())
    }
}

impl Drop for VsockSurface {
    fn drop(&mut self) {
        self.shutdown.cancel();
        if let Some(task) = self.task.take() {
            task.abort();
        }
        if let Some(mut mux) = self.mux.take() {
            if let Err(error) = mux.cleanup() {
                tracing::warn!(%error, "failed to clean vsock mux while dropping surface");
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_surface(
    runtime_dir: PathBuf,
    mux_filename: std::ffi::OsString,
    mux_path: PathBuf,
    mux_listener: UnixListener,
    mux_owner_uid: u32,
    machine: VirtualMachine,
    forwards: Arc<crate::forward::ForwardTable>,
    mut registered: BTreeSet<u32>,
    listeners: Vec<(u32, PathBuf, VsockListener)>,
    mut watcher: Option<RecommendedWatcher>,
    dirty_tx: mpsc::Sender<()>,
    mut dirty_rx: mpsc::Receiver<()>,
    watcher_failed: Arc<AtomicBool>,
    shutdown: CancellationToken,
) -> eyre::Result<()> {
    let mut tasks = JoinSet::new();
    tasks.spawn(mux::serve(
        mux_listener,
        mux_owner_uid,
        machine.clone(),
        shutdown.clone(),
    ));
    for (port, path, listener) in listeners {
        spawn_listener(&mut tasks, port, path, listener, shutdown.clone());
    }

    let mut retry = tokio::time::interval(WATCHER_RETRY_INTERVAL);
    retry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut registration_retry = false;
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            signal = dirty_rx.recv() => {
                if signal.is_none() {
                    break;
                }
                if watcher_failed.swap(false, Ordering::AcqRel) {
                    tracing::warn!(path = %runtime_dir.display(), "vsock listener watcher reported an error; retrying");
                    watcher = None;
                }
                registration_retry = reconcile_runtime(
                    &machine,
                    &forwards,
                    &runtime_dir,
                    &mux_filename,
                    &mut registered,
                    &mut tasks,
                    &shutdown,
                ).await;
            }
            _ = retry.tick() => {
                let mut watcher_restored = false;
                if watcher.is_none() {
                    match discovery::install_watcher(
                        &runtime_dir,
                        dirty_tx.clone(),
                        watcher_failed.clone(),
                    ) {
                        Ok(restored) => {
                            watcher = Some(restored);
                            watcher_restored = true;
                            tracing::info!(path = %runtime_dir.display(), "vsock listener discovery watcher restored");
                        }
                        Err(error) => tracing::warn!(path = %runtime_dir.display(), %error, "vsock listener discovery watcher remains unavailable"),
                    }
                }
                if watcher_restored || registration_retry {
                    registration_retry = reconcile_runtime(
                        &machine,
                        &forwards,
                        &runtime_dir,
                        &mux_filename,
                        &mut registered,
                        &mut tasks,
                        &shutdown,
                    ).await;
                }
            }
            result = tasks.join_next(), if !tasks.is_empty() => {
                if let Some(Err(error)) = result {
                    tracing::warn!(%error, "vsock surface task failed");
                }
            }
        }
    }
    drop(watcher);
    while tasks.join_next().await.is_some() {}
    tracing::debug!(path = %mux_path.display(), "vsock surface stopped");
    Ok(())
}

async fn reconcile_runtime(
    machine: &VirtualMachine,
    forwards: &Arc<crate::forward::ForwardTable>,
    runtime_dir: &Path,
    mux_filename: &std::ffi::OsStr,
    registered: &mut BTreeSet<u32>,
    tasks: &mut JoinSet<()>,
    shutdown: &CancellationToken,
) -> bool {
    let _registration = forwards.lock_registrations().await;
    registered.extend(forwards.registered_ports());
    let discovered = match discovery::scan(runtime_dir, mux_filename) {
        Ok(discovered) => discovered,
        Err(error) => {
            tracing::warn!(machine = machine.name(), path = %runtime_dir.display(), %error, "failed to reconcile vsock listeners");
            return true;
        }
    };
    let mut listeners = Vec::new();
    let retry = match register_discovered(machine, registered, &mut listeners, discovered, false)
        .await
    {
        Ok(retry) => retry,
        Err(error) => {
            tracing::warn!(machine = machine.name(), %error, "failed to register runtime vsock listener");
            true
        }
    };
    for (port, path, listener) in listeners {
        spawn_listener(tasks, port, path, listener, shutdown.clone());
    }
    retry
}

async fn register_discovered(
    machine: &VirtualMachine,
    registered: &mut BTreeSet<u32>,
    listeners: &mut Vec<(u32, PathBuf, VsockListener)>,
    discovered: Vec<(u32, PathBuf)>,
    initial: bool,
) -> eyre::Result<bool> {
    let mut retry = false;
    for (port, path) in discovered {
        if registered.contains(&port) {
            continue;
        }
        if registration_limit_reached(registered.len()) {
            tracing::warn!(machine = machine.name(), port, path = %path.display(), limit = MAX_LISTENER_REGISTRATIONS, "ignored vsock listener at registration limit");
            continue;
        }
        match machine.listen_vsock(port).await {
            Ok(listener) => {
                registered.insert(port);
                listeners.push((port, path, listener));
            }
            Err(error) if !initial => {
                tracing::warn!(machine = machine.name(), port, path = %path.display(), %error, "failed to register discovered vsock listener; retrying on a later scan");
                retry = true;
            }
            Err(error) => {
                return Err(eyre::eyre!(
                    "register initial vsock listener {} for {}: {}",
                    port,
                    path.display(),
                    error
                ));
            }
        }
    }
    Ok(retry)
}

fn registration_limit_reached(registered: usize) -> bool {
    registered >= MAX_LISTENER_REGISTRATIONS
}

fn spawn_listener(
    tasks: &mut JoinSet<()>,
    port: u32,
    path: PathBuf,
    listener: VsockListener,
    shutdown: CancellationToken,
) {
    tasks.spawn(serve_listener(port, path, listener, shutdown));
}

async fn serve_listener(
    port: u32,
    path: PathBuf,
    mut listener: VsockListener,
    shutdown: CancellationToken,
) {
    let mut relays = JoinSet::new();
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            accepted = listener.accept() => match accepted {
                Ok(guest) => match tokio::select! {
                    result = UnixStream::connect(&path) => Some(result),
                    _ = shutdown.cancelled() => None,
                } {
                    None => break,
                    Some(Ok(host)) => {
                        let shutdown = shutdown.clone();
                        relays.spawn(async move {
                            if let Err(error) = relay::relay(guest, host, shutdown).await {
                                tracing::debug!(port, %error, "guest-initiated vsock relay ended with an error");
                            }
                        });
                    }
                    Some(Err(error)) => tracing::debug!(port, path = %path.display(), %error, "reset guest connection because the host listener is unavailable"),
                },
                Err(error) => {
                    tracing::warn!(port, %error, "guest-initiated vsock accept failed");
                    tokio::select! {
                        _ = tokio::time::sleep(Duration::from_millis(10)) => {}
                        _ = shutdown.cancelled() => break,
                    }
                }
            },
            result = relays.join_next(), if !relays.is_empty() => {
                if let Some(Err(error)) = result {
                    tracing::warn!(port, %error, "guest-initiated vsock relay task failed");
                }
            }
        }
    }
    while relays.join_next().await.is_some() {}
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;

    use crate::virt::{BackendKind, VirtualMachine, VmConfig};
    use crate::vsock::{register_discovered, registration_limit_reached, PreparedVsockSurface};

    fn temp_dir(_label: &str) -> std::path::PathBuf {
        let path = std::path::Path::new("/tmp").join(format!(
            "vs-{:x}-{:x}",
            std::process::id(),
            rand::random::<u32>()
        ));
        std::fs::create_dir(&path).expect("create temp directory");
        path
    }

    #[test]
    fn listener_registration_limit_is_exactly_1024() {
        assert!(!registration_limit_reached(1023));
        assert!(registration_limit_reached(1024));
        assert!(registration_limit_reached(1025));
    }

    #[tokio::test]
    async fn listener_registration_limit_is_deterministic_and_monotonic() {
        const FIRST_NEW_PORT: u32 = 2000;
        const SECOND_NEW_PORT: u32 = 2001;
        const REPLACEMENT_PORT: u32 = 2002;

        let root = std::path::Path::new("/tmp").join(format!(
            "vsr-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&root).expect("create short temp directory");
        let config = VmConfig::builder("surface-registration-limit")
            .base_directory(&root)
            .kernel(Path::new("/mock-kernel"))
            .build();
        let machine =
            VirtualMachine::with_backend(BackendKind::Mock, config).expect("create mock machine");
        machine.start().await.expect("start mock machine");
        let discovered = vec![
            (
                FIRST_NEW_PORT,
                root.join(format!("vsock.sock_{FIRST_NEW_PORT}")),
            ),
            (
                SECOND_NEW_PORT,
                root.join(format!("vsock.sock_{SECOND_NEW_PORT}")),
            ),
        ];
        let mut registered = (1..=1023).collect::<std::collections::BTreeSet<_>>();
        let mut listeners = Vec::new();

        assert!(
            !register_discovered(&machine, &mut registered, &mut listeners, discovered, false,)
                .await
                .expect("register listeners")
        );
        assert_eq!(registered.len(), 1024);
        assert_eq!(listeners.len(), 1);
        assert!(registered.contains(&FIRST_NEW_PORT));
        assert!(!registered.contains(&SECOND_NEW_PORT));

        assert!(!register_discovered(
            &machine,
            &mut registered,
            &mut listeners,
            vec![(
                REPLACEMENT_PORT,
                root.join(format!("vsock.sock_{REPLACEMENT_PORT}")),
            )],
            false,
        )
        .await
        .expect("reconcile after reaching the limit"));
        assert_eq!(registered.len(), 1024);
        assert_eq!(listeners.len(), 1);
        assert!(!registered.contains(&REPLACEMENT_PORT));

        drop(listeners);
        machine.stop().await.expect("stop mock machine");
        std::fs::remove_dir_all(root).expect("remove temp directory");
    }

    #[tokio::test]
    async fn mux_connects_without_losing_pipelined_bytes_and_cleans_up() {
        let root = temp_dir("mux");
        let runtime_dir = root.join("run");
        std::fs::create_dir(&runtime_dir).expect("create runtime directory");
        let config = VmConfig::builder("surface-mux")
            .base_directory(&root)
            .kernel(Path::new("/mock-kernel"))
            .build();
        let machine =
            VirtualMachine::with_backend(BackendKind::Mock, config).expect("create mock machine");
        let prepared = PreparedVsockSurface::prepare(&runtime_dir, Path::new("vsock.sock"))
            .expect("prepare surface");
        machine.start().await.expect("start mock machine");
        let forwards = crate::forward::ForwardTable::prepare_machine(&[], &runtime_dir, None)
            .await
            .expect("prepare empty forward table");
        let mut surface = prepared
            .activate(machine.clone(), forwards)
            .await
            .expect("activate surface");

        let mux_path = runtime_dir.join("vsock.sock");
        let mut client = UnixStream::connect(&mux_path).await.expect("connect mux");
        client
            .write_all(b"CONNECT 22\nhello")
            .await
            .expect("write pipelined request");
        let acknowledgement = format!("OK {}\n", 1_u32 << 30);
        let mut received = vec![0_u8; acknowledgement.len() + 5];
        client
            .read_exact(&mut received)
            .await
            .expect("read acknowledgement and echo");
        assert_eq!(
            &received[..acknowledgement.len()],
            acknowledgement.as_bytes()
        );
        assert_eq!(&received[acknowledgement.len()..], b"hello");

        surface.shutdown().await.expect("stop surface");
        machine.stop().await.expect("stop mock machine");
        assert!(!mux_path.exists());
        let _ = std::fs::remove_dir_all(root);
    }
}
