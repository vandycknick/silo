use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::mpsc;

pub(crate) const MAX_LISTENER_REGISTRATIONS: usize = 1024;

pub(crate) fn scan(
    runtime_dir: &Path,
    mux_filename: &OsStr,
) -> std::io::Result<Vec<(u32, PathBuf)>> {
    let mut listeners = Vec::new();
    for entry in std::fs::read_dir(runtime_dir)? {
        let entry = entry?;
        let Some(port) = listener_port(mux_filename, &entry.file_name()) else {
            continue;
        };
        if port == protocol::DEFAULT_GUEST_CONTROL_PORT {
            continue;
        }
        let metadata = match std::fs::symlink_metadata(entry.path()) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        if metadata.file_type().is_symlink() || !metadata.file_type().is_socket() {
            continue;
        }
        listeners.push((port, entry.path()));
    }
    listeners.sort_unstable_by_key(|(port, _)| *port);
    listeners.dedup_by_key(|(port, _)| *port);
    Ok(listeners)
}

pub(crate) fn listener_port(mux_filename: &OsStr, filename: &OsStr) -> Option<u32> {
    let mux = mux_filename.as_bytes();
    let filename = filename.as_bytes();
    if filename.len() <= mux.len() + 1
        || !filename.starts_with(mux)
        || filename.get(mux.len()) != Some(&b'_')
    {
        return None;
    }
    let raw = std::str::from_utf8(&filename[mux.len() + 1..]).ok()?;
    if raw.len() > 1 && raw.starts_with('0') {
        return None;
    }
    let port = raw.parse::<u32>().ok()?;
    (port.to_string() == raw).then_some(port)
}

pub(crate) fn install_watcher(
    runtime_dir: &Path,
    dirty: mpsc::Sender<()>,
    failed: Arc<AtomicBool>,
) -> notify::Result<RecommendedWatcher> {
    let mut watcher = notify::recommended_watcher(move |result: notify::Result<notify::Event>| {
        if result.is_err() {
            failed.store(true, Ordering::Release);
        }
        let _ = dirty.try_send(());
    })?;
    watcher.watch(runtime_dir, RecursiveMode::NonRecursive)?;
    Ok(watcher)
}

#[cfg(test)]
mod tests {
    use std::ffi::{OsStr, OsString};
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::symlink;

    use tokio::net::UnixListener;

    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;

    use tokio::sync::mpsc;

    use crate::vsock::discovery::{install_watcher, listener_port, scan};

    fn temp_dir() -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "vmmon-vsock-discovery-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&path).expect("create temp directory");
        path
    }

    #[test]
    fn parses_only_canonical_listener_names() {
        let mux = OsStr::new("vsock.sock");
        for (name, expected) in [
            ("vsock.sock_0", Some(0)),
            ("vsock.sock_22", Some(22)),
            ("vsock.sock_4294967295", Some(u32::MAX)),
            ("vsock.sock_00", None),
            ("vsock.sock_01", None),
            ("vsock.sock_+1", None),
            ("vsock.sock_-1", None),
            ("vsock.sock_4294967296", None),
            ("vsock.sock_", None),
            ("other_22", None),
        ] {
            assert_eq!(listener_port(mux, OsStr::new(name)), expected, "{name}");
        }
        assert_eq!(
            listener_port(mux, &OsString::from_vec(b"vsock.sock_\xff".to_vec())),
            None
        );
    }

    #[tokio::test]
    async fn scan_returns_only_real_canonical_sockets_in_port_order() {
        let dir = temp_dir();
        let mut sockets = Vec::new();
        for port in [5000, 22, protocol::DEFAULT_GUEST_CONTROL_PORT] {
            sockets.push(
                UnixListener::bind(dir.join(format!("vsock.sock_{port}")))
                    .expect("bind listener socket"),
            );
        }
        std::fs::write(dir.join("vsock.sock_40"), b"regular").expect("create regular entry");
        std::fs::create_dir(dir.join("vsock.sock_41")).expect("create directory entry");
        symlink(dir.join("vsock.sock_22"), dir.join("vsock.sock_42")).expect("create symlink");
        let _noncanonical =
            UnixListener::bind(dir.join("vsock.sock_05000")).expect("bind noncanonical socket");

        let discovered = scan(&dir, OsStr::new("vsock.sock")).expect("scan listeners");
        assert_eq!(
            discovered.iter().map(|(port, _)| *port).collect::<Vec<_>>(),
            [22, 5000]
        );

        drop(sockets);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn watcher_reports_real_directory_changes_through_a_bounded_signal() {
        let dir = temp_dir();
        let (dirty_tx, mut dirty_rx) = mpsc::channel(1);
        let failed = Arc::new(AtomicBool::new(false));
        let _watcher = install_watcher(&dir, dirty_tx, failed).expect("install watcher");

        let _listener =
            UnixListener::bind(dir.join("vsock.sock_5000")).expect("publish listener socket");
        tokio::time::timeout(std::time::Duration::from_secs(5), dirty_rx.recv())
            .await
            .expect("watch notification deadline")
            .expect("watch notification");

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn watcher_installation_recovers_after_the_directory_appears() {
        let parent = temp_dir();
        let dir = parent.join("missing");
        let (dirty_tx, _dirty_rx) = mpsc::channel(1);
        let failed = Arc::new(AtomicBool::new(false));
        assert!(install_watcher(&dir, dirty_tx, failed).is_err());

        std::fs::create_dir(&dir).expect("create recovered directory");
        let (dirty_tx, mut dirty_rx) = mpsc::channel(1);
        let failed = Arc::new(AtomicBool::new(false));
        let _watcher = install_watcher(&dir, dirty_tx, failed).expect("restore watcher");
        let _listener = UnixListener::bind(dir.join("vsock.sock_5000"))
            .expect("publish listener after recovery");
        tokio::time::timeout(std::time::Duration::from_secs(5), dirty_rx.recv())
            .await
            .expect("recovered watch notification deadline")
            .expect("recovered watch notification");

        let _ = std::fs::remove_dir_all(parent);
    }
}
