//! Optional frontend lifetime. The only owner-pipe writer stays in this task.
use crate::{control::ControlState, status::StatusPublisher};
use eyre::Context;
use prost::Message;
use silo_secrets::{FileStore, Secret, SecretName, SecretScope, SecretStore};
use silod_spec::{
    daemon::v1 as w,
    status::{ComponentState, ComponentStatus, ShutdownProtection},
};
use std::{
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::Duration,
};
use tokio::{io::AsyncWriteExt, process::Command};
use tokio_util::sync::CancellationToken;
use zeroize::{Zeroize, Zeroizing};

const FRAME_LIMIT: usize = 64 * 1024;
const SECRET_LIMIT: usize = 16 * 1024;

fn sibling(executable: &Path, name: &str, executable_file: bool) -> eyre::Result<PathBuf> {
    let parent = executable
        .parent()
        .ok_or_else(|| eyre::eyre!("missing executable parent"))?;
    let path = parent.join(name);
    let m = std::fs::symlink_metadata(&path)?;
    eyre::ensure!(
        m.is_file()
            && !m.file_type().is_symlink()
            && (m.uid() == nix::unistd::geteuid().as_raw() || m.uid() == 0)
            && m.mode() & 0o022 == 0
            && (!executable_file || m.mode() & 0o111 != 0),
        "unsafe helper package sibling {name}"
    );
    let canonical = path.canonicalize()?;
    eyre::ensure!(
        canonical.parent() == Some(parent),
        "helper sibling escaped package"
    );
    Ok(canonical)
}
fn document(path: PathBuf) -> eyre::Result<Option<Vec<u8>>> {
    match std::fs::symlink_metadata(&path) {
        Ok(m) => {
            eyre::ensure!(m.is_dir(), "document root is not a directory");
            Ok(Some(silo_vm_control::path_to_wire(&path.canonicalize()?)))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}
fn credential(store: &FileStore, name: &str) -> eyre::Result<Option<Vec<u8>>> {
    match store
        .get(&SecretScope::Home, &SecretName::new(name)?)
        .map_err(|_| eyre::eyre!("cannot read helper credential {name}"))?
    {
        None => Ok(None),
        Some(Secret::Plain(value)) => {
            eyre::ensure!(
                value.as_bytes().len() <= SECRET_LIMIT,
                "helper credential {name} exceeds 16KiB"
            );
            Ok(Some(value.as_bytes().to_vec()))
        }
        Some(_) => eyre::bail!("helper credential {name} must be plain"),
    }
}
fn settings(c: &silo_config::tailscale::TailscaleConfig) -> eyre::Result<w::TailscaleSettings> {
    let d = c.vm().defaults();
    let ceilings = c.vm().ceilings();
    Ok(w::TailscaleSettings {
        hostname: c.hostname().into(),
        tag: c.tag().into(),
        control_url: c.control_url().into(),
        enrollment_mode: match c.enrollment_mode() {
            silo_config::tailscale::EnrollmentMode::OauthApp => w::EnrollmentMode::OauthApp as i32,
            silo_config::tailscale::EnrollmentMode::Interactive => {
                w::EnrollmentMode::Interactive as i32
            }
            silo_config::tailscale::EnrollmentMode::None => w::EnrollmentMode::None as i32,
        },
        disable_key_expiry: c.disable_key_expiry(),
        default_image: c.vm().default_image().into(),
        allowed_registries: c.vm().allowed_registries().to_vec(),
        defaults: Some(w::ResourceDefaults {
            cpus: d.cpus().try_into()?,
            memory_bytes: d.memory(),
            disk_bytes: d.disk(),
        }),
        ceilings: Some(w::ResourceCeilings {
            cpus: ceilings.cpus().try_into()?,
            memory_bytes: ceilings.memory(),
            disk_bytes: ceilings.disk(),
            vms_per_principal: ceilings.vms_per_principal(),
        }),
        sessions_global: c.sessions().global(),
        sessions_per_peer: c.sessions().per_peer(),
        disk_reserve_bytes: c.disk_reserve(),
        stop_budget: Some(c.shutdown().stop_budget().try_into()?),
        shutdown_margin: Some(c.shutdown().margin().try_into()?),
    })
}
fn encode(mut bootstrap: w::HelperBootstrap) -> eyre::Result<Zeroizing<Vec<u8>>> {
    let size = bootstrap.encoded_len();
    let result = if size == 0 || size > FRAME_LIMIT {
        Err(eyre::eyre!("helper bootstrap exceeds frame limit"))
    } else {
        let mut frame = Zeroizing::new(Vec::with_capacity(size + 4));
        frame.extend_from_slice(&(size as u32).to_be_bytes());
        bootstrap
            .encode(&mut *frame)
            .map(|()| frame)
            .map_err(Into::into)
    };
    bootstrap.client_secret.zeroize();
    bootstrap.oauth_app_secret.zeroize();
    bootstrap.api_token.zeroize();
    result
}
async fn write_frame(
    owner: &mut tokio::process::ChildStdin,
    frame: &[u8],
    budget: Duration,
) -> eyre::Result<()> {
    let prefix: [u8; 4] = frame
        .get(..4)
        .ok_or_else(|| eyre::eyre!("truncated bootstrap prefix"))?
        .try_into()?;
    let length = u32::from_be_bytes(prefix) as usize;
    eyre::ensure!(
        length != 0 && length <= FRAME_LIMIT && frame.len() == length + 4,
        "invalid helper bootstrap frame length"
    );
    tokio::time::timeout(budget, owner.write_all(frame))
        .await
        .map_err(|_| eyre::eyre!("helper bootstrap write deadline expired"))??;
    Ok(())
}
fn bootstrap(
    identity: &w::DaemonStatus,
    c: &silo_config::tailscale::TailscaleConfig,
    generation: uuid::Uuid,
) -> eyre::Result<w::HelperBootstrap> {
    Ok(w::HelperBootstrap {
        protocol_major: identity.protocol_major,
        product_version: identity.product_version.clone(),
        daemon_generation: identity.generation.clone(),
        helper_generation: generation.to_string(),
        control_endpoint: identity.control_endpoint.clone(),
        home: identity.home.clone(),
        config_dir: identity.config_dir.clone(),
        settings: Some(settings(c)?),
        ..Default::default()
    })
}

fn spawn(path: &Path, shutdown_only: bool) -> eyre::Result<tokio::process::Child> {
    let mut command = Command::new(path);
    if shutdown_only {
        command.arg("--shutdown-only");
    }
    command
        .args(["--bootstrap-fd", "0"])
        .stdin(Stdio::piped())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .kill_on_drop(true);
    for (key, _) in std::env::vars_os() {
        let bytes = key.as_encoded_bytes();
        if bytes.starts_with(b"SILO_") || bytes.starts_with(b"TS_") || bytes.starts_with(b"TSNET_")
        {
            command.env_remove(key);
        }
    }
    Ok(command.spawn()?)
}

#[cfg(target_os = "linux")]
/// One-shot owner pipe, deliberately independent of normal helper generations.
pub(crate) async fn host_shutdown(
    identity: &w::DaemonStatus,
    config: &silo_config::tailscale::TailscaleConfig,
    deadline: tokio::time::Instant,
) -> eyre::Result<()> {
    let exe = std::env::current_exe()?.canonicalize()?;
    let path = sibling(&exe, "taild", true).wrap_err("matching taild sibling unavailable")?;
    let frame = encode(bootstrap(identity, config, uuid::Uuid::new_v4())?)?;
    let mut child = spawn(&path, true)?;
    let mut owner = child
        .stdin
        .take()
        .ok_or_else(|| eyre::eyre!("helper owner pipe unavailable"))?;
    let result = tokio::time::timeout_at(deadline, async {
        write_frame(&mut owner, &frame, Duration::from_secs(2)).await?;
        drop(frame);
        let status = child.wait().await?;
        eyre::ensure!(status.success(), "shutdown helper exited: {status}");
        Ok::<(), eyre::Report>(())
    })
    .await
    .map_err(|_| eyre::eyre!("shutdown helper deadline expired"))
    .and_then(|r| r);
    if result.is_err() {
        tokio::time::timeout(Duration::from_secs(2), reap(&mut child))
            .await
            .map_err(|_| eyre::eyre!("shutdown helper kill/reap deadline expired"))??;
    }
    // EOF is owner loss, so retain the writer until the child is reaped.
    drop(owner);
    result
}
async fn prepare(
    state: &ControlState,
    c: &silo_config::tailscale::TailscaleConfig,
    generation: uuid::Uuid,
) -> eyre::Result<(PathBuf, Zeroizing<Vec<u8>>)> {
    let exe = std::env::current_exe()?.canonicalize()?;
    let taild = sibling(&exe, "taild", true).wrap_err("matching taild sibling unavailable")?;
    let bridge = sibling(
        &exe,
        if cfg!(target_os = "macos") {
            "libsilo_go_ffi.dylib"
        } else {
            "libsilo_go_ffi.so"
        },
        false,
    )
    .wrap_err("matching native bridge sibling unavailable")?;
    let components = state.components().await?;
    let host = &state.host;
    let store = FileStore::new(host.home());
    // Allocate credential fields last and erase them even when later reads fail.
    let mut bootstrap = bootstrap(&state.get_status().await?, c, generation)?;
    bootstrap.templates_dir = document(host.config_dir().join("templates"))?;
    bootstrap.policies_dir = document(host.config_dir().join("policies"))?;
    bootstrap.runtime_components = Some(w::RuntimeComponents {
        supervisor_path: silo_vm_control::path_to_wire(components.supervisor()),
        netd_path: silo_vm_control::path_to_wire(components.netd()),
        kernel_path: silo_vm_control::path_to_wire(components.kernel()),
        initramfs_path: silo_vm_control::path_to_wire(components.initramfs()),
        agent_path: silo_vm_control::path_to_wire(components.agent()),
        asset_dir: silo_vm_control::path_to_wire(components.asset_dir()),
    });
    bootstrap.native_bridge_path = silo_vm_control::path_to_wire(&bridge);
    let (tx, rx) = tokio::sync::oneshot::channel();
    // FileStore uses a blocking advisory lock. An external same-user writer
    // must not pin Tokio runtime shutdown; this thread never owns a lifeline.
    std::thread::Builder::new()
        .name("taild-bootstrap".into())
        .spawn(move || {
            let result = (|| {
                let read = (|| -> eyre::Result<()> {
                    bootstrap.client_secret = credential(&store, "tailscale.lobby.client_secret")?;
                    bootstrap.oauth_app_secret =
                        credential(&store, "tailscale.lobby.oauth_app_secret")?;
                    bootstrap.api_token = credential(&store, "tailscale.lobby.api_token")?;
                    Ok(())
                })();
                if let Err(error) = read {
                    bootstrap.client_secret.zeroize();
                    bootstrap.oauth_app_secret.zeroize();
                    bootstrap.api_token.zeroize();
                    return Err(error);
                }
                encode(bootstrap)
            })();
            let _ = tx.send(result);
        })?;
    let frame = rx.await??;
    Ok((taild, frame))
}
fn publish(
    publisher: &StatusPublisher,
    state: ComponentState,
    count: u32,
    diagnostic: Option<String>,
) -> eyre::Result<()> {
    publisher.set_tailscale(ComponentStatus {
        enabled: true,
        state,
        diagnostic,
        approval_url: None,
        dns_name: None,
        restart_count: count,
        shutdown_protection: if cfg!(target_os = "macos") {
            ShutdownProtection::Unsupported
        } else {
            ShutdownProtection::Unavailable
        },
    })
}
fn terminate(child: &tokio::process::Child) -> eyre::Result<()> {
    if let Some(pid) = child.id() {
        // The unreaped child owns this PID; no shell or process-group signalling.
        match nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(pid.try_into()?),
            nix::sys::signal::Signal::SIGTERM,
        ) {
            Ok(()) | Err(nix::errno::Errno::ESRCH) => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}
async fn reap(child: &mut tokio::process::Child) -> eyre::Result<()> {
    child.start_kill()?;
    child.wait().await?;
    Ok(())
}
pub(crate) async fn serve(
    state: Arc<ControlState>,
    config: silo_config::tailscale::TailscaleConfig,
    publisher: Arc<StatusPublisher>,
    shutdown: CancellationToken,
) -> eyre::Result<()> {
    let mut count = 0u32;
    let mut delay = 1u64;
    loop {
        if shutdown.is_cancelled() {
            return Ok(());
        }
        let generation = uuid::Uuid::new_v4();
        let prepared = tokio::select! {
            result = tokio::time::timeout(Duration::from_secs(10), prepare(&state, &config, generation)) => result.map_err(|_| eyre::eyre!("helper setup deadline expired")).and_then(|r| r),
            _ = shutdown.cancelled() => return Ok(()),
        };
        let (path, frame) = match prepared {
            Ok(v) => v,
            Err(error) => {
                publish(
                    &publisher,
                    ComponentState::Failed,
                    count,
                    Some(format!("{error:#}")),
                )?;
                return Ok(());
            }
        };
        publish(&publisher, ComponentState::Starting, count, None)?;
        state.set_helper_generation(Some(generation)).await;
        let mut child = match spawn(&path, false) {
            Ok(child) => child,
            Err(error) => {
                state.set_helper_generation(None).await;
                publish(
                    &publisher,
                    ComponentState::Failed,
                    count,
                    Some(format!("helper spawn failed: {error}")),
                )?;
                return Ok(());
            }
        };
        // Child stdin is a FIFO. std/process creates CLOEXEC parent endpoints;
        // only the read end is duplicated to fd0 in the helper.
        let mut owner = child
            .stdin
            .take()
            .ok_or_else(|| eyre::eyre!("helper owner pipe unavailable"))?;
        let write = tokio::select! {
            result = write_frame(&mut owner, &frame, Duration::from_secs(10)) => result,
            _ = shutdown.cancelled() => Err(eyre::eyre!("helper bootstrap interrupted by shutdown")),
        };
        drop(frame);
        let healthy_since = tokio::time::Instant::now();
        let exit = if write.is_err() {
            reap(&mut child).await?;
            None
        } else {
            tokio::select! {
                result = child.wait() => Some(result?),
                _ = shutdown.cancelled() => {
                    terminate(&child)?;
                    match tokio::time::timeout(Duration::from_secs(78), child.wait()).await {
                        Ok(result) => { result?; }
                        Err(_) => { tokio::time::timeout(Duration::from_secs(2), reap(&mut child)).await
                            .map_err(|_| eyre::eyre!("helper kill/reap deadline expired"))??; }
                    }
                    drop(owner);
                    state.set_helper_generation(None).await;
                    return Ok(());
                }
            }
        };
        drop(owner);
        state.set_helper_generation(None).await;
        if shutdown.is_cancelled() {
            return Ok(());
        }
        let diagnostic = match write {
            Err(e) => format!("{e:#}"),
            Ok(()) => match exit {
                Some(status) => format!("helper exited: {status}"),
                None => "helper exited without a process status".into(),
            },
        };
        publish(&publisher, ComponentState::Failed, count, Some(diagnostic))?;
        if exit.is_some_and(|s| s.code() == Some(2)) {
            return Ok(());
        }
        if healthy_since.elapsed() >= Duration::from_secs(60) {
            delay = 1;
        }
        tokio::select! { _ = shutdown.cancelled() => return Ok(()), _ = tokio::time::sleep(Duration::from_secs(delay)) => {} }
        delay = (delay * 2).min(30);
        count = count.saturating_add(1);
    }
}

#[cfg(test)]
mod tests {
    use crate::helper::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    #[test]
    fn shutdown_frame_never_resolves_assets_documents_or_credentials() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        let config = root.path().join("config");
        std::fs::create_dir(&home).unwrap();
        std::fs::create_dir(&config).unwrap();
        // These paths would fail ordinary preparation; shutdown never reads them.
        std::fs::write(home.join("secrets.json"), b"invalid secrets").unwrap();
        symlink(root.path().join("missing"), config.join("templates")).unwrap();
        symlink(root.path().join("missing"), config.join("policies")).unwrap();
        let daemon = uuid::Uuid::new_v4();
        let helper = uuid::Uuid::new_v4();
        let identity = w::DaemonStatus {
            protocol_major: 1,
            product_version: env!("CARGO_PKG_VERSION").into(),
            generation: daemon.to_string(),
            home: silo_vm_control::path_to_wire(&home.canonicalize().unwrap()),
            config_dir: silo_vm_control::path_to_wire(&config.canonicalize().unwrap()),
            control_endpoint: b"/private/control.sock".to_vec(),
            ..Default::default()
        };
        let config = silo_config::GlobalConfig::default();
        let frame = encode(bootstrap(&identity, config.tailscale(), helper).unwrap()).unwrap();
        let decoded = w::HelperBootstrap::decode(&frame[4..]).unwrap();
        assert_eq!(decoded.daemon_generation, daemon.to_string());
        assert_eq!(decoded.helper_generation, helper.to_string());
        assert_eq!(decoded.home, identity.home);
        assert_eq!(decoded.config_dir, identity.config_dir);
        assert_eq!(decoded.control_endpoint, identity.control_endpoint);
        assert!(decoded.native_bridge_path.is_empty());
        assert!(decoded.runtime_components.is_none());
        assert!(decoded.templates_dir.is_none());
        assert!(decoded.policies_dir.is_none());
        assert!(decoded.client_secret.is_none());
        assert!(decoded.oauth_app_secret.is_none());
        assert!(decoded.api_token.is_none());
        assert_eq!(
            decoded.settings,
            Some(settings(config.tailscale()).unwrap())
        );
        assert!(!home.join("state.db").exists());
        assert!(!home.join("taild").exists());
    }
    #[test]
    fn siblings_reject_links_writable_and_nonexecutable_files() {
        let root = tempfile::tempdir().unwrap();
        let exe = root.path().join("silod");
        let target = root.path().join("taild");
        std::fs::write(&target, b"binary").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(sibling(&exe, "taild", true).unwrap(), target);
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o720)).unwrap();
        assert!(sibling(&exe, "taild", true).is_err());
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(sibling(&exe, "taild", true).is_err());
        symlink(&target, root.path().join("linked")).unwrap();
        assert!(sibling(&exe, "linked", false).is_err());
    }
    #[test]
    fn frame_limit_and_big_endian_prefix() {
        let b = w::HelperBootstrap {
            protocol_major: 1,
            ..Default::default()
        };
        let frame = encode(b).unwrap();
        assert_eq!(
            u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize,
            frame.len() - 4
        );
        assert!(w::HelperBootstrap::decode(&frame[4..]).is_ok());
        assert!(encode(w::HelperBootstrap {
            client_secret: Some(vec![1; FRAME_LIMIT]),
            ..Default::default()
        })
        .is_err());
    }
    #[tokio::test]
    async fn malformed_frames_never_reach_owner_pipe() {
        let mut child = Command::new("/bin/cat")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let mut owner = child.stdin.take().unwrap();
        for frame in [vec![], vec![0; 4], vec![0, 0, 0, 1], vec![0, 1, 0, 1]] {
            assert!(write_frame(&mut owner, &frame, Duration::from_millis(20))
                .await
                .is_err());
        }
        drop(owner);
        let output = tokio::time::timeout(Duration::from_secs(2), child.wait_with_output())
            .await
            .unwrap()
            .unwrap();
        assert!(output.stdout.is_empty());
    }
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn stalled_bootstrap_writer_has_bounded_deadline() {
        let mut child = Command::new("/bin/sleep")
            .arg("10")
            .stdin(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let mut owner = child.stdin.take().unwrap();
        assert!(nix::fcntl::fcntl(&owner, nix::fcntl::FcntlArg::F_SETPIPE_SZ(4096)).unwrap() > 0);
        let mut frame = vec![0; FRAME_LIMIT + 4];
        frame[..4].copy_from_slice(&(FRAME_LIMIT as u32).to_be_bytes());
        assert!(write_frame(&mut owner, &frame, Duration::from_millis(20))
            .await
            .is_err());
        drop(owner);
        child.kill().await.unwrap();
    }
    #[tokio::test]
    async fn owner_writer_is_not_inherited_by_other_children() {
        let mut reader = Command::new("/bin/cat")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let owner = reader.stdin.take().unwrap();
        let mut unrelated = Command::new("/bin/sleep")
            .arg("10")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        drop(owner);
        assert!(tokio::time::timeout(Duration::from_secs(2), reader.wait())
            .await
            .unwrap()
            .unwrap()
            .success());
        assert!(unrelated.try_wait().unwrap().is_none());
        unrelated.kill().await.unwrap();
    }
    #[test]
    fn credentials_missing_plain_bounded_and_corrupt() {
        let root = tempfile::tempdir().unwrap();
        let store = FileStore::new(root.path());
        let name = SecretName::new("tailscale.lobby.client_secret").unwrap();
        assert!(credential(&store, name.as_str()).unwrap().is_none());
        store
            .put(
                &SecretScope::Home,
                &name,
                Secret::Plain(silo_secrets::SecretBytes::new(vec![1; SECRET_LIMIT])),
            )
            .unwrap();
        assert_eq!(
            credential(&store, name.as_str()).unwrap().unwrap().len(),
            SECRET_LIMIT
        );
        store
            .put(
                &SecretScope::Home,
                &name,
                Secret::Plain(silo_secrets::SecretBytes::new(vec![1; SECRET_LIMIT + 1])),
            )
            .unwrap();
        assert!(credential(&store, name.as_str()).is_err());
        std::fs::write(store.path(), b"not json").unwrap();
        assert!(credential(&store, name.as_str()).is_err());
    }
    #[test]
    fn oauth_frontend_credentials_are_not_projected_as_plain() {
        let root = tempfile::tempdir().unwrap();
        let store = FileStore::new(root.path());
        let name = SecretName::new("tailscale.lobby.client_secret").unwrap();
        store
            .put(
                &SecretScope::Home,
                &name,
                Secret::OAuth(silo_secrets::OAuthSecret {
                    provider: None,
                    access_token: silo_secrets::SecretBytes::new(b"access".to_vec()),
                    refresh_token: silo_secrets::SecretBytes::new(b"refresh".to_vec()),
                    expires_at: chrono::Utc::now(),
                    account_id: None,
                    created_at: None,
                    updated_at: None,
                }),
            )
            .unwrap();
        assert!(credential(&store, name.as_str()).is_err());
    }
}
