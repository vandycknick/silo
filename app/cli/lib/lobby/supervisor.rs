//! Owns the lobby for one daemon lifetime, independently of gateway generations.
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use eyre::WrapErr;
use parking_lot::RwLock;
use silo_secrets::{FileStore, Secret, SecretName, SecretScope, SecretStore};
use silod_spec::status::{LobbyPhase, LobbyStatus};
use tokio::{task::JoinSet, time::Instant};
use tokio_util::sync::CancellationToken;

use crate::{
    config::tailscale::TailscaleConfig,
    daemon::{control::lobby::Management, status::StatusPublisher},
    lobby::{
        audit::Audit,
        consent::{Manager, OAuth, Registry},
        failure::{Code, Failure},
        identity::{self, Limits},
        identity_source::IdentitySource,
        jobs,
        metrics::Metrics,
        service::{enrollment::NodePin, Service, ServiceConfig},
        ssh::server::Server,
        state,
        tailnet::{
            tsgate::{adjacent_binary, Tsgate},
            wire::{Bootstrap, Listener, NodeState, Phase},
        },
    },
};

const CAPABILITY: &str = "github.com/vandycknick/silo";
const STOP_BUDGET: Duration = Duration::from_secs(85);
const SECRET_LIMIT: usize = 16 * 1024;

pub(crate) struct LobbyContext {
    pub(crate) host: libvm::HostPaths,
    pub(crate) settings: TailscaleConfig,
    pub(crate) management: Management,
    pub(crate) publisher: Arc<StatusPublisher>,
    pub(crate) binary: PathBuf,
}

impl LobbyContext {
    pub(crate) fn new(
        host: libvm::HostPaths,
        settings: TailscaleConfig,
        management: Management,
        publisher: Arc<StatusPublisher>,
    ) -> eyre::Result<Self> {
        Ok(Self {
            host,
            settings,
            management,
            publisher,
            binary: adjacent_binary()?,
        })
    }
}

struct Credentials {
    client_secret: Option<String>,
    oauth_app_secret: Option<String>,
}

fn credential(store: &FileStore, name: &str) -> eyre::Result<Option<String>> {
    match store
        .get(&SecretScope::Home, &SecretName::new(name)?)
        .map_err(|_| eyre::eyre!("cannot read lobby credential {name}"))?
    {
        None => Ok(None),
        Some(Secret::Plain(value)) => {
            eyre::ensure!(
                value.as_bytes().len() <= SECRET_LIMIT,
                "lobby credential {name} exceeds 16KiB"
            );
            Ok(Some(
                std::str::from_utf8(value.as_bytes())
                    .wrap_err_with(|| format!("lobby credential {name} is not UTF-8"))?
                    .to_owned(),
            ))
        }
        Some(_) => eyre::bail!("lobby credential {name} must be plain"),
    }
}

async fn credentials(home: &Path) -> eyre::Result<Credentials> {
    let store = FileStore::new(home);
    let (send, receive) = tokio::sync::oneshot::channel();
    // FileStore's advisory lock must not pin Tokio runtime shutdown.
    std::thread::Builder::new()
        .name("lobby-credentials".into())
        .spawn(move || {
            let result = (|| {
                let client_secret = credential(&store, "tailscale.lobby.client_secret")?;
                let oauth_app_secret = credential(&store, "tailscale.lobby.oauth_app_secret")?;
                credential(&store, "tailscale.lobby.api_token")?;
                Ok(Credentials {
                    client_secret,
                    oauth_app_secret,
                })
            })();
            let _ = send.send(result);
        })?;
    receive.await?
}

fn lobby_status(state: &NodeState, restarts: u32) -> LobbyStatus {
    LobbyStatus {
        phase: match state.phase {
            Phase::Starting => LobbyPhase::Starting,
            Phase::NeedsLogin => LobbyPhase::NeedsLogin,
            Phase::NeedsTag => LobbyPhase::NeedsTag,
            Phase::Running => LobbyPhase::Ready,
            Phase::Failed => LobbyPhase::Failed,
        },
        dns_name: state.dns_name.clone(),
        approval_url: state.approval_url.clone(),
        diagnostic: state.error.clone(),
        restart_count: restarts,
        updated_at: chrono::Utc::now().to_rfc3339(),
    }
}

fn failed(diagnostic: String, restarts: u32) -> LobbyStatus {
    let mut state = NodeState::starting();
    state.phase = Phase::Failed;
    state.error = Some(diagnostic);
    lobby_status(&state, restarts)
}

type CurrentGate = Arc<RwLock<Option<Arc<Tsgate>>>>;

fn identity_source(current: CurrentGate, settings: &TailscaleConfig) -> IdentitySource {
    let (vms, cpus, memory, disk) = settings.vm_ceilings();
    let ceilings = Limits {
        vms,
        cpus,
        memory,
        disk,
    };
    Arc::new(move |remote| {
        let remote = remote.to_owned();
        let current = current.clone();
        Arc::new(move || {
            let remote = remote.clone();
            let gate = current.read().clone();
            Box::pin(async move {
                let gate = gate.ok_or_else(|| {
                    Failure::new(Code::Unavailable, "tailnet identity unavailable")
                })?;
                let whois = gate
                    .whois(&remote)
                    .await
                    .map_err(|_| Failure::new(Code::Unavailable, "tailnet identity unavailable"))?;
                identity::from_whois(&whois, ceilings)
            })
        })
    })
}

struct Frontends {
    service: Arc<Service>,
    ssh: Arc<Server>,
    oauth: Option<Arc<OAuth>>,
}

struct Storage {
    instance: String,
    audit: Audit,
}

async fn frontends(
    ctx: &LobbyContext,
    node: &NodeState,
    credentials: &Credentials,
    identity: IdentitySource,
    metrics: Arc<Metrics>,
    jobs: Arc<jobs::Registry>,
    storage: Storage,
) -> eyre::Result<Frontends> {
    let pin = NodePin {
        tailnet: node
            .tailnet
            .clone()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| eyre::eyre!("running lobby has no verified tailnet"))?,
        suffix: node
            .suffix
            .clone()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| eyre::eyre!("running lobby has no verified DNS suffix"))?,
        control_url: ctx.settings.control_url().into(),
    };
    let oauth = credentials
        .oauth_app_secret
        .as_ref()
        .map(|secret| {
            OAuth::new(
                Arc::new(Registry::new()),
                secret.clone(),
                format!(
                    "https://{}.{}/oauth/callback",
                    ctx.settings.hostname(),
                    pin.suffix.trim_end_matches('.')
                ),
                None,
            )
            .map(Arc::new)
        })
        .transpose()?;
    let consent = oauth.as_ref().map(|_| {
        Arc::new(Manager {
            enrollment: ctx.settings.enrollment_mode(),
            oauth: oauth.clone(),
            metrics: metrics.clone(),
        }) as Arc<dyn crate::lobby::service::enrollment::ConsentProvider>
    });
    let service = Arc::new(Service::new(ServiceConfig {
        home: ctx.host.home().into(),
        config_dir: ctx.host.config_dir().into(),
        management: ctx.management.clone(),
        settings: ctx.settings.clone(),
        capability: CAPABILITY.into(),
        instance: storage.instance,
        audit: storage.audit,
        jobs,
        visible_names: Arc::new(|| Box::pin(async { Ok(Vec::new()) })),
        node_pin: Some(pin),
        lobby_hostname: ctx.settings.hostname().into(),
        vm_nodes_enabled: true,
        consent,
    })?);
    service.reload_documents().await?;
    let ssh = Arc::new(Server::new(
        ctx.host.home(),
        &ctx.settings,
        identity,
        service.clone(),
    )?);
    Ok(Frontends {
        service,
        ssh,
        oauth,
    })
}

pub(crate) fn initial_status() -> LobbyStatus {
    lobby_status(&NodeState::starting(), 0)
}

pub(crate) async fn run(ctx: LobbyContext, cancel: CancellationToken) -> eyre::Result<()> {
    let result = run_inner(&ctx, cancel).await;
    if let Err(error) = &result {
        let restarts = ctx
            .publisher
            .wire()?
            .lobby
            .map_or(0, |lobby| lobby.restart_count);
        ctx.publisher
            .set_lobby(Some(failed(format!("{error:#}"), restarts)))?;
    }
    result
}

async fn run_inner(ctx: &LobbyContext, cancel: CancellationToken) -> eyre::Result<()> {
    ctx.publisher.set_lobby(Some(initial_status()))?;
    let _lock = state::lock_home(ctx.host.home())?;
    state::private_dir(ctx.host.home().join("lobby/principals"))?;
    state::private_dir(ctx.host.home().join("tsgate"))?;
    let mut storage = Some(Storage {
        instance: state::instance(ctx.host.home())?,
        audit: Audit::open(ctx.host.home(), 10 << 20, 3)?,
    });
    let credentials = tokio::select! {
        _ = cancel.cancelled() => return Ok(()),
        result = tokio::time::timeout(Duration::from_secs(10), credentials(ctx.host.home())) => result.wrap_err("lobby credential read deadline expired")??,
    };
    let current: CurrentGate = Arc::default();
    let identity = identity_source(current.clone(), &ctx.settings);
    let metrics = Arc::new(Metrics::new());
    let job_cancel = CancellationToken::new();
    let jobs = Arc::new(jobs::Registry::new(
        job_cancel.clone(),
        1024,
        metrics.clone(),
    ));
    let http_cancel = CancellationToken::new();
    let mut tasks = JoinSet::new();
    let mut fronts: Option<Frontends> = None;
    let mut active = None;
    let mut restarts = 0u32;
    let mut delay = Duration::from_secs(1);
    let result: eyre::Result<()> = async {
        loop {
            if cancel.is_cancelled() { return Ok(()); }
            ctx.publisher.set_lobby(Some(lobby_status(&NodeState::starting(), restarts)))?;
            let bootstrap = Bootstrap {
                version: 1, hostname: ctx.settings.hostname().into(), tag: ctx.settings.tag().into(), control_url: ctx.settings.control_url().into(),
                state_dir: ctx.host.home().join("tsgate").to_str().ok_or_else(|| eyre::eyre!("tsgate state directory is not UTF-8"))?.into(), capability: CAPABILITY.into(),
                client_secret: credentials.client_secret.clone(), api_base_url: None,
            };
            let spawned = tokio::select! {
                _ = cancel.cancelled() => return Ok(()),
                result = tokio::time::timeout(Duration::from_secs(10), Tsgate::spawn(&ctx.binary, bootstrap)) => result.wrap_err("tsgate spawn deadline expired").and_then(|r| r.map_err(Into::into)),
            };
            let diagnostic = match spawned {
                Err(error) => format!("tsgate spawn failed: {error:#}"),
                Ok((gate, mut connections)) => {
                    let gate = Arc::new(gate);
                    active = Some(gate.clone());
                    *current.write() = Some(gate.clone());
                    let mut node = gate.state();
                    let started = Instant::now();
                    let diagnostic = loop {
                        let state = node.borrow_and_update().clone();
                        if state.phase == Phase::Running && fronts.is_none() {
                            let storage = storage.take().ok_or_else(|| eyre::eyre!("lobby storage already consumed"))?;
                            fronts = Some(tokio::select! {
                                _ = cancel.cancelled() => return Ok(()),
                                result = frontends(ctx, &state, &credentials, identity.clone(), metrics.clone(), jobs.clone(), storage) => result?,
                            });
                        }
                        ctx.publisher.set_lobby(Some(lobby_status(&state, restarts)))?;
                        tokio::select! {
                            biased;
                            _ = cancel.cancelled() => return Ok(()),
                            exit = gate.wait() => break format!("tsgate exited: {}", exit?),
                            changed = node.changed() => {
                                if changed.is_err() { break "tsgate control seam closed".into(); }
                            }
                            connection = connections.recv() => {
                                let Some(connection) = connection else { break "tsgate connection stream closed".into(); };
                                if let Some(fronts) = &fronts {
                                    let service = fronts.service.clone();
                                    let ssh = fronts.ssh.clone();
                                    let oauth = fronts.oauth.clone();
                                    let identity = identity.clone();
                                    let metrics = metrics.clone();
                                    let cancel = http_cancel.clone();
                                    tasks.spawn(async move {
                                        match connection.listener {
                                            Listener::Ssh => { if let Err(error) = ssh.serve_stream(&connection.remote, connection.stream).await { tracing::debug!(%error, "lobby SSH connection ended"); } }
                                            Listener::Http => { if let Err(error) = crate::lobby::http::serve_connection(connection.stream, connection.remote, identity, service, metrics, oauth, cancel).await { tracing::debug!(%error, "lobby HTTP connection ended"); } }
                                        }
                                    });
                                }
                            }
                            result = tasks.join_next(), if !tasks.is_empty() => {
                                if let Some(Err(error)) = result { tracing::warn!(%error, "lobby connection task failed"); }
                            }
                        }
                    };
                    *current.write() = None;
                    gate.shutdown().await?;
                    active = None;
                    if started.elapsed() >= Duration::from_secs(60) { delay = Duration::from_secs(1); }
                    diagnostic
                }
            };
            restarts = restarts.saturating_add(1);
            ctx.publisher.set_lobby(Some(failed(diagnostic, restarts)))?;
            tokio::select! { _ = cancel.cancelled() => return Ok(()), _ = tokio::time::sleep(delay) => {} }
            delay = (delay * 2).min(Duration::from_secs(60));
        }
    }.await;
    let deadline = Instant::now() + STOP_BUDGET;
    http_cancel.cancel();
    let drained = tokio::time::timeout_at(deadline, async {
        let gateway = async {
            if let Some(gate) = active {
                gate.shutdown().await?;
            }
            Ok::<_, eyre::Report>(())
        };
        let sessions = async {
            if let Some(fronts) = &fronts {
                fronts.ssh.shutdown(deadline - Duration::from_secs(1)).await;
            }
        };
        let (gateway, (), jobs) = tokio::join!(gateway, sessions, jobs.wait(&job_cancel));
        gateway?;
        jobs?;
        while tasks.join_next().await.is_some() {}
        Ok::<_, eyre::Report>(())
    })
    .await
    .wrap_err("lobby shutdown deadline expired")
    .and_then(|r| r);
    *current.write() = None;
    job_cancel.cancel();
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    if let Some(fronts) = fronts {
        fronts.service.config().audit.close()?;
    }
    result.and(drained)
}

#[cfg(test)]
mod tests {
    use crate::{
        daemon::status::StatusPublisher,
        lobby::{
            identity_source::IdentitySource,
            metrics::Metrics,
            service::testing,
            supervisor::{
                credential, identity_source, lobby_status, run, CurrentGate, LobbyContext,
                CAPABILITY, SECRET_LIMIT, STOP_BUDGET,
            },
            tailnet::{
                tsgate::Tsgate,
                wire::{Bootstrap, NodeState, Phase},
            },
        },
    };
    use silo_secrets::{FileStore, Secret, SecretBytes, SecretName, SecretScope, SecretStore};
    use silod_spec::{
        paths::DaemonPaths,
        status::{DaemonStatus, LobbyPhase},
    };
    use std::{
        path::{Path, PathBuf},
        process::Stdio,
        sync::Arc,
        time::Duration,
    };
    use tokio::{
        io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines},
        process::{Child, ChildStdin, ChildStdout},
        time::Instant,
    };
    use tokio_util::sync::CancellationToken;

    fn go_build(dir: &Path, package: &str, name: &str) -> PathBuf {
        let binary = dir.join(name);
        let status = std::process::Command::new("go")
            .current_dir(Path::new(env!("CARGO_MANIFEST_DIR")).join("../tsgate"))
            .env("CGO_ENABLED", "0")
            .args(["build", "-mod=readonly", "-o"])
            .arg(&binary)
            .arg(package)
            .status()
            .expect("Go toolchain required for offline lobby tests");
        assert!(status.success(), "go build {package}");
        binary
    }

    struct Testnet {
        child: Child,
        input: ChildStdin,
        output: Lines<BufReader<ChildStdout>>,
        control_url: String,
    }

    impl Testnet {
        async fn start(binary: &Path, capability: &str) -> Self {
            let mut child = tokio::process::Command::new(binary)
                .args(["--capability", CAPABILITY, "--cap-value", capability])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .kill_on_drop(true)
                .spawn()
                .unwrap();
            let input = child.stdin.take().unwrap();
            let mut output = BufReader::new(child.stdout.take().unwrap()).lines();
            let ready = tokio::time::timeout(Duration::from_secs(60), output.next_line())
                .await
                .expect("offline peer ready")
                .unwrap()
                .unwrap();
            let control_url = serde_json::from_str::<serde_json::Value>(&ready).unwrap()
                ["control_url"]
                .as_str()
                .unwrap()
                .into();
            Self {
                child,
                input,
                output,
                control_url,
            }
        }

        async fn ssh(&mut self, command: &str, input: &str, pty: bool) -> eyre::Result<SshResult> {
            let line = format!(
                "ssh lobby {} {}{}\n",
                serde_json::to_string(command)?,
                serde_json::to_string(input)?,
                if pty { " pty" } else { "" }
            );
            self.input.write_all(line.as_bytes()).await?;
            let reply = tokio::time::timeout(Duration::from_secs(245), self.output.next_line())
                .await??
                .ok_or_else(|| eyre::eyre!("testnet ended during SSH command {command}"))?;
            let result: SshResult = serde_json::from_str(&reply)?;
            eyre::ensure!(
                result.ssh == "ok",
                "SSH transport failed for {command}: {result:?}"
            );
            Ok(result)
        }

        async fn ssh_success(
            &mut self,
            command: &str,
            input: &str,
            pty: bool,
        ) -> eyre::Result<SshResult> {
            let result = self.ssh(command, input, pty).await?;
            eyre::ensure!(result.exit == 0, "{command} failed: {result:?}");
            Ok(result)
        }

        async fn stop(mut self) {
            self.input.write_all(b"quit\n").await.unwrap();
            assert!(
                tokio::time::timeout(Duration::from_secs(10), self.child.wait())
                    .await
                    .unwrap()
                    .unwrap()
                    .success()
            );
        }
    }

    #[derive(Debug, serde::Deserialize)]
    struct SshResult {
        ssh: String,
        stdout: String,
        stderr: String,
        exit: i32,
        #[serde(default, rename = "error")]
        _error: Option<String>,
    }

    struct RunningLobby {
        cancel: CancellationToken,
        task: Option<tokio::task::JoinHandle<eyre::Result<()>>>,
    }

    impl Drop for RunningLobby {
        fn drop(&mut self) {
            self.cancel.cancel();
        }
    }

    impl RunningLobby {
        async fn start(fixture: &testing::Fixture, binary: &Path, net: &Testnet) -> Self {
            let home = fixture.root.path().join("home");
            let host = libvm::HostPaths::new(&home, fixture.root.path().join("config"));
            let publisher = Arc::new(
                StatusPublisher::new(&host, uuid::Uuid::new_v4(), "ssh-lobby-test".into(), None)
                    .unwrap(),
            );
            let settings = serde_yaml_ng::from_str(&format!(
                "hostname: lobby\ncontrol-url: {}\n",
                net.control_url
            ))
            .unwrap();
            let cancel = CancellationToken::new();
            let task = tokio::spawn(run(
                LobbyContext {
                    host,
                    settings,
                    management: fixture.management.clone(),
                    publisher,
                    binary: binary.into(),
                },
                cancel.clone(),
            ));
            ready(&DaemonPaths::new(&home), 0).await;
            Self {
                cancel,
                task: Some(task),
            }
        }

        async fn stop(mut self) {
            self.cancel.cancel();
            tokio::time::timeout(STOP_BUDGET, self.task.take().unwrap())
                .await
                .expect("SSH lobby stops within budget")
                .unwrap()
                .unwrap();
        }
    }

    fn bootstrap(home: &Path, control_url: &str) -> Bootstrap {
        Bootstrap {
            version: 1,
            hostname: "lobby".into(),
            tag: "tag:silo".into(),
            control_url: control_url.into(),
            state_dir: home.join("tsgate").to_str().unwrap().into(),
            capability: CAPABILITY.into(),
            client_secret: None,
            api_base_url: None,
        }
    }

    async fn running(gate: &Tsgate) {
        let mut state = gate.state();
        tokio::time::timeout(
            Duration::from_secs(60),
            state.wait_for(|node| node.phase == Phase::Running),
        )
        .await
        .expect("gateway running")
        .unwrap();
        assert_eq!(gate.state().borrow().phase, Phase::Running);
    }

    async fn ready(paths: &DaemonPaths, restart_count: u32) -> DaemonStatus {
        tokio::time::timeout(Duration::from_secs(60), async {
            loop {
                if let Ok(bytes) = std::fs::read(paths.status()) {
                    let status: DaemonStatus = serde_json::from_slice(&bytes).unwrap();
                    if status.lobby.as_ref().is_some_and(|lobby| {
                        lobby.phase == LobbyPhase::Ready && lobby.restart_count == restart_count
                    }) {
                        return status;
                    }
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("lobby reaches ready")
    }

    #[test]
    fn every_gateway_phase_and_diagnostic_is_published() {
        let mut state = NodeState::starting();
        state.dns_name = Some("lobby.tail.test".into());
        state.approval_url = Some("https://login.tailscale.com/approve".into());
        state.error = Some("requested tag missing".into());
        for (phase, expected) in [
            (Phase::Starting, LobbyPhase::Starting),
            (Phase::NeedsLogin, LobbyPhase::NeedsLogin),
            (Phase::NeedsTag, LobbyPhase::NeedsTag),
            (Phase::Running, LobbyPhase::Ready),
            (Phase::Failed, LobbyPhase::Failed),
        ] {
            state.phase = phase;
            let published = lobby_status(&state, 7);
            assert_eq!(published.phase, expected);
            assert_eq!(published.restart_count, 7);
            assert_eq!(published.dns_name, state.dns_name);
            assert_eq!(published.approval_url, state.approval_url);
            assert_eq!(published.diagnostic, state.error);
        }
    }

    #[test]
    fn home_credentials_are_optional_plain_bounded_and_fail_closed() {
        let root = tempfile::tempdir().unwrap();
        let store = FileStore::new(root.path());
        for key in [
            "tailscale.lobby.client_secret",
            "tailscale.lobby.oauth_app_secret",
            "tailscale.lobby.api_token",
        ] {
            let name = SecretName::new(key).unwrap();
            assert!(credential(&store, key).unwrap().is_none());
            store
                .put(
                    &SecretScope::Home,
                    &name,
                    Secret::Plain(SecretBytes::new(vec![b'x'; SECRET_LIMIT])),
                )
                .unwrap();
            assert_eq!(
                credential(&store, key).unwrap().unwrap().len(),
                SECRET_LIMIT
            );
            store
                .put(
                    &SecretScope::Home,
                    &name,
                    Secret::Plain(SecretBytes::new(vec![b'x'; SECRET_LIMIT + 1])),
                )
                .unwrap();
            assert!(credential(&store, key).is_err());
            store
                .put(
                    &SecretScope::Home,
                    &name,
                    Secret::OAuth(silo_secrets::OAuthSecret {
                        provider: None,
                        access_token: SecretBytes::new(b"access".to_vec()),
                        refresh_token: SecretBytes::new(b"refresh".to_vec()),
                        expires_at: chrono::Utc::now(),
                        account_id: None,
                        created_at: None,
                        updated_at: None,
                    }),
                )
                .unwrap();
            assert!(credential(&store, key).is_err());
        }
        std::fs::write(store.path(), b"corrupt").unwrap();
        assert!(credential(&store, "tailscale.lobby.client_secret").is_err());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn real_gateway_restarts_without_stopping_vms_and_cancels_within_budget() {
        let bin = tempfile::tempdir().unwrap();
        let gate_binary = go_build(bin.path(), "./cmd/tsgate", "tsgate");
        let testnet_binary = go_build(bin.path(), "./cmd/tsgate-testnet", "tsgate-testnet");
        let net = Testnet::start(&testnet_binary, r#"{"actions":["*"]}"#).await;
        let fixture = testing::fixture().await;
        let machine = testing::stopped_vm(&fixture, "survives-gateway-restart", "user:1").await;
        let home = fixture.root.path().join("home");
        let host = libvm::HostPaths::new(&home, fixture.root.path().join("config"));
        let publisher = Arc::new(
            StatusPublisher::new(&host, uuid::Uuid::new_v4(), "lobby-test".into(), None).unwrap(),
        );
        let settings = serde_yaml_ng::from_str(&format!(
            "hostname: lobby\ncontrol-url: {}\n",
            net.control_url
        ))
        .unwrap();
        let ctx = LobbyContext {
            host,
            settings,
            management: fixture.management.clone(),
            publisher,
            binary: gate_binary.clone(),
        };
        let cancel = CancellationToken::new();
        let task = tokio::spawn(run(ctx, cancel.clone()));
        let paths = DaemonPaths::new(&home);
        let status = ready(&paths, 0).await;
        assert!(status
            .lobby
            .unwrap()
            .dns_name
            .unwrap()
            .starts_with("lobby."));
        // Match the exact private binary path, not a global process name.
        let processes = std::process::Command::new("ps")
            .args(["-axo", "pid=,args="])
            .output()
            .unwrap();
        assert!(processes.status.success());
        let process = String::from_utf8(processes.stdout).unwrap();
        let pid = process
            .lines()
            .find_map(|line| {
                let mut fields = line.split_whitespace();
                let pid = fields.next()?;
                (fields.next()? == gate_binary.to_str().unwrap())
                    .then(|| pid.parse::<i32>().unwrap())
            })
            .expect("supervised gateway child");
        nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(pid),
            nix::sys::signal::Signal::SIGKILL,
        )
        .unwrap();
        let restarted = ready(&paths, 1).await;
        assert!(restarted
            .lobby
            .unwrap()
            .dns_name
            .unwrap()
            .starts_with("lobby."));
        assert_eq!(
            fixture.management.inspect(&machine.id).await.unwrap().id,
            machine.id
        );
        let stopped = Instant::now();
        cancel.cancel();
        tokio::time::timeout(STOP_BUDGET, task)
            .await
            .expect("lobby stops within budget")
            .unwrap()
            .unwrap();
        assert!(stopped.elapsed() < STOP_BUDGET);
        assert!(crate::lobby::state::lock_home(&home).is_ok());
        net.stop().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn offline_peer_http_health_authorizes_real_whois_capability() {
        let bin = tempfile::tempdir().unwrap();
        let gate_binary = go_build(bin.path(), "./cmd/tsgate", "tsgate");
        let testnet_binary = go_build(bin.path(), "./cmd/tsgate-testnet", "tsgate-testnet");
        for (grant, expected) in [
            (r#"{"actions":["vm.exec"]}"#, "HTTP/1.1 403"),
            (r#"{"actions":["vm.read"]}"#, "HTTP/1.1 200"),
        ] {
            let mut net = Testnet::start(&testnet_binary, grant).await;
            let fixture = testing::fixture().await;
            let (gate, mut connections) = Tsgate::spawn(
                &gate_binary,
                bootstrap(&fixture.root.path().join("home"), &net.control_url),
            )
            .await
            .unwrap();
            let gate = Arc::new(gate);
            running(&gate).await;
            let current: CurrentGate = Arc::new(parking_lot::RwLock::new(Some(gate.clone())));
            let identity: IdentitySource = identity_source(current, &Default::default());
            let request =
                serde_json::to_string("GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
            net.input
                .write_all(format!("probe lobby {request}\n").as_bytes())
                .await
                .unwrap();
            let connection = tokio::time::timeout(Duration::from_secs(30), connections.recv())
                .await
                .unwrap()
                .unwrap();
            // testcontrol has no certificates. Its real port-22 stream exercises
            // the HTTP handler after the same fd handoff, not the TLS listener.
            let handler = tokio::spawn(crate::lobby::http::serve_connection(
                connection.stream,
                connection.remote,
                identity,
                Arc::new(fixture.service),
                Arc::new(Metrics::new()),
                None,
                CancellationToken::new(),
            ));
            let probe = tokio::time::timeout(Duration::from_secs(30), net.output.next_line())
                .await
                .expect("HTTP probe response")
                .unwrap()
                .unwrap();
            let probe: serde_json::Value = serde_json::from_str(&probe).unwrap();
            assert_eq!(probe["probe"], "ok", "{probe}");
            assert!(
                probe["received"].as_str().unwrap().starts_with(expected),
                "{probe}"
            );
            tokio::time::timeout(Duration::from_secs(5), handler)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            assert!(gate.shutdown().await.unwrap().success());
            net.stop().await;
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn offline_peer_ssh_uses_supervisor_identity_and_denies_ungranted_commands() {
        let bin = tempfile::tempdir().unwrap();
        let gate_binary = go_build(bin.path(), "./cmd/tsgate", "tsgate");
        let testnet_binary = go_build(bin.path(), "./cmd/tsgate-testnet", "tsgate-testnet");
        for (grant, allowed) in [
            (r#"{"actions":["*"]}"#, true),
            (r#"{"actions":["vm.exec"]}"#, false),
        ] {
            let mut net = Testnet::start(&testnet_binary, grant).await;
            let fixture = testing::fixture().await;
            let lobby = RunningLobby::start(&fixture, &gate_binary, &net).await;
            let whoami = net.ssh_success("whoami --json", "", false).await.unwrap();
            let envelope: serde_json::Value = serde_json::from_str(&whoami.stdout).unwrap();
            assert_eq!(envelope["ok"], true, "{whoami:?}");
            assert_eq!(
                envelope["data"]["peer"]["principals"],
                serde_json::json!(["tag:peer"])
            );
            let listed = net.ssh("ls", "", false).await.unwrap();
            assert_eq!(listed.exit, if allowed { 0 } else { 4 }, "{listed:?}");
            if !allowed {
                assert!(listed.stderr.contains("capability required"), "{listed:?}");
            }
            lobby.stop().await;
            net.stop().await;
        }
    }

    async fn exercise_guest_over_ssh(net: &mut Testnet, name: &str) -> eyre::Result<()> {
        use sha2::{Digest, Sha256};
        let image = std::env::var("SILO_LOBBY_E2E_IMAGE")
            .unwrap_or_else(|_| "docker.io/library/alpine:latest".into());
        let image = format!("'{}'", image.replace('\'', "'\\''"));
        let create = net
            .ssh_success(
                &format!("create --json {image} --name {name} --memory 512MiB --disk 1GiB"),
                "",
                false,
            )
            .await?;
        let created: serde_json::Value = serde_json::from_str(&create.stdout)?;
        eyre::ensure!(
            created["ok"] == true && created["data"]["state"] == "succeeded",
            "create did not complete: {create:?}"
        );
        let executed = net
            .ssh_success(&format!("exec {name} -- echo hi"), "", false)
            .await?;
        eyre::ensure!(
            executed.stdout == "hi\n",
            "guest stdout mismatch: {executed:?}"
        );
        let payload = "tailnet file transfer\n\0with channel EOF\n".repeat(512);
        net.ssh_success(&format!("cp - {name}:/root/x"), &payload, false)
            .await?;
        let downloaded = net
            .ssh_success(&format!("cp {name}:/root/x -"), "", false)
            .await?;
        eyre::ensure!(
            Sha256::digest(downloaded.stdout.as_bytes()) == Sha256::digest(payload.as_bytes()),
            "SSH upload/download digest mismatch"
        );
        net.ssh_success(&format!("logs {name}"), "", false).await?;
        let shell = net
            .ssh_success(
                &format!("shell {name}"),
                "printf 'ssh-pty-ready\\n'\nexit\n",
                true,
            )
            .await?;
        eyre::ensure!(
            shell.stdout.contains("ssh-pty-ready"),
            "guest PTY shell did not run input: {shell:?}"
        );
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn native_offline_peer_ssh_create_exec_copy_logs_shell_and_remove() {
        if std::env::var_os("SILO_LOBBY_E2E_RUNTIME").is_none() {
            eprintln!("set SILO_LOBBY_E2E_RUNTIME to run the full-path SSH guest test");
            return;
        }
        if cfg!(target_os = "linux") && !Path::new("/dev/kvm").exists() {
            eprintln!("SILO_LOBBY_E2E_RUNTIME SSH guest test requires /dev/kvm");
            return;
        }
        let bin = tempfile::tempdir().unwrap();
        let gate_binary = go_build(bin.path(), "./cmd/tsgate", "tsgate");
        let testnet_binary = go_build(bin.path(), "./cmd/tsgate-testnet", "tsgate-testnet");
        let mut net = Testnet::start(&testnet_binary, r#"{"actions":["*"]}"#).await;
        let fixture = testing::fixture().await;
        let lobby = RunningLobby::start(&fixture, &gate_binary, &net).await;
        let name = format!("ssh-{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
        let exercised = exercise_guest_over_ssh(&mut net, &name).await;
        let mut removed = net
            .ssh_success(&format!("rm {name} --force --yes"), "", false)
            .await;
        // Always clean up a guest, including when an earlier assertion failed.
        let cleanup = match fixture.management.inspect(&name).await {
            Ok(machine) => {
                if removed.is_ok() {
                    removed = Err(eyre::eyre!("SSH rm left the VM in inventory"));
                }
                fixture
                    .cleanup_vm(&machine.id)
                    .await
                    .map_err(eyre::Report::new)
            }
            Err(error) if error.code() == tonic::Code::NotFound => Ok(()),
            Err(error) => Err(eyre::Report::new(error)),
        };
        lobby.stop().await;
        net.stop().await;
        cleanup.unwrap();
        exercised.unwrap();
        removed.unwrap();
    }
}
