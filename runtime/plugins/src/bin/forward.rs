use std::collections::{BTreeSet, HashMap};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use agent_spec::{ForwardApiRequest, ForwardApiResponse, ForwardStreamRequest};
use plugins::Plugin;
use serde::Deserialize;
use tokio::io::{copy_bidirectional, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UnixListener, UnixStream};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tracing::warn;

const AUTO_DISCOVER_POLL_INTERVAL: Duration = Duration::from_secs(2);
const MAX_PREAMBLE_BYTES: usize = 4096;

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Default)]
struct ForwardPluginConfig {
    #[serde(default)]
    tcp: TcpForwardPluginConfig,
    #[serde(default)]
    uds: Vec<UdsForwardPluginConfig>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Default)]
struct TcpForwardPluginConfig {
    #[serde(default)]
    auto_discover: bool,
    #[serde(default)]
    ports: Vec<TcpPortForwardPluginConfig>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
struct TcpPortForwardPluginConfig {
    guest_port: u16,
    host_port: u16,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
struct UdsForwardPluginConfig {
    guest_path: String,
    host_path: String,
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let plugin = Arc::new(Plugin::init("forward").await?);
    if let Err(err) = run(Arc::clone(&plugin)).await {
        let message = format!("forward plugin failed: {err}");
        let _ = plugin.fail(&message);
        return Err(err);
    }

    Ok(())
}

async fn run(plugin: Arc<Plugin>) -> io::Result<()> {
    let config: ForwardPluginConfig = plugin.config()?;

    let auto_discover = config.tcp.auto_discover;

    for mapping in &config.tcp.ports {
        spawn_tcp_listener(Arc::clone(&plugin), mapping.host_port, mapping.guest_port)?;
    }

    for uds in &config.uds {
        let host_path = resolve_host_socket_path(&plugin.socks_dir(), &uds.host_path)?;
        spawn_uds_listener(Arc::clone(&plugin), host_path, uds.guest_path.clone())?;
    }

    if auto_discover {
        run_auto_discover(plugin, config.tcp.ports).await
    } else {
        std::future::pending::<()>().await;
        Ok(())
    }
}

fn spawn_tcp_listener(
    plugin: Arc<Plugin>,
    host_port: u16,
    guest_port: u16,
) -> io::Result<JoinHandle<()>> {
    let listener = std::net::TcpListener::bind(("127.0.0.1", host_port))?;
    listener.set_nonblocking(true)?;
    let listener = TcpListener::from_std(listener)?;

    Ok(tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let plugin = Arc::clone(&plugin);
                    tokio::spawn(async move {
                        if let Err(err) = proxy_tcp(plugin, stream, guest_port).await {
                            eprintln!("forward tcp proxy failed: {err}");
                        }
                    });
                }
                Err(err) => {
                    eprintln!("forward tcp listener accept failed on {host_port}: {err}");
                    return;
                }
            }
        }
    }))
}

fn spawn_uds_listener(
    plugin: Arc<Plugin>,
    host_path: PathBuf,
    guest_path: String,
) -> io::Result<JoinHandle<()>> {
    if let Some(parent) = host_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if host_path.exists() {
        let _ = std::fs::remove_file(&host_path);
    }
    let listener = std::os::unix::net::UnixListener::bind(&host_path)?;
    listener.set_nonblocking(true)?;
    let listener = UnixListener::from_std(listener)?;

    Ok(tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let plugin = Arc::clone(&plugin);
                    let guest_path = guest_path.clone();
                    tokio::spawn(async move {
                        if let Err(err) = proxy_uds(plugin, stream, guest_path).await {
                            eprintln!("forward uds proxy failed: {err}");
                        }
                    });
                }
                Err(err) => {
                    eprintln!(
                        "forward uds listener accept failed on {}: {err}",
                        host_path.display()
                    );
                    return;
                }
            }
        }
    }))
}

async fn run_auto_discover(
    plugin: Arc<Plugin>,
    static_ports: Vec<TcpPortForwardPluginConfig>,
) -> io::Result<()> {
    let static_host_ports: BTreeSet<u16> = static_ports
        .iter()
        .map(|mapping| mapping.host_port)
        .collect();
    let mut dynamic_listeners: HashMap<u16, DynamicTcpListener> = HashMap::new();
    let mut bind_failures: HashMap<u16, String> = HashMap::new();

    loop {
        let discovered = list_tcp_ports(&plugin).await?;
        let desired: BTreeSet<u16> = discovered
            .into_iter()
            .filter(|port| !static_host_ports.contains(port))
            .collect();

        for port in desired.iter().copied() {
            if dynamic_listeners.contains_key(&port) {
                continue;
            }
            match spawn_dynamic_tcp_listener(Arc::clone(&plugin), port) {
                Ok(listener) => {
                    dynamic_listeners.insert(port, listener);
                    bind_failures.remove(&port);
                }
                Err(err) => {
                    let message = format!("bind 127.0.0.1:{port}: {err}");
                    warn!(port, error = %err, "forward auto-discovered bind failed");
                    bind_failures.insert(port, message);
                }
            }
        }

        let stale_ports: Vec<u16> = dynamic_listeners
            .keys()
            .copied()
            .filter(|port| !desired.contains(port))
            .collect();
        for port in stale_ports {
            if let Some(listener) = dynamic_listeners.remove(&port) {
                listener.shutdown();
            }
            bind_failures.remove(&port);
        }

        tokio::time::sleep(AUTO_DISCOVER_POLL_INTERVAL).await;
    }
}

fn spawn_dynamic_tcp_listener(plugin: Arc<Plugin>, port: u16) -> io::Result<DynamicTcpListener> {
    let listener = std::net::TcpListener::bind(("127.0.0.1", port))?;
    listener.set_nonblocking(true)?;
    let listener = TcpListener::from_std(listener)?;
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel();

    let task = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => return,
                result = listener.accept() => {
                    match result {
                        Ok((stream, _)) => {
                            let plugin = Arc::clone(&plugin);
                            tokio::spawn(async move {
                                if let Err(err) = proxy_tcp(plugin, stream, port).await {
                                    eprintln!("forward auto-discovered tcp proxy failed: {err}");
                                }
                            });
                        }
                        Err(err) => {
                            eprintln!("forward auto-discovered listener accept failed on {port}: {err}");
                            return;
                        }
                    }
                }
            }
        }
    });

    Ok(DynamicTcpListener { shutdown_tx, task })
}

async fn list_tcp_ports(plugin: &Plugin) -> io::Result<BTreeSet<u16>> {
    let mut stream = plugin.connect().await?;
    write_json_line(
        &mut stream,
        &ForwardStreamRequest::Api {
            request: ForwardApiRequest::ListTcpPorts,
        },
    )
    .await?;

    match read_json_line::<ForwardApiResponse, _>(&mut stream).await? {
        ForwardApiResponse::TcpPorts { ports } => Ok(ports.into_iter().collect()),
        ForwardApiResponse::Error { message } => Err(io::Error::other(message)),
    }
}

async fn proxy_tcp(plugin: Arc<Plugin>, mut host: TcpStream, guest_port: u16) -> io::Result<()> {
    let mut guest = plugin.connect().await?;
    write_json_line(&mut guest, &ForwardStreamRequest::Tcp { guest_port }).await?;
    let _ = copy_bidirectional(&mut host, &mut guest).await?;
    Ok(())
}

async fn proxy_uds(
    plugin: Arc<Plugin>,
    mut host: UnixStream,
    guest_path: String,
) -> io::Result<()> {
    let mut guest = plugin.connect().await?;
    write_json_line(&mut guest, &ForwardStreamRequest::Uds { guest_path }).await?;
    let _ = copy_bidirectional(&mut host, &mut guest).await?;
    Ok(())
}

fn resolve_host_socket_path(socks_dir: &Path, host_path: &str) -> io::Result<PathBuf> {
    let path = Path::new(host_path);
    if path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("absolute host_path is not supported: {host_path}"),
        ));
    }
    Ok(socks_dir.join(path))
}

async fn read_json_line<T, S>(stream: &mut S) -> io::Result<T>
where
    T: serde::de::DeserializeOwned,
    S: AsyncRead + Unpin,
{
    let mut buf = Vec::new();
    loop {
        let mut byte = [0_u8; 1];
        let read = stream.read(&mut byte).await?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "stream closed before preamble completed",
            ));
        }
        if byte[0] == b'\n' {
            break;
        }
        buf.push(byte[0]);
        if buf.len() > MAX_PREAMBLE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "stream preamble exceeded max size",
            ));
        }
    }

    serde_json::from_slice(&buf).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("decode forward message: {err}"),
        )
    })
}

async fn write_json_line<T, S>(stream: &mut S, value: &T) -> io::Result<()>
where
    T: serde::Serialize,
    S: AsyncWrite + Unpin,
{
    let payload = serde_json::to_vec(value).map_err(io::Error::other)?;
    stream.write_all(&payload).await?;
    stream.write_all(b"\n").await?;
    stream.flush().await
}

struct DynamicTcpListener {
    shutdown_tx: oneshot::Sender<()>,
    task: JoinHandle<()>,
}

impl DynamicTcpListener {
    fn shutdown(self) {
        let _ = self.shutdown_tx.send(());
        self.task.abort();
    }
}
