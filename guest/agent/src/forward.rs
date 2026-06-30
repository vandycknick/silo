use std::collections::BTreeSet;
use std::io;
use std::sync::Arc;

use agent_spec::{AgentForwardConfig, ForwardApiRequest, ForwardApiResponse, ForwardStreamRequest};
use tokio::io::{copy_bidirectional, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UnixStream};
use tokio_vsock::VsockStream;

const MAX_PREAMBLE_BYTES: usize = 4096;
const MIN_DISCOVER_PORT: u16 = 1025;

#[derive(Clone)]
pub struct ForwardService {
    config: AgentForwardConfig,
    baseline_ports: Arc<BTreeSet<u16>>,
}

impl ForwardService {
    pub fn new(config: AgentForwardConfig) -> io::Result<Self> {
        let baseline_ports = discover_listening_tcp_ports()?;
        Ok(Self {
            config,
            baseline_ports: Arc::new(baseline_ports),
        })
    }

    pub async fn handle_connection(&self, mut stream: VsockStream) -> io::Result<()> {
        let request = read_json_line::<ForwardStreamRequest, _>(&mut stream).await?;
        match request {
            ForwardStreamRequest::Api { request } => self.handle_api(stream, request).await,
            ForwardStreamRequest::Tcp { guest_port } => handle_tcp(stream, guest_port).await,
            ForwardStreamRequest::Uds { guest_path } => {
                handle_uds(stream, &self.config, &guest_path).await
            }
        }
    }

    async fn handle_api(
        &self,
        mut stream: VsockStream,
        request: ForwardApiRequest,
    ) -> io::Result<()> {
        let response = match request {
            ForwardApiRequest::ListTcpPorts => match self.discover_promoted_tcp_ports() {
                Ok(ports) => ForwardApiResponse::TcpPorts {
                    ports: ports.into_iter().collect(),
                },
                Err(err) => ForwardApiResponse::Error {
                    message: format!("discover tcp ports: {err}"),
                },
            },
        };

        write_json_line(&mut stream, &response).await
    }

    fn discover_promoted_tcp_ports(&self) -> io::Result<BTreeSet<u16>> {
        let current_ports = discover_listening_tcp_ports()?;
        Ok(current_ports
            .difference(&self.baseline_ports)
            .copied()
            .filter(|port| *port >= MIN_DISCOVER_PORT)
            .collect())
    }
}

async fn handle_tcp(mut stream: VsockStream, guest_port: u16) -> io::Result<()> {
    let mut target = TcpStream::connect(("127.0.0.1", guest_port)).await?;
    let _ = copy_bidirectional(&mut stream, &mut target).await?;
    Ok(())
}

async fn handle_uds(
    mut stream: VsockStream,
    config: &AgentForwardConfig,
    guest_path: &str,
) -> io::Result<()> {
    if !config
        .uds
        .iter()
        .any(|entry| entry.guest_path == guest_path)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("guest uds path is not configured for forwarding: {guest_path}"),
        ));
    }

    let mut target = UnixStream::connect(guest_path).await?;
    let _ = copy_bidirectional(&mut stream, &mut target).await?;
    Ok(())
}

fn discover_listening_tcp_ports() -> io::Result<BTreeSet<u16>> {
    let mut ports = BTreeSet::new();
    collect_tcp_ports("/proc/net/tcp", &mut ports)?;
    collect_tcp_ports("/proc/net/tcp6", &mut ports)?;
    Ok(ports)
}

fn collect_tcp_ports(path: &str, ports: &mut BTreeSet<u16>) -> io::Result<()> {
    let contents = std::fs::read_to_string(path)?;
    for line in contents.lines().skip(1) {
        let columns: Vec<&str> = line.split_whitespace().collect();
        if columns.len() < 4 || columns[3] != "0A" {
            continue;
        }

        let Some((_, port_hex)) = columns[1].split_once(':') else {
            continue;
        };
        let Ok(port) = u16::from_str_radix(port_hex, 16) else {
            continue;
        };
        ports.insert(port);
    }
    Ok(())
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
            format!("decode forward preamble: {err}"),
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

#[cfg(test)]
mod tests {
    use super::discover_listening_tcp_ports;

    #[test]
    fn discover_tcp_ports_reads_proc_without_crashing() {
        let _ = discover_listening_tcp_ports();
    }
}
