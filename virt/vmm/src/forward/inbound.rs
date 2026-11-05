use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use forward_spec::{GuestHalf, Reply, TargetLine, MAX_TARGET_LINE_BYTES};
use tokio::io::AsyncWriteExt;
use tokio::task::JoinSet;
use tokio::time::Instant;

use crate::forward::host_socket::{HostStream, OwnedHostListener};
use crate::forward::{ForwardEntry, GuestHalfAvailability};
use crate::live::gate::{GateKind, GatePermit, LiveGate};
use crate::virt::VirtualMachine;

const MAX_PARKED_PER_FORWARD: usize = 64;
pub(crate) const PARK_TIMEOUT: Duration = Duration::from_secs(30);
const FORWARD_SETUP_TIMEOUT: Duration = Duration::from_secs(5);

struct Parked {
    stream: HostStream,
    deadline: Instant,
}

pub(crate) async fn serve(
    listener: OwnedHostListener,
    entry: Arc<ForwardEntry>,
    machine: VirtualMachine,
    gate: Arc<LiveGate>,
    park_timeout: Duration,
) {
    let mut availability = entry.availability.subscribe();
    let mut parked = VecDeque::<Parked>::new();
    let mut connections = JoinSet::new();
    let mut expiry = tokio::time::interval(Duration::from_millis(100));
    expiry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = entry.shutdown.cancelled() => break,
            accepted = listener.accept() => match accepted {
                Ok(stream) => admit(stream, &entry, &machine, &gate, &availability, &mut parked, &mut connections, park_timeout).await,
                Err(error) => tracing::warn!(forward = %entry.name, %error, "forward accept failed"),
            },
            changed = availability.changed() => {
                if changed.is_err() { break; }
                let current = availability.borrow().clone();
                match current {
                    GuestHalfAvailability::Available(_) => {
                        let now = Instant::now();
                        while let Some(mut parked_connection) = parked.pop_front() {
                            if parked_connection.deadline <= now {
                                entry.refuse();
                                let _ = parked_connection.stream.shutdown().await;
                                continue;
                            }
                            dispatch(
                                parked_connection.stream,
                                &entry,
                                &machine,
                                &gate,
                                &mut connections,
                            )
                            .await;
                        }
                    }
                    GuestHalfAvailability::Unsupported => {
                        entry.refuse_by(parked.len());
                        parked.clear();
                    }
                    GuestHalfAvailability::Unknown => {}
                }
            }
            _ = expiry.tick() => {
                let now = Instant::now();
                while parked.front().is_some_and(|connection| connection.deadline <= now) {
                    parked.pop_front();
                    entry.refuse();
                }
            }
            result = connections.join_next(), if !connections.is_empty() => {
                if let Some(Err(error)) = result {
                    tracing::warn!(forward = %entry.name, %error, "forward connection task failed");
                }
            }
        }
    }
    drop(listener);
    parked.clear();
    connections.abort_all();
    while connections.join_next().await.is_some() {}
}

#[allow(clippy::too_many_arguments)]
async fn admit(
    mut stream: HostStream,
    entry: &Arc<ForwardEntry>,
    machine: &VirtualMachine,
    gate: &Arc<LiveGate>,
    availability: &tokio::sync::watch::Receiver<GuestHalfAvailability>,
    parked: &mut VecDeque<Parked>,
    connections: &mut JoinSet<()>,
    park_timeout: Duration,
) {
    let current = availability.borrow().clone();
    match current {
        GuestHalfAvailability::Available(_) => {
            dispatch(stream, entry, machine, gate, connections).await
        }
        GuestHalfAvailability::Unknown if parked.len() < MAX_PARKED_PER_FORWARD => {
            // Admission must happen when the host connection arrives, not
            // retroactively when the guest half becomes available.
            let _admission = match gate.try_admit(GateKind::ForwardConnection) {
                Ok(permit) => permit,
                Err(refusal) => {
                    entry.refuse();
                    tracing::debug!(forward = %entry.name, %refusal, "forward connection refused");
                    let _ = stream.shutdown().await;
                    return;
                }
            };
            parked.push_back(Parked {
                stream,
                deadline: Instant::now() + park_timeout,
            });
        }
        GuestHalfAvailability::Unknown | GuestHalfAvailability::Unsupported => {
            entry.refuse();
            let _ = stream.shutdown().await;
        }
    }
}

/// Start guest-side setup for one host connection. Setup (vsock connect and
/// the agent CONNECT exchange) is admitted through the live fence before any
/// guest contact; the permit ends once the relay is established, so a pause
/// drains in-flight setup without waiting for established streams.
async fn dispatch(
    mut stream: HostStream,
    entry: &Arc<ForwardEntry>,
    machine: &VirtualMachine,
    gate: &Arc<LiveGate>,
    connections: &mut JoinSet<()>,
) {
    let setup = match gate.try_admit(GateKind::ForwardConnection) {
        Ok(setup) => setup,
        Err(refusal) => {
            entry.refuse();
            tracing::debug!(forward = %entry.name, %refusal, "forward connection refused");
            let _ = stream.shutdown().await;
            return;
        }
    };
    let entry = entry.clone();
    let machine = machine.clone();
    connections.spawn(async move {
        if let Err(error) = handle_connection(stream, entry.clone(), machine, setup).await {
            entry.refuse();
            tracing::debug!(forward = %entry.name, target = %entry.spec.connect, %error, "forward connection refused");
        }
    });
}

async fn handle_connection(
    mut client: HostStream,
    entry: Arc<ForwardEntry>,
    machine: VirtualMachine,
    setup: GatePermit,
) -> eyre::Result<()> {
    let lifetime = entry
        .connection_lifetime()
        .ok_or_else(|| eyre::eyre!("guest half is unavailable"))?;
    let mut guest = tokio::select! {
        _ = lifetime.cancelled() => return Ok(()),
        result = tokio::time::timeout(FORWARD_SETUP_TIMEOUT, async {
        let lease = machine.reserve_public_vsock()?;
        match entry.guest_half.clone() {
            GuestHalf::Vsock(port) => machine
                .connect_vsock_reserved(port, lease)
                .await
                .map_err(eyre::Report::from),
            GuestHalf::Agent(address) => {
                let mut stream = machine
                    .connect_vsock_reserved(forward_spec::FORWARD_VSOCK_PORT, lease)
                    .await?;
                stream
                    .write_all(&forward_spec::encode_connect(&TargetLine::Address(
                        address,
                    ))?)
                    .await?;
                let reply = forward_spec::io::read_line(&mut stream, MAX_TARGET_LINE_BYTES).await?;
                match forward_spec::parse_reply(&reply)? {
                    Reply::Ok => Ok(stream),
                    Reply::Err(reason) => Err(eyre::eyre!("guest dialer replied ERR {reason}")),
                }
            }
        }
        }) => result.map_err(|_| eyre::eyre!("forward setup timed out"))??,
    };
    drop(setup);
    let _connection = entry.connection_opened();
    crate::vsock::relay::relay(&mut client, &mut guest, lifetime)
        .await
        .map_err(eyre::Report::from)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    use crate::live::gate::LiveGate;
    use crate::virt::{BackendKind, VirtualMachine, VmConfig};

    async fn echoed(client: &mut TcpStream, payload: &[u8]) -> Vec<u8> {
        client.write_all(payload).await.unwrap();
        let mut received = vec![0; payload.len()];
        tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut received))
            .await
            .expect("echo before deadline")
            .unwrap();
        received
    }

    /// A refused connection is closed without ever reaching the guest echo.
    async fn assert_refused(address: std::net::SocketAddr) {
        let mut client = TcpStream::connect(address).await.unwrap();
        let _ = client.write_all(b"x").await;
        let mut byte = [0; 1];
        let read = tokio::time::timeout(Duration::from_secs(5), client.read(&mut byte))
            .await
            .expect("refusal before deadline");
        assert!(
            matches!(read, Ok(0) | Err(_)),
            "fenced connection reached the guest: {read:?}"
        );
    }

    #[test]
    fn park_timeout_default_is_thirty_seconds() {
        assert_eq!(
            crate::forward::inbound::PARK_TIMEOUT,
            Duration::from_secs(30)
        );
    }

    #[tokio::test]
    async fn live_fence_refuses_new_forward_connections_and_keeps_established_streams() {
        let root =
            std::path::Path::new("/tmp").join(format!("fl-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir(&root).unwrap();
        let config = VmConfig::builder("forward-fence")
            .base_directory(&root)
            .kernel(std::path::Path::new("/mock-kernel"))
            .build();
        let machine = VirtualMachine::with_backend(BackendKind::Mock, config).unwrap();
        machine.start().await.unwrap();
        let gate = LiveGate::new();
        // Inbound vsock forward onto the mock guest's byte echo port.
        let forward = forward_spec::Forward::new(
            forward_spec::Endpoint::Host(forward_spec::Address::Tcp(
                "127.0.0.1:0".parse().unwrap(),
            )),
            forward_spec::Endpoint::Vsock(agent_spec::SSH_VSOCK_PORT),
        );
        let table = crate::forward::ForwardTable::prepare_machine(
            &[forward],
            &root,
            None,
            crate::forward::inbound::PARK_TIMEOUT,
            gate.clone(),
        )
        .await
        .unwrap();
        table.activate(machine.clone());
        let entry = table.entries().remove(0);
        let Some(forward_spec::Endpoint::Host(forward_spec::Address::Tcp(address))) =
            entry.snapshot().bound
        else {
            panic!("inbound forward must report its bound TCP listener");
        };

        let mut established = TcpStream::connect(address).await.unwrap();
        assert_eq!(echoed(&mut established, b"before").await, b"before");
        assert_eq!(entry.snapshot().active_connections, 1);

        // The setup permit ends once the relay is up: an established stream
        // never delays the drain and keeps relaying while fenced.
        assert!(gate.close());
        gate.drain(tokio::time::Instant::now() + Duration::from_millis(500))
            .await
            .unwrap();
        assert_eq!(echoed(&mut established, b"during").await, b"during");

        // New connection setup is refused before any guest contact.
        assert_refused(address).await;
        let snapshot = entry.snapshot();
        assert_eq!(snapshot.refused_connections, 1);
        assert_eq!(snapshot.active_connections, 1);

        // Unavailable guest transport must not park arrivals across a fence.
        let available = entry
            .availability
            .send_replace(crate::forward::GuestHalfAvailability::Unknown);
        assert_refused(address).await;
        assert_eq!(entry.snapshot().refused_connections, 2);
        entry.availability.send_replace(available);

        assert!(gate.reopen());
        let mut reopened = TcpStream::connect(address).await.unwrap();
        assert_eq!(echoed(&mut reopened, b"after").await, b"after");
        assert_eq!(echoed(&mut established, b"still").await, b"still");

        // Stop seals the fence for good.
        gate.seal();
        assert_refused(address).await;
        assert_eq!(entry.snapshot().refused_connections, 3);
        assert_eq!(echoed(&mut established, b"final").await, b"final");

        drop((established, reopened));
        table.shutdown().await.unwrap();
        machine.stop().await.unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }
}
