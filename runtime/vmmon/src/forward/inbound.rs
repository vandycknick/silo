use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use forward_spec::{GuestHalf, Reply, TargetLine, MAX_TARGET_LINE_BYTES};
use tokio::io::AsyncWriteExt;
use tokio::task::JoinSet;
use tokio::time::Instant;

use crate::forward::host_socket::{HostStream, OwnedHostListener};
use crate::forward::{ForwardEntry, GuestHalfAvailability};
use crate::virt::VirtualMachine;

const MAX_PARKED_PER_FORWARD: usize = 64;
const PARK_TIMEOUT: Duration = Duration::from_secs(30);
const FORWARD_SETUP_TIMEOUT: Duration = Duration::from_secs(5);

struct Parked {
    stream: HostStream,
    deadline: Instant,
}

pub(crate) async fn serve(
    listener: OwnedHostListener,
    entry: Arc<ForwardEntry>,
    machine: VirtualMachine,
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
                Ok(stream) => admit(stream, &entry, &machine, &availability, &mut parked, &mut connections).await,
                Err(error) => tracing::warn!(forward = %entry.name, %error, "forward accept failed"),
            },
            changed = availability.changed() => {
                if changed.is_err() { break; }
                let current = availability.borrow().clone();
                entry.apply_availability(current.clone());
                match current {
                    GuestHalfAvailability::Available(_) => {
                        let now = Instant::now();
                        while let Some(mut parked_connection) = parked.pop_front() {
                            if parked_connection.deadline <= now {
                                entry.refuse();
                                let _ = parked_connection.stream.shutdown().await;
                                continue;
                            }
                            spawn_connection(
                                parked_connection.stream,
                                entry.clone(),
                                machine.clone(),
                                availability.clone(),
                                &mut connections,
                            );
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
    parked.clear();
    while connections.join_next().await.is_some() {}
}

async fn admit(
    mut stream: HostStream,
    entry: &Arc<ForwardEntry>,
    machine: &VirtualMachine,
    availability: &tokio::sync::watch::Receiver<GuestHalfAvailability>,
    parked: &mut VecDeque<Parked>,
    connections: &mut JoinSet<()>,
) {
    let current = availability.borrow().clone();
    match current {
        GuestHalfAvailability::Available(_) => spawn_connection(
            stream,
            entry.clone(),
            machine.clone(),
            availability.clone(),
            connections,
        ),
        GuestHalfAvailability::Unknown if parked.len() < MAX_PARKED_PER_FORWARD => {
            parked.push_back(Parked {
                stream,
                deadline: Instant::now() + PARK_TIMEOUT,
            });
        }
        GuestHalfAvailability::Unknown | GuestHalfAvailability::Unsupported => {
            entry.refuse();
            let _ = stream.shutdown().await;
        }
    }
}

fn spawn_connection(
    stream: HostStream,
    entry: Arc<ForwardEntry>,
    machine: VirtualMachine,
    availability: tokio::sync::watch::Receiver<GuestHalfAvailability>,
    connections: &mut JoinSet<()>,
) {
    connections.spawn(async move {
        if let Err(error) = handle_connection(stream, entry.clone(), machine, availability).await {
            entry.refuse();
            tracing::debug!(forward = %entry.name, target = %entry.spec.connect, %error, "forward connection refused");
        }
    });
}

async fn handle_connection(
    mut client: HostStream,
    entry: Arc<ForwardEntry>,
    machine: VirtualMachine,
    mut availability: tokio::sync::watch::Receiver<GuestHalfAvailability>,
) -> eyre::Result<()> {
    let expected = availability.borrow().clone();
    let mut guest = tokio::time::timeout(FORWARD_SETUP_TIMEOUT, async {
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
                    .write_all(&forward_spec::encode_connect(&TargetLine::Address(address)))
                    .await?;
                let reply = forward_spec::io::read_line(&mut stream, MAX_TARGET_LINE_BYTES).await?;
                match forward_spec::parse_reply(&reply)? {
                    Reply::Ok => Ok(stream),
                    Reply::Err(reason) => Err(eyre::eyre!("guest dialer replied ERR {reason}")),
                }
            }
        }
    })
    .await
    .map_err(|_| eyre::eyre!("forward setup timed out"))??;

    entry.connection_opened();
    let result = match &entry.guest_half {
        GuestHalf::Agent(_) => tokio::select! {
            result = crate::vsock::relay::relay(&mut client, &mut guest, entry.shutdown.clone()) => result,
            changed = availability.changed() => {
                let _ = changed;
                if *availability.borrow() == expected {
                    entry.connection_closed();
                    return Ok(());
                }
                Ok(())
            }
        },
        GuestHalf::Vsock(_) => {
            crate::vsock::relay::relay(&mut client, &mut guest, entry.shutdown.clone()).await
        }
    };
    entry.connection_closed();
    result.map_err(eyre::Report::from)
}
