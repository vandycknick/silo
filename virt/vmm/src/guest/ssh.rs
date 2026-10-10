use std::future::Future;
use std::io;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{oneshot, watch};
use tokio_util::sync::{CancellationToken, WaitForCancellationFutureOwned};

use crate::state::{InstanceStore, SshVerificationTarget, StoreError};
use crate::virt::VirtualMachine;

const CHECK_INTERVAL: Duration = Duration::from_secs(60);
const ATTEMPT_BUDGET: Duration = Duration::from_secs(5);

#[derive(Default)]
struct Schedule {
    completed: Option<(u64, Instant)>,
}

impl Schedule {
    fn due(&self, epoch: u64, now: Instant) -> Instant {
        match self.completed {
            Some((previous, completed)) if previous == epoch => completed + CHECK_INTERVAL,
            _ => now,
        }
    }

    fn complete(&mut self, epoch: u64, now: Instant) {
        self.completed = Some((epoch, now));
    }
}

pub(crate) async fn supervise_ssh_verification(
    machine: VirtualMachine,
    machine_dir: PathBuf,
    store: Arc<InstanceStore>,
    shutdown: CancellationToken,
) {
    if let Err(error) = supervise(machine, machine_dir, store, shutdown).await {
        tracing::error!(%error, "SSH verification supervisor stopped");
    }
}

async fn supervise(
    machine: VirtualMachine,
    machine_dir: PathBuf,
    store: Arc<InstanceStore>,
    shutdown: CancellationToken,
) -> Result<(), StoreError> {
    let mut generation = store.subscribe();
    let mut schedule = Schedule::default();
    loop {
        generation.borrow_and_update();
        if shutdown.is_cancelled() {
            return Ok(());
        }
        let Some(target) = store.ssh_verification_target()? else {
            tokio::select! {
                _ = shutdown.cancelled() => return Ok(()),
                changed = generation.changed() => if changed.is_err() { return Ok(()); },
            }
            continue;
        };
        let due = schedule.due(target.epoch, Instant::now());
        if due > Instant::now() {
            tokio::select! {
                _ = shutdown.cancelled() => return Ok(()),
                changed = generation.changed() => if changed.is_err() { return Ok(()); },
                _ = tokio::time::sleep_until(due.into()) => {},
            }
            continue;
        }
        // This call owns and drains the sole network/pin slot, even after publishing a timeout.
        if let Some(completed) = attempt(
            &machine,
            &machine_dir,
            &store,
            &target,
            &shutdown,
            &mut generation,
        )
        .await?
        {
            schedule.complete(target.epoch, completed);
        }
    }
}

async fn target_changed(
    store: &InstanceStore,
    target: &SshVerificationTarget,
    generation: &mut watch::Receiver<u64>,
) -> Result<(), StoreError> {
    loop {
        generation.borrow_and_update();
        if store
            .ssh_verification_target()?
            .is_none_or(|current| current.epoch != target.epoch)
        {
            return Ok(());
        }
        if generation.changed().await.is_err() {
            return Ok(());
        }
    }
}

enum Completion<T> {
    Result(T),
    Timeout,
    Invalidated(Result<(), StoreError>),
}

async fn attempt(
    machine: &VirtualMachine,
    machine_dir: &std::path::Path,
    store: &InstanceStore,
    target: &SshVerificationTarget,
    shutdown: &CancellationToken,
    generation: &mut watch::Receiver<u64>,
) -> Result<Option<Instant>, StoreError> {
    let deadline = tokio::time::Instant::now() + ATTEMPT_BUDGET;
    let cancel = CancellationToken::new();
    let guard = cancel.clone().drop_guard();
    let (closed_tx, closed_rx) = oneshot::channel();
    let network = async {
        let expected = russh::keys::PublicKey::from_openssh(&target.host_public_key)?;
        let stream = machine.connect_vsock(target.port).await?;
        let stream = ProbeStream::new(stream, cancel.clone(), closed_tx);
        verify_ssh_stream(stream, expected.clone()).await?;
        Ok::<_, eyre::Report>(expected)
    };
    let outcome = {
        tokio::pin!(network);
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => Completion::Invalidated(Ok(())),
            changed = target_changed(store, target, generation) => Completion::Invalidated(changed),
            _ = tokio::time::sleep_until(deadline) => Completion::Timeout,
            result = &mut network => Completion::Result(result),
        }
    };
    drop(guard);
    // Publish failures before draining potentially delayed resources.
    let expected = match outcome {
        Completion::Timeout => {
            let completed = publish(
                store,
                target,
                Err("SSH listener verification timed out".into()),
            );
            let _ = closed_rx.await;
            return completed.map(Some);
        }
        Completion::Invalidated(result) => {
            let _ = closed_rx.await;
            return result.map(|()| None);
        }
        Completion::Result(Ok(expected)) => expected,
        Completion::Result(Err(error)) => {
            let completed = publish(store, target, Err(error.to_string()));
            let _ = closed_rx.await;
            return completed.map(Some);
        }
    };
    let _ = closed_rx.await;
    if shutdown.is_cancelled()
        || store
            .ssh_verification_target()?
            .is_none_or(|current| current.epoch != target.epoch)
    {
        return Ok(None);
    }
    if tokio::time::Instant::now() >= deadline {
        return publish(
            store,
            target,
            Err("SSH listener verification timed out".into()),
        )
        .map(Some);
    }
    let dir = machine_dir.to_path_buf();
    let mut pin =
        tokio::task::spawn_blocking(move || utils::ssh::try_verify_host_key_pin(&dir, &expected));
    let outcome = tokio::select! {
        biased;
        _ = shutdown.cancelled() => Completion::Invalidated(Ok(())),
        changed = target_changed(store, target, generation) => Completion::Invalidated(changed),
        _ = tokio::time::sleep_until(deadline) => Completion::Timeout,
        result = &mut pin => Completion::Result(result),
    };
    match outcome {
        Completion::Result(result) => {
            let result = result
                .map_err(|error| error.to_string())
                .and_then(|result| result.map_err(|error| error.to_string()));
            publish(store, target, result).map(Some)
        }
        Completion::Timeout => {
            let completed = publish(
                store,
                target,
                Err("SSH listener pin verification timed out".into()),
            );
            let _ = pin.await;
            completed.map(Some)
        }
        Completion::Invalidated(result) => {
            let _ = pin.await;
            result.map(|()| None)
        }
    }
}

fn publish(
    store: &InstanceStore,
    target: &SshVerificationTarget,
    result: Result<(), String>,
) -> Result<Instant, StoreError> {
    if let Err(error) = &result {
        tracing::warn!(%error, "guest SSH readiness verification failed");
    }
    store.complete_ssh_verification(target, result)?;
    Ok(Instant::now())
}

struct ProbeStream<S> {
    stream: Option<S>,
    cancelled: Pin<Box<WaitForCancellationFutureOwned>>,
    closed: Option<oneshot::Sender<()>>,
}

impl<S> ProbeStream<S> {
    fn new(stream: S, cancel: CancellationToken, closed: oneshot::Sender<()>) -> Self {
        Self {
            stream: Some(stream),
            cancelled: Box::pin(cancel.cancelled_owned()),
            closed: Some(closed),
        }
    }

    fn check(&mut self, cx: &mut Context<'_>) -> io::Result<&mut S> {
        if self.cancelled.as_mut().poll(cx).is_ready() {
            self.stream.take();
            if let Some(closed) = self.closed.take() {
                let _ = closed.send(());
            }
        }
        self.stream
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::ConnectionAborted, "SSH probe canceled"))
    }
}

impl<S> Drop for ProbeStream<S> {
    fn drop(&mut self) {
        self.stream.take();
        if let Some(closed) = self.closed.take() {
            let _ = closed.send(());
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ProbeStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(self.check(cx)?).poll_read(cx, buf)
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for ProbeStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(self.check(cx)?).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(self.check(cx)?).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(self.check(cx)?).poll_shutdown(cx)
    }
}

async fn verify_ssh_stream<S>(stream: S, expected: russh::keys::PublicKey) -> eyre::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let handle = russh::client::connect_stream(
        Arc::new(russh::client::Config::default()),
        stream,
        ListenerKey { expected },
    )
    .await?;
    handle
        .disconnect(russh::Disconnect::ByApplication, "readiness probe", "en")
        .await?;
    match handle.await {
        Ok(()) | Err(russh::Error::Disconnect) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

struct ListenerKey {
    expected: russh::keys::PublicKey,
}
impl russh::client::Handler for ListenerKey {
    type Error = russh::Error;
    async fn check_server_key(
        &mut self,
        key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(key.key_data() == self.expected.key_data())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use russh::keys::ssh_key::{private::Ed25519Keypair, PrivateKey};
    use tokio::io::AsyncReadExt;
    use tokio::sync::oneshot;
    use tokio_util::sync::CancellationToken;

    use crate::guest::ssh::{verify_ssh_stream, ProbeStream, Schedule, CHECK_INTERVAL};

    #[test]
    fn schedule_uses_completion_and_epoch_not_heartbeat() {
        let now = Instant::now();
        let mut schedule = Schedule::default();
        assert_eq!(schedule.due(1, now), now);
        let completed = now + Duration::from_secs(4);
        schedule.complete(1, completed);
        for seconds in [5, 10, 15, 60, 64, 100] {
            assert_eq!(
                schedule.due(1, now + Duration::from_secs(seconds)),
                completed + CHECK_INTERVAL,
            );
        }
        assert_eq!(schedule.due(2, completed), completed);
        // Failures use the same completion path, with no rapid retry schedule.
        let failed = completed + CHECK_INTERVAL + Duration::from_secs(5);
        schedule.complete(1, failed);
        assert_eq!(schedule.due(1, failed), failed + CHECK_INTERVAL);
        assert_eq!(schedule.due(3, failed), failed);
    }

    struct RejectAuth;
    impl russh::server::Handler for RejectAuth {
        type Error = russh::Error;
    }

    #[tokio::test]
    async fn actual_ssh_kex_accepts_only_the_reported_listener_key() {
        let host = PrivateKey::from(Ed25519Keypair::from_seed(&[1; 32]));
        let other = PrivateKey::from(Ed25519Keypair::from_seed(&[2; 32]));
        for (expected, valid) in [
            (host.public_key().clone(), true),
            (other.public_key().clone(), false),
        ] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let stream = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
                .await
                .unwrap();
            let (server_stream, _) = listener.accept().await.unwrap();
            let config = Arc::new(russh::server::Config {
                keys: vec![host.clone()],
                ..Default::default()
            });
            let server = tokio::spawn(async move {
                if let Ok(session) =
                    russh::server::run_stream(config, server_stream, RejectAuth).await
                {
                    let _ = session.await;
                }
            });
            let cancel = CancellationToken::new();
            let guard = cancel.clone().drop_guard();
            let (closed_tx, closed_rx) = oneshot::channel();
            let result = tokio::time::timeout(
                Duration::from_secs(5),
                verify_ssh_stream(ProbeStream::new(stream, cancel, closed_tx), expected),
            )
            .await
            .unwrap();
            assert_eq!(result.is_ok(), valid, "{result:?}");
            drop(guard);
            tokio::time::timeout(Duration::from_secs(2), closed_rx)
                .await
                .unwrap()
                .unwrap();
            // Joining, rather than aborting, proves the accepted connection was closed.
            tokio::time::timeout(Duration::from_secs(2), server)
                .await
                .unwrap()
                .unwrap();
        }
    }

    #[tokio::test]
    async fn canceled_and_timed_out_stalled_peers_close_before_slot_reuse() {
        let host = PrivateKey::from(Ed25519Keypair::from_seed(&[1; 32]));
        for attempt in 0..6 {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let stream = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
                .await
                .unwrap();
            let (mut peer, _) = listener.accept().await.unwrap();
            let cancel = CancellationToken::new();
            let guard = cancel.clone().drop_guard();
            let (closed_tx, closed_rx) = oneshot::channel();
            let handshake = verify_ssh_stream(
                ProbeStream::new(stream, cancel.clone(), closed_tx),
                host.public_key().clone(),
            );
            if attempt % 2 == 0 {
                assert!(tokio::time::timeout(Duration::from_millis(25), handshake)
                    .await
                    .is_err());
            } else {
                tokio::pin!(handshake);
                tokio::select! {
                    result = &mut handshake => panic!("stalled peer completed: {result:?}"),
                    _ = tokio::time::sleep(Duration::from_millis(25)) => cancel.cancel(),
                }
                assert!(handshake.await.is_err());
            }
            drop(guard);
            tokio::time::timeout(Duration::from_secs(2), closed_rx)
                .await
                .unwrap()
                .unwrap();
            let mut received = Vec::new();
            tokio::time::timeout(Duration::from_secs(2), peer.read_to_end(&mut received))
                .await
                .unwrap()
                .unwrap();
            assert!(received.starts_with(b"SSH-2.0-"));
        }
    }
}
