use std::time::Duration;

use bento_protocol::negotiate::{
    Accept, Negotiate, Reject, RejectCode, Response as NegotiateResponse, Upgrade,
    NEGOTIATE_PROTOCOL_VERSION,
};
use eyre::Context;
use tokio::net::{UnixListener, UnixStream};
use tokio_util::sync::CancellationToken;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) struct NegotiateListener {
    listener: UnixListener,
    shutdown: CancellationToken,
}

pub(crate) struct PendingNegotiation {
    stream: UnixStream,
    request_id: u64,
    upgrade: Upgrade,
}

impl PendingNegotiation {
    pub(crate) fn upgrade(&self) -> &Upgrade {
        &self.upgrade
    }

    pub(crate) async fn accept(mut self) -> eyre::Result<(UnixStream, Upgrade)> {
        accept(&mut self.stream, self.request_id, None).await?;
        Ok((self.stream, self.upgrade))
    }

    pub(crate) async fn reject(
        mut self,
        code: RejectCode,
        message: impl Into<String>,
        retry_after_ms: Option<u32>,
    ) -> eyre::Result<()> {
        reject(
            &mut self.stream,
            self.request_id,
            code,
            message,
            retry_after_ms,
        )
        .await
    }
}

impl NegotiateListener {
    pub(crate) fn new(listener: UnixListener, shutdown: CancellationToken) -> Self {
        Self { listener, shutdown }
    }

    pub(crate) async fn next(&self) -> Option<PendingNegotiation> {
        loop {
            let (mut stream, _) = tokio::select! {
                _ = self.shutdown.cancelled() => {
                    tracing::info!("instance control socket shutting down");
                    return None;
                }
                accepted = self.listener.accept() => {
                    match accepted {
                        Ok(accepted) => accepted,
                        Err(err) => {
                            tracing::warn!(error = %err, "accept control socket connection failed");
                            continue;
                        }
                    }
                }
            };

            let request =
                match tokio::time::timeout(HANDSHAKE_TIMEOUT, Negotiate::read_from(&mut stream))
                    .await
                {
                    Ok(Ok(request)) => request,
                    Ok(Err(err)) => {
                        tracing::warn!(error = %err, "failed to read Negotiate request");
                        continue;
                    }
                    Err(_) => {
                        tracing::warn!("timed out waiting for Negotiate request");
                        continue;
                    }
                };

            if request.protocol_version != NEGOTIATE_PROTOCOL_VERSION {
                if let Err(err) = reject(
                    &mut stream,
                    request.request_id,
                    RejectCode::UnsupportedProtocol,
                    format!(
                        "Negotiate protocol version {} is unsupported",
                        request.protocol_version
                    ),
                    None,
                )
                .await
                {
                    tracing::warn!(error = %err, "failed to reject unsupported protocol");
                }
                continue;
            }

            if !peer_uid_matches_current(&stream) {
                if let Err(err) = reject(
                    &mut stream,
                    request.request_id,
                    RejectCode::PermissionDenied,
                    "peer uid is not authorized for this socket",
                    None,
                )
                .await
                {
                    tracing::warn!(error = %err, "failed to reject unauthorized peer");
                }
                continue;
            }

            return Some(PendingNegotiation {
                stream,
                request_id: request.request_id,
                upgrade: request.upgrade,
            });
        }
    }
}

async fn accept(
    stream: &mut UnixStream,
    request_id: u64,
    message: Option<String>,
) -> eyre::Result<()> {
    NegotiateResponse::Accept(Accept {
        request_id,
        message,
    })
    .write_to(stream)
    .await
    .context("write Negotiate accept")?;
    Ok(())
}

async fn reject(
    stream: &mut UnixStream,
    request_id: u64,
    code: RejectCode,
    message: impl Into<String>,
    retry_after_ms: Option<u32>,
) -> eyre::Result<()> {
    NegotiateResponse::Reject(Reject {
        request_id,
        code,
        message: message.into(),
        retry_after_ms,
    })
    .write_to(stream)
    .await
    .context("write Negotiate reject")?;
    Ok(())
}

fn peer_uid_matches_current(stream: &UnixStream) -> bool {
    match peer_uid(stream) {
        Ok(peer_uid) => peer_uid == unsafe { libc::geteuid() },
        Err(err) => {
            tracing::warn!(error = %err, "failed to resolve peer uid");
            false
        }
    }
}

#[cfg(target_os = "macos")]
fn peer_uid(stream: &UnixStream) -> std::io::Result<u32> {
    use std::os::fd::AsRawFd;

    let fd = stream.as_raw_fd();
    let mut euid: libc::uid_t = 0;
    let mut egid: libc::gid_t = 0;
    let rc = unsafe { libc::getpeereid(fd, &mut euid, &mut egid) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(euid)
}

#[cfg(target_os = "linux")]
fn peer_uid(stream: &UnixStream) -> std::io::Result<u32> {
    use std::os::fd::AsRawFd;

    let fd = stream.as_raw_fd();
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast::<libc::c_void>(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(cred.uid)
}
