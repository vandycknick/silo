use std::io;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const NEGOTIATE_PROTOCOL_VERSION: u16 = 1;
pub const MAX_NEGOTIATE_FRAME_BYTES: usize = 16 * 1024;
pub const MAX_MESSAGE_BYTES: usize = 1024;
pub const MAX_AUTH_TOKEN_BYTES: usize = 4096;
pub const NEGOTIATE_STREAM_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Upgrade {
    Serial,
    Shell,
    Api { api_version: u32 },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Negotiate {
    pub protocol_version: u16,
    pub request_id: u64,
    pub upgrade: Upgrade,
    pub auth_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Accept {
    pub request_id: u64,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RejectCode {
    UnsupportedProtocol,
    UnsupportedUpgrade,
    UnsupportedService,
    ServiceStarting,
    ServiceUnavailable,
    PermissionDenied,
    AuthFailed,
    Internal,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Reject {
    pub request_id: u64,
    pub code: RejectCode,
    pub message: String,
    pub retry_after_ms: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Response {
    Accept(Accept),
    Reject(Reject),
}

#[derive(Debug)]
pub enum ClientUpgradeStreamError {
    Io(io::Error),
    Reject(Reject),
}

impl std::fmt::Display for ClientUpgradeStreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(err) => write!(f, "{err}"),
            Self::Reject(reject) => write!(f, "{}", reject.message),
        }
    }
}

impl std::error::Error for ClientUpgradeStreamError {}

impl Negotiate {
    pub fn new(request_id: u64, upgrade: Upgrade) -> Self {
        Self {
            protocol_version: NEGOTIATE_PROTOCOL_VERSION,
            request_id,
            upgrade,
            auth_token: None,
        }
    }

    pub fn validate(&self) -> io::Result<()> {
        if let Some(token) = &self.auth_token {
            if token.len() > MAX_AUTH_TOKEN_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "auth token exceeded max length",
                ));
            }
        }

        Ok(())
    }

    pub async fn read_from(stream: &mut (impl AsyncRead + Unpin)) -> io::Result<Self> {
        let payload = read_frame_async(stream).await?;
        let msg = deserialize_frame::<Self>(&payload)?;
        msg.validate()?;
        Ok(msg)
    }

    pub async fn write_to(&self, stream: &mut (impl AsyncWrite + Unpin)) -> io::Result<()> {
        self.validate()?;
        write_framed_async(stream, self).await
    }

    pub async fn client_upgrade_stream_v1(
        stream: tokio::net::UnixStream,
        upgrade: Upgrade,
    ) -> Result<tokio::net::UnixStream, ClientUpgradeStreamError> {
        let mut stream = stream;
        let negotiate = async {
            Negotiate::new(1, upgrade)
                .write_to(&mut stream)
                .await
                .map_err(ClientUpgradeStreamError::Io)?;

            match Response::read_from(&mut stream)
                .await
                .map_err(ClientUpgradeStreamError::Io)?
            {
                Response::Accept(_) => Ok(()),
                Response::Reject(reject) => Err(ClientUpgradeStreamError::Reject(reject)),
            }
        };

        match tokio::time::timeout(NEGOTIATE_STREAM_TIMEOUT, negotiate).await {
            Ok(Ok(())) => Ok(stream),
            Ok(Err(err)) => Err(err),
            Err(_) => Err(ClientUpgradeStreamError::Io(io::Error::new(
                io::ErrorKind::TimedOut,
                "negotiate stream timed out",
            ))),
        }
    }
}

impl Accept {
    pub fn validate(&self) -> io::Result<()> {
        if let Some(message) = &self.message {
            if message.len() > MAX_MESSAGE_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "accept message exceeded max length",
                ));
            }
        }

        Ok(())
    }

    pub async fn read_from(stream: &mut (impl AsyncRead + Unpin)) -> io::Result<Self> {
        let payload = read_frame_async(stream).await?;
        let msg = deserialize_frame::<Self>(&payload)?;
        msg.validate()?;
        Ok(msg)
    }

    pub async fn write_to(&self, stream: &mut (impl AsyncWrite + Unpin)) -> io::Result<()> {
        self.validate()?;
        write_framed_async(stream, self).await
    }
}

impl Reject {
    pub fn validate(&self) -> io::Result<()> {
        if self.message.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "reject message cannot be empty",
            ));
        }

        if self.message.len() > MAX_MESSAGE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "reject message exceeded max length",
            ));
        }

        Ok(())
    }

    pub async fn read_from(stream: &mut (impl AsyncRead + Unpin)) -> io::Result<Self> {
        let payload = read_frame_async(stream).await?;
        let msg = deserialize_frame::<Self>(&payload)?;
        msg.validate()?;
        Ok(msg)
    }

    pub async fn write_to(&self, stream: &mut (impl AsyncWrite + Unpin)) -> io::Result<()> {
        self.validate()?;
        write_framed_async(stream, self).await
    }
}

impl Response {
    pub async fn read_from(stream: &mut (impl AsyncRead + Unpin)) -> io::Result<Self> {
        let payload = read_frame_async(stream).await?;
        let response = deserialize_frame::<Self>(&payload)?;
        match &response {
            Self::Accept(accept) => accept.validate()?,
            Self::Reject(reject) => reject.validate()?,
        }
        Ok(response)
    }

    pub async fn write_to(&self, stream: &mut (impl AsyncWrite + Unpin)) -> io::Result<()> {
        write_framed_async(stream, self).await
    }
}

async fn write_framed_async(
    stream: &mut (impl AsyncWrite + Unpin),
    value: &impl Serialize,
) -> io::Result<()> {
    let payload = postcard::to_stdvec(value).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("serialize Negotiate frame: {err}"),
        )
    })?;

    if payload.len() > MAX_NEGOTIATE_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Negotiate frame exceeded max size",
        ));
    }

    let len = payload.len() as u32;
    stream.write_all(&len.to_le_bytes()).await?;
    stream.write_all(&payload).await?;
    stream.flush().await
}

async fn read_frame_async(stream: &mut (impl AsyncRead + Unpin)) -> io::Result<Vec<u8>> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;
    let len = u32::from_le_bytes(header) as usize;

    if len > MAX_NEGOTIATE_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Negotiate frame exceeded max size",
        ));
    }

    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).await?;
    Ok(payload)
}

fn deserialize_frame<T: for<'de> Deserialize<'de>>(payload: &[u8]) -> io::Result<T> {
    postcard::from_bytes(payload).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("decode Negotiate frame failed: {err}"),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_accept_round_trip() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build tokio runtime");

        rt.block_on(async {
            let (mut writer, mut reader) = tokio::io::duplex(4096);
            let expected = Response::Accept(Accept {
                request_id: 7,
                message: Some("ok".to_string()),
            });

            let write_task = tokio::spawn(async move {
                expected
                    .write_to(&mut writer)
                    .await
                    .expect("write accept response")
            });

            let decoded = Response::read_from(&mut reader)
                .await
                .expect("read response frame");

            write_task.await.expect("writer task join");
            assert_eq!(
                decoded,
                Response::Accept(Accept {
                    request_id: 7,
                    message: Some("ok".to_string())
                })
            );
        });
    }

    #[test]
    fn response_reject_round_trip() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build tokio runtime");

        rt.block_on(async {
            let (mut writer, mut reader) = tokio::io::duplex(4096);
            let expected = Response::Reject(Reject {
                request_id: 9,
                code: RejectCode::UnsupportedService,
                message: "unsupported".to_string(),
                retry_after_ms: None,
            });

            let write_task = tokio::spawn(async move {
                expected
                    .write_to(&mut writer)
                    .await
                    .expect("write reject response")
            });

            let decoded = Response::read_from(&mut reader)
                .await
                .expect("read response frame");

            write_task.await.expect("writer task join");
            assert_eq!(
                decoded,
                Response::Reject(Reject {
                    request_id: 9,
                    code: RejectCode::UnsupportedService,
                    message: "unsupported".to_string(),
                    retry_after_ms: None,
                })
            );
        });
    }

    #[test]
    fn oversized_frame_is_rejected() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build tokio runtime");

        rt.block_on(async {
            let (mut writer, mut reader) = tokio::io::duplex(64);
            let oversized_len = (MAX_NEGOTIATE_FRAME_BYTES as u32) + 1;

            writer
                .write_all(&oversized_len.to_le_bytes())
                .await
                .expect("write frame header");
            writer.flush().await.expect("flush frame header");
            drop(writer);

            let err = Response::read_from(&mut reader)
                .await
                .expect_err("oversized frame should fail");
            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
            assert!(err.to_string().contains("exceeded max size"));
        });
    }

    #[test]
    fn client_upgrade_stream_accepts_response() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build tokio runtime");

        rt.block_on(async {
            let (client, mut server) =
                tokio::net::UnixStream::pair().expect("create unix stream pair");

            let server_task = tokio::spawn(async move {
                let request = Negotiate::read_from(&mut server)
                    .await
                    .expect("read negotiate request");
                assert_eq!(request.protocol_version, NEGOTIATE_PROTOCOL_VERSION);

                Response::Accept(Accept {
                    request_id: request.request_id,
                    message: None,
                })
                .write_to(&mut server)
                .await
                .expect("write accept response");
            });

            let result =
                Negotiate::client_upgrade_stream_v1(client, Upgrade::Api { api_version: 1 }).await;

            server_task.await.expect("server task join");
            assert!(result.is_ok());
        });
    }

    #[test]
    fn client_upgrade_stream_returns_reject() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build tokio runtime");

        rt.block_on(async {
            let (client, mut server) =
                tokio::net::UnixStream::pair().expect("create unix stream pair");

            let server_task = tokio::spawn(async move {
                let request = Negotiate::read_from(&mut server)
                    .await
                    .expect("read negotiate request");

                Response::Reject(Reject {
                    request_id: request.request_id,
                    code: RejectCode::UnsupportedUpgrade,
                    message: "not supported yet".to_string(),
                    retry_after_ms: None,
                })
                .write_to(&mut server)
                .await
                .expect("write reject response");
            });

            let result =
                Negotiate::client_upgrade_stream_v1(client, Upgrade::Api { api_version: 1 }).await;

            server_task.await.expect("server task join");
            match result {
                Ok(_) => panic!("expected reject error"),
                Err(ClientUpgradeStreamError::Reject(reject)) => {
                    assert_eq!(reject.code, RejectCode::UnsupportedUpgrade);
                    assert_eq!(reject.message, "not supported yet");
                }
                Err(ClientUpgradeStreamError::Io(err)) => {
                    panic!("unexpected io error: {err}");
                }
            }
        });
    }
}
