use std::io;
use std::pin::Pin;
use std::time::Duration;

use forward_spec::{
    encode_reply, parse_connect, Address, ErrReason, Reply, TargetLine, MAX_TARGET_LINE_BYTES,
};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UnixStream};

const SETUP_TIMEOUT: Duration = Duration::from_secs(5);

trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T> AsyncStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}
type ConnectedStream = Pin<Box<dyn AsyncStream>>;

pub(crate) async fn handle<S>(mut client: S) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let setup = tokio::time::timeout(SETUP_TIMEOUT, async {
        let line = forward_spec::io::read_line(&mut client, MAX_TARGET_LINE_BYTES)
            .await
            .map_err(|_| ErrReason::Invalid)?;
        let address = match parse_connect(&line).map_err(|_| ErrReason::Invalid)? {
            TargetLine::Address(address) => address,
            TargetLine::Token(_) => return Err(ErrReason::Invalid),
        };
        let target = connect(address).await?;
        client
            .write_all(encode_reply(&Reply::Ok))
            .await
            .map_err(|_| ErrReason::Refused)?;
        Ok::<_, ErrReason>(target)
    })
    .await;

    let mut target = match setup {
        Ok(Ok(target)) => target,
        Ok(Err(reason)) => {
            write_error(&mut client, reason).await?;
            return Ok(());
        }
        Err(_) => {
            write_error(&mut client, ErrReason::Timeout).await?;
            return Ok(());
        }
    };

    tokio::io::copy_bidirectional(&mut client, &mut target).await?;
    Ok(())
}

async fn connect(address: Address) -> Result<ConnectedStream, ErrReason> {
    match address {
        Address::Tcp(address) => TcpStream::connect(address)
            .await
            .map(|stream| Box::pin(stream) as ConnectedStream)
            .map_err(map_connect_error),
        Address::Unix(path) => UnixStream::connect(path)
            .await
            .map(|stream| Box::pin(stream) as ConnectedStream)
            .map_err(map_connect_error),
    }
}

fn map_connect_error(error: io::Error) -> ErrReason {
    match error.kind() {
        io::ErrorKind::NotFound => ErrReason::NotFound,
        io::ErrorKind::PermissionDenied => ErrReason::Permission,
        io::ErrorKind::TimedOut => ErrReason::Timeout,
        io::ErrorKind::HostUnreachable
        | io::ErrorKind::NetworkUnreachable
        | io::ErrorKind::AddrNotAvailable => ErrReason::Unreachable,
        io::ErrorKind::ConnectionRefused => ErrReason::Refused,
        _ => ErrReason::Refused,
    }
}

async fn write_error<S>(stream: &mut S, reason: ErrReason) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    stream.write_all(encode_reply(&Reply::Err(reason))).await
}

#[cfg(test)]
mod tests {
    use std::io;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, UnixListener};

    async fn spawn_tcp_echo() -> io::Result<std::net::SocketAddr> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let (mut reader, mut writer) = stream.split();
                let _ = tokio::io::copy(&mut reader, &mut writer).await;
            }
        });
        Ok(address)
    }

    #[tokio::test]
    async fn preserves_pipelined_bytes_for_tcp() {
        let address = spawn_tcp_echo().await.expect("spawn echo");
        let (mut client, server) = tokio::io::duplex(1024);
        let task = tokio::spawn(crate::forward::dialer::handle(server));
        client
            .write_all(format!("CONNECT tcp:{address}\nhello").as_bytes())
            .await
            .expect("write request");

        let mut response = [0_u8; 8];
        client
            .read_exact(&mut response)
            .await
            .expect("read response");
        assert_eq!(&response, b"OK\nhello");
        drop(client);
        task.await.expect("join dialer").expect("dialer result");
    }

    #[tokio::test]
    async fn connects_to_unix_target() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("echo.sock");
        let listener = UnixListener::bind(&path).expect("bind unix echo");
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let (mut reader, mut writer) = stream.split();
                let _ = tokio::io::copy(&mut reader, &mut writer).await;
            }
        });
        let (mut client, server) = tokio::io::duplex(1024);
        let task = tokio::spawn(crate::forward::dialer::handle(server));
        client
            .write_all(format!("CONNECT unix:{}\nping", path.display()).as_bytes())
            .await
            .expect("write request");
        let mut response = [0_u8; 7];
        client
            .read_exact(&mut response)
            .await
            .expect("read response");
        assert_eq!(&response, b"OK\nping");
        drop(client);
        task.await.expect("join dialer").expect("dialer result");
    }

    #[tokio::test]
    async fn maps_refused_missing_and_invalid_targets() {
        let occupied = TcpListener::bind("127.0.0.1:0").await.expect("bind port");
        let address = occupied.local_addr().expect("local address");
        drop(occupied);
        let directory = tempfile::tempdir().expect("tempdir");
        let cases = [
            (
                format!("CONNECT tcp:{address}\n"),
                b"ERR refused\n".as_slice(),
            ),
            (
                format!(
                    "CONNECT unix:{}\n",
                    directory.path().join("missing").display()
                ),
                b"ERR not-found\n".as_slice(),
            ),
            (
                "CONNECT 00000000000000000000000000000000\n".to_string(),
                b"ERR invalid\n".as_slice(),
            ),
            (
                "CONNECT tcp:80\r\n".to_string(),
                b"ERR invalid\n".as_slice(),
            ),
            (
                format!("CONNECT unix:/{}\n", "x".repeat(498)),
                b"ERR invalid\n".as_slice(),
            ),
        ];

        for (request, expected) in cases {
            let (mut client, server) = tokio::io::duplex(1024);
            let task = tokio::spawn(crate::forward::dialer::handle(server));
            client
                .write_all(request.as_bytes())
                .await
                .expect("write request");
            let mut response = Vec::new();
            client
                .read_to_end(&mut response)
                .await
                .expect("read response");
            assert_eq!(response, expected, "request {request:?}");
            task.await.expect("join dialer").expect("dialer result");
        }
    }
}
