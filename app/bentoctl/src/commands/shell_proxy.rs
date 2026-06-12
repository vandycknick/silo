use std::fmt::{Display, Formatter};
use std::io;
use std::time::Duration;

use bento_libvm::{MachineRef, Runtime};
use clap::Args;
use eyre::Context;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};

const FIRST_BACKEND_BYTE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Args, Debug)]
#[command(hide = true)]
pub struct Cmd {
    #[arg(long)]
    pub name: String,
}

impl Display for Cmd {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "--name {}", self.name)
    }
}

impl Cmd {
    pub async fn run(&self, libvm: &Runtime) -> eyre::Result<()> {
        let machine = libvm
            .get_machine(&MachineRef::parse(self.name.clone())?)
            .await?;
        let stream = machine
            .open_shell_stream(true)
            .await
            .context("open negotiated shell stream")?;
        proxy_stdio(stream).await
    }
}

async fn proxy_stdio(stream: tokio::net::UnixStream) -> eyre::Result<()> {
    proxy_streams(tokio::io::stdin(), tokio::io::stdout(), stream).await
}

async fn proxy_streams<R, W>(
    input: R,
    output: W,
    stream: tokio::net::UnixStream,
) -> eyre::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    proxy_streams_with_timeout(input, output, stream, FIRST_BACKEND_BYTE_TIMEOUT).await
}

async fn proxy_streams_with_timeout<R, W>(
    input: R,
    mut output: W,
    stream: tokio::net::UnixStream,
    first_backend_byte_timeout: Duration,
) -> eyre::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let (stream_read, stream_write) = stream.into_split();
    let stream_read =
        wait_for_first_byte(stream_read, &mut output, first_backend_byte_timeout).await?;
    let input = relay_input(input, stream_write);
    let output = relay_output(stream_read, output);

    tokio::pin!(input);
    tokio::pin!(output);

    tokio::select! {
        result = &mut output => result,
        result = &mut input => {
            result?;
            output.await
        }
    }
}

async fn wait_for_first_byte<W>(
    mut stream_read: OwnedReadHalf,
    output: &mut W,
    timeout: Duration,
) -> eyre::Result<OwnedReadHalf>
where
    W: AsyncWrite + Unpin,
{
    let mut byte = [0_u8; 1];
    let read = tokio::time::timeout(timeout, stream_read.read(&mut byte))
        .await
        .context("timed out waiting for SSH banner from shell backend")?
        .context("read first byte from shell backend")?;

    if read == 0 {
        eyre::bail!("shell backend closed before SSH banner");
    }

    output
        .write_all(&byte[..read])
        .await
        .context("write first byte from shell backend")?;
    output
        .flush()
        .await
        .context("flush first byte from shell backend")?;

    Ok(stream_read)
}

async fn relay_input<R>(mut input: R, mut stream_write: OwnedWriteHalf) -> eyre::Result<()>
where
    R: AsyncRead + Unpin,
{
    match tokio::io::copy(&mut input, &mut stream_write).await {
        Ok(_) => {}
        Err(err) if is_expected_disconnect(&err) => return Ok(()),
        Err(err) => return Err(err).context("relay shell input"),
    }

    match stream_write.shutdown().await {
        Ok(()) => Ok(()),
        Err(err) if is_expected_disconnect(&err) => Ok(()),
        Err(err) => Err(err).context("shutdown shell input stream"),
    }
}

async fn relay_output<W>(mut stream_read: OwnedReadHalf, mut output: W) -> eyre::Result<()>
where
    W: AsyncWrite + Unpin,
{
    match tokio::io::copy(&mut stream_read, &mut output).await {
        Ok(_) => {}
        Err(err) if is_expected_disconnect(&err) => return Ok(()),
        Err(err) => return Err(err).context("relay shell output"),
    }

    match output.flush().await {
        Ok(()) => Ok(()),
        Err(err) if is_expected_disconnect(&err) => Ok(()),
        Err(err) => Err(err).context("flush shell output"),
    }
}

fn is_expected_disconnect(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::NotConnected
            | io::ErrorKind::UnexpectedEof
            | io::ErrorKind::Interrupted
    )
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;

    use crate::commands::shell_proxy::{proxy_streams, proxy_streams_with_timeout};

    #[tokio::test]
    async fn proxy_exits_when_backend_closes_while_input_is_pending() {
        let (stream, backend) = UnixStream::pair().expect("unix stream pair should be created");
        let (input, _input_peer) = tokio::io::duplex(16);
        let output = tokio::io::sink();

        let proxy = tokio::spawn(proxy_streams(input, output, stream));
        drop(backend);

        let err = tokio::time::timeout(Duration::from_secs(1), proxy)
            .await
            .expect("proxy should exit when backend closes")
            .expect("proxy task should join")
            .expect_err("pre-banner backend close should fail");

        assert!(err.to_string().contains("closed before SSH banner"));
    }

    #[tokio::test]
    async fn proxy_exits_when_backend_stays_open_without_banner() {
        let (stream, _backend) = UnixStream::pair().expect("unix stream pair should be created");
        let (input, _input_peer) = tokio::io::duplex(16);
        let output = tokio::io::sink();

        let proxy = tokio::spawn(proxy_streams_with_timeout(
            input,
            output,
            stream,
            Duration::from_millis(10),
        ));

        let err = tokio::time::timeout(Duration::from_secs(1), proxy)
            .await
            .expect("proxy should exit when backend sends no banner")
            .expect("proxy task should join")
            .expect_err("pre-banner backend timeout should fail");

        assert!(err.to_string().contains("timed out waiting for SSH banner"));
    }

    #[tokio::test]
    async fn proxy_relays_remaining_output_after_input_eof() {
        let (stream, mut backend) = UnixStream::pair().expect("unix stream pair should be created");
        let (input, mut input_peer) = tokio::io::duplex(16);
        let (output, mut output_peer) = tokio::io::duplex(16);

        let proxy = tokio::spawn(proxy_streams(input, output, stream));

        backend
            .write_all(b"w")
            .await
            .expect("backend banner byte should be written");

        input_peer
            .write_all(b"hello")
            .await
            .expect("test input should be written");
        drop(input_peer);

        let mut input_buf = [0_u8; 5];
        backend
            .read_exact(&mut input_buf)
            .await
            .expect("backend should receive proxied input");
        assert_eq!(&input_buf, b"hello");

        let mut eof_buf = [0_u8; 1];
        let read = backend
            .read(&mut eof_buf)
            .await
            .expect("backend should observe input EOF");
        assert_eq!(read, 0);

        backend
            .write_all(b"orld")
            .await
            .expect("backend output should be written");
        drop(backend);

        tokio::time::timeout(Duration::from_secs(1), proxy)
            .await
            .expect("proxy should exit after backend closes")
            .expect("proxy task should join")
            .expect("proxy should finish cleanly");

        let mut output_buf = Vec::new();
        output_peer
            .read_to_end(&mut output_buf)
            .await
            .expect("test output should be readable");
        assert_eq!(&output_buf, b"world");
    }
}
