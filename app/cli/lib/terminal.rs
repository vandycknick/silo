use std::os::fd::{AsFd, AsRawFd};

use eyre::Context as _;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub(crate) async fn attach_serial_stream<S>(stream: S) -> eyre::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    print_serial_exit_hint();
    proxy_serial_stdio(stream).await
}

fn print_serial_exit_hint() {
    // nix does not expose isatty without enabling another feature just for this guard.
    if unsafe { libc::isatty(std::io::stderr().as_raw_fd()) } == 0 {
        return;
    }

    eprintln!("Connected to serial console. Exit with Ctrl+]");
}

async fn proxy_serial_stdio<S>(stream: S) -> eyre::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let _raw_terminal = RawTerminalGuard::new()?;
    proxy_serial_io(stream, tokio::io::stdin(), tokio::io::stdout()).await
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SerialInputEnd {
    Detached,
    Eof,
}

async fn proxy_serial_io<S, R, W>(stream: S, mut input: R, mut output: W) -> eyre::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let (mut stream_read, mut stream_write) = tokio::io::split(stream);

    let input_task = async {
        let mut buf = [0_u8; 1024];

        loop {
            let n = input
                .read(&mut buf)
                .await
                .context("relay serial input read")?;
            if n == 0 {
                stream_write
                    .shutdown()
                    .await
                    .context("relay serial input shutdown")?;
                return Ok::<SerialInputEnd, eyre::Report>(SerialInputEnd::Eof);
            }

            let chunk = &buf[..n];
            if let Some(detach_index) = chunk.iter().position(|byte| *byte == 0x1d) {
                if detach_index > 0 {
                    stream_write
                        .write_all(&chunk[..detach_index])
                        .await
                        .context("relay serial input write")?;
                }
                stream_write
                    .shutdown()
                    .await
                    .context("relay serial input shutdown")?;
                return Ok(SerialInputEnd::Detached);
            }

            stream_write
                .write_all(chunk)
                .await
                .context("relay serial input write")?;
        }
    };

    let output_task = async {
        tokio::io::copy(&mut stream_read, &mut output)
            .await
            .context("relay serial output")?;
        output.flush().await.context("flush serial output")?;
        Ok::<(), eyre::Report>(())
    };

    tokio::pin!(input_task);
    tokio::pin!(output_task);
    tokio::select! {
        result = &mut output_task => result,
        result = &mut input_task => match result? {
            SerialInputEnd::Detached => Ok(()),
            SerialInputEnd::Eof => output_task.await,
        },
    }
}

struct RawTerminalGuard {
    fd: std::os::fd::OwnedFd,
    original: libc::termios,
    enabled: bool,
}

impl RawTerminalGuard {
    fn new() -> eyre::Result<Self> {
        let stdin = std::io::stdin();
        let fd = stdin.as_fd().try_clone_to_owned().context("dup stdin fd")?;

        // nix's safe termios API is behind a feature this crate does not otherwise need.
        if unsafe { libc::isatty(fd.as_raw_fd()) } == 0 {
            return Ok(Self {
                fd,
                original: unsafe { std::mem::zeroed() },
                enabled: false,
            });
        }

        let mut original = unsafe { std::mem::zeroed::<libc::termios>() };
        if unsafe { libc::tcgetattr(fd.as_raw_fd(), &mut original) } != 0 {
            return Err(std::io::Error::last_os_error()).context("tcgetattr stdin");
        }

        let mut raw = original;
        raw.c_iflag &= !(libc::IGNBRK
            | libc::BRKINT
            | libc::PARMRK
            | libc::ISTRIP
            | libc::INLCR
            | libc::IGNCR
            | libc::ICRNL
            | libc::IXON);
        raw.c_oflag &= !libc::OPOST;
        raw.c_lflag &= !(libc::ECHO | libc::ECHONL | libc::ICANON | libc::ISIG | libc::IEXTEN);
        raw.c_cflag &= !(libc::CSIZE | libc::PARENB);
        raw.c_cflag |= libc::CS8;
        raw.c_cc[libc::VMIN] = 1;
        raw.c_cc[libc::VTIME] = 0;

        if unsafe { libc::tcsetattr(fd.as_raw_fd(), libc::TCSAFLUSH, &raw) } != 0 {
            return Err(std::io::Error::last_os_error()).context("tcsetattr stdin raw");
        }

        Ok(Self {
            fd,
            original,
            enabled: true,
        })
    }
}

impl Drop for RawTerminalGuard {
    fn drop(&mut self) {
        if self.enabled {
            let _ =
                unsafe { libc::tcsetattr(self.fd.as_raw_fd(), libc::TCSAFLUSH, &self.original) };
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::terminal::proxy_serial_io;

    #[tokio::test]
    async fn detach_returns_without_waiting_for_serial_output_to_close() {
        let (stream, mut peer) = tokio::io::duplex(1024);
        let (mut input_writer, input_reader) = tokio::io::duplex(64);
        input_writer
            .write_all(b"before\x1dafter")
            .await
            .expect("write terminal input");

        tokio::time::timeout(
            Duration::from_secs(1),
            proxy_serial_io(stream, input_reader, tokio::io::sink()),
        )
        .await
        .expect("detach should not wait for output EOF")
        .expect("detach should succeed");

        let mut forwarded = Vec::new();
        peer.read_to_end(&mut forwarded)
            .await
            .expect("read forwarded input");
        assert_eq!(forwarded, b"before");
    }

    #[tokio::test]
    async fn serial_output_eof_cancels_pending_terminal_input() {
        let (stream, peer) = tokio::io::duplex(64);
        let (_input_writer, input_reader) = tokio::io::duplex(64);
        drop(peer);

        tokio::time::timeout(
            Duration::from_secs(1),
            proxy_serial_io(stream, input_reader, tokio::io::sink()),
        )
        .await
        .expect("output EOF should cancel input relay")
        .expect("output EOF should succeed");
    }

    #[tokio::test]
    async fn terminal_eof_half_closes_input_and_drains_serial_output() {
        let (stream, mut peer) = tokio::io::duplex(1024);
        let peer_task = tokio::spawn(async move {
            let mut input = Vec::new();
            peer.read_to_end(&mut input)
                .await
                .expect("observe input half-close");
            peer.write_all(b"final output")
                .await
                .expect("write final output");
            peer.shutdown().await.expect("close serial output");
            input
        });
        let (output_writer, mut output_reader) = tokio::io::duplex(1024);

        proxy_serial_io(stream, tokio::io::empty(), output_writer)
            .await
            .expect("proxy serial stream");

        let mut output = Vec::new();
        output_reader
            .read_to_end(&mut output)
            .await
            .expect("read drained output");
        assert!(peer_task.await.expect("peer task joins").is_empty());
        assert_eq!(output, b"final output");
    }
}
