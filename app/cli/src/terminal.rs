use std::os::fd::{AsFd, AsRawFd};

use eyre::Context;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

pub(crate) async fn attach_serial_stream(stream: UnixStream) -> eyre::Result<()> {
    print_serial_exit_hint();
    proxy_serial_stdio(stream).await
}

fn print_serial_exit_hint() {
    if unsafe { libc::isatty(std::io::stderr().as_raw_fd()) } == 0 {
        return;
    }

    eprintln!("Connected to serial console. Exit with Ctrl+]");
}

async fn proxy_serial_stdio(stream: UnixStream) -> eyre::Result<()> {
    let _raw_terminal = RawTerminalGuard::new()?;

    let (mut stream_read, mut stream_write) = stream.into_split();

    let input = async {
        let mut stdin = tokio::io::stdin();
        let mut buf = [0u8; 1024];

        loop {
            let n = stdin
                .read(&mut buf)
                .await
                .context("relay serial input read")?;
            if n == 0 {
                break;
            }

            let chunk = &buf[..n];
            if chunk.contains(&0x1d) {
                let filtered: Vec<u8> = chunk.iter().copied().filter(|b| *b != 0x1d).collect();
                if !filtered.is_empty() {
                    stream_write
                        .write_all(&filtered)
                        .await
                        .context("relay serial input write")?;
                }
                stream_write
                    .shutdown()
                    .await
                    .context("relay serial input shutdown")?;
                break;
            }

            stream_write
                .write_all(chunk)
                .await
                .context("relay serial input write")?;
        }

        Ok::<(), eyre::Report>(())
    };

    let output = async {
        let mut stdout = tokio::io::stdout();
        tokio::io::copy(&mut stream_read, &mut stdout)
            .await
            .context("relay serial output")?;
        stdout.flush().await.context("flush serial output")?;
        Ok::<(), eyre::Report>(())
    };

    tokio::try_join!(output, input)?;
    Ok(())
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
