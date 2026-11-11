use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::AsyncWrite;

/// Only daemon-owned terminal text is translated; guest stdout stays untouched.
pub(crate) struct HumanWriter<W> {
    inner: W,
    bytes: [u8; 8192],
    length: usize,
    offset: usize,
    consumed: usize,
    cr: bool,
}

impl<W> HumanWriter<W> {
    pub(crate) fn new(inner: W) -> Self {
        Self {
            inner,
            bytes: [0; 8192],
            length: 0,
            offset: 0,
            consumed: 0,
            cr: false,
        }
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for HumanWriter<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.length == 0 {
            this.consumed = input.len().min(4096);
            for &byte in &input[..this.consumed] {
                if byte == b'\n' && !this.cr {
                    this.bytes[this.length] = b'\r';
                    this.length += 1;
                }
                this.bytes[this.length] = byte;
                this.length += 1;
                this.cr = byte == b'\r';
            }
        }
        while this.offset < this.length {
            match Pin::new(&mut this.inner).poll_write(cx, &this.bytes[this.offset..this.length]) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(0)) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                Poll::Ready(Ok(n)) => this.offset += n,
            }
        }
        this.length = 0;
        this.offset = 0;
        Poll::Ready(Ok(this.consumed))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use crate::lobby::ssh::output::HumanWriter;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn translates_bare_newlines_across_writes() {
        let mut output = HumanWriter::new(Vec::new());
        output.write_all(b"a\nb\r").await.unwrap();
        output.write_all(b"\nc\n").await.unwrap();
        assert_eq!(output.inner, b"a\r\nb\r\nc\r\n");
    }
}
