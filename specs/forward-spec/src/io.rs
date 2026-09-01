use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt};

/// Read exactly one newline-terminated line without consuming following bytes.
pub async fn read_line<R>(reader: &mut R, limit: usize) -> Result<Vec<u8>, ReadLineError>
where
    R: AsyncRead + Unpin,
{
    let mut line = Vec::new();
    loop {
        if line.len() == limit {
            return Err(ReadLineError::TooLong { limit });
        }
        let mut byte = [0_u8; 1];
        match reader.read(&mut byte).await? {
            0 => return Err(ReadLineError::UnexpectedEof),
            _ => {
                line.push(byte[0]);
                if byte[0] == b'\n' {
                    return Ok(line);
                }
            }
        }
    }
}

#[derive(Debug, Error)]
pub enum ReadLineError {
    #[error("I/O error while reading line: {0}")]
    Io(#[from] std::io::Error),
    #[error("EOF before line terminator")]
    UnexpectedEof,
    #[error("line exceeds inclusive limit of {limit} bytes")]
    TooLong { limit: usize },
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncReadExt;

    use crate::io::{read_line, ReadLineError};

    #[tokio::test]
    async fn reads_through_newline_without_overreading() {
        let mut input = b"OK\npayload".as_slice();
        assert_eq!(read_line(&mut input, 3).await.unwrap(), b"OK\n");
        let mut payload = Vec::new();
        input.read_to_end(&mut payload).await.unwrap();
        assert_eq!(payload, b"payload");
    }

    #[tokio::test]
    async fn enforces_inclusive_limit() {
        let mut exact = b"abc\n".as_slice();
        assert_eq!(read_line(&mut exact, 4).await.unwrap(), b"abc\n");

        let mut long = b"abcd\n".as_slice();
        assert!(matches!(
            read_line(&mut long, 4).await,
            Err(ReadLineError::TooLong { limit: 4 })
        ));
        assert_eq!(long, b"\n");
    }

    #[tokio::test]
    async fn reports_eof_before_newline() {
        let mut input = b"unfinished".as_slice();
        assert!(matches!(
            read_line(&mut input, 32).await,
            Err(ReadLineError::UnexpectedEof)
        ));
    }
}
