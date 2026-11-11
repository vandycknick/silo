use std::{
    collections::VecDeque,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    sync::Mutex,
};

use crate::lobby::ssh::notices::{Notice, Notices};

pub(crate) type Writer = Arc<Mutex<Box<dyn AsyncWrite + Send + Unpin>>>;

struct Input {
    reader: Box<dyn AsyncRead + Send + Unpin>,
    skip_lf: bool,
}

#[derive(Clone)]
pub(crate) struct SharedInput {
    input: Arc<parking_lot::Mutex<Input>>,
}

impl SharedInput {
    pub(crate) fn new(reader: impl AsyncRead + Send + Unpin + 'static) -> Self {
        Self {
            input: Arc::new(parking_lot::Mutex::new(Input {
                reader: Box::new(reader),
                skip_lf: false,
            })),
        }
    }

    fn after_cr(&mut self) {
        self.input.lock().skip_lf = true;
    }
}

impl AsyncRead for SharedInput {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buffer.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        // Never retain a lock across Pending: cancelling a guest stdin read must
        // leave the same transport immediately available to the next prompt.
        let mut input = self.input.lock();
        if input.skip_lf {
            let mut byte = [0];
            let mut one = ReadBuf::new(&mut byte);
            match Pin::new(&mut input.reader).poll_read(cx, &mut one) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {
                    input.skip_lf = false;
                    if one.filled().is_empty() {
                        return Poll::Ready(Ok(()));
                    }
                    if byte[0] != b'\n' {
                        buffer.put_slice(&byte);
                        return Poll::Ready(Ok(()));
                    }
                }
            }
        }
        Pin::new(&mut input.reader).poll_read(cx, buffer)
    }
}

#[derive(Debug)]
pub(crate) enum Line {
    Text(String),
    Cancelled,
    Eof,
}

pub(crate) struct Editor {
    input: SharedInput,
    output: Writer,
    history: VecDeque<String>,
    terminal: bool,
    notices: Option<(tokio::sync::mpsc::Receiver<Notice>, Arc<Notices>)>,
}

impl Editor {
    pub(crate) fn new(input: SharedInput, output: Writer, terminal: bool) -> Self {
        Self {
            input,
            output,
            history: VecDeque::new(),
            terminal,
            notices: None,
        }
    }

    pub(crate) fn notices(
        &mut self,
        receiver: tokio::sync::mpsc::Receiver<Notice>,
        state: Arc<Notices>,
    ) {
        self.notices = Some((receiver, state));
    }

    pub(crate) fn clear_notices(&mut self) {
        self.notices = None;
    }

    async fn write(&mut self, text: &str) -> io::Result<()> {
        let mut output = self.output.lock().await;
        output.write_all(text.as_bytes()).await?;
        output.flush().await
    }

    async fn redraw(&mut self, prompt: &str, line: &[char], cursor: usize) -> io::Result<()> {
        let text: String = line.iter().collect();
        let tail: String = line[cursor..].iter().collect();
        let width = console::measure_text_width(&tail);
        let mut text = format!("\r\x1b[2K{prompt}{text}");
        if width > 0 {
            text.push_str(&format!("\x1b[{width}D"));
        }
        self.write(&text).await
    }

    pub(crate) async fn read_line(
        &mut self,
        prompt: &str,
        limit: usize,
        remember: bool,
    ) -> io::Result<Line> {
        if self.terminal {
            self.write("\x1b[?2004h").await?;
        }
        let result = self.read(prompt, limit, remember).await;
        if self.terminal {
            self.write("\x1b[?2004l").await?;
        }
        result
    }

    async fn read(&mut self, prompt: &str, limit: usize, remember: bool) -> io::Result<Line> {
        self.write(prompt).await?;
        let mut line = Vec::<char>::new();
        let mut cursor = 0;
        let mut paste = false;
        let mut overflow = false;
        let mut history = self.history.len();
        let mut saved = Vec::new();
        loop {
            let next = tokio::select! {
                byte = self.input.read_u8() => byte,
                notice = async {
                    match self.notices.as_mut() {
                        Some((receiver, _)) => receiver.recv().await,
                        None => std::future::pending().await,
                    }
                } => {
                    if let Some(notice) = notice {
                        if let Some((_, state)) = self.notices.as_ref() {
                            let state = state.clone();
                            if state.was_shown(&notice.id, &notice.url) { continue; }
                            let text = format!("\r\x1b[2KTailscale login required for {}\r\n  {}\r\nUse: show {}\r\n", notice.name, notice.url, notice.name);
                            self.write(&text).await?;
                            self.redraw(prompt, &line, cursor).await?;
                            state.shown(&notice.id, &notice.url);
                        }
                    } else {
                        self.notices = None;
                    }
                    continue;
                }
            };
            let byte = match next {
                Ok(byte) => byte,
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(Line::Eof),
                Err(error) => return Err(error),
            };
            if byte == 27 && self.terminal {
                let mut sequence = Vec::with_capacity(8);
                for _ in 0..64 {
                    let byte = self.input.read_u8().await?;
                    sequence.push(byte);
                    if sequence.len() == 1 && byte != b'[' && byte != b'O' {
                        break;
                    }
                    if sequence.len() > 1 && (0x40..=0x7e).contains(&byte) {
                        break;
                    }
                }
                match sequence.as_slice() {
                    b"[200~" => paste = true,
                    b"[201~" => paste = false,
                    b"[D" | b"OD" if !paste => cursor = cursor.saturating_sub(1),
                    b"[C" | b"OC" if !paste => cursor = (cursor + 1).min(line.len()),
                    b"[H" | b"OH" if !paste => cursor = 0,
                    b"[F" | b"OF" if !paste => cursor = line.len(),
                    b"[3~" if !paste && cursor < line.len() => {
                        line.remove(cursor);
                    }
                    b"[A" | b"OA" if !paste && history > 0 => {
                        if history == self.history.len() {
                            saved = line.clone();
                        }
                        history -= 1;
                        line = self.history[history].chars().collect();
                        cursor = line.len();
                    }
                    b"[B" | b"OB" if !paste && history < self.history.len() => {
                        history += 1;
                        line = if history == self.history.len() {
                            saved.clone()
                        } else {
                            self.history[history].chars().collect()
                        };
                        cursor = line.len();
                    }
                    _ => {}
                }
                self.redraw(prompt, &line, cursor).await?;
                continue;
            }
            if !paste {
                match byte {
                    b'\r' | b'\n' => {
                        if byte == b'\r' {
                            self.input.after_cr();
                        }
                        if self.terminal {
                            self.write("\r\n").await?;
                        }
                        if overflow {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidInput,
                                "input line too long",
                            ));
                        }
                        let text: String = line.iter().collect();
                        if remember && !text.trim().is_empty() && self.history.back() != Some(&text)
                        {
                            if self.history.len() == 100 {
                                self.history.pop_front();
                            }
                            self.history.push_back(text.clone());
                        }
                        return Ok(Line::Text(text));
                    }
                    3 => {
                        if self.terminal {
                            self.write("^C\r\n").await?;
                        }
                        return Ok(Line::Cancelled);
                    }
                    4 if line.is_empty() => return Ok(Line::Eof),
                    4 if !self.terminal => return Ok(Line::Cancelled),
                    4 if cursor < line.len() => {
                        line.remove(cursor);
                    }
                    8 | 127 if self.terminal && cursor > 0 => {
                        cursor -= 1;
                        line.remove(cursor);
                    }
                    1 if self.terminal => cursor = 0,
                    5 if self.terminal => cursor = line.len(),
                    21 if self.terminal => {
                        line.drain(..cursor);
                        cursor = 0;
                    }
                    11 if self.terminal => {
                        line.truncate(cursor);
                    }
                    _ => {
                        self.insert(byte, &mut line, &mut cursor, limit, &mut overflow)
                            .await?;
                    }
                }
            } else if matches!(byte, b'\r' | b'\n' | b'\t') {
                self.insert(b' ', &mut line, &mut cursor, limit, &mut overflow)
                    .await?;
            } else {
                self.insert(byte, &mut line, &mut cursor, limit, &mut overflow)
                    .await?;
            }
            if self.terminal {
                self.redraw(prompt, &line, cursor).await?;
            }
        }
    }

    async fn insert(
        &mut self,
        byte: u8,
        line: &mut Vec<char>,
        cursor: &mut usize,
        limit: usize,
        overflow: &mut bool,
    ) -> io::Result<()> {
        if byte < 32 || byte == 127 {
            return Ok(());
        }
        let mut bytes = [0; 4];
        bytes[0] = byte;
        let length = match byte {
            0..=127 => 1,
            0xc2..=0xdf => 2,
            0xe0..=0xef => 3,
            0xf0..=0xf4 => 4,
            _ => return Err(io::ErrorKind::InvalidData.into()),
        };
        self.input.read_exact(&mut bytes[1..length]).await?;
        let character = std::str::from_utf8(&bytes[..length])
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?
            .chars()
            .next()
            .ok_or(io::ErrorKind::InvalidData)?;
        if character.is_control() {
            return Ok(());
        }
        if line.iter().map(|ch| ch.len_utf8()).sum::<usize>() + length > limit {
            *overflow = true;
            return Ok(());
        }
        line.insert(*cursor, character);
        *cursor += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::lobby::ssh::input::{Editor, Line, SharedInput};
    use std::sync::Arc;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        sync::Mutex,
    };

    #[tokio::test]
    async fn unicode_editing_history_paste_and_crlf() {
        let input = SharedInput::new(
            &b"a\xc3\xa9\x1b[D\x7fz\r\n\x1b[A\r\x1b[200~hello\nworld\x03\x1b[201~\r\x03\x04"[..],
        );
        let mut editor = Editor::new(
            input,
            Arc::new(Mutex::new(Box::new(tokio::io::sink()))),
            true,
        );
        for expected in ["zé", "zé", "hello world"] {
            assert!(
                matches!(editor.read_line("silo> ", 100, true).await.unwrap(), Line::Text(line) if line == expected)
            );
        }
        assert!(matches!(
            editor.read_line("silo> ", 100, true).await.unwrap(),
            Line::Cancelled
        ));
        assert!(matches!(
            editor.read_line("silo> ", 100, true).await.unwrap(),
            Line::Eof
        ));
    }

    #[tokio::test]
    async fn cr_returns_without_lf_and_shared_guest_reader_skips_it_once() {
        let (mut client, server) = tokio::io::duplex(64);
        let input = SharedInput::new(server);
        let mut editor = Editor::new(
            input.clone(),
            Arc::new(Mutex::new(Box::new(tokio::io::sink()))),
            false,
        );
        client.write_all(b"yes\r").await.unwrap();
        assert!(
            matches!(tokio::time::timeout(std::time::Duration::from_secs(1), editor.read_line("", 100, false)).await.unwrap().unwrap(), Line::Text(line) if line == "yes")
        );
        client.write_all(b"\nbody").await.unwrap();
        let mut guest = input;
        let mut body = [0; 4];
        guest.read_exact(&mut body).await.unwrap();
        assert_eq!(&body, b"body");
    }

    #[tokio::test]
    async fn cancelled_guest_read_releases_transport_for_the_prompt() {
        let (mut client, server) = tokio::io::duplex(64);
        let input = SharedInput::new(server);
        let mut guest = input.clone();
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(10), guest.read_u8())
                .await
                .is_err()
        );
        client.write_all(b"next\r").await.unwrap();
        let mut editor = Editor::new(
            input,
            Arc::new(Mutex::new(Box::new(tokio::io::sink()))),
            true,
        );
        assert!(
            matches!(tokio::time::timeout(std::time::Duration::from_secs(1), editor.read_line("", 100, false)).await.unwrap().unwrap(), Line::Text(line) if line == "next")
        );
    }

    #[tokio::test]
    async fn paste_requires_enter_and_overflow_cannot_be_shortened_into_a_command() {
        let (mut client, server) = tokio::io::duplex(128);
        let mut editor = Editor::new(
            SharedInput::new(server),
            Arc::new(Mutex::new(Box::new(tokio::io::sink()))),
            true,
        );
        client
            .write_all(b"\x1b[200~one\ntwo\x1b[201~")
            .await
            .unwrap();
        {
            let line = editor.read_line("", 100, false);
            tokio::pin!(line);
            assert!(
                tokio::time::timeout(std::time::Duration::from_millis(10), &mut line)
                    .await
                    .is_err()
            );
            client.write_all(b"\r").await.unwrap();
            assert!(matches!(line.await.unwrap(), Line::Text(line) if line == "one two"));
        }
        client.write_all(b"12345\x7f\x7f\r").await.unwrap();
        assert_eq!(
            editor.read_line("", 4, false).await.unwrap_err().kind(),
            std::io::ErrorKind::InvalidInput
        );
    }
}
