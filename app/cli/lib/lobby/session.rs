#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Window {
    pub(crate) rows: u16,
    pub(crate) columns: u16,
}

impl Default for Window {
    fn default() -> Self {
        Self {
            rows: 24,
            columns: 80,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Signal {
    Int,
    Term,
    Hup,
    Quit,
    Kill,
    Usr1,
    Usr2,
}

pub(crate) struct Terminal {
    pub(crate) term: String,
    pub(crate) window: tokio::sync::watch::Receiver<Window>,
}

pub(crate) struct SessionIo {
    pub(crate) stdin: Box<dyn tokio::io::AsyncRead + Send + Unpin>,
    pub(crate) stdout: Box<dyn tokio::io::AsyncWrite + Send + Unpin>,
    pub(crate) stderr: Box<dyn tokio::io::AsyncWrite + Send + Unpin>,
    pub(crate) terminal: Option<Terminal>,
    pub(crate) signals: tokio::sync::mpsc::Receiver<Signal>,
    pub(crate) cancel: tokio_util::sync::CancellationToken,
}

pub(crate) type Prompt = std::sync::Arc<
    dyn Fn(
            String,
            usize,
        ) -> futures::future::BoxFuture<'static, crate::lobby::failure::Outcome<String>>
        + Send
        + Sync,
>;
pub(crate) type ApprovalShown = std::sync::Arc<dyn Fn(&str, &str) + Send + Sync>;

pub(crate) struct SessionExtras {
    pub(crate) prompt: Option<Prompt>,
    pub(crate) approval_shown: Option<ApprovalShown>,
}

#[cfg(test)]
mod tests {
    use crate::lobby::session::Window;

    #[test]
    fn default_window_is_twenty_four_by_eighty() {
        assert_eq!(
            Window::default(),
            Window {
                rows: 24,
                columns: 80
            }
        );
    }
}
