use parking_lot::Mutex;
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Duration,
};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::lobby::{caller::Caller, ssh::server::Dispatcher};

pub(crate) struct Notice {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) url: String,
}

#[derive(Default)]
pub(crate) struct Notices(Mutex<HashMap<String, String>>);

impl Notices {
    pub(crate) fn shown(&self, id: &str, url: &str) {
        self.0.lock().insert(id.to_owned(), url.to_owned());
    }

    pub(crate) fn was_shown(&self, id: &str, url: &str) -> bool {
        self.0.lock().get(id).is_some_and(|seen| seen == url)
    }

    fn update(&self, notices: Vec<Notice>) -> Vec<Notice> {
        let mut seen = self.0.lock();
        let present: HashSet<_> = notices.iter().map(|notice| notice.id.as_str()).collect();
        seen.retain(|id, _| present.contains(id.as_str()));
        let mut messages = Vec::new();
        for notice in notices {
            if notice.url.is_empty() {
                seen.remove(&notice.id);
                continue;
            }
            if seen.get(&notice.id) == Some(&notice.url) {
                continue;
            }
            messages.push(notice);
        }
        messages
    }

    pub(crate) async fn poll(
        self: Arc<Self>,
        dispatcher: Arc<dyn Dispatcher>,
        caller: Caller,
        output: mpsc::Sender<Notice>,
        cancel: CancellationToken,
    ) {
        let mut interval = tokio::time::interval(Duration::from_secs(2));
        interval.tick().await;
        loop {
            tokio::select! { _ = cancel.cancelled() => return, _ = interval.tick() => {} }
            let fetch = async {
                let peer = caller.fresh().await?;
                dispatcher.notices(&peer).await
            };
            let notices = tokio::select! {
                _ = cancel.cancelled() => return,
                result = tokio::time::timeout(Duration::from_secs(5), fetch) => match result {
                    Ok(Ok(notices)) => notices,
                    _ => continue,
                }
            };
            for message in self.update(notices) {
                tokio::select! { _ = cancel.cancelled() => return, result = output.send(message) => if result.is_err() { return; } }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::lobby::ssh::notices::{Notice, Notices};

    #[test]
    fn notices_deduplicate_and_reappear_after_removal() {
        let state = Notices::default();
        let notice = || {
            vec![Notice {
                id: "id".into(),
                name: "vm".into(),
                url: "https://login".into(),
            }]
        };
        assert_eq!(state.update(notice()).len(), 1);
        state.shown("id", "https://login");
        assert!(state.update(notice()).is_empty());
        state.update(Vec::new());
        assert_eq!(state.update(notice()).len(), 1);
        state.shown("id", "new");
        assert!(state
            .update(vec![Notice {
                id: "id".into(),
                name: "vm".into(),
                url: "new".into()
            }])
            .is_empty());
    }
}
