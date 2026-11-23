use std::{sync::Arc, time::Duration};

use futures::future::BoxFuture;

use crate::lobby::failure::{Code, Failure, Outcome};
use crate::lobby::identity::Peer;

pub(crate) type Resolve = Arc<dyn Fn() -> BoxFuture<'static, Outcome<Peer>> + Send + Sync>;

#[derive(Clone)]
pub(crate) struct Caller {
    pub(crate) peer: Peer,
    resolve: Resolve,
}

impl Caller {
    pub(crate) fn new(peer: Peer, resolve: Resolve) -> Self {
        Self { peer, resolve }
    }

    pub(crate) async fn fresh(&self) -> Outcome<Peer> {
        let peer = tokio::time::timeout(Duration::from_secs(15), (self.resolve)())
            .await
            .map_err(|_| Failure::new(Code::Forbidden, "identity unavailable or changed"))?
            .map_err(|_| Failure::new(Code::Forbidden, "identity unavailable or changed"))?;
        if !peer.valid() || peer.node_id != self.peer.node_id {
            return Err(Failure::new(
                Code::Forbidden,
                "identity unavailable or changed",
            ));
        }
        Ok(peer)
    }
}

#[cfg(test)]
mod tests {
    use crate::lobby::caller::Caller;
    use crate::lobby::failure::{Code, Failure};
    use crate::lobby::identity::{Peer, Principal};
    use std::sync::Arc;

    fn peer() -> Peer {
        Peer {
            principals: vec![Principal::parse("user:1").unwrap()],
            node_id: "node".into(),
            observed_at: chrono::Utc::now(),
            ..Peer::default()
        }
    }

    #[tokio::test]
    async fn refresh_accepts_valid_identity_and_denies_failures_or_changes() {
        let original = peer();
        let fresh = original.clone();
        let caller = Caller::new(
            original.clone(),
            Arc::new(move || {
                let fresh = fresh.clone();
                Box::pin(async move { Ok(fresh) })
            }),
        );
        assert_eq!(caller.fresh().await.unwrap(), original);
        for replacement in [
            Peer::default(),
            Peer {
                node_id: "changed".into(),
                ..peer()
            },
        ] {
            let caller = Caller::new(
                original.clone(),
                Arc::new(move || {
                    let replacement = replacement.clone();
                    Box::pin(async move { Ok(replacement) })
                }),
            );
            assert_eq!(caller.fresh().await.unwrap_err().code, Code::Forbidden);
        }
        let caller = Caller::new(
            original,
            Arc::new(|| {
                Box::pin(async { Err(Failure::new(Code::Unavailable, "private resolver error")) })
            }),
        );
        assert_eq!(
            caller.fresh().await.unwrap_err().message,
            "identity unavailable or changed"
        );
    }

    #[tokio::test]
    async fn refresh_has_a_fifteen_second_bound() {
        let caller = Caller::new(peer(), Arc::new(|| Box::pin(std::future::pending())));
        let start = tokio::time::Instant::now();
        assert_eq!(caller.fresh().await.unwrap_err().code, Code::Forbidden);
        assert!(start.elapsed() >= std::time::Duration::from_secs(15));
        assert!(start.elapsed() < std::time::Duration::from_secs(20));
    }
}
