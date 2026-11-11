//! OAuth app consent precedes VM creation. State belongs to one creation attempt
//! and principal, expires after 15 minutes, and is consumed before code exchange.
//! Dropping acquire removes its state and cancels any in-flight exchange.

use std::{collections::HashMap, sync::Arc, time::Duration};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use futures::future::BoxFuture;
use parking_lot::Mutex;
use tokio::{sync::oneshot, time::Instant};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use crate::config::tailscale::EnrollmentMode;
use crate::lobby::{
    failure::{Code, Failure, Outcome},
    identity::Principal,
    jobs::Progress,
    metrics::Metrics,
    service::enrollment::ConsentProvider,
};

const CONSENT_FAILURE: &str = "consent denied, expired or interrupted; no VM was created";
const TOKEN_LIMIT: usize = 65536;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    User,
    Interactive,
    Tag,
    None,
}

struct Entry {
    attempt: String,
    owner: Principal,
    expires: Instant,
    cancel: CancellationToken,
    result: oneshot::Sender<Approval>,
}

struct Approval {
    attempt: String,
    owner: Principal,
    result: Outcome<Vec<u8>>,
}

pub(crate) struct Registry {
    entries: Mutex<HashMap<String, Entry>>,
    lifetime: Duration,
}

impl Default for Registry {
    fn default() -> Self {
        Self::with_lifetime(Duration::from_secs(15 * 60))
    }
}

impl Registry {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    fn with_lifetime(lifetime: Duration) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            lifetime,
        }
    }

    fn begin(
        self: &Arc<Self>,
        attempt: &str,
        owner: &Principal,
        oauth: &OAuth,
    ) -> Outcome<Pending> {
        if attempt.is_empty() {
            return Err(Failure::new(Code::Unavailable, "consent unavailable"));
        }
        let mut entropy = [0u8; 32];
        entropy[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
        entropy[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
        let nonce = URL_SAFE_NO_PAD.encode(entropy);
        let mut url = reqwest::Url::parse("https://login.tailscale.com/a/oauth_authorize")
            .map_err(|_| Failure::new(Code::Unavailable, "consent unavailable"))?;
        url.query_pairs_mut().extend_pairs([
            ("client_id", oauth.client_id.as_str()),
            ("redirect_uri", oauth.redirect.as_str()),
            ("scope", "auth_keys:create:once"),
            ("response_type", "code"),
            ("state", nonce.as_str()),
        ]);
        let expires = Instant::now() + self.lifetime;
        let cancel = CancellationToken::new();
        let (tx, rx) = oneshot::channel();
        let mut entries = self.entries.lock();
        entries.retain(|_, entry| Instant::now() < entry.expires && !entry.cancel.is_cancelled());
        entries.insert(
            nonce.clone(),
            Entry {
                attempt: attempt.to_owned(),
                owner: owner.clone(),
                expires,
                cancel: cancel.clone(),
                result: tx,
            },
        );
        Ok(Pending {
            registry: self.clone(),
            attempt: attempt.to_owned(),
            owner: owner.clone(),
            nonce,
            url: url.into(),
            expires,
            cancel,
            result: rx,
        })
    }

    fn cancel(&self, nonce: &str, attempt: &str, owner: &Principal) -> bool {
        let mut entries = self.entries.lock();
        if !entries
            .get(nonce)
            .is_some_and(|entry| entry.attempt == attempt && entry.owner == *owner)
        {
            return false;
        }
        if let Some(entry) = entries.remove(nonce) {
            entry.cancel.cancel();
        }
        true
    }

    /// Removal is atomic and precedes exchange, including exchanges that fail.
    fn consume(&self, nonce: &str) -> Option<Entry> {
        let entry = self.entries.lock().remove(nonce)?;
        if Instant::now() >= entry.expires || entry.cancel.is_cancelled() {
            return None;
        }
        Some(entry)
    }
}

struct Pending {
    registry: Arc<Registry>,
    attempt: String,
    owner: Principal,
    nonce: String,
    url: String,
    expires: Instant,
    cancel: CancellationToken,
    result: oneshot::Receiver<Approval>,
}

impl Pending {
    async fn wait(&mut self, attempt: &str, owner: &Principal) -> Outcome<Vec<u8>> {
        if self.attempt != attempt || self.owner != *owner {
            return Err(consent_failure(Code::PendingApproval));
        }
        tokio::select! {
            biased;
            _ = tokio::time::sleep_until(self.expires) => Err(consent_failure(Code::Expired)),
            approval = &mut self.result => {
                let approval = approval.map_err(|_| consent_failure(Code::PendingApproval))?;
                if approval.attempt != attempt || approval.owner != *owner {
                    return Err(consent_failure(Code::PendingApproval));
                }
                approval.result
            }
        }
    }
}

impl Drop for Pending {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.registry
            .cancel(&self.nonce, &self.attempt, &self.owner);
    }
}

pub(crate) struct Callback {
    pub(crate) status: hyper::StatusCode,
    pub(crate) body: &'static str,
}

pub(crate) struct OAuth {
    registry: Arc<Registry>,
    client_id: String,
    secret: Zeroizing<String>,
    redirect: String,
    endpoint: reqwest::Url,
    client: reqwest::Client,
}

impl OAuth {
    /// The optional base changes only the token endpoint, never the consent URL.
    pub(crate) fn new(
        registry: Arc<Registry>,
        secret: Zeroizing<String>,
        redirect: String,
        base: Option<&str>,
    ) -> Outcome<Self> {
        let invalid = || Failure::new(Code::Unavailable, "invalid OAuth app configuration");
        let (client_id, rest) = secret
            .strip_prefix("tskey-app-")
            .and_then(|s| s.split_once('-'))
            .ok_or_else(invalid)?;
        if client_id.is_empty()
            || rest.is_empty()
            || secret
                .chars()
                .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '?' | '#'))
        {
            return Err(invalid());
        }
        let redirect_url = reqwest::Url::parse(&redirect).map_err(|_| invalid())?;
        if redirect_url.scheme() != "https"
            || redirect_url.host_str().is_none()
            || redirect_url.fragment().is_some()
            || !redirect_url.username().is_empty()
            || redirect_url.password().is_some()
        {
            return Err(invalid());
        }
        let mut endpoint = reqwest::Url::parse(base.unwrap_or("https://api.tailscale.com"))
            .map_err(|_| invalid())?;
        if !matches!(endpoint.scheme(), "https" | "http")
            || endpoint.host_str().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
        {
            return Err(invalid());
        }
        endpoint.set_path("/api/v2/oauth/token");
        endpoint.set_query(None);
        endpoint.set_fragment(None);
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|_| invalid())?;
        Ok(Self {
            registry,
            client_id: client_id.to_owned(),
            secret,
            redirect,
            endpoint,
            client,
        })
    }

    /// TLS has already been terminated by tsgate. Only one-use state authenticates this route.
    pub(crate) async fn callback(&self, query: &str, has_body: bool) -> Callback {
        use hyper::StatusCode;
        let bad = |body| Callback {
            status: StatusCode::BAD_REQUEST,
            body,
        };
        if has_body || query.len() > 16384 || !valid_query(query) {
            return bad("invalid callback\n");
        }
        let Ok(url) = reqwest::Url::parse(&format!("https://callback.invalid/?{query}")) else {
            return bad("invalid callback\n");
        };
        let mut state = None;
        let mut code = None;
        let mut error = None;
        for (key, value) in url.query_pairs() {
            let slot = match key.as_ref() {
                "state" => &mut state,
                "code" => &mut code,
                "error" => &mut error,
                _ => continue,
            };
            if slot.replace(value.into_owned()).is_some() {
                return bad("invalid callback\n");
            }
        }
        let Some(entry) = state
            .as_deref()
            .and_then(|nonce| self.registry.consume(nonce))
        else {
            return bad("expired or invalid state\n");
        };
        let result = if error.as_deref().is_some_and(|e| !e.is_empty())
            || code.as_deref().is_none_or(str::is_empty)
        {
            Err(consent_failure(Code::PendingApproval))
        } else {
            tokio::select! {
                biased;
                _ = entry.cancel.cancelled() => Err(consent_failure(Code::PendingApproval)),
                _ = tokio::time::sleep_until(entry.expires) => Err(consent_failure(Code::Expired)),
                result = self.exchange(code.as_deref().unwrap_or_default()) => result,
            }
        };
        let ok = result.is_ok();
        if entry
            .result
            .send(Approval {
                attempt: entry.attempt,
                owner: entry.owner,
                result,
            })
            .is_err()
            || !ok
        {
            return bad("approval failed; return to your terminal\n");
        }
        Callback {
            status: StatusCode::OK,
            body: "Approved. Return to your terminal.\n",
        }
    }

    async fn exchange(&self, code: &str) -> Outcome<Vec<u8>> {
        let failed = || consent_failure(Code::PendingApproval);
        let mut response = self
            .client
            .post(self.endpoint.clone())
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("client_id", self.client_id.as_str()),
                ("client_secret", self.secret.as_str()),
                ("redirect_uri", self.redirect.as_str()),
            ])
            .send()
            .await
            .map_err(|_| failed())?;
        if response.status() != reqwest::StatusCode::OK
            || response
                .content_length()
                .is_some_and(|n| n > TOKEN_LIMIT as u64)
        {
            return Err(failed());
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| failed())? {
            if chunk.len() > TOKEN_LIMIT - bytes.len() {
                return Err(failed());
            }
            bytes.extend_from_slice(&chunk);
        }
        #[derive(serde::Deserialize)]
        struct Token {
            access_token: String,
        }
        let token: Token = serde_json::from_slice(&bytes).map_err(|_| failed())?;
        if !valid_token(&token.access_token) {
            return Err(failed());
        }
        Ok(token.access_token.into_bytes())
    }
}

fn valid_query(query: &str) -> bool {
    let bytes = query.as_bytes();
    let mut position = 0;
    while let Some(byte) = bytes.get(position) {
        if *byte == b'%' {
            if !bytes.get(position + 1).is_some_and(u8::is_ascii_hexdigit)
                || !bytes.get(position + 2).is_some_and(u8::is_ascii_hexdigit)
            {
                return false;
            }
            position += 3;
        } else if *byte == b';' {
            return false;
        } else {
            position += 1;
        }
    }
    true
}

fn valid_token(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= 16384
        && !token.starts_with("tskey-client-")
        && !token.contains("://")
        && !token
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '?' | '#'))
}

fn consent_failure(code: Code) -> Failure {
    Failure::new(code, CONSENT_FAILURE)
}

pub(crate) struct Manager {
    pub(crate) enrollment: EnrollmentMode,
    pub(crate) oauth: Option<Arc<OAuth>>,
    pub(crate) metrics: Arc<Metrics>,
}

impl Manager {
    pub(crate) fn mode(&self, owner: &Principal) -> Mode {
        match self.enrollment {
            EnrollmentMode::None => Mode::None,
            _ if owner.is_tag() => Mode::Tag,
            EnrollmentMode::OauthApp if self.oauth.is_some() => Mode::User,
            _ => Mode::Interactive,
        }
    }
}

struct EnrollmentLatency<'a> {
    metrics: &'a Metrics,
    started: Instant,
    ok: bool,
}

impl Drop for EnrollmentLatency<'_> {
    fn drop(&mut self) {
        self.metrics
            .latency("enrollment", self.started.elapsed(), self.ok);
    }
}

impl ConsentProvider for Manager {
    fn acquire<'a>(
        &'a self,
        attempt: &'a str,
        owner: &'a Principal,
        progress: Progress,
    ) -> BoxFuture<'a, Outcome<Option<Vec<u8>>>> {
        Box::pin(async move {
            if self.mode(owner) != Mode::User {
                return Ok(None);
            }
            let mut latency = EnrollmentLatency {
                metrics: &self.metrics,
                started: Instant::now(),
                ok: false,
            };
            let result = async {
                let oauth = self.oauth.as_ref().ok_or_else(|| {
                    Failure::new(Code::Unavailable, "configured OAuth app unavailable")
                })?;
                let mut pending = oauth.registry.begin(attempt, owner, oauth)?;
                progress(format!("approve: {}", pending.url));
                pending.wait(attempt, owner).await.map(Some)
            }
            .await;
            latency.ok = result.is_ok();
            result
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::config::tailscale::EnrollmentMode;
    use crate::lobby::{
        consent::{valid_token, Manager, Mode, OAuth, Registry},
        failure::Code,
        identity::Principal,
        metrics::Metrics,
        service::enrollment::ConsentProvider,
    };
    use std::{
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
        time::Duration,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const SECRET: &str = "tskey-app-client-fixture-secret";
    const TOKEN: &str = "opaque-fixture-provisioning-token";

    struct Upstream {
        base: String,
        calls: Arc<AtomicUsize>,
        task: tokio::task::JoinHandle<()>,
    }

    impl Drop for Upstream {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    async fn upstream(status: u16, body: String, extra: &'static str) -> Upstream {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let calls = Arc::new(AtomicUsize::new(0));
        let count = calls.clone();
        let task = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                count.fetch_add(1, Ordering::SeqCst);
                let mut bytes = Vec::new();
                let mut buffer = [0u8; 4096];
                loop {
                    let read = stream.read(&mut buffer).await.unwrap();
                    if read == 0 {
                        break;
                    }
                    bytes.extend_from_slice(&buffer[..read]);
                    let request = String::from_utf8_lossy(&bytes);
                    if let Some((head, body)) = request.split_once("\r\n\r\n") {
                        let length: usize = head
                            .lines()
                            .find_map(|line| {
                                line.to_ascii_lowercase()
                                    .strip_prefix("content-length:")
                                    .map(|s| s.trim().parse().unwrap())
                            })
                            .unwrap_or(0);
                        if body.len() >= length {
                            break;
                        }
                    }
                }
                let request = String::from_utf8(bytes).unwrap();
                assert!(request.starts_with("POST /api/v2/oauth/token HTTP/1.1\r\n"));
                for field in [
                    "grant_type=authorization_code",
                    "code=fresh-code",
                    "client_id=client",
                    "client_secret=tskey-app-client-fixture-secret",
                    "redirect_uri=https%3A%2F%2Flobby.tail.test%2Foauth%2Fcallback",
                ] {
                    assert!(request.contains(field), "missing exchange field");
                }
                let response = format!("HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nConnection: close\r\n{extra}\r\n{body}", body.len());
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        });
        Upstream { base, calls, task }
    }

    fn oauth(registry: Arc<Registry>, base: Option<&str>) -> Arc<OAuth> {
        Arc::new(
            OAuth::new(
                registry,
                SECRET.to_owned().into(),
                "https://lobby.tail.test/oauth/callback".into(),
                base,
            )
            .unwrap(),
        )
    }
    #[test]
    fn oauth_retains_the_zeroizing_secret_allocation() {
        let secret = zeroize::Zeroizing::new(SECRET.to_owned());
        let allocation = secret.as_ptr();
        let oauth = OAuth::new(
            Arc::new(Registry::new()),
            secret,
            "https://lobby.tail.test/oauth/callback".into(),
            None,
        )
        .unwrap();
        let stored: &zeroize::Zeroizing<String> = &oauth.secret;
        assert_eq!(stored.as_ptr(), allocation);
        assert_eq!(stored.as_str(), SECRET);
    }

    fn manager(oauth: Arc<OAuth>) -> Arc<Manager> {
        Arc::new(Manager {
            enrollment: EnrollmentMode::OauthApp,
            oauth: Some(oauth),
            metrics: Arc::new(Metrics::new()),
        })
    }

    async fn acquire(
        manager: Arc<Manager>,
    ) -> (
        String,
        tokio::task::JoinHandle<crate::lobby::failure::Outcome<Option<Vec<u8>>>>,
    ) {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let job = tokio::spawn(async move {
            manager
                .acquire(
                    "creation-attempt",
                    &Principal::parse("user:1").unwrap(),
                    Arc::new(move |line| {
                        tx.send(line).unwrap();
                    }),
                )
                .await
        });
        let approval = rx.recv().await.unwrap();
        let url = reqwest::Url::parse(approval.strip_prefix("approve: ").unwrap()).unwrap();
        assert!(url
            .query_pairs()
            .any(|(name, value)| name == "scope" && value == "auth_keys:create:once"));
        let nonce = url
            .query_pairs()
            .find(|(name, _)| name == "state")
            .unwrap()
            .1
            .into_owned();
        (nonce, job)
    }

    #[test]
    fn modes_and_opaque_token_contract() {
        let registry = Arc::new(Registry::new());
        for (owner, enrollment, app, want) in [
            ("user:1", EnrollmentMode::OauthApp, true, Mode::User),
            ("user:1", EnrollmentMode::OauthApp, false, Mode::Interactive),
            (
                "user:1",
                EnrollmentMode::Interactive,
                true,
                Mode::Interactive,
            ),
            ("tag:ci", EnrollmentMode::Interactive, false, Mode::Tag),
            ("tag:ci", EnrollmentMode::None, false, Mode::None),
        ] {
            let manager = Manager {
                enrollment,
                oauth: app.then(|| oauth(registry.clone(), None)),
                metrics: Arc::new(Metrics::new()),
            };
            assert_eq!(manager.mode(&Principal::parse(owner).unwrap()), want);
        }
        for token in [
            "opaque-provisioning-token",
            "tskey-auth-key",
            "tskey-app-undocumented-token",
            "a.jwt.payload",
        ] {
            assert!(valid_token(token));
        }
        for token in [
            "",
            "tskey-client-secret",
            "https://discovery.test/key",
            "key?scope=tag:ci",
            "key\n",
        ] {
            assert!(!valid_token(token));
        }
    }

    #[tokio::test]
    async fn nonce_cannot_be_reused_for_another_attempt_or_principal() {
        let upstream = upstream(200, format!("{{\"access_token\":\"{TOKEN}\"}}"), "").await;
        let registry = Arc::new(Registry::new());
        let oauth = oauth(registry.clone(), Some(&upstream.base));
        let owner = Principal::parse("user:1").unwrap();
        let other = Principal::parse("user:2").unwrap();
        let mut first = registry.begin("attempt-1", &owner, &oauth).unwrap();
        assert!(!registry.cancel(&first.nonce, "attempt-2", &owner));
        assert!(!registry.cancel(&first.nonce, "attempt-1", &other));
        assert_eq!(
            first.wait("attempt-2", &owner).await.unwrap_err().code,
            Code::PendingApproval
        );
        assert_eq!(
            first.wait("attempt-1", &other).await.unwrap_err().code,
            Code::PendingApproval
        );
        assert!(registry.entries.lock().contains_key(&first.nonce));
        assert_eq!(
            oauth
                .callback(&format!("state={}&code=fresh-code", first.nonce), false)
                .await
                .status,
            200
        );
        assert_eq!(
            first.wait("attempt-1", &owner).await.unwrap(),
            TOKEN.as_bytes()
        );

        let mut next = registry.begin("attempt-2", &other, &oauth).unwrap();
        assert_eq!(
            oauth
                .callback(&format!("state={}&code=fresh-code", first.nonce), false)
                .await
                .status,
            400
        );
        assert!(matches!(
            next.result.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ));
        assert_eq!(
            oauth
                .callback(&format!("state={}&code=fresh-code", next.nonce), false)
                .await
                .status,
            200
        );
        assert_eq!(
            next.wait("attempt-2", &other).await.unwrap(),
            TOKEN.as_bytes()
        );
        assert_eq!(upstream.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn callback_result_binding_is_checked_after_nonce_consumption() {
        let upstream = upstream(200, format!("{{\"access_token\":\"{TOKEN}\"}}"), "").await;
        for (attempt, principal) in [("attempt-2", "user:1"), ("attempt-1", "user:2")] {
            let registry = Arc::new(Registry::new());
            let oauth = oauth(registry.clone(), Some(&upstream.base));
            let owner = Principal::parse("user:1").unwrap();
            let other = Principal::parse(principal).unwrap();
            let mut first = registry.begin("attempt-1", &owner, &oauth).unwrap();
            let mut second = registry.begin(attempt, &other, &oauth).unwrap();
            std::mem::swap(&mut first.result, &mut second.result);
            assert_eq!(
                oauth
                    .callback(&format!("state={}&code=fresh-code", first.nonce), false)
                    .await
                    .status,
                200
            );
            assert_eq!(
                second.wait(attempt, &other).await.unwrap_err().code,
                Code::PendingApproval
            );
        }
    }

    #[tokio::test]
    async fn success_is_bound_and_atomically_consumed_without_logging_secrets() {
        #[derive(Clone)]
        struct Capture(Arc<parking_lot::Mutex<Vec<u8>>>);
        impl std::io::Write for Capture {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let captured = Capture(Arc::default());
        let writer = captured.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(move || writer.clone())
            .finish();
        use tracing::instrument::WithSubscriber;
        async {
            let upstream = upstream(200, format!("{{\"access_token\":\"{TOKEN}\"}}"), "").await;
            let registry = Arc::new(Registry::new());
            let oauth = oauth(registry.clone(), Some(&upstream.base));
            let (nonce, job) = acquire(manager(oauth.clone())).await;
            {
                let entries = registry.entries.lock();
                let entry = entries.get(&nonce).unwrap();
                assert_eq!(entry.attempt, "creation-attempt");
                assert_eq!(entry.owner.as_str(), "user:1");
            }
            assert_eq!(
                oauth
                    .callback("state=wrong&code=fresh-code", false)
                    .await
                    .status,
                400
            );
            let mut callbacks = Vec::new();
            for _ in 0..12 {
                let oauth = oauth.clone();
                let query = format!("state={nonce}&code=fresh-code");
                let dispatch = tracing::dispatcher::get_default(Clone::clone);
                callbacks.push(tokio::spawn(
                    async move { oauth.callback(&query, false).await.status }
                        .with_subscriber(dispatch),
                ));
            }
            let mut successes = 0;
            for task in callbacks {
                if task.await.unwrap() == 200 {
                    successes += 1;
                }
            }
            assert_eq!(successes, 1);
            assert_eq!(upstream.calls.load(Ordering::SeqCst), 1);
            assert_eq!(job.await.unwrap().unwrap().unwrap(), TOKEN.as_bytes());
            assert!(registry.entries.lock().is_empty());
        }
        .with_subscriber(subscriber)
        .await;
        let log = String::from_utf8(captured.0.lock().clone()).unwrap();
        for secret in [SECRET, TOKEN, "fresh-code"] {
            assert!(!log.contains(secret));
        }
    }

    #[tokio::test]
    async fn denial_expiry_cancellation_and_malformed_callbacks_never_exchange() {
        let upstream = upstream(200, format!("{{\"access_token\":\"{TOKEN}\"}}"), "").await;
        let registry = Arc::new(Registry::new());
        let oauth = oauth(registry.clone(), Some(&upstream.base));
        let (nonce, job) = acquire(manager(oauth.clone())).await;
        for query in [
            format!("state={nonce}&state={nonce}&code=fresh-code"),
            format!("state={nonce}&code=%zz"),
            format!("state={nonce}&code=fresh-code&code=again"),
        ] {
            assert_eq!(oauth.callback(&query, false).await.status, 400);
        }
        assert_eq!(
            oauth
                .callback(&format!("state={nonce}&code=fresh-code"), true)
                .await
                .status,
            400
        );
        assert_eq!(
            oauth
                .callback(&format!("state={nonce}&error=access_denied"), false)
                .await
                .status,
            400
        );
        let failure = job.await.unwrap().unwrap_err();
        assert_eq!((failure.code, failure.exit), (Code::PendingApproval, 8));
        assert_eq!(
            failure.message,
            "consent denied, expired or interrupted; no VM was created"
        );
        assert_eq!(
            oauth
                .callback(&format!("state={nonce}&code=fresh-code"), false)
                .await
                .status,
            400
        );

        let short_registry = Arc::new(Registry::with_lifetime(Duration::from_millis(15)));
        let short_oauth =
            crate::lobby::consent::tests::oauth(short_registry.clone(), Some(&upstream.base));
        let (nonce, job) = acquire(manager(short_oauth.clone())).await;
        assert_eq!(job.await.unwrap().unwrap_err().code, Code::Expired);
        assert!(short_registry.entries.lock().is_empty());
        assert_eq!(
            short_oauth
                .callback(&format!("state={nonce}&code=fresh-code"), false)
                .await
                .status,
            400
        );

        let (nonce, job) = acquire(manager(oauth.clone())).await;
        assert!(registry.cancel(
            &nonce,
            "creation-attempt",
            &Principal::parse("user:1").unwrap()
        ));
        let failure = job.await.unwrap().unwrap_err();
        assert_eq!((failure.code, failure.exit), (Code::PendingApproval, 8));
        assert_eq!(
            oauth
                .callback(&format!("state={nonce}&code=fresh-code"), false)
                .await
                .status,
            400
        );

        let (nonce, job) = acquire(manager(oauth.clone())).await;
        job.abort();
        assert!(job.await.unwrap_err().is_cancelled());
        assert!(registry.entries.lock().is_empty());
        assert_eq!(
            oauth
                .callback(&format!("state={nonce}&code=fresh-code"), false)
                .await
                .status,
            400
        );
        assert_eq!(upstream.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn exchange_failures_are_bounded_and_never_retried() {
        for (status, body, extra) in [
            (
                200,
                "{\"access_token\":\"tskey-client-not-a-key\"}".into(),
                "",
            ),
            (200, "x".repeat(65537), ""),
            (
                200,
                "{\"access_token\":\"https://discovery.invalid/key\"}".into(),
                "",
            ),
            (200, "{\"access_token\":\"\"}".into(), ""),
            (200, "not-json".into(), ""),
            (503, SECRET.into(), ""),
            (
                302,
                "".into(),
                "Location: http://127.0.0.1:1/credential-leak\r\n",
            ),
        ] {
            let upstream = upstream(status, body, extra).await;
            let registry = Arc::new(Registry::new());
            let oauth = oauth(registry.clone(), Some(&upstream.base));
            let (nonce, job) = acquire(manager(oauth.clone())).await;
            for _ in 0..2 {
                assert_eq!(
                    oauth
                        .callback(&format!("state={nonce}&code=fresh-code"), false)
                        .await
                        .status,
                    400
                );
            }
            let failure = job.await.unwrap().unwrap_err();
            assert_eq!((failure.code, failure.exit), (Code::PendingApproval, 8));
            assert!(!failure.message.contains(SECRET));
            assert_eq!(upstream.calls.load(Ordering::SeqCst), 1);
            assert!(registry.entries.lock().is_empty());
        }
    }

    #[tokio::test]
    async fn dropping_acquire_cancels_inflight_exchange_and_closes_socket() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let registry = Arc::new(Registry::new());
        let oauth = oauth(registry.clone(), Some(&base));
        let (nonce, job) = acquire(manager(oauth.clone())).await;
        let callback = tokio::spawn(async move {
            oauth
                .callback(&format!("state={nonce}&code=fresh-code"), false)
                .await
                .status
        });
        let (mut stream, _) = listener.accept().await.unwrap();
        job.abort();
        assert!(job.await.unwrap_err().is_cancelled());
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), callback)
                .await
                .unwrap()
                .unwrap(),
            400
        );
        let mut bytes = Vec::new();
        tokio::time::timeout(Duration::from_secs(1), stream.read_to_end(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        assert!(registry.entries.lock().is_empty());
    }
}
