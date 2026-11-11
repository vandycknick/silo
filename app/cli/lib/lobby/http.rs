//! HTTP/1 over already accepted, TLS-terminated streams. Connection identity is
//! resolved afresh for each health or metrics request; callback state is its own
//! one-use authority. All responses disable caching.

use std::{
    convert::Infallible,
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use hyper::{
    body::{Body, Bytes, Frame, Incoming, SizeHint},
    header::{HeaderValue, CACHE_CONTROL, CONTENT_TYPE},
    server::conn::http1,
    service::service_fn,
    Method, Request, Response, StatusCode,
};
use hyper_util::rt::TokioIo;
use parking_lot::Mutex;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    time::{Instant, Sleep},
};
use tokio_util::sync::CancellationToken;

use crate::lobby::{
    consent::OAuth, failure::Code, identity_source::IdentitySource, metrics::Metrics,
    service::Service,
};

/// One accepted, TLS-terminated tsgate stream. Headers never participate in identity.
pub(crate) async fn serve_connection<S>(
    stream: S,
    remote: String,
    identity: IdentitySource,
    service: Arc<Service>,
    metrics: Arc<Metrics>,
    oauth: Option<Arc<OAuth>>,
    cancel: CancellationToken,
) -> Result<(), hyper::Error>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let state = Arc::new(Mutex::new(Phase::Header {
        started: Instant::now(),
    }));
    let io = TimedIo {
        stream,
        state: state.clone(),
        read_timer: Box::pin(tokio::time::sleep(Duration::from_secs(5))),
        write_timer: Box::pin(tokio::time::sleep(Duration::from_secs(35))),
        response_written: false,
    };
    let handler = service_fn(move |request: Request<Incoming>| {
        let resolve = identity(&remote);
        let service = service.clone();
        let metrics = metrics.clone();
        let oauth = oauth.clone();
        let state = state.clone();
        async move {
            let has_body = request.body().size_hint().exact() != Some(0);
            {
                let mut phase = state.lock();
                let started = match *phase {
                    Phase::Header { started } => started,
                    _ => Instant::now(),
                };
                *phase = Phase::Response {
                    read_deadline: has_body.then_some(started + Duration::from_secs(10)),
                    write_deadline: Instant::now() + Duration::from_secs(35),
                };
            }
            let response = match tokio::time::timeout(
                Duration::from_secs(35),
                route(request, resolve, &service, &metrics, oauth.as_deref()),
            )
            .await
            {
                Ok(response) => response,
                Err(_) => response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "text/plain; charset=utf-8",
                    "unavailable\n".into(),
                ),
            };
            Ok::<_, Infallible>(response)
        }
    });
    let mut builder = http1::Builder::new();
    // TimedIo separates the first-byte idle deadline from the header deadline.
    builder
        .header_read_timeout(None)
        .max_buf_size(16 * 1024)
        .half_close(true);
    let connection = builder.serve_connection(TokioIo::new(io), handler);
    tokio::pin!(connection);
    tokio::select! {
        result = &mut connection => result,
        _ = cancel.cancelled() => {
            connection.as_mut().graceful_shutdown();
            match tokio::time::timeout(Duration::from_secs(35), &mut connection).await {
                Ok(result) => result,
                Err(_) => Ok(()),
            }
        }
    }
}

async fn route(
    request: Request<Incoming>,
    resolve: crate::lobby::caller::Resolve,
    service: &Service,
    metrics: &Metrics,
    oauth: Option<&OAuth>,
) -> Response<TextBody> {
    if request.method() != Method::GET {
        let mut result = response(
            StatusCode::METHOD_NOT_ALLOWED,
            "text/plain; charset=utf-8",
            "method not allowed\n".into(),
        );
        result
            .headers_mut()
            .insert(hyper::header::ALLOW, HeaderValue::from_static("GET"));
        return result;
    }
    match request.uri().path() {
        "/oauth/callback" => {
            let Some(oauth) = oauth else {
                return response(
                    StatusCode::NOT_FOUND,
                    "text/plain; charset=utf-8",
                    "not found\n".into(),
                );
            };
            let callback = oauth
                .callback(
                    request.uri().query().unwrap_or_default(),
                    request.body().size_hint().exact() != Some(0),
                )
                .await;
            response(
                callback.status,
                "text/plain; charset=utf-8",
                callback.body.into(),
            )
        }
        "/healthz" | "/metrics" => {
            let started = Instant::now();
            let identity = tokio::time::timeout(Duration::from_secs(15), resolve()).await;
            let ok = matches!(&identity, Ok(Ok(peer)) if peer.valid());
            metrics.latency("whois", started.elapsed(), ok);
            let peer = match identity {
                Ok(Ok(peer)) if peer.valid() => peer,
                _ => {
                    return response(
                        StatusCode::FORBIDDEN,
                        "text/plain; charset=utf-8",
                        "forbidden\n".into(),
                    )
                }
            };
            if request.uri().path() == "/metrics"
                && !peer
                    .principals
                    .iter()
                    .any(|principal| principal.as_str() == service.config().settings.tag())
            {
                return response(
                    StatusCode::FORBIDDEN,
                    "text/plain; charset=utf-8",
                    "forbidden\n".into(),
                );
            }
            match service.health(&peer).await {
                Ok(_) if request.uri().path() == "/metrics" => {
                    let mut text = String::from("lobby_runtime_ready 1\nlobby_tailnet_ready 1\n");
                    text.push_str(&metrics.render());
                    response(StatusCode::OK, "text/plain; version=0.0.4", text)
                }
                Ok(health) => match serde_json::to_string(&health) {
                    Ok(text) => response(StatusCode::OK, "application/json", text),
                    Err(_) => response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "text/plain; charset=utf-8",
                        "unavailable\n".into(),
                    ),
                },
                Err(error) => response(
                    if error.code == Code::Unavailable {
                        StatusCode::SERVICE_UNAVAILABLE
                    } else {
                        StatusCode::FORBIDDEN
                    },
                    "text/plain; charset=utf-8",
                    "unavailable or forbidden\n".into(),
                ),
            }
        }
        _ => response(
            StatusCode::NOT_FOUND,
            "text/plain; charset=utf-8",
            "not found\n".into(),
        ),
    }
}

fn response(status: StatusCode, content_type: &'static str, text: String) -> Response<TextBody> {
    let mut response = Response::new(TextBody(Some(Bytes::from(text))));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
    response
}

struct TextBody(Option<Bytes>);
impl Body for TextBody {
    type Data = Bytes;
    type Error = Infallible;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        Poll::Ready(self.0.take().map(|bytes| Ok(Frame::data(bytes))))
    }
    fn is_end_stream(&self) -> bool {
        self.0.is_none()
    }
    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.0.as_ref().map_or(0, |bytes| bytes.len() as u64))
    }
}

#[derive(Clone, Copy)]
enum Phase {
    Header {
        started: Instant,
    },
    Response {
        read_deadline: Option<Instant>,
        write_deadline: Instant,
    },
    Idle {
        started: Instant,
    },
}

struct TimedIo<S> {
    stream: S,
    state: Arc<Mutex<Phase>>,
    read_timer: Pin<Box<Sleep>>,
    write_timer: Pin<Box<Sleep>>,
    response_written: bool,
}

fn deadline(timer: &mut Pin<Box<Sleep>>, when: Instant, cx: &mut Context<'_>) -> io::Result<()> {
    if timer.deadline() != when {
        timer.as_mut().reset(when);
    }
    if timer.as_mut().poll(cx).is_ready() {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "HTTP connection timed out",
        ));
    }
    Ok(())
}

impl<S: AsyncRead + Unpin> AsyncRead for TimedIo<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let phase = *this.state.lock();
        let when = match phase {
            Phase::Header { started } => Some(started + Duration::from_secs(5)),
            Phase::Idle { started } => Some(started + Duration::from_secs(30)),
            Phase::Response { read_deadline, .. } => read_deadline,
        };
        if let Some(when) = when {
            if let Err(error) = deadline(&mut this.read_timer, when, cx) {
                return Poll::Ready(Err(error));
            }
        }
        let before = buffer.filled().len();
        let result = Pin::new(&mut this.stream).poll_read(cx, buffer);
        if matches!(result, Poll::Ready(Ok(())))
            && buffer.filled().len() > before
            && matches!(phase, Phase::Idle { .. })
        {
            *this.state.lock() = Phase::Header {
                started: Instant::now(),
            };
        }
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for TimedIo<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if let Phase::Response { write_deadline, .. } = *this.state.lock() {
            if let Err(error) = deadline(&mut this.write_timer, write_deadline, cx) {
                return Poll::Ready(Err(error));
            }
        }
        let result = Pin::new(&mut this.stream).poll_write(cx, bytes);
        if matches!(result, Poll::Ready(Ok(count)) if count > 0) {
            this.response_written = true;
        }
        result
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Phase::Response { write_deadline, .. } = *this.state.lock() {
            if let Err(error) = deadline(&mut this.write_timer, write_deadline, cx) {
                return Poll::Ready(Err(error));
            }
        }
        let result = Pin::new(&mut this.stream).poll_flush(cx);
        if matches!(result, Poll::Ready(Ok(()))) && this.response_written {
            this.response_written = false;
            let mut phase = this.state.lock();
            if matches!(*phase, Phase::Response { .. }) {
                *phase = Phase::Idle {
                    started: Instant::now(),
                };
            }
        }
        result
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use crate::lobby::{
        caller::Resolve,
        http::{serve_connection, Phase, TimedIo},
        identity::{Action, Peer, Permissions, Principal},
        identity_source::IdentitySource,
        metrics::Metrics,
        service::{testing, Service},
    };
    use parking_lot::Mutex;
    use std::{
        io,
        sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            Arc,
        },
        time::Duration,
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        time::Instant,
    };
    use tokio_util::sync::CancellationToken;

    fn peer(read: bool) -> Peer {
        Peer {
            principals: vec![
                Principal::parse("user:1").unwrap(),
                Principal::parse("tag:silo").unwrap(),
            ],
            node_id: "actual-node".into(),
            observed_at: chrono::Utc::now(),
            permissions: Permissions {
                actions: if read { vec![Action::Read] } else { vec![] },
                ..Permissions::default()
            },
            ..Peer::default()
        }
    }

    fn identity(read: bool) -> IdentitySource {
        Arc::new(move |remote| {
            assert_eq!(remote, "100.64.0.1:1234");
            let peer = peer(read);
            let resolve: Resolve = Arc::new(move || {
                let peer = peer.clone();
                Box::pin(async move { Ok(peer) })
            });
            resolve
        })
    }

    async fn request(service: Arc<Service>, identity: IdentitySource, request: &str) -> String {
        request_with_oauth(service, identity, request, None).await
    }

    async fn request_with_oauth(
        service: Arc<Service>,
        identity: IdentitySource,
        request: &str,
        oauth: Option<Arc<crate::lobby::consent::OAuth>>,
    ) -> String {
        let (mut client, stream) = tokio::net::UnixStream::pair().unwrap();
        let server = tokio::spawn(serve_connection(
            stream,
            "100.64.0.1:1234".into(),
            identity,
            service,
            Arc::new(Metrics::new()),
            oauth,
            CancellationToken::new(),
        ));
        client.write_all(request.as_bytes()).await.unwrap();
        client.shutdown().await.unwrap();
        let mut output = String::new();
        tokio::time::timeout(Duration::from_secs(10), client.read_to_string(&mut output))
            .await
            .unwrap()
            .unwrap();
        server.await.unwrap().unwrap();
        output
    }

    #[tokio::test]
    async fn routes_require_real_identity_and_ignore_authority_headers() {
        let fixture = testing::fixture().await;
        let service: Arc<Service> = fixture.service.clone().into();
        for path in ["/healthz", "/metrics"] {
            let query = format!("GET {path} HTTP/1.1\r\nHost: lobby\r\nX-Tailscale-User-Login: admin@example.com\r\nX-Forwarded-For: 100.100.100.100\r\nConnection: close\r\n\r\n");
            let denied = request(service.clone(), identity(false), &query).await;
            assert!(denied.starts_with("HTTP/1.1 403 "), "{denied}");
            assert!(denied.contains("cache-control: no-store\r\n"));
            let allowed = request(service.clone(), identity(true), &query).await;
            assert!(allowed.starts_with("HTTP/1.1 200 "), "{allowed}");
            assert!(allowed.contains("cache-control: no-store\r\n"));
            if path == "/healthz" {
                assert!(allowed.ends_with("{\"runtime\":true,\"tailnet\":true}"));
                assert!(allowed.contains("content-type: application/json\r\n"));
            } else {
                assert!(allowed.contains("lobby_runtime_ready 1\nlobby_tailnet_ready 1\n"));
                assert!(allowed
                    .contains("lobby_whois_duration_seconds_count{outcome=\"succeeded\"} 1\n"));
                assert!(!allowed.contains("user:1"));
            }
            let post = request(service.clone(), identity(true), &format!("POST {path} HTTP/1.1\r\nHost: lobby\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")).await;
            assert!(post.starts_with("HTTP/1.1 405 "), "{post}");
        }
        for path in ["/unknown", "/oauth/callback"] {
            let output = request(
                service.clone(),
                identity(true),
                &format!("GET {path} HTTP/1.1\r\nHost: lobby\r\nConnection: close\r\n\r\n"),
            )
            .await;
            assert!(output.starts_with("HTTP/1.1 404 "), "{output}");
        }
    }

    #[tokio::test]
    async fn metrics_requires_the_configured_lobby_tag_but_health_does_not() {
        let fixture = testing::fixture().await;
        let service = Arc::new(fixture.service.clone());
        for (tag, metrics_status) in [
            (None, 403),
            (Some("tag:other"), 403),
            (Some("tag:silo"), 200),
        ] {
            let source: IdentitySource = Arc::new(move |_| {
                Arc::new(move || {
                    let mut peer = peer(true);
                    peer.principals = vec![Principal::parse("user:1").unwrap()];
                    if let Some(tag) = tag {
                        peer.principals.push(Principal::parse(tag).unwrap());
                    }
                    Box::pin(async move { Ok(peer) })
                })
            });
            for (path, status) in [("/healthz", 200), ("/metrics", metrics_status)] {
                let output = request(
                    service.clone(),
                    source.clone(),
                    &format!("GET {path} HTTP/1.1\r\nHost: lobby\r\nConnection: close\r\n\r\n"),
                )
                .await;
                assert!(
                    output.starts_with(&format!("HTTP/1.1 {status} ")),
                    "{output}"
                );
            }
        }
    }

    async fn read_response(stream: &mut tokio::net::UnixStream) -> String {
        let mut bytes = Vec::new();
        loop {
            bytes.push(stream.read_u8().await.unwrap());
            let text = String::from_utf8_lossy(&bytes);
            if let Some((head, body)) = text.split_once("\r\n\r\n") {
                let length: usize = head
                    .lines()
                    .find_map(|line| {
                        line.strip_prefix("content-length: ")
                            .map(|n| n.parse().unwrap())
                    })
                    .unwrap();
                if body.len() == length {
                    return text.into_owned();
                }
            }
        }
    }

    #[tokio::test]
    async fn keepalive_reauthorizes_each_request_and_caps_headers() {
        let fixture = testing::fixture().await;
        let service: Arc<Service> = fixture.service.clone().into();
        let allowed = Arc::new(AtomicBool::new(true));
        let calls = Arc::new(AtomicUsize::new(0));
        let grant = allowed.clone();
        let count = calls.clone();
        let source: IdentitySource = Arc::new(move |_| {
            let grant = grant.clone();
            let count = count.clone();
            Arc::new(move || {
                count.fetch_add(1, Ordering::SeqCst);
                let peer = peer(grant.load(Ordering::SeqCst));
                Box::pin(async move { Ok(peer) })
            })
        });
        let (mut client, stream) = tokio::net::UnixStream::pair().unwrap();
        let server = tokio::spawn(serve_connection(
            stream,
            "remote".into(),
            source,
            service.clone(),
            Arc::new(Metrics::new()),
            None,
            CancellationToken::new(),
        ));
        let query = "GET /healthz HTTP/1.1\r\nHost: lobby\r\n\r\n";
        client.write_all(query.as_bytes()).await.unwrap();
        assert!(read_response(&mut client)
            .await
            .starts_with("HTTP/1.1 200 "));
        allowed.store(false, Ordering::SeqCst);
        client.write_all(query.as_bytes()).await.unwrap();
        assert!(read_response(&mut client)
            .await
            .starts_with("HTTP/1.1 403 "));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        drop(client);
        server.await.unwrap().unwrap();

        let (mut client, stream) = tokio::net::UnixStream::pair().unwrap();
        let server = tokio::spawn(serve_connection(
            stream,
            "100.64.0.1:1234".into(),
            identity(true),
            service,
            Arc::new(Metrics::new()),
            None,
            CancellationToken::new(),
        ));
        client.write_all(format!("GET /healthz HTTP/1.1\r\nHost: lobby\r\nX-Oversized: {}\r\nConnection: close\r\n\r\n", "x".repeat(17 * 1024)).as_bytes()).await.unwrap();
        let mut output = String::new();
        let _ = client.read_to_string(&mut output).await;
        assert!(server.await.unwrap().unwrap_err().is_parse_too_large());
    }

    #[tokio::test]
    async fn transport_enforces_header_body_idle_and_write_deadlines() {
        for phase in [
            Phase::Header {
                started: Instant::now() - Duration::from_secs(6),
            },
            Phase::Idle {
                started: Instant::now() - Duration::from_secs(31),
            },
            Phase::Response {
                read_deadline: Some(Instant::now() - Duration::from_secs(1)),
                write_deadline: Instant::now() + Duration::from_secs(35),
            },
        ] {
            let (_client, stream) = tokio::net::UnixStream::pair().unwrap();
            let mut io = TimedIo {
                stream,
                state: Arc::new(Mutex::new(phase)),
                read_timer: Box::pin(tokio::time::sleep(Duration::ZERO)),
                write_timer: Box::pin(tokio::time::sleep(Duration::ZERO)),
                response_written: false,
            };
            assert_eq!(
                io.read_u8().await.unwrap_err().kind(),
                io::ErrorKind::TimedOut
            );
        }
        let (_client, stream) = tokio::net::UnixStream::pair().unwrap();
        let mut io = TimedIo {
            stream,
            state: Arc::new(Mutex::new(Phase::Response {
                read_deadline: None,
                write_deadline: Instant::now() - Duration::from_secs(1),
            })),
            read_timer: Box::pin(tokio::time::sleep(Duration::ZERO)),
            write_timer: Box::pin(tokio::time::sleep(Duration::ZERO)),
            response_written: false,
        };
        assert_eq!(
            io.write_all(b"response").await.unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
    }

    #[tokio::test]
    async fn callback_exchanges_once_without_health_authority() {
        use crate::config::tailscale::EnrollmentMode;
        use crate::lobby::{
            consent::{Manager, OAuth, Registry},
            service::enrollment::ConsentProvider,
        };
        let fixture = testing::fixture().await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let token_server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut bytes = Vec::new();
            let mut chunk = [0; 4096];
            loop {
                let read = stream.read(&mut chunk).await.unwrap();
                assert_ne!(read, 0);
                bytes.extend_from_slice(&chunk[..read]);
                let request = String::from_utf8_lossy(&bytes);
                if let Some((head, body)) = request.split_once("\r\n\r\n") {
                    let length: usize = head
                        .lines()
                        .find_map(|line| {
                            line.strip_prefix("content-length: ")
                                .map(|n| n.parse().unwrap())
                        })
                        .unwrap();
                    if body.len() == length {
                        break;
                    }
                }
            }
            let request = String::from_utf8(bytes).unwrap();
            assert!(request.contains("code=fresh-code"));
            let body = "{\"access_token\":\"opaque-provisioning-key\"}";
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
        });
        let oauth = Arc::new(
            OAuth::new(
                Arc::new(Registry::new()),
                String::from("tskey-app-id-fixture-secret").into(),
                "https://lobby.tail.test/oauth/callback".into(),
                Some(&base),
            )
            .unwrap(),
        );
        let manager = Manager {
            enrollment: EnrollmentMode::OauthApp,
            oauth: Some(oauth.clone()),
            metrics: Arc::new(Metrics::new()),
        };
        let (progress, mut approval) = tokio::sync::mpsc::unbounded_channel();
        let acquire = tokio::spawn(async move {
            manager
                .acquire(
                    "attempt",
                    &Principal::parse("user:1").unwrap(),
                    Arc::new(move |line| {
                        progress.send(line).unwrap();
                    }),
                )
                .await
        });
        let approval = approval.recv().await.unwrap();
        let url = reqwest::Url::parse(approval.strip_prefix("approve: ").unwrap()).unwrap();
        let state = url
            .query_pairs()
            .find(|(name, _)| name == "state")
            .unwrap()
            .1
            .into_owned();
        let query = format!("GET /oauth/callback?state={state}&code=fresh-code HTTP/1.1\r\nHost: lobby\r\nConnection: close\r\n\r\n");
        let service: Arc<Service> = fixture.service.clone().into();
        let approved = request_with_oauth(
            service.clone(),
            identity(false),
            &query,
            Some(oauth.clone()),
        )
        .await;
        assert!(approved.starts_with("HTTP/1.1 200 "), "{approved}");
        assert!(approved.contains("cache-control: no-store\r\n"));
        assert_eq!(
            acquire.await.unwrap().unwrap().unwrap(),
            b"opaque-provisioning-key"
        );
        let replay = request_with_oauth(service, identity(false), &query, Some(oauth)).await;
        assert!(replay.starts_with("HTTP/1.1 400 "), "{replay}");
        assert!(fixture.management.inventory().await.unwrap().is_empty());
        token_server.await.unwrap();
    }

    #[tokio::test]
    async fn unavailable_runtime_is_503_only_after_authorization() {
        use sqlx::{ConnectOptions, Connection};
        let fixture = testing::fixture().await;
        let mut database = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(fixture.root.path().join("home/state.db"))
            .connect()
            .await
            .unwrap();
        sqlx::query("DROP TABLE machine_config")
            .execute(&mut database)
            .await
            .unwrap();
        database.close().await.unwrap();
        let service: Arc<Service> = fixture.service.clone().into();
        for path in ["/healthz", "/metrics"] {
            let query = format!("GET {path} HTTP/1.1\r\nHost: lobby\r\nConnection: close\r\n\r\n");
            let allowed = request(service.clone(), identity(true), &query).await;
            assert!(allowed.starts_with("HTTP/1.1 503 "), "{allowed}");
            let denied = request(service.clone(), identity(false), &query).await;
            assert!(denied.starts_with("HTTP/1.1 403 "), "{denied}");
            assert!(!allowed.contains("machine_config"));
            assert!(!allowed.contains("state.db"));
        }
    }
}
