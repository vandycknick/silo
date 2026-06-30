use std::io;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use plugins::Plugin;

#[tokio::main]
async fn main() -> io::Result<()> {
    let plugin = Plugin::init("hello-world").await?;

    loop {
        let stream = plugin.accept().await?;
        tokio::spawn(async move {
            if let Err(err) = handle_connection(stream).await {
                eprintln!("hello-world plugin connection failed: {err}");
            }
        });
    }
}

async fn handle_connection(stream: plugins::AsyncStream) -> io::Result<()> {
    let io = TokioIo::new(stream);
    http1::Builder::new()
        .serve_connection(io, service_fn(handle_request))
        .await
        .map_err(io::Error::other)
}

async fn handle_request(
    request: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    let response = if request.method() == Method::GET {
        Response::builder()
            .status(StatusCode::OK)
            .header(hyper::header::CONTENT_TYPE, "text/plain")
            .body(Full::new(Bytes::from_static(b"hello world\n")))
            .expect("response should build")
    } else {
        Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header(hyper::header::CONTENT_TYPE, "text/plain")
            .body(Full::new(Bytes::from_static(b"not found\n")))
            .expect("response should build")
    };

    Ok(response)
}
