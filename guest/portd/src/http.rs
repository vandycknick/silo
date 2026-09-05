use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, SocketAddrV4, TcpStream, ToSocketAddrs};
use std::time::Duration;

use nix::sys::socket::{setsockopt, sockopt};

const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_BODY_BYTES: usize = 64 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) struct PublicationHold {
    stream: TcpStream,
}

impl PublicationHold {
    pub(crate) fn drain_stream(&self) -> io::Result<TcpStream> {
        self.stream.try_clone()
    }

    pub(crate) fn close(&self) {
        let _ = self.stream.shutdown(Shutdown::Both);
    }
}

impl Drop for PublicationHold {
    fn drop(&mut self) {
        self.close();
    }
}

pub(crate) struct PublicationClient {
    endpoint: Endpoint,
    stream: TcpStream,
}

impl PublicationClient {
    pub(crate) fn connect(endpoint: &str) -> Result<Self, String> {
        let endpoint = Endpoint::parse(endpoint)?;
        let address = endpoint
            .socket_address()
            .map_err(|error| format!("resolve publication endpoint {endpoint}: {error}"))?;
        let stream = TcpStream::connect_timeout(&address, IO_TIMEOUT)
            .map_err(|error| format!("connect publication endpoint {endpoint}: {error}"))?;
        // A crashed netd cannot send FIN through the virtual network. Bound
        // silent peer loss instead of retaining ingress until Linux's defaults
        // (typically hours) eventually notice it.
        setsockopt(&stream, sockopt::KeepAlive, &true)
            .and_then(|()| setsockopt(&stream, sockopt::TcpKeepIdle, &5_u32))
            .and_then(|()| setsockopt(&stream, sockopt::TcpKeepInterval, &1_u32))
            .and_then(|()| setsockopt(&stream, sockopt::TcpKeepCount, &3_u32))
            .map_err(|error| format!("configure publication keepalive {endpoint}: {error}"))?;
        stream
            .set_read_timeout(Some(IO_TIMEOUT))
            .map_err(|error| format!("configure publication endpoint {endpoint}: {error}"))?;
        stream
            .set_write_timeout(Some(IO_TIMEOUT))
            .map_err(|error| format!("configure publication endpoint {endpoint}: {error}"))?;

        Ok(Self { endpoint, stream })
    }

    pub(crate) fn addresses(&self) -> Result<(Ipv4Addr, Ipv4Addr), String> {
        let local = self
            .stream
            .local_addr()
            .map_err(|error| format!("inspect publication source: {error}"))?;
        let peer = self
            .stream
            .peer_addr()
            .map_err(|error| format!("inspect publication gateway: {error}"))?;
        match (local, peer) {
            (SocketAddr::V4(local), SocketAddr::V4(peer)) => Ok((*local.ip(), *peer.ip())),
            _ => Err("publication control connection must use IPv4".to_string()),
        }
    }

    pub(crate) fn expose(
        self,
        host_ip: IpAddr,
        host_port: u16,
        ingress: SocketAddrV4,
    ) -> Result<PublicationHold, String> {
        let Self {
            endpoint,
            mut stream,
        } = self;
        let local = SocketAddr::new(host_ip, host_port).to_string();
        let body = format!(r#"{{"local":"{local}","remote":"{ingress}","protocol":"tcp"}}"#);
        let request = format!(
        "POST /services/forwarder/expose/session HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n{}",
        endpoint.authority,
        body.len(),
        body
    );
        stream
            .write_all(request.as_bytes())
            .map_err(|error| format!("write publication request to {endpoint}: {error}"))?;

        let mut reader = BufReader::new(stream);
        let status = read_line(&mut reader, MAX_HEADER_BYTES)
            .map_err(|error| format!("read publication response from {endpoint}: {error}"))?;
        let status_code = status
            .split_whitespace()
            .nth(1)
            .ok_or_else(|| format!("invalid publication response status line {status:?}"))?
            .parse::<u16>()
            .map_err(|error| {
                format!("invalid publication response status line {status:?}: {error}")
            })?;
        let headers = read_headers(&mut reader).map_err(|error| {
            format!("read publication response headers from {endpoint}: {error}")
        })?;
        if status_code != 200 {
            let body = read_error_body(&mut reader, &headers)
                .map_err(|error| format!("read publication error from {endpoint}: {error}"))?;
            let body = String::from_utf8_lossy(&body);
            let body = body.trim();
            return Err(if body.is_empty() {
                format!("publication endpoint returned HTTP {status_code}")
            } else {
                body.to_string()
            });
        }
        if !headers.chunked {
            return Err("publication endpoint response is not chunked".to_string());
        }
        let first_chunk = read_chunk(&mut reader)
            .map_err(|error| format!("read publication response body from {endpoint}: {error}"))?;
        serde_json::from_slice::<serde_json::Value>(&first_chunk)
            .map_err(|error| format!("invalid publication response JSON: {error}"))?;
        let stream = reader.into_inner();
        stream
            .set_read_timeout(None)
            .map_err(|error| format!("configure publication hold {endpoint}: {error}"))?;
        Ok(PublicationHold { stream })
    }
}

#[derive(Debug)]
struct Endpoint {
    authority: String,
    host: String,
    port: u16,
}

impl Endpoint {
    fn parse(value: &str) -> Result<Self, String> {
        let authority = value
            .strip_prefix("http://")
            .ok_or_else(|| "publication endpoint must use http://".to_string())?;
        if authority.is_empty() || authority.contains(['/', '?', '#']) {
            return Err(format!("invalid publication endpoint {value:?}"));
        }
        let (host, port) = if let Some(bracketed) = authority.strip_prefix('[') {
            let (host, suffix) = bracketed
                .split_once(']')
                .ok_or_else(|| format!("invalid publication endpoint {value:?}"))?;
            let port = if suffix.is_empty() {
                80
            } else {
                suffix
                    .strip_prefix(':')
                    .ok_or_else(|| format!("invalid publication endpoint {value:?}"))?
                    .parse::<u16>()
                    .map_err(|error| format!("invalid publication endpoint port: {error}"))?
            };
            (host.to_string(), port)
        } else if let Some((host, port)) = authority.rsplit_once(':') {
            let port = port
                .parse::<u16>()
                .map_err(|error| format!("invalid publication endpoint port: {error}"))?;
            (host.to_string(), port)
        } else {
            (authority.to_string(), 80)
        };
        if host.is_empty() || port == 0 {
            return Err(format!("invalid publication endpoint {value:?}"));
        }
        Ok(Self {
            authority: authority.to_string(),
            host,
            port,
        })
    }

    fn socket_address(&self) -> io::Result<SocketAddr> {
        (self.host.as_str(), self.port)
            .to_socket_addrs()?
            .find(SocketAddr::is_ipv4)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    "no IPv4 gateway address resolved",
                )
            })
    }
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "http://{}", self.authority)
    }
}

#[derive(Default)]
struct Headers {
    chunked: bool,
    content_length: Option<usize>,
}

fn read_headers(reader: &mut impl BufRead) -> io::Result<Headers> {
    let mut headers = Headers::default();
    let mut total = 0;
    loop {
        let line = read_line(reader, MAX_HEADER_BYTES.saturating_sub(total))?;
        total += line.len() + 2;
        if line.is_empty() {
            return Ok(headers);
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "malformed HTTP header"))?;
        if name.eq_ignore_ascii_case("transfer-encoding")
            && value.trim().eq_ignore_ascii_case("chunked")
        {
            headers.chunked = true;
        }
        if name.eq_ignore_ascii_case("content-length") {
            let length = value.trim().parse::<usize>().map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid content length: {error}"),
                )
            })?;
            if length > MAX_BODY_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "HTTP body is too large",
                ));
            }
            headers.content_length = Some(length);
        }
    }
}

fn read_error_body(reader: &mut impl BufRead, headers: &Headers) -> io::Result<Vec<u8>> {
    if headers.chunked {
        let mut body = Vec::new();
        loop {
            let chunk = read_chunk(reader)?;
            if chunk.is_empty() {
                return Ok(body);
            }
            if body.len() + chunk.len() > MAX_BODY_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "HTTP body is too large",
                ));
            }
            body.extend(chunk);
        }
    }
    let length = headers.content_length.unwrap_or(MAX_BODY_BYTES);
    let mut body = Vec::new();
    reader.take(length as u64).read_to_end(&mut body)?;
    Ok(body)
}

fn read_chunk(reader: &mut impl BufRead) -> io::Result<Vec<u8>> {
    let size_line = read_line(reader, 128)?;
    let size_text = size_line.split(';').next().unwrap_or_default();
    let size = usize::from_str_radix(size_text, 16).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid chunk size: {error}"),
        )
    })?;
    if size > MAX_BODY_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "HTTP chunk is too large",
        ));
    }
    let mut chunk = vec![0; size];
    reader.read_exact(&mut chunk)?;
    let mut terminator = [0; 2];
    reader.read_exact(&mut terminator)?;
    if terminator != *b"\r\n" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid chunk terminator",
        ));
    }
    Ok(chunk)
}

fn read_line(reader: &mut impl BufRead, limit: usize) -> io::Result<String> {
    if limit == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "HTTP headers are too large",
        ));
    }
    let mut bytes = Vec::new();
    let read = reader
        .take((limit + 1) as u64)
        .read_until(b'\n', &mut bytes)?;
    if read == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "unexpected HTTP EOF",
        ));
    }
    if bytes.len() > limit || !bytes.ends_with(b"\n") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "HTTP line is too large",
        ));
    }
    bytes.pop();
    if bytes.last() == Some(&b'\r') {
        bytes.pop();
    }
    String::from_utf8(bytes).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("HTTP line is not UTF-8: {error}"),
        )
    })
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::{IpAddr, Ipv4Addr, TcpListener};
    use std::thread;

    use crate::http::PublicationClient;

    #[test]
    fn sends_exact_request_and_accepts_chunked_success() {
        let (endpoint, server) = server(|mut stream| {
            let (headers, body) = read_request(&mut stream);
            assert!(headers.starts_with("POST /services/forwarder/expose/session HTTP/1.1\r\n"));
            assert_eq!(
                body,
                br#"{"local":"0.0.0.0:8080","remote":"127.0.0.1:42001","protocol":"tcp"}"#
            );
            let publication = b"{\"local\":\"0.0.0.0:8080\",\"remote\":\"127.0.0.1:42001\",\"protocol\":\"tcp\"}\n";
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n",
                publication.len()
            )
            .expect("write response");
            stream.write_all(publication).expect("write publication");
            stream.write_all(b"\r\n").expect("write chunk end");
        });
        let client = PublicationClient::connect(&endpoint).expect("connect to gateway");
        assert_eq!(
            client.addresses().expect("addresses"),
            (Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST)
        );
        let hold = client
            .expose(
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                8080,
                "127.0.0.1:42001".parse().unwrap(),
            )
            .expect("open publication");
        hold.close();
        server.join().expect("join server");
    }

    #[test]
    fn returns_non_success_body() {
        let (endpoint, server) = server(|mut stream| {
            read_request(&mut stream);
            let body = b"bind policy denied\n";
            write!(
                stream,
                "HTTP/1.1 403 Forbidden\r\nContent-Length: {}\r\n\r\n",
                body.len()
            )
            .expect("write headers");
            stream.write_all(body).expect("write body");
        });
        let error = PublicationClient::connect(&endpoint)
            .expect("connect to gateway")
            .expose(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                8080,
                "127.0.0.1:42001".parse().unwrap(),
            )
            .err()
            .expect("403 must fail");
        assert_eq!(error, "bind policy denied");
        server.join().expect("join server");
    }

    #[test]
    fn control_endpoint_requires_an_ipv4_gateway() {
        let ipv4 = crate::http::Endpoint::parse("http://127.0.0.1:80").unwrap();
        assert_eq!(
            ipv4.socket_address().unwrap(),
            "127.0.0.1:80".parse().unwrap()
        );
        let ipv6 = crate::http::Endpoint::parse("http://[::1]:80").unwrap();
        assert_eq!(
            ipv6.socket_address().unwrap_err().kind(),
            std::io::ErrorKind::AddrNotAvailable
        );
    }

    #[test]
    fn connection_error_names_endpoint() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind temporary listener");
        let endpoint = format!(
            "http://{}",
            listener.local_addr().expect("listener address")
        );
        drop(listener);
        let error = PublicationClient::connect(&endpoint)
            .err()
            .expect("connection must fail");
        assert!(error.contains(&endpoint), "unexpected error: {error}");
    }

    fn read_request(stream: &mut std::net::TcpStream) -> (String, Vec<u8>) {
        let mut reader = BufReader::new(stream);
        let mut headers = String::new();
        loop {
            let mut line = String::new();
            assert_ne!(reader.read_line(&mut line).expect("read request header"), 0);
            headers.push_str(&line);
            if line == "\r\n" {
                break;
            }
        }
        let length = headers
            .lines()
            .find_map(|line| line.strip_prefix("Content-Length: "))
            .expect("content length")
            .parse::<usize>()
            .expect("parse content length");
        let mut body = vec![0; length];
        reader.read_exact(&mut body).expect("read body");
        (headers, body)
    }

    fn server(
        handler: impl FnOnce(std::net::TcpStream) + Send + 'static,
    ) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind server");
        let endpoint = format!("http://{}", listener.local_addr().expect("server address"));
        let handle = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept request");
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            handler(stream);
        });
        (endpoint, handle)
    }
}
