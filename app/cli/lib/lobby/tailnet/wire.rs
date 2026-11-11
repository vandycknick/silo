//! Frames on the tsgate control socket. The contract lives in the lobby ADR
//! (0022): a 4-byte big-endian length, one JSON object, and exactly one
//! `SCM_RIGHTS` fd riding with every `conn` frame.
//!
//! ```text
//!  sendmsg(conn) ──► [len][{"type":"conn",...}]  + fd
//!                     ^ the fd sticks to the first byte of the frame
//!  recvmsg      ──► bytes into `buf`, fds into `fds` (FIFO)
//!  decode       ──► conn frame pops exactly one fd; nothing else may own one
//! ```

use std::collections::VecDeque;
use std::fmt;
use std::os::fd::OwnedFd;

use serde::{Deserialize, Serialize};

pub(crate) const MAX_FRAME: usize = 64 * 1024;
const HEADER: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum WireError {
    EmptyFrame,
    Oversize(usize),
    Truncated,
    Malformed(String),
    MissingFd,
    UnexpectedFd,
    TooManyFds(usize),
    InvalidReply(u64),
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyFrame => f.write_str("empty frame"),
            Self::Oversize(n) => write!(f, "frame of {n} bytes exceeds {MAX_FRAME}"),
            Self::Truncated => f.write_str("control socket closed inside a frame"),
            Self::Malformed(e) => write!(f, "malformed frame: {e}"),
            Self::MissingFd => f.write_str("conn frame without a file descriptor"),
            Self::UnexpectedFd => f.write_str("file descriptor attached to a non-conn frame"),
            Self::TooManyFds(n) => write!(f, "{n} file descriptors in one control message"),
            Self::InvalidReply(id) => {
                write!(
                    f,
                    "reply {id} must carry exactly one of whois, status, error"
                )
            }
        }
    }
}

impl std::error::Error for WireError {}

/// First frame silod sends. Secrets travel only here, never in argv or env.
#[derive(Clone, Serialize)]
pub(crate) struct Bootstrap {
    pub(crate) version: u32,
    pub(crate) hostname: String,
    pub(crate) tag: String,
    pub(crate) control_url: String,
    pub(crate) state_dir: String,
    pub(crate) capability: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) client_secret: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) api_base_url: Option<String>,
}

impl fmt::Debug for Bootstrap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Bootstrap")
            .field("hostname", &self.hostname)
            .field("tag", &self.tag)
            .field("control_url", &self.control_url)
            .field("state_dir", &self.state_dir)
            .field("capability", &self.capability)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "<redacted>"),
            )
            .field("api_base_url", &self.api_base_url)
            .finish()
    }
}

#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum Request {
    Bootstrap(Bootstrap),
    Whois { id: u64, remote: String },
    Status { id: u64 },
    Shutdown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Phase {
    Starting,
    NeedsLogin,
    NeedsTag,
    Running,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub(crate) struct NodeState {
    pub(crate) phase: Phase,
    #[serde(default)]
    pub(crate) approval_url: Option<String>,
    #[serde(default)]
    pub(crate) dns_name: Option<String>,
    #[serde(default)]
    pub(crate) tailnet: Option<String>,
    #[serde(default)]
    pub(crate) suffix: Option<String>,
    #[serde(default)]
    pub(crate) tags: Vec<String>,
    #[serde(default)]
    pub(crate) error: Option<String>,
}

impl NodeState {
    pub(crate) fn starting() -> Self {
        Self {
            phase: Phase::Starting,
            approval_url: None,
            dns_name: None,
            tailnet: None,
            suffix: None,
            tags: Vec::new(),
            error: None,
        }
    }
}

/// Version-1 peer identity, owned by this repository so a future in-process
/// tailnet produces the same shape.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub(crate) struct Whois {
    pub(crate) node_id: String,
    pub(crate) node_name: String,
    #[serde(default)]
    pub(crate) tags: Vec<String>,
    pub(crate) user_id: i64,
    pub(crate) login_name: String,
    #[serde(default)]
    pub(crate) display_name: String,
    #[serde(default)]
    pub(crate) capability: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Listener {
    Ssh,
    Http,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum ReplyBody {
    Whois(Whois),
    Status(NodeState),
}

#[derive(Deserialize)]
struct RawReply {
    id: u64,
    whois: Option<Whois>,
    status: Option<NodeState>,
    error: Option<String>,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Incoming {
    State(NodeState),
    Conn { listener: Listener, remote: String },
    Reply(RawReply),
}

#[derive(Debug)]
pub(crate) enum Event {
    State(NodeState),
    Conn {
        listener: Listener,
        remote: String,
        stream: OwnedFd,
    },
    Reply {
        id: u64,
        result: Result<ReplyBody, String>,
    },
}

pub(crate) fn encode(request: &Request) -> Result<Vec<u8>, WireError> {
    let body = serde_json::to_vec(request).map_err(|e| WireError::Malformed(e.to_string()))?;
    if body.len() > MAX_FRAME {
        return Err(WireError::Oversize(body.len()));
    }
    let len = u32::try_from(body.len()).map_err(|_| WireError::Oversize(body.len()))?;
    let mut frame = Vec::with_capacity(HEADER + body.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(&body);
    Ok(frame)
}

/// Incremental decoder fed by `recvmsg`. Pure, so every malformed case is a
/// unit test instead of a socket choreography.
#[derive(Default)]
pub(crate) struct Decoder {
    buf: Vec<u8>,
    fds: VecDeque<OwnedFd>,
}

impl Decoder {
    pub(crate) fn push(&mut self, bytes: &[u8], fds: Vec<OwnedFd>) -> Result<(), WireError> {
        if fds.len() > 1 {
            return Err(WireError::TooManyFds(fds.len()));
        }
        self.buf.extend_from_slice(bytes);
        self.fds.extend(fds);
        Ok(())
    }

    pub(crate) fn next(&mut self) -> Result<Option<Event>, WireError> {
        let Some(header) = self.buf.first_chunk::<HEADER>() else {
            return self.fd_without_bytes().map(|()| None);
        };
        let len = u32::from_be_bytes(*header) as usize;
        if len == 0 {
            return Err(WireError::EmptyFrame);
        }
        if len > MAX_FRAME {
            return Err(WireError::Oversize(len));
        }
        if self.buf.len() < HEADER + len {
            return Ok(None);
        }
        let parsed: Result<Incoming, _> = serde_json::from_slice(&self.buf[HEADER..HEADER + len]);
        self.buf.drain(..HEADER + len);
        let event = match parsed.map_err(|e| WireError::Malformed(e.to_string()))? {
            Incoming::State(state) => Event::State(state),
            Incoming::Conn { listener, remote } => {
                let stream = self.fds.pop_front().ok_or(WireError::MissingFd)?;
                Event::Conn {
                    listener,
                    remote,
                    stream,
                }
            }
            Incoming::Reply(reply) => Event::Reply {
                id: reply.id,
                result: match (reply.whois, reply.status, reply.error) {
                    (Some(whois), None, None) => Ok(ReplyBody::Whois(whois)),
                    (None, Some(status), None) => Ok(ReplyBody::Status(status)),
                    (None, None, Some(error)) => Err(error),
                    _ => return Err(WireError::InvalidReply(reply.id)),
                },
            },
        };
        if !matches!(event, Event::Conn { .. }) {
            self.fd_without_bytes()?;
        }
        Ok(Some(event))
    }

    /// The control socket reached EOF. Anything still buffered is a cut frame.
    pub(crate) fn finish(&self) -> Result<(), WireError> {
        if !self.buf.is_empty() {
            return Err(WireError::Truncated);
        }
        self.fd_without_bytes()
    }

    // An fd always arrives with the bytes of its conn frame, so a queued fd
    // with no buffered bytes left to claim it belonged to some other frame.
    fn fd_without_bytes(&self) -> Result<(), WireError> {
        if self.buf.is_empty() && !self.fds.is_empty() {
            return Err(WireError::UnexpectedFd);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;

    use crate::lobby::tailnet::wire::{
        encode, Bootstrap, Decoder, Event, Listener, Phase, ReplyBody, Request, WireError,
        MAX_FRAME,
    };

    fn frame(json: &str) -> Vec<u8> {
        let mut out = (json.len() as u32).to_be_bytes().to_vec();
        out.extend_from_slice(json.as_bytes());
        out
    }

    fn fd() -> OwnedFd {
        let (a, _b) = UnixStream::pair().unwrap();
        OwnedFd::from(a)
    }

    fn decode_all(decoder: &mut Decoder) -> Result<Vec<Event>, WireError> {
        let mut events = Vec::new();
        while let Some(event) = decoder.next()? {
            events.push(event);
        }
        Ok(events)
    }

    #[test]
    fn encodes_requests_with_big_endian_length_and_type_tag() {
        let bytes = encode(&Request::Whois {
            id: 7,
            remote: "100.64.0.1:4242".into(),
        })
        .unwrap();
        let len = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
        assert_eq!(len, bytes.len() - 4);
        let value: serde_json::Value = serde_json::from_slice(&bytes[4..]).unwrap();
        assert_eq!(
            value,
            serde_json::json!({"type": "whois", "id": 7, "remote": "100.64.0.1:4242"})
        );
        let shutdown: serde_json::Value =
            serde_json::from_slice(&encode(&Request::Shutdown).unwrap()[4..]).unwrap();
        assert_eq!(shutdown, serde_json::json!({"type": "shutdown"}));
    }

    #[test]
    fn bootstrap_omits_absent_secrets_and_never_debug_prints_them() {
        let mut bootstrap = Bootstrap {
            version: 1,
            hostname: "silo".into(),
            tag: "tag:silo".into(),
            control_url: String::new(),
            state_dir: "/home/u/.silo/tsgate".into(),
            capability: "github.com/vandycknick/silo".into(),
            client_secret: None,
            api_base_url: None,
        };
        let plain: serde_json::Value =
            serde_json::from_slice(&encode(&Request::Bootstrap(bootstrap.clone())).unwrap()[4..])
                .unwrap();
        assert!(plain.get("client_secret").is_none());
        assert_eq!(plain["type"], "bootstrap");
        bootstrap.client_secret = Some("tskey-client-secret".into());
        assert!(!format!("{bootstrap:?}").contains("tskey-client-secret"));
        let with: serde_json::Value =
            serde_json::from_slice(&encode(&Request::Bootstrap(bootstrap)).unwrap()[4..]).unwrap();
        assert_eq!(with["client_secret"], "tskey-client-secret");
    }

    #[test]
    fn decodes_frames_split_at_every_byte_boundary() {
        let mut stream = frame(
            r#"{"type":"state","phase":"needs_login","approval_url":"https://login","tags":[]}"#,
        );
        stream.extend(frame(
            r#"{"type":"reply","id":3,"error":"WhoIs unavailable"}"#,
        ));
        for split in 0..=stream.len() {
            let mut decoder = Decoder::default();
            decoder.push(&stream[..split], vec![]).unwrap();
            let mut events = decode_all(&mut decoder).unwrap();
            decoder.push(&stream[split..], vec![]).unwrap();
            events.extend(decode_all(&mut decoder).unwrap());
            decoder.finish().unwrap();
            assert_eq!(events.len(), 2, "split at {split}");
            match &events[0] {
                Event::State(state) => {
                    assert_eq!(state.phase, Phase::NeedsLogin);
                    assert_eq!(state.approval_url.as_deref(), Some("https://login"));
                }
                other => panic!("unexpected {other:?}"),
            }
            match &events[1] {
                Event::Reply {
                    id: 3,
                    result: Err(e),
                } => assert_eq!(e, "WhoIs unavailable"),
                other => panic!("unexpected {other:?}"),
            }
        }
    }

    #[test]
    fn conn_frame_claims_its_fd_and_whois_reply_decodes() {
        let mut decoder = Decoder::default();
        let mut bytes = frame(r#"{"type":"conn","listener":"ssh","remote":"100.64.0.9:5555"}"#);
        decoder.push(&bytes, vec![fd()]).unwrap();
        bytes = frame(
            r#"{"type":"reply","id":1,"whois":{"node_id":"n1","node_name":"peer.ts.net.","tags":["tag:peer"],"user_id":9,"login_name":"tagged-devices","capability":[{"actions":["*"]}]}}"#,
        );
        decoder.push(&bytes, vec![]).unwrap();
        let events = decode_all(&mut decoder).unwrap();
        decoder.finish().unwrap();
        match &events[0] {
            Event::Conn {
                listener: Listener::Ssh,
                remote,
                ..
            } => assert_eq!(remote, "100.64.0.9:5555"),
            other => panic!("unexpected {other:?}"),
        }
        match &events[1] {
            Event::Reply {
                id: 1,
                result: Ok(ReplyBody::Whois(whois)),
            } => {
                assert_eq!(whois.tags, vec!["tag:peer".to_string()]);
                assert_eq!(
                    whois.capability,
                    vec![serde_json::json!({"actions": ["*"]})]
                );
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn fd_arriving_with_a_preceding_frame_tail_still_belongs_to_the_conn_frame() {
        let mut decoder = Decoder::default();
        let state = frame(r#"{"type":"state","phase":"running","tags":["tag:silo"]}"#);
        let conn = frame(r#"{"type":"conn","listener":"http","remote":"100.64.0.2:1"}"#);
        decoder.push(&state[..3], vec![]).unwrap();
        let mut rest = state[3..].to_vec();
        rest.extend(&conn);
        decoder.push(&rest, vec![fd()]).unwrap();
        let events = decode_all(&mut decoder).unwrap();
        assert!(matches!(events[0], Event::State(_)));
        assert!(matches!(
            events[1],
            Event::Conn {
                listener: Listener::Http,
                ..
            }
        ));
        decoder.finish().unwrap();
    }

    #[test]
    fn rejects_every_malformed_case_in_the_contract() {
        let cases: Vec<(&str, Vec<u8>, usize, WireError)> = vec![
            ("zero length", vec![0, 0, 0, 0], 0, WireError::EmptyFrame),
            (
                "oversize",
                ((MAX_FRAME + 1) as u32).to_be_bytes().to_vec(),
                0,
                WireError::Oversize(MAX_FRAME + 1),
            ),
            (
                "not json",
                frame("{nope"),
                0,
                WireError::Malformed(String::new()),
            ),
            (
                "not an object",
                frame("[1]"),
                0,
                WireError::Malformed(String::new()),
            ),
            (
                "missing type",
                frame(r#"{"phase":"running"}"#),
                0,
                WireError::Malformed(String::new()),
            ),
            (
                "non-string type",
                frame(r#"{"type":5}"#),
                0,
                WireError::Malformed(String::new()),
            ),
            (
                "unknown type",
                frame(r#"{"type":"bootstrap"}"#),
                0,
                WireError::Malformed(String::new()),
            ),
            (
                "bad listener",
                frame(r#"{"type":"conn","listener":"ftp","remote":"1.2.3.4:5"}"#),
                1,
                WireError::Malformed(String::new()),
            ),
            (
                "conn without fd",
                frame(r#"{"type":"conn","listener":"ssh","remote":"1.2.3.4:5"}"#),
                0,
                WireError::MissingFd,
            ),
            (
                "fd on a state frame",
                frame(r#"{"type":"state","phase":"starting"}"#),
                1,
                WireError::UnexpectedFd,
            ),
            (
                "reply with nothing",
                frame(r#"{"type":"reply","id":4}"#),
                0,
                WireError::InvalidReply(4),
            ),
            (
                "reply with two bodies",
                frame(r#"{"type":"reply","id":5,"error":"x","status":{"phase":"running"}}"#),
                0,
                WireError::InvalidReply(5),
            ),
        ];
        for (name, bytes, fds, expected) in cases {
            let mut decoder = Decoder::default();
            decoder
                .push(&bytes, (0..fds).map(|_| fd()).collect())
                .unwrap();
            let error = decode_all(&mut decoder).expect_err(name);
            match (&error, &expected) {
                (WireError::Malformed(_), WireError::Malformed(_)) => {}
                _ => assert_eq!(error, expected, "{name}"),
            }
        }
    }

    #[test]
    fn rejects_two_fds_in_one_control_message_and_truncation_at_eof() {
        let mut decoder = Decoder::default();
        assert_eq!(
            decoder.push(b"", vec![fd(), fd()]).unwrap_err(),
            WireError::TooManyFds(2)
        );
        for cut in [2, 6] {
            let mut decoder = Decoder::default();
            let bytes = frame(r#"{"type":"state","phase":"starting"}"#);
            decoder.push(&bytes[..cut], vec![]).unwrap();
            assert!(decoder.next().unwrap().is_none());
            assert_eq!(decoder.finish().unwrap_err(), WireError::Truncated);
        }
        let mut decoder = Decoder::default();
        decoder.push(b"", vec![fd()]).unwrap();
        assert_eq!(decoder.finish().unwrap_err(), WireError::UnexpectedFd);
    }
}
