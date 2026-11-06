//! Candidate-only transport from the restore IRQ acceptance gate to this run's
//! native AP2 hardware IRQ witness. Compiled only with `restore-irq-probe` on
//! Linux x86_64: a normal worker has no endpoint, thread or state.
//!
//! ```text
//!  gate ──connect "\0silo-irq-probe/<machine>/<run>"──► accept (SO_PEERCRED uid == euid)
//!       ──one JSON line (≤128 KiB, 5 s)──► lifecycle journal admission
//!                                              │ fresh native operation
//!                                              ▼
//!                                        native irq_probe (5 s)
//!       ◄──one JSON line: ok | refused | failed── then close
//! ```
//!
//! Source construction runs only under the run's published User pause and
//! never on a restored run. Guest command words are written only into a
//! running machine that no pause, capture or unexposed restore owns. The
//! transport grants nothing: it neither pauses, resumes, captures nor
//! activates, so every generation/Activate/Thaw/exposure barrier stays with
//! the ordinary lifecycle.

use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine as _;
use libkrun::live::irq_probe::{Fixture, ProbeCommand, ProbeObservation, ProbeRequest};
use uuid::Uuid;

use crate::krun::worker::lifecycle::{Binding, ProbeRefusal, Shared};
use crate::krun::worker::native::KrunNative;
use crate::virt::lifecycle::NativeFailure;

/// Whole request line, newline included. Bounds a base64 fixture of at most
/// 0x3000 code bytes plus a symbol table of at most 64 KiB.
const MAX_REQUEST: usize = 128 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const NATIVE_TIMEOUT: Duration = Duration::from_secs(5);
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
const ACCEPT_RETRY: Duration = Duration::from_millis(100);
const BACKLOG: i32 = 4;

/// The run's abstract socket name, without the leading NUL.
fn endpoint_name(binding: Binding) -> String {
    format!(
        "silo-irq-probe/{}/{}",
        binding.machine_id.hyphenated(),
        binding.run_id.hyphenated()
    )
}

/// Bind this run's endpoint and serve it on a dedicated thread for the
/// process lifetime. A second worker of the same run cannot bind it.
pub(crate) fn serve(lifecycle: Arc<Shared<KrunNative>>, binding: Binding) -> io::Result<()> {
    let listener = listen(binding)?;
    let identity = Identity {
        pid: std::process::id(),
        machine_id: binding.machine_id,
        run_id: binding.run_id,
    };
    std::thread::Builder::new()
        .name("krun-irq-probe".to_string())
        .spawn(move || {
            accept_loop(&listener, identity, |request, deadline| {
                dispatch(&lifecycle, request, deadline)
            })
        })
        .map(drop)
}

fn listen(binding: Binding) -> io::Result<UnixListener> {
    use nix::sys::socket::{
        bind, listen, socket, AddressFamily, Backlog, SockFlag, SockType, UnixAddr,
    };
    let socket = socket(
        AddressFamily::Unix,
        SockType::Stream,
        SockFlag::SOCK_CLOEXEC,
        None,
    )?;
    bind(
        socket.as_raw_fd(),
        &UnixAddr::new_abstract(endpoint_name(binding).as_bytes())?,
    )?;
    listen(&socket, Backlog::new(BACKLOG)?)?;
    Ok(UnixListener::from(socket))
}

/// Connections are served strictly one at a time; each is bounded by the
/// request, native and write deadlines.
fn accept_loop(
    listener: &UnixListener,
    identity: Identity,
    dispatch: impl Fn(Request, Instant) -> Outcome,
) {
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                if let Err(error) = connection(stream, identity, &dispatch) {
                    eprintln!("krun irq probe connection failed: {error}");
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => {
                eprintln!("krun irq probe accept failed: {error}");
                std::thread::sleep(ACCEPT_RETRY);
            }
        }
    }
}

fn connection(
    mut stream: UnixStream,
    identity: Identity,
    dispatch: &impl Fn(Request, Instant) -> Outcome,
) -> io::Result<()> {
    let peer = nix::sys::socket::getsockopt(&stream, nix::sys::socket::sockopt::PeerCredentials)?;
    if peer.uid() != nix::unistd::geteuid().as_raw() {
        // Closed without a reply: a foreign user learns nothing of this run.
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "irq probe peer is not the worker's user",
        ));
    }
    stream.set_write_timeout(Some(WRITE_TIMEOUT))?;
    let outcome = match read_frame(&mut stream, Instant::now() + REQUEST_TIMEOUT)
        .and_then(|frame| parse(&frame))
    {
        Ok(request) => dispatch(request, Instant::now() + NATIVE_TIMEOUT),
        Err(detail) => Outcome::Refused {
            reason: Reason::Malformed,
            detail: Some(detail),
        },
    };
    let mut bytes =
        serde_json::to_vec(&Response { identity, outcome }).map_err(io::Error::other)?;
    bytes.push(b'\n');
    stream.write_all(&bytes)
}

/// Exactly one newline-terminated request within the deadline and bound.
fn read_frame(stream: &mut UnixStream, deadline: Instant) -> Result<Vec<u8>, String> {
    let mut frame = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("request deadline elapsed".into());
        }
        stream
            .set_read_timeout(Some(remaining))
            .map_err(|error| error.to_string())?;
        match stream.read(&mut chunk) {
            Ok(0) => return Err("request ended before its newline".into()),
            Ok(count) => {
                frame.extend_from_slice(&chunk[..count]);
                if let Some(end) = frame.iter().position(|byte| *byte == b'\n') {
                    if end >= MAX_REQUEST {
                        return Err("request exceeds its bound".into());
                    }
                    if end + 1 != frame.len() {
                        return Err("one request per connection".into());
                    }
                    frame.truncate(end);
                    return Ok(frame);
                }
                if frame.len() >= MAX_REQUEST {
                    return Err("request exceeds its bound".into());
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                return Err("request deadline elapsed".into())
            }
            Err(error) => return Err(error.to_string()),
        }
    }
}

fn parse(frame: &[u8]) -> Result<Request, String> {
    if frame
        .iter()
        .copied()
        .find(|byte| !byte.is_ascii_whitespace())
        != Some(b'{')
    {
        return Err("irq probe request must be a JSON object".into());
    }
    serde_json::from_slice(frame).map_err(|error| format!("invalid irq probe request: {error}"))
}

fn fixture(code: &str, symbols: String) -> Result<Fixture, String> {
    let code = base64::engine::general_purpose::STANDARD
        .decode(code)
        .map_err(|_| "fixture code is not standard base64".to_string())?;
    Fixture::new(code, symbols)
}

fn dispatch(lifecycle: &Shared<KrunNative>, request: Request, deadline: Instant) -> Outcome {
    let result = match request {
        Request::Initialize { code, symbols } => {
            let fixture = match fixture(&code, symbols) {
                Ok(fixture) => fixture,
                Err(detail) => {
                    return Outcome::Refused {
                        reason: Reason::Fixture,
                        detail: Some(detail),
                    }
                }
            };
            lifecycle.probe_source(|native, token, operation| {
                native.irq_probe(
                    ProbeRequest::Initialize {
                        pause: token.clone(),
                        fixture,
                    },
                    operation,
                    deadline,
                )
            })
        }
        Request::Command { command } => lifecycle.probe_running(|native, operation| {
            native.irq_probe(ProbeRequest::Command(command.into()), operation, deadline)
        }),
        Request::Observe {} => lifecycle.probe_observe(|native, operation| {
            native.irq_probe(ProbeRequest::Observe, operation, deadline)
        }),
    };
    match result {
        Ok(Ok(observation)) => Outcome::Ok {
            observation: observation.into(),
        },
        Ok(Err(native)) => Outcome::Failed { native },
        Err(refusal) => Outcome::Refused {
            reason: refusal.into(),
            detail: None,
        },
    }
}

#[derive(Debug, PartialEq, Eq, serde::Deserialize)]
#[serde(tag = "request", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    /// Source construction from the assembled witness and its `nm` table.
    Initialize {
        code: String,
        symbols: String,
    },
    Command {
        command: GuestCommand,
    },
    Observe {},
}

/// The existing guest witness command words; nothing else is writable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum GuestCommand {
    Pending,
    Reset,
    Accept,
    Unmask,
}

impl From<GuestCommand> for ProbeCommand {
    fn from(command: GuestCommand) -> Self {
        match command {
            GuestCommand::Pending => Self::Pending,
            GuestCommand::Reset => Self::Reset,
            GuestCommand::Accept => Self::Accept,
            GuestCommand::Unmask => Self::Unmask,
        }
    }
}

#[derive(Debug, Clone, Copy, serde::Serialize)]
struct Identity {
    pid: u32,
    machine_id: Uuid,
    run_id: Uuid,
}

#[derive(Debug, serde::Serialize)]
struct Response {
    #[serde(flatten)]
    identity: Identity,
    #[serde(flatten)]
    outcome: Outcome,
}

#[derive(Debug, serde::Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum Outcome {
    Ok {
        observation: Observation,
    },
    /// Nothing native ran.
    Refused {
        reason: Reason,
        detail: Option<String>,
    },
    /// The native call was admitted and failed; it may have taken effect.
    Failed {
        native: NativeFailure,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum Reason {
    Malformed,
    Fixture,
    Restored,
    NotPaused,
    Busy,
    NotRunning,
    Exhausted,
}

impl From<ProbeRefusal> for Reason {
    fn from(refusal: ProbeRefusal) -> Self {
        match refusal {
            ProbeRefusal::Restored => Self::Restored,
            ProbeRefusal::NotPaused => Self::NotPaused,
            ProbeRefusal::Busy => Self::Busy,
            ProbeRefusal::NotRunning => Self::NotRunning,
            ProbeRefusal::Exhausted => Self::Exhausted,
        }
    }
}

/// Actual owner RAM words and retained native AP2 vector state; `None` where
/// no native cut is retained.
#[derive(Debug, PartialEq, Eq, serde::Serialize)]
struct Observation {
    words: [u64; 23],
    irq_publication: [u64; 2],
    pending: Option<bool>,
    in_service: Option<bool>,
    deadline: Option<u64>,
}

impl From<ProbeObservation> for Observation {
    fn from(observation: ProbeObservation) -> Self {
        Self {
            words: observation.words,
            irq_publication: observation.irq_publication,
            pending: observation.pending,
            in_service: observation.in_service,
            deadline: observation.deadline,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::time::{Duration, Instant};

    use libkrun::live::irq_probe::ProbeObservation;
    use uuid::Uuid;

    use crate::krun::worker::irq_probe::{
        accept_loop, endpoint_name, fixture, listen, parse, read_frame, GuestCommand, Identity,
        Observation, Outcome, Reason, Request, Response, MAX_REQUEST,
    };
    use crate::krun::worker::lifecycle::Binding;
    use crate::virt::lifecycle::{NativeFailure, NativeFailureKind};

    fn binding() -> Binding {
        Binding {
            machine_id: Uuid::new_v4(),
            run_id: Uuid::new_v4(),
        }
    }

    fn connect(binding: Binding) -> UnixStream {
        use std::os::linux::net::SocketAddrExt;
        use std::os::unix::net::SocketAddr;
        let address =
            SocketAddr::from_abstract_name(endpoint_name(binding).as_bytes()).expect("address");
        UnixStream::connect_addr(&address).expect("connect")
    }

    fn json(response: &Response) -> serde_json::Value {
        serde_json::to_value(response).expect("serialize")
    }

    #[test]
    fn endpoint_is_the_exact_run_identity_within_the_abstract_bound() {
        let binding = Binding {
            machine_id: Uuid::parse_str("6f0c1f0e-9a51-4c47-8d3c-0c6b3c1e2a10").expect("uuid"),
            run_id: Uuid::parse_str("0b6f5f9d-2b33-4f7e-a1f2-9a3c5d7e8f01").expect("uuid"),
        };
        let name = endpoint_name(binding);
        assert_eq!(
            name,
            "silo-irq-probe/6f0c1f0e-9a51-4c47-8d3c-0c6b3c1e2a10/0b6f5f9d-2b33-4f7e-a1f2-9a3c5d7e8f01"
        );
        // sun_path minus the leading abstract NUL.
        assert!(name.len() <= 107);
    }

    #[test]
    fn requests_are_closed_and_strict() {
        assert_eq!(
            parse(br#"{"request":"initialize","code":"AA==","symbols":"x"}"#),
            Ok(Request::Initialize {
                code: "AA==".into(),
                symbols: "x".into()
            })
        );
        for (word, command) in [
            ("pending", GuestCommand::Pending),
            ("reset", GuestCommand::Reset),
            ("accept", GuestCommand::Accept),
            ("unmask", GuestCommand::Unmask),
        ] {
            assert_eq!(
                parse(format!(r#"{{"request":"command","command":"{word}"}}"#).as_bytes()),
                Ok(Request::Command { command })
            );
        }
        assert_eq!(parse(br#"{"request":"observe"}"#), Ok(Request::Observe {}));
        for invalid in [
            &br#"{"request":"observe","operation":1}"#[..],
            br#"{"request":"command","command":"arm-13"}"#,
            br#"{"request":"command","command":"accept","case":2}"#,
            br#"{"request":"command"}"#,
            br#"{"request":"initialize","code":"AA=="}"#,
            br#"{"request":"pause"}"#,
            br#"{"command":"accept"}"#,
            br#"["observe"]"#,
            b"observe",
            b"",
        ] {
            assert!(
                parse(invalid).is_err(),
                "{}",
                String::from_utf8_lossy(invalid)
            );
        }
    }

    #[test]
    fn fixture_code_must_be_standard_base64_and_a_valid_native_fixture() {
        assert_eq!(
            fixture("not base64!", String::new()).err(),
            Some("fixture code is not standard base64".to_string())
        );
        assert!(fixture("", String::new()).is_err(), "empty code");
        assert!(
            fixture("AAAA", "1c001000 T _start\n".into()).is_err(),
            "native refuses missing witness symbols"
        );
    }

    #[test]
    fn a_frame_is_exactly_one_bounded_newline_terminated_request() {
        let far = || Instant::now() + Duration::from_secs(5);
        let (mut client, mut server) = UnixStream::pair().expect("pair");
        client
            .write_all(b"{\"request\":\"observe\"}\n")
            .expect("write");
        assert_eq!(
            read_frame(&mut server, far()),
            Ok(b"{\"request\":\"observe\"}".to_vec())
        );

        let (mut client, mut server) = UnixStream::pair().expect("pair");
        client
            .write_all(b"{\"request\":\"observe\"}")
            .expect("write");
        drop(client);
        assert!(
            read_frame(&mut server, far()).is_err(),
            "EOF before newline"
        );

        let (mut client, mut server) = UnixStream::pair().expect("pair");
        client
            .write_all(b"{\"request\":\"observe\"}\n{\"request\":\"observe\"}\n")
            .expect("write");
        assert_eq!(
            read_frame(&mut server, far()),
            Err("one request per connection".to_string())
        );

        let (client, mut server) = UnixStream::pair().expect("pair");
        let writer = std::thread::spawn(move || {
            let mut client = client;
            let _ = client.write_all(&vec![b' '; MAX_REQUEST]);
            let _ = client.write_all(b"\n");
        });
        assert_eq!(
            read_frame(&mut server, far()),
            Err("request exceeds its bound".to_string())
        );
        drop(server);
        writer.join().expect("writer");

        let (_client, mut server) = UnixStream::pair().expect("pair");
        let started = Instant::now();
        assert_eq!(
            read_frame(&mut server, Instant::now() + Duration::from_millis(50)),
            Err("request deadline elapsed".to_string())
        );
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn the_run_endpoint_is_unique_and_malformed_requests_never_reach_native() {
        let binding = binding();
        let listener = listen(binding).expect("listen");
        assert!(
            listen(binding).is_err(),
            "a second owner of the run endpoint"
        );
        let identity = Identity {
            pid: std::process::id(),
            machine_id: binding.machine_id,
            run_id: binding.run_id,
        };
        std::thread::spawn(move || {
            accept_loop(&listener, identity, |_, _| {
                unreachable!("malformed requests never reach native")
            })
        });
        for request in [&b"observe\n"[..], b"{\"request\":\"observe\",\"x\":1}\n"] {
            let mut stream = connect(binding);
            stream.write_all(request).expect("request");
            let mut reply = String::new();
            stream.read_to_string(&mut reply).expect("reply");
            assert!(reply.ends_with('\n') && reply.matches('\n').count() == 1);
            let reply: serde_json::Value = serde_json::from_str(&reply).expect("json");
            assert_eq!(reply["status"], "refused");
            assert_eq!(reply["reason"], "malformed");
            assert_eq!(reply["pid"], std::process::id());
            assert_eq!(reply["machine_id"], binding.machine_id.to_string());
            assert_eq!(reply["run_id"], binding.run_id.to_string());
        }
    }

    #[test]
    fn responses_carry_identity_and_one_closed_outcome() {
        let identity = Identity {
            pid: 7,
            machine_id: Uuid::new_v4(),
            run_id: Uuid::new_v4(),
        };
        let mut words = [0u64; 23];
        words[0] = 0x53494c4f;
        words[8] = 1;
        let observed = json(&Response {
            identity,
            outcome: Outcome::Ok {
                observation: Observation::from(ProbeObservation {
                    words,
                    irq_publication: [4, 4],
                    pending: Some(true),
                    in_service: Some(false),
                    deadline: None,
                }),
            },
        });
        assert_eq!(
            observed,
            serde_json::json!({
                "pid": 7,
                "machine_id": identity.machine_id.to_string(),
                "run_id": identity.run_id.to_string(),
                "status": "ok",
                "observation": {
                    "words": words,
                    "irq_publication": [4, 4],
                    "pending": true,
                    "in_service": false,
                    "deadline": null,
                },
            })
        );
        let refused = json(&Response {
            identity,
            outcome: Outcome::Refused {
                reason: Reason::NotPaused,
                detail: None,
            },
        });
        assert_eq!(refused["status"], "refused");
        assert_eq!(refused["reason"], "not_paused");
        let failed = json(&Response {
            identity,
            outcome: Outcome::Failed {
                native: NativeFailure::with_detail(NativeFailureKind::Participant, "AP2 started"),
            },
        });
        assert_eq!(failed["status"], "failed");
        assert_eq!(failed["native"]["detail"], "AP2 started");
    }
}
