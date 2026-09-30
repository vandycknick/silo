use std::io::{self, Write};
use std::os::fd::OwnedFd;
use std::process::Command;
use std::time::{Duration, Instant};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Serialize, Serializer};
use silo_policy::NetworkPolicy;
use zeroize::Zeroizing;

use crate::secrets::ResolvedSecrets;
use crate::LibVmError;

const JSON_LIMIT: usize = 16384;
const HEADER_LIMIT: usize = 128;

struct Base64Bytes<'a>(&'a [u8]);

impl Serialize for Base64Bytes<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let length = base64::encoded_len(self.0.len(), true)
            .ok_or_else(|| serde::ser::Error::custom("secret encoding exceeds limit"))?;
        if length > JSON_LIMIT {
            return Err(serde::ser::Error::custom(format!(
                "secret encoding size {length} exceeds limit {JSON_LIMIT}"
            )));
        }
        let mut encoded = Zeroizing::new(vec![0u8; length]);
        STANDARD
            .encode_slice(self.0, &mut encoded)
            .map_err(serde::ser::Error::custom)?;
        let encoded = std::str::from_utf8(&encoded).map_err(serde::ser::Error::custom)?;
        serializer.serialize_str(encoded)
    }
}

#[derive(Serialize)]
struct Secret<'a> {
    name: &'a str,
    value: Base64Bytes<'a>,
}

#[derive(Serialize)]
struct Provider<'a> {
    version: u8,
    command: &'a str,
    args: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    timeout_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_skew_seconds: Option<u64>,
    grant: Base64Bytes<'a>,
}

#[derive(Serialize)]
struct Payload<'a> {
    version: u8,
    secrets: Vec<Secret<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    provider: Option<Provider<'a>>,
}

struct BoundedJson(Zeroizing<Vec<u8>>);

impl Write for BoundedJson {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > JSON_LIMIT.saturating_sub(self.0.len()) {
            return Err(io::Error::other(format!(
                "netd secret JSON size at least {} exceeds limit {JSON_LIMIT}",
                self.0.len().saturating_add(bytes.len())
            )));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(crate) fn frame(
    launch: &ResolvedSecrets,
    policy: Option<&NetworkPolicy>,
    reference: &str,
) -> Result<Zeroizing<Vec<u8>>, LibVmError> {
    launch.validate_for_policy(policy, reference)?;
    let provider = launch
        .oauth_refresh_hook
        .as_ref()
        .map(|hook| {
            let command = hook
                .command
                .to_str()
                .ok_or_else(|| LibVmError::NetworkRuntime {
                    reference: reference.into(),
                    message: "OAuth refresh hook command must be valid UTF-8".into(),
                })?;
            Ok::<_, LibVmError>(Provider {
                version: 1,
                command,
                args: &hook.args,
                timeout_ms: hook.timeout_ms,
                refresh_skew_seconds: hook.refresh_skew_seconds,
                grant: Base64Bytes(&hook.auth),
            })
        })
        .transpose()?;
    let payload = Payload {
        version: 1,
        secrets: launch
            .secrets
            .iter()
            .map(|secret| Secret {
                name: &secret.slot,
                value: Base64Bytes(&secret.value),
            })
            .collect(),
        provider,
    };
    // Fixed capacities avoid reallocations leaving secret copies in freed memory.
    let mut json = BoundedJson(Zeroizing::new(Vec::with_capacity(JSON_LIMIT)));
    serde_json::to_writer(&mut json, &payload).map_err(|error| LibVmError::NetworkRuntime {
        reference: reference.into(),
        message: format!("serialize netd secret payload: {error}"),
    })?;
    let mut frame = Zeroizing::new(Vec::with_capacity(JSON_LIMIT + HEADER_LIMIT));
    write!(&mut *frame, "Content-Length: {}\r\n\r\n", json.0.len())?;
    frame.extend_from_slice(&json.0);
    Ok(frame)
}

pub(crate) fn strip_environment(command: &mut Command) {
    for (name, _) in std::env::vars_os() {
        if name.as_encoded_bytes().starts_with(b"SILO_NET_") {
            command.env_remove(name);
        }
    }
}

/// Own the writer across awaits so success, error and cancellation all send EOF.
pub(crate) async fn write_frame(
    writer: OwnedFd,
    frame: Zeroizing<Vec<u8>>,
    deadline: Instant,
) -> Result<(), String> {
    nix::fcntl::fcntl(
        &writer,
        nix::fcntl::FcntlArg::F_SETFL(nix::fcntl::OFlag::O_NONBLOCK),
    )
    .map_err(|error| format!("configure netd secret writer: {error}"))?;
    let mut offset = 0;
    while offset < frame.len() {
        if Instant::now() >= deadline {
            return Err("timed out writing netd secret payload".into());
        }
        match nix::unistd::write(&writer, &frame[offset..]) {
            Ok(0) => return Err("netd secret writer made no progress".into()),
            Ok(count) => offset += count,
            Err(nix::errno::Errno::EINTR) => continue,
            Err(nix::errno::Errno::EAGAIN) => {
                tokio::time::sleep(
                    Duration::from_millis(5)
                        .min(deadline.saturating_duration_since(Instant::now())),
                )
                .await;
            }
            Err(error) => return Err(format!("write netd secret payload: {error}")),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Read;
    use std::os::fd::OwnedFd;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use silo_policy::NetworkPolicy;
    use zeroize::Zeroizing;

    use crate::machine::{EgressCredentials, V1RefreshProvider};
    use crate::network::secret_transport::{frame, strip_environment, write_frame, JSON_LIMIT};

    fn policy() -> NetworkPolicy {
        NetworkPolicy::from_json_str(r#"{"version":1,"endpoints":[{"name":"api","kind":"https","family":"http","transport":"https-mitm","tls":"terminate","capabilities":["credential-injection"],"hosts":["api.example.com"]}],"credentials":[{"name":"api-key","kind":"bearer_token","endpoint":"api"},{"name":"api_key","kind":"bearer_token","endpoint":"api"},{"name":"codex","kind":"openai_codex_oauth","endpoint":"api"}]}"#).unwrap()
    }

    fn credentials() -> EgressCredentials {
        EgressCredentials::new()
            .secret_bytes("api-key.token", vec![0, 255, 128, 10])
            .secret("api_key.token", "distinct")
            .secret("codex.oauth.access_token", "token")
            .secret("codex.oauth.expires_at", "2026-09-30T00:00:00Z")
    }

    fn body(frame: &[u8]) -> serde_json::Value {
        let start = frame.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        assert!(start <= 128);
        assert_eq!(
            &frame[..start],
            format!("Content-Length: {}\r\n\r\n", frame.len() - start).as_bytes()
        );
        assert!(frame.len() - start <= JSON_LIMIT);
        serde_json::from_slice(&frame[start..]).unwrap()
    }

    #[test]
    fn payload_preserves_binary_exact_names_and_provider_defaults() {
        assert_eq!(
            body(&frame(&crate::secrets::ResolvedSecrets::default(), None, "test").unwrap()),
            serde_json::json!({"version":1,"secrets":[]})
        );
        for timing in [None, Some(0), Some(42)] {
            let mut hook = V1RefreshProvider::new("/usr/bin/silo", vec![0, 255, 128]);
            hook.timeout_ms = timing;
            hook.refresh_skew_seconds = timing;
            let payload = body(
                &frame(
                    &credentials().oauth_refresh_hook(hook),
                    Some(&policy()),
                    "test",
                )
                .unwrap(),
            );
            assert_eq!(payload["secrets"][0]["name"], "api-key.token");
            assert_eq!(payload["secrets"][1]["name"], "api_key.token");
            assert_eq!(
                STANDARD
                    .decode(payload["secrets"][0]["value"].as_str().unwrap())
                    .unwrap(),
                [0, 255, 128, 10]
            );
            assert_eq!(
                STANDARD
                    .decode(payload["provider"]["grant"].as_str().unwrap())
                    .unwrap(),
                [0, 255, 128]
            );
            assert_eq!(payload["provider"]["args"], serde_json::json!([]));
            assert_eq!(payload["provider"]["timeout_ms"].as_u64(), timing);
            assert_eq!(payload["provider"]["refresh_skew_seconds"].as_u64(), timing);
        }
    }

    #[test]
    fn payload_enforces_cap_and_validation() {
        let policy = policy();
        let mut launch = credentials();
        launch.secrets[0].value = vec![1; JSON_LIMIT];
        assert!(frame(&launch.into(), Some(&policy), "test").is_err());
        let mut launch: crate::secrets::ResolvedSecrets = credentials().into();
        launch.oauth_refresh_hook = Some(V1RefreshProvider::new("/bin/true", vec![1; JSON_LIMIT]));
        assert!(frame(&launch, Some(&policy), "test").is_err());
        assert!(frame(
            &credentials().secret("api-key.token", "duplicate").into(),
            Some(&policy),
            "test"
        )
        .is_err());
        assert!(frame(
            &credentials().secret("unknown", "unknown").into(),
            Some(&policy),
            "test"
        )
        .is_err());
        assert!(frame(&credentials().into(), None, "test").is_err());
        // Find the exact last accepted size, including provider metadata and JSON escaping.
        let mut launch = credentials()
            .oauth_refresh_hook(V1RefreshProvider::new("/bin/true", b"grant".to_vec()));
        let mut last = 0;
        for size in 11000..12500 {
            launch.credentials.secrets[0].value.resize(size, 1);
            if let Ok(bytes) = frame(&launch, Some(&policy), "test") {
                last = size;
                body(&bytes);
            } else {
                assert!(last > 0);
                assert_eq!(size, last + 1);
                break;
            }
        }
        assert!(last > 0);
    }

    fn pipe() -> (std::io::PipeReader, OwnedFd) {
        let (reader, writer) = std::io::pipe().unwrap();
        let writer = OwnedFd::from(writer);
        #[cfg(target_os = "linux")]
        nix::fcntl::fcntl(&writer, nix::fcntl::FcntlArg::F_SETPIPE_SZ(4096)).unwrap();
        (reader, writer)
    }

    #[tokio::test]
    async fn real_slow_reader_handles_partial_writes_and_eof() {
        let (reader, writer) = pipe();
        let mut command = Command::new("/usr/bin/python3");
        command.args(["-c", "import os,time\nwhile True:\n b=os.read(0,127)\n if not b: break\n os.write(1,b)\n time.sleep(.001)"]);
        strip_environment(&mut command);
        let mut child = command
            .stdin(reader)
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        // Drain output concurrently so this test does not invent a second pipe deadlock.
        let mut output = child.stdout.take().unwrap();
        let drain = std::thread::spawn(move || {
            let mut bytes = Vec::new();
            output.read_to_end(&mut bytes).unwrap();
            bytes
        });
        let expected = vec![b'x'; 16000];
        write_frame(
            writer,
            Zeroizing::new(expected.clone()),
            Instant::now() + Duration::from_secs(3),
        )
        .await
        .unwrap();
        assert!(child.wait().unwrap().success());
        assert_eq!(drain.join().unwrap(), expected);
    }

    #[tokio::test]
    async fn real_closed_reader_reports_epipe() {
        let (reader, writer) = pipe();
        let mut child = Command::new("/bin/true").stdin(reader).spawn().unwrap();
        assert!(child.wait().unwrap().success());
        let error = write_frame(
            writer,
            Zeroizing::new(vec![1; 16000]),
            Instant::now() + Duration::from_secs(1),
        )
        .await
        .unwrap_err();
        assert!(error.contains("EPIPE"), "{error}");
    }

    #[tokio::test]
    async fn real_stalled_reader_times_out_and_cancellation_closes_writer() {
        for cancel in [false, true] {
            let (reader, writer) = pipe();
            let mut child = Command::new("/usr/bin/python3")
                .args([
                    "-c",
                    "import os,time\ntime.sleep(.15)\nwhile os.read(0,4096): pass",
                ])
                .stdin(reader)
                .spawn()
                .unwrap();
            let start = Instant::now();
            let future = write_frame(
                writer,
                Zeroizing::new(vec![1; 128 * 1024]),
                start + Duration::from_millis(40),
            );
            if cancel {
                assert!(tokio::time::timeout(Duration::from_millis(20), future)
                    .await
                    .is_err());
            } else {
                assert!(future.await.unwrap_err().contains("timed out"));
            }
            assert!(start.elapsed() < Duration::from_millis(120));
            // The delayed reader must observe EOF without killing it.
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                if let Some(status) = child.try_wait().unwrap() {
                    assert!(status.success());
                    break;
                }
                if Instant::now() >= deadline {
                    child.kill().unwrap();
                    child.wait().unwrap();
                    panic!("writer was retained after timeout/cancellation");
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
    }
}
