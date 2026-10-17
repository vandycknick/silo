//! Run-scoped provider contract. Transport payload v1 embeds provider config v2.
use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{MachineScopeId, SecretError, SecretField, SecretName, SecretScope};

pub const MAX_BODY: usize = 1 << 20;
pub const MAX_HEADER: usize = 128;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretGrant {
    pub version: u8,
    pub store: String,
    pub machine: MachineScopeId,
    pub run: String,
    pub issued_at: DateTime<Utc>,
    pub allowed: Vec<AllowedSecret>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowedSecret {
    pub slot: SecretName,
    pub key: SecretName,
    pub field: SecretField,
    pub backing_scope: SecretScope,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestScope {
    pub machine: MachineScopeId,
    pub run: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderRequest {
    pub version: u8,
    pub operation: String,
    pub grant: String,
    pub scope: RequestScope,
    pub names: Vec<SecretName>,
    pub reason: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectedSecret {
    pub name: SecretName,
    pub value: String,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "lowercase", deny_unknown_fields)]
pub enum ProviderResponse {
    Ok {
        version: u8,
        secrets: Vec<ProjectedSecret>,
    },
    Error {
        version: u8,
        error: ProviderError,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderError {
    pub code: String,
    pub message: String,
    pub retryable: bool,
}

pub fn file_identity(path: &Path) -> Result<String, SecretError> {
    if !path.is_absolute() {
        return Err(SecretError::InvalidRequest(
            "provider store path must be absolute".into(),
        ));
    }
    let path = path
        .to_str()
        .ok_or_else(|| SecretError::InvalidRequest("store path must be UTF-8".into()))?;
    Ok(format!("file:{path}"))
}

impl SecretGrant {
    pub fn issue(
        store: &Path,
        machine: MachineScopeId,
        run: String,
        allowed: Vec<AllowedSecret>,
    ) -> Result<Self, SecretError> {
        Ok(Self {
            version: 2,
            store: file_identity(store)?,
            machine,
            run,
            issued_at: Utc::now(),
            allowed,
        })
    }
    /// Validate the whole grant and request before opening a store or taking locks.
    pub fn authorize<'a>(
        &'a self,
        store: &Path,
        request: &ProviderRequest,
    ) -> Result<Vec<&'a AllowedSecret>, SecretError> {
        let denied =
            || SecretError::Unauthorized("provider grant does not authorize this request".into());
        if self.version != 2
            || self.store != file_identity(store)?
            || self.run.is_empty()
            || self.machine != request.scope.machine
            || self.run != request.scope.run
        {
            return Err(denied());
        }
        let mut slots = BTreeSet::new();
        for allowed in &self.allowed {
            if !slots.insert(allowed.slot.as_str())
                || allowed.slot.as_str().starts_with("silo.")
                || allowed.key.as_str().starts_with("silo.")
                || allowed.field == SecretField::Value
                || matches!(&allowed.backing_scope, SecretScope::Machine { id } if id != &self.machine)
            {
                return Err(denied());
            }
        }
        let mut names = BTreeSet::new();
        if request.names.is_empty() {
            return Err(denied());
        }
        request
            .names
            .iter()
            .map(|name| {
                if !names.insert(name.as_str()) {
                    return Err(denied());
                }
                self.allowed
                    .iter()
                    .find(|entry| &entry.slot == name)
                    .ok_or_else(denied)
            })
            .collect()
    }
}

pub fn read_json_frame<R: Read, T: for<'de> Deserialize<'de>>(
    mut reader: R,
) -> Result<T, SecretError> {
    let invalid = || SecretError::InvalidRequest("invalid Content-Length frame".into());
    let mut header = Vec::with_capacity(MAX_HEADER);
    while !header.ends_with(b"\r\n\r\n") {
        if header.len() == MAX_HEADER {
            return Err(invalid());
        }
        let mut byte = [0];
        reader.read_exact(&mut byte)?;
        header.push(byte[0]);
    }
    let digits = header
        .strip_prefix(b"Content-Length: ")
        .and_then(|s| s.strip_suffix(b"\r\n\r\n"))
        .ok_or_else(invalid)?;
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return Err(invalid());
    }
    let length = std::str::from_utf8(digits)
        .map_err(|_| invalid())?
        .parse::<usize>()
        .map_err(|_| invalid())?;
    if length > MAX_BODY {
        return Err(invalid());
    }
    let mut body = Zeroizing::new(vec![0; length]);
    reader.read_exact(&mut body)?;
    let mut trailing = [0];
    if reader.read(&mut trailing)? != 0 {
        return Err(invalid());
    }
    Ok(serde_json::from_slice(&body)?)
}

pub fn write_json_frame<W: Write, T: Serialize>(
    mut writer: W,
    value: &T,
) -> Result<(), SecretError> {
    let mut body = BoundedBody(Zeroizing::new(Vec::with_capacity(MAX_BODY)));
    serde_json::to_writer(&mut body, value)?;
    write!(writer, "Content-Length: {}\r\n\r\n", body.0.len())?;
    writer.write_all(&body.0)?;
    writer.flush()?;
    Ok(())
}

struct BoundedBody(Zeroizing<Vec<u8>>);
impl Write for BoundedBody {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > MAX_BODY.saturating_sub(self.0.len()) {
            return Err(std::io::Error::other("provider body exceeds 1 MiB"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::grant::*;

    #[test]
    fn grant_round_trip_and_strict_frames() {
        let grant = SecretGrant {
            version: 2,
            store: "file:/tmp/secrets.json".into(),
            machine: MachineScopeId::new("0123456789abcdef0123456789abcdef").unwrap(),
            run: "run".into(),
            issued_at: Utc::now(),
            allowed: vec![AllowedSecret {
                slot: SecretName::new("codex.oauth.access_token").unwrap(),
                key: SecretName::new("openai_codex_oauth.codex.oauth").unwrap(),
                field: SecretField::OAuthAccessToken,
                backing_scope: SecretScope::Home,
            }],
        };
        let mut frame = Vec::new();
        write_json_frame(&mut frame, &grant).unwrap();
        let decoded: SecretGrant = read_json_frame(frame.as_slice()).unwrap();
        assert_eq!(decoded.store, grant.store);
        assert_eq!(decoded.allowed[0].backing_scope, SecretScope::Home);
        for bad in [
            b"\r\n\r\n".as_slice(),
            b"Content-Length: 1048577\r\n\r\n",
            b"Content-Length: 9999999999999999999999999999999\r\n\r\n",
            b"Content-Length: -1\r\n\r\n",
            b"Content-Length: 2\r\n\r\n{",
            b"Content-Length: 2\r\nOther: x\r\n\r\n{}",
            b"Content-Length: 2\r\n\r\n{}x",
        ] {
            assert!(read_json_frame::<_, SecretGrant>(bad).is_err());
        }
        assert!(read_json_frame::<_, SecretGrant>(vec![b'x'; 129].as_slice()).is_err());
        for body in [
            r#"{"version":2,"unknown":true}"#,
            r#"{"version":2,"version":2}"#,
        ] {
            let frame = format!("Content-Length: {}\r\n\r\n{body}", body.len());
            assert!(read_json_frame::<_, SecretGrant>(frame.as_bytes()).is_err());
        }
    }
}
