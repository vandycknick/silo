//! Typed, scoped secrets with a legacy-compatible, transactional file store.
use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::Zeroizing;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct SecretName(String);

impl SecretName {
    pub fn new(name: impl Into<String>) -> Result<Self, SecretError> {
        let name = name.into();
        if name.is_empty() {
            return Err(SecretError::InvalidRequest(
                "secret name cannot be empty".into(),
            ));
        }
        if name.split('.').any(str::is_empty) {
            return Err(SecretError::InvalidRequest(format!(
                "secret name `{name}` is not allowed"
            )));
        }
        if !name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
        {
            return Err(SecretError::InvalidRequest(format!("secret name `{name}` may only contain ASCII letters, numbers, dots, underscores, and dashes")));
        }
        Ok(Self(name))
    }

    /// Explicit compatibility address for reading/removing an existing record.
    /// `put` revalidates names, so this cannot create new legacy keys.
    pub fn legacy(name: impl Into<String>) -> Self {
        Self(name.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for SecretName {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Self::new(String::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct MachineScopeId(String);

impl MachineScopeId {
    pub fn new(id: impl Into<String>) -> Result<Self, SecretError> {
        let id = id.into();
        if id.len() != 32
            || !id
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            return Err(SecretError::InvalidRequest(
                "machine scope id must be 32 lowercase hex characters".into(),
            ));
        }
        Ok(Self(id))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for MachineScopeId {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Self::new(String::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecretScope {
    Home,
    Machine { id: MachineScopeId },
}

#[derive(Clone, PartialEq, Eq)]
pub struct SecretBytes(Zeroizing<Vec<u8>>);

impl SecretBytes {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(Zeroizing::new(bytes.into()))
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    pub fn as_str(&self) -> Result<&str, SecretError> {
        std::str::from_utf8(&self.0)
            .map_err(|_| SecretError::InvalidRequest("file store secrets must be UTF-8".into()))
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Secret {
    Plain(SecretBytes),
    OAuth(OAuthSecret),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthSecret {
    pub provider: Option<String>,
    pub access_token: SecretBytes,
    pub refresh_token: SecretBytes,
    pub expires_at: DateTime<Utc>,
    pub account_id: Option<String>,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecretField {
    Value,
    OAuthAccessToken,
    OAuthExpiresAt,
    OAuthAccountId,
}

impl Secret {
    pub fn project(&self, field: SecretField) -> Option<SecretBytes> {
        match (self, field) {
            (Self::Plain(value), SecretField::Value) => Some(value.clone()),
            (Self::OAuth(o), SecretField::OAuthAccessToken) => Some(o.access_token.clone()),
            (Self::OAuth(o), SecretField::OAuthExpiresAt) => Some(SecretBytes::new(
                o.expires_at
                    .to_rfc3339_opts(SecondsFormat::AutoSi, true)
                    .into_bytes(),
            )),
            (Self::OAuth(o), SecretField::OAuthAccountId) => o
                .account_id
                .as_ref()
                .map(|v| SecretBytes::new(v.as_bytes().to_vec())),
            _ => None,
        }
    }
    pub fn expires_at(&self) -> Option<DateTime<Utc>> {
        match self {
            Self::Plain(_) => None,
            Self::OAuth(o) => Some(o.expires_at),
        }
    }
    pub fn kind(&self) -> SecretKind {
        match self {
            Self::Plain(_) => SecretKind::Plain,
            Self::OAuth(_) => SecretKind::OAuth,
        }
    }
    pub fn secret_type(&self) -> &'static str {
        match self {
            Self::Plain(_) => "plain",
            Self::OAuth(_) => "oauth",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretKind {
    Plain,
    OAuth,
}

#[derive(Debug, Clone)]
pub struct SecretEntry {
    pub name: SecretName,
    pub kind: SecretKind,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, thiserror::Error)]
pub enum SecretError {
    #[error("secret not found")]
    NotFound,
    #[error("secret store is read-only")]
    ReadOnly,
    #[error("{0}")]
    Unauthorized(String),
    #[error("{0}")]
    InvalidRequest(String),
    #[error("{0}")]
    ProviderUnavailable(String),
    #[error("{0}")]
    ProviderRejected(String),
    #[error("rate limited")]
    RateLimited,
    #[error("unsupported operation")]
    Unsupported,
    #[error("{0}")]
    Internal(String),
}

impl SecretError {
    pub fn wire_code(&self) -> &'static str {
        match self {
            Self::NotFound => "not_found",
            Self::ReadOnly => "read_only",
            Self::Unauthorized(_) => "unauthorized",
            Self::InvalidRequest(_) => "invalid_request",
            Self::ProviderUnavailable(_) => "provider_unavailable",
            Self::ProviderRejected(_) => "provider_rejected",
            Self::RateLimited => "rate_limited",
            Self::Unsupported => "unsupported",
            Self::Internal(_) => "internal_error",
        }
    }
}

impl From<std::io::Error> for SecretError {
    fn from(e: std::io::Error) -> Self {
        Self::Internal(e.to_string())
    }
}
impl From<serde_json::Error> for SecretError {
    fn from(e: serde_json::Error) -> Self {
        Self::InvalidRequest(e.to_string())
    }
}

/// Address understood by an out-of-process secret provider. Stores without a
/// compatible address still support ordinary start-time secret resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SecretStoreDescriptor {
    /// Home record file; Machine records are addressed by scope relative to it.
    File { store_file: PathBuf },
}

pub trait SecretStore: Send + Sync + fmt::Debug {
    /// Returns the actual provider address, rather than a runtime-home default.
    /// External stores can leave this unset until their provider protocol exists.
    fn descriptor(&self) -> Option<SecretStoreDescriptor> {
        None
    }
    fn get(&self, scope: &SecretScope, name: &SecretName) -> Result<Option<Secret>, SecretError>;
    fn put(
        &self,
        scope: &SecretScope,
        name: &SecretName,
        secret: Secret,
    ) -> Result<(), SecretError>;
    fn delete(&self, scope: &SecretScope, name: &SecretName) -> Result<bool, SecretError>;
    fn list(&self, scope: &SecretScope) -> Result<Vec<SecretEntry>, SecretError>;
    fn delete_scope(&self, scope: &SecretScope) -> Result<(), SecretError>;
    fn list_scopes(&self) -> Result<Vec<SecretScope>, SecretError> {
        Err(SecretError::Unsupported)
    }
}

/// Disk values remain strings, matching the original CLI format. Non-UTF-8 puts
/// fail before mutation. Untouched records retain their exact JSON values,
/// including absent/null optional fields and timestamp spelling.
#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
enum DiskSecret {
    Plain {
        value: String,
    },
    OAuth {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        provider: Option<String>,
        access_token: String,
        refresh_token: String,
        expires_at: DateTime<Utc>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        account_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        created_at: Option<DateTime<Utc>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        updated_at: Option<DateTime<Utc>>,
    },
}

impl DiskSecret {
    fn decode(value: Value) -> Result<Secret, SecretError> {
        Ok(match serde_json::from_value(value)? {
            Self::Plain { value } => Secret::Plain(SecretBytes::new(value.into_bytes())),
            Self::OAuth {
                provider,
                access_token,
                refresh_token,
                expires_at,
                account_id,
                created_at,
                updated_at,
            } => Secret::OAuth(OAuthSecret {
                provider,
                access_token: SecretBytes::new(access_token.into_bytes()),
                refresh_token: SecretBytes::new(refresh_token.into_bytes()),
                expires_at,
                account_id,
                created_at,
                updated_at,
            }),
        })
    }
    fn encode(secret: Secret) -> Result<Value, SecretError> {
        let disk = match secret {
            Secret::Plain(value) => Self::Plain {
                value: value.as_str()?.to_owned(),
            },
            Secret::OAuth(o) => Self::OAuth {
                provider: o.provider,
                access_token: o.access_token.as_str()?.to_owned(),
                refresh_token: o.refresh_token.as_str()?.to_owned(),
                expires_at: o.expires_at,
                account_id: o.account_id,
                created_at: o.created_at,
                updated_at: o.updated_at,
            },
        };
        Ok(serde_json::to_value(disk)?)
    }
}

#[derive(Debug, Clone)]
pub struct FileStore {
    home: PathBuf,
    home_file: PathBuf,
}

impl FileStore {
    pub fn new(home: impl Into<PathBuf>) -> Self {
        let home = home.into();
        Self {
            home_file: home.join("secrets.json"),
            home,
        }
    }
    /// Compatibility for the v1 provider's explicit `--store-file` argument.
    pub fn with_store_file(path: impl Into<PathBuf>) -> Result<Self, SecretError> {
        let mut home_file = path.into();
        let home = home_file
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."))
            .to_path_buf();
        if home_file.file_name().is_none() {
            return Err(SecretError::InvalidRequest(
                "invalid secret store path".into(),
            ));
        }
        if home_file.parent().is_some_and(|p| p.as_os_str().is_empty()) {
            home_file = Path::new(".").join(home_file);
        }
        Ok(Self { home, home_file })
    }
    pub fn path(&self) -> &Path {
        &self.home_file
    }
    pub fn scope_path(&self, scope: &SecretScope) -> PathBuf {
        match scope {
            SecretScope::Home => self.home_file.clone(),
            SecretScope::Machine { id } => self
                .home
                .join("machines")
                .join(id.as_str())
                .join("secrets.json"),
        }
    }
    fn lock(&self, scope: &SecretScope) -> Result<(PathBuf, File), SecretError> {
        let path = self.scope_path(scope);
        let parent = path
            .parent()
            .ok_or_else(|| SecretError::InvalidRequest("invalid secret store path".into()))?;
        match scope {
            SecretScope::Home => {
                secure_directory(parent)?;
            }
            SecretScope::Machine { .. } => {
                let metadata = fs::metadata(parent).map_err(|error| {
                    if error.kind() == std::io::ErrorKind::NotFound {
                        SecretError::NotFound
                    } else {
                        error.into()
                    }
                })?;
                if !metadata.is_dir() {
                    return Err(SecretError::InvalidRequest(format!(
                        "machine secret scope path {} is not a directory",
                        parent.display()
                    )));
                }
                permissions(parent, 0o700)?;
            }
        }
        let mut lock_name = path.as_os_str().to_os_string();
        lock_name.push(".lock");
        let lock = secure_options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(PathBuf::from(lock_name))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            lock.set_permissions(fs::Permissions::from_mode(0o600))?;
        }
        lock.lock()?;
        Ok((path, lock))
    }
    /// The closure must use only the supplied transaction, never re-enter this
    /// store. Errors discard all changes. The persistent sidecar survives JSON
    /// replacement and scope deletion, so every reader/writer locks one inode.
    pub fn transaction<T>(
        &self,
        scope: &SecretScope,
        operation: impl FnOnce(&mut ScopeTransaction) -> Result<T, SecretError>,
    ) -> Result<T, SecretError> {
        let mut tx = self.begin_transaction(scope)?;
        let result = operation(&mut tx)?;
        tx.commit()?;
        Ok(result)
    }
    /// Acquire once, then retain this guard through an asynchronous provider
    /// operation. Acquire on a blocking thread; commit never re-locks the scope.
    pub fn begin_transaction(&self, scope: &SecretScope) -> Result<ScopeTransaction, SecretError> {
        let (path, _lock) = self.lock(scope)?;
        Ok(ScopeTransaction {
            records: read_records(&path)?,
            dirty: false,
            path,
            _lock,
        })
    }
}

pub struct ScopeTransaction {
    records: BTreeMap<String, Value>,
    dirty: bool,
    path: PathBuf,
    _lock: File,
}

impl fmt::Debug for ScopeTransaction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ScopeTransaction { <redacted> }")
    }
}
impl ScopeTransaction {
    pub fn commit(self) -> Result<(), SecretError> {
        if self.dirty {
            write_records(&self.path, &self.records)?;
        }
        Ok(())
    }
    pub fn get(&self, name: &SecretName) -> Result<Option<Secret>, SecretError> {
        self.records
            .get(name.as_str())
            .cloned()
            .map(DiskSecret::decode)
            .transpose()
    }
    pub fn put(&mut self, name: &SecretName, secret: Secret) -> Result<(), SecretError> {
        SecretName::new(name.as_str())?;
        if self.get(name).ok().flatten().as_ref() == Some(&secret) {
            return Ok(());
        }
        let value = DiskSecret::encode(secret)?;
        self.records.insert(name.as_str().into(), value);
        self.dirty = true;
        Ok(())
    }
    pub fn delete(&mut self, name: &SecretName) -> bool {
        let removed = self.records.remove(name.as_str()).is_some();
        self.dirty |= removed;
        removed
    }
    pub fn list(&self) -> Result<Vec<SecretEntry>, SecretError> {
        self.records
            .iter()
            .map(|(name, value)| {
                let secret = DiskSecret::decode(value.clone())?;
                Ok(SecretEntry {
                    name: SecretName::legacy(name),
                    kind: secret.kind(),
                    expires_at: secret.expires_at(),
                })
            })
            .collect()
    }
}

impl SecretStore for FileStore {
    fn descriptor(&self) -> Option<SecretStoreDescriptor> {
        Some(SecretStoreDescriptor::File {
            store_file: self.home_file.clone(),
        })
    }
    fn get(&self, scope: &SecretScope, name: &SecretName) -> Result<Option<Secret>, SecretError> {
        self.transaction(scope, |tx| tx.get(name))
    }
    fn put(
        &self,
        scope: &SecretScope,
        name: &SecretName,
        secret: Secret,
    ) -> Result<(), SecretError> {
        self.transaction(scope, |tx| tx.put(name, secret))
    }
    fn delete(&self, scope: &SecretScope, name: &SecretName) -> Result<bool, SecretError> {
        self.transaction(scope, |tx| Ok(tx.delete(name)))
    }
    fn list(&self, scope: &SecretScope) -> Result<Vec<SecretEntry>, SecretError> {
        self.transaction(scope, |tx| tx.list())
    }
    fn delete_scope(&self, scope: &SecretScope) -> Result<(), SecretError> {
        let (path, _lock) = self.lock(scope)?;
        match fs::remove_file(&path) {
            Ok(()) => {
                File::open(path.parent().ok_or(SecretError::NotFound)?)?.sync_all()?;
                Ok(())
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
    fn list_scopes(&self) -> Result<Vec<SecretScope>, SecretError> {
        let mut scopes = Vec::new();
        if self.home_file.is_file() {
            scopes.push(SecretScope::Home);
        }
        let entries = match fs::read_dir(self.home.join("machines")) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(scopes),
            Err(e) => return Err(e.into()),
        };
        for entry in entries {
            let entry = entry?;
            if entry.file_type()?.is_dir() && entry.path().join("secrets.json").is_file() {
                if let Some(id) = entry
                    .file_name()
                    .to_str()
                    .and_then(|v| MachineScopeId::new(v).ok())
                {
                    scopes.push(SecretScope::Machine { id });
                }
            }
        }
        scopes.sort_by_key(|scope| self.scope_path(scope));
        Ok(scopes)
    }
}

fn read_records(path: &Path) -> Result<BTreeMap<String, Value>, SecretError> {
    let raw = match fs::read(path) {
        Ok(raw) => Zeroizing::new(raw),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(e) => return Err(e.into()),
    };
    if raw.iter().all(u8::is_ascii_whitespace) {
        return Ok(BTreeMap::new());
    }
    Ok(serde_json::from_slice(&raw)?)
}

fn write_records(path: &Path, records: &BTreeMap<String, Value>) -> Result<(), SecretError> {
    let parent = path.parent().ok_or(SecretError::NotFound)?;
    let filename = path
        .file_name()
        .ok_or(SecretError::NotFound)?
        .to_string_lossy();
    let mut body = Zeroizing::new(serde_json::to_vec_pretty(records)?);
    body.push(b'\n');
    // create_new, not truncation, makes stale/interrupted temporary files safe.
    let (temp, mut file) = (0u64..)
        .find_map(|sequence| {
            let temp = parent.join(format!(
                ".{filename}.tmp.{}.{}",
                std::process::id(),
                sequence
            ));
            match secure_options().write(true).create_new(true).open(&temp) {
                Ok(file) => Some(Ok((temp, file))),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => None,
                Err(e) => Some(Err(e)),
            }
        })
        .ok_or_else(|| SecretError::Internal("temporary file namespace exhausted".into()))??;
    let result = (|| {
        file.write_all(&body)?;
        file.sync_all()?;
        fs::rename(&temp, path)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

fn secure_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
}
fn secure_directory(path: &Path) -> Result<(), SecretError> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)?;
    permissions(path, 0o700)
}
fn permissions(path: &Path, mode: u32) -> Result<(), SecretError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
    }
    Ok(())
}
