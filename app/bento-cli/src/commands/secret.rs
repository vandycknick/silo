use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use chrono::{SecondsFormat, Utc};
use clap::{Args, Subcommand};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tabwriter::TabWriter;

const OPENAI_CODEX_CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";
const OPENAI_DEVICE_CODE_URL: &str = "https://auth.openai.com/api/accounts/deviceauth/usercode";
const OPENAI_DEVICE_POLL_URL: &str = "https://auth.openai.com/api/accounts/deviceauth/token";
const OPENAI_TOKEN_URL: &str = "https://auth.openai.com/oauth/token";
const OPENAI_DEVICE_VERIFY_URL: &str = "https://auth.openai.com/codex/device";
const OPENAI_DEVICE_REDIRECT_URI: &str = "https://auth.openai.com/deviceauth/callback";
const OPENAI_CODEX_PROVIDER: &str = "openai-codex";
const OPENAI_CODEX_KIND: &str = "openai_codex_oauth";
const OPENAI_DEVICE_LOGIN_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const SECRET_STORE_FILE_NAME: &str = "secrets.json";

#[derive(Args, Debug)]
#[command(
    about = "Manage Bento secrets",
    after_help = "Examples:\n  bento secret login openai-codex --name personal\n  printf '%s' \"$TOKEN\" | bento secret set bearer_token github-api --token-stdin\n  printf '%s' \"$TOKEN\" | bento secret set bearer_token.github-api.token --value-stdin\n  bento secret set aws_credential prod --profile production-admin\n  bento secret list\n  bento secret show openai_codex_oauth.personal.oauth\n  bento secret rm bearer_token.github-api.token --force\n"
)]
pub struct Cmd {
    #[command(subcommand)]
    pub command: SecretSubcommand,
}

impl Display for Cmd {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "secret")
    }
}

#[derive(Subcommand, Debug)]
pub enum SecretSubcommand {
    #[command(about = "Log in to a secret provider")]
    Login(LoginCmd),
    #[command(about = "Write a plain secret")]
    Set(SetCmd),
    #[command(about = "List saved secrets", visible_alias = "ls")]
    List(ListCmd),
    #[command(about = "Show a saved secret")]
    Show(ShowCmd),
    #[command(name = "rm", about = "Remove a saved secret")]
    Rm(RmCmd),
}

#[derive(Args, Debug)]
pub struct LoginCmd {
    /// Secret provider to log in to. Currently: openai-codex.
    #[arg(value_name = "PROVIDER", value_parser = parse_provider)]
    pub provider: LoginProvider,
    /// Secret name to save.
    #[arg(long)]
    pub name: String,
}

#[derive(Args, Debug)]
pub struct SetCmd {
    /// Either an exact secret key, or a credential kind and credential name.
    #[arg(value_name = "TARGET", num_args = 1..=2)]
    pub target: Vec<String>,
    /// Exact-key secret value. Prefer --value-stdin to avoid shell history.
    #[arg(long)]
    pub value: Option<String>,
    /// Read the exact-key secret value from stdin.
    #[arg(long)]
    pub value_stdin: bool,
    /// Provider token value. Prefer --token-stdin to avoid shell history.
    #[arg(long)]
    pub token: Option<String>,
    /// Read the provider token value from stdin.
    #[arg(long)]
    pub token_stdin: bool,
    /// Basic auth password. Prefer --password-stdin to avoid shell history.
    #[arg(long)]
    pub password: Option<String>,
    /// Read the basic auth password from stdin.
    #[arg(long)]
    pub password_stdin: bool,
    /// AWS access key id.
    #[arg(long)]
    pub access_key_id: Option<String>,
    /// Read the AWS access key id from stdin.
    #[arg(long)]
    pub access_key_id_stdin: bool,
    /// AWS secret access key. Prefer --secret-access-key-stdin to avoid shell history.
    #[arg(long)]
    pub secret_access_key: Option<String>,
    /// Read the AWS secret access key from stdin.
    #[arg(long)]
    pub secret_access_key_stdin: bool,
    /// Optional AWS session token. Prefer --session-token-stdin to avoid shell history.
    #[arg(long)]
    pub session_token: Option<String>,
    /// Read the optional AWS session token from stdin.
    #[arg(long)]
    pub session_token_stdin: bool,
    /// AWS shared-config profile name. When set, this credential uses the profile resolver.
    #[arg(long)]
    pub profile: Option<String>,
    /// Replace an existing secret.
    #[arg(long)]
    pub force: bool,
}

#[derive(Args, Debug)]
pub struct ListCmd {
    /// Output secrets as JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct ShowCmd {
    /// Secret name to show.
    #[arg(value_name = "NAME")]
    pub name: String,
    /// Output secret metadata as JSON.
    #[arg(long)]
    pub json: bool,
    /// Print only the secret store path.
    #[arg(long)]
    pub path: bool,
}

#[derive(Args, Debug)]
pub struct RmCmd {
    /// Secret name to remove.
    #[arg(value_name = "NAME")]
    pub name: String,
    /// Remove without prompting.
    #[arg(long)]
    pub force: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoginProvider {
    OpenAICodex,
}

impl Cmd {
    pub async fn run(&self) -> eyre::Result<()> {
        let store = SecretStore::from_env()?;
        match &self.command {
            SecretSubcommand::Login(cmd) => login(&store, cmd).await,
            SecretSubcommand::Set(cmd) => set_plain_secret(&store, cmd),
            SecretSubcommand::List(cmd) => list_secrets(&store, cmd),
            SecretSubcommand::Show(cmd) => show_secret(&store, cmd),
            SecretSubcommand::Rm(cmd) => remove_secret(&store, cmd),
        }
    }
}

fn parse_provider(input: &str) -> Result<LoginProvider, String> {
    match input {
        OPENAI_CODEX_PROVIDER => Ok(LoginProvider::OpenAICodex),
        other => Err(format!(
            "unsupported secret provider '{other}', expected {OPENAI_CODEX_PROVIDER}"
        )),
    }
}

async fn login(store: &SecretStore, cmd: &LoginCmd) -> eyre::Result<()> {
    let key = slot_key(OPENAI_CODEX_KIND, &cmd.name, "oauth");
    if store.contains(&key)? {
        eyre::bail!(
            "secret `{}` already exists in {}",
            key,
            store.path().display()
        );
    }

    let token = match cmd.provider {
        LoginProvider::OpenAICodex => login_openai_codex().await?,
    };
    let now = rfc3339_now();
    let secret = Secret::OAuth {
        access_token: token.access_token,
        refresh_token: token.refresh_token,
        expires_at: expires_at_from_seconds(token.expires_in),
        account_id: None,
        created_at: now.clone(),
        updated_at: now,
    };
    store.put(&key, secret)?;

    println!("saved secret `{}` in {}", key, store.path().display());
    println!();
    print_hcl_snippet(&cmd.name);
    Ok(())
}

async fn login_openai_codex() -> eyre::Result<TokenResponse> {
    let client = reqwest::Client::builder()
        .user_agent(concat!("bento/", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(30))
        .build()?;

    let device = start_openai_device_flow(&client).await?;
    let interval = Duration::from_secs(device.interval_seconds().unwrap_or(5).max(1));
    println!("Open this URL:");
    println!();
    println!("{}", OPENAI_DEVICE_VERIFY_URL);
    println!();
    println!("Enter code:");
    println!();
    println!("{}", device.user_code);
    println!();
    print!("Waiting for login");
    std::io::stdout().flush()?;

    let deadline = tokio::time::Instant::now() + OPENAI_DEVICE_LOGIN_TIMEOUT;
    loop {
        if tokio::time::Instant::now() >= deadline {
            println!();
            eyre::bail!("timed out waiting for OpenAI Codex login");
        }
        tokio::time::sleep(interval).await;
        match poll_openai_device_flow(&client, &device).await? {
            DevicePoll::Pending => {
                print!(".");
                std::io::stdout().flush()?;
            }
            DevicePoll::Authorized { code, verifier } => {
                println!();
                return exchange_openai_code(&client, &code, &verifier).await;
            }
        }
    }
}

async fn start_openai_device_flow(client: &reqwest::Client) -> eyre::Result<DeviceStartResponse> {
    let response = client
        .post(OPENAI_DEVICE_CODE_URL)
        .json(&serde_json::json!({ "client_id": OPENAI_CODEX_CLIENT_ID }))
        .send()
        .await?;
    let device: DeviceStartResponse =
        decode_json_response(response, "start OpenAI Codex device login").await?;
    if device.device_auth_id.is_empty() || device.user_code.is_empty() {
        eyre::bail!("OpenAI Codex device login returned an incomplete response");
    }
    Ok(device)
}

async fn poll_openai_device_flow(
    client: &reqwest::Client,
    device: &DeviceStartResponse,
) -> eyre::Result<DevicePoll> {
    let response = client
        .post(OPENAI_DEVICE_POLL_URL)
        .json(&serde_json::json!({
            "device_auth_id": &device.device_auth_id,
            "user_code": &device.user_code,
        }))
        .send()
        .await?;
    let status = response.status();
    let body = response.text().await?;
    if is_pending_device_poll_response(status, &body) {
        return Ok(DevicePoll::Pending);
    }
    if !status.is_success() {
        eyre::bail!(
            "poll OpenAI Codex device login returned {}: {}",
            status,
            sanitize_response_body(&body)
        );
    }
    let parsed: DevicePollResponse = serde_json::from_str(&body)?;
    if parsed.authorization_code.is_empty() || parsed.code_verifier.is_empty() {
        return Ok(DevicePoll::Pending);
    }
    Ok(DevicePoll::Authorized {
        code: parsed.authorization_code,
        verifier: parsed.code_verifier,
    })
}

async fn exchange_openai_code(
    client: &reqwest::Client,
    code: &str,
    verifier: &str,
) -> eyre::Result<TokenResponse> {
    let response = client
        .post(OPENAI_TOKEN_URL)
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("code_verifier", verifier),
            ("client_id", OPENAI_CODEX_CLIENT_ID),
            ("redirect_uri", OPENAI_DEVICE_REDIRECT_URI),
        ])
        .send()
        .await?;
    let token: TokenResponse =
        decode_json_response(response, "exchange OpenAI Codex login code").await?;
    if token.access_token.is_empty() {
        eyre::bail!("OpenAI Codex token response did not include an access token");
    }
    if token.refresh_token.is_empty() {
        eyre::bail!("OpenAI Codex token response did not include a refresh token");
    }
    Ok(token)
}

async fn decode_json_response<T>(response: reqwest::Response, context: &str) -> eyre::Result<T>
where
    T: for<'de> Deserialize<'de>,
{
    let status = response.status();
    let body = response.text().await?;
    if !status.is_success() {
        eyre::bail!(
            "{context} returned {}: {}",
            status,
            sanitize_response_body(&body)
        );
    }
    Ok(serde_json::from_str(&body)?)
}

fn set_plain_secret(store: &SecretStore, cmd: &SetCmd) -> eyre::Result<()> {
    if cmd.stdin_source_count() > 1 {
        eyre::bail!("only one stdin-backed secret value can be provided at a time");
    }

    match cmd.target.as_slice() {
        [key] => {
            if cmd.has_provider_specific_source() {
                eyre::bail!(
                    "provider-specific options require `bento secret set <kind> <name> ...`"
                );
            }
            let value =
                plain_secret_value(&cmd.value, cmd.value_stdin, "value", read_stdin_string)?;
            write_plain_secret(store, key, value, cmd.force)
        }
        [kind, name] => set_provider_plain_secret(store, kind, name, cmd),
        _ => eyre::bail!("provide either an exact secret key or a credential kind and name"),
    }
}

fn set_provider_plain_secret(
    store: &SecretStore,
    kind: &str,
    name: &str,
    cmd: &SetCmd,
) -> eyre::Result<()> {
    if cmd.has_exact_key_source() {
        eyre::bail!("--value and --value-stdin are only valid with an exact secret key");
    }

    let entries = match kind {
        "basic_auth" => {
            if cmd.has_token_source() || cmd.has_static_aws_source() || cmd.profile.is_some() {
                eyre::bail!("basic_auth accepts --password or --password-stdin only");
            }
            vec![(
                slot_key(kind, name, "password"),
                plain_secret_value(
                    &cmd.password,
                    cmd.password_stdin,
                    "password",
                    read_stdin_string,
                )?,
            )]
        }
        "bearer_token" => {
            if cmd.has_password_source() || cmd.has_static_aws_source() || cmd.profile.is_some() {
                eyre::bail!("bearer_token accepts --token or --token-stdin only");
            }
            vec![(
                slot_key(kind, name, "token"),
                plain_secret_value(&cmd.token, cmd.token_stdin, "token", read_stdin_string)?,
            )]
        }
        "header_token" => {
            if cmd.has_password_source() || cmd.has_static_aws_source() || cmd.profile.is_some() {
                eyre::bail!("header_token accepts --token or --token-stdin only");
            }
            vec![(
                slot_key(kind, name, "token"),
                plain_secret_value(&cmd.token, cmd.token_stdin, "token", read_stdin_string)?,
            )]
        }
        "aws_credential" => aws_secret_entries(kind, name, cmd)?,
        other => eyre::bail!(
            "unsupported credential kind `{other}` for `bento secret set`; use an exact secret key with --value if needed"
        ),
    };
    write_plain_secret_entries(store, entries, cmd.force)
}

fn aws_secret_entries(kind: &str, name: &str, cmd: &SetCmd) -> eyre::Result<Vec<(String, String)>> {
    if cmd.has_token_source() || cmd.has_password_source() {
        eyre::bail!("aws_credential accepts AWS slot options only");
    }
    if let Some(profile) = &cmd.profile {
        if cmd.has_static_aws_source() {
            eyre::bail!(
                "provide either --profile or static AWS key slots for aws_credential, not both"
            );
        }
        return Ok(vec![(slot_key(kind, name, "profile"), profile.clone())]);
    }

    let mut entries = vec![
        (
            slot_key(kind, name, "access_key_id"),
            plain_secret_value(
                &cmd.access_key_id,
                cmd.access_key_id_stdin,
                "access-key-id",
                read_stdin_string,
            )?,
        ),
        (
            slot_key(kind, name, "secret_access_key"),
            plain_secret_value(
                &cmd.secret_access_key,
                cmd.secret_access_key_stdin,
                "secret-access-key",
                read_stdin_string,
            )?,
        ),
    ];
    if let Some(session_token) = optional_plain_secret_value(
        &cmd.session_token,
        cmd.session_token_stdin,
        "session-token",
        read_stdin_string,
    )? {
        entries.push((slot_key(kind, name, "session_token"), session_token));
    }
    Ok(entries)
}

fn plain_secret_value<F>(
    value: &Option<String>,
    value_stdin: bool,
    label: &str,
    read_stdin: F,
) -> eyre::Result<String>
where
    F: FnOnce() -> eyre::Result<String>,
{
    match (value, value_stdin) {
        (Some(_), true) => eyre::bail!("provide either --{label} or --{label}-stdin, not both"),
        (Some(value), false) => Ok(value.clone()),
        (None, true) => read_stdin(),
        (None, false) => eyre::bail!("provide --{label} or --{label}-stdin"),
    }
}

fn optional_plain_secret_value<F>(
    value: &Option<String>,
    value_stdin: bool,
    label: &str,
    read_stdin: F,
) -> eyre::Result<Option<String>>
where
    F: FnOnce() -> eyre::Result<String>,
{
    match (value, value_stdin) {
        (Some(_), true) => eyre::bail!("provide either --{label} or --{label}-stdin, not both"),
        (Some(value), false) => Ok(Some(value.clone())),
        (None, true) => read_stdin().map(Some),
        (None, false) => Ok(None),
    }
}

impl SetCmd {
    fn stdin_source_count(&self) -> usize {
        [
            self.value_stdin,
            self.token_stdin,
            self.password_stdin,
            self.access_key_id_stdin,
            self.secret_access_key_stdin,
            self.session_token_stdin,
        ]
        .into_iter()
        .filter(|enabled| *enabled)
        .count()
    }

    fn has_exact_key_source(&self) -> bool {
        self.value.is_some() || self.value_stdin
    }

    fn has_token_source(&self) -> bool {
        self.token.is_some() || self.token_stdin
    }

    fn has_password_source(&self) -> bool {
        self.password.is_some() || self.password_stdin
    }

    fn has_static_aws_source(&self) -> bool {
        self.access_key_id.is_some()
            || self.access_key_id_stdin
            || self.secret_access_key.is_some()
            || self.secret_access_key_stdin
            || self.session_token.is_some()
            || self.session_token_stdin
    }

    fn has_provider_specific_source(&self) -> bool {
        self.has_token_source()
            || self.has_password_source()
            || self.has_static_aws_source()
            || self.profile.is_some()
    }
}

fn read_stdin_string() -> eyre::Result<String> {
    let mut value = String::new();
    std::io::stdin().read_to_string(&mut value)?;
    Ok(value)
}

fn write_plain_secret(
    store: &SecretStore,
    name: &str,
    value: String,
    force: bool,
) -> eyre::Result<()> {
    if store.contains(name)? && !force {
        eyre::bail!(
            "secret `{}` already exists in {}; pass --force to replace it",
            name,
            store.path().display()
        );
    }
    store.put(name, Secret::Plain { value })?;
    println!("saved secret `{}` in {}", name, store.path().display());
    Ok(())
}

fn write_plain_secret_entries(
    store: &SecretStore,
    entries: Vec<(String, String)>,
    force: bool,
) -> eyre::Result<()> {
    if entries.is_empty() {
        eyre::bail!("no secret slots to write");
    }
    if !force {
        for (name, _) in &entries {
            if store.contains(name)? {
                eyre::bail!(
                    "secret `{}` already exists in {}; pass --force to replace it",
                    name,
                    store.path().display()
                );
            }
        }
    }
    for (name, value) in &entries {
        store.put(
            name,
            Secret::Plain {
                value: value.clone(),
            },
        )?;
    }
    for (name, _) in entries {
        println!("saved secret `{}` in {}", name, store.path().display());
    }
    Ok(())
}

fn slot_key(kind: &str, name: &str, slot: &str) -> String {
    format!("{kind}.{name}.{slot}")
}

fn list_secrets(store: &SecretStore, cmd: &ListCmd) -> eyre::Result<()> {
    let secrets = store.list()?;
    if cmd.json {
        println!("{}", serde_json::to_string_pretty(&secrets)?);
        return Ok(());
    }

    let mut out = TabWriter::new(std::io::stdout()).padding(2);
    writeln!(&mut out, "PROVIDER\tNAME\tKIND\tEXPIRES_AT\tPATH")?;
    for secret in secrets {
        writeln!(
            &mut out,
            "{}\t{}\t{}\t{}\t{}",
            secret.provider,
            secret.name,
            secret.kind,
            secret.expires_at,
            secret.path.display()
        )?;
    }
    out.flush()?;
    Ok(())
}

fn show_secret(store: &SecretStore, cmd: &ShowCmd) -> eyre::Result<()> {
    let path = store.path();
    if cmd.path {
        println!("{}", path.display());
        return Ok(());
    }
    let secret = store.get(&cmd.name)?;
    let redacted = RedactedSecret::from_secret(&cmd.name, &secret, path);
    if cmd.json {
        println!("{}", serde_json::to_string_pretty(&redacted)?);
    } else {
        println!("provider: {}", redacted.provider);
        println!("name: {}", cmd.name);
        println!("path: {}", path.display());
        println!("type: {}", redacted.secret_type);
        println!("kind: {}", redacted.kind);
        if let Some(expires_at) = redacted.expires_at.as_deref() {
            println!("expires_at: {expires_at}");
        }
        if let Some(account_id) = redacted.account_id.as_deref() {
            println!("account_id: {account_id}");
        }
        for field in &redacted.redacted_fields {
            println!("{field}: <redacted>");
        }
    }
    Ok(())
}

fn remove_secret(store: &SecretStore, cmd: &RmCmd) -> eyre::Result<()> {
    if !cmd.force {
        eyre::bail!("refusing to remove secret `{}` without --force", cmd.name);
    }
    store.remove(&cmd.name)?;
    println!(
        "removed secret `{}` from {}",
        cmd.name,
        store.path().display()
    );
    Ok(())
}

fn print_hcl_snippet(name: &str) {
    println!("Use this credential name in policy for an HTTPS endpoint:");
    println!();
    println!("credential \"{}\" \"{}\" {{", OPENAI_CODEX_KIND, name);
    println!("  endpoint = https.openai-codex");
    println!("}}");
}

#[derive(Debug, Deserialize)]
struct DeviceStartResponse {
    device_auth_id: String,
    user_code: String,
    #[serde(default)]
    interval: Value,
}

impl DeviceStartResponse {
    fn interval_seconds(&self) -> Option<u64> {
        match &self.interval {
            Value::Number(number) => number.as_u64(),
            Value::String(text) => text.parse::<u64>().ok(),
            _ => None,
        }
    }
}

enum DevicePoll {
    Pending,
    Authorized { code: String, verifier: String },
}

#[derive(Debug, Deserialize)]
struct DevicePollResponse {
    #[serde(default)]
    authorization_code: String,
    #[serde(default)]
    code_verifier: String,
}

#[derive(Debug, Deserialize)]
struct DevicePollErrorResponse {
    error: Option<DevicePollError>,
}

#[derive(Debug, Deserialize)]
struct DevicePollError {
    #[serde(default)]
    code: String,
}

fn is_pending_device_poll_response(status: StatusCode, body: &str) -> bool {
    if status == StatusCode::ACCEPTED || status == StatusCode::NO_CONTENT {
        return true;
    }
    let Ok(response) = serde_json::from_str::<DevicePollErrorResponse>(body) else {
        return false;
    };
    let Some(error) = response.error else {
        return false;
    };
    matches!(
        error.code.as_str(),
        "deviceauth_authorization_pending" | "authorization_pending"
    )
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    #[serde(default)]
    access_token: String,
    #[serde(default)]
    refresh_token: String,
    #[serde(default)]
    expires_in: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
enum Secret {
    #[serde(rename = "plain")]
    Plain { value: String },
    #[serde(rename = "oauth")]
    OAuth {
        access_token: String,
        refresh_token: String,
        expires_at: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        account_id: Option<String>,
        created_at: String,
        updated_at: String,
    },
}

impl Secret {
    fn provider(&self) -> &'static str {
        match self {
            Secret::Plain { .. } => "plain",
            Secret::OAuth { .. } => OPENAI_CODEX_PROVIDER,
        }
    }

    fn kind(&self) -> &'static str {
        match self {
            Secret::Plain { .. } => "plain",
            Secret::OAuth { .. } => OPENAI_CODEX_KIND,
        }
    }

    fn secret_type(&self) -> &'static str {
        match self {
            Secret::Plain { .. } => "plain",
            Secret::OAuth { .. } => "oauth",
        }
    }

    fn expires_at(&self) -> Option<&str> {
        match self {
            Secret::Plain { .. } => None,
            Secret::OAuth { expires_at, .. } => Some(expires_at.as_str()),
        }
    }
}

#[derive(Debug, Serialize)]
struct RedactedSecret {
    provider: &'static str,
    name: String,
    path: PathBuf,
    secret_type: &'static str,
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    account_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    created_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    updated_at: Option<String>,
    redacted_fields: Vec<&'static str>,
}

impl RedactedSecret {
    fn from_secret(name: &str, secret: &Secret, path: &Path) -> Self {
        match secret {
            Secret::Plain { .. } => Self {
                provider: secret.provider(),
                name: name.to_string(),
                path: path.to_path_buf(),
                secret_type: secret.secret_type(),
                kind: secret.kind(),
                expires_at: None,
                account_id: None,
                created_at: None,
                updated_at: None,
                redacted_fields: vec!["value"],
            },
            Secret::OAuth {
                expires_at,
                account_id,
                created_at,
                updated_at,
                ..
            } => Self {
                provider: secret.provider(),
                name: name.to_string(),
                path: path.to_path_buf(),
                secret_type: secret.secret_type(),
                kind: secret.kind(),
                expires_at: Some(expires_at.clone()),
                account_id: account_id.clone(),
                created_at: Some(created_at.clone()),
                updated_at: Some(updated_at.clone()),
                redacted_fields: vec!["access_token", "refresh_token"],
            },
        }
    }
}

#[derive(Debug, Serialize)]
struct SecretSummary {
    provider: &'static str,
    name: String,
    kind: &'static str,
    expires_at: String,
    path: PathBuf,
}

struct SecretStore {
    path: PathBuf,
}

impl SecretStore {
    fn from_env() -> eyre::Result<Self> {
        Ok(Self::new(
            resolve_default_data_dir()?.join(SECRET_STORE_FILE_NAME),
        ))
    }

    fn new(path: PathBuf) -> Self {
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn contains(&self, name: &str) -> eyre::Result<bool> {
        validate_secret_name(name)?;
        Ok(self.read_all()?.contains_key(name))
    }

    fn put(&self, name: &str, secret: Secret) -> eyre::Result<()> {
        validate_secret_name(name)?;
        let mut secrets = self.read_all()?;
        secrets.insert(name.to_string(), secret);
        self.write_all(&secrets)
    }

    fn get(&self, name: &str) -> eyre::Result<Secret> {
        validate_secret_name(name)?;
        self.read_all()?
            .remove(name)
            .ok_or_else(|| eyre::eyre!("secret `{name}` not found"))
    }

    fn remove(&self, name: &str) -> eyre::Result<()> {
        validate_secret_name(name)?;
        let mut secrets = self.read_all()?;
        if secrets.remove(name).is_none() {
            eyre::bail!("secret `{name}` not found");
        }
        self.write_all(&secrets)
    }

    fn list(&self) -> eyre::Result<Vec<SecretSummary>> {
        let mut secrets = self
            .read_all()?
            .into_iter()
            .map(|(name, secret)| SecretSummary {
                provider: secret.provider(),
                name,
                kind: secret.kind(),
                expires_at: secret.expires_at().unwrap_or_default().to_string(),
                path: self.path.clone(),
            })
            .collect::<Vec<_>>();
        secrets.sort_by(|a, b| a.provider.cmp(b.provider).then(a.name.cmp(&b.name)));
        Ok(secrets)
    }

    fn read_all(&self) -> eyre::Result<BTreeMap<String, Secret>> {
        if !self.path.exists() {
            return Ok(BTreeMap::new());
        }
        let raw = std::fs::read_to_string(&self.path)?;
        if raw.trim().is_empty() {
            return Ok(BTreeMap::new());
        }
        let secrets = serde_json::from_str::<BTreeMap<String, Secret>>(&raw)?;
        for name in secrets.keys() {
            validate_secret_name(name)?;
        }
        Ok(secrets)
    }

    fn write_all(&self, secrets: &BTreeMap<String, Secret>) -> eyre::Result<()> {
        let Some(parent) = self.path.parent() else {
            eyre::bail!("invalid secret store path {}", self.path.display());
        };
        std::fs::create_dir_all(parent)?;
        set_secure_dir_permissions(parent)?;
        let file_name = self
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| eyre::eyre!("invalid secret store path {}", self.path.display()))?;
        let tmp_path = self
            .path
            .with_file_name(format!(".{file_name}.tmp.{}", std::process::id()));
        let mut body = serde_json::to_vec_pretty(secrets)?;
        body.push(b'\n');
        write_secure_file(&tmp_path, &body)?;
        set_secure_file_permissions(&tmp_path)?;
        std::fs::rename(&tmp_path, &self.path)?;
        set_secure_file_permissions(&self.path)?;
        Ok(())
    }
}

fn validate_secret_name(name: &str) -> eyre::Result<()> {
    if name.is_empty() {
        eyre::bail!("secret name cannot be empty");
    }
    if name == "." || name == ".." || name.starts_with('.') {
        eyre::bail!("secret name `{name}` is not allowed");
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        eyre::bail!("secret name `{name}` may only contain ASCII letters, numbers, dots, underscores, and dashes");
    }
    Ok(())
}

fn resolve_default_data_dir() -> eyre::Result<PathBuf> {
    if let Some(data_home) = env_absolute_path("XDG_DATA_HOME")? {
        return Ok(data_home.join("bento"));
    }
    let home = env_absolute_path("HOME")?
        .ok_or_else(|| eyre::eyre!("could not resolve Bento data dir from HOME"))?;
    Ok(home.join(".local/share/bento"))
}

fn env_absolute_path(name: &'static str) -> eyre::Result<Option<PathBuf>> {
    let Some(value) = std::env::var_os(name) else {
        return Ok(None);
    };
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        eyre::bail!(
            "environment variable {name} must be an absolute path: {}",
            path.display()
        );
    }
    Ok(Some(path))
}

fn expires_at_from_seconds(expires_in: i64) -> String {
    let expires_at = if expires_in > 0 {
        Utc::now() + chrono::Duration::seconds(expires_in)
    } else {
        Utc::now()
    };
    expires_at.to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn rfc3339_now() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn sanitize_response_body(body: &str) -> String {
    let body = body.trim();
    if body.is_empty() {
        return "<empty>".to_string();
    }
    let mut chars = body.chars();
    let prefix = chars.by_ref().take(512).collect::<String>();
    if chars.next().is_some() {
        format!("{}...", prefix)
    } else {
        prefix
    }
}

#[cfg(unix)]
fn write_secure_file(path: &Path, body: &[u8]) -> eyre::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(body)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_secure_file(path: &Path, body: &[u8]) -> eyre::Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?;
    file.write_all(body)?;
    Ok(())
}

#[cfg(unix)]
fn set_secure_dir_permissions(path: &Path) -> eyre::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = std::fs::metadata(path)?.permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(path, permissions)?;
    Ok(())
}

#[cfg(not(unix))]
fn set_secure_dir_permissions(_path: &Path) -> eyre::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_secure_file_permissions(path: &Path) -> eyre::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = std::fs::metadata(path)?.permissions();
    permissions.set_mode(0o600);
    std::fs::set_permissions(path, permissions)?;
    Ok(())
}

#[cfg(not(unix))]
fn set_secure_file_permissions(_path: &Path) -> eyre::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use clap::Parser;
    use reqwest::StatusCode;

    use crate::commands::{BentoCmd, Command};

    use super::{
        is_pending_device_poll_response, plain_secret_value, set_plain_secret, slot_key,
        write_plain_secret, LoginProvider, Secret, SecretStore, SecretSubcommand, SetCmd,
        OPENAI_CODEX_KIND,
    };

    #[test]
    fn secret_login_openai_codex_parses() {
        let cmd = BentoCmd::try_parse_from([
            "bento",
            "secret",
            "login",
            "openai-codex",
            "--name",
            "personal",
        ])
        .expect("secret login should parse");

        let secret = match cmd.cmd {
            Command::Secret(cmd) => cmd,
            other => panic!("expected secret command, got {other:?}"),
        };
        let login = match secret.command {
            SecretSubcommand::Login(cmd) => cmd,
            other => panic!("expected login command, got {other:?}"),
        };

        assert_eq!(login.provider, LoginProvider::OpenAICodex);
        assert_eq!(login.name, "personal");
    }

    #[test]
    fn credentials_subcommand_is_removed() {
        assert!(BentoCmd::try_parse_from(["bento", "credentials", "list"]).is_err());
    }

    #[test]
    fn secret_login_rejects_policy_credential_kind_as_provider() {
        assert!(BentoCmd::try_parse_from([
            "bento",
            "secret",
            "login",
            "openai_codex_oauth",
            "--name",
            "personal",
        ])
        .is_err());
    }

    #[test]
    fn secret_set_exact_key_plain_value_parses() {
        let cmd = BentoCmd::try_parse_from([
            "bento",
            "secret",
            "set",
            "bearer_token.github-api.token",
            "--value",
            "secret-token",
            "--force",
        ])
        .expect("secret set should parse");

        let secret = match cmd.cmd {
            Command::Secret(cmd) => cmd,
            other => panic!("expected secret command, got {other:?}"),
        };
        let set = match secret.command {
            SecretSubcommand::Set(cmd) => cmd,
            other => panic!("expected set command, got {other:?}"),
        };

        assert_eq!(set.target, ["bearer_token.github-api.token"]);
        assert_eq!(set.value.as_deref(), Some("secret-token"));
        assert!(set.force);
    }

    #[test]
    fn secret_set_provider_aware_value_parses() {
        let cmd = BentoCmd::try_parse_from([
            "bento",
            "secret",
            "set",
            "bearer_token",
            "github-api",
            "--token-stdin",
            "--force",
        ])
        .expect("provider-aware secret set should parse");

        let secret = match cmd.cmd {
            Command::Secret(cmd) => cmd,
            other => panic!("expected secret command, got {other:?}"),
        };
        let set = match secret.command {
            SecretSubcommand::Set(cmd) => cmd,
            other => panic!("expected set command, got {other:?}"),
        };

        assert_eq!(set.target, ["bearer_token", "github-api"]);
        assert!(set.token_stdin);
        assert!(set.force);
    }

    #[test]
    fn plain_secret_value_validates_sources() {
        assert!(plain_secret_value(&None, false, "value", || Ok("stdin".to_string())).is_err());
        assert!(
            plain_secret_value(&Some("argument".to_string()), true, "value", || Ok(
                "stdin".to_string()
            ))
            .is_err()
        );

        let value = plain_secret_value(&None, true, "value", || Ok("stdin".to_string()))
            .expect("stdin value");
        assert_eq!(value, "stdin");
    }

    #[test]
    fn set_provider_aware_bearer_token_writes_slot_key() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = SecretStore::new(dir.path().join("secrets.json"));
        let mut cmd = set_cmd(["bearer_token", "github-api"]);
        cmd.token = Some("secret-token".to_string());

        set_plain_secret(&store, &cmd).expect("write bearer token");

        let loaded = store
            .get("bearer_token.github-api.token")
            .expect("read bearer token slot");
        match loaded {
            Secret::Plain { value } => assert_eq!(value, "secret-token"),
            other => panic!("expected plain secret, got {other:?}"),
        }
    }

    #[test]
    fn set_provider_aware_aws_profile_writes_profile_slot() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = SecretStore::new(dir.path().join("secrets.json"));
        let mut cmd = set_cmd(["aws_credential", "prod"]);
        cmd.profile = Some("production-admin".to_string());

        set_plain_secret(&store, &cmd).expect("write aws profile");

        let loaded = store
            .get("aws_credential.prod.profile")
            .expect("read aws profile slot");
        match loaded {
            Secret::Plain { value } => assert_eq!(value, "production-admin"),
            other => panic!("expected plain secret, got {other:?}"),
        }
    }

    #[test]
    fn set_provider_aware_aws_static_writes_required_slots() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = SecretStore::new(dir.path().join("secrets.json"));
        let mut cmd = set_cmd(["aws_credential", "prod"]);
        cmd.access_key_id = Some("AKIAEXAMPLE".to_string());
        cmd.secret_access_key = Some("secret".to_string());
        cmd.session_token = Some("session".to_string());

        set_plain_secret(&store, &cmd).expect("write aws slots");

        assert_plain_secret(&store, "aws_credential.prod.access_key_id", "AKIAEXAMPLE");
        assert_plain_secret(&store, "aws_credential.prod.secret_access_key", "secret");
        assert_plain_secret(&store, "aws_credential.prod.session_token", "session");
    }

    #[test]
    fn write_plain_secret_writes_and_protects_existing_secret() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = SecretStore::new(dir.path().join("secrets.json"));

        write_plain_secret(&store, "api-token", "secret-token".to_string(), false)
            .expect("write plain secret");
        let loaded = store.get("api-token").expect("read plain secret");
        match loaded {
            Secret::Plain { value } => assert_eq!(value, "secret-token"),
            other => panic!("expected plain secret, got {other:?}"),
        }

        assert!(write_plain_secret(&store, "api-token", "new-token".to_string(), false).is_err());
        write_plain_secret(&store, "api-token", "new-token".to_string(), true)
            .expect("force replace plain secret");
        let loaded = store.get("api-token").expect("read replaced plain secret");
        match loaded {
            Secret::Plain { value } => assert_eq!(value, "new-token"),
            other => panic!("expected plain secret, got {other:?}"),
        }
    }

    #[test]
    fn secret_store_writes_single_json_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("secrets.json");
        let store = SecretStore::new(path.clone());
        let secret = Secret::OAuth {
            access_token: "access".to_string(),
            refresh_token: "refresh".to_string(),
            expires_at: "2026-06-02T12:00:00Z".to_string(),
            account_id: None,
            created_at: "2026-06-02T11:00:00Z".to_string(),
            updated_at: "2026-06-02T11:00:00Z".to_string(),
        };

        let key = slot_key(OPENAI_CODEX_KIND, "personal", "oauth");
        store.put(&key, secret).expect("write secret");

        assert_eq!(path, dir.path().join("secrets.json"));
        let raw = std::fs::read_to_string(&path).expect("read secret store");
        assert!(raw.contains(r#""type": "oauth""#));
        let loaded = store.get(&key).expect("read secret");
        match loaded {
            Secret::OAuth { refresh_token, .. } => assert_eq!(refresh_token, "refresh"),
            other => panic!("expected oauth secret, got {other:?}"),
        }
        let listed = store.list().expect("list secrets");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].kind, OPENAI_CODEX_KIND);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mode = std::fs::metadata(&path)
                .expect("secret store metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn secret_store_rejects_path_names() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = SecretStore::new(dir.path().join("secrets.json"));

        assert!(store
            .put(
                "../bad",
                Secret::Plain {
                    value: "bad".to_string()
                }
            )
            .is_err());
        assert!(store
            .put(
                ".hidden",
                Secret::Plain {
                    value: "bad".to_string()
                }
            )
            .is_err());
    }

    fn set_cmd<const N: usize>(target: [&str; N]) -> SetCmd {
        SetCmd {
            target: target.into_iter().map(str::to_string).collect(),
            value: None,
            value_stdin: false,
            token: None,
            token_stdin: false,
            password: None,
            password_stdin: false,
            access_key_id: None,
            access_key_id_stdin: false,
            secret_access_key: None,
            secret_access_key_stdin: false,
            session_token: None,
            session_token_stdin: false,
            profile: None,
            force: false,
        }
    }

    fn assert_plain_secret(store: &SecretStore, name: &str, expected: &str) {
        let loaded = store.get(name).expect("read plain secret");
        match loaded {
            Secret::Plain { value } => assert_eq!(value, expected),
            other => panic!("expected plain secret, got {other:?}"),
        }
    }

    #[test]
    fn secret_store_reads_shared_fixture() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("testdata/secrets/basic.json");
        let store = SecretStore::new(path);

        let plain = store.get("something").expect("plain fixture secret");
        match plain {
            Secret::Plain { value } => assert_eq!(value, "123"),
            other => panic!("expected plain secret, got {other:?}"),
        }

        let oauth = store
            .get("openai_codex_oauth.personal.oauth")
            .expect("oauth fixture secret");
        match oauth {
            Secret::OAuth {
                access_token,
                refresh_token,
                ..
            } => {
                assert_eq!(access_token, "access-token");
                assert_eq!(refresh_token, "refresh-token");
            }
            other => panic!("expected oauth secret, got {other:?}"),
        }
    }

    #[test]
    fn device_poll_treats_openai_pending_error_as_pending() {
        let body = r#"{
  "error": {
    "message": "Device authorization is pending. Please try again.",
    "type": "invalid_request_error",
    "code": "deviceauth_authorization_pending"
  }
}"#;

        assert!(is_pending_device_poll_response(StatusCode::FORBIDDEN, body));
    }

    #[test]
    fn device_poll_treats_standard_pending_error_as_pending() {
        let body = r#"{"error":{"code":"authorization_pending"}}"#;

        assert!(is_pending_device_poll_response(
            StatusCode::BAD_REQUEST,
            body
        ));
    }

    #[test]
    fn device_poll_does_not_hide_other_errors() {
        let body = r#"{"error":{"code":"invalid_grant"}}"#;

        assert!(!is_pending_device_poll_response(
            StatusCode::FORBIDDEN,
            body
        ));
    }
}
