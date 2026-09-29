use std::io::{BufRead, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{SecondsFormat, Utc};
use clap::{Args, Subcommand};
use libvm::{
    EgressCredentials, NetworkCredential, NetworkPolicy, NetworkSecretAlternative,
    NetworkSecretKind, NetworkSecretRequirement, NetworkSecretSlot, OAuthRefreshHook,
};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use silo_secrets::{
    FileStore, OAuthSecret, Secret, SecretBytes, SecretField, SecretName, SecretScope, SecretStore,
};

use crate::context::Context;
use crate::ui::{self, OutputFormat, Table};

const OPENAI_CODEX_CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";
const OPENAI_DEVICE_CODE_URL: &str = "https://auth.openai.com/api/accounts/deviceauth/usercode";
const OPENAI_DEVICE_POLL_URL: &str = "https://auth.openai.com/api/accounts/deviceauth/token";
const OPENAI_TOKEN_URL: &str = "https://auth.openai.com/oauth/token";
const OPENAI_DEVICE_VERIFY_URL: &str = "https://auth.openai.com/codex/device";
const OPENAI_DEVICE_REDIRECT_URI: &str = "https://auth.openai.com/deviceauth/callback";
const OPENAI_CODEX_PROVIDER: &str = "openai-codex";
const OPENAI_CODEX_KIND: &str = "openai_codex_oauth";
const OPENAI_DEVICE_LOGIN_TIMEOUT: Duration = Duration::from_secs(10 * 60);

const EXAMPLES: &[&str] = &[
    "silo secret login openai-codex --name personal",
    "printf '%s' \"$TOKEN\" | silo secret set bearer_token github-api --token-stdin",
    "printf '%s' \"$TOKEN\" | silo secret set bearer_token.github-api.token --value-stdin",
    "silo secret set aws_credential prod --profile production-admin",
    "silo secret list",
    "silo secret show openai_codex_oauth.personal.oauth",
    "silo secret rm bearer_token.github-api.token --force",
];

#[derive(Args, Debug)]
#[command(
    about = "Manage Silo secrets",
    after_help = crate::help::examples(EXAMPLES)
)]
pub struct Cmd {
    #[command(subcommand)]
    pub(crate) command: SecretSubcommand,
}

#[derive(Subcommand, Debug)]
pub(crate) enum SecretSubcommand {
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
    #[command(name = "refresh-oauth", hide = true)]
    RefreshOAuth(RefreshOAuthCmd),
}

#[derive(Args, Debug)]
pub(crate) struct LoginCmd {
    /// Secret provider to log in to. Currently: openai-codex.
    #[arg(value_name = "PROVIDER", value_parser = parse_provider)]
    pub(crate) provider: LoginProvider,
    /// Secret name to save.
    #[arg(long)]
    pub(crate) name: String,
}

#[derive(Args, Debug)]
pub(crate) struct SetCmd {
    /// Either an exact secret key, or a credential kind and credential name.
    #[arg(value_name = "TARGET", num_args = 1..=2)]
    pub(crate) target: Vec<String>,
    /// Exact-key secret value. Prefer --value-stdin to avoid shell history.
    #[arg(long)]
    pub(crate) value: Option<String>,
    /// Read the exact-key secret value from stdin.
    #[arg(long)]
    pub(crate) value_stdin: bool,
    /// Provider token value. Prefer --token-stdin to avoid shell history.
    #[arg(long)]
    pub(crate) token: Option<String>,
    /// Read the provider token value from stdin.
    #[arg(long)]
    pub(crate) token_stdin: bool,
    /// Basic auth password. Prefer --password-stdin to avoid shell history.
    #[arg(long)]
    pub(crate) password: Option<String>,
    /// Read the basic auth password from stdin.
    #[arg(long)]
    pub(crate) password_stdin: bool,
    /// AWS access key id.
    #[arg(long)]
    pub(crate) access_key_id: Option<String>,
    /// Read the AWS access key id from stdin.
    #[arg(long)]
    pub(crate) access_key_id_stdin: bool,
    /// AWS secret access key. Prefer --secret-access-key-stdin to avoid shell history.
    #[arg(long)]
    pub(crate) secret_access_key: Option<String>,
    /// Read the AWS secret access key from stdin.
    #[arg(long)]
    pub(crate) secret_access_key_stdin: bool,
    /// Optional AWS session token. Prefer --session-token-stdin to avoid shell history.
    #[arg(long)]
    pub(crate) session_token: Option<String>,
    /// Read the optional AWS session token from stdin.
    #[arg(long)]
    pub(crate) session_token_stdin: bool,
    /// AWS shared-config profile name. When set, this credential uses the profile resolver.
    #[arg(long)]
    pub(crate) profile: Option<String>,
    /// Replace an existing secret.
    #[arg(long)]
    pub(crate) force: bool,
}

#[derive(Args, Debug)]
pub(crate) struct ListCmd {
    /// Output format.
    #[arg(long, value_enum, value_name = "FORMAT", default_value_t = OutputFormat::Plain)]
    pub(crate) format: OutputFormat,
}

#[derive(Args, Debug)]
pub(crate) struct ShowCmd {
    /// Secret name to show.
    #[arg(value_name = "NAME")]
    pub(crate) name: String,
    /// Output format.
    #[arg(long, value_enum, value_name = "FORMAT", default_value_t = OutputFormat::Plain)]
    pub(crate) format: OutputFormat,
    /// Print only the secret store path.
    #[arg(long)]
    pub(crate) path: bool,
}

#[derive(Args, Debug)]
pub(crate) struct RmCmd {
    /// Secret name to remove.
    #[arg(value_name = "NAME")]
    pub(crate) name: String,
    /// Remove without prompting.
    #[arg(long)]
    pub(crate) force: bool,
}

#[derive(Args, Debug)]
pub(crate) struct RefreshOAuthCmd {
    /// Secret store file used by the launch that created this hook.
    #[arg(long = "store-file")]
    pub(crate) store_file: PathBuf,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LoginProvider {
    OpenAICodex,
}

impl Cmd {
    pub async fn run(self, _context: &mut Context) -> eyre::Result<()> {
        match &self.command {
            SecretSubcommand::Login(command) => {
                let store = file_store_from_env()?;
                login(&store, command).await
            }
            SecretSubcommand::Set(command) => {
                let store = file_store_from_env()?;
                set_plain_secret(&store, command)
            }
            SecretSubcommand::List(command) => {
                let store = file_store_from_env()?;
                list_secrets(&store, command)
            }
            SecretSubcommand::Show(command) => {
                let store = file_store_from_env()?;
                show_secret(&store, command)
            }
            SecretSubcommand::Rm(command) => {
                let store = file_store_from_env()?;
                remove_secret(&store, command)
            }
            SecretSubcommand::RefreshOAuth(command) => refresh_oauth(command).await,
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

async fn login(store: &FileStore, command: &LoginCmd) -> eyre::Result<()> {
    let key = slot_key(OPENAI_CODEX_KIND, &command.name, "oauth");
    let name = cli_secret_name(&key)?;
    if store.get(&SecretScope::Home, &name)?.is_some() {
        eyre::bail!(
            "secret `{}` already exists in {}",
            key,
            store.path().display()
        );
    }

    let token = match command.provider {
        LoginProvider::OpenAICodex => login_openai_codex().await?,
    };
    let now = timestamp_now();
    let secret = Secret::OAuth(OAuthSecret {
        provider: None,
        access_token: SecretBytes::new(token.access_token.into_bytes()),
        refresh_token: SecretBytes::new(token.refresh_token.into_bytes()),
        expires_at: expires_at_from_seconds(token.expires_in).parse()?,
        account_id: None,
        created_at: Some(now),
        updated_at: Some(now),
    });
    store.transaction(&SecretScope::Home, |tx| {
        if tx.get(&name)?.is_some() {
            return Err(silo_secrets::SecretError::InvalidRequest(format!(
                "secret `{key}` already exists in {}",
                store.path().display()
            )));
        }
        tx.put(&name, secret)
    })?;

    ui::success(format!(
        "saved secret `{}` in {}",
        key,
        store.path().display()
    ));
    print_hcl_snippet(&command.name)?;
    Ok(())
}

async fn login_openai_codex() -> eyre::Result<TokenResponse> {
    let client = reqwest::Client::builder()
        .user_agent(concat!("silo/", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(30))
        .build()?;

    let device = start_openai_device_flow(&client).await?;
    let interval = Duration::from_secs(device.interval_seconds().unwrap_or(5).max(1));
    {
        let stderr = std::io::stderr();
        let mut out = stderr.lock();
        writeln!(out, "Open this URL:")?;
        writeln!(out)?;
        writeln!(out, "{OPENAI_DEVICE_VERIFY_URL}")?;
        writeln!(out)?;
        writeln!(out, "Enter code:")?;
        writeln!(out)?;
        writeln!(out, "{}", device.user_code)?;
        writeln!(out)?;
        write!(out, "Waiting for login")?;
        out.flush()?;
    }

    let deadline = tokio::time::Instant::now() + OPENAI_DEVICE_LOGIN_TIMEOUT;
    loop {
        if tokio::time::Instant::now() >= deadline {
            eprintln!();
            eyre::bail!("timed out waiting for OpenAI Codex login");
        }
        tokio::time::sleep(interval).await;
        match poll_openai_device_flow(&client, &device).await? {
            DevicePoll::Pending => {
                eprint!(".");
                std::io::stderr().flush()?;
            }
            DevicePoll::Authorized { code, verifier } => {
                eprintln!();
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

fn set_plain_secret(store: &FileStore, command: &SetCmd) -> eyre::Result<()> {
    if command.stdin_source_count() > 1 {
        eyre::bail!("only one stdin-backed secret value can be provided at a time");
    }

    match command.target.as_slice() {
        [key] => {
            if command.has_provider_specific_source() {
                eyre::bail!(
                    "provider-specific options require `silo secret set <kind> <name> ...`"
                );
            }
            let value = plain_secret_value(
                &command.value,
                command.value_stdin,
                "value",
                read_stdin_string,
            )?;
            write_plain_secret(store, key, value, command.force)
        }
        [kind, name] => set_provider_plain_secret(store, kind, name, command),
        _ => eyre::bail!("provide either an exact secret key or a credential kind and name"),
    }
}

fn set_provider_plain_secret(
    store: &FileStore,
    kind: &str,
    name: &str,
    command: &SetCmd,
) -> eyre::Result<()> {
    if command.has_exact_key_source() {
        eyre::bail!("--value and --value-stdin are only valid with an exact secret key");
    }

    let entries = match kind {
        "basic_auth" => {
            if command.has_token_source()
                || command.has_static_aws_source()
                || command.profile.is_some()
            {
                eyre::bail!("basic_auth accepts --password or --password-stdin only");
            }
            vec![(
                slot_key(kind, name, "password"),
                plain_secret_value(
                    &command.password,
                    command.password_stdin,
                    "password",
                    read_stdin_string,
                )?,
            )]
        }
        "bearer_token" => {
            if command.has_password_source()
                || command.has_static_aws_source()
                || command.profile.is_some()
            {
                eyre::bail!("bearer_token accepts --token or --token-stdin only");
            }
            vec![(
                slot_key(kind, name, "token"),
                plain_secret_value(
                    &command.token,
                    command.token_stdin,
                    "token",
                    read_stdin_string,
                )?,
            )]
        }
        "header_token" => {
            if command.has_password_source()
                || command.has_static_aws_source()
                || command.profile.is_some()
            {
                eyre::bail!("header_token accepts --token or --token-stdin only");
            }
            vec![(
                slot_key(kind, name, "token"),
                plain_secret_value(
                    &command.token,
                    command.token_stdin,
                    "token",
                    read_stdin_string,
                )?,
            )]
        }
        "aws_credential" => aws_secret_entries(kind, name, command)?,
        other => eyre::bail!(
            "unsupported credential kind `{other}` for `silo secret set`; use an exact secret key with --value if needed"
        ),
    };
    write_plain_secret_entries(store, entries, command.force)
}

fn aws_secret_entries(
    kind: &str,
    name: &str,
    command: &SetCmd,
) -> eyre::Result<Vec<(String, String)>> {
    if command.has_token_source() || command.has_password_source() {
        eyre::bail!("aws_credential accepts AWS slot options only");
    }
    if let Some(profile) = &command.profile {
        if command.has_static_aws_source() {
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
                &command.access_key_id,
                command.access_key_id_stdin,
                "access-key-id",
                read_stdin_string,
            )?,
        ),
        (
            slot_key(kind, name, "secret_access_key"),
            plain_secret_value(
                &command.secret_access_key,
                command.secret_access_key_stdin,
                "secret-access-key",
                read_stdin_string,
            )?,
        ),
    ];
    if let Some(session_token) = optional_plain_secret_value(
        &command.session_token,
        command.session_token_stdin,
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
    store: &FileStore,
    name: &str,
    value: String,
    force: bool,
) -> eyre::Result<()> {
    write_plain_secret_entries(store, vec![(name.to_owned(), value)], force)
}

fn write_plain_secret_entries(
    store: &FileStore,
    entries: Vec<(String, String)>,
    force: bool,
) -> eyre::Result<()> {
    if entries.is_empty() {
        eyre::bail!("no secret slots to write");
    }
    let names = entries
        .iter()
        .map(|(name, _)| cli_secret_name(name))
        .collect::<eyre::Result<Vec<_>>>()?;
    store.transaction(&SecretScope::Home, |tx| {
        for name in &names {
            if !force && tx.get(name)?.is_some() {
                return Err(silo_secrets::SecretError::InvalidRequest(format!(
                    "secret `{}` already exists in {}; pass --force to replace it",
                    name.as_str(),
                    store.path().display()
                )));
            }
        }
        for (name, (_, value)) in names.iter().zip(&entries) {
            tx.put(
                name,
                Secret::Plain(SecretBytes::new(value.as_bytes().to_vec())),
            )?;
        }
        Ok(())
    })?;
    for (name, _) in entries {
        ui::success(format!(
            "saved secret `{}` in {}",
            name,
            store.path().display()
        ));
    }
    Ok(())
}

fn slot_key(kind: &str, name: &str, slot: &str) -> String {
    format!("{kind}.{name}.{slot}")
}

#[derive(Debug, Serialize, Deserialize)]
struct OAuthRefreshGrant {
    version: u8,
    store_file: PathBuf,
    credentials: Vec<OAuthRefreshGrantCredential>,
}

#[derive(Debug, Serialize, Deserialize)]
struct OAuthRefreshGrantCredential {
    name: String,
    kind: String,
    endpoint: String,
    secret_key: String,
}

pub(crate) fn egress_credentials_from_secret_store(
    policy: &NetworkPolicy,
) -> eyre::Result<EgressCredentials> {
    if policy.secret_slots().is_empty() {
        return Ok(EgressCredentials::new());
    }
    let hook_command = std::env::current_exe()?;
    let store = file_store_from_env()?;
    egress_credentials_from_store(policy, &store, &hook_command)
}

fn egress_credentials_from_store(
    policy: &NetworkPolicy,
    store: &FileStore,
    hook_command: &Path,
) -> eyre::Result<EgressCredentials> {
    let mut credentials = EgressCredentials::new();
    let mut supplied_slots = std::collections::BTreeSet::new();
    let slots = policy.secret_slots();
    let mut profile_owners = std::collections::BTreeSet::new();
    for slot in &slots {
        if slot.source.key.as_str().starts_with("aws_credential.")
            && slot.name.ends_with(".profile")
            && projected_slot_value(store, slot)?.is_some()
        {
            if let Some((owner, _)) = slot.name.split_once('.') {
                profile_owners.insert(owner.to_owned());
            }
        }
    }
    for slot in slots {
        if slot.name.split_once('.').is_some_and(|(owner, field)| {
            profile_owners.contains(owner)
                && matches!(
                    field,
                    "access_key_id" | "secret_access_key" | "session_token"
                )
        }) {
            continue;
        }
        if let Some(value) = projected_slot_value(store, &slot)? {
            supplied_slots.insert(slot.name.clone());
            credentials = credentials.secret(slot.name, value);
        }
    }
    let missing = missing_network_secret_requirements(policy, &supplied_slots);
    if !missing.is_empty() {
        eyre::bail!(format_missing_network_secrets(&missing, store.path()));
    }
    if let Some(hook) = oauth_refresh_hook_from_store(policy, store, hook_command)? {
        credentials = credentials.oauth_refresh_hook(hook);
    }
    Ok(credentials)
}

fn oauth_refresh_hook_from_store(
    policy: &NetworkPolicy,
    store: &FileStore,
    hook_command: &Path,
) -> eyre::Result<Option<OAuthRefreshHook>> {
    let grant = oauth_refresh_grant(policy, store)?;
    if grant.credentials.is_empty() {
        return Ok(None);
    }
    let auth = serde_json::to_vec(&grant)?;
    Ok(Some(
        OAuthRefreshHook::new(hook_command, auth)
            .arg("secret")
            .arg("refresh-oauth")
            .arg("--store-file")
            .arg(store.path().to_string_lossy()),
    ))
}

fn oauth_refresh_grant(
    policy: &NetworkPolicy,
    store: &FileStore,
) -> eyre::Result<OAuthRefreshGrant> {
    let mut credentials = Vec::new();
    for credential in policy.credentials() {
        let Some(slot) = policy.secret_slots().into_iter().find(|slot| {
            slot.kind == NetworkSecretKind::OAuth
                && slot.name == format!("{}.oauth.access_token", credential.name)
        }) else {
            continue;
        };
        let key = slot.source.key;
        let Some(secret) = store.get(&SecretScope::Home, &key)? else {
            continue;
        };
        if matches!(secret, Secret::OAuth(_)) {
            credentials.push(OAuthRefreshGrantCredential {
                name: credential.name.clone(),
                kind: credential.kind.clone(),
                endpoint: credential.endpoint.clone(),
                secret_key: key.as_str().to_owned(),
            });
        }
    }
    Ok(OAuthRefreshGrant {
        version: 1,
        store_file: store.path().to_path_buf(),
        credentials,
    })
}

fn projected_slot_value(
    store: &FileStore,
    slot: &NetworkSecretSlot,
) -> eyre::Result<Option<String>> {
    // Exact raw slot records predate canonical store keys and take precedence.
    let (key, secret, field) =
        if let Some(secret) = store.get(&SecretScope::Home, &SecretName::legacy(&slot.name))? {
            (&slot.name[..], secret, SecretField::Value)
        } else if let Some(secret) = store.get(&SecretScope::Home, &slot.source.key)? {
            (slot.source.key.as_str(), secret, slot.source.field)
        } else {
            return Ok(None);
        };
    let expected = if field == SecretField::Value {
        "plain"
    } else {
        "oauth"
    };
    if secret.secret_type() != expected {
        eyre::bail!(
            "secret `{key}` in {} has type {}, expected {expected}",
            store.path().display(),
            secret.secret_type()
        );
    }
    secret
        .project(field)
        .map(|value| non_empty_secret_value(key, value.as_str()?.to_owned(), store.path()))
        .transpose()
}

fn credential_for_slot<'a>(
    policy: &'a NetworkPolicy,
    slot_name: &str,
) -> Option<&'a NetworkCredential> {
    let (name, _) = slot_name.split_once('.')?;
    policy
        .credentials()
        .iter()
        .find(|credential| credential.name == name)
}

fn non_empty_secret_value(key: &str, value: String, path: &Path) -> eyre::Result<String> {
    if value.is_empty() {
        eyre::bail!("secret `{key}` in {} has an empty value", path.display());
    }
    Ok(value)
}

#[derive(Debug)]
struct MissingNetworkSecret {
    owner: String,
    expected: Vec<Vec<String>>,
    hint: String,
}

impl MissingNetworkSecret {
    fn new(policy: &NetworkPolicy, requirement: &NetworkSecretRequirement) -> Self {
        Self {
            owner: requirement.owner.clone(),
            expected: expected_secret_requirement_keys(policy, requirement),
            hint: secret_requirement_hint(policy, requirement),
        }
    }
}

fn missing_network_secret_requirements(
    policy: &NetworkPolicy,
    supplied_slots: &std::collections::BTreeSet<String>,
) -> Vec<MissingNetworkSecret> {
    policy
        .secret_requirements()
        .into_iter()
        .filter(|requirement| {
            !requirement.alternatives.iter().any(|alternative| {
                alternative
                    .slots
                    .iter()
                    .all(|slot| supplied_slots.contains(slot))
            })
        })
        .map(|requirement| MissingNetworkSecret::new(policy, &requirement))
        .collect()
}

fn expected_secret_requirement_keys(
    policy: &NetworkPolicy,
    requirement: &NetworkSecretRequirement,
) -> Vec<Vec<String>> {
    let mut expected = Vec::new();
    for alternative in &requirement.alternatives {
        expected.extend(expected_secret_alternative_keys(policy, alternative));
    }
    expected.sort();
    expected.dedup();
    expected
}

fn expected_secret_alternative_keys(
    policy: &NetworkPolicy,
    alternative: &NetworkSecretAlternative,
) -> Vec<Vec<String>> {
    let mut keys = alternative
        .slots
        .iter()
        .filter_map(|name| policy_slot(policy, name))
        .map(|slot| slot.source.key.as_str().to_owned())
        .collect::<Vec<_>>();
    keys.sort();
    keys.dedup();
    if keys.is_empty() {
        vec![alternative.slots.clone()]
    } else {
        vec![keys, alternative.slots.clone()]
    }
}

fn credential_for_alternative<'a>(
    policy: &'a NetworkPolicy,
    alternative: &NetworkSecretAlternative,
) -> Option<&'a NetworkCredential> {
    let first_slot = alternative.slots.first()?;
    let credential = credential_for_slot(policy, first_slot)?;
    if alternative.slots.iter().all(|slot| {
        credential_for_slot(policy, slot).is_some_and(|candidate| candidate.name == credential.name)
    }) {
        Some(credential)
    } else {
        None
    }
}

fn policy_slot(policy: &NetworkPolicy, slot_name: &str) -> Option<NetworkSecretSlot> {
    policy
        .secret_slots()
        .into_iter()
        .find(|slot| slot.name == slot_name)
}

fn tailscale_tunnel_for_alternative(alternative: &NetworkSecretAlternative) -> Option<&str> {
    let [slot] = alternative.slots.as_slice() else {
        return None;
    };
    slot.strip_suffix(".tailscale.auth_key")
}

fn credential_secret_hint(credential: &NetworkCredential) -> String {
    match credential.kind.as_str() {
        OPENAI_CODEX_KIND => format!("run `silo secret login openai-codex --name {}`", credential.name),
        "basic_auth" => format!(
            "write it with `printf '%s' \"$PASSWORD\" | silo secret set basic_auth {} --password-stdin`",
            credential.name
        ),
        "bearer_token" => format!(
            "write it with `printf '%s' \"$TOKEN\" | silo secret set bearer_token {} --token-stdin`",
            credential.name
        ),
        "header_token" => format!(
            "write it with `printf '%s' \"$TOKEN\" | silo secret set header_token {} --token-stdin`",
            credential.name
        ),
        "aws_credential" => format!(
            "write a profile with `silo secret set aws_credential {} --profile <profile>` or static keys with `silo secret set aws_credential {} --access-key-id ... --secret-access-key-stdin`",
            credential.name, credential.name
        ),
        _ => format!(
            "write a matching secret with `silo secret set {}`",
            credential.name
        ),
    }
}

fn secret_requirement_hint(
    policy: &NetworkPolicy,
    requirement: &NetworkSecretRequirement,
) -> String {
    if let Some(credential) = requirement
        .alternatives
        .iter()
        .find_map(|alternative| credential_for_alternative(policy, alternative))
    {
        return credential_secret_hint(credential);
    }
    if let Some(tunnel_name) = requirement
        .alternatives
        .iter()
        .find_map(tailscale_tunnel_for_alternative)
    {
        return format!(
            "write it with `printf '%s' \"$SECRET\" | silo secret set tailscale.{tunnel_name}.auth_key --value-stdin`"
        );
    }
    "write the required network secret material with `silo secret set`".to_string()
}

fn format_missing_network_secrets(missing: &[MissingNetworkSecret], path: &Path) -> String {
    let mut message = format!(
        "missing required network secret material for persisted network policy in {}",
        path.display()
    );
    for missing in missing {
        message.push_str("\n- ");
        message.push_str(&missing.owner);
        message.push_str("\n  expected one of: ");
        message.push_str(&format_expected_secret_alternatives(&missing.expected));
        message.push_str("\n  hint: ");
        message.push_str(&missing.hint);
    }
    message
}

fn format_expected_secret_alternatives(alternatives: &[Vec<String>]) -> String {
    alternatives
        .iter()
        .map(|alternative| {
            alternative
                .iter()
                .map(|key| format!("`{key}`"))
                .collect::<Vec<_>>()
                .join(" and ")
        })
        .collect::<Vec<_>>()
        .join(" or ")
}

fn list_secrets(store: &FileStore, command: &ListCmd) -> eyre::Result<()> {
    let mut secrets = store
        .list(&SecretScope::Home)?
        .into_iter()
        .map(|entry| SecretSummary {
            provider: if entry.kind == silo_secrets::SecretKind::Plain {
                "plain"
            } else {
                OPENAI_CODEX_PROVIDER
            },
            name: entry.name.as_str().to_owned(),
            kind: if entry.kind == silo_secrets::SecretKind::Plain {
                "plain"
            } else {
                OPENAI_CODEX_KIND
            },
            expires_at: entry
                .expires_at
                .map(|v| v.to_rfc3339_opts(SecondsFormat::AutoSi, true))
                .unwrap_or_default(),
            path: store.path().to_owned(),
        })
        .collect::<Vec<_>>();
    secrets.sort_by(|a, b| a.provider.cmp(b.provider).then(a.name.cmp(&b.name)));
    match command.format {
        OutputFormat::Json => ui::print_json(&secrets),
        OutputFormat::Plain => {
            let mut table = Table::new(["PROVIDER", "NAME", "KIND", "EXPIRES_AT", "PATH"]);
            for secret in secrets {
                table.add_row([
                    secret.provider.to_string(),
                    secret.name,
                    secret.kind.to_string(),
                    if secret.expires_at.is_empty() {
                        "-".to_string()
                    } else {
                        secret.expires_at
                    },
                    secret.path.display().to_string(),
                ]);
            }
            table.print()
        }
    }
}

fn show_secret(store: &FileStore, command: &ShowCmd) -> eyre::Result<()> {
    let path = store.path();
    if command.path {
        println!("{}", path.display());
        return Ok(());
    }
    let secret = store
        .get(&SecretScope::Home, &SecretName::legacy(&command.name))?
        .ok_or_else(|| eyre::eyre!("secret `{}` not found", command.name))?;
    let redacted = RedactedSecret::from_secret(&command.name, &secret, path);
    match command.format {
        OutputFormat::Json => ui::print_json(&redacted),
        OutputFormat::Plain => print_secret_details(&redacted),
    }
}

fn print_secret_details(secret: &RedactedSecret) -> eyre::Result<()> {
    let mut rows = vec![
        ("provider".to_string(), secret.provider.to_string()),
        ("name".to_string(), secret.name.clone()),
        ("path".to_string(), secret.path.display().to_string()),
        ("type".to_string(), secret.secret_type.to_string()),
        ("kind".to_string(), secret.kind.to_string()),
    ];
    if let Some(expires_at) = &secret.expires_at {
        rows.push(("expires_at".to_string(), expires_at.clone()));
    }
    if let Some(account_id) = &secret.account_id {
        rows.push(("account_id".to_string(), account_id.clone()));
    }
    for field in &secret.redacted_fields {
        rows.push(((*field).to_string(), "<redacted>".to_string()));
    }
    ui::print_detail_rows(&rows)
}

fn remove_secret(store: &FileStore, command: &RmCmd) -> eyre::Result<()> {
    if !command.force {
        eyre::bail!(
            "refusing to remove secret `{}` without --force",
            command.name
        );
    }
    if !store.delete(&SecretScope::Home, &SecretName::legacy(&command.name))? {
        eyre::bail!("secret `{}` not found", command.name);
    }
    ui::success(format!(
        "removed secret `{}` from {}",
        command.name,
        store.path().display()
    ));
    Ok(())
}

fn print_hcl_snippet(name: &str) -> eyre::Result<()> {
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    writeln!(out)?;
    writeln!(
        out,
        "Use this credential name in policy for an HTTPS endpoint:"
    )?;
    writeln!(out)?;
    writeln!(out, "credential \"{}\" \"{}\" {{", OPENAI_CODEX_KIND, name)?;
    writeln!(out, "  endpoint = https.openai-codex")?;
    writeln!(out, "}}")?;
    Ok(())
}

async fn refresh_oauth(command: &RefreshOAuthCmd) -> eyre::Result<()> {
    let request = read_json_frame(std::io::stdin().lock())?;
    let store = FileStore::with_store_file(command.store_file.clone())?;
    let response = match refresh_oauth_request(&store, &command.store_file, request).await {
        Ok(oauth) => OAuthRefreshHookResponse::ok(oauth),
        Err(error) => OAuthRefreshHookResponse::error(error),
    };
    write_json_frame(std::io::stdout().lock(), &response)
}

async fn refresh_oauth_request(
    store: &FileStore,
    store_file: &Path,
    request: OAuthRefreshHookRequest,
) -> Result<OAuthRefreshHookOAuth, OAuthRefreshFailure> {
    if request.version != 1 || request.operation != "oauth_refresh" {
        return Err(OAuthRefreshFailure::invalid_request(
            "unsupported OAuth refresh request",
        ));
    }
    let grant = decode_oauth_refresh_grant(&request.grant)?;
    if grant.version != 1 {
        return Err(OAuthRefreshFailure::unauthorized(
            "unsupported OAuth refresh grant version",
        ));
    }
    if grant.store_file != store_file {
        return Err(OAuthRefreshFailure::unauthorized(
            "OAuth refresh grant does not match requested secret store",
        ));
    }
    let Some(grant_credential) = grant.credentials.iter().find(|candidate| {
        candidate.name == request.credential.name
            && candidate.kind == request.credential.kind
            && candidate.endpoint == request.credential.endpoint
    }) else {
        return Err(OAuthRefreshFailure::unauthorized(
            "OAuth refresh grant does not allow this credential",
        ));
    };
    match request.credential.kind.as_str() {
        OPENAI_CODEX_KIND => refresh_openai_codex_oauth(store, &grant_credential.secret_key).await,
        other => Err(OAuthRefreshFailure::invalid_request(format!(
            "OAuth credential kind {other:?} is not refreshable by this command"
        ))),
    }
}

fn decode_oauth_refresh_grant(encoded: &str) -> Result<OAuthRefreshGrant, OAuthRefreshFailure> {
    let raw = STANDARD
        .decode(encoded)
        .map_err(|err| OAuthRefreshFailure::unauthorized(format!("decode refresh auth: {err}")))?;
    serde_json::from_slice(&raw)
        .map_err(|err| OAuthRefreshFailure::unauthorized(format!("parse refresh auth: {err}")))
}

async fn refresh_openai_codex_oauth(
    store: &FileStore,
    key: &str,
) -> Result<OAuthRefreshHookOAuth, OAuthRefreshFailure> {
    let store = store.clone();
    let mut tx = tokio::task::spawn_blocking(move || store.begin_transaction(&SecretScope::Home))
        .await
        .map_err(|err| OAuthRefreshFailure::internal(err.to_string()))?
        .map_err(|err| OAuthRefreshFailure::internal(err.to_string()))?;
    let name = SecretName::legacy(key);
    let secret = tx
        .get(&name)
        .map_err(|err| OAuthRefreshFailure::internal(err.to_string()))?
        .ok_or_else(|| OAuthRefreshFailure::not_found("OAuth secret was not found"))?;
    let Secret::OAuth(OAuthSecret {
        provider,
        refresh_token,
        account_id,
        created_at,
        ..
    }) = secret
    else {
        return Err(OAuthRefreshFailure::invalid_request(format!(
            "secret {key:?} is not an OAuth secret"
        )));
    };
    if refresh_token.is_empty() {
        return Err(OAuthRefreshFailure::invalid_request(
            "OAuth secret does not contain a refresh token",
        ));
    }
    let client = reqwest::Client::builder()
        .user_agent(concat!("silo/", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|err| OAuthRefreshFailure::internal(err.to_string()))?;
    let token = refresh_openai_codex_token(
        &client,
        refresh_token
            .as_str()
            .map_err(|err| OAuthRefreshFailure::invalid_request(err.to_string()))?,
    )
    .await?;
    let next_refresh_token = if token.refresh_token.is_empty() {
        refresh_token
    } else {
        SecretBytes::new(token.refresh_token.into_bytes())
    };
    let expires_at = expires_at_from_seconds(token.expires_in);
    let updated = Secret::OAuth(OAuthSecret {
        provider,
        access_token: SecretBytes::new(token.access_token.as_bytes().to_vec()),
        refresh_token: next_refresh_token,
        expires_at: expires_at
            .parse()
            .map_err(|err: chrono::ParseError| OAuthRefreshFailure::internal(err.to_string()))?,
        account_id: account_id.clone(),
        created_at,
        updated_at: Some(timestamp_now()),
    });
    tx.put(&name, updated)
        .map_err(|err| OAuthRefreshFailure::internal(err.to_string()))?;
    tx.commit()
        .map_err(|err| OAuthRefreshFailure::internal(err.to_string()))?;
    Ok(OAuthRefreshHookOAuth {
        access_token: token.access_token,
        expires_at,
        account_id,
    })
}

async fn refresh_openai_codex_token(
    client: &reqwest::Client,
    refresh_token: &str,
) -> Result<TokenResponse, OAuthRefreshFailure> {
    let response = client
        .post(OPENAI_TOKEN_URL)
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", OPENAI_CODEX_CLIENT_ID),
        ])
        .send()
        .await
        .map_err(|err| OAuthRefreshFailure::provider_unavailable(err.to_string()))?;
    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|err| OAuthRefreshFailure::provider_unavailable(err.to_string()))?;
    if !status.is_success() {
        return Err(OAuthRefreshFailure::provider_rejected(format!(
            "OpenAI Codex OAuth refresh returned {status}: {}",
            sanitize_response_body(&body)
        )));
    }
    let token = serde_json::from_str::<TokenResponse>(&body)
        .map_err(|err| OAuthRefreshFailure::provider_rejected(err.to_string()))?;
    if token.access_token.is_empty() {
        return Err(OAuthRefreshFailure::provider_rejected(
            "OpenAI Codex OAuth refresh did not include an access token",
        ));
    }
    Ok(token)
}

fn read_json_frame<R, T>(reader: R) -> eyre::Result<T>
where
    R: Read,
    T: for<'de> Deserialize<'de>,
{
    let mut reader = std::io::BufReader::new(reader);
    let mut content_length = None;
    loop {
        let mut line = String::new();
        let bytes = reader.read_line(&mut line)?;
        if bytes == 0 {
            eyre::bail!("missing Content-Length frame header");
        }
        let header = line.trim_end_matches(['\r', '\n']);
        if header.is_empty() {
            break;
        }
        let Some((name, value)) = header.split_once(':') else {
            eyre::bail!("invalid frame header {header:?}");
        };
        if name.eq_ignore_ascii_case("content-length") {
            content_length = Some(value.trim().parse::<usize>()?);
        }
    }
    let length = content_length.ok_or_else(|| eyre::eyre!("missing Content-Length header"))?;
    let mut body = vec![0; length];
    reader.read_exact(&mut body)?;
    Ok(serde_json::from_slice(&body)?)
}

fn write_json_frame<W, T>(mut writer: W, value: &T) -> eyre::Result<()>
where
    W: Write,
    T: Serialize,
{
    let body = serde_json::to_vec(value)?;
    write!(writer, "Content-Length: {}\r\n\r\n", body.len())?;
    writer.write_all(&body)?;
    writer.flush()?;
    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
struct OAuthRefreshHookRequest {
    version: u8,
    operation: String,
    #[serde(default)]
    grant: String,
    credential: OAuthRefreshHookCredential,
    #[allow(dead_code)]
    reason: String,
    #[allow(dead_code)]
    expires_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct OAuthRefreshHookCredential {
    name: String,
    kind: String,
    endpoint: String,
}

#[derive(Debug, Serialize)]
struct OAuthRefreshHookResponse {
    version: u8,
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    oauth: Option<OAuthRefreshHookOAuth>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<OAuthRefreshHookError>,
}

impl OAuthRefreshHookResponse {
    fn ok(oauth: OAuthRefreshHookOAuth) -> Self {
        Self {
            version: 1,
            status: "ok",
            oauth: Some(oauth),
            error: None,
        }
    }

    fn error(error: OAuthRefreshFailure) -> Self {
        Self {
            version: 1,
            status: "error",
            oauth: None,
            error: Some(OAuthRefreshHookError {
                code: error.code,
                message: error.message,
                retryable: error.retryable,
            }),
        }
    }
}

#[derive(Debug, Serialize)]
struct OAuthRefreshHookOAuth {
    access_token: String,
    expires_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    account_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct OAuthRefreshHookError {
    code: &'static str,
    message: String,
    #[serde(skip_serializing_if = "is_false")]
    retryable: bool,
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Debug)]
struct OAuthRefreshFailure {
    code: &'static str,
    message: String,
    retryable: bool,
}

impl OAuthRefreshFailure {
    fn unauthorized(message: impl Into<String>) -> Self {
        Self {
            code: "unauthorized",
            message: message.into(),
            retryable: false,
        }
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self {
            code: "not_found",
            message: message.into(),
            retryable: false,
        }
    }

    fn provider_unavailable(message: impl Into<String>) -> Self {
        Self {
            code: "provider_unavailable",
            message: message.into(),
            retryable: true,
        }
    }

    fn provider_rejected(message: impl Into<String>) -> Self {
        Self {
            code: "provider_rejected",
            message: message.into(),
            retryable: false,
        }
    }

    fn invalid_request(message: impl Into<String>) -> Self {
        Self {
            code: "invalid_request",
            message: message.into(),
            retryable: false,
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self {
            code: "internal_error",
            message: message.into(),
            retryable: false,
        }
    }
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
            Secret::Plain(_) => Self {
                provider: "plain",
                name: name.to_string(),
                path: path.to_path_buf(),
                secret_type: secret.secret_type(),
                kind: "plain",
                expires_at: None,
                account_id: None,
                created_at: None,
                updated_at: None,
                redacted_fields: vec!["value"],
            },
            Secret::OAuth(OAuthSecret {
                expires_at,
                account_id,
                created_at,
                updated_at,
                ..
            }) => Self {
                provider: OPENAI_CODEX_PROVIDER,
                name: name.to_string(),
                path: path.to_path_buf(),
                secret_type: secret.secret_type(),
                kind: OPENAI_CODEX_KIND,
                expires_at: Some(expires_at.to_rfc3339_opts(SecondsFormat::AutoSi, true)),
                account_id: account_id.clone(),
                created_at: created_at.map(|v| v.to_rfc3339_opts(SecondsFormat::AutoSi, true)),
                updated_at: updated_at.map(|v| v.to_rfc3339_opts(SecondsFormat::AutoSi, true)),
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

fn file_store_from_env() -> eyre::Result<FileStore> {
    Ok(FileStore::new(libvm::HostPaths::from_env()?.home()))
}

fn cli_secret_name(name: &str) -> eyre::Result<SecretName> {
    let name = SecretName::new(name)?;
    if name.as_str().starts_with("silo.") {
        eyre::bail!(
            "secret name `{}` is reserved for Silo-generated secrets",
            name.as_str()
        );
    }
    Ok(name)
}

fn expires_at_from_seconds(expires_in: i64) -> String {
    let expires_at = if expires_in > 0 {
        Utc::now() + chrono::Duration::seconds(expires_in)
    } else {
        Utc::now()
    };
    expires_at.to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn timestamp_now() -> chrono::DateTime<Utc> {
    let now = Utc::now();
    now - chrono::Duration::nanoseconds(i64::from(now.timestamp_subsec_nanos()))
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

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use clap::Parser;
    use reqwest::StatusCode;

    use crate::app::Cli;
    use crate::commands::Command;

    use crate::commands::secret::{
        egress_credentials_from_store, is_pending_device_poll_response, plain_secret_value,
        read_json_frame, set_plain_secret, slot_key, write_json_frame, write_plain_secret,
        LoginProvider, OAuthRefreshGrant, OAuthRefreshHookRequest, SecretSubcommand, SetCmd,
        OPENAI_CODEX_KIND,
    };
    use silo_secrets::{
        FileStore, OAuthSecret, Secret, SecretBytes, SecretKind, SecretName, SecretScope,
        SecretStore,
    };

    fn plain(value: &str) -> Secret {
        Secret::Plain(SecretBytes::new(value.as_bytes().to_vec()))
    }
    fn get(store: &FileStore, name: &str) -> Secret {
        store
            .get(&SecretScope::Home, &SecretName::legacy(name))
            .unwrap()
            .unwrap()
    }
    fn put(store: &FileStore, name: &str, secret: Secret) {
        store
            .put(&SecretScope::Home, &SecretName::new(name).unwrap(), secret)
            .unwrap();
    }

    #[test]
    fn secret_login_openai_codex_parses() {
        let cli = Cli::try_parse_from([
            "silo",
            "secret",
            "login",
            "openai-codex",
            "--name",
            "personal",
        ])
        .expect("secret login should parse");

        let secret = match cli.command {
            Command::Secret(command) => command,
            other => panic!("expected secret command, got {other:?}"),
        };
        let login = match secret.command {
            SecretSubcommand::Login(command) => command,
            other => panic!("expected login command, got {other:?}"),
        };

        assert_eq!(login.provider, LoginProvider::OpenAICodex);
        assert_eq!(login.name, "personal");
    }

    #[test]
    fn credentials_subcommand_is_removed() {
        assert!(Cli::try_parse_from(["silo", "credentials", "list"]).is_err());
    }

    #[test]
    fn secret_login_rejects_policy_credential_kind_as_provider() {
        assert!(Cli::try_parse_from([
            "silo",
            "secret",
            "login",
            "openai_codex_oauth",
            "--name",
            "personal",
        ])
        .is_err());
    }

    #[test]
    fn secret_refresh_oauth_parses_but_is_hidden() {
        let cli = Cli::try_parse_from([
            "silo",
            "secret",
            "refresh-oauth",
            "--store-file",
            "/tmp/secrets.json",
        ])
        .expect("hidden refresh command should parse");

        let secret = match cli.command {
            Command::Secret(command) => command,
            other => panic!("expected secret command, got {other:?}"),
        };
        assert!(matches!(secret.command, SecretSubcommand::RefreshOAuth(_)));

        let help = Cli::command().render_long_help().to_string();
        assert!(!help.contains("refresh-oauth"));
    }

    #[test]
    fn secret_set_exact_key_plain_value_parses() {
        let cli = Cli::try_parse_from([
            "silo",
            "secret",
            "set",
            "bearer_token.github-api.token",
            "--value",
            "secret-token",
            "--force",
        ])
        .expect("secret set should parse");

        let secret = match cli.command {
            Command::Secret(command) => command,
            other => panic!("expected secret command, got {other:?}"),
        };
        let set = match secret.command {
            SecretSubcommand::Set(command) => command,
            other => panic!("expected set command, got {other:?}"),
        };

        assert_eq!(set.target, ["bearer_token.github-api.token"]);
        assert_eq!(set.value.as_deref(), Some("secret-token"));
        assert!(set.force);
    }

    #[test]
    fn secret_set_provider_aware_value_parses() {
        let cli = Cli::try_parse_from([
            "silo",
            "secret",
            "set",
            "bearer_token",
            "github-api",
            "--token-stdin",
            "--force",
        ])
        .expect("provider-aware secret set should parse");

        let secret = match cli.command {
            Command::Secret(command) => command,
            other => panic!("expected secret command, got {other:?}"),
        };
        let set = match secret.command {
            SecretSubcommand::Set(command) => command,
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
        let store = FileStore::new(dir.path());
        let mut command = set_cmd(["bearer_token", "github-api"]);
        command.token = Some("secret-token".to_string());

        set_plain_secret(&store, &command).expect("write bearer token");

        let loaded = get(&store, "bearer_token.github-api.token");
        match loaded {
            Secret::Plain(value) => assert_eq!(value.as_str().unwrap(), "secret-token"),
            other => panic!("expected plain secret, got {other:?}"),
        }
    }

    #[test]
    fn set_provider_aware_aws_profile_writes_profile_slot() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = FileStore::new(dir.path());
        let mut command = set_cmd(["aws_credential", "prod"]);
        command.profile = Some("production-admin".to_string());

        set_plain_secret(&store, &command).expect("write aws profile");

        let loaded = get(&store, "aws_credential.prod.profile");
        match loaded {
            Secret::Plain(value) => assert_eq!(value.as_str().unwrap(), "production-admin"),
            other => panic!("expected plain secret, got {other:?}"),
        }
    }

    #[test]
    fn set_provider_aware_aws_static_writes_required_slots() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = FileStore::new(dir.path());
        let mut command = set_cmd(["aws_credential", "prod"]);
        command.access_key_id = Some("AKIAEXAMPLE".to_string());
        command.secret_access_key = Some("secret".to_string());
        command.session_token = Some("session".to_string());

        set_plain_secret(&store, &command).expect("write aws slots");

        assert_plain_secret(&store, "aws_credential.prod.access_key_id", "AKIAEXAMPLE");
        assert_plain_secret(&store, "aws_credential.prod.secret_access_key", "secret");
        assert_plain_secret(&store, "aws_credential.prod.session_token", "session");
    }

    #[test]
    fn egress_credentials_read_openai_oauth_secret() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = FileStore::new(dir.path());
        let key = slot_key(OPENAI_CODEX_KIND, "personal", "oauth");
        put(
            &store,
            &key,
            Secret::OAuth(OAuthSecret {
                provider: None,
                access_token: SecretBytes::new(b"access-token".to_vec()),
                refresh_token: SecretBytes::new(b"refresh-token".to_vec()),
                expires_at: "2026-07-04T00:00:00Z".parse().unwrap(),
                account_id: Some("acct_123".to_string()),
                created_at: Some("2026-07-03T00:00:00Z".parse().unwrap()),
                updated_at: Some("2026-07-03T00:00:00Z".parse().unwrap()),
            }),
        );
        let policy = network_policy(
            r#"{
                "version": 1,
                "endpoints": [
                    { "name": "openai", "kind": "https", "family": "http", "transport": "https-mitm", "tls": "terminate", "capabilities": ["credential-injection"], "hosts": ["chatgpt.com"] }
                ],
                "credentials": [
                    { "name": "personal", "kind": "openai_codex_oauth", "endpoint": "openai" }
                ]
            }"#,
        );

        let launch = egress_credentials_from_store(
            &policy,
            &store,
            PathBuf::from("/usr/bin/silo").as_path(),
        )
        .expect("egress credentials");

        assert_egress_secret(&launch, "personal.oauth.access_token", "access-token");
        assert_egress_secret(&launch, "personal.oauth.expires_at", "2026-07-04T00:00:00Z");
        assert_egress_secret(&launch, "personal.oauth.account_id", "acct_123");
        assert!(!launch
            .secrets
            .iter()
            .any(|secret| secret.value == b"refresh-token"));

        let hook = launch.oauth_refresh_hook.as_ref().expect("oauth hook");
        assert_eq!(hook.command, PathBuf::from("/usr/bin/silo"));
        assert_eq!(
            hook.args,
            vec![
                "secret".to_string(),
                "refresh-oauth".to_string(),
                "--store-file".to_string(),
                store.path().to_string_lossy().to_string(),
            ]
        );
        let grant: OAuthRefreshGrant = serde_json::from_slice(&hook.auth).expect("hook grant");
        assert_eq!(grant.store_file, store.path());
        assert_eq!(grant.credentials.len(), 1);
        assert_eq!(grant.credentials[0].name, "personal");
        assert_eq!(grant.credentials[0].kind, OPENAI_CODEX_KIND);
        assert_eq!(grant.credentials[0].endpoint, "openai");
        assert_eq!(grant.credentials[0].secret_key, key);
    }

    #[test]
    fn egress_credentials_report_missing_oauth_secret_with_hint() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = FileStore::new(dir.path());
        let policy = network_policy(
            r#"{
                "version": 1,
                "endpoints": [
                    { "name": "openai", "kind": "https", "family": "http", "transport": "https-mitm", "tls": "terminate", "capabilities": ["credential-injection"], "hosts": ["chatgpt.com"] }
                ],
                "credentials": [
                    { "name": "personal", "kind": "openai_codex_oauth", "endpoint": "openai" }
                ]
            }"#,
        );

        let error = egress_credentials_from_store(
            &policy,
            &store,
            PathBuf::from("/usr/bin/silo").as_path(),
        )
        .expect_err("missing secret");
        let message = error.to_string();

        assert!(message.contains("personal.oauth.access_token"));
        assert!(message.contains("personal.oauth.expires_at"));
        assert!(message.contains("openai_codex_oauth.personal.oauth"));
        assert!(message.contains("silo secret login openai-codex --name personal"));
    }

    #[test]
    fn egress_credentials_read_provider_plain_secret() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = FileStore::new(dir.path());
        put(
            &store,
            "bearer_token.github-api.token",
            plain("github-token"),
        );
        let policy = network_policy(
            r#"{
                "version": 1,
                "endpoints": [
                    { "name": "github", "kind": "https", "family": "http", "transport": "https-mitm", "tls": "terminate", "capabilities": ["credential-injection"], "hosts": ["github.com"] }
                ],
                "credentials": [
                    { "name": "github-api", "kind": "bearer_token", "endpoint": "github" }
                ]
            }"#,
        );

        let launch = egress_credentials_from_store(
            &policy,
            &store,
            PathBuf::from("/usr/bin/silo").as_path(),
        )
        .expect("egress credentials");

        assert_egress_secret(&launch, "github-api.token", "github-token");
        assert!(launch.oauth_refresh_hook.is_none());
    }

    #[test]
    fn egress_credentials_read_aws_profile_secret() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = FileStore::new(dir.path());
        put(
            &store,
            "aws_credential.prod.profile",
            plain("production-admin"),
        );
        put(
            &store,
            "aws_credential.prod.access_key_id",
            plain("AKIAIGNORED"),
        );
        put(
            &store,
            "aws_credential.prod.secret_access_key",
            plain("ignored-secret"),
        );
        let policy = aws_network_policy();

        let launch = egress_credentials_from_store(
            &policy,
            &store,
            PathBuf::from("/usr/bin/silo").as_path(),
        )
        .expect("egress credentials");

        assert_egress_secret(&launch, "prod.profile", "production-admin");
        assert!(!launch
            .secrets
            .iter()
            .any(|secret| secret.slot == "prod.access_key_id"));
        assert!(!launch
            .secrets
            .iter()
            .any(|secret| secret.slot == "prod.secret_access_key"));
    }

    #[test]
    fn egress_credentials_read_aws_static_secret_pair() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = FileStore::new(dir.path());
        put(
            &store,
            "aws_credential.prod.access_key_id",
            plain("AKIAEXAMPLE"),
        );
        put(
            &store,
            "aws_credential.prod.secret_access_key",
            plain("secret"),
        );
        put(
            &store,
            "aws_credential.prod.session_token",
            plain("session"),
        );
        let policy = aws_network_policy();

        let launch = egress_credentials_from_store(
            &policy,
            &store,
            PathBuf::from("/usr/bin/silo").as_path(),
        )
        .expect("egress credentials");

        assert_egress_secret(&launch, "prod.access_key_id", "AKIAEXAMPLE");
        assert_egress_secret(&launch, "prod.secret_access_key", "secret");
        assert_egress_secret(&launch, "prod.session_token", "session");
    }

    #[test]
    fn egress_legacy_raw_slots_take_precedence_and_profiles_suppress_stale_fields() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileStore::new(dir.path());
        put(&store, "aws_credential.prod.profile", plain("canonical"));
        put(&store, "prod.profile", plain("legacy-profile"));
        // Empty stale static fields must never be projected when a profile wins.
        put(&store, "prod.access_key_id", plain(""));
        put(&store, "aws_credential.prod.secret_access_key", plain(""));
        let credentials = egress_credentials_from_store(
            &aws_network_policy(),
            &store,
            std::path::Path::new("/usr/bin/silo"),
        )
        .unwrap();
        assert_eq!(credentials.secrets.len(), 1);
        assert_egress_secret(&credentials, "prod.profile", "legacy-profile");
    }

    #[test]
    fn egress_oauth_raw_overrides_and_optional_tailscale() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileStore::new(dir.path());
        let policy = network_policy(
            r#"{
            "version":1,
            "endpoints":[{"name":"api","kind":"https","family":"http","transport":"https-mitm","tls":"terminate","capabilities":["credential-injection"],"hosts":["example.com"]}],
            "credentials":[{"name":"personal","kind":"openai_codex_oauth","endpoint":"api"}],
            "tailscale":[{"name":"work"}]
        }"#,
        );
        put(
            &store,
            "personal.oauth.access_token",
            plain("legacy-access"),
        );
        put(
            &store,
            "personal.oauth.expires_at",
            plain("2026-09-30T00:00:00Z"),
        );
        let credentials =
            egress_credentials_from_store(&policy, &store, std::path::Path::new("/usr/bin/silo"))
                .unwrap();
        assert_eq!(credentials.secrets.len(), 2);
        assert!(credentials.oauth_refresh_hook.is_none());
        assert_egress_secret(&credentials, "personal.oauth.access_token", "legacy-access");
        put(&store, "tailscale.work.auth_key", plain("canonical-key"));
        put(&store, "work.tailscale.auth_key", plain("legacy-key"));
        let credentials =
            egress_credentials_from_store(&policy, &store, std::path::Path::new("/usr/bin/silo"))
                .unwrap();
        assert_egress_secret(&credentials, "work.tailscale.auth_key", "legacy-key");
        put(&store, "personal.oauth.access_token", plain(""));
        assert!(egress_credentials_from_store(
            &policy,
            &store,
            std::path::Path::new("/usr/bin/silo")
        )
        .unwrap_err()
        .to_string()
        .contains("has an empty value"));
    }

    #[test]
    fn egress_credentials_report_missing_aws_profile_or_static_pair() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = FileStore::new(dir.path());
        put(
            &store,
            "aws_credential.prod.session_token",
            plain("session"),
        );
        let policy = aws_network_policy();

        let error = egress_credentials_from_store(
            &policy,
            &store,
            PathBuf::from("/usr/bin/silo").as_path(),
        )
        .expect_err("missing aws credential material");
        let message = error.to_string();

        assert!(message.contains("aws_credential.prod.profile"));
        assert!(message.contains("prod.profile"));
        assert!(message.contains("aws_credential.prod.access_key_id"));
        assert!(message.contains("aws_credential.prod.secret_access_key"));
        assert!(message.contains("silo secret set aws_credential prod --profile <profile>"));
    }

    #[test]
    fn oauth_refresh_frames_round_trip_json() {
        let request = OAuthRefreshHookRequest {
            version: 1,
            operation: "oauth_refresh".to_string(),
            grant: "e30=".to_string(),
            credential: crate::commands::secret::OAuthRefreshHookCredential {
                name: "personal".to_string(),
                kind: OPENAI_CODEX_KIND.to_string(),
                endpoint: "openai".to_string(),
            },
            reason: "expires_soon".to_string(),
            expires_at: "2026-07-04T00:00:00Z".to_string(),
        };
        let mut frame = Vec::new();
        write_json_frame(&mut frame, &request).expect("write frame");

        let decoded: OAuthRefreshHookRequest =
            read_json_frame(frame.as_slice()).expect("read frame");
        assert_eq!(decoded.version, 1);
        assert_eq!(decoded.operation, "oauth_refresh");
        assert_eq!(decoded.grant, "e30=");
        assert_eq!(decoded.credential.name, "personal");
        assert_eq!(decoded.credential.kind, OPENAI_CODEX_KIND);
        assert_eq!(decoded.credential.endpoint, "openai");
    }

    #[test]
    fn write_plain_secret_writes_and_protects_existing_secret() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = FileStore::new(dir.path());

        write_plain_secret(&store, "api-token", "secret-token".to_string(), false)
            .expect("write plain secret");
        let loaded = get(&store, "api-token");
        match loaded {
            Secret::Plain(value) => assert_eq!(value.as_str().unwrap(), "secret-token"),
            other => panic!("expected plain secret, got {other:?}"),
        }

        assert!(write_plain_secret(&store, "api-token", "new-token".to_string(), false).is_err());
        write_plain_secret(&store, "api-token", "new-token".to_string(), true)
            .expect("force replace plain secret");
        let loaded = get(&store, "api-token");
        match loaded {
            Secret::Plain(value) => assert_eq!(value.as_str().unwrap(), "new-token"),
            other => panic!("expected plain secret, got {other:?}"),
        }
    }

    #[test]
    fn secret_store_writes_single_json_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("secrets.json");
        let store = FileStore::with_store_file(path.clone()).unwrap();
        let secret = Secret::OAuth(OAuthSecret {
            provider: None,
            access_token: SecretBytes::new(b"access".to_vec()),
            refresh_token: SecretBytes::new(b"refresh".to_vec()),
            expires_at: "2026-06-02T12:00:00Z".parse().unwrap(),
            account_id: None,
            created_at: Some("2026-06-02T11:00:00Z".parse().unwrap()),
            updated_at: Some("2026-06-02T11:00:00Z".parse().unwrap()),
        });

        let key = slot_key(OPENAI_CODEX_KIND, "personal", "oauth");
        put(&store, &key, secret);

        assert_eq!(path, dir.path().join("secrets.json"));
        let raw = std::fs::read_to_string(&path).expect("read secret store");
        assert!(raw.contains(r#""type": "oauth""#));
        let loaded = get(&store, &key);
        match loaded {
            Secret::OAuth(o) => assert_eq!(o.refresh_token.as_str().unwrap(), "refresh"),
            other => panic!("expected oauth secret, got {other:?}"),
        }
        let listed = store.list(&SecretScope::Home).expect("list secrets");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].kind, SecretKind::OAuth);

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
        let store = FileStore::new(dir.path());

        assert!(store
            .put(
                &SecretScope::Home,
                &SecretName::legacy("../bad"),
                plain("bad")
            )
            .is_err());
        assert!(store
            .put(
                &SecretScope::Home,
                &SecretName::legacy(".hidden"),
                plain("bad")
            )
            .is_err());
    }

    #[test]
    fn secret_store_reads_shared_fixture() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("testdata/secrets/basic.json");
        let dir = tempfile::tempdir().unwrap();
        std::fs::copy(path, dir.path().join("secrets.json")).unwrap();
        let store = FileStore::new(dir.path());

        let plain = get(&store, "something");
        match plain {
            Secret::Plain(value) => assert_eq!(value.as_str().unwrap(), "123"),
            other => panic!("expected plain secret, got {other:?}"),
        }

        let oauth = get(&store, "openai_codex_oauth.personal.oauth");
        match oauth {
            Secret::OAuth(OAuthSecret {
                access_token,
                refresh_token,
                ..
            }) => {
                assert_eq!(access_token.as_str().unwrap(), "access-token");
                assert_eq!(refresh_token.as_str().unwrap(), "refresh-token");
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

    fn network_policy(source: &str) -> libvm::NetworkPolicy {
        libvm::NetworkPolicy::from_json_str(source).expect("network policy")
    }

    fn aws_network_policy() -> libvm::NetworkPolicy {
        network_policy(
            r#"{
                "version": 1,
                "endpoints": [
                    { "name": "aws", "kind": "https", "family": "http", "transport": "https-mitm", "tls": "terminate", "capabilities": ["credential-injection"], "hosts": ["sts.amazonaws.com"] }
                ],
                "credentials": [
                    { "name": "prod", "kind": "aws_credential", "endpoint": "aws" }
                ]
            }"#,
        )
    }

    fn assert_egress_secret(credentials: &libvm::EgressCredentials, slot: &str, expected: &str) {
        let secret = credentials
            .secrets
            .iter()
            .find(|secret| secret.slot == slot)
            .unwrap_or_else(|| panic!("missing egress secret {slot}"));
        assert_eq!(secret.value, expected.as_bytes());
    }

    fn assert_plain_secret(store: &FileStore, name: &str, expected: &str) {
        let loaded = get(store, name);
        match loaded {
            Secret::Plain(value) => assert_eq!(value.as_str().unwrap(), expected),
            other => panic!("expected plain secret, got {other:?}"),
        }
    }
}
