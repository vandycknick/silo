use std::collections::BTreeMap;
use std::io::{BufRead, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{SecondsFormat, Utc};
use clap::{Args, Subcommand};
use libvm::{
    NetworkCredential, NetworkLaunch, NetworkPolicy, NetworkSecretAlternative, NetworkSecretKind,
    NetworkSecretRequirement, NetworkSecretSlot, OAuthRefreshHook,
};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::Value;

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
const SECRET_STORE_FILE_NAME: &str = "secrets.json";
const OAUTH_REFRESH_AUTH_ENV: &str = "SILO_NET_OAUTH_REFRESH_AUTH";

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
                let store = SecretStore::from_env()?;
                login(&store, command).await
            }
            SecretSubcommand::Set(command) => {
                let store = SecretStore::from_env()?;
                set_plain_secret(&store, command)
            }
            SecretSubcommand::List(command) => {
                let store = SecretStore::from_env()?;
                list_secrets(&store, command)
            }
            SecretSubcommand::Show(command) => {
                let store = SecretStore::from_env()?;
                show_secret(&store, command)
            }
            SecretSubcommand::Rm(command) => {
                let store = SecretStore::from_env()?;
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

async fn login(store: &SecretStore, command: &LoginCmd) -> eyre::Result<()> {
    let key = slot_key(OPENAI_CODEX_KIND, &command.name, "oauth");
    if store.contains(&key)? {
        eyre::bail!(
            "secret `{}` already exists in {}",
            key,
            store.path().display()
        );
    }

    let token = match command.provider {
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

fn set_plain_secret(store: &SecretStore, command: &SetCmd) -> eyre::Result<()> {
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
    store: &SecretStore,
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
    ui::success(format!(
        "saved secret `{}` in {}",
        name,
        store.path().display()
    ));
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

pub(crate) fn network_launch_from_secret_store(
    policy: &NetworkPolicy,
) -> eyre::Result<NetworkLaunch> {
    if policy.secret_slots().is_empty() {
        return Ok(NetworkLaunch::new());
    }
    let hook_command = std::env::current_exe()?;
    let store = SecretStore::from_env()?;
    network_launch_from_store(policy, &store, &hook_command)
}

fn network_launch_from_store(
    policy: &NetworkPolicy,
    store: &SecretStore,
    hook_command: &Path,
) -> eyre::Result<NetworkLaunch> {
    let mut launch = NetworkLaunch::new();
    let mut supplied_slots = std::collections::BTreeSet::new();
    for slot in policy.secret_slots() {
        if should_skip_network_slot(policy, store, &slot)? {
            continue;
        }
        if let Some(value) = network_secret_value(policy, store, &slot)? {
            supplied_slots.insert(slot.name.clone());
            launch = launch.secret(slot.name, value);
        }
    }
    let missing = missing_network_secret_requirements(policy, &supplied_slots);
    if !missing.is_empty() {
        eyre::bail!(format_missing_network_secrets(&missing, store.path()));
    }
    if let Some(hook) = oauth_refresh_hook_from_store(policy, store, hook_command)? {
        launch = launch.oauth_refresh_hook(hook);
    }
    Ok(launch)
}

fn oauth_refresh_hook_from_store(
    policy: &NetworkPolicy,
    store: &SecretStore,
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
    store: &SecretStore,
) -> eyre::Result<OAuthRefreshGrant> {
    let mut credentials = Vec::new();
    for credential in policy.credentials() {
        if !credential_uses_oauth_secret_slots(policy, credential) {
            continue;
        }
        let key = slot_key(&credential.kind, &credential.name, "oauth");
        let Some(secret) = store.get_optional(&key)? else {
            continue;
        };
        if matches!(secret, Secret::OAuth { .. }) {
            credentials.push(OAuthRefreshGrantCredential {
                name: credential.name.clone(),
                kind: credential.kind.clone(),
                endpoint: credential.endpoint.clone(),
                secret_key: key,
            });
        }
    }
    Ok(OAuthRefreshGrant {
        version: 1,
        store_file: store.path().to_path_buf(),
        credentials,
    })
}

fn credential_uses_oauth_secret_slots(
    policy: &NetworkPolicy,
    credential: &NetworkCredential,
) -> bool {
    let prefix = format!("{}.", credential.name);
    policy
        .secret_slots()
        .into_iter()
        .any(|slot| slot.kind == NetworkSecretKind::OAuth && slot.name.starts_with(prefix.as_str()))
}

fn network_secret_value(
    policy: &NetworkPolicy,
    store: &SecretStore,
    slot: &NetworkSecretSlot,
) -> eyre::Result<Option<String>> {
    if let Some(secret) = store.get_optional(&slot.name)? {
        return secret_plain_value(&slot.name, secret, store.path()).map(Some);
    }

    if let Some(credential) = credential_for_slot(policy, &slot.name) {
        return credential_secret_value(store, credential, slot);
    }

    tailscale_secret_value(store, &slot.name)
}

fn should_skip_network_slot(
    policy: &NetworkPolicy,
    store: &SecretStore,
    slot: &NetworkSecretSlot,
) -> eyre::Result<bool> {
    let Some(credential) = credential_for_slot(policy, &slot.name) else {
        return Ok(false);
    };
    if credential.kind != "aws_credential" {
        return Ok(false);
    }
    let Some(slot_suffix) = slot.name.strip_prefix(&format!("{}.", credential.name)) else {
        return Ok(false);
    };
    if !matches!(
        slot_suffix,
        "access_key_id" | "secret_access_key" | "session_token"
    ) {
        return Ok(false);
    }
    Ok(network_secret_value(
        policy,
        store,
        &NetworkSecretSlot {
            name: format!("{}.profile", credential.name),
            required: false,
            kind: NetworkSecretKind::Plain,
        },
    )?
    .is_some())
}

fn credential_secret_value(
    store: &SecretStore,
    credential: &NetworkCredential,
    slot: &NetworkSecretSlot,
) -> eyre::Result<Option<String>> {
    let Some(slot_suffix) = slot.name.strip_prefix(&format!("{}.", credential.name)) else {
        return Ok(None);
    };
    match slot.kind {
        NetworkSecretKind::Plain => {
            let key = slot_key(&credential.kind, &credential.name, slot_suffix);
            store
                .get_optional(&key)?
                .map(|secret| secret_plain_value(&key, secret, store.path()))
                .transpose()
        }
        NetworkSecretKind::OAuth => {
            let Some(oauth_field) = slot_suffix.strip_prefix("oauth.") else {
                return Ok(None);
            };
            let key = slot_key(&credential.kind, &credential.name, "oauth");
            let Some(secret) = store.get_optional(&key)? else {
                return Ok(None);
            };
            secret_oauth_field(&key, secret, oauth_field, store.path())
        }
    }
}

fn tailscale_secret_value(store: &SecretStore, slot_name: &str) -> eyre::Result<Option<String>> {
    let Some((name, "tailscale.auth_key")) = slot_name.split_once('.') else {
        return Ok(None);
    };
    let key = format!("tailscale.{name}.auth_key");
    store
        .get_optional(&key)?
        .map(|secret| secret_plain_value(&key, secret, store.path()))
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

fn secret_plain_value(key: &str, secret: Secret, path: &Path) -> eyre::Result<String> {
    match secret {
        Secret::Plain { value } => non_empty_secret_value(key, value, path),
        other => eyre::bail!(
            "secret `{key}` in {} has type {}, expected plain",
            path.display(),
            other.secret_type()
        ),
    }
}

fn secret_oauth_field(
    key: &str,
    secret: Secret,
    field: &str,
    path: &Path,
) -> eyre::Result<Option<String>> {
    let Secret::OAuth {
        access_token,
        expires_at,
        account_id,
        ..
    } = secret
    else {
        eyre::bail!(
            "secret `{key}` in {} has type plain, expected oauth",
            path.display()
        );
    };
    match field {
        "access_token" => non_empty_secret_value(key, access_token, path).map(Some),
        "expires_at" => non_empty_secret_value(key, expires_at, path).map(Some),
        "account_id" => account_id
            .map(|value| non_empty_secret_value(key, value, path))
            .transpose(),
        _ => Ok(None),
    }
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
    if let Some(credential) = credential_for_alternative(policy, alternative) {
        let slot_suffixes = alternative
            .slots
            .iter()
            .filter_map(|slot| slot.strip_prefix(&format!("{}.", credential.name)))
            .collect::<Vec<_>>();
        let slot_kinds = alternative
            .slots
            .iter()
            .filter_map(|slot_name| policy_slot(policy, slot_name).map(|slot| slot.kind))
            .collect::<Vec<_>>();
        if slot_kinds
            .iter()
            .all(|kind| *kind == NetworkSecretKind::OAuth)
        {
            return vec![
                vec![slot_key(&credential.kind, &credential.name, "oauth")],
                alternative.slots.clone(),
            ];
        }
        if slot_kinds
            .iter()
            .all(|kind| *kind == NetworkSecretKind::Plain)
            && slot_suffixes.len() == alternative.slots.len()
        {
            return vec![
                slot_suffixes
                    .iter()
                    .map(|suffix| slot_key(&credential.kind, &credential.name, suffix))
                    .collect(),
                alternative.slots.clone(),
            ];
        }
    }

    if let Some(tunnel_name) = tailscale_tunnel_for_alternative(alternative) {
        return vec![
            vec![format!("tailscale.{tunnel_name}.auth_key")],
            alternative.slots.clone(),
        ];
    }

    vec![alternative.slots.clone()]
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

fn list_secrets(store: &SecretStore, command: &ListCmd) -> eyre::Result<()> {
    let secrets = store.list()?;
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

fn show_secret(store: &SecretStore, command: &ShowCmd) -> eyre::Result<()> {
    let path = store.path();
    if command.path {
        println!("{}", path.display());
        return Ok(());
    }
    let secret = store.get(&command.name)?;
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

fn remove_secret(store: &SecretStore, command: &RmCmd) -> eyre::Result<()> {
    if !command.force {
        eyre::bail!(
            "refusing to remove secret `{}` without --force",
            command.name
        );
    }
    store.remove(&command.name)?;
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
    let store = SecretStore::new(command.store_file.clone());
    let response = match refresh_oauth_request(&store, &command.store_file, request).await {
        Ok(oauth) => OAuthRefreshHookResponse::ok(oauth),
        Err(error) => OAuthRefreshHookResponse::error(error),
    };
    write_json_frame(std::io::stdout().lock(), &response)
}

async fn refresh_oauth_request(
    store: &SecretStore,
    store_file: &Path,
    request: OAuthRefreshHookRequest,
) -> Result<OAuthRefreshHookOAuth, OAuthRefreshFailure> {
    if request.version != 1 || request.operation != "oauth_refresh" {
        return Err(OAuthRefreshFailure::invalid_request(
            "unsupported OAuth refresh request",
        ));
    }
    let encoded_auth = std::env::var(OAUTH_REFRESH_AUTH_ENV).map_err(|_| {
        OAuthRefreshFailure::unauthorized(format!("{OAUTH_REFRESH_AUTH_ENV} is required"))
    })?;
    let grant = decode_oauth_refresh_grant(&encoded_auth)?;
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
    let secret = store
        .get_optional(&grant_credential.secret_key)
        .map_err(|err| OAuthRefreshFailure::internal(err.to_string()))?
        .ok_or_else(|| OAuthRefreshFailure::not_found("OAuth secret was not found"))?;
    match request.credential.kind.as_str() {
        OPENAI_CODEX_KIND => {
            refresh_openai_codex_oauth(store, &grant_credential.secret_key, secret).await
        }
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
    store: &SecretStore,
    key: &str,
    secret: Secret,
) -> Result<OAuthRefreshHookOAuth, OAuthRefreshFailure> {
    let Secret::OAuth {
        refresh_token,
        account_id,
        created_at,
        ..
    } = secret
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
    let token = refresh_openai_codex_token(&client, &refresh_token).await?;
    let next_refresh_token = if token.refresh_token.is_empty() {
        refresh_token
    } else {
        token.refresh_token
    };
    let expires_at = expires_at_from_seconds(token.expires_in);
    let updated = Secret::OAuth {
        access_token: token.access_token.clone(),
        refresh_token: next_refresh_token,
        expires_at: expires_at.clone(),
        account_id: account_id.clone(),
        created_at,
        updated_at: rfc3339_now(),
    };
    store
        .put(key, updated)
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
            Self::Plain { .. } => "plain",
            Self::OAuth { .. } => OPENAI_CODEX_PROVIDER,
        }
    }

    fn kind(&self) -> &'static str {
        match self {
            Self::Plain { .. } => "plain",
            Self::OAuth { .. } => OPENAI_CODEX_KIND,
        }
    }

    fn secret_type(&self) -> &'static str {
        match self {
            Self::Plain { .. } => "plain",
            Self::OAuth { .. } => "oauth",
        }
    }

    fn expires_at(&self) -> Option<&str> {
        match self {
            Self::Plain { .. } => None,
            Self::OAuth { expires_at, .. } => Some(expires_at.as_str()),
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
        self.get_optional(name)?
            .ok_or_else(|| eyre::eyre!("secret `{name}` not found"))
    }

    fn get_optional(&self, name: &str) -> eyre::Result<Option<Secret>> {
        validate_secret_name(name)?;
        Ok(self.read_all()?.remove(name))
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
        return Ok(data_home.join("silo"));
    }
    let home = env_absolute_path("HOME")?
        .ok_or_else(|| eyre::eyre!("could not resolve Silo data dir from HOME"))?;
    Ok(home.join(".local/share/silo"))
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

    use crate::app::Cli;
    use crate::commands::Command;

    use super::{
        is_pending_device_poll_response, network_launch_from_store, plain_secret_value,
        read_json_frame, set_plain_secret, slot_key, write_json_frame, write_plain_secret,
        LoginProvider, OAuthRefreshGrant, OAuthRefreshHookRequest, Secret, SecretStore,
        SecretSubcommand, SetCmd, OPENAI_CODEX_KIND,
    };

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
        let store = SecretStore::new(dir.path().join("secrets.json"));
        let mut command = set_cmd(["bearer_token", "github-api"]);
        command.token = Some("secret-token".to_string());

        set_plain_secret(&store, &command).expect("write bearer token");

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
        let mut command = set_cmd(["aws_credential", "prod"]);
        command.profile = Some("production-admin".to_string());

        set_plain_secret(&store, &command).expect("write aws profile");

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
    fn network_launch_reads_openai_oauth_secret() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = SecretStore::new(dir.path().join("secrets.json"));
        let key = slot_key(OPENAI_CODEX_KIND, "personal", "oauth");
        store
            .put(
                &key,
                Secret::OAuth {
                    access_token: "access-token".to_string(),
                    refresh_token: "refresh-token".to_string(),
                    expires_at: "2026-07-04T00:00:00Z".to_string(),
                    account_id: Some("acct_123".to_string()),
                    created_at: "2026-07-03T00:00:00Z".to_string(),
                    updated_at: "2026-07-03T00:00:00Z".to_string(),
                },
            )
            .expect("write oauth secret");
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

        let launch =
            network_launch_from_store(&policy, &store, PathBuf::from("/usr/bin/silo").as_path())
                .expect("network launch");

        assert_network_secret(&launch, "personal.oauth.access_token", "access-token");
        assert_network_secret(&launch, "personal.oauth.expires_at", "2026-07-04T00:00:00Z");
        assert_network_secret(&launch, "personal.oauth.account_id", "acct_123");
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
    fn network_launch_reports_missing_oauth_secret_with_hint() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = SecretStore::new(dir.path().join("secrets.json"));
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

        let error =
            network_launch_from_store(&policy, &store, PathBuf::from("/usr/bin/silo").as_path())
                .expect_err("missing secret");
        let message = error.to_string();

        assert!(message.contains("personal.oauth.access_token"));
        assert!(message.contains("personal.oauth.expires_at"));
        assert!(message.contains("openai_codex_oauth.personal.oauth"));
        assert!(message.contains("silo secret login openai-codex --name personal"));
    }

    #[test]
    fn network_launch_reads_provider_plain_secret() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = SecretStore::new(dir.path().join("secrets.json"));
        store
            .put(
                "bearer_token.github-api.token",
                Secret::Plain {
                    value: "github-token".to_string(),
                },
            )
            .expect("write token secret");
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

        let launch =
            network_launch_from_store(&policy, &store, PathBuf::from("/usr/bin/silo").as_path())
                .expect("network launch");

        assert_network_secret(&launch, "github-api.token", "github-token");
        assert!(launch.oauth_refresh_hook.is_none());
    }

    #[test]
    fn network_launch_reads_aws_profile_secret() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = SecretStore::new(dir.path().join("secrets.json"));
        store
            .put(
                "aws_credential.prod.profile",
                Secret::Plain {
                    value: "production-admin".to_string(),
                },
            )
            .expect("write aws profile");
        store
            .put(
                "aws_credential.prod.access_key_id",
                Secret::Plain {
                    value: "AKIAIGNORED".to_string(),
                },
            )
            .expect("write ignored access key");
        store
            .put(
                "aws_credential.prod.secret_access_key",
                Secret::Plain {
                    value: "ignored-secret".to_string(),
                },
            )
            .expect("write ignored secret key");
        let policy = aws_network_policy();

        let launch =
            network_launch_from_store(&policy, &store, PathBuf::from("/usr/bin/silo").as_path())
                .expect("network launch");

        assert_network_secret(&launch, "prod.profile", "production-admin");
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
    fn network_launch_reads_aws_static_secret_pair() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = SecretStore::new(dir.path().join("secrets.json"));
        store
            .put(
                "aws_credential.prod.access_key_id",
                Secret::Plain {
                    value: "AKIAEXAMPLE".to_string(),
                },
            )
            .expect("write access key");
        store
            .put(
                "aws_credential.prod.secret_access_key",
                Secret::Plain {
                    value: "secret".to_string(),
                },
            )
            .expect("write secret key");
        store
            .put(
                "aws_credential.prod.session_token",
                Secret::Plain {
                    value: "session".to_string(),
                },
            )
            .expect("write session token");
        let policy = aws_network_policy();

        let launch =
            network_launch_from_store(&policy, &store, PathBuf::from("/usr/bin/silo").as_path())
                .expect("network launch");

        assert_network_secret(&launch, "prod.access_key_id", "AKIAEXAMPLE");
        assert_network_secret(&launch, "prod.secret_access_key", "secret");
        assert_network_secret(&launch, "prod.session_token", "session");
    }

    #[test]
    fn network_launch_reports_missing_aws_profile_or_static_pair() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = SecretStore::new(dir.path().join("secrets.json"));
        store
            .put(
                "aws_credential.prod.session_token",
                Secret::Plain {
                    value: "session".to_string(),
                },
            )
            .expect("write session token");
        let policy = aws_network_policy();

        let error =
            network_launch_from_store(&policy, &store, PathBuf::from("/usr/bin/silo").as_path())
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
            credential: super::OAuthRefreshHookCredential {
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
        assert_eq!(decoded.credential.name, "personal");
        assert_eq!(decoded.credential.kind, OPENAI_CODEX_KIND);
        assert_eq!(decoded.credential.endpoint, "openai");
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

    fn assert_network_secret(launch: &libvm::NetworkLaunch, slot: &str, expected: &str) {
        let secret = launch
            .secrets
            .iter()
            .find(|secret| secret.slot == slot)
            .unwrap_or_else(|| panic!("missing network secret {slot}"));
        assert_eq!(secret.value, expected.as_bytes());
    }

    fn assert_plain_secret(store: &SecretStore, name: &str, expected: &str) {
        let loaded = store.get(name).expect("read plain secret");
        match loaded {
            Secret::Plain { value } => assert_eq!(value, expected),
            other => panic!("expected plain secret, got {other:?}"),
        }
    }
}
