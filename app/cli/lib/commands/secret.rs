use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{SecondsFormat, Utc};
use clap::{Args, Subcommand};
use libvm::{
    NetworkCredential, NetworkPolicy, NetworkSecretAlternative, NetworkSecretRequirement,
    NetworkSecretSlot,
};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use silo_secrets::grant::{
    read_json_frame, write_json_frame, ProjectedSecret, ProviderError, ProviderRequest,
    ProviderResponse, SecretGrant,
};
use silo_secrets::{
    FileStore, OAuthSecret, Secret, SecretBytes, SecretName, SecretScope, SecretStore,
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
    #[command(name = "provide", hide = true)]
    Provide(ProvideCmd),
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
pub(crate) struct ProvideCmd {
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
            SecretSubcommand::Provide(command) => provide(command).await,
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

pub(crate) fn map_start_error(error: libvm::LibVmError, home: Option<&Path>) -> eyre::Report {
    match error {
        libvm::LibVmError::MissingNetworkSecrets {
            requirements,
            policy,
            ..
        } => {
            let missing = requirements
                .iter()
                .map(|r| MissingNetworkSecret::new(&policy, r))
                .collect::<Vec<_>>();
            eyre::eyre!(format_missing_network_secrets(
                &missing,
                &home.unwrap_or(Path::new(".")).join("secrets.json")
            ))
        }
        other => other.into(),
    }
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

async fn provide(command: &ProvideCmd) -> eyre::Result<()> {
    let result = match read_json_frame(std::io::stdin().lock()) {
        Ok(request) => provide_request(&command.store_file, request, OPENAI_TOKEN_URL).await,
        Err(_) => Err(OAuthRefreshFailure::invalid_request(
            "invalid provider frame",
        )),
    };
    let response = match result {
        Ok(secrets) => ProviderResponse::Ok {
            version: 2,
            secrets,
        },
        Err(error) => ProviderResponse::Error {
            version: 2,
            error: ProviderError {
                code: error.code.into(),
                message: error.message,
                retryable: error.retryable,
            },
        },
    };
    Ok(write_json_frame(std::io::stdout().lock(), &response)?)
}

async fn provide_request(
    store_file: &Path,
    request: ProviderRequest,
    token_endpoint: &str,
) -> Result<Vec<ProjectedSecret>, OAuthRefreshFailure> {
    if request.version != 2
        || request.operation != "get"
        || !matches!(request.reason.as_str(), "expired" | "expires_soon")
    {
        return Err(OAuthRefreshFailure::invalid_request(
            "unsupported provider request",
        ));
    }
    let raw = STANDARD
        .decode(&request.grant)
        .map_err(|_| OAuthRefreshFailure::unauthorized("invalid provider grant"))?;
    if raw.len() > silo_secrets::grant::MAX_BODY || STANDARD.encode(&raw) != request.grant {
        return Err(OAuthRefreshFailure::unauthorized(
            "invalid provider grant encoding",
        ));
    }
    let grant: SecretGrant = serde_json::from_slice(&raw)
        .map_err(|_| OAuthRefreshFailure::unauthorized("invalid provider grant"))?;
    let allowed = grant.authorize(store_file, &request).map_err(|_| {
        OAuthRefreshFailure::unauthorized("provider grant does not authorize this request")
    })?;
    // Validate all names and supported backing kinds before any store IO.
    if allowed.iter().any(|entry| {
        !entry.key.as_str().starts_with("openai_codex_oauth.")
            || !entry.key.as_str().ends_with(".oauth")
    }) {
        return Err(OAuthRefreshFailure::invalid_request(
            "unsupported OAuth backing kind",
        ));
    }
    let store = FileStore::with_store_file(store_file).map_err(OAuthRefreshFailure::from)?;
    let mut groups: Vec<(SecretScope, Vec<&silo_secrets::grant::AllowedSecret>)> = Vec::new();
    for entry in allowed {
        if let Some((_, entries)) = groups
            .iter_mut()
            .find(|(scope, _)| scope == &entry.backing_scope)
        {
            entries.push(entry);
        } else {
            groups.push((entry.backing_scope.clone(), vec![entry]));
        }
    }
    // All provider requests acquire unique scopes in the same path order. Keep
    // every lock until prevalidation and refresh finish, without re-entering a
    // locked scope through FileStore::get/put.
    groups.sort_by_key(|(scope, _)| store.scope_path(scope));
    let scopes = groups
        .iter()
        .map(|(scope, _)| scope.clone())
        .collect::<Vec<_>>();
    let transactions = tokio::task::spawn_blocking(move || {
        scopes
            .iter()
            .map(|scope| store.begin_transaction(scope))
            .collect::<Result<Vec<_>, _>>()
    })
    .await
    .map_err(|e| OAuthRefreshFailure::internal(e.to_string()))?
    .map_err(OAuthRefreshFailure::from)?;
    let mut plans = Vec::new();
    for ((_, entries), tx) in groups.into_iter().zip(transactions) {
        let mut records = std::collections::BTreeMap::new();
        for entry in &entries {
            if records.contains_key(&entry.key) {
                continue;
            }
            let secret = tx
                .get(&entry.key)
                .map_err(OAuthRefreshFailure::from)?
                .ok_or_else(|| OAuthRefreshFailure::not_found("OAuth secret was not found"))?;
            if !matches!(secret, Secret::OAuth(_)) {
                return Err(OAuthRefreshFailure::invalid_request(
                    "backing record is not an OAuth secret",
                ));
            }
            records.insert(entry.key.clone(), secret);
        }
        // Validate every requested projection in every locked scope before the
        // first irreversible HTTP refresh, including optional fields removed
        // since the runtime issued its grant.
        for entry in &entries {
            let value = records
                .get(&entry.key)
                .and_then(|record| record.project(entry.field))
                .ok_or_else(|| OAuthRefreshFailure::not_found("OAuth projection was not found"))?;
            if value.is_empty() {
                return Err(OAuthRefreshFailure::invalid_request(
                    "OAuth projection is empty",
                ));
            }
        }
        for secret in records.values() {
            if let Secret::OAuth(record) = secret {
                if record.expires_at <= Utc::now() + chrono::Duration::seconds(300) {
                    if record.refresh_token.is_empty() {
                        return Err(OAuthRefreshFailure::invalid_request(
                            "OAuth secret does not contain a refresh token",
                        ));
                    }
                    record
                        .refresh_token
                        .as_str()
                        .map_err(OAuthRefreshFailure::from)?;
                }
            }
        }
        plans.push((tx, entries, records));
    }
    let mut projected = Vec::new();
    for (tx, entries, records) in &mut plans {
        for (name, secret) in records.iter_mut() {
            if secret
                .expires_at()
                .is_some_and(|expiry| expiry <= Utc::now() + chrono::Duration::seconds(300))
            {
                *secret = refresh_openai_codex_oauth(secret.clone(), token_endpoint).await?;
                tx.put(name, secret.clone())
                    .map_err(OAuthRefreshFailure::from)?;
                // Do not lose a rotated refresh token if a subsequent record's
                // upstream refresh fails. The response remains all-or-none.
                tx.persist().map_err(OAuthRefreshFailure::from)?;
            }
        }
        for entry in entries.iter() {
            let value = records
                .get(&entry.key)
                .and_then(|record| record.project(entry.field))
                .ok_or_else(|| OAuthRefreshFailure::not_found("OAuth projection was not found"))?;
            projected.push(ProjectedSecret {
                name: entry.slot.clone(),
                value: STANDARD.encode(value.as_bytes()),
            });
        }
    }
    Ok(projected)
}

async fn refresh_openai_codex_oauth(
    secret: Secret,
    token_endpoint: &str,
) -> Result<Secret, OAuthRefreshFailure> {
    let Secret::OAuth(OAuthSecret {
        provider,
        refresh_token,
        account_id,
        created_at,
        ..
    }) = secret
    else {
        return Err(OAuthRefreshFailure::invalid_request(
            "backing record is not an OAuth secret",
        ));
    };
    if refresh_token.is_empty() {
        return Err(OAuthRefreshFailure::invalid_request(
            "OAuth secret does not contain a refresh token",
        ));
    }
    let client = reqwest::Client::builder()
        .user_agent(concat!("silo/", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(8))
        .build()
        .map_err(|err| OAuthRefreshFailure::internal(err.to_string()))?;
    let token = refresh_openai_codex_token(
        &client,
        token_endpoint,
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
    Ok(updated)
}

async fn refresh_openai_codex_token(
    client: &reqwest::Client,
    token_endpoint: &str,
    refresh_token: &str,
) -> Result<TokenResponse, OAuthRefreshFailure> {
    let response = client
        .post(token_endpoint)
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", OPENAI_CODEX_CLIENT_ID),
        ])
        .send()
        .await
        .map_err(|_| OAuthRefreshFailure::provider_unavailable("token endpoint unavailable"))?;
    let status = response.status();
    let body = response.text().await.map_err(|_| {
        OAuthRefreshFailure::provider_unavailable("token endpoint response unavailable")
    })?;
    if !status.is_success() {
        return Err(OAuthRefreshFailure::provider_rejected(format!(
            "OpenAI Codex OAuth refresh returned {status}"
        )));
    }
    let token = serde_json::from_str::<TokenResponse>(&body)
        .map_err(|_| OAuthRefreshFailure::provider_rejected("invalid token endpoint response"))?;
    if token.access_token.is_empty() {
        return Err(OAuthRefreshFailure::provider_rejected(
            "OpenAI Codex OAuth refresh did not include an access token",
        ));
    }
    Ok(token)
}

#[derive(Debug)]
struct OAuthRefreshFailure {
    code: &'static str,
    message: String,
    retryable: bool,
}

impl From<silo_secrets::SecretError> for OAuthRefreshFailure {
    fn from(error: silo_secrets::SecretError) -> Self {
        Self {
            code: error.wire_code(),
            message: "secret store operation failed".into(),
            retryable: matches!(
                error,
                silo_secrets::SecretError::ProviderUnavailable(_)
                    | silo_secrets::SecretError::RateLimited
            ),
        }
    }
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
    use std::time::Duration;

    use clap::Parser;
    use reqwest::StatusCode;

    use crate::app::Cli;
    use crate::commands::Command;

    use crate::commands::secret::{
        is_pending_device_poll_response, plain_secret_value, read_json_frame, set_plain_secret,
        slot_key, write_json_frame, write_plain_secret, LoginProvider, ProviderRequest,
        SecretSubcommand, SetCmd, OPENAI_CODEX_KIND,
    };
    use silo_secrets::{
        FileStore, OAuthSecret, Secret, SecretBytes, SecretKind, SecretName, SecretScope,
        SecretStore,
    };

    fn plain(value: &str) -> Secret {
        Secret::Plain(SecretBytes::new(value.as_bytes().to_vec()))
    }

    #[cfg(unix)]
    #[test]
    fn provider_http_child() {
        use std::os::fd::FromRawFd;
        let Ok(endpoint) = std::env::var("SILO_TEST_PROVIDER_ENDPOINT") else {
            return;
        };
        let store = std::env::var("SILO_TEST_PROVIDER_STORE").unwrap();
        let fd = std::env::var("SILO_TEST_PROVIDER_FD")
            .unwrap()
            .parse()
            .unwrap();
        let output = unsafe { std::fs::File::from_raw_fd(fd) };
        let request = read_json_frame(std::io::stdin().lock()).unwrap();
        let secrets = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(crate::commands::secret::provide_request(
                std::path::Path::new(&store),
                request,
                &endpoint,
            ))
            .unwrap();
        write_json_frame(
            output,
            &silo_secrets::grant::ProviderResponse::Ok {
                version: 2,
                secrets,
            },
        )
        .unwrap();
    }

    #[cfg(unix)]
    fn subprocess_provider_get(
        store: PathBuf,
        endpoint: String,
        request: ProviderRequest,
    ) -> Vec<silo_secrets::grant::ProjectedSecret> {
        use std::os::fd::{AsRawFd, BorrowedFd};
        use std::os::unix::process::CommandExt;
        use std::process::Stdio;
        let (reader, writer) = std::io::pipe().unwrap();
        let fd = writer.as_raw_fd();
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
            .env_clear()
            .env("SILO_TEST_PROVIDER_ENDPOINT", endpoint)
            .env("SILO_TEST_PROVIDER_STORE", store)
            .env("SILO_TEST_PROVIDER_FD", fd.to_string())
            .args([
                "--exact",
                "commands::secret::tests::provider_http_child",
                "--nocapture",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        unsafe {
            command.pre_exec(move || {
                nix::fcntl::fcntl(
                    BorrowedFd::borrow_raw(fd),
                    nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::empty()),
                )
                .map_err(std::io::Error::from)?;
                Ok(())
            });
        }
        let mut child = command.spawn().unwrap();
        drop(writer);
        write_json_frame(child.stdin.take().unwrap(), &request).unwrap();
        let response = silo_secrets::grant::read_json_frame(reader).unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        match response {
            silo_secrets::grant::ProviderResponse::Ok { secrets, .. } => secrets,
            _ => panic!("provider error"),
        }
    }

    struct LocalTokenEndpoint {
        url: String,
        stop: Option<std::sync::mpsc::Sender<()>>,
        server: Option<std::thread::JoinHandle<Vec<String>>>,
    }

    impl LocalTokenEndpoint {
        fn start(rejected_checkpoint: Option<(String, PathBuf, String)>) -> Self {
            use std::io::{Read, Write};
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let url = format!("http://{}/token", listener.local_addr().unwrap());
            listener.set_nonblocking(true).unwrap();
            let (stop, receiver) = std::sync::mpsc::channel();
            let server = std::thread::spawn(move || {
                let mut requests = Vec::new();
                while matches!(
                    receiver.try_recv(),
                    Err(std::sync::mpsc::TryRecvError::Empty)
                ) {
                    let (mut socket, _) = match listener.accept() {
                        Ok(connection) => connection,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(2));
                            continue;
                        }
                        Err(e) => panic!("{e}"),
                    };
                    socket
                        .set_read_timeout(Some(Duration::from_secs(3)))
                        .unwrap();
                    let mut header = Vec::new();
                    while !header.ends_with(b"\r\n\r\n") {
                        let mut byte = [0];
                        socket.read_exact(&mut byte).unwrap();
                        header.push(byte[0]);
                        assert!(header.len() < 8192);
                    }
                    let header = String::from_utf8(header).unwrap();
                    assert!(header.starts_with("POST /token HTTP/1.1"));
                    let length = header
                        .lines()
                        .find_map(|line| {
                            line.to_ascii_lowercase()
                                .strip_prefix("content-length: ")
                                .map(|n| n.parse::<usize>().unwrap())
                        })
                        .unwrap();
                    let mut body = vec![0; length];
                    socket.read_exact(&mut body).unwrap();
                    let body = String::from_utf8(body).unwrap();
                    assert!(body.contains("grant_type=refresh_token"));
                    assert!(body.contains("client_id=app_EMoamEEZ73f0CkXaXp7hrann"));
                    let token = body
                        .split('&')
                        .find_map(|field| field.strip_prefix("refresh_token="))
                        .unwrap();
                    let rejected = rejected_checkpoint
                        .as_ref()
                        .is_some_and(|(reject, _, _)| reject == token);
                    let (status, response) = if rejected {
                        let (_, path, key) = rejected_checkpoint.as_ref().unwrap();
                        let disk: serde_json::Value =
                            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
                        assert_eq!(
                            disk[key]["refresh_token"], "first-refresh-rotated",
                            "first rotation must be durable before the second endpoint call"
                        );
                        ("400 Bad Request", r#"{"error":"invalid_grant"}"#.to_owned())
                    } else {
                        ("200 OK",serde_json::json!({"access_token":format!("{token}-access"),"refresh_token":format!("{token}-rotated"),"expires_in":3600}).to_string())
                    };
                    write!(socket,"HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}",response.len()).unwrap();
                    requests.push(body);
                }
                requests
            });
            Self {
                url,
                stop: Some(stop),
                server: Some(server),
            }
        }
        fn finish(mut self) -> Vec<String> {
            self.stop.take().unwrap().send(()).unwrap();
            self.server.take().unwrap().join().unwrap()
        }
    }
    impl Drop for LocalTokenEndpoint {
        fn drop(&mut self) {
            if let Some(stop) = self.stop.take() {
                let _ = stop.send(());
            }
            if let Some(server) = self.server.take() {
                let _ = server.join();
            }
        }
    }

    fn expired_provider_record(refresh: &str, account: Option<&str>) -> Secret {
        Secret::OAuth(OAuthSecret {
            provider: None,
            access_token: SecretBytes::new(b"old-access".to_vec()),
            refresh_token: SecretBytes::new(refresh.as_bytes().to_vec()),
            expires_at: "2020-01-01T00:00:00Z".parse().unwrap(),
            account_id: account.map(str::to_owned),
            created_at: None,
            updated_at: None,
        })
    }
    fn provider_request_for(
        store: &FileStore,
        addresses: &[(&str, &str, SecretScope, bool)],
    ) -> ProviderRequest {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        use silo_secrets::grant::{AllowedSecret, RequestScope, SecretGrant};
        use silo_secrets::{MachineScopeId, SecretField};
        let machine = MachineScopeId::new("0123456789abcdef0123456789abcdef").unwrap();
        let mut allowed = Vec::new();
        for (slot, key, scope, account) in addresses {
            for (suffix, field) in [
                ("access_token", SecretField::OAuthAccessToken),
                ("expires_at", SecretField::OAuthExpiresAt),
                ("account_id", SecretField::OAuthAccountId),
            ] {
                if suffix == "account_id" && !account {
                    continue;
                }
                allowed.push(AllowedSecret {
                    slot: SecretName::new(format!("{slot}.oauth.{suffix}")).unwrap(),
                    key: SecretName::new(*key).unwrap(),
                    field,
                    backing_scope: scope.clone(),
                });
            }
        }
        let grant =
            SecretGrant::issue(store.path(), machine.clone(), "run".into(), allowed).unwrap();
        ProviderRequest {
            version: 2,
            operation: "get".into(),
            grant: STANDARD.encode(serde_json::to_vec(&grant).unwrap()),
            scope: RequestScope {
                machine,
                run: "run".into(),
            },
            names: grant
                .allowed
                .iter()
                .map(|entry| entry.slot.clone())
                .collect(),
            reason: "expired".into(),
        }
    }

    #[tokio::test]
    async fn provider_prevalidates_all_scopes_and_projections_before_http_or_writes() {
        use crate::commands::secret::provide_request;
        use silo_secrets::MachineScopeId;
        for invalid in [
            "removed-account",
            "plain",
            "missing",
            "empty-account",
            "empty-refresh",
        ] {
            for reverse in [false, true] {
                let dir = tempfile::tempdir().unwrap();
                let store = FileStore::new(dir.path());
                let machine = SecretScope::Machine {
                    id: MachineScopeId::new("0123456789abcdef0123456789abcdef").unwrap(),
                };
                std::fs::create_dir_all(store.scope_path(&machine).parent().unwrap()).unwrap();
                let first = "openai_codex_oauth.first.oauth";
                let second = "openai_codex_oauth.second.oauth";
                store
                    .put(
                        &machine,
                        &SecretName::new(first).unwrap(),
                        expired_provider_record("first-refresh", Some("first-account")),
                    )
                    .unwrap();
                let invalid_record = match invalid {
                    "plain" => plain("wrong-kind"),
                    "removed-account" => expired_provider_record("second-refresh", None),
                    "empty-account" => expired_provider_record("second-refresh", Some("")),
                    "empty-refresh" => expired_provider_record("", Some("second-account")),
                    _ => expired_provider_record("second-refresh", Some("second-account")),
                };
                if invalid != "missing" {
                    store
                        .put(
                            &SecretScope::Home,
                            &SecretName::new(second).unwrap(),
                            invalid_record,
                        )
                        .unwrap();
                } else {
                    std::fs::write(store.path(), b"{}").unwrap();
                }
                let before_home = std::fs::read(store.path()).unwrap();
                let before_machine = std::fs::read(store.scope_path(&machine)).unwrap();
                let mut addresses = vec![
                    ("first", first, machine.clone(), true),
                    ("second", second, SecretScope::Home, true),
                ];
                if reverse {
                    addresses.reverse();
                }
                let endpoint = LocalTokenEndpoint::start(None);
                let result = provide_request(
                    store.path(),
                    provider_request_for(&store, &addresses),
                    &endpoint.url,
                )
                .await;
                assert!(result.is_err(), "{invalid}");
                assert!(
                    endpoint.finish().is_empty(),
                    "{invalid}: invalid later scope reached upstream"
                );
                assert_eq!(std::fs::read(store.path()).unwrap(), before_home);
                assert_eq!(
                    std::fs::read(store.scope_path(&machine)).unwrap(),
                    before_machine
                );
            }
        }
    }

    #[tokio::test]
    async fn provider_keeps_successful_rotation_when_later_http_refresh_fails() {
        use crate::commands::secret::provide_request;
        use silo_secrets::MachineScopeId;
        for separate_scopes in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let store = FileStore::new(dir.path());
            let first_scope = if separate_scopes {
                SecretScope::Machine {
                    id: MachineScopeId::new("0123456789abcdef0123456789abcdef").unwrap(),
                }
            } else {
                SecretScope::Home
            };
            std::fs::create_dir_all(store.scope_path(&first_scope).parent().unwrap()).unwrap();
            let first = "openai_codex_oauth.first.oauth";
            let second = "openai_codex_oauth.second.oauth";
            store
                .put(
                    &first_scope,
                    &SecretName::new(first).unwrap(),
                    expired_provider_record("first-refresh", Some("account")),
                )
                .unwrap();
            let second_record = expired_provider_record("reject-refresh", Some("account"));
            store
                .put(
                    &SecretScope::Home,
                    &SecretName::new(second).unwrap(),
                    second_record.clone(),
                )
                .unwrap();
            let endpoint = LocalTokenEndpoint::start(Some((
                "reject-refresh".into(),
                store.scope_path(&first_scope),
                first.into(),
            )));
            let request = provider_request_for(
                &store,
                &[
                    ("second", second, SecretScope::Home, true),
                    ("first", first, first_scope.clone(), true),
                ],
            );
            let result = provide_request(store.path(), request, &endpoint.url).await;
            assert_eq!(result.err().unwrap().code, "provider_rejected");
            let requests = endpoint.finish();
            assert_eq!(requests.len(), 2);
            assert!(requests[0].contains("refresh_token=first-refresh"));
            assert!(requests[1].contains("refresh_token=reject-refresh"));
            let Secret::OAuth(first_record) = store
                .get(&first_scope, &SecretName::new(first).unwrap())
                .unwrap()
                .unwrap()
            else {
                panic!("OAuth")
            };
            assert_eq!(
                first_record.refresh_token.as_bytes(),
                b"first-refresh-rotated"
            );
            assert_eq!(
                first_record.access_token.as_bytes(),
                b"first-refresh-access"
            );
            assert_eq!(
                store
                    .get(&SecretScope::Home, &SecretName::new(second).unwrap())
                    .unwrap()
                    .unwrap(),
                second_record
            );
            // Retrying the all-or-none response must reuse the durable first
            // rotation and refresh only the failed record.
            let endpoint = LocalTokenEndpoint::start(None);
            let request = provider_request_for(
                &store,
                &[
                    ("second", second, SecretScope::Home, true),
                    ("first", first, first_scope.clone(), true),
                ],
            );
            let values = provide_request(store.path(), request, &endpoint.url)
                .await
                .unwrap();
            assert_eq!(values.len(), 6);
            let requests = endpoint.finish();
            assert_eq!(requests.len(), 1);
            assert!(requests[0].contains("refresh_token=reject-refresh"));
        }
    }

    #[tokio::test]
    async fn provider_refreshes_real_http_once_per_exact_scope_record_and_persists() {
        use crate::commands::secret::provide_request;
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        use silo_secrets::grant::{AllowedSecret, ProviderRequest, RequestScope, SecretGrant};
        use silo_secrets::{MachineScopeId, SecretField};
        use std::io::{Read, Write};
        for machine_backed in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let store = FileStore::new(dir.path());
            let machine = MachineScopeId::new("0123456789abcdef0123456789abcdef").unwrap();
            let scope = if machine_backed {
                SecretScope::Machine {
                    id: machine.clone(),
                }
            } else {
                SecretScope::Home
            };
            std::fs::create_dir_all(store.scope_path(&scope).parent().unwrap()).unwrap();
            let key = SecretName::new("openai_codex_oauth.personal.oauth").unwrap();
            let created = "2025-01-01T00:00:00Z".parse().unwrap();
            store
                .put(
                    &scope,
                    &key,
                    Secret::OAuth(OAuthSecret {
                        provider: if machine_backed {
                            Some("openai-codex".into())
                        } else {
                            None
                        },
                        access_token: SecretBytes::new(b"old-access".to_vec()),
                        refresh_token: SecretBytes::new(b"private-refresh-only-at-host".to_vec()),
                        expires_at: "2020-01-01T00:00:00Z".parse().unwrap(),
                        account_id: Some("account".into()),
                        created_at: Some(created),
                        updated_at: None,
                    }),
                )
                .unwrap();
            if machine_backed {
                store
                    .put(&SecretScope::Home, &key, plain("home-must-stay-untouched"))
                    .unwrap();
            }
            let home_before = std::fs::read(store.path()).ok();
            let allowed = [
                ("access_token", SecretField::OAuthAccessToken),
                ("expires_at", SecretField::OAuthExpiresAt),
                ("account_id", SecretField::OAuthAccountId),
            ]
            .into_iter()
            .map(|(suffix, field)| AllowedSecret {
                slot: SecretName::new(format!("personal.oauth.{suffix}")).unwrap(),
                key: key.clone(),
                field,
                backing_scope: scope.clone(),
            })
            .collect::<Vec<_>>();
            let grant =
                SecretGrant::issue(store.path(), machine.clone(), "run".into(), allowed).unwrap();
            let encoded = STANDARD.encode(serde_json::to_vec(&grant).unwrap());
            assert!(!String::from_utf8(serde_json::to_vec(&grant).unwrap())
                .unwrap()
                .contains("private-refresh"));
            let request = || ProviderRequest {
                version: 2,
                operation: "get".into(),
                grant: encoded.clone(),
                scope: RequestScope {
                    machine: machine.clone(),
                    run: "run".into(),
                },
                names: grant.allowed.iter().map(|a| a.slot.clone()).collect(),
                reason: "expired".into(),
            };
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let endpoint = format!("http://{}/token", listener.local_addr().unwrap());
            listener.set_nonblocking(true).unwrap();
            let (stop_tx, stop_rx) = std::sync::mpsc::channel();
            let server = std::thread::spawn(move || {
                let mut count = 0;
                while stop_rx.try_recv().is_err() {
                    let (mut socket, _) = match listener.accept() {
                        Ok(s) => s,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(std::time::Duration::from_millis(2));
                            continue;
                        }
                        Err(e) => panic!("{e}"),
                    };
                    socket
                        .set_read_timeout(Some(std::time::Duration::from_secs(3)))
                        .unwrap();
                    let mut bytes = Vec::new();
                    while !bytes.ends_with(b"\r\n\r\n") {
                        let mut b = [0];
                        socket.read_exact(&mut b).unwrap();
                        bytes.push(b[0]);
                    }
                    let header = String::from_utf8(bytes).unwrap();
                    let length = header
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .strip_prefix("content-length: ")
                                .map(|n| n.parse::<usize>().unwrap())
                        })
                        .unwrap();
                    let mut body = vec![0; length];
                    socket.read_exact(&mut body).unwrap();
                    let body = String::from_utf8(body).unwrap();
                    assert!(header.starts_with("POST /token HTTP/1.1"));
                    assert!(body.contains("grant_type=refresh_token"));
                    assert!(body.contains("refresh_token=private-refresh-only-at-host"));
                    assert!(body.contains("client_id=app_EMoamEEZ73f0CkXaXp7hrann"));
                    let response = r#"{"access_token":"new-local-access","refresh_token":"rotated-host-refresh","expires_in":3600}"#;
                    write!(socket,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}",response.len()).unwrap();
                    count += 1;
                }
                count
            });
            #[cfg(unix)]
            let first = {
                let path = store.path().to_path_buf();
                let endpoint = endpoint.clone();
                let request = request();
                tokio::task::spawn_blocking(move || {
                    subprocess_provider_get(path, endpoint, request)
                })
            };
            #[cfg(unix)]
            let second = {
                let path = store.path().to_path_buf();
                let endpoint = endpoint.clone();
                let request = request();
                tokio::task::spawn_blocking(move || {
                    subprocess_provider_get(path, endpoint, request)
                })
            };
            #[cfg(unix)]
            let (first, second) = tokio::join!(first, second);
            #[cfg(unix)]
            let responses = [first.unwrap(), second.unwrap()];
            #[cfg(not(unix))]
            let responses = [
                provide_request(store.path(), request(), &endpoint)
                    .await
                    .unwrap(),
                provide_request(store.path(), request(), &endpoint)
                    .await
                    .unwrap(),
            ];
            for response in responses {
                assert_eq!(response.len(), 3);
                assert_eq!(
                    STANDARD
                        .decode(
                            &response
                                .iter()
                                .find(|s| s.name.as_str().ends_with("access_token"))
                                .unwrap()
                                .value
                        )
                        .unwrap(),
                    b"new-local-access"
                );
                let mut wire = Vec::new();
                write_json_frame(
                    &mut wire,
                    &silo_secrets::grant::ProviderResponse::Ok {
                        version: 2,
                        secrets: response,
                    },
                )
                .unwrap();
                assert!(!String::from_utf8(wire)
                    .unwrap()
                    .contains(&STANDARD.encode(b"rotated-host-refresh")));
            }
            stop_tx.send(()).unwrap();
            assert_eq!(server.join().unwrap(), 1);
            let Secret::OAuth(record) = store.get(&scope, &key).unwrap().unwrap() else {
                panic!("OAuth")
            };
            assert_eq!(record.access_token.as_bytes(), b"new-local-access");
            assert_eq!(record.refresh_token.as_bytes(), b"rotated-host-refresh");
            assert_eq!(
                record.provider,
                if machine_backed {
                    Some("openai-codex".into())
                } else {
                    None
                }
            );
            assert_eq!(record.created_at, Some(created));
            assert!(record.updated_at.is_some());
            assert_eq!(record.account_id.as_deref(), Some("account"));
            if machine_backed {
                assert_eq!(std::fs::read(store.path()).ok(), home_before);
            }
            let bytes = std::fs::read(store.scope_path(&scope)).unwrap();
            let values = provide_request(store.path(), request(), "http://127.0.0.1:1/unreachable")
                .await
                .unwrap();
            assert_eq!(values.len(), 3);
            assert_eq!(std::fs::read(store.scope_path(&scope)).unwrap(), bytes);
        }
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
    fn secret_provide_parses_but_is_hidden() {
        let cli = Cli::try_parse_from([
            "silo",
            "secret",
            "provide",
            "--store-file",
            "/tmp/secrets.json",
        ])
        .expect("hidden refresh command should parse");

        let secret = match cli.command {
            Command::Secret(command) => command,
            other => panic!("expected secret command, got {other:?}"),
        };
        assert!(matches!(secret.command, SecretSubcommand::Provide(_)));

        let help = Cli::command().render_long_help().to_string();
        assert!(!help.contains("provide"));
    }

    #[test]
    fn structured_missing_secret_error_preserves_hint_snapshot() {
        let policy = libvm::NetworkPolicy::from_json_str(r#"{"version":1,"endpoints":[{"name":"api","kind":"https","family":"http","transport":"https-mitm","tls":"terminate","capabilities":["credential-injection"],"hosts":["example.com"]}],"credentials":[{"name":"personal","kind":"openai_codex_oauth","endpoint":"api"}]}"#).unwrap();
        let error = libvm::LibVmError::MissingNetworkSecrets {
            reference: "test".into(),
            requirements: policy.secret_requirements(),
            keys: vec!["openai_codex_oauth.personal.oauth".into()],
            policy: Box::new(policy),
        };
        let message = crate::commands::secret::map_start_error(
            error,
            Some(std::path::Path::new("/tmp/home")),
        )
        .to_string();
        assert_eq!(message, "missing required network secret material for persisted network policy in /tmp/home/secrets.json\n- credential openai_codex_oauth.personal\n  expected one of: `openai_codex_oauth.personal.oauth` or `personal.oauth.access_token` and `personal.oauth.expires_at`\n  hint: run `silo secret login openai-codex --name personal`");
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
    fn oauth_refresh_frames_round_trip_json() {
        let request = ProviderRequest {
            version: 2,
            operation: "get".to_string(),
            grant: "e30=".to_string(),
            scope: silo_secrets::grant::RequestScope {
                machine: silo_secrets::MachineScopeId::new("0123456789abcdef0123456789abcdef")
                    .unwrap(),
                run: "run".into(),
            },
            names: vec![SecretName::new("personal.oauth.access_token").unwrap()],
            reason: "expires_soon".to_string(),
        };
        let mut frame = Vec::new();
        write_json_frame(&mut frame, &request).expect("write frame");

        let decoded: ProviderRequest = read_json_frame(frame.as_slice()).expect("read frame");
        assert_eq!(decoded.version, 2);
        assert_eq!(decoded.operation, "get");
        assert_eq!(decoded.grant, "e30=");
        assert_eq!(decoded.names[0].as_str(), "personal.oauth.access_token");
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

    fn assert_plain_secret(store: &FileStore, name: &str, expected: &str) {
        let loaded = get(store, name);
        match loaded {
            Secret::Plain(value) => assert_eq!(value.as_str().unwrap(), expected),
            other => panic!("expected plain secret, got {other:?}"),
        }
    }
}
